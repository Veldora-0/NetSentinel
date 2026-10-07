"""NetSentinel File Integrity Monitoring (FIM) Module.

Establishes cryptographic and metadata baselines for monitored system and
application files, periodically verifies their integrity, and generates
structured SecurityEvents upon detecting file creation, deletion, modification,
replacement, or metadata/permission changes.
"""

from collections import deque
import hashlib
import logging
import os
import stat
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid


try:
    from detector import SecurityEvent
except ImportError:
    from backend.detector import SecurityEvent

try:
    from config import Config
except ImportError:
    from backend.config import Config

logger = logging.getLogger("netsentinel.host.fim")

# Change detection event types
FILE_CREATED = "FILE_CREATED"
FILE_DELETED = "FILE_DELETED"
FILE_MODIFIED = "FILE_MODIFIED"
FILE_REPLACED = "FILE_REPLACED"
FILE_METADATA_CHANGED = "FILE_METADATA_CHANGED"

FIM_DETECTION_TYPES = {
    FILE_CREATED,
    FILE_DELETED,
    FILE_MODIFIED,
    FILE_REPLACED,
    FILE_METADATA_CHANGED,
}

# Baseline record status definitions
STATUS_BASELINE = "BASELINE"
STATUS_MISSING = "MISSING"
STATUS_CHANGED = "CHANGED"
STATUS_UNREADABLE = "UNREADABLE"


def hash_file(
    filepath: str,
    max_size: int = 10485760,
    chunk_size: int = 65536,
) -> Tuple[Optional[str], Optional[str]]:
    """Compute SHA-256 cryptographic digest of a file safely using chunked reading.

    Args:
        filepath: Absolute filesystem path to the target file.
        max_size: Maximum permissible file size in bytes (default 10 MB).
        chunk_size: Read buffer size in bytes (default 64 KiB).

    Returns:
        Tuple of (sha256_hexdigest, error_or_skip_reason).
    """
    try:
        # Use lstat to inspect link attributes safely without blind link following
        st = os.lstat(filepath)
    except FileNotFoundError:
        return None, "FILE_NOT_FOUND"
    except PermissionError:
        return None, "PERMISSION_DENIED"
    except OSError as ex:
        return None, f"STAT_ERROR: {ex}"

    # Do NOT follow symbolic links into arbitrary locations
    if stat.S_ISLNK(st.st_mode):
        return None, "SYMLINK"

    # Only regular files have meaningful content hashes
    if not stat.S_ISREG(st.st_mode):
        return None, "NON_REGULAR"

    # Enforce maximum file size safety bound
    if st.st_size > max_size:
        return None, "SKIPPED_OVERSIZED"

    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest(), None
    except FileNotFoundError:
        return None, "FILE_NOT_FOUND"
    except PermissionError:
        return None, "PERMISSION_DENIED"
    except OSError as ex:
        return None, f"READ_ERROR: {ex}"


class FileIntegrityMonitor:
    """Core File Integrity Monitoring (FIM) engine for host system verification."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        baseline_loader: Optional[Callable[[], Dict[str, Dict[str, Any]]]] = None,
        baseline_saver: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        cfg = config or (getattr(Config, "FIM_SETTINGS", {}) if hasattr(Config, "FIM_SETTINGS") else {})

        self.enabled = bool(cfg.get("fim_enabled", True))
        self.interval_seconds = float(cfg.get("fim_interval_sec", 30.0))
        self.configured_paths: List[str] = [
            os.path.abspath(p.strip())
            for p in cfg.get("fim_paths", ["/etc/passwd", "/etc/group", "/etc/ssh/sshd_config"])
            if p.strip()
        ]
        self.critical_paths: Set[str] = {
            os.path.abspath(p.strip())
            for p in cfg.get(
                "fim_critical_paths",
                ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config", "/etc/sudoers"],
            )
            if p.strip()
        }
        self.max_files = int(cfg.get("fim_max_files", 1000))
        self.max_file_size = int(cfg.get("fim_max_file_size", 10485760))
        self.chunk_size = int(cfg.get("fim_chunk_size", 65536))

        # Optional database persistence hooks (decoupled from direct DB imports)
        self.baseline_loader = baseline_loader
        self.baseline_saver = baseline_saver

        # State management
        self._lock = threading.RLock()
        self._baseline: Dict[str, Dict[str, Any]] = {}
        self.baseline_ready: bool = False
        self._last_reported: Dict[str, Tuple[str, Optional[str], Optional[int], Optional[str], Optional[int], Optional[int]]] = {}

        # Worker metrics & operational state
        self._last_scan_at: Optional[float] = None
        self._last_change_at: Optional[float] = None
        self._last_error: Optional[str] = None
        self._recent_events: deque = deque(maxlen=100)

        # Standalone worker thread support
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable[[SecurityEvent], None]] = []

    def set_persistence(
        self,
        loader: Optional[Callable[[], Dict[str, Dict[str, Any]]]],
        saver: Optional[Callable[[str, Dict[str, Any]], None]],
    ) -> None:
        """Register or update database persistence hooks."""
        with self._lock:
            self.baseline_loader = loader
            self.baseline_saver = saver

    def add_event_callback(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Register a callback for FIM-generated SecurityEvents."""
        self._callbacks.append(callback)

    def _dispatch_event(self, event: SecurityEvent) -> None:
        """Dispatch a SecurityEvent to all registered callbacks."""
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as ex:
                logger.debug("Error in FIM event callback: %s", ex)

    def initialize(self) -> None:
        """Initialize baseline state on startup.

        Loads existing baseline from database if available to survive restarts,
        or creates a new baseline if none exists.
        """
        with self._lock:
            loaded = False
            if self.baseline_loader:
                try:
                    persisted = self.baseline_loader()
                    if persisted:
                        for path, rec in persisted.items():
                            if "exists" not in rec:
                                rec["exists"] = (rec.get("status") != STATUS_MISSING)
                            self._baseline[path] = rec
                        self.baseline_ready = True
                        loaded = True
                        logger.info("FIM: Restored %d baseline records from database", len(persisted))
                except Exception as ex:
                    self._last_error = f"Failed to load baseline: {ex}"
                    logger.warning("FIM: Could not load persisted baseline: %s", ex)

            if not loaded:
                self.build_baseline()

    def inspect_file(self, path: str) -> Dict[str, Any]:
        """Inspect file metadata and compute cryptographic hash safely.

        Args:
            path: Target file path.

        Returns:
            Dictionary containing metadata, hash, and status.
        """
        now = time.time()
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return {
                "path": path,
                "exists": False,
                "file_type": "missing",
                "sha256": None,
                "size": None,
                "mode": None,
                "uid": None,
                "gid": None,
                "inode": None,
                "mtime": None,
                "status": STATUS_MISSING,
                "last_verified": now,
            }
        except PermissionError:
            return {
                "path": path,
                "exists": True,
                "file_type": "unreadable",
                "sha256": None,
                "size": None,
                "mode": None,
                "uid": None,
                "gid": None,
                "inode": None,
                "mtime": None,
                "status": STATUS_UNREADABLE,
                "last_verified": now,
            }
        except OSError as ex:
            return {
                "path": path,
                "exists": False,
                "file_type": "error",
                "sha256": None,
                "size": None,
                "mode": None,
                "uid": None,
                "gid": None,
                "inode": None,
                "mtime": None,
                "status": STATUS_UNREADABLE,
                "error": str(ex),
                "last_verified": now,
            }

        # Resolve type safely without following links
        is_symlink = stat.S_ISLNK(st.st_mode)
        is_dir = stat.S_ISDIR(st.st_mode)
        is_reg = stat.S_ISREG(st.st_mode)

        if is_symlink:
            file_type = "symlink"
        elif is_dir:
            file_type = "directory"
        elif is_reg:
            file_type = "regular"
        else:
            file_type = "special"

        mode_octal = oct(st.st_mode & 0o777)
        sha256 = None
        status = STATUS_BASELINE

        if is_reg:
            digest, reason = hash_file(path, max_size=self.max_file_size, chunk_size=self.chunk_size)
            if reason == "PERMISSION_DENIED":
                status = STATUS_UNREADABLE
            elif reason == "FILE_NOT_FOUND":
                status = STATUS_MISSING
            else:
                sha256 = digest

        return {
            "path": path,
            "exists": True,
            "file_type": file_type,
            "sha256": sha256,
            "size": st.st_size if not is_dir else None,
            "mode": mode_octal,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "inode": st.st_ino,
            "mtime": st.st_mtime,
            "status": status,
            "last_verified": now,
        }

    def get_monitored_files(self) -> List[str]:
        """Resolve all configured paths into an explicit, bounded list of target files.

        Recursively traverses directories without following symlinks and enforces
        the maximum file count bound.
        """
        targets: Set[str] = set()

        for config_path in self.configured_paths:
            norm_path = os.path.abspath(config_path)

            if len(targets) >= self.max_files:
                break

            try:
                st = os.lstat(norm_path)
            except (FileNotFoundError, PermissionError, OSError):
                # Include target even if missing or unreadable so baseline records state
                targets.add(norm_path)
                continue

            # If directory: recursively enumerate regular files up to max_files
            if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                try:
                    for root, dirs, files in os.walk(norm_path, followlinks=False):
                        if len(targets) >= self.max_files:
                            break
                        for f in files:
                            if len(targets) >= self.max_files:
                                break
                            filepath = os.path.abspath(os.path.join(root, f))
                            # Avoid symlink loops or traversal outside
                            try:
                                f_st = os.lstat(filepath)
                                if stat.S_ISREG(f_st.st_mode) or stat.S_ISLNK(f_st.st_mode):
                                    targets.add(filepath)
                            except OSError:
                                targets.add(filepath)
                except Exception as ex:
                    logger.debug("Error walking directory %s: %s", norm_path, ex)
            else:
                targets.add(norm_path)

        return sorted(list(targets))

    def build_baseline(self, paths: Optional[List[str]] = None) -> Dict[str, Any]:
        """Establish initial integrity baseline for configured or specified paths.

        Does NOT emit security events for initial baseline establishment.
        """
        with self._lock:
            target_list = paths or self.get_monitored_files()
            count = 0
            missing = 0
            unreadable = 0

            for p in target_list:
                meta = self.inspect_file(p)
                now = time.time()
                meta["first_seen"] = meta.get("first_seen", now)
                self._baseline[p] = meta
                count += 1

                if meta["status"] == STATUS_MISSING:
                    missing += 1
                elif meta["status"] == STATUS_UNREADABLE:
                    unreadable += 1

                if self.baseline_saver:
                    try:
                        self.baseline_saver(p, meta)
                    except Exception as ex:
                        logger.debug("Failed saving baseline record for %s: %s", p, ex)

            self.baseline_ready = True
            logger.info(
                "FIM baseline established: %d files (%d missing, %d unreadable)",
                count,
                missing,
                unreadable,
            )
            return {
                "established": True,
                "total_files": count,
                "missing": missing,
                "unreadable": unreadable,
            }

    def rebuild_baseline(self, paths: Optional[List[str]] = None) -> Dict[str, Any]:
        """Operator-controlled rebaseline for specified or all monitored paths.

        Updates expected baseline without clearing historical security events.
        """
        with self._lock:
            target_list = paths or self.get_monitored_files()
            updated = 0

            for p in target_list:
                meta = self.inspect_file(p)
                prev = self._baseline.get(p)
                first_seen = prev.get("first_seen", time.time()) if prev else time.time()
                meta["first_seen"] = first_seen
                meta["status"] = STATUS_BASELINE if meta["exists"] and meta["status"] != STATUS_UNREADABLE else meta["status"]
                self._baseline[p] = meta
                # Clear previous change alert state so future changes are cleanly detected
                self._last_reported.pop(p, None)
                updated += 1

                if self.baseline_saver:
                    try:
                        self.baseline_saver(p, meta)
                    except Exception as ex:
                        logger.debug("Failed updating baseline record for %s: %s", p, ex)

            logger.info("FIM re-baseline completed: updated %d path(s)", updated)
            return {
                "success": True,
                "updated_count": updated,
                "paths": target_list,
            }

    def verify_integrity(self, now: Optional[float] = None) -> List[SecurityEvent]:
        """Perform a single verification cycle comparing filesystem state against baseline.

        Returns:
            List of generated SecurityEvents for newly detected changes.
        """
        with self._lock:
            current_time = float(now) if now is not None else time.time()
            self._last_scan_at = current_time

            if not self.baseline_ready:
                self.build_baseline()
                return []

            events: List[SecurityEvent] = []
            targets = set(self._baseline.keys()).union(set(self.get_monitored_files()))

            for path in targets:
                curr = self.inspect_file(path)
                prev = self._baseline.get(path)

                # Case 1: File created (previously absent from baseline, or baseline was missing)
                prev_exists = prev.get("exists", prev.get("status") != STATUS_MISSING) if prev else False
                if not prev or prev.get("status") == STATUS_MISSING or not prev_exists:
                    if curr.get("exists", False) and curr.get("status") != STATUS_UNREADABLE:
                        change_type = FILE_CREATED
                        sev = "HIGH" if path in self.critical_paths else "MEDIUM"
                        self._process_change(
                            path=path,
                            change_type=change_type,
                            severity=sev,
                            prev=prev or {},
                            curr=curr,
                            now=current_time,
                            events=events,
                        )
                    continue

                # Case 2: File deleted (previously existed in baseline, now missing)
                if not curr.get("exists", False) or curr.get("status") == STATUS_MISSING:
                    change_type = FILE_DELETED
                    sev = "HIGH" if path in self.critical_paths else "MEDIUM"
                    self._process_change(
                        path=path,
                        change_type=change_type,
                        severity=sev,
                        prev=prev,
                        curr=curr,
                        now=current_time,
                        events=events,
                    )
                    continue

                # Case 3: Both exist - evaluate identity, hash, and metadata
                # Check for replacement (e.g. inode replacement while path remains)
                prev_ino = prev.get("inode")
                curr_ino = curr.get("inode")
                prev_type = prev.get("file_type")
                curr_type = curr.get("file_type")

                if (prev_ino is not None and curr_ino is not None and prev_ino != curr_ino) or (prev_type != curr_type):
                    change_type = FILE_REPLACED
                    sev = "HIGH"
                    self._process_change(
                        path=path,
                        change_type=change_type,
                        severity=sev,
                        prev=prev,
                        curr=curr,
                        now=current_time,
                        events=events,
                    )
                    continue

                # Content modification check (compare cryptographic hashes)
                prev_hash = prev.get("sha256")
                curr_hash = curr.get("sha256")

                if prev_hash and curr_hash and prev_hash != curr_hash:
                    change_type = FILE_MODIFIED
                    sev = "HIGH" if path in self.critical_paths else "MEDIUM"
                    self._process_change(
                        path=path,
                        change_type=change_type,
                        severity=sev,
                        prev=prev,
                        curr=curr,
                        now=current_time,
                        events=events,
                    )
                    continue

                # Metadata change check (permissions, ownership)
                prev_mode = prev.get("mode")
                curr_mode = curr.get("mode")
                prev_uid = prev.get("uid")
                curr_uid = curr.get("uid")
                prev_gid = prev.get("gid")
                curr_gid = curr.get("gid")

                metadata_diff = (
                    (prev_mode is not None and curr_mode is not None and prev_mode != curr_mode)
                    or (prev_uid is not None and curr_uid is not None and prev_uid != curr_uid)
                    or (prev_gid is not None and curr_gid is not None and prev_gid != curr_gid)
                )

                if metadata_diff:
                    change_type = FILE_METADATA_CHANGED
                    sev = "MEDIUM" if path in self.critical_paths else "LOW"
                    self._process_change(
                        path=path,
                        change_type=change_type,
                        severity=sev,
                        prev=prev,
                        curr=curr,
                        now=current_time,
                        events=events,
                    )
                    continue

                # If no difference: update verification timestamp and clear change latch if restored
                if path in self._last_reported:
                    del self._last_reported[path]
                prev["last_verified"] = current_time
                prev["status"] = STATUS_BASELINE if curr.get("status") != STATUS_UNREADABLE else STATUS_UNREADABLE

            return events

    def _process_change(
        self,
        path: str,
        change_type: str,
        severity: str,
        prev: Dict[str, Any],
        curr: Dict[str, Any],
        now: float,
        events: List[SecurityEvent],
    ) -> None:
        """Handle detected change, enforce de-duplication, record state, and build event."""
        # De-duplication fingerprint across consecutive scans
        fp = (
            change_type,
            curr.get("sha256"),
            curr.get("inode"),
            curr.get("mode"),
            curr.get("uid"),
            curr.get("gid"),
        )
        if self._last_reported.get(path) == fp:
            # Change already reported and unchanged since last scan; do not emit duplicate alert
            return

        self._last_reported[path] = fp
        self._last_change_at = now

        # Update baseline record status
        if path in self._baseline:
            self._baseline[path]["status"] = STATUS_CHANGED if curr.get("exists", False) else STATUS_MISSING
            self._baseline[path]["last_verified"] = now

        # Build explainable, non-speculative description
        if change_type == FILE_CREATED:
            desc = f"New file created at monitored path {path}"
        elif change_type == FILE_DELETED:
            desc = f"Monitored file deleted from path {path}"
        elif change_type == FILE_MODIFIED:
            desc = f"Integrity fingerprint changed for monitored file {path}"
        elif change_type == FILE_REPLACED:
            desc = f"Monitored file identity changed (inode replacement) for {path}"
        elif change_type == FILE_METADATA_CHANGED:
            desc = f"File permissions or ownership metadata changed for {path}"
        else:
            desc = f"File integrity event ({change_type}) for {path}"

        evidence = {
            "path": path,
            "change_type": change_type,
            "previous_sha256": prev.get("sha256"),
            "current_sha256": curr.get("sha256"),
            "previous_mode": prev.get("mode"),
            "current_mode": curr.get("mode"),
            "previous_uid": prev.get("uid"),
            "current_uid": curr.get("uid"),
            "previous_gid": prev.get("gid"),
            "current_gid": curr.get("gid"),
            "previous_inode": prev.get("inode"),
            "current_inode": curr.get("inode"),
            "size": curr.get("size"),
            "file_type": curr.get("file_type", "regular"),
            "source": "host",
        }

        # Source IP is strictly None for host-local file integrity events
        event_id = f"fim-{uuid.uuid4().hex[:12]}"
        event = SecurityEvent(
            event_id=event_id,
            timestamp=now,
            detection_type=change_type,
            severity=severity,
            source_ip=None,
            destination_ip=None,
            protocol=None,
            source_port=None,
            destination_port=None,
            rule_name=f"FIM_{change_type}",
            description=desc,
            evidence=evidence,
        )


        events.append(event)
        self._recent_events.append(event.to_dict())

    def get_status(self) -> Dict[str, Any]:
        """Return operational telemetry and baseline statistics for FIM."""
        with self._lock:
            changed_count = sum(1 for b in self._baseline.values() if b.get("status") == STATUS_CHANGED)
            missing_count = sum(1 for b in self._baseline.values() if b.get("status") == STATUS_MISSING)
            unreadable_count = sum(1 for b in self._baseline.values() if b.get("status") == STATUS_UNREADABLE)

            return {
                "enabled": self.enabled,
                "interval_seconds": self.interval_seconds,
                "baseline_ready": self.baseline_ready,
                "monitored_path_count": len(self.configured_paths),
                "baseline_file_count": len(self._baseline),
                "changed_count": changed_count,
                "missing_count": missing_count,
                "unreadable_count": unreadable_count,
                "last_scan_at": self._last_scan_at,
                "last_change_at": self._last_change_at,
                "last_error": self._last_error,
                "max_files": self.max_files,
                "max_file_size": self.max_file_size,
            }

    # =========================================================================
    # Standalone Thread Support
    # =========================================================================

    def start(self) -> bool:
        """Start the background FIM verification worker thread."""
        if not self.enabled:
            logger.info("FIM is disabled by configuration")
            return False

        if self._worker_thread and self._worker_thread.is_alive():
            return True

        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._run_loop, name="NetSentinel-FIMWorker", daemon=True
        )
        self._worker_thread.start()
        logger.info("FileIntegrityMonitor background worker started (interval: %.1fs)", self.interval_seconds)
        return True

    def stop(self) -> None:
        """Stop the background FIM worker thread."""
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        self._worker_thread = None
        logger.info("FileIntegrityMonitor background worker stopped")

    def _run_loop(self) -> None:
        """Periodic verification loop."""
        while not self._stop_event.is_set():
            try:
                events = self.verify_integrity()
                for ev in events:
                    self._dispatch_event(ev)
            except Exception as ex:
                self._last_error = str(ex)
                logger.debug("Error in FIM verification cycle: %s", ex)

            if self._stop_event.wait(self.interval_seconds):
                break
