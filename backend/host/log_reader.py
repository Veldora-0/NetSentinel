"""NetSentinel SSH Authentication Log Reader Module.

Implements resilient, incremental log tailing for Linux authentication logs
and systemd journal SSH service events. Handles rotation, absence, and permissions.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("netsentinel.host.log_reader")

CANDIDATE_AUTH_LOGS = [
    "/var/log/auth.log",
    "/var/log/secure",
]


class SSHLogReader:
    """Incremental Linux authentication log reader and tailer."""

    def __init__(
        self,
        custom_path: Optional[str] = None,
        read_from_start: bool = False,
        configured_path: Optional[str] = None,
    ):
        chosen_path = configured_path if configured_path is not None else custom_path
        self.custom_path = chosen_path.strip() if chosen_path and chosen_path.strip() else None
        self.read_from_start = read_from_start

        self.current_path: Optional[str] = None
        self.last_inode: Optional[int] = None
        self.last_offset: int = 0
        self.status: str = "uninitialized"  # "RUNNING", "not_found", "permission_denied", "error"
        self.status_message: str = ""
        self.total_lines_read: int = 0
        self._journal_source = False
        self._journal_cursor: Optional[str] = None
        self._journalctl = shutil.which("journalctl")

        self._discover_log_file()

    @property
    def offset(self) -> int:
        """Current byte offset in the log file."""
        return self.last_offset

    def _discover_log_file(self) -> Optional[str]:
        """Discover active authentication log path."""
        candidates = [self.custom_path] if self.custom_path else CANDIDATE_AUTH_LOGS

        for path in candidates:
            if path and os.path.exists(path):
                # Verify read permissions
                if os.access(path, os.R_OK):
                    self.current_path = path
                    self.status = "RUNNING"
                    self.status_message = f"Tailing authentication log: {path}"
                    self._init_position(path)
                    logger.info("Found readable auth log at %s", path)
                    return path
                else:
                    self.current_path = path
                    self.status = "PERMISSION_DENIED"
                    self.status_message = f"Read permission denied for log: {path}"
                    logger.warning("Permission denied reading %s", path)
                    return path

        # Some Linux distributions keep authentication events only in journald
        # and do not create /var/log/auth.log or /var/log/secure.
        if not self.custom_path and self._discover_journal():
            return self.current_path

        self.current_path = None
        self.status = "NOT_FOUND"
        self.status_message = "No standard auth log found (/var/log/auth.log, /var/log/secure)"
        logger.debug("No active authentication log file found among candidates")
        return None

    def _discover_journal(self) -> bool:
        """Use journald as a fallback when no standard auth log file exists."""
        if not self._journalctl:
            return False
        try:
            result = subprocess.run(
                [
                    self._journalctl,
                    "--no-pager",
                    "-n", "0",
                    "--show-cursor",
                    "-o", "json",
                    "-u", "ssh.service",
                    "-u", "sshd.service",
                ],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if result.returncode != 0:
                self.status = "PERMISSION_DENIED" if "permission" in result.stderr.lower() else "ERROR"
                self.status_message = result.stderr.strip() or "Unable to query the system journal"
                return False
            for line in result.stdout.splitlines():
                if line.startswith("-- cursor: "):
                    self._journal_cursor = line.removeprefix("-- cursor: ").strip() or None
            self._journal_source = True
            self.current_path = "journald (ssh.service, sshd.service)"
            self.status = "RUNNING"
            self.status_message = "Monitoring SSH authentication events from journald"
            return True
        except subprocess.TimeoutExpired:
            self.status = "ERROR"
            self.status_message = "Timed out while checking the system journal"
        except Exception as ex:
            self.status = "ERROR"
            self.status_message = f"Unable to query the system journal: {ex}"
        return False

    def _read_journal_lines(self, max_lines: int) -> List[str]:
        """Return new SSH service messages since the last journal cursor."""
        if not self._journalctl and not self._discover_journal():
            return []
        command = [self._journalctl, "--no-pager", "-o", "json", "-u", "ssh.service", "-u", "sshd.service"]
        if self._journal_cursor:
            command.append(f"--after-cursor={self._journal_cursor}")
        else:
            command.extend(["--since=-5s"])
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=3, check=False)
            if result.returncode != 0:
                self.status = "PERMISSION_DENIED" if "permission" in result.stderr.lower() else "ERROR"
                self.status_message = result.stderr.strip() or "Unable to read SSH events from journald"
                return []
            messages = []
            for line in result.stdout.splitlines():
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                cursor = entry.get("__CURSOR")
                if cursor:
                    self._journal_cursor = cursor
                message = entry.get("MESSAGE")
                if isinstance(message, str) and message.strip():
                    messages.append(message.strip())
            self.status = "RUNNING"
            self.status_message = "Monitoring SSH authentication events from journald"
            self.total_lines_read += len(messages)
            return messages[-max_lines:]
        except subprocess.TimeoutExpired:
            self.status = "ERROR"
            self.status_message = "Timed out reading SSH events from journald"
        except Exception as ex:
            self.status = "ERROR"
            self.status_message = f"Error reading SSH events from journald: {ex}"
        return []

    def _init_position(self, path: str) -> None:
        """Initialize read offset for newly opened log file."""
        try:
            st = os.stat(path)
            self.last_inode = st.st_ino
            if self.read_from_start:
                self.last_offset = 0
            else:
                # Start at current end of file to prevent reprocessing historical entries
                self.last_offset = st.st_size
        except Exception as ex:
            logger.debug("Error initializing file position for %s: %s", path, ex)
            self.last_offset = 0
            self.last_inode = None

    def read_new_lines(self, max_lines: int = 500) -> List[str]:
        """Read newly appended lines from authentication log incrementally.

        Args:
            max_lines: Upper bound of lines to return in a single cycle.

        Returns:
            List of new log line strings.
        """
        if self._journal_source:
            return self._read_journal_lines(max_lines)

        # Re-check discovery if log file wasn't found previously
        if not self.current_path or self.status in ("NOT_FOUND", "PERMISSION_DENIED"):
            found = self._discover_log_file()
            if not found or self.status != "RUNNING":
                return []

        if not os.path.exists(self.current_path):
            self.status = "NOT_FOUND"
            self.status_message = f"Log file {self.current_path} disappeared"
            return []

        try:
            st = os.stat(self.current_path)

            # Detect log rotation or truncation
            is_rotated = (self.last_inode is not None and st.st_ino != self.last_inode)
            is_truncated = (st.st_size < self.last_offset)

            if is_rotated or is_truncated:
                logger.info("Log rotation or truncation detected on %s (resetting offset)", self.current_path)
                self.last_inode = st.st_ino
                self.last_offset = 0

            # Open and read new lines
            new_lines: List[str] = []
            with open(self.current_path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self.last_offset)
                count = 0
                while count < max_lines:
                    line = fh.readline()
                    if not line:
                        break
                    line_clean = line.strip()
                    if line_clean:
                        new_lines.append(line_clean)
                    count += 1
                self.last_offset = fh.tell()

            self.total_lines_read += len(new_lines)
            self.status = "RUNNING"
            return new_lines

        except PermissionError:
            self.status = "PERMISSION_DENIED"
            self.status_message = f"Read permission denied for log: {self.current_path}"
            return []
        except Exception as ex:
            self.status = "ERROR"
            self.status_message = f"Error reading log {self.current_path}: {str(ex)}"
            logger.debug("Log read exception: %s", ex)
            return []

    def get_status(self) -> Dict[str, Any]:
        """Return operational reader status summary."""
        return {
            "current_path": self.current_path,
            "source": "journald" if self._journal_source else "file",
            "status": self.status,
            "status_message": self.status_message,
            "last_offset": self.last_offset,
            "total_lines_read": self.total_lines_read,
        }
