"""NetSentinel Worker Lifecycle, Watchdog, and Graceful Shutdown Coordinator.

Maintains centralized registration of core and optional background workers,
monitors heartbeats, identifies stale or crashed threads, orchestrates ordered graceful shutdown,
and executes safe startup capability checks.
"""

from dataclasses import dataclass, field
import logging
import os
import shutil
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("netsentinel.lifecycle")

# Standard Worker Operational States
STATUS_HEALTHY = "HEALTHY"
STATUS_DEGRADED = "DEGRADED"
STATUS_DISABLED = "DISABLED"
STATUS_FAILED = "FAILED"
STATUS_STOPPED = "STOPPED"


class WorkerStatus:
    """Namespace for standard worker lifecycle operational states."""
    HEALTHY = STATUS_HEALTHY
    DEGRADED = STATUS_DEGRADED
    DISABLED = STATUS_DISABLED
    FAILED = STATUS_FAILED
    STOPPED = STATUS_STOPPED



@dataclass
class WorkerRecord:
    """Internal metadata for a registered subsystem worker."""
    name: str
    role: str
    is_optional: bool = False
    instance: Optional[Any] = None
    stop_callable: Optional[Callable[[], Any]] = None
    health_check_callable: Optional[Callable[[], Any]] = None
    stale_threshold_sec: float = 60.0
    last_heartbeat: float = field(default_factory=time.time)
    last_error: Optional[str] = None
    override_status: Optional[str] = None
    error_count: int = 0

    def get_effective_status(self) -> str:
        """Derive current health state based on thread state, errors, and heartbeats."""
        if self.override_status:
            return self.override_status

        # If instance has an explicit enabled flag that is False, it's DISABLED
        if self.instance and hasattr(self.instance, "enabled") and not self.instance.enabled:
            return STATUS_DISABLED

        # If instance has a status attribute
        if self.instance and hasattr(self.instance, "status"):
            inst_status = str(self.instance.status).lower()
            if inst_status in ("stopped", "idle"):
                return STATUS_STOPPED
            if inst_status in ("permission_denied", "error"):
                return STATUS_DEGRADED if self.is_optional else STATUS_FAILED
            if inst_status == "starting":
                return STATUS_HEALTHY

        # Check for thread failure if instance manages a thread
        thread_obj = None
        if self.instance:
            if isinstance(self.instance, threading.Thread):
                thread_obj = self.instance
            else:
                for attr in ("_thread", "_worker_thread", "_capture_thread", "thread"):
                    if hasattr(self.instance, attr):
                        t = getattr(self.instance, attr)
                        if isinstance(t, threading.Thread):
                            thread_obj = t
                            break

        if thread_obj:
            if thread_obj.ident is not None and not thread_obj.is_alive():
                is_stopped = False
                if hasattr(self.instance, "_stop_event") and getattr(self.instance, "_stop_event").is_set():
                    is_stopped = True
                elif hasattr(self.instance, "runtime_status") and self.instance.runtime_status in ("stopped", "idle"):
                    is_stopped = True
                elif hasattr(self.instance, "status") and str(self.instance.status).lower() in ("stopped", "idle"):
                    is_stopped = True

                if not is_stopped:
                    return STATUS_DEGRADED if self.is_optional else STATUS_FAILED

        # Check for custom is_alive callable on instance (e.g. mock or custom worker)
        if self.instance and hasattr(self.instance, "is_alive") and callable(self.instance.is_alive) and not isinstance(self.instance, threading.Thread):
            try:
                if not self.instance.is_alive():
                    return STATUS_DEGRADED if self.is_optional else STATUS_FAILED
            except Exception:
                return STATUS_DEGRADED if self.is_optional else STATUS_FAILED

        # Check for stale heartbeat
        now = time.time()
        if (now - self.last_heartbeat) > (self.stale_threshold_sec * 2):
            return STATUS_DEGRADED

        if self.last_error:
            return STATUS_DEGRADED

        return STATUS_HEALTHY


class LifecycleManager:
    """Coordinates startup readiness, worker health tracking, watchdog checks, and graceful shutdown."""

    def __init__(self):
        self._lock = threading.RLock()
        self._workers: Dict[str, WorkerRecord] = {}
        self._is_shutting_down = False
        self._shutdown_event = threading.Event()

    @property
    def shutdown_event(self) -> threading.Event:
        """Shared event signaling workers to terminate loops."""
        return self._shutdown_event

    def register_worker(
        self,
        name: str,
        instance: Any,
        role: str = "Worker Subsystem",
        is_optional: bool = False,
        stale_threshold_sec: float = 60.0,
        stop_callable: Optional[Callable[[], Any]] = None,
        health_check: Optional[Callable[[], Any]] = None,
    ) -> None:
        """Register a worker thread or subsystem manager with the lifecycle coordinator."""
        with self._lock:
            # Derive stop method if not explicitly provided
            if stop_callable is None and hasattr(instance, "stop"):
                stop_callable = instance.stop

            # Derive health_check callable if not explicitly provided
            if health_check is None:
                if hasattr(instance, "check_health") and callable(instance.check_health):
                    health_check = instance.check_health
                elif hasattr(instance, "is_healthy") and callable(instance.is_healthy):
                    health_check = instance.is_healthy

            self._workers[name] = WorkerRecord(
                name=name,
                role=role,
                is_optional=is_optional,
                instance=instance,
                stop_callable=stop_callable,
                health_check_callable=health_check,
                stale_threshold_sec=stale_threshold_sec,
                last_heartbeat=time.time(),
            )
            logger.debug("Registered worker '%s' (role=%s, optional=%s)", name, role, is_optional)

    def record_heartbeat(self, name: str) -> None:
        """Update worker heartbeat timestamp if worker is functioning."""
        with self._lock:
            w = self._workers.get(name)
            if not w:
                return

            inst = w.instance
            # Verify thread is alive if worker manages an active thread
            thread_obj = None
            if inst:
                if isinstance(inst, threading.Thread):
                    thread_obj = inst
                else:
                    for attr in ("_thread", "_worker_thread", "_capture_thread", "thread"):
                        if hasattr(inst, attr):
                            t = getattr(inst, attr)
                            if isinstance(t, threading.Thread):
                                thread_obj = t
                                break

            if thread_obj and thread_obj.ident is not None and not thread_obj.is_alive():
                # Thread unexpectedly died! Do not mark healthy or update heartbeat
                w.last_error = f"Worker thread for '{name}' died unexpectedly"
                return

            # Check if custom is_alive returns False
            if inst and hasattr(inst, "is_alive") and callable(inst.is_alive) and not isinstance(inst, threading.Thread):
                try:
                    if not inst.is_alive():
                        w.last_error = f"Worker '{name}' is not alive"
                        return
                except Exception as ex:
                    w.last_error = f"Worker '{name}' is_alive check failed: {ex}"
                    return

            # Check if instance is in explicit error status
            if inst and hasattr(inst, "status") and str(inst.status).lower() in ("error", "permission_denied", "failed"):
                return

            w.last_heartbeat = time.time()
            if w.last_error:
                # Valid recovery: worker is genuinely operating without errors
                w.last_error = None

    def check_worker_health(self, name: str) -> Tuple[bool, Optional[str]]:
        """Perform a valid health check on a registered worker and update lifecycle state.
        
        Returns:
            Tuple of (is_healthy, error_or_reason).
        """
        with self._lock:
            w = self._workers.get(name)
            if not w:
                return False, f"Worker '{name}' not found"

            if w.override_status:
                return (w.override_status == STATUS_HEALTHY), None

            inst = w.instance

            # 1. If disabled by configuration, it is in expected DISABLED posture (not an error)
            if inst and hasattr(inst, "enabled") and not inst.enabled:
                return True, None

            # 2. Check thread failure if instance manages a thread
            thread_obj = None
            if inst:
                if isinstance(inst, threading.Thread):
                    thread_obj = inst
                else:
                    for attr in ("_thread", "_worker_thread", "_capture_thread", "thread"):
                        if hasattr(inst, attr):
                            t = getattr(inst, attr)
                            if isinstance(t, threading.Thread):
                                thread_obj = t
                                break

            if thread_obj and thread_obj.ident is not None and not thread_obj.is_alive():
                is_stopped = False
                if hasattr(inst, "_stop_event") and getattr(inst, "_stop_event").is_set():
                    is_stopped = True
                elif hasattr(inst, "runtime_status") and inst.runtime_status in ("stopped", "idle"):
                    is_stopped = True
                elif hasattr(inst, "status") and str(inst.status).lower() in ("stopped", "idle"):
                    is_stopped = True

                if not is_stopped:
                    err_msg = f"Worker thread for '{name}' died unexpectedly"
                    w.last_error = err_msg
                    w.error_count += 1
                    return False, err_msg

            # 3. Check custom is_alive callable if present
            if inst and hasattr(inst, "is_alive") and callable(inst.is_alive) and not isinstance(inst, threading.Thread):
                try:
                    if not inst.is_alive():
                        err_msg = f"Worker '{name}' is not alive"
                        w.last_error = err_msg
                        w.error_count += 1
                        return False, err_msg
                except Exception as ex:
                    err_msg = f"Worker '{name}' is_alive check failed: {ex}"
                    w.last_error = err_msg
                    w.error_count += 1
                    return False, err_msg

            # 4. Check instance status attribute for explicit error or permission denial
            if inst and hasattr(inst, "status"):
                st_lower = str(inst.status).lower()
                if st_lower in ("error", "permission_denied", "failed"):
                    err_msg = f"Worker '{name}' reported status: {inst.status}"
                    w.last_error = err_msg
                    return False, err_msg

            # 5. Check custom health check callable if provided
            if w.health_check_callable:
                try:
                    res = w.health_check_callable()
                    ok = res[0] if isinstance(res, tuple) else bool(res)
                    err_msg = res[1] if isinstance(res, tuple) and len(res) > 1 else None
                    if not ok:
                        msg = err_msg or f"Health check failed for '{name}'"
                        w.last_error = msg
                        w.error_count += 1
                        return False, msg
                except Exception as ex:
                    msg = f"Health check exception for '{name}': {ex}"
                    w.last_error = msg
                    w.error_count += 1
                    return False, msg

            # 6. If all checks succeeded, verify recovery from any previous error
            if w.last_error:
                w.last_error = None

            # 7. Record fresh heartbeat upon successful health check
            w.last_heartbeat = time.time()
            return True, None

    def check_all_workers_health(self) -> Dict[str, Tuple[bool, Optional[str]]]:
        """Perform health checks across all registered workers."""
        with self._lock:
            results = {}
            for name in list(self._workers.keys()):
                results[name] = self.check_worker_health(name)
            return results

    def record_recovery(self, name: str) -> bool:
        """Attempt to validate recovery of a worker and clear its error if genuine."""
        ok, _ = self.check_worker_health(name)
        return ok

    def record_error(self, name: str, error_msg: str) -> None:
        """Record an operational error against a registered worker."""
        with self._lock:
            w = self._workers.get(name)
            if w:
                w.last_error = str(error_msg)
                w.error_count += 1
                logger.warning("Worker '%s' reported error: %s", name, error_msg)

    def record_worker_error(self, name: str, error_msg: str) -> None:
        """Alias for record_error."""
        self.record_error(name, error_msg)

    def set_worker_status(self, name: str, status: str, error: Optional[str] = None) -> None:
        """Directly override worker status (e.g. DISABLED, FAILED)."""
        with self._lock:
            w = self._workers.get(name)
            if w:
                w.override_status = status
                if error is not None:
                    w.last_error = str(error)

    def get_worker_status(self, name: str) -> Optional[Dict[str, Any]]:
        """Return operational details for a specific registered worker."""
        with self._lock:
            w = self._workers.get(name)
            if not w:
                return None
            return {
                "name": w.name,
                "role": w.role,
                "status": w.get_effective_status(),
                "is_optional": w.is_optional,
                "last_heartbeat": w.last_heartbeat,
                "last_error": w.last_error,
                "error_count": w.error_count,
            }

    def get_all_worker_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Return status dictionary for all registered workers."""
        with self._lock:
            statuses = {}
            for name in self._workers:
                st = self.get_worker_status(name)
                if st:
                    statuses[name] = st
            return statuses

    def assess_readiness(self) -> Tuple[bool, Dict[str, Any]]:
        """Evaluate overall application readiness.

        Readiness succeeds if all required (non-optional) workers are HEALTHY or DEGRADED (operating).
        Fails (False) if any required worker has FAILED or is uninitialized.

        Returns:
            Tuple of (is_ready, diagnostics_dict).
        """
        with self._lock:
            checks: Dict[str, str] = {}
            all_ready = True

            for name, w in self._workers.items():
                st = w.get_effective_status()
                checks[name] = st
                if not w.is_optional and st == STATUS_FAILED:
                    all_ready = False

            return all_ready, checks

    def stop_all(self, timeout_per_worker: float = 2.0, timeout: Optional[float] = None) -> None:
        """Gracefully stop all registered workers in reverse-dependency order.

        Prevents duplicate shutdown calls and protects against thread hangs.
        """
        if timeout is not None:
            timeout_per_worker = timeout
        with self._lock:
            if self._is_shutting_down:
                logger.debug("Shutdown already in progress; skipping duplicate call.")
                return
            self._is_shutting_down = True
            self._shutdown_event.set()

        logger.info("Initiating graceful shutdown of NetSentinel background workers...")

        # Preferred shutdown order:
        # 1. Packet capture (stop raw stream)
        # 2. Network detectors (rules, ML, ARP)
        # 3. Host manager (FIM, SSH, processes)
        # 4. Telemetry worker
        # 5. Threat Intelligence worker
        # 6. Firewall cleanup
        ordered_names = [
            "packet_capture",
            "metrics_emitter",
            "threat_intel",
            "host_manager",
            "telemetry",
            "ml_detector",
            "firewall",
        ]

        with self._lock:
            # Add any workers not explicitly in the ordered list
            for name in self._workers:
                if name not in ordered_names:
                    ordered_names.append(name)

        for name in ordered_names:
            worker = self._workers.get(name)
            if not worker or not worker.stop_callable:
                continue

            try:
                logger.info("Stopping worker '%s'...", name)
                # Run stop callable in a short-lived thread to enforce timeout
                stop_fn = worker.stop_callable
                t = threading.Thread(target=stop_fn, name=f"Stop-{name}", daemon=True)
                t.start()
                t.join(timeout=timeout_per_worker)
                if t.is_alive():
                    logger.warning("Worker '%s' did not stop within %.1fs timeout", name, timeout_per_worker)
                worker.override_status = STATUS_STOPPED
            except Exception as ex:
                logger.warning("Error stopping worker '%s': %s", name, ex)

        logger.info("NetSentinel shutdown sequence complete.")


def check_firewall_capabilities(firewall_instance: Any) -> Dict[str, Any]:
    """Inspect system privileges and iptables binary availability without modifying rules.

    Returns:
        Dictionary detailing firewall operational capability.
    """
    if not firewall_instance:
        return {"capable": False, "reason": "Firewall instance not initialized", "mode": "disabled"}

    if not firewall_instance.enabled:
        return {"capable": True, "reason": "Firewall disabled by configuration", "mode": "disabled"}

    if firewall_instance.dry_run:
        return {"capable": True, "reason": "Firewall running in simulated mode (dry_run=True)", "mode": "dry_run"}

    # Live iptables capability inspection
    iptables_bin = shutil.which("iptables")
    if not iptables_bin:
        logger.warning("iptables binary not found in system PATH. Firewall mitigation unavailable.")
        return {
            "capable": False,
            "reason": "iptables binary not found in system PATH",
            "mode": "unavailable",
        }

    # Test read-only query capability (list rules)
    try:
        res = subprocess.run(
            [iptables_bin, "-L", "-n"],
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
        if res.returncode == 0:
            return {"capable": True, "reason": "iptables permissions confirmed", "mode": "live"}
        else:
            err_msg = res.stderr.strip() or f"exit code {res.returncode}"
            logger.warning(
                "Insufficient privileges to execute iptables: %s. Mitigation running in degraded state.",
                err_msg,
            )
            return {
                "capable": False,
                "reason": f"Permission denied on iptables: {err_msg}",
                "mode": "permission_denied",
            }
    except Exception as ex:
        logger.warning("Failed probing iptables capability: %s", ex)
        return {
            "capable": False,
            "reason": f"Capability probe failed: {ex}",
            "mode": "error",
        }
