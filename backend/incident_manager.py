"""NetSentinel Incident Manager.

Implements the Incident Correlation and Investigation Layer (Phase 9).
Aggregates security alerts, risk assessments, and firewall mitigation actions
into stateful, contextual security incidents organized by attacker source IP
or host system identity within bounded time windows.
"""

import copy
import datetime
import logging
import platform
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Set

try:
    from database import (
        get_incident_by_id,
        query_incidents,
        query_incident_stats,
        save_incident_evidence_record,
        save_incident_record,
    )
except ImportError:
    from backend.database import (
        get_incident_by_id,
        query_incidents,
        query_incident_stats,
        save_incident_evidence_record,
        save_incident_record,
    )

logger = logging.getLogger("netsentinel.incident_manager")

# Standard incident statuses
STATUS_OPEN = "OPEN"
STATUS_ACKNOWLEDGED = "ACKNOWLEDGED"
STATUS_RESOLVED = "RESOLVED"
STATUS_CLOSED = "CLOSED"

VALID_STATUSES = {STATUS_OPEN, STATUS_ACKNOWLEDGED, STATUS_RESOLVED, STATUS_CLOSED}

# Severity score mapping
SEVERITY_SCORES = {
    "LOW": 0.20,
    "MEDIUM": 0.40,
    "HIGH": 0.70,
    "CRITICAL": 0.90,
}

SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def score_to_severity(score: float) -> str:
    """Map numeric risk score to standard severity string."""
    if score >= 0.80:
        return "CRITICAL"
    if score >= 0.60:
        return "HIGH"
    if score >= 0.35:
        return "MEDIUM"
    return "LOW"


FIM_DETECTION_TYPES = {
    "FILE_CREATED",
    "FILE_DELETED",
    "FILE_MODIFIED",
    "FILE_REPLACED",
    "FILE_METADATA_CHANGED",
}


def get_detection_domain(detection_type: str) -> str:
    """Determine domain (network or host) from detection type."""
    det = str(detection_type).upper()
    if det in ("SSH_AUTH_FAILURE", "SSH_BRUTE_FORCE", "SUSPICIOUS_PROCESS") or det in FIM_DETECTION_TYPES:
        return "host"
    if det == "CROSS_DOMAIN_ATTACK":
        return "cross-domain"
    return "network"



class IncidentEvidence:
    """Representation of an individual security artifact attached to an incident."""

    def __init__(
        self,
        incident_id: str,
        evidence_type: str,
        reference_id: str,
        timestamp: float,
        source_ip: Optional[str] = None,
        detection_type: Optional[str] = None,
        severity: Optional[str] = None,
        risk_score: Optional[float] = None,
        summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        evidence_id: Optional[str] = None,
    ):
        self.evidence_id = evidence_id or str(uuid.uuid4())
        self.incident_id = incident_id
        self.evidence_type = evidence_type  # SECURITY_EVENT, RISK_ASSESSMENT, FIREWALL_ACTION
        self.reference_id = reference_id
        self.timestamp = float(timestamp)
        self.source_ip = source_ip
        self.detection_type = detection_type
        self.severity = severity
        self.risk_score = risk_score
        self.summary = summary
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence to dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "incident_id": self.incident_id,
            "evidence_type": self.evidence_type,
            "reference_id": self.reference_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "detection_type": self.detection_type,
            "severity": self.severity,
            "risk_score": round(self.risk_score, 4) if self.risk_score is not None else None,
            "summary": self.summary,
            "metadata": self.metadata,
        }


class Incident:
    """Stateful security incident aggregating related events and actions."""

    def __init__(
        self,
        correlation_key: str,
        primary_source_ip: Optional[str] = None,
        incident_id: Optional[str] = None,
        created_at: Optional[float] = None,
    ):
        now = time.time()
        self.incident_id = incident_id or f"inc-{uuid.uuid4().hex[:12]}"
        self.correlation_key = correlation_key
        self.primary_source_ip = primary_source_ip
        self.created_at = float(created_at) if created_at is not None else now
        self.updated_at = self.created_at
        self.first_seen = self.created_at
        self.last_seen = self.created_at

        self.status = STATUS_OPEN
        self.severity = "LOW"
        self.risk_score = 0.0
        self.title = f"Security Incident {self.incident_id}"
        self.summary = ""
        self.correlation_reason = ""

        self.attack_domains: Set[str] = set()
        self.detection_types: Set[str] = set()
        self.event_count = 0
        self.risk_assessment_count = 0
        self.firewall_action_count = 0

        self.closed_at: Optional[float] = None
        self.resolution: Optional[str] = None
        self.analyst_note: Optional[str] = None

        self.evidence_list: List[IncidentEvidence] = []

    def to_dict(self, include_evidence: bool = False) -> Dict[str, Any]:
        """Convert incident to JSON-serializable dictionary."""
        data = {
            "incident_id": self.incident_id,
            "correlation_key": self.correlation_key,
            "primary_source_ip": self.primary_source_ip,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "status": self.status,
            "severity": self.severity,
            "risk_score": round(self.risk_score, 4),
            "title": self.title,
            "summary": self.summary,
            "correlation_reason": self.correlation_reason,
            "attack_domains": sorted(list(self.attack_domains)),
            "detection_types": sorted(list(self.detection_types)),
            "event_count": self.event_count,
            "risk_assessment_count": self.risk_assessment_count,
            "firewall_action_count": self.firewall_action_count,
            "closed_at": self.closed_at,
            "resolution": self.resolution,
            "analyst_note": self.analyst_note,
        }
        if include_evidence:
            data["evidence"] = [e.to_dict() for e in self.evidence_list]
        return data


class IncidentManager:
    """Thread-safe engine for correlating security events into contextual incidents."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        on_incident_created: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_incident_updated: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_incident_status_changed: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        cfg = config or {}
        self.incident_window_sec = float(cfg.get("incident_window_sec", 300.0))
        self.max_active_incidents = int(cfg.get("max_active_incidents", 1000))
        self.cross_domain_boost = float(cfg.get("cross_domain_boost", 0.10))
        self.multi_vector_boost = float(cfg.get("multi_vector_boost", 0.05))
        self.max_incident_boost = float(cfg.get("max_incident_boost", 0.20))
        self.auto_resolve_sec = float(cfg.get("auto_resolve_sec", 86400.0))

        self.on_incident_created = on_incident_created
        self.on_incident_updated = on_incident_updated
        self.on_incident_status_changed = on_incident_status_changed

        self._lock = threading.RLock()
        # Active incidents keyed by correlation_key (e.g. "ip:192.168.1.10" or "host:debian")
        self._active_by_key: Dict[str, Incident] = {}
        # Fast lookup by incident_id
        self._incidents_by_id: Dict[str, Incident] = {}

    def resolve_correlation_key(self, event_or_data: Any) -> tuple[str, Optional[str]]:
        """Resolve the correlation key and primary source IP from an event or dictionary.

        Returns:
            Tuple of (correlation_key, primary_source_ip).
        """
        if isinstance(event_or_data, dict):
            src_ip = event_or_data.get("source_ip")
            det_type = str(event_or_data.get("detection_type", "")).upper()
            evidence = event_or_data.get("evidence", {})
        else:
            src_ip = getattr(event_or_data, "source_ip", None)
            det_type = str(getattr(event_or_data, "detection_type", "")).upper()
            evidence = getattr(event_or_data, "evidence", {})

        src_ip_str = str(src_ip).strip() if (src_ip is not None and str(src_ip).strip()) else None

        # Rule: Host events without an external source IP must correlate to host identity, NOT 127.0.0.1
        is_fim = det_type in FIM_DETECTION_TYPES
        is_host_only = (
            det_type == "SUSPICIOUS_PROCESS"
            or is_fim
            or (evidence and isinstance(evidence, dict) and evidence.get("source") == "host" and not src_ip_str)
            or (src_ip_str in ("127.0.0.1", "::1", "localhost") and (det_type == "SUSPICIOUS_PROCESS" or is_fim))
        )

        if is_host_only:
            hostname = platform.node() or "localhost"
            return f"host:{hostname}", None


        if src_ip_str and src_ip_str not in ("127.0.0.1", "::1", "None", ""):
            return f"ip:{src_ip_str}", src_ip_str

        # Fallback to local host identity if no valid source IP
        hostname = platform.node() or "localhost"
        return f"host:{hostname}", None

    def correlate_security_event(
        self,
        event: Any,
        risk_assessment: Optional[Any] = None,
    ) -> Incident:
        """Correlate a SecurityEvent and optional RiskAssessment into an incident."""
        with self._lock:
            # Extract basic event fields
            if isinstance(event, dict):
                ev_id = event.get("event_id") or str(uuid.uuid4())
                ev_ts = float(event.get("timestamp", time.time()))
                det_type = str(event.get("detection_type", "UNKNOWN")).upper()
                sev = str(event.get("severity", "LOW")).upper()
                desc = str(event.get("description", ""))
                ev_meta = event.get("evidence", {})
            else:
                ev_id = getattr(event, "event_id", str(uuid.uuid4()))
                ev_ts = float(getattr(event, "timestamp", time.time()))
                det_type = str(getattr(event, "detection_type", "UNKNOWN")).upper()
                sev = str(getattr(event, "severity", "LOW")).upper()
                desc = getattr(event, "description", "")
                ev_meta = getattr(event, "evidence", {})

            corr_key, primary_src = self.resolve_correlation_key(event)

            # Determine risk score contribution
            event_score = SEVERITY_SCORES.get(sev, 0.20)
            if risk_assessment:
                if isinstance(risk_assessment, dict):
                    assessment_score = float(risk_assessment.get("combined_score", event_score))
                else:
                    assessment_score = float(getattr(risk_assessment, "combined_score", event_score))
                candidate_score = max(event_score, assessment_score)
            else:
                candidate_score = event_score

            incident = self._get_or_create_incident(corr_key, primary_src, ev_ts)
            is_new = (incident.event_count == 0)

            # Update temporal bounds
            incident.updated_at = max(incident.updated_at, ev_ts)
            incident.last_seen = max(incident.last_seen, ev_ts)
            incident.first_seen = min(incident.first_seen, ev_ts)

            # Add detection type and domain
            incident.detection_types.add(det_type)
            domain = get_detection_domain(det_type)
            if domain == "cross-domain":
                incident.attack_domains.add("network")
                incident.attack_domains.add("host")
            else:
                incident.attack_domains.add(domain)

            incident.event_count += 1
            save_incident_record(incident)

            # Attach event evidence
            ev_evidence = IncidentEvidence(
                incident_id=incident.incident_id,
                evidence_type="SECURITY_EVENT",
                reference_id=ev_id,
                timestamp=ev_ts,
                source_ip=primary_src,
                detection_type=det_type,
                severity=sev,
                risk_score=event_score,
                summary=desc or f"{det_type} detected",
                metadata=ev_meta if isinstance(ev_meta, dict) else {"raw": str(ev_meta)},
            )
            incident.evidence_list.append(ev_evidence)
            save_incident_evidence_record(ev_evidence)

            # Attach risk assessment evidence if provided
            if risk_assessment:
                incident.risk_assessment_count += 1
                if isinstance(risk_assessment, dict):
                    risk_id = risk_assessment.get("assessment_id") or str(uuid.uuid4())
                    r_score = float(risk_assessment.get("combined_score", candidate_score))
                    r_level = str(risk_assessment.get("risk_level", sev))
                    r_sum = f"Risk assessment: score={r_score:.2f}, level={r_level}"
                    r_meta = risk_assessment
                else:
                    risk_id = getattr(risk_assessment, "assessment_id", str(uuid.uuid4()))
                    r_score = float(getattr(risk_assessment, "combined_score", candidate_score))
                    r_level = str(getattr(risk_assessment, "risk_level", sev))
                    r_sum = f"Risk assessment: score={r_score:.2f}, level={r_level}"
                    r_meta = risk_assessment.to_dict() if hasattr(risk_assessment, "to_dict") else {}

                risk_evidence = IncidentEvidence(
                    incident_id=incident.incident_id,
                    evidence_type="RISK_ASSESSMENT",
                    reference_id=risk_id,
                    timestamp=ev_ts,
                    source_ip=primary_src,
                    detection_type=det_type,
                    severity=r_level,
                    risk_score=r_score,
                    summary=r_sum,
                    metadata=r_meta if isinstance(r_meta, dict) else {},
                )
                incident.evidence_list.append(risk_evidence)
                save_incident_evidence_record(risk_evidence)

            # Recalculate deterministic incident risk score and title/summary
            self._update_incident_metrics(incident, candidate_score)

            # Persist incident state
            save_incident_record(incident)

            # Emit callbacks
            incident_dict = incident.to_dict(include_evidence=False)
            if is_new and self.on_incident_created:
                try:
                    self.on_incident_created(incident_dict)
                except Exception as ex:
                    logger.debug("on_incident_created callback error: %s", ex)
            elif not is_new and self.on_incident_updated:
                try:
                    self.on_incident_updated(incident_dict)
                except Exception as ex:
                    logger.debug("on_incident_updated callback error: %s", ex)

            return incident

    def correlate_firewall_action(
        self,
        action: str,
        source_ip: str,
        reason: str,
        timestamp: Optional[float] = None,
        duration: Optional[float] = None,
        action_id: Optional[str] = None,
    ) -> Optional[Incident]:
        """Correlate a firewall block/unblock action to an active incident for that source IP."""
        with self._lock:
            ts = float(timestamp) if timestamp is not None else time.time()
            corr_key = f"ip:{source_ip}"

            # Find active incident or existing incident for this key
            incident = self._active_by_key.get(corr_key)
            if not incident:
                # If no active incident in memory, check recent incidents in database
                existing_recs = query_incidents(
                    limit=1,
                    status=STATUS_OPEN,
                    primary_source_ip=source_ip,
                )
                if existing_recs.get("incidents"):
                    inc_data = existing_recs["incidents"][0]
                    incident = self._hydrate_incident(inc_data["incident_id"])

            if not incident:
                # Create a targeted incident if none exists for this firewall action
                incident = self._get_or_create_incident(corr_key, source_ip, ts)

            incident.updated_at = max(incident.updated_at, ts)
            incident.last_seen = max(incident.last_seen, ts)
            incident.firewall_action_count += 1
            save_incident_record(incident)

            act_summary = f"Firewall {action.upper()}: {reason}"
            meta = {
                "action": action,
                "source_ip": source_ip,
                "reason": reason,
                "duration": duration,
            }
            fw_ev = IncidentEvidence(
                incident_id=incident.incident_id,
                evidence_type="FIREWALL_ACTION",
                reference_id=action_id or str(uuid.uuid4()),
                timestamp=ts,
                source_ip=source_ip,
                summary=act_summary,
                metadata=meta,
            )
            incident.evidence_list.append(fw_ev)
            save_incident_evidence_record(fw_ev)

            # Re-generate summary to reflect firewall action
            self._update_incident_metrics(incident, incident.risk_score)
            save_incident_record(incident)

            if self.on_incident_updated:
                try:
                    self.on_incident_updated(incident.to_dict(include_evidence=False))
                except Exception as ex:
                    logger.debug("on_incident_updated callback error: %s", ex)

            return incident

    def transition_status(
        self,
        incident_id: str,
        target_status: str,
        analyst_note: Optional[str] = None,
        resolution: Optional[str] = None,
    ) -> tuple[bool, str, Optional[Dict[str, Any]]]:
        """Perform a validated status transition on an incident.

        Returns:
            Tuple of (success, message, incident_dict).
        """
        target = str(target_status).upper().strip()
        if target not in VALID_STATUSES:
            return False, f"Invalid target status '{target_status}'. Valid: {list(VALID_STATUSES)}", None

        with self._lock:
            incident = self.get_incident(incident_id, include_evidence=True)
            if not incident:
                return False, f"Incident '{incident_id}' not found.", None

            current_status = incident["status"]
            if current_status == target:
                # Idempotent or note update
                if analyst_note or resolution:
                    now = time.time()
                    self._update_stored_incident_notes(incident_id, analyst_note, resolution, now)
                    updated = self.get_incident(incident_id, include_evidence=False)
                    return True, f"Incident {incident_id} notes updated.", updated
                return True, f"Incident is already in status {target}.", incident

            # Transition validation rules
            valid_transition = False
            if current_status == STATUS_OPEN:
                valid_transition = target in (STATUS_ACKNOWLEDGED, STATUS_RESOLVED, STATUS_CLOSED)
            elif current_status == STATUS_ACKNOWLEDGED:
                valid_transition = target in (STATUS_OPEN, STATUS_RESOLVED, STATUS_CLOSED)
            elif current_status in (STATUS_RESOLVED, STATUS_CLOSED):
                valid_transition = target in (STATUS_OPEN, STATUS_ACKNOWLEDGED, STATUS_RESOLVED, STATUS_CLOSED)

            if not valid_transition:
                return False, f"Cannot transition incident from {current_status} to {target}.", None

            now = time.time()
            closed_at = now if target in (STATUS_RESOLVED, STATUS_CLOSED) else None

            # Update memory model if active
            inc_obj = self._incidents_by_id.get(incident_id)
            if inc_obj:
                inc_obj.status = target
                inc_obj.updated_at = now
                if closed_at is not None:
                    inc_obj.closed_at = closed_at
                if resolution:
                    inc_obj.resolution = resolution
                if analyst_note:
                    inc_obj.analyst_note = analyst_note
                # If resolved or closed, remove from active correlation so new traffic starts a clean incident
                if target in (STATUS_RESOLVED, STATUS_CLOSED):
                    self._active_by_key.pop(inc_obj.correlation_key, None)
                elif target in (STATUS_OPEN, STATUS_ACKNOWLEDGED):
                    # Reinstate in active correlation
                    self._active_by_key[inc_obj.correlation_key] = inc_obj

                save_incident_record(inc_obj)
                res_dict = inc_obj.to_dict(include_evidence=False)
            else:
                # Update DB directly
                rec = get_incident_by_id(incident_id, include_evidence=False)
                if rec:
                    rec["status"] = target
                    rec["updated_at"] = now
                    rec["closed_at"] = closed_at
                    if resolution:
                        rec["resolution"] = resolution
                    if analyst_note:
                        rec["analyst_note"] = analyst_note
                    save_incident_record(rec)
                    res_dict = rec
                else:
                    return False, f"Incident record '{incident_id}' not found.", None

            # Notify listeners
            if self.on_incident_status_changed:
                try:
                    self.on_incident_status_changed({
                        "incident_id": incident_id,
                        "old_status": current_status,
                        "new_status": target,
                        "timestamp": now,
                        "analyst_note": analyst_note,
                        "resolution": resolution,
                    })
                except Exception as ex:
                    logger.debug("on_incident_status_changed callback error: %s", ex)

            return True, f"Incident transitioned from {current_status} to {target}.", res_dict

    def get_incident(self, incident_id: str, include_evidence: bool = True) -> Optional[Dict[str, Any]]:
        """Retrieve an incident by ID from active memory or database."""
        with self._lock:
            inc_obj = self._incidents_by_id.get(incident_id)
            if inc_obj:
                return inc_obj.to_dict(include_evidence=include_evidence)

            # Query database
            return get_incident_by_id(incident_id, include_evidence=include_evidence)

    def build_incident_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """Construct a unified, chronological timeline of all events and actions for an incident."""
        with self._lock:
            inc = self.get_incident(incident_id, include_evidence=True)
            if not inc:
                return []

            timeline = []

            # 1. Incident Creation Milestone
            timeline.append({
                "timestamp": inc["created_at"],
                "type": "MILESTONE",
                "milestone": "INCIDENT_CREATED",
                "title": f"Incident Created: {inc['title']}",
                "description": f"Incident {inc['incident_id']} opened with initial severity {inc['severity']} (Risk score: {inc['risk_score']:.2f}).",
                "severity": inc["severity"],
                "source_ip": inc["primary_source_ip"],
                "metadata": {
                    "correlation_key": inc["correlation_key"],
                    "correlation_reason": inc.get("correlation_reason", ""),
                },
            })

            # 2. Evidence Items
            evidence_items = inc.get("evidence", [])
            for ev in evidence_items:
                ev_type = ev.get("evidence_type", "SECURITY_EVENT")
                ts = ev.get("timestamp", inc["created_at"])
                det = ev.get("detection_type")
                sev = ev.get("severity") or inc["severity"]
                summary = ev.get("summary", "")
                meta = ev.get("metadata", {})

                if ev_type == "SECURITY_EVENT":
                    is_fim = (det or "").upper() in FIM_DETECTION_TYPES
                    t_title = f"File Integrity: {det.replace('FILE_', '').title()}" if is_fim else f"Detection: {det or 'Alert'}"
                    t_desc = summary or ("File integrity change detected" if is_fim else f"Security event {det} recorded")
                    timeline.append({
                        "timestamp": ts,
                        "type": "SECURITY_EVENT",
                        "title": t_title,
                        "description": t_desc,
                        "severity": sev,
                        "source_ip": ev.get("source_ip") or inc["primary_source_ip"],
                        "metadata": meta,
                    })

                elif ev_type == "RISK_ASSESSMENT":
                    score = ev.get("risk_score")
                    timeline.append({
                        "timestamp": ts,
                        "type": "RISK_ASSESSMENT",
                        "title": f"Risk Evaluation: {sev}",
                        "description": summary or f"Risk assessed as {sev} (score {score})",
                        "severity": sev,
                        "source_ip": ev.get("source_ip") or inc["primary_source_ip"],
                        "metadata": meta,
                    })
                elif ev_type == "FIREWALL_ACTION":
                    act = meta.get("action", "ACTION").upper()
                    timeline.append({
                        "timestamp": ts,
                        "type": "FIREWALL_ACTION",
                        "title": f"Mitigation: Firewall {act}",
                        "description": summary or f"Automated firewall action {act} executed",
                        "severity": "CRITICAL" if act == "BLOCK" else "INFO",
                        "source_ip": ev.get("source_ip") or inc["primary_source_ip"],
                        "metadata": meta,
                    })

            # 3. Status milestones (Resolution / Closure)
            if inc.get("status") in (STATUS_RESOLVED, STATUS_CLOSED) and inc.get("closed_at"):
                timeline.append({
                    "timestamp": inc["closed_at"],
                    "type": "MILESTONE",
                    "milestone": f"INCIDENT_{inc['status']}",
                    "title": f"Incident {inc['status'].title()}",
                    "description": inc.get("resolution") or f"Marked as {inc['status']} by operator.",
                    "severity": "INFO",
                    "source_ip": inc["primary_source_ip"],
                    "metadata": {
                        "analyst_note": inc.get("analyst_note"),
                        "resolution": inc.get("resolution"),
                    },
                })

            # Sort chronologically
            timeline.sort(key=lambda x: x["timestamp"])
            return timeline

    def get_incident_summary(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Generate an executive/SOC report summary for an incident."""
        with self._lock:
            inc = self.get_incident(incident_id, include_evidence=True)
            if not inc:
                return None

            first_seen_iso = (
                datetime.datetime.fromtimestamp(inc["first_seen"], tz=datetime.timezone.utc).isoformat()
                if inc["first_seen"]
                else None
            )
            last_seen_iso = (
                datetime.datetime.fromtimestamp(inc["last_seen"], tz=datetime.timezone.utc).isoformat()
                if inc["last_seen"]
                else None
            )
            duration_sec = max(0.0, inc["last_seen"] - inc["first_seen"])

            # Aggregate detection types breakdown
            ev_list = inc.get("evidence", [])
            sec_events = [e for e in ev_list if e.get("evidence_type") == "SECURITY_EVENT"]
            fw_events = [e for e in ev_list if e.get("evidence_type") == "FIREWALL_ACTION"]

            return {
                "incident_id": inc["incident_id"],
                "title": inc["title"],
                "summary": inc["summary"],
                "status": inc["status"],
                "severity": inc["severity"],
                "risk_score": inc["risk_score"],
                "primary_source_ip": inc["primary_source_ip"],
                "correlation_key": inc["correlation_key"],
                "correlation_reason": inc.get("correlation_reason", ""),
                "first_seen": inc["first_seen"],
                "first_seen_iso": first_seen_iso,
                "last_seen": inc["last_seen"],
                "last_seen_iso": last_seen_iso,
                "duration_seconds": round(duration_sec, 2),
                "attack_domains": inc["attack_domains"],
                "attack_vectors": inc["detection_types"],
                "total_events": inc["event_count"],
                "total_assessments": inc["risk_assessment_count"],
                "total_mitigations": inc["firewall_action_count"],
                "analyst_note": inc.get("analyst_note"),
                "resolution": inc.get("resolution"),
                "closed_at": inc.get("closed_at"),
                "mitigations_applied": [
                    {
                        "action": e.get("metadata", {}).get("action"),
                        "timestamp": e.get("timestamp"),
                        "summary": e.get("summary"),
                    }
                    for e in fw_events
                ],
            }

    # ==========================================================================
    # Internal Helpers
    # ==========================================================================

    def _get_or_create_incident(
        self,
        correlation_key: str,
        primary_source_ip: Optional[str],
        timestamp: float,
    ) -> Incident:
        """Find an active open/acknowledged incident within window or create a new one."""
        existing = self._active_by_key.get(correlation_key)
        if existing and existing.status in (STATUS_OPEN, STATUS_ACKNOWLEDGED):
            # Check if within correlation window
            if (timestamp - existing.last_seen) <= self.incident_window_sec:
                return existing
            else:
                # Window expired for this active incident: pop it from active tracking
                self._active_by_key.pop(correlation_key, None)

        # Enforce memory bounds before allocating a new incident
        if len(self._active_by_key) >= self.max_active_incidents:
            self._prune_oldest_active()

        # Create new incident
        new_inc = Incident(
            correlation_key=correlation_key,
            primary_source_ip=primary_source_ip,
            created_at=timestamp,
        )
        self._active_by_key[correlation_key] = new_inc
        self._incidents_by_id[new_inc.incident_id] = new_inc
        return new_inc

    def _update_incident_metrics(self, incident: Incident, incoming_score: float) -> None:
        """Compute monotonic risk score, boosted severity, and explainable title & summary."""
        # 1. Monotonic base score: cannot be lower than existing or incoming
        base_score = max(incident.risk_score, float(incoming_score))

        # 2. Deterministic correlation boosts
        boost = 0.0
        # Cross-domain boost: both network and host
        if len(incident.attack_domains) >= 2:
            boost += self.cross_domain_boost
        # Multi-vector boost: 2 or more distinct attack types
        if len(incident.detection_types) >= 2:
            boost += self.multi_vector_boost

        boost = min(boost, self.max_incident_boost)
        final_score = min(1.0, base_score + boost)
        incident.risk_score = final_score

        # 3. Severity mapping (monotonic rule: cannot downgrade during active correlation)
        new_sev = score_to_severity(final_score)
        curr_idx = SEVERITY_LEVELS.index(incident.severity) if incident.severity in SEVERITY_LEVELS else 0
        new_idx = SEVERITY_LEVELS.index(new_sev) if new_sev in SEVERITY_LEVELS else 0
        incident.severity = SEVERITY_LEVELS[max(curr_idx, new_idx)]

        # 4. Dynamic explainable title (strictly objective, no speculative APT terminology)
        src_label = incident.primary_source_ip or incident.correlation_key.replace("host:", "Host ")
        det_list = sorted(list(incident.detection_types))
        det_count = len(det_list)

        if "cross-domain" in det_list or len(incident.attack_domains) >= 2:
            incident.title = f"Correlated Cross-Domain Activity from {src_label}"
        elif det_count == 1:
            det_name = det_list[0].replace("_", " ").title()
            incident.title = f"{det_name} Activity from {src_label}"
        elif det_count > 1:
            det_summary = ", ".join(d.replace("_", " ").title() for d in det_list[:2])
            if det_count > 2:
                det_summary += f" +{det_count - 2} more"
            incident.title = f"Multi-Vector Activity from {src_label} ({det_summary})"
        else:
            incident.title = f"Security Activity from {src_label}"

        # 5. Explainable correlation reason
        domain_str = " & ".join(sorted(list(incident.attack_domains))) if incident.attack_domains else "network"
        vectors_str = ", ".join(sorted(list(incident.detection_types))) if incident.detection_types else "None"
        fw_clause = f"; {incident.firewall_action_count} mitigation action(s) triggered" if incident.firewall_action_count > 0 else ""

        incident.correlation_reason = (
            f"Aggregated {incident.event_count} event(s) for target {src_label} across [{domain_str}] domains "
            f"(vectors: {vectors_str}) within {self.incident_window_sec:.0f}s correlation window{fw_clause}."
        )

        # 6. Concise incident summary
        incident.summary = (
            f"Incident {incident.incident_id} ({incident.severity}): {incident.title}. "
            f"Risk score is {incident.risk_score:.2f} based on {incident.event_count} detection(s) and {incident.firewall_action_count} mitigation(s)."
        )

    def _prune_oldest_active(self) -> None:
        """Evict oldest active incident to preserve memory limits."""
        if not self._active_by_key:
            return
        oldest_key = min(self._active_by_key.keys(), key=lambda k: self._active_by_key[k].last_seen)
        self._active_by_key.pop(oldest_key, None)

    def _update_stored_incident_notes(
        self, incident_id: str, note: Optional[str], resolution: Optional[str], updated_at: float
    ) -> None:
        """Helper to update notes on active or persisted incident."""
        inc_obj = self._incidents_by_id.get(incident_id)
        if inc_obj:
            if note:
                inc_obj.analyst_note = note
            if resolution:
                inc_obj.resolution = resolution
            inc_obj.updated_at = updated_at
            save_incident_record(inc_obj)
        else:
            rec = get_incident_by_id(incident_id, include_evidence=False)
            if rec:
                if note:
                    rec["analyst_note"] = note
                if resolution:
                    rec["resolution"] = resolution
                rec["updated_at"] = updated_at
                save_incident_record(rec)

    def _hydrate_incident(self, incident_id: str) -> Optional[Incident]:
        """Load an incident from SQLite into in-memory structure."""
        data = get_incident_by_id(incident_id, include_evidence=True)
        if not data:
            return None
        inc = Incident(
            correlation_key=data["correlation_key"],
            primary_source_ip=data.get("primary_source_ip"),
            incident_id=data["incident_id"],
            created_at=data["created_at"],
        )
        inc.updated_at = data["updated_at"]
        inc.first_seen = data["first_seen"]
        inc.last_seen = data["last_seen"]
        inc.status = data["status"]
        inc.severity = data["severity"]
        inc.risk_score = data["risk_score"]
        inc.title = data["title"]
        inc.summary = data.get("summary", "")
        inc.correlation_reason = data.get("correlation_reason", "")
        inc.attack_domains = set(data.get("attack_domains", []))
        inc.detection_types = set(data.get("detection_types", []))
        inc.event_count = data.get("event_count", 0)
        inc.risk_assessment_count = data.get("risk_assessment_count", 0)
        inc.firewall_action_count = data.get("firewall_action_count", 0)
        inc.closed_at = data.get("closed_at")
        inc.resolution = data.get("resolution")
        inc.analyst_note = data.get("analyst_note")

        for ev_data in data.get("evidence", []):
            ev = IncidentEvidence(
                incident_id=inc.incident_id,
                evidence_type=ev_data["evidence_type"],
                reference_id=ev_data["reference_id"],
                timestamp=ev_data["timestamp"],
                source_ip=ev_data.get("source_ip"),
                detection_type=ev_data.get("detection_type"),
                severity=ev_data.get("severity"),
                risk_score=ev_data.get("risk_score"),
                summary=ev_data.get("summary", ""),
                metadata=ev_data.get("metadata", {}),
                evidence_id=ev_data.get("evidence_id"),
            )
            inc.evidence_list.append(ev)

        self._incidents_by_id[inc.incident_id] = inc
        if inc.status in (STATUS_OPEN, STATUS_ACKNOWLEDGED):
            self._active_by_key[inc.correlation_key] = inc

        return inc
