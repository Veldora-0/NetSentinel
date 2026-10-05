"""NetSentinel Database Module.

Establishes SQLite configuration, SQLAlchemy database instance, and
persistence models for security events, risk assessments, firewall actions,
and host system telemetry records.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional
import uuid
from flask_sqlalchemy import SQLAlchemy

logger = logging.getLogger("netsentinel.database")

db = SQLAlchemy()


class SecurityEventRecord(db.Model):
    """SQLAlchemy model for persistent rule-based and anomaly security events."""
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    timestamp = db.Column(db.Float, nullable=False, index=True)
    detection_type = db.Column(db.String(50), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)
    source_ip = db.Column(db.String(64), nullable=True, index=True)
    destination_ip = db.Column(db.String(64), nullable=True)
    protocol = db.Column(db.String(20), nullable=True)
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    description = db.Column(db.String(255), nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    rule_name = db.Column(db.String(50), nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        """Convert database record to dictionary."""
        ev_dict = {}
        if self.evidence:
            try:
                ev_dict = json.loads(self.evidence)
            except Exception:
                ev_dict = {"raw": self.evidence}

        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "detection_type": self.detection_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "description": self.description,
            "evidence": ev_dict,
            "rule_name": self.rule_name,
        }


class RiskAssessmentRecord(db.Model):
    """SQLAlchemy model for persistent security risk assessments."""
    __tablename__ = "risk_assessments"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    timestamp = db.Column(db.Float, nullable=False, index=True)
    source_ip = db.Column(db.String(64), nullable=False, index=True)
    destination_ip = db.Column(db.String(64), nullable=True)
    rule_score = db.Column(db.Float, nullable=False)
    ml_anomaly_score = db.Column(db.Float, nullable=False)
    combined_score = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False, index=True)
    recommended_action = db.Column(db.String(20), nullable=False)
    actual_action = db.Column(db.String(20), nullable=False, default="NONE")
    blocked = db.Column(db.Boolean, default=False)
    block_expires_at = db.Column(db.Float, nullable=True)
    reason = db.Column(db.String(255), nullable=True)
    detection_types = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.Text, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        """Convert database record to JSON-serializable dictionary."""
        return {
            "assessment_id": self.assessment_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "rule_score": self.rule_score,
            "ml_anomaly_score": self.ml_anomaly_score,
            "combined_score": self.combined_score,
            "risk_level": self.risk_level,
            "recommended_action": self.recommended_action,
            "actual_action": self.actual_action,
            "blocked": self.blocked,
            "block_expires_at": self.block_expires_at,
            "reason": self.reason,
            "detection_types": json.loads(self.detection_types) if self.detection_types else [],
        }


class FirewallActionRecord(db.Model):
    """SQLAlchemy model for persistent firewall mitigation block/unblock actions."""
    __tablename__ = "firewall_actions"

    id = db.Column(db.Integer, primary_key=True)
    action_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    timestamp = db.Column(db.Float, nullable=False, index=True)
    action = db.Column(db.String(20), nullable=False, index=True)  # "block" or "unblock"
    source_ip = db.Column(db.String(64), nullable=False, index=True)
    success = db.Column(db.Boolean, default=True)
    reason = db.Column(db.String(255), nullable=True)
    risk_score = db.Column(db.Float, nullable=True)
    assessment_id = db.Column(db.String(64), nullable=True)
    expires_at = db.Column(db.Float, nullable=True)
    error_message = db.Column(db.String(255), nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        """Convert database record to dictionary."""
        return {
            "action_id": self.action_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "source_ip": self.source_ip,
            "success": self.success,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "assessment_id": self.assessment_id,
            "expires_at": self.expires_at,
            "error_message": self.error_message,
        }


class HostTelemetryRecord(db.Model):
    """SQLAlchemy model for persistent host system telemetry metrics."""
    __tablename__ = "host_telemetry"

    id = db.Column(db.Integer, primary_key=True)
    telemetry_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    timestamp = db.Column(db.Float, nullable=False, index=True)
    cpu_percent = db.Column(db.Float, nullable=False)
    memory_percent = db.Column(db.Float, nullable=False)
    memory_used_bytes = db.Column(db.BigInteger, nullable=False)
    memory_available_bytes = db.Column(db.BigInteger, nullable=False)
    disk_percent = db.Column(db.Float, nullable=False)
    disk_used_bytes = db.Column(db.BigInteger, nullable=False)
    disk_free_bytes = db.Column(db.BigInteger, nullable=False)
    load_1 = db.Column(db.Float, nullable=True)
    load_5 = db.Column(db.Float, nullable=True)
    load_15 = db.Column(db.Float, nullable=True)
    network_bytes_sent = db.Column(db.BigInteger, nullable=False)
    network_bytes_recv = db.Column(db.BigInteger, nullable=False)
    network_packets_sent = db.Column(db.BigInteger, nullable=False)
    network_packets_recv = db.Column(db.BigInteger, nullable=False)
    host_tx_bps = db.Column(db.Float, default=0.0)
    host_rx_bps = db.Column(db.Float, default=0.0)
    host_tx_pps = db.Column(db.Float, default=0.0)
    host_rx_pps = db.Column(db.Float, default=0.0)

    def to_dict(self) -> Dict[str, Any]:
        """Convert database record to dictionary."""
        return {
            "telemetry_id": self.telemetry_id,
            "timestamp": self.timestamp,
            "cpu_percent": round(self.cpu_percent, 2),
            "memory_percent": round(self.memory_percent, 2),
            "memory_used_bytes": self.memory_used_bytes,
            "memory_available_bytes": self.memory_available_bytes,
            "disk_percent": round(self.disk_percent, 2),
            "disk_used_bytes": self.disk_used_bytes,
            "disk_free_bytes": self.disk_free_bytes,
            "load_1": round(self.load_1, 2) if self.load_1 is not None else None,
            "load_5": round(self.load_5, 2) if self.load_5 is not None else None,
            "load_15": round(self.load_15, 2) if self.load_15 is not None else None,
            "network_bytes_sent": self.network_bytes_sent,
            "network_bytes_recv": self.network_bytes_recv,
            "network_packets_sent": self.network_packets_sent,
            "network_packets_recv": self.network_packets_recv,
            "host_tx_bps": round(self.host_tx_bps, 2),
            "host_rx_bps": round(self.host_rx_bps, 2),
            "host_tx_pps": round(self.host_tx_pps, 2),
            "host_rx_pps": round(self.host_rx_pps, 2),
        }


class IncidentRecord(db.Model):
    """SQLAlchemy model for aggregated security incidents."""
    __tablename__ = "incidents"

    incident_id = db.Column(db.String(64), primary_key=True, index=True)
    created_at = db.Column(db.Float, nullable=False, index=True)
    updated_at = db.Column(db.Float, nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="OPEN", index=True)  # OPEN, ACKNOWLEDGED, RESOLVED, CLOSED
    severity = db.Column(db.String(20), nullable=False, default="LOW", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = db.Column(db.Float, nullable=False, default=0.0)
    title = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.Text, nullable=True)
    primary_source_ip = db.Column(db.String(64), nullable=True, index=True)
    correlation_key = db.Column(db.String(128), nullable=False, index=True)
    attack_domains = db.Column(db.Text, nullable=True)  # JSON list e.g. ["network", "host"]
    detection_types = db.Column(db.Text, nullable=True)  # JSON list e.g. ["PORT_SCAN", "SSH_BRUTE_FORCE"]
    event_count = db.Column(db.Integer, nullable=False, default=0)
    risk_assessment_count = db.Column(db.Integer, nullable=False, default=0)
    firewall_action_count = db.Column(db.Integer, nullable=False, default=0)
    first_seen = db.Column(db.Float, nullable=False, index=True)
    last_seen = db.Column(db.Float, nullable=False, index=True)
    closed_at = db.Column(db.Float, nullable=True)
    resolution = db.Column(db.String(255), nullable=True)
    analyst_note = db.Column(db.Text, nullable=True)
    correlation_reason = db.Column(db.Text, nullable=True)

    evidence_records = db.relationship(
        "IncidentEvidenceRecord",
        backref="incident",
        lazy="dynamic",
        cascade="all, delete-orphan",
        order_by="IncidentEvidenceRecord.timestamp.asc()",
    )

    def to_dict(self, include_evidence: bool = False) -> Dict[str, Any]:
        """Convert incident record to JSON-serializable dictionary."""
        d = {
            "incident_id": self.incident_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "severity": self.severity,
            "risk_score": round(self.risk_score, 4),
            "title": self.title,
            "summary": self.summary or "",
            "primary_source_ip": self.primary_source_ip,
            "correlation_key": self.correlation_key,
            "attack_domains": json.loads(self.attack_domains) if self.attack_domains else [],
            "detection_types": json.loads(self.detection_types) if self.detection_types else [],
            "event_count": self.event_count,
            "risk_assessment_count": self.risk_assessment_count,
            "firewall_action_count": self.firewall_action_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "closed_at": self.closed_at,
            "resolution": self.resolution,
            "analyst_note": self.analyst_note,
            "correlation_reason": self.correlation_reason or "",
        }
        if include_evidence:
            d["evidence"] = [e.to_dict() for e in self.evidence_records.all()]
        return d


class IncidentEvidenceRecord(db.Model):
    """SQLAlchemy model for linking security artifacts to an incident."""
    __tablename__ = "incident_evidence"

    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    incident_id = db.Column(
        db.String(64),
        db.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_type = db.Column(db.String(32), nullable=False, index=True)  # SECURITY_EVENT, RISK_ASSESSMENT, FIREWALL_ACTION
    reference_id = db.Column(db.String(64), nullable=False, index=True)
    timestamp = db.Column(db.Float, nullable=False, index=True)
    source_ip = db.Column(db.String(64), nullable=True)
    detection_type = db.Column(db.String(50), nullable=True)
    severity = db.Column(db.String(20), nullable=True)
    risk_score = db.Column(db.Float, nullable=True)
    summary = db.Column(db.String(255), nullable=False)
    metadata_json = db.Column(db.Text, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence record to dictionary."""
        meta = {}
        if self.metadata_json:
            try:
                meta = json.loads(self.metadata_json)
            except Exception:
                meta = {"raw": self.metadata_json}
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
            "metadata": meta,
        }


class FileIntegrityBaselineRecord(db.Model):
    """SQLAlchemy model for persistent File Integrity Monitoring baseline records."""
    __tablename__ = "fim_baseline"

    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(512), unique=True, nullable=False, index=True)
    file_type = db.Column(db.String(32), default="regular", nullable=False)
    sha256 = db.Column(db.String(64), nullable=True)
    size = db.Column(db.BigInteger, nullable=True)
    mode = db.Column(db.String(10), nullable=True)
    uid = db.Column(db.Integer, nullable=True)
    gid = db.Column(db.Integer, nullable=True)
    inode = db.Column(db.BigInteger, nullable=True)
    mtime = db.Column(db.Float, nullable=True)
    first_seen = db.Column(db.Float, nullable=False)
    last_verified = db.Column(db.Float, nullable=False, index=True)
    status = db.Column(db.String(32), default="BASELINE", nullable=False, index=True)

    def to_dict(self) -> Dict[str, Any]:
        """Convert baseline record to dictionary."""
        return {
            "id": self.id,
            "path": self.path,
            "file_type": self.file_type,
            "sha256": self.sha256,
            "size": self.size,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "inode": self.inode,
            "mtime": self.mtime,
            "first_seen": self.first_seen,
            "last_verified": self.last_verified,
            "status": self.status,
        }


# ==============================================================================
# Persistence Helper Functions
# ==============================================================================


def save_security_event_record(event: Any) -> bool:
    """Persist a SecurityEvent or MLAnomalyEvent to the database safely."""
    try:
        if isinstance(event, dict):
            event_id = event.get("event_id") or str(uuid.uuid4())
            ts = float(event.get("timestamp", time.time()))
            det_type = str(event.get("detection_type", "UNKNOWN"))
            sev = str(event.get("severity", "LOW"))
            raw_src = event.get("source_ip")
            src_ip = str(raw_src).strip() if (raw_src is not None and str(raw_src).strip()) else "127.0.0.1"
            dst_ip = event.get("destination_ip")
            raw_proto = event.get("protocol")
            proto = str(raw_proto) if (raw_proto is not None and str(raw_proto).strip()) else None
            src_p = event.get("source_port")
            dst_p = event.get("destination_port")
            desc = event.get("description", "")
            evidence_data = event.get("evidence", {})
            rule_name = event.get("rule_name")
        else:
            event_id = getattr(event, "event_id", str(uuid.uuid4()))
            ts = float(getattr(event, "timestamp", time.time()))
            det_type = str(getattr(event, "detection_type", "UNKNOWN"))
            sev = str(getattr(event, "severity", "LOW"))
            raw_src = getattr(event, "source_ip", None)
            src_ip = str(raw_src).strip() if (raw_src is not None and str(raw_src).strip()) else "127.0.0.1"
            dst_ip = getattr(event, "destination_ip", None)
            raw_proto = getattr(event, "protocol", None)
            proto = str(raw_proto) if (raw_proto is not None and str(raw_proto).strip()) else None
            src_p = getattr(event, "source_port", None)
            dst_p = getattr(event, "destination_port", None)
            desc = getattr(event, "description", "")
            evidence_data = getattr(event, "evidence", {})
            rule_name = getattr(event, "rule_name", None)

        record = SecurityEventRecord(
            event_id=event_id,
            timestamp=ts,
            detection_type=det_type,
            severity=sev,
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol=proto,
            source_port=src_p,
            destination_port=dst_p,
            description=desc[:255] if desc else "",
            evidence=json.dumps(evidence_data) if isinstance(evidence_data, (dict, list)) else str(evidence_data),
            rule_name=rule_name,
        )
        db.session.add(record)
        db.session.commit()
        return True
    except Exception as ex:
        db.session.rollback()
        logger.debug("Database security event save failed: %s", ex)
        return False


def save_assessment_record(
    assessment: Any, actual_action: str = "NONE", block_expires_at: Optional[float] = None
) -> bool:
    """Persist a RiskAssessment to SQLite database safely."""
    try:
        record = RiskAssessmentRecord(
            assessment_id=assessment.assessment_id,
            timestamp=assessment.timestamp,
            source_ip=assessment.source_ip,
            destination_ip=assessment.destination_ip,
            rule_score=assessment.rule_score,
            ml_anomaly_score=assessment.ml_anomaly_score,
            combined_score=assessment.combined_score,
            risk_level=assessment.risk_level,
            recommended_action=assessment.recommended_action,
            actual_action=actual_action,
            blocked=assessment.blocked,
            block_expires_at=block_expires_at,
            reason=(assessment.reason[:255] if assessment.reason else ""),
            detection_types=json.dumps(getattr(assessment, "detection_types", [])),
            evidence=json.dumps(getattr(assessment, "evidence", {})),
        )
        db.session.add(record)
        db.session.commit()
        return True
    except Exception as ex:
        db.session.rollback()
        logger.debug("Database assessment save failed: %s", ex)
        return False


def save_firewall_action_record(
    action: str,
    source_ip: str,
    success: bool = True,
    reason: str = "",
    risk_score: Optional[float] = None,
    assessment_id: Optional[str] = None,
    expires_at: Optional[float] = None,
    error_message: Optional[str] = None,
    timestamp: Optional[float] = None,
) -> bool:
    """Persist a firewall action (block/unblock) to the database safely."""
    try:
        record = FirewallActionRecord(
            action_id=str(uuid.uuid4()),
            timestamp=timestamp if timestamp is not None else time.time(),
            action=action,
            source_ip=source_ip,
            success=success,
            reason=reason[:255] if reason else "",
            risk_score=risk_score,
            assessment_id=assessment_id,
            expires_at=expires_at,
            error_message=error_message[:255] if error_message else None,
        )
        db.session.add(record)
        db.session.commit()
        return True
    except Exception as ex:
        db.session.rollback()
        logger.debug("Database firewall action save failed: %s", ex)
        return False


def save_host_telemetry_record(telemetry_data: Dict[str, Any]) -> bool:
    """Persist a host telemetry snapshot to SQLite safely."""
    try:
        record = HostTelemetryRecord(
            telemetry_id=telemetry_data.get("telemetry_id") or str(uuid.uuid4()),
            timestamp=telemetry_data.get("timestamp", time.time()),
            cpu_percent=float(telemetry_data.get("cpu_percent", 0.0)),
            memory_percent=float(telemetry_data.get("memory_percent", 0.0)),
            memory_used_bytes=int(telemetry_data.get("memory_used_bytes", 0)),
            memory_available_bytes=int(telemetry_data.get("memory_available_bytes", 0)),
            disk_percent=float(telemetry_data.get("disk_percent", 0.0)),
            disk_used_bytes=int(telemetry_data.get("disk_used_bytes", 0)),
            disk_free_bytes=int(telemetry_data.get("disk_free_bytes", 0)),
            load_1=telemetry_data.get("load_1"),
            load_5=telemetry_data.get("load_5"),
            load_15=telemetry_data.get("load_15"),
            network_bytes_sent=int(telemetry_data.get("network_bytes_sent", 0)),
            network_bytes_recv=int(telemetry_data.get("network_bytes_recv", 0)),
            network_packets_sent=int(telemetry_data.get("network_packets_sent", 0)),
            network_packets_recv=int(telemetry_data.get("network_packets_recv", 0)),
            host_tx_bps=float(telemetry_data.get("host_tx_bps", 0.0)),
            host_rx_bps=float(telemetry_data.get("host_rx_bps", 0.0)),
            host_tx_pps=float(telemetry_data.get("host_tx_pps", 0.0)),
            host_rx_pps=float(telemetry_data.get("host_rx_pps", 0.0)),
        )
        db.session.add(record)
        db.session.commit()
        return True
    except Exception as ex:
        db.session.rollback()
        logger.debug("Database host telemetry save failed: %s", ex)
        return False


def save_incident_record(incident: Any) -> bool:
    """Persist or update an IncidentRecord in SQLite safely."""
    try:
        if isinstance(incident, dict):
            inc_id = incident.get("incident_id") or str(uuid.uuid4())
            created_at = float(incident.get("created_at", time.time()))
            updated_at = float(incident.get("updated_at", time.time()))
            status = str(incident.get("status", "OPEN"))
            severity = str(incident.get("severity", "LOW"))
            risk_score = float(incident.get("risk_score", 0.0))
            title = str(incident.get("title", f"Incident {inc_id}"))
            summary = str(incident.get("summary", ""))
            primary_source_ip = incident.get("primary_source_ip")
            correlation_key = str(incident.get("correlation_key", primary_source_ip or inc_id))
            attack_domains = incident.get("attack_domains", [])
            if isinstance(attack_domains, (list, set)):
                attack_domains_json = json.dumps(list(attack_domains))
            else:
                attack_domains_json = str(attack_domains)
            detection_types = incident.get("detection_types", [])
            if isinstance(detection_types, (list, set)):
                detection_types_json = json.dumps(list(detection_types))
            else:
                detection_types_json = str(detection_types)
            event_count = int(incident.get("event_count", 0))
            risk_assessment_count = int(incident.get("risk_assessment_count", 0))
            firewall_action_count = int(incident.get("firewall_action_count", 0))
            first_seen = float(incident.get("first_seen", created_at))
            last_seen = float(incident.get("last_seen", updated_at))
            closed_at = incident.get("closed_at")
            closed_at_val = float(closed_at) if closed_at is not None else None
            resolution = incident.get("resolution")
            analyst_note = incident.get("analyst_note")
            correlation_reason = incident.get("correlation_reason")
        else:
            inc_id = getattr(incident, "incident_id", str(uuid.uuid4()))
            created_at = float(getattr(incident, "created_at", time.time()))
            updated_at = float(getattr(incident, "updated_at", time.time()))
            status = str(getattr(incident, "status", "OPEN"))
            severity = str(getattr(incident, "severity", "LOW"))
            risk_score = float(getattr(incident, "risk_score", 0.0))
            title = str(getattr(incident, "title", f"Incident {inc_id}"))
            summary = str(getattr(incident, "summary", ""))
            primary_source_ip = getattr(incident, "primary_source_ip", None)
            correlation_key = str(getattr(incident, "correlation_key", primary_source_ip or inc_id))
            ad = getattr(incident, "attack_domains", [])
            attack_domains_json = json.dumps(list(ad)) if isinstance(ad, (list, set)) else str(ad)
            dt = getattr(incident, "detection_types", [])
            detection_types_json = json.dumps(list(dt)) if isinstance(dt, (list, set)) else str(dt)
            event_count = int(getattr(incident, "event_count", 0))
            risk_assessment_count = int(getattr(incident, "risk_assessment_count", 0))
            firewall_action_count = int(getattr(incident, "firewall_action_count", 0))
            first_seen = float(getattr(incident, "first_seen", created_at))
            last_seen = float(getattr(incident, "last_seen", updated_at))
            cl = getattr(incident, "closed_at", None)
            closed_at_val = float(cl) if cl is not None else None
            resolution = getattr(incident, "resolution", None)
            analyst_note = getattr(incident, "analyst_note", None)
            correlation_reason = getattr(incident, "correlation_reason", None)

        existing = IncidentRecord.query.filter_by(incident_id=inc_id).first()
        if existing:
            existing.updated_at = updated_at
            existing.status = status
            existing.severity = severity
            existing.risk_score = risk_score
            existing.title = title
            existing.summary = summary
            existing.primary_source_ip = primary_source_ip
            existing.correlation_key = correlation_key
            existing.attack_domains = attack_domains_json
            existing.detection_types = detection_types_json
            existing.event_count = event_count
            existing.risk_assessment_count = risk_assessment_count
            existing.firewall_action_count = firewall_action_count
            existing.first_seen = first_seen
            existing.last_seen = last_seen
            existing.closed_at = closed_at_val
            existing.resolution = resolution
            existing.analyst_note = analyst_note
            existing.correlation_reason = correlation_reason
        else:
            rec = IncidentRecord(
                incident_id=inc_id,
                created_at=created_at,
                updated_at=updated_at,
                status=status,
                severity=severity,
                risk_score=risk_score,
                title=title,
                summary=summary,
                primary_source_ip=primary_source_ip,
                correlation_key=correlation_key,
                attack_domains=attack_domains_json,
                detection_types=detection_types_json,
                event_count=event_count,
                risk_assessment_count=risk_assessment_count,
                firewall_action_count=firewall_action_count,
                first_seen=first_seen,
                last_seen=last_seen,
                closed_at=closed_at_val,
                resolution=resolution,
                analyst_note=analyst_note,
                correlation_reason=correlation_reason,
            )
            db.session.add(rec)

        db.session.commit()
        return True
    except Exception as ex:
        db.session.rollback()
        logger.debug("Database incident save failed: %s", ex)
        return False


def save_incident_evidence_record(evidence: Any) -> bool:
    """Persist an IncidentEvidenceRecord in SQLite safely."""
    try:
        if isinstance(evidence, dict):
            ev_id = evidence.get("evidence_id") or str(uuid.uuid4())
            inc_id = str(evidence.get("incident_id"))
            ev_type = str(evidence.get("evidence_type", "SECURITY_EVENT"))
            ref_id = str(evidence.get("reference_id", ev_id))
            ts = float(evidence.get("timestamp", time.time()))
            src_ip = evidence.get("source_ip")
            det_type = evidence.get("detection_type")
            sev = evidence.get("severity")
            risk_s = evidence.get("risk_score")
            risk_val = float(risk_s) if risk_s is not None else None
            summary = str(evidence.get("summary", ""))
            meta = evidence.get("metadata", {})
            meta_json = json.dumps(meta) if isinstance(meta, dict) else str(meta)
        else:
            ev_id = getattr(evidence, "evidence_id", str(uuid.uuid4()))
            inc_id = str(getattr(evidence, "incident_id"))
            ev_type = str(getattr(evidence, "evidence_type", "SECURITY_EVENT"))
            ref_id = str(getattr(evidence, "reference_id", ev_id))
            ts = float(getattr(evidence, "timestamp", time.time()))
            src_ip = getattr(evidence, "source_ip", None)
            det_type = getattr(evidence, "detection_type", None)
            sev = getattr(evidence, "severity", None)
            risk_s = getattr(evidence, "risk_score", None)
            risk_val = float(risk_s) if risk_s is not None else None
            summary = str(getattr(evidence, "summary", ""))
            meta = getattr(evidence, "metadata", {})
            meta_json = json.dumps(meta) if isinstance(meta, dict) else str(meta)

        existing = IncidentEvidenceRecord.query.filter_by(evidence_id=ev_id).first()
        if existing:
            existing.summary = summary
            existing.metadata_json = meta_json
        else:
            rec = IncidentEvidenceRecord(
                evidence_id=ev_id,
                incident_id=inc_id,
                evidence_type=ev_type,
                reference_id=ref_id,
                timestamp=ts,
                source_ip=src_ip,
                detection_type=det_type,
                severity=sev,
                risk_score=risk_val,
                summary=summary,
                metadata_json=meta_json,
            )
            db.session.add(rec)

        db.session.commit()
        return True
    except Exception as ex:
        db.session.rollback()
        logger.debug("Database incident evidence save failed: %s", ex)
        return False



# ==============================================================================
# Historical Query Functions
# ==============================================================================

def query_security_events(
    limit: int = 50,
    offset: int = 0,
    since: Optional[float] = None,
    until: Optional[float] = None,
    source_ip: Optional[str] = None,
    detection_type: Optional[str] = None,
    severity: Optional[str] = None,
) -> Dict[str, Any]:
    """Query persisted security events with filtering and pagination."""
    try:
        limit = max(1, min(limit, 500))
        offset = max(0, offset)

        query = SecurityEventRecord.query

        if since is not None:
            query = query.filter(SecurityEventRecord.timestamp >= since)
        if until is not None:
            query = query.filter(SecurityEventRecord.timestamp <= until)
        if source_ip and source_ip.strip():
            query = query.filter(SecurityEventRecord.source_ip == source_ip.strip())
        if detection_type and detection_type.strip():
            query = query.filter(SecurityEventRecord.detection_type == detection_type.strip().upper())
        if severity and severity.strip():
            query = query.filter(SecurityEventRecord.severity == severity.strip().upper())

        total = query.count()
        records = query.order_by(SecurityEventRecord.timestamp.desc()).offset(offset).limit(limit).all()

        return {
            "total": total,
            "count": len(records),
            "limit": limit,
            "offset": offset,
            "events": [r.to_dict() for r in records],
        }
    except Exception as ex:
        logger.debug("Database security events query failed: %s", ex)
        return {"total": 0, "count": 0, "limit": limit, "offset": offset, "events": []}


def query_risk_history(
    limit: int = 50,
    offset: int = 0,
    since: Optional[float] = None,
    until: Optional[float] = None,
    source_ip: Optional[str] = None,
    risk_level: Optional[str] = None,
) -> Dict[str, Any]:
    """Query persisted risk assessments with filtering and pagination."""
    try:
        limit = max(1, min(limit, 500))
        offset = max(0, offset)

        query = RiskAssessmentRecord.query

        if since is not None:
            query = query.filter(RiskAssessmentRecord.timestamp >= since)
        if until is not None:
            query = query.filter(RiskAssessmentRecord.timestamp <= until)
        if source_ip and source_ip.strip():
            query = query.filter(RiskAssessmentRecord.source_ip == source_ip.strip())
        if risk_level and risk_level.strip():
            query = query.filter(RiskAssessmentRecord.risk_level == risk_level.strip().upper())

        total = query.count()
        records = query.order_by(RiskAssessmentRecord.timestamp.desc()).offset(offset).limit(limit).all()

        return {
            "total": total,
            "count": len(records),
            "limit": limit,
            "offset": offset,
            "assessments": [r.to_dict() for r in records],
        }
    except Exception as ex:
        logger.debug("Database risk history query failed: %s", ex)
        return {"total": 0, "count": 0, "limit": limit, "offset": offset, "assessments": []}


def get_incident_by_id(incident_id: str, include_evidence: bool = True) -> Optional[Dict[str, Any]]:
    """Retrieve an incident by its ID, optionally including associated evidence."""
    try:
        record = IncidentRecord.query.filter_by(incident_id=incident_id).first()
        if not record:
            return None
        return record.to_dict(include_evidence=include_evidence)
    except Exception as ex:
        logger.debug("Database get incident by ID failed: %s", ex)
        return None


def query_incidents(
    limit: int = 50,
    offset: int = 0,
    since: Optional[float] = None,
    until: Optional[float] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    primary_source_ip: Optional[str] = None,
    correlation_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Query persisted incidents with filtering and pagination."""
    try:
        limit = max(1, min(limit, 500))
        offset = max(0, offset)

        query = IncidentRecord.query

        if since is not None:
            query = query.filter(IncidentRecord.updated_at >= since)
        if until is not None:
            query = query.filter(IncidentRecord.updated_at <= until)
        if status and status.strip():
            query = query.filter(IncidentRecord.status == status.strip().upper())
        if severity and severity.strip():
            query = query.filter(IncidentRecord.severity == severity.strip().upper())
        if primary_source_ip and primary_source_ip.strip():
            query = query.filter(IncidentRecord.primary_source_ip == primary_source_ip.strip())
        if correlation_key and correlation_key.strip():
            query = query.filter(IncidentRecord.correlation_key == correlation_key.strip())

        total = query.count()
        records = query.order_by(IncidentRecord.updated_at.desc()).offset(offset).limit(limit).all()

        return {
            "total": total,
            "count": len(records),
            "limit": limit,
            "offset": offset,
            "incidents": [r.to_dict(include_evidence=False) for r in records],
        }
    except Exception as ex:
        logger.debug("Database incidents query failed: %s", ex)
        return {"total": 0, "count": 0, "limit": limit, "offset": offset, "incidents": []}


def query_incident_stats(since_timestamp: Optional[float] = None) -> Dict[str, Any]:
    """Query high-level incident metrics and distribution."""
    try:
        query = IncidentRecord.query
        if since_timestamp is not None:
            query = query.filter(IncidentRecord.created_at >= since_timestamp)

        total_incidents = query.count()
        open_count = query.filter(IncidentRecord.status == "OPEN").count()
        acknowledged_count = query.filter(IncidentRecord.status == "ACKNOWLEDGED").count()
        resolved_count = query.filter(IncidentRecord.status == "RESOLVED").count()
        closed_count = query.filter(IncidentRecord.status == "CLOSED").count()

        # Severity breakdown
        sev_query = db.session.query(IncidentRecord.severity, db.func.count(IncidentRecord.incident_id))
        if since_timestamp is not None:
            sev_query = sev_query.filter(IncidentRecord.created_at >= since_timestamp)
        severities = dict(sev_query.group_by(IncidentRecord.severity).all())

        # Top sources
        top_sources_query = (
            db.session.query(IncidentRecord.primary_source_ip, db.func.count(IncidentRecord.incident_id))
            .filter(IncidentRecord.primary_source_ip.isnot(None))
        )
        if since_timestamp is not None:
            top_sources_query = top_sources_query.filter(IncidentRecord.created_at >= since_timestamp)
        top_sources = [
            {"source_ip": ip, "count": count}
            for ip, count in top_sources_query.group_by(IncidentRecord.primary_source_ip)
            .order_by(db.func.count(IncidentRecord.incident_id).desc())
            .limit(5)
            .all()
        ]

        return {
            "total_incidents": total_incidents,
            "open": open_count,
            "acknowledged": acknowledged_count,
            "resolved": resolved_count,
            "closed": closed_count,
            "severities": severities,
            "top_sources": top_sources,
        }
    except Exception as ex:
        logger.debug("Database incident stats query failed: %s", ex)
        return {
            "total_incidents": 0,
            "open": 0,
            "acknowledged": 0,
            "resolved": 0,
            "closed": 0,
            "severities": {},
            "top_sources": [],
        }


def query_security_summary(since_timestamp: Optional[float] = None) -> Dict[str, Any]:
    """Generate aggregate statistics across security events, risks, firewall actions, and incidents."""
    try:
        ev_query = SecurityEventRecord.query
        risk_query = RiskAssessmentRecord.query
        fw_query = FirewallActionRecord.query
        inc_query = IncidentRecord.query

        if since_timestamp is not None:
            ev_query = ev_query.filter(SecurityEventRecord.timestamp >= since_timestamp)
            risk_query = risk_query.filter(RiskAssessmentRecord.timestamp >= since_timestamp)
            fw_query = fw_query.filter(FirewallActionRecord.timestamp >= since_timestamp)
            inc_query = inc_query.filter(IncidentRecord.created_at >= since_timestamp)

        total_events = ev_query.count()
        total_assessments = risk_query.count()
        total_firewall_actions = fw_query.count()
        incidents_total = inc_query.count()
        incidents_open = inc_query.filter(IncidentRecord.status.in_(["OPEN", "ACKNOWLEDGED"])).count()
        incidents_critical = inc_query.filter(IncidentRecord.severity == "CRITICAL").count()
        incidents_resolved = inc_query.filter(IncidentRecord.status.in_(["RESOLVED", "CLOSED"])).count()

        # Breakdown by detection type
        type_counts_query = (
            db.session.query(SecurityEventRecord.detection_type, db.func.count(SecurityEventRecord.id))
        )
        if since_timestamp is not None:
            type_counts_query = type_counts_query.filter(SecurityEventRecord.timestamp >= since_timestamp)
        detection_types = dict(type_counts_query.group_by(SecurityEventRecord.detection_type).all())

        # Breakdown by severity
        sev_counts_query = (
            db.session.query(SecurityEventRecord.severity, db.func.count(SecurityEventRecord.id))
        )
        if since_timestamp is not None:
            sev_counts_query = sev_counts_query.filter(SecurityEventRecord.timestamp >= since_timestamp)
        severities = dict(sev_counts_query.group_by(SecurityEventRecord.severity).all())

        # Top 5 source IPs by event count
        top_ips_query = (
            db.session.query(SecurityEventRecord.source_ip, db.func.count(SecurityEventRecord.id))
        )
        if since_timestamp is not None:
            top_ips_query = top_ips_query.filter(SecurityEventRecord.timestamp >= since_timestamp)
        top_ips = [
            {"source_ip": ip, "count": count}
            for ip, count in top_ips_query.group_by(SecurityEventRecord.source_ip)
            .order_by(db.func.count(SecurityEventRecord.id).desc())
            .limit(5)
            .all()
        ]

        # Top 5 source IPs by incident count
        top_inc_sources_query = (
            db.session.query(IncidentRecord.primary_source_ip, db.func.count(IncidentRecord.incident_id))
            .filter(IncidentRecord.primary_source_ip.isnot(None))
        )
        if since_timestamp is not None:
            top_inc_sources_query = top_inc_sources_query.filter(IncidentRecord.created_at >= since_timestamp)
        top_inc_sources = [
            {"source_ip": ip, "count": count}
            for ip, count in top_inc_sources_query.group_by(IncidentRecord.primary_source_ip)
            .order_by(db.func.count(IncidentRecord.incident_id).desc())
            .limit(5)
            .all()
        ]

        # Risk score stats
        risk_stats_query = db.session.query(
            db.func.max(RiskAssessmentRecord.combined_score),
            db.func.avg(RiskAssessmentRecord.combined_score),
        )
        if since_timestamp is not None:
            risk_stats_query = risk_stats_query.filter(RiskAssessmentRecord.timestamp >= since_timestamp)
        max_score, avg_score = risk_stats_query.first() or (0.0, 0.0)

        # Firewall action breakdown
        fw_action_counts = dict(
            db.session.query(FirewallActionRecord.action, db.func.count(FirewallActionRecord.id))
            .group_by(FirewallActionRecord.action)
            .all()
        )

        return {
            "total_events": total_events,
            "total_assessments": total_assessments,
            "total_firewall_actions": total_firewall_actions,
            "incidents_total": incidents_total,
            "incidents_open": incidents_open,
            "incidents_critical": incidents_critical,
            "incidents_resolved": incidents_resolved,
            "detection_types": detection_types,
            "severities": severities,
            "top_source_ips": top_ips,
            "top_incident_sources": top_inc_sources,
            "highest_risk_score": round(float(max_score or 0.0), 4),
            "average_risk_score": round(float(avg_score or 0.0), 4),
            "firewall_actions": fw_action_counts,
        }
    except Exception as ex:
        logger.debug("Database summary query failed: %s", ex)
        return {
            "total_events": 0,
            "total_assessments": 0,
            "total_firewall_actions": 0,
            "incidents_total": 0,
            "incidents_open": 0,
            "incidents_critical": 0,
            "incidents_resolved": 0,
            "detection_types": {},
            "severities": {},
            "top_source_ips": [],
            "top_incident_sources": [],
            "highest_risk_score": 0.0,
            "average_risk_score": 0.0,
            "firewall_actions": {},
        }


def query_telemetry_history(
    limit: int = 60, since: Optional[float] = None, until: Optional[float] = None
) -> Dict[str, Any]:
    """Retrieve bounded historical host telemetry records ordered chronologically."""
    try:
        limit = max(1, min(limit, 500))
        query = HostTelemetryRecord.query

        if since is not None:
            query = query.filter(HostTelemetryRecord.timestamp >= since)
        if until is not None:
            query = query.filter(HostTelemetryRecord.timestamp <= until)

        records = query.order_by(HostTelemetryRecord.timestamp.desc()).limit(limit).all()
        # Return in ascending chronological order for straightforward frontend chart consumption
        ordered = list(reversed(records))

        return {
            "count": len(ordered),
            "telemetry": [r.to_dict() for r in ordered],
        }
    except Exception as ex:
        logger.debug("Database telemetry history query failed: %s", ex)
        return {"count": 0, "telemetry": []}


# ==============================================================================
# File Integrity Monitoring (FIM) Helper Functions (Phase 10)
# ==============================================================================

def save_fim_baseline_record(record_data: Any, meta: Optional[Dict[str, Any]] = None) -> bool:
    """Insert or update a File Integrity Monitoring baseline record."""
    try:
        if meta is not None and isinstance(record_data, str):
            data = dict(meta)
            data["path"] = record_data
        elif isinstance(record_data, dict):
            data = record_data
        else:
            return False

        path = data.get("path")
        if not path:
            return False

        rec = FileIntegrityBaselineRecord.query.filter_by(path=path).first()
        now = time.time()
        if not rec:
            rec = FileIntegrityBaselineRecord(
                path=path,
                file_type=data.get("file_type", "regular"),
                sha256=data.get("sha256"),
                size=data.get("size"),
                mode=data.get("mode"),
                uid=data.get("uid"),
                gid=data.get("gid"),
                inode=data.get("inode"),
                mtime=data.get("mtime"),
                first_seen=data.get("first_seen", now),
                last_verified=data.get("last_verified", now),
                status=data.get("status", "BASELINE"),
            )
            db.session.add(rec)
        else:
            rec.file_type = data.get("file_type", rec.file_type)
            rec.sha256 = data.get("sha256", rec.sha256)
            rec.size = data.get("size", rec.size)
            rec.mode = data.get("mode", rec.mode)
            rec.uid = data.get("uid", rec.uid)
            rec.gid = data.get("gid", rec.gid)
            rec.inode = data.get("inode", rec.inode)
            rec.mtime = data.get("mtime", rec.mtime)
            rec.last_verified = data.get("last_verified", now)
            rec.status = data.get("status", rec.status)

        db.session.commit()
        return True
    except Exception as ex:
        db.session.rollback()
        logger.debug("Database FIM baseline save failed for %s: %s", path if 'path' in locals() else None, ex)
        return False



def get_fim_baseline_record(path: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single FIM baseline record by normalized file path."""
    try:
        rec = FileIntegrityBaselineRecord.query.filter_by(path=path).first()
        return rec.to_dict() if rec else None
    except Exception as ex:
        logger.debug("Database FIM record lookup failed: %s", ex)
        return None


def get_all_fim_baseline_records() -> Dict[str, Dict[str, Any]]:
    """Retrieve all persisted FIM baseline records mapped by path."""
    try:
        records = FileIntegrityBaselineRecord.query.all()
        return {r.path: r.to_dict() for r in records}
    except Exception as ex:
        logger.debug("Database FIM all baseline query failed: %s", ex)
        return {}


def delete_fim_baseline_record(path: str) -> bool:
    """Delete a single FIM baseline record by path."""
    try:
        rec = FileIntegrityBaselineRecord.query.filter_by(path=path).first()
        if rec:
            db.session.delete(rec)
            db.session.commit()
            return True
        return False
    except Exception as ex:
        db.session.rollback()
        logger.debug("Database FIM baseline delete failed: %s", ex)
        return False


def query_fim_baseline(
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    """Query paginated FIM baseline records with optional status and path filtering."""
    try:
        query = FileIntegrityBaselineRecord.query
        if status:
            query = query.filter(FileIntegrityBaselineRecord.status == status.upper())
        if path:
            query = query.filter(FileIntegrityBaselineRecord.path.like(f"%{path}%"))

        total = query.count()
        records = (
            query.order_by(FileIntegrityBaselineRecord.path.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "baseline": [r.to_dict() for r in records],
        }
    except Exception as ex:
        logger.debug("Database FIM baseline query failed: %s", ex)
        return {"total": 0, "limit": limit, "offset": offset, "baseline": []}


def query_fim_stats() -> Dict[str, Any]:
    """Compute aggregate counts for FIM baseline records."""
    try:
        total = FileIntegrityBaselineRecord.query.count()
        baseline_cnt = FileIntegrityBaselineRecord.query.filter_by(status="BASELINE").count()
        changed_cnt = FileIntegrityBaselineRecord.query.filter_by(status="CHANGED").count()
        missing_cnt = FileIntegrityBaselineRecord.query.filter_by(status="MISSING").count()
        unreadable_cnt = FileIntegrityBaselineRecord.query.filter_by(status="UNREADABLE").count()

        return {
            "total_files": total,
            "baseline_count": baseline_cnt,
            "changed_count": changed_cnt,
            "missing_count": missing_cnt,
            "unreadable_count": unreadable_cnt,
        }
    except Exception as ex:
        logger.debug("Database FIM stats query failed: %s", ex)
        return {
            "total_files": 0,
            "baseline_count": 0,
            "changed_count": 0,
            "missing_count": 0,
            "unreadable_count": 0,
        }


def query_fim_events(
    limit: int = 50,
    offset: int = 0,
    since: Optional[float] = None,
    until: Optional[float] = None,
    change_type: Optional[str] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    """Query persisted FIM security events from SecurityEventRecord."""
    fim_types = ["FILE_CREATED", "FILE_DELETED", "FILE_MODIFIED", "FILE_REPLACED", "FILE_METADATA_CHANGED"]
    try:
        query = SecurityEventRecord.query.filter(SecurityEventRecord.detection_type.in_(fim_types))
        if change_type and change_type.upper() in fim_types:
            query = query.filter(SecurityEventRecord.detection_type == change_type.upper())
        if since is not None:
            query = query.filter(SecurityEventRecord.timestamp >= since)
        if until is not None:
            query = query.filter(SecurityEventRecord.timestamp <= until)
        if path:
            query = query.filter(SecurityEventRecord.evidence.like(f"%{path}%"))

        total = query.count()
        records = (
            query.order_by(SecurityEventRecord.timestamp.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "events": [r.to_dict() for r in records],
        }
    except Exception as ex:
        logger.debug("Database FIM events query failed: %s", ex)
        return {"total": 0, "limit": limit, "offset": offset, "events": []}


def cleanup_old_records(retention_days: int = 7) -> Dict[str, int]:

    """Prune historical database records older than the retention threshold.

    Preserves active (OPEN, ACKNOWLEDGED) incidents indefinitely. Only RESOLVED
    and CLOSED incidents older than retention_days are pruned along with their evidence.
    Does not modify active in-memory firewall block state.
    """
    try:
        cutoff = time.time() - (retention_days * 86400)

        del_events = (
            SecurityEventRecord.query.filter(SecurityEventRecord.timestamp < cutoff).delete(
                synchronize_session=False
            )
        )
        del_risks = (
            RiskAssessmentRecord.query.filter(RiskAssessmentRecord.timestamp < cutoff).delete(
                synchronize_session=False
            )
        )
        del_fw = (
            FirewallActionRecord.query.filter(FirewallActionRecord.timestamp < cutoff).delete(
                synchronize_session=False
            )
        )
        del_telemetry = (
            HostTelemetryRecord.query.filter(HostTelemetryRecord.timestamp < cutoff).delete(
                synchronize_session=False
            )
        )
        del_incidents = (
            IncidentRecord.query.filter(
                IncidentRecord.status.in_(["RESOLVED", "CLOSED"]),
                IncidentRecord.updated_at < cutoff,
            ).delete(synchronize_session=False)
        )
        del_evidence = (
            IncidentEvidenceRecord.query.filter(
                IncidentEvidenceRecord.timestamp < cutoff,
                ~IncidentEvidenceRecord.incident_id.in_(
                    db.session.query(IncidentRecord.incident_id)
                ),
            ).delete(synchronize_session=False)
        )

        db.session.commit()
        logger.info(
            "Retention cleanup completed (cutoff=%.0f): pruned %d events, %d risks, %d fw actions, %d telemetry, %d incidents, %d evidence records",
            cutoff,
            del_events,
            del_risks,
            del_fw,
            del_telemetry,
            del_incidents,
            del_evidence,
        )
        return {
            "deleted_events": del_events,
            "deleted_risks": del_risks,
            "deleted_firewall_actions": del_fw,
            "deleted_telemetry": del_telemetry,
            "deleted_incidents": del_incidents,
            "deleted_evidence": del_evidence,
        }
    except Exception as ex:
        db.session.rollback()
        logger.error("Failed to run retention cleanup: %s", ex)
        return {
            "deleted_events": 0,
            "deleted_risks": 0,
            "deleted_firewall_actions": 0,
            "deleted_telemetry": 0,
            "deleted_incidents": 0,
            "deleted_evidence": 0,
        }


def get_persisted_assessments(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve newest persisted risk assessments from database."""
    try:
        records = (
            RiskAssessmentRecord.query.order_by(RiskAssessmentRecord.timestamp.desc())
            .limit(limit)
            .all()
        )
        return [r.to_dict() for r in records]
    except Exception as ex:
        logger.debug("Database assessment query failed: %s", ex)
        return []


def init_db(app) -> None:
    """Initialize SQLAlchemy with the Flask application context."""
    db.init_app(app)
    with app.app_context():
        db.create_all()
