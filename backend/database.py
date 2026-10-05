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
    source_ip = db.Column(db.String(64), nullable=False, index=True)
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
            src_ip = str(event.get("source_ip", ""))
            dst_ip = event.get("destination_ip")
            proto = event.get("protocol")
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
            src_ip = str(getattr(event, "source_ip", ""))
            dst_ip = getattr(event, "destination_ip", None)
            proto = getattr(event, "protocol", None)
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


def query_security_summary(since_timestamp: Optional[float] = None) -> Dict[str, Any]:
    """Generate aggregate statistics across security events, risks, and firewall actions."""
    try:
        ev_query = SecurityEventRecord.query
        risk_query = RiskAssessmentRecord.query
        fw_query = FirewallActionRecord.query

        if since_timestamp is not None:
            ev_query = ev_query.filter(SecurityEventRecord.timestamp >= since_timestamp)
            risk_query = risk_query.filter(RiskAssessmentRecord.timestamp >= since_timestamp)
            fw_query = fw_query.filter(FirewallActionRecord.timestamp >= since_timestamp)

        total_events = ev_query.count()
        total_assessments = risk_query.count()
        total_firewall_actions = fw_query.count()

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

        # Top 5 source IPs by incident count
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
            "detection_types": detection_types,
            "severities": severities,
            "top_source_ips": top_ips,
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
            "detection_types": {},
            "severities": {},
            "top_source_ips": [],
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


def cleanup_old_records(retention_days: int = 7) -> Dict[str, int]:
    """Prune historical database records older than the retention threshold.

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

        db.session.commit()
        logger.info(
            "Retention cleanup completed (cutoff=%.0f): pruned %d events, %d risks, %d fw actions, %d telemetry records",
            cutoff,
            del_events,
            del_risks,
            del_fw,
            del_telemetry,
        )
        return {
            "deleted_events": del_events,
            "deleted_risks": del_risks,
            "deleted_firewall_actions": del_fw,
            "deleted_telemetry": del_telemetry,
        }
    except Exception as ex:
        db.session.rollback()
        logger.error("Failed to run retention cleanup: %s", ex)
        return {
            "deleted_events": 0,
            "deleted_risks": 0,
            "deleted_firewall_actions": 0,
            "deleted_telemetry": 0,
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
