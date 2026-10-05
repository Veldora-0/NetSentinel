"""NetSentinel Database Module.

Establishes SQLite configuration, SQLAlchemy database instance, and
persistence models for security events, risk assessments, and firewall mitigation records.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from flask_sqlalchemy import SQLAlchemy

logger = logging.getLogger("netsentinel.database")

db = SQLAlchemy()


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
    risk_level = db.Column(db.String(20), nullable=False)
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
