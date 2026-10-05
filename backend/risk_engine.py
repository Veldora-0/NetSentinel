"""NetSentinel Composite Risk Engine Module.

Combines rule-based intrusion detections, machine learning anomaly scores,
and historical source IP frequency to compute deterministic, explainable risk scores,
assign risk levels, and recommend mitigation actions.
"""

from collections import deque
from dataclasses import dataclass, asdict
import logging
import threading
import time
from typing import Any, Dict, List, Optional
import uuid

from config import Config

logger = logging.getLogger("netsentinel.risk_engine")


@dataclass
class RiskAssessment:
    """Structured security risk assessment result."""
    assessment_id: str
    timestamp: float
    source_ip: str
    destination_ip: Optional[str]
    rule_score: float
    ml_anomaly_score: float
    combined_score: float
    risk_level: str
    recommended_action: str
    detection_types: List[str]
    evidence: Dict[str, Any]
    blocked: bool
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert assessment dataclass to JSON-serializable dictionary."""
        return asdict(self)


class RiskEngine:
    """Composite security risk evaluation and decision engine."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or Config.RISK_SETTINGS

        self.rule_weight = float(cfg.get("rule_weight", 0.65))
        self.ml_weight = float(cfg.get("ml_weight", 0.35))
        self.severity_scores: Dict[str, float] = cfg.get(
            "severity_scores",
            {"LOW": 0.20, "MEDIUM": 0.40, "HIGH": 0.70, "CRITICAL": 0.90},
        )
        self.repeat_increment = float(cfg.get("repeat_increment", 0.05))
        self.max_repeat_boost = float(cfg.get("max_repeat_boost", 0.20))
        self.history_window_seconds = float(cfg.get("history_window_seconds", 60.0))
        self.auto_block_threshold = float(cfg.get("auto_block_threshold", 0.80))
        self.max_tracked_ips = int(cfg.get("max_tracked_ips", 1000))
        self.max_history = int(cfg.get("max_assessment_history", 100))

        # Thread-safe in-memory state
        self._lock = threading.RLock()
        self._ip_history: Dict[str, deque] = {}
        self._recent_assessments: deque = deque(maxlen=self.max_history)
        self._stats = {
            "total_assessments": 0,
            "low_count": 0,
            "medium_count": 0,
            "high_count": 0,
            "critical_count": 0,
            "blocked_count": 0,
        }

    def _determine_risk_level_and_action(self, score: float) -> tuple[str, str]:
        """Map normalized combined score to risk level and recommended action."""
        if score < 0.30:
            return "LOW", "monitor"
        elif score < 0.60:
            return "MEDIUM", "log"
        elif score < 0.80:
            return "HIGH", "alert"
        else:
            return "CRITICAL", "block"

    def _get_repeat_boost(self, source_ip: str, now: float) -> float:
        """Calculate repeat detection boost for a source IP within time window."""
        if not source_ip or source_ip not in self._ip_history:
            return 0.0

        history = self._ip_history[source_ip]
        cutoff = now - self.history_window_seconds
        while history and history[0] < cutoff:
            history.popleft()

        repeat_count = max(0, len(history) - 1)
        return min(repeat_count * self.repeat_increment, self.max_repeat_boost)

    def _record_ip_event(self, source_ip: str, now: float) -> None:
        """Record detection event occurrence for source IP."""
        if not source_ip:
            return

        if source_ip not in self._ip_history:
            if len(self._ip_history) >= self.max_tracked_ips:
                self.cleanup_stale_state(now)
            if len(self._ip_history) >= self.max_tracked_ips:
                oldest_ip = next(iter(self._ip_history))
                del self._ip_history[oldest_ip]
            self._ip_history[source_ip] = deque()

        self._ip_history[source_ip].append(now)

    def calculate_risk_score(
        self, rule_alerts: Optional[List[Dict[str, Any]]] = None, ml_anomaly_score: float = 0.0
    ) -> float:
        """Calculate composite risk score without updating state."""
        ml_score = max(0.0, min(1.0, float(ml_anomaly_score or 0.0)))
        alerts = rule_alerts or []

        if not alerts:
            combined = self.ml_weight * ml_score
            return round(max(0.0, min(1.0, combined)), 4)

        base_rule_score = 0.0
        for alert in alerts:
            sev = alert.get("severity", "LOW") if isinstance(alert, dict) else getattr(alert, "severity", "LOW")
            score = self.severity_scores.get(sev.upper(), 0.20)
            if score > base_rule_score:
                base_rule_score = score

        combined = (self.rule_weight * base_rule_score) + (self.ml_weight * ml_score)
        return round(max(0.0, min(1.0, combined)), 4)

    def assess(
        self,
        source_ip: str,
        destination_ip: Optional[str] = None,
        rule_alerts: Optional[List[Any]] = None,
        ml_anomaly_score: float = 0.0,
    ) -> RiskAssessment:
        """Evaluate overall threat level, compute composite score, and record assessment."""
        now = time.time()
        alerts = rule_alerts or []
        ml_score = max(0.0, min(1.0, float(ml_anomaly_score or 0.0)))

        with self._lock:
            self._record_ip_event(source_ip, now)
            repeat_boost = self._get_repeat_boost(source_ip, now)

            # Determine rule score and detection types
            detection_types = []
            base_rule_score = 0.0
            evidence_details = []

            for alert in alerts:
                if isinstance(alert, dict):
                    sev = alert.get("severity", "LOW")
                    dtype = alert.get("detection_type", "UNKNOWN")
                    desc = alert.get("description", "")
                    evidence_details.append({"type": dtype, "severity": sev, "desc": desc})
                else:
                    sev = getattr(alert, "severity", "LOW")
                    dtype = getattr(alert, "detection_type", "UNKNOWN")
                    desc = getattr(alert, "description", "")
                    evidence_details.append({"type": dtype, "severity": sev, "desc": desc})

                if dtype not in detection_types:
                    detection_types.append(dtype)

                score = self.severity_scores.get(sev.upper(), 0.20)
                if score > base_rule_score:
                    base_rule_score = score

            if alerts:
                effective_rule_score = min(1.0, base_rule_score + repeat_boost)
                combined = (self.rule_weight * effective_rule_score) + (self.ml_weight * ml_score)
            else:
                effective_rule_score = 0.0
                combined = self.ml_weight * ml_score

            combined_clamped = round(max(0.0, min(1.0, combined)), 4)
            risk_level, action = self._determine_risk_level_and_action(combined_clamped)

            reason_parts = []
            if alerts:
                reason_parts.append(f"Rule detections: {', '.join(detection_types)}")
            if repeat_boost > 0.0:
                reason_parts.append(f"repeated activity (+{repeat_boost:.2f})")
            if ml_score > 0.0:
                reason_parts.append(f"ML anomaly score: {ml_score:.2f}")

            reason = " | ".join(reason_parts) if reason_parts else "Routine traffic observation"

            assessment = RiskAssessment(
                assessment_id=uuid.uuid4().hex[:12],
                timestamp=now,
                source_ip=source_ip,
                destination_ip=destination_ip,
                rule_score=round(effective_rule_score, 4),
                ml_anomaly_score=round(ml_score, 4),
                combined_score=combined_clamped,
                risk_level=risk_level,
                recommended_action=action,
                detection_types=detection_types,
                evidence={
                    "base_rule_score": base_rule_score,
                    "repeat_boost": round(repeat_boost, 4),
                    "rule_weight": self.rule_weight,
                    "ml_weight": self.ml_weight,
                    "alert_count": len(alerts),
                    "alerts": evidence_details,
                },
                blocked=False,
                reason=reason,
            )

            self._recent_assessments.append(assessment)
            self._stats["total_assessments"] += 1
            if risk_level == "LOW":
                self._stats["low_count"] += 1
            elif risk_level == "MEDIUM":
                self._stats["medium_count"] += 1
            elif risk_level == "HIGH":
                self._stats["high_count"] += 1
            elif risk_level == "CRITICAL":
                self._stats["critical_count"] += 1

            return assessment

    def evaluate_threat(
        self, source_ip: str, rule_alerts: Optional[List[Any]] = None, ml_anomaly_score: float = 0.0
    ) -> Dict[str, Any]:
        """Backward-compatible evaluation interface."""
        assessment = self.assess(source_ip=source_ip, rule_alerts=rule_alerts, ml_anomaly_score=ml_anomaly_score)
        return {
            "source_ip": assessment.source_ip,
            "risk_score": assessment.combined_score,
            "threat_level": assessment.risk_level,
            "action": assessment.recommended_action.upper(),
            "assessment": assessment.to_dict(),
        }

    def mark_blocked(self, assessment_id: str, blocked: bool = True) -> bool:
        """Mark an assessment record as actively blocked."""
        with self._lock:
            for item in self._recent_assessments:
                if item.assessment_id == assessment_id:
                    item.blocked = blocked
                    if blocked:
                        self._stats["blocked_count"] += 1
                    return True
        return False

    def get_recent_assessments(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent risk assessments newest first."""
        with self._lock:
            items = list(self._recent_assessments)
            items.reverse()
            return [a.to_dict() for a in items[:limit]]

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics across evaluated risk assessments."""
        with self._lock:
            recent_scores = [a.combined_score for a in self._recent_assessments]
            avg_score = round(sum(recent_scores) / len(recent_scores), 4) if recent_scores else 0.0
            highest_score = max(recent_scores) if recent_scores else 0.0

            return {
                **self._stats,
                "average_risk_score": avg_score,
                "highest_risk_score": highest_score,
                "recent_assessment_count": len(self._recent_assessments),
                "tracked_ips_count": len(self._ip_history),
            }

    def cleanup_stale_state(self, now: Optional[float] = None) -> int:
        """Prune source IPs whose last detection exceeded the history window."""
        current_time = now or time.time()
        cutoff = current_time - self.history_window_seconds
        removed_count = 0

        with self._lock:
            stale_ips = []
            for ip, history in self._ip_history.items():
                while history and history[0] < cutoff:
                    history.popleft()
                if not history:
                    stale_ips.append(ip)

            for ip in stale_ips:
                del self._ip_history[ip]
                removed_count += 1

        return removed_count
