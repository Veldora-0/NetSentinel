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

        # Phase 7: Network + Host Evidence Correlation Settings
        self.correlation_window_seconds = float(cfg.get("correlation_window_sec", 300.0))
        self.correlation_boost = float(cfg.get("correlation_boost", 0.10))
        self.max_correlation_boost = float(cfg.get("max_correlation_boost", 0.20))

        # Thread-safe in-memory state
        self._lock = threading.RLock()
        self._ip_history: Dict[str, deque] = {}
        self._correlation_history: Dict[str, deque] = {}  # ip -> deque of (timestamp, category, type)
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
        self,
        rule_alerts: Optional[List[Dict[str, Any]]] = None,
        ml_anomaly_score: float = 0.0,
        ti_summary: Optional[Any] = None,
    ) -> float:
        """Calculate composite risk score without updating state."""
        ml_score = max(0.0, min(1.0, float(ml_anomaly_score or 0.0)))
        alerts = rule_alerts or []

        if not alerts:
            combined = self.ml_weight * ml_score
        else:
            base_rule_score = 0.0
            for alert in alerts:
                sev = alert.get("severity", "LOW") if isinstance(alert, dict) else getattr(alert, "severity", "LOW")
                score = self.severity_scores.get(sev.upper(), 0.20)
                if score > base_rule_score:
                    base_rule_score = score
            combined = (self.rule_weight * base_rule_score) + (self.ml_weight * ml_score)

        if ti_summary:
            ti_data = ti_summary.to_dict() if hasattr(ti_summary, "to_dict") else ti_summary
            ti_rep = str(ti_data.get("reputation", "UNKNOWN")).upper()
            ti_stale = bool(ti_data.get("stale", False))
            base_ti_mod = self.TI_MODIFIERS.get(ti_rep, 0.0)
            ti_mod = round(base_ti_mod * 0.5, 4) if ti_stale else base_ti_mod
            combined = min(1.0, combined + ti_mod)

        return round(max(0.0, min(1.0, combined)), 4)


    NETWORK_DETECTION_TYPES = {
        "PORT_SCAN", "SYN_FLOOD", "NULL_SCAN", "XMAS_SCAN",
        "ARP_SPOOFING", "ARP_IDENTITY_CONFLICT", "ICMP_SWEEP"
    }
    HOST_DETECTION_TYPES = {
        "SSH_AUTH_FAILURE",
        "SSH_BRUTE_FORCE",
        "SUSPICIOUS_PROCESS",
        "FILE_CREATED",
        "FILE_DELETED",
        "FILE_MODIFIED",
        "FILE_REPLACED",
        "FILE_METADATA_CHANGED",
    }


    def _classify_detection_type(self, dtype: str) -> str:
        """Classify a detection type into network or host domain."""
        up = (dtype or "").upper()
        if up in self.NETWORK_DETECTION_TYPES:
            return "network"
        elif up in self.HOST_DETECTION_TYPES:
            return "host"
        return "other"

    def _record_correlation(self, source_ip: str, alerts: List[Any], now: float) -> None:
        """Record detection event occurrences by domain for correlation."""
        if not source_ip:
            return

        if source_ip not in self._correlation_history:
            if len(self._correlation_history) >= self.max_tracked_ips:
                self.cleanup_stale_state(now)
            if len(self._correlation_history) >= self.max_tracked_ips:
                oldest_ip = next(iter(self._correlation_history))
                del self._correlation_history[oldest_ip]
            self._correlation_history[source_ip] = deque()

        history = self._correlation_history[source_ip]
        for a in alerts:
            dtype = a.get("detection_type", "UNKNOWN") if isinstance(a, dict) else getattr(a, "detection_type", "UNKNOWN")
            ts = a.get("timestamp", now) if isinstance(a, dict) else getattr(a, "timestamp", now)
            cat = self._classify_detection_type(dtype)
            history.append((ts, cat, dtype))

        cutoff = now - self.correlation_window_seconds
        while history and history[0][0] < cutoff:
            history.popleft()

    def _check_correlation(self, source_ip: str, now: float) -> tuple[bool, float, str]:
        """Check if source IP has correlated network and host intrusion evidence within window."""
        if not source_ip or source_ip not in self._correlation_history:
            return False, 0.0, ""

        history = self._correlation_history[source_ip]
        cutoff = now - self.correlation_window_seconds
        while history and history[0][0] < cutoff:
            history.popleft()

        has_network = any(item[1] == "network" for item in history)
        has_host = any(item[1] == "host" for item in history)

        if has_network and has_host:
            boost = min(self.correlation_boost, self.max_correlation_boost)
            note = "Correlated hybrid attack: network reconnaissance and host authentication activity from same source"
            return True, boost, note

        return False, 0.0, ""

    TI_MODIFIERS = {
        "MALICIOUS": 0.15,
        "SUSPICIOUS": 0.05,
        "CONFLICTING": 0.02,
        "CLEAN": 0.00,
        "UNKNOWN": 0.00,
    }

    def assess_rule_event(
        self,
        event: Any,
        ml_anomaly_score: float = 0.0,
        ti_summary: Optional[Any] = None,
    ) -> RiskAssessment:
        """Convenience method to evaluate a single SecurityEvent instance."""
        src_ip = getattr(event, "source_ip", None) or "127.0.0.1"
        dst_ip = getattr(event, "destination_ip", None)
        return self.assess(
            source_ip=src_ip,
            destination_ip=dst_ip,
            rule_alerts=[event],
            ml_anomaly_score=ml_anomaly_score,
            ti_summary=ti_summary,
        )

    def assess(
        self,
        source_ip: Optional[str],
        destination_ip: Optional[str] = None,
        rule_alerts: Optional[List[Any]] = None,
        ml_anomaly_score: float = 0.0,
        ti_summary: Optional[Any] = None,
    ) -> RiskAssessment:

        """Evaluate overall threat level, compute composite score, and record assessment."""
        now = time.time()
        safe_source_ip = source_ip if (source_ip and source_ip.strip()) else "127.0.0.1"
        alerts = rule_alerts or []
        ml_score = max(0.0, min(1.0, float(ml_anomaly_score or 0.0)))

        with self._lock:
            self._record_ip_event(safe_source_ip, now)
            self._record_correlation(safe_source_ip, alerts, now)
            repeat_boost = self._get_repeat_boost(safe_source_ip, now)
            is_correlated, correlation_boost, correlation_note = self._check_correlation(safe_source_ip, now)

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

            # Apply bounded correlation boost if both network and host evidence are present
            if is_correlated and correlation_boost > 0.0:
                combined = min(1.0, combined + correlation_boost)

            # Phase 11: Threat Intelligence Bounded Modifier
            ti_data = ti_summary.to_dict() if hasattr(ti_summary, "to_dict") else (ti_summary or {})
            ti_rep = str(ti_data.get("reputation", "UNKNOWN")).upper()
            ti_stale = bool(ti_data.get("stale", False))
            ti_conf = float(ti_data.get("confidence", 0.0))
            ti_avail = bool(ti_data.get("available", True)) and (ti_rep != "UNKNOWN" or bool(ti_data.get("providers_checked", 0)))
            ti_providers = int(ti_data.get("providers_checked", 0) or len(ti_data.get("provider_results", {})))
            ti_consensus = str(ti_data.get("consensus", "UNKNOWN"))

            base_ti_mod = self.TI_MODIFIERS.get(ti_rep, 0.0)
            ti_boost = round(base_ti_mod * 0.5, 4) if ti_stale else base_ti_mod

            if ti_boost > 0.0:
                combined = min(1.0, combined + ti_boost)

            combined_clamped = round(max(0.0, min(1.0, combined)), 4)
            risk_level, action = self._determine_risk_level_and_action(combined_clamped)

            reason_parts = []
            if alerts:
                reason_parts.append(f"Rule detections: {', '.join(detection_types)}")
            if is_correlated and correlation_boost > 0.0:
                reason_parts.append(f"{correlation_note} (+{correlation_boost:.2f})")
            if repeat_boost > 0.0:
                reason_parts.append(f"repeated activity (+{repeat_boost:.2f})")
            if ti_boost > 0.0:
                stale_tag = " (stale)" if ti_stale else ""
                reason_parts.append(f"Threat Intelligence: {ti_rep}{stale_tag} (+{ti_boost:.2f})")
            if ml_score > 0.0:
                reason_parts.append(f"ML anomaly score: {ml_score:.2f}")

            reason = " | ".join(reason_parts) if reason_parts else "Routine traffic observation"

            assessment = RiskAssessment(
                assessment_id=uuid.uuid4().hex[:12],
                timestamp=now,
                source_ip=safe_source_ip,
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
                    "correlation_boost": round(correlation_boost, 4),
                    "correlated": is_correlated,
                    "correlation_note": correlation_note if is_correlated else None,
                    "correlation_reason": correlation_note if is_correlated else None,
                    "ti_reputation": ti_rep,
                    "ti_score_modifier": ti_boost,
                    "ti_confidence": round(ti_conf, 4),
                    "ti_provider_count": ti_providers,
                    "ti_stale": ti_stale,
                    "ti_consensus": ti_consensus,
                    "ti_available": ti_avail,
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

            # Prune correlation history
            cutoff_corr = current_time - self.correlation_window_seconds
            stale_corr = []
            for ip, hist in self._correlation_history.items():
                while hist and hist[0][0] < cutoff_corr:
                    hist.popleft()
                if not hist:
                    stale_corr.append(ip)

            for ip in stale_corr:
                del self._correlation_history[ip]

        return removed_count
