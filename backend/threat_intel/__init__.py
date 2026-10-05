"""NetSentinel Threat Intelligence Package.

Exposes normalized threat intelligence data structures, provider adapters, IP eligibility
validators, and the ThreatIntelService coordinator.
"""

from .models import (
    ThreatIntelResult,
    AggregatedThreatIntel,
    REPUTATION_UNKNOWN,
    REPUTATION_CLEAN,
    REPUTATION_SUSPICIOUS,
    REPUTATION_MALICIOUS,
    REPUTATION_CONFLICTING,
    CONSENSUS_STRONG_POSITIVE,
    CONSENSUS_MODERATE_POSITIVE,
    CONSENSUS_CLEAN,
    CONSENSUS_CONFLICTING,
    CONSENSUS_UNKNOWN,
)
from .eligibility import is_eligible_public_ip, normalize_ip
from .providers import BaseThreatIntelProvider, AbuseIPDBProvider, VirusTotalProvider
from .cache import ThreatIntelCache
from .service import ThreatIntelService

__all__ = [
    "ThreatIntelResult",
    "AggregatedThreatIntel",
    "REPUTATION_UNKNOWN",
    "REPUTATION_CLEAN",
    "REPUTATION_SUSPICIOUS",
    "REPUTATION_MALICIOUS",
    "REPUTATION_CONFLICTING",
    "CONSENSUS_STRONG_POSITIVE",
    "CONSENSUS_MODERATE_POSITIVE",
    "CONSENSUS_CLEAN",
    "CONSENSUS_CONFLICTING",
    "CONSENSUS_UNKNOWN",
    "is_eligible_public_ip",
    "normalize_ip",
    "BaseThreatIntelProvider",
    "AbuseIPDBProvider",
    "VirusTotalProvider",
    "ThreatIntelCache",
    "ThreatIntelService",
]
