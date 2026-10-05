"""NetSentinel Threat Intelligence Models.

Defines the normalized Threat Intelligence result contract, aggregated reputation
dataclasses, and standardized reputation classification constants.
"""

from dataclasses import dataclass, field, asdict
import time
from typing import Any, Dict, List, Optional

# Standard normalized reputation classifications
REPUTATION_UNKNOWN = "UNKNOWN"
REPUTATION_CLEAN = "CLEAN"
REPUTATION_SUSPICIOUS = "SUSPICIOUS"
REPUTATION_MALICIOUS = "MALICIOUS"
REPUTATION_CONFLICTING = "CONFLICTING"

VALID_REPUTATIONS = {
    REPUTATION_UNKNOWN,
    REPUTATION_CLEAN,
    REPUTATION_SUSPICIOUS,
    REPUTATION_MALICIOUS,
    REPUTATION_CONFLICTING,
}

# Consensus types for aggregated provider intelligence
CONSENSUS_STRONG_POSITIVE = "STRONG_POSITIVE"
CONSENSUS_MODERATE_POSITIVE = "MODERATE_POSITIVE"
CONSENSUS_CLEAN = "CLEAN"
CONSENSUS_CONFLICTING = "CONFLICTING"
CONSENSUS_UNKNOWN = "UNKNOWN"


@dataclass
class ThreatIntelResult:
    """Normalized security result from a single threat intelligence provider."""
    indicator: str
    indicator_type: str = "ipv4"  # "ipv4" | "ipv6"
    provider: str = ""
    queried_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600.0)
    available: bool = True
    reputation: str = REPUTATION_UNKNOWN
    abuse_confidence: Optional[int] = None
    malicious_score: Optional[float] = None
    suspicious_score: Optional[float] = None
    report_count: int = 0
    last_reported_at: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    as_owner: Optional[str] = None
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    confidence: float = 0.0
    source_url: Optional[str] = None
    error: Optional[str] = None
    raw_provider_reference: Optional[str] = None

    @property
    def is_stale(self) -> bool:
        """Check if result has passed its expiration timestamp."""
        return time.time() > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert result dataclass to JSON-serializable dictionary."""
        d = asdict(self)
        d["stale"] = self.is_stale
        d["confidence"] = round(self.confidence, 4)
        return d


@dataclass
class AggregatedThreatIntel:
    """Unified consensus summary combining multiple threat intelligence providers."""
    ip: str
    reputation: str = REPUTATION_UNKNOWN
    confidence: float = 0.0
    consensus: str = CONSENSUS_UNKNOWN
    providers_checked: int = 0
    providers_available: int = 0
    abuse_score: Optional[int] = None
    report_count: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    country: Optional[str] = None
    asn: Optional[str] = None
    as_owner: Optional[str] = None
    last_checked: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600.0)
    stale: bool = False
    provider_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert aggregate dataclass to JSON-serializable dictionary."""
        d = asdict(self)
        d["confidence"] = round(self.confidence, 4)
        return d
