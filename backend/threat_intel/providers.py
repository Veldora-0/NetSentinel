"""NetSentinel Threat Intelligence Provider Adapters.

Implements normalized adapters for external threat intelligence providers (AbuseIPDB, VirusTotal).
Ensures HTTPS-only transport, strict timeouts, TLS verification, rate-limit backoff, and privacy
guardrails. Never logs or leaks API keys.
"""

from abc import ABC, abstractmethod
import logging
import time
from typing import Any, Dict, Optional
import requests

from .models import (
    ThreatIntelResult,
    REPUTATION_UNKNOWN,
    REPUTATION_CLEAN,
    REPUTATION_SUSPICIOUS,
    REPUTATION_MALICIOUS,
)
from .eligibility import is_eligible_public_ip

logger = logging.getLogger("netsentinel.threat_intel.providers")


class BaseThreatIntelProvider(ABC):
    """Abstract base adapter for threat intelligence lookup providers."""

    def __init__(
        self,
        name: str,
        enabled: bool = False,
        api_key: str = "",
        timeout: float = 8.0,
        min_request_interval: float = 15.0,
    ):
        self.name = name
        self.enabled = bool(enabled)
        self._api_key = str(api_key).strip() if api_key else ""
        self.timeout = float(timeout)
        self.min_request_interval = float(min_request_interval)
        self.last_request_time = 0.0
        self.rate_limited_until = 0.0
        self._session = requests.Session()

    @property
    def is_configured(self) -> bool:
        """Check if provider is enabled and configured with an API key."""
        return self.enabled and bool(self._api_key)

    @property
    def is_rate_limited(self) -> bool:
        """Check if provider is currently in a rate-limit backoff period."""
        return time.time() < self.rate_limited_until

    def _apply_rate_limit(self, backoff_seconds: float = 60.0) -> None:
        """Set rate limit backoff window."""
        self.rate_limited_until = time.time() + backoff_seconds
        logger.warning(
            "TI Provider %s hit rate limit (HTTP 429). Backing off for %.0f seconds.",
            self.name,
            backoff_seconds,
        )

    def _check_request_interval(self) -> None:
        """Enforce minimum delay between external requests to respect provider limits."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    @abstractmethod
    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        """Query external provider and return a normalized ThreatIntelResult."""
        pass


class AbuseIPDBProvider(BaseThreatIntelProvider):
    """AbuseIPDB IP Check API v2 Adapter."""

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        enabled: bool = False,
        api_key: str = "",
        max_age_days: int = 90,
        timeout: float = 8.0,
        min_request_interval: float = 15.0,
    ):
        super().__init__(
            name="AbuseIPDB",
            enabled=enabled,
            api_key=api_key,
            timeout=timeout,
            min_request_interval=min_request_interval,
        )
        self.max_age_days = int(max_age_days)

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        """Query AbuseIPDB for IP reputation."""
        now = time.time()
        if not is_eligible_public_ip(ip):
            return ThreatIntelResult(
                indicator=ip,
                provider=self.name,
                available=False,
                reputation=REPUTATION_UNKNOWN,
                error="IP is not eligible for external lookup (private/loopback/invalid)",
            )

        if not self.is_configured:
            return ThreatIntelResult(
                indicator=ip,
                provider=self.name,
                available=False,
                reputation=REPUTATION_UNKNOWN,
                error="Provider not configured or disabled",
            )

        if self.is_rate_limited:
            return ThreatIntelResult(
                indicator=ip,
                provider=self.name,
                available=False,
                reputation=REPUTATION_UNKNOWN,
                error="Provider currently rate-limited (HTTP 429 backoff)",
            )

        self._check_request_interval()

        headers = {
            "Key": self._api_key,
            "Accept": "application/json",
            "User-Agent": "NetSentinel-HIDS/1.0",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": self.max_age_days,
            "verbose": "",
        }

        try:
            resp = self._session.get(
                self.API_URL,
                headers=headers,
                params=params,
                timeout=self.timeout,
                verify=True,
            )

            if resp.status_code == 429:
                # Rate limited
                retry_after = 60.0
                if "Retry-After" in resp.headers:
                    try:
                        retry_after = float(resp.headers["Retry-After"])
                    except Exception:
                        pass
                self._apply_rate_limit(retry_after)
                return ThreatIntelResult(
                    indicator=ip,
                    provider=self.name,
                    available=False,
                    reputation=REPUTATION_UNKNOWN,
                    error="Rate limit exceeded (HTTP 429)",
                )

            if resp.status_code == 404:
                return ThreatIntelResult(
                    indicator=ip,
                    provider=self.name,
                    available=True,
                    reputation=REPUTATION_UNKNOWN,
                    confidence=0.0,
                    error=None,
                )

            if resp.status_code != 200:
                return ThreatIntelResult(
                    indicator=ip,
                    provider=self.name,
                    available=False,
                    reputation=REPUTATION_UNKNOWN,
                    error=f"Provider returned HTTP {resp.status_code}",
                )

            data = resp.json().get("data", {})
            abuse_score = int(data.get("abuseConfidenceScore", 0))
            total_reports = int(data.get("totalReports", 0))
            country = data.get("countryCode")
            isp = data.get("isp")
            domain = data.get("domain")
            usage_type = data.get("usageType")
            last_reported = data.get("lastReportedAt")

            # Determine reputation
            if abuse_score >= 50 or total_reports >= 5:
                reputation = REPUTATION_MALICIOUS
                confidence = min(1.0, max(0.5, abuse_score / 100.0))
            elif abuse_score >= 15 or total_reports >= 2:
                reputation = REPUTATION_SUSPICIOUS
                confidence = min(1.0, max(0.4, abuse_score / 100.0))
            else:
                reputation = REPUTATION_CLEAN
                confidence = 0.80

            categories = []
            if usage_type:
                categories.append(usage_type)

            tags = []
            if domain:
                tags.append(f"domain:{domain}")

            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ipv6" if ":" in ip else "ipv4",
                provider=self.name,
                queried_at=now,
                expires_at=now + 3600.0,
                available=True,
                reputation=reputation,
                abuse_confidence=abuse_score,
                malicious_score=float(abuse_score),
                report_count=total_reports,
                last_reported_at=last_reported,
                country=country,
                as_owner=isp,
                categories=categories,
                tags=tags,
                confidence=confidence,
                source_url=f"https://www.abuseipdb.com/check/{ip}",
                error=None,
            )

        except requests.exceptions.Timeout:
            logger.debug("AbuseIPDB request timed out for %s", ip)
            return ThreatIntelResult(
                indicator=ip,
                provider=self.name,
                available=False,
                reputation=REPUTATION_UNKNOWN,
                error="Request timed out",
            )
        except requests.exceptions.RequestException as ex:
            logger.debug("AbuseIPDB request error for %s: %s", ip, ex)
            return ThreatIntelResult(
                indicator=ip,
                provider=self.name,
                available=False,
                reputation=REPUTATION_UNKNOWN,
                error=f"HTTP request failed: {type(ex).__name__}",
            )
        except Exception as ex:
            logger.debug("AbuseIPDB response parsing error for %s: %s", ip, ex)
            return ThreatIntelResult(
                indicator=ip,
                provider=self.name,
                available=False,
                reputation=REPUTATION_UNKNOWN,
                error=f"Malformed response: {type(ex).__name__}",
            )


class VirusTotalProvider(BaseThreatIntelProvider):
    """VirusTotal IP Address Report API v3 Adapter."""

    BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    def __init__(
        self,
        enabled: bool = False,
        api_key: str = "",
        timeout: float = 8.0,
        min_request_interval: float = 15.0,
    ):
        super().__init__(
            name="VirusTotal",
            enabled=enabled,
            api_key=api_key,
            timeout=timeout,
            min_request_interval=min_request_interval,
        )

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        """Query VirusTotal v3 for IP reputation."""
        now = time.time()
        if not is_eligible_public_ip(ip):
            return ThreatIntelResult(
                indicator=ip,
                provider=self.name,
                available=False,
                reputation=REPUTATION_UNKNOWN,
                error="IP is not eligible for external lookup (private/loopback/invalid)",
            )

        if not self.is_configured:
            return ThreatIntelResult(
                indicator=ip,
                provider=self.name,
                available=False,
                reputation=REPUTATION_UNKNOWN,
                error="Provider not configured or disabled",
            )

        if self.is_rate_limited:
            return ThreatIntelResult(
                indicator=ip,
                provider=self.name,
                available=False,
                reputation=REPUTATION_UNKNOWN,
                error="Provider currently rate-limited (HTTP 429 backoff)",
            )

        self._check_request_interval()

        headers = {
            "x-apikey": self._api_key,
            "Accept": "application/json",
            "User-Agent": "NetSentinel-HIDS/1.0",
        }
        url = self.BASE_URL.format(ip=ip)

        try:
            resp = self._session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=True,
            )

            if resp.status_code == 429:
                retry_after = 60.0
                if "Retry-After" in resp.headers:
                    try:
                        retry_after = float(resp.headers["Retry-After"])
                    except Exception:
                        pass
                self._apply_rate_limit(retry_after)
                return ThreatIntelResult(
                    indicator=ip,
                    provider=self.name,
                    available=False,
                    reputation=REPUTATION_UNKNOWN,
                    error="Rate limit exceeded (HTTP 429)",
                )

            if resp.status_code == 404:
                # Indicator not found in VirusTotal dataset (unknown/not indexed)
                return ThreatIntelResult(
                    indicator=ip,
                    provider=self.name,
                    available=True,
                    reputation=REPUTATION_UNKNOWN,
                    confidence=0.0,
                    error=None,
                )

            if resp.status_code != 200:
                return ThreatIntelResult(
                    indicator=ip,
                    provider=self.name,
                    available=False,
                    reputation=REPUTATION_UNKNOWN,
                    error=f"Provider returned HTTP {resp.status_code}",
                )

            body = resp.json().get("data", {})
            attrs = body.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            reputation_score = int(attrs.get("reputation", 0))
            country = attrs.get("country")
            as_owner = attrs.get("as_owner")
            asn_raw = attrs.get("asn")
            asn = str(asn_raw) if asn_raw is not None else None

            # Determine reputation
            if malicious >= 3 or reputation_score <= -10:
                reputation = REPUTATION_MALICIOUS
                confidence = min(1.0, 0.5 + (malicious * 0.1))
            elif malicious >= 1 or suspicious >= 2 or reputation_score < 0:
                reputation = REPUTATION_SUSPICIOUS
                confidence = 0.65
            elif malicious == 0 and suspicious <= 1 and (harmless > 0 or undetected > 0):
                reputation = REPUTATION_CLEAN
                confidence = 0.80
            else:
                reputation = REPUTATION_UNKNOWN
                confidence = 0.0

            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ipv6" if ":" in ip else "ipv4",
                provider=self.name,
                queried_at=now,
                expires_at=now + 3600.0,
                available=True,
                reputation=reputation,
                malicious_score=float(malicious),
                suspicious_score=float(suspicious),
                report_count=malicious + suspicious,
                country=country,
                asn=asn,
                as_owner=as_owner,
                confidence=confidence,
                source_url=f"https://www.virustotal.com/gui/ip-address/{ip}",
                error=None,
            )

        except requests.exceptions.Timeout:
            logger.debug("VirusTotal request timed out for %s", ip)
            return ThreatIntelResult(
                indicator=ip,
                provider=self.name,
                available=False,
                reputation=REPUTATION_UNKNOWN,
                error="Request timed out",
            )
        except requests.exceptions.RequestException as ex:
            logger.debug("VirusTotal request error for %s: %s", ip, ex)
            return ThreatIntelResult(
                indicator=ip,
                provider=self.name,
                available=False,
                reputation=REPUTATION_UNKNOWN,
                error=f"HTTP request failed: {type(ex).__name__}",
            )
        except Exception as ex:
            logger.debug("VirusTotal response parsing error for %s: %s", ip, ex)
            return ThreatIntelResult(
                indicator=ip,
                provider=self.name,
                available=False,
                reputation=REPUTATION_UNKNOWN,
                error=f"Malformed response: {type(ex).__name__}",
            )
