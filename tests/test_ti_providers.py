"""Unit tests for NetSentinel Threat Intelligence Provider Adapters (AbuseIPDB, VirusTotal)."""

from unittest.mock import MagicMock, patch
import requests

from threat_intel.providers import (
    AbuseIPDBProvider,
    VirusTotalProvider,
)
from threat_intel.models import (
    REPUTATION_UNKNOWN,
    REPUTATION_CLEAN,
    REPUTATION_SUSPICIOUS,
    REPUTATION_MALICIOUS,
)


def test_abuseipdb_clean_ip():
    """Verify AbuseIPDB returns CLEAN for an IP with 0 abuse score."""
    provider = AbuseIPDBProvider(
        enabled=True,
        api_key="test_abuse_key",
        timeout=5.0,
        min_request_interval=0.0,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "countryCode": "US",
            "isp": "Google LLC",
            "domain": "google.com",
            "usageType": "Data Center/Web Hosting/Transit",
        }
    }

    with patch.object(provider._session, "get", return_value=mock_resp) as mock_get:
        result = provider.lookup_ip("8.8.8.8")
        assert result.available is True
        assert result.reputation == REPUTATION_CLEAN
        assert result.abuse_confidence == 0
        assert result.country == "US"
        assert result.as_owner == "Google LLC"
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["headers"]["Key"] == "test_abuse_key"
        assert call_kwargs["verify"] is True


def test_abuseipdb_malicious_ip():
    """Verify AbuseIPDB returns MALICIOUS for score >= 50 or reports >= 5."""
    provider = AbuseIPDBProvider(
        enabled=True,
        api_key="test_abuse_key",
        min_request_interval=0.0,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "ipAddress": "185.220.101.5",
            "abuseConfidenceScore": 95,
            "totalReports": 42,
            "countryCode": "DE",
            "isp": "Bad ISP",
        }
    }

    with patch.object(provider._session, "get", return_value=mock_resp):
        result = provider.lookup_ip("185.220.101.5")
        assert result.available is True
        assert result.reputation == REPUTATION_MALICIOUS
        assert result.abuse_confidence == 95
        assert result.confidence >= 0.90


def test_abuseipdb_rate_limiting_429():
    """Verify AbuseIPDB handles HTTP 429 and triggers backoff."""
    provider = AbuseIPDBProvider(
        enabled=True,
        api_key="test_abuse_key",
        min_request_interval=0.0,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {"Retry-After": "30"}

    with patch.object(provider._session, "get", return_value=mock_resp):
        result = provider.lookup_ip("8.8.8.8")
        assert result.available is False
        assert result.reputation == REPUTATION_UNKNOWN
        assert "429" in (result.error or "")
        assert provider.is_rate_limited is True


def test_virustotal_clean_ip():
    """Verify VirusTotal returns CLEAN when malicious count is 0 and harmless > 0."""
    provider = VirusTotalProvider(
        enabled=True,
        api_key="test_vt_key",
        min_request_interval=0.0,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 75,
                    "undetected": 10,
                },
                "reputation": 100,
                "country": "US",
                "as_owner": "Cloudflare",
                "network": "1.1.1.0/24",
            }
        }
    }

    with patch.object(provider._session, "get", return_value=mock_resp) as mock_get:
        result = provider.lookup_ip("1.1.1.1")
        assert result.available is True
        assert result.reputation == REPUTATION_CLEAN
        assert result.country == "US"
        assert result.as_owner == "Cloudflare"
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["headers"]["x-apikey"] == "test_vt_key"
        assert call_kwargs["verify"] is True


def test_virustotal_malicious_ip():
    """Verify VirusTotal returns MALICIOUS when malicious engines >= 3."""
    provider = VirusTotalProvider(
        enabled=True,
        api_key="test_vt_key",
        min_request_interval=0.0,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 14,
                    "suspicious": 3,
                    "harmless": 20,
                    "undetected": 40,
                },
                "reputation": -50,
                "country": "CN",
                "as_owner": "Host Provider",
            }
        }
    }

    with patch.object(provider._session, "get", return_value=mock_resp):
        result = provider.lookup_ip("93.184.216.34")
        assert result.available is True
        assert result.reputation == REPUTATION_MALICIOUS
        assert result.malicious_score == 14.0
        assert result.confidence >= 0.8


def test_provider_rejects_private_ip():
    """Verify providers reject private IPs immediately without network call."""
    abuse = AbuseIPDBProvider(enabled=True, api_key="test", min_request_interval=0.0)
    vt = VirusTotalProvider(enabled=True, api_key="test", min_request_interval=0.0)

    with patch.object(abuse._session, "get") as mock_get:
        res = abuse.lookup_ip("192.168.1.1")
        assert res.available is False
        assert "not eligible" in (res.error or "")
        mock_get.assert_not_called()

    with patch.object(vt._session, "get") as mock_get:
        res = vt.lookup_ip("10.0.0.1")
        assert res.available is False
        assert "not eligible" in (res.error or "")
        mock_get.assert_not_called()


def test_provider_network_timeout():
    """Verify timeouts are handled cleanly without exceptions."""
    abuse = AbuseIPDBProvider(enabled=True, api_key="test", min_request_interval=0.0)
    with patch.object(abuse._session, "get", side_effect=requests.exceptions.Timeout("Timed out")):
        res = abuse.lookup_ip("8.8.8.8")
        assert res.available is False
        assert res.reputation == REPUTATION_UNKNOWN
        assert "timed out" in (res.error or "").lower()
