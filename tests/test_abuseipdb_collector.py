"""
tests/test_abuseipdb_collector.py
----------------------------------
Unit tests for collectors/abuseipdb.py — fully offline.

AbuseIPDB is a post-processor that annotates IP indicators with
community abuse-confidence scores. Tests mirror the GreyNoise
test shape: private-IP filter, cache, run cap, and _check_ip
HTTP handling.
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock

from collectors.abuseipdb import AbuseIPDBCollector, _is_private, _ip_hash


# ---------------------------------------------------------------------------
# _is_private tests
# ---------------------------------------------------------------------------

class TestIsPrivate:

    def test_rfc1918_10(self):
        assert _is_private("10.0.0.1") is True

    def test_rfc1918_192(self):
        assert _is_private("192.168.1.1") is True

    def test_loopback(self):
        assert _is_private("127.0.0.1") is True

    def test_public_ipv4(self):
        assert _is_private("8.8.8.8") is False


# ---------------------------------------------------------------------------
# _ip_hash tests
# ---------------------------------------------------------------------------

class TestIpHash:

    def test_deterministic(self):
        assert _ip_hash("1.2.3.4") == _ip_hash("1.2.3.4")

    def test_different_ips_different_hashes(self):
        assert _ip_hash("1.2.3.4") != _ip_hash("1.2.3.5")

    def test_length_capped(self):
        assert len(_ip_hash("1.2.3.4")) == 16


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------

class TestAbuseIPDBCache:

    def test_save_and_load(self, tmp_path, monkeypatch):
        import collectors.abuseipdb as aipdb_module
        monkeypatch.setattr(aipdb_module, "CACHE_DIR", tmp_path)

        collector = AbuseIPDBCollector(api_key="test")
        context = {
            "abuse_confidence_score": 95,
            "total_reports":          142,
            "num_distinct_users":     38,
            "country_code":           "CN",
            "isp":                    "Example ISP",
            "domain":                 "example.com",
            "usage_type":             "Data Center/Web Hosting/Transit",
            "is_whitelisted":         False,
            "last_reported_at":       "2026-08-15T10:30:00+00:00",
        }
        collector._save_cache("1.2.3.4", context)
        assert collector._load_cache("1.2.3.4") == context

    def test_missing_returns_none(self, tmp_path, monkeypatch):
        import collectors.abuseipdb as aipdb_module
        monkeypatch.setattr(aipdb_module, "CACHE_DIR", tmp_path)

        collector = AbuseIPDBCollector(api_key="test")
        assert collector._load_cache("1.2.3.4") is None

    def test_stale_cache_returns_none(self, tmp_path, monkeypatch):
        import collectors.abuseipdb as aipdb_module
        monkeypatch.setattr(aipdb_module, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(aipdb_module, "CACHE_TTL_DAYS", 0)

        collector = AbuseIPDBCollector(api_key="test")
        collector._save_cache("1.2.3.4", {"abuse_confidence_score": 50})
        assert collector._load_cache("1.2.3.4") is None


# ---------------------------------------------------------------------------
# enrich_ips end-to-end
# ---------------------------------------------------------------------------

class TestEnrichIps:

    def _fake_context(self, score=95):
        return {
            "abuse_confidence_score": score,
            "total_reports":          142,
            "num_distinct_users":     38,
            "country_code":           "CN",
            "isp":                    "Example ISP",
            "domain":                 "example.com",
            "usage_type":             "Data Center/Web Hosting/Transit",
            "is_whitelisted":         False,
            "last_reported_at":       "2026-08-15T10:30:00+00:00",
        }

    def test_missing_api_key_returns_empty(self):
        collector = AbuseIPDBCollector(api_key="")
        result = collector.enrich_ips(
            [{"type": "ip", "value": "8.8.8.8"}], "APT28",
        )
        assert result == {}

    def test_no_ip_indicators_returns_empty(self, tmp_path, monkeypatch):
        import collectors.abuseipdb as aipdb_module
        monkeypatch.setattr(aipdb_module, "CACHE_DIR", tmp_path)

        collector = AbuseIPDBCollector(api_key="test")
        result = collector.enrich_ips(
            [{"type": "hash_sha256", "value": "a" * 64}], "APT28",
        )
        assert result == {}

    def test_private_ips_filtered(self, tmp_path, monkeypatch):
        import collectors.abuseipdb as aipdb_module
        monkeypatch.setattr(aipdb_module, "CACHE_DIR", tmp_path)

        collector = AbuseIPDBCollector(api_key="test")
        indicators = [
            {"type": "ip", "value": "10.0.0.1"},
            {"type": "ip", "value": "192.168.1.1"},
        ]
        with patch.object(collector, "_check_ip") as mock:
            result = collector.enrich_ips(indicators, "APT28")
        assert result == {}
        mock.assert_not_called()

    def test_uses_cache_before_live_lookup(self, tmp_path, monkeypatch):
        import collectors.abuseipdb as aipdb_module
        monkeypatch.setattr(aipdb_module, "CACHE_DIR", tmp_path)

        collector = AbuseIPDBCollector(api_key="test")
        cached = self._fake_context()
        collector._save_cache("8.8.8.8", cached)

        with patch.object(collector, "_check_ip") as mock:
            result = collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        assert result["8.8.8.8"] == cached
        mock.assert_not_called()

    def test_live_lookup_populates_cache(self, tmp_path, monkeypatch):
        import collectors.abuseipdb as aipdb_module
        monkeypatch.setattr(aipdb_module, "CACHE_DIR", tmp_path)

        collector = AbuseIPDBCollector(api_key="test")
        ctx = self._fake_context()
        with patch.object(collector, "_check_ip", return_value=ctx):
            result = collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        assert result["8.8.8.8"] == ctx
        assert collector._load_cache("8.8.8.8") == ctx

    def test_lookup_miss_writes_sentinel_cache(self, tmp_path, monkeypatch):
        import collectors.abuseipdb as aipdb_module
        monkeypatch.setattr(aipdb_module, "CACHE_DIR", tmp_path)

        collector = AbuseIPDBCollector(api_key="test")
        with patch.object(collector, "_check_ip", return_value=None):
            collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        cached = collector._load_cache("8.8.8.8")
        assert cached is not None
        # Sentinel: -1 signals "we tried but got nothing back"
        assert cached["abuse_confidence_score"] == -1

    def test_deduplicates_ips(self, tmp_path, monkeypatch):
        import collectors.abuseipdb as aipdb_module
        monkeypatch.setattr(aipdb_module, "CACHE_DIR", tmp_path)

        collector = AbuseIPDBCollector(api_key="test")
        indicators = [
            {"type": "ip", "value": "8.8.8.8"},
            {"type": "ip", "value": "8.8.8.8"},
        ]
        with patch.object(collector, "_check_ip",
                          return_value=self._fake_context()) as mock:
            collector.enrich_ips(indicators, "APT28")
        assert mock.call_count == 1

    def test_run_cap_enforced(self, tmp_path, monkeypatch):
        import collectors.abuseipdb as aipdb_module
        monkeypatch.setattr(aipdb_module, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(aipdb_module, "MAX_IPS_PER_RUN", 5)

        collector = AbuseIPDBCollector(api_key="test")
        indicators = [{"type": "ip", "value": f"8.8.8.{i}"} for i in range(20)]
        with patch.object(collector, "_check_ip",
                          return_value=self._fake_context()) as mock:
            collector.enrich_ips(indicators, "APT28")
        assert mock.call_count == 5


# ---------------------------------------------------------------------------
# _check_ip HTTP handling
# ---------------------------------------------------------------------------

class TestCheckIp:

    def _mock_response(self, payload: dict) -> MagicMock:
        m = MagicMock()
        m.__enter__ = lambda self: m
        m.__exit__  = lambda self, *args: None
        m.read.return_value = json.dumps(payload).encode()
        return m

    def test_success_returns_context(self):
        collector = AbuseIPDBCollector(api_key="test")
        payload = {
            "data": {
                "ipAddress":            "8.8.8.8",
                "abuseConfidenceScore": 95,
                "totalReports":         142,
                "numDistinctUsers":     38,
                "countryCode":          "CN",
                "isp":                  "Example ISP",
                "domain":               "example.com",
                "usageType":            "Data Center/Web Hosting/Transit",
                "isWhitelisted":        False,
                "lastReportedAt":       "2026-08-15T10:30:00+00:00",
            }
        }
        response = self._mock_response(payload)
        with patch("collectors.abuseipdb.urlopen", return_value=response):
            result = collector._check_ip("8.8.8.8")
        assert result is not None
        assert result["abuse_confidence_score"] == 95
        assert result["country_code"] == "CN"

    def test_empty_data_returns_none(self):
        collector = AbuseIPDBCollector(api_key="test")
        response = self._mock_response({"data": {}})
        with patch("collectors.abuseipdb.urlopen", return_value=response):
            assert collector._check_ip("8.8.8.8") is None

    def test_422_returns_none(self):
        from urllib.error import HTTPError

        collector = AbuseIPDBCollector(api_key="test")
        err = HTTPError("url", 422, "Invalid IP", {}, None)
        with patch("collectors.abuseipdb.urlopen", side_effect=err):
            assert collector._check_ip("bogus") is None

    def test_429_returns_none(self):
        from urllib.error import HTTPError

        collector = AbuseIPDBCollector(api_key="test")
        err = HTTPError("url", 429, "Rate Limited", {}, None)
        with patch("collectors.abuseipdb.urlopen", side_effect=err):
            assert collector._check_ip("8.8.8.8") is None


# ---------------------------------------------------------------------------
# query() is an intentional stub
# ---------------------------------------------------------------------------

class TestQueryStub:

    def test_query_returns_none(self):
        collector = AbuseIPDBCollector(api_key="test")
        assert collector.query("APT28") is None
