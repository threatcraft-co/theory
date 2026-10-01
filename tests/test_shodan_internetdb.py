"""
tests/test_shodan_internetdb.py
---------------------------------
Unit tests for collectors/shodan_internetdb.py — fully offline.

Shodan InternetDB is a post-processor, same shape as GreyNoise/AbuseIPDB:
it takes existing IP indicators and annotates each with open-port/CVE
context. Tests cover the private-IP filter, cache, MAX_IPS_PER_RUN
capping, and _lookup_ip HTTP handling (including the 404-means-no-data
path, which is InternetDB-specific).
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock

from collectors.shodan_internetdb import ShodanInternetDBCollector, _is_private, _ip_hash


# ---------------------------------------------------------------------------
# _is_private tests
# ---------------------------------------------------------------------------

class TestIsPrivate:

    def test_rfc1918_10(self):
        assert _is_private("10.0.0.1") is True

    def test_rfc1918_192(self):
        assert _is_private("192.168.1.1") is True

    def test_rfc1918_172_16(self):
        assert _is_private("172.16.0.1") is True

    def test_loopback(self):
        assert _is_private("127.0.0.1") is True

    def test_link_local(self):
        assert _is_private("169.254.1.1") is True

    def test_ipv6_loopback(self):
        assert _is_private("::1") is True

    def test_ipv6_link_local(self):
        assert _is_private("fe80::1") is True

    def test_ipv6_unique_local(self):
        assert _is_private("fd00::1") is True

    def test_public_ipv4(self):
        assert _is_private("8.8.8.8") is False

    def test_public_ipv4_not_reserved(self):
        assert _is_private("185.220.101.1") is False

    def test_invalid_ip_treated_as_private(self):
        # Not a parseable IP at all -> don't waste a lookup on it.
        assert _is_private("not-an-ip") is True


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

class TestShodanCache:

    def test_save_and_load(self, tmp_path, monkeypatch):
        import collectors.shodan_internetdb as sdb_module
        monkeypatch.setattr(sdb_module, "CACHE_DIR", tmp_path)

        collector = ShodanInternetDBCollector()
        context = {
            "ports":     [22, 80, 443],
            "hostnames": ["example.com"],
            "cpes":      ["cpe:/a:openssh:openssh:8.2"],
            "tags":      ["cloud"],
            "vulns":     ["CVE-2021-1234"],
        }
        collector._save_cache("1.2.3.4", context)
        loaded = collector._load_cache("1.2.3.4")
        assert loaded == context

    def test_missing_returns_none(self, tmp_path, monkeypatch):
        import collectors.shodan_internetdb as sdb_module
        monkeypatch.setattr(sdb_module, "CACHE_DIR", tmp_path)

        collector = ShodanInternetDBCollector()
        assert collector._load_cache("1.2.3.4") is None

    def test_stale_cache_returns_none(self, tmp_path, monkeypatch):
        import collectors.shodan_internetdb as sdb_module
        monkeypatch.setattr(sdb_module, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(sdb_module, "CACHE_TTL_HOURS", 0)

        collector = ShodanInternetDBCollector()
        collector._save_cache("1.2.3.4", dict(sdb_module._EMPTY_RESULT))
        assert collector._load_cache("1.2.3.4") is None

    def test_corrupt_cache_file_returns_none(self, tmp_path, monkeypatch):
        import collectors.shodan_internetdb as sdb_module
        monkeypatch.setattr(sdb_module, "CACHE_DIR", tmp_path)

        collector = ShodanInternetDBCollector()
        cache_path = tmp_path / f"{_ip_hash('1.2.3.4')}.json"
        tmp_path.mkdir(parents=True, exist_ok=True)
        cache_path.write_text("not valid json{{{", encoding="utf-8")
        assert collector._load_cache("1.2.3.4") is None


# ---------------------------------------------------------------------------
# enrich_ips end-to-end
# ---------------------------------------------------------------------------

class TestEnrichIps:

    def test_no_ip_indicators_returns_empty(self, tmp_path, monkeypatch):
        import collectors.shodan_internetdb as sdb_module
        monkeypatch.setattr(sdb_module, "CACHE_DIR", tmp_path)

        collector = ShodanInternetDBCollector()
        result = collector.enrich_ips(
            [{"type": "domain", "value": "evil.com"}],
            "APT28",
        )
        assert result == {}

    def test_empty_indicator_list_returns_empty(self, tmp_path, monkeypatch):
        import collectors.shodan_internetdb as sdb_module
        monkeypatch.setattr(sdb_module, "CACHE_DIR", tmp_path)

        collector = ShodanInternetDBCollector()
        assert collector.enrich_ips([], "APT28") == {}

    def test_private_ips_filtered(self, tmp_path, monkeypatch):
        import collectors.shodan_internetdb as sdb_module
        monkeypatch.setattr(sdb_module, "CACHE_DIR", tmp_path)

        collector = ShodanInternetDBCollector()
        indicators = [
            {"type": "ip", "value": "10.0.0.1"},
            {"type": "ip", "value": "192.168.1.1"},
            {"type": "ip", "value": "127.0.0.1"},
        ]
        with patch.object(collector, "_lookup_ip") as mock_lookup:
            result = collector.enrich_ips(indicators, "APT28")
        assert result == {}
        mock_lookup.assert_not_called()

    def test_uses_cache_before_live_lookup(self, tmp_path, monkeypatch):
        import collectors.shodan_internetdb as sdb_module
        monkeypatch.setattr(sdb_module, "CACHE_DIR", tmp_path)

        collector = ShodanInternetDBCollector()
        cached = {
            "ports": [22, 443], "hostnames": [], "cpes": [], "tags": [], "vulns": [],
        }
        collector._save_cache("8.8.8.8", cached)

        with patch.object(collector, "_lookup_ip") as mock_lookup:
            result = collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        assert result["8.8.8.8"] == cached
        mock_lookup.assert_not_called()

    def test_live_lookup_populates_cache(self, tmp_path, monkeypatch):
        import collectors.shodan_internetdb as sdb_module
        monkeypatch.setattr(sdb_module, "CACHE_DIR", tmp_path)

        collector = ShodanInternetDBCollector()
        fake_context = {
            "ports": [22, 80, 443], "hostnames": ["example.com"],
            "cpes": [], "tags": [], "vulns": ["CVE-2021-1234"],
        }
        with patch.object(collector, "_lookup_ip", return_value=fake_context):
            result = collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        assert result["8.8.8.8"] == fake_context
        assert collector._load_cache("8.8.8.8") == fake_context

    def test_lookup_404_miss_still_writes_empty_cache(self, tmp_path, monkeypatch):
        # Rationale: caching the 404 as an empty result means a re-run
        # doesn't keep re-querying an IP Shodan has nothing on.
        import collectors.shodan_internetdb as sdb_module
        monkeypatch.setattr(sdb_module, "CACHE_DIR", tmp_path)

        collector = ShodanInternetDBCollector()
        with patch.object(collector, "_lookup_ip", return_value=None):
            result = collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        # Miss -> not included in the returned results dict...
        assert "8.8.8.8" not in result
        # ...but the miss itself is cached as an empty result.
        cached = collector._load_cache("8.8.8.8")
        assert cached == dict(sdb_module._EMPTY_RESULT)

    def test_deduplicates_ips(self, tmp_path, monkeypatch):
        import collectors.shodan_internetdb as sdb_module
        monkeypatch.setattr(sdb_module, "CACHE_DIR", tmp_path)

        collector = ShodanInternetDBCollector()
        indicators = [
            {"type": "ip", "value": "8.8.8.8"},
            {"type": "ip", "value": "8.8.8.8"},
        ]
        with patch.object(collector, "_lookup_ip",
                          return_value={"ports": [53], "hostnames": [],
                                         "cpes": [], "tags": [], "vulns": []}) as mock:
            collector.enrich_ips(indicators, "APT28")
        assert mock.call_count == 1

    def test_run_cap_enforced(self, tmp_path, monkeypatch):
        import collectors.shodan_internetdb as sdb_module
        monkeypatch.setattr(sdb_module, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(sdb_module, "MAX_IPS_PER_RUN", 3)

        collector = ShodanInternetDBCollector()
        indicators = [{"type": "ip", "value": f"8.8.8.{i}"} for i in range(10)]

        with patch.object(collector, "_lookup_ip",
                          return_value={"ports": [], "hostnames": [],
                                         "cpes": [], "tags": [], "vulns": []}) as mock:
            collector.enrich_ips(indicators, "APT28")

        assert mock.call_count == 3


# ---------------------------------------------------------------------------
# _lookup_ip HTTP handling
# ---------------------------------------------------------------------------

class TestLookupIp:

    def _mock_response(self, payload: dict) -> MagicMock:
        m = MagicMock()
        m.__enter__ = lambda self: m
        m.__exit__  = lambda self, *args: None
        m.read.return_value = json.dumps(payload).encode()
        return m

    def test_success_returns_context(self):
        collector = ShodanInternetDBCollector()
        response = self._mock_response({
            "ip":        "8.8.8.8",
            "ports":     [443, 80, 22],
            "hostnames": ["dns.google"],
            "cpes":      ["cpe:/a:openssh:openssh:8.2"],
            "tags":      ["cloud"],
            "vulns":     ["CVE-2021-5678", "CVE-2021-1234"],
        })
        with patch("collectors.shodan_internetdb.urlopen", return_value=response):
            result = collector._lookup_ip("8.8.8.8")
        assert result is not None
        # ports and vulns are sorted
        assert result["ports"] == [22, 80, 443]
        assert result["vulns"] == ["CVE-2021-1234", "CVE-2021-5678"]
        assert result["hostnames"] == ["dns.google"]
        assert result["tags"] == ["cloud"]

    def test_missing_fields_default_to_empty_lists(self):
        collector = ShodanInternetDBCollector()
        response = self._mock_response({"ip": "8.8.8.8"})
        with patch("collectors.shodan_internetdb.urlopen", return_value=response):
            result = collector._lookup_ip("8.8.8.8")
        assert result == {"ports": [], "hostnames": [], "cpes": [], "tags": [], "vulns": []}

    def test_404_returns_none(self):
        from urllib.error import HTTPError

        collector = ShodanInternetDBCollector()
        err = HTTPError("url", 404, "Not Found", {}, None)
        with patch("collectors.shodan_internetdb.urlopen", side_effect=err):
            assert collector._lookup_ip("8.8.8.8") is None

    def test_other_http_error_retries_then_returns_none(self):
        from urllib.error import HTTPError

        collector = ShodanInternetDBCollector()
        err = HTTPError("url", 500, "Server Error", {}, None)
        with patch("collectors.shodan_internetdb.urlopen", side_effect=err), \
             patch("collectors.shodan_internetdb.time.sleep"):
            assert collector._lookup_ip("8.8.8.8") is None

    def test_url_error_retries_then_returns_none(self):
        from urllib.error import URLError

        collector = ShodanInternetDBCollector()
        err = URLError("connection refused")
        with patch("collectors.shodan_internetdb.urlopen", side_effect=err), \
             patch("collectors.shodan_internetdb.time.sleep"):
            assert collector._lookup_ip("8.8.8.8") is None


# ---------------------------------------------------------------------------
# query() is an intentional stub — enrichment-only collector
# ---------------------------------------------------------------------------

class TestQueryStub:

    def test_query_returns_none(self):
        collector = ShodanInternetDBCollector()
        assert collector.query("APT28") is None

    def test_requires_api_key_is_false(self):
        assert ShodanInternetDBCollector.REQUIRES_API_KEY is False

    def test_is_available_without_key(self):
        collector = ShodanInternetDBCollector()
        assert collector.is_available() is True
