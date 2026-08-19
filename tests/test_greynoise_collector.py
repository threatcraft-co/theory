"""
tests/test_greynoise_collector.py
----------------------------------
Unit tests for collectors/greynoise.py — fully offline.

GreyNoise is a post-processor: it takes existing IP indicators and
annotates each with noise/RIOT/classification context. Tests cover
the private IP filter, cache, and _lookup_ip HTTP handling paths.
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock

from collectors.greynoise import GreyNoiseCollector, _is_private, _ip_hash


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


# ---------------------------------------------------------------------------
# _ip_hash tests
# ---------------------------------------------------------------------------

class TestIpHash:

    def test_deterministic(self):
        assert _ip_hash("1.2.3.4") == _ip_hash("1.2.3.4")

    def test_different_ips_different_hashes(self):
        assert _ip_hash("1.2.3.4") != _ip_hash("1.2.3.5")

    def test_length_capped(self):
        # Must fit in a safe cache filename
        assert len(_ip_hash("1.2.3.4")) == 16


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------

class TestGreyNoiseCache:

    def test_save_and_load(self, tmp_path, monkeypatch):
        import collectors.greynoise as gn_module
        monkeypatch.setattr(gn_module, "CACHE_DIR", tmp_path)

        collector = GreyNoiseCollector(api_key="test")
        context = {
            "noise":          True,
            "riot":           False,
            "classification": "malicious",
            "name":           "",
            "last_seen":      "2026-08-01",
            "link":           "https://viz.greynoise.io/ip/1.2.3.4",
        }
        collector._save_cache("1.2.3.4", context)
        loaded = collector._load_cache("1.2.3.4")
        assert loaded == context

    def test_missing_returns_none(self, tmp_path, monkeypatch):
        import collectors.greynoise as gn_module
        monkeypatch.setattr(gn_module, "CACHE_DIR", tmp_path)

        collector = GreyNoiseCollector(api_key="test")
        assert collector._load_cache("1.2.3.4") is None

    def test_stale_cache_returns_none(self, tmp_path, monkeypatch):
        import collectors.greynoise as gn_module
        monkeypatch.setattr(gn_module, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(gn_module, "CACHE_TTL_DAYS", 0)

        collector = GreyNoiseCollector(api_key="test")
        collector._save_cache("1.2.3.4", {"noise": True})
        assert collector._load_cache("1.2.3.4") is None


# ---------------------------------------------------------------------------
# enrich_ips end-to-end
# ---------------------------------------------------------------------------

class TestEnrichIps:

    def test_missing_api_key_returns_empty(self):
        collector = GreyNoiseCollector(api_key="")
        result = collector.enrich_ips(
            [{"type": "ip", "value": "8.8.8.8"}],
            "APT28",
        )
        assert result == {}

    def test_no_ip_indicators_returns_empty(self, tmp_path, monkeypatch):
        import collectors.greynoise as gn_module
        monkeypatch.setattr(gn_module, "CACHE_DIR", tmp_path)

        collector = GreyNoiseCollector(api_key="test")
        result = collector.enrich_ips(
            [{"type": "domain", "value": "evil.com"}],
            "APT28",
        )
        assert result == {}

    def test_private_ips_filtered(self, tmp_path, monkeypatch):
        import collectors.greynoise as gn_module
        monkeypatch.setattr(gn_module, "CACHE_DIR", tmp_path)

        collector = GreyNoiseCollector(api_key="test")
        indicators = [
            {"type": "ip", "value": "10.0.0.1"},
            {"type": "ip", "value": "192.168.1.1"},
            {"type": "ip", "value": "127.0.0.1"},
        ]
        # No public IPs -> should return empty without any HTTP calls.
        with patch.object(collector, "_lookup_ip") as mock_lookup:
            result = collector.enrich_ips(indicators, "APT28")
        assert result == {}
        mock_lookup.assert_not_called()

    def test_uses_cache_before_live_lookup(self, tmp_path, monkeypatch):
        import collectors.greynoise as gn_module
        monkeypatch.setattr(gn_module, "CACHE_DIR", tmp_path)

        collector = GreyNoiseCollector(api_key="test")
        cached = {
            "noise": True, "riot": False, "classification": "malicious",
            "name": "", "last_seen": "2026-08-01", "link": "",
        }
        collector._save_cache("8.8.8.8", cached)

        with patch.object(collector, "_lookup_ip") as mock_lookup:
            result = collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        assert result["8.8.8.8"] == cached
        mock_lookup.assert_not_called()

    def test_live_lookup_populates_cache(self, tmp_path, monkeypatch):
        import collectors.greynoise as gn_module
        monkeypatch.setattr(gn_module, "CACHE_DIR", tmp_path)

        collector = GreyNoiseCollector(api_key="test")
        fake_context = {
            "noise": True, "riot": False, "classification": "malicious",
            "name": "", "last_seen": "2026-08-01", "link": "",
        }
        with patch.object(collector, "_lookup_ip", return_value=fake_context):
            result = collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        assert result["8.8.8.8"] == fake_context
        # And it should be cached for next time
        assert collector._load_cache("8.8.8.8") == fake_context

    def test_lookup_miss_still_writes_neutral_cache(self, tmp_path, monkeypatch):
        # Rationale: caching the miss prevents burning the tiny 50/week
        # Community quota on the same never-seen IP on every run.
        import collectors.greynoise as gn_module
        monkeypatch.setattr(gn_module, "CACHE_DIR", tmp_path)

        collector = GreyNoiseCollector(api_key="test")
        with patch.object(collector, "_lookup_ip", return_value=None):
            collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        cached = collector._load_cache("8.8.8.8")
        assert cached is not None
        assert cached["classification"] == "unknown"

    def test_deduplicates_ips(self, tmp_path, monkeypatch):
        import collectors.greynoise as gn_module
        monkeypatch.setattr(gn_module, "CACHE_DIR", tmp_path)

        collector = GreyNoiseCollector(api_key="test")
        indicators = [
            {"type": "ip", "value": "8.8.8.8"},
            {"type": "ip", "value": "8.8.8.8"},
        ]
        with patch.object(collector, "_lookup_ip",
                          return_value={"noise": False, "riot": True,
                                         "classification": "benign",
                                         "name": "Google Public DNS",
                                         "last_seen": "", "link": ""}) as mock:
            collector.enrich_ips(indicators, "APT28")
        # Only one lookup should have been made even though the IP appeared twice.
        assert mock.call_count == 1

    def test_run_cap_enforced(self, tmp_path, monkeypatch):
        # Community tier is only 50/week — cap conservative at 25/run.
        import collectors.greynoise as gn_module
        monkeypatch.setattr(gn_module, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(gn_module, "MAX_IPS_PER_RUN", 3)

        collector = GreyNoiseCollector(api_key="test")
        # 10 unique public IPs
        indicators = [{"type": "ip", "value": f"8.8.8.{i}"} for i in range(10)]

        with patch.object(collector, "_lookup_ip",
                          return_value={"noise": False, "riot": False,
                                         "classification": "unknown",
                                         "name": "", "last_seen": "",
                                         "link": ""}) as mock:
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
        collector = GreyNoiseCollector(api_key="test")
        response = self._mock_response({
            "ip":             "8.8.8.8",
            "noise":          False,
            "riot":           True,
            "classification": "benign",
            "name":           "Google Public DNS",
            "last_seen":      "2026-08-01",
            "link":           "https://viz.greynoise.io/ip/8.8.8.8",
            "message":        "Success",
        })
        with patch("collectors.greynoise.urlopen", return_value=response):
            result = collector._lookup_ip("8.8.8.8")
        assert result is not None
        assert result["riot"] is True
        assert result["classification"] == "benign"
        assert result["name"] == "Google Public DNS"

    def test_success_but_unknown_message_returns_none(self):
        collector = GreyNoiseCollector(api_key="test")
        response = self._mock_response({"message": "IP not observed"})
        with patch("collectors.greynoise.urlopen", return_value=response):
            result = collector._lookup_ip("8.8.8.8")
        assert result is None

    def test_404_returns_none(self):
        from urllib.error import HTTPError

        collector = GreyNoiseCollector(api_key="test")
        err = HTTPError("url", 404, "Not Found", {}, None)
        with patch("collectors.greynoise.urlopen", side_effect=err):
            assert collector._lookup_ip("8.8.8.8") is None

    def test_429_returns_none(self):
        from urllib.error import HTTPError

        collector = GreyNoiseCollector(api_key="test")
        err = HTTPError("url", 429, "Rate Limited", {}, None)
        with patch("collectors.greynoise.urlopen", side_effect=err):
            assert collector._lookup_ip("8.8.8.8") is None


# ---------------------------------------------------------------------------
# query() is an intentional stub
# ---------------------------------------------------------------------------

class TestQueryStub:

    def test_query_returns_none(self):
        collector = GreyNoiseCollector(api_key="test")
        assert collector.query("APT28") is None
