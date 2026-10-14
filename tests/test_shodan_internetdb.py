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

from datetime import timedelta
from unittest.mock import patch

import pytest

import collectors.shodan_internetdb as sdb_module
from tests._http_fakes import http_error, net_error, ok, raw, seam
from theory.disk_cache import DiskCache
from theory.http_client import BadResponse, RateLimited, TransportError


def make_collector(tmp_path, clock=None):
    """A collector whose cache lives in tmp_path (never the real cache dir)."""
    collector = ShodanInternetDBCollector()
    kwargs = {"clock": clock} if clock else {}
    collector._cache = DiskCache(
        "shodan_internetdb", ttl=timedelta(hours=sdb_module.CACHE_TTL_HOURS),
        root=tmp_path, **kwargs,
    )
    return collector


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
from collectors.shodan_internetdb import ShodanInternetDBCollector


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------

class TestShodanCache:

    def test_save_and_load(self, tmp_path):

        collector = make_collector(tmp_path)
        context = {
            "ports":     [22, 80, 443],
            "hostnames": ["example.com"],
            "cpes":      ["cpe:/a:openssh:openssh:8.2"],
            "tags":      ["cloud"],
            "vulns":     ["CVE-2021-1234"],
        }
        collector._cache.put("1.2.3.4", context)
        loaded = collector._cache.get("1.2.3.4")
        assert loaded.value == context

    def test_missing_returns_none(self, tmp_path):

        collector = make_collector(tmp_path)
        assert collector._cache.get("1.2.3.4") is None

    def test_stale_cache_returns_none(self, tmp_path):
        now = [1_000_000.0]
        collector = make_collector(tmp_path, clock=lambda: now[0])
        collector._cache.put("1.2.3.4", {"ports": [22], "hostnames": [], "cpes": [], "tags": [], "vulns": []})
        now[0] += 25 * 3600   # TTL is 24 hours
        assert collector._cache.get("1.2.3.4") is None



# ---------------------------------------------------------------------------
# enrich_ips end-to-end
# ---------------------------------------------------------------------------

class TestEnrichIps:

    def test_no_ip_indicators_returns_empty(self, tmp_path):

        collector = make_collector(tmp_path)
        result = collector.enrich_ips(
            [{"type": "domain", "value": "evil.com"}],
            "APT28",
        )
        assert result == {}

    def test_empty_indicator_list_returns_empty(self, tmp_path):

        collector = make_collector(tmp_path)
        assert collector.enrich_ips([], "APT28") == {}

    def test_private_ips_filtered(self, tmp_path):

        collector = make_collector(tmp_path)
        indicators = [
            {"type": "ip", "value": "10.0.0.1"},
            {"type": "ip", "value": "192.168.1.1"},
            {"type": "ip", "value": "127.0.0.1"},
        ]
        with patch.object(collector, "_lookup_ip") as mock_lookup:
            result = collector.enrich_ips(indicators, "APT28")
        assert result == {}
        mock_lookup.assert_not_called()

    def test_uses_cache_before_live_lookup(self, tmp_path):

        collector = make_collector(tmp_path)
        cached = {
            "ports": [22, 443], "hostnames": [], "cpes": [], "tags": [], "vulns": [],
        }
        collector._cache.put("8.8.8.8", cached)

        with patch.object(collector, "_lookup_ip") as mock_lookup:
            result = collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        assert result["8.8.8.8"] == cached
        mock_lookup.assert_not_called()

    def test_live_lookup_populates_cache(self, tmp_path):

        collector = make_collector(tmp_path)
        fake_context = {
            "ports": [22, 80, 443], "hostnames": ["example.com"],
            "cpes": [], "tags": [], "vulns": ["CVE-2021-1234"],
        }
        with patch.object(collector, "_lookup_ip", return_value=fake_context):
            result = collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        assert result["8.8.8.8"] == fake_context
        assert collector._cache.get("8.8.8.8").value == fake_context

    def test_lookup_404_miss_is_remembered_and_left_out(self, tmp_path):
        # Rationale: remembering the 404 means a re-run doesn't keep
        # re-querying an IP Shodan has nothing on. It stays out of the
        # results, on the first run and on every run after.
        collector = make_collector(tmp_path)
        with patch.object(collector, "_lookup_ip", return_value=None) as lookup:
            first = collector.enrich_ips([{"type": "ip", "value": "8.8.8.8"}], "APT28")
            second = collector.enrich_ips([{"type": "ip", "value": "8.8.8.8"}], "APT28")
        assert first == second == {}
        assert collector._cache.get("8.8.8.8").is_miss
        assert lookup.call_count == 1

    def test_deduplicates_ips(self, tmp_path):

        collector = make_collector(tmp_path)
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
        monkeypatch.setattr(sdb_module, "MAX_IPS_PER_RUN", 3)

        collector = make_collector(tmp_path)
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

    def test_success_returns_context(self):
        collector = ShodanInternetDBCollector()
        with seam(ok({
            "ip":        "8.8.8.8",
            "ports":     [443, 80, 22],
            "hostnames": ["dns.google"],
            "cpes":      ["cpe:/a:openssh:openssh:8.2"],
            "tags":      ["cloud"],
            "vulns":     ["CVE-2021-5678", "CVE-2021-1234"],
        })) as urlopen:
            result = collector._lookup_ip("8.8.8.8")
        assert result is not None
        # ports and vulns are sorted
        assert result["ports"] == [22, 80, 443]
        assert result["vulns"] == ["CVE-2021-1234", "CVE-2021-5678"]
        assert result["hostnames"] == ["dns.google"]
        assert result["tags"] == ["cloud"]
        assert urlopen.call_args.args[0].full_url == f"{sdb_module.API_BASE}/8.8.8.8"

    def test_missing_fields_default_to_empty_lists(self):
        collector = ShodanInternetDBCollector()
        with seam(ok({"ip": "8.8.8.8"})):
            result = collector._lookup_ip("8.8.8.8")
        assert result == {"ports": [], "hostnames": [], "cpes": [], "tags": [], "vulns": []}

    def test_404_means_nothing_on_file(self):
        collector = ShodanInternetDBCollector()
        with seam(http_error(404)):
            assert collector._lookup_ip("8.8.8.8") is None

    def test_server_error_retries_then_raises(self):
        """Old behaviour: returned None, which the caller cached as a miss
        for 24 hours. A 500 says nothing about the IP."""
        collector = ShodanInternetDBCollector()
        with seam(http_error(500), repeat_last=True) as urlopen, pytest.raises(TransportError):
            collector._lookup_ip("8.8.8.8")
        assert urlopen.call_count == 2

    def test_network_error_retries_then_raises(self):
        collector = ShodanInternetDBCollector()
        with seam(net_error("connection refused"), repeat_last=True) as urlopen, \
                pytest.raises(TransportError):
            collector._lookup_ip("8.8.8.8")
        assert urlopen.call_count == 2

    def test_429_raises_rate_limited(self):
        collector = ShodanInternetDBCollector()
        with seam(http_error(429), repeat_last=True), pytest.raises(RateLimited):
            collector._lookup_ip("8.8.8.8")

    def test_garbage_body_raises(self):
        collector = ShodanInternetDBCollector()
        with seam(raw(b"<html>")), pytest.raises(BadResponse):
            collector._lookup_ip("8.8.8.8")


# ---------------------------------------------------------------------------
# End to end through the real client: what a failure does to the cache
# ---------------------------------------------------------------------------

def public_ips(n):
    return [{"type": "ip", "value": f"8.8.8.{i}"} for i in range(1, n + 1)]


class TestFailuresNeverBecomeCachedAnswers:
    def test_outage_gives_up_quickly_and_caches_nothing(self, tmp_path):
        collector = make_collector(tmp_path)
        with seam(net_error("down"), repeat_last=True) as urlopen:
            assert collector.enrich_ips(public_ips(20), "APT28") == {}
        assert urlopen.call_count == 6          # 3 IPs x 2 attempts, then stop
        assert not list(tmp_path.glob("*.json"))

    def test_rate_limit_stops_the_run_and_caches_nothing_further(self, tmp_path):
        collector = make_collector(tmp_path)
        ok_ip = ok({"ports": [22]})
        with seam(ok_ip, http_error(429), http_error(429)) as urlopen:
            results = collector.enrich_ips(public_ips(5), "APT28")
        assert set(results) == {"8.8.8.1"}
        for n in (2, 3, 4, 5):
            assert collector._cache.get(f"8.8.8.{n}") is None
        assert urlopen.call_count == 3          # 1 ok + 429 retried once, then stop

    def test_failure_then_recovery(self, tmp_path):
        collector = make_collector(tmp_path)
        with seam(net_error("blip"), repeat_last=True):
            collector.enrich_ips(public_ips(1), "APT28")
        with seam(ok({"ports": [443]})):
            results = collector.enrich_ips(public_ips(1), "APT28")
        assert results["8.8.8.1"]["ports"] == [443]

    def test_404_is_cached_as_a_miss(self, tmp_path):
        collector = make_collector(tmp_path)
        with seam(http_error(404)) as urlopen:
            first = collector.enrich_ips(public_ips(1), "APT28")
            second = collector.enrich_ips(public_ips(1), "APT28")
        assert first == second == {} and urlopen.call_count == 1


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
