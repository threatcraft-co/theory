"""
tests/test_urlscan_io.py
---------------------------
Unit tests for collectors/urlscan_io.py — fully offline.

urlscan.io is a post-processor like greynoise/abuseipdb/shodan_internetdb,
but enriches domain/URL indicators (not IPs) with public scan history.
Tests cover query building, cache, enrich_urls, and _lookup HTTP handling.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from unittest.mock import patch

import pytest

import collectors.urlscan_io as us_module
from tests._http_fakes import http_error, net_error, ok, raw, seam
from theory.disk_cache import DiskCache
from theory.http_client import BadResponse, RateLimited, TransportError


def make_collector(tmp_path, clock=None):
    """A collector whose cache lives in tmp_path (never the real cache dir)."""
    collector = URLScanIOCollector()
    kwargs = {"clock": clock} if clock else {}
    collector._cache = DiskCache(
        "urlscan_io", ttl=timedelta(hours=us_module.CACHE_TTL_HOURS),
        root=tmp_path, **kwargs,
    )
    return collector


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
from collectors.urlscan_io import URLScanIOCollector, _build_query


# ---------------------------------------------------------------------------
# _build_query tests
# ---------------------------------------------------------------------------

class TestBuildQuery:

    def test_domain_query(self):
        assert _build_query("domain", "evil.com") == "domain:evil.com"

    def test_url_query_quoted(self):
        assert _build_query("url", "http://evil.com/x") == 'page.url:"http://evil.com/x"'

    def test_unsupported_type_returns_none(self):
        assert _build_query("ip", "8.8.8.8") is None

    def test_hash_type_returns_none(self):
        assert _build_query("hash_sha256", "deadbeef") is None


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------

class TestURLScanCache:

    def test_save_and_load(self, tmp_path):

        collector = make_collector(tmp_path)
        context = {"scan_count": 2, "malicious_count": 1, "scans": [{"url": "http://evil.com"}]}
        collector._cache.put("evil.com", context)
        assert collector._cache.get("evil.com").value == context

    def test_missing_returns_none(self, tmp_path):

        collector = make_collector(tmp_path)
        assert collector._cache.get("evil.com") is None

    def test_stale_cache_returns_none(self, tmp_path):
        now = [1_000_000.0]
        collector = make_collector(tmp_path, clock=lambda: now[0])
        collector._cache.put("evil.com", {"scan_count": 1, "malicious_count": 0, "scans": []})
        now[0] += 25 * 3600   # TTL is 24 hours
        assert collector._cache.get("evil.com") is None



# ---------------------------------------------------------------------------
# enrich_urls end-to-end
# ---------------------------------------------------------------------------

class TestEnrichUrls:

    def test_no_eligible_indicators_returns_empty(self, tmp_path):

        collector = make_collector(tmp_path)
        result = collector.enrich_urls(
            [{"type": "ip", "value": "8.8.8.8"}, {"type": "hash_sha256", "value": "abc"}],
            "APT28",
        )
        assert result == {}

    def test_empty_indicator_list_returns_empty(self, tmp_path):

        collector = make_collector(tmp_path)
        assert collector.enrich_urls([], "APT28") == {}

    def test_deduplicates_values(self, tmp_path):

        collector = make_collector(tmp_path)
        indicators = [
            {"type": "domain", "value": "evil.com"},
            {"type": "domain", "value": "evil.com"},
        ]
        with patch.object(collector, "_lookup",
                          return_value={"scan_count": 1, "malicious_count": 0, "scans": []}) as mock:
            collector.enrich_urls(indicators, "APT28")
        assert mock.call_count == 1

    def test_uses_cache_before_live_lookup(self, tmp_path):

        collector = make_collector(tmp_path)
        cached = {"scan_count": 3, "malicious_count": 1, "scans": [{"url": "http://evil.com"}]}
        collector._cache.put("evil.com", cached)

        with patch.object(collector, "_lookup") as mock_lookup:
            result = collector.enrich_urls([{"type": "domain", "value": "evil.com"}], "APT28")
        assert result["evil.com"] == cached
        mock_lookup.assert_not_called()

    def test_cached_empty_result_not_included_in_results(self, tmp_path):

        collector = make_collector(tmp_path)
        collector._cache.put_miss("nobody-scanned-this.com")

        with patch.object(collector, "_lookup") as mock_lookup:
            result = collector.enrich_urls(
                [{"type": "domain", "value": "nobody-scanned-this.com"}], "APT28",
            )
        assert result == {}
        mock_lookup.assert_not_called()

    def test_live_lookup_with_hits_populates_results_and_cache(self, tmp_path):

        collector = make_collector(tmp_path)
        fake_context = {"scan_count": 2, "malicious_count": 1, "scans": [{"url": "http://evil.com", "malicious": True}]}
        with patch.object(collector, "_lookup", return_value=fake_context):
            result = collector.enrich_urls([{"type": "domain", "value": "evil.com"}], "APT28")
        assert result["evil.com"] == fake_context
        assert collector._cache.get("evil.com").value == fake_context

    def test_live_lookup_with_no_hits_is_remembered_but_not_returned(self, tmp_path):
        collector = make_collector(tmp_path)
        empty_context = {"scan_count": 0, "malicious_count": 0, "scans": []}
        with patch.object(collector, "_lookup", return_value=empty_context) as lookup:
            first = collector.enrich_urls([{"type": "domain", "value": "evil.com"}], "APT28")
            second = collector.enrich_urls([{"type": "domain", "value": "evil.com"}], "APT28")
        assert first == second == {}
        assert collector._cache.get("evil.com").is_miss
        assert lookup.call_count == 1

    def test_unsearchable_indicator_is_a_remembered_miss(self, tmp_path):
        collector = make_collector(tmp_path)
        with patch.object(collector, "_lookup", return_value=None):
            result = collector.enrich_urls([{"type": "domain", "value": "evil.com"}], "APT28")
        assert result == {}
        assert collector._cache.get("evil.com").is_miss

    def test_lookup_failure_is_not_cached(self, tmp_path):
        """Old behaviour: any failure was cached as an empty result for 24h."""
        collector = make_collector(tmp_path)
        with patch.object(collector, "_lookup", side_effect=TransportError("boom")):
            result = collector.enrich_urls([{"type": "domain", "value": "evil.com"}], "APT28")
        assert result == {}
        assert collector._cache.get("evil.com") is None

    def test_run_cap_enforced(self, tmp_path, monkeypatch):
        monkeypatch.setattr(us_module, "MAX_PER_RUN", 3)

        collector = make_collector(tmp_path)
        indicators = [{"type": "domain", "value": f"evil{i}.com"} for i in range(10)]

        with patch.object(collector, "_lookup",
                          return_value={"scan_count": 1, "malicious_count": 0, "scans": []}) as mock:
            collector.enrich_urls(indicators, "APT28")
        assert mock.call_count == 3

    def test_url_type_indicator_also_enriched(self, tmp_path):

        collector = make_collector(tmp_path)
        with patch.object(collector, "_lookup",
                          return_value={"scan_count": 1, "malicious_count": 1, "scans": []}) as mock:
            result = collector.enrich_urls(
                [{"type": "url", "value": "http://evil.com/payload"}], "APT28",
            )
        assert "http://evil.com/payload" in result
        mock.assert_called_once_with("url", "http://evil.com/payload")


# ---------------------------------------------------------------------------
# _lookup / _parse_results
# ---------------------------------------------------------------------------

class TestLookup:

    def test_success_parses_results(self):
        collector = URLScanIOCollector()
        response = ok({
            "results": [
                {
                    "page": {"url": "http://evil.com", "ip": "1.2.3.4", "country": "US"},
                    "task": {"time": "2026-08-01T00:00:00"},
                    "verdicts": {"overall": {"malicious": True, "score": 90}},
                    "tags": ["phishing"],
                },
            ],
        })
        with seam(response):
            result = collector._lookup("domain", "evil.com")
        assert result["scan_count"] == 1
        assert result["malicious_count"] == 1
        assert result["scans"][0]["ip"] == "1.2.3.4"
        assert result["scans"][0]["tags"] == ["phishing"]

    def test_empty_results_returns_zero_counts(self):
        collector = URLScanIOCollector()
        response = ok({"results": []})
        with seam(response):
            result = collector._lookup("domain", "never-scanned.example")
        assert result == {"scan_count": 0, "malicious_count": 0, "scans": []}

    def test_unsupported_ioc_type_returns_none(self):
        collector = URLScanIOCollector()
        assert collector._lookup("ip", "8.8.8.8") is None

    def test_404_returns_empty_result(self):
        collector = URLScanIOCollector()
        with seam(http_error(404)):
            result = collector._lookup("domain", "evil.com")
        assert result == {"scan_count": 0, "malicious_count": 0, "scans": []}

    def test_server_error_retries_then_raises(self):
        """Old behaviour: returned None, cached as an empty result for 24h."""
        collector = URLScanIOCollector()
        with seam(http_error(500), repeat_last=True) as urlopen, pytest.raises(TransportError):
            collector._lookup("domain", "evil.com")
        assert urlopen.call_count == 2

    def test_network_error_retries_then_raises(self):
        collector = URLScanIOCollector()
        with seam(net_error("connection refused"), repeat_last=True), pytest.raises(TransportError):
            collector._lookup("domain", "evil.com")

    def test_429_raises_rate_limited(self):
        collector = URLScanIOCollector()
        with seam(http_error(429), repeat_last=True), pytest.raises(RateLimited):
            collector._lookup("domain", "evil.com")

    def test_garbage_body_raises(self):
        collector = URLScanIOCollector()
        with seam(raw(b"<html>")), pytest.raises(BadResponse):
            collector._lookup("domain", "evil.com")

    def test_query_is_sent_url_encoded(self):
        collector = URLScanIOCollector()
        with seam(ok({"results": []})) as urlopen:
            collector._lookup("url", "http://evil.com/x?a=b")
        url = urlopen.call_args.args[0].full_url
        assert url.startswith(us_module.API_BASE + "?q=")
        assert " " not in url and '"' not in url

    def test_api_key_included_in_headers_when_set(self):
        collector = URLScanIOCollector(api_key="test-key")
        response = ok({"results": []})
        with seam(response) as urlopen:
            collector._lookup("domain", "evil.com")
        assert urlopen.call_args.args[0].get_header("Api-key") == "test-key"

    def test_truncates_to_max_results(self):
        collector = URLScanIOCollector()
        many_results = [
            {"page": {"url": f"http://evil{i}.com", "ip": "", "country": ""},
             "task": {"time": ""}, "verdicts": {"overall": {}}, "tags": []}
            for i in range(20)
        ]
        response = ok({"results": many_results})
        with seam(response):
            result = collector._lookup("domain", "evil.com")
        assert result["scan_count"] == 20  # total count preserved
        assert len(result["scans"]) == us_module.MAX_RESULTS  # but only a handful kept


# ---------------------------------------------------------------------------
# End to end through the real client: what a failure does to the cache
# ---------------------------------------------------------------------------

HIT = {"results": [{"page": {"url": "http://evil.com"}, "task": {}, "verdicts": {"overall": {}}}]}


def domains(n):
    return [{"type": "domain", "value": f"evil{i}.com"} for i in range(1, n + 1)]


class TestFailuresNeverBecomeCachedAnswers:
    def test_rate_limit_stops_the_run_and_blanks_nothing(self, tmp_path):
        """Regression: one 429 used to cache an empty result, for 24 hours,
        for every domain it touched."""
        collector = make_collector(tmp_path)
        with seam(ok(HIT), http_error(429), http_error(429)) as urlopen:
            results = collector.enrich_urls(domains(5), "APT28")
        assert set(results) == {"evil1.com"}
        for n in (2, 3, 4, 5):
            assert collector._cache.get(f"evil{n}.com") is None
        assert urlopen.call_count == 3

    def test_outage_gives_up_quickly_and_caches_nothing(self, tmp_path):
        collector = make_collector(tmp_path)
        with seam(net_error("down"), repeat_last=True) as urlopen:
            assert collector.enrich_urls(domains(20), "APT28") == {}
        assert urlopen.call_count == 6
        assert not list(tmp_path.glob("*.json"))

    def test_zero_scans_is_a_real_answer_and_is_remembered(self, tmp_path):
        collector = make_collector(tmp_path)
        with seam(ok({"results": []})) as urlopen:
            first = collector.enrich_urls(domains(1), "APT28")
            second = collector.enrich_urls(domains(1), "APT28")
        assert first == second == {} and urlopen.call_count == 1
        assert collector._cache.get("evil1.com").is_miss

    def test_failure_then_recovery(self, tmp_path):
        collector = make_collector(tmp_path)
        with seam(net_error("blip"), repeat_last=True):
            collector.enrich_urls(domains(1), "APT28")
        with seam(ok(HIT)):
            results = collector.enrich_urls(domains(1), "APT28")
        assert "evil1.com" in results

    def test_api_key_never_appears_in_logs(self, tmp_path, caplog):
        collector = URLScanIOCollector(api_key="sekrit-us-key")
        collector._cache = DiskCache("urlscan_io", ttl=timedelta(days=1), root=tmp_path)
        caplog.set_level(logging.DEBUG)
        with seam(http_error(403), repeat_last=True):
            collector.enrich_urls(domains(3), "APT28")
        assert "sekrit-us-key" not in caplog.text


# ---------------------------------------------------------------------------
# query() is an intentional stub — enrichment-only collector
# ---------------------------------------------------------------------------

class TestQueryStub:

    def test_query_returns_none(self):
        collector = URLScanIOCollector()
        assert collector.query("APT28") is None

    def test_requires_api_key_is_false(self):
        assert URLScanIOCollector.REQUIRES_API_KEY is False

    def test_is_available_without_key(self):
        collector = URLScanIOCollector()
        assert collector.is_available() is True
