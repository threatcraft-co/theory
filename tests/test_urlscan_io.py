"""
tests/test_urlscan_io.py
---------------------------
Unit tests for collectors/urlscan_io.py — fully offline.

urlscan.io is a post-processor like greynoise/abuseipdb/shodan_internetdb,
but enriches domain/URL indicators (not IPs) with public scan history.
Tests cover query building, cache, enrich_urls, and _lookup HTTP handling.
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock

from collectors.urlscan_io import URLScanIOCollector, _build_query, _key_hash


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
# _key_hash tests
# ---------------------------------------------------------------------------

class TestKeyHash:

    def test_deterministic(self):
        assert _key_hash("evil.com") == _key_hash("evil.com")

    def test_different_values_different_hashes(self):
        assert _key_hash("evil.com") != _key_hash("good.com")

    def test_length_capped(self):
        assert len(_key_hash("evil.com")) == 16


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------

class TestURLScanCache:

    def test_save_and_load(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)

        collector = URLScanIOCollector()
        context = {"scan_count": 2, "malicious_count": 1, "scans": [{"url": "http://evil.com"}]}
        collector._save_cache("evil.com", context)
        assert collector._load_cache("evil.com") == context

    def test_missing_returns_none(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)

        collector = URLScanIOCollector()
        assert collector._load_cache("evil.com") is None

    def test_stale_cache_returns_none(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(us_module, "CACHE_TTL_HOURS", 0)

        collector = URLScanIOCollector()
        collector._save_cache("evil.com", dict(us_module._EMPTY_RESULT))
        assert collector._load_cache("evil.com") is None

    def test_corrupt_cache_file_returns_none(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)

        collector = URLScanIOCollector()
        tmp_path.mkdir(parents=True, exist_ok=True)
        cache_path = tmp_path / f"{_key_hash('evil.com')}.json"
        cache_path.write_text("not valid json{{{", encoding="utf-8")
        assert collector._load_cache("evil.com") is None


# ---------------------------------------------------------------------------
# enrich_urls end-to-end
# ---------------------------------------------------------------------------

class TestEnrichUrls:

    def test_no_eligible_indicators_returns_empty(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)

        collector = URLScanIOCollector()
        result = collector.enrich_urls(
            [{"type": "ip", "value": "8.8.8.8"}, {"type": "hash_sha256", "value": "abc"}],
            "APT28",
        )
        assert result == {}

    def test_empty_indicator_list_returns_empty(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)

        collector = URLScanIOCollector()
        assert collector.enrich_urls([], "APT28") == {}

    def test_deduplicates_values(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)

        collector = URLScanIOCollector()
        indicators = [
            {"type": "domain", "value": "evil.com"},
            {"type": "domain", "value": "evil.com"},
        ]
        with patch.object(collector, "_lookup",
                          return_value={"scan_count": 1, "malicious_count": 0, "scans": []}) as mock:
            collector.enrich_urls(indicators, "APT28")
        assert mock.call_count == 1

    def test_uses_cache_before_live_lookup(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)

        collector = URLScanIOCollector()
        cached = {"scan_count": 3, "malicious_count": 1, "scans": [{"url": "http://evil.com"}]}
        collector._save_cache("evil.com", cached)

        with patch.object(collector, "_lookup") as mock_lookup:
            result = collector.enrich_urls([{"type": "domain", "value": "evil.com"}], "APT28")
        assert result["evil.com"] == cached
        mock_lookup.assert_not_called()

    def test_cached_empty_result_not_included_in_results(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)

        collector = URLScanIOCollector()
        collector._save_cache("nobody-scanned-this.com", dict(us_module._EMPTY_RESULT))

        with patch.object(collector, "_lookup") as mock_lookup:
            result = collector.enrich_urls(
                [{"type": "domain", "value": "nobody-scanned-this.com"}], "APT28",
            )
        assert result == {}
        mock_lookup.assert_not_called()

    def test_live_lookup_with_hits_populates_results_and_cache(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)

        collector = URLScanIOCollector()
        fake_context = {"scan_count": 2, "malicious_count": 1, "scans": [{"url": "http://evil.com", "malicious": True}]}
        with patch.object(collector, "_lookup", return_value=fake_context):
            result = collector.enrich_urls([{"type": "domain", "value": "evil.com"}], "APT28")
        assert result["evil.com"] == fake_context
        assert collector._load_cache("evil.com") == fake_context

    def test_live_lookup_with_no_hits_cached_but_not_returned(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)

        collector = URLScanIOCollector()
        empty_context = {"scan_count": 0, "malicious_count": 0, "scans": []}
        with patch.object(collector, "_lookup", return_value=empty_context):
            result = collector.enrich_urls([{"type": "domain", "value": "evil.com"}], "APT28")
        assert result == {}
        assert collector._load_cache("evil.com") == empty_context

    def test_lookup_failure_caches_empty_result(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)

        collector = URLScanIOCollector()
        with patch.object(collector, "_lookup", return_value=None):
            result = collector.enrich_urls([{"type": "domain", "value": "evil.com"}], "APT28")
        assert result == {}
        assert collector._load_cache("evil.com") == dict(us_module._EMPTY_RESULT)

    def test_run_cap_enforced(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(us_module, "MAX_PER_RUN", 3)

        collector = URLScanIOCollector()
        indicators = [{"type": "domain", "value": f"evil{i}.com"} for i in range(10)]

        with patch.object(collector, "_lookup",
                          return_value={"scan_count": 1, "malicious_count": 0, "scans": []}) as mock:
            collector.enrich_urls(indicators, "APT28")
        assert mock.call_count == 3

    def test_url_type_indicator_also_enriched(self, tmp_path, monkeypatch):
        import collectors.urlscan_io as us_module
        monkeypatch.setattr(us_module, "CACHE_DIR", tmp_path)

        collector = URLScanIOCollector()
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

    def _mock_response(self, payload: dict) -> MagicMock:
        m = MagicMock()
        m.__enter__ = lambda self: m
        m.__exit__  = lambda self, *args: None
        m.read.return_value = json.dumps(payload).encode()
        return m

    def test_success_parses_results(self):
        collector = URLScanIOCollector()
        response = self._mock_response({
            "results": [
                {
                    "page": {"url": "http://evil.com", "ip": "1.2.3.4", "country": "US"},
                    "task": {"time": "2026-08-01T00:00:00"},
                    "verdicts": {"overall": {"malicious": True, "score": 90}},
                    "tags": ["phishing"],
                },
            ],
        })
        with patch("collectors.urlscan_io.urlopen", return_value=response):
            result = collector._lookup("domain", "evil.com")
        assert result["scan_count"] == 1
        assert result["malicious_count"] == 1
        assert result["scans"][0]["ip"] == "1.2.3.4"
        assert result["scans"][0]["tags"] == ["phishing"]

    def test_empty_results_returns_zero_counts(self):
        collector = URLScanIOCollector()
        response = self._mock_response({"results": []})
        with patch("collectors.urlscan_io.urlopen", return_value=response):
            result = collector._lookup("domain", "never-scanned.example")
        assert result == {"scan_count": 0, "malicious_count": 0, "scans": []}

    def test_unsupported_ioc_type_returns_none(self):
        collector = URLScanIOCollector()
        assert collector._lookup("ip", "8.8.8.8") is None

    def test_404_returns_empty_result(self):
        from urllib.error import HTTPError

        collector = URLScanIOCollector()
        err = HTTPError("url", 404, "Not Found", {}, None)
        with patch("collectors.urlscan_io.urlopen", side_effect=err):
            result = collector._lookup("domain", "evil.com")
        assert result == {"scan_count": 0, "malicious_count": 0, "scans": []}

    def test_other_http_error_retries_then_returns_none(self):
        from urllib.error import HTTPError

        collector = URLScanIOCollector()
        err = HTTPError("url", 500, "Server Error", {}, None)
        with patch("collectors.urlscan_io.urlopen", side_effect=err), \
             patch("collectors.urlscan_io.time.sleep"):
            assert collector._lookup("domain", "evil.com") is None

    def test_url_error_retries_then_returns_none(self):
        from urllib.error import URLError

        collector = URLScanIOCollector()
        err = URLError("connection refused")
        with patch("collectors.urlscan_io.urlopen", side_effect=err), \
             patch("collectors.urlscan_io.time.sleep"):
            assert collector._lookup("domain", "evil.com") is None

    def test_api_key_included_in_headers_when_set(self):
        collector = URLScanIOCollector(api_key="test-key")
        response = self._mock_response({"results": []})
        captured_requests = []

        def fake_urlopen(req, timeout=None):
            captured_requests.append(req)
            return response

        with patch("collectors.urlscan_io.urlopen", side_effect=fake_urlopen):
            collector._lookup("domain", "evil.com")
        assert captured_requests[0].get_header("Api-key") == "test-key"

    def test_truncates_to_max_results(self):
        collector = URLScanIOCollector()
        many_results = [
            {"page": {"url": f"http://evil{i}.com", "ip": "", "country": ""},
             "task": {"time": ""}, "verdicts": {"overall": {}}, "tags": []}
            for i in range(20)
        ]
        response = self._mock_response({"results": many_results})
        with patch("collectors.urlscan_io.urlopen", return_value=response):
            result = collector._lookup("domain", "evil.com")
        import collectors.urlscan_io as us_module
        assert result["scan_count"] == 20  # total count preserved
        assert len(result["scans"]) == us_module.MAX_RESULTS  # but only a handful kept


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
