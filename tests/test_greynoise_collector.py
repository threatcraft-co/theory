"""
tests/test_greynoise_collector.py
----------------------------------
Unit tests for collectors/greynoise.py — fully offline.

GreyNoise is a post-processor: it takes existing IP indicators and
annotates each with noise/RIOT/classification context. Tests cover
the private IP filter, cache, and _lookup_ip HTTP handling paths.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from unittest.mock import patch

import pytest

import collectors.greynoise as gn_module
from collectors.greynoise import GreyNoiseCollector
from tests._http_fakes import http_error, net_error, ok, seam
from theory.disk_cache import DiskCache
from theory.http_client import BadResponse, HttpError, RateLimited, TransportError


def make_collector(tmp_path, clock=None):
    """A collector whose cache lives in tmp_path (never the real cache dir)."""
    collector = GreyNoiseCollector(api_key="test")
    kwargs = {"clock": clock} if clock else {}
    collector._cache = DiskCache(
        "greynoise", ttl=timedelta(days=gn_module.CACHE_TTL_DAYS),
        root=tmp_path, **kwargs,
    )
    return collector


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------

class TestGreyNoiseCache:

    def test_save_and_load(self, tmp_path):

        collector = make_collector(tmp_path)
        context = {
            "noise":          True,
            "riot":           False,
            "classification": "malicious",
            "name":           "",
            "last_seen":      "2026-08-01",
            "link":           "https://viz.greynoise.io/ip/1.2.3.4",
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
        collector._cache.put("1.2.3.4", {"noise": True})
        now[0] += 8 * 86400   # TTL is 7 days
        assert collector._cache.get("1.2.3.4") is None


# ---------------------------------------------------------------------------
# enrich_ips end-to-end
# ---------------------------------------------------------------------------

class TestEnrichIps:

    def test_missing_api_key_returns_empty(self, monkeypatch):
        # api_key="" alone doesn't test the "no key" path — the collector
        # falls back to os.environ.get("GREYNOISE_API_KEY") when the
        # constructor arg is falsy, so a real key in the environment
        # (e.g. from a developer's .env) silently masks this test.
        monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
        collector = GreyNoiseCollector(api_key="")
        result = collector.enrich_ips(
            [{"type": "ip", "value": "8.8.8.8"}],
            "APT28",
        )
        assert result == {}

    def test_no_ip_indicators_returns_empty(self, tmp_path):

        collector = make_collector(tmp_path)
        result = collector.enrich_ips(
            [{"type": "domain", "value": "evil.com"}],
            "APT28",
        )
        assert result == {}

    def test_private_ips_filtered(self, tmp_path):

        collector = make_collector(tmp_path)
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

    def test_uses_cache_before_live_lookup(self, tmp_path):

        collector = make_collector(tmp_path)
        cached = {
            "noise": True, "riot": False, "classification": "malicious",
            "name": "", "last_seen": "2026-08-01", "link": "",
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
            "noise": True, "riot": False, "classification": "malicious",
            "name": "", "last_seen": "2026-08-01", "link": "",
        }
        with patch.object(collector, "_lookup_ip", return_value=fake_context):
            result = collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        assert result["8.8.8.8"] == fake_context
        # And it should be cached for next time
        assert collector._cache.get("8.8.8.8").value == fake_context

    def test_lookup_miss_is_remembered_and_left_out(self, tmp_path):
        # Rationale: remembering the miss prevents burning the tiny 50/week
        # Community quota on the same never-seen IP on every run. It stays
        # out of the results, so the first run and every later run annotate
        # exactly the same IPs.
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
                          return_value={"noise": False, "riot": True,
                                         "classification": "benign",
                                         "name": "Google Public DNS",
                                         "last_seen": "", "link": ""}) as mock:
            collector.enrich_ips(indicators, "APT28")
        # Only one lookup should have been made even though the IP appeared twice.
        assert mock.call_count == 1

    def test_run_cap_enforced(self, tmp_path, monkeypatch):
        # Community tier is only 50/week — cap conservative at 25/run.
        monkeypatch.setattr(gn_module, "MAX_IPS_PER_RUN", 3)

        collector = make_collector(tmp_path)
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

    def test_success_returns_context(self):
        collector = GreyNoiseCollector(api_key="test")
        response = ok({
            "ip":             "8.8.8.8",
            "noise":          False,
            "riot":           True,
            "classification": "benign",
            "name":           "Google Public DNS",
            "last_seen":      "2026-08-01",
            "link":           "https://viz.greynoise.io/ip/8.8.8.8",
            "message":        "Success",
        })
        with seam(response) as urlopen:
            result = collector._lookup_ip("8.8.8.8")
        assert result is not None
        assert result["riot"] is True
        assert result["classification"] == "benign"
        assert result["name"] == "Google Public DNS"
        req = urlopen.call_args.args[0]
        assert req.full_url == f"{gn_module.API_BASE}/8.8.8.8"
        assert req.get_header("Key") == "test"

    def test_success_but_unknown_message_returns_none(self):
        collector = GreyNoiseCollector(api_key="test")
        with seam(ok({"message": "IP not observed"})):
            assert collector._lookup_ip("8.8.8.8") is None

    def test_404_means_not_in_dataset(self):
        collector = GreyNoiseCollector(api_key="test")
        with seam(http_error(404)):
            assert collector._lookup_ip("8.8.8.8") is None

    def test_429_is_an_error_not_an_answer(self):
        """The old code returned None here, which the caller then cached as
        'GreyNoise has never seen this IP' for seven days."""
        collector = GreyNoiseCollector(api_key="test")
        with seam(http_error(429)) as urlopen, pytest.raises(RateLimited):
            collector._lookup_ip("8.8.8.8")
        assert urlopen.call_count == 1   # weekly quota: no point waiting it out

    @pytest.mark.parametrize("failure", [
        pytest.param(lambda: http_error(503), id="5xx"),
        pytest.param(lambda: net_error("timed out"), id="network"),
    ])
    def test_transient_failures_raise(self, failure):
        collector = GreyNoiseCollector(api_key="test")
        with seam(failure(), repeat_last=True), pytest.raises(TransportError):
            collector._lookup_ip("8.8.8.8")

    def test_bad_key_raises(self):
        collector = GreyNoiseCollector(api_key="test")
        with seam(http_error(401)), pytest.raises(HttpError):
            collector._lookup_ip("8.8.8.8")

    def test_garbage_body_raises(self):
        from tests._http_fakes import raw
        collector = GreyNoiseCollector(api_key="test")
        with seam(raw(b"<html>")), pytest.raises(BadResponse):
            collector._lookup_ip("8.8.8.8")


# ---------------------------------------------------------------------------
# End to end through the real client: what a failure does to the cache
# ---------------------------------------------------------------------------

SUCCESS = {
    "noise": True, "riot": False, "classification": "malicious", "name": "x",
    "last_seen": "2026-08-01", "link": "l", "message": "Success",
}


def public_ips(n):
    return [{"type": "ip", "value": f"8.8.8.{i}"} for i in range(1, n + 1)]


class TestFailuresNeverBecomeCachedAnswers:
    def test_rate_limit_stops_the_run_and_poisons_nothing(self, tmp_path):
        """Regression: after the Community quota ran out, every remaining IP
        used to be cached as classification 'unknown' for 7 days."""
        collector = make_collector(tmp_path)
        with seam(ok(SUCCESS), http_error(429)) as urlopen:
            results = collector.enrich_ips(public_ips(5), "APT28")
        assert set(results) == {"8.8.8.1"}
        assert urlopen.call_count == 2                   # stopped at the 429
        assert collector._cache.get("8.8.8.1") is not None
        for n in (2, 3, 4, 5):
            assert collector._cache.get(f"8.8.8.{n}") is None

    def test_next_run_retries_what_the_rate_limit_skipped(self, tmp_path):
        collector = make_collector(tmp_path)
        with seam(ok(SUCCESS), http_error(429)):
            collector.enrich_ips(public_ips(3), "APT28")
        with seam(ok(SUCCESS), ok(SUCCESS)) as urlopen:
            results = collector.enrich_ips(public_ips(3), "APT28")
        assert set(results) == {"8.8.8.1", "8.8.8.2", "8.8.8.3"}
        assert urlopen.call_count == 2                   # .1 came from cache

    def test_outage_gives_up_quickly_and_caches_nothing(self, tmp_path):
        collector = make_collector(tmp_path)
        with seam(net_error("down"), repeat_last=True) as urlopen:
            results = collector.enrich_ips(public_ips(20), "APT28")
        assert results == {}
        # 3 IPs x 2 attempts each, then the circuit breaker opens
        assert urlopen.call_count == 6
        assert not list(tmp_path.glob("*.json"))

    def test_404_is_cached_as_a_miss(self, tmp_path):
        collector = make_collector(tmp_path)
        with seam(http_error(404)) as urlopen:
            first = collector.enrich_ips(public_ips(1), "APT28")
            second = collector.enrich_ips(public_ips(1), "APT28")
        assert first == second == {}
        assert urlopen.call_count == 1
        assert collector._cache.get("8.8.8.1").is_miss

    def test_one_warning_when_the_run_is_cut_short(self, tmp_path, caplog):
        collector = make_collector(tmp_path)
        caplog.set_level(logging.WARNING, logger="collectors._enrich")
        with seam(http_error(429)):
            collector.enrich_ips(public_ips(3), "APT28")
        assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1
        assert "rate limited" in caplog.text and "not cached" in caplog.text

    def test_api_key_never_appears_in_logs(self, tmp_path, caplog):
        collector = GreyNoiseCollector(api_key="sekrit-gn-key")
        collector._cache = DiskCache("greynoise", ttl=timedelta(days=1), root=tmp_path)
        caplog.set_level(logging.DEBUG)
        with seam(http_error(403), repeat_last=True):
            collector.enrich_ips(public_ips(3), "APT28")
        assert "sekrit-gn-key" not in caplog.text


# ---------------------------------------------------------------------------
# query() is an intentional stub
# ---------------------------------------------------------------------------

class TestQueryStub:

    def test_query_returns_none(self):
        collector = GreyNoiseCollector(api_key="test")
        assert collector.query("APT28") is None
