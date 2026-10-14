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

import logging
from datetime import timedelta
from unittest.mock import patch

import pytest

import collectors.abuseipdb as aipdb_module
from tests._http_fakes import http_error, net_error, ok, raw, seam
from theory.disk_cache import DiskCache
from theory.http_client import BadResponse, HttpError, RateLimited, TransportError


def make_collector(tmp_path, clock=None):
    """A collector whose cache lives in tmp_path (never the real cache dir)."""
    collector = AbuseIPDBCollector(api_key="test")
    kwargs = {"clock": clock} if clock else {}
    collector._cache = DiskCache(
        "abuseipdb", ttl=timedelta(days=aipdb_module.CACHE_TTL_DAYS),
        root=tmp_path, **kwargs,
    )
    return collector


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
from collectors.abuseipdb import AbuseIPDBCollector


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------

class TestAbuseIPDBCache:

    def test_save_and_load(self, tmp_path):

        collector = make_collector(tmp_path)
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
        collector._cache.put("1.2.3.4", context)
        assert collector._cache.get("1.2.3.4").value == context

    def test_missing_returns_none(self, tmp_path):

        collector = make_collector(tmp_path)
        assert collector._cache.get("1.2.3.4") is None

    def test_stale_cache_returns_none(self, tmp_path):
        now = [1_000_000.0]
        collector = make_collector(tmp_path, clock=lambda: now[0])
        collector._cache.put("1.2.3.4", {"abuse_confidence_score": 50})
        now[0] += 4 * 86400   # TTL is 3 days
        assert collector._cache.get("1.2.3.4") is None


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

    def test_missing_api_key_returns_empty(self, monkeypatch):
        # Passing api_key="" alone isn't enough to test the "no key"
        # path — the collector falls back to os.environ.get("ABUSEIPDB_API_KEY")
        # when the constructor arg is falsy, so a real key in the
        # environment (e.g. from a developer's .env) silently masks
        # this test unless the env var itself is cleared too.
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        collector = AbuseIPDBCollector(api_key="")
        result = collector.enrich_ips(
            [{"type": "ip", "value": "8.8.8.8"}], "APT28",
        )
        assert result == {}

    def test_no_ip_indicators_returns_empty(self, tmp_path):

        collector = make_collector(tmp_path)
        result = collector.enrich_ips(
            [{"type": "hash_sha256", "value": "a" * 64}], "APT28",
        )
        assert result == {}

    def test_private_ips_filtered(self, tmp_path):

        collector = make_collector(tmp_path)
        indicators = [
            {"type": "ip", "value": "10.0.0.1"},
            {"type": "ip", "value": "192.168.1.1"},
        ]
        with patch.object(collector, "_check_ip") as mock:
            result = collector.enrich_ips(indicators, "APT28")
        assert result == {}
        mock.assert_not_called()

    def test_uses_cache_before_live_lookup(self, tmp_path):

        collector = make_collector(tmp_path)
        cached = self._fake_context()
        collector._cache.put("8.8.8.8", cached)

        with patch.object(collector, "_check_ip") as mock:
            result = collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        assert result["8.8.8.8"] == cached
        mock.assert_not_called()

    def test_live_lookup_populates_cache(self, tmp_path):

        collector = make_collector(tmp_path)
        ctx = self._fake_context()
        with patch.object(collector, "_check_ip", return_value=ctx):
            result = collector.enrich_ips(
                [{"type": "ip", "value": "8.8.8.8"}], "APT28",
            )
        assert result["8.8.8.8"] == ctx
        assert collector._cache.get("8.8.8.8").value == ctx

    def test_lookup_miss_is_remembered_and_left_out(self, tmp_path):
        # The old code wrote a sentinel dict (abuse_confidence_score = -1) that
        # a *later* run then annotated onto the IOC, while the run that
        # created it did not. A miss is now a real "nothing on file" entry
        # and is left out of results every time.
        collector = make_collector(tmp_path)
        with patch.object(collector, "_check_ip", return_value=None) as check:
            first = collector.enrich_ips([{"type": "ip", "value": "8.8.8.8"}], "APT28")
            second = collector.enrich_ips([{"type": "ip", "value": "8.8.8.8"}], "APT28")
        assert first == second == {}
        assert collector._cache.get("8.8.8.8").is_miss
        assert check.call_count == 1

    def test_deduplicates_ips(self, tmp_path):

        collector = make_collector(tmp_path)
        indicators = [
            {"type": "ip", "value": "8.8.8.8"},
            {"type": "ip", "value": "8.8.8.8"},
        ]
        with patch.object(collector, "_check_ip",
                          return_value=self._fake_context()) as mock:
            collector.enrich_ips(indicators, "APT28")
        assert mock.call_count == 1

    def test_run_cap_enforced(self, tmp_path, monkeypatch):
        monkeypatch.setattr(aipdb_module, "MAX_IPS_PER_RUN", 5)

        collector = make_collector(tmp_path)
        indicators = [{"type": "ip", "value": f"8.8.8.{i}"} for i in range(20)]
        with patch.object(collector, "_check_ip",
                          return_value=self._fake_context()) as mock:
            collector.enrich_ips(indicators, "APT28")
        assert mock.call_count == 5


# ---------------------------------------------------------------------------
# _check_ip HTTP handling
# ---------------------------------------------------------------------------

class TestCheckIp:

    PAYLOAD = {
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

    def test_success_returns_context(self):
        collector = AbuseIPDBCollector(api_key="test")
        with seam(ok(self.PAYLOAD)) as urlopen:
            result = collector._check_ip("8.8.8.8")
        assert result is not None
        assert result["abuse_confidence_score"] == 95
        assert result["country_code"] == "CN"
        req = urlopen.call_args.args[0]
        assert req.get_header("Key") == "test"
        assert "ipAddress=8.8.8.8" in req.full_url
        assert "maxAgeInDays=90" in req.full_url

    def test_empty_data_returns_none(self):
        collector = AbuseIPDBCollector(api_key="test")
        with seam(ok({"data": {}})):
            assert collector._check_ip("8.8.8.8") is None

    def test_422_is_a_remembered_miss(self):
        """AbuseIPDB answers 422 for addresses it will never score. That is
        deterministic for the input, so it is a real (cacheable) answer."""
        collector = AbuseIPDBCollector(api_key="test")
        with seam(http_error(422)):
            assert collector._check_ip("bogus") is None

    def test_429_is_an_error_not_an_answer(self):
        """The old code returned None here and the caller cached a sentinel
        score of -1 for three days, for every IP left in the run."""
        collector = AbuseIPDBCollector(api_key="test")
        with seam(http_error(429)) as urlopen, pytest.raises(RateLimited):
            collector._check_ip("8.8.8.8")
        assert urlopen.call_count == 1   # daily quota: waiting will not help

    @pytest.mark.parametrize("failure", [
        pytest.param(lambda: http_error(503), id="5xx"),
        pytest.param(lambda: net_error("timed out"), id="network"),
    ])
    def test_transient_failures_raise(self, failure):
        collector = AbuseIPDBCollector(api_key="test")
        with seam(failure(), repeat_last=True), pytest.raises(TransportError):
            collector._check_ip("8.8.8.8")

    def test_bad_key_raises(self):
        collector = AbuseIPDBCollector(api_key="test")
        with seam(http_error(401)), pytest.raises(HttpError):
            collector._check_ip("8.8.8.8")

    def test_garbage_body_raises(self):
        collector = AbuseIPDBCollector(api_key="test")
        with seam(raw(b"<html>")), pytest.raises(BadResponse):
            collector._check_ip("8.8.8.8")


# ---------------------------------------------------------------------------
# End to end through the real client: what a failure does to the cache
# ---------------------------------------------------------------------------

def public_ips(n):
    return [{"type": "ip", "value": f"8.8.8.{i}"} for i in range(1, n + 1)]


class TestFailuresNeverBecomeCachedAnswers:
    def test_daily_quota_stops_the_run_and_poisons_nothing(self, tmp_path):
        """Regression: after a 429 the run said 'Stopping enrichment' but
        carried on, caching score -1 for every remaining IP for 3 days."""
        collector = make_collector(tmp_path)
        with seam(ok(TestCheckIp.PAYLOAD), http_error(429)) as urlopen:
            results = collector.enrich_ips(public_ips(5), "APT28")
        assert set(results) == {"8.8.8.1"}
        assert urlopen.call_count == 2
        for n in (2, 3, 4, 5):
            assert collector._cache.get(f"8.8.8.{n}") is None

    def test_next_run_picks_up_where_the_quota_stopped_it(self, tmp_path):
        collector = make_collector(tmp_path)
        with seam(ok(TestCheckIp.PAYLOAD), http_error(429)):
            collector.enrich_ips(public_ips(3), "APT28")
        with seam(ok(TestCheckIp.PAYLOAD), ok(TestCheckIp.PAYLOAD)) as urlopen:
            results = collector.enrich_ips(public_ips(3), "APT28")
        assert len(results) == 3 and urlopen.call_count == 2

    def test_outage_gives_up_quickly_and_caches_nothing(self, tmp_path):
        collector = make_collector(tmp_path)
        with seam(net_error("down"), repeat_last=True) as urlopen:
            assert collector.enrich_ips(public_ips(20), "APT28") == {}
        assert urlopen.call_count == 6          # 3 IPs x 2 attempts, then stop
        assert not list(tmp_path.glob("*.json"))

    def test_422_is_cached_as_a_miss(self, tmp_path):
        collector = make_collector(tmp_path)
        with seam(http_error(422)) as urlopen:
            first = collector.enrich_ips(public_ips(1), "APT28")
            second = collector.enrich_ips(public_ips(1), "APT28")
        assert first == second == {} and urlopen.call_count == 1
        assert collector._cache.get("8.8.8.1").is_miss

    def test_api_key_never_appears_in_logs(self, tmp_path, caplog):
        collector = AbuseIPDBCollector(api_key="sekrit-aipdb-key")
        collector._cache = DiskCache("abuseipdb", ttl=timedelta(days=1), root=tmp_path)
        caplog.set_level(logging.DEBUG)
        with seam(http_error(403), repeat_last=True):
            collector.enrich_ips(public_ips(3), "APT28")
        assert "sekrit-aipdb-key" not in caplog.text


# ---------------------------------------------------------------------------
# query() is an intentional stub
# ---------------------------------------------------------------------------

class TestQueryStub:

    def test_query_returns_none(self):
        collector = AbuseIPDBCollector(api_key="test")
        assert collector.query("APT28") is None
