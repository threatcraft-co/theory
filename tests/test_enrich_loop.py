"""
tests/test_enrich_loop.py
-------------------------
The rules in collectors/_enrich.py, one test per rule.
"""

from __future__ import annotations

import logging
from datetime import timedelta

import pytest

from collectors._enrich import enrich_keys
from theory.disk_cache import DiskCache
from theory.http_client import BadResponse, HttpError, NotFound, RateLimited, TransportError

SRC = "TestSource"


@pytest.fixture(autouse=True)
def sleeps(monkeypatch):
    calls: list[float] = []
    monkeypatch.setattr("time.sleep", calls.append)
    return calls


@pytest.fixture
def cache(tmp_path):
    return DiskCache("enrich", ttl=timedelta(days=1), root=tmp_path)


class Loader:
    """Scripted per-key outcomes; records which keys were actually looked up."""

    def __init__(self, outcomes: dict):
        self.outcomes = outcomes
        self.calls: list[str] = []

    def __call__(self, key):
        self.calls.append(key)
        outcome = self.outcomes[key]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def run(cache, loader, keys, **kw):
    return enrich_keys(keys, cache=cache, load=loader, source=SRC, **kw)


class TestAnswers:
    def test_data_is_returned_and_cached(self, cache):
        loader = Loader({"a": {"score": 1}})
        results, stats = run(cache, loader, ["a"])
        assert results == {"a": {"score": 1}}
        assert cache.get("a").value == {"score": 1}
        assert (stats.live, stats.cached, stats.failed) == (1, 0, 0)

    def test_second_run_is_free(self, cache, sleeps):
        loader = Loader({"a": {"score": 1}})
        run(cache, loader, ["a"])
        sleeps.clear()
        results, stats = run(cache, loader, ["a"])
        assert results == {"a": {"score": 1}}
        assert loader.calls == ["a"]          # not called again
        assert stats.cached == 1 and sleeps == []   # and no pacing either

    def test_none_is_a_cached_miss_left_out_of_results(self, cache):
        loader = Loader({"a": None})
        results, _ = run(cache, loader, ["a"])
        assert results == {}
        assert cache.get("a").is_miss

    def test_not_found_is_a_cached_miss(self, cache):
        loader = Loader({"a": NotFound("404", status=404)})
        results, stats = run(cache, loader, ["a"])
        assert results == {}
        assert cache.get("a").is_miss
        assert stats.live == 1 and stats.failed == 0

    def test_cached_miss_is_left_out_just_like_a_live_miss(self, cache):
        """First run and every later run must annotate the same IPs."""
        loader = Loader({"a": None, "b": {"x": 1}})
        first, _ = run(cache, loader, ["a", "b"])
        second, _ = run(cache, loader, ["a", "b"])
        assert first == second == {"b": {"x": 1}}
        assert loader.calls == ["a", "b"]

    def test_pacing_follows_live_lookups_only(self, cache, sleeps):
        loader = Loader({"a": {"x": 1}, "b": None})
        run(cache, loader, ["a", "b"], pace=0.7)
        assert sleeps == [0.7, 0.7]


class TestFailuresAreNeverCached:
    @pytest.mark.parametrize("exc", [
        TransportError("timeout"),
        TransportError("503", status=503),
        BadResponse("garbage"),
        HttpError("403", status=403),
    ])
    def test_failure_is_not_cached_and_not_a_miss(self, cache, exc):
        loader = Loader({"a": exc})
        results, stats = run(cache, loader, ["a"])
        assert results == {}
        assert cache.get("a") is None
        assert stats.failed == 1 and stats.failed_keys == ["a"]

    def test_failure_does_not_poison_the_next_run(self, cache):
        run(cache, Loader({"a": TransportError("blip")}), ["a"])
        results, _ = run(cache, Loader({"a": {"x": 1}}), ["a"])
        assert results == {"a": {"x": 1}}

    def test_a_failure_does_not_block_other_keys(self, cache):
        loader = Loader({"a": TransportError("blip"), "b": {"x": 1}, "c": {"x": 2}})
        results, stats = run(cache, loader, ["a", "b", "c"])
        assert results == {"b": {"x": 1}, "c": {"x": 2}}
        assert stats.failed == 1 and stats.stopped is None

    def test_no_pacing_after_a_failure(self, cache, sleeps):
        run(cache, Loader({"a": TransportError("blip")}), ["a"], pace=5)
        assert sleeps == []


class TestRateLimit:
    def test_rate_limit_stops_the_run_and_caches_nothing_further(self, cache):
        loader = Loader({
            "a": {"x": 1},
            "b": RateLimited("429"),
            "c": {"x": 3},
            "d": {"x": 4},
        })
        results, stats = run(cache, loader, ["a", "b", "c", "d"])
        assert results == {"a": {"x": 1}}
        assert loader.calls == ["a", "b"]            # c, d never attempted
        assert cache.get("b") is None and cache.get("c") is None and cache.get("d") is None
        assert stats.stopped == "rate limited"
        assert stats.not_attempted == 3     # b itself (unanswered), c, d

    def test_cached_keys_after_the_limit_are_still_served(self, cache):
        """Stopping means no more *requests*. Data we already hold is free,
        so dropping it would throw away answers for no reason."""
        cache.put("d", {"x": 4})
        loader = Loader({"a": RateLimited("429")})
        results, stats = run(cache, loader, ["a", "d"])
        assert results == {"d": {"x": 4}}
        assert loader.calls == ["a"]
        assert stats.cached == 1 and stats.not_attempted == 1

    def test_earlier_cached_keys_are_still_served(self, cache):
        cache.put("a", {"x": 1})
        loader = Loader({"b": RateLimited("429")})
        results, stats = run(cache, loader, ["a", "b"])
        assert results == {"a": {"x": 1}}
        assert stats.cached == 1


class TestCircuitBreaker:
    def test_stops_after_consecutive_failures(self, cache):
        keys = [f"k{i}" for i in range(10)]
        loader = Loader({k: TransportError("down") for k in keys})
        results, stats = run(cache, loader, keys, max_consecutive_failures=3)
        assert results == {}
        assert loader.calls == ["k0", "k1", "k2"]
        assert stats.stopped == "3 consecutive failures"
        assert stats.failed == 3
        assert stats.not_attempted == 7

    def test_a_success_resets_the_count(self, cache):
        loader = Loader({
            "a": TransportError("x"), "b": TransportError("x"),
            "c": {"ok": 1},
            "d": TransportError("x"), "e": TransportError("x"),
            "f": {"ok": 2},
        })
        results, stats = run(cache, loader, list("abcdef"), max_consecutive_failures=3)
        assert set(results) == {"c", "f"}
        assert stats.stopped is None and stats.failed == 4

    def test_a_definitive_miss_resets_the_count(self, cache):
        loader = Loader({
            "a": TransportError("x"), "b": TransportError("x"),
            "c": NotFound("404", status=404),
            "d": TransportError("x"), "e": TransportError("x"),
        })
        _, stats = run(cache, loader, list("abcde"), max_consecutive_failures=3)
        assert stats.stopped is None


class TestReporting:
    def test_clean_run_is_silent(self, cache, caplog):
        caplog.set_level(logging.WARNING)
        run(cache, Loader({"a": {"x": 1}, "b": None}), ["a", "b"])
        assert caplog.records == []

    def test_one_warning_when_some_lookups_fail(self, cache, caplog):
        caplog.set_level(logging.WARNING)
        run(cache, Loader({"a": TransportError("boom"), "b": {"x": 1}}), ["a", "b"])
        assert len(caplog.records) == 1
        message = caplog.records[0].getMessage()
        assert SRC in message and "1 of 2" in message and "not cached" in message

    def test_one_warning_when_stopped_early(self, cache, caplog):
        caplog.set_level(logging.WARNING)
        run(cache, Loader({"a": {"x": 1}, "b": RateLimited("429"), "c": None}), list("abc"))
        assert len(caplog.records) == 1
        message = caplog.records[0].getMessage()
        assert "stopped early" in message and "rate limited" in message
        assert "2 not attempted" in message  # b (unanswered) and c

    def test_empty_input(self, cache):
        results, stats = run(cache, Loader({}), [])
        assert results == {} and stats.live == 0
