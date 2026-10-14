"""
tests/test_disk_cache.py
------------------------
DiskCache behaviour, including the regression that motivated it: a failed
fetch must never be remembered as "the source has nothing".
"""

from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path

import pytest

from theory import disk_cache as disk_cache_module
from theory.disk_cache import DiskCache
from theory.http_client import (
    BadResponse,
    HttpError,
    NotFound,
    RateLimited,
    TransportError,
)


class Clock:
    def __init__(self, now: float = 1_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, **kw) -> None:
        self.now += timedelta(**kw).total_seconds()


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def cache(tmp_path, clock):
    return DiskCache("unit", ttl=timedelta(hours=24), root=tmp_path / "unit", clock=clock)


class TestBasics:
    def test_roundtrip(self, cache):
        cache.put("k", {"a": [1, 2]})
        entry = cache.get("k")
        assert entry is not None
        assert entry.value == {"a": [1, 2]}
        assert not entry.is_miss

    def test_absent_key(self, cache):
        assert cache.get("nope") is None

    def test_a_cached_empty_value_is_a_hit_not_a_miss(self, cache):
        cache.put("k", [])
        entry = cache.get("k")
        assert entry is not None and entry.value == [] and not entry.is_miss

    def test_expiry(self, cache, clock):
        cache.put("k", 1)
        clock.advance(hours=23, minutes=59)
        assert cache.get("k") is not None
        clock.advance(minutes=2)
        assert cache.get("k") is None

    def test_misses_can_have_their_own_ttl(self, tmp_path, clock):
        c = DiskCache("u", ttl=timedelta(days=7), miss_ttl=timedelta(hours=1),
                      root=tmp_path / "u", clock=clock)
        c.put("hit", 1)
        c.put_miss("miss")
        clock.advance(hours=2)
        assert c.get("hit") is not None
        assert c.get("miss") is None

    def test_clock_skew_into_the_future_is_a_miss(self, cache, clock):
        cache.put("k", 1)
        clock.now -= 3600  # entry now claims to be from the future
        assert cache.get("k") is None


class TestRobustness:
    def test_corrupt_file_is_a_miss(self, cache):
        cache.put("k", 1)
        next(cache.directory.glob("*.json")).write_text("{not json", encoding="utf-8")
        assert cache.get("k") is None

    def test_truncated_file_is_a_miss(self, cache):
        cache.put("k", {"big": "x" * 100})
        f = next(cache.directory.glob("*.json"))
        f.write_text(f.read_text(encoding="utf-8")[:20], encoding="utf-8")
        assert cache.get("k") is None

    def test_legacy_format_is_ignored(self, cache):
        # Shape written by the old per-collector caches
        cache.directory.mkdir(parents=True)
        cache.put("k", 1)
        f = next(cache.directory.glob("*.json"))
        f.write_text(json.dumps({"cached_at": "2026-10-01T00:00:00", "iocs": [1]}), encoding="utf-8")
        assert cache.get("k") is None

    @pytest.mark.parametrize("bad", ["abc", None, True, [1]])
    def test_bad_timestamp_is_a_miss(self, cache, bad):
        cache.put("k", 1)
        f = next(cache.directory.glob("*.json"))
        payload = json.loads(f.read_text(encoding="utf-8"))
        payload["stored_at"] = bad
        f.write_text(json.dumps(payload), encoding="utf-8")
        assert cache.get("k") is None

    def test_non_dict_payload_is_a_miss(self, cache):
        cache.put("k", 1)
        next(cache.directory.glob("*.json")).write_text("[1, 2]", encoding="utf-8")
        assert cache.get("k") is None

    def test_unserialisable_value_does_not_raise(self, cache):
        cache.put("k", {"s": {1, 2}})  # sets are not JSON
        assert cache.get("k") is None

    def test_unwritable_directory_does_not_raise(self, tmp_path, clock):
        blocker = tmp_path / "file"
        blocker.write_text("i am a file, not a dir")
        c = DiskCache("u", ttl=timedelta(hours=1), root=blocker / "sub", clock=clock)
        c.put("k", 1)             # must not raise
        assert c.get("k") is None

    def test_no_partial_files_left_behind(self, cache):
        cache.put("k", 1)
        assert not list(cache.directory.glob("*.part"))


class TestKeys:
    @pytest.mark.parametrize("key", [
        "../../etc/passwd", "..\\..\\windows", "/abs/path", "a/b/c",
        "2001:db8::1", "x" * 500, "名前", "", "  ", ".", "..",
    ])
    def test_hostile_keys_stay_inside_the_directory(self, cache, key):
        cache.put(key, "v")
        files = list(cache.directory.glob("*.json"))
        assert len(files) == 1
        assert files[0].parent == cache.directory
        assert cache.get(key).value == "v"

    def test_keys_that_slug_alike_do_not_collide(self, cache):
        cache.put("Cobalt Strike", "a")
        cache.put("cobalt_strike", "b")
        assert cache.get("Cobalt Strike").value == "a"
        assert cache.get("cobalt_strike").value == "b"

    def test_ipv4_and_ipv6_do_not_collide_with_each_other(self, cache):
        cache.put("1.2.3.4", 4)
        cache.put("::1", 6)
        assert cache.get("1.2.3.4").value == 4
        assert cache.get("::1").value == 6

    def test_filename_is_readable(self, cache):
        cache.put("Cobalt Strike", 1)
        assert next(cache.directory.glob("*.json")).name.startswith("cobalt_strike-")


class TestLocation:
    def test_directory_follows_theory_home_at_call_time(self, tmp_path, monkeypatch):
        c = DiskCache("greynoise", ttl=timedelta(hours=1))   # no explicit root
        monkeypatch.setenv("THEORY_HOME", str(tmp_path / "home_a"))
        first = c.directory
        monkeypatch.setenv("THEORY_HOME", str(tmp_path / "home_b"))
        second = c.directory
        assert first != second
        assert first.name == second.name == "greynoise"
        assert str(tmp_path / "home_b") in str(second)

    def test_importing_does_not_touch_the_filesystem(self, tmp_path):
        DiskCache("never_created", ttl=timedelta(hours=1))
        assert not (Path.cwd() / ".cache" / "never_created").exists()


class TestFetch:
    """fetch() is where the 'failure is not a miss' rule is enforced."""

    def test_miss_calls_loader_once_then_serves_from_cache(self, cache):
        calls = []

        def loader():
            calls.append(1)
            return {"iocs": [1]}

        assert cache.fetch("k", loader) == {"iocs": [1]}
        assert cache.fetch("k", loader) == {"iocs": [1]}
        assert len(calls) == 1

    def test_empty_but_successful_result_is_cached(self, cache):
        calls = []

        def loader():
            calls.append(1)
            return []

        cache.fetch("k", loader)
        assert cache.fetch("k", loader, default="D") == []
        assert len(calls) == 1

    def test_not_found_is_remembered_and_returns_default(self, cache):
        calls = []

        def loader():
            calls.append(1)
            raise NotFound("404", url="https://x.test/a", status=404)

        assert cache.fetch("k", loader, default={"empty": True}) == {"empty": True}
        assert cache.fetch("k", loader, default={"empty": True}) == {"empty": True}
        assert len(calls) == 1
        assert cache.get("k").is_miss

    @pytest.mark.parametrize("exc", [
        TransportError("timeout"),
        TransportError("503", status=503),
        RateLimited("429"),
        BadResponse("garbage"),
        HttpError("403", status=403),
    ])
    def test_failures_propagate_and_are_never_cached(self, cache, exc):
        """THE regression: a timeout/429/5xx must not read as 'no data'."""
        def loader():
            raise exc

        with pytest.raises(type(exc)):
            cache.fetch("k", loader)
        assert cache.get("k") is None
        assert not list(cache.directory.glob("*.json")) if cache.directory.exists() else True

    def test_recovers_after_a_failure(self, cache):
        state = {"n": 0}

        def loader():
            state["n"] += 1
            if state["n"] == 1:
                raise TransportError("flaky")
            return ["real data"]

        with pytest.raises(TransportError):
            cache.fetch("k", loader)
        assert cache.fetch("k", loader) == ["real data"]

    def test_non_http_exceptions_are_not_swallowed(self, cache):
        def loader():
            raise KeyError("bug in the collector")

        with pytest.raises(KeyError):
            cache.fetch("k", loader)
        assert cache.get("k") is None

    def test_expired_miss_triggers_a_refetch(self, tmp_path, clock):
        c = DiskCache("u", ttl=timedelta(days=1), miss_ttl=timedelta(hours=1),
                      root=tmp_path / "u", clock=clock)
        answers = [NotFound("404"), ["now there is data"]]

        def loader():
            a = answers.pop(0)
            if isinstance(a, BaseException):
                raise a
            return a

        assert c.fetch("k", loader, default=[]) == []
        clock.advance(hours=2)
        assert c.fetch("k", loader, default=[]) == ["now there is data"]


def test_module_exposes_schema_version():
    # A bump here must be deliberate: it invalidates every user's cache.
    assert disk_cache_module.SCHEMA_VERSION == 1


def test_cache_files_are_plain_json_with_expected_fields(cache):
    cache.put("k", {"a": 1})
    record = json.loads(next(cache.directory.glob("*.json")).read_text(encoding="utf-8"))
    assert set(record) == {"v", "stored_at", "miss", "value"}
    assert record["v"] == 1 and record["miss"] is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_read_only_cache_dir_degrades_gracefully(tmp_path, clock):
    d = tmp_path / "ro"
    d.mkdir()
    d.chmod(0o500)
    try:
        c = DiskCache("u", ttl=timedelta(hours=1), root=d, clock=clock)
        c.put("k", 1)   # must not raise (root may bypass perms; either way no exception)
    finally:
        d.chmod(0o700)
