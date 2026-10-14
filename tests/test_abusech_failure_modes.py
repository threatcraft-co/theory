"""
tests/test_abusech_failure_modes.py
-----------------------------------
ThreatFox, URLhaus and MalwareBazaar share one contract, so they share one
test suite: a failed request must never be remembered as "abuse.ch has
nothing on this family".

Before the shared HttpClient/DiskCache, each of these cached an empty list
for 24 hours on *any* exception (a timeout, a 429, a 503) and on abuse.ch's
error replies (a revoked Auth-Key arrives as HTTP 200 with a `query_status`
string). One bad minute therefore blanked a family for a day, silently.

Parametrised so the three cannot drift apart again.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable

import pytest

import collectors.malware_bazaar as mb_module
import collectors.threatfox as tf_module
import collectors.urlhaus as uh_module
from collectors.malware_bazaar import MalwareBazaarCollector
from collectors.threatfox import ThreatFoxCollector
from collectors.urlhaus import URLhausCollector
from tests import (
    test_malware_bazaar_collector as mb_tests,
    test_threatfox_collector as tf_tests,
    test_urlhaus_collector as uh_tests,
)
from tests._http_fakes import http_error, net_error, ok, seam
from theory.disk_cache import DiskCache

KEY = "test-key-not-real"
FAMILY = "Emotet"


@dataclass(frozen=True)
class Spec:
    name: str
    module: Any
    cls: type
    endpoint: str
    data_key: str                     # where the results list lives in a reply
    success: dict
    no_results: dict
    content_type: str
    body_matches: Callable[[bytes], bool]


SPECS = [
    Spec(
        "threatfox", tf_module, ThreatFoxCollector, tf_module.API_URL, "data",
        tf_tests.SAMPLE_TAGINFO_RESPONSE, tf_tests.NO_RESULTS_RESPONSE,
        "application/json",
        lambda b: json.loads(b) == {"query": "taginfo", "tag": FAMILY,
                                    "limit": tf_module.MAX_IOCS_PER_FAMILY},
    ),
    Spec(
        "urlhaus", uh_module, URLhausCollector, uh_module.TAG_ENDPOINT, "urls",
        uh_tests.SAMPLE_TAG_RESPONSE, uh_tests.NO_RESULTS_RESPONSE,
        "application/x-www-form-urlencoded",
        lambda b: b == f"tag={FAMILY}&limit={uh_module.MAX_URLS_PER_FAMILY}".encode(),
    ),
    Spec(
        "malware_bazaar", mb_module, MalwareBazaarCollector, mb_module.API_URL, "data",
        mb_tests.SAMPLE_TAGINFO_RESPONSE, mb_tests.NO_RESULTS_RESPONSE,
        "application/x-www-form-urlencoded",
        lambda b: b == (
            f"query=get_taginfo&tag={FAMILY}&limit={mb_module.MAX_SAMPLES_PER_FAMILY}"
        ).encode(),
    ),
]


@pytest.fixture(params=SPECS, ids=lambda s: s.name)
def spec(request):
    return request.param


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)


def make(spec: Spec, tmp_path) -> Any:
    collector = spec.cls(api_key=KEY)
    collector._cache = DiskCache(
        spec.name, ttl=timedelta(hours=spec.module.CACHE_TTL_HOURS), root=tmp_path,
    )
    return collector


def collect(collector, families=(FAMILY,)):
    return collector.collect_for_malware_families(list(families), "APT28")


def cached(collector, spec: Spec, family: str = FAMILY):
    return collector._cache.get(spec.module._slugify(family))


class TestSuccess:
    def test_request_is_sent_correctly(self, spec, tmp_path):
        collector = make(spec, tmp_path)
        with seam(ok(spec.success)) as urlopen:
            result = collect(collector)

        assert result is not None and result["indicators"]
        req = urlopen.call_args.args[0]
        assert req.get_method() == "POST"
        assert req.full_url == spec.endpoint
        assert req.get_header("Auth-key") == KEY
        assert req.get_header("Content-type") == spec.content_type
        assert spec.body_matches(req.data), req.data

    def test_second_run_is_served_from_cache(self, spec, tmp_path):
        collector = make(spec, tmp_path)
        with seam(ok(spec.success)) as urlopen:
            first = collect(collector)
            second = collect(collector)
        assert urlopen.call_count == 1
        assert first["indicators"] == second["indicators"]

    def test_no_results_is_a_real_answer_and_is_cached(self, spec, tmp_path):
        collector = make(spec, tmp_path)
        with seam(ok(spec.no_results)) as urlopen:
            assert collect(collector) is None
            assert collect(collector) is None
        assert urlopen.call_count == 1
        entry = cached(collector, spec)
        assert entry is not None and entry.value == []


class TestFailuresAreNeverCached:
    @pytest.mark.parametrize("failure", [
        pytest.param(lambda: net_error("timed out"), id="timeout"),
        pytest.param(lambda: http_error(429), id="rate-limited"),
        pytest.param(lambda: http_error(503), id="server-error"),
        pytest.param(lambda: http_error(401), id="unauthorised"),
        pytest.param(lambda: http_error(403), id="forbidden"),
    ])
    def test_transport_and_http_failures(self, spec, tmp_path, failure):
        collector = make(spec, tmp_path)
        with seam(failure(), repeat_last=True):
            assert collect(collector) is None
        assert cached(collector, spec) is None

    @pytest.mark.parametrize("payload", [
        pytest.param({"query_status": "unauthorized"}, id="error-status-no-data"),
        pytest.param({"query_status": "unauthorized", "data": []}, id="error-status-empty-data"),
        pytest.param({"query_status": "unauthorized", "data": "Your Auth-Key is not valid"},
                     id="error-status-string-data"),
        pytest.param({"query_status": "illegal_search_term"}, id="rejected-term"),
        pytest.param({"data": [], "urls": []}, id="status-missing"),
        pytest.param("not a dict", id="not-a-dict"),
        pytest.param([], id="bare-list"),
    ])
    def test_error_replies_sent_as_http_200(self, spec, tmp_path, payload):
        """abuse.ch reports a revoked key as a 200 with a status string."""
        collector = make(spec, tmp_path)
        with seam(ok(payload)):
            assert collect(collector) is None
        assert cached(collector, spec) is None

    def test_ok_status_with_wrong_shape(self, spec, tmp_path):
        collector = make(spec, tmp_path)
        with seam(ok({"query_status": "ok", spec.data_key: "oops, a string"})):
            assert collect(collector) is None
        assert cached(collector, spec) is None

    def test_invalid_json_body(self, spec, tmp_path):
        from tests._http_fakes import raw
        collector = make(spec, tmp_path)
        with seam(raw(b"<html>Bad gateway</html>")):
            assert collect(collector) is None
        assert cached(collector, spec) is None

    def test_a_failure_does_not_poison_the_next_run(self, spec, tmp_path):
        collector = make(spec, tmp_path)
        with seam(net_error("blip"), repeat_last=True):
            assert collect(collector) is None
        with seam(ok(spec.success)):
            result = collect(collector)
        assert result is not None and result["indicators"]

    def test_one_failing_family_does_not_stop_the_others(self, spec, tmp_path):
        collector = make(spec, tmp_path)
        # two attempts for the first family fail, then the second succeeds
        with seam(net_error("blip"), net_error("blip"), ok(spec.success)):
            result = collect(collector, families=("Broken", FAMILY))
        assert result is not None and result["indicators"]
        assert cached(collector, spec, "Broken") is None
        assert cached(collector, spec, FAMILY) is not None


class TestReporting:
    def test_failures_are_reported_once_as_a_warning(self, spec, tmp_path, caplog):
        collector = make(spec, tmp_path)
        caplog.set_level(logging.WARNING, logger=spec.module.__name__)
        with seam(http_error(503), repeat_last=True):
            collect(collector, families=("A", "B", "C"))
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        message = warnings[0].getMessage()
        assert "3 of 3" in message and "not cached" in message

    def test_api_key_never_appears_in_logs(self, spec, tmp_path, caplog):
        collector = make(spec, tmp_path)
        caplog.set_level(logging.DEBUG)
        with seam(http_error(403), repeat_last=True):
            collect(collector)
        with seam(ok(spec.success)):
            collect(collector, families=("Other",))
        assert KEY not in caplog.text


def test_malware_bazaar_illegal_tag_is_a_definitive_empty(tmp_path):
    """MalwareBazaar answers `illegal_tag` for tags it will never accept.
    That is deterministic for the input, so it is a real (cacheable) answer."""
    spec = next(s for s in SPECS if s.name == "malware_bazaar")
    collector = make(spec, tmp_path)
    with seam(ok({"query_status": "illegal_tag"})) as urlopen:
        assert collect(collector) is None
        assert collect(collector) is None
    assert urlopen.call_count == 1
    assert cached(collector, spec).value == []
