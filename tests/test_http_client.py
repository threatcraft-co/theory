"""
tests/test_http_client.py
-------------------------
The HttpClient contract: a request returns a body or raises a typed error,
and only NotFound means "the source has nothing".

All network access goes through the single seam `theory.http_client._urlopen`.
"""

from __future__ import annotations

import json
import logging
import urllib.error

import pytest

from theory import http_client
from tests._http_fakes import FakeResponse, http_error, ok, seam
from theory.http_client import (
    BadResponse,
    HttpClient,
    HttpError,
    NotFound,
    RateLimited,
    TransportError,
)

URL = "https://example.test/api/v1/lookup"


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def client(sleeps):
    return HttpClient(sleep=sleeps.append)


class TestSuccess:
    def test_get_json(self, client):
        with seam(ok({"a": 1})):
            assert client.get_json(URL) == {"a": 1}

    def test_params_are_encoded(self, client):
        with seam(ok({})) as m:
            client.get_json(URL, params={"q": "APT 28", "n": 5})
        req = m.call_args.args[0]
        assert req.full_url == f"{URL}?q=APT+28&n=5"

    def test_params_append_to_existing_query(self, client):
        with seam(ok({})) as m:
            client.get_json(URL + "?x=1", params={"y": 2})
        assert m.call_args.args[0].full_url == f"{URL}?x=1&y=2"

    def test_default_headers_and_override(self, sleeps):
        c = HttpClient(headers={"Key": "secret"}, sleep=sleeps.append)
        with seam(ok({})) as m:
            c.get_json(URL, headers={"Accept": "text/plain"})
        req = m.call_args.args[0]
        assert req.get_header("User-agent").startswith("Theory-ThreatIntel/2.0")
        assert req.get_header("Key") == "secret"
        assert req.get_header("Accept") == "text/plain"

    def test_post_json_sets_content_type_and_body(self, client):
        with seam(ok({"query_status": "ok"})) as m:
            result = client.post_json(URL, {"query": "taginfo", "tag": "x"}, headers={"Auth-Key": "k"})
        req = m.call_args.args[0]
        assert result == {"query_status": "ok"}
        assert req.get_method() == "POST"
        assert req.get_header("Content-type") == "application/json"
        assert req.get_header("Auth-key") == "k"
        assert json.loads(req.data) == {"query": "taginfo", "tag": "x"}

    def test_post_form(self, client):
        with seam(ok({})) as m:
            client.post_form(URL, {"selector": "time", "limit": 5})
        req = m.call_args.args[0]
        assert req.get_header("Content-type") == "application/x-www-form-urlencoded"
        assert req.data == b"selector=time&limit=5"

    def test_get_text_and_bytes(self, client):
        with seam(FakeResponse(b"hello"), FakeResponse(b"\xff\xfe")):
            assert client.get_text(URL) == "hello"
            assert client.get_bytes(URL) == b"\xff\xfe"


class TestClassification:
    def test_404_is_a_definitive_miss_and_not_retried(self, client, sleeps):
        with seam(http_error(404)) as m, pytest.raises(NotFound) as info:
            client.get_json(URL)
        assert info.value.is_definitive_miss
        assert info.value.status == 404
        assert m.call_count == 1 and sleeps == []

    def test_410_is_a_definitive_miss(self, client):
        with seam(http_error(410)), pytest.raises(NotFound):
            client.get_json(URL)

    @pytest.mark.parametrize("code", [400, 401, 403, 422])
    def test_other_4xx_not_retried_and_not_a_miss(self, client, sleeps, code):
        with seam(http_error(code)) as m, pytest.raises(HttpError) as info:
            client.get_json(URL)
        assert not isinstance(info.value, NotFound)
        assert not info.value.is_definitive_miss
        assert info.value.status == code
        assert m.call_count == 1 and sleeps == []

    def test_transport_failure_is_not_a_miss(self, client):
        with seam(urllib.error.URLError("dns"), urllib.error.URLError("dns")), \
                pytest.raises(TransportError) as info:
            client.get_json(URL)
        assert not info.value.is_definitive_miss

    def test_timeout_is_a_transport_error(self, client):
        with seam(TimeoutError("slow"), TimeoutError("slow")), pytest.raises(TransportError):
            client.get_json(URL)

    def test_persistent_5xx_is_a_transport_error(self, client):
        with seam(http_error(503), http_error(503)), pytest.raises(TransportError) as info:
            client.get_json(URL)
        assert info.value.status == 503
        assert not info.value.is_definitive_miss


class TestRetry:
    def test_recovers_after_transient_failure(self, client, sleeps):
        with seam(urllib.error.URLError("reset"), ok({"a": 1})) as m:
            assert client.get_json(URL) == {"a": 1}
        assert m.call_count == 2
        assert sleeps == [2.0]

    def test_429_retries_then_raises_rate_limited(self, client, sleeps):
        with seam(http_error(429), http_error(429)), pytest.raises(RateLimited) as info:
            client.get_json(URL)
        assert info.value.status == 429
        assert not info.value.is_definitive_miss
        assert sleeps == [2.0]

    def test_retry_after_is_honoured_and_capped(self, client, sleeps):
        with seam(http_error(429, retry_after="7"), ok({})):
            client.get_json(URL)
        assert sleeps == [7.0]

        sleeps.clear()
        with seam(http_error(429, retry_after="9999"), ok({})):
            client.get_json(URL)
        assert sleeps == [http_client.MAX_RETRY_AFTER]

    def test_garbage_retry_after_falls_back_to_backoff(self, client, sleeps):
        with seam(http_error(429, retry_after="Wed, 21 Oct 2026 07:28:00 GMT"), ok({})):
            client.get_json(URL)
        assert sleeps == [2.0]

    def test_quota_apis_can_opt_out_of_429_retry(self, sleeps):
        c = HttpClient(retry_statuses={500, 502, 503, 504}, sleep=sleeps.append)
        with seam(http_error(429)) as m, pytest.raises(RateLimited):
            c.get_json(URL)
        assert m.call_count == 1 and sleeps == []

    def test_attempts_bound_the_work(self, sleeps):
        c = HttpClient(attempts=3, sleep=sleeps.append)
        with seam(*[urllib.error.URLError("x")] * 3) as m, pytest.raises(TransportError):
            c.get_json(URL)
        assert m.call_count == 3
        assert sleeps == [2.0, 4.0]

    def test_attempts_must_be_positive(self):
        with pytest.raises(ValueError):
            HttpClient(attempts=0)


class TestResponseValidation:
    def test_non_https_refused_before_any_request(self, client):
        with seam() as m, pytest.raises(HttpError, match="non-https"):
            client.get_json("http://example.test/x")
        m.assert_not_called()

    def test_https_requirement_can_be_relaxed_explicitly(self, sleeps):
        c = HttpClient(require_https=False, sleep=sleeps.append)
        with seam(ok({"a": 1})):
            assert c.get_json("http://localhost:11434/api") == {"a": 1}

    def test_oversize_body_refused(self, sleeps):
        c = HttpClient(max_bytes=10, sleep=sleeps.append)
        with seam(FakeResponse(b"x" * 11)), pytest.raises(BadResponse, match="exceeded"):
            c.get_bytes(URL)

    def test_body_at_the_limit_is_accepted(self, sleeps):
        c = HttpClient(max_bytes=10, sleep=sleeps.append)
        with seam(FakeResponse(b"x" * 10)):
            assert c.get_bytes(URL) == b"x" * 10

    def test_oversize_is_not_retried(self, sleeps):
        c = HttpClient(max_bytes=1, sleep=sleeps.append)
        with seam(FakeResponse(b"xx")) as m, pytest.raises(BadResponse):
            c.get_bytes(URL)
        assert m.call_count == 1

    def test_invalid_json_is_a_bad_response_not_a_miss(self, client):
        with seam(FakeResponse(b"<html>oops</html>")), pytest.raises(BadResponse) as info:
            client.get_json(URL)
        assert not info.value.is_definitive_miss

    def test_empty_body_is_a_bad_response(self, client):
        with seam(FakeResponse(b"  ")), pytest.raises(BadResponse, match="empty"):
            client.get_json(URL)


class TestSecretsStayOutOfLogsAndErrors:
    """Some sources carry API keys in the query string. A security tool's
    debug log must not become the place they leak."""

    SECRET = "s3cr3t-key-value"

    def test_error_message_and_attribute_drop_the_query(self, client):
        with seam(http_error(403)), pytest.raises(HttpError) as info:
            client.get_json(URL, params={"apikey": self.SECRET})
        assert self.SECRET not in str(info.value)
        assert self.SECRET not in info.value.url
        assert info.value.url == URL

    def test_debug_logging_drops_the_query(self, client, caplog):
        caplog.set_level(logging.DEBUG, logger="theory.http_client")
        with seam(ok({})):
            client.get_json(URL, params={"apikey": self.SECRET}, headers={"Key": self.SECRET})
        assert caplog.records, "expected a debug line"
        assert self.SECRET not in caplog.text

    def test_transport_error_message_drops_the_query(self, client):
        with seam(urllib.error.URLError("boom"), urllib.error.URLError("boom")), \
                pytest.raises(TransportError) as info:
            client.get_json(URL, params={"apikey": self.SECRET})
        assert self.SECRET not in str(info.value)

    def test_userinfo_in_url_is_dropped(self):
        err = HttpError("x", url="https://user:pw@example.test/p?k=v")
        assert err.url == "https://example.test/p"
