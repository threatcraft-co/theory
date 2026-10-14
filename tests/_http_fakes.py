"""
tests/_http_fakes.py
--------------------
Shared fakes for tests of anything that talks HTTP through
`theory.http_client`. One seam (`theory.http_client._urlopen`) covers every
collector, so a collector test never needs to patch its own module's urlopen.

    from tests._http_fakes import seam, ok, http_error

    with seam(ok({"query_status": "ok", "data": []})) as urlopen:
        ...
    req = urlopen.call_args.args[0]       # the urllib Request that was sent
"""

from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message
from unittest.mock import patch

from theory import http_client


class FakeResponse:
    """Context-manager stand-in for the object urlopen returns."""

    def __init__(self, body: bytes = b"{}"):
        self._body = io.BytesIO(body)

    def read(self, n: int = -1) -> bytes:
        return self._body.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def ok(payload) -> FakeResponse:
    """A 200 whose body is `payload` encoded as JSON."""
    return FakeResponse(json.dumps(payload).encode())


def raw(body: bytes) -> FakeResponse:
    return FakeResponse(body)


def http_error(
    code: int, retry_after: str | None = None, url: str = "https://example.test/",
) -> urllib.error.HTTPError:
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError(url, code, "err", headers, io.BytesIO(b""))


def net_error(reason: str = "unreachable") -> urllib.error.URLError:
    return urllib.error.URLError(reason)


def seam(*responses, repeat_last: bool = False):
    """Patch the single urlopen seam with a queue of responses/exceptions.

    Each item is returned (or raised, if it is an exception) in order. With
    `repeat_last=True` the final item is reused indefinitely, which is what a
    persistently failing server looks like. Running off the end of the queue
    otherwise fails loudly, so an unexpected extra request is a test failure
    rather than a silent hang.
    """
    queue = list(responses)

    def fake(req, timeout=None):
        if not queue:
            raise AssertionError(f"unexpected request: {req.get_method()} {req.full_url}")
        item = queue[0] if (repeat_last and len(queue) == 1) else queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    return patch.object(http_client, "_urlopen", side_effect=fake)
