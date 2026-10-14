"""
theory.http_client
------------------
The one place THEORY makes outbound HTTP requests on behalf of collectors.

Before this module, 15 collectors each hand-rolled `urlopen` + a retry loop
+ error handling, 40-80 lines apiece, and no two agreed on what a failure
meant. The worst consequence was not the duplication: several collectors
turned *any* failure (a timeout, a 429, a 503) into "the source has nothing
on this", and then cached that answer for up to a week.

The contract here is deliberately small:

    * A request either returns a body, or raises an HttpError.
    * HttpError subclasses say what kind of failure it was.
    * Exactly one of them, NotFound, means "the source answered and has no
      data for this". Only that one is safe to remember as a miss
      (`HttpError.is_definitive_miss`). Everything else is a failure to
      find out, and must never be cached as if it were an answer.

Design notes
------------
* https only by default. Threat-intel feeds have no business on cleartext.
* Response size is capped while reading, not after.
* Retries: transport errors and 5xx always; 429 unless the caller opts out
  (daily-quota APIs such as AbuseIPDB should stop, not wait); other 4xx
  never, because repeating a 401 or 422 cannot change the answer.
* Log lines carry method + scheme + host + path. Never the query string
  (API keys travel there for some sources) and never headers.
* Thread-safe: instances hold configuration only, so P3.3 can run
  collectors in parallel without sharing state.
* Tests patch exactly one seam: `theory.http_client._urlopen`.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlencode, urlsplit

logger = logging.getLogger(__name__)

USER_AGENT = (
    "Theory-ThreatIntel/2.0 (github.com/threatcraft-co/theory; "
    "open-source threat actor intelligence framework)"
)

DEFAULT_TIMEOUT = 20.0
DEFAULT_ATTEMPTS = 2          # total tries, not extra retries
DEFAULT_BACKOFF = 2.0         # seconds; wait before retry n is backoff * n
DEFAULT_MAX_BYTES = 50 * 1024 * 1024
MAX_RETRY_AFTER = 30.0        # never sleep longer than this on a Retry-After

DEFAULT_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

# Single seam for tests. Looked up at call time, so patching
# `theory.http_client._urlopen` affects every client.
_urlopen = urllib.request.urlopen


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class HttpError(RuntimeError):
    """A request did not produce a usable response.

    `status` is the HTTP status when there was one (None for transport
    failures). `is_definitive_miss` is True only when the source itself
    answered that it has nothing — see NotFound.
    """

    is_definitive_miss = False

    def __init__(self, message: str, *, url: str = "", status: int | None = None) -> None:
        super().__init__(message)
        self.url = _safe_url(url)
        self.status = status


class NotFound(HttpError):
    """404/410: the source answered, and it has nothing for this key.

    The only failure that may be remembered as a negative cache entry.
    """

    is_definitive_miss = True


class RateLimited(HttpError):
    """429 that survived the retry budget. `retry_after` is seconds, if sent."""

    def __init__(self, message: str, *, url: str = "", retry_after: float | None = None) -> None:
        super().__init__(message, url=url, status=429)
        self.retry_after = retry_after


class TransportError(HttpError):
    """Network failure, timeout, or persistent 5xx. We learned nothing."""


class BadResponse(HttpError):
    """A 2xx whose body was unusable: too large, empty, or not valid JSON."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class HttpClient:
    """Configured once per collector, used for every request it makes."""

    def __init__(
        self,
        *,
        user_agent: str = USER_AGENT,
        timeout: float = DEFAULT_TIMEOUT,
        attempts: int = DEFAULT_ATTEMPTS,
        backoff: float = DEFAULT_BACKOFF,
        max_bytes: int = DEFAULT_MAX_BYTES,
        headers: Mapping[str, str] | None = None,
        retry_statuses: Iterable[int] = DEFAULT_RETRY_STATUSES,
        require_https: bool = True,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if attempts < 1:
            raise ValueError("attempts must be >= 1")
        self.user_agent = user_agent
        self.timeout = timeout
        self.attempts = attempts
        self.backoff = backoff
        self.max_bytes = max_bytes
        self.headers = dict(headers or {})
        self.retry_statuses = frozenset(retry_statuses)
        self.require_https = require_https
        self._sleep = sleep   # None -> time.sleep, looked up at call time

    # -- public API ---------------------------------------------------------

    def get_json(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> Any:
        body = self.request("GET", url, params=params, headers=headers, timeout=timeout)
        return _parse_json(body, url)

    def post_json(
        self,
        url: str,
        payload: Any,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> Any:
        merged = {"Content-Type": "application/json"}
        if headers:
            merged.update(headers)
        body = self.request(
            "POST", url,
            data=json.dumps(payload).encode("utf-8"),
            headers=merged, timeout=timeout,
        )
        return _parse_json(body, url)

    def post_form(
        self,
        url: str,
        fields: Mapping[str, Any],
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> Any:
        """POST application/x-www-form-urlencoded, parse the reply as JSON."""
        merged = {"Content-Type": "application/x-www-form-urlencoded"}
        if headers:
            merged.update(headers)
        body = self.request(
            "POST", url,
            data=urlencode(fields).encode("utf-8"),
            headers=merged, timeout=timeout,
        )
        return _parse_json(body, url)

    def get_bytes(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        return self.request(
            "GET", url, params=params, headers=headers,
            timeout=timeout, max_bytes=max_bytes,
        )

    def get_text(self, url: str, **kwargs: Any) -> str:
        return self.get_bytes(url, **kwargs).decode("utf-8", errors="replace")

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        data: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        """Perform a request and return the raw body, or raise HttpError."""
        if params:
            sep = "&" if urlsplit(url).query else "?"
            url = f"{url}{sep}{urlencode(params, doseq=True)}"

        if self.require_https and urlsplit(url).scheme.lower() != "https":
            raise HttpError(f"refusing non-https URL: {_safe_url(url)}", url=url)

        request_headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        request_headers.update(self.headers)
        if headers:
            request_headers.update(headers)

        limit = max_bytes if max_bytes is not None else self.max_bytes
        wait_for = timeout if timeout is not None else self.timeout
        safe = _safe_url(url)

        last: HttpError | None = None
        for attempt in range(1, self.attempts + 1):
            req = urllib.request.Request(url, data=data, headers=request_headers, method=method)
            logger.debug("%s %s (attempt %d/%d)", method, safe, attempt, self.attempts)
            retry_after: float | None = None
            try:
                with _urlopen(req, timeout=wait_for) as resp:  # noqa: S310 - scheme checked above
                    body = resp.read(limit + 1)
                if len(body) > limit:
                    raise BadResponse(
                        f"response from {safe} exceeded {limit} bytes", url=url, status=200,
                    )
                return body
            except BadResponse:
                raise
            except urllib.error.HTTPError as exc:
                retry_after = _retry_after(exc)
                last = _classify_status(exc.code, url, retry_after)
                if exc.code not in self.retry_statuses:
                    raise last from exc
            except (urllib.error.URLError, OSError, ValueError) as exc:
                # URLError wraps DNS/connect failures; OSError covers
                # timeouts and resets; ValueError covers malformed URLs,
                # which will not improve on retry but are cheap to bound.
                last = TransportError(f"could not fetch {safe}: {exc}", url=url)

            if attempt < self.attempts:
                delay = retry_after if retry_after is not None else self.backoff * attempt
                (self._sleep or time.sleep)(min(delay, MAX_RETRY_AFTER))

        assert last is not None
        raise last


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_url(url: str) -> str:
    """scheme://host/path — no query string, no fragment, no credentials."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        return f"{parts.scheme}://{host}{parts.path}"
    except ValueError:
        return "<unparseable url>"


def _retry_after(exc: urllib.error.HTTPError) -> float | None:
    raw = exc.headers.get("Retry-After") if exc.headers else None
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return None  # HTTP-date form: not worth parsing for a bounded wait


def _classify_status(status: int, url: str, retry_after: float | None) -> HttpError:
    safe = _safe_url(url)
    if status in (404, 410):
        return NotFound(f"HTTP {status} from {safe}", url=url, status=status)
    if status == 429:
        return RateLimited(f"HTTP 429 from {safe}", url=url, retry_after=retry_after)
    if status >= 500:
        return TransportError(f"HTTP {status} from {safe}", url=url, status=status)
    return HttpError(f"HTTP {status} from {safe}", url=url, status=status)


def _parse_json(body: bytes, url: str) -> Any:
    if not body.strip():
        raise BadResponse(f"empty response from {_safe_url(url)}", url=url, status=200)
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BadResponse(
            f"{_safe_url(url)} did not return JSON ({exc.__class__.__name__})",
            url=url, status=200,
        ) from exc
