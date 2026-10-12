"""
theory._net
-----------
Safe remote fetches for the bundle/catalog refreshes behind
`theory --update-bundles`.

Why this exists
---------------
Those refreshes used `curl -L -o <cache-path> <url>` with no --fail. curl
exits 0 on an HTTP 404 or 500 and writes the error body to the output file,
so a bad response silently replaced a good cache with an HTML error page or
a JSON {"message": "Not Found"}. On the next run the MITRE collector failed
to parse its bundle, fell back to a TAXII client that isn't even a declared
dependency, and MITRE quietly disappeared from every dossier — with no
error anywhere.

This module fetches to a temporary file, validates the parsed result, and
only then atomically replaces the destination. A failure leaves whatever
was already there untouched.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

USER_AGENT = (
    "Theory-ThreatIntel/2.0 (github.com/threatcraft-co/theory; "
    "open-source threat actor intelligence framework)"
)

DEFAULT_TIMEOUT = 60
DEFAULT_MAX_BYTES = 200 * 1024 * 1024   # 200 MB — the ATT&CK bundle is ~35 MB


class DownloadError(RuntimeError):
    """A refresh failed. The destination file was not modified."""


def fetch_bytes(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    headers: dict[str, str] | None = None,
) -> bytes:
    """GET a URL over https and return the body.

    Raises DownloadError on a non-2xx status, a transport failure, a
    non-https scheme, or a body larger than max_bytes.
    """
    if not url.lower().startswith("https://"):
        raise DownloadError(f"refusing non-https URL: {url!r}")

    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)
    req = urllib.request.Request(url, headers=request_headers)

    try:
        # urlopen raises HTTPError for 4xx/5xx, which is the behaviour the
        # old `curl` call was missing.
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https enforced above
            body = resp.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise DownloadError(f"HTTP {exc.code} from {url}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise DownloadError(f"could not fetch {url}: {exc}") from exc

    if len(body) > max_bytes:
        raise DownloadError(
            f"response from {url} exceeded {max_bytes} bytes — refusing to cache it"
        )
    if not body:
        raise DownloadError(f"empty response from {url}")
    return body


def atomic_write(dest: Path, data: bytes) -> None:
    """Write data to dest atomically (temp file in the same dir, then replace)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(dest.parent), suffix=".part")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def download_json(
    url: str,
    dest: Path,
    *,
    validate: Callable[[Any], None] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> tuple[int, Any]:
    """Fetch JSON, validate its shape, then atomically replace dest.

    `validate` is called with the parsed object and should raise (any
    exception) if the payload isn't what was expected. Nothing is written
    unless the fetch, the parse, and the validation all succeed.

    Returns (bytes_written, parsed_object).
    """
    body = fetch_bytes(url, timeout=timeout, max_bytes=max_bytes)

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise DownloadError(
            f"{url} did not return JSON ({exc}) — keeping the existing {dest.name}"
        ) from exc

    if validate is not None:
        try:
            validate(parsed)
        except DownloadError:
            raise
        except Exception as exc:
            raise DownloadError(
                f"{url} returned JSON that failed validation ({exc}) — "
                f"keeping the existing {dest.name}"
            ) from exc

    atomic_write(dest, body)
    return len(body), parsed


# ---------------------------------------------------------------------------
# Validators for the specific catalogs THEORY refreshes
# ---------------------------------------------------------------------------

def validate_attack_bundle(obj: Any) -> None:
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")
    if obj.get("type") != "bundle":
        raise ValueError(f"expected a STIX bundle, got type={obj.get('type')!r}")
    objects = obj.get("objects")
    if not isinstance(objects, list) or len(objects) < 1000:
        raise ValueError(
            f"expected >=1000 STIX objects, got {len(objects) if isinstance(objects, list) else 'none'}"
        )


def validate_misp_galaxy(obj: Any) -> None:
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")
    values = obj.get("values")
    if not isinstance(values, list) or len(values) < 500:
        raise ValueError(
            f"expected >=500 actors, got {len(values) if isinstance(values, list) else 'none'}"
        )


def validate_kev_catalog(obj: Any) -> None:
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")
    vulns = obj.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise ValueError("no vulnerabilities array")
