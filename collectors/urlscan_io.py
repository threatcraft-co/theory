"""
collectors/urlscan_io.py
--------------------------
Enriches domain/URL IOCs with urlscan.io scan history — prior scan
verdicts (malicious/suspicious tags), the IP and country the page
resolved to, and when it was last scanned.

urlscan.io's SEARCH endpoint is public and keyless by default — it
queries scans other people have already submitted, which is exactly
the "has anyone already seen this domain/URL and what did it look
like" question an actor profile needs, without THEORY ever submitting
the indicator itself (submission is the part that needs a key and
would also leak the IOC to a third party — THEORY only ever reads
existing public scan results). An optional URLSCAN_API_KEY raises the
default rate limit but is never required.

API: GET https://urlscan.io/api/v1/search/?q={query}
  query is `domain:{domain}` for a domain IOC, `page.url:"{url}"` for
  a full URL IOC. Response:
    {"results": [{"page": {"url", "domain", "ip", "country"},
                  "task": {"time"},
                  "verdicts": {"overall": {"malicious": bool, "score": int}},
                  "tags": [...] }, ...]}
No results (empty list) means "nobody has scanned this (that's
public)" — not an error, and is cached as a miss the same as a real
empty result so a re-run doesn't keep re-querying a dead end.

Cache: .cache/urlscan_io/{key_hash}.json, TTL 24 hours (scan history
for a domain can grow day to day as new scans are submitted by other
users).
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote

from collectors.base import BaseCollector

logger = logging.getLogger(__name__)

SOURCE_ID       = "urlscan_io"
API_BASE        = "https://urlscan.io/api/v1/search/"
CACHE_DIR       = Path(".cache/urlscan_io")
CACHE_TTL_HOURS = 24
TIMEOUT         = 10
RETRY_MAX       = 2
RETRY_WAIT      = 2
MAX_PER_RUN     = 40
MAX_RESULTS     = 5  # most recent scans only — this is a "has anyone seen this" check, not deep research

_EMPTY_RESULT: dict[str, Any] = {"scan_count": 0, "malicious_count": 0, "scans": []}


def _key_hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _build_query(ioc_type: str, value: str) -> str | None:
    if ioc_type == "domain":
        return f"domain:{value}"
    if ioc_type == "url":
        return f'page.url:"{value}"'
    return None


class URLScanIOCollector(BaseCollector):
    """Enriches domain/URL indicators with urlscan.io public scan
    history. No API key required — post-processor, called after the
    main pipeline has aggregated all IOCs, same shape as
    GreyNoiseCollector/AbuseIPDBCollector/ShodanInternetDBCollector."""

    SOURCE_ID = SOURCE_ID
    REQUIRES_API_KEY = False

    def __init__(self, api_key: str | None = None, config: dict | None = None):
        super().__init__(api_key=api_key, config=config or {})

    def query(self, actor_name: str) -> dict | None:
        """Standard interface stub — urlscan.io is enrichment-only."""
        return None

    def enrich_urls(self, indicators: list[dict], actor_name: str) -> dict[str, dict]:
        """Enrich domain/URL indicators with urlscan.io scan history.

        Returns {value: {"scan_count": int, "malicious_count": int,
        "scans": [{"url", "ip", "country", "time", "malicious", "score",
        "tags"}]}}, one entry per domain/URL indicator that had at
        least one public scan on record.
        """
        targets: dict[str, str] = {}  # value -> ioc_type, deduped
        for ioc in indicators:
            ioc_type = ioc.get("type")
            if ioc_type not in ("domain", "url"):
                continue
            value = (ioc.get("value") or "").strip()
            if value and value not in targets:
                targets[value] = ioc_type

        if not targets:
            logger.debug("urlscan.io: no domain/URL indicators to enrich")
            return {}

        values = sorted(targets.keys())[:MAX_PER_RUN]
        logger.info(
            "urlscan.io: enriching %d domains/URLs (of %d total) for %s",
            len(values), len(targets), actor_name,
        )

        results: dict[str, dict] = {}
        lookup_count = 0

        for value in values:
            cached = self._load_cache(value)
            if cached is not None:
                if cached.get("scan_count", 0) > 0:
                    results[value] = cached
                continue

            context = self._lookup(targets[value], value)
            if context is not None:
                self._save_cache(value, context)
                lookup_count += 1
                if context.get("scan_count", 0) > 0:
                    results[value] = context
            else:
                self._save_cache(value, dict(_EMPTY_RESULT))

            time.sleep(0.3)  # polite pacing on a shared free service

        with_hits = sum(1 for r in results.values() if r.get("malicious_count"))
        logger.info(
            "urlscan.io: %d results (%d live lookups), %d with malicious scans on record.",
            len(results), lookup_count, with_hits,
        )
        return results

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def _lookup(self, ioc_type: str, value: str) -> dict | None:
        query = _build_query(ioc_type, value)
        if not query:
            return None

        url = f"{API_BASE}?q={quote(query)}"
        headers = {"Accept": "application/json", "User-Agent": "THEORY/1.0 threat-intel-research"}
        if self.api_key:
            headers["API-Key"] = self.api_key
        req = Request(url, headers=headers)

        for attempt in range(1, RETRY_MAX + 1):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return self._parse_results(data.get("results", []) or [])
            except HTTPError as exc:
                if exc.code == 404:
                    return dict(_EMPTY_RESULT)
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT * attempt)
                else:
                    logger.debug("urlscan.io lookup failed for %s: HTTP %d", value, exc.code)
                    return None
            except URLError:
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT)
                else:
                    return None
        return None

    @staticmethod
    def _parse_results(raw_results: list[dict]) -> dict:
        scans = []
        malicious_count = 0
        for r in raw_results[:MAX_RESULTS]:
            page     = r.get("page", {}) or {}
            verdicts = (r.get("verdicts", {}) or {}).get("overall", {}) or {}
            is_malicious = bool(verdicts.get("malicious"))
            if is_malicious:
                malicious_count += 1
            scans.append({
                "url":       page.get("url", ""),
                "ip":        page.get("ip", ""),
                "country":   page.get("country", ""),
                "time":      (r.get("task", {}) or {}).get("time", ""),
                "malicious": is_malicious,
                "score":     verdicts.get("score", 0),
                "tags":      r.get("tags", []) or [],
            })
        return {
            "scan_count":      len(raw_results),
            "malicious_count": malicious_count,
            "scans":           scans,
        }

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _load_cache(self, value: str) -> dict | None:
        cache_path = CACHE_DIR / f"{_key_hash(value)}.json"
        if not cache_path.exists():
            return None
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

        cached_at = payload.get("_cached_at", 0)
        if time.time() - cached_at > CACHE_TTL_HOURS * 3600:
            return None  # stale

        return payload.get("data")

    def _save_cache(self, value: str, data: dict) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path = CACHE_DIR / f"{_key_hash(value)}.json"
        try:
            cache_path.write_text(
                json.dumps({"_cached_at": time.time(), "data": data}),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("urlscan.io: failed to write cache for %s: %s", value, exc)
