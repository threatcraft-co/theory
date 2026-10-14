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

Cache: .cache/urlscan_io/, TTL 24 hours (see theory.disk_cache). Scan history
for a domain can grow day to day as new scans are submitted by other users.
"No scans on record" is remembered as a miss; a 429, timeout or 5xx is not
cached (search quotas are tight, and one 429 used to blank every remaining
domain for a day).
"""
from __future__ import annotations

import logging
from datetime import timedelta

from collectors._enrich import enrich_keys
from collectors.base import BaseCollector

from theory.disk_cache import DiskCache
from theory.http_client import HttpClient, NotFound

logger = logging.getLogger(__name__)

SOURCE_ID       = "urlscan_io"
API_BASE        = "https://urlscan.io/api/v1/search/"
CACHE_TTL_HOURS = 24
TIMEOUT         = 10
RETRY_MAX       = 2
RETRY_WAIT      = 2
MAX_PER_RUN     = 40
MAX_RESULTS     = 5  # most recent scans only — this is a "has anyone seen this" check, not deep research

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
        headers = {"API-Key": self.api_key} if self.api_key else {}
        self._http = HttpClient(
            timeout=TIMEOUT, attempts=RETRY_MAX, backoff=RETRY_WAIT, headers=headers,
        )
        self._cache = DiskCache(SOURCE_ID, ttl=timedelta(hours=CACHE_TTL_HOURS))

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

        def load(value: str) -> dict | None:
            context = self._lookup(targets[value], value)
            # "No scans on record" is an answer, but not an annotation:
            # remember it as a miss and leave the indicator unannotated.
            if context is None or not context.get("scan_count", 0):
                return None
            return context

        results, stats = enrich_keys(
            values, cache=self._cache, load=load,
            source="urlscan.io", pace=0.3,   # polite pacing on a shared free service
        )
        lookup_count = stats.live

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
        """Search urlscan.io for one domain/URL.

        Returns a (possibly zero-count) result dict when urlscan.io answered,
        including 404; None for an indicator type it cannot search. Raises
        HttpError when the question could not be answered (429, timeout,
        5xx); those are not cached.
        """
        query = _build_query(ioc_type, value)
        if not query:
            return None

        try:
            data = self._http.get_json(API_BASE, params={"q": query})
        except NotFound:
            return {"scan_count": 0, "malicious_count": 0, "scans": []}
        raw_results = data.get("results") if isinstance(data, dict) else None
        return self._parse_results(raw_results or [])

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
