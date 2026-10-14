"""
collectors/urlhaus.py
----------------------
Pulls malicious distribution URLs from URLhaus (abuse.ch) by malware tag.

URLhaus tracks URLs actively used for malware distribution. Where
ThreatFox provides C2 infrastructure IOCs and MalwareBazaar provides
sample hashes, URLhaus provides the delivery layer: the actual URLs
that serve payloads.

This fills a gap in the dossier's IOC coverage: initial access URLs
and payload delivery infrastructure tied to specific malware families.

Strategy: for each malware family in the actor profile, query
URLhaus's tag endpoint to pull associated distribution URLs.

API docs: https://urlhaus-api.abuse.ch/
Endpoint: https://urlhaus-api.abuse.ch/v1/tag/ (POST, form-encoded)

Auth: requires ABUSECH_API_KEY (free at https://auth.abuse.ch/).
      Same key works across all abuse.ch services.

Cache: .cache/urlhaus/, TTL 24 hours (see theory.disk_cache). Only real answers
are cached; failures and error replies are not.
"""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import timedelta
from typing import Any

from collectors._abusech import interpret_query_status
from collectors.base import BaseCollector

from theory.disk_cache import DiskCache
from theory.http_client import BadResponse, HttpClient, HttpError

logger = logging.getLogger(__name__)

SOURCE_ID             = "urlhaus"
API_BASE              = "https://urlhaus-api.abuse.ch/v1"
TAG_ENDPOINT          = f"{API_BASE}/tag/"
CACHE_TTL_HOURS       = 24
TIMEOUT               = 15
RETRY_MAX             = 2
RETRY_WAIT            = 2
MAX_URLS_PER_FAMILY   = 50

# URLhaus threat types mapped to THEORY labels
_THREAT_LABELS: dict[str, str] = {
    "malware_download": "Payload Delivery",
    "malware":          "Payload Delivery",
}

# URL statuses that indicate operational intelligence value
_ACTIVE_STATUSES = {"online", "unknown"}


class URLhausCollector(BaseCollector):
    """
    Queries URLhaus by malware family tag for distribution URLs.

    Enrichment-only: called after the main pipeline has built the
    actor profile with malware family names from MITRE and Malpedia.
    """

    SOURCE_ID = SOURCE_ID
    REQUIRES_API_KEY = True

    def __init__(self, api_key: str | None = None, config: dict | None = None):
        super().__init__(api_key=api_key, config=config or {})
        # Fall back to env var so the collector works when instantiated
        # with no arguments.
        self._abusech_key = api_key or os.environ.get("ABUSECH_API_KEY", "")
        self._http = HttpClient(
            timeout=TIMEOUT, attempts=RETRY_MAX, backoff=RETRY_WAIT,
            headers={"Auth-Key": self._abusech_key},
        )
        self._cache = DiskCache(SOURCE_ID, ttl=timedelta(hours=CACHE_TTL_HOURS))

    def query(self, actor_name: str) -> dict | None:
        """Standard interface stub -- URLhaus is enrichment-only."""
        return None

    def collect_for_malware_families(
        self,
        malware_names: list[str],
        actor_name: str,
    ) -> dict[str, Any] | None:
        """
        Query URLhaus for each malware family and aggregate URLs.

        Args:
            malware_names: Malware/tool names from the actor profile.
            actor_name:    Canonical actor name (for schema output).

        Returns:
            CommonSchema-compatible dict, or None if no URLs found.
        """
        if not malware_names:
            return None

        if not self._abusech_key:
            logger.info(
                "URLhaus: skipped -- no ABUSECH_API_KEY. "
                "Get one free at https://auth.abuse.ch/"
            )
            return None

        all_iocs: list[dict] = []
        seen_urls: set[str] = set()
        family_hits: dict[str, int] = {}

        logger.info(
            "URLhaus: querying %d malware families for %s",
            len(malware_names), actor_name,
        )

        failed: dict[str, str] = {}
        for family_name in malware_names:
            try:
                urls = self._fetch_family_urls(family_name)
            except HttpError as exc:
                failed[family_name] = str(exc)
                continue
            if urls:
                family_hits[family_name] = len(urls)
                for url_ioc in urls:
                    key = url_ioc["value"].lower()
                    if key not in seen_urls:
                        seen_urls.add(key)
                        url_ioc["malware_family"] = family_name
                        all_iocs.append(url_ioc)

        if failed:
            # Not cached: the next run asks again rather than believing
            # "nothing found" for a day because of one timeout or a bad key.
            logger.warning(
                "URLhaus: %d of %d families could not be queried (not cached); "
                "first error: %s",
                len(failed), len(malware_names), next(iter(failed.values())),
            )

        if not all_iocs:
            logger.info("URLhaus: no URLs found for any malware family")
            return None

        # Sort: active URLs first, then by recency
        all_iocs.sort(key=lambda x: (
            0 if x.get("url_status") in _ACTIVE_STATUSES else 1,
            x.get("first_seen", ""),
        ), reverse=True)

        # Cap total IOCs to avoid overwhelming the dossier
        all_iocs = all_iocs[:200]

        logger.info(
            "URLhaus: %d unique URLs across %d families with hits: %s",
            len(all_iocs),
            len(family_hits),
            ", ".join(f"{k}({v})" for k, v in list(family_hits.items())[:5]),
        )

        return {
            "actor_name":    actor_name,
            "source_id":     SOURCE_ID,
            "aliases":       [],
            "description":   "",
            "origin":        "",
            "first_seen":    "",
            "motivations":   [],
            "techniques":    [],
            "indicators":    all_iocs,
            "malware":       [],
            "campaigns":     [],
            "sectors":       [],
            "family_hits":   family_hits,
            "raw_source":    "URLhaus (abuse.ch)",
        }

    # ------------------------------------------------------------------
    # Per-family URL fetch
    # ------------------------------------------------------------------

    def _fetch_family_urls(self, family_name: str) -> list[dict]:
        """Query URLhaus for URLs tagged with a malware family.

        Returns [] when URLhaus answered that it has nothing. Raises
        HttpError when the question could not be answered (timeout, 5xx, 429,
        bad key); those outcomes are never cached.
        """
        def load() -> list[dict]:
            data = self._http.post_form(
                TAG_ENDPOINT, {"tag": family_name, "limit": MAX_URLS_PER_FAMILY},
            )
            time.sleep(0.3)  # polite pacing — abuse.ch is a community resource
            if not interpret_query_status(data, source="URLhaus", url=TAG_ENDPOINT):
                logger.debug("URLhaus: no results for %r", family_name)
                return []
            raw = data.get("urls") or []
            if not isinstance(raw, list):
                raise BadResponse("URLhaus: unexpected data shape", url=TAG_ENDPOINT, status=200)
            parsed = [self._parse_url(item) for item in raw]
            parsed = [item for item in parsed if item]
            logger.debug("URLhaus: %d urls for %r", len(parsed), family_name)
            return parsed

        return self._cache.fetch(_slugify(family_name), load, default=[])

    # ------------------------------------------------------------------
    # URL parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_url(raw: dict) -> dict | None:
        """Parse a raw URLhaus record into THEORY's IOC schema."""
        url_value = (raw.get("url") or "").strip()
        if not url_value:
            return None

        url_status   = (raw.get("url_status") or "").lower()
        threat       = (raw.get("threat") or "").lower()
        threat_label = _THREAT_LABELS.get(threat, "Payload Delivery")
        date_added   = (raw.get("dateadded") or "")[:10]
        tags         = raw.get("tags") or []
        reporter     = (raw.get("reporter") or "").strip()
        host         = (raw.get("host") or "").strip()

        # Extract payload hashes if available
        payloads = raw.get("payloads") or []
        payload_hashes = []
        for p in payloads[:3]:
            sha256 = (p.get("response_sha256") or "").strip()
            if sha256:
                payload_hashes.append(sha256)

        # Determine confidence based on status
        if url_status == "online":
            confidence = 90
        elif url_status == "offline":
            confidence = 50
        else:
            confidence = 65

        description = f"{threat_label} URL"
        if host:
            description += f" ({host})"
        if url_status == "online":
            description += " [ACTIVE]"

        return {
            "type":            "url",
            "value":           url_value,
            "confidence":      confidence,
            "threat_type":     "payload_delivery",
            "threat_label":    threat_label,
            "first_seen":      date_added,
            "last_seen":       "",
            "tags":            tags if isinstance(tags, list) else [],
            "malware":         "",
            "description":     description,
            "sources":         [SOURCE_ID],
            # Extra fields
            "url_status":      url_status,
            "host":            host,
            "reporter":        reporter,
            "payload_hashes":  payload_hashes,
        }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _slugify(name: str) -> str:
    """Convert malware name to a safe cache filename."""
    return re.sub(r"[^a-z0-9_]", "_", name.lower())[:80]
