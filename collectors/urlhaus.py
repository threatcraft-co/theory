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

Cache: .cache/urlhaus/{family_slug}.json, TTL 24 hours
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from collectors.base import BaseCollector

logger = logging.getLogger(__name__)

SOURCE_ID             = "urlhaus"
API_BASE              = "https://urlhaus-api.abuse.ch/v1"
TAG_ENDPOINT          = f"{API_BASE}/tag/"
CACHE_DIR             = Path(".cache/urlhaus")
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

        for family_name in malware_names:
            urls = self._fetch_family_urls(family_name)
            if urls:
                family_hits[family_name] = len(urls)
                for url_ioc in urls:
                    key = url_ioc["value"].lower()
                    if key not in seen_urls:
                        seen_urls.add(key)
                        url_ioc["malware_family"] = family_name
                        all_iocs.append(url_ioc)
            time.sleep(0.3)

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
        """Query URLhaus for URLs tagged with a malware family."""
        cache_key = _slugify(family_name)
        cached = self._load_cache(cache_key)
        if cached is not None:
            return cached

        form_data = urlencode({
            "tag":   family_name,
            "limit": MAX_URLS_PER_FAMILY,
        }).encode("utf-8")

        try:
            data = self._api_post(TAG_ENDPOINT, form_data)
        except Exception as exc:
            logger.debug("URLhaus fetch failed for %r: %s", family_name, exc)
            self._save_cache(cache_key, [])
            return []

        if not isinstance(data, dict):
            self._save_cache(cache_key, [])
            return []

        query_status = data.get("query_status", "")
        if query_status == "no_results":
            logger.debug("URLhaus: no results for %r", family_name)
            self._save_cache(cache_key, [])
            return []

        raw_urls = data.get("urls", []) or []
        if not isinstance(raw_urls, list):
            self._save_cache(cache_key, [])
            return []

        parsed = [self._parse_url(u) for u in raw_urls]
        parsed = [u for u in parsed if u]

        self._save_cache(cache_key, parsed)
        logger.debug("URLhaus: %d URLs for %r", len(parsed), family_name)
        return parsed

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

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _load_cache(self, cache_key: str) -> list[dict] | None:
        cache_path = CACHE_DIR / f"{cache_key}.json"
        if not cache_path.exists():
            return None
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            cached_at = datetime.fromisoformat(data.get("cached_at", "2000-01-01"))
            age = datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc)
            if age > timedelta(hours=CACHE_TTL_HOURS):
                logger.debug("URLhaus cache stale for %s", cache_key)
                return None
            return data.get("urls", [])
        except Exception:
            return None

    def _save_cache(self, cache_key: str, urls: list[dict]) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path = CACHE_DIR / f"{cache_key}.json"
        cache_path.write_text(
            json.dumps({
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "urls":      urls,
            }, indent=2),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _api_post(self, url: str, form_data: bytes) -> Any:
        """POST form-encoded data to URLhaus API."""
        req = Request(
            url,
            data=form_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Auth-Key":     self._abusech_key,
                "User-Agent":   "THEORY/1.0 threat-intel-research",
            },
            method="POST",
        )
        for attempt in range(1, RETRY_MAX + 1):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except HTTPError as exc:
                if exc.code == 429 and attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT * attempt)
                else:
                    raise
            except URLError:
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT)
                else:
                    raise
        return {}


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _slugify(name: str) -> str:
    """Convert malware name to a safe cache filename."""
    return re.sub(r"[^a-z0-9_]", "_", name.lower())[:80]
