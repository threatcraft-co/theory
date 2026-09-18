"""
collectors/circl_misp.py
-------------------------
Pulls threat event data (indicators, tags, descriptions) from CIRCL's
free public OSINT MISP feed.

Data source:
  https://www.circl.lu/doc/misp/feed-osint/
  Manifest: https://www.circl.lu/doc/misp/feed-osint/manifest.json
  Events:   https://www.circl.lu/doc/misp/feed-osint/<event-uuid>.json

CIRCL (Computer Incident Response Center Luxembourg) publishes a
standing feed of MISP events aggregated from public threat reporting —
several thousand events, each with an "info" title, tags (including
MISP Galaxy actor/malware cluster tags), and a set of attributes
(IOCs: IPs, domains, URLs, hashes, etc). No authentication required.

Why this is different from misp_galaxy:
  misp_galaxy.py pulls the static *cluster definitions* — the alias
  table and metadata for ~1000 named actors. This collector pulls
  *event data* — actual indicators tied to specific reported activity,
  searchable by actor name/alias appearing in an event's title or tags.
  They're complementary: misp_galaxy tells you who an actor is;
  circl_misp tells you what's been directly reported about them.

Search strategy:
  The manifest (~a few MB) is a single indexed file listing every
  event's info/date/tags without requiring a fetch per event, so
  actor matching happens against the manifest first — case-insensitive
  substring match against info + tag values, using the same canonical
  alias resolution as other collectors. Only matched events (capped)
  are then fetched individually for their attribute lists.

Pipeline position:
  Actor-centric collector, same as otx.py / misp_galaxy.py — query()
  returns a schema-conformant profile with indicators/campaigns
  populated directly (no separate enrichment pass needed).
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from collectors.base import BaseCollector

try:
    from collectors.cisa_advisories import resolve_canonical, ALIAS_TABLE
except ImportError:
    def resolve_canonical(name: str) -> str:
        return name.strip()
    ALIAS_TABLE: dict[str, list[str]] = {}

logger = logging.getLogger(__name__)

SOURCE_ID = "circl_misp"

FEED_BASE = "https://www.circl.lu/doc/misp/feed-osint"
MANIFEST_URL = f"{FEED_BASE}/manifest.json"

CACHE_DIR = Path(".cache/circl_misp")
MANIFEST_CACHE = CACHE_DIR / "manifest.json"
MANIFEST_CACHE_TTL_SECONDS = 24 * 3600   # 24 hours — feed updates frequently
EVENT_CACHE_TTL_SECONDS = 7 * 24 * 3600  # events themselves rarely change once published

TIMEOUT = 30
RETRY_MAX = 2
RETRY_WAIT = 3

# Don't fetch unbounded matches for a broadly-named actor — cap it and
# prioritize the most recently dated matching events.
MAX_EVENTS_FETCHED = 8
MAX_ATTRIBUTES_PER_EVENT = 100   # some events carry hundreds of IOCs; keep it sane

# MISP attribute type -> THEORY indicator type
_TYPE_MAP: dict[str, str] = {
    "ip-dst": "ip", "ip-src": "ip", "ip-dst|port": "ip", "ip-src|port": "ip",
    "domain": "domain", "hostname": "domain",
    "url": "url", "uri": "url",
    "md5": "hash_md5", "sha1": "hash_sha1", "sha256": "hash_sha256",
    "email-src": "email", "email-dst": "email", "email": "email",
    "filename": "filename",
    "regkey": "registry_key",
    "mutex": "mutex",
}


class CirclMispCollector(BaseCollector):
    """Collector for CIRCL's free public OSINT MISP event feed."""

    SOURCE_ID = SOURCE_ID
    REQUIRES_API_KEY = False

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._manifest: dict[str, Any] | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def query(self, actor_name: str) -> dict[str, Any] | None:
        canonical = resolve_canonical(actor_name)
        search_terms = self._search_terms(actor_name, canonical)

        manifest = self._load_manifest()
        if manifest is None:
            logger.warning("CIRCL MISP: manifest unavailable, skipping.")
            return None

        matches = self._match_events(manifest, search_terms)
        if not matches:
            logger.info("CIRCL MISP: no matching events for '%s'.", canonical)
            matches = []

        indicators: list[dict] = []
        campaigns: list[dict] = []
        seen_info: set[str] = set()

        for event_uuid, meta in matches[:MAX_EVENTS_FETCHED]:
            event = self._load_event(event_uuid)
            if not event:
                continue
            ev = event.get("Event", event)

            info = (ev.get("info") or "").strip()
            if info and info not in seen_info:
                seen_info.add(info)
                campaigns.append({
                    "name": info,
                    "description": "",
                    "url": f"{FEED_BASE}/{event_uuid}.json",
                    "first_seen": (ev.get("date") or ""),
                    "last_seen": "",
                })

            for attr in ev.get("Attribute", [])[:MAX_ATTRIBUTES_PER_EVENT]:
                ind = self._map_attribute(attr, info)
                if ind:
                    indicators.append(ind)

        logger.info(
            "CIRCL MISP: %d matching events, %d indicators for '%s'.",
            len(matches), len(indicators), canonical,
        )

        return {
            "actor_name": canonical,
            "source_id": SOURCE_ID,
            "source_url": "https://www.circl.lu/doc/misp/feed-osint/",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "aliases": [],
            "description": "",
            "suspected_origin": None,
            "origin": "",
            "motivation": [],
            "motivations": [],
            "first_seen": None,
            "sponsorship": None,
            "target_sectors": [],
            "sectors": [],
            "target_countries": [],
            "techniques": [],
            "malware": [],
            "indicators": indicators,
            "campaigns": campaigns,
            "cves": [],
            "source_citation": SOURCE_ID,
            "raw_source": "CIRCL OSINT MISP Feed",
        }

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def _search_terms(self, actor_name: str, canonical: str) -> list[str]:
        terms = {actor_name.strip().lower(), canonical.strip().lower()}
        for alias in ALIAS_TABLE.get(canonical, []):
            terms.add(alias.strip().lower())
        return [t for t in terms if t]

    def _match_events(
        self, manifest: dict[str, Any], search_terms: list[str]
    ) -> list[tuple[str, dict]]:
        matched: list[tuple[str, dict]] = []
        for event_uuid, meta in manifest.items():
            haystack = (meta.get("info") or "").lower()
            tags = meta.get("Tag") or []
            tag_text = " ".join(
                (t.get("name", "") if isinstance(t, dict) else str(t)) for t in tags
            ).lower()
            haystack = f"{haystack} {tag_text}"

            if any(term in haystack for term in search_terms):
                matched.append((event_uuid, meta))

        # Most recent first
        matched.sort(key=lambda m: m[1].get("date", ""), reverse=True)
        return matched

    def _map_attribute(self, attr: dict, event_info: str) -> dict[str, Any] | None:
        raw_type = (attr.get("type") or "").lower()
        theory_type = _TYPE_MAP.get(raw_type)
        if not theory_type:
            return None

        value = (attr.get("value") or "").strip()
        if not value:
            return None
        # Some MISP composite types carry "value|value" (e.g. ip-dst|port) —
        # take just the first component for the ones we map to a single type.
        if "|" in value and raw_type in ("ip-dst|port", "ip-src|port"):
            value = value.split("|")[0].strip()

        return {
            "type": theory_type,
            "value": value,
            "confidence": 0,   # numeric placeholder; THEORY recomputes via source-count confidence
            "threat_type": "",
            "threat_label": "",
            "first_seen": (attr.get("timestamp") or ""),
            "last_seen": "",
            "tags": [],
            "malware": "",
            "description": event_info,
            "sources": [SOURCE_ID],
        }

    # ------------------------------------------------------------------
    # Manifest + event loading with caching
    # ------------------------------------------------------------------

    def _load_manifest(self) -> dict[str, Any] | None:
        if self._manifest is not None:
            return self._manifest

        if MANIFEST_CACHE.exists():
            age = time.time() - MANIFEST_CACHE.stat().st_mtime
            if age < MANIFEST_CACHE_TTL_SECONDS:
                try:
                    self._manifest = json.loads(MANIFEST_CACHE.read_text(encoding="utf-8"))
                    return self._manifest
                except (json.JSONDecodeError, OSError):
                    pass

        data = self._download(MANIFEST_URL)
        if data is None:
            if MANIFEST_CACHE.exists():
                logger.warning("CIRCL MISP: download failed, using stale manifest cache.")
                try:
                    self._manifest = json.loads(MANIFEST_CACHE.read_text(encoding="utf-8"))
                    return self._manifest
                except Exception:
                    pass
            return None

        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            MANIFEST_CACHE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:
            logger.debug("CIRCL MISP: manifest cache write failed: %s", exc)

        self._manifest = data
        return data

    def _load_event(self, event_uuid: str) -> dict[str, Any] | None:
        cache_path = CACHE_DIR / f"{event_uuid}.json"
        if cache_path.exists():
            age = time.time() - cache_path.stat().st_mtime
            if age < EVENT_CACHE_TTL_SECONDS:
                try:
                    return json.loads(cache_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    pass

        data = self._download(f"{FEED_BASE}/{event_uuid}.json")
        if data is None:
            return None

        try:
            cache_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:
            logger.debug("CIRCL MISP: event cache write failed for %s: %s", event_uuid, exc)

        return data

    def _download(self, url: str) -> dict[str, Any] | None:
        req = Request(url, headers={
            "User-Agent": "THEORY/1.0 threat-intel-research",
            "Accept": "application/json",
        })
        for attempt in range(1, RETRY_MAX + 1):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except HTTPError as exc:
                logger.warning(
                    "CIRCL MISP: HTTP %d on attempt %d/%d for %s.",
                    exc.code, attempt, RETRY_MAX, url,
                )
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT * attempt)
            except (URLError, OSError, json.JSONDecodeError) as exc:
                logger.warning(
                    "CIRCL MISP: request error on attempt %d/%d for %s: %s",
                    attempt, RETRY_MAX, url, exc,
                )
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT)
        return None


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

class CirclMispMapper:
    """Post-processing mapper. Records from the collector are already
    schema-conformant; this validates and passes through."""

    def map(self, raw: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise ValueError(f"Expected dict, got {type(raw).__name__}")
        actor_name = (raw.get("actor_name") or "").strip()
        if not actor_name:
            raise ValueError("raw record missing 'actor_name'")
        return raw
