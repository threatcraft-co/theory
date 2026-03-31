"""
collectors/malpedia.py
----------------------
Pulls malware family data from Malpedia.

API response for /api/get/actor/{slug}:
{
  "families": {
    "win.x_agent": {"urls": [...], "uuid": "...", "notes": [], ...},
    ...
  },
  "description": "...",
  "meta": {...},
  "value": "APT28",
  "uuid": "..."
}

No auth required. Responses cached to .cache/malpedia/.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from collectors.base import BaseCollector
from collectors.cisa_advisories import resolve_canonical

logger = logging.getLogger(__name__)

SOURCE_ID  = "malpedia"
BASE_URL   = "https://malpedia.caad.fkie.fraunhofer.de"
CACHE_DIR  = Path(".cache/malpedia")
TIMEOUT    = 15
RETRY_MAX  = 2
RETRY_WAIT = 2

_MALPEDIA_ACTOR_SLUGS: dict[str, str] = {
    "APT28":          "apt28",
    "APT29":          "apt29",
    "APT41":          "apt41",
    "Lazarus Group":  "lazarus_group",
    "APT10":          "apt10",
    "Sandworm":       "sandworm",
    "Turla":          "turla",
    "APT33":          "apt33",
    "APT34":          "apt34",
    "Kimsuky":        "kimsuky",
    "FIN7":           "fin7",
    "FIN8":           "fin8",
    "Volt Typhoon":   "volt_typhoon",
    "Equation Group": "equation_group",
}

# ISO 3166 → country name
_ISO_TO_COUNTRY: dict[str, str] = {
    "RU": "Russia", "CN": "China", "IR": "Iran",
    "KP": "North Korea", "US": "United States",
    "UK": "United Kingdom", "IN": "India",
    "VN": "Vietnam", "BY": "Belarus",
}


class MalpediaCollector(BaseCollector):

    SOURCE_ID = SOURCE_ID

    def query(self, actor_name: str) -> dict | None:
        return self.collect(actor_name)

    def collect(self, actor_name: str) -> dict[str, Any] | None:
        canonical = resolve_canonical(actor_name)
        slug      = _MALPEDIA_ACTOR_SLUGS.get(canonical) or \
                    canonical.lower().replace(" ", "_").replace("-", "_")

        logger.info("Malpedia: querying actor slug %r", slug)

        actor_data = self._fetch_actor(slug)
        if actor_data is None:
            return None

        # families is a dict: { "win.x_agent": {urls, uuid, ...}, ... }
        families_raw = actor_data.get("families", {})
        if isinstance(families_raw, dict):
            family_slugs = list(families_raw.keys())
        elif isinstance(families_raw, list):
            family_slugs = [str(s) for s in families_raw]
        else:
            family_slugs = []

        families = self._enrich_families(family_slugs[:30])

        meta = actor_data.get("meta", {}) or {}

        return {
            "actor_name":   canonical,
            "source_id":    SOURCE_ID,
            "aliases":      self._extract_aliases(actor_data),
            "description":  actor_data.get("description", "") or "",
            "origin":       self._extract_origin(meta),
            "first_seen":   str(meta.get("since", "")) if meta.get("since") else "",
            "motivations":  self._extract_motivations(meta),
            "techniques":   [],
            "indicators":   [],
            "malware":      families,
            "campaigns":    [],
            "sectors":      self._extract_sectors(meta),
            "malpedia_url": f"{BASE_URL}/actor/{slug}",
            "raw_source":   "Malpedia",
        }

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    def _fetch_actor(self, slug: str) -> dict | None:
        url = f"{BASE_URL}/api/get/actor/{slug}"
        try:
            data = _fetch_json(url, cache_key=f"actor_{slug}")
            if not data or not isinstance(data, dict):
                logger.info("Malpedia: actor %r returned no data.", slug)
                return None
            # Malpedia returns {"detail": "Not found."} for missing actors
            if "detail" in data and "families" not in data:
                logger.info("Malpedia: actor %r not found.", slug)
                return None
            return data
        except Exception as exc:
            logger.warning("Malpedia actor fetch failed for %r: %s", slug, exc)
            return None

    def _enrich_families(self, family_slugs: list[str]) -> list[dict]:
        families: list[dict] = []
        for slug in family_slugs:
            detail = self._fetch_family(slug)
            if detail:
                families.append(self._normalise_family(slug, detail))
            time.sleep(0.1)
        return families

    def _fetch_family(self, slug: str) -> dict | None:
        url = f"{BASE_URL}/api/get/family/{slug}"
        try:
            return _fetch_json(url, cache_key=f"family_{slug}")
        except Exception as exc:
            logger.debug("Malpedia family fetch failed for %r: %s", slug, exc)
            return None

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_family(slug: str, detail: dict) -> dict:
        name = detail.get("common_name") or _slug_to_display(slug)
        desc = detail.get("description", "") or ""
        desc = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", desc)  # strip md links
        return {
            "name":          name,
            "type":          _classify_family(detail),
            "description":   (desc[:400].rstrip() + "…") if len(desc) > 400 else desc,
            "aliases":       detail.get("alt_names", []) or [],
            "malpedia_slug": slug,
            "yara_count":    len(detail.get("yara", []) or []),
            "sources":       [SOURCE_ID],
        }

    @staticmethod
    def _extract_aliases(actor_data: dict) -> list[str]:
        # Malpedia stores synonyms under meta.synonyms or as a list of names
        meta = actor_data.get("meta", {}) or {}
        syns = meta.get("synonyms", []) or []
        return [s for s in syns if s]

    @staticmethod
    def _extract_origin(meta: dict) -> str:
        country = meta.get("country", "") or ""
        return _ISO_TO_COUNTRY.get(country.upper(), country)

    @staticmethod
    def _extract_motivations(meta: dict) -> list[str]:
        mot = meta.get("motivation", []) or []
        if isinstance(mot, str):
            return [mot] if mot else []
        return [m for m in mot if m]

    @staticmethod
    def _extract_sectors(meta: dict) -> list[str]:
        targets = meta.get("cfr-target-category", []) or \
                  meta.get("cfr_target_category", []) or []
        if isinstance(targets, str):
            return [targets] if targets else []
        return [t for t in targets if t]


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

class MalpediaMapper:

    def map(self, raw: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise ValueError(f"Expected dict, got {type(raw).__name__}")
        actor_name = (raw.get("actor_name") or "").strip()
        if not actor_name:
            raise ValueError("raw record missing 'actor_name'")
        return {
            "actor_name":   actor_name,
            "source_id":    raw.get("source_id", SOURCE_ID),
            "aliases":      _clean(raw.get("aliases", [])),
            "description":  raw.get("description", ""),
            "origin":       raw.get("origin", ""),
            "first_seen":   raw.get("first_seen", ""),
            "motivations":  _clean(raw.get("motivations", [])),
            "techniques":   [],
            "indicators":   [],
            "malware":      self._map_malware(raw.get("malware", [])),
            "campaigns":    [],
            "sectors":      _clean(raw.get("sectors", [])),
            "malpedia_url": raw.get("malpedia_url", ""),
        }

    def _map_malware(self, families: list[dict]) -> list[dict]:
        out = []
        for f in families:
            if not isinstance(f, dict) or not (f.get("name") or "").strip():
                continue
            out.append({
                "name":        f["name"],
                "type":        f.get("type", "malware"),
                "description": f.get("description", ""),
                "aliases":     f.get("aliases", []),
                "yara_count":  f.get("yara_count", 0),
                "sources":     f.get("sources", [SOURCE_ID]),
            })
        return out


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _slug_to_display(slug: str) -> str:
    name = re.sub(r"^[a-z]+\.", "", slug)
    return name.replace("_", " ").title()


def _classify_family(detail: dict) -> str:
    tags = [t.lower() for t in (detail.get("tags") or [])]
    for tag, label in [
        ("ransomware", "ransomware"), ("backdoor", "backdoor"),
        ("rootkit", "rootkit"),       ("loader", "loader"),
        ("dropper", "loader"),        ("infostealer", "infostealer"),
        ("stealer", "infostealer"),   ("rat", "rat"),
        ("wiper", "wiper"),           ("tool", "tool"),
        ("utility", "tool"),
    ]:
        if tag in tags:
            return label
    return "malware"


def _clean(items: list) -> list[str]:
    seen: set[str] = set()
    out:  list[str] = []
    for item in items:
        s = str(item).strip()
        if s and s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    return out


def _fetch_json(url: str, cache_key: str | None = None,
                timeout: int = TIMEOUT) -> Any:
    if cache_key:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path = CACHE_DIR / f"{cache_key}.json"
        if cache_path.exists():
            logger.debug("Cache hit: %s", cache_key)
            return json.loads(cache_path.read_text(encoding="utf-8"))

    req = Request(url, headers={"User-Agent": "THEORY/1.0 threat-intel-research"})
    for attempt in range(1, RETRY_MAX + 1):
        try:
            with urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if cache_key:
                    cache_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
                return data
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
    return None
