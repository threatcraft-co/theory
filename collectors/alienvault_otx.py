"""
collectors/alienvault_otx.py
-----------------------------
Pulls threat actor intelligence from AlienVault OTX.

Key fix vs Phase 4 initial: OTX search results don't include indicators —
we must fetch each pulse individually via /api/v1/pulses/{id} to get IOCs.

API key: set OTX_API_KEY in .env
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote

from collectors.base import BaseCollector
from collectors.cisa_advisories import resolve_canonical, all_aliases_for

logger = logging.getLogger(__name__)

SOURCE_ID  = "alienvault_otx"
BASE_URL   = "https://otx.alienvault.com"
CACHE_DIR  = Path(".cache/otx")
TIMEOUT    = 10    # shorter timeout — fail fast, don't block the pipeline
RETRY_MAX  = 2
RETRY_WAIT = 2

_IOC_TYPE_MAP: dict[str, str] = {
    "IPv4":            "ip",
    "IPv6":            "ip",
    "domain":          "domain",
    "hostname":        "domain",
    "URL":             "url",
    "FileHash-MD5":    "hash_md5",
    "FileHash-SHA1":   "hash_sha1",
    "FileHash-SHA256": "hash_sha256",
    "email":           "email",
    "CVE":             "cve",
}

# OTX adversary slugs (the /adversaries/ endpoint uses these)
_OTX_ACTOR_SLUGS: dict[str, str] = {
    "APT28":          "APT28",
    "APT29":          "APT29",
    "APT41":          "APT41",
    "Lazarus Group":  "Lazarus+Group",
    "APT10":          "APT10",
    "Sandworm":       "Sandworm",
    "Turla":          "Turla",
    "APT33":          "APT33",
    "APT34":          "OilRig",
    "Kimsuky":        "Kimsuky",
    "FIN7":           "FIN7",
    "Volt Typhoon":   "Volt+Typhoon",
    "Scattered Spider": "Scattered+Spider",
}

_MAX_IOCS_PER_TYPE = 10
_MAX_PULSES        = 15   # reduced to limit network time
# Only search canonical name + 2 most recognisable aliases to avoid timeouts
_MAX_ALIAS_SEARCHES = 2


class AlienVaultOTXCollector(BaseCollector):

    SOURCE_ID = SOURCE_ID

    def __init__(self):
        self._api_key = self._load_api_key()

    def query(self, actor_name: str) -> dict | None:
        return self.collect(actor_name)

    def collect(self, actor_name: str) -> dict[str, Any] | None:
        if not self._api_key:
            logger.error("OTX_API_KEY not set. Add it to your .env file.")
            return None

        canonical = resolve_canonical(actor_name)
        slug      = _OTX_ACTOR_SLUGS.get(canonical, canonical)
        aliases   = all_aliases_for(actor_name)

        logger.info("OTX: querying actor %r (slug: %s)", canonical, slug)

        # 1. Try the adversary endpoint (returns pulse list with indicators)
        pulses = self._fetch_adversary_pulses(slug)

        # 2. Fall back to pulse search — canonical name only first
        if not pulses:
            pulses = self._search_and_fetch_pulses(canonical, aliases)

        if not pulses:
            logger.info("OTX: no pulses found for %r", canonical)
            return None

        iocs       = self._aggregate_iocs(pulses)
        sectors    = self._extract_sectors(pulses)
        techniques = self._extract_techniques(pulses)
        malware    = self._extract_malware(pulses)
        first_seen = self._extract_first_seen(pulses)

        return {
            "actor_name":  canonical,
            "source_id":   SOURCE_ID,
            "aliases":     [],
            "description": self._build_description(pulses),
            "origin":      "",
            "first_seen":  first_seen,
            "motivations": [],
            "techniques":  techniques,
            "indicators":  iocs,
            "malware":     malware,
            "campaigns":   [],
            "sectors":     sectors,
            "pulse_count": len(pulses),
            "raw_source":  "AlienVault OTX",
        }

    # ------------------------------------------------------------------
    # API key
    # ------------------------------------------------------------------

    @staticmethod
    def _load_api_key() -> str:
        key = os.environ.get("OTX_API_KEY", "")
        if key:
            return key
        env_path = Path(".env")
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                if line.startswith("OTX_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        return ""

    # ------------------------------------------------------------------
    # Adversary endpoint — returns pulses WITH indicators inline
    # ------------------------------------------------------------------

    def _fetch_adversary_pulses(self, slug: str) -> list[dict]:
        url = f"{BASE_URL}/api/v1/adversaries/{quote(slug)}/pulses/?limit={_MAX_PULSES}"
        try:
            data   = self._get(url, cache_key=f"adv_{slug.lower().replace('+','_')}")
            pulses = data.get("results", []) if isinstance(data, dict) else []
            logger.info("OTX adversary endpoint: %d pulses", len(pulses))
            return pulses
        except Exception as exc:
            logger.debug("OTX adversary endpoint failed for %r: %s", slug, exc)
            return []

    # ------------------------------------------------------------------
    # Search fallback — search returns stubs, fetch each pulse for IOCs
    # ------------------------------------------------------------------

    def _search_and_fetch_pulses(
        self, canonical: str, aliases: frozenset[str]
    ) -> list[dict]:
        # Search only canonical name + top N aliases to avoid timeouts
        search_terms = [canonical]
        # Pick short, distinctive aliases (avoid IDs like G0007, TA422)
        clean_aliases = [
            a for a in aliases
            if len(a) > 4 and not re.match(r"^[gt]\d+$", a, re.I)
        ]
        search_terms += clean_aliases[:_MAX_ALIAS_SEARCHES]

        stub_ids:  dict[str, dict] = {}   # id → stub
        for term in search_terms:
            cache_key = f"search_{re.sub(r'[^a-z0-9]', '_', term.lower())}"
            url = f"{BASE_URL}/api/v1/search/pulses?q={quote(term)}&limit=10"
            try:
                data = self._get(url, cache_key=cache_key)
                for pulse in (data.get("results", []) if isinstance(data, dict) else []):
                    pid = pulse.get("id", "")
                    if pid and pid not in stub_ids:
                        stub_ids[pid] = pulse
            except Exception as exc:
                logger.debug("OTX search failed for %r: %s", term, exc)

        logger.info("OTX search: %d unique pulse stubs", len(stub_ids))

        # Fetch full pulse detail (includes indicators) for each stub
        full_pulses: list[dict] = []
        for pid in list(stub_ids.keys())[:_MAX_PULSES]:
            full = self._fetch_pulse(pid)
            if full:
                full_pulses.append(full)

        return full_pulses

    def _fetch_pulse(self, pulse_id: str) -> dict | None:
        url = f"{BASE_URL}/api/v1/pulses/{pulse_id}"
        try:
            return self._get(url, cache_key=f"pulse_{pulse_id}")
        except Exception as exc:
            logger.debug("OTX pulse fetch failed for %r: %s", pulse_id, exc)
            return None

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _get(self, url: str, cache_key: str | None = None) -> Any:
        if cache_key:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache_path = CACHE_DIR / f"{cache_key}.json"
            if cache_path.exists():
                logger.debug("OTX cache hit: %s", cache_key)
                return json.loads(cache_path.read_text(encoding="utf-8"))

        req = Request(url, headers={
            "X-OTX-API-KEY": self._api_key,
            "User-Agent":    "THEORY/1.0 threat-intel-research",
        })

        for attempt in range(1, RETRY_MAX + 1):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    if cache_key:
                        cache_path.write_text(json.dumps(data, indent=2),
                                              encoding="utf-8")
                    return data
            except HTTPError as exc:
                if exc.code == 403:
                    logger.error("OTX 403 — check your API key.")
                    raise
                if exc.code == 429 and attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT * attempt)
                else:
                    raise
            except Exception as exc:
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT)
                else:
                    logger.debug("OTX request failed: %s", exc)
                    raise
        return {}

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def _aggregate_iocs(self, pulses: list[dict]) -> list[dict]:
        seen:    set[str]           = set()
        by_type: dict[str, list]    = {}

        for pulse in pulses:
            for ind in (pulse.get("indicators") or []):
                ioc_type = _IOC_TYPE_MAP.get(ind.get("type", ""), "")
                if not ioc_type:
                    continue
                value = (ind.get("indicator") or "").strip()
                if not value or value in seen:
                    continue
                seen.add(value)
                by_type.setdefault(ioc_type, []).append({
                    "type":        ioc_type,
                    "value":       value,
                    "description": ind.get("description", ""),
                    "created":     ind.get("created", ""),
                    "sources":     [SOURCE_ID],
                })

        result: list[dict] = []
        for ioc_type in sorted(by_type):
            result.extend(by_type[ioc_type][:_MAX_IOCS_PER_TYPE])

        logger.info("OTX: %d unique IOCs extracted", len(result))
        return result

    def _extract_sectors(self, pulses: list[dict]) -> list[str]:
        seen:    set[str]  = set()
        sectors: list[str] = []
        for pulse in pulses:
            for tag in (pulse.get("tags") or []):
                for kw, sector in _SECTOR_MAP.items():
                    if kw in tag.lower() and sector.lower() not in seen:
                        seen.add(sector.lower())
                        sectors.append(sector)
        return sectors

    def _extract_techniques(self, pulses: list[dict]) -> list[dict]:
        seen: set[str]   = set()
        out:  list[dict] = []
        for pulse in pulses:
            text = " ".join([
                pulse.get("description", ""),
                " ".join(pulse.get("tags", [])),
                " ".join(
                    str(r.get("external_id", ""))
                    for r in (pulse.get("attack_ids") or [])
                ),
            ])
            for tid in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text):
                if tid not in seen:
                    seen.add(tid)
                    out.append({
                        "technique_id":   tid,
                        "technique_name": "",
                        "tactic":         "",
                        "tactics":        [],
                        "description":    "",
                        "detection":      "",
                        "sources":        [SOURCE_ID],
                    })
        # Also extract from attack_ids field directly
        for pulse in pulses:
            for atk in (pulse.get("attack_ids") or []):
                tid = (atk.get("id") or atk.get("external_id") or "").strip().upper()
                if re.match(r"^T\d{4}(?:\.\d{3})?$", tid) and tid not in seen:
                    seen.add(tid)
                    out.append({
                        "technique_id":   tid,
                        "technique_name": atk.get("display_name", ""),
                        "tactic":         "",
                        "tactics":        [],
                        "description":    "",
                        "detection":      "",
                        "sources":        [SOURCE_ID],
                    })
        return out

    def _extract_malware(self, pulses: list[dict]) -> list[dict]:
        seen: set[str]   = set()
        out:  list[dict] = []
        for pulse in pulses:
            for mw in (pulse.get("malware_families") or []):
                name = (mw.get("display_name") or mw.get("id") or "").strip()
                if name and name.lower() not in seen:
                    seen.add(name.lower())
                    out.append({
                        "name":    name,
                        "type":    "malware",
                        "description": "",
                        "sources": [SOURCE_ID],
                    })
        return out

    def _extract_first_seen(self, pulses: list[dict]) -> str:
        years = []
        for pulse in pulses:
            m = re.match(r"(\d{4})", pulse.get("created", ""))
            if m:
                years.append(m.group(1))
        return min(years) if years else ""

    def _build_description(self, pulses: list[dict]) -> str:
        if not pulses:
            return ""
        best = max(pulses, key=lambda p: p.get("subscriber_count", 0))
        desc = best.get("description", "") or ""
        return (desc[:800].rstrip() + "…") if len(desc) > 800 else desc


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

class AlienVaultOTXMapper:

    def map(self, raw: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise ValueError(f"Expected dict, got {type(raw).__name__}")
        actor_name = (raw.get("actor_name") or "").strip()
        if not actor_name:
            raise ValueError("raw record missing 'actor_name'")
        return {
            "actor_name":  actor_name,
            "source_id":   raw.get("source_id", SOURCE_ID),
            "aliases":     _clean(raw.get("aliases", [])),
            "description": raw.get("description", ""),
            "origin":      raw.get("origin", ""),
            "first_seen":  raw.get("first_seen", ""),
            "motivations": _clean(raw.get("motivations", [])),
            "techniques":  self._map_techniques(raw.get("techniques", [])),
            "indicators":  self._map_indicators(raw.get("indicators", [])),
            "malware":     self._map_malware(raw.get("malware", [])),
            "campaigns":   [],
            "sectors":     _clean(raw.get("sectors", [])),
            "pulse_count": raw.get("pulse_count", 0),
        }

    def _map_techniques(self, techniques: list[dict]) -> list[dict]:
        out = []
        for t in techniques:
            tid = (t.get("technique_id") or "").strip().upper()
            if not tid:
                continue
            out.append({
                "technique_id":   tid,
                "technique_name": t.get("technique_name", ""),
                "tactic":         t.get("tactic", ""),
                "tactics":        t.get("tactics", []),
                "description":    "",
                "detection":      "",
                "sources":        t.get("sources", [SOURCE_ID]),
            })
        return out

    def _map_indicators(self, indicators: list[dict]) -> list[dict]:
        return [
            {
                "type":        i["type"],
                "value":       i["value"],
                "description": i.get("description", ""),
                "sources":     i.get("sources", [SOURCE_ID]),
            }
            for i in indicators
            if i.get("type") and i.get("value")
        ]

    def _map_malware(self, malware: list[dict]) -> list[dict]:
        return [
            {
                "name":        m["name"],
                "type":        m.get("type", "malware"),
                "description": m.get("description", ""),
                "sources":     m.get("sources", [SOURCE_ID]),
            }
            for m in malware
            if m.get("name")
        ]


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

_SECTOR_MAP: dict[str, str] = {
    "energy": "Energy",         "oil": "Energy",
    "gas": "Energy",            "financial": "Financial Services",
    "banking": "Financial Services", "healthcare": "Healthcare",
    "hospital": "Healthcare",   "government": "Government",
    "defense": "Defense",       "military": "Defense",
    "telecom": "Telecommunications", "transport": "Transportation",
    "water": "Water",           "manufacturing": "Manufacturing",
    "education": "Education",   "technology": "Technology",
    "aerospace": "Aerospace",   "media": "Media",
    "ngo": "NGO",               "think tank": "Think Tank",
}


def _clean(items: list) -> list[str]:
    seen: set[str] = set()
    out:  list[str] = []
    for item in items:
        s = str(item).strip()
        if s and s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    return out
