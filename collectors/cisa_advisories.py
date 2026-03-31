"""
collectors/cisa_advisories.py
------------------------------
Pulls two CISA data sources:

  1. KEV catalog  — CISA Known Exploited Vulnerabilities (JSON feed, no auth)
  2. AA advisories — CISA alert index scraped for actor-attributed advisories

Actor matching uses a cross-naming alias resolver so that "APT28",
"Fancy Bear", "Sofacy", and "Strontium" all resolve to the same group.

CISA data sources:
  KEV:  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  Advisories index: https://www.cisa.gov/news-events/cybersecurity-advisories
                    (filtered by tag: Russia / China / Iran / North Korea / APT*)
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from collectors.base import BaseCollector

logger = logging.getLogger(__name__)

SOURCE_ID = "cisa"

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# CISA advisory index — JSON feed (undocumented but stable since 2022)
ADVISORY_INDEX_URL = (
    "https://www.cisa.gov/api/glossary/all-items"  # tags endpoint
)

# Fallback: CISA publishes a structured advisory list here
ADVISORY_LIST_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/cybersecurity-advisories.json"
)

_TIMEOUT    = 15   # seconds
_RETRY_MAX  = 2
_RETRY_WAIT = 2


# ---------------------------------------------------------------------------
# Cross-naming alias table
# ---------------------------------------------------------------------------
# Format: canonical_name → frozenset of all known aliases (lowercase)
# Sources: MITRE ATT&CK, CrowdStrike, Mandiant, Microsoft, Recorded Future
#
# This is intentionally kept in the collector (not a config file) so it
# travels with the code and can be extended via PR.

ALIAS_TABLE: dict[str, frozenset[str]] = {
    "APT28": frozenset({
        "apt28", "fancy bear", "sofacy", "sofacy group", "pawn storm",
        "sednit", "strontium", "iron twilight", "threat group-4127",
        "tg-4127", "forest blizzard", "frozenlake", "ta422",
        "unc2589", "g0007",
    }),
    "APT29": frozenset({
        "apt29", "cozy bear", "the dukes", "office monkeys", "cozyduke",
        "minidionis", "seaduke", "hammertoss", "yttrium", "iron hemlock",
        "nobelium", "midnight blizzard", "unc2452", "g0016",
    }),
    "APT41": frozenset({
        "apt41", "double dragon", "winnti group", "barium", "bronze atlas",
        "ta415", "wicked panda", "wicked spider", "g0096",
    }),
    "Lazarus Group": frozenset({
        "lazarus group", "hidden cobra", "zinc", "diamond sleet",
        "apt38", "temp.hermit", "whois team", "g0032",
    }),
    "APT10": frozenset({
        "apt10", "stone panda", "menupass", "red apollo", "cvnx",
        "potassium", "bronze riverside", "g0045",
    }),
    "Sandworm": frozenset({
        "sandworm", "sandworm team", "voodoo bear", "quedagh",
        "electrum", "iridium", "seashell blizzard", "ta74", "g0034",
    }),
    "Turla": frozenset({
        "turla", "snake", "venomous bear", "waterbug", "uroboros",
        "krypton", "secret blizzard", "g0010",
    }),
    "Equation Group": frozenset({
        "equation group", "equation", "g0020",
    }),
    "APT33": frozenset({
        "apt33", "refined kitten", "magnallium", "holmium",
        "peach sandstorm", "g0064",
    }),
    "APT34": frozenset({
        "apt34", "oilrig", "helix kitten", "crambus", "cobalt gypsy",
        "hazel sandstorm", "g0049",
    }),
    "Kimsuky": frozenset({
        "kimsuky", "velvet chollima", "thallium", "black banshee",
        "emerald sleet", "g0094",
    }),
    "FIN7": frozenset({
        "fin7", "carbanak", "navigator group", "g0046",
    }),
    "FIN8": frozenset({
        "fin8", "syssphinx", "g0061",
    }),
    "Volt Typhoon": frozenset({
        "volt typhoon", "bronze silhouette", "vanguard panda",
        "dev-0391", "unc3236", "g1017",
    }),
    "Salt Typhoon": frozenset({
        "salt typhoon", "ghostemperor", "famsec", "earth estries",
        "unc2286",
    }),
    "Scattered Spider": frozenset({
        "scattered spider", "unc3944", "octo tempest", "0ktapus",
        "starfraud", "muddled libra",
    }),
}

# Inverted index: alias_lower → canonical name
_ALIAS_TO_CANONICAL: dict[str, str] = {}
for _canonical, _aliases in ALIAS_TABLE.items():
    for _alias in _aliases:
        _ALIAS_TO_CANONICAL[_alias] = _canonical
    _ALIAS_TO_CANONICAL[_canonical.lower()] = _canonical


def resolve_canonical(name: str) -> str:
    """
    Map any actor name/alias to its canonical name.
    Falls back to the input itself (title-cased) if unknown.
    """
    return _ALIAS_TO_CANONICAL.get(name.strip().lower(), name.strip())


def all_aliases_for(name: str) -> frozenset[str]:
    """Return all known aliases (lowercase) for a canonical or alias name."""
    canonical = resolve_canonical(name)
    return ALIAS_TABLE.get(canonical, frozenset({name.lower()}))


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class CisaAdvisoriesCollector(BaseCollector):

    SOURCE_ID = SOURCE_ID

    def query(self, actor_name: str) -> dict | None:
        return self.collect(actor_name)

    def collect(self, actor_name: str) -> dict[str, Any] | None:
        canonical  = resolve_canonical(actor_name)
        search_set = all_aliases_for(actor_name) | {actor_name.lower()}

        logger.info("CISA: searching for %r (canonical: %s)", actor_name, canonical)

        kev_vulns    = self._fetch_kev(search_set)
        aa_advisories = self._fetch_advisories(search_set)

        if not kev_vulns and not aa_advisories:
            logger.info("CISA: no data found for %r", actor_name)
            return None

        return {
            "actor_name":   canonical or actor_name,
            "source_id":    SOURCE_ID,
            "aliases":      sorted(search_set - {canonical.lower()}),
            "description":  "",
            "origin":       "",
            "first_seen":   "",
            "motivations":  [],
            "techniques":   self._techniques_from_advisories(aa_advisories),
            "indicators":   [],
            "malware":      [],
            "campaigns":    [],
            "sectors":      self._sectors_from_advisories(aa_advisories),
            "cves":         kev_vulns,
            "advisories":   [
                {
                    "title": a.get("title", ""),
                    "url":   a.get("url", ""),
                    "date":  a.get("date", ""),
                }
                for a in aa_advisories
            ],
            "raw_source":   "CISA KEV + Advisories",
        }

    # ------------------------------------------------------------------
    # KEV catalog
    # ------------------------------------------------------------------

    def _fetch_kev(self, search_set: frozenset[str]) -> list[dict]:
        """
        Download the KEV catalog and filter entries where the notes field
        mentions any alias of the target actor.
        """
        try:
            data = _fetch_json(KEV_URL)
        except Exception as exc:
            logger.warning("KEV fetch failed: %s", exc)
            return []

        vulns     = data.get("vulnerabilities", [])
        matched   : list[dict] = []

        for v in vulns:
            notes = (v.get("notes") or "").lower()
            name  = (v.get("vulnerabilityName") or "").lower()
            text  = notes + " " + name

            if any(alias in text for alias in search_set):
                matched.append({
                    "cve_id":      v.get("cveID", ""),
                    "product":     v.get("product", ""),
                    "vendor":      v.get("vendorProject", ""),
                    "description": v.get("shortDescription", ""),
                    "due_date":    v.get("dueDate", ""),
                    "date_added":  v.get("dateAdded", ""),
                })

        logger.info("KEV: %d matching vulns for this actor", len(matched))
        return matched

    # ------------------------------------------------------------------
    # AA advisories
    # ------------------------------------------------------------------

    def _fetch_advisories(self, search_set: frozenset[str]) -> list[dict]:
        """
        Fetch CISA cybersecurity advisories and filter those attributing
        the target actor.  Tries the JSON feed first, falls back gracefully.
        """
        advisories: list[dict] = []

        # Try the JSON feed
        for url in (ADVISORY_LIST_URL,):
            try:
                data  = _fetch_json(url)
                items = data if isinstance(data, list) else data.get("items", [])
                for item in items:
                    if self._advisory_matches(item, search_set):
                        advisories.append(self._normalise_advisory(item))
                if advisories:
                    break
            except Exception as exc:
                logger.debug("Advisory feed %s failed: %s", url, exc)

        logger.info("CISA advisories: %d matched", len(advisories))
        return advisories

    @staticmethod
    def _advisory_matches(item: dict, search_set: frozenset[str]) -> bool:
        """Return True if any alias appears in the advisory's text fields."""
        haystack = " ".join([
            (item.get("title")       or ""),
            (item.get("summary")     or ""),
            (item.get("description") or ""),
            (item.get("tags")        or ""),
            (item.get("body")        or ""),
        ]).lower()
        return any(alias in haystack for alias in search_set)

    @staticmethod
    def _normalise_advisory(item: dict) -> dict:
        return {
            "title":    item.get("title", ""),
            "url":      item.get("url", item.get("link", "")),
            "date":     item.get("date", item.get("published", "")),
            "summary":  item.get("summary", item.get("description", "")),
            "sectors":  _extract_sectors(item.get("tags", "") + " " + item.get("summary", "")),
            "techniques": _extract_technique_ids(
                item.get("body", "") + " " + item.get("summary", "")
            ),
        }

    # ------------------------------------------------------------------
    # Aggregation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _techniques_from_advisories(advisories: list[dict]) -> list[dict]:
        seen: set[str] = set()
        out : list[dict] = []
        for adv in advisories:
            for tid in adv.get("techniques", []):
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
        return out

    @staticmethod
    def _sectors_from_advisories(advisories: list[dict]) -> list[str]:
        seen: set[str] = set()
        out : list[str] = []
        for adv in advisories:
            for s in adv.get("sectors", []):
                if s.lower() not in seen:
                    seen.add(s.lower())
                    out.append(s)
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SECTOR_KEYWORDS: dict[str, str] = {
    "energy":          "Energy",
    "electric":        "Energy",
    "oil":             "Energy",
    "gas":             "Energy",
    "financial":       "Financial Services",
    "bank":            "Financial Services",
    "health":          "Healthcare",
    "hospital":        "Healthcare",
    "government":      "Government",
    "federal":         "Government",
    "defense":         "Defense",
    "military":        "Defense",
    "telecom":         "Telecommunications",
    "transport":       "Transportation",
    "water":           "Water",
    "critical infra":  "Critical Infrastructure",
    "manufacturing":   "Manufacturing",
    "education":       "Education",
    "academia":        "Education",
}


def _extract_sectors(text: str) -> list[str]:
    text_lower = text.lower()
    found: dict[str, bool] = {}
    for kw, sector in _SECTOR_KEYWORDS.items():
        if kw in text_lower and sector not in found:
            found[sector] = True
    return list(found.keys())


def _extract_technique_ids(text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)))


def _fetch_json(url: str, timeout: int = _TIMEOUT) -> Any:
    req = Request(url, headers={"User-Agent": "THEORY/1.0 threat-intel-research"})
    for attempt in range(1, _RETRY_MAX + 1):
        try:
            with urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            if exc.code == 429 and attempt < _RETRY_MAX:
                time.sleep(_RETRY_WAIT)
            else:
                raise
        except URLError as exc:
            if attempt < _RETRY_MAX:
                time.sleep(_RETRY_WAIT)
            else:
                raise
