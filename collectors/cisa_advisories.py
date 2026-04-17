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

# CISA advisory index — XML/RSS feed (official, stable)
ADVISORY_INDEX_URL = (
    "https://www.cisa.gov/api/glossary/all-items"  # tags endpoint
)

# CISA publishes all cybersecurity advisories as an XML feed
ADVISORY_LIST_URL = (
    "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml"
)

_TIMEOUT    = 15   # seconds
_RETRY_MAX  = 2
_RETRY_WAIT = 2


# ---------------------------------------------------------------------------
# Cross-naming alias table — loaded from config/actors.yaml
# ---------------------------------------------------------------------------
# The alias table is now maintained in config/actors.yaml.
# Edit that file to add new actors or aliases — no Python required.
#
# This module exposes the same public API as before:
#   ALIAS_TABLE            dict[str, frozenset[str]]
#   resolve_canonical(name) → str
#   all_aliases_for(name)   → frozenset[str]

from pathlib import Path as _Path
import yaml as _yaml

_ACTORS_YAML = _Path("config/actors.yaml")
_ALIAS_TABLE_CACHE: dict[str, frozenset[str]] | None = None
_ALIAS_TO_CANONICAL_CACHE: dict[str, str] | None = None


def _load_actors_yaml() -> tuple[dict[str, frozenset[str]], dict[str, str]]:
    """
    Load and cache the actor alias table from config/actors.yaml.
    Returns (ALIAS_TABLE, _ALIAS_TO_CANONICAL).
    Falls back to empty dicts if the file is missing or malformed.
    """
    global _ALIAS_TABLE_CACHE, _ALIAS_TO_CANONICAL_CACHE
    if _ALIAS_TABLE_CACHE is not None:
        return _ALIAS_TABLE_CACHE, _ALIAS_TO_CANONICAL_CACHE

    alias_table: dict[str, frozenset[str]] = {}
    alias_to_canonical: dict[str, str] = {}

    try:
        data = _yaml.safe_load(_ACTORS_YAML.read_text(encoding="utf-8"))
        actors = data.get("actors", {}) or {}
        for canonical, meta in actors.items():
            if not isinstance(meta, dict):
                continue
            raw_aliases = meta.get("aliases", []) or []
            aliases = frozenset(str(a).lower().strip() for a in raw_aliases if a)
            alias_table[canonical] = aliases
            for alias in aliases:
                alias_to_canonical[alias] = canonical
            alias_to_canonical[canonical.lower()] = canonical
    except FileNotFoundError:
        logger.warning(
            "config/actors.yaml not found — alias resolution disabled. "
            "Run from the theory repo root or check your working directory."
        )
    except Exception as exc:
        logger.error("Failed to load config/actors.yaml: %s", exc)

    _ALIAS_TABLE_CACHE = alias_table
    _ALIAS_TO_CANONICAL_CACHE = alias_to_canonical
    return alias_table, alias_to_canonical


def _get_alias_table() -> dict[str, frozenset[str]]:
    table, _ = _load_actors_yaml()
    return table


def _get_alias_to_canonical() -> dict[str, str]:
    _, index = _load_actors_yaml()
    return index


# Module-level attribute for direct import compatibility
# (e.g. `from collectors.cisa_advisories import ALIAS_TABLE`)
class _AliasTableProxy:
    """Proxy that behaves like a dict but loads from YAML on first access."""
    def __getitem__(self, key):   return _get_alias_table()[key]
    def __contains__(self, key): return key in _get_alias_table()
    def __iter__(self):          return iter(_get_alias_table())
    def __len__(self):           return len(_get_alias_table())
    def items(self):             return _get_alias_table().items()
    def keys(self):              return _get_alias_table().keys()
    def values(self):            return _get_alias_table().values()
    def get(self, key, default=None): return _get_alias_table().get(key, default)


ALIAS_TABLE = _AliasTableProxy()  # type: ignore[assignment]


def resolve_canonical(name: str) -> str:
    """
    Map any actor name/alias to its canonical name.
    Falls back to the input itself if unknown.
    Reads from config/actors.yaml via _get_alias_to_canonical().
    """
    return _get_alias_to_canonical().get(name.strip().lower(), name.strip())


def all_aliases_for(name: str) -> frozenset[str]:
    """Return all known aliases (lowercase) for a canonical or alias name."""
    canonical = resolve_canonical(name)
    return _get_alias_table().get(canonical, frozenset({name.lower()}))


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

        # Try the XML feed
        for url in (ADVISORY_LIST_URL,):
            try:
                items = _fetch_advisory_xml(url)
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


def _fetch_advisory_xml(url: str, timeout: int = _TIMEOUT) -> list[dict]:
    """
    Fetch the CISA cybersecurity advisories XML feed and parse into item dicts.
    Returns a list of dicts with title, url, date, summary fields.
    """
    import xml.etree.ElementTree as ET
    req = Request(url, headers={"User-Agent": "THEORY/1.0 threat-intel-research"})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")

    root = ET.fromstring(raw)
    # Handle both RSS (<channel><item>) and Atom (<entry>) formats
    ns   = {"atom": "http://www.w3.org/2005/Atom"}
    items: list[dict] = []

    # RSS format
    for item in root.findall(".//item"):
        def _t(tag: str) -> str:
            el = item.find(tag)
            return (el.text or "") if el is not None else ""
        items.append({
            "title":       _t("title"),
            "url":         _t("link"),
            "date":        _t("pubDate"),
            "summary":     _t("description"),
            "description": _t("description"),
            "body":        _t("description"),
            "tags":        _t("category"),
        })

    # Atom format fallback
    if not items:
        for entry in root.findall("atom:entry", ns):
            def _at(tag: str) -> str:
                el = entry.find(f"atom:{tag}", ns)
                return (el.text or "") if el is not None else ""
            link_el = entry.find("atom:link", ns)
            link = link_el.get("href", "") if link_el is not None else ""
            items.append({
                "title":       _at("title"),
                "url":         link,
                "date":        _at("updated"),
                "summary":     _at("summary"),
                "description": _at("summary"),
                "body":        _at("content"),
                "tags":        "",
            })

    return items


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
