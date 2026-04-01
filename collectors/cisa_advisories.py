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

    # ── Russia ────────────────────────────────────────────────────────

    "APT28": frozenset({
        "apt28", "fancy bear", "sofacy", "sofacy group", "pawn storm",
        "sednit", "strontium", "iron twilight", "threat group-4127",
        "tg-4127", "forest blizzard", "frozenlake", "gruesomeLarch",
        "sig40", "grizzly steppe", "atk5", "fighting ursa", "itg05",
        "blue athena", "ta422", "t-apt-12", "apt-c-20", "uac-0028",
        "uac-0001", "bluedelta", "apt 28", "tsarteam", "group-4127",
        "grey-cloud", "snakemackerel", "swallowtail", "g0007",
    }),

    "APT29": frozenset({
        "apt29", "cozy bear", "cozyduke", "the dukes", "office monkeys",
        "midnight blizzard", "nobelium", "iron hemlock", "dark halo",
        "unc2452", "yttrium", "minidionis", "hammertoss", "g0016",
        "itg11", "npu", "cozy duke",
    }),

    "Sandworm": frozenset({
        "sandworm", "sandworm team", "voodoo bear", "iridium",
        "seashell blizzard", "electrum", "quedagh", "iron viking",
        "telebots", "blackenergy", "g0034", "uac-0113", "uac-0082",
        "industroyer", "notpetya group",
    }),

    "Turla": frozenset({
        "turla", "snake", "uroburos", "venomous bear", "krypton",
        "secret blizzard", "iron hunter", "waterbug", "g0010",
        "carbon spider", "penquin turla", "kazuar",
    }),

    "Gamaredon": frozenset({
        "gamaredon", "primitive bear", "shuckworm", "actinium",
        "iron tilden", "uac-0010", "g0047", "armageddon",
        "callisto group",
    }),

    # ── China ────────────────────────────────────────────────────────

    "APT10": frozenset({
        "apt10", "menupass", "stone panda", "bronze riverside",
        "potassium", "cvnx", "happyyongzi", "cloud hopper",
        "g0045", "red apollo", "hogfish",
    }),

    "APT41": frozenset({
        "apt41", "double dragon", "barium", "winnti group",
        "bronze atlas", "wicked spider", "wicked panda",
        "lead", "g0096", "axiom", "blackfly",
    }),

    "Volt Typhoon": frozenset({
        "volt typhoon", "bronze silhouette", "vanguard panda",
        "dev-0391", "unc3236", "insidious taurus", "g1017",
    }),

    "Salt Typhoon": frozenset({
        "salt typhoon", "ghostemperor", "earth estries",
        "famsec", "unc2286", "g1045",
    }),

    "APT40": frozenset({
        "apt40", "temp.periscope", "temp.jumper", "bronze mohawk",
        "leviathan", "gadolinium", "ta423", "g0065",
        "red ladon", "indrik spider",
    }),

    "APT31": frozenset({
        "apt31", "zirconium", "judgment panda", "bronze vinewood",
        "g0128", "violet typhoon",
    }),

    "APT34": frozenset({
        "apt34", "oilrig", "crambus", "cobalt gypsy",
        "chrysene", "g0049", "helix kitten", "hazel sandstorm",
    }),

    "BlackTech": frozenset({
        "blacktech", "circuit panda", "radio panda",
        "palmerworm", "temp.overboard", "g0098",
    }),

    "Earth Lusca": frozenset({
        "earth lusca", "charcoal typhoon", "fishmonger",
        "bronze university", "ta428", "g1006",
    }),

    # ── North Korea (DPRK) ───────────────────────────────────────────

    "Lazarus Group": frozenset({
        "lazarus group", "lazarus", "hidden cobra", "zinc",
        "nickel academy", "diamond sleet", "apt38", "whois team",
        "g0032", "temp.hermit",
        "labyrinth chollima", "stardust chollima",
    }),

    "Kimsuky": frozenset({
        "kimsuky", "black banshee", "emerald sleet", "velvet chollima",
        "thallium", "g0094", "ta406", "spring dragon",
    }),

    "Andariel": frozenset({
        "andariel", "silent chollima", "stonefly", "plutonium",
        "g0138", "dark seoul", "operation troy",
    }),

    "Bluenoroff": frozenset({
        "bluenoroff", "sapphire sleet", "copernicium",
    }),

    # ── Iran ────────────────────────────────────────────────────────

    "APT33": frozenset({
        "apt33", "refined kitten", "magnallium", "holmium",
        "elfin", "g0064", "peach sandstorm", "raspite",
    }),

    "Charming Kitten": frozenset({
        "charming kitten", "apt35", "phosphorus", "mint sandstorm",
        "ta453", "newscaster", "g0059", "cobalt illusion",
        "tortoiseshell", "iridescent ursa",
    }),

    "MuddyWater": frozenset({
        "muddywater", "mercury", "static kitten", "seedworm",
        "temp.zagros", "mango sandstorm", "g0069", "ta450",
    }),

    "Moses Staff": frozenset({
        "moses staff", "cobalt sapling", "g1009",
    }),

    "Agrius": frozenset({
        "agrius", "pink sandstorm", "americium", "unc2322",
        "g1030", "BlackShadow",
    }),

    # ── Financially Motivated ────────────────────────────────────────

    "FIN7": frozenset({
        "fin7", "carbanak", "navigator group", "sangria tempest", "g0046",
    }),

    "FIN8": frozenset({
        "fin8", "syssphinx", "g0061",
    }),

    "FIN6": frozenset({
        "fin6", "itg08", "skeleton spider", "g0037",
        "magecart group 6",
    }),

    "Lapsus$": frozenset({
        "lapsus$", "lapsus", "scatter swine", "dev-0537",
        "unc3661", "g1004", "strawberry tempest",
    }),

    "Scattered Spider": frozenset({
        "scattered spider", "0ktapus", "starfraud", "unc3944",
        "muddled libra", "octo tempest", "g1015", "dev-0671",
        "roasted 0ktapus",
    }),

    "Wizard Spider": frozenset({
        "wizard spider", "unc1878", "gold blackburn",
        "g0102", "ryuk group", "conti group",
    }),

    "TA505": frozenset({
        "ta505", "cl0p group", "gold tahoe",
        "g0092", "hive0065",
    }),

    "Cl0p": frozenset({
        "cl0p", "clop", "fin11", "g0158",
    }),

    # ── Hacktivism / Gray Zone ───────────────────────────────────────

    "KillNet": frozenset({
        "killnet", "killmilk",
    }),

    "Anonymous Sudan": frozenset({
        "anonymous sudan", "anonsud", "g1024",
    }),

    "Predatory Sparrow": frozenset({
        "predatory sparrow", "gonjeshke darande",
    }),

    "Equation Group": frozenset({
        "equation group", "equation", "g0020",
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
