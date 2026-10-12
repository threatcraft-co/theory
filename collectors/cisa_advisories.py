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

import yaml as _yaml

from theory.paths import config_file
_ALIAS_TABLE_CACHE: dict[str, frozenset[str]] | None = None
_ALIAS_TO_CANONICAL_CACHE: dict[str, str] | None = None
_NORMALIZED_TO_CANONICAL_CACHE: dict[str, str] | None = None


def _normalize_loose(name: str) -> str:
    """Strip spaces/hyphens/underscores (in addition to case) so
    'Scattered Spider', 'scattered-spider', 'scattered_spider', and
    'scatteredspider' all normalize to the same key. Used as a fallback
    when the exact (space-preserving) lookup misses — e.g. someone typing
    a multi-word actor name as one concatenated word on the command line."""
    return "".join(ch for ch in name.strip().lower() if ch.isalnum())


def _load_actors_yaml() -> tuple[dict[str, frozenset[str]], dict[str, str]]:
    """
    Load and cache the actor alias table from config/actors.yaml.
    Returns (ALIAS_TABLE, _ALIAS_TO_CANONICAL).
    Falls back to empty dicts if the file is missing or malformed.
    """
    global _ALIAS_TABLE_CACHE, _ALIAS_TO_CANONICAL_CACHE, _NORMALIZED_TO_CANONICAL_CACHE
    if _ALIAS_TABLE_CACHE is not None:
        return _ALIAS_TABLE_CACHE, _ALIAS_TO_CANONICAL_CACHE

    alias_table: dict[str, frozenset[str]] = {}
    alias_to_canonical: dict[str, str] = {}
    normalized_to_canonical: dict[str, str] = {}

    actors_yaml = config_file("actors.yaml")
    try:
        data = _yaml.safe_load(actors_yaml.read_text(encoding="utf-8"))
        actors = data.get("actors", {}) or {}
        for canonical, meta in actors.items():
            if not isinstance(meta, dict):
                continue
            raw_aliases = meta.get("aliases", []) or []
            aliases = frozenset(str(a).lower().strip() for a in raw_aliases if a)
            alias_table[canonical] = aliases
            for alias in aliases:
                alias_to_canonical[alias] = canonical
                normalized = _normalize_loose(alias)
                # If two different aliases normalize to the same collapsed
                # form (rare, but possible — e.g. two actors whose names
                # differ only by a hyphen/space), first-seen wins rather
                # than silently overwriting; the exact-match dict above is
                # still authoritative for anything that isn't ambiguous.
                normalized_to_canonical.setdefault(normalized, canonical)
            alias_to_canonical[canonical.lower()] = canonical
            normalized_to_canonical.setdefault(_normalize_loose(canonical), canonical)
    except FileNotFoundError:
        logger.warning(
            "actors.yaml not found at %s — alias resolution disabled. "
            "Set THEORY_CONFIG_DIR to point at a directory containing it.",
            actors_yaml,
        )
    except Exception as exc:
        logger.error("Failed to load %s: %s", actors_yaml, exc)

    _ALIAS_TABLE_CACHE = alias_table
    _ALIAS_TO_CANONICAL_CACHE = alias_to_canonical
    _NORMALIZED_TO_CANONICAL_CACHE = normalized_to_canonical
    return alias_table, alias_to_canonical


def _get_normalized_to_canonical() -> dict[str, str]:
    _load_actors_yaml()
    return _NORMALIZED_TO_CANONICAL_CACHE or {}


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

    Tries an exact match first (space-preserving, case-insensitive), then
    falls back to a normalized match (spaces/hyphens/underscores stripped)
    so a multi-word actor name typed as one word on the command line —
    e.g. `--actor scatteredspider` instead of `--actor "Scattered Spider"`
    — still resolves correctly instead of silently returning an empty
    profile.

    Falls back to the input itself if truly unknown.
    """
    cleaned = name.strip().lower()
    exact = _get_alias_to_canonical().get(cleaned)
    if exact:
        return exact
    normalized = _get_normalized_to_canonical().get(_normalize_loose(name))
    if normalized:
        return normalized
    return name.strip()


def suggest_similar(name: str, limit: int = 3) -> list[str]:
    """Suggest close-match canonical actor names for an unresolved input,
    for CLI 'did you mean' hints. Matches against both canonical names and
    known aliases so a near-miss alias (not just a near-miss canonical
    name) still surfaces a useful suggestion."""
    import difflib

    table = _get_alias_to_canonical()
    if not table:
        return []
    cleaned = name.strip().lower()
    matches = difflib.get_close_matches(cleaned, table.keys(), n=limit * 3, cutoff=0.6)
    seen: list[str] = []
    for m in matches:
        canonical = table[m]
        if canonical not in seen:
            seen.append(canonical)
        if len(seen) >= limit:
            break
    return seen


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
        from theory.actors import registry

        identity = registry().get(actor_name)
        if identity is None:
            logger.info("CISA: %r is not a known actor — nothing to match against", actor_name)
            return None
        canonical = identity.canonical

        logger.info("CISA: searching for %r (canonical: %s)", actor_name, canonical)

        aa_advisories = self._fetch_advisories(identity)
        cves = self._cves_from_advisories(aa_advisories)

        if not cves and not aa_advisories:
            logger.info("CISA: no data found for %r", actor_name)
            return None

        return {
            "actor_name":   canonical or actor_name,
            "source_id":    SOURCE_ID,
            "aliases":      sorted(identity.identity_names - {canonical.lower()}),
            "description":  "",
            "origin":       "",
            "first_seen":   "",
            "motivations":  [],
            "techniques":   self._techniques_from_advisories(aa_advisories),
            "indicators":   [],
            "malware":      [],
            "campaigns":    [],
            "sectors":      self._sectors_from_advisories(aa_advisories),
            "cves":         cves,
            "advisories":   [
                {
                    "title": a.get("title", ""),
                    "url":   a.get("url", ""),
                    "date":  a.get("date", ""),
                }
                for a in aa_advisories
            ],
            "raw_source":   "CISA Advisories + KEV cross-reference",
        }

    # ------------------------------------------------------------------
    # CVE attribution
    # ------------------------------------------------------------------
    #
    # IMPORTANT: CVE attribution comes from CVE IDs mentioned in the text
    # of advisories already confirmed to be about this specific actor
    # (via _advisory_matches, which requires the actor's name/alias to
    # appear in the advisory's own title/summary/tags). This used to
    # instead download the entire KEV catalog and substring-match the
    # actor's name against KEV's free-text 'notes'/'vulnerabilityName'
    # fields — but KEV has no actor-attribution field at all (it's
    # purely CVE-centric: vendor, product, exploitation date), so that
    # match was essentially coincidental whenever it hit, not a real
    # actor-CVE association, and silently returned nothing the rest of
    # the time. A CVE ID that literally appears in the body text of an
    # advisory CISA wrote specifically about this actor is a real,
    # scoped signal; a CVE whose KEV notes field happens to contain the
    # same substring as the actor's name is not.
    #
    # The KEV catalog is still useful here — once we have real,
    # actor-scoped CVE IDs, we cross-reference each one *by exact ID*
    # against KEV to enrich it with vendor/product/due_date/date_added
    # when available. That's a precise lookup, not a fuzzy one, so it's
    # kept as enrichment rather than as the attribution source itself.
    #
    # For truly comprehensive, dedicated actor-to-CVE search, use the
    # `vuldb` source — it queries a real per-actor CVE database directly
    # rather than inferring attribution from advisory prose.

    def _cves_from_advisories(self, advisories: list[dict]) -> list[dict]:
        seen: set[str] = set()
        cve_ids: list[str] = []
        for adv in advisories:
            for cve_id in adv.get("cves", []):
                if cve_id not in seen:
                    seen.add(cve_id)
                    cve_ids.append(cve_id)

        if not cve_ids:
            return []

        kev_metadata = self._kev_metadata_for(cve_ids)
        return [
            {
                "cve_id":      cve_id,
                "product":     kev_metadata.get(cve_id, {}).get("product", ""),
                "vendor":      kev_metadata.get(cve_id, {}).get("vendor", ""),
                "description": kev_metadata.get(cve_id, {}).get("description", ""),
                "due_date":    kev_metadata.get(cve_id, {}).get("due_date", ""),
                "date_added":  kev_metadata.get(cve_id, {}).get("date_added", ""),
                "sources":     [SOURCE_ID] + (["cisa_kev"] if cve_id in kev_metadata else []),
            }
            for cve_id in cve_ids
        ]

    @staticmethod
    def _kev_metadata_for(cve_ids: list[str]) -> dict[str, dict]:
        """Look up a specific set of CVE IDs against the KEV catalog by
        exact ID match (not fuzzy text matching). Returns only entries
        that actually exist in KEV; CVEs not in KEV simply get no extra
        metadata, which is correct — not everything mentioned in an
        advisory is a KEV-confirmed actively-exploited CVE."""
        wanted = set(cve_ids)
        try:
            data = _fetch_json(KEV_URL)
        except Exception as exc:
            logger.warning("KEV fetch failed: %s", exc)
            return {}

        out: dict[str, dict] = {}
        for v in data.get("vulnerabilities", []):
            cid = v.get("cveID", "")
            if cid in wanted:
                out[cid] = {
                    "product":     v.get("product", ""),
                    "vendor":      v.get("vendorProject", ""),
                    "description": v.get("shortDescription", ""),
                    "due_date":    v.get("dueDate", ""),
                    "date_added":  v.get("dateAdded", ""),
                }
        return out

    # ------------------------------------------------------------------
    # AA advisories
    # ------------------------------------------------------------------

    def _fetch_advisories(self, identity) -> list[dict]:
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
                    if self._advisory_matches(item, identity):
                        advisories.append(self._normalise_advisory(item))
                if advisories:
                    break
            except Exception as exc:
                logger.debug("Advisory feed %s failed: %s", url, exc)

        logger.info("CISA advisories: %d matched", len(advisories))
        return advisories

    @staticmethod
    def _advisory_matches(item: dict, identity) -> bool:
        """True if this advisory is actually about the actor.

        Was a raw substring test over the full MISP-derived alias set. With
        335 aliases of <=5 characters, many of them ordinary English words,
        that attributed unrelated advisories to whoever happened to own a
        matching substring: an Akira ransomware advisory matched APT3 (via
        "ups" inside "groups") and APT41 (via "lead" inside "leading").

        Now a word-boundary match over recall terms only — stop-words and
        short non-identifier aliases are excluded, and identifier aliases
        match exactly (apt4 never matches apt41).
        """
        from theory.actors import mentions

        return bool(mentions(
            identity,
            item.get("title") or "",
            item.get("summary") or "",
            item.get("description") or "",
            item.get("tags") or "",
            item.get("body") or "",
        ))

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
            "cves": _extract_cve_ids(
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

# Sector keywords are matched on word boundaries, and ambiguous bare words
# are qualified. Substring matching produced nonsense: "banking trojan"
# scored Financial Services, "health check" scored Healthcare, and
# "watering hole" scored Water — all three from one sentence about a
# phishing campaign.
_SECTOR_PATTERNS: list[tuple[str, str]] = [
    (r"energy|electric(?:al|ity)?\s+(?:grid|utility|sector)|power\s+(?:grid|plant|utility)", "Energy"),
    (r"oil\s*(?:and|&)?\s*gas|petroleum|refiner(?:y|ies)|pipeline", "Energy"),
    (r"financial\s+(?:services|sector|institutions?)|banking\s+(?:sector|industry)|\bbanks?\b|fintech", "Financial Services"),
    (r"health\s*care|healthcare|hospitals?|medical\s+(?:centers?|facilities)|clinics?", "Healthcare"),
    (r"governments?|federal\s+agenc(?:y|ies)|public\s+sector|ministr(?:y|ies)", "Government"),
    (r"defen[cs]e\s+(?:sector|industrial|contractors?)|militar(?:y|ies)|armed\s+forces", "Defense"),
    (r"telecom(?:munications?)?|mobile\s+operators?|isps?\b", "Telecommunications"),
    (r"transport(?:ation)?|aviation|airlines?|railways?|maritime\s+shipping", "Transportation"),
    (r"water\s+(?:utilit(?:y|ies)|treatment|sector|authority)|wastewater", "Water"),
    (r"critical\s+infrastructure", "Critical Infrastructure"),
    (r"manufactur(?:ing|ers?)|industrial\s+control", "Manufacturing"),
    (r"education(?:al)?\s+(?:sector|institutions?)|universit(?:y|ies)|academia|schools?", "Education"),
    (r"aerospace", "Aerospace"),
    (r"technology\s+(?:sector|companies)|software\s+(?:vendors?|companies)", "Technology"),
    (r"\bmedia\b|journalis(?:m|ts)|broadcasters?", "Media"),
    (r"\bngos?\b|non-?governmental|civil\s+society", "NGO"),
    (r"think\s+tanks?", "Think Tank"),
]

_SECTOR_COMPILED = [(re.compile(p, re.IGNORECASE), label) for p, label in _SECTOR_PATTERNS]


def _extract_sectors(text: str) -> list[str]:
    """Infer target sectors from advisory prose.

    Deliberately conservative: a false sector on a dossier is worse than a
    missing one, because it drives the sector-specific framing in the
    executive summary and playbook.
    """
    if not text:
        return []
    found: list[str] = []
    for pattern, label in _SECTOR_COMPILED:
        if label not in found and pattern.search(text):
            found.append(label)
    return found


def _extract_technique_ids(text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)))


def _extract_cve_ids(text: str) -> list[str]:
    """Extract CVE IDs mentioned directly in advisory text. Scoped to
    advisories already confirmed to be about a specific actor (see
    _advisory_matches), so a CVE ID found here is a real, actor-relevant
    signal — unlike matching an actor's name against KEV's unrelated
    free-text notes field."""
    return list(dict.fromkeys(
        m.upper() for m in re.findall(r"\bCVE-\d{4}-\d{4,}\b", text, re.IGNORECASE)
    ))


def _fetch_advisory_xml(url: str, timeout: int = _TIMEOUT) -> list[dict]:
    """
    Fetch the CISA cybersecurity advisories XML feed and parse into item dicts.
    Returns a list of dicts with title, url, date, summary fields.
    """
    # defusedxml, not the stdlib parser. SECURITY.md states that the
    # stdlib parser "is not used on attacker-influenceable content" —
    # until now this feed was the exception that made that false. The
    # practical risk is low (CISA is a trustworthy origin and expat has
    # its own mitigations), but a published guarantee should be true.
    from defusedxml import ElementTree as ET
    from defusedxml.common import DefusedXmlException

    req = Request(url, headers={"User-Agent": "THEORY/1.0 threat-intel-research"})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")

    try:
        root = ET.fromstring(raw)
    except DefusedXmlException as exc:
        logger.warning("CISA advisory feed rejected by hardened parser: %s", exc)
        return []

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
        except URLError:
            if attempt < _RETRY_MAX:
                time.sleep(_RETRY_WAIT)
            else:
                raise
