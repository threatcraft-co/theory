"""
processors/deduplicator.py
---------------------------
Merges raw collector results into a single unified actor
profile. Applies confidence weighting based on source count and provenance.

Confidence logic:
  HIGH   — technique/indicator seen in 2+ independent sources
  MEDIUM — seen in exactly 1 high-provenance source (mitre_attack, cisa_advisories)
  LOW    — seen in exactly 1 community/vendor source
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_HIGH_PROVENANCE_SOURCES = frozenset({
    "mitre_attack",
    "cisa_advisories",
})


def deduplicate(results: list[dict]) -> dict:
    if not results:
        return {"actor_name": "unknown"}

    unified: dict[str, Any] = {}

    # ── Scalar fields ────────────────────────────────────────────────
    for key in ("actor_name", "mitre_group_id"):
        for r in results:
            val = r.get(key)
            if val:
                unified[key] = val
                break

    # suspected_origin / origin — support both field names
    for r in results:
        val = r.get("suspected_origin") or r.get("origin")
        if val:
            unified["suspected_origin"] = val
            unified["origin"] = val
            break

    # first_seen
    for r in results:
        val = r.get("first_seen")
        if val:
            unified["first_seen"] = val
            break

    # description
    for r in results:
        val = r.get("description")
        if val:
            unified["description"] = val
            break

    # ── List fields ──────────────────────────────────────────────────
    # Support both field name variants across collectors
    unified["aliases"]     = _dedup_strings(_collect(results, "aliases"))
    unified["motivations"] = _dedup_strings(
        _collect(results, "motivations") + _collect(results, "motivation")
    )
    unified["sectors"]     = _dedup_strings(
        _collect(results, "sectors") + _collect(results, "target_sectors")
    )

    # ── Techniques ──────────────────────────────────────────────────
    unified["techniques"] = _merge_techniques(results)

    # ── Malware ─────────────────────────────────────────────────────
    unified["malware"] = _merge_malware(results)

    # ── Indicators ──────────────────────────────────────────────────
    unified["indicators"] = _merge_indicators(results)

    # ── CVEs ────────────────────────────────────────────────────────
    unified["cves"] = _merge_cves(results)

    # ── Advisories ──────────────────────────────────────────────────
    unified["advisories"] = _merge_advisories(results)

    # ── Campaigns ───────────────────────────────────────────────────
    unified["campaigns"] = _merge_campaigns(results)

    # ── Pass-through fields ──────────────────────────────────────────
    for key in ("sigma_rules", "vendor_intel", "vendor_intel_count"):
        for r in results:
            if key in r:
                unified[key] = r[key]
                break

    # ── Sources cited ────────────────────────────────────────────────
    cited: set[str] = set()
    for r in results:
        # source_id is the canonical identifier used by tests and mappers
        sid = r.get("source_id") or r.get("source") or ""
        if sid:
            cited.add(sid)
        # Also pick up any pre-aggregated citations from sub-results
        cited.update(r.get("sources_cited", []))
    unified["sources_cited"] = sorted(cited)

    unified.setdefault("actor_name", _resolve_actor_name(results))

    # ── _sources: list of source dicts for downstream inspection ─────
    unified["_sources"] = [
        {
            "source_id":       r.get("source_id", ""),
            "source_citation": r.get("source_citation", ""),
            "source_url":      r.get("source_url", ""),
            "retrieved_at":    r.get("retrieved_at", ""),
        }
        for r in results
        if r.get("source_id")
    ]

    # ── Confidence ───────────────────────────────────────────────────
    _apply_confidence(unified)

    return unified


# ---------------------------------------------------------------------------
# Technique merging
# ---------------------------------------------------------------------------

def _merge_techniques(results: list[dict]) -> list[dict]:
    by_id: dict[str, dict] = {}
    for r in results:
        source = r.get("source_id") or r.get("source") or "unknown"
        for tech in r.get("techniques", []):
            tid = tech.get("technique_id", "")
            if not tid:
                continue
            # Always use the result's source_id as authoritative —
            # the technique's own "source" field is a collector default, not
            # the identity of which pipeline result contributed it.
            tech_source = source
            if tid not in by_id:
                by_id[tid] = {**tech, "_sources": [tech_source]}
            else:
                existing = by_id[tid]
                if tech_source not in existing["_sources"]:
                    existing["_sources"].append(tech_source)
                for field in ("description", "detection", "name", "tactic"):
                    if not existing.get(field) and tech.get(field):
                        existing[field] = tech[field]
                # Merge detection_recs
                if isinstance(tech.get("detection_recs"), list):
                    existing_recs = existing.get("detection_recs") or []
                    for rec in tech["detection_recs"]:
                        if rec not in existing_recs:
                            existing_recs.append(rec)
                    existing["detection_recs"] = existing_recs
    return list(by_id.values())


# ---------------------------------------------------------------------------
# Indicator merging — track which sources saw each IOC
# ---------------------------------------------------------------------------

def _merge_indicators(results: list[dict]) -> list[dict]:
    # key → {ioc dict with sources list}
    by_key: dict[str, dict] = {}
    for r in results:
        source = r.get("source_id") or r.get("source") or "unknown"
        for ioc in r.get("indicators", []):
            key = f"{ioc.get('type','')}:{ioc.get('value','').lower()}"
            if key not in by_key:
                entry = {**ioc}
                entry["sources"] = list(ioc.get("sources") or [])
                if source not in entry["sources"]:
                    entry["sources"].append(source)
                by_key[key] = entry
            else:
                if source not in by_key[key]["sources"]:
                    by_key[key]["sources"].append(source)
    return list(by_key.values())


# ---------------------------------------------------------------------------
# Malware merging
# ---------------------------------------------------------------------------

def _merge_malware(results: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for r in results:
        for m in r.get("malware", []):
            name = (m.get("name") or "").lower().strip()
            if not name:
                continue
            if name not in seen:
                seen[name] = {**m}
            else:
                for field in ("description", "type", "aliases", "yara_count"):
                    if not seen[name].get(field) and m.get(field):
                        seen[name][field] = m[field]
    return list(seen.values())


# ---------------------------------------------------------------------------
# CVE / Advisory / Campaign merging
# ---------------------------------------------------------------------------

def _merge_cves(results: list[dict]) -> list[dict]:
    seen: set[str] = set()
    merged: list[dict] = []
    for r in results:
        for cve in r.get("cves", []):
            cid = cve.get("cve_id", "")
            if cid and cid not in seen:
                seen.add(cid)
                merged.append(cve)
    return merged


def _merge_advisories(results: list[dict]) -> list[dict]:
    seen: set[str] = set()
    merged: list[dict] = []
    for r in results:
        for adv in r.get("advisories", []):
            key = adv.get("url") or adv.get("title", "")
            if key and key not in seen:
                seen.add(key)
                merged.append(adv)
    return merged


def _merge_campaigns(results: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for r in results:
        for c in r.get("campaigns", []):
            name = (c.get("name") or "").strip()
            if not name:
                continue
            if name not in seen:
                seen[name] = {**c}
            else:
                for field in ("description", "url", "first_seen", "last_seen"):
                    if not seen[name].get(field) and c.get(field):
                        seen[name][field] = c[field]
    return list(seen.values())


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

def _apply_confidence(unified: dict) -> None:
    for tech in unified.get("techniques", []):
        tech["confidence"] = _confidence_for(tech.get("_sources", []))
    for ind in unified.get("indicators", []):
        ind["confidence"] = _confidence_for(ind.get("sources", []))


def _confidence_for(sources: list) -> str:
    """
    HIGH   — 2+ independent sources corroborate this item.
    MEDIUM — exactly 1 high-provenance source (MITRE ATT&CK or CISA).
    LOW    — exactly 1 community/vendor source.
    """
    n = len(sources)
    if n >= 2:
        return "HIGH"
    if n == 1 and sources[0] in _HIGH_PROVENANCE_SOURCES:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _resolve_actor_name(results: list) -> str:
    for r in results:
        name = r.get("actor_name", "").strip()
        if name:
            return name
    return "unknown"


def _dedup_strings(values: list) -> list:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if not v:
            continue
        lv = str(v).lower().strip()
        if lv and lv not in seen:
            seen.add(lv)
            out.append(v)
    return out


def _collect(results: list[dict], key: str) -> list:
    out = []
    for r in results:
        val = r.get(key, [])
        if isinstance(val, list):
            out.extend(val)
    return out
