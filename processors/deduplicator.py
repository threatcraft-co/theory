"""
processors/deduplicator.py

Merges a list of normalized CommonSchema dicts into a single unified actor
profile. Applies confidence weighting based on source count and provenance.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("theory.processors.deduplicator")

_HIGH_PROVENANCE_SOURCES = frozenset({"mitre_attack", "cisa_advisories"})


def deduplicate(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge normalized CommonSchema dicts into a single unified actor profile."""
    if not results:
        logger.warning("deduplicator received empty results list.")
        return _empty_profile("unknown")

    actor_name = _resolve_actor_name(results)
    unified = _empty_profile(actor_name)

    for result in results:
        if not isinstance(result, dict):
            continue
        source_id = result.get("source_id", "unknown")

        _merge_scalar(unified, result, "suspected_origin")
        _merge_scalar(unified, result, "first_seen")
        _merge_scalar(unified, result, "sponsorship")

        unified["aliases"].extend(result.get("aliases", []))
        unified["motivation"].extend(result.get("motivation", []))
        unified["target_sectors"].extend(result.get("target_sectors", []))
        unified["target_countries"].extend(result.get("target_countries", []))
        unified["campaigns"].extend(result.get("campaigns", []))

        _merge_techniques(unified, result.get("techniques", []), source_id)
        _merge_malware(unified, result.get("malware", []))
        _merge_indicators(unified, result.get("indicators", []), source_id)

        citation = result.get("source_citation") or source_id
        if source_id not in [s["source_id"] for s in unified["_sources"]]:
            unified["_sources"].append({
                "source_id": source_id,
                "source_citation": citation,
                "source_url": result.get("source_url", ""),
                "retrieved_at": result.get("retrieved_at", ""),
            })

    unified["aliases"] = _dedup_strings(unified["aliases"])
    unified["motivation"] = _dedup_strings(unified["motivation"])
    unified["target_sectors"] = _dedup_strings(unified["target_sectors"])
    unified["target_countries"] = _dedup_strings(unified["target_countries"])

    _apply_confidence(unified)

    logger.info(
        "Deduplication complete for %r: %d techniques, %d indicators, %d malware, %d campaigns.",
        actor_name,
        len(unified["techniques"]),
        len(unified["indicators"]),
        len(unified["malware"]),
        len(unified["campaigns"]),
    )
    return unified


def _merge_scalar(unified: dict, source: dict, field: str) -> None:
    if not unified.get(field) and source.get(field):
        unified[field] = source[field]


def _merge_techniques(unified: dict, techniques: list, source_id: str) -> None:
    index = unified["_technique_index"]
    for tech in techniques:
        tid = tech.get("technique_id")
        if not tid:
            continue
        if tid in index:
            existing = unified["techniques"][index[tid]]
            if source_id not in existing.get("_sources", []):
                existing.setdefault("_sources", []).append(source_id)
            if not existing.get("description") and tech.get("description"):
                existing["description"] = tech["description"]
            if not existing.get("tactic") and tech.get("tactic"):
                existing["tactic"] = tech["tactic"]
            existing_recs = existing.setdefault("detection_recs", [])
            for rec in tech.get("detection_recs", []):
                if rec not in existing_recs:
                    existing_recs.append(rec)
        else:
            entry = dict(tech)
            entry["_sources"] = [source_id]
            entry.setdefault("detection_recs", [])
            index[tid] = len(unified["techniques"])
            unified["techniques"].append(entry)


def _merge_malware(unified: dict, malware: list) -> None:
    index = unified["_malware_index"]
    for m in malware:
        name = m.get("name", "").strip()
        if not name:
            continue
        key = name.lower()
        if key not in index:
            index.add(key)
            unified["malware"].append(dict(m))
        else:
            for existing in unified["malware"]:
                if existing.get("name", "").lower() == key:
                    if not existing.get("description") and m.get("description"):
                        existing["description"] = m["description"]
                    break


def _merge_indicators(unified: dict, indicators: list, source_id: str) -> None:
    index = unified["_indicator_index"]
    for ind in indicators:
        itype = ind.get("type", "")
        ivalue = ind.get("value", "")
        if not itype or not ivalue:
            continue
        key = (itype, ivalue.lower())
        if key in index:
            sources = unified["indicators"][index[key]].setdefault("sources", [])
            if source_id not in sources:
                sources.append(source_id)
        else:
            entry = dict(ind)
            entry["sources"] = [source_id]
            index[key] = len(unified["indicators"])
            unified["indicators"].append(entry)


def _apply_confidence(unified: dict) -> None:
    for tech in unified["techniques"]:
        tech["confidence"] = _confidence_for(tech.get("_sources", []))
    for ind in unified["indicators"]:
        ind["confidence"] = _confidence_for(ind.get("sources", []))


def _confidence_for(sources: list) -> str:
    if len(sources) >= 2:
        return "HIGH"
    if len(sources) == 1 and sources[0] in _HIGH_PROVENANCE_SOURCES:
        return "MEDIUM"
    return "LOW"


def _resolve_actor_name(results: list) -> str:
    for r in results:
        name = r.get("actor_name", "").strip()
        if name:
            return name
    return "unknown"


def _dedup_strings(values: list) -> list:
    seen: dict[str, str] = {}
    for v in values:
        if isinstance(v, str) and v.strip():
            key = v.strip().lower()
            if key not in seen:
                seen[key] = v.strip()
    return list(seen.values())


def _empty_profile(actor_name: str) -> dict[str, Any]:
    return {
        "actor_name": actor_name,
        "aliases": [],
        "suspected_origin": None,
        "motivation": [],
        "first_seen": None,
        "sponsorship": None,
        "target_sectors": [],
        "target_countries": [],
        "techniques": [],
        "malware": [],
        "indicators": [],
        "campaigns": [],
        "_sources": [],
        "_technique_index": {},
        "_malware_index": set(),
        "_indicator_index": {},
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
