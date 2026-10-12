"""
processors/normalizer.py

Validates and standardizes each CommonSchema dict before it enters the
aggregation pipeline. Enforces contracts — does not transform intelligence.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from dateutil import parser as dateutil_parser

from theory.schema import (
    CANONICAL_INDICATOR_TYPES,
    CANONICAL_MOTIVATIONS,
    SECTOR_NORMALIZATION,
    CommonSchema,
)

logger = logging.getLogger("theory.processors.normalizer")

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class NormalizationError(Exception):
    """Raised when a CommonSchema dict is so malformed it cannot be normalized."""


def normalize(data: dict[str, Any]) -> CommonSchema:
    """Normalize a raw CommonSchema dict from a collector."""
    if not isinstance(data, dict):
        raise NormalizationError(
            f"Collector returned {type(data).__name__}, expected dict."
        )
    actor_name = data.get("actor_name")
    source_id = data.get("source_id")
    if not actor_name or not isinstance(actor_name, str):
        raise NormalizationError("CommonSchema missing required field: actor_name")
    if not source_id or not isinstance(source_id, str):
        raise NormalizationError("CommonSchema missing required field: source_id")

    # Collectors emit origin/motivations/sectors; the schema historically
    # named them suspected_origin/motivation/target_sectors. Accept either
    # spelling on the way in and emit BOTH on the way out, so neither the
    # deduplicator nor the reporters have to guess — and so nothing has to
    # reach back into the raw records to recover a field the normalizer
    # dropped, which is what the pipeline used to do.
    origin = data.get("origin") or data.get("suspected_origin")
    motivations = data.get("motivations") or data.get("motivation") or []
    sectors = data.get("sectors") or data.get("target_sectors") or []

    normalized_motivations = _normalize_motivations(motivations)
    normalized_sectors = _normalize_sectors(sectors)
    origin_str = _coerce_str(origin)

    return {
        "actor_name": _normalize_actor_name(actor_name),
        "aliases": _normalize_string_list(data.get("aliases", [])),
        "source_id": source_id.strip(),
        "source_url": _coerce_str(data.get("source_url")),
        "retrieved_at": _normalize_timestamp(data.get("retrieved_at")),

        # Attribution — both spellings, same value
        "origin": origin_str,
        "suspected_origin": origin_str,
        "motivations": normalized_motivations,
        "motivation": normalized_motivations,
        "first_seen": _normalize_timestamp_lenient(data.get("first_seen")),
        "sponsorship": _coerce_str(data.get("sponsorship")),

        # Narrative — previously dropped entirely, which is why every
        # dossier's actor description came out empty.
        "description": _coerce_str(data.get("description")),

        # Target profile — both spellings, same value
        "sectors": normalized_sectors,
        "target_sectors": normalized_sectors,
        "target_countries": _normalize_string_list(data.get("target_countries", [])),

        "techniques": _normalize_techniques(data.get("techniques", []), source_id),
        "malware": _normalize_malware(data.get("malware", [])),
        "indicators": _normalize_indicators(data.get("indicators", []), source_id),
        "campaigns": _normalize_campaigns(data.get("campaigns", [])),
        "cves": _normalize_cves(data.get("cves", []), source_id),

        # Advisory records (CISA) — previously dropped, then re-read from
        # the raw records by the pipeline as a workaround.
        "advisories": _normalize_advisories(data.get("advisories", [])),

        # Provenance / passthrough metadata the reporters surface
        "source_citation": _coerce_str(data.get("source_citation")) or source_id,
        "raw_source": _coerce_str(data.get("raw_source")),
        "mitre_id": _coerce_str(data.get("mitre_id") or data.get("mitre_group_id")),
    }


def _coerce_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_actor_name(name: str) -> str:
    return " ".join(name.split())


def _normalize_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    seen: dict[str, str] = {}
    for v in values:
        if isinstance(v, str) and v.strip():
            key = v.strip().lower()
            if key not in seen:
                seen[key] = v.strip()
    return list(seen.values())


def _normalize_timestamp(value: Any) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
        except (OSError, ValueError, OverflowError):
            pass
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return datetime.now(timezone.utc).isoformat()
        try:
            dt = dateutil_parser.parse(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            pass
    logger.warning("Could not parse timestamp %r; using current UTC time.", value)
    return datetime.now(timezone.utc).isoformat()


def _normalize_timestamp_lenient(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        stripped = value.strip()
        if re.fullmatch(r"\d{4}", stripped):
            return stripped
        if not stripped:
            return ""
    return _normalize_timestamp(value)


def _normalize_motivations(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    result = []
    for v in values:
        if not isinstance(v, str):
            continue
        normalized = v.strip().lower()
        if normalized in CANONICAL_MOTIVATIONS:
            result.append(normalized)
        else:
            if "unknown" not in result:
                result.append("unknown")
    return list(dict.fromkeys(result))


def _normalize_sectors(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    result, seen = [], set()
    for v in values:
        if not isinstance(v, str):
            continue
        canonical = SECTOR_NORMALIZATION.get(v.strip().lower(), v.strip().title())
        if canonical not in seen:
            seen.add(canonical)
            result.append(canonical)
    return result


def _normalize_technique_id(tid: str) -> str | None:
    cleaned = tid.strip().upper()
    return cleaned if _TECHNIQUE_RE.match(cleaned) else None


def _normalize_techniques(values: Any, source_id: str) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    result = []
    for entry in values:
        if not isinstance(entry, dict):
            continue
        raw_id = entry.get("technique_id", "")
        if not raw_id:
            continue
        normalized_id = _normalize_technique_id(str(raw_id))
        if normalized_id is None:
            continue
        # technique_name and name are the same thing under two names:
        # collectors emit technique_name, reporters read both.
        name = _coerce_str(entry.get("name") or entry.get("technique_name"))
        detection = _coerce_str(entry.get("detection"))
        detection_recs = entry.get("detection_recs") or ([detection] if detection else [])
        sources = entry.get("sources") or [source_id]
        result.append({
            "technique_id": normalized_id,
            "name": name,
            "technique_name": name,
            "tactic": _coerce_str(entry.get("tactic")),
            "tactics": entry.get("tactics") or [],
            "description": _coerce_str(entry.get("description")),
            "detection": detection,
            "detection_recs": list(detection_recs),
            "source": _coerce_str(entry.get("source")) or source_id,
            "sources": list(sources) if isinstance(sources, list) else [source_id],
        })
    return result


def _normalize_indicators(values: Any, source_id: str = "") -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    type_aliases = {
        "ipv4": "ip", "ipv6": "ip",
        "md5": "hash_md5", "sha256": "hash_sha256", "sha1": "hash_sha1",
        "filehash-md5": "hash_md5", "filehash-sha256": "hash_sha256",
        "filehash-sha1": "hash_sha1", "file_hash": "hash_sha256",
        "hostname": "domain", "fqdn": "domain", "uri": "url",
    }
    result = []
    for entry in values:
        if not isinstance(entry, dict):
            continue
        raw_type = _coerce_str(entry.get("type")).lower()
        canonical_type = type_aliases.get(raw_type, raw_type)
        if canonical_type not in CANONICAL_INDICATOR_TYPES:
            continue
        value = _coerce_str(entry.get("value"))
        if not value:
            continue
        # Carry provenance and enrichment through. Dropping these is what
        # made every collector IOC arrive at the deduplicator with no
        # sources list, so corroboration was never detected and confidence
        # was never assigned.
        sources = entry.get("sources") or ([source_id] if source_id else [])
        normalized = {
            "type": canonical_type,
            "value": value,
            "context": _coerce_str(entry.get("context")) or _coerce_str(entry.get("description")),
            "description": _coerce_str(entry.get("description")),
            "first_seen": _normalize_timestamp_lenient(
                entry.get("first_seen") or entry.get("created")
            ),
            "sources": list(sources) if isinstance(sources, list) else [str(sources)],
        }
        for optional in ("confidence", "malware_family", "threat_type",
                         "threat_label", "last_seen", "tags", "attribution"):
            if entry.get(optional) not in (None, "", [], {}):
                normalized[optional] = entry[optional]
        result.append(normalized)
    return result


def _normalize_malware(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    result = []
    for entry in values:
        if not isinstance(entry, dict):
            continue
        name = _coerce_str(entry.get("name"))
        if not name:
            continue
        normalized = {
            "name": name,
            "type": _coerce_str(entry.get("type")),
            "description": _coerce_str(entry.get("description")),
        }
        for optional in ("aliases", "yara_count", "sources", "malpedia_url",
                         "yara_rules", "yara_rule_count"):
            if entry.get(optional) not in (None, "", [], {}):
                normalized[optional] = entry[optional]
        result.append(normalized)
    return result


def _normalize_campaigns(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    result = []
    for entry in values:
        if not isinstance(entry, dict):
            continue
        description = _coerce_str(entry.get("description"))
        reference = _coerce_str(entry.get("reference") or entry.get("url"))
        name = _coerce_str(entry.get("name"))
        # A named campaign is worth keeping even with no prose or link —
        # dropping it lost MITRE campaign names that carry only dates.
        if not name and not description and not reference:
            continue
        normalized = {
            "name": name,
            "date": _normalize_timestamp_lenient(entry.get("date")),
            "description": description,
            "reference": reference,
            "url": reference,
        }
        for optional in ("first_seen", "last_seen"):
            if entry.get(optional) not in (None, "", [], {}):
                normalized[optional] = entry[optional]
        result.append(normalized)
    return result


def _normalize_cves(values: Any, source_id: str) -> list[dict[str, Any]]:
    """Normalize CVE entries.

    Accepts entries from any collector (MITRE, CISA advisories, MISP Galaxy,
    OTX, future VulnCheck) and standardizes them. Preserves KEV enrichment
    fields when present, and normalizes both `cve_id` (new) and `cveID`
    (legacy CISA field) input formats.

    Invalid CVE IDs are dropped. Deduplicates by CVE identifier
    (case-insensitive).
    """
    if not isinstance(values, list):
        return []

    seen: dict[str, dict[str, Any]] = {}

    for entry in values:
        if not isinstance(entry, dict):
            continue

        # Support both new (cve_id) and legacy (cveID) field names
        raw_id = _coerce_str(entry.get("cve_id") or entry.get("cveID"))
        if not raw_id:
            continue

        normalized_id = raw_id.upper()
        if not _CVE_RE.match(normalized_id):
            continue

        # Merge if we've already seen this CVE from another collector's array
        if normalized_id in seen:
            existing = seen[normalized_id]
            # Union sources
            for src in (entry.get("sources") or [source_id]):
                if src and src not in existing["sources"]:
                    existing["sources"].append(src)
            # Union MITRE contexts if present
            for ctx in (entry.get("mitre_contexts") or []):
                if ctx and ctx not in existing.get("mitre_contexts", []):
                    existing.setdefault("mitre_contexts", []).append(ctx)
            for ref in (entry.get("mitre_references") or []):
                if ref and ref not in existing.get("mitre_references", []):
                    existing.setdefault("mitre_references", []).append(ref)
            # Prefer the longer description
            new_desc = _coerce_str(entry.get("description"))
            if new_desc and len(new_desc) > len(existing.get("description", "")):
                existing["description"] = new_desc
            # Preserve KEV enrichment fields from whichever entry carries them
            for kev_field in (
                "kev_confirmed", "kev_date_added", "kev_due_date",
                "kev_ransomware", "kev_vendor", "kev_product",
                "kev_vulnerability_name",
            ):
                if kev_field in entry and kev_field not in existing:
                    existing[kev_field] = entry[kev_field]
            # Preserve legacy CISA-specific fields similarly
            for cisa_field in ("product", "vendor", "due_date", "date_added"):
                if entry.get(cisa_field) and not existing.get(cisa_field):
                    existing[cisa_field] = entry[cisa_field]
            continue

        # New CVE entry
        normalized_entry: dict[str, Any] = {
            "cve_id": normalized_id,
            "sources": list(entry.get("sources") or [source_id]),
        }

        # Preserve optional descriptive/context fields when present
        desc = _coerce_str(entry.get("description"))
        if desc:
            normalized_entry["description"] = desc

        if entry.get("mitre_contexts"):
            normalized_entry["mitre_contexts"] = list(entry["mitre_contexts"])
        if entry.get("mitre_references"):
            normalized_entry["mitre_references"] = list(entry["mitre_references"])

        # Preserve KEV enrichment fields when present (added by cisa_kev)
        for kev_field in (
            "kev_confirmed", "kev_date_added", "kev_due_date",
            "kev_ransomware", "kev_vendor", "kev_product",
            "kev_vulnerability_name",
        ):
            if kev_field in entry:
                normalized_entry[kev_field] = entry[kev_field]

        # Preserve legacy CISA-specific fields when present
        for cisa_field in ("product", "vendor", "due_date", "date_added"):
            if entry.get(cisa_field):
                normalized_entry[cisa_field] = entry[cisa_field]

        seen[normalized_id] = normalized_entry

    return list(seen.values())


def _normalize_advisories(values: Any) -> list[dict[str, Any]]:
    """Normalize advisory records (currently CISA only).

    Previously absent: advisories were dropped by the normalizer and the
    pipeline re-read them from the raw collector records to put them back.
    """
    if not isinstance(values, list):
        return []
    result: list[dict[str, Any]] = []
    for entry in values:
        if not isinstance(entry, dict):
            continue
        title = _coerce_str(entry.get("title"))
        url = _coerce_str(entry.get("url"))
        if not title and not url:
            continue
        result.append({
            "title": title,
            "url": url,
            "date": _coerce_str(entry.get("date")),
            "summary": _coerce_str(entry.get("summary")),
        })
    return result
