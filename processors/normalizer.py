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

from schema import (
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

    return {
        "actor_name": _normalize_actor_name(actor_name),
        "aliases": _normalize_string_list(data.get("aliases", [])),
        "source_id": source_id.strip(),
        "source_url": _coerce_str(data.get("source_url")),
        "retrieved_at": _normalize_timestamp(data.get("retrieved_at")),
        "suspected_origin": _coerce_str(data.get("suspected_origin")),
        "motivation": _normalize_motivations(data.get("motivation", [])),
        "first_seen": _normalize_timestamp_lenient(data.get("first_seen")),
        "sponsorship": _coerce_str(data.get("sponsorship")),
        "target_sectors": _normalize_sectors(data.get("target_sectors", [])),
        "target_countries": _normalize_string_list(data.get("target_countries", [])),
        "techniques": _normalize_techniques(data.get("techniques", []), source_id),
        "malware": _normalize_malware(data.get("malware", [])),
        "indicators": _normalize_indicators(data.get("indicators", [])),
        "campaigns": _normalize_campaigns(data.get("campaigns", [])),
        "cves": _normalize_cves(data.get("cves", []), source_id),
        "source_citation": _coerce_str(data.get("source_citation")) or source_id,
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
        result.append({
            "technique_id": normalized_id,
            "name": _coerce_str(entry.get("name")),
            "tactic": _coerce_str(entry.get("tactic")),
            "description": _coerce_str(entry.get("description")),
            "source": _coerce_str(entry.get("source")) or source_id,
            "detection_recs": entry.get("detection_recs", []),
        })
    return result


def _normalize_indicators(values: Any) -> list[dict[str, Any]]:
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
        result.append({
            "type": canonical_type,
            "value": value,
            "context": _coerce_str(entry.get("context")),
            "first_seen": _normalize_timestamp_lenient(entry.get("first_seen")),
            "sources": entry.get("sources", []),
        })
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
        result.append({
            "name": name,
            "type": _coerce_str(entry.get("type")),
            "description": _coerce_str(entry.get("description")),
        })
    return result


def _normalize_campaigns(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    result = []
    for entry in values:
        if not isinstance(entry, dict):
            continue
        description = _coerce_str(entry.get("description"))
        reference = _coerce_str(entry.get("reference"))
        if not description and not reference:
            continue
        result.append({
            "name": _coerce_str(entry.get("name")),
            "date": _normalize_timestamp_lenient(entry.get("date")),
            "description": description,
            "reference": reference,
        })
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
