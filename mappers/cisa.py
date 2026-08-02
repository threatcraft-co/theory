"""
mappers/cisa.py
---------------
Maps raw CisaAdvisoriesCollector output → CommonSchema.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class CisaMapper:

    def map(self, raw: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise ValueError(f"Expected dict, got {type(raw).__name__}")
        actor_name = (raw.get("actor_name") or "").strip()
        if not actor_name:
            raise ValueError("raw record missing 'actor_name'")

        return {
            "actor_name":    actor_name,
            "source_id":     raw.get("source_id", "cisa"),
            "aliases":       _clean(raw.get("aliases", [])),
            "description":   raw.get("description", ""),
            "origin":        raw.get("origin", ""),
            "first_seen":    raw.get("first_seen", ""),
            "motivations":   _clean(raw.get("motivations", [])),
            "techniques":    self._map_techniques(raw.get("techniques", [])),
            "indicators":    [],
            "malware":       [],
            "campaigns":     [],
            "sectors":       _clean(raw.get("sectors", [])),
            # CISA-specific enrichments passed through for the dossier reporter
            "cves":          raw.get("cves", []),
            "advisories":    raw.get("advisories", []),
        }

    def _map_techniques(self, techniques: list[dict]) -> list[dict]:
        out = []
        for t in techniques:
            if not isinstance(t, dict):
                continue
            tid = (t.get("technique_id") or "").strip().upper()
            if not tid:
                continue
            out.append({
                "technique_id":   tid,
                "technique_name": t.get("technique_name", ""),
                "tactic":         t.get("tactic", ""),
                "tactics":        t.get("tactics", []),
                "description":    t.get("description", ""),
                "detection":      t.get("detection", ""),
                "sources":        t.get("sources", ["cisa"]),
            })
        return out


def _clean(items: list) -> list[str]:
    seen: set[str] = set()
    out : list[str] = []
    for item in items:
        s = str(item).strip()
        if s and s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    return out
