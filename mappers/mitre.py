"""
mappers/mitre.py
----------------
Transforms raw output from MitreAttackCollector into a validated
CommonSchema dict, ready for the normalizer and deduplicator.

The mapper is intentionally thin: heavy normalisation lives in
processors/normalizer.py.  This layer handles MITRE-specific
structural quirks only.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class MitreMapper:
    """
    Maps a raw MITRE ATT&CK collector record to the THEORY CommonSchema.

    Usage::

        mapper = MitreMapper()
        schema_record = mapper.map(raw_dict)
    """

    # Tactic display-name → canonical ATT&CK tactic slug mapping.
    # Used to produce consistent tactic labels in the dossier TTP table.
    TACTIC_SLUGS: dict[str, str] = {
        "reconnaissance":        "Reconnaissance",
        "resource development":  "Resource Development",
        "initial access":        "Initial Access",
        "execution":             "Execution",
        "persistence":           "Persistence",
        "privilege escalation":  "Privilege Escalation",
        "defense evasion":       "Defense Evasion",
        "credential access":     "Credential Access",
        "discovery":             "Discovery",
        "lateral movement":      "Lateral Movement",
        "collection":            "Collection",
        "command and control":   "Command and Control",
        "exfiltration":          "Exfiltration",
        "impact":                "Impact",
    }

    def map(self, raw: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a raw MitreAttackCollector record to CommonSchema.

        Args:
            raw: Dict as returned by ``MitreAttackCollector.collect()``.

        Returns:
            CommonSchema-compatible dict.

        Raises:
            ValueError: If ``raw`` is missing required top-level keys.
        """
        if not isinstance(raw, dict):
            raise ValueError(f"Expected dict, got {type(raw).__name__}")

        actor_name = raw.get("actor_name", "").strip()
        if not actor_name:
            raise ValueError("raw record is missing 'actor_name'")

        return {
            # ── Identity ──────────────────────────────────────────────
            "actor_name":  actor_name,
            "source_id":   raw.get("source_id", "mitre_attack"),
            "aliases":     self._clean_string_list(raw.get("aliases", [])),
            "description": raw.get("description", ""),
            # ── Attribution ───────────────────────────────────────────
            "origin":      raw.get("origin", ""),
            "first_seen":  raw.get("first_seen", ""),
            "motivations": self._clean_string_list(raw.get("motivations", [])),
            # ── TTPs ──────────────────────────────────────────────────
            "techniques":  self._map_techniques(raw.get("techniques", [])),
            # ── Indicators (MITRE publishes none) ─────────────────────
            "indicators":  [],
            # ── Malware & Tools ───────────────────────────────────────
            "malware":     self._map_malware(raw.get("malware", [])),
            # ── Campaigns ─────────────────────────────────────────────
            "campaigns":   self._map_campaigns(raw.get("campaigns", [])),
            # ── Sectors ───────────────────────────────────────────────
            "sectors":     [],
            # ── Meta ──────────────────────────────────────────────────
            "mitre_group_id": raw.get("mitre_id", ""),
        }

    # ------------------------------------------------------------------
    # Sub-object mappers
    # ------------------------------------------------------------------

    def _map_techniques(self, techniques: list[dict]) -> list[dict]:
        """Normalise tactic labels and ensure required keys exist."""
        mapped: list[dict] = []
        for t in techniques:
            if not isinstance(t, dict):
                continue
            tid = (t.get("technique_id") or "").strip().upper()
            if not tid:
                continue

            tactic_raw = (t.get("tactic") or "").strip().lower()
            tactic     = self.TACTIC_SLUGS.get(tactic_raw, tactic_raw.title())

            mapped.append({
                "technique_id":   tid,
                "technique_name": t.get("technique_name", ""),
                "tactic":         tactic,
                "tactics":        [
                    self.TACTIC_SLUGS.get(x.lower(), x.title())
                    for x in (t.get("tactics") or [])
                ],
                "description":    t.get("description", ""),
                "detection":      t.get("detection", ""),
                "sources":        t.get("sources", ["mitre_attack"]),
            })

        return mapped

    def _map_malware(self, malware: list[dict]) -> list[dict]:
        """Pass-through with key guarantee."""
        mapped: list[dict] = []
        for m in malware:
            if not isinstance(m, dict):
                continue
            name = (m.get("name") or "").strip()
            if not name:
                continue
            mapped.append({
                "name":        name,
                "type":        m.get("type", "malware"),
                "description": m.get("description", ""),
            })
        return mapped

    def _map_campaigns(self, campaigns: list[dict]) -> list[dict]:
        """Pass-through with key guarantee."""
        mapped: list[dict] = []
        for c in campaigns:
            if not isinstance(c, dict):
                continue
            name = (c.get("name") or "").strip()
            if not name:
                continue
            mapped.append({
                "name":        name,
                "description": c.get("description", ""),
                "first_seen":  str(c.get("first_seen") or ""),
                "last_seen":   str(c.get("last_seen") or ""),
            })
        return mapped

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _clean_string_list(items: list) -> list[str]:
        """Strip whitespace, remove empty strings, deduplicate case-insensitively.

        The first-seen casing wins (e.g. ["Fancy Bear", "fancy bear"] → ["Fancy Bear"]).
        """
        seen_lower: set[str]  = set()
        result:     list[str] = []
        for item in items:
            s = str(item).strip()
            if s and s.lower() not in seen_lower:
                seen_lower.add(s.lower())
                result.append(s)
        return result
