"""
reporters/stix_reporter.py
---------------------------
Exports a THEORY CommonSchema profile as a STIX 2.1 bundle.

STIX 2.1 is the standard format for threat intelligence sharing.
The bundle produced here is compatible with:
  - MISP (Malware Information Sharing Platform)
  - OpenCTI
  - Splunk Enterprise Security (TAXII connector)
  - Microsoft Sentinel
  - Any STIX-aware TIP or SOAR

STIX objects produced:
  identity        → THEORY as the producer
  intrusion-set   → the threat actor
  attack-pattern  → one per ATT&CK technique (with MITRE external ref)
  malware         → one per malware family
  indicator       → one per IOC with STIX pattern
  relationship    → actor→technique (uses), actor→malware (uses),
                    actor→indicator (indicates), malware→indicator (indicates)
  report          → wraps the full bundle

No external dependencies — pure Python stdlib.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Resolved at call time via theory.paths so THEORY_HOME and
# installed-package use work from any working directory.
def _output_dir() -> Path:
    from theory.paths import dossier_dir
    return dossier_dir()
SPEC_VERSION = "2.1"

# THEORY's own identity object — stable ID so bundles are mergeable.
#
# This was previously a hand-written string ending in "theory000001", which
# is not valid hexadecimal and therefore not a valid UUID. Since every object
# in every bundle carries created_by_ref pointing at it, that single malformed
# identifier made whole bundles fail strict STIX validation. A UUIDv5 over a
# fixed namespace keeps the "stable across runs, mergeable" property that the
# hard-coded value was reaching for, while actually being a UUID.
THEORY_IDENTITY_UUID = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/threatcraft-co/theory")
THEORY_IDENTITY_ID = f"identity--{THEORY_IDENTITY_UUID}"
THEORY_IDENTITY = {
    "type":           "identity",
    "spec_version":   SPEC_VERSION,
    "id":             THEORY_IDENTITY_ID,
    "name":           "THEORY",
    "identity_class": "system",
    "description":    (
        "THEORY — open-source multi-source threat actor intelligence framework. "
        "https://github.com/threatcraft-co/theory"
    ),
    "created":        "2025-01-01T00:00:00.000Z",
    "modified":       "2025-01-01T00:00:00.000Z",
}

# IOC type → STIX 2.1 pattern template
_IOC_PATTERNS: dict[str, str] = {
    "ip":          "[ipv4-addr:value = '{value}']",
    "domain":      "[domain-name:value = '{value}']",
    "url":         "[url:value = '{value}']",
    "hash_md5":    "[file:hashes.'MD5' = '{value}']",
    "hash_sha1":   "[file:hashes.'SHA-1' = '{value}']",
    "hash_sha256": "[file:hashes.'SHA-256' = '{value}']",
    "email":       "[email-addr:value = '{value}']",
    "cve":         "[vulnerability:name = '{value}']",
}

# Confidence label → STIX confidence (0-100). The deduplicator emits
# HIGH/MEDIUM/LOW strings while abuse.ch enrichers emit 0-100 integers, and
# both land in the same indicators list — _stix_confidence normalises either.
_CONFIDENCE_MAP = {"high": 85, "medium": 50, "low": 15}


def _stix_confidence(conf) -> int | None:
    """Normalise a THEORY confidence (int 0-100 or HIGH/MEDIUM/LOW) to a
    STIX confidence integer. Returns None when there is nothing to assert,
    so the field is omitted rather than guessed."""
    if conf is None or conf == "":
        return None
    if isinstance(conf, bool):
        return None
    if isinstance(conf, (int, float)):
        return max(0, min(int(conf), 100))
    return _CONFIDENCE_MAP.get(str(conf).strip().lower())


def _stix_quote(value: str) -> str:
    """Escape a value for a single-quoted STIX pattern literal.

    Backslash must be escaped first, otherwise escaping the quote would
    produce a dangling escape (\' -> \\' is correct; ' -> \' is not
    enough on its own when the value already contains a backslash)."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _ip_pattern(value: str) -> str | None:
    """Build the correct STIX pattern for an IPv4 or IPv6 indicator.

    Every 'ip' indicator previously used an ipv4-addr pattern, so OTX IPv6
    values and any unsplit ThreatFox ip:port values produced patterns that
    are invalid STIX and are rejected or mis-ingested by MISP/OpenCTI.
    Returns None for anything that is not a parseable address, so the
    caller can skip it rather than emit a malformed object."""
    import ipaddress
    host = str(value).strip()
    if host.startswith("[") and "]" in host:        # [2001:db8::1]:443
        host = host[1:host.index("]")]
    elif host.count(":") == 1:                       # 198.51.100.7:8443
        host = host.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    kind = "ipv4-addr" if ip.version == 4 else "ipv6-addr"
    return f"[{kind}:value = '{ip}']"


class StixReporter:
    """
    Builds and saves STIX 2.1 bundles from THEORY profiles.

    Usage::

        reporter = StixReporter()
        bundle   = reporter.build_bundle(profile)
        path     = reporter.save(profile)
    """

    def build_bundle(self, profile: dict[str, Any]) -> dict:
        """
        Convert a THEORY profile to a STIX 2.1 bundle dict.

        Args:
            profile: Merged CommonSchema profile from theory.run().

        Returns:
            STIX 2.1 bundle as a Python dict (JSON-serialisable).
        """
        now      = _now_stix()
        objects  = [THEORY_IDENTITY]
        all_ids  = []   # every object ID for the Report refs

        # ── 1. Intrusion Set ──────────────────────────────────────────
        actor_stix_id = _make_id("intrusion-set")
        actor_obj     = self._intrusion_set(profile, actor_stix_id, now)
        objects.append(actor_obj)
        all_ids.append(actor_stix_id)

        # ── 2. Attack Patterns (techniques) ──────────────────────────
        tid_to_stix: dict[str, str] = {}
        for t in (profile.get("techniques") or []):
            tid = (t.get("technique_id") or "").strip().upper()
            if not tid or tid in tid_to_stix:
                continue
            ap_id = _make_id("attack-pattern")
            tid_to_stix[tid] = ap_id
            objects.append(self._attack_pattern(t, ap_id, now))
            all_ids.append(ap_id)

            # Relationship: actor uses technique
            rel = self._relationship(
                "uses", actor_stix_id, ap_id, now,
                description=f"{profile.get('actor_name','')} uses {tid}",
            )
            objects.append(rel)
            all_ids.append(rel["id"])

        # ── 3. Malware objects ────────────────────────────────────────
        malware_name_to_stix: dict[str, str] = {}
        for m in (profile.get("malware") or []):
            name = (m.get("name") or "").strip()
            if not name or name.lower() in malware_name_to_stix:
                continue
            mw_id = _make_id("malware")
            malware_name_to_stix[name.lower()] = mw_id
            objects.append(self._malware(m, mw_id, now))
            all_ids.append(mw_id)

            # Relationship: actor uses malware
            rel = self._relationship(
                "uses", actor_stix_id, mw_id, now,
                description=f"{profile.get('actor_name','')} uses {name}",
            )
            objects.append(rel)
            all_ids.append(rel["id"])

        # ── 4. Indicators (IOCs) ──────────────────────────────────────
        seen_patterns: set[str] = set()
        for ioc in (profile.get("indicators") or []):
            ioc_type = ioc.get("type", "")
            value    = (ioc.get("value") or "").strip()
            if not value or not ioc_type:
                continue

            if ioc_type == "ip":
                pattern = _ip_pattern(value)
                if pattern is None:
                    logger.debug("STIX: skipping unparseable IP indicator %r", value)
                    continue
            else:
                pattern_tmpl = _IOC_PATTERNS.get(ioc_type)
                if not pattern_tmpl:
                    continue
                pattern = pattern_tmpl.format(value=_stix_quote(value))
            if pattern in seen_patterns:
                continue
            seen_patterns.add(pattern)

            ind_id = _make_id("indicator")
            conf   = ioc.get("confidence", 0)
            ind    = self._indicator(ioc, pattern, ind_id, now, conf)
            objects.append(ind)
            all_ids.append(ind_id)

            # Relationship target depends on how the indicator was obtained.
            #
            # Previously every indicator asserted `indicates --> intrusion-set`
            # regardless of provenance, so an IP that ThreatFox returned for
            # Cobalt Strike was exported to MISP/OpenCTI as a confirmed
            # indicator of this actor. Only actor-attributed evidence makes
            # that claim now; family-level evidence points at the malware,
            # which is what the source actually established.
            from theory.attribution import ACTOR, attribution_of

            level = attribution_of(ioc)
            family = (ioc.get("malware_family") or "").strip().lower()

            if level == ACTOR:
                rel = self._relationship(
                    "indicates", ind_id, actor_stix_id, now,
                    description=f"IOC attributed to {profile.get('actor_name','')}",
                )
                objects.append(rel)
                all_ids.append(rel["id"])
            elif family not in malware_name_to_stix:
                # Family-level evidence with no malware object to point at
                # would otherwise vanish from the bundle entirely. Keep the
                # link to the actor but say what it actually means.
                rel = self._relationship(
                    "related-to", ind_id, actor_stix_id, now,
                    description=(
                        f"IOC linked to tooling used by {profile.get('actor_name','')} "
                        f"({level} attribution) — not established as this actor's own "
                        f"infrastructure"
                    ),
                )
                objects.append(rel)
                all_ids.append(rel["id"])

            # If the IOC names a malware family we emitted, link to it.
            # For family/shared_tool evidence this is the primary (and only)
            # assertion; `family` is already computed above.
            if family and family in malware_name_to_stix:
                rel2 = self._relationship(
                    "indicates", ind_id, malware_name_to_stix[family], now,
                    description=f"IOC associated with {ioc.get('malware_family','')}",
                )
                objects.append(rel2)
                all_ids.append(rel2["id"])

        # ── 5. Campaigns ─────────────────────────────────────────────
        for c in (profile.get("campaigns") or []):
            name = (c.get("name") or "").strip()
            if not name:
                continue
            camp_id = _make_id("campaign")
            objects.append(self._campaign(c, camp_id, now))
            all_ids.append(camp_id)

            rel = self._relationship(
                "attributed-to", camp_id, actor_stix_id, now,
                description=f"Campaign attributed to {profile.get('actor_name','')}",
            )
            objects.append(rel)
            all_ids.append(rel["id"])

        # ── 6. Report (wraps everything) ──────────────────────────────
        report = self._report(profile, all_ids, now)
        objects.append(report)

        return {
            "type":         "bundle",
            "id":           _make_id("bundle"),
            # No spec_version here. STIX 2.0 required it on the bundle; 2.1
            # removed it and each SDO carries its own instead, so emitting it
            # made the bundle invalid under both specs — 2.1 parsers reject it
            # as an unexpected property. The per-object spec_version fields
            # below are the 2.1-correct placement.
            "objects":      objects,
        }

    def save(self, profile: dict[str, Any]) -> Path:
        """Build bundle and write to output/dossiers/<actor>.stix.json."""
        _output_dir()
        actor_slug = _slugify(profile.get("actor_name", "unknown"))
        path       = _output_dir() / f"{actor_slug}.stix.json"
        bundle     = self.build_bundle(profile)
        path.write_text(
            json.dumps(bundle, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("STIX bundle saved → %s (%d objects)", path, len(bundle["objects"]))
        return path

    # ------------------------------------------------------------------
    # Object builders
    # ------------------------------------------------------------------

    def _intrusion_set(
        self, profile: dict, stix_id: str, now: str
    ) -> dict:
        actor_name  = profile.get("actor_name", "Unknown")
        aliases     = profile.get("aliases", []) or []
        description = profile.get("description", "") or ""
        motivations = profile.get("motivations", []) or []
        first_seen  = profile.get("first_seen", "") or ""
        origin      = profile.get("origin", "") or ""
        gid         = profile.get("mitre_group_id", "") or ""

        obj: dict[str, Any] = {
            "type":         "intrusion-set",
            "spec_version": SPEC_VERSION,
            "id":           stix_id,
            "created":      now,
            "modified":     now,
            "created_by_ref": THEORY_IDENTITY_ID,
            "name":         actor_name,
            "description":  description or f"Threat actor {actor_name}.",
            "aliases":      aliases,
        }

        if motivations:
            # Map to STIX primary_motivation vocabulary where possible
            obj["primary_motivation"]    = _map_motivation(motivations[0])
            if len(motivations) > 1:
                obj["secondary_motivations"] = [
                    _map_motivation(m) for m in motivations[1:]
                ]

        if first_seen:
            obj["first_seen"] = _year_to_stix(first_seen)

        if origin:
            obj["x_theory_origin"] = origin   # custom extension

        if gid:
            obj["external_references"] = [{
                "source_name": "mitre-attack",
                "external_id": gid,
                "url": f"https://attack.mitre.org/groups/{gid}/",
            }]

        return obj

    def _attack_pattern(self, t: dict, stix_id: str, now: str) -> dict:
        tid  = (t.get("technique_id") or "").strip().upper()
        name = t.get("technique_name") or t.get("name") or tid
        desc = t.get("description", "") or ""

        obj: dict[str, Any] = {
            "type":         "attack-pattern",
            "spec_version": SPEC_VERSION,
            "id":           stix_id,
            "created":      now,
            "modified":     now,
            "created_by_ref": THEORY_IDENTITY_ID,
            "name":         name or tid,
            "description":  desc,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/"
                       if "." in tid else
                       f"https://attack.mitre.org/techniques/{tid}/",
            }],
        }

        # Kill chain phase
        tactic = t.get("tactic", "") or ""
        if tactic:
            obj["kill_chain_phases"] = [{
                "kill_chain_name": "mitre-attack",
                "phase_name":      tactic.lower().replace(" ", "-"),
            }]

        # Detection as custom extension
        detection = t.get("detection", "") or ""
        if detection:
            obj["x_mitre_detection"] = detection

        return obj

    def _malware(self, m: dict, stix_id: str, now: str) -> dict:
        name = (m.get("name") or "").strip()
        desc = m.get("description", "") or ""
        mtype = m.get("type", "malware") or "malware"

        # Map THEORY type → STIX malware-type vocabulary
        stix_types = _map_malware_type(mtype)

        obj: dict[str, Any] = {
            "type":          "malware",
            "spec_version":  SPEC_VERSION,
            "id":            stix_id,
            "created":       now,
            "modified":      now,
            "created_by_ref": THEORY_IDENTITY_ID,
            "name":          name,
            "description":   desc,
            "malware_types": stix_types,
            "is_family":     True,
        }

        aliases = m.get("aliases", []) or []
        if aliases:
            obj["aliases"] = [a for a in aliases if a and a != name]

        return obj

    def _indicator(
        self,
        ioc:     dict,
        pattern: str,
        stix_id: str,
        now:     str,
        conf:    int,
    ) -> dict:
        ioc_type    = ioc.get("type", "")
        value       = ioc.get("value", "")
        first_seen  = ioc.get("first_seen", "") or now
        description = ioc.get("description", "") or f"{ioc_type}: {value}"
        threat_type = ioc.get("threat_label", "") or ""

        obj: dict[str, Any] = {
            "type":              "indicator",
            "spec_version":      SPEC_VERSION,
            "id":                stix_id,
            "created":           now,
            "modified":          now,
            "created_by_ref":    THEORY_IDENTITY_ID,
            "name":              f"{ioc_type}: {value}",
            "description":       description,
            "pattern":           pattern,
            "pattern_type":      "stix",
            "valid_from":        _date_to_stix(first_seen) if first_seen != now else now,
            "indicator_types":   _map_indicator_type(ioc_type, threat_type),
        }

        stix_conf = _stix_confidence(conf)
        if stix_conf is not None:
            obj["confidence"] = stix_conf

        # Source attribution
        sources = ioc.get("sources", []) or []
        if sources:
            obj["x_theory_sources"] = sources

        malware_family = ioc.get("malware_family", "")
        if malware_family:
            obj["x_theory_malware_family"] = malware_family

        return obj

    def _campaign(self, c: dict, stix_id: str, now: str) -> dict:
        name = (c.get("name") or "").strip()
        desc = c.get("description", "") or ""
        obj: dict[str, Any] = {
            "type":           "campaign",
            "spec_version":   SPEC_VERSION,
            "id":             stix_id,
            "created":        now,
            "modified":       now,
            "created_by_ref": THEORY_IDENTITY_ID,
            "name":           name,
            "description":    desc,
        }
        first = c.get("first_seen", "") or ""
        if first:
            obj["first_seen"] = _date_to_stix(first)
        last = c.get("last_seen", "") or ""
        if last:
            obj["last_seen"] = _date_to_stix(last)
        return obj

    def _relationship(
        self,
        rel_type:   str,
        source_ref: str,
        target_ref: str,
        now:        str,
        description: str = "",
    ) -> dict:
        obj: dict[str, Any] = {
            "type":              "relationship",
            "spec_version":      SPEC_VERSION,
            "id":                _make_id("relationship"),
            "created":           now,
            "modified":          now,
            "created_by_ref":    THEORY_IDENTITY_ID,
            "relationship_type": rel_type,
            "source_ref":        source_ref,
            "target_ref":        target_ref,
        }
        if description:
            obj["description"] = description
        return obj

    def _report(
        self,
        profile:  dict,
        all_ids:  list[str],
        now:      str,
    ) -> dict:
        actor_name = profile.get("actor_name", "Unknown")
        sources    = ", ".join(profile.get("sources_cited", []) or [])
        return {
            "type":           "report",
            "spec_version":   SPEC_VERSION,
            "id":             _make_id("report"),
            "created":        now,
            "modified":       now,
            "created_by_ref": THEORY_IDENTITY_ID,
            "name":           f"THEORY Dossier: {actor_name}",
            "description":    (
                f"Automated threat actor intelligence report for {actor_name}, "
                f"generated by THEORY from sources: {sources}."
            ),
            "report_types":   ["threat-actor"],
            "published":      now,
            "object_refs":    [THEORY_IDENTITY_ID] + all_ids,
            "labels":         ["threat-intelligence", "theory-generated"],
            "x_theory_sources": profile.get("sources_cited", []),
            "x_theory_sigma_rule_count": profile.get("sigma_rule_count", 0),
            "x_theory_threatfox_ioc_count": profile.get("threatfox_ioc_count", 0),
        }


# ---------------------------------------------------------------------------
# Vocabulary mappers
# ---------------------------------------------------------------------------

def _map_motivation(motivation: str) -> str:
    """Map THEORY motivation string → STIX attack-motivation vocabulary."""
    m = (motivation or "").lower().strip()
    _MAP = {
        "espionage":       "espionage",
        "financial":       "financial-gain",
        "financial crime": "financial-gain",
        "ideology":        "ideology",
        "destruction":     "dominance",
        "destructive":     "dominance",
        "notoriety":       "notoriety",
        "coercion":        "coercion",
        "dominance":       "dominance",
    }
    for key, val in _MAP.items():
        if key in m:
            return val
    return "unknown"


def _map_malware_type(mtype: str) -> list[str]:
    """Map THEORY malware type → STIX malware-type open vocabulary."""
    _MAP = {
        "backdoor":    ["backdoor"],
        "ransomware":  ["ransomware"],
        "rootkit":     ["rootkit"],
        "loader":      ["dropper"],
        "infostealer": ["spyware"],
        "rat":         ["remote-access-trojan"],
        "wiper":       ["disk-eraser"],
        "tool":        ["tool"],
        "malware":     ["malware"],
    }
    return _MAP.get((mtype or "").lower(), ["malware"])


def _map_indicator_type(ioc_type: str, threat_type: str) -> list[str]:
    """Map IOC type + threat type → STIX indicator-type vocabulary."""
    threat_lower = (threat_type or "").lower()
    if "c2" in threat_lower or "botnet" in threat_lower or "command" in threat_lower:
        return ["malicious-activity", "compromised"]
    if "payload" in threat_lower:
        return ["malicious-activity"]
    type_map = {
        "ip":          ["malicious-activity"],
        "domain":      ["malicious-activity"],
        "url":         ["malicious-activity"],
        "hash_md5":    ["malicious-activity"],
        "hash_sha1":   ["malicious-activity"],
        "hash_sha256": ["malicious-activity"],
        "email":       ["malicious-activity"],
        "cve":         ["compromised"],
    }
    return type_map.get(ioc_type, ["unknown"])


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _make_id(stix_type: str) -> str:
    """Generate a deterministic-looking STIX ID."""
    return f"{stix_type}--{uuid.uuid4()}"


def _now_stix() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _year_to_stix(year_str: str) -> str:
    """Convert '2004' → '2004-01-01T00:00:00.000Z'."""
    m = re.match(r"(\d{4})", str(year_str))
    return f"{m.group(1)}-01-01T00:00:00.000Z" if m else _now_stix()


def _date_to_stix(date_str: str) -> str:
    """Convert 'YYYY-MM-DD' or 'YYYY' → STIX timestamp."""
    if not date_str:
        return _now_stix()
    if re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        return f"{date_str}T00:00:00.000Z"
    if re.match(r"^\d{4}$", date_str):
        return f"{date_str}-01-01T00:00:00.000Z"
    return _now_stix()


def _slugify(name: str) -> str:
    return name.lower().replace(" ", "_").replace("/", "_")


import re  # noqa: E402 — needed for _year_to_stix/_date_to_stix
