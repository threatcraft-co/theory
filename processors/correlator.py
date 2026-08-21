"""
processors/correlator.py
------------------------
Intelligence Correlation Engine

Runs after deduplication and enrichment, before reporting.
Transforms parallel data lists into cross-referenced intelligence
by building relationship graphs between techniques, malware, IOCs,
CVEs, campaigns, and detection rules.

This is the layer that turns THEORY from a multi-source aggregator into
an intelligence framework. Instead of handing analysts six parallel tables
and asking them to mentally stitch connections together, the correlator
builds those connections programmatically and surfaces:

  - Which malware families are linked to which IOCs (and how fresh they are)
  - Which techniques have detection coverage (Sigma/YARA) and which are gaps
  - Which CVEs are confirmed-exploited and which malware/techniques they map to
  - A kill-chain view grouping everything by attack phase
  - Prioritised analyst actions: what to block, detect, patch, and hunt — today

Usage in the pipeline:
  After:  deduplication + enrichment (Sigma, ThreatFox, GreyNoise, etc.)
  Before: reporting (dossier, HTML, playbook, etc.)

  from processors.correlator import correlate
  profile = correlate(profile)
  # profile["correlations"] now contains cross-referenced intelligence
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Kill chain ordering — MITRE ATT&CK tactic phases in operational sequence
# ---------------------------------------------------------------------------

TACTIC_ORDER: dict[str, int] = {
    "reconnaissance":        0,
    "resource development":  1,
    "initial access":        2,
    "execution":             3,
    "persistence":           4,
    "privilege escalation":  5,
    "defense evasion":       6,
    "credential access":     7,
    "discovery":             8,
    "lateral movement":      9,
    "collection":            10,
    "command and control":   11,
    "exfiltration":          12,
    "impact":                13,
}

# IOC freshness thresholds (days)
FRESH_DAYS = 30
AGING_DAYS = 90


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def correlate(profile: dict[str, Any]) -> dict[str, Any]:
    """
    Build cross-referenced intelligence from an enriched actor profile.

    Adds ``profile["correlations"]`` containing:
      - ``malware_intel``    — per-family IOC/detection/CVE links
      - ``technique_intel``  — per-technique malware/CVE/detection links
      - ``kill_chain``       — tactic-phase-ordered view of the full profile
      - ``priority_actions`` — ranked analyst recommendations
      - ``coverage``         — detection coverage statistics
      - ``stats``            — summary counts

    Args:
        profile: Enriched actor profile dict (post-deduplication).

    Returns:
        The same profile dict, with ``correlations`` added.
    """
    techniques = profile.get("techniques", [])
    malware    = profile.get("malware", [])
    indicators = profile.get("indicators", [])
    cves       = profile.get("cves", [])
    campaigns  = profile.get("campaigns", [])

    # ── Build indexes ─────────────────────────────────────────────────
    ioc_by_family   = _index_iocs_by_family(indicators)
    cve_refs        = _index_cve_references(cves)
    malware_names   = {(m.get("name") or "").lower(): m for m in malware if m.get("name")}
    technique_index = {(t.get("technique_id") or "").upper(): t for t in techniques}

    # ── Cross-reference: malware ↔ IOCs ↔ CVEs ───────────────────────
    malware_intel = _build_malware_intel(
        malware, ioc_by_family, cve_refs, technique_index
    )

    # ── Cross-reference: techniques ↔ malware ↔ CVEs ↔ Sigma ────────
    technique_intel = _build_technique_intel(
        techniques, malware_names, cve_refs, ioc_by_family
    )

    # ── Kill chain view ──────────────────────────────────────────────
    kill_chain = _build_kill_chain(
        techniques, malware_intel, ioc_by_family
    )

    # ── Detection coverage ───────────────────────────────────────────
    coverage = _build_coverage(techniques)

    # ── Priority actions ─────────────────────────────────────────────
    priority_actions = _build_priority_actions(
        malware_intel, technique_intel, cves, indicators, coverage
    )

    # ── Summary stats ────────────────────────────────────────────────
    stats = _build_stats(
        techniques, malware, indicators, cves, campaigns,
        malware_intel, coverage
    )

    profile["correlations"] = {
        "malware_intel":    malware_intel,
        "technique_intel":  technique_intel,
        "kill_chain":       kill_chain,
        "priority_actions": priority_actions,
        "coverage":         coverage,
        "stats":            stats,
    }

    logger.info(
        "Correlator: %d technique links, %d malware links, %d priority actions",
        len(technique_intel),
        len(malware_intel),
        len(priority_actions),
    )

    return profile


# ---------------------------------------------------------------------------
# Index builders
# ---------------------------------------------------------------------------

def _index_iocs_by_family(indicators: list[dict]) -> dict[str, list[dict]]:
    """
    Group IOCs by their malware_family field (lowercase key).

    ThreatFox, MalwareBazaar, and URLhaus all tag IOCs with the malware
    family they belong to. This index lets us answer: "for malware X,
    what IOCs do we have, and how fresh are they?"
    """
    by_family: dict[str, list[dict]] = defaultdict(list)
    for ioc in indicators:
        family = (
            ioc.get("malware_family")
            or ioc.get("malware")
            or ""
        ).strip().lower()
        if family:
            by_family[family].append(ioc)
    return dict(by_family)


def _index_cve_references(cves: list[dict]) -> dict[str, list[dict]]:
    """
    Build a reverse index from MITRE references back to CVEs.

    CVEs extracted from MITRE ATT&CK carry ``mitre_references`` — the
    technique IDs or malware/campaign names whose descriptions mentioned
    the CVE. This index lets us answer: "for technique T1190, which CVEs
    are associated?" or "for malware Mimikatz, which CVEs?"
    """
    ref_index: dict[str, list[dict]] = defaultdict(list)
    for cve in cves:
        for ref in (cve.get("mitre_references") or []):
            key = ref.strip().upper() if ref.startswith("T") else ref.strip().lower()
            ref_index[key].append(cve)
    return dict(ref_index)


# ---------------------------------------------------------------------------
# Malware intelligence
# ---------------------------------------------------------------------------

def _build_malware_intel(
    malware:         list[dict],
    ioc_by_family:   dict[str, list[dict]],
    cve_refs:        dict[str, list[dict]],
    technique_index: dict[str, dict],
) -> list[dict]:
    """
    For each malware family in the profile, build a cross-referenced
    intelligence card showing: IOC count/freshness, detection coverage,
    linked CVEs, and linked techniques.
    """
    results: list[dict] = []
    now = datetime.now(timezone.utc)

    for m in malware:
        name      = (m.get("name") or "").strip()
        name_low  = name.lower()
        if not name:
            continue

        # ── IOC linkage ───────────────────────────────────────────────
        # Try exact match first, then fuzzy prefix/substring
        family_iocs = _fuzzy_family_lookup(name_low, ioc_by_family)
        iocs_by_type: dict[str, int] = defaultdict(int)
        fresh = aging = stale = 0
        for ioc in family_iocs:
            iocs_by_type[ioc.get("type", "unknown")] += 1
            age = _ioc_age_days(ioc, now)
            if age is not None:
                if age <= FRESH_DAYS:
                    fresh += 1
                elif age <= AGING_DAYS:
                    aging += 1
                else:
                    stale += 1
            else:
                stale += 1  # no date → treat as stale

        # ── CVE linkage ───────────────────────────────────────────────
        linked_cves = cve_refs.get(name_low, [])
        # Also check aliases
        for alias in (m.get("aliases") or []):
            linked_cves.extend(cve_refs.get(alias.lower(), []))
        # Deduplicate
        seen_cve_ids: set[str] = set()
        unique_cves: list[dict] = []
        for cve in linked_cves:
            cid = cve.get("cve_id", "")
            if cid and cid not in seen_cve_ids:
                seen_cve_ids.add(cid)
                unique_cves.append(cve)

        # ── Detection coverage ────────────────────────────────────────
        has_yara  = bool(m.get("yara_rules") or m.get("yara_rule_count"))
        has_sigma = False  # set below via technique linkage

        # ── Technique linkage (via CVE mitre_references) ──────────────
        linked_technique_ids: set[str] = set()
        for cve in unique_cves:
            for ref in (cve.get("mitre_references") or []):
                if ref.upper().startswith("T") and ref.upper() in technique_index:
                    linked_technique_ids.add(ref.upper())
                    t = technique_index[ref.upper()]
                    if t.get("sigma_rules"):
                        has_sigma = True

        entry = {
            "name":                name,
            "type":                m.get("type", "malware"),
            "ioc_count":           len(family_iocs),
            "iocs_by_type":        dict(iocs_by_type),
            "iocs_fresh":          fresh,
            "iocs_aging":          aging,
            "iocs_stale":          stale,
            "has_sigma":           has_sigma,
            "has_yara":            has_yara,
            "yara_rule_count":     m.get("yara_rule_count", 0),
            "linked_cves":         [c.get("cve_id", "") for c in unique_cves],
            "linked_cves_kev":     [c.get("cve_id", "") for c in unique_cves if c.get("kev_confirmed")],
            "linked_technique_ids": sorted(linked_technique_ids),
        }

        # Only include entries that have at least one connection
        if family_iocs or unique_cves or has_yara or linked_technique_ids:
            results.append(entry)

    # Sort: families with fresh IOCs first, then by total IOC count
    results.sort(key=lambda x: (-x["iocs_fresh"], -x["ioc_count"]))
    return results


def _fuzzy_family_lookup(
    name_low: str,
    ioc_by_family: dict[str, list[dict]],
) -> list[dict]:
    """
    Match a malware name to IOC family keys with some tolerance.

    ThreatFox tags like "AgentTesla" but Malpedia calls it "Agent Tesla",
    MITRE might call it "Agent Tesla". We try:
      1. Exact match
      2. Stripped match (remove spaces/hyphens/underscores)
      3. Substring containment (either direction)
    """
    # Exact
    if name_low in ioc_by_family:
        return ioc_by_family[name_low]

    # Stripped
    stripped = name_low.replace(" ", "").replace("-", "").replace("_", "")
    for key, iocs in ioc_by_family.items():
        key_stripped = key.replace(" ", "").replace("-", "").replace("_", "")
        if stripped == key_stripped:
            return iocs

    # Substring (bidirectional, but only if name is long enough to be meaningful)
    if len(name_low) >= 4:
        for key, iocs in ioc_by_family.items():
            if name_low in key or key in name_low:
                return iocs

    return []


# ---------------------------------------------------------------------------
# Technique intelligence
# ---------------------------------------------------------------------------

def _build_technique_intel(
    techniques:    list[dict],
    malware_names: dict[str, dict],
    cve_refs:      dict[str, list[dict]],
    ioc_by_family: dict[str, list[dict]],
) -> list[dict]:
    """
    For each technique, build a cross-referenced intelligence card showing:
    linked malware, linked CVEs (especially KEV), Sigma coverage, and
    whether there are actionable IOCs downstream.
    """
    results: list[dict] = []

    for t in techniques:
        tid = (t.get("technique_id") or "").upper()
        if not tid:
            continue

        sigma_rules = t.get("sigma_rules", [])
        sigma_count = len(sigma_rules)

        # ── CVE linkage ───────────────────────────────────────────────
        linked_cves = cve_refs.get(tid, [])
        kev_cves    = [c for c in linked_cves if c.get("kev_confirmed")]

        # ── Malware linkage (via CVE mitre_references to this technique) ──
        # A technique links to malware when:
        #   a) A CVE references both this technique and a malware name
        #   b) The malware has IOCs (making the chain actionable)
        linked_malware_names: set[str] = set()
        linked_ioc_count = 0

        for cve in linked_cves:
            for ref in (cve.get("mitre_references") or []):
                ref_low = ref.strip().lower()
                if ref_low in malware_names:
                    linked_malware_names.add(malware_names[ref_low]["name"])

        # Also check: does any malware in the profile have IOCs?
        # If so, those malware are implicitly linked (same actor, same profile)
        for mname_low, m in malware_names.items():
            family_iocs = _fuzzy_family_lookup(mname_low, ioc_by_family)
            if family_iocs:
                linked_ioc_count += len(family_iocs)

        entry = {
            "technique_id":     tid,
            "technique_name":   t.get("technique_name") or t.get("name", ""),
            "tactic":           t.get("tactic", ""),
            "confidence":       (t.get("confidence") or "LOW").upper(),
            "sigma_count":      sigma_count,
            "sigma_levels":     _sigma_level_summary(sigma_rules),
            "has_detection":    sigma_count > 0,
            "linked_cve_ids":   [c.get("cve_id", "") for c in linked_cves],
            "kev_cve_ids":      [c.get("cve_id", "") for c in kev_cves],
            "linked_malware":   sorted(linked_malware_names),
        }
        results.append(entry)

    return results


def _sigma_level_summary(sigma_rules: list[dict]) -> dict[str, int]:
    """Count Sigma rules by severity level."""
    counts: dict[str, int] = defaultdict(int)
    for rule in sigma_rules:
        level = (rule.get("level") or "unknown").lower()
        counts[level] += 1
    return dict(counts)


# ---------------------------------------------------------------------------
# Kill chain view
# ---------------------------------------------------------------------------

def _build_kill_chain(
    techniques:    list[dict],
    malware_intel: list[dict],
    ioc_by_family: dict[str, list[dict]],
) -> list[dict]:
    """
    Group techniques by tactic phase in kill-chain order, annotating each
    phase with detection status, involved malware, and downstream IOC count.

    This gives analysts a sequential view: "how does this actor operate
    from reconnaissance through impact, and where can I see them?"
    """
    # Group techniques by tactic
    by_tactic: dict[str, list[dict]] = defaultdict(list)
    for t in techniques:
        tactic = (t.get("tactic") or "").strip()
        if tactic:
            by_tactic[tactic].append(t)

    # Build malware set per tactic phase (all malware in the profile is
    # implicitly relevant to each phase where the actor operates)
    all_malware_with_iocs = {
        m["name"] for m in malware_intel if m.get("ioc_count", 0) > 0
    }

    # Build ordered phases
    phases: list[dict] = []
    for tactic, techs in sorted(
        by_tactic.items(),
        key=lambda x: TACTIC_ORDER.get(x[0].lower(), 99),
    ):
        has_sigma = any(t.get("sigma_rules") for t in techs)
        has_any_detection = has_sigma or any(t.get("detection") for t in techs)

        # Count techniques by confidence in this phase
        conf_counts = defaultdict(int)
        for t in techs:
            conf = (t.get("confidence") or "LOW").upper()
            conf_counts[conf] += 1

        phases.append({
            "tactic":            tactic,
            "phase_order":       TACTIC_ORDER.get(tactic.lower(), 99),
            "technique_count":   len(techs),
            "technique_ids":     [t.get("technique_id", "") for t in techs],
            "confidence_breakdown": dict(conf_counts),
            "has_detection":     has_any_detection,
            "sigma_rule_count":  sum(len(t.get("sigma_rules", [])) for t in techs),
            "detection_gap":     not has_any_detection,
        })

    return phases


# ---------------------------------------------------------------------------
# Detection coverage
# ---------------------------------------------------------------------------

def _build_coverage(techniques: list[dict]) -> dict[str, Any]:
    """
    Calculate detection coverage across all techniques.

    Returns a summary of what's covered, what's a gap, and where
    the highest-priority gaps are (HIGH confidence + no detection).
    """
    total      = len(techniques)
    with_sigma = 0
    with_any   = 0
    gaps: list[dict]      = []
    critical_gaps: list[dict] = []

    for t in techniques:
        sigma   = t.get("sigma_rules", [])
        det_str = t.get("detection", "")
        has_det = bool(sigma) or bool(det_str)

        if sigma:
            with_sigma += 1
        if has_det:
            with_any += 1
        else:
            gap_entry = {
                "technique_id":   t.get("technique_id", ""),
                "technique_name": t.get("technique_name") or t.get("name", ""),
                "tactic":         t.get("tactic", ""),
                "confidence":     (t.get("confidence") or "LOW").upper(),
            }
            gaps.append(gap_entry)
            if gap_entry["confidence"] == "HIGH":
                critical_gaps.append(gap_entry)

    # Sort gaps: HIGH confidence first, then by tactic phase order
    gaps.sort(key=lambda x: (
        {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["confidence"], 3),
        TACTIC_ORDER.get(x["tactic"].lower(), 99),
    ))
    critical_gaps.sort(key=lambda x: TACTIC_ORDER.get(x["tactic"].lower(), 99))

    pct = round((with_any / total) * 100) if total else 0
    sigma_pct = round((with_sigma / total) * 100) if total else 0

    return {
        "total_techniques":      total,
        "with_sigma":            with_sigma,
        "with_any_detection":    with_any,
        "coverage_pct":          pct,
        "sigma_coverage_pct":    sigma_pct,
        "gaps":                  gaps,
        "critical_gaps":         critical_gaps,
        "gap_count":             len(gaps),
        "critical_gap_count":    len(critical_gaps),
    }


# ---------------------------------------------------------------------------
# Priority actions
# ---------------------------------------------------------------------------

def _build_priority_actions(
    malware_intel:   list[dict],
    technique_intel: list[dict],
    cves:            list[dict],
    indicators:      list[dict],
    coverage:        dict[str, Any],
) -> list[dict]:
    """
    Generate ranked analyst recommendations based on the correlated data.

    Priority logic:
      1. BLOCK — fresh IOCs that can be blocked right now
      2. PATCH — KEV-confirmed CVEs (federally mandated, actively exploited)
      3. DETECT — high-confidence techniques with no Sigma coverage
      4. HUNT — malware families with infrastructure but no detection
      5. MONITOR — aging IOCs worth watching, vendor intel signals

    Each action includes enough context for an analyst to act on it
    without reading the full dossier.
    """
    actions: list[dict] = []
    now = datetime.now(timezone.utc)
    priority = 0

    # ── 1. BLOCK: Fresh IOCs ─────────────────────────────────────────
    fresh_iocs = [
        ioc for ioc in indicators
        if _ioc_age_days(ioc, now) is not None and _ioc_age_days(ioc, now) <= FRESH_DAYS
    ]
    if fresh_iocs:
        # Group by malware family for context
        by_family: dict[str, list[dict]] = defaultdict(list)
        no_family: list[dict] = []
        for ioc in fresh_iocs:
            family = (ioc.get("malware_family") or ioc.get("malware") or "").strip()
            if family:
                by_family[family].append(ioc)
            else:
                no_family.append(ioc)

        for family, family_iocs in sorted(by_family.items(), key=lambda x: -len(x[1])):
            priority += 1
            type_summary = _type_summary(family_iocs)
            actions.append({
                "priority":  priority,
                "action":    "block",
                "urgency":   "critical",
                "title":     f"Block {len(family_iocs)} fresh {family} IOCs",
                "detail":    (
                    f"{len(family_iocs)} indicators seen within the last {FRESH_DAYS} days "
                    f"linked to {family}: {type_summary}. "
                    f"These are active infrastructure — block immediately."
                ),
                "ioc_count":     len(family_iocs),
                "ioc_types":     _type_counts(family_iocs),
                "malware_family": family,
            })

        if no_family:
            priority += 1
            actions.append({
                "priority":  priority,
                "action":    "block",
                "urgency":   "high",
                "title":     f"Block {len(no_family)} fresh unattributed IOCs",
                "detail":    (
                    f"{len(no_family)} recent indicators without family attribution: "
                    f"{_type_summary(no_family)}."
                ),
                "ioc_count": len(no_family),
                "ioc_types": _type_counts(no_family),
            })

    # ── 2. PATCH: KEV-confirmed CVEs ─────────────────────────────────
    kev_cves = [c for c in cves if c.get("kev_confirmed")]
    if kev_cves:
        ransomware_cves = [c for c in kev_cves if c.get("kev_ransomware")]
        non_ransom_cves = [c for c in kev_cves if not c.get("kev_ransomware")]

        if ransomware_cves:
            priority += 1
            cve_ids = [c.get("cve_id", "") for c in ransomware_cves]
            actions.append({
                "priority": priority,
                "action":   "patch",
                "urgency":  "critical",
                "title":    f"Patch {len(ransomware_cves)} ransomware-linked CVE{'s' if len(ransomware_cves) != 1 else ''}",
                "detail":   (
                    f"CISA KEV-confirmed and flagged for ransomware use: "
                    f"{', '.join(cve_ids)}. "
                    f"These vulnerabilities are actively exploited by this actor "
                    f"in ransomware campaigns."
                ),
                "cve_ids":  cve_ids,
            })

        if non_ransom_cves:
            priority += 1
            cve_ids = [c.get("cve_id", "") for c in non_ransom_cves]
            actions.append({
                "priority": priority,
                "action":   "patch",
                "urgency":  "high",
                "title":    f"Patch {len(non_ransom_cves)} KEV-confirmed CVE{'s' if len(non_ransom_cves) != 1 else ''}",
                "detail":   (
                    f"CISA Known Exploited Vulnerabilities confirmed for this actor: "
                    f"{', '.join(cve_ids[:5])}"
                    f"{'...' if len(cve_ids) > 5 else ''}."
                ),
                "cve_ids":  cve_ids,
            })

    # ── 3. DETECT: Critical detection gaps ───────────────────────────
    critical_gaps = coverage.get("critical_gaps", [])
    if critical_gaps:
        priority += 1
        gap_ids = [g["technique_id"] for g in critical_gaps]
        actions.append({
            "priority":  priority,
            "action":    "detect",
            "urgency":   "high",
            "title":     f"Close {len(critical_gaps)} high-confidence detection gap{'s' if len(critical_gaps) != 1 else ''}",
            "detail":    (
                f"{len(critical_gaps)} techniques confirmed by multiple sources "
                f"have no Sigma detection rules: "
                f"{', '.join(gap_ids[:6])}"
                f"{'...' if len(gap_ids) > 6 else ''}. "
                f"These are high-confidence TTPs with no automated detection."
            ),
            "technique_ids": gap_ids,
        })

    # Also flag medium-confidence gaps in early kill chain phases
    early_phase_gaps = [
        g for g in coverage.get("gaps", [])
        if g["confidence"] != "HIGH"
        and TACTIC_ORDER.get(g["tactic"].lower(), 99) <= 3  # up to Execution
    ]
    if early_phase_gaps:
        priority += 1
        gap_ids = [g["technique_id"] for g in early_phase_gaps]
        actions.append({
            "priority":  priority,
            "action":    "detect",
            "urgency":   "medium",
            "title":     f"Cover {len(early_phase_gaps)} early-stage detection gap{'s' if len(early_phase_gaps) != 1 else ''}",
            "detail":    (
                f"Techniques in Reconnaissance through Execution phases lack detection: "
                f"{', '.join(gap_ids[:6])}"
                f"{'...' if len(gap_ids) > 6 else ''}. "
                f"Early-stage visibility is critical for preventing initial compromise."
            ),
            "technique_ids": gap_ids,
        })

    # ── 4. HUNT: Malware with infrastructure but no detection ────────
    for mi in malware_intel:
        if mi["ioc_count"] > 0 and not mi["has_sigma"] and not mi["has_yara"]:
            priority += 1
            actions.append({
                "priority":      priority,
                "action":        "hunt",
                "urgency":       "medium",
                "title":         f"Hunt for {mi['name']} — {mi['ioc_count']} IOCs, no detection rules",
                "detail":        (
                    f"{mi['name']} ({mi['type']}) has {mi['ioc_count']} known IOCs "
                    f"({mi['iocs_fresh']} fresh, {mi['iocs_aging']} aging) "
                    f"but no Sigma or YARA rules in the profile. "
                    f"Manual threat hunting recommended."
                ),
                "malware_name":  mi["name"],
                "ioc_count":     mi["ioc_count"],
            })

    # ── 5. MONITOR: Aging IOCs worth watching ────────────────────────
    aging_iocs = [
        ioc for ioc in indicators
        if _ioc_age_days(ioc, now) is not None
        and FRESH_DAYS < _ioc_age_days(ioc, now) <= AGING_DAYS
    ]
    if aging_iocs and len(aging_iocs) >= 3:  # only worth mentioning if meaningful count
        priority += 1
        actions.append({
            "priority": priority,
            "action":   "monitor",
            "urgency":  "low",
            "title":    f"Monitor {len(aging_iocs)} aging IOCs for reactivation",
            "detail":   (
                f"{len(aging_iocs)} indicators are 31-90 days old: "
                f"{_type_summary(aging_iocs)}. "
                f"Aging infrastructure may be reactivated. Keep in watchlists "
                f"but don't over-prioritise for blocking."
            ),
            "ioc_count": len(aging_iocs),
            "ioc_types": _type_counts(aging_iocs),
        })

    return actions


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------

def _build_stats(
    techniques:    list[dict],
    malware:       list[dict],
    indicators:    list[dict],
    cves:          list[dict],
    campaigns:     list[dict],
    malware_intel: list[dict],
    coverage:      dict[str, Any],
) -> dict[str, Any]:
    """Build summary statistics for the correlated profile."""
    now = datetime.now(timezone.utc)

    fresh = sum(1 for i in indicators if _ioc_age_days(i, now) is not None and _ioc_age_days(i, now) <= FRESH_DAYS)
    aging = sum(1 for i in indicators if _ioc_age_days(i, now) is not None and FRESH_DAYS < _ioc_age_days(i, now) <= AGING_DAYS)
    stale = len(indicators) - fresh - aging

    malware_with_iocs = sum(1 for m in malware_intel if m.get("ioc_count", 0) > 0)

    return {
        "techniques_total":         len(techniques),
        "techniques_with_sigma":    coverage.get("with_sigma", 0),
        "techniques_with_detection": coverage.get("with_any_detection", 0),
        "detection_coverage_pct":   coverage.get("coverage_pct", 0),
        "sigma_coverage_pct":       coverage.get("sigma_coverage_pct", 0),
        "detection_gap_count":      coverage.get("gap_count", 0),
        "critical_gap_count":       coverage.get("critical_gap_count", 0),
        "malware_total":            len(malware),
        "malware_with_iocs":        malware_with_iocs,
        "iocs_total":               len(indicators),
        "iocs_fresh":               fresh,
        "iocs_aging":               aging,
        "iocs_stale":               stale,
        "cves_total":               len(cves),
        "cves_kev_confirmed":       sum(1 for c in cves if c.get("kev_confirmed")),
        "cves_ransomware":          sum(1 for c in cves if c.get("kev_ransomware")),
        "campaigns_total":          len(campaigns),
        "priority_action_count":    0,  # filled by caller
        "kill_chain_phases":        0,  # filled by caller
    }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _ioc_age_days(ioc: dict, now: datetime) -> int | None:
    """Calculate the age of an IOC in days. Returns None if no date."""
    raw = (ioc.get("last_seen") or ioc.get("first_seen") or "").strip()
    if not raw:
        return None
    try:
        seen = datetime.strptime(raw[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return (now - seen).days
    except (ValueError, TypeError):
        return None


def _type_summary(iocs: list[dict]) -> str:
    """Produce a human-readable summary of IOC types, e.g. '5 domains, 3 IPs, 6 hashes'."""
    counts = _type_counts(iocs)
    parts = []
    # Display in a sensible order
    for label in ("domain", "ip", "url", "hash_sha256", "hash_md5", "hash_sha1", "email"):
        if label in counts:
            display = {
                "domain": "domains",
                "ip": "IPs",
                "url": "URLs",
                "hash_sha256": "SHA256 hashes",
                "hash_md5": "MD5 hashes",
                "hash_sha1": "SHA1 hashes",
                "email": "emails",
            }.get(label, label)
            parts.append(f"{counts[label]} {display}")
    # Catch any remaining types
    for label, count in sorted(counts.items()):
        if label not in ("domain", "ip", "url", "hash_sha256", "hash_md5", "hash_sha1", "email"):
            parts.append(f"{count} {label}")
    return ", ".join(parts) if parts else "0 indicators"


def _type_counts(iocs: list[dict]) -> dict[str, int]:
    """Count IOCs by type."""
    counts: dict[str, int] = defaultdict(int)
    for ioc in iocs:
        counts[ioc.get("type", "unknown")] += 1
    return dict(counts)
