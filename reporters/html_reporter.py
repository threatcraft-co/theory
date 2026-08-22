"""
reporters/html_reporter.py
---------------------------
Generates a single-file self-contained HTML dossier from a THEORY actor profile.

No server required — opens in any browser, works offline.
All CSS and JS are embedded inline. No external dependencies.

Design: Dark intelligence-grade aesthetic. Deep navy/charcoal, red/amber/green
confidence accents, monospace for technique IDs and IOCs. Collapsible sections,
sortable TTP table, fresh IOC highlighting. Shareable as a single file.

Now with correlator integration: renders profile["correlations"] as
priority actions, kill chain timeline, coverage meter, and cross-referenced
malware intel cards. Techniques and malware carry data attributes for
cross-section highlighting when clicked.

Usage:
  theory --actor APT28 --sources mitre,malpedia,otx --output html
  # writes: output/dossiers/apt28.html
"""

from __future__ import annotations

import json
import logging
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("output/dossiers")


class HtmlReporter:

    def build(self, profile: dict[str, Any]) -> str:
        """Build the full self-contained HTML string."""
        actor      = profile.get("actor_name", "Unknown Actor")
        gid        = profile.get("mitre_group_id", "")
        origin     = profile.get("origin", "—")
        first      = profile.get("first_seen", "—")
        motives    = ", ".join(profile.get("motivations", [])) or "—"
        aliases    = profile.get("aliases", [])
        sources    = ", ".join(profile.get("sources_cited", [])) or "—"
        overview   = profile.get("actor_overview", "")
        techniques = profile.get("techniques", [])
        malware    = profile.get("malware", [])
        indicators = profile.get("indicators", [])
        campaigns  = profile.get("campaigns", [])
        sectors    = profile.get("sectors", [])
        cves       = profile.get("cves", [])
        advisories = profile.get("advisories", [])
        vendor_intel = profile.get("vendor_intel", [])
        correlations = profile.get("correlations", {})
        det_repos  = _match_detection_repos(profile)
        generated  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Confidence counts
        high   = sum(1 for t in techniques if t.get("confidence","").upper() == "HIGH")
        medium = sum(1 for t in techniques if t.get("confidence","").upper() == "MEDIUM")
        low    = sum(1 for t in techniques if t.get("confidence","").upper() == "LOW")

        # Partition IOCs by freshness
        fresh_iocs, aging_iocs, stale_iocs = _partition_iocs_three(indicators)

        # Coverage stats (from correlator, or compute fallback)
        coverage = correlations.get("coverage", {})
        coverage_pct = coverage.get("coverage_pct", 0)
        critical_gap_count = coverage.get("critical_gap_count", 0)

        # Build IOC family lookup for malware cross-referencing
        malware_intel = correlations.get("malware_intel", [])
        malware_intel_by_name = {mi["name"].lower(): mi for mi in malware_intel}

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(actor)} — THEORY Intelligence Dossier</title>
{_css()}
</head>
<body>
<div class="header-bar">
  <div class="header-brand">THEORY</div>
  <div class="header-meta">
    <span class="header-meta-item">Generated: {generated}</span>
    <span class="header-meta-sep">·</span>
    <span class="header-meta-item">Sources: {_esc(sources)}</span>
  </div>
</div>

<div class="container">

  <!-- ── HERO ─────────────────────────────────────────────── -->
  <div class="hero">
    <div class="hero-left">
      <h1 class="actor-name">{_esc(actor)}</h1>
      {f'<span class="mitre-badge">MITRE {_esc(gid)}</span>' if gid else ''}
      <div class="actor-meta">
        <div class="meta-item"><span class="meta-label">Origin</span><span class="meta-value">{_esc(origin)}</span></div>
        <div class="meta-item"><span class="meta-label">First Seen</span><span class="meta-value">{_esc(str(first))}</span></div>
        <div class="meta-item"><span class="meta-label">Motivation</span><span class="meta-value">{_esc(motives)}</span></div>
      </div>
      {f'<div class="aliases-row"><span class="meta-label">Also Known As</span> <span class="aliases-list">{_esc(", ".join(aliases[:12]))}</span></div>' if aliases else ''}
    </div>
    <div class="hero-right">
      <div class="conf-summary">
        <div class="conf-item high"><span class="conf-num">{high}</span><span class="conf-label">HIGH</span></div>
        <div class="conf-item med"><span class="conf-num">{medium}</span><span class="conf-label">MED</span></div>
        <div class="conf-item low"><span class="conf-num">{low}</span><span class="conf-label">LOW</span></div>
        <div class="conf-item iocs"><span class="conf-num">{len(indicators)}</span><span class="conf-label">IOCs</span></div>
      </div>
      {_coverage_meter(coverage_pct, critical_gap_count, coverage) if coverage.get("total_techniques", 0) > 0 else ''}
    </div>
  </div>

  {_section_priority_actions(correlations.get("priority_actions", [])) if correlations.get("priority_actions") else ''}

  {_section_overview(overview) if overview else ''}

  {_section_kill_chain(correlations.get("kill_chain", [])) if correlations.get("kill_chain") else ''}

  {_section_ttps(techniques, correlations.get("technique_intel", []))}

  {_section_iocs(fresh_iocs, aging_iocs, stale_iocs) if indicators else ''}

  {_section_malware(malware, malware_intel_by_name) if malware else ''}

  {_section_campaigns(campaigns) if campaigns else ''}

  {_section_vendor_intel(vendor_intel) if vendor_intel else ''}

  {_section_detection_repos(det_repos) if det_repos else ''}

  {_section_sectors_cves(sectors, cves, advisories) if (sectors or cves or advisories) else ''}

  <div class="footer">
    <span>THEORY — Multi-Source Threat Actor Intelligence Framework</span>
    <span class="footer-sep">·</span>
    <a href="https://github.com/threatcraft-co/theory" class="footer-link">github.com/threatcraft-co/theory</a>
    <span class="footer-sep">·</span>
    <span>Generated {generated}</span>
  </div>

</div>
{_js()}
</body>
</html>"""
        return html

    def save(self, profile: dict[str, Any]) -> Path:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        slug = _canonical_slug(profile)
        path = OUTPUT_DIR / f"{slug}.html"
        path.write_text(self.build(profile), encoding="utf-8")
        logger.info("HTML dossier saved → %s", path)
        return path


# ---------------------------------------------------------------------------
# NEW: Coverage meter (hero-right addition)
# ---------------------------------------------------------------------------

def _coverage_meter(pct: int, critical_gaps: int, coverage: dict) -> str:
    """Compact detection coverage meter shown in the hero-right area."""
    if pct >= 70:
        color_cls = "cov-good"
    elif pct >= 40:
        color_cls = "cov-med"
    else:
        color_cls = "cov-poor"

    gap_label = ""
    if critical_gaps > 0:
        gap_label = f'<span class="cov-gap">{critical_gaps} critical gap{"s" if critical_gaps != 1 else ""}</span>'

    return f"""
    <div class="coverage-meter {color_cls}">
      <div class="cov-header">
        <span class="cov-title">DETECTION COVERAGE</span>
        <span class="cov-pct">{pct}%</span>
      </div>
      <div class="cov-bar">
        <div class="cov-fill" style="width:{pct}%"></div>
      </div>
      <div class="cov-detail">
        <span>{coverage.get("with_any_detection", 0)}/{coverage.get("total_techniques", 0)} techniques covered</span>
        {gap_label}
      </div>
    </div>"""


# ---------------------------------------------------------------------------
# NEW: Priority Actions panel
# ---------------------------------------------------------------------------

def _section_priority_actions(actions: list[dict]) -> str:
    """Top-of-dossier ranked action list — what to do right now."""
    if not actions:
        return ""

    # Action icon glyphs (simple unicode, keeps single-file promise)
    action_glyphs = {
        "block":   "◼",
        "patch":   "▲",
        "detect":  "◆",
        "hunt":    "●",
        "monitor": "○",
    }

    cards = ""
    for a in actions:
        action_type = a.get("action", "monitor")
        urgency     = a.get("urgency", "low")
        title       = a.get("title", "")
        detail      = a.get("detail", "")
        priority    = a.get("priority", 0)
        glyph       = action_glyphs.get(action_type, "○")

        # Extract any linked IDs for cross-referencing
        malware_family = a.get("malware_family", "")
        cve_ids        = a.get("cve_ids", [])
        tech_ids       = a.get("technique_ids", [])

        # Build meta pill row
        meta_pills = []
        if a.get("ioc_count"):
            meta_pills.append(f'<span class="pa-pill">{a["ioc_count"]} IOCs</span>')
        if malware_family:
            meta_pills.append(f'<span class="pa-pill pa-pill-link" data-malware="{_esc(malware_family.lower())}">{_esc(malware_family)}</span>')
        for cid in cve_ids[:5]:
            meta_pills.append(f'<span class="pa-pill pa-pill-cve">{_esc(cid)}</span>')
        if len(cve_ids) > 5:
            meta_pills.append(f'<span class="pa-pill">+{len(cve_ids) - 5} more</span>')
        for tid in tech_ids[:5]:
            meta_pills.append(f'<span class="pa-pill pa-pill-link" data-technique="{_esc(tid)}">{_esc(tid)}</span>')
        if len(tech_ids) > 5:
            meta_pills.append(f'<span class="pa-pill">+{len(tech_ids) - 5} more</span>')
        meta_html = f'<div class="pa-meta">{"".join(meta_pills)}</div>' if meta_pills else ""

        cards += f"""<div class="pa-card pa-{urgency}" data-action="{action_type}">
  <div class="pa-index">{priority:02d}</div>
  <div class="pa-glyph">{glyph}</div>
  <div class="pa-body">
    <div class="pa-head">
      <span class="pa-action-label">{action_type.upper()}</span>
      <span class="pa-urgency">{urgency}</span>
    </div>
    <div class="pa-title">{_esc(title)}</div>
    <div class="pa-detail">{_esc(detail)}</div>
    {meta_html}
  </div>
</div>"""

    return f"""
  <div class="section priority-actions-section collapsible open" id="sec-actions">
    <div class="section-header pa-section-header" onclick="toggle('sec-actions')">
      <div class="pa-header-left">
        <h2 class="section-title">Priority Actions <span class="section-count">{len(actions)}</span></h2>
        <span class="pa-subhead">Ranked by urgency — start at the top</span>
      </div>
      <span class="section-toggle">▾</span>
    </div>
    <div class="section-body pa-body-wrap">
      <div class="pa-grid">{cards}</div>
    </div>
  </div>"""


# ---------------------------------------------------------------------------
# NEW: Kill Chain timeline
# ---------------------------------------------------------------------------

def _section_kill_chain(phases: list[dict]) -> str:
    """Horizontal kill-chain strip: all 14 tactics, populated ones highlighted."""
    if not phases:
        return ""

    # Full ordered set of tactics — we render all 14, dimming empty ones
    all_tactics = [
        ("Reconnaissance",       "Recon",       0),
        ("Resource Development", "Resource",    1),
        ("Initial Access",       "Initial",     2),
        ("Execution",            "Execution",   3),
        ("Persistence",          "Persistence", 4),
        ("Privilege Escalation", "PrivEsc",     5),
        ("Defense Evasion",      "DefEvasion",  6),
        ("Credential Access",    "CredAccess",  7),
        ("Discovery",            "Discovery",   8),
        ("Lateral Movement",     "Lateral",     9),
        ("Collection",           "Collection",  10),
        ("Command and Control",  "C2",          11),
        ("Exfiltration",         "Exfil",       12),
        ("Impact",               "Impact",      13),
    ]

    # Index active phases by tactic name
    active = {p["tactic"]: p for p in phases}

    nodes = ""
    for tactic, short, idx in all_tactics:
        phase = active.get(tactic)
        if phase:
            tcount = phase.get("technique_count", 0)
            sigma  = phase.get("sigma_rule_count", 0)
            gap    = phase.get("detection_gap", False)
            # Coverage class: red if gap, green if any sigma, amber if techniques but no detection
            if sigma > 0:
                node_cls = "kc-covered"
            elif gap:
                node_cls = "kc-gap"
            else:
                node_cls = "kc-active"
            sigma_badge = f'<span class="kc-sigma">σ{sigma}</span>' if sigma else ''
            tech_ids    = phase.get("technique_ids", [])
            data_attr   = f'data-technique-ids="{",".join(tech_ids)}"'
            nodes += f"""<div class="kc-node {node_cls}" {data_attr} title="{_esc(tactic)} — {tcount} technique{'s' if tcount != 1 else ''}, {sigma} Sigma rule{'s' if sigma != 1 else ''}">
  <div class="kc-num">{idx:02d}</div>
  <div class="kc-label">{_esc(short)}</div>
  <div class="kc-count">{tcount}</div>
  {sigma_badge}
</div>"""
        else:
            nodes += f"""<div class="kc-node kc-empty" title="{_esc(tactic)} — no observed techniques">
  <div class="kc-num">{idx:02d}</div>
  <div class="kc-label">{_esc(short)}</div>
  <div class="kc-count">–</div>
</div>"""

    return f"""
  <div class="section collapsible open" id="sec-killchain">
    <div class="section-header" onclick="toggle('sec-killchain')">
      <div class="pa-header-left">
        <h2 class="section-title">Kill Chain</h2>
        <span class="pa-subhead">MITRE ATT&amp;CK tactic sequence — hover for detail, click to filter TTPs</span>
      </div>
      <span class="section-toggle">▾</span>
    </div>
    <div class="section-body kc-body-wrap">
      <div class="kc-strip">{nodes}</div>
      <div class="kc-legend">
        <span class="kc-legend-item"><span class="kc-swatch kc-covered"></span>Detection coverage</span>
        <span class="kc-legend-item"><span class="kc-swatch kc-active"></span>Active, no detection string</span>
        <span class="kc-legend-item"><span class="kc-swatch kc-gap"></span>Gap — no detection at all</span>
        <span class="kc-legend-item"><span class="kc-swatch kc-empty"></span>Not observed</span>
      </div>
    </div>
  </div>"""


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _section_overview(overview: str) -> str:
    return f"""
  <div class="section collapsible open" id="sec-overview">
    <div class="section-header" onclick="toggle('sec-overview')">
      <h2 class="section-title">Intelligence Overview</h2>
      <span class="section-toggle">▾</span>
    </div>
    <div class="section-body">
      <div class="overview-text">{_esc(overview)}</div>
      <div class="overview-badge">LLM-synthesized from all sources</div>
    </div>
  </div>"""


def _section_ttps(techniques: list[dict], technique_intel: list[dict]) -> str:
    if not techniques:
        return ""

    # Build technique_intel lookup by TID
    ti_by_tid = {ti["technique_id"]: ti for ti in technique_intel}

    rows = ""
    for t in sorted(techniques, key=lambda x: x.get("technique_id", "")):
        tid   = t.get("technique_id", "")
        tac   = t.get("tactic", "")
        name  = t.get("technique_name") or t.get("name", "")
        conf  = (t.get("confidence") or "low").upper()
        sigma = len(t.get("sigma_rules", []))
        att_url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"

        sigma_badge = f'<span class="sigma-badge" title="{sigma} Sigma rules">σ {sigma}</span>' if sigma else ''
        conf_cls    = {"HIGH": "conf-high", "MEDIUM": "conf-med", "LOW": "conf-low"}.get(conf, "conf-low")

        # Cross-reference indicators from correlator
        ti = ti_by_tid.get(tid, {})
        kev_badge = ""
        if ti.get("kev_cve_ids"):
            kev_badge = f'<span class="kev-badge" title="Linked to CISA KEV CVEs: {", ".join(ti["kev_cve_ids"])}">KEV</span>'

        rows += f"""<tr data-tactic="{_esc(tac)}" data-conf="{conf}" data-tid="{_esc(tid)}" class="ttp-row">
  <td><a href="{att_url}" target="_blank" class="tid-link">{_esc(tid)}</a></td>
  <td class="tactic-cell">{_esc(tac)}</td>
  <td>{_esc(name)}{sigma_badge}{kev_badge}</td>
  <td><span class="conf-badge {conf_cls}">{conf}</span></td>
</tr>"""

    # Tactic filter buttons
    tactics = sorted(set(t.get("tactic","") for t in techniques if t.get("tactic")))
    filter_btns = '<button class="filter-btn active" onclick="filterTactic(\'all\', this)">All</button>'
    for tac in tactics:
        filter_btns += f'<button class="filter-btn" onclick="filterTactic(\'{_esc(tac)}\', this)">{_esc(tac)}</button>'

    return f"""
  <div class="section collapsible open" id="sec-ttps">
    <div class="section-header" onclick="toggle('sec-ttps')">
      <h2 class="section-title">TTPs <span class="section-count">{len(techniques)}</span></h2>
      <span class="section-toggle">▾</span>
    </div>
    <div class="section-body">
      <div class="filter-bar">{filter_btns}</div>
      <div class="table-wrap">
        <table class="data-table" id="ttp-table">
          <thead>
            <tr>
              <th onclick="sortTable('ttp-table',0)" class="sortable">Technique ↕</th>
              <th onclick="sortTable('ttp-table',1)" class="sortable">Tactic ↕</th>
              <th>Name</th>
              <th onclick="sortTable('ttp-table',3)" class="sortable">Confidence ↕</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>
  </div>"""


def _section_iocs(fresh: list, aging: list, stale: list) -> str:
    def _ioc_rows(iocs: list, row_class: str) -> str:
        rows = ""
        for ioc in iocs[:100]:
            ioc_type = ioc.get("type", "")
            value    = _defang_html(ioc_type, ioc.get("value", ""))
            family   = ioc.get("malware_family", "")
            family_attr = f' data-family="{_esc(family.lower())}"' if family else ""
            seen     = ioc.get("last_seen") or ioc.get("first_seen") or ""
            conf     = ioc.get("confidence", "")
            conf_str = str(conf) if conf else ""
            rows += f'<tr class="{row_class} ioc-row"{family_attr}><td class="mono">{_esc(ioc_type)}</td><td class="mono ioc-value">{_esc(value)}</td><td>{_esc(family)}</td><td>{_esc(seen)}</td><td>{_esc(conf_str)}</td></tr>'
        return rows

    all_rows = _ioc_rows(fresh, "ioc-fresh") + _ioc_rows(aging, "ioc-aging") + _ioc_rows(stale, "ioc-stale")
    total = len(fresh) + len(aging) + len(stale)

    legend = f"""<div class="ioc-legend">
  <span class="legend-item fresh">🟢 FRESH ({len(fresh)} ≤30d)</span>
  <span class="legend-item aging">🟡 AGING ({len(aging)} 31–90d)</span>
  <span class="legend-item stale">🔴 STALE ({len(stale)} >90d)</span>
</div>"""

    return f"""
  <div class="section collapsible open" id="sec-iocs">
    <div class="section-header" onclick="toggle('sec-iocs')">
      <h2 class="section-title">Indicators of Compromise <span class="section-count">{total}</span></h2>
      <span class="section-toggle">▾</span>
    </div>
    <div class="section-body">
      {legend}
      <div class="table-wrap">
        <table class="data-table" id="ioc-table">
          <thead><tr><th>Type</th><th>Value</th><th>Malware Family</th><th>Last Seen</th><th>Confidence</th></tr></thead>
          <tbody>{all_rows}</tbody>
        </table>
      </div>
      <p class="ioc-note">⚠ IOC values are defanged for safe display. Raw values available in CSV export.</p>
    </div>
  </div>"""


def _section_malware(malware: list, malware_intel_by_name: dict) -> str:
    """Malware cards enhanced with correlator IOC/CVE/detection intelligence."""
    cards = ""
    for m in malware:
        name  = m.get("name", "")
        mtype = m.get("type", "malware")
        desc  = m.get("description", "")
        yara  = m.get("yara_count", 0) or m.get("yara_rule_count", 0)

        # Correlator intel for this malware family
        mi = malware_intel_by_name.get(name.lower(), {})
        ioc_count      = mi.get("ioc_count", 0)
        iocs_fresh     = mi.get("iocs_fresh", 0)
        iocs_aging     = mi.get("iocs_aging", 0)
        iocs_stale     = mi.get("iocs_stale", 0)
        iocs_by_type   = mi.get("iocs_by_type", {})
        linked_cves    = mi.get("linked_cves", [])
        linked_kev     = mi.get("linked_cves_kev", [])
        has_sigma      = mi.get("has_sigma", False)

        # Badges row
        badges = []
        if yara:
            badges.append(f'<span class="mc-badge mc-badge-yara">{yara} YARA</span>')
        if has_sigma:
            badges.append('<span class="mc-badge mc-badge-sigma">Sigma</span>')
        if linked_kev:
            badges.append(f'<span class="mc-badge mc-badge-kev" title="KEV CVEs: {", ".join(linked_kev)}">KEV × {len(linked_kev)}</span>')
        badges_html = "".join(badges)

        # IOC intel row (only if we have IOCs)
        ioc_row = ""
        if ioc_count > 0:
            type_summary_parts = []
            type_labels = {"domain": "domains", "ip": "IPs", "url": "URLs",
                           "hash_sha256": "SHA256", "hash_md5": "MD5",
                           "hash_sha1": "SHA1", "email": "emails"}
            for tkey, tlabel in type_labels.items():
                if tkey in iocs_by_type:
                    type_summary_parts.append(f'{iocs_by_type[tkey]} {tlabel}')
            type_summary = ", ".join(type_summary_parts) if type_summary_parts else f"{ioc_count} indicators"

            freshness_parts = []
            if iocs_fresh:
                freshness_parts.append(f'<span class="mc-fresh">{iocs_fresh} fresh</span>')
            if iocs_aging:
                freshness_parts.append(f'<span class="mc-aging">{iocs_aging} aging</span>')
            if iocs_stale:
                freshness_parts.append(f'<span class="mc-stale">{iocs_stale} stale</span>')
            freshness_html = " · ".join(freshness_parts)

            ioc_row = f"""<div class="mc-intel-row">
  <span class="mc-intel-label">IOCs</span>
  <span class="mc-intel-value">{ioc_count} — {_esc(type_summary)}</span>
  <span class="mc-intel-freshness">{freshness_html}</span>
</div>"""

        # CVE intel row
        cve_row = ""
        if linked_cves:
            cve_pills = ""
            for cve_id in linked_cves[:8]:
                is_kev = cve_id in linked_kev
                cls = "mc-cve-pill mc-cve-kev" if is_kev else "mc-cve-pill"
                cve_pills += f'<span class="{cls}">{_esc(cve_id)}</span>'
            if len(linked_cves) > 8:
                cve_pills += f'<span class="mc-cve-pill mc-cve-more">+{len(linked_cves) - 8}</span>'
            cve_row = f"""<div class="mc-intel-row mc-intel-cves">
  <span class="mc-intel-label">CVEs</span>
  <div class="mc-cve-pills">{cve_pills}</div>
</div>"""

        desc_html = f'<p class="mc-desc">{_esc(desc[:220])}{"…" if len(desc) > 220 else ""}</p>' if desc else ""

        # Malware card gets data attribute so IOCs can be highlighted when clicked
        cards += f"""<div class="mc-card" data-malware="{_esc(name.lower())}" onclick="highlightMalware('{_esc(name.lower())}', this)">
  <div class="mc-head">
    <span class="mc-name">{_esc(name)}</span>
    <span class="mc-type">{_esc(mtype)}</span>
    <div class="mc-badges">{badges_html}</div>
  </div>
  {desc_html}
  {ioc_row}
  {cve_row}
</div>"""

    return f"""
  <div class="section collapsible open" id="sec-malware">
    <div class="section-header" onclick="toggle('sec-malware')">
      <h2 class="section-title">Malware &amp; Tools <span class="section-count">{len(malware)}</span></h2>
      <span class="section-toggle">▾</span>
    </div>
    <div class="section-body">
      <p class="section-desc">Click a card to highlight its IOCs in the section above.</p>
      <div class="mc-grid">{cards}</div>
    </div>
  </div>"""


def _section_campaigns(campaigns: list) -> str:
    items = ""
    for c in campaigns:
        name  = c.get("name", "")
        desc  = c.get("description", "")
        fs    = c.get("first_seen", "")
        ls    = c.get("last_seen", "")
        url   = c.get("url", "")
        period = f'<span class="campaign-period">{_esc(str(fs)[:10])} – {_esc(str(ls)[:10])}</span>' if fs or ls else ""
        link   = f'<a href="{_esc(url)}" target="_blank" class="campaign-link">ATT&amp;CK ↗</a>' if url else ""
        desc_html = f'<p class="campaign-desc">{_esc(desc)}</p>' if desc else ""
        items += f"""<div class="campaign-card">
  <div class="campaign-header">
    <span class="campaign-name">{_esc(name)}</span>
    {period}{link}
  </div>
  {desc_html}
</div>"""

    return f"""
  <div class="section collapsible" id="sec-campaigns">
    <div class="section-header" onclick="toggle('sec-campaigns')">
      <h2 class="section-title">Campaigns <span class="section-count">{len(campaigns)}</span></h2>
      <span class="section-toggle">▸</span>
    </div>
    <div class="section-body">{items}</div>
  </div>"""


def _section_vendor_intel(vendor_intel: list) -> str:
    items = ""
    for item in vendor_intel:
        source    = item.get("source", "")
        date      = item.get("date", "")
        title     = item.get("title", "")
        url       = item.get("url", "")
        relevance = item.get("relevance", 0)
        actor_sum = item.get("actor_summary", "")
        land_sum  = item.get("landscape_summary", "")
        rel_cls   = "rel-high" if relevance >= 70 else "rel-med" if relevance >= 40 else "rel-low"
        rel_label = "HIGH" if relevance >= 70 else "MED" if relevance >= 40 else "LOW"
        title_html = f'<a href="{_esc(url)}" target="_blank" class="intel-title">{_esc(title)}</a>' if url else f'<span class="intel-title">{_esc(title)}</span>'
        actor_html = f'<p class="intel-summary">{_esc(actor_sum)}</p>' if actor_sum else ""
        land_html  = f'<p class="intel-context"><em>Context: {_esc(land_sum)}</em></p>' if land_sum else ""
        items += f"""<div class="intel-card">
  <div class="intel-header">
    <span class="intel-source">{_esc(source)}</span>
    <span class="intel-date">{_esc(date)}</span>
    <span class="rel-badge {rel_cls}">{rel_label}</span>
  </div>
  {title_html}
  {actor_html}
  {land_html}
</div>"""

    return f"""
  <div class="section collapsible" id="sec-vendor">
    <div class="section-header" onclick="toggle('sec-vendor')">
      <h2 class="section-title">Recent Intelligence <span class="section-count">{len(vendor_intel)}</span></h2>
      <span class="section-toggle">▸</span>
    </div>
    <div class="section-body">{items}</div>
  </div>"""


def _section_detection_repos(repos: list) -> str:
    items = ""
    for repo in repos:
        tier  = "Official" if repo.get("tier") == 1 else "Community"
        tier_cls = "tier-official" if repo.get("tier") == 1 else "tier-community"
        items += f"""<div class="repo-card">
  <div class="repo-header">
    <a href="{_esc(repo['url'])}" target="_blank" class="repo-name">{_esc(repo['name'])}</a>
    <span class="repo-tier {tier_cls}">{tier}</span>
  </div>
  <div class="repo-platform">{_esc(repo.get('platform','').title())}</div>
</div>"""

    return f"""
  <div class="section collapsible" id="sec-detrepos">
    <div class="section-header" onclick="toggle('sec-detrepos')">
      <h2 class="section-title">Detection Resources <span class="section-count">{len(repos)}</span></h2>
      <span class="section-toggle">▸</span>
    </div>
    <div class="section-body">
      <p class="section-desc">Curated detection repositories matched to this actor's techniques and targeted platforms.</p>
      <div class="repo-grid">{items}</div>
    </div>
  </div>"""


def _advisory_item_html(a: dict) -> str:
    """
    Render one CISA advisory as an HTML fragment. Extracted from an f-string
    generator that used backslash escapes inside brace expressions — that
    syntax is Python 3.12+ only and breaks the linter on 3.11.
    """
    date  = _esc(a.get("date", ""))
    title = _esc(a.get("title", ""))
    url   = a.get("url", "")
    if url:
        link_open  = f'<a href="{_esc(url)}" target="_blank">'
        link_close = "</a>"
    else:
        link_open  = "<span>"
        link_close = "</span>"
    return (
        f'<div class="advisory-item">'
        f'<span class="advisory-date">{date}</span>'
        f'{link_open}{title}{link_close}'
        f'</div>'
    )


def _section_sectors_cves(sectors: list, cves: list, advisories: list) -> str:
    sector_html = ""
    if sectors:
        tags = "".join(f'<span class="sector-tag">{_esc(s)}</span>' for s in sectors)
        sector_html = f'<div class="sectors-row">{tags}</div>'

    cve_html = ""
    if cves:
        rows = "".join(
            f'<tr><td class="mono">{_esc(c.get("cve_id",""))}</td>'
            f'<td>{_esc(c.get("product",""))}</td>'
            f'<td>{_esc(c.get("vendor",""))}</td>'
            f'<td>{_esc(c.get("date_added",""))}</td></tr>'
            for c in cves
        )
        cve_html = f"""<h3 class="subsection-title">Known Exploited CVEs (CISA KEV)</h3>
<div class="table-wrap"><table class="data-table">
<thead><tr><th>CVE ID</th><th>Product</th><th>Vendor</th><th>Date Added</th></tr></thead>
<tbody>{rows}</tbody></table></div>"""

    adv_html = ""
    if advisories:
        items = "".join(_advisory_item_html(a) for a in advisories)
        adv_html = f'<h3 class="subsection-title">CISA Advisories</h3><div class="advisories-list">{items}</div>'

    return f"""
  <div class="section collapsible" id="sec-context">
    <div class="section-header" onclick="toggle('sec-context')">
      <h2 class="section-title">Targeting &amp; Advisories</h2>
      <span class="section-toggle">▸</span>
    </div>
    <div class="section-body">{sector_html}{cve_html}{adv_html}</div>
  </div>"""


# ---------------------------------------------------------------------------
# Embedded CSS
# ---------------------------------------------------------------------------

def _css() -> str:
    return """<style>
:root {
  --bg:        #0d1117;
  --bg2:       #161b22;
  --bg3:       #1c2333;
  --border:    #30363d;
  --text:      #e6edf3;
  --text2:     #8b949e;
  --accent:    #58a6ff;
  --high:      #f85149;
  --med:       #e3b341;
  --low:       #3fb950;
  --fresh:     #3fb950;
  --aging:     #e3b341;
  --stale:     #6e7681;
  /* Priority action urgency colors */
  --u-critical: #f85149;
  --u-high:     #ff9a3c;
  --u-medium:   #e3b341;
  --u-low:      #58a6ff;
  --mono:      'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  --sans:      'IBM Plex Sans', 'Inter', system-ui, sans-serif;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--sans);
  font-size: 14px; line-height: 1.6; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Header bar */
.header-bar { background: var(--bg2); border-bottom: 1px solid var(--border);
  padding: 10px 24px; display: flex; justify-content: space-between;
  align-items: center; position: sticky; top: 0; z-index: 100; }
.header-brand { font-family: var(--mono); font-size: 13px; font-weight: 700;
  letter-spacing: 0.15em; color: var(--accent); }
.header-meta { display: flex; gap: 12px; font-size: 12px; color: var(--text2); }
.header-meta-sep { color: var(--border); }

/* Container */
.container { max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }

/* Hero */
.hero { display: flex; justify-content: space-between; align-items: flex-start;
  padding: 32px 0 24px; border-bottom: 1px solid var(--border); margin-bottom: 32px; gap: 24px; }
.hero-right { display: flex; flex-direction: column; gap: 16px; align-items: flex-end; }
.actor-name { font-family: var(--mono); font-size: 2.4rem; font-weight: 700;
  letter-spacing: -0.02em; color: var(--text); margin-bottom: 10px; }
.mitre-badge { display: inline-block; font-family: var(--mono); font-size: 11px;
  background: var(--bg3); border: 1px solid var(--border); color: var(--text2);
  padding: 2px 10px; border-radius: 4px; margin-bottom: 16px; }
.actor-meta { display: flex; gap: 24px; flex-wrap: wrap; margin-bottom: 12px; }
.meta-item { display: flex; flex-direction: column; gap: 2px; }
.meta-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text2); }
.meta-value { font-size: 13px; color: var(--text); }
.aliases-row { font-size: 12px; color: var(--text2); margin-top: 8px; }
.aliases-list { color: var(--text); }

/* Confidence summary */
.conf-summary { display: flex; gap: 16px; }
.conf-item { display: flex; flex-direction: column; align-items: center;
  background: var(--bg2); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px 20px; min-width: 70px; }
.conf-num { font-family: var(--mono); font-size: 1.8rem; font-weight: 700; line-height: 1; }
.conf-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em;
  color: var(--text2); margin-top: 4px; }
.conf-item.high .conf-num { color: var(--high); }
.conf-item.med .conf-num  { color: var(--med); }
.conf-item.low .conf-num  { color: var(--low); }
.conf-item.iocs .conf-num { color: var(--accent); }

/* Coverage meter (hero) */
.coverage-meter { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 8px; padding: 12px 16px; min-width: 320px; }
.cov-header { display: flex; justify-content: space-between; align-items: baseline;
  margin-bottom: 8px; }
.cov-title { font-size: 10px; letter-spacing: 0.12em; color: var(--text2);
  font-family: var(--mono); }
.cov-pct { font-family: var(--mono); font-size: 1.4rem; font-weight: 700; }
.cov-bar { background: var(--bg3); height: 6px; border-radius: 3px;
  overflow: hidden; margin-bottom: 8px; }
.cov-fill { height: 100%; border-radius: 3px; transition: width 0.4s ease; }
.coverage-meter.cov-good  .cov-pct { color: var(--low); }
.coverage-meter.cov-good  .cov-fill { background: var(--low); }
.coverage-meter.cov-med   .cov-pct { color: var(--med); }
.coverage-meter.cov-med   .cov-fill { background: var(--med); }
.coverage-meter.cov-poor  .cov-pct { color: var(--high); }
.coverage-meter.cov-poor  .cov-fill { background: var(--high); }
.cov-detail { display: flex; justify-content: space-between;
  font-size: 11px; color: var(--text2); font-family: var(--mono); }
.cov-gap { color: var(--high); font-weight: 600; }

/* Sections */
.section { margin-bottom: 24px; border: 1px solid var(--border);
  border-radius: 8px; overflow: hidden; }
.section-header { display: flex; justify-content: space-between; align-items: center;
  padding: 14px 20px; background: var(--bg2); cursor: pointer;
  user-select: none; transition: background 0.15s; }
.section-header:hover { background: var(--bg3); }
.section-title { font-size: 14px; font-weight: 600; letter-spacing: 0.02em; }
.section-count { display: inline-block; background: var(--bg3); color: var(--text2);
  font-size: 11px; font-family: var(--mono); padding: 1px 7px;
  border-radius: 10px; margin-left: 8px; border: 1px solid var(--border); }
.section-toggle { font-size: 16px; color: var(--text2); transition: transform 0.2s; }
.section-body { padding: 20px; background: var(--bg); display: none; }
.section.open .section-body { display: block; }
.section.open .section-toggle { transform: rotate(0deg); }
.section-desc { font-size: 13px; color: var(--text2); margin-bottom: 16px; }
.subsection-title { font-size: 13px; font-weight: 600; margin: 20px 0 12px;
  color: var(--text2); text-transform: uppercase; letter-spacing: 0.08em; }

/* ── PRIORITY ACTIONS ─────────────────────────────────────── */
.priority-actions-section { border-color: var(--u-critical);
  box-shadow: 0 0 0 1px rgba(248,81,73,0.08); }
.pa-section-header { background: linear-gradient(90deg,
  rgba(248,81,73,0.10) 0%, var(--bg2) 60%); }
.pa-header-left { display: flex; flex-direction: column; gap: 2px; }
.pa-subhead { font-size: 11px; color: var(--text2); letter-spacing: 0.02em; }
.pa-body-wrap { padding: 16px 20px 20px; }
.pa-grid { display: flex; flex-direction: column; gap: 8px; }
.pa-card { display: grid;
  grid-template-columns: 40px 32px 1fr;
  align-items: stretch; gap: 0;
  background: var(--bg2); border: 1px solid var(--border);
  border-left: 4px solid var(--u-low);
  border-radius: 6px; overflow: hidden;
  transition: border-color 0.15s, transform 0.1s; }
.pa-card:hover { transform: translateX(2px); }
.pa-card.pa-critical { border-left-color: var(--u-critical); }
.pa-card.pa-high     { border-left-color: var(--u-high); }
.pa-card.pa-medium   { border-left-color: var(--u-medium); }
.pa-card.pa-low      { border-left-color: var(--u-low); }
.pa-index { font-family: var(--mono); font-size: 11px; color: var(--text2);
  padding: 14px 0 0 12px; letter-spacing: 0.05em; }
.pa-glyph { font-size: 16px; padding: 14px 0 0 4px;
  color: var(--text2); text-align: center; }
.pa-card.pa-critical .pa-glyph { color: var(--u-critical); }
.pa-card.pa-high     .pa-glyph { color: var(--u-high); }
.pa-card.pa-medium   .pa-glyph { color: var(--u-medium); }
.pa-card.pa-low      .pa-glyph { color: var(--u-low); }
.pa-body { padding: 12px 16px 14px 8px; }
.pa-head { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
.pa-action-label { font-family: var(--mono); font-size: 10px; font-weight: 700;
  letter-spacing: 0.14em; color: var(--text); }
.pa-urgency { font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em;
  color: var(--text2); font-family: var(--mono); }
.pa-card.pa-critical .pa-urgency { color: var(--u-critical); }
.pa-card.pa-high     .pa-urgency { color: var(--u-high); }
.pa-card.pa-medium   .pa-urgency { color: var(--u-medium); }
.pa-card.pa-low      .pa-urgency { color: var(--u-low); }
.pa-title { font-size: 14px; font-weight: 600; color: var(--text); margin-bottom: 4px; }
.pa-detail { font-size: 13px; color: var(--text2); line-height: 1.6; }
.pa-meta { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 10px; }
.pa-pill { font-family: var(--mono); font-size: 10px; padding: 2px 8px;
  border-radius: 3px; background: var(--bg3); color: var(--text2);
  border: 1px solid var(--border); }
.pa-pill-cve { color: var(--high); border-color: rgba(248,81,73,0.3); }
.pa-pill-link { cursor: pointer; transition: all 0.15s; }
.pa-pill-link:hover { color: var(--accent); border-color: var(--accent); }

/* ── KILL CHAIN ───────────────────────────────────────────── */
.kc-body-wrap { padding: 20px 20px 16px; }
.kc-strip { display: grid; grid-template-columns: repeat(14, minmax(0, 1fr));
  gap: 3px; margin-bottom: 14px; }
.kc-node { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 4px; padding: 8px 4px; text-align: center;
  cursor: pointer; transition: transform 0.1s, border-color 0.15s;
  position: relative; overflow: hidden; }
.kc-node:hover { transform: translateY(-2px); border-color: var(--text2); }
.kc-node::after { content: ""; position: absolute; top: 0; left: 0; right: 0;
  height: 2px; background: transparent; }
.kc-node.kc-covered::after { background: var(--low); }
.kc-node.kc-active::after  { background: var(--med); }
.kc-node.kc-gap::after     { background: var(--high); }
.kc-node.kc-empty          { opacity: 0.35; cursor: default; }
.kc-node.kc-empty:hover    { transform: none; }
.kc-num { font-family: var(--mono); font-size: 9px; color: var(--text2);
  margin-bottom: 2px; }
.kc-label { font-size: 10px; font-weight: 600; color: var(--text);
  line-height: 1.2; margin-bottom: 4px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.kc-count { font-family: var(--mono); font-size: 14px; font-weight: 700;
  color: var(--text); }
.kc-node.kc-empty .kc-count { color: var(--text2); font-weight: 400; }
.kc-sigma { display: inline-block; font-family: var(--mono); font-size: 9px;
  color: var(--low); margin-top: 2px; }
.kc-legend { display: flex; gap: 16px; flex-wrap: wrap; font-size: 11px;
  color: var(--text2); }
.kc-legend-item { display: inline-flex; align-items: center; gap: 6px; }
.kc-swatch { width: 12px; height: 3px; border-radius: 1px; display: inline-block; }
.kc-swatch.kc-covered { background: var(--low); }
.kc-swatch.kc-active  { background: var(--med); }
.kc-swatch.kc-gap     { background: var(--high); }
.kc-swatch.kc-empty   { background: var(--bg3); border: 1px solid var(--border); }

/* Overview */
.overview-text { font-size: 14px; line-height: 1.8; color: var(--text);
  max-width: 80ch; margin-bottom: 12px; }
.overview-badge { display: inline-block; font-size: 11px; color: var(--text2);
  border: 1px solid var(--border); padding: 2px 10px; border-radius: 4px;
  font-family: var(--mono); }

/* Filter bar */
.filter-bar { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 16px; }
.filter-btn { background: var(--bg2); border: 1px solid var(--border);
  color: var(--text2); padding: 4px 12px; border-radius: 4px; cursor: pointer;
  font-size: 12px; transition: all 0.15s; font-family: var(--sans); }
.filter-btn:hover { border-color: var(--accent); color: var(--text); }
.filter-btn.active { background: var(--accent); color: #000; border-color: var(--accent); font-weight: 600; }

/* Tables */
.table-wrap { overflow-x: auto; }
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.data-table th { background: var(--bg2); color: var(--text2); font-size: 11px;
  text-transform: uppercase; letter-spacing: 0.08em; padding: 8px 12px;
  text-align: left; border-bottom: 1px solid var(--border); white-space: nowrap; }
.data-table td { padding: 8px 12px; border-bottom: 1px solid var(--border);
  vertical-align: middle; }
.data-table tr:last-child td { border-bottom: none; }
.data-table tr:hover td { background: var(--bg2); }
.sortable { cursor: pointer; }
.sortable:hover { color: var(--text); }
.tid-link { font-family: var(--mono); font-size: 12px; color: var(--accent); }
.tactic-cell { color: var(--text2); font-size: 12px; }
.mono { font-family: var(--mono); font-size: 12px; }
.ioc-value { word-break: break-all; max-width: 320px; }

/* Cross-highlight state */
.ioc-row.mc-highlighted td { background: rgba(88,166,255,0.08); }
.ioc-row.mc-highlighted td:first-child { border-left-color: var(--accent) !important; border-left-width: 3px; }
.ttp-row.tid-highlighted td { background: rgba(88,166,255,0.08); }
.mc-card.mc-active { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }

/* Confidence badges */
.conf-badge { font-family: var(--mono); font-size: 10px; font-weight: 700;
  padding: 2px 8px; border-radius: 3px; letter-spacing: 0.05em; }
.conf-high { background: rgba(248,81,73,0.15); color: var(--high); border: 1px solid rgba(248,81,73,0.3); }
.conf-med  { background: rgba(227,179,65,0.15); color: var(--med);  border: 1px solid rgba(227,179,65,0.3); }
.conf-low  { background: rgba(63,185,80,0.15);  color: var(--low);  border: 1px solid rgba(63,185,80,0.3); }

/* Sigma / KEV badges (inline on TTP name) */
.sigma-badge { font-family: var(--mono); font-size: 10px; color: var(--accent);
  background: rgba(88,166,255,0.1); border: 1px solid rgba(88,166,255,0.2);
  padding: 1px 6px; border-radius: 3px; margin-left: 6px; }
.kev-badge { font-family: var(--mono); font-size: 10px; color: var(--high);
  background: rgba(248,81,73,0.12); border: 1px solid rgba(248,81,73,0.28);
  padding: 1px 6px; border-radius: 3px; margin-left: 6px; font-weight: 700;
  letter-spacing: 0.05em; }

/* IOC rows */
.ioc-fresh td:first-child { border-left: 3px solid var(--fresh); }
.ioc-aging td:first-child { border-left: 3px solid var(--aging); }
.ioc-stale td:first-child { border-left: 3px solid var(--stale); }
.ioc-legend { display: flex; gap: 20px; margin-bottom: 16px; font-size: 12px; }
.ioc-note { font-size: 11px; color: var(--text2); margin-top: 12px;
  padding: 8px 12px; background: var(--bg2); border-radius: 4px;
  border-left: 3px solid var(--med); }

/* ── MALWARE INTEL CARDS ─────────────────────────────────── */
.mc-grid { display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 12px; }
.mc-card { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 6px; padding: 14px; cursor: pointer;
  transition: border-color 0.15s, transform 0.1s; }
.mc-card:hover { border-color: var(--text2); transform: translateY(-1px); }
.mc-head { display: flex; align-items: center; gap: 10px;
  flex-wrap: wrap; margin-bottom: 8px; }
.mc-name { font-family: var(--mono); font-size: 13px; font-weight: 700; color: var(--text); }
.mc-type { font-size: 11px; color: var(--text2); background: var(--bg3);
  padding: 1px 8px; border-radius: 3px; border: 1px solid var(--border); }
.mc-badges { display: flex; gap: 6px; margin-left: auto; }
.mc-badge { font-family: var(--mono); font-size: 10px; padding: 1px 7px;
  border-radius: 3px; font-weight: 700; letter-spacing: 0.05em; }
.mc-badge-yara  { color: var(--med); background: rgba(227,179,65,0.1);
  border: 1px solid rgba(227,179,65,0.25); }
.mc-badge-sigma { color: var(--accent); background: rgba(88,166,255,0.1);
  border: 1px solid rgba(88,166,255,0.25); }
.mc-badge-kev   { color: var(--high); background: rgba(248,81,73,0.12);
  border: 1px solid rgba(248,81,73,0.28); }
.mc-desc { font-size: 12px; color: var(--text2); line-height: 1.6; margin-bottom: 10px; }
.mc-intel-row { display: flex; align-items: baseline; gap: 10px;
  padding: 8px 0; border-top: 1px solid var(--border);
  font-size: 12px; flex-wrap: wrap; }
.mc-intel-cves { align-items: flex-start; }
.mc-intel-label { font-family: var(--mono); font-size: 10px; letter-spacing: 0.1em;
  color: var(--text2); min-width: 44px; }
.mc-intel-value { color: var(--text); flex: 1; min-width: 0; }
.mc-intel-freshness { font-size: 11px; font-family: var(--mono); }
.mc-fresh { color: var(--fresh); }
.mc-aging { color: var(--aging); }
.mc-stale { color: var(--stale); }
.mc-cve-pills { display: flex; gap: 4px; flex-wrap: wrap; flex: 1; }
.mc-cve-pill { font-family: var(--mono); font-size: 10px; padding: 1px 6px;
  border-radius: 3px; background: var(--bg3); color: var(--text2);
  border: 1px solid var(--border); }
.mc-cve-pill.mc-cve-kev { color: var(--high); border-color: rgba(248,81,73,0.3);
  background: rgba(248,81,73,0.06); }
.mc-cve-pill.mc-cve-more { color: var(--text2); }

/* Campaign cards */
.campaign-card { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 6px; padding: 14px; margin-bottom: 12px; }
.campaign-header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }
.campaign-name { font-size: 14px; font-weight: 600; color: var(--text); }
.campaign-period { font-size: 12px; color: var(--text2); font-family: var(--mono); }
.campaign-link { font-size: 11px; color: var(--accent); margin-left: auto; }
.campaign-desc { font-size: 13px; color: var(--text2); line-height: 1.7; }

/* Vendor intel */
.intel-card { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 6px; padding: 14px; margin-bottom: 12px; }
.intel-header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.intel-source { font-weight: 600; font-size: 13px; }
.intel-date { font-size: 12px; color: var(--text2); }
.intel-title { font-size: 13px; color: var(--accent); display: block; margin-bottom: 8px; }
.intel-summary { font-size: 13px; color: var(--text); line-height: 1.7; margin-bottom: 6px; }
.intel-context { font-size: 12px; color: var(--text2); }
.rel-badge { font-size: 10px; font-family: var(--mono); font-weight: 700;
  padding: 2px 7px; border-radius: 3px; margin-left: auto; }
.rel-high { background: rgba(248,81,73,0.15); color: var(--high); }
.rel-med  { background: rgba(227,179,65,0.15); color: var(--med); }
.rel-low  { background: rgba(63,185,80,0.15);  color: var(--low); }

/* Detection repos */
.repo-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px,1fr)); gap: 10px; }
.repo-card { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 6px; padding: 12px; }
.repo-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px; }
.repo-name { font-size: 13px; font-weight: 600; color: var(--accent); }
.repo-tier { font-size: 10px; padding: 1px 7px; border-radius: 3px; font-family: var(--mono); }
.tier-official  { background: rgba(63,185,80,0.1); color: var(--low); border: 1px solid rgba(63,185,80,0.2); }
.tier-community { background: rgba(139,148,158,0.1); color: var(--text2); border: 1px solid var(--border); }
.repo-platform { font-size: 11px; color: var(--text2); }

/* Sectors */
.sectors-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }
.sector-tag { background: var(--bg2); border: 1px solid var(--border);
  color: var(--text2); font-size: 12px; padding: 3px 12px; border-radius: 20px; }

/* Advisories */
.advisories-list { display: flex; flex-direction: column; gap: 8px; }
.advisory-item { font-size: 13px; display: flex; gap: 12px; }
.advisory-date { font-family: var(--mono); font-size: 12px; color: var(--text2); white-space: nowrap; }

/* Footer */
.footer { margin-top: 48px; padding: 20px 0; border-top: 1px solid var(--border);
  font-size: 12px; color: var(--text2); display: flex; gap: 12px;
  align-items: center; flex-wrap: wrap; }
.footer-sep { color: var(--border); }
.footer-link { color: var(--text2); }
.footer-link:hover { color: var(--accent); }

@media (max-width: 900px) {
  .kc-strip { grid-template-columns: repeat(7, minmax(0, 1fr)); }
  .kc-label { font-size: 9px; }
}
@media (max-width: 768px) {
  .hero { flex-direction: column; }
  .hero-right { align-items: flex-start; width: 100%; }
  .coverage-meter { min-width: 0; width: 100%; }
  .conf-summary { flex-wrap: wrap; }
  .actor-name { font-size: 1.8rem; }
  .pa-card { grid-template-columns: 32px 28px 1fr; }
  .pa-index { padding-left: 8px; font-size: 10px; }
}
@media (max-width: 560px) {
  .kc-strip { grid-template-columns: repeat(4, minmax(0, 1fr)); }
}

@media (prefers-reduced-motion: reduce) {
  * { animation: none !important; transition: none !important; }
}
</style>"""


# ---------------------------------------------------------------------------
# Embedded JavaScript
# ---------------------------------------------------------------------------

def _js() -> str:
    return """<script>
function toggle(id) {
  const el = document.getElementById(id);
  el.classList.toggle('open');
  const arrow = el.querySelector('.section-toggle');
  arrow.textContent = el.classList.contains('open') ? '▾' : '▸';
}

function filterTactic(tactic, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#ttp-table tbody tr').forEach(row => {
    row.style.display = (tactic === 'all' || row.dataset.tactic === tactic) ? '' : 'none';
  });
}

function sortTable(tableId, col) {
  const table = document.getElementById(tableId);
  const tbody = table.querySelector('tbody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  const dir   = table.dataset.sortCol == col && table.dataset.sortDir == 'asc' ? 'desc' : 'asc';
  table.dataset.sortCol = col;
  table.dataset.sortDir = dir;
  rows.sort((a, b) => {
    const av = (a.cells[col]?.textContent || '').trim();
    const bv = (b.cells[col]?.textContent || '').trim();
    return dir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  rows.forEach(r => tbody.appendChild(r));
}

/* ── Cross-highlight: click a malware card, highlight matching IOCs ── */
let _activeMalware = null;
function highlightMalware(family, cardEl) {
  const isSame = _activeMalware === family;
  document.querySelectorAll('.mc-card.mc-active').forEach(c => c.classList.remove('mc-active'));
  document.querySelectorAll('.ioc-row.mc-highlighted').forEach(r => r.classList.remove('mc-highlighted'));
  if (isSame) { _activeMalware = null; return; }
  _activeMalware = family;
  cardEl.classList.add('mc-active');
  document.querySelectorAll('.ioc-row[data-family]').forEach(row => {
    const rf = row.dataset.family || '';
    if (rf === family || rf.includes(family) || family.includes(rf)) {
      row.classList.add('mc-highlighted');
    }
  });
  const iocSection = document.getElementById('sec-iocs');
  if (iocSection && !iocSection.classList.contains('open')) {
    toggle('sec-iocs');
  }
}

/* ── Kill chain node click → filter TTP table by that tactic's techniques ── */
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.kc-node:not(.kc-empty)').forEach(node => {
    node.addEventListener('click', function() {
      const ids = (node.dataset.techniqueIds || '').split(',').filter(Boolean);
      if (!ids.length) return;
      document.querySelectorAll('.ttp-row').forEach(row => {
        row.style.display = ids.includes(row.dataset.tid) ? '' : 'none';
        if (ids.includes(row.dataset.tid)) {
          row.classList.add('tid-highlighted');
          setTimeout(() => row.classList.remove('tid-highlighted'), 2000);
        }
      });
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      const ttpSection = document.getElementById('sec-ttps');
      if (ttpSection && !ttpSection.classList.contains('open')) toggle('sec-ttps');
      ttpSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  /* Priority-action pills that reference techniques or malware */
  document.querySelectorAll('.pa-pill-link').forEach(pill => {
    pill.addEventListener('click', function(e) {
      e.stopPropagation();
      const tid  = pill.dataset.technique;
      const mal  = pill.dataset.malware;
      if (tid) {
        const row = document.querySelector('.ttp-row[data-tid="' + tid + '"]');
        if (row) {
          const ttpSection = document.getElementById('sec-ttps');
          if (ttpSection && !ttpSection.classList.contains('open')) toggle('sec-ttps');
          row.classList.add('tid-highlighted');
          row.scrollIntoView({ behavior: 'smooth', block: 'center' });
          setTimeout(() => row.classList.remove('tid-highlighted'), 2600);
        }
      } else if (mal) {
        const card = document.querySelector('.mc-card[data-malware="' + mal + '"]');
        if (card) {
          const mSection = document.getElementById('sec-malware');
          if (mSection && !mSection.classList.contains('open')) toggle('sec-malware');
          highlightMalware(mal, card);
          card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }
    });
  });
});
</script>"""


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _esc(s: str) -> str:
    """HTML-escape a string."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _defang_html(ioc_type: str, value: str) -> str:
    """Defang IOC for safe HTML display."""
    if ioc_type not in {"url", "domain", "ip"} or not value:
        return value
    v = value.replace("https://", "hxxps://").replace("http://", "hxxp://")
    if "hxxp" in v or "://" in v:
        sep    = v.find("://")
        scheme = v[:sep + 3]
        rest   = v[sep + 3:]
        slash  = rest.find("/")
        host   = rest[:slash] if slash != -1 else rest
        path   = rest[slash:] if slash != -1 else ""
        v = scheme + host.replace(".", "[.]") + path
    else:
        v = v.replace(".", "[.]")
    return v


def _partition_iocs_three(
    indicators: list[dict],
) -> tuple[list[dict], list[dict], list[dict]]:
    """Split IOCs into FRESH, AGING, STALE buckets."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    fresh, aging, stale = [], [], []
    for ioc in indicators:
        raw = (ioc.get("last_seen") or ioc.get("first_seen") or "").strip()
        if not raw:
            stale.append(ioc)
            continue
        try:
            seen     = datetime.strptime(raw[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            age_days = (now - seen).days
            if age_days <= 30:
                fresh.append(ioc)
            elif age_days <= 90:
                aging.append(ioc)
            else:
                stale.append(ioc)
        except (ValueError, TypeError):
            stale.append(ioc)
    type_order = {"domain": 0, "ip": 1, "url": 2}
    key = lambda x: (type_order.get(x.get("type", ""), 9), x.get("value", ""))
    return sorted(fresh, key=key), sorted(aging, key=key), sorted(stale, key=key)


def _match_detection_repos(profile: dict, max_results: int = 6) -> list[dict]:
    """Load and match detection repos — same logic as dossier.py."""
    try:
        import yaml
        config_path = Path("config/detection_repos.yaml")
        if not config_path.exists():
            return []
        data  = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        repos = data.get("detection_repos", [])
    except Exception:
        return []

    profile_tags: set[str] = set()
    for s in (profile.get("sectors") or []):
        profile_tags.add(s.lower().replace(" ", "-"))
    for t in (profile.get("techniques") or []):
        tac = (t.get("tactic") or "").lower().replace(" ", "-")
        if tac:
            profile_tags.add(tac)
    for m in (profile.get("malware") or []):
        mtype = (m.get("type") or "").lower()
        if mtype:
            profile_tags.add(mtype)
    profile_tags.add("universal")

    scored: list[tuple[int, dict]] = []
    for repo in repos:
        overlap    = len(profile_tags & set(repo.get("tags", [])))
        tier_bonus = 2 if repo.get("tier") == 1 else 0
        score      = overlap + tier_bonus
        if score > 0:
            scored.append((score, repo))

    scored.sort(key=lambda x: -x[0])
    return [r for _, r in scored[:max_results]]


def _canonical_slug(profile: dict) -> str:
    actor = profile.get("actor_name", "unknown")
    try:
        from collectors.cisa_advisories import ALIAS_TABLE
        actor_lower = actor.lower()
        for canonical, aliases in ALIAS_TABLE.items():
            if canonical.lower() == actor_lower or actor_lower in aliases:
                return re.sub(r"[^a-z0-9]", "_", canonical.lower())
    except Exception:
        pass
    return re.sub(r"[^a-z0-9]", "_", actor.lower())
