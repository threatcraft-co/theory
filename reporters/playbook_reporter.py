"""
reporters/playbook_reporter.py
-------------------------------
Generates an Incident Response playbook from a THEORY actor profile.

The playbook is a structured, analyst-ready checklist that turns intelligence
into action — not a narrative, not a wall of data.

Sections:
  1. Header          — actor, confidence summary, sources
  2. Immediate IOC Blocks — FRESH/AGING indicators formatted for firewall/SIEM
  3. Detection Checklist — TTPs as [ ] checkboxes with Sigma links
  4. Hunt Hypotheses — LLM-generated plain-language hunt queries per high-conf TTP
  5. Malware Reference — known families, types, and hashes
  6. Containment Guidance — LLM-generated, sector-aware steps
  7. References — all source URLs cited in the profile

Output formats:
  Markdown (.md)   — renders in GitHub, Confluence, Notion, Linear, ServiceNow
  Jira (.txt)      — Jira wiki markup for direct paste into issue descriptions

Usage:
  theory --actor APT28 --sources mitre,sigma --output playbook
  theory --actor APT28 --sources mitre,sigma --output playbook --playbook-format jira
"""

from __future__ import annotations

import logging
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("output/dossiers")

# Freshness thresholds (days) — must match dossier.py
_FRESH_DAYS  = 30
_AGING_DAYS  = 90


class PlaybookReporter:

    def build(
        self,
        profile:         dict[str, Any],
        sector:          str = "",
        playbook_format: str = "markdown",
        llm_provider:    Any = None,
    ) -> str:
        """
        Build the full playbook string in the requested format.

        Args:
            profile:         Unified THEORY actor profile dict.
            sector:          Optional sector context for containment guidance.
            playbook_format: "markdown" or "jira"
            llm_provider:    Optional LLM provider for hunt/containment sections.

        Returns:
            The playbook as a string in the requested format.
        """
        actor_name   = profile.get("actor_name", "Unknown Actor")
        origin       = profile.get("origin", "unknown")
        motivations  = ", ".join(profile.get("motivations", [])) or "unknown"
        sources      = ", ".join(profile.get("sources_cited", []))
        mitre_id     = profile.get("mitre_group_id", "")
        generated    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        techniques   = profile.get("techniques", [])
        malware      = profile.get("malware", [])
        indicators   = profile.get("indicators", [])

        # Partition indicators by freshness
        fresh_iocs, aging_iocs = _partition_iocs(indicators)

        # Confidence summary
        high   = sum(1 for t in techniques if t.get("confidence","").upper() == "HIGH")
        medium = sum(1 for t in techniques if t.get("confidence","").upper() == "MEDIUM")
        low    = sum(1 for t in techniques if t.get("confidence","").upper() == "LOW")

        # LLM sections (optional — graceful if no provider)
        hunt_text        = ""
        containment_text = ""
        if llm_provider and llm_provider.available:
            hunt_text        = _generate_hunt_hypotheses(profile, llm_provider)
            containment_text = _generate_containment(profile, sector, llm_provider)

        # Build in requested format
        if playbook_format == "jira":
            return _render_jira(
                actor_name, mitre_id, origin, motivations, sources, generated,
                sector, techniques, malware, fresh_iocs, aging_iocs,
                high, medium, low, hunt_text, containment_text, profile,
            )
        else:
            return _render_markdown(
                actor_name, mitre_id, origin, motivations, sources, generated,
                sector, techniques, malware, fresh_iocs, aging_iocs,
                high, medium, low, hunt_text, containment_text, profile,
            )

    def save(
        self,
        profile:         dict[str, Any],
        sector:          str = "",
        playbook_format: str = "markdown",
        llm_provider:    Any = None,
    ) -> Path:
        """Build and save the playbook. Returns the saved path."""
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        slug = _canonical_slug(profile)
        ext  = "_jira.txt" if playbook_format == "jira" else "_playbook.md"
        path = OUTPUT_DIR / f"{slug}{ext}"

        content = self.build(profile, sector, playbook_format, llm_provider)
        path.write_text(content, encoding="utf-8")
        logger.info("Playbook saved → %s", path)
        return path

    def summary(self, profile: dict[str, Any], path: Path) -> None:
        """Print a compact terminal summary after saving."""
        try:
            from rich.console import Console
            from rich.panel   import Panel
            console = Console(stderr=True)
        except ImportError:
            print(f"[theory] Playbook saved → {path}")
            return

        actor      = profile.get("actor_name", "Unknown")
        techniques = profile.get("techniques", [])
        indicators = profile.get("indicators", [])
        fresh, aging = _partition_iocs(indicators)
        high   = sum(1 for t in techniques if t.get("confidence","").upper() == "HIGH")
        sigma  = sum(1 for t in techniques if t.get("sigma_rules"))

        lines = [
            f"[bold cyan]{actor}[/] IR Playbook generated",
            f"  [dim]Techniques:[/] {len(techniques)} total  "
            f"[red]{high} HIGH[/]  [dim]|[/]  "
            f"[green]{len(fresh)} FRESH IOCs[/]  [dim]|[/]  "
            f"[cyan]{sigma} Sigma rules[/]",
            f"  [dim]Saved →[/] {path}",
        ]
        console.print()
        for line in lines:
            console.print(line)
        console.print()


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def _render_markdown(
    actor_name, mitre_id, origin, motivations, sources, generated,
    sector, techniques, malware, fresh_iocs, aging_iocs,
    high, medium, low, hunt_text, containment_text, profile,
) -> str:
    L: list[str] = []
    a = L.append

    mitre_suffix = f" ({mitre_id})" if mitre_id else ""
    sector_line  = f"\n> **Sector context:** {sector}" if sector else ""

    a(f"# IR Playbook — {actor_name}{mitre_suffix}")
    a("")
    a(f"> **Generated:** {generated}  ")
    a(f"> **Origin:** {origin}  |  **Motivation:** {motivations}  |  **Sources:** {sources}")
    a(f"> **TTP Confidence:** {high} HIGH / {medium} MEDIUM / {low} LOW{sector_line}")
    a("")
    a("---")
    a("")

    # ── 1. Immediate IOC Blocks ──────────────────────────────────────────
    if fresh_iocs or aging_iocs:
        a("## 🚨 Immediate Actions — Block These Now")
        a("")
        a("> These indicators were seen recently and carry the highest operational risk.")
        a("> Add to your firewall deny list, SIEM blocklist, or EDR exclusion list immediately.")
        a("")

        if fresh_iocs:
            a("### 🟢 FRESH Indicators (seen within 30 days)")
            a("")
            _md_ioc_table(L, fresh_iocs)

        if aging_iocs:
            a("### 🟡 AGING Indicators (31–90 days)")
            a("")
            a("> Still operationally relevant — monitor and investigate on hit.")
            a("")
            _md_ioc_table(L, aging_iocs)

        a("---")
        a("")

    # ── 2. Detection Checklist ───────────────────────────────────────────
    a("## 🔍 Detection Checklist")
    a("")
    a("> Work through this list. Check off each technique as coverage is confirmed.")
    a("")

    # Group by tactic
    by_tactic: dict[str, list[dict]] = {}
    for t in sorted(techniques, key=lambda x: (x.get("tactic",""), x.get("technique_id",""))):
        tactic = t.get("tactic") or "Unknown"
        by_tactic.setdefault(tactic, []).append(t)

    for tactic, ttps in by_tactic.items():
        a(f"### {tactic}")
        a("")
        for t in ttps:
            tid   = t.get("technique_id", "")
            name  = t.get("technique_name") or t.get("name", "")
            conf  = t.get("confidence", "").upper()
            conf_badge = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "⚪"}.get(conf, "⚪")
            sigma_rules = t.get("sigma_rules", [])
            sigma_count = len(sigma_rules)

            # Technique checkbox line
            att_url = f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/"
            a(f"- [ ] {conf_badge} **[{tid}]({att_url}) — {name}**  `{conf}`")

            # Sigma rules inline
            if sigma_rules:
                top = sigma_rules[0]
                more = f" _(+{sigma_count-1} more)_" if sigma_count > 1 else ""
                a(f"  - Sigma: [{top.get('title','')}]({top.get('url','')})"
                  f"  `{top.get('level','').upper()}`  ·  {top.get('logsource','')} {more}")
            elif t.get("detection"):
                a(f"  - Detection: {textwrap.shorten(t['detection'], 100, placeholder='…')}")
            a("")

    a("---")
    a("")

    # ── 3. Hunt Hypotheses ───────────────────────────────────────────────
    if hunt_text:
        a("## 🎯 Threat Hunt Hypotheses")
        a("")
        a("> LLM-generated hunt starting points based on this actor's confirmed TTPs.")
        a("> These are hypotheses — validate against your environment before acting.")
        a("")
        a(hunt_text.strip())
        a("")
        a("---")
        a("")

    # ── 4. Malware Reference ─────────────────────────────────────────────
    if malware:
        a("## 🦠 Known Malware & Tools")
        a("")
        a("| Name | Type | Notes |")
        a("|---|---|---|")
        for m in malware:
            desc = textwrap.shorten(m.get("description", ""), 100, placeholder="…")
            a(f"| **{m.get('name','')}** | {m.get('type','')} | {desc} |")
        a("")
        a("---")
        a("")

    # ── 5. Containment Guidance ──────────────────────────────────────────
    if containment_text:
        a("## 🛡️ Containment & Response Guidance")
        a("")
        if sector:
            a(f"> _Sector context applied: {sector}_")
            a("")
        a(containment_text.strip())
        a("")
        a("---")
        a("")

    # ── 6. References ────────────────────────────────────────────────────
    a("## 📚 References")
    a("")
    for src in profile.get("_sources", []):
        citation = src.get("source_citation") or src.get("source_id", "")
        url      = src.get("source_url", "")
        if url:
            a(f"- [{citation}]({url})")
        elif citation:
            a(f"- {citation}")

    campaigns = profile.get("campaigns", [])
    for c in campaigns:
        if c.get("url"):
            a(f"- [{c.get('name','')}]({c['url']})")

    a("")
    a(f"_Generated by THEORY — github.com/threatcraft-co/theory_")

    return "\n".join(L)


def _defang_ioc(ioc_type: str, value: str) -> str:
    """Defang a URL/domain/IP for safe display. Inline copy of dossier._defang()."""
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


def _md_ioc_table(L: list[str], iocs: list[dict]) -> None:
    """Append a defanged IOC table to the line list."""
    L.append("| Type | Value | Malware Family | Last Seen |")
    L.append("|---|---|---|---|")
    for ioc in iocs[:50]:  # cap at 50 per freshness bucket
        ioc_type = ioc.get("type", "")
        value    = _defang_ioc(ioc_type, ioc.get("value", ""))
        family   = ioc.get("malware_family", "")
        seen     = ioc.get("last_seen") or ioc.get("first_seen") or ""
        L.append(f"| {ioc_type} | `{value}` | {family} | {seen} |")
    L.append("")


# ---------------------------------------------------------------------------
# Jira wiki markup renderer
# ---------------------------------------------------------------------------

def _render_jira(
    actor_name, mitre_id, origin, motivations, sources, generated,
    sector, techniques, malware, fresh_iocs, aging_iocs,
    high, medium, low, hunt_text, containment_text, profile,
) -> str:
    L: list[str] = []
    a = L.append

    mitre_suffix = f" ({mitre_id})" if mitre_id else ""
    a(f"h1. IR Playbook — {actor_name}{mitre_suffix}")
    a("")
    a(f"*Generated:* {generated}")
    a(f"*Origin:* {origin} | *Motivation:* {motivations} | *Sources:* {sources}")
    a(f"*TTP Confidence:* {high} HIGH / {medium} MEDIUM / {low} LOW")
    if sector:
        a(f"*Sector context:* {sector}")
    a("")
    a("----")
    a("")

    # IOC blocks
    if fresh_iocs or aging_iocs:
        a("h2. Immediate Actions — Block These Now")
        a("")
        if fresh_iocs:
            a("h3. FRESH Indicators (seen within 30 days)")
            a("")
            a("||Type||Value||Malware Family||Last Seen||")
            for ioc in fresh_iocs[:50]:
                val = _defang_ioc(ioc.get("type",""), ioc.get("value",""))
                a(f"|{ioc.get('type','')}|{val}|{ioc.get('malware_family','')}|{ioc.get('last_seen') or ioc.get('first_seen','')}|")
            a("")

        if aging_iocs:
            a("h3. AGING Indicators (31–90 days)")
            a("")
            a("||Type||Value||Malware Family||Last Seen||")
            for ioc in aging_iocs[:50]:
                val = _defang_ioc(ioc.get("type",""), ioc.get("value",""))
                a(f"|{ioc.get('type','')}|{val}|{ioc.get('malware_family','')}|{ioc.get('last_seen') or ioc.get('first_seen','')}|")
            a("")

        a("----")
        a("")

    # Detection checklist
    a("h2. Detection Checklist")
    a("")
    by_tactic: dict[str, list[dict]] = {}
    for t in sorted(techniques, key=lambda x: (x.get("tactic",""), x.get("technique_id",""))):
        tactic = t.get("tactic") or "Unknown"
        by_tactic.setdefault(tactic, []).append(t)

    for tactic, ttps in by_tactic.items():
        a(f"h3. {tactic}")
        a("")
        for t in ttps:
            tid   = t.get("technique_id", "")
            name  = t.get("technique_name") or t.get("name", "")
            conf  = t.get("confidence", "").upper()
            sigma_rules = t.get("sigma_rules", [])
            att_url = f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/"
            a(f"* ( ) [{tid}|{att_url}] — {name} *[{conf}]*")
            if sigma_rules:
                top = sigma_rules[0]
                more = f" (+{len(sigma_rules)-1} more)" if len(sigma_rules) > 1 else ""
                a(f"** Sigma: [{top.get('title','')}|{top.get('url','')}] {top.get('level','').upper()} {more}")
        a("")

    a("----")
    a("")

    # Hunt hypotheses
    if hunt_text:
        a("h2. Threat Hunt Hypotheses")
        a("")
        a(hunt_text.strip())
        a("")
        a("----")
        a("")

    # Malware
    if malware:
        a("h2. Known Malware & Tools")
        a("")
        a("||Name||Type||Notes||")
        for m in malware:
            desc = textwrap.shorten(m.get("description",""), 100, placeholder="…")
            a(f"|*{m.get('name','')}*|{m.get('type','')}|{desc}|")
        a("")
        a("----")
        a("")

    # Containment
    if containment_text:
        a("h2. Containment & Response Guidance")
        if sector:
            a(f"_Sector context: {sector}_")
        a("")
        a(containment_text.strip())
        a("")
        a("----")
        a("")

    # References
    a("h2. References")
    a("")
    for src in profile.get("_sources", []):
        citation = src.get("source_citation") or src.get("source_id","")
        url      = src.get("source_url","")
        if url:
            a(f"* [{citation}|{url}]")
        elif citation:
            a(f"* {citation}")
    a("")
    a(f"_Generated by THEORY — [github.com/threatcraft-co/theory|https://github.com/threatcraft-co/theory]_")

    return "\n".join(L)


# ---------------------------------------------------------------------------
# LLM synthesis helpers
# ---------------------------------------------------------------------------

def _generate_hunt_hypotheses(profile: dict, provider: Any) -> str:
    """Generate plain-language threat hunt hypotheses for HIGH-confidence TTPs."""
    techniques = profile.get("techniques", [])
    actor_name = profile.get("actor_name", "this actor")

    high_ttps = [
        f"{t.get('technique_id','')} ({t.get('technique_name') or t.get('name','')})"
        for t in techniques
        if t.get("confidence","").upper() == "HIGH"
    ][:10]

    if not high_ttps:
        high_ttps = [
            f"{t.get('technique_id','')} ({t.get('technique_name') or t.get('name','')})"
            for t in techniques[:5]
        ]

    if not high_ttps:
        return ""

    prompt = f"""You are a threat hunter writing an IR playbook section.

Actor: {actor_name}
Highest-confidence techniques: {', '.join(high_ttps)}

Write 4-6 concrete threat hunt hypotheses as a numbered list.
Each hypothesis should:
- Start with "Hypothesis:" 
- Be one sentence describing what to hunt for and where
- Reference a specific log source or data type (e.g. Windows Event Log, EDR telemetry, DNS logs)
- Be specific enough to act on immediately

Format exactly as:
1. Hypothesis: [specific hunt statement]
2. Hypothesis: [specific hunt statement]
...

Output only the numbered list. No preamble, no explanation."""

    try:
        return provider.complete(
            "You are a senior threat hunter writing concise, actionable hunt hypotheses.",
            prompt,
        )
    except Exception as exc:
        logger.warning("Hunt hypothesis generation failed: %s", exc)
        return ""


def _generate_containment(profile: dict, sector: str, provider: Any) -> str:
    """Generate sector-aware containment and response steps."""
    actor_name  = profile.get("actor_name", "this actor")
    origin      = profile.get("origin", "unknown")
    motivations = ", ".join(profile.get("motivations", [])) or "unknown"
    malware     = [m.get("name","") for m in profile.get("malware", [])[:6] if m.get("name")]
    techniques  = profile.get("techniques", [])

    # Focus on the highest-confidence TTPs
    high_ttps = [
        t.get("technique_name") or t.get("name","")
        for t in techniques
        if t.get("confidence","").upper() == "HIGH"
    ][:6]

    sector_ctx = (
        f"The affected organization operates in the {sector} sector. "
        f"Tailor containment steps specifically for {sector} environments."
        if sector else
        "Provide general containment steps applicable across sectors."
    )

    prompt = f"""You are an incident responder writing containment guidance for an IR playbook.

Actor: {actor_name}
Origin: {origin}
Motivation: {motivations}
Known malware: {', '.join(malware) if malware else 'unknown'}
Confirmed techniques: {', '.join(high_ttps) if high_ttps else 'various'}
{sector_ctx}

Write 6-8 specific, actionable containment and response steps as a numbered list.
Each step should be concrete and immediately executable.
Include steps for: isolation, evidence preservation, credential reset, and monitoring.

Format exactly as:
1. [Action verb] — [specific step]
2. [Action verb] — [specific step]
...

Output only the numbered list. No preamble."""

    try:
        return provider.complete(
            "You are a senior incident responder writing concise, actionable playbook steps.",
            prompt,
        )
    except Exception as exc:
        logger.warning("Containment generation failed: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _partition_iocs(
    indicators: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Split indicators into FRESH and AGING buckets. Exclude STALE and UNKNOWN."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    fresh: list[dict] = []
    aging: list[dict] = []

    for ioc in indicators:
        raw = (ioc.get("last_seen") or ioc.get("first_seen") or "").strip()
        if not raw:
            continue
        try:
            seen     = datetime.strptime(raw[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            age_days = (now - seen).days
            if age_days <= _FRESH_DAYS:
                fresh.append(ioc)
            elif age_days <= _AGING_DAYS:
                aging.append(ioc)
            # STALE (>90 days) excluded from playbook — not operationally useful for blocking
        except (ValueError, TypeError):
            continue

    # Sort: domains first, then IPs, then URLs, then hashes
    type_order = {"domain": 0, "ip": 1, "url": 2,
                  "hash_md5": 3, "hash_sha256": 3, "hash_sha1": 3}
    key = lambda x: (type_order.get(x.get("type",""), 9), x.get("value",""))
    return sorted(fresh, key=key), sorted(aging, key=key)


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
