"""
reporters/dossier.py
--------------------
Renders a merged CommonSchema profile as:
  1. Rich terminal output (falls back to plain text if Rich not installed)
  2. Markdown file → output/dossiers/<actor>.md

Sections rendered:
  - Overview (origin, first seen, motivations, aliases)
  - TTP Table (Technique ID | Tactic | Name | Confidence)
  - Detection Opportunities
  - Associated Malware / Tools
  - Campaigns
  - Targeted Sectors           [CISA Phase 3]
  - Known Exploited CVEs       [CISA Phase 3]
  - CISA Advisories            [CISA Phase 3]
"""

from __future__ import annotations

import logging
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("output/dossiers")

try:
    from rich.console import Console
    from rich.table   import Table
    from rich.panel   import Panel
    from rich         import box as rich_box
    _RICH = True
except ImportError:
    _RICH = False


class DossierReporter:

    def render(self, profile: dict[str, Any]) -> None:
        if _RICH:
            self._render_rich(profile)
        else:
            self._render_plain(profile)

    def save_markdown(self, profile: dict[str, Any]) -> Path:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        actor_slug = _slugify(profile.get("actor_name", "unknown"))
        path = OUTPUT_DIR / f"{actor_slug}.md"
        path.write_text(self._build_markdown(profile), encoding="utf-8")
        logger.info("Dossier saved → %s", path)
        return path

    # ------------------------------------------------------------------
    # Rich renderer
    # ------------------------------------------------------------------

    def _render_rich(self, profile: dict[str, Any]) -> None:
        console  = Console()
        actor    = profile.get("actor_name", "Unknown")
        gid      = profile.get("mitre_group_id", "")
        origin   = profile.get("origin", "Unknown")
        first    = profile.get("first_seen", "Unknown")
        motives  = ", ".join(profile.get("motivations", [])) or "Unknown"
        aliases  = ", ".join(profile.get("aliases", [])) or "—"
        desc     = profile.get("description", "")
        sources  = ", ".join(profile.get("sources_cited", [])) or "unknown"

        header = f"[bold cyan]{actor}[/]"
        if gid:
            header += f"  [dim]({gid})[/]"

        console.print()
        console.print(Panel(header, expand=False))
        console.print()

        meta = Table.grid(padding=(0, 2))
        meta.add_column(style="dim")
        meta.add_column()
        meta.add_row("Sources",       sources)
        meta.add_row("Origin",        origin)
        meta.add_row("First Seen",    first)
        meta.add_row("Motivations",   motives)
        meta.add_row("Also Known As", aliases)
        console.print(meta)

        if desc:
            console.print()
            console.print(Panel(textwrap.fill(desc, 90), title="[bold]Overview[/]", border_style="dim"))

        # TTP table
        techniques = profile.get("techniques", [])
        if techniques:
            console.print()
            console.print("[bold]TTP Table[/]")
            ttp = Table("Technique ID", "Tactic", "Name", "Confidence", "Detection Guidance",
                        box=rich_box.SIMPLE_HEAD, header_style="bold magenta")
            detections: list[dict] = []
            for t in sorted(techniques, key=lambda x: x.get("technique_id", "")):
                conf     = t.get("confidence", "low").upper()
                conf_fmt = {"HIGH": "[green]HIGH[/]", "MEDIUM": "[yellow]MED[/]", "LOW": "[red]LOW[/]"}.get(conf, conf)
                det      = t.get("detection", "")
                ttp.add_row(
                    t.get("technique_id", ""),
                    t.get("tactic", ""),
                    t.get("technique_name", ""),
                    conf_fmt,
                    textwrap.shorten(det, 60, placeholder="…") if det else "—",
                )
                if det:
                    detections.append(t)
            console.print(ttp)

            if detections:
                console.print()
                console.print("[bold]Detection Opportunities[/]")
                for d in detections:
                    console.print(f"  [cyan]{d['technique_id']}[/] {d.get('technique_name','')}")
                    sigma_rules = d.get("sigma_rules", [])
                    if sigma_rules:
                        for rule in sigma_rules:
                            level     = rule.get("level", "").upper()
                            level_fmt = {
                                "HIGH":     "[red]HIGH[/]",
                                "MEDIUM":   "[yellow]MED[/]",
                                "LOW":      "[dim]LOW[/]",
                                "CRITICAL": "[bold red]CRIT[/]",
                            }.get(level, f"[dim]{level}[/]")
                            console.print(
                                f"    [dim]▸[/] {rule['title']}  "
                                f"{level_fmt}  "
                                f"[dim]{rule.get('logsource','')}"
                                f"{'  ' + rule['url'] if rule.get('url') else ''}[/]"
                            )
                            cond = rule.get("condition_summary", "")
                            if cond:
                                console.print(f"      [dim italic]Condition: {cond}[/]")
                    else:
                        det = d.get("detection", "")
                        if det:
                            for line in textwrap.wrap(det, 80):
                                console.print(f"    [dim]{line}[/]")
                    console.print()

        # Malware
        malware = profile.get("malware", [])
        if malware:
            console.print("[bold]Associated Malware / Tools[/]")
            mw = Table("Name", "Type", "Description", box=rich_box.SIMPLE_HEAD, header_style="bold magenta")
            for m in malware:
                mw.add_row(m.get("name",""), m.get("type",""),
                           textwrap.shorten(m.get("description",""), 70, placeholder="…"))
            console.print(mw)

        # IOCs
        indicators = profile.get("indicators", [])
        if indicators:
            console.print()
            tf_count = profile.get("threatfox_ioc_count", 0)
            otx_count = len(indicators) - tf_count
            title_parts = []
            if otx_count > 0:
                title_parts.append(f"OTX: {otx_count}")
            if tf_count > 0:
                title_parts.append(f"ThreatFox: {tf_count}")
            ioc_title = f"[bold]Indicators of Compromise[/] [dim]({', '.join(title_parts)})[/]"
            console.print(ioc_title)

            ioc_table = Table(
                "Type", "Value", "Confidence", "Threat Type", "Malware Family", "First Seen",
                box=rich_box.SIMPLE_HEAD, header_style="bold magenta"
            )
            by_type: dict[str, list] = {}
            for ioc in indicators:
                by_type.setdefault(ioc.get("type", "unknown"), []).append(ioc)
            for ioc_type in sorted(by_type):
                for ioc in by_type[ioc_type]:
                    conf     = ioc.get("confidence", 0)
                    conf_str = ""
                    if conf:
                        if conf == 100:
                            conf_str = "[green]HIGH[/]"
                        elif conf >= 75:
                            conf_str = "[yellow]MED[/]"
                        else:
                            conf_str = "[red]LOW[/]"
                    ioc_table.add_row(
                        ioc_type,
                        ioc.get("value", ""),
                        conf_str,
                        ioc.get("threat_label", ioc.get("description", "")),
                        ioc.get("malware_family", ""),
                        ioc.get("first_seen", ""),
                    )
            console.print(ioc_table)

            # ThreatFox family summary
            family_hits = profile.get("threatfox_family_hits", {})
            if family_hits:
                top = sorted(family_hits.items(), key=lambda x: -x[1])[:5]
                console.print(
                    f"  [dim]Top families: "
                    + ", ".join(f"{k} ({v})" for k, v in top)
                    + "[/]"
                )

        # Sectors
        sectors = profile.get("sectors", [])
        if sectors:
            console.print()
            console.print(f"[bold]Targeted Sectors:[/] {', '.join(sectors)}")

        # CVEs
        cves = profile.get("cves", [])
        if cves:
            console.print()
            console.print("[bold]Known Exploited CVEs (CISA KEV)[/]")
            ct = Table("CVE ID", "Product", "Vendor", "Date Added",
                       box=rich_box.SIMPLE_HEAD, header_style="bold magenta")
            for c in cves:
                ct.add_row(c.get("cve_id",""), c.get("product",""),
                           c.get("vendor",""), c.get("date_added",""))
            console.print(ct)

        # Advisories
        advisories = profile.get("advisories", [])
        if advisories:
            console.print()
            console.print("[bold]CISA Advisories[/]")
            for a in advisories:
                console.print(f"  • [cyan]{a.get('date','')}[/]  {a.get('title','')}")
                if a.get("url"):
                    console.print(f"    [dim]{a['url']}[/]")

        # Recent Intelligence (vendor synthesis)
        vendor_intel = profile.get("vendor_intel", [])
        if vendor_intel:
            console.print()
            console.print("[bold]Recent Intelligence[/]")
            console.print(f"  [dim]Synthesized from {len(vendor_intel)} vendor research articles[/]")
            console.print()
            for item in vendor_intel:
                relevance  = item.get("relevance", 0)
                rel_badge  = (
                    "[green]●[/]" if relevance >= 70 else
                    "[yellow]●[/]" if relevance >= 40 else
                    "[dim]●[/]"
                )
                console.print(
                    f"  {rel_badge} [bold]{item.get('source','')}[/]  "
                    f"[dim]{item.get('date','')}[/]"
                )
                console.print(f"    [dim italic]{item.get('title','')}[/]")
                console.print()
                # Actor-specific synthesis
                actor_sum = item.get("actor_summary", "")
                if actor_sum:
                    for line in textwrap.wrap(actor_sum, 80):
                        console.print(f"    {line}")
                    console.print()
                # Landscape context
                land_sum = item.get("landscape_summary", "")
                if land_sum:
                    console.print(f"    [dim]Context: {textwrap.shorten(land_sum, 120, placeholder='…')}[/]")
                    console.print()
                if item.get("url"):
                    console.print(f"    [dim]{item['url']}[/]")
                console.print()

        # Campaigns
        campaigns = profile.get("campaigns", [])
        if campaigns:
            console.print()
            console.print("[bold]Campaigns[/]")
            for c in campaigns:
                console.print(f"  • [cyan]{c['name']}[/]  {c.get('first_seen','')} – {c.get('last_seen','')}")

        console.print()
        console.print(f"[dim]Generated {_now_utc()}[/]")
        console.print()

    # ------------------------------------------------------------------
    # Plain / fallback
    # ------------------------------------------------------------------

    def _render_plain(self, profile: dict[str, Any]) -> None:
        print(self._build_markdown(profile))

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def _build_markdown(self, profile: dict[str, Any]) -> str:
        actor    = profile.get("actor_name", "Unknown")
        gid      = profile.get("mitre_group_id", "")
        origin   = profile.get("origin", "Unknown")
        first    = profile.get("first_seen", "Unknown")
        motives  = ", ".join(profile.get("motivations", [])) or "Unknown"
        aliases  = ", ".join(profile.get("aliases", [])) or "—"
        desc     = profile.get("description", "")
        sources  = ", ".join(profile.get("sources_cited", [])) or "unknown"
        techs    = profile.get("techniques", [])
        malware  = profile.get("malware", [])
        camps    = profile.get("campaigns", [])
        sectors  = profile.get("sectors", [])
        cves     = profile.get("cves", [])
        advisories = profile.get("advisories", [])

        L: list[str] = []
        a = L.append

        a(f"# Threat Actor Dossier: {actor}")
        if gid:
            a(f"> MITRE ATT&CK Group ID: **{gid}**")
        a(f"> Generated: {_now_utc()}  |  Sources: {sources}")
        a("")
        a("## Overview")
        a("")
        a("| Field | Value |")
        a("|---|---|")
        a(f"| **Origin** | {origin} |")
        a(f"| **First Seen** | {first} |")
        a(f"| **Motivations** | {motives} |")
        a(f"| **Also Known As** | {aliases} |")
        a("")

        if desc:
            a(desc)
            a("")

        if techs:
            a("## TTP Table")
            a("")
            a("| Technique ID | Tactic | Name | Confidence |")
            a("|---|---|---|---|")
            for t in sorted(techs, key=lambda x: x.get("technique_id", "")):
                a(f"| {t.get('technique_id','')} | {t.get('tactic','')} | {t.get('technique_name','')} | {t.get('confidence','low').upper()} |")
            a("")

            detections = [t for t in techs if t.get("sigma_rules") or t.get("detection")]
            if detections:
                a("## Detection Opportunities")
                a("")
                for d in sorted(detections, key=lambda x: x.get("technique_id", "")):
                    a(f"### {d['technique_id']} — {d.get('technique_name','')}")
                    a("")
                    sigma_rules = d.get("sigma_rules", [])
                    if sigma_rules:
                        a(f"**Sigma Rules ({len(sigma_rules)})**")
                        a("")
                        a("| Rule | Level | Log Source | Condition |")
                        a("|---|---|---|---|")
                        for rule in sigma_rules:
                            title  = rule.get("title", "")
                            url    = rule.get("url", "")
                            title_md = f"[{title}]({url})" if url else title
                            a(
                                f"| {title_md} "
                                f"| {rule.get('level','').upper()} "
                                f"| {rule.get('logsource','')} "
                                f"| {rule.get('condition_summary','')} |"
                            )
                        a("")
                    elif d.get("detection"):
                        a(d["detection"])
                        a("")

        indicators = profile.get("indicators", [])
        if indicators:
            tf_count  = profile.get("threatfox_ioc_count", 0)
            otx_count = len(indicators) - tf_count
            src_note  = []
            if otx_count > 0:
                src_note.append(f"OTX: {otx_count}")
            if tf_count > 0:
                src_note.append(f"ThreatFox: {tf_count}")
            a(f"## Indicators of Compromise ({', '.join(src_note)})")
            a("")
            a("| Type | Value | Confidence | Threat Type | Malware Family | First Seen |")
            a("|---|---|---|---|---|---|")
            by_type: dict[str, list] = {}
            for ioc in indicators:
                by_type.setdefault(ioc.get("type", "unknown"), []).append(ioc)
            for ioc_type in sorted(by_type):
                for ioc in by_type[ioc_type]:
                    conf = ioc.get("confidence", "")
                    if conf == 100:
                        conf_str = "HIGH"
                    elif conf and int(conf) >= 75:
                        conf_str = "MED"
                    elif conf:
                        conf_str = "LOW"
                    else:
                        conf_str = ""
                    a(
                        f"| {ioc_type} "
                        f"| {ioc.get('value','')} "
                        f"| {conf_str} "
                        f"| {ioc.get('threat_label', ioc.get('description',''))} "
                        f"| {ioc.get('malware_family','')} "
                        f"| {ioc.get('first_seen','')} |"
                    )
            family_hits = profile.get("threatfox_family_hits", {})
            if family_hits:
                a("")
                top = sorted(family_hits.items(), key=lambda x: -x[1])[:8]
                a(f"> **ThreatFox family hits:** {', '.join(f'{k} ({v})' for k,v in top)}")
            a("")

        if sectors:
            a("## Targeted Sectors")
            a("")
            for s in sectors:
                a(f"- {s}")
            a("")

        if cves:
            a("## Known Exploited CVEs (CISA KEV)")
            a("")
            a("| CVE ID | Product | Vendor | Date Added |")
            a("|---|---|---|---|")
            for c in cves:
                a(f"| {c.get('cve_id','')} | {c.get('product','')} | {c.get('vendor','')} | {c.get('date_added','')} |")
            a("")

        if advisories:
            a("## CISA Advisories")
            a("")
            for adv in advisories:
                url_part = f" — [{adv['url']}]({adv['url']})" if adv.get("url") else ""
                a(f"- **{adv.get('date','')}** {adv.get('title','')}{url_part}")
            a("")

        if malware:
            a("## Associated Malware / Tools")
            a("")
            a("| Name | Type | Description |")
            a("|---|---|---|")
            for m in malware:
                a(f"| {m.get('name','')} | {m.get('type','')} | {textwrap.shorten(m.get('description',''), 120, placeholder='…')} |")
            a("")

        vendor_intel = profile.get("vendor_intel", [])
        if vendor_intel:
            a("## Recent Intelligence")
            a("")
            a(f"> Synthesized from {len(vendor_intel)} vendor research articles using AI.")
            a("")
            for item in vendor_intel:
                relevance = item.get("relevance", 0)
                rel_label = "HIGH" if relevance >= 70 else "MEDIUM" if relevance >= 40 else "LOW"
                a(f"### {item.get('source','')} — {item.get('date','')}  `{rel_label} relevance`")
                a("")
                a(f"**[{item.get('title','')}]({item.get('url','')})**")
                a("")
                actor_sum = item.get("actor_summary", "")
                if actor_sum:
                    a(actor_sum)
                    a("")
                land_sum = item.get("landscape_summary", "")
                if land_sum:
                    a(f"*Landscape context: {land_sum}*")
                    a("")
            a("")

        if camps:
            a("## Campaigns")
            a("")
            for c in camps:
                period = f" ({c.get('first_seen','?')} – {c.get('last_seen','?')})" if c.get("first_seen") or c.get("last_seen") else ""
                a(f"- **{c['name']}**{period}")
                if c.get("description"):
                    a(f"  {textwrap.shorten(c['description'], 140, placeholder='…')}")
            a("")

        return "\n".join(L)


def _slugify(name: str) -> str:
    return name.lower().replace(" ", "_").replace("/", "_")


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
