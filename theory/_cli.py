"""
theory._cli
-----------
THEORY — Multi-source Threat Actor Intelligence Framework

An open-source alternative to enterprise threat intelligence platforms.
Built for analysts, hunters, students, and researchers who believe
good intelligence shouldn't require a six-figure subscription.

Usage examples
--------------
  # Basic dossier
  python theory.py --actor APT28

  # Multi-source with all enrichments
  python theory.py --actor APT28 --sources mitre,malpedia,misp_galaxy,cisa_kev,otx,sigma,threatfox

  # Export all formats
  python theory.py --actor "Lazarus Group" --sources mitre,malpedia --output all

  # STIX bundle for MISP/OpenCTI import
  python theory.py --actor Turla --sources mitre,otx --output stix

  # Don't save files, just print
  python theory.py --actor APT41 --sources mitre --no-save

  # See what's available
  python theory.py --list-sources
  python theory.py --list-actors

  # Refresh cached data
  python theory.py --update-bundles
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Load .env before anything else touches os.environ
# ---------------------------------------------------------------------------
# Collectors read their API keys via os.environ.get() at construction time.
# If .env isn't loaded before the first collector is instantiated, every
# key-requiring collector silently skips itself with a "no API key" message,
# even when the key is sitting right there in .env.
#
# python-dotenv is already a hard dependency in pyproject.toml, so this
# import should always succeed. The try/except is belt-and-suspenders for
# unusual installs (e.g. someone pip-installing individual files).
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Logging — clean format, WARNING by default
# ---------------------------------------------------------------------------

try:
    from rich.logging import RichHandler
    from rich.console import Console as _RichConsole
    logging.basicConfig(
        level=logging.WARNING,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(
            console=_RichConsole(stderr=True),
            show_path=False,
            rich_tracebacks=False,
        )],
    )
except ImportError:
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s  %(name)s  %(message)s",
    )
logger = logging.getLogger("theory")


# ---------------------------------------------------------------------------
# Source registry
# ---------------------------------------------------------------------------

SUPPORTED_SOURCES: dict[str, str | None] = {
    "mitre":       "collectors.mitre_attack.MitreAttackCollector",
    "cisa":        "collectors.cisa_advisories.CisaAdvisoriesCollector",
    "cisa_kev":    "collectors.cisa_kev.CisaKevCollector",
    "malpedia":    "collectors.malpedia.MalpediaCollector",
    "misp_galaxy": "collectors.misp_galaxy.MispGalaxyCollector",
    "circl_misp":  "collectors.circl_misp.CirclMispCollector",
    "otx":         "collectors.alienvault_otx.AlienVaultOTXCollector",
    "vuldb":       "collectors.vuldb.VulDBCollector",
    "nvd":         "collectors.nvd.NVDCollector",
    "personal":    "collectors.personal_intel.PersonalIntelCollector",
    # Enrichment-only — accepted by CLI but handled separately
    "sigma":          None,
    "yara":           None,
    "threatfox":      None,
    "malware_bazaar": None,
    "urlhaus":        None,
    "greynoise":      None,
    "abuseipdb":      None,
    "vendor":         None,   # vendor intelligence synthesis (requires LLM provider)
}

SOURCE_DESCRIPTIONS: dict[str, str] = {
    "mitre":       "MITRE ATT&CK — techniques, malware, campaigns (local bundle, offline)",
    "cisa":        "CISA advisories + KEV catalog (free, no auth)",
    "cisa_kev":    "CISA KEV — 1600+ confirmed-exploited CVEs, ransomware flags (free, no auth)",
    "malpedia":    "Malpedia malware family database (free, no auth)",
    "misp_galaxy": "MISP Galaxy — 1000+ actors, aliases, attribution, target sectors (free, no auth)",
    "circl_misp":  "CIRCL OSINT MISP feed — event-level indicators + campaign context by actor/alias match (free, no auth)",
    "otx":         "AlienVault OTX pulses + IOCs (free, requires OTX_API_KEY in .env)",
    "nvd":         "NIST NVD — CVSS scores/vectors, CWE classification, references for CVEs already in the profile (free, optional NVD_API_KEY raises rate limit)",
    "sigma":          "SigmaHQ detection rules mapped to ATT&CK (free, optional GITHUB_TOKEN)",
    "yara":           "YARA file detection rules matched to malware families (free, local clone)",
    "threatfox":      "ThreatFox IOCs by malware family (free, no auth)",
    "malware_bazaar": "MalwareBazaar sample hashes by malware family (free, requires ABUSECH_API_KEY)",
    "urlhaus":        "URLhaus malware distribution URLs by family (free, requires ABUSECH_API_KEY)",
    "greynoise":      "GreyNoise IP noise/RIOT context — distinguishes targeted vs background activity (free, 50/week)",
    "abuseipdb":      "AbuseIPDB IP reputation scores from community reports (free, 1000/day)",
    "vuldb":          "VulDB actor-CVE correlation and exploit intelligence (free tier, 50 credits/day)",
    "vendor":         "Vendor intelligence synthesis — LLM-synthesized summaries from 35+ research blogs (requires LLM provider in .env)",
    "personal":       "Your own local research indicators — gitignored redirect, never leaves your machine (set up with --init-personal)",
}

SOURCE_REQUIRES: dict[str, str] = {
    "otx":            "OTX_API_KEY",
    "sigma":          "GITHUB_TOKEN (optional, recommended)",
    "malware_bazaar": "ABUSECH_API_KEY",
    "urlhaus":        "ABUSECH_API_KEY",
    "greynoise":      "GREYNOISE_API_KEY",
    "abuseipdb":      "ABUSEIPDB_API_KEY",
    "vuldb":          "VULDB_API_KEY",
    "vendor":         "ANTHROPIC_API_KEY or OPENAI_API_KEY or Ollama running locally",
}

ENRICHMENT_SOURCES: dict[str, str] = {
    "sigma":          "collectors.sigma_rules.SigmaCollector",
    "yara":           "collectors.yara_rules.YaraRulesCollector",
    "threatfox":      "collectors.threatfox.ThreatFoxCollector",
    "malware_bazaar": "collectors.malware_bazaar.MalwareBazaarCollector",
    "urlhaus":        "collectors.urlhaus.URLhausCollector",
    "greynoise":      "collectors.greynoise.GreyNoiseCollector",
    "abuseipdb":      "collectors.abuseipdb.AbuseIPDBCollector",
    "vendor":         "collectors.vendor_intel.VendorIntelCollector",
}

MAPPER_REGISTRY: dict[str, str] = {
    "mitre":       "mappers.mitre.MitreMapper",
    "cisa":        "mappers.cisa.CisaMapper",
    "cisa_kev":    "collectors.cisa_kev.CisaKevMapper",
    "malpedia":    "collectors.malpedia.MalpediaMapper",
    "misp_galaxy": "collectors.misp_galaxy.MispGalaxyMapper",
    "circl_misp":  "collectors.circl_misp.CirclMispMapper",
    "otx":         "collectors.alienvault_otx.AlienVaultOTXMapper",
    "nvd":         "collectors.nvd.NVDMapper",
}

# Default source combination — good balance of coverage vs speed
# All keyless and free, providing complementary intelligence:
#   mitre       → techniques, software, campaigns
#   cisa        → advisories, KEV CVEs (actor-attributed)
#   cisa_kev    → 1600+ confirmed-exploited CVEs, ransomware flags
#   malpedia    → malware families, YARA counts
#   misp_galaxy → 1000+ actors, deep alias lists, attribution, target sectors
DEFAULT_SOURCES = "mitre,cisa,cisa_kev,malpedia,misp_galaxy"


# ---------------------------------------------------------------------------
# Info commands
# ---------------------------------------------------------------------------

def cmd_list_sources() -> None:
    """Print a formatted table of all available sources."""
    try:
        from rich.console import Console
        from rich.table   import Table
        from rich         import box as rich_box
        console = Console()
        console.print()
        console.print("[bold cyan]THEORY — Available Sources[/]")
        console.print()

        t = Table("Key", "Description", "Auth Required", "Cache",
                  box=rich_box.SIMPLE_HEAD, header_style="bold magenta")

        cache_ttls = {
            "mitre":          "7 days (.cache/enterprise-attack.json)",
            "cisa":           "per request",
            "cisa_kev":       "24 hours (.cache/cisa_kev/)",
            "malpedia":       "per request (.cache/malpedia/)",
            "misp_galaxy":    "7 days (.cache/misp_galaxy/)",
            "circl_misp":     "24h manifest / 7 days per event (.cache/circl_misp/)",
            "otx":            "per request (.cache/otx/)",
            "nvd":            "30 days per CVE (.cache/nvd/)",
            "sigma":          "7 days (.cache/sigma-repo/)",
            "yara":           "7 days (.cache/yara-rules-repo/)",
            "threatfox":      "24 hours (.cache/threatfox/)",
            "malware_bazaar": "24 hours (.cache/malware_bazaar/)",
            "urlhaus":        "24 hours (.cache/urlhaus/)",
            "greynoise":      "7 days (.cache/greynoise/)",
            "abuseipdb":      "3 days (.cache/abuseipdb/)",
            "vuldb":          "7 days (.cache/vuldb/)",
            "personal":       "none — reads your local file directly, every run",
        }

        for key, desc in SOURCE_DESCRIPTIONS.items():
            auth = SOURCE_REQUIRES.get(key, "none")
            cache = cache_ttls.get(key, "—")
            t.add_row(
                f"[cyan]{key}[/]",
                desc,
                f"[yellow]{auth}[/]" if auth != "none" else "[dim]none[/]",
                f"[dim]{cache}[/]",
            )
        console.print(t)
        console.print()
        console.print("[dim]Usage: python theory.py --actor APT28 --sources mitre,malpedia,otx,sigma,threatfox[/]")
        console.print()

    except ImportError:
        print("\nTHEORY — Available Sources\n")
        print(f"{'Key':<12} {'Auth':<25} Description")
        print("-" * 80)
        for key, desc in SOURCE_DESCRIPTIONS.items():
            auth = SOURCE_REQUIRES.get(key, "none")
            print(f"{key:<12} {auth:<25} {desc}")
        print()


def cmd_list_actors() -> None:
    """Print all actors in the cross-source alias table."""
    try:
        from collectors.cisa_advisories import ALIAS_TABLE
    except ImportError:
        print("Could not load alias table.")
        return

    try:
        from rich.console import Console
        from rich.table   import Table
        from rich         import box as rich_box
        console = Console()
        console.print()
        console.print(f"[bold cyan]THEORY — Known Actors ({len(ALIAS_TABLE)})[/]")
        console.print("[dim]These actors have cross-source alias resolution built in.[/]")
        console.print("[dim]Any actor name or alias in this list will resolve correctly across all sources.[/]")
        console.print()

        t = Table("Canonical Name", "Alias Count", "Sample Aliases",
                  box=rich_box.SIMPLE_HEAD, header_style="bold magenta")

        for canonical, aliases in sorted(ALIAS_TABLE.items()):
            sample = ", ".join(sorted(aliases)[:4])
            if len(aliases) > 4:
                sample += f" +{len(aliases)-4} more"
            t.add_row(
                f"[cyan]{canonical}[/]",
                str(len(aliases)),
                f"[dim]{sample}[/]",
            )
        console.print(t)
        console.print()
        console.print("[dim]Tip: --actor accepts any alias. 'Fancy Bear', 'Strontium', and 'APT28' all work.[/]")
        console.print()

    except ImportError:
        from collectors.cisa_advisories import ALIAS_TABLE
        print(f"\nTHEORY — Known Actors ({len(ALIAS_TABLE)})\n")
        for canonical, aliases in sorted(ALIAS_TABLE.items()):
            print(f"  {canonical:<25} ({len(aliases)} aliases)")
        print()


def cmd_update_bundles() -> None:
    """Refresh the ATT&CK bundle and clear stale caches."""
    import subprocess
    import shutil
    from pathlib import Path

    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    def _print(msg: str, style: str = "") -> None:
        if console:
            console.print(f"[{style}]{msg}[/]" if style else msg)
        else:
            print(msg)

    _print("\nTHEORY — Update Bundles\n", "bold cyan")

    # 1. ATT&CK bundle
    bundle_path = Path(".cache/enterprise-attack.json")
    bundle_path.parent.mkdir(exist_ok=True)
    url = (
        "https://github.com/mitre-attack/attack-stix-data/raw/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    _print("Downloading MITRE ATT&CK bundle…", "dim")
    _print(f"  Source: {url}", "dim")

    try:
        result = subprocess.run(
            ["curl", "-L", "--progress-bar", "-o", str(bundle_path), url],
            check=True,
        )
        size_mb = bundle_path.stat().st_size / 1_048_576
        _print(f"  ✓ ATT&CK bundle updated ({size_mb:.1f} MB)", "green")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        _print(f"  ✗ ATT&CK bundle update failed: {exc}", "red")
        _print("  Run manually: curl -L {url} -o .cache/enterprise-attack.json", "dim")

    # 2. Update Sigma repo (fetch + reset to handle force-pushes)
    sigma_repo = Path(".cache/sigma-repo")
    if sigma_repo.exists():
        _print("  Updating Sigma rules…", "dim")
        import subprocess as _sp
        result = _sp.run(
            ["git", "-C", str(sigma_repo), "fetch", "origin", "--depth=1"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            result = _sp.run(
                ["git", "-C", str(sigma_repo), "reset", "--hard", "origin/master"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                _print("  ✓ Sigma rules updated", "green")
            else:
                _print(f"  ✗ Sigma reset failed: {result.stderr[:100]}", "red")
        else:
            _print(f"  ✗ Sigma fetch failed: {result.stderr[:100]}", "red")
    else:
        _print("  ✓ Sigma repo not yet cloned — will clone on next --sources sigma run", "dim")

    # 3. MISP Galaxy threat-actor cluster
    misp_cache = Path(".cache/misp_galaxy/threat-actor.json")
    misp_url = (
        "https://raw.githubusercontent.com/MISP/misp-galaxy"
        "/main/clusters/threat-actor.json"
    )
    _print("  Updating MISP Galaxy threat-actor cluster…", "dim")
    try:
        misp_cache.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            ["curl", "-sL", "-o", str(misp_cache), misp_url],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode == 0 and misp_cache.exists():
            import json as _json
            count = len(_json.loads(misp_cache.read_text()).get("values", []))
            size_kb = misp_cache.stat().st_size / 1024
            _print(
                f"  ✓ MISP Galaxy updated — {count} actors ({size_kb:.0f} KB)",
                "green",
            )
        else:
            _print(f"  ✗ MISP Galaxy update failed: {r.stderr[:80]}", "red")
    except Exception as exc:
        _print(f"  ✗ MISP Galaxy update error: {exc}", "red")

    # 4. CISA KEV catalog
    kev_cache = Path(".cache/cisa_kev/known_exploited_vulnerabilities.json")
    kev_url = (
        "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
        "known_exploited_vulnerabilities.json"
    )
    _print("  Updating CISA KEV catalog…", "dim")
    try:
        kev_cache.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            ["curl", "-sL", "-o", str(kev_cache), kev_url],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode == 0 and kev_cache.exists():
            import json as _json
            kev_data = _json.loads(kev_cache.read_text())
            count = kev_data.get("count", 0)
            version = kev_data.get("catalogVersion", "unknown")
            _print(
                f"  ✓ CISA KEV updated — v{version}, {count} CVEs",
                "green",
            )
        else:
            _print(f"  ✗ CISA KEV update failed: {r.stderr[:80]}", "red")
    except Exception as exc:
        _print(f"  ✗ CISA KEV update error: {exc}", "red")

    # 5. ThreatFox cache — let 24hr TTL handle expiry naturally
    _print("  ✓ ThreatFox cache preserved (24hr TTL handles expiry automatically)", "dim")

    # 6. Clone/update CyberMonitor APT Campaign Collection (historical context)
    apt_path = Path(".cache/apt-campaigns")
    apt_url  = "https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections.git"
    if apt_path.exists():
        _print("  Updating APT campaign collection (git pull)…", "dim")
        try:
            r = subprocess.run(
                ["git", "-C", str(apt_path), "pull", "--depth=1"],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode == 0:
                _print("  ✓ APT campaign collection updated", "green")
            else:
                _print(f"  ✗ APT campaign update failed: {r.stderr[:80]}", "red")
        except Exception as exc:
            _print(f"  ✗ APT campaign update error: {exc}", "red")
    else:
        _print("  Cloning CyberMonitor APT Campaign Collection (one time, ~200MB)…", "dim")
        try:
            r = subprocess.run(
                ["git", "clone", "--depth", "1", "--filter=blob:none",
                 "--no-tags", apt_url, str(apt_path)],
                capture_output=True, text=True, timeout=300,
            )
            if r.returncode == 0:
                _print("  ✓ APT campaign collection cloned → .cache/apt-campaigns/", "green")
            else:
                _print(f"  ✗ APT campaign clone failed: {r.stderr[:80]}", "red")
        except Exception as exc:
            _print(f"  ✗ APT campaign clone error: {exc}", "red")

    # 7. YARA Rules repo
    yara_repo = Path(".cache/yara-rules-repo")
    if yara_repo.exists():
        _print("  Updating YARA rules…", "dim")
        result = subprocess.run(
            ["git", "-C", str(yara_repo), "fetch", "origin", "--depth=1"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            result = subprocess.run(
                ["git", "-C", str(yara_repo), "reset", "--hard", "origin/HEAD"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                _print("  ✓ YARA rules updated", "green")
            else:
                _print(f"  ✗ YARA reset failed: {result.stderr[:100]}", "red")
        else:
            _print(f"  ✗ YARA fetch failed: {result.stderr[:100]}", "red")
    else:
        _print("  ✓ YARA rules repo not yet cloned — will clone on next --sources yara run", "dim")

    # 8. Leave Malpedia + OTX caches — per-family/per-pulse, expensive to rebuild
    _print("\n  Malpedia + OTX caches preserved (clear manually if needed).", "dim")
    _print("  Run THEORY normally to rebuild Sigma + ThreatFox caches.\n", "dim")
    _print("Update complete.\n", "bold green")


# ---------------------------------------------------------------------------
# theory ask — tool-calling LLM synthesis over local data only
# ---------------------------------------------------------------------------

def cmd_ask(argv: list[str]) -> None:
    """`theory ask "<question>"` — natural-language questions answered
    only from THEORY's own local data (the persistent correlation graph
    and personal research notes), via collectors/intelligence_agent.py."""
    if not argv or not " ".join(argv).strip():
        print('\nusage: theory ask "<question>"')
        print('example: theory ask "what do we know about 1.1.1.1?"\n')
        sys.exit(1)

    question = " ".join(argv).strip()

    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    def _p(msg: str, style: str = "") -> None:
        if console:
            console.print(f"[{style}]{msg}[/]" if style else msg)
        else:
            print(msg)

    _p(f"\n[theory ask] {question}", "dim")

    from collectors.intelligence_agent import ask
    answer = ask(question)

    _p("")
    _p(answer)
    _p("")


# ---------------------------------------------------------------------------
# Personal research redirect — theory --init-personal
# ---------------------------------------------------------------------------

def cmd_init_personal(path: str | None) -> None:
    """`theory --init-personal [--personal-path PATH]` — set up the
    gitignored redirect + starter personal indicators file."""
    from collectors.personal_intel import REDIRECT_PATH, init_personal
    target = init_personal(path)

    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    def _p(msg: str, style: str = "") -> None:
        if console:
            console.print(f"[{style}]{msg}[/]" if style else msg)
        else:
            print(msg)

    _p("\nTHEORY — Personal research redirect", "bold cyan")
    _p(f"  Redirect (gitignored):  {REDIRECT_PATH.resolve()}")
    _p(f"  Personal indicators:    {target}")
    _p("\n  Add your own research to that file, then query it with:")
    _p("    theory --actor APT28 --sources personal,mitre,cisa", "dim")
    _p("\n  Nothing in either file is committed, shared, or uploaded by THEORY.\n", "dim")


# ---------------------------------------------------------------------------
# Cross-run graph queries — theory --ioc / --technique, standalone or
# combined with --actor for a connection query
# ---------------------------------------------------------------------------

def _graph_console():
    try:
        from rich.console import Console
        return Console()
    except ImportError:
        return None


def cmd_query_ioc(value: str) -> bool:
    """Standalone `theory --ioc VALUE` lookup against the persistent graph.

    Returns True if the IOC has ever been recorded, False otherwise —
    callers use this for an accurate process exit code.
    """
    from processors.graph import query_ioc
    result  = query_ioc(value)
    console = _graph_console()

    def _p(msg: str, style: str = "") -> None:
        if console:
            console.print(f"[{style}]{msg}[/]" if style else msg)
        else:
            print(msg)

    _p(f"\nTHEORY — Graph lookup: IOC {value!r}", "bold cyan")
    if not result["found"]:
        _p("  Not found. No prior `theory --actor` run has reported this indicator.", "dim")
        _p("  Run an actor query with a source that collects IOCs (otx, threatfox, "
           "malware_bazaar, urlhaus, abuseipdb, greynoise) to populate the graph.\n", "dim")
        return False

    _p(f"  Type:        {result.get('ioc_type') or 'unknown'}")
    _p(f"  First seen:  {result['first_seen']}    Last seen: {result['last_seen']}")
    _p(f"  Sources:     {', '.join(result['sources']) or '—'}")

    if result["linked_actors"]:
        _p("\n  Linked actors:", "bold")
        for a in result["linked_actors"]:
            _p(f"    - {a['label']}  (via {a['relation']}; {', '.join(a['sources']) or '—'})")
    if result["linked_malware"]:
        _p("\n  Linked malware:", "bold")
        for m in result["linked_malware"]:
            _p(f"    - {m['label']}")
    if result["linked_techniques"]:
        _p("\n  Linked techniques:", "bold")
        for t in result["linked_techniques"]:
            _p(f"    - {t['label']}")
    if result["linked_cves"]:
        _p("\n  Linked CVEs:", "bold")
        for c in result["linked_cves"]:
            _p(f"    - {c['label']}")
    _p("")
    return True


def cmd_query_technique(technique_id: str) -> bool:
    """Standalone `theory --technique ID` lookup against the persistent graph."""
    from processors.graph import query_technique
    result  = query_technique(technique_id)
    console = _graph_console()

    def _p(msg: str, style: str = "") -> None:
        if console:
            console.print(f"[{style}]{msg}[/]" if style else msg)
        else:
            print(msg)

    _p(f"\nTHEORY — Graph lookup: technique {technique_id.strip().upper()!r}", "bold cyan")
    if not result["found"]:
        _p("  Not found. No prior `theory --actor` run has reported this technique.", "dim")
        _p("  Run an actor query with --sources including mitre to populate the graph.\n", "dim")
        return False

    _p(f"  Name:        {result.get('label', '')}")
    _p(f"  First seen:  {result['first_seen']}    Last seen: {result['last_seen']}")

    if result["linked_actors"]:
        _p("\n  Actors observed using this technique:", "bold")
        for a in result["linked_actors"]:
            _p(f"    - {a['label']}  ({', '.join(a['sources']) or '—'})")
    else:
        _p("\n  No actors linked yet.", "dim")
    if result["linked_cves"]:
        _p("\n  Linked CVEs:", "bold")
        for c in result["linked_cves"]:
            _p(f"    - {c['label']}")
    _p("")
    return True


def cmd_query_attack_type(label: str) -> bool:
    """Standalone `theory --attack-type LABEL` lookup against the
    persistent graph (matched against actor motivations + malware type)."""
    from processors.graph import query_attack_type
    result  = query_attack_type(label)
    console = _graph_console()

    def _p(msg: str, style: str = "") -> None:
        if console:
            console.print(f"[{style}]{msg}[/]" if style else msg)
        else:
            print(msg)

    _p(f"\nTHEORY — Graph lookup: attack type {label!r}", "bold cyan")
    if not result["matched_actors"] and not result["matched_malware"]:
        _p("  No matches. Nothing in the graph has a motivation or malware type "
           f"matching {label!r} yet.", "dim")
        _p("  This checks actor motivations and malware types recorded by past "
           "`theory --actor` runs — not a separate attack-pattern taxonomy.\n", "dim")
        return False

    if result["matched_actors"]:
        _p("\n  Matched actors:", "bold")
        for a in result["matched_actors"]:
            _p(f"    - {a['label']}")
    if result["matched_malware"]:
        _p("\n  Matched malware:", "bold")
        for m in result["matched_malware"]:
            _p(f"    - {m['label']}  ({m['malware_type']})")
    _p("")
    return True


def cmd_check_attack_type(actor: str, label: str) -> bool:
    """`theory --actor X --attack-type LABEL` — is this actor associated
    with this attack type, per its recorded motivations/malware types?

    Attack type isn't a graph node (see query_attack_type's docstring for
    why), so this doesn't go through find_connection like --ioc/--technique
    do — it just checks whether the actor appears in query_attack_type's
    match list.
    """
    from processors.graph import canonical_id, query_attack_type
    result  = query_attack_type(label)
    console = _graph_console()

    def _p(msg: str, style: str = "") -> None:
        if console:
            console.print(f"[{style}]{msg}[/]" if style else msg)
        else:
            print(msg)

    actor_canon = canonical_id("actor", actor)
    matched = any(a["id"] == actor_canon for a in result["matched_actors"])

    _p(f"\nTHEORY — Attack-type check: actor:{actor_canon}  <->  attack-type:{label}", "bold cyan")
    if matched:
        _p("  MATCH — this actor's recorded motivations or malware are associated "
           f"with {label!r}.\n", "bold green")
    else:
        _p(f"  No match — {actor_canon} has no recorded motivation or malware type "
           f"matching {label!r}.\n", "yellow")
    return matched


def cmd_find_connection(entity_a: tuple[str, str], entity_b: tuple[str, str]) -> bool:
    """Cross-correlative / multi-axis query: `theory --actor X --ioc Y`
    (or --technique). Prints whether the two are connected in the
    persistent graph and through what — this is the "multi-flag query"
    semantics: one combined question, not two independent lookups.
    """
    from processors.graph import find_connection
    result  = find_connection(entity_a, entity_b)
    console = _graph_console()

    def _p(msg: str, style: str = "") -> None:
        if console:
            console.print(f"[{style}]{msg}[/]" if style else msg)
        else:
            print(msg)

    a_label = f"{entity_a[0]}:{entity_a[1]}"
    b_label = f"{entity_b[0]}:{entity_b[1]}"
    _p(f"\nTHEORY — Connection query: {a_label}  <->  {b_label}", "bold cyan")

    if not result["connected"]:
        if result.get("reason") == "one_or_both_unknown":
            for label, entity in (("entity_a", entity_a), ("entity_b", entity_b)):
                known = result[label]["known"]
                if not known:
                    _p(f"  {entity[0]} {entity[1]!r} has no prior data in the graph.", "dim")
            _p("  Cannot determine a connection — one or both entities are unrecorded.\n", "dim")
        else:
            _p("  No known connection. Both entities are in the graph, but THEORY has "
               "never recorded a direct link or a shared relationship between them.\n", "yellow")
        return False

    if result["path"] == "direct":
        _p(f"  CONNECTED — direct link ({result['relation']})", "bold green")
        _p(f"  Sources:     {', '.join(result['sources']) or '—'}")
        _p(f"  First seen:  {result['first_seen']}    Last seen: {result['last_seen']}\n")
    else:
        bridges = ", ".join(f"{b['type']}:{b['label']}" for b in result["bridges"])
        _p("  CONNECTED — via shared relationship", "bold green")
        _p(f"  Bridge(s):   {bridges}\n")
    return True


# ---------------------------------------------------------------------------
# Progress bar support
# ---------------------------------------------------------------------------

def _make_progress():
    """Return a Rich progress context manager if Rich is available, else None."""
    try:
        from rich.progress import (
            Progress, SpinnerColumn, TextColumn,
            BarColumn, TaskProgressColumn, TimeElapsedColumn,
        )
        from rich.console import Console
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            transient=True,
            console=Console(stderr=True),
        )
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _load_class(dotted_path: str):
    import importlib
    module_path, class_name = dotted_path.rsplit(".", 1)
    return getattr(importlib.import_module(module_path), class_name)


def _load_normalize_fn():
    try:
        from processors.normalizer import Normalizer  # type: ignore
        return Normalizer().normalize
    except (ImportError, AttributeError):
        pass
    try:
        from processors.normalizer import normalizer  # type: ignore
        return normalizer
    except ImportError:
        pass
    try:
        from processors.normalizer import normalize  # type: ignore
        return normalize
    except ImportError:
        pass
    logger.debug("Normalizer not available — using passthrough (records already structured).")
    return lambda r: r


def _sanitize_profile(profile: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively strip non-JSON-serialisable keys and types.
    The scaffold's deduplicator stores internal indexes:
      _technique_index  → dict with tuple keys
      _malware_index    → set
      _indicator_index  → dict with tuple keys
    These must be removed before any output.
    """
    def _clean(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _clean(v) for k, v in obj.items() if isinstance(k, str)}
        if isinstance(obj, list):
            return [_clean(i) for i in obj]
        if isinstance(obj, set):
            return sorted(str(i) for i in obj)
        return obj
    return _clean(profile)


def _collect_and_map(actor: str, source_key: str) -> dict[str, Any] | None:
    collector_path = SUPPORTED_SOURCES.get(source_key, "NOT_FOUND")
    if collector_path == "NOT_FOUND":
        logger.warning("Unknown source %r — skipping.", source_key)
        return None
    if collector_path is None:
        return None   # enrichment-only
    try:
        raw = _load_class(collector_path)().query(actor)
    except Exception as exc:
        logger.error("Collector %r failed: %s", source_key, exc)
        return None
    if raw is None:
        return None
    mapper_path = MAPPER_REGISTRY.get(source_key)
    if mapper_path:
        try:
            raw = _load_class(mapper_path)().map(raw)
        except Exception as exc:
            logger.error("Mapper %r failed: %s", source_key, exc)
            return None
    return raw


def _enrich_profile(profile: dict[str, Any], source_key: str) -> dict[str, Any]:
    enricher_path = ENRICHMENT_SOURCES.get(source_key)
    if not enricher_path:
        return profile
    try:
        enricher = _load_class(enricher_path)()

        if source_key == "sigma":
            tids = [
                t.get("technique_id", "")
                for t in (profile.get("techniques") or [])
                if t.get("technique_id")
            ]
            if not tids:
                return profile
            sigma_map = enricher.collect_for_techniques(tids)
            for t in (profile.get("techniques") or []):
                tid   = t.get("technique_id", "")
                rules = sigma_map.get(tid, [])
                if rules:
                    t["sigma_rules"]      = rules
                    t["sigma_rule_count"] = len(rules)
                    first = rules[0]["title"]
                    extra = len(rules) - 1
                    t["detection"] = (
                        f"{first} (+{extra} more)" if extra > 0 else first
                    )
            profile["sigma_rule_count"] = sum(len(v) for v in sigma_map.values())
            logger.info("Sigma: enriched %d techniques with %d rules",
                        len(sigma_map), profile["sigma_rule_count"])

        elif source_key == "vendor":
            from collectors.intelligence_synthesizer import (
                IntelligenceSynthesizer, load_provider
            )
            provider    = load_provider()
            if not provider:
                logger.warning(
                    "No LLM provider available for vendor synthesis. "
                    "Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or start Ollama."
                )
                return profile

            synthesizer = IntelligenceSynthesizer(provider)
            actor_name  = profile.get("actor_name", "")

            # Always use ALIAS_TABLE for full alias coverage regardless of
            # which sources ran. This ensures vendor search catches articles
            # that mention "Fancy Bear", "Strontium", "Sofacy" etc. even when
            # the user typed --actor APT28.
            try:
                from collectors.cisa_advisories import ALIAS_TABLE
                canonical = actor_name
                # Find canonical key (profile may have stored the resolved name)
                table_aliases: list[str] = []
                for canon, alias_set in ALIAS_TABLE.items():
                    if (canon.lower() == actor_name.lower()
                            or actor_name.lower() in alias_set):
                        canonical  = canon
                        table_aliases = list(alias_set)
                        break
                aliases = table_aliases or (profile.get("aliases", []) or [])
            except Exception:
                aliases = profile.get("aliases", []) or []

            # Fetch articles from vendor feeds
            collector   = enricher   # VendorIntelCollector
            articles    = collector.collect(
                actor_name  = actor_name,
                aliases     = aliases,
                lookback_days = int(os.environ.get("THEORY_INTEL_LOOKBACK", "365")),
            )

            if not articles:
                logger.info("Vendor intel: no relevant articles found for %r", actor_name)
                return profile

            # Synthesize with LLM
            synthesized = synthesizer.synthesize_batch(
                articles   = articles,
                actor_name = actor_name,
                aliases    = aliases,
                max_items  = int(os.environ.get("THEORY_INTEL_MAX_ITEMS", "15")),
            )

            if synthesized:
                profile["vendor_intel"]       = synthesized
                profile["vendor_intel_count"] = len(synthesized)
                logger.info(
                    "Vendor intel: synthesized %d articles using %s",
                    len(synthesized), provider.name,
                )

        elif source_key == "threatfox":
            malware_names = [
                m.get("name", "")
                for m in (profile.get("malware") or [])
                if m.get("name")
            ]
            if not malware_names:
                return profile
            result = enricher.collect_for_malware_families(
                malware_names, profile.get("actor_name", "")
            )
            if not result:
                return profile
            existing = profile.get("indicators", [])
            seen = {
                f"{i.get('type','')}:{i.get('value','').lower()}"
                for i in existing
            }
            new_iocs = []
            for ioc in (result.get("indicators") or []):
                key = f"{ioc.get('type','')}:{ioc.get('value','').lower()}"
                if key not in seen:
                    seen.add(key)
                    new_iocs.append(ioc)
            profile["indicators"] = existing + new_iocs
            profile["threatfox_ioc_count"]   = len(new_iocs)
            profile["threatfox_family_hits"]  = result.get("family_hits", {})
            logger.info("ThreatFox: added %d IOCs", len(new_iocs))

        elif source_key == "malware_bazaar":
            malware_names = [
                m.get("name", "")
                for m in (profile.get("malware") or [])
                if m.get("name")
            ]
            if not malware_names:
                return profile
            abusech_key = os.environ.get("ABUSECH_API_KEY", "")
            enricher_inst = enricher.__class__(api_key=abusech_key) if not abusech_key else enricher
            if abusech_key:
                enricher_inst = _load_class(enricher_path)(api_key=abusech_key)
            else:
                enricher_inst = enricher
            result = enricher_inst.collect_for_malware_families(
                malware_names, profile.get("actor_name", "")
            )
            if not result:
                return profile
            existing = profile.get("indicators", [])
            seen = {
                f"{i.get('type','')}:{i.get('value','').lower()}"
                for i in existing
            }
            new_iocs = []
            for ioc in (result.get("indicators") or []):
                key = f"{ioc.get('type','')}:{ioc.get('value','').lower()}"
                if key not in seen:
                    seen.add(key)
                    new_iocs.append(ioc)
            profile["indicators"] = existing + new_iocs
            profile["malware_bazaar_ioc_count"]  = len(new_iocs)
            profile["malware_bazaar_family_hits"] = result.get("family_hits", {})
            logger.info("MalwareBazaar: added %d sample hashes", len(new_iocs))

        elif source_key == "urlhaus":
            malware_names = [
                m.get("name", "")
                for m in (profile.get("malware") or [])
                if m.get("name")
            ]
            if not malware_names:
                return profile
            abusech_key = os.environ.get("ABUSECH_API_KEY", "")
            if abusech_key:
                enricher_inst = _load_class(enricher_path)(api_key=abusech_key)
            else:
                enricher_inst = enricher
            result = enricher_inst.collect_for_malware_families(
                malware_names, profile.get("actor_name", "")
            )
            if not result:
                return profile
            existing = profile.get("indicators", [])
            seen = {
                f"{i.get('type','')}:{i.get('value','').lower()}"
                for i in existing
            }
            new_iocs = []
            for ioc in (result.get("indicators") or []):
                key = f"{ioc.get('type','')}:{ioc.get('value','').lower()}"
                if key not in seen:
                    seen.add(key)
                    new_iocs.append(ioc)
            profile["indicators"] = existing + new_iocs
            profile["urlhaus_ioc_count"]  = len(new_iocs)
            profile["urlhaus_family_hits"] = result.get("family_hits", {})
            logger.info("URLhaus: added %d distribution URLs", len(new_iocs))

        elif source_key == "yara":
            malware_names = [
                m.get("name", "")
                for m in (profile.get("malware") or [])
                if m.get("name")
            ]
            if not malware_names:
                return profile
            yara_map = enricher.collect_for_malware_families(malware_names)
            if not yara_map:
                return profile
            # Attach YARA rules to matching malware entries
            for m in (profile.get("malware") or []):
                name = (m.get("name") or "")
                rules = yara_map.get(name, [])
                if rules:
                    m["yara_rules"]      = rules
                    m["yara_rule_count"] = len(rules)
            profile["yara_rule_count"] = sum(len(v) for v in yara_map.values())
            logger.info(
                "YARA: enriched %d families with %d rules",
                len(yara_map), profile["yara_rule_count"],
            )

        elif source_key == "greynoise":
            gn_key = os.environ.get("GREYNOISE_API_KEY", "")
            if gn_key:
                enricher_inst = _load_class(enricher_path)(api_key=gn_key)
            else:
                enricher_inst = enricher
            gn_context = enricher_inst.enrich_ips(
                profile.get("indicators", []),
                profile.get("actor_name", ""),
            )
            if gn_context:
                # Annotate each IP indicator with GreyNoise context
                for ioc in (profile.get("indicators") or []):
                    if ioc.get("type") == "ip":
                        ctx = gn_context.get(ioc.get("value", ""))
                        if ctx:
                            ioc["greynoise"] = ctx
                profile["greynoise_enriched"] = len(gn_context)
                benign = sum(
                    1 for c in gn_context.values()
                    if c.get("riot") or c.get("classification") == "benign"
                )
                logger.info(
                    "GreyNoise: enriched %d IPs (%d benign/RIOT)",
                    len(gn_context), benign,
                )

        elif source_key == "abuseipdb":
            aipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")
            if aipdb_key:
                enricher_inst = _load_class(enricher_path)(api_key=aipdb_key)
            else:
                enricher_inst = enricher
            aipdb_context = enricher_inst.enrich_ips(
                profile.get("indicators", []),
                profile.get("actor_name", ""),
            )
            if aipdb_context:
                for ioc in (profile.get("indicators") or []):
                    if ioc.get("type") == "ip":
                        ctx = aipdb_context.get(ioc.get("value", ""))
                        if ctx:
                            ioc["abuseipdb"] = ctx
                profile["abuseipdb_enriched"] = len(aipdb_context)
                high_abuse = sum(
                    1 for c in aipdb_context.values()
                    if c.get("abuse_confidence_score", 0) >= 75
                )
                logger.info(
                    "AbuseIPDB: enriched %d IPs (%d high-abuse)",
                    len(aipdb_context), high_abuse,
                )

    except Exception as exc:
        logger.error("Enrichment %r failed: %s", source_key, exc)
    return profile


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run(
    actor:          str,
    sources:        list[str],
    output:         str  = "dossier",
    save:           bool = True,
    verbose:        bool = False,
    sector:         str  = "",
    detection_path: str  = "",
    **kwargs: Any,
) -> dict[str, Any] | None:

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Disable progress bar in verbose mode — log output and Rich live display
    # conflict and produce garbled multi-line output when both run together.
    progress = None if verbose else _make_progress()

    # ── 1. Collect & map ──────────────────────────────────────────────
    collect_sources  = [s for s in sources if s not in ENRICHMENT_SOURCES]
    enrich_sources   = [s for s in sources if s in ENRICHMENT_SOURCES]
    raw_records: list[dict] = []

    if progress:
        with progress:
            task = progress.add_task(
                f"Collecting intelligence for [bold]{actor}[/]…",
                total=len(collect_sources),
            )
            for source_key in collect_sources:
                progress.update(task, description=f"Querying [cyan]{source_key}[/]…")
                record = _collect_and_map(actor, source_key)
                if record:
                    raw_records.append(record)
                progress.advance(task)
    else:
        for source_key in collect_sources:
            record = _collect_and_map(actor, source_key)
            if record:
                raw_records.append(record)

    if not raw_records:
        print(f"\n[theory] No data found for actor: {actor!r}", file=sys.stderr)
        try:
            from collectors.cisa_advisories import suggest_similar
            suggestions = suggest_similar(actor)
        except Exception:
            suggestions = []
        if suggestions:
            print(f"[theory] Did you mean: {', '.join(suggestions)}?", file=sys.stderr)
        print("[theory] Try --list-actors to see supported actors, or check your source keys with --list-sources.\n",
              file=sys.stderr)
        return None

    # ── 2. Normalise ──────────────────────────────────────────────────
    _normalize  = _load_normalize_fn()
    normalised: list[dict] = []
    for record in raw_records:
        try:
            normalised.append(_normalize(record))
        except Exception as exc:
            logger.warning("Normalizer rejected a record: %s", exc)

    if not normalised:
        print("[theory] All records failed normalisation.", file=sys.stderr)
        return None

    # ── 3. Deduplicate ────────────────────────────────────────────────
    from processors.deduplicator import deduplicate
    profile = deduplicate(normalised)

    # Remap normalizer field names → reporter field names
    if not profile.get("origin") and profile.get("suspected_origin"):
        profile["origin"] = profile["suspected_origin"]
    if not profile.get("motivations"):
        raw_mot = profile.get("motivation")
        if raw_mot:
            profile["motivations"] = [raw_mot] if isinstance(raw_mot, str) else list(raw_mot)
    if not profile.get("sectors") and profile.get("target_sectors"):
        profile["sectors"] = profile["target_sectors"]

    # Restore technique metadata stripped by normalizer
    _technique_meta: dict[str, dict] = {}
    for raw in raw_records:
        for t in (raw.get("techniques") or []):
            tid = (t.get("technique_id") or "").strip().upper()
            if tid and tid not in _technique_meta:
                _technique_meta[tid] = {
                    "technique_name": t.get("technique_name", ""),
                    "detection":      t.get("detection", ""),
                    "tactic":         t.get("tactic", ""),
                }
    for t in (profile.get("techniques") or []):
        tid  = (t.get("technique_id") or "").upper()
        meta = _technique_meta.get(tid, {})
        if not t.get("name") and meta.get("technique_name"):
            t["name"] = meta["technique_name"]
        if not t.get("detection_recs") and meta.get("detection"):
            t["detection_recs"] = [meta["detection"]]
        t["technique_name"] = t.get("name") or meta.get("technique_name", "")
        t["detection"]      = (t.get("detection_recs") or [meta.get("detection", "")])[0]
        if not t.get("tactic") and meta.get("tactic"):
            t["tactic"] = meta["tactic"]

    # Pass through CISA/OTX/ThreatFox enrichments
    all_cves: list = []; all_advisories: list = []; all_sectors: list = []; all_iocs: list = []
    seen_cves: set[str] = set(); seen_adv: set[str] = set()
    seen_sect: set[str] = set(); seen_iocs: set[str] = set()
    for raw in raw_records:
        for cve in (raw.get("cves") or []):
            cid = cve.get("cve_id", "")
            if cid and cid not in seen_cves:
                seen_cves.add(cid); all_cves.append(cve)
        for adv in (raw.get("advisories") or []):
            key = adv.get("url") or adv.get("title", "")
            if key and key not in seen_adv:
                seen_adv.add(key); all_advisories.append(adv)
        for s in (raw.get("sectors") or []):
            if s and s.lower() not in seen_sect:
                seen_sect.add(s.lower()); all_sectors.append(s)
        for ioc in (raw.get("indicators") or []):
            key = f"{ioc.get('type','')}:{ioc.get('value','').lower()}"
            if key not in seen_iocs:
                seen_iocs.add(key); all_iocs.append(ioc)

    if all_cves:        profile["cves"]       = all_cves
    if all_advisories:  profile["advisories"]  = all_advisories
    if all_sectors and not profile.get("sectors"): profile["sectors"] = all_sectors
    if all_iocs:        profile["indicators"]  = all_iocs

    # ── CISA KEV cross-reference ──────────────────────────────────────
    # If cisa_kev was in the sources list, enrich all CVEs (regardless of
    # which source reported them) with confirmed-exploited flags,
    # ransomware attribution, vendor/product metadata, and remediation
    # dates from the KEV catalog.
    if "cisa_kev" in collect_sources and profile.get("cves"):
        try:
            from collectors.cisa_kev import enrich_profile_with_kev
            profile = enrich_profile_with_kev(profile)
            logger.info(
                "KEV enrichment: %d/%d CVEs confirmed, %d ransomware-flagged",
                profile.get("kev_confirmed_count", 0),
                len(profile.get("cves", [])),
                profile.get("kev_ransomware_count", 0),
            )
        except Exception as exc:
            logger.warning("CISA KEV enrichment failed: %s", exc)

    # ── NVD cross-reference ───────────────────────────────────────────
    # If nvd was in the sources list, enrich all CVEs (regardless of
    # which source reported them) with CVSS scores/vectors, CWE
    # classification, and reference links from the NVD API.
    if "nvd" in collect_sources and profile.get("cves"):
        try:
            from collectors.nvd import enrich_profile_with_nvd
            profile = enrich_profile_with_nvd(profile)
            logger.info(
                "NVD enrichment: %d/%d CVEs enriched with CVSS/CWE detail",
                profile.get("nvd_enriched_count", 0),
                len(profile.get("cves", [])),
            )
        except Exception as exc:
            logger.warning("NVD enrichment failed: %s", exc)

    # Malpedia malware enrichment
    malpedia_meta: dict[str, dict] = {}
    for raw in raw_records:
        if raw.get("source_id") == "malpedia":
            for m in (raw.get("malware") or []):
                name = (m.get("name") or "").lower()
                if name: malpedia_meta[name] = m
    for m in (profile.get("malware") or []):
        name = (m.get("name") or "").lower()
        meta = malpedia_meta.get(name, {})
        if meta.get("aliases")    and not m.get("aliases"):    m["aliases"]    = meta["aliases"]
        if meta.get("yara_count") and not m.get("yara_count"): m["yara_count"] = meta["yara_count"]
        if meta.get("description") and not m.get("description"): m["description"] = meta["description"]

    # Metadata
    if not profile.get("origin") or not profile.get("motivations"):
        for raw in raw_records:
            if not profile.get("origin") and raw.get("origin"):
                profile["origin"] = raw["origin"]
            if not profile.get("motivations") and raw.get("motivations"):
                profile["motivations"] = raw["motivations"]

    profile["sources_cited"] = list({r.get("source_id", "unknown") for r in normalised})
    for r in raw_records:
        if r.get("mitre_id") or r.get("mitre_group_id"):
            profile["mitre_group_id"] = r.get("mitre_id") or r.get("mitre_group_id")
            break

    # ── 4. Enrichment (Sigma + ThreatFox) ────────────────────────────
    for source_key in enrich_sources:
        if source_key == "sigma" and progress:
            tids = [t.get("technique_id","") for t in (profile.get("techniques") or []) if t.get("technique_id")]
            with progress:
                task = progress.add_task(
                    f"Fetching Sigma rules for [bold]{len(tids)} techniques[/]…",
                    total=len(tids),
                )
                # Monkey-patch the sigma collector to update progress
                _orig_fetch = None
                try:
                    from collectors import sigma_rules as _sm
                    _orig_fetch = _sm.SigmaCollector._find_rules_for_technique
                    def _patched(self, tid):
                        result = _orig_fetch(self, tid)
                        progress.advance(task)
                        return result
                    _sm.SigmaCollector._find_rules_for_technique = _patched
                    profile = _enrich_profile(profile, source_key)
                finally:
                    if _orig_fetch:
                        _sm.SigmaCollector._fetch_rules_for_technique = _orig_fetch
        elif source_key == "vendor":
            profile = _enrich_profile(profile, source_key)
        else:
            profile = _enrich_profile(profile, source_key)

    # ── 5. LLM Actor Overview ────────────────────────────────────────
    # Generate a synthesized actor synopsis using the full profile.
    # Works with or without vendor intel — uses all available data.
    # Uses the name the user actually queried, not the canonical alias.
    try:
        from collectors.intelligence_synthesizer import (
            IntelligenceSynthesizer, load_provider,
        )
        _provider = load_provider()
        if _provider and _provider.available:
            _synth   = IntelligenceSynthesizer(_provider)
            _overview = _synth.synthesize_overview(
                profile      = profile,
                queried_name = actor,   # the name the user typed
            )
            if _overview:
                profile["actor_overview"] = _overview
                logger.info("Actor overview synthesized (%d chars)", len(_overview))
        else:
            logger.debug("No LLM provider — skipping actor overview")
    except Exception as _exc:
        logger.warning("Actor overview synthesis failed: %s", _exc)

    # ── 5½. Correlation ──────────────────────────────────────────────
    # Cross-reference all enriched data: techniques ↔ malware ↔ IOCs ↔
    # CVEs ↔ Sigma/YARA. Produces profile["correlations"] with linked
    # intelligence, kill chain view, priority actions, and coverage stats.
    try:
        from processors.correlator import correlate
        profile = correlate(profile)
        logger.info(
            "Correlation: %d priority actions, %d%% detection coverage",
            len(profile.get("correlations", {}).get("priority_actions", [])),
            profile.get("correlations", {}).get("coverage", {}).get("coverage_pct", 0),
        )
    except Exception as _exc:
        logger.warning("Correlation engine failed: %s", _exc)

    # ── 5¾. Persistent correlation graph ─────────────────────────────
    # Fold this run's entities (actor, IOCs, techniques, malware, CVEs,
    # campaigns) into the local cross-run graph at output/graph/graph.json.
    # This is what makes `theory --ioc`, `theory --technique`, and
    # multi-flag connection queries (`theory --actor X --ioc Y`) possible —
    # without it, every run would be an island with no memory of any
    # other. Disable with --no-graph if you don't want this run recorded
    # (e.g. one-off/throwaway queries, or researching something sensitive
    # you don't want persisted even locally).
    if not kwargs.get("no_graph"):
        try:
            from processors.graph import ingest_profile
            ingest_profile(profile)
        except Exception as _exc:
            logger.warning("Graph ingestion failed: %s", _exc)

    # ── 6. Output ─────────────────────────────────────────────────────
    if output == "json":
        _output_json(profile, save)
    elif output == "stix":
        _output_stix(profile, save)
    elif output == "csv":
        _output_csv(profile, save)
    elif output == "exec":
        _output_exec(profile, save, sector=sector)
    elif output == "navigator":
        _output_navigator(profile, save)
    elif output == "playbook":
        _output_playbook(profile, save,
                         sector=sector,
                         playbook_format=kwargs.get("playbook_format", "markdown"))
    elif output == "html":
        _output_html(profile, save)
    elif output == "all":
        _output_dossier(profile, save)
        _output_json(profile, save)
        _output_stix(profile, save)
        _output_csv(profile, save)
        _output_navigator(profile, save)
        _output_html(profile, save)
    else:
        _output_dossier(profile, save)

    # Coverage gap — runs after any output if --detection-path set
    if detection_path:
        _output_coverage_gap(profile, detection_path, save)

    return profile


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _output_dossier(profile: dict[str, Any], save: bool) -> None:
    from reporters.dossier import DossierReporter
    reporter = DossierReporter()
    reporter.render(profile)
    if save:
        path = reporter.save_markdown(profile)
        print(f"\n[theory] Dossier saved → {path}")


def _output_stix(profile: dict[str, Any], save: bool) -> None:
    import signal
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except AttributeError:
        pass
    from reporters.stix_reporter import StixReporter
    clean  = _sanitize_profile(profile)
    bundle = StixReporter().build_bundle(clean)
    try:
        print(json.dumps(bundle, indent=2, default=str))
    except BrokenPipeError:
        pass
    if save:
        path = StixReporter().save(clean)
        print(f"\n[theory] STIX bundle saved → {path}", file=sys.stderr)


def _output_csv(profile: dict[str, Any], save: bool) -> None:
    from reporters.csv_reporter import CsvReporter
    reporter = CsvReporter()
    clean    = _sanitize_profile(profile)
    try:
        print(reporter.to_string(clean))
    except BrokenPipeError:
        pass
    if save:
        path = reporter.save(clean)
        print(f"\n[theory] IOC CSV saved → {path}", file=sys.stderr)


def _output_json(profile: dict[str, Any], save: bool) -> None:
    clean = _sanitize_profile(profile)
    try:
        print(json.dumps(clean, indent=2, default=str))
    except BrokenPipeError:
        pass
    if save:
        from reporters.json_reporter import JsonReporter
        path = JsonReporter().save(clean)
        print(f"\n[theory] JSON saved → {path}", file=sys.stderr)



def _output_navigator(profile: dict[str, Any], save: bool) -> None:
    """
    Export an ATT&CK Navigator layer (v4.5) from the actor profile.
    Color-coded by confidence: HIGH=red, MEDIUM=amber, LOW=yellow.
    Importable directly into https://mitre-attack.github.io/attack-navigator/
    """
    from reporters.navigator_reporter import NavigatorReporter
    reporter = NavigatorReporter()
    clean    = _sanitize_profile(profile)
    try:
        print(reporter.to_string(clean))
    except BrokenPipeError:
        pass
    if save:
        path = reporter.save(clean)
        try:
            from rich.console import Console
            Console(stderr=True).print(
                f"[dim][theory] Navigator layer saved → {path}[/dim]\n"
                f"[dim]  Import at: https://mitre-attack.github.io/attack-navigator/[/dim]"
            )
        except ImportError:
            print(f"\n[theory] Navigator layer saved → {path}", file=sys.stderr)


def _output_coverage_gap(
    profile: dict[str, Any],
    detection_path: str,
    save: bool,
) -> None:
    """
    Compare actor TTPs against a local detection repo and report gaps.
    Pass --detection-path /path/to/your/sigma/rules to use.

    Reports:
      - Coverage %  (how many of the actor's TTPs have a local rule)
      - Covered     (techniques you can already detect)
      - Gap         (techniques with no local detection — sorted by confidence)
    """
    import subprocess
    from pathlib import Path as _Path

    try:
        from rich.console import Console
        from rich.table   import Table
        from rich         import box as rich_box
        console = Console()
        _rich   = True
    except ImportError:
        console = None
        _rich   = False

    det_path = _Path(detection_path)
    if not det_path.exists():
        msg = f"[theory] Detection path not found: {detection_path}"
        print(msg, file=sys.stderr)
        return

    actor_name = profile.get("actor_name", "Unknown Actor")
    techniques = profile.get("techniques", [])

    if not techniques:
        print("[theory] No techniques in profile — run with mitre source.", file=sys.stderr)
        return

    # For each technique, grep the detection path for the technique ID
    covered:  list[dict] = []
    gaps:     list[dict] = []

    for t in sorted(techniques, key=lambda x: x.get("technique_id", "")):
        tid  = (t.get("technique_id") or "").strip().upper()
        if not tid:
            continue
        try:
            result = subprocess.run(
                ["grep", "-rl", "--include=*.yml", "--include=*.yaml",
                 tid.lower(), str(det_path)],
                capture_output=True, text=True, timeout=10,
            )
            has_rule = bool(result.stdout.strip())
        except Exception:
            has_rule = False

        entry = {
            "technique_id":   tid,
            "technique_name": t.get("technique_name") or t.get("name", ""),
            "tactic":         t.get("tactic", ""),
            "confidence":     (t.get("confidence") or "LOW").upper(),
        }

        if has_rule:
            covered.append(entry)
        else:
            gaps.append(entry)

    total    = len(covered) + len(gaps)
    pct      = round((len(covered) / total) * 100) if total else 0

    # Sort gaps: HIGH confidence first (most important to fix)
    conf_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    gaps.sort(key=lambda x: (conf_order.get(x["confidence"], 3), x["technique_id"]))

    if _rich and console:
        console.print()
        console.print(f"[bold cyan]Detection Coverage Gap Analysis — {actor_name}[/]")
        console.print(f"[dim]Detection path: {detection_path}[/dim]")
        console.print()

        # Summary bar
        bar_filled  = int(pct / 5)
        bar_empty   = 20 - bar_filled
        color       = "green" if pct >= 70 else "yellow" if pct >= 40 else "red"
        bar         = f"[{color}]{'█' * bar_filled}[/][dim]{'░' * bar_empty}[/]"
        console.print(
            f"  Coverage: {bar} [{color}]{pct}%[/]  "
            f"({len(covered)}/{total} techniques)"
        )
        console.print()

        if gaps:
            console.print(f"[bold red]Coverage Gaps ({len(gaps)} techniques)[/]")
            gap_table = Table(
                "Technique ID", "Name", "Tactic", "Confidence",
                box=rich_box.SIMPLE_HEAD, header_style="bold magenta",
            )
            for g in gaps:
                conf     = g["confidence"]
                conf_fmt = {
                    "HIGH":   "[red]HIGH[/]",
                    "MEDIUM": "[yellow]MED[/]",
                    "LOW":    "[dim]LOW[/]",
                }.get(conf, conf)
                gap_table.add_row(
                    g["technique_id"],
                    g["technique_name"],
                    g["tactic"],
                    conf_fmt,
                )
            console.print(gap_table)
            console.print()

        if covered:
            console.print(f"[bold green]Covered ({len(covered)} techniques)[/]")
            cov_table = Table(
                "Technique ID", "Name", "Tactic",
                box=rich_box.SIMPLE_HEAD, header_style="bold magenta",
            )
            for c in covered:
                cov_table.add_row(
                    c["technique_id"],
                    c["technique_name"],
                    c["tactic"],
                )
            console.print(cov_table)
            console.print()
    else:
        print(f"\nDetection Coverage — {actor_name}: {pct}% ({len(covered)}/{total})")
        print(f"Gaps ({len(gaps)}):")
        for g in gaps:
            print(f"  {g['technique_id']} [{g['confidence']}] {g['technique_name']}")

    if save:
        import re as _re
        OUTPUT_DIR = _Path("output/dossiers")
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        slug = _re.sub(r"[^a-z0-9]", "_", actor_name.lower())
        path = OUTPUT_DIR / f"{slug}_coverage_gap.md"

        lines = [
            f"# Detection Coverage Gap Analysis — {actor_name}",
            f"> Coverage: **{pct}%** ({len(covered)}/{total} techniques covered)",
            f"> Detection path: `{detection_path}`",
            f"> Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "",
        ]

        if gaps:
            lines += [
                f"## Coverage Gaps ({len(gaps)} techniques)",
                "",
                "| Technique ID | Name | Tactic | Confidence |",
                "|---|---|---|---|",
            ]
            for g in gaps:
                lines.append(
                    f"| {g['technique_id']} | {g['technique_name']} "
                    f"| {g['tactic']} | {g['confidence']} |"
                )
            lines.append("")

        if covered:
            lines += [
                f"## Covered ({len(covered)} techniques)",
                "",
                "| Technique ID | Name | Tactic |",
                "|---|---|---|",
            ]
            for c in covered:
                lines.append(
                    f"| {c['technique_id']} | {c['technique_name']} | {c['tactic']} |"
                )
            lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        if _rich and console:
            console.print(f"[dim][theory] Coverage gap report saved → {path}[/dim]")
        else:
            print(f"[theory] Coverage gap report saved → {path}")


def _output_playbook(
    profile:         dict[str, Any],
    save:            bool,
    sector:          str = "",
    playbook_format: str = "markdown",
) -> None:
    """
    Generate and save an IR playbook from the actor profile.
    Prints a compact summary to terminal; saves the full playbook to file.
    """
    from reporters.playbook_reporter import PlaybookReporter

    # Try to load LLM provider for hunt/containment sections
    llm_provider = None
    try:
        from collectors.intelligence_synthesizer import load_provider
        llm_provider = load_provider()
        if llm_provider and not llm_provider.available:
            llm_provider = None
    except Exception:
        pass

    reporter = PlaybookReporter()
    clean    = _sanitize_profile(profile)

    if save:
        path = reporter.save(clean, sector=sector,
                             playbook_format=playbook_format,
                             llm_provider=llm_provider)
        reporter.summary(clean, path)
    else:
        # --no-save: print to stdout
        content = reporter.build(clean, sector=sector,
                                 playbook_format=playbook_format,
                                 llm_provider=llm_provider)
        try:
            print(content)
        except BrokenPipeError:
            pass


def _output_html(profile: dict[str, Any], save: bool) -> None:
    """Generate a self-contained HTML dossier."""
    from reporters.html_reporter import HtmlReporter
    reporter = HtmlReporter()
    clean    = _sanitize_profile(profile)
    if save:
        path = reporter.save(clean)
        try:
            from rich.console import Console
            Console(stderr=True).print(
                f"[dim][theory] HTML dossier saved → {path}[/dim]\n"
                f"[dim]  Open in any browser — no server required.[/dim]"
            )
        except ImportError:
            print(f"\n[theory] HTML dossier saved → {path}", file=sys.stderr)
    else:
        try:
            print(reporter.build(clean))
        except BrokenPipeError:
            pass

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

EPILOG = """
examples:
  theory --actor APT28
  theory --actor "Fancy Bear" --sources mitre,malpedia,misp_galaxy,otx
  theory --actor Lazarus --sources mitre,malpedia,misp_galaxy,cisa_kev,otx,sigma,threatfox
  theory --actor APT41 --sources mitre,otx --output stix
  theory --actor APT28 --sources mitre,otx,threatfox --output csv
  theory --actor Turla --sources mitre,malpedia,misp_galaxy,cisa_kev --output all
  theory --actor APT29 --sources mitre --no-save
  theory --actor APT28 --output exec
  theory --actor "Lazarus Group" --output exec --sector finance
  theory --actor APT28 --output navigator
  theory --actor APT28 --sources mitre,sigma --output playbook
  theory --actor APT28 --sources mitre,sigma --output playbook --playbook-format jira
  theory --actor APT28 --sources mitre,malpedia,misp_galaxy,cisa_kev,otx --output html
  theory --actor APT28 --sources mitre,sigma --detection-path ~/my-sigma-rules
  theory --list-sources
  theory --list-actors
  theory --update-bundles

notes:
  - --actor accepts any name or alias (e.g. "Cozy Bear" = APT29 = Midnight Blizzard)
  - Run --update-bundles periodically to refresh ATT&CK data, Sigma rules, MISP Galaxy, and CISA KEV
  - See docs/SCHEDULED_UPDATES.md to automate updates with cron or launchd
  - First run with --sources sigma takes ~10 min to build the cache (instant after)
  - Default sources: mitre,cisa,cisa_kev,malpedia,misp_galaxy (all keyless, free)
  - cisa_kev cross-references profile CVEs against 1600+ confirmed-exploited CVEs
  - Add otx for IOCs (free API key) and sigma for detection rule mapping
  - Set OTX_API_KEY and GITHUB_TOKEN in .env for best results
  - Output files are saved to output/dossiers/
"""


BANNER = r"""
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░
   ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░
"""

BANNER_SUBTITLE = (
    "  multi-source threat actor intelligence\n"
    "  open-source · free forever · built for the community\n"
    "  github.com/threatcraft-co/theory\n"
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="theory",
        description=(
            "THEORY — open-source multi-source threat actor intelligence framework.\n"
            "Generates analyst-grade dossiers from MITRE ATT&CK, MISP Galaxy, CISA KEV, Malpedia, OTX, Sigma, ThreatFox, and more."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Actor ──────────────────────────────────────────────────────────
    p.add_argument(
        "--actor", "-a",
        metavar="NAME",
        help=(
            'Threat actor name or any known alias. '
            'Examples: "APT28", "Fancy Bear", "Cozy Bear", "Lazarus Group", "Volt Typhoon". '
            'Use --list-actors to see all supported actors and their aliases.'
        ),
    )

    # ── Sources ────────────────────────────────────────────────────────
    source_keys = ", ".join(SOURCE_DESCRIPTIONS.keys())
    p.add_argument(
        "--sources", "-s",
        metavar="SOURCE[,SOURCE...]",
        default=DEFAULT_SOURCES,
        help=(
            f"Comma-separated intelligence sources. Available: {source_keys}. "
            f"Default: {DEFAULT_SOURCES}. "
            "Use --list-sources for details on each source."
        ),
    )

    # ── Output format ──────────────────────────────────────────────────
    p.add_argument(
        "--output", "-o",
        choices=["dossier", "json", "stix", "csv", "all", "exec", "navigator", "playbook", "html"],
        default="dossier",
        metavar="FORMAT",
        help=(
            "Output format. "
            "dossier = terminal + markdown file (default). "
            "json = raw profile JSON. "
            "stix = STIX 2.1 bundle for MISP/OpenCTI/Sentinel import. "
            "csv = IOC-only CSV table (for SIEM ingestion). "
            "all = write all formats. "
            "exec = non-technical executive summary (BLUF, requires LLM key). "
            "navigator = ATT&CK Navigator layer JSON. "
            "playbook = IR playbook checklist (markdown or Jira format). "
            "html = self-contained HTML dossier (shareable, opens in any browser)."
        ),
    )

    # ── Sector context (for exec output) ──────────────────────────────
    p.add_argument(
        "--sector",
        metavar="SECTOR",
        default="",
        help=(
            "Optional sector context for --output exec. "
            "Focuses the executive summary on your industry. "
            "Examples: energy, healthcare, finance, government, defence"
        ),
    )

    # ── Playbook format ───────────────────────────────────────────────
    p.add_argument(
        "--playbook-format",
        choices=["markdown", "jira"],
        default="markdown",
        metavar="FORMAT",
        help=(
            "Output format for --output playbook. "
            "markdown = GitHub/Confluence/Notion/ServiceNow compatible (default). "
            "jira = Jira wiki markup for direct paste into issue descriptions."
        ),
    )

    # ── Detection gap analysis ─────────────────────────────────────────
    p.add_argument(
        "--detection-path",
        metavar="PATH",
        default="",
        help=(
            "Path to your local Sigma detection rule directory. "
            "Enables coverage gap analysis — THEORY compares actor TTPs "
            "against your deployed rules and reports which techniques lack coverage."
        ),
    )

    # ── File saving ────────────────────────────────────────────────────
    p.add_argument(
        "--no-save",
        action="store_true",
        help="Print output to terminal only — do not write files to output/dossiers/.",
    )
    p.add_argument(
        "--no-graph",
        action="store_true",
        help=(
            "Don't record this run's entities (IOCs, techniques, malware, CVEs) "
            "in the local persistent correlation graph at output/graph/graph.json."
        ),
    )

    # ── Cross-run query modes ────────────────────────────────────────────
    # These query the persistent correlation graph (processors/graph.py)
    # built up from every prior `theory --actor` run — not just the data
    # collected in the current invocation.
    #
    #   theory --ioc 1.1.1.1              -> standalone IOC lookup
    #   theory --technique T1566          -> standalone technique lookup
    #   theory --actor APT28 --ioc 1.1.1.1
    #       -> a single cross-correlative question: is THIS actor
    #          connected to THIS IOC in anything THEORY has ever
    #          recorded — not two independent reports stapled together.
    query = p.add_argument_group("cross-run graph queries")
    query.add_argument(
        "--ioc",
        metavar="VALUE",
        default="",
        help=(
            "Query the persistent correlation graph for an indicator (IP, domain, "
            "hash, URL, email) across every past `theory --actor` run. "
            "Combine with --actor to ask whether that actor is connected to this IOC."
        ),
    )
    query.add_argument(
        "--technique",
        metavar="ID",
        default="",
        help=(
            "Query the persistent correlation graph for an ATT&CK technique ID "
            "(e.g. T1566) across every past `theory --actor` run. "
            "Combine with --actor to ask whether that actor is connected to this technique."
        ),
    )
    query.add_argument(
        "--attack-type",
        metavar="LABEL",
        default="",
        help=(
            "Query the persistent correlation graph for an attack-type label "
            "(e.g. ransomware, espionage, financial) matched against recorded actor "
            "motivations and malware types. Combine with --actor to check whether "
            "that actor matches this attack type."
        ),
    )

    # ── Verbosity ──────────────────────────────────────────────────────
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging. Shows which sources are queried and what data is returned.",
    )

    # ── Info commands ──────────────────────────────────────────────────
    info = p.add_argument_group("information commands (no actor required)")
    info.add_argument(
        "--list-sources",
        action="store_true",
        help="Show all available intelligence sources with auth requirements and cache info.",
    )
    info.add_argument(
        "--list-actors",
        action="store_true",
        help="Show all actors with built-in cross-source alias resolution.",
    )
    info.add_argument(
        "--update-bundles",
        action="store_true",
        help=(
            "Refresh the local ATT&CK STIX bundle and Sigma rules. "
            "Run periodically to stay current with new ATT&CK releases and Sigma rules."
        ),
    )
    info.add_argument(
        "--init-personal",
        action="store_true",
        help=(
            "Set up the personal research redirect: a gitignored config/local_sources.yaml "
            "pointing at a private indicators file (default: ~/.theory/personal_indicators.yaml, "
            "outside this repo). Then use --sources personal to query it alongside any actor."
        ),
    )
    info.add_argument(
        "--personal-path",
        metavar="PATH",
        default="",
        help=(
            "Use with --init-personal to point the redirect at a custom path instead of "
            "the default ~/.theory/personal_indicators.yaml."
        ),
    )

    return p


def _print_banner() -> None:
    try:
        from rich.console import Console
        c = Console(stderr=True)
        c.print(f"[cyan]{BANNER}[/cyan]", end="")
        c.print(f"[dim]{BANNER_SUBTITLE}[/dim]")
    except ImportError:
        import sys
        print(BANNER, file=sys.stderr)
        print(BANNER_SUBTITLE, file=sys.stderr)


def main(argv: list[str] | None = None) -> None:
    # ── `theory serve` — intercept before argparse ────────────────────
    # Serve is a separate command, not a flag, so we catch it early.
    _args = argv if argv is not None else sys.argv[1:]
    if _args and _args[0] == "serve":
        from server.cli_serve import cmd_serve
        cmd_serve(_args[1:])
        return

    # ── `theory ask "<question>"` — tool-calling LLM synthesis ─────────
    # Answers a natural-language question using only THEORY's own local
    # data (the persistent correlation graph + personal research notes),
    # via the provider-agnostic tool loop in collectors/intelligence_agent.py.
    if _args and _args[0] == "ask":
        cmd_ask(_args[1:])
        return

    _print_banner()
    parser = _build_parser()
    args   = parser.parse_args(argv)

    # ── Info commands (no --actor needed) ─────────────────────────────
    if args.list_sources:
        cmd_list_sources()
        return

    if args.list_actors:
        cmd_list_actors()
        return

    if args.update_bundles:
        cmd_update_bundles()
        return

    if args.init_personal:
        cmd_init_personal(args.personal_path or None)
        return

    # ── Standalone cross-run graph queries (no --actor) ────────────────
    # `theory --ioc VALUE` / `theory --technique ID` / `theory --attack-type
    # LABEL` on their own query the persistent correlation graph built up
    # from every past `theory --actor` run — they don't collect anything
    # new themselves.
    if not args.actor and (args.ioc or args.technique or args.attack_type):
        found = True
        if args.ioc:
            found = cmd_query_ioc(args.ioc) and found
        if args.technique:
            found = cmd_query_technique(args.technique) and found
        if args.attack_type:
            found = cmd_query_attack_type(args.attack_type) and found
        sys.exit(0 if found else 1)

    # ── Require --actor for everything else ───────────────────────────
    if not args.actor:
        parser.print_help()
        print("\nerror: --actor is required (or use --ioc / --technique / --attack-type "
              "for a standalone graph lookup). Try: theory --actor APT28\n")
        sys.exit(1)

    sources = [s.strip().lower() for s in args.sources.split(",") if s.strip()]

    # Validate sources
    unknown = [s for s in sources if s not in SUPPORTED_SOURCES]
    if unknown:
        print(f"\n[theory] Unknown source(s): {', '.join(unknown)}")
        print(f"[theory] Available: {', '.join(SUPPORTED_SOURCES.keys())}")
        print("[theory] Run --list-sources for details.\n")
        sys.exit(1)

    # Hint: let users know OTX is available if not in their sources
    if "otx" not in sources:
        try:
            from rich.console import Console as _C
            _C(stderr=True).print(
                "[dim]💡 Tip: add [cyan]otx[/cyan] to --sources for community IOC data "
                "(requires OTX_API_KEY in .env — free at otx.alienvault.com)[/dim]"
            )
        except ImportError:
            pass  # skip hint if Rich not available

    profile = run(
        actor            = args.actor,
        sources          = sources,
        output           = args.output,
        save             = not args.no_save,
        verbose          = args.verbose,
        sector           = args.sector,
        detection_path   = args.detection_path,
        playbook_format  = args.playbook_format,
        no_graph         = args.no_graph,
    )

    # ── Multi-flag cross-correlative query ─────────────────────────────
    # `theory --actor X --ioc Y` (or --technique) is one combined
    # question — is X connected to Y in anything THEORY has recorded —
    # not the actor dossier and a separate IOC report stapled together.
    # Runs after the actor pipeline so this run's own data has already
    # been folded into the graph and is available to the connection query.
    if profile and (args.ioc or args.technique):
        if args.ioc:
            cmd_find_connection(("actor", args.actor), ("ioc", args.ioc))
        if args.technique:
            cmd_find_connection(("actor", args.actor), ("technique", args.technique))

    if profile and args.attack_type:
        cmd_check_attack_type(args.actor, args.attack_type)

    sys.exit(0 if profile else 1)


if __name__ == "__main__":  # pragma: no cover
    main()
