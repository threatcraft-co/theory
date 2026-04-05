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
  python theory.py --actor APT28 --sources mitre,malpedia,otx,sigma,threatfox

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
    "mitre":     "collectors.mitre_attack.MitreAttackCollector",
    "cisa":      "collectors.cisa_advisories.CisaAdvisoriesCollector",
    "malpedia":  "collectors.malpedia.MalpediaCollector",
    "otx":       "collectors.alienvault_otx.AlienVaultOTXCollector",
    # Enrichment-only — accepted by CLI but handled separately
    "sigma":     None,
    "threatfox": None,
    "vendor":    None,   # vendor intelligence synthesis (requires LLM provider)
}

SOURCE_DESCRIPTIONS: dict[str, str] = {
    "mitre":     "MITRE ATT&CK — techniques, malware, campaigns (local bundle, offline)",
    "cisa":      "CISA advisories + KEV catalog (free, no auth)",
    "malpedia":  "Malpedia malware family database (free, no auth)",
    "otx":       "AlienVault OTX pulses + IOCs (free, requires OTX_API_KEY in .env)",
    "sigma":     "SigmaHQ detection rules mapped to ATT&CK (free, optional GITHUB_TOKEN)",
    "threatfox": "ThreatFox IOCs by malware family (free, no auth)",
    "vendor":    "Vendor intelligence synthesis — LLM-synthesized summaries from 35+ research blogs (requires LLM provider in .env)",
}

SOURCE_REQUIRES: dict[str, str] = {
    "otx":    "OTX_API_KEY",
    "sigma":  "GITHUB_TOKEN (optional, recommended)",
    "vendor": "ANTHROPIC_API_KEY or OPENAI_API_KEY or Ollama running locally",
}

ENRICHMENT_SOURCES: dict[str, str] = {
    "sigma":       "collectors.sigma_rules.SigmaCollector",
    "threatfox":   "collectors.threatfox.ThreatFoxCollector",
    "vendor":      "collectors.vendor_intel.VendorIntelCollector",
}

MAPPER_REGISTRY: dict[str, str] = {
    "mitre":    "mappers.mitre.MitreMapper",
    "cisa":     "mappers.cisa.CisaMapper",
    "malpedia": "collectors.malpedia.MalpediaMapper",
    "otx":      "collectors.alienvault_otx.AlienVaultOTXMapper",
}

# Default source combination — good balance of coverage vs speed
DEFAULT_SOURCES = "mitre,cisa,malpedia"


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
            "mitre":     "7 days (.cache/enterprise-attack.json)",
            "cisa":      "per request",
            "malpedia":  "per request (.cache/malpedia/)",
            "otx":       "per request (.cache/otx/)",
            "sigma":     "7 days (.cache/sigma/)",
            "threatfox": "24 hours (.cache/threatfox/)",
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

    # 2. Update Sigma repo (git pull)
    sigma_repo = Path(".cache/sigma-repo")
    if sigma_repo.exists():
        _print("  Updating Sigma rules (git pull)…", "dim")
        import subprocess as _sp
        result = _sp.run(
            ["git", "-C", str(sigma_repo), "pull", "--depth=1"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            _print("  ✓ Sigma rules updated", "green")
        else:
            _print(f"  ✗ Sigma pull failed: {result.stderr[:100]}", "red")
    else:
        _print("  ✓ Sigma repo not yet cloned — will clone on next --sources sigma run", "dim")

    # 3. ThreatFox cache — let 24hr TTL handle expiry naturally
    _print("  ✓ ThreatFox cache preserved (24hr TTL handles expiry automatically)", "dim")

    # 4. Clone/update CyberMonitor APT Campaign Collection (historical context)
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

    # 5. Leave Malpedia + OTX caches — per-family/per-pulse, expensive to rebuild
    _print("\n  Malpedia + OTX caches preserved (clear manually if needed).", "dim")
    _print("  Run THEORY normally to rebuild Sigma + ThreatFox caches.\n", "dim")
    _print("Update complete.\n", "bold green")


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
    elif output == "all":
        _output_dossier(profile, save)
        _output_json(profile, save)
        _output_stix(profile, save)
        _output_csv(profile, save)
        _output_navigator(profile, save)
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

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

EPILOG = """
examples:
  theory --actor APT28
  theory --actor "Fancy Bear" --sources mitre,malpedia,otx
  theory --actor Lazarus --sources mitre,malpedia,otx,sigma,threatfox
  theory --actor APT41 --sources mitre,otx --output stix
  theory --actor APT28 --sources mitre,otx,threatfox --output csv
  theory --actor Turla --sources mitre,malpedia --output all
  theory --actor APT29 --sources mitre --no-save
  theory --actor APT28 --output exec
  theory --actor "Lazarus Group" --output exec --sector finance
  theory --actor APT28 --output navigator
  theory --actor APT28 --sources mitre,sigma --detection-path ~/my-sigma-rules
  theory --list-sources
  theory --list-actors
  theory --update-bundles

notes:
  - --actor accepts any name or alias (e.g. "Cozy Bear" = APT29 = Midnight Blizzard)
  - Run --update-bundles periodically to refresh ATT&CK data and Sigma rules
  - See docs/SCHEDULED_UPDATES.md to automate updates with cron or launchd
  - First run with --sources sigma takes ~10 min to build the cache (instant after)
  - Default sources: mitre,cisa,malpedia (keyless). Add otx for IOCs (free API key)
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
            "Generates analyst-grade dossiers from MITRE ATT&CK, Malpedia, OTX, Sigma, ThreatFox, and more."
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
        choices=["dossier", "json", "stix", "csv", "all", "exec", "navigator"],
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
            "navigator = ATT&CK Navigator layer JSON."
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

    # ── Require --actor for everything else ───────────────────────────
    if not args.actor:
        parser.print_help()
        print("\nerror: --actor is required. Try: theory --actor APT28\n")
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
        actor          = args.actor,
        sources        = sources,
        output         = args.output,
        save           = not args.no_save,
        verbose        = args.verbose,
        sector         = args.sector,
        detection_path = args.detection_path,
    )

    sys.exit(0 if profile else 1)


if __name__ == "__main__":  # pragma: no cover
    main()
