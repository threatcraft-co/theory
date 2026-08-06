#!/usr/bin/env bash
# =============================================================================
# THEORY Demo Script
# Comprehensive walkthrough of THEORY v1.0.0 capabilities
# Run from the theory/ repo root with your .env configured
# =============================================================================

set -euo pipefail

DEMO_DIR="output/demo"
mkdir -p "$DEMO_DIR"

divider() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

pause() {
    echo ""
    read -rp "  [press enter to continue]" _
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# 0. SETUP CHECK
# ─────────────────────────────────────────────────────────────────────────────

divider "0 — SETUP CHECK"

echo "Checking THEORY installation..."
theory --help > /dev/null 2>&1 && echo "  ✓ theory CLI installed" || { echo "  ✗ theory not found. Run: pip install -e ."; exit 1; }

echo "Checking .env..."
if [ -f .env ]; then
    echo "  ✓ .env exists"
    grep -q "OTX_API_KEY=." .env 2>/dev/null && echo "  ✓ OTX_API_KEY configured" || echo "  ⚠ OTX_API_KEY not set (otx source will be skipped)"
    grep -q "ANTHROPIC_API_KEY=.\|OPENAI_API_KEY=." .env 2>/dev/null && echo "  ✓ LLM provider configured" || echo "  ⚠ No LLM key set (vendor source and overviews will be skipped)"
else
    echo "  ⚠ No .env found. Proceeding with no-auth sources only."
fi

echo "Checking ATT&CK bundle..."
if [ -d ".cache" ] && find .cache -name "*.json" -size +1M 2>/dev/null | grep -q .; then
    echo "  ✓ ATT&CK bundle cached"
else
    echo "  ⚠ No ATT&CK bundle found. Downloading..."
    theory --update-bundles
fi

pause

# ─────────────────────────────────────────────────────────────────────────────
# 1. INFO COMMANDS
# ─────────────────────────────────────────────────────────────────────────────

divider "1 — INFO COMMANDS"

echo "$ theory --list-sources"
echo ""
theory --list-sources

pause

echo "$ theory --list-actors"
echo ""
theory --list-actors

pause

# ─────────────────────────────────────────────────────────────────────────────
# 2. BASIC DOSSIER (default sources, terminal + markdown)
# ─────────────────────────────────────────────────────────────────────────────

divider "2 — BASIC DOSSIER: APT28 (default sources)"

echo "$ theory --actor APT28"
echo ""
theory --actor APT28

pause

# ─────────────────────────────────────────────────────────────────────────────
# 3. ALIAS RESOLUTION
# ─────────────────────────────────────────────────────────────────────────────

divider "3 — ALIAS RESOLUTION"

echo "All three of these resolve to the same actor and produce the same canonical output file:"
echo ""
echo "$ theory --actor 'Fancy Bear' --no-save"
echo "$ theory --actor 'Forest Blizzard' --no-save"
echo "$ theory --actor 'STRONTIUM' --no-save"
echo ""
echo "Running with 'Fancy Bear'..."
echo ""
theory --actor "Fancy Bear" --no-save

pause

# ─────────────────────────────────────────────────────────────────────────────
# 4. MULTI-SOURCE ENRICHMENT
# ─────────────────────────────────────────────────────────────────────────────

divider "4 — MULTI-SOURCE ENRICHMENT"

echo "Adding community IOC sources to the base dossier:"
echo ""
echo "$ theory --actor APT29 --sources mitre,cisa,malpedia,otx,sigma,threatfox"
echo ""
theory --actor APT29 --sources mitre,cisa,malpedia,otx,sigma,threatfox

pause

# ─────────────────────────────────────────────────────────────────────────────
# 5. OUTPUT FORMATS
# ─────────────────────────────────────────────────────────────────────────────

divider "5a — JSON EXPORT"

echo "$ theory --actor 'Lazarus Group' --output json"
echo ""
theory --actor "Lazarus Group" --output json
echo ""
echo "  → Saved to output/dossiers/lazarus_group.json"

pause

divider "5b — STIX 2.1 BUNDLE"

echo "$ theory --actor Turla --sources mitre,malpedia --output stix"
echo ""
theory --actor Turla --sources mitre,malpedia --output stix
echo ""
echo "  → Saved to output/dossiers/turla.stix.json"
echo "  → Importable into MISP, OpenCTI, Splunk ES, Microsoft Sentinel"

pause

divider "5c — IOC CSV"

echo "$ theory --actor Sandworm --sources mitre,otx,threatfox --output csv"
echo ""
theory --actor Sandworm --sources mitre,otx,threatfox --output csv
echo ""
echo "  → Saved to output/dossiers/sandworm.csv"
echo "  → Raw IOC values (not defanged) for SIEM lookup table ingestion"

pause

divider "5d — ATT&CK NAVIGATOR LAYER"

echo "$ theory --actor APT41 --sources mitre,malpedia --output navigator"
echo ""
theory --actor APT41 --sources mitre,malpedia --output navigator
echo ""
echo "  → Saved to output/dossiers/apt41.navigator.json"
echo "  → Import at https://mitre-attack.github.io/attack-navigator/"

pause

divider "5e — HTML DOSSIER"

echo "$ theory --actor 'Volt Typhoon' --sources mitre,cisa,malpedia --output html"
echo ""
theory --actor "Volt Typhoon" --sources mitre,cisa,malpedia --output html
echo ""
echo "  → Saved to output/dossiers/volt_typhoon.html"
echo "  → Self-contained, shareable, opens in any browser"

pause

divider "5f — IR PLAYBOOK (Markdown)"

echo "$ theory --actor APT28 --sources mitre,sigma --output playbook"
echo ""
theory --actor APT28 --sources mitre,sigma --output playbook
echo ""
echo "  → Saved to output/dossiers/apt28_playbook.md"

pause

divider "5g — IR PLAYBOOK (Jira)"

echo "$ theory --actor APT28 --sources mitre,sigma --output playbook --playbook-format jira"
echo ""
theory --actor APT28 --sources mitre,sigma --output playbook --playbook-format jira
echo ""
echo "  → Paste directly into Jira issue descriptions"

pause

divider "5h — ALL FORMATS AT ONCE"

echo "$ theory --actor 'Kimsuky' --sources mitre,cisa,malpedia --output all"
echo ""
theory --actor "Kimsuky" --sources mitre,cisa,malpedia --output all
echo ""
echo "  → Generates dossier + JSON + STIX + CSV + Navigator + HTML simultaneously"

pause

# ─────────────────────────────────────────────────────────────────────────────
# 6. VENDOR INTELLIGENCE SYNTHESIS (requires LLM key)
# ─────────────────────────────────────────────────────────────────────────────

divider "6 — VENDOR INTELLIGENCE SYNTHESIS"

if grep -q "ANTHROPIC_API_KEY=.\|OPENAI_API_KEY=." .env 2>/dev/null; then
    echo "LLM provider detected. Running vendor intel synthesis..."
    echo ""
    echo "$ theory --actor 'Scattered Spider' --sources mitre,cisa,malpedia,vendor"
    echo ""
    theory --actor "Scattered Spider" --sources mitre,cisa,malpedia,vendor
else
    echo "  ⚠ No LLM key configured. Skipping vendor intelligence demo."
    echo "  To enable: add ANTHROPIC_API_KEY or OPENAI_API_KEY to .env"
fi

pause

# ─────────────────────────────────────────────────────────────────────────────
# 7. EXECUTIVE SUMMARY (requires LLM key)
# ─────────────────────────────────────────────────────────────────────────────

divider "7 — EXECUTIVE SUMMARY"

if grep -q "ANTHROPIC_API_KEY=.\|OPENAI_API_KEY=." .env 2>/dev/null; then
    echo "$ theory --actor 'Salt Typhoon' --output exec --sector telecommunications"
    echo ""
    theory --actor "Salt Typhoon" --output exec --sector telecommunications
else
    echo "  ⚠ No LLM key configured. Skipping executive summary demo."
fi

pause

# ─────────────────────────────────────────────────────────────────────────────
# 8. VERBOSE MODE
# ─────────────────────────────────────────────────────────────────────────────

divider "8 — VERBOSE MODE (debug output)"

echo "$ theory --actor 'Charming Kitten' --sources mitre,cisa --verbose --no-save"
echo ""
theory --actor "Charming Kitten" --sources mitre,cisa --verbose --no-save

pause

# ─────────────────────────────────────────────────────────────────────────────
# 9. SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

divider "9 — DEMO COMPLETE"

echo "Actors demonstrated:"
echo "  APT28 (Fancy Bear)       — basic dossier, alias resolution, IR playbook"
echo "  APT29 (Cozy Bear)        — multi-source enrichment"
echo "  Lazarus Group             — JSON export"
echo "  Turla                     — STIX 2.1 export"
echo "  Sandworm                  — IOC CSV export"
echo "  APT41                     — ATT&CK Navigator layer"
echo "  Volt Typhoon              — HTML dossier"
echo "  Kimsuky                   — all-format export"
echo "  Scattered Spider          — vendor intel synthesis"
echo "  Salt Typhoon              — executive summary"
echo "  Charming Kitten           — verbose/debug mode"
echo ""
echo "Output files:"
ls -la output/dossiers/ 2>/dev/null || echo "  (no files saved — all ran with --no-save or output dir not created)"
echo ""
echo "Tests:"
echo "  $ pytest tests/ -v    # 337 offline tests, no API keys needed"
echo ""
echo "Repository: github.com/threatcraft-co/theory"
echo ""
