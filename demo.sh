#!/usr/bin/env bash
# =============================================================================
# THEORY Demo — Single Comprehensive Run
# Demonstrates all THEORY v1.0.0 capabilities in one pass
# Run from the theory/ repo root with your .env configured
# =============================================================================

set -euo pipefail

DEMO_DIR="output/demo"
mkdir -p "$DEMO_DIR"

PASS=0
FAIL=0
SKIP=0

HAS_OTX=false
HAS_LLM=false

# ── Helpers ──────────────────────────────────────────────────────────────────

divider() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

run() {
    local label="$1"
    shift
    echo "  ▸ $label"
    echo "    \$ $*"
    if "$@" > /dev/null 2>&1; then
        echo "    ✓ pass"
        ((PASS++))
    else
        echo "    ✗ fail"
        ((FAIL++))
    fi
    echo ""
}

skip() {
    local label="$1"
    local reason="$2"
    echo "  ▸ $label"
    echo "    ⚠ skipped — $reason"
    ((SKIP++))
    echo ""
}

# ── Preflight ────────────────────────────────────────────────────────────────

divider "PREFLIGHT"

theory --help > /dev/null 2>&1 && echo "  ✓ theory CLI installed" || { echo "  ✗ theory not found. Run: pip install -e ."; exit 1; }

if [ -f .env ]; then
    echo "  ✓ .env exists"
    grep -q "OTX_API_KEY=." .env 2>/dev/null && { HAS_OTX=true; echo "  ✓ OTX_API_KEY configured"; } || echo "  ⚠ OTX_API_KEY not set (otx steps will be skipped)"
    grep -q "ANTHROPIC_API_KEY=.\|OPENAI_API_KEY=." .env 2>/dev/null && { HAS_LLM=true; echo "  ✓ LLM provider configured"; } || echo "  ⚠ No LLM key set (vendor + exec steps will be skipped)"
else
    echo "  ⚠ No .env found. Running no-auth sources only."
fi

if [ -d ".cache" ] && find .cache -name "*.json" -size +1M 2>/dev/null | grep -q .; then
    echo "  ✓ ATT&CK bundle cached"
else
    echo "  ⚠ No ATT&CK bundle found. Downloading..."
    theory --update-bundles
fi

# ── Info Commands ────────────────────────────────────────────────────────────

divider "INFO COMMANDS"

run "List available sources" \
    theory --list-sources

run "List tracked actors" \
    theory --list-actors

# ── Dossier Generation ───────────────────────────────────────────────────────

divider "DOSSIER GENERATION"

run "Basic dossier (default sources)" \
    theory --actor APT28

run "Multi-source enrichment (mitre + cisa + malpedia + sigma)" \
    theory --actor APT29 --sources mitre,cisa,malpedia,sigma

if $HAS_OTX; then
    run "Multi-source enrichment with OTX + ThreatFox IOCs" \
        theory --actor APT29 --sources mitre,cisa,malpedia,otx,sigma,threatfox
else
    skip "Multi-source enrichment with OTX + ThreatFox IOCs" "no OTX_API_KEY"
fi

# ── Alias Resolution ────────────────────────────────────────────────────────

divider "ALIAS RESOLUTION"

echo "  All three resolve to the same canonical actor (APT28):"
echo ""

run "Resolve alias: Fancy Bear" \
    theory --actor "Fancy Bear" --no-save

run "Resolve alias: Forest Blizzard" \
    theory --actor "Forest Blizzard" --no-save

run "Resolve alias: STRONTIUM" \
    theory --actor "STRONTIUM" --no-save

# ── Output Formats ───────────────────────────────────────────────────────────

divider "OUTPUT FORMATS"

run "JSON export" \
    theory --actor "Lazarus Group" --output json

run "STIX 2.1 bundle" \
    theory --actor Turla --sources mitre,malpedia --output stix

if $HAS_OTX; then
    run "IOC CSV export" \
        theory --actor Sandworm --sources mitre,otx,threatfox --output csv
else
    run "IOC CSV export (no OTX, mitre only)" \
        theory --actor Sandworm --sources mitre --output csv
fi

run "ATT&CK Navigator layer" \
    theory --actor APT41 --sources mitre,malpedia --output navigator

run "HTML dossier" \
    theory --actor "Volt Typhoon" --sources mitre,cisa,malpedia --output html

run "IR playbook (Markdown)" \
    theory --actor APT28 --sources mitre,sigma --output playbook

run "IR playbook (Jira format)" \
    theory --actor APT28 --sources mitre,sigma --output playbook --playbook-format jira

run "All formats at once" \
    theory --actor Kimsuky --sources mitre,cisa,malpedia --output all

# ── LLM-Powered Features ────────────────────────────────────────────────────

divider "LLM-POWERED FEATURES"

if $HAS_LLM; then
    run "Vendor intelligence synthesis" \
        theory --actor "Scattered Spider" --sources mitre,cisa,malpedia,vendor

    run "Executive summary (sector-scoped)" \
        theory --actor "Salt Typhoon" --output exec --sector telecommunications
else
    skip "Vendor intelligence synthesis" "no LLM key"
    skip "Executive summary (sector-scoped)" "no LLM key"
fi

# ── Debug Mode ───────────────────────────────────────────────────────────────

divider "DEBUG MODE"

run "Verbose output" \
    theory --actor "Charming Kitten" --sources mitre,cisa --verbose --no-save

# ── Results ──────────────────────────────────────────────────────────────────

divider "RESULTS"

echo "  Actors covered:"
echo "    APT28 (Fancy Bear / Forest Blizzard / STRONTIUM)"
echo "    APT29 (Cozy Bear)"
echo "    APT41 (Wicked Panda)"
echo "    Charming Kitten"
echo "    Kimsuky"
echo "    Lazarus Group"
echo "    Salt Typhoon"
echo "    Sandworm"
echo "    Scattered Spider"
echo "    Turla"
echo "    Volt Typhoon"
echo ""
echo "  Output files:"
ls -la output/dossiers/ 2>/dev/null || echo "    (none saved)"
echo ""
echo "  Tests: pytest tests/ -v"
echo "  Repo:  github.com/threatcraft-co/theory"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASS: $PASS  |  FAIL: $FAIL  |  SKIP: $SKIP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
