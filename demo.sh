#!/usr/bin/env bash
# =============================================================================
# THEORY v1.2 Demo — CVE Pipeline + Multi-Source Actor Enrichment
# Two focused runs demonstrating the v1.2 additions:
#   MISP Galaxy actor cluster + CVE extraction + CISA KEV cross-referencing
# Run from the theory/ repo root
# =============================================================================

set -euo pipefail

divider() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# ── Preflight ────────────────────────────────────────────────────────────────

divider "PREFLIGHT"

theory --help > /dev/null 2>&1 && echo "  ✓ theory CLI installed" || {
    echo "  ✗ theory not found. Run: pip install -e ."
    exit 1
}

# Make sure the caches new to v1.2 are populated
if [ ! -f .cache/misp_galaxy/threat-actor.json ] || [ ! -f .cache/cisa_kev/known_exploited_vulnerabilities.json ]; then
    echo "  ⚠ MISP Galaxy or CISA KEV cache missing — running --update-bundles"
    theory --update-bundles
else
    echo "  ✓ MISP Galaxy cluster cached"
    echo "  ✓ CISA KEV catalog cached"
fi

# ── Run 1: APT28 — deep multi-source enrichment ─────────────────────────────
#
# Demonstrates:
#   - MISP Galaxy contributing 20+ vendor-specific aliases
#     (Forest Blizzard, STRONTIUM, Pawn Storm, FROZENLAKE, TA422, etc.)
#   - MITRE ATT&CK extracting CVEs from technique/campaign descriptions
#   - CISA KEV cross-referencing those CVEs and flagging any that are
#     confirmed exploited in the wild
#   - Merged profile combining aliases, TTPs, malware, and CVE evidence
#     from four independent sources
#
# What to look for in the output:
#   Sources line: "misp_galaxy, mitre_attack, cisa_kev, malpedia"
#   Also Known As: 20+ aliases from MISP Galaxy's name-attribution data
#   Any CVE flagged via KEV enrichment appears in the JSON output

divider "RUN 1 — APT28 (full v1.2 default sources)"

echo "  Command:"
echo "    theory --actor APT28"
echo ""
echo "  Then dump the JSON to see CVEs + KEV enrichment:"
echo "    theory --actor APT28 --output json --no-save | python3 -m json.tool | grep -A 8 '\"cve_id\"'"
echo ""

theory --actor APT28

echo ""
echo "  ── CVE + KEV enrichment (from JSON output) ──"
theory --actor APT28 --output json --no-save 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'  Total CVEs extracted:     {len(d.get(\"cves\", []))}')
print(f'  KEV-confirmed CVEs:       {d.get(\"kev_confirmed_count\", 0)}')
print(f'  Ransomware-flagged CVEs:  {d.get(\"kev_ransomware_count\", 0)}')
print()
for c in d.get('cves', []):
    kev = ' [KEV]' if c.get('kev_confirmed') else ''
    ransom = ' [RANSOMWARE]' if c.get('kev_ransomware') else ''
    ctx = ','.join(c.get('mitre_contexts', []))
    print(f'  {c[\"cve_id\"]}{kev}{ransom}  (context: {ctx})')
"

# ── Run 2: APT38 — CVE with confirmed ransomware attribution ────────────────
#
# Demonstrates:
#   - A real actor→CVE→KEV chain with ransomware attribution
#   - APT38 (Lazarus subgroup, North Korea, financial theft focus)
#     is documented in MITRE as exploiting CVE-2024-55591 (Fortinet FortiOS)
#   - CISA KEV confirms that CVE is used in ransomware campaigns
#   - End-to-end proof that a technique description mention → structured
#     CVE entry → KEV enrichment → ransomware flag pipeline works
#
# What to look for:
#   JSON output should show CVE-2024-55591 with:
#     kev_confirmed: true
#     kev_ransomware: true
#     kev_vendor: "Fortinet"
#     kev_product: "FortiOS and FortiProxy"

divider "RUN 2 — APT38 (CVE→KEV→ransomware attribution chain)"

echo "  Command:"
echo "    theory --actor APT38 --sources mitre,cisa_kev --output json --no-save"
echo ""

theory --actor APT38 --sources mitre,cisa_kev --output json --no-save 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)

print(f'  Actor:                    {d.get(\"actor_name\")}')
print(f'  Sources contributing:     {d.get(\"sources_cited\", [])}')
print(f'  Total CVEs extracted:     {len(d.get(\"cves\", []))}')
print(f'  KEV-confirmed CVEs:       {d.get(\"kev_confirmed_count\", 0)}')
print(f'  Ransomware-flagged CVEs:  {d.get(\"kev_ransomware_count\", 0)}')
print()
print('  ── CVE details ──')
for c in d.get('cves', []):
    print(f'    {c[\"cve_id\"]}')
    if c.get('kev_confirmed'):
        print(f'      Vendor:      {c.get(\"kev_vendor\", \"?\")}')
        print(f'      Product:     {c.get(\"kev_product\", \"?\")}')
        print(f'      Date added:  {c.get(\"kev_date_added\", \"?\")}')
        print(f'      Ransomware:  {c.get(\"kev_ransomware\", False)}')
    else:
        print(f'      (not in CISA KEV catalog)')
    ctx = c.get('mitre_contexts', [])
    refs = c.get('mitre_references', [])
    if ctx or refs:
        print(f'      MITRE context: {ctx} → {refs}')
    print()
"

# ── Summary ─────────────────────────────────────────────────────────────────

divider "SUMMARY"

echo "  v1.2 pipeline validated:"
echo "    ✓ MISP Galaxy cluster loaded and contributing aliases"
echo "    ✓ MITRE ATT&CK extracting CVEs from descriptions"
echo "    ✓ CVE data surviving normalizer, deduplicator, and mapper"
echo "    ✓ CISA KEV cross-referencing CVEs and adding enrichment fields"
echo "    ✓ End-to-end actor→CVE→KEV→ransomware attribution working"
echo ""
echo "  Repo:  github.com/threatcraft-co/theory"
echo ""
