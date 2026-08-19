![Theory Logo](media/Theory%20Logo.png)

[![CI](https://github.com/threatcraft-co/theory/actions/workflows/ci.yml/badge.svg)](https://github.com/threatcraft-co/theory/actions/workflows/ci.yml)

**Multi-source threat actor intelligence for everyone.**

THEORY is an open-source alternative to enterprise threat intelligence platforms. It generates analyst-grade dossiers on threat actors by aggregating data from MITRE ATT&CK, MISP Galaxy, Malpedia, AlienVault OTX, SigmaHQ, YARA-Rules, ThreatFox, MalwareBazaar, URLhaus, GreyNoise, AbuseIPDB, VulDB, CISA, and vendor research blogs — then synthesizes everything using an LLM into a clean executive overview and actor-specific intelligence summaries.

Built for threat intelligence analysts, detection engineers, security researchers, and students who believe good intelligence shouldn't require a six-figure subscription.

---

## What THEORY produces

For any supported threat actor, THEORY generates:

- **LLM-written synopsis** — 4-6 sentence executive overview synthesized from all available data, at the top of every dossier
- **TTP table** — every known technique with tactic, confidence score, and detection guidance
- **Detection opportunities** — Sigma rules mapped to actor TTPs and YARA rules matched to malware families
- **Malware inventory** — all associated families with full descriptions, sample hashes (MalwareBazaar), and YARA detection coverage
- **IOC table** — deduplicated, defanged indicators from OTX, ThreatFox, MalwareBazaar, and URLhaus with confidence scores and malware family attribution
- **IP enrichment** — GreyNoise noise/RIOT context and AbuseIPDB reputation scores annotate every public IP indicator so analysts can distinguish targeted infrastructure from internet background radiation
- **Vulnerability intelligence** — CVEs from CISA KEV, NVD, and VulDB with CVSS scores, exploit availability, and remediation status
- **Recent intelligence** — LLM-synthesized summaries of recent vendor research articles, with source attribution and links
- **Campaigns** — full campaign descriptions with dates and ATT&CK links
- **Targeted sectors** and CISA advisories
- **IR playbooks** — analyst-ready checklists with IOC blocks, detection checklists, hunt hypotheses, and containment guidance
- **ATT&CK Navigator layers** — confidence-colored heatmaps importable directly into MITRE Navigator
- **HTML dossiers** — self-contained, shareable intelligence reports that open in any browser
- **Detection coverage gap reports** — compare actor TTPs against your local detection rules

Output formats: terminal dossier, markdown, JSON, STIX 2.1 (for MISP/OpenCTI/Sentinel), IOC CSV, HTML, ATT&CK Navigator, and IR playbook (markdown or Jira).

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/threatcraft-co/theory
cd theory

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install THEORY and dependencies
pip install -e .

# 4. Download the ATT&CK bundle (required for MITRE source)
theory --update-bundles

# 5. Configure your API keys
cp .env.example .env
# Edit .env and add your OTX_API_KEY (free at otx.alienvault.com)

# 6. Run your first dossier
theory --actor APT28
```

That's it. Your first dossier renders in the terminal and saves to `output/dossiers/apt28.md`.

---

## Sources

| Key | Source | Auth Required | Cache |
|---|---|---|---|
| `mitre` | MITRE ATT&CK (local bundle) | None | 7 days |
| `cisa` | CISA Advisories + KEV | None | Per request |
| `cisa_kev` | CISA KEV — 1600+ confirmed-exploited CVEs | None | 24 hours |
| `malpedia` | Malpedia malware database | None | Per request |
| `misp_galaxy` | MISP Galaxy — 1000+ actors with deep alias lists | None | 7 days |
| `otx` | AlienVault OTX | `OTX_API_KEY` | Per request |
| `sigma` | SigmaHQ detection rules (local clone) | `GITHUB_TOKEN` (optional) | 7 days |
| `yara` | YARA-Rules file/memory detection rules (local clone) | None | 7 days |
| `threatfox` | ThreatFox IOCs | None | 24 hours |
| `malware_bazaar` | MalwareBazaar sample hashes | `ABUSECH_API_KEY` | 24 hours |
| `urlhaus` | URLhaus malware distribution URLs | `ABUSECH_API_KEY` | 24 hours |
| `greynoise` | GreyNoise IP noise/RIOT context | `GREYNOISE_API_KEY` | 7 days |
| `abuseipdb` | AbuseIPDB IP reputation scores | `ABUSEIPDB_API_KEY` | 3 days |
| `vuldb` | VulDB actor-CVE correlation | `VULDB_API_KEY` | 7 days |
| `vendor` | Vendor intel synthesis (LLM) | LLM API key | 7 days |

**Coming in v1.2 — Additional IOC Enrichment:**

| Key | Source | Auth Required | Free Tier |
|---|---|---|---|
| `shodan` | Shodan host data + C2 detection | `SHODAN_API_KEY` | 100 queries/month |
| `censys` | Censys certificate + host data | `CENSYS_API_KEY` | Community tier |
| `criminalip` | Criminal IP threat scoring | `CRIMINALIP_API_KEY` | Free tier |
| `virustotal` | VirusTotal hash + domain reputation | `VIRUSTOTAL_API_KEY` | 500 requests/day |

```bash
# Live status of all sources
theory --list-sources
```

---

## Usage

### Basic dossier
```bash
theory --actor APT28
theory --actor "Fancy Bear"         # alias resolution — same output
theory --actor "Forest Blizzard"    # same actor, different name
```

### Choosing sources
```bash
# Default (mitre + cisa + cisa_kev + malpedia + misp_galaxy, no auth needed)
theory --actor APT28

# Add community IOCs
theory --actor APT28 --sources mitre,cisa,malpedia,otx

# Full enrichment including detection rules (Sigma + YARA)
theory --actor APT28 --sources mitre,cisa,malpedia,otx,sigma,yara,threatfox

# Complete abuse.ch trifecta (network + file + delivery IOCs)
theory --actor APT28 --sources mitre,malpedia,threatfox,malware_bazaar,urlhaus

# IP enrichment (GreyNoise + AbuseIPDB annotate every public IP)
theory --actor APT28 --sources mitre,otx,threatfox,greynoise,abuseipdb

# Vulnerability intelligence (CISA KEV + VulDB actor-CVE correlation)
theory --actor APT28 --sources mitre,cisa_kev,vuldb

# Everything, with vendor intelligence synthesis (requires LLM key in .env)
theory --actor APT28 --sources mitre,cisa,malpedia,misp_galaxy,otx,sigma,yara,threatfox,malware_bazaar,urlhaus,greynoise,abuseipdb,vuldb,vendor
```

### Output formats
```bash
# Terminal + markdown file (default)
theory --actor APT28

# Raw JSON profile
theory --actor APT28 --output json

# STIX 2.1 bundle (import into MISP, OpenCTI, Sentinel)
theory --actor APT28 --output stix

# IOC-only CSV (for SIEM lookup tables)
theory --actor APT28 --sources mitre,otx,threatfox --output csv

# Self-contained HTML dossier (shareable, opens in any browser)
theory --actor APT28 --sources mitre,malpedia,otx --output html

# ATT&CK Navigator layer (import at mitre-attack.github.io/attack-navigator)
theory --actor APT28 --sources mitre,malpedia,otx --output navigator

# IR playbook with detection checklist and IOC blocks
theory --actor APT28 --sources mitre,sigma --output playbook

# IR playbook in Jira wiki markup
theory --actor APT28 --sources mitre,sigma --output playbook --playbook-format jira

# Non-technical executive summary (BLUF format, requires LLM key)
theory --actor APT28 --output exec

# Executive summary with sector context
theory --actor "Lazarus Group" --output exec --sector finance

# All formats at once (dossier + JSON + STIX + CSV + Navigator + HTML)
theory --actor APT28 --output all

# Print only — don't write files
theory --actor APT28 --no-save
```

### Detection coverage gap analysis
```bash
# Compare actor TTPs against your local detection rules
theory --actor APT28 --sources mitre,sigma --detection-path ~/my-sigma-rules

# Output: coverage %, covered techniques, and gaps sorted by confidence
```

### Browse what's available
```bash
theory --list-actors    # 35 supported actors with aliases
theory --list-sources   # all sources with auth and cache info
```

### Maintenance
```bash
# Refresh ATT&CK bundle, Sigma rules, YARA rules, MISP Galaxy, CISA KEV, and APT campaign collection
theory --update-bundles
```

### Verbose / debug mode
```bash
theory --actor APT28 --sources mitre,cisa --verbose
```

---

## Alias resolution

THEORY knows 35 actors by all their names (275 aliases total). Any alias resolves to the same canonical dossier:

```bash
theory --actor "Cozy Bear"          # → APT29
theory --actor "Midnight Blizzard"  # → APT29
theory --actor "Nobelium"           # → APT29
theory --actor "NOBELIUM"           # → APT29 (case-insensitive)
```

The output file is always named by the canonical actor — `--actor "Fancy Bear"` produces `apt28.md`, not `fancy_bear.md`.

```bash
theory --list-actors    # see all 35 actors and their aliases
```

---

## LLM Actor Synopsis

Every dossier opens with an **Intelligence Overview** — a 4-6 sentence executive synopsis written by Claude (or your configured LLM) using the full aggregated profile as context.

The synopsis:
- Uses the name you queried, not aliases
- Covers origin, motivations, target sectors, signature TTPs, notable malware, and recent activity
- Works with or without `--sources vendor` — synthesizes from structured MITRE data alone if needed
- Appears at the top of both the terminal output and the markdown file

**LLM provider resolution order:** Claude → OpenAI → Ollama. Set `THEORY_LLM_PROVIDER` in `.env` to override, or leave blank to auto-detect. Ollama runs fully offline.

---

## Vendor Intelligence Synthesis

When you add `vendor` to your sources, THEORY fetches recent articles from 40+ threat research blogs (Mandiant, Google TAG, Unit 42, Secureworks, Recorded Future, CrowdStrike, Kaspersky GReAT, Check Point Research, Sophos, Proofpoint, and more) and uses an LLM to synthesize what each article reveals about your actor specifically.

```bash
# Set your preferred provider and API key in .env
THEORY_LLM_PROVIDER=claude
ANTHROPIC_API_KEY=your_key_here

# Run with synthesis
theory --actor "Lazarus Group" --sources mitre,malpedia,otx,vendor
```

The dossier includes a **Recent Intelligence** section with actor-specific summaries, source attribution, and direct links to original articles.

---

## Sigma Detection Rules

THEORY uses a local clone of the SigmaHQ repository — no rate limits, no API, instant results.

```bash
# First run clones the repo (~150MB, ~1-2 minutes, one time only)
theory --actor APT28 --sources mitre,sigma --no-save

# Every subsequent run is instant
theory --actor APT28 --sources mitre,sigma --no-save
```

Detection rules are linked directly to actor TTPs in the dossier. See `docs/SIGMA_RATE_LIMITS.md` for full details.

---

## YARA Rules

Where Sigma covers log-based and network detection, YARA covers file-based and memory detection. THEORY uses a local clone of the Yara-Rules/rules repository — no rate limits, no API, instant results.

```bash
# First run clones the repo (~50MB, ~1 minute, one time only)
theory --actor APT28 --sources mitre,malpedia,yara --no-save

# Every subsequent run is instant
theory --actor APT28 --sources mitre,malpedia,yara --no-save
```

YARA rules are matched to malware family names in the actor profile (from MITRE, Malpedia, and MISP Galaxy) and attached to the corresponding malware entries in the dossier. Sigma and YARA together give complete detection coverage: network AND endpoint.

---

## IP Enrichment (GreyNoise + AbuseIPDB)

Every public IP indicator in the dossier can be annotated with two independent enrichment signals:

- **GreyNoise** distinguishes targeted activity from internet background noise. An IP flagged as RIOT (known benign service like a CDN or DNS resolver) or as scanning noise is almost certainly a false positive. This saves analysts from chasing leads that lead nowhere.
- **AbuseIPDB** provides a community abuse-confidence score (0-100) reflecting how many independent reporters have flagged the IP as abusive.

```bash
# Enrich all IP IOCs with both sources
theory --actor APT28 --sources mitre,otx,threatfox,greynoise,abuseipdb
```

Free tier limits are conservative on both — GreyNoise Community is 50 lookups/week and AbuseIPDB is 1000 checks/day — so THEORY caps enrichment at 25 IPs per run for GreyNoise and 50 for AbuseIPDB, and caches aggressively (7 days for GreyNoise, 3 for AbuseIPDB).

---

## abuse.ch Trifecta (ThreatFox + MalwareBazaar + URLhaus)

One free API key from [auth.abuse.ch](https://auth.abuse.ch/) unlocks three complementary IOC sources that together cover every stage of a malware infrastructure lifecycle:

- **ThreatFox** — command and control IOCs (IPs, domains, URLs) by malware family
- **MalwareBazaar** — sample hashes (SHA256, MD5, SHA1) with file metadata and signatures
- **URLhaus** — active and historical payload distribution URLs

```bash
# Complete abuse.ch coverage — network C2, file hashes, delivery URLs
theory --actor APT28 --sources mitre,malpedia,threatfox,malware_bazaar,urlhaus
```

---

## HTML Dossier

THEORY generates self-contained HTML dossiers with a dark intelligence-grade aesthetic. No server required — opens in any browser, works offline. All CSS and JS are embedded inline.

```bash
theory --actor APT28 --sources mitre,malpedia,otx --output html
# writes: output/dossiers/apt28.html
```

Features: collapsible sections, sortable TTP table, tactic filter buttons, IOC freshness indicators (fresh/aging/stale), malware cards, vendor intel cards, and a confidence summary header. Shareable as a single file.

---

## ATT&CK Navigator Export

THEORY exports ATT&CK Navigator v4.5 layers, color-coded by confidence level (HIGH=red, MEDIUM=amber, LOW=yellow). Techniques with Sigma coverage get a score boost.

```bash
theory --actor APT28 --sources mitre,malpedia,otx --output navigator
# writes: output/dossiers/apt28.navigator.json
```

Import into Navigator:
1. Go to https://mitre-attack.github.io/attack-navigator/
2. Open Layer → Upload from Local
3. Select the `.navigator.json` file

---

## IR Playbook

THEORY generates incident response playbooks from actor profiles — structured, analyst-ready checklists that turn intelligence into action.

```bash
# Markdown format (renders in GitHub, Confluence, Notion, ServiceNow)
theory --actor APT28 --sources mitre,sigma --output playbook

# Jira wiki markup (paste directly into issue descriptions)
theory --actor APT28 --sources mitre,sigma --output playbook --playbook-format jira
```

Playbook sections:
- **Immediate IOC Blocks** — FRESH and AGING indicators formatted for firewall/SIEM
- **Detection Checklist** — TTPs as checkboxes with Sigma rule links, grouped by tactic
- **Hunt Hypotheses** — LLM-generated plain-language hunt queries per high-confidence TTP
- **Malware Reference** — known families, types, and hashes
- **Containment Guidance** — LLM-generated, sector-aware response steps (use `--sector` to tailor)
- **References** — all source URLs cited in the profile

---

## Detection Coverage Gap Analysis

Compare an actor's TTPs against your local detection rules to find where you lack coverage.

```bash
theory --actor APT28 --sources mitre,sigma --detection-path ~/my-sigma-rules
```

THEORY greps your detection directory for each technique ID and reports:
- Coverage percentage with a visual bar
- **Gaps** — techniques with no local rule, sorted by confidence (HIGH first)
- **Covered** — techniques you can already detect

Saves a markdown report to `output/dossiers/<actor>_coverage_gap.md`.

---

## IOC Safety

All URLs, domains, and IPs in THEORY dossiers are automatically defanged using industry-standard notation — `hxxp://`, `[.]` — so they cannot be accidentally clicked or resolved in any markdown renderer, browser, or IDE preview.

The IOC CSV export (`--output csv`) retains raw values for SIEM ingestion, where your platform handles the defanging.

---

## Adding custom feeds

Add your own RSS feeds to `config/feeds.yaml`:

```yaml
custom:
  - name: My Internal TI Feed
    url: https://internal.company.com/threat-intel
    rss: https://internal.company.com/threat-intel/rss
    type: rss
    tier: 2
    apt_focus: true
    tags: [internal, custom]
    enabled: true
```

---

## STIX 2.1 Export

THEORY produces valid STIX 2.1 bundles importable into:

- **MISP** — import via `Events → Import → STIX 2.x`
- **OpenCTI** — import via the STIX connector
- **Splunk Enterprise Security** — via the TAXII connector
- **Microsoft Sentinel** — via the Threat Intelligence data connector

```bash
theory --actor APT28 --sources mitre,malpedia,otx --output stix
# writes: output/dossiers/apt28.stix.json
```

---

## Architecture

```
theory/                              ← Python package (CLI entry point)
  __init__.py                        ← public API: main(), run()
  __main__.py                        ← enables python -m theory
  _cli.py                            ← pipeline orchestrator
  _version.py                        ← version string

theory.py                            ← compatibility shim (points to package)

collectors/
  base.py                            ← base collector class
  mitre_attack.py                    ← MITRE ATT&CK (local STIX bundle)
  cisa_advisories.py                 ← CISA advisories + alias table
  cisa_kev.py                        ← CISA KEV catalog cross-referencing
  misp_galaxy.py                     ← MISP Galaxy threat-actor cluster
  malpedia.py                        ← Malpedia malware database
  alienvault_otx.py                  ← AlienVault OTX pulses and IOCs
  sigma_rules.py                     ← SigmaHQ local clone (no rate limits)
  yara_rules.py                      ← YARA-Rules local clone (file/memory detection)
  threatfox.py                       ← ThreatFox IOC database (network C2)
  malware_bazaar.py                  ← MalwareBazaar sample hashes (file IOCs)
  urlhaus.py                         ← URLhaus malware distribution URLs
  greynoise.py                       ← GreyNoise IP noise/RIOT enrichment
  abuseipdb.py                       ← AbuseIPDB IP reputation enrichment
  vuldb.py                           ← VulDB actor-CVE correlation
  vendor_intel.py                    ← RSS feed fetcher + relevance scorer
  intelligence_synthesizer.py        ← LLM provider abstraction + synthesis

processors/
  normalizer.py                      ← Schema validation and normalization
  deduplicator.py                    ← Cross-source dedup + confidence scoring

mappers/
  mitre.py                           ← MITRE ATT&CK mapper
  cisa.py                            ← CISA mapper

reporters/
  dossier.py                         ← Rich terminal + markdown output
  json_reporter.py                   ← JSON profile export
  stix_reporter.py                   ← STIX 2.1 bundle export
  csv_reporter.py                    ← IOC-only CSV export
  html_reporter.py                   ← Self-contained HTML dossier
  navigator_reporter.py              ← ATT&CK Navigator layer export
  playbook_reporter.py               ← IR playbook (markdown + Jira)

config/
  feeds.yaml                         ← 40+ verified vendor intelligence feeds
  detection_repos.yaml               ← curated detection repo registry
  actors.yaml                        ← actor configuration

docs/
  SIGMA_RATE_LIMITS.md               ← Sigma architecture docs
  SCHEDULED_UPDATES.md               ← Cron/launchd automation setup
  SECURITY_AUDIT_2026-06.md          ← Security audit documentation

tests/                               ← 493+ offline tests
```

---

## Running the tests

```bash
pytest tests/ -v                              # all tests
pytest tests/test_stix_reporter.py -v        # STIX only
pytest tests/test_phase9_vendor_intel.py -v  # vendor intel only
pytest tests/test_security_hardening.py -v   # security hardening
```

All tests run fully offline — no API keys required.

---

## Requirements

- Python 3.11+
- Dependencies installed via `pip install -e .`
- ATT&CK bundle downloaded via `theory --update-bundles`
- API keys: see `.env.example` for the full list with registration links

---

## Contributing

See `CONTRIBUTING.md` for the full guide. Quick reference:

**Adding a new actor** — edit `config/actors.yaml` and add a new entry with the canonical name, aliases, and metadata. See the existing entries in that file for the schema.

**Adding a new source** — implement collector, mapper, and tests. See `CONTRIBUTING.md`.

**Adding a vendor feed** — edit `config/feeds.yaml` and add to the `sources` list.

**Reporting issues** — `github.com/threatcraft-co/theory/issues`

---

## Legal

THEORY aggregates publicly available third-party data. See `DISCLAIMER.md` and `LEGAL.md` for full terms.

---

## License

MIT License — see `LICENSE` for details.

---

*Built by [Threatcraft](https://github.com/threatcraft-co) — open-source threat intelligence for the security community.*
