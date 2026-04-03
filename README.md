![Theory Logo](media/Theory%20Logo.png)

**Multi-source threat actor intelligence for everyone.**

THEORY is an open-source alternative to enterprise threat intelligence platforms. It generates analyst-grade dossiers on threat actors by aggregating data from MITRE ATT&CK, Malpedia, AlienVault OTX, SigmaHQ, ThreatFox, CISA, and vendor research blogs — then synthesizes everything using an LLM into a clean executive overview and actor-specific intelligence summaries.

Built for threat intelligence analysts, detection engineers, security researchers, and students who believe good intelligence shouldn't require a six-figure subscription.

---

## What THEORY produces

For any supported threat actor, THEORY generates:

- **LLM-written synopsis** — 4-6 sentence executive overview synthesized from all available data, at the top of every dossier
- **TTP table** — every known technique with tactic, confidence score, and detection guidance
- **Detection opportunities** — Sigma rules mapped directly to actor TTPs
- **Malware inventory** — all associated families with full descriptions
- **IOC table** — deduplicated indicators from OTX and ThreatFox with confidence scores and malware family attribution
- **Recent intelligence** — LLM-synthesized summaries of recent vendor research articles, with source attribution and links
- **Campaigns** — full campaign descriptions with dates and ATT&CK links
- **Targeted sectors** and CISA advisories

Output formats: terminal dossier, markdown, JSON, STIX 2.1 (for MISP/OpenCTI/Sentinel), and IOC CSV.

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
| `malpedia` | Malpedia malware database | None | Per request |
| `otx` | AlienVault OTX | `OTX_API_KEY` | Per request |
| `sigma` | SigmaHQ detection rules (local clone) | None | Permanent |
| `threatfox` | ThreatFox IOCs | None | 24 hours |
| `vendor` | Vendor intel synthesis (LLM) | LLM API key | 7 days |

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
# Default (fast, no Sigma)
theory --actor APT28 --sources mitre,malpedia,otx

# Full enrichment including detection rules
theory --actor APT28 --sources mitre,malpedia,otx,sigma,threatfox

# With vendor intelligence synthesis (requires LLM key in .env)
theory --actor APT28 --sources mitre,malpedia,otx,sigma,threatfox,vendor
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

# All formats at once
theory --actor APT28 --output all

# Print only — don't write files
theory --actor APT28 --no-save
```

### Browse what's available
```bash
theory --list-actors    # 35 supported actors with aliases
theory --list-sources   # all sources with auth and cache info
```

### Maintenance
```bash
# Refresh ATT&CK bundle, Sigma rules, and APT campaign collection
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

Every dossier now opens with an **Intelligence Overview** — a 4-6 sentence executive synopsis written by Claude (or your configured LLM) using the full aggregated profile as context.

The synopsis:
- Uses the name you queried, not aliases
- Covers origin, motivations, target sectors, signature TTPs, notable malware, and recent activity
- Works with or without `--sources vendor` — synthesizes from structured MITRE data alone if needed
- Appears at the top of both the terminal output and the markdown file

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
  mitre_attack.py                    ← MITRE ATT&CK (local STIX bundle)
  cisa_advisories.py                 ← CISA advisories + KEV + alias table
  malpedia.py                        ← Malpedia malware database
  alienvault_otx.py                  ← AlienVault OTX pulses and IOCs
  sigma_rules.py                     ← SigmaHQ local clone (no rate limits)
  threatfox.py                       ← ThreatFox IOC database (enrichment)
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

config/
  feeds.yaml                         ← 40 verified vendor intelligence feeds

docs/
  SIGMA_RATE_LIMITS.md               ← Sigma architecture docs
  SCHEDULED_UPDATES.md               ← Cron/launchd automation setup

tests/                               ← 310 passing tests
```

---

## Running the tests

```bash
pytest tests/ -v                              # all 310 tests
pytest tests/test_stix_reporter.py -v        # STIX only
pytest tests/test_phase9_vendor_intel.py -v  # vendor intel only
```

All tests run fully offline — no API keys required.

---

## Requirements

- Python 3.11+
- Dependencies installed via `pip install -e .`
- ATT&CK bundle downloaded via `theory --update-bundles`
- API keys: `OTX_API_KEY` for OTX source, LLM key for synopsis and vendor synthesis

---

## Contributing

See `CONTRIBUTING.md` for the full guide. Quick reference:

**Adding a new actor** — edit `collectors/cisa_advisories.py` and add to `ALIAS_TABLE`:

```python
"Actor Name": frozenset({
    "actor name", "alias one", "alias two", "g0000",
}),
```

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
