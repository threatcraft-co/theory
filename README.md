![Theory Logo](media/Theory%20Logo.png)

**Multi-source threat actor intelligence for everyone.**

THEORY is an open-source alternative to enterprise threat intelligence platforms. It generates analyst-grade dossiers on threat actors by aggregating data from MITRE ATT&CK, Malpedia, AlienVault OTX, SigmaHQ, ThreatFox, CISA, and vendor research blogs — then optionally synthesizes recent articles using an LLM of your choice.

Built for threat intelligence analysts, detection engineers, security researchers, and students who believe good intelligence shouldn't require a six-figure subscription.


---

## What THEORY produces

For any supported threat actor, THEORY generates:

- **TTP table** — every known technique with tactic, confidence score, and detection guidance
- **Detection opportunities** — Sigma rules mapped directly to actor TTPs
- **Malware inventory** — all associated families with descriptions and aliases
- **IOC table** — deduplicated indicators from OTX and ThreatFox with confidence scores and malware family attribution
- **Recent intelligence** — LLM-synthesized summaries of recent vendor research articles, with source attribution and links
- **Targeted sectors** and **campaigns**

Output formats: terminal dossier, markdown, JSON, STIX 2.1 (for MISP/OpenCTI/Sentinel), and IOC CSV.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/threatcraft-co/theory
cd theory

# 2. Create a virtual environment and install dependencies
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. Download the ATT&CK bundle (required for MITRE source)
mkdir -p .cache
curl -L https://github.com/mitre-attack/attack-stix-data/raw/master/enterprise-attack/enterprise-attack.json \
     -o .cache/enterprise-attack.json

# 4. Configure your API keys
cp .env.example .env
# Edit .env and add your OTX_API_KEY (free at otx.alienvault.com)

# 5. Run your first dossier
python theory.py --actor APT28
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
| `sigma` | SigmaHQ detection rules | `GITHUB_TOKEN` (optional) | 7 days |
| `threatfox` | ThreatFox IOCs | None | 24 hours |
| `vendor` | Vendor intel synthesis (LLM) | LLM API key | 7 days |

```bash
# Use --list-sources for live status
python theory.py --list-sources
```

---

## Usage

### Basic dossier
```bash
python theory.py --actor APT28
python theory.py --actor "Fancy Bear"       # alias resolution
python theory.py --actor "Forest Blizzard"  # same actor, different name
```

### Choosing sources
```bash
# Default (fast, no sigma)
python theory.py --actor APT28 --sources mitre,malpedia,otx

# Full enrichment
python theory.py --actor APT28 --sources mitre,malpedia,otx,sigma,threatfox

# With vendor intelligence synthesis (requires LLM key in .env)
python theory.py --actor APT28 --sources mitre,malpedia,otx,sigma,threatfox,vendor
```

### Output formats
```bash
# Terminal + markdown file (default)
python theory.py --actor APT28

# Raw JSON profile
python theory.py --actor APT28 --output json

# STIX 2.1 bundle (import into MISP, OpenCTI, Sentinel)
python theory.py --actor APT28 --output stix

# IOC-only CSV (for SIEM lookup tables)
python theory.py --actor APT28 --sources mitre,otx,threatfox --output csv

# All formats at once
python theory.py --actor APT28 --output all

# Print only — don't write files
python theory.py --actor APT28 --no-save
```

### Browse what's available
```bash
python theory.py --list-actors    # 50+ supported actors with aliases
python theory.py --list-sources   # all sources with auth and cache info
```

### Maintenance
```bash
# Refresh ATT&CK bundle + clear Sigma/ThreatFox caches
python theory.py --update-bundles
```

### Verbose mode
```bash
python theory.py --actor APT28 --sources mitre,otx --verbose
```

---

## Alias resolution

THEORY knows 50+ actors by all their names. Any alias resolves to the same dossier:

```bash
python theory.py --actor "Cozy Bear"         # → APT29
python theory.py --actor "Midnight Blizzard" # → APT29
python theory.py --actor "Nobelium"          # → APT29
python theory.py --actor "NOBELIUM"          # → APT29 (case-insensitive)
```

```bash
python theory.py --list-actors               # see all actors and their aliases
```

---

## Vendor Intelligence Synthesis

When you add `vendor` to your sources, THEORY fetches recent articles from 35+ threat research blogs (Mandiant, Google TAG, Unit 42, Secureworks, Recorded Future, Okta, CrowdStrike, Kaspersky GReAT, and more) and uses an LLM to synthesize what each article reveals about your actor specifically.

```bash
# 1. Set your preferred provider and API key in .env
THEORY_LLM_PROVIDER=vendor    # or claude, openai, ollama
LLM_API_KEY=your_key    # get yours at vendor.agnostic.com

# 2. Run with synthesis
python theory.py --actor "Lazarus Group" --sources mitre,malpedia,otx,vendor
```

The dossier will include a **Recent Intelligence** section:

```
● Recorded Future  2026-01-07   HIGH relevance
  GRU-Linked BlueDelta Evolves Credential Harvesting

  APT28 evolved credential-harvesting campaigns targeting government,
  energy, and research organizations across Europe and Eurasia as of
  early 2026, reflecting a shift toward intensified collection against
  critical infrastructure.

  Context: This reflects an ongoing shift toward persistent,
  low-detection-risk credential harvesting as a precursor to targeted
  destructive operations.

  https://recordedfuture.com/research/...
```

Synthesis results are cached for 7 days — subsequent runs are instant.

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

For paywalled sources, add your session cookie to `.env`:

```bash
FEED_COOKIE_RECORDED_FUTURE=your_session_cookie_here
```

---

## STIX 2.1 Export

THEORY produces valid STIX 2.1 bundles importable into:

- **MISP** — import via `Events → Import → STIX 2.x`
- **OpenCTI** — import via the STIX connector
- **Splunk Enterprise Security** — via the TAXII connector
- **Microsoft Sentinel** — via the Threat Intelligence data connector

```bash
python theory.py --actor APT28 --sources mitre,malpedia,otx --output stix
# writes: output/dossiers/apt28.stix.json
```

The bundle includes: identity, intrusion-set, attack-pattern, malware, indicator objects with STIX patterns, relationship objects, and a report wrapper.

---

## Architecture

```
theory.py                          ← CLI entry point and pipeline orchestrator

collectors/
  mitre_attack.py                  ← MITRE ATT&CK (local STIX bundle)
  cisa_advisories.py               ← CISA advisories + KEV + alias table
  malpedia.py                      ← Malpedia malware database
  alienvault_otx.py                ← AlienVault OTX pulses and IOCs
  sigma_rules.py                   ← SigmaHQ GitHub search (enrichment)
  threatfox.py                     ← ThreatFox IOC database (enrichment)
  vendor_intel.py                  ← RSS feed fetcher + relevance scorer
  intelligence_synthesizer.py      ← LLM provider abstraction + synthesis

processors/
  normalizer.py                    ← Scaffold normalizer
  deduplicator.py                  ← Cross-source deduplication

mappers/
  mitre.py                         ← MITRE ATT&CK mapper
  cisa.py                          ← CISA mapper

reporters/
  dossier.py                       ← Rich terminal + markdown output
  json_reporter.py                 ← JSON profile export
  stix_reporter.py                 ← STIX 2.1 bundle export
  csv_reporter.py                  ← IOC-only CSV export

config/
  feeds.yaml                       ← Vendor intelligence feed registry

tests/                             ← 296 passing tests across 9 phases
```

---

## Running the tests

```bash
pytest tests/ -v                              # all 296 tests
pytest tests/test_stix_reporter.py -v        # STIX only
pytest tests/test_phase9_vendor_intel.py -v  # vendor intel only
```

All tests run fully offline — no API keys required for the test suite.

---

## Requirements

- Python 3.11+
- Dependencies in `requirements.txt` (Rich, requests, python-dotenv)
- ATT&CK bundle (downloaded by Quick Start step 3)
- API keys: OTX required for OTX source, others optional

---

## Contributing

THEORY is open-source and community contributions are welcome.

**Adding a new actor** — edit `collectors/cisa_advisories.py` and add an entry to `ALIAS_TABLE`:

```python
"Actor Name": frozenset({
    "actor name", "alias one", "alias two", "mitre-id",
}),
```

**Adding a new source** — see `CONTRIBUTING.md` for the full guide on implementing a collector, mapper, and test suite.

**Adding a vendor feed** — edit `config/feeds.yaml` and add to the `sources` list.

**Reporting issues** — open an issue at `github.com/threatcraft-co/theory/issues`.

---

## Legal

THEORY aggregates publicly available third-party data. See `DISCLAIMER.md` and `LEGAL.md` for full terms, including GDPR provisions and guidance on authorized security research use.

---

## License

MIT License — see `LICENSE` for details.

---

*Built by [Threatcraft](https://github.com/threatcraft-co) — open-source threat intelligence for the security community.*
