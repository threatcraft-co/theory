![Theory Logo](media/Theory%20Logo.png)

[![CI](https://github.com/threatcraft-co/theory/actions/workflows/ci.yml/badge.svg)](https://github.com/threatcraft-co/theory/actions/workflows/ci.yml)

**Multi-source threat actor intelligence for everyone — with memory.**

THEORY is an open-source alternative to enterprise threat intelligence platforms. It generates analyst-grade dossiers on threat actors by aggregating data from 20 free and keyless-by-default sources — MITRE ATT&CK, MISP Galaxy, CIRCL MISP, Malpedia, AlienVault OTX, SigmaHQ, YARA-Rules, ThreatFox, MalwareBazaar, URLhaus, GreyNoise, AbuseIPDB, Shodan InternetDB, urlscan.io, VulDB, NVD, CISA, CISA KEV, and vendor research blogs — then synthesizes everything using an LLM into a clean executive overview and actor-specific intelligence summaries.

As of v2.0, THEORY isn't stateless. Every run feeds a **persistent correlation graph** that accumulates across every query you've ever made, so you can ask "have I ever seen this IP?" or "is this actor connected to this CVE?" without re-running collection, track what's changed for an actor over time, and even watch one continuously.

Built for threat intelligence analysts, detection engineers, security researchers, and students who believe good intelligence shouldn't require a six-figure subscription.

---

## What THEORY produces

For any supported threat actor, THEORY generates:

- **LLM-written synopsis** — 4-6 sentence executive overview synthesized from all available data, at the top of every dossier
- **TTP table** — every known technique with tactic, confidence score, and detection guidance
- **Detection opportunities** — Sigma rules mapped to actor TTPs and YARA rules matched to malware families, plus draft Sigma rule skeletons for every gap
- **Malware inventory** — all associated families with full descriptions, sample hashes (MalwareBazaar), and YARA detection coverage
- **IOC table** — deduplicated, defanged indicators from OTX, ThreatFox, MalwareBazaar, URLhaus, and CIRCL MISP with confidence scores and malware family attribution
- **IP and domain enrichment** — GreyNoise noise/RIOT context, AbuseIPDB reputation scores, Shodan InternetDB open-port/CVE data, and urlscan.io scan history annotate every public IP and domain/URL indicator so analysts can distinguish real infrastructure from internet background radiation
- **Vulnerability intelligence** — CVEs extracted from actor TTPs and cross-referenced against CISA KEV, NVD, and VulDB, with CVSS scores, exploit availability, and remediation status
- **Recent intelligence** — LLM-synthesized summaries of recent vendor research articles, with source attribution and links
- **Campaigns** — full campaign descriptions with dates and ATT&CK links
- **Targeted sectors** and CISA advisories
- **IR playbooks** — analyst-ready checklists with IOC blocks, detection checklists, hunt hypotheses, and containment guidance
- **ATT&CK Navigator layers** — confidence-colored heatmaps importable directly into MITRE Navigator
- **HTML dossiers** — self-contained, shareable intelligence reports that open in any browser
- **Detection coverage gap reports** — compare actor TTPs against your local detection rules

And, persisted across every run rather than per-dossier:

- **A correlation graph** you can query directly — by indicator, technique, CVE, or attack type — with or without re-running collection
- **Change tracking** — what's new or different for an actor since the last time you checked, on demand or continuously
- **Grounded Q&A** — ask a question in plain English and get an answer sourced only from what THEORY has actually recorded

Output formats: terminal dossier, markdown, JSON, STIX 2.1 (for MISP/OpenCTI/Sentinel), IOC CSV, HTML, ATT&CK Navigator, IR playbook (markdown or Jira), and Sigma rule skeletons.

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
# Everything else — including 2 of the 20 sources — needs no key at all

# 6. Run your first dossier
theory --actor APT28
```

That's it. Your first dossier renders in the terminal and saves to `output/dossiers/apt28.md` — and the run is now in your local correlation graph at `output/graph/graph.json`, ready to query.

```bash
# Ask the graph directly, any time after that first run
theory --ioc 1.1.1.1
theory ask "what do we know about APT28's malware?"
```

---

## Sources

20 sources, 15 of which need no API key or signup at all.

| Key | Source | Auth Required | Cache |
|---|---|---|---|
| `mitre` | MITRE ATT&CK — techniques, malware, campaigns (local bundle) | None | 7 days |
| `cisa` | CISA advisories + KEV catalog | None | Per request |
| `cisa_kev` | CISA KEV — 1,600+ confirmed-exploited CVEs, ransomware flags | None | 24 hours |
| `malpedia` | Malpedia malware family database | None | Per request |
| `misp_galaxy` | MISP Galaxy — 1,000+ actors, aliases, attribution, target sectors | None | 7 days |
| `circl_misp` | CIRCL OSINT MISP feed — event-level indicators + campaign context | None | 24h / 7 days |
| `otx` | AlienVault OTX pulses + IOCs | `OTX_API_KEY` | Per request |
| `nvd` | NIST NVD — CVSS scores, CWE classification, references | None (optional key raises rate limit) | 30 days/CVE |
| `sigma` | SigmaHQ detection rules mapped to ATT&CK (local clone) | None (`GITHUB_TOKEN` optional) | 7 days |
| `yara` | YARA file detection rules matched to malware families (local clone) | None | 7 days |
| `threatfox` | ThreatFox IOCs by malware family | None | 24 hours |
| `malware_bazaar` | MalwareBazaar sample hashes by malware family | `ABUSECH_API_KEY` | 24 hours |
| `urlhaus` | URLhaus malware distribution URLs by family | `ABUSECH_API_KEY` | 24 hours |
| `greynoise` | GreyNoise IP noise/RIOT context | `GREYNOISE_API_KEY` | 7 days |
| `abuseipdb` | AbuseIPDB IP reputation scores from community reports | `ABUSEIPDB_API_KEY` | 3 days |
| `shodan_internetdb` | Shodan InternetDB — open ports, hostnames, CPEs, known CVEs on an IP | None | 24 hours |
| `urlscan_io` | urlscan.io public scan history for domains/URLs | None (optional key raises rate limit) | 24 hours |
| `vuldb` | VulDB actor-CVE correlation and exploit intelligence | `VULDB_API_KEY` | 7 days |
| `vendor` | Vendor intelligence synthesis — 50 research blogs, LLM-synthesized | LLM API key | 7 days |
| `personal` | Your own local research indicators — gitignored, never leaves your machine | None | none (reads live) |

`shodan_internetdb` is **not** the paid Shodan search API — it's Shodan's own free, keyless InternetDB lookup service, a deliberately different thing. The paid Shodan and Censys APIs remain unimplemented (see `pyproject.toml`'s `internet-scan` extra); VirusTotal was considered and skipped in favor of urlscan.io, which covers similar ground without a signup.

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

# IP + domain enrichment (GreyNoise, AbuseIPDB, Shodan InternetDB, urlscan.io)
theory --actor APT28 --sources mitre,otx,threatfox,greynoise,abuseipdb,shodan_internetdb,urlscan_io

# Vulnerability intelligence (CISA KEV + NVD + VulDB)
theory --actor APT28 --sources mitre,cisa_kev,nvd,vuldb

# Your own research alongside public sources
theory --actor APT28 --sources personal,mitre,cisa

# Everything, with vendor intelligence synthesis (requires LLM key in .env)
theory --actor APT28 --sources mitre,cisa,cisa_kev,malpedia,misp_galaxy,circl_misp,otx,nvd,sigma,yara,threatfox,malware_bazaar,urlhaus,greynoise,abuseipdb,shodan_internetdb,urlscan_io,vuldb,vendor
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

# Draft Sigma rule skeletons for every detection gap
theory --actor APT28 --sources mitre,sigma --output sigma-skeleton

# All formats at once
theory --actor APT28 --output all

# Print only — don't write files, don't touch the correlation graph
theory --actor APT28 --no-save --no-graph
```

### Cross-run graph queries

Every `--actor` run feeds a persistent correlation graph at `output/graph/graph.json` — a typed, bidirectional graph of actors, indicators, techniques, malware, CVEs, and campaigns that accumulates across every run you've ever made. You can query it directly, two ways:

```bash
# Standalone — what does THEORY know about this, across every past run?
theory --ioc 1.1.1.1
theory --technique T1566
theory --attack-type ransomware
theory --cve CVE-2023-23397

# Combined with --actor — one question: is THIS actor connected to THIS
# entity, in anything THEORY has ever recorded? (Not two reports stapled
# together — checks for a direct link first, then a shared "bridge" node.)
theory --actor APT28 --ioc 1.1.1.1
theory --actor APT28 --technique T1566
theory --actor APT28 --attack-type espionage
theory --actor APT28 --cve CVE-2023-23397
```

`--attack-type` is deliberately grounded in two fields THEORY already collects reliably — actor motivations and malware type — rather than a separate, hand-built attack-pattern taxonomy. Disable graph writes for a one-off run with `--no-graph`.

### Grounded Q&A — `theory ask`
```bash
theory ask "what do we know about 1.1.1.1?"
theory ask "is APT28 connected to T1566?"
theory ask "what are my own notes on Lazarus Group?"
```

Answers come **only** from what THEORY has actually recorded — the persistent graph and your personal research notes — never from the model's own training data passed off as current intel. Works with any configured LLM provider (Claude, OpenAI, Ollama) via a provider-agnostic tool-calling protocol.

### Change tracking — `theory diff` and `--watch`
```bash
# Compare the last two JSON runs for an actor (free — one step of history
# is kept automatically whenever you run --output json or all)
theory --actor APT28 --output json
# ... time passes, new intel appears, you run again ...
theory --actor APT28 --output json
theory diff --actor APT28

# Compare any two profile files directly
theory diff --from old.json --to new.json

# Re-run on a timer and report only what changed (Ctrl+C to stop)
theory --actor APT28 --watch
theory --actor APT28 --watch --watch-interval 900   # every 15 minutes
```

### Your own local research
```bash
# One-time setup — creates a gitignored redirect + starter file
theory --init-personal

# Add your own indicators to ~/.theory/personal_indicators.yaml, then:
theory --actor APT28 --sources personal,mitre,cisa
```

Two-layer, gitignored indirection: `config/local_sources.yaml` → a private file outside the repo entirely (default `~/.theory/personal_indicators.yaml`, overridable with `--personal-path`). Even an accidental commit of the redirect leaks only a path, never your research.

### Detection coverage gap analysis
```bash
# Compare actor TTPs against your local detection rules
theory --actor APT28 --sources mitre,sigma --detection-path ~/my-sigma-rules

# Output: coverage %, covered techniques, and gaps sorted by confidence

# Turn every gap into a starting-point Sigma rule (logsource/selection left as TODO)
theory --actor APT28 --sources mitre,sigma --output sigma-skeleton
```

### Browse what's available
```bash
theory --list-actors    # 1,019 supported actors with 2,455 aliases
theory --list-sources   # all 20 sources with auth and cache info
```

### Maintenance
```bash
# Refresh ATT&CK bundle, Sigma rules, YARA rules, MISP Galaxy cluster, and CISA KEV catalog
theory --update-bundles
```

### Verbose / debug mode
```bash
theory --actor APT28 --sources mitre,cisa --verbose
```

### Optional local web UI
```bash
pip install -e ".[serve]"
theory serve                     # localhost:8088, opens browser
```

Same pipeline as the CLI, nothing leaves your machine. See `server/README.md`. (The v2.0 graph queries, `theory ask`, `diff`, and `--watch` are CLI-only for now.)

---

## Alias resolution

THEORY knows **1,019 actors** by all their names (**2,455 aliases** total — expanded from an initial hand-curated ~35 via a one-time MISP Galaxy import). Any alias resolves to the same canonical dossier:

```bash
theory --actor "Cozy Bear"          # → APT29
theory --actor "Midnight Blizzard"  # → APT29
theory --actor "Nobelium"           # → APT29
theory --actor "NOBELIUM"           # → APT29 (case-insensitive)
```

The output file is always named by the canonical actor — `--actor "Fancy Bear"` produces `apt28.md`, not `fancy_bear.md`. Querying an actor THEORY doesn't have an alias entry for still works — it just falls back to the raw name you typed instead of resolving the full alias set, which costs some recall on sources other than `misp_galaxy` itself.

```bash
theory --list-actors    # see all 1,019 actors and their aliases
```

---

## LLM Actor Synopsis

Every dossier opens with an **Intelligence Overview** — a 4-6 sentence executive synopsis written by Claude (or your configured LLM) using the full aggregated profile as context.

The synopsis:
- Uses the name you queried, not aliases
- Covers origin, motivations, target sectors, signature TTPs, notable malware, and recent activity
- Works with or without `--sources vendor` — synthesizes from structured MITRE data alone if needed
- Appears at the top of both the terminal output and the markdown file

**LLM provider resolution order:** Claude → OpenAI → Ollama. Set `THEORY_LLM_PROVIDER` in `.env` to override, or leave blank to auto-detect. Ollama runs fully offline. The same provider resolution backs `theory ask` and the LLM-generated playbook/exec-summary content.

---

## Vendor Intelligence Synthesis

When you add `vendor` to your sources, THEORY fetches recent articles from 50 threat research blogs (Mandiant, Google TAG, Unit 42, Secureworks, Recorded Future, CrowdStrike, Kaspersky GReAT, Check Point Research, Sophos, Proofpoint, and more) and uses an LLM to synthesize what each article reveals about your actor specifically. Sites without an RSS feed can be ingested via a sitemap-based feed type instead — see "Adding custom feeds" below.

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

Detection rules are linked directly to actor TTPs in the dossier. Techniques with no matching rule show up in the detection-coverage gap analysis below, and can be turned into draft rule skeletons with `--output sigma-skeleton`. See `docs/SIGMA_RATE_LIMITS.md` for full architecture details.

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

## IP and Domain Enrichment

Every public IP indicator can be annotated with up to three independent reputation/context signals, and every domain/URL indicator with one more:

- **GreyNoise** distinguishes targeted activity from internet background noise. An IP flagged as RIOT (known benign service like a CDN or DNS resolver) or as scanning noise is almost certainly a false positive.
- **AbuseIPDB** provides a community abuse-confidence score (0-100) reflecting how many independent reporters have flagged the IP as abusive.
- **Shodan InternetDB** reports what the infrastructure actually looks like right now — open ports, hostnames, CPEs, and any CVEs Shodan has flagged against the IP. Free and keyless; a different question than the two above ("what does this look like" vs. "is this malicious").
- **urlscan.io** reports whether anyone has publicly scanned a domain or URL already, what it resolved to, and whether it was flagged malicious. Free and keyless; only ever reads existing public scans.

```bash
# Enrich IPs with all three IP sources, plus domain/URL scan history
theory --actor APT28 --sources mitre,otx,threatfox,greynoise,abuseipdb,shodan_internetdb,urlscan_io
```

Free tier limits are conservative — GreyNoise Community is 50 lookups/week and AbuseIPDB is 1,000 checks/day, so THEORY caps enrichment per run (25 for GreyNoise, 50 for AbuseIPDB, 40 for Shodan InternetDB and urlscan.io) and caches aggressively (7 days for GreyNoise, 3 for AbuseIPDB, 24 hours for the two newer keyless sources since open ports and scan history change faster than IP reputation).

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

## Vulnerability Intelligence

CVEs mentioned in MITRE ATT&CK technique and campaign descriptions are extracted automatically and cross-referenced against three sources:

- **CISA KEV** — flags confirmed-exploited CVEs and ransomware associations (1,600+ entries). Free, no auth.
- **NVD** — CVSS scores and vectors, CWE classification, and reference links for CVEs already in the profile. Free; an optional `NVD_API_KEY` raises the rate limit from 5 to 50 requests/30s.
- **VulDB** — actor-to-CVE correlation with exploitability and exploit-pricing data. Requires `VULDB_API_KEY` (free tier: 50 credits/day).

```bash
theory --actor APT28 --sources mitre,cisa_kev,nvd,vuldb
```

Once a CVE is in the graph, you can query it directly — see "Cross-run graph queries" above.

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

Saves a markdown report to `output/dossiers/<actor>_coverage_gap.md`. Turn every gap directly into a starting-point Sigma rule:

```bash
theory --actor APT28 --sources mitre,sigma --output sigma-skeleton
# writes: output/dossiers/<actor>_sigma_skeletons.yml
```

Skeletons are deliberately boilerplate-only — title, rule ID, status, ATT&CK tags, and references are filled in, but `logsource` and `detection.selection` are left as explicit `TODO` markers for you to fill in from your own environment. THEORY has no way to know your log sources, and a plausible-looking fabricated rule is worse than a blank one.

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

Sites without an RSS feed can be ingested via a sitemap instead:

```yaml
custom:
  - name: Vendor Without RSS
    url: https://vendor.com/blog/
    sitemap: https://vendor.com/sitemap.xml
    type: sitemap
    url_pattern: "/blog/"       # filters the sitemap to relevant URLs
    tier: 2
    tags: [vendor]
    enabled: true
```

THEORY fetches the sitemap, filters by `url_pattern`, sorts by recency, and follows one level of sitemap indexes (gzipped sitemaps supported).

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
  circl_misp.py                      ← CIRCL OSINT MISP feed
  malpedia.py                        ← Malpedia malware database
  alienvault_otx.py                  ← AlienVault OTX pulses and IOCs
  nvd.py                             ← NIST NVD CVE enrichment
  sigma_rules.py                     ← SigmaHQ local clone (no rate limits)
  yara_rules.py                      ← YARA-Rules local clone (file/memory detection)
  threatfox.py                       ← ThreatFox IOC database (network C2)
  malware_bazaar.py                  ← MalwareBazaar sample hashes (file IOCs)
  urlhaus.py                         ← URLhaus malware distribution URLs
  greynoise.py                       ← GreyNoise IP noise/RIOT enrichment
  abuseipdb.py                       ← AbuseIPDB IP reputation enrichment
  shodan_internetdb.py               ← Shodan InternetDB IP enrichment (free, keyless)
  urlscan_io.py                      ← urlscan.io domain/URL scan-history enrichment
  vuldb.py                           ← VulDB actor-CVE correlation
  vendor_intel.py                    ← RSS/sitemap feed fetcher + relevance scorer
  intelligence_synthesizer.py        ← LLM provider abstraction + synthesis
  intelligence_agent.py              ← provider-agnostic tool-calling loop (`theory ask`)
  personal_intel.py                  ← gitignored personal research redirect

processors/
  normalizer.py                      ← Schema validation and normalization
  deduplicator.py                    ← Cross-source dedup + confidence scoring
  correlator.py                      ← cross-referenced views: kill chain, coverage, priority actions
  graph.py                           ← persistent correlation graph + multi-axis queries
  diff.py                            ← change-tracking engine (`theory diff` / `--watch`)
  sigma_skeleton.py                  ← draft Sigma rule generation for detection gaps

mappers/
  mitre.py                           ← MITRE ATT&CK mapper
  cisa.py                            ← CISA mapper

reporters/
  dossier.py                         ← Rich terminal + markdown output
  json_reporter.py                   ← JSON profile export (rotates .previous.json for diffing)
  stix_reporter.py                   ← STIX 2.1 bundle export
  csv_reporter.py                    ← IOC-only CSV export
  html_reporter.py                   ← Self-contained HTML dossier
  navigator_reporter.py              ← ATT&CK Navigator layer export
  playbook_reporter.py               ← IR playbook (markdown + Jira)

server/                              ← optional local web UI (`theory serve`, FastAPI + SSE)

config/
  feeds.yaml                         ← 50 verified vendor intelligence feeds
  detection_repos.yaml               ← curated detection repo registry
  actors.yaml                        ← 1,019 actors / 2,455 aliases (curated + MISP Galaxy import)

scripts/
  import_misp_actors.py              ← one-time, additive MISP Galaxy actor-table expansion

docs/
  SIGMA_RATE_LIMITS.md               ← Sigma architecture docs
  SCHEDULED_UPDATES.md               ← Cron/launchd automation setup
  SECURITY_AUDIT_2026-06.md          ← Security audit documentation
  NEW_SOURCE_CHECKLIST.md            ← checklist for adding a new collector

tests/                               ← 806+ offline tests
```

---

## Running the tests

```bash
pytest tests/ -v                              # all tests
pytest tests/test_graph.py -v                 # persistent correlation graph only
pytest tests/test_stix_reporter.py -v         # STIX only
pytest tests/test_security_hardening.py -v    # security hardening
```

All tests run fully offline — no API keys required. Four environment variables
(`ABUSEIPDB_API_KEY`, `VULDB_API_KEY`, `GREYNOISE_API_KEY`, `ABUSECH_API_KEY`) should
be set to throwaway values (e.g. `fake`) when running the suite locally, so a real
key in your own `.env` can't accidentally change which code path a "missing key"
test exercises — CI always runs with all secrets unset.

---

## Requirements

- Python 3.11+
- Dependencies installed via `pip install -e .`
- ATT&CK bundle downloaded via `theory --update-bundles`
- API keys: see `.env.example` for the full list with registration links — only `OTX_API_KEY` is needed for the default-plus-community experience; 15 of the 20 sources need no key at all

---

## Contributing

See `CONTRIBUTING.md` for the full guide. Quick reference:

**Adding a new actor** — edit `config/actors.yaml` and add a new entry with the canonical name, aliases, and metadata. See the existing entries in that file for the schema.

**Adding a new source** — implement collector, mapper, and tests. See `CONTRIBUTING.md` and `docs/NEW_SOURCE_CHECKLIST.md`.

**Adding a vendor feed** — edit `config/feeds.yaml` and add to the `sources` list (RSS or sitemap).

**Reporting issues** — `github.com/threatcraft-co/theory/issues`

---

## Legal

THEORY aggregates publicly available third-party data. See `DISCLAIMER.md` and `LEGAL.md` for full terms.

---

## License

MIT License — see `LICENSE` for details.

---

*Built by [Threatcraft](https://github.com/threatcraft-co) — open-source threat intelligence for the security community.*
