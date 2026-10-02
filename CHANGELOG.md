# Changelog

All notable changes to THEORY are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] — 2026-10-02

v2.0 turns THEORY from a stateless report generator into a tool with memory: every
`--actor` run now feeds a persistent correlation graph that later runs and standalone
queries can draw on, THEORY can answer questions in plain English grounded only in
its own local data, and it can track what changed for an actor over time — including
watching continuously. Also closes out the IOC-enrichment surface with two more
keyless sources and fixes a long-standing confidence-scoring bug.

### Added

- **Persistent correlation graph** (`processors/graph.py`) — every `--actor` run now
  folds its actors, indicators, techniques, malware, CVEs, and campaigns into a
  typed, bidirectional graph persisted at `output/graph/graph.json`. Unlike a single
  dossier, the graph accumulates across every run you've ever made, so it can answer
  questions no single run could. Disable with `--no-graph`.
- **Multi-axis cross-run queries** — `--ioc`, `--technique`, `--attack-type`, and
  `--cve` each work two ways:
  - **Standalone** (no `--actor`): `theory --ioc 1.1.1.1` — what does THEORY know
    about this entity, across every past run?
  - **Combined with `--actor`**: `theory --actor APT28 --ioc 1.1.1.1` — is this
    specific actor connected to this entity, in anything THEORY has ever recorded?
    This is one question, not two reports stapled together — it checks for a direct
    edge first, then a shared one-hop "bridge" node (e.g. both link to the same
    malware family).
  - `--attack-type` (e.g. `ransomware`, `espionage`, `financial`) is deliberately
    grounded in two fields THEORY already collects reliably — actor motivations and
    malware type — rather than a separate, hand-built attack-pattern taxonomy that
    would be easy to get subtly wrong.
  - `--cve` completes the correlation set the 1.1.0 VulDB addition was seeded for.
- **`theory ask "<question>"`** — a provider-agnostic, tool-calling LLM layer
  (`collectors/intelligence_agent.py`) that answers questions using ONLY what
  THEORY has actually recorded: the persistent graph and your personal research
  notes. It never answers from the model's own training data passed off as current
  intel. Works with any configured provider (Claude, OpenAI, Ollama) via a simple
  `TOOL: <name> <argument>` text protocol layered on top of the existing
  `complete()` interface — no provider-specific tool-calling API required, so it's
  fully testable offline. Five tools: `query_ioc`, `query_technique`, `query_actor`,
  `query_cve`, `query_personal`.
- **`theory diff`** — change tracking across runs, with one free step of history:
  `JsonReporter.save()` now rotates the previous `{actor}.json` to
  `{actor}.previous.json` before writing, so `theory diff --actor APT28` works
  immediately after any two `--output json` (or `all`) runs, no new storage format
  or opt-in flag required. `theory diff --from old.json --to new.json` compares any
  two profile files directly. Reports added/removed techniques, malware, indicators,
  CVEs, campaigns, and confidence-level changes.
- **`--watch` / `--watch-interval`** — re-runs an actor query on a timer (default
  hourly) and reports only what changed since the last check, using the same
  diffing engine as `theory diff`, but in-memory across iterations of one session
  (kept deliberately separate from `theory diff`'s disk-based comparison, so each
  stays independently testable). Runs until interrupted with Ctrl+C.
- **`--output sigma-skeleton`** — generates a draft Sigma rule skeleton
  (`processors/sigma_skeleton.py`) for every technique the detection-coverage
  analysis flags as a gap. These are deliberately boilerplate-only: title, a fresh
  rule ID, status, ATT&CK tags, and references are pre-filled from the actor
  profile, but `logsource` and `detection.selection` are left as explicit `TODO`
  markers. THEORY has no way to know your actual log sources or field names, and
  fabricating plausible-looking detection logic would be worse than leaving it
  blank — an analyst starts from "here's the shape" instead of a blank file, not
  from invented logic they might trust too readily.
- **Shodan InternetDB collector** (`shodan_internetdb`) — free, keyless IP
  enrichment (open ports, hostnames, CPEs, known CVEs currently associated with an
  IP). Distinct from the paid Shodan API (never implemented — see "Removed"
  below) — InternetDB is a deliberately stripped-down, free, no-auth lookup
  service Shodan runs for exactly this use case.
- **urlscan.io collector** (`urlscan_io`) — free, keyless public scan-history
  lookups for domain/URL indicators: has anyone already scanned this, what did it
  resolve to (IP/country), and was it flagged malicious. Only ever reads existing
  public scans — THEORY never submits an indicator for scanning, which would both
  require a key and leak the indicator to a third party. An optional
  `URLSCAN_API_KEY` raises the rate limit but is never required.
- **`--cve ID`** flag and `query_cve()` — see "Multi-axis cross-run queries" above.
- **73 new offline tests** across the graph, personal research redirect, LLM
  tool-calling, diff engine, watch mode, Sigma skeleton generator, and the two new
  IP/domain enrichment collectors. Suite grew from 733 to 806 passing.

### Fixed

- **Chronic MEDIUM-confidence bug in cross-source deduplication**
  (`processors/deduplicator.py`). `_HIGH_PROVENANCE_SOURCES` listed the source key
  as `"cisa_advisories"`, but the real CISA collector's `SOURCE_ID` is `"cisa"` —
  `"cisa_advisories"` never appears in any actual pipeline run. Every
  CISA-sourced technique and indicator was silently demoted from MEDIUM to LOW
  confidence on every run since the collector was introduced. The existing test
  fixtures had the identical typo baked in, which is why it went uncaught — fixed
  those too and added two regression tests that lock in both directions.

### Changed

- **Personal research redirect** (`--init-personal`, `--personal-path`, the
  `personal` source) — a gitignored, two-layer indirection
  (`config/local_sources.yaml` → a private indicators file, default
  `~/.theory/personal_indicators.yaml`, outside the repo entirely) so you can keep
  your own research alongside every public source without ever risking committing
  it. Even an accidental commit of the redirect file leaks only a path, never
  research content.

### Removed

- **The `internet-scan` optional dependency group's premise.** `pyproject.toml`
  still declares an installable `shodan`/`censys` extra for the *paid* Shodan and
  Censys APIs, which remain unimplemented and are not on a committed roadmap —
  that gap is now filled by the free, keyless `shodan_internetdb` source above,
  which needs no extra dependency at all. The `.env.example` "planned sources"
  section for `SHODAN_API_KEY`/`CENSYS_API_KEY`/`CRIMINALIP_API_KEY`/
  `VIRUSTOTAL_API_KEY` has been removed accordingly; none of those paid services
  are implemented, and VirusTotal in particular was deliberately skipped in favor
  of urlscan.io, which covers similar ground without requiring a signup.

---

## [1.2.0] — 2026-08-14 to 2026-09-18

Expands actor coverage by two orders of magnitude, adds a structured CVE
pipeline, and ships an optional local web UI.

### Added

- **Actor alias table expanded from ~35 to 1,019 actors (2,455 aliases)**
  (`scripts/import_misp_actors.py`) — a one-time, additive, non-destructive import
  from the MISP Galaxy threat-actor cluster (CC0-licensed, 1,000+ clusters with
  synonyms, country attribution, and MITRE Group ID cross-references). Existing
  hand-curated entries were never overwritten — their alias lists were unioned
  with MISP's synonyms for the same actor, and origin/motivation were filled in
  only where blank. Every other collector that relies on `config/actors.yaml` for
  cross-source name resolution (OTX, Malpedia, CISA advisories, vendor intel)
  benefits immediately, since querying an actor only MISP knew about previously
  meant searching on one name string instead of the full alias set.
- **MISP Galaxy collector** (`misp_galaxy`) — live queries against the same
  threat-actor cluster the import script above uses once, for deep alias lists,
  attribution, and target-sector data on every run. Free, no auth.
- **CISA KEV collector** (`cisa_kev`) — the Known Exploited Vulnerabilities
  catalog as its own source (previously folded into the `cisa` collector), cross-
  referencing CVEs extracted from actor profiles against 1,600+ confirmed-
  exploited CVEs and flagging ransomware associations. Free, no auth.
- **CVE extraction and correlation pipeline** — MITRE ATT&CK technique and
  campaign descriptions are mined for CVE references, which flow through the
  normalizer/deduplicator into a first-class `cves` profile field, then through
  CISA KEV enrichment (`kev_confirmed`, `kev_ransomware`, `kev_vendor`,
  `kev_product`, `kev_date_added`). This is the pipeline `--cve` (v2.0) later
  learned to query directly.
- **`theory serve`** — an optional local web UI (`server/`), built on FastAPI +
  Server-Sent Events, calling the exact same `theory._cli.run()` pipeline as the
  CLI. Binds to `127.0.0.1` by default; nothing leaves your machine except the
  API calls your chosen sources already make. Install with `pip install -e
  ".[serve]"`. See `server/README.md`.
- **NVD collector** (`nvd`) — CVSS scores/vectors, CWE classification, and
  references for CVEs already present in the profile. Free; optional
  `NVD_API_KEY` raises the rate limit from 5 to 50 requests/30s.
- **CIRCL MISP collector** (`circl_misp`) — event-level indicators and campaign
  context from CIRCL's OSINT MISP feed, matched by actor/alias. Free, no auth.
- **Sitemap-based vendor feeds** (`collectors/vendor_intel.py`) — vendor research
  blogs without an RSS feed can now be ingested via `type: sitemap` in
  `config/feeds.yaml`: THEORY fetches the sitemap, filters by `url_pattern`, sorts
  by recency, and follows one level of sitemap indexes. Gzipped sitemaps
  supported. The vendor feed registry grew from ~35 to 50 verified sources.
- **`demo.sh`** — an end-to-end script demonstrating the MISP Galaxy → CVE
  extraction → CISA KEV → ransomware-attribution chain against real actor data.

---

## [1.1.0] — 2026-08-19

Expands intelligence sources from 7 to 13 with six new collectors covering file-based detection, additional IOC types, IP enrichment, and vulnerability correlation.

### Added

- **MalwareBazaar collector** (`malware_bazaar`) — sample hashes (SHA256, MD5, SHA1) with file type, size, and signature metadata, queried by malware family. Requires `ABUSECH_API_KEY`.
- **URLhaus collector** (`urlhaus`) — active and historical malware distribution URLs by family, with online/offline status and payload hash references. Requires `ABUSECH_API_KEY`.
- **GreyNoise collector** (`greynoise`) — IP enrichment that distinguishes targeted activity from internet background noise. Annotates every public IP indicator with noise/RIOT/classification context. Requires `GREYNOISE_API_KEY`.
- **AbuseIPDB collector** (`abuseipdb`) — IP reputation enrichment from community abuse reports. Annotates every public IP indicator with abuse-confidence scores, ISP, country, and usage type. Requires `ABUSEIPDB_API_KEY`.
- **YARA-Rules collector** (`yara`) — file and memory detection rules from the Yara-Rules/rules repository, matched by malware family name. Local clone architecture mirrors SigmaHQ. No auth required.
- **VulDB collector** (`vuldb`) — actor-to-CVE correlation with CVSS scores, exploitability, exploit pricing, and remediation status. Seeds the v2.0 `--cve` correlation layer. Requires `VULDB_API_KEY`.
- **Two new enrichment patterns**: the `collect_for_malware_families()` interface (MalwareBazaar, URLhaus, YARA — pattern shared with existing ThreatFox) and the `enrich_ips()` post-processor interface (GreyNoise, AbuseIPDB).
- **`ABUSECH_API_KEY` shared credential** — one free key from auth.abuse.ch unlocks ThreatFox, MalwareBazaar, and URLhaus. Future-proofs ThreatFox for the pending abuse.ch auth standardization.
- **`--update-bundles` extended** to refresh the YARA-Rules local clone alongside the existing Sigma clone.
- **`cache_ttls` metadata** in `--list-sources` for all six new sources.
- **156 new offline tests** across the six new collectors, bringing the total from 337 to 493+.
- **New source checklist** at `docs/NEW_SOURCE_CHECKLIST.md` — a copy-paste template for every future collector addition covering code, wiring, environment, docs, tests, and verification.

### Changed

- **`.env.example` restructured** into logical sections: LLM providers, core threat intel, abuse.ch ecosystem, IOC enrichment, vulnerability intelligence, v1.2 planned, and optional. Removed unused `MALPEDIA_API_KEY` (Malpedia uses the public API without auth). Moved `NVD_API_KEY` under Vulnerability Intelligence.
- **Source count in intro** updated from 7 to 13, with the new sources listed explicitly in the README.

## [1.0.0] — 2026-08-12

Initial public release.

### Added

- **7 intelligence sources**: MITRE ATT&CK (local STIX bundle), CISA advisories + KEV, Malpedia, AlienVault OTX, SigmaHQ (local clone), ThreatFox, and vendor research blogs (40+ feeds)
- **35 supported threat actors** with 275 aliases and case-insensitive resolution
- **LLM-written intelligence overview** at the top of every dossier, synthesized from all available data (Claude, OpenAI, or Ollama)
- **Vendor intelligence synthesis** via RSS ingestion and LLM relevance scoring
- **Output formats**: terminal dossier, markdown, JSON, STIX 2.1, IOC CSV, HTML, ATT&CK Navigator layer, IR playbook (markdown and Jira wiki markup), and executive summary (BLUF format with optional sector context)
- **Detection coverage gap analysis** against local Sigma rule directories
- **IOC safety**: automatic defanging of all URLs, domains, and IPs in human-readable output
- **Custom feed support** via `config/feeds.yaml`
- **Custom detection repo registry** via `config/detection_repos.yaml`
- **Confidence scoring** with cross-source deduplication
- **ATT&CK Navigator layers** color-coded by confidence level with Sigma coverage boost
- **HTML dossiers** with collapsible sections, sortable TTP tables, tactic filters, IOC freshness indicators, and inline CSS/JS
- **IR playbooks** with IOC blocks, detection checklists, LLM-generated hunt hypotheses, and sector-aware containment guidance
- **Hardened XML parsing** via defusedxml (billion laughs and XXE prevention on RSS feeds)
- **337 fully offline tests** with no API key requirements
- **CI pipeline** with multi-version Python testing (3.11, 3.12), ruff linting, and pip-audit dependency scanning
- **Security audit documentation** and responsible disclosure process

[2.0.0]: https://github.com/threatcraft-co/theory/releases/tag/v2.0.0
[1.2.0]: https://github.com/threatcraft-co/theory/releases/tag/v1.2.0
[1.1.0]: https://github.com/threatcraft-co/theory/releases/tag/v1.1.0
[1.0.0]: https://github.com/threatcraft-co/theory/releases/tag/v1.0.0
