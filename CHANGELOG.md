# Changelog

All notable changes to THEORY are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] — Unreleased

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

[1.1.0]: https://github.com/threatcraft-co/theory/releases/tag/v1.1.0
[1.0.0]: https://github.com/threatcraft-co/theory/releases/tag/v1.0.0
