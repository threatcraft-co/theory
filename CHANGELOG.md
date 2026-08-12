# Changelog

All notable changes to THEORY are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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

[1.0.0]: https://github.com/threatcraft-co/theory/releases/tag/v1.0.0
