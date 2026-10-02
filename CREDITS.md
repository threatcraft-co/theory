# Credits

THEORY is original work by [Threatcraft](https://github.com/threatcraft-co), built from scratch. No existing repositories were forked. The following data sources, APIs, libraries, and tools made it possible.

---

## Threat Intelligence Data Sources

**[MITRE ATT&CK](https://attack.mitre.org/)**
The foundational framework THEORY is built around. TTP data, technique descriptions, actor profiles, campaigns, and malware relationships are sourced from the ATT&CK STIX bundle, published by The MITRE Corporation under the [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) license. THEORY is not affiliated with or endorsed by MITRE.

**[CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)**
Advisories and actor attribution data from the U.S. Cybersecurity and Infrastructure Security Agency, a U.S. government agency. Content is in the public domain.

**[Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)**
Malware family database maintained by Fraunhofer FKIE. Used for malware descriptions, aliases, and YARA rule counts. Accessed via their public API.

**[AlienVault OTX](https://otx.alienvault.com/)**
Threat intelligence pulses and IOC data from AT&T Cybersecurity's Open Threat Exchange. Accessed via their free public API.

**[SigmaHQ](https://github.com/SigmaHQ/sigma)**
Community detection rules mapped to ATT&CK techniques. Maintained by the Sigma project contributors. Published under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md). THEORY clones the SigmaHQ repository locally and queries it offline — no Sigma rules are redistributed.

**[Yara-Rules](https://github.com/Yara-Rules/rules)**
Community file and memory detection rules, matched to malware family names. THEORY clones this repository locally and queries it offline, mirroring the SigmaHQ architecture — no rules are redistributed.

**[ThreatFox](https://threatfox.abuse.ch/)**
IOC database from abuse.ch. Used for malware-attributed indicators of compromise. Accessed via their free public API.

**[MalwareBazaar](https://bazaar.abuse.ch/)**
Malware sample hash database (SHA256/MD5/SHA1) from abuse.ch, queried by malware family. Accessed via their free API (requires a free `auth.abuse.ch` key, shared with ThreatFox and URLhaus).

**[URLhaus](https://urlhaus.abuse.ch/)**
Active and historical malware distribution URL database from abuse.ch. Accessed via their free API (shared `auth.abuse.ch` key).

**[GreyNoise](https://www.greynoise.io/)**
IP enrichment distinguishing targeted activity from internet background noise. Accessed via the GreyNoise Community API (free tier, registration required).

**[AbuseIPDB](https://www.abuseipdb.com/)**
Community-sourced IP abuse reporting and reputation scoring. Accessed via their free API tier.

**[Shodan InternetDB](https://internetdb.shodan.io/)**
Free, keyless lookup service run by Shodan — open ports, hostnames, CPEs, and known CVEs currently associated with an IP. Distinct from Shodan's paid search API, which THEORY does not use or require.

**[urlscan.io](https://urlscan.io/)**
Public scan-history search for domains and URLs — prior verdicts, resolved IP/country. THEORY only reads existing public scan results via the free search endpoint; it never submits anything for scanning.

**[VulDB](https://vuldb.com/)**
Actor-to-CVE correlation, CVSS scoring, and exploit intelligence. Accessed via their API (free tier: 50 credits/day).

**[NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/)**
CVSS scores and vectors, CWE classification, and reference links for CVEs. A U.S. government resource; content is in the public domain. Accessed via the free NVD API.

**[MISP Galaxy](https://github.com/MISP/misp-galaxy)**
Threat-actor cluster data — 1,000+ actors with synonyms, country attribution, and MITRE Group ID cross-references. Maintained by the MISP Project and contributors, published under [CC0 1.0](https://github.com/MISP/misp-galaxy/blob/main/LICENSE). Queried live as the `misp_galaxy` source, and used once via `scripts/import_misp_actors.py` to expand THEORY's own `config/actors.yaml` alias table from ~35 to 1,019 actors.

**[CIRCL MISP OSINT feed](https://www.circl.lu/)**
Event-level indicators and campaign context from the Computer Incident Response Center Luxembourg's public OSINT MISP instance. Accessed via their free public feed.

**[CyberMonitor APT Campaign Collection](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections)**
Community-maintained collection of historical APT campaign reports. Used as an optional offline context source when `--update-bundles` is run. Published under [Apache 2.0](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/LICENSE).

---

## Vendor Intelligence Feeds

THEORY's vendor intelligence feature aggregates 50 publicly available RSS and sitemap feeds from security research blogs including Mandiant, Google TAG, Unit 42 (Palo Alto Networks), Microsoft MSTIC, CrowdStrike, Cisco Talos, Recorded Future, Kaspersky GReAT (Securelist), Check Point Research, SentinelOne Labs, Elastic Security Labs, Proofpoint, Wiz, Datadog Security Labs, Sophos, The DFIR Report, Red Canary, Krebs on Security, Bleeping Computer, and others.

All articles are fetched from their original sources and attributed by name and URL in every dossier. THEORY does not reproduce or redistribute article content — it generates original LLM syntheses with source attribution and links. All rights to original articles remain with their respective publishers.

---

## Python Libraries

| Library | Author / Maintainer | License | Use in THEORY |
|---|---|---|---|
| [Rich](https://github.com/Textualize/rich) | Will McGugan / Textualize | MIT | Terminal dossier rendering |
| [requests](https://github.com/psf/requests) | Kenneth Reitz / PSF | Apache 2.0 | HTTP feed fetching |
| [python-dotenv](https://github.com/theskumar/python-dotenv) | Saurabh Kumar | BSD-3-Clause | `.env` configuration loading |
| [PyYAML](https://github.com/yaml/pyyaml) | Kirill Simonov | MIT | `feeds.yaml` / `actors.yaml` parsing |
| [stix2](https://github.com/oasis-open/csdl-stix-python) | OASIS Open | BSD-3-Clause | STIX 2.1 export |
| [feedparser](https://github.com/kurtmckee/feedparser) | Kurt McKee et al. | BSD-2-Clause | RSS/Atom vendor feed parsing |
| [python-dateutil](https://github.com/dateutil/dateutil) | Gustavo Niemeyer et al. | Apache 2.0 / BSD | Flexible date parsing across source formats |
| [Jinja2](https://github.com/pallets/jinja) | Pallets | BSD-3-Clause | HTML dossier templating |
| [click](https://github.com/pallets/click) | Pallets | BSD-3-Clause | CLI ergonomics helpers |
| [watchdog](https://github.com/gorakhargosh/watchdog) | Yesudeep Mangalapilly et al. | Apache 2.0 | Filesystem watching |
| [schedule](https://github.com/dbader/schedule) | Daniel Bader | MIT | Lightweight job scheduling |
| [defusedxml](https://github.com/tiran/defusedxml) | Christian Heimes | PSF License | Hardened XML parsing — refuses entity expansion and XXE on attacker-influenceable RSS feeds |
| [FastAPI](https://github.com/tiangolo/fastapi) | Sebastián Ramírez | MIT | Optional local web UI (`theory serve`) |
| [uvicorn](https://github.com/encode/uvicorn) | Encode | BSD-3-Clause | ASGI server for the optional web UI |
| [sse-starlette](https://github.com/sysid/sse-starlette) | Thomas Schmidt | BSD-3-Clause | Server-Sent Events for the optional web UI's live progress |

Standard library modules (`concurrent.futures`, `xml.etree`, `urllib`, `json`, `re`, `argparse`, `logging`, and others) are part of the Python standard library, maintained by the Python Software Foundation under the PSF License.

---

## LLM Providers

THEORY's synthesis engine supports multiple LLM providers. None are required to run THEORY — they are optional for the `vendor` source and actor overview features.

- **[Anthropic Claude](https://www.anthropic.com/)** — via the Anthropic Messages API
- **[OpenAI](https://openai.com/)** — via the OpenAI Chat Completions API
- **[Ollama](https://ollama.com/)** — for fully local, offline inference

THEORY was developed with assistance from **Claude** (Anthropic), which helped design the architecture, write and debug code across all phases — including the v2.0 persistent correlation graph, multi-axis queries, tool-calling `theory ask`, change tracking, and new collectors — and draft documentation throughout the project.

---

## Development Tools

**[Python](https://www.python.org/)** — Python Software Foundation License
**[pytest](https://pytest.org/)** — MIT License
**[pytest-cov](https://github.com/pytest-dev/pytest-cov)** — MIT License
**[ruff](https://github.com/astral-sh/ruff)** — MIT License
**[pip-audit](https://github.com/pypa/pip-audit)** — Apache 2.0 — supply-chain vulnerability scanning in CI
**[git](https://git-scm.com/)** — GPL-2.0
**[git-filter-repo](https://github.com/newren/git-filter-repo)** — MIT License — used to sanitize repository history before public release

---

## Inspiration

THEORY was built in the spirit of the open-source security community — the analysts, researchers, and engineers who publish their work freely so that everyone can build better defenses. Special thanks to the maintainers of every data source and library listed above for keeping their work public and free.

---

*THEORY is not affiliated with, endorsed by, or sponsored by any of the organizations listed above.*
