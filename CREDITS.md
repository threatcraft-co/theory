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

**[ThreatFox](https://threatfox.abuse.ch/)**
IOC database from abuse.ch. Used for malware-attributed indicators of compromise. Accessed via their free public API.

**[CyberMonitor APT Campaign Collection](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections)**
Community-maintained collection of historical APT campaign reports. Used as an optional offline context source when `--update-bundles` is run. Published under [Apache 2.0](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/LICENSE).

---

## Vendor Intelligence Feeds

THEORY's vendor intelligence feature aggregates publicly available RSS feeds from security research blogs including Mandiant, Google TAG, Unit 42 (Palo Alto Networks), Microsoft MSTIC, CrowdStrike, Cisco Talos, Recorded Future, Kaspersky GReAT (Securelist), Check Point Research, SentinelOne Labs, Elastic Security Labs, Proofpoint, Wiz, Datadog Security Labs, Sophos, The DFIR Report, Red Canary, Krebs on Security, Bleeping Computer, and others.

All articles are fetched from their original sources and attributed by name and URL in every dossier. THEORY does not reproduce or redistribute article content — it generates original LLM syntheses with source attribution and links. All rights to original articles remain with their respective publishers.

---

## Python Libraries

| Library | Author / Maintainer | License | Use in THEORY |
|---|---|---|---|
| [Rich](https://github.com/Textualize/rich) | Will McGugan / Textualize | MIT | Terminal dossier rendering |
| [requests](https://github.com/psf/requests) | Kenneth Reitz / PSF | Apache 2.0 | HTTP feed fetching |
| [python-dotenv](https://github.com/theskumar/python-dotenv) | Saurabh Kumar | BSD-3-Clause | `.env` configuration loading |
| [PyYAML](https://github.com/yaml/pyyaml) | Kirill Simonov | MIT | `feeds.yaml` parsing |
| [stix2](https://github.com/oasis-open/csdl-stix-python) | OASIS Open | BSD-3-Clause | STIX 2.1 export |

Standard library modules (`concurrent.futures`, `xml.etree`, `urllib`, `json`, `re`, `argparse`, `logging`, and others) are part of the Python standard library, maintained by the Python Software Foundation under the PSF License.

---

## LLM Providers

THEORY's synthesis engine supports multiple LLM providers. None are required to run THEORY — they are optional for the `vendor` source and actor overview features.

- **[Anthropic Claude](https://www.anthropic.com/)** — via the Anthropic Messages API
- **[OpenAI](https://openai.com/)** — via the OpenAI Chat Completions API
- **[Ollama](https://ollama.com/)** — for fully local, offline inference

THEORY was developed with assistance from **Claude** (Anthropic), which helped design the architecture, write and debug code across all phases, and draft documentation throughout the project.

---

## Development Tools

**[Python](https://www.python.org/)** — Python Software Foundation License
**[pytest](https://pytest.org/)** — MIT License
**[ruff](https://github.com/astral-sh/ruff)** — MIT License
**[git](https://git-scm.com/)** — GPL-2.0
**[git-filter-repo](https://github.com/newren/git-filter-repo)** — MIT License — used to sanitize repository history before public release

---

## Inspiration

THEORY was built in the spirit of the open-source security community — the analysts, researchers, and engineers who publish their work freely so that everyone can build better defenses. Special thanks to the maintainers of every data source and library listed above for keeping their work public and free.

---

*THEORY is not affiliated with, endorsed by, or sponsored by any of the organizations listed above.*
