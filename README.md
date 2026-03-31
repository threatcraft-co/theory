# THEORY
### Multi-Source Threat Actor Intelligence Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Status: Active Development](https://img.shields.io/badge/Status-Active%20Development-green.svg)]()

---

## Overview

Theory is an open-source threat intelligence framework that automates adversary profiling using publicly available data sources. Given a single threat actor name as input, Theory systematically queries a curated set of public threat intelligence platforms, aggregates the results, and produces a structured analyst dossier as output.

The project is built on a core principle of the intelligence tradecraft: **no single source tells the whole story.** Theory triangulates across multiple independent data sources to produce a more complete, more reliable picture of an adversary than any one feed can provide on its own.

The output is not raw data. It is a finished intelligence product — a structured, human-readable dossier that maps the adversary's behavior, infrastructure patterns, malware ecosystem, and target profile, with every claim sourced and timestamped.

---

## Motivation

Vendor threat reports from major security firms represent some of the most thorough adversary profiling available — but they are static artifacts. They are written once, published once, and require proprietary telemetry, internal tooling, and large dedicated teams to produce.

Theory explores a different question: **how much actionable intelligence can a disciplined analyst extract using only public sources and open APIs?**

This project does not aim to replicate or compete with enterprise threat intelligence platforms. It is designed to demonstrate that structured, analyst-grade intelligence products can be produced systematically from freely available data — and to build tooling that makes that process repeatable, inspectable, and extensible.

---

## What Theory Produces

For each queried threat actor, Theory generates a structured markdown dossier containing the following sections:

| Section | Description |
|---|---|
| **Executive Summary** | Plain-language overview of the actor, their motivation, and operational scope |
| **Attribution & Background** | Known origin, first observed activity, suspected affiliation or sponsorship |
| **Target Profile** | Industries, geographies, and organization types historically targeted |
| **Tactics, Techniques & Procedures** | Mapped adversary behavior using the MITRE ATT&CK framework |
| **Known Malware & Tooling** | Malware families, custom tools, and commodity software associated with the actor |
| **Infrastructure Indicators** | Domains, IP ranges, certificate patterns, and hosting behaviors |
| **Recent Activity** | Latest public reporting, advisories, and observed campaigns |
| **Detection Opportunities** | Where and how defenders can identify this actor based on their known TTPs |
| **Sources** | Every source cited with retrieval URL and timestamp |

The **Detection Opportunities** section is the distinguishing output of Theory. The framework does not stop at documenting the threat — it translates observed behavior into defensive recommendations, bridging threat intelligence and detection engineering.

---

## Architecture

```
Theory/
│
├── Theory.py              # Main entry point
├── config/
│   └── sources.yaml         # Source configuration and API key management
├── collectors/
│   ├── __init__.py
│   └── [source modules]     # One module per intelligence source
├── processors/
│   ├── __init__.py
│   ├── normalizer.py        # Standardizes data across sources
│   └── deduplicator.py      # Removes overlapping indicators
├── mappers/
│   ├── __init__.py
│   └── mitre.py             # MITRE ATT&CK technique resolution
├── reporters/
│   ├── __init__.py
│   └── dossier.py           # Dossier rendering engine
├── output/
│   └── dossiers/            # Generated dossiers stored here
├── requirements.txt
└── README.md
```

---

## Data Sources

Theory is designed to be **source-agnostic by architecture.** Each intelligence source is implemented as an independent collector module. Sources can be added, removed, or swapped without modifying the core framework.

The current collector suite queries publicly available threat intelligence platforms including government advisory feeds, community-maintained indicator databases, passive DNS and certificate transparency infrastructure, and open-source threat sharing platforms.

A complete and current list of active sources is maintained in [`config/sources.yaml`](config/sources.yaml).

> **Note:** Some sources require free API key registration. See [Setup](#setup) for details.

---

## Sample Output

```
# Threat Actor Dossier: Scattered Spider
Generated: 2025-03-15 | Theory v0.3.0

## Executive Summary
Scattered Spider (also tracked as UNC3944, Octo Tempest) is a financially motivated
threat actor group first observed in 2022. The group is notable for sophisticated
social engineering tradecraft — particularly SIM swapping and helpdesk impersonation —
and has demonstrated an ability to rapidly escalate privileges within targeted
organizations. The group has targeted telecommunications, hospitality, and technology
sectors, with notable intrusions at high-profile organizations throughout 2023-2024.

## Tactics, Techniques & Procedures
| ATT&CK ID | Technique | Description |
|---|---|---|
| T1566.004 | Spearphishing via Voice | Helpdesk impersonation to reset MFA |
| T1621 | MFA Request Generation | MFA fatigue / push bombing |
| T1078 | Valid Accounts | Leveraging stolen credentials post-social engineering |
| T1484 | Domain Policy Modification | Azure AD / Entra ID tenant manipulation |
...

## Detection Opportunities
- Alert on MFA push sequences exceeding threshold within short time window (T1621)
- Monitor helpdesk password reset requests correlated with new device enrollments
- Detect anomalous Azure AD role assignments, particularly to guest accounts
...

## Sources
[1] CISA Advisory AA23-320A — https://www.cisa.gov/... — Retrieved 2025-03-15
[2] MITRE ATT&CK G1015 — https://attack.mitre.org/... — Retrieved 2025-03-15
...
```

---

## Setup

### Prerequisites

- Python 3.8 or higher
- pip
- API keys for applicable sources (free registration — see [`config/sources.yaml`](config/sources.yaml) for links)

### Installation

```bash
# Clone the repository
git clone https://github.com/threatcraft-co/theory.git
cd Theory

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure your API keys
cp config/sources.yaml.example config/sources.yaml
# Edit config/sources.yaml and add your keys
```

---

## Usage

### Basic Query

```bash
python Theory.py --actor "Scattered Spider"
```

### Specify Output Format

```bash
python Theory.py --actor "APT28" --format markdown
python Theory.py --actor "APT28" --format json
```

### Limit to Specific Source Categories

```bash
python Theory.py --actor "LockBit" --sources mitre,advisories
```

### Output Location

By default, dossiers are saved to `output/dossiers/` using the format:
```
output/dossiers/[actor_name]_[timestamp].md
```

---

## Methodology

Theory follows a five-phase collection and analysis cycle on every query:

**1. Normalization**
All incoming data is normalized to a common schema before processing. This prevents duplicate indicators from being counted across sources and ensures clean output regardless of how each source formats its data.

**2. Source Triangulation**
Indicators and behavioral data are cross-referenced across sources. Claims supported by multiple independent sources are weighted more heavily in the final output. Single-source claims are surfaced but flagged.

**3. ATT&CK Mapping**
Known behaviors are mapped to MITRE ATT&CK technique IDs where applicable. This provides a standardized behavioral vocabulary that is meaningful to both offensive and defensive practitioners.

**4. Detection Translation**
ATT&CK mappings are used to derive detection recommendations. Each technique has known detection data sources — Theory surfaces these as concrete defensive recommendations rather than abstract technique references.

**5. Sourced Output**
Every claim in the generated dossier is traceable to its source. No unsourced assertions are included. All sources are logged with retrieval timestamps to support analyst review and reproducibility.

---

## Extending Theory

Adding a new intelligence source requires implementing a single collector module:

```python
# collectors/my_source.py

class MySourceCollector:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def query(self, actor_name: str) -> dict:
        # Query your source
        # Return normalized data dict
        pass
```

Register the module in `config/sources.yaml` and Theory will include it automatically in the collection cycle.

---

## Roadmap

- [x] Core framework architecture
- [x] MITRE ATT&CK integration
- [x] Markdown dossier rendering
- [ ] JSON and STIX 2.1 output formats
- [ ] Sigma rule generation from TTP mappings
- [ ] Batch actor processing
- [ ] Dossier versioning and diff tracking (compare actor activity over time)
- [ ] Web interface for dossier browsing
- [ ] GitHub Actions workflow for scheduled actor monitoring

---

## Limitations

Theory is bounded by the availability and quality of public data. It does not have access to proprietary threat intelligence feeds, classified reporting, or internal telemetry. The framework is designed to surface publicly known information in a structured and repeatable way — it is a research and learning tool, not a replacement for commercial threat intelligence platforms.

Attribution in threat intelligence is inherently uncertain. Theory surfaces attributions as reported by the sources it queries and does not independently validate or assert attribution claims.

---

## Contributing

Contributions are welcome. If you'd like to add a new collector module, improve the dossier template, or extend the detection mapping logic, please open an issue first to discuss the change before submitting a pull request.

Please ensure any new collector modules include:
- Clean error handling for failed or rate-limited API responses
- Normalized output conforming to the common schema
- Documentation in `config/sources.yaml`

---

## Disclaimer

Theory queries publicly available data sources only. No proprietary, classified, or non-public data is accessed. All information surfaced by this tool is available to any member of the public through the referenced sources directly.

This tool is intended for educational purposes, security research, and the development of defensive intelligence capabilities. The author does not condone the use of this tool or its outputs for offensive purposes.

---

## License

MIT License — see [LICENSE](LICENSE) for full terms.

---

## Author

Built and maintained as an open research project in threat intelligence and detection engineering.

---

*Theory is under active development. The roadmap, source list, and output format are subject to change as the project matures.*
