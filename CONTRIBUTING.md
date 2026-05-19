# Contributing to THEORY

Thank you for helping make threat intelligence more accessible. THEORY is built
by the security community, for the security community.

---

## Ways to contribute

- **Add a new actor** to the alias table (easiest, no Python required)
- **Add a new intelligence source** (collector + mapper + tests)
- **Add a vendor feed** to the RSS registry
- **Add a detection repository** to `config/detection_repos.yaml`
- **Fix a bug** or improve an existing collector
- **Improve documentation**
- **Report issues** at github.com/threatcraft-co/theory/issues

For security vulnerabilities, do **not** open a public issue. See
[SECURITY.md](SECURITY.md) for the private disclosure process.

---

## Development setup

```bash
git clone https://github.com/threatcraft-co/theory
cd theory
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Download the ATT&CK bundle
theory --update-bundles

# Run tests before making changes (all should pass)
pytest tests/ -v

# Run linter
ruff check . --select E,F,W --ignore E501,E402,W291,W292,W293,E701,E702,F401,F541,F841,F811,F821
```

---

## Adding a new actor (easiest contribution)

Actors are defined in `config/actors.yaml` — no Python required. The file is
loaded at runtime, and any name or alias in it resolves to the canonical actor
name in dossier output and file naming.

### Format

```yaml
actors:
  Charming Kitten:
    origin: Iran
    motivation: espionage
    aliases:
      - charming kitten
      - apt35
      - phosphorus
      - mint sandstorm
      - ta453
      - cobalt illusion
      - g0059
      - newscaster
      - cobalt mirage
```

### Fields

| Field        | Required | Description                                                    |
| ------------ | -------- | -------------------------------------------------------------- |
| `aliases`    | Yes      | List of all known names in **lowercase**                       |
| `origin`     | No       | Country or region of attribution (`Russia`, `China`, `Iran`, `North Korea`, `unknown`) |
| `motivation` | No       | Primary motivation: `espionage`, `financial`, `hacktivism`, `destruction`, `unknown` |

### Rules

- All aliases must be **lowercase**.
- The top-level key (canonical name) uses title case — it appears in dossier output and filenames.
- Include the **canonical name itself in lowercase** as one of the aliases.
- Include the **MITRE Group ID** (e.g. `g0007`) if the actor is tracked in ATT&CK.
- Include all major vendor naming conventions you know of:
  - **Microsoft Blizzard taxonomy** (e.g. `forest blizzard`, `midnight blizzard`)
  - **CrowdStrike animal taxonomy** (e.g. `fancy bear`, `cozy bear`)
  - **Mandiant FIN/APT numbering** (e.g. `apt28`, `fin7`)
  - **Secureworks Iron/Bronze/Cobalt taxonomy** (e.g. `iron twilight`, `cobalt gypsy`)
  - **Proofpoint TA numbering** (e.g. `ta422`)
  - **CISA UAC designations** when relevant
- No duplicate aliases across different actors.
- Open a PR with a link to at least one authoritative source confirming the actor exists (MITRE ATT&CK page, vendor research, government advisory).

### Verifying your addition

After editing `config/actors.yaml`:

```bash
# Confirm the YAML parses correctly
python -c "import yaml; yaml.safe_load(open('config/actors.yaml'))"

# Confirm alias resolution works
theory --list-actors                  # your actor should appear in the table
theory --actor "your alias here"      # should resolve to the canonical name
```

If `--list-actors` shows your entry with the expected alias count, you're done.

---

## Adding a new intelligence source

A source in THEORY consists of three components:

### 1. Collector (`collectors/<source_name>.py`)

```python
class MySourceCollector:
    def query(self, actor_name: str) -> dict | None:
        """
        Query the source for this actor.
        Returns a raw data dict with source_id set, or None if not found.
        Must handle network errors gracefully — never raise unhandled exceptions.
        """
        return {
            "source_id":  "my_source",
            "actor_name": actor_name,
            "techniques": [...],
            "malware":    [...],
            "indicators": [...],
        }
```

### 2. Mapper (`mappers/<source_name>.py` or inline in collector)

```python
class MySourceMapper:
    def map(self, raw: dict) -> dict:
        """Transform raw collector output to THEORY CommonSchema."""
        return {
            "source_id":  raw["source_id"],
            "actor_name": raw["actor_name"],
            "techniques": [
                {
                    "technique_id":   t["id"],
                    "technique_name": t["name"],
                    "tactic":         t["tactic"],
                    "description":    t.get("description", ""),
                    "detection":      "",
                }
                for t in raw.get("techniques", [])
            ],
            "malware":    raw.get("malware", []),
            "indicators": raw.get("indicators", []),
        }
```

### 3. Tests (`tests/test_<source_name>.py`)

All tests must run fully offline using `unittest.mock`. No real API calls in
the test suite. See `tests/test_threatfox_collector.py` for a good example.

**Minimum test coverage:**

- Collector returns `None` for unknown actor
- Collector handles network errors gracefully (timeout, connection refused, 5xx responses)
- Mapper produces correctly structured output
- Cache save and load works correctly (if your collector caches)

### 4. Register in `theory/_cli.py`

Add your source to `SUPPORTED_SOURCES` and `SOURCE_DESCRIPTIONS`:

```python
SUPPORTED_SOURCES = {
    # existing sources...
    "mysource": "collectors.my_source.MySourceCollector",
}

SOURCE_DESCRIPTIONS = {
    # existing descriptions...
    "mysource": "My Source — description (auth requirements)",
}
```

### 5. Update the README

Add a row to the Sources table in `README.md` so users can discover your
collector.

---

## Adding a vendor feed

Edit `config/feeds.yaml` and add to the `sources` list:

```yaml
- name: Vendor Research Blog
  url: https://vendor.com/blog/security/
  rss: https://vendor.com/blog/security/rss.xml
  type: rss
  tier: 2              # 1=government, 2=major vendor, 3=community
  apt_focus: true      # true if the source specifically covers nation-state actors
  tags: [apt, malware, campaigns]
  enabled: true
```

To verify the RSS feed works before submitting:

```bash
python -c "
from collectors.vendor_intel import _parse_rss_xml
from urllib.request import urlopen
content = urlopen('https://vendor.com/blog/security/rss.xml').read().decode()
entries = _parse_rss_xml(content)
print(f'Found {len(entries)} entries')
print(entries[0] if entries else 'No entries')
"
```

Feeds that consistently return zero entries on multiple verification runs will
be rejected. Stale or broken feeds degrade dossier quality.

---

## Adding a detection repository

THEORY surfaces a list of curated detection repos in every dossier, matched to
the actor's techniques and targeted platforms. To add a new resource, edit
`config/detection_repos.yaml`:

```yaml
- name: "My Detection Library"
  url:  "https://github.com/myorg/detections"
  platform: "splunk"               # or elastic, sentinel, sigma, panther, etc.
  tags: [siem, cloud, identity]    # used for actor matching
  tier: 1                          # 1=vendor-official, 2=community, 3=reference
```

### Requirements

- Must be a **publicly accessible** repository or documentation page.
- Must contain **detection logic** — not just a marketing page or product overview.
- Must be **actively maintained** (commit activity within the last 12 months for community repos).
- Tags should match the existing taxonomy: `siem`, `edr`, `endpoint`, `cloud`,
  `aws`, `azure`, `gcp`, `identity`, `idp`, `network`, `dns`, `c2`, `dfir`,
  `threat-hunting`, `ransomware`, or `universal`.

---

## Pull request checklist

- [ ] All existing tests still pass (`pytest tests/ -v` — should show 310+ passing)
- [ ] New code has tests (fully offline, no real API calls)
- [ ] Linter passes (`ruff check .` with the project's ignore list)
- [ ] New actor entries are added to `config/actors.yaml`, include the MITRE Group ID if applicable, and have 3+ aliases
- [ ] No duplicate aliases with existing entries (verify with `theory --list-actors`)
- [ ] New sources include a collector, a mapper, a test file, and a `SUPPORTED_SOURCES` entry
- [ ] New vendor feeds have been verified to return entries
- [ ] No API keys or secrets in the PR (check `git diff` carefully before pushing)
- [ ] `README.md` updated if you added a user-facing feature
- [ ] Commit messages follow the format `feat:`, `fix:`, `docs:`, `test:`, or `refactor:`

---

## Code style

- Python 3.11+ compatible
- Type hints on all public functions
- Docstrings on all classes and public methods
- No external dependencies beyond those declared in `pyproject.toml`
- All collectors must handle network errors gracefully (try/except, return `None`)
- All collectors must implement caching with a documented TTL
- All IOC values in human-readable output (markdown, HTML, terminal) must be defanged
- All collectors must use a User-Agent header that identifies THEORY by name and links to the repository

---

## Testing philosophy

- **Offline-first.** Every test must be runnable without network access and without API keys. CI runs with all secrets unset.
- **No live data dependencies.** Tests must not assert against specific live actor profiles, IOC values, or vendor article counts — those change. Mock them.
- **Use relative dates.** Tests involving freshness scoring or lookback windows must use `datetime.now() - timedelta(...)` for test data, not hardcoded dates. Hardcoded dates silently fall outside lookback windows and cause silent test failures months later.
- **Fixtures over fakes.** When a collector needs realistic input, place a real-looking JSON sample in `tests/fixtures/` rather than constructing one inline.

---

## Reporting security issues

For security vulnerabilities in THEORY itself — code execution, path traversal,
injection, hardcoded credentials, dependency vulnerabilities, prompt injection,
output integrity issues — do **not** open a public GitHub issue.

See [SECURITY.md](SECURITY.md) for the private disclosure process. Reports go
to `threatcraft@proton.me` with the subject prefix `SECURITY:`.

---

## Questions

Open an issue at github.com/threatcraft-co/theory/issues or reach out at
`threatcraft@proton.me`.

---

*Maintained by [Threatcraft](https://github.com/threatcraft-co).*
