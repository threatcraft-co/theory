# Contributing to THEORY

Thank you for helping make threat intelligence more accessible. THEORY is built
by the security community, for the security community.

---

## Ways to contribute

- **Add a new actor** to the alias table
- **Add a new intelligence source** (collector + mapper + tests)
- **Add a vendor feed** to the RSS registry
- **Fix a bug** or improve an existing collector
- **Improve documentation**
- **Report issues** at github.com/threatcraft-co/theory/issues

---

## Adding a new actor (easiest contribution)

Edit `collectors/cisa_advisories.py` and add an entry to `ALIAS_TABLE`.

The alias table is a dict mapping a canonical actor name to a frozenset of
all known aliases in lowercase. The canonical name is the name THEORY uses
in dossier output and file names.

```python
# In collectors/cisa_advisories.py, inside ALIAS_TABLE:

"Charming Kitten": frozenset({
    "charming kitten",   # canonical (lowercase)
    "apt35",             # MITRE ID
    "phosphorus",        # Microsoft naming
    "mint sandstorm",    # Microsoft Blizzard naming
    "ta453",             # Proofpoint naming
    "cobalt illusion",   # Secureworks naming
    "g0059",             # MITRE Group ID
}),
```

**Rules:**
- All aliases must be lowercase
- Include MITRE Group ID (G####) as an alias
- Include all major vendor naming conventions you know of
- The canonical name uses title case as it will appear in output
- Open a PR with a link to at least one source confirming the actor exists

---

## Adding a new intelligence source

A source in THEORY consists of three components:

### 1. Collector (`collectors/<source_name>.py`)

The collector fetches raw data from the source and returns it in a
consistent dict structure. Follow this interface:

```python
class MySourceCollector:
    def query(self, actor_name: str) -> dict | None:
        """
        Query the source for this actor.

        Args:
            actor_name: Canonical actor name (e.g. "APT28")

        Returns:
            Raw data dict with source_id set, or None if not found.
        """
        # ... fetch data ...
        return {
            "source_id":    "my_source",
            "actor_name":   actor_name,
            "techniques":   [...],
            "malware":      [...],
            "indicators":   [...],
            # ... other fields ...
        }
```

### 2. Mapper (`mappers/<source_name>.py` or inline in collector)

The mapper transforms the raw collector output into the THEORY CommonSchema:

```python
class MySourceMapper:
    def map(self, raw: dict) -> dict:
        """Transform raw collector output to CommonSchema."""
        return {
            "source_id":    raw["source_id"],
            "actor_name":   raw["actor_name"],
            "techniques": [
                {
                    "technique_id":   t["id"],
                    "technique_name": t["name"],
                    "tactic":         t["tactic"],
                    "confidence":     "medium",
                    "detection":      "",
                }
                for t in raw.get("techniques", [])
            ],
            "malware":      raw.get("malware", []),
            "indicators":   raw.get("indicators", []),
        }
```

### 3. Tests (`tests/test_<source_name>.py`)

All tests must run fully offline using `unittest.mock`. No real API calls
in the test suite. See `tests/test_threatfox_collector.py` for a good example.

**Minimum test coverage:**
- Collector returns None for unknown actor
- Collector handles network errors gracefully
- Mapper produces correctly structured output
- Cache save and load works correctly

### 4. Register in theory.py

Add your source to `SUPPORTED_SOURCES` and `SOURCE_DESCRIPTIONS` in `theory.py`:

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

---

## Adding a vendor feed

Edit `config/feeds.yaml` and add to the `sources` list:

```yaml
- name: Vendor Research Blog
  url: https://vendor.com/blog/security/
  rss: https://vendor.com/blog/security/rss.xml
  type: rss
  tier: 2              # 1=government, 2=major vendor, 3=community
  apt_focus: true      # true if source specifically covers nation-state actors
  tags: [apt, malware, campaigns]
  enabled: true
```

To verify the RSS feed works:

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

---

## Development setup

```bash
git clone https://github.com/threatcraft-co/theory
cd theory
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install ruff pytest pytest-cov

# Run tests before making changes (all should pass)
pytest tests/ -v

# Run linter
ruff check . --select E,F,W --ignore E501,E402
```

---

## Pull request checklist

- [ ] All existing tests still pass (`pytest tests/ -v`)
- [ ] New code has tests (fully offline, no real API calls)
- [ ] New actor entries include MITRE Group ID and 3+ aliases
- [ ] New sources include collector, mapper, and test file
- [ ] `DISCLAIMER.md` updated if new data sources introduce new data types
- [ ] No API keys or secrets in the PR

---

## Code style

- Python 3.11+ compatible
- Type hints on all public functions
- Docstrings on all classes and public methods
- No external dependencies beyond `requirements.txt`
- All collectors must handle network errors gracefully (try/except, return None)
- All collectors must implement caching with a documented TTL

---

## Questions?

Open an issue at `github.com/threatcraft-co/theory/issues` or reach out at
`threatcraft@proton.me`.
