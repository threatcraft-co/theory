# Contributing to THEORY

Thank you for helping make threat intelligence more accessible. THEORY is built
by the security community, for the security community.

---

## Ways to contribute

- **Add a new actor** to the alias table (easiest, no Python required)
- **Add a new intelligence source** (collector + mapper + tests)
- **Add a vendor feed** to the RSS registry
- **Add a detection repository** to `theory/data/detection_repos.yaml`
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
pip install -e ".[dev,serve]"

# Download the ATT&CK bundle
theory --update-bundles

# Run the tests before making changes. The suite is hermetic (it clears API
# keys and points THEORY_HOME at a temp directory), so no special environment
# is needed. Run it on Python 3.11 too - that is the supported floor.
pytest tests/ -q

# Run the linter (configuration lives in pyproject.toml; CI runs it bare)
ruff check .
```

---

## Adding a new actor (easiest contribution)

Actors are defined in `theory/data/actors.yaml` - no Python required. It ships
inside the package and is loaded at runtime. (A `config/actors.yaml` in your
working directory, or in `$THEORY_CONFIG_DIR`, overrides it for local use.)

`theory/data/actors.yaml` currently holds 1,033 actors, most of which came from
the MISP Galaxy threat-actor cluster and MITRE ATT&CK via
`scripts/build_actor_identities.py`. For a single new actor, hand-edit the YAML
as below - you don't need the script.

### Two kinds of name

THEORY keeps two lists per actor because they do two different jobs, and mixing
them up was the source of the worst bug in v1:

- **`identity_names`** answer *"which actor did the user mean?"* `--actor X`
  resolves by **exact match** against these. A name belongs here only if it
  denotes **this actor and no other**.
- **`recall_aliases`** answer *"does this document mention the actor?"* They
  are matched on word boundaries. If you leave this out, it is derived from
  `identity_names` (minus stop-words and very short names).

A name that vendors use for *different* groups (for example one catalog merges
APT41 with Winnti while another keeps them apart) goes under `contested`
instead: it is recorded for the analyst but never used to resolve or match.

> An entry with only `aliases:` is **not enough**. Its canonical name will
> resolve, but none of its aliases will, and `--actor <alias>` fails with
> "Unknown actor".

### Format

```yaml
actors:
  Charming Kitten:
    origin: Iran
    motivation: espionage
    mitre_id: G0059              # optional: the pinned ATT&CK group
    aliases:
      - charming kitten
      - apt35
      - phosphorus
      - mint sandstorm
      - ta453
    identity_names:              # exact-match names for --actor
      - charming kitten
      - apt35
      - phosphorus
      - mint sandstorm
      - ta453
```

### Fields

| Field            | Required | Description |
| ---------------- | -------- | ----------- |
| `aliases`        | Yes      | Every known name, **lowercase** |
| `identity_names` | Yes      | The subset that unambiguously means *this* actor (lowercase). Include the canonical name |
| `recall_aliases` | No       | Names usable as evidence in free text. Derived from `identity_names` if omitted |
| `contested`      | No       | Names another catalog assigns to a different group |
| `mitre_id`       | No       | Pinned ATT&CK group id (`G0059`). Only set it if you have checked ATT&CK's own page for the group |
| `origin`         | No       | Country or region of attribution (`Russia`, `China`, `Iran`, `North Korea`, `unknown`) |
| `motivation`     | No       | `espionage`, `financial`, `hacktivism`, `destruction`, `unknown` |

### Rules

- All names are **lowercase**; the top-level key (canonical name) uses its usual capitalisation.
- Include the **canonical name in lowercase** and, if the actor is in ATT&CK, the **MITRE Group ID** (e.g. `g0007`).
- Cover the major vendor taxonomies you know of: Microsoft (`forest blizzard`), CrowdStrike (`fancy bear`), Mandiant (`apt28`, `fin7`), Secureworks (`iron twilight`), Proofpoint (`ta422`), CISA designations.
- **Never put a name in `identity_names` that another actor also uses.** If two groups share a name, list it under `contested` for both.
- Don't reuse a MITRE group id for a second actor.
- Open a PR with a link to at least one authoritative source confirming the actor exists (MITRE ATT&CK page, vendor research, government advisory).

### Verifying your addition

```bash
# Confirm the YAML parses
python -c "import yaml; yaml.safe_load(open('theory/data/actors.yaml'))"

# Confirm every name resolves to the right actor
theory --list-actors                  # your actor should appear in the table
theory --actor "your alias here"      # should resolve to the canonical name

# The identity tests catch merged or ambiguous names
pytest tests/test_actor_identity.py -q
```

If you regenerate the file with `scripts/build_actor_identities.py`, only a
hand-pinned `mitre_id` is preserved. Review the diff and re-apply any other
hand edit.

---

## Adding a new intelligence source

**Before you start:** open [`docs/NEW_SOURCE_CHECKLIST.md`](docs/NEW_SOURCE_CHECKLIST.md) and copy it into a scratch file or GitHub issue. It covers every file that needs updating (collector code, pipeline wiring in `_cli.py`, `.env.example`, README, CHANGELOG, SECURITY, DISCLAIMER, tests, and final verification steps). This list exists because things fall through the cracks otherwise.

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

Add your source to `SUPPORTED_SOURCES` and `SOURCE_DESCRIPTIONS` (and, if it needs
a key, `SOURCE_REQUIRES`):

```python
SUPPORTED_SOURCES = {
    # existing sources...
    "mysource": "collectors.my_source.MySourceCollector",
}

SOURCE_DESCRIPTIONS = {
    # existing descriptions...
    "mysource": "My Source — description (auth requirements)",
}

SOURCE_REQUIRES = {
    # only if your source needs an API key
    "mysource": "MYSOURCE_API_KEY",
}
```

If your source is a **standard collector** (returns a full actor profile via
`query(actor_name)`), that's it — it's picked up automatically. If it's an
**enrichment-only post-processor** (like `greynoise`, `abuseipdb`,
`shodan_internetdb`, or `urlscan_io` — it annotates IOCs already collected by
other sources rather than returning its own profile), you also need:

```python
SUPPORTED_SOURCES = {
    # ...
    "mysource": None,   # enrichment-only sources map to None here
}

ENRICHMENT_SOURCES = {
    # ...
    "mysource": "collectors.my_source.MySourceCollector",
}
```

plus a dispatch branch in `_enrich_profile()` that calls your collector's
`enrich_ips()` (for IP indicators — see `greynoise.py`/`abuseipdb.py`/
`shodan_internetdb.py`) or `enrich_urls()` (for domain/URL indicators — see
`urlscan_io.py`) and annotates matching indicators with the result. Both
`run()` and the standalone `_enrich_profile()` call this the same way the
existing enrichment sources do — copy the nearest existing branch rather than
inventing a new shape.

Also add your source's cache TTL to the `cache_ttls` dict inside
`cmd_list_sources()` so `theory --list-sources` reports it correctly.

### 5. Update the README

Add a row to the Sources table in `README.md` so users can discover your
collector, and bump the source count mentioned near the top if it changed.

---

## Adding a vendor feed

Edit `theory/data/feeds.yaml` and add to the `sources` list:

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

If the vendor doesn't publish an RSS feed, use `type: sitemap` instead — THEORY
fetches the sitemap, filters by `url_pattern`, sorts by recency, and follows
one level of sitemap indexes (gzipped sitemaps supported):

```yaml
- name: Vendor Without RSS
  url: https://vendor.com/blog/
  sitemap: https://vendor.com/sitemap.xml
  type: sitemap
  url_pattern: "/blog/"
  tier: 2
  tags: [vendor]
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
`theory/data/detection_repos.yaml`:

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

- [ ] All existing tests still pass (`pytest tests/ -v` with the four `*_API_KEY=fake` env vars set — should show 806+ passing)
- [ ] New code has tests (fully offline, no real API calls)
- [ ] Linter passes (`ruff check .` with the project's ignore list)
- [ ] New actor entries are added to `theory/data/actors.yaml`, include `identity_names` (an `aliases`-only entry will not resolve), include the MITRE Group ID if applicable, and have 3+ aliases
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

Report privately through [GitHub's private vulnerability reporting](https://github.com/threatcraft-co/theory/security/advisories/new)
or via email at `admin@threatcraft.co` with the subject prefix `SECURITY:`.
See [SECURITY.md](SECURITY.md) for the full disclosure process.

---

## Questions

Open an issue at github.com/threatcraft-co/theory/issues or reach out at
`admin@threatcraft.co`.

---

*Maintained by [Threatcraft](https://github.com/threatcraft-co).*
