# New Source Checklist

Use this checklist every time a new collector, enrichment source, or data feed is added to THEORY. Copy the raw markdown into a GitHub issue or scratch file and check items off as you go.

---

## Collector code

- [ ] Collector file created in `collectors/` and follows the naming convention (`snake_case.py`)
- [ ] Inherits from `BaseCollector` (standard collectors) or uses standalone class (local-clone collectors like Sigma/YARA)
- [ ] `SOURCE_ID` class attribute set (matches the key used in `_cli.py` registries)
- [ ] `REQUIRES_API_KEY` set correctly (`True` or `False`)
- [ ] `query()` method implemented (standard collectors) or enrichment entry point documented
- [ ] Cache implemented with documented TTL in `.cache/<source_name>/`
- [ ] User-Agent header set to `THEORY/1.0 threat-intel-research` (or the constant from `base.py`)
- [ ] Rate limiting handled gracefully (HTTP 429 catch, backoff, informative log message with free tier limits)
- [ ] Network errors handled without raising (try/except, return None or empty)
- [ ] Returns CommonSchema-compatible dict (standard collectors) or documented enrichment dict

## Pipeline wiring (`theory/_cli.py`)

- [ ] Added to `SUPPORTED_SOURCES` (dotted path for standard collectors, `None` for enrichment-only)
- [ ] Added to `SOURCE_DESCRIPTIONS` with auth info in the description string
- [ ] Added to `SOURCE_REQUIRES` if an API key is needed (key name matches `.env.example`)
- [ ] Added to `ENRICHMENT_SOURCES` if enrichment-only (with dotted path to class)
- [ ] Added to `MAPPER_REGISTRY` if a separate mapper class exists
- [ ] Handler added in `_enrich_profile()` (enrichment sources only)
- [ ] Cache TTL added to `cache_ttls` dict in `cmd_list_sources()`
- [ ] Added to `cmd_update_bundles()` if source uses a local clone (git fetch + reset block)

## Environment and configuration

- [ ] `.env.example` updated with new API key variable, registration URL, and free tier limits
- [ ] `.gitignore` covers the new cache directory if it isn't already caught by `.cache/`

## Documentation updates

### README.md

- [ ] Row added to the **Sources** table (Key, Source, Auth Required, Cache)
- [ ] If planned/future: row added to the "Coming in v1.2" table instead
- [ ] **Architecture** tree updated with the new collector file
- [ ] Usage examples updated if the new source changes a recommended `--sources` combination
- [ ] Intro paragraph updated if the source list at the top changed
- [ ] Description paragraph updated if the source count changed (e.g. "7 intelligence sources" becomes "8")

### CHANGELOG.md

- [ ] Entry added under the next unreleased version heading
- [ ] Listed under `### Added` with a one-line description of what the source provides

### SECURITY.md

- [ ] "What THEORY is" bullet updated if the new source introduces a new type of outbound connection
- [ ] API list in "A client that makes outbound HTTPS requests to..." updated with the new source name
- [ ] Path traversal scope updated if the source writes to a new directory (e.g. a new local clone)
- [ ] If the source introduces a new attack surface (e.g. a new input vector, a new file format), add it to the threat model
- [ ] Security Practices section updated if the source introduces a new credential type

### DISCLAIMER.md

- [ ] Source list in Section 1 ("Nature of the Tool") updated to include the new source name
- [ ] No other changes needed unless the source introduces a fundamentally new data type

### CONTRIBUTING.md

- [ ] No changes needed unless the contribution workflow changed (new required fields, new test patterns)
- [ ] If the new source pattern is novel (e.g. IP enrichment post-processors), consider adding a note or example

## Tests

- [ ] Test file created at `tests/test_<source_name>_collector.py`
- [ ] All tests run fully offline (mocked HTTP, no real API calls)
- [ ] Test cases cover: happy path, empty results, rate limiting (429), network errors, cache hit/miss/stale, malformed responses
- [ ] Schema conformance validated (returned dict matches CommonSchema or documented enrichment format)
- [ ] Existing tests still pass (`pytest tests/ -v`)

## Final verification

- [ ] `theory --list-sources` shows the new source with correct description, auth, and cache info
- [ ] `theory --actor APT28 --sources mitre,<new_source>` runs without errors (or skips gracefully if no API key)
- [ ] `theory --update-bundles` includes the new source if it uses a local clone
- [ ] No secrets in the commit (`git diff` reviewed, gitleaks pre-commit hook passes)
- [ ] Linter passes (`ruff check .`)
