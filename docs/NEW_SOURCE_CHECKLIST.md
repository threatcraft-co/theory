# New Source Checklist

Use this checklist every time a new collector, enrichment source, or data feed is added to THEORY. Copy the raw markdown into a GitHub issue or scratch file and check items off as you go.

---

## Collector code

- [ ] Collector file created in `collectors/` and follows the naming convention (`snake_case.py`)
- [ ] Inherits from `BaseCollector` (standard collectors) or uses standalone class (local-clone collectors like Sigma/YARA)
- [ ] `SOURCE_ID` class attribute set (matches the key used in `_cli.py` registries)
- [ ] `REQUIRES_API_KEY` set correctly (`True` or `False`)
- [ ] `query()` method implemented (standard collectors) or enrichment entry point documented
- [ ] Requests go through `theory.http_client.HttpClient`, not `urlopen`/`requests` directly (https-only, retry/backoff, response size cap, typed errors, and no query string or header ever reaches a log line, all for free). The default User-Agent identifies THEORY; don't override it unless the API requires
- [ ] Responses are cached with `theory.disk_cache.DiskCache` and a documented TTL, in `.cache/<source_name>/`
- [ ] **Only real answers are cached.** "The source has nothing" (404, `no_results`) is remembered as a miss (`DiskCache.fetch` does this when the loader raises `NotFound`). A timeout, 429, 5xx, bad key, or an error reply sent as HTTP 200 is **never** cached: it says nothing about the indicator. Treat any status string you do not recognise as an error, not as "empty"
- [ ] Rate limiting handled: quota-based APIs (daily/weekly caps) pass `retry_statuses` without 429 and stop the run on `RateLimited` instead of continuing and caching misses; log the free-tier limit
- [ ] Per-indicator enrichment sources use `collectors/_enrich.enrich_keys` (cache, pacing, stop-on-429, stop after repeated failures, one summary warning) and `collectors/_ip.is_public_ip` for IP filtering, rather than their own loop or `startswith` checks
- [ ] Failure-mode tests exist: a timeout, 429, 5xx and an error-as-200 each leave the cache empty and the next run retries. See `tests/test_abusech_failure_modes.py` and `tests/test_greynoise_collector.py` for the pattern, and `tests/_http_fakes.py` for the shared fakes
- [ ] `HttpError` is handled at the collector boundary and reported once (a single warning), not swallowed into an empty result
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
- [ ] If the source isn't implemented yet (planned/future), don't add it to the Sources table at all — note it in `CHANGELOG.md` or an issue instead. (There is no "coming soon" table in the README as of v2.0 — a past one went stale and was removed; don't reintroduce it.)
- [ ] **Architecture** tree updated with the new collector file
- [ ] Usage examples updated if the new source changes a recommended `--sources` combination
- [ ] Intro paragraph and "N sources, M of which need no key" line updated if the source count changed
- [ ] Description paragraph updated if the source count changed (e.g. "20 intelligence sources" becomes "21")

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
