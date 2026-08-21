# Security Audit — June 2026

A defense-in-depth review of THEORY's threat surfaces. The audit was performed against `main` at commit `31faaf6` (v1.0.0) and applied in [PR #TODO]. It was AI-assisted, with all findings reviewed and changes approved by the maintainer before merge — consistent with the AI-assisted-development disclosure in [`CREDITS.md`](../CREDITS.md).

The audit closes one open repository-hygiene issue ([#10](https://github.com/threatcraft-co/theory/issues/10)) and adds defense-in-depth in three areas explicitly named in [`SECURITY.md`](../SECURITY.md): prompt injection through the LLM synthesis path, XML parsing of attacker-influenceable feeds, and supply-chain hygiene.

No exploitable vulnerabilities were found in the secret-management or credential paths. No hardcoded keys exist in the codebase or in the post-`git filter-repo` history.

---

## Scope

- Secret and credential review across code and git history
- Prompt-injection isolation in `collectors/intelligence_synthesizer.py`
- XML parser hardening in `collectors/vendor_intel.py`
- GitHub Actions workflow permissions
- Dependency reconciliation and vulnerability scanning
- Repository hygiene (Issue [#10](https://github.com/threatcraft-co/theory/issues/10))

---

## Findings and remediation

### HIGH — Prompt-injection isolation in LLM synthesis

THEORY's vendor intelligence synthesizer reads RSS articles from third-party security blogs and asks an LLM to summarize them. Because RSS publishers control the article body, title, source name, and publication date, those fields are attacker-influenceable in the same way any user input would be.

The pre-audit prompt templates interpolated those fields directly into the system instructions with no structural separation. A hostile vendor blog could have included content designed to break out of the implicit content boundary and steer the model's output — for example, by emitting text that looked like a new instruction block followed by attacker-chosen content.

**Remediation.** All third-party content is now wrapped in `<untrusted_article>` (for raw RSS bodies) or `<untrusted_vendor_intel>` (for already-synthesized text re-ingested during dossier opener generation) XML tags. The system prompt explicitly defines a trust boundary instructing the model to treat content inside those tags as data to be analyzed, never as instructions to follow. A defense-in-depth sanitizer (`_sanitize_for_prompt`) neutralizes any attempts to close those fences before interpolation by replacing the angle brackets in fence-tag patterns with square brackets. Control characters are stripped. Both fences (article and re-ingested intel) and both interpolation sites (`synthesize`, `synthesize_overview`, `synthesize_executive_summary`) received the same treatment.

This is consistent with prompt-injection defense guidance from Anthropic and other LLM vendors: explicit instruction-data separation in the system prompt, structural fencing of untrusted content, and input normalization at the boundary.

### HIGH — XML parser hardening (defusedxml)

`collectors/vendor_intel.py` parses vendor RSS and Atom feeds using `xml.etree.ElementTree`. Python's own documentation states that the standard-library XML parsers are not safe against maliciously constructed data — specifically entity-expansion attacks (commonly known as "billion laughs" or quadratic blowup) and external-entity references (XXE). Vendor RSS URLs are configurable and the feeds themselves are third-party content, so both attacks are applicable to THEORY's threat model.

**Remediation.** The parser now uses [`defusedxml`](https://pypi.org/project/defusedxml/), a drop-in API-compatible replacement that refuses entity expansion and external references. `DefusedXmlException` is caught alongside `ParseError` and logged at WARNING level so administrators can see when a hostile feed is rejected. Test coverage includes a billion-laughs payload and an XXE payload referencing `/etc/passwd`; both are rejected with no memory growth and no file disclosure.

### MEDIUM — CI workflow permissions

The CI workflow (`.github/workflows/ci.yml`) did not declare an explicit `permissions:` block, which meant the `GITHUB_TOKEN` ran with maximum default permissions on every push and pull request. This was not exploitable as the workflow currently performs no write operations, but it sets a poor default for future expansion (e.g. release-artifact upload, PR comments).

**Remediation.** The workflow now declares `permissions: contents: read` at the workflow level. Any future job that needs additional scopes will need to opt in explicitly.

### MEDIUM — Repository hygiene (Issue [#10](https://github.com/threatcraft-co/theory/issues/10))

The `.gitignore` contained a typo that concatenated `.DS_Store` and `.cache/` onto a single line, with the result that neither pattern was applied as intended. Consequently `.cache/` (including a tracked ~50 MB MITRE ATT&CK bundle) and `output/dossiers/` were both committed to the repository over multiple revisions. The dossier outputs included `apt28_iocs.csv` with raw, undefanged indicator-of-compromise values.

**Remediation.** The `.gitignore` was corrected. The previously-tracked `.cache/`, `output/dossiers/`, and `.DS_Store` files were untracked from `main` and purged from history with `git filter-repo`. Repository size dropped accordingly; clones are noticeably faster.

### MEDIUM — Dependency reconciliation and vulnerability scanning

`pyproject.toml` and `requirements.txt` had drifted apart. CI installed from `requirements.txt`, the install path used `pyproject.toml`, and the two disagreed on five packages. No CI step performed any supply-chain vulnerability check.

**Remediation.** `pyproject.toml` is now the single canonical dependency source. CI installs the project in editable mode with the `[dev]` extra (`pip install -e ".[dev]"`), which transitively resolves the test and lint tooling. `requirements.txt` and `requirements-dev.txt` are retained as one-line pointer files for tools that expect them (Dependabot ecosystem detection in particular). A `pip-audit` step now runs on every CI pipeline, currently non-blocking pending triage of any baseline advisories.

`.env.example` was also brought current — the LLM provider keys (`THEORY_LLM_PROVIDER`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OLLAMA_HOST`, `OLLAMA_MODEL`) and the v1.2 IOC enrichment keys (`SHODAN_API_KEY`, `CENSYS_API_KEY`, `CRIMINALIP_API_KEY`, `VIRUSTOTAL_API_KEY`) are now documented with registration links.

### LOW — Code hygiene

Three LLM providers in `collectors/intelligence_synthesizer.py` each carried a private copy of `.env` parsing logic. Consolidating that into a single `_load_env_value` helper removes about thirty lines of duplicate code and makes provider implementations easier to read. No behavioral change.

---

## Verification

- All pre-existing tests pass (310 tests, fully offline).
- A new `tests/test_security_hardening.py` adds 22 tests covering the prompt-fencing instructions, sanitizer behavior, end-to-end injection resistance, defusedxml rejection of malicious XML, and the shared env loader.
- `pip-audit` runs in CI on every push and pull request.

---

## What was not changed

- The threat model in [`SECURITY.md`](../SECURITY.md) remains accurate; this audit operationalized its existing categories rather than expanding scope.
- No breaking changes to the public CLI, output formats, or `CommonSchema`.
- No new required configuration — defaults are preserved end-to-end.
- The LLM provider model identifiers and prompt task descriptions are unchanged in substance; only the trust-boundary framing and fencing were added.

---

## Reporting issues

Per [`SECURITY.md`](../SECURITY.md), report security issues privately to **admin@threatcraft.co** with the subject line `SECURITY: <brief description>`. Do not open public GitHub issues for security reports.

---

*Audit dated 2026-06-16. Maintained by [Threatcraft](https://github.com/threatcraft-co).*
