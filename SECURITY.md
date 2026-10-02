# Security Policy

THEORY is a tool used by security professionals. The maintainers take security issues in THEORY itself seriously and welcome responsible disclosure of any vulnerabilities found in the codebase or its dependencies.

This document describes what is in scope, how to report a vulnerability privately, and what to expect after you do.

---

## Threat Model

Before reporting an issue, it helps to understand what THEORY is and is not.

**What THEORY is:**

- A local command-line Python tool that runs on the user's machine.
- A client that makes outbound HTTPS requests to public threat intelligence APIs (MITRE ATT&CK, MISP Galaxy, CIRCL MISP, CISA, CISA KEV, AlienVault OTX, Malpedia, NVD, ThreatFox, MalwareBazaar, URLhaus, GreyNoise, AbuseIPDB, Shodan InternetDB, urlscan.io, VulDB, SigmaHQ, YARA-Rules, vendor RSS/sitemap feeds).
- A file writer that produces dossiers in the user's local `output/dossiers/` directory.
- As of v2.0, a file writer that also maintains a **persistent correlation graph** at `output/graph/graph.json`, accumulating entities across runs — this is still a local file the user's own process writes, not a server or multi-tenant store.
- Optionally, via `theory serve`, a local-only web server bound to `127.0.0.1` by default, calling the same pipeline as the CLI (see `server/README.md`). This does not change the threat model below — there is no remote-accessible deployment mode.

**What THEORY is not:**

- A server with remote exposure by default. `theory serve` binds to localhost only.
- A multi-user system. There are no accounts, no authentication, no session management.
- A data store Threatcraft has access to. THEORY does not persist user data anywhere except local files the user's own process writes — including the v2.0 correlation graph and optional personal-research notes, both of which stay on the user's machine.

The threat surface is therefore narrow and centers on:

1. **Code injection or arbitrary execution** through actor names, file paths, configuration values, or — new in v2.0 — a model's response text in `theory ask`'s tool-calling loop (which parses `TOOL: <name> <argument>` lines from LLM output and dispatches to a fixed, small set of local-only read functions; it never executes arbitrary code or shell commands from model output, and every tool it can call is a pure local lookup against the correlation graph or personal notes).
2. **Path traversal** in file writes (cache, dossier output, Sigma clone, YARA clone, the correlation graph, the personal-research redirect).
3. **Supply chain risk** through dependencies declared in `pyproject.toml`.
4. **Prompt injection** in LLM-synthesized content where attacker-controlled text from a third-party source (a vendor blog, an OTX pulse, or — new in v2.0 — a graph entry originally sourced from third-party threat intel, now re-surfaced to the model via `theory ask`'s tool results) reaches an LLM prompt. Mitigated by fenced input, a trust-boundary system prompt, and input sanitization — see the June 2026 audit for details. The v2.0 `theory ask` tool-calling loop extends this trust boundary: tool results are returned to the model as plain JSON data, and the system prompt instructs the model to treat them as data, not instructions.
5. **XML parsing of attacker-influenceable feeds.** RSS/Atom sources are third-party content. Parsed with `defusedxml` to refuse entity expansion and external entity references.
6. **Sensitive data leakage** through unintended commits (cached API responses, dossiers, environment variables, the gitignored personal-research redirect and its target file, the correlation graph).
7. **Output integrity** — dossiers must accurately reflect their sources and must not be silently tampered with. This now extends to the correlation graph and `theory diff`/`--watch` output: a diff must accurately reflect what changed between two real snapshots.

If your finding fits one of those categories, it is in scope.

---

## In Scope

The following are considered valid security issues:

- Arbitrary code execution from any input vector (actor names, file paths, configuration files, environment variables, API responses, RSS feed contents).
- Path traversal allowing writes outside `.cache/`, `output/dossiers/`, `output/graph/`, the Sigma clone directory, the YARA clone directory, or the personal-research file the gitignored redirect points at.
- Local file disclosure beyond what the running user can already read.
- Injection of malicious content into rendered dossiers (HTML, markdown, terminal) that bypasses IOC defanging or executes in the user's browser when opening an HTML dossier.
- Prompt injection that bypasses the `<untrusted_article>` / `<untrusted_vendor_intel>` fencing and the `_sanitize_for_prompt` sanitizer, causing the LLM to produce attacker-chosen output that reaches the dossier without provenance.
- XML-based denial of service or file disclosure that bypasses `defusedxml`'s protections.
- Hardcoded secrets, credentials, or tokens committed to the repository at any point in its history.
- Dependency vulnerabilities with a clear exploitation path through THEORY's call patterns.
- Bypass of the alias resolution system that causes THEORY to query or display data for the wrong actor.
- GitHub Actions workflow issues that could allow tampering with releases or test results.

---

## Out of Scope

The following are not security issues for THEORY:

- Reports of malicious IOCs in dossiers. By design, THEORY surfaces threat actor infrastructure — that is the point of the tool. All URLs, domains, and IPs are defanged in human-readable outputs.
- Rate-limit or quota concerns at upstream APIs. Users are responsible for managing their own API keys and respecting source terms of service.
- Findings that require an attacker to already have local code execution on the user's machine.
- Issues in upstream data sources (MITRE, CISA, OTX, etc.). Report those to the source maintainers.
- Issues in third-party detection rules, malware family names, or attribution data displayed in dossiers. THEORY is a presentation layer for public data, not the data's author.
- Performance, accuracy, or completeness of intelligence content. Those belong in regular GitHub issues, not security reports.
- Reports generated solely by automated scanners without a demonstrated exploitation path.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security reports.**

Two private reporting channels are available:

1. **GitHub private vulnerability reporting** — go to the [Security tab](https://github.com/threatcraft-co/theory/security/advisories/new) on this repository and submit a report directly through GitHub. This is the fastest path to a tracked advisory.

2. **Email** — send your report to **`admin@threatcraft.co`** with the subject line `SECURITY: <brief description>`. If the issue is sensitive enough that you want to encrypt the report, request a PGP key in your initial email and one will be provided.

Either channel reaches the maintainers. Use whichever you prefer.

In your report, please include:

1. A clear description of the issue and where it lives in the codebase (file, function, line range if known).
2. The exact steps required to reproduce the issue.
3. The version of THEORY you tested against (`theory --version` or commit hash).
4. Your assessment of the impact: what an attacker could do, and under what preconditions.
5. Any proof-of-concept code, command output, or screenshots that demonstrate the issue.
6. Whether you would like to be credited in the release notes for the fix.

If the issue is sensitive enough that you want to encrypt the report, request a PGP key in your initial email and one will be provided.

---

## What to Expect

THEORY is maintained by a small team. Response times reflect that, but every report will be acknowledged.

| Stage | Target |
| --- | --- |
| Acknowledgment of receipt | Within 5 business days |
| Initial assessment and triage | Within 14 days |
| Fix or mitigation plan | Within 30 days for high-severity issues |
| Public disclosure | Coordinated with you, typically 90 days after report or upon fix release, whichever comes first |

You will be kept informed at each step. If a fix takes longer than expected, you will hear why.

---

## Disclosure Policy

THEORY follows a coordinated disclosure model:

- The maintainers will work with you to understand and reproduce the issue.
- A fix or mitigation will be developed privately.
- Once a fix is released, the vulnerability will be disclosed publicly, with credit to the reporter unless they prefer otherwise.
- If a reporter publishes details before a fix is available, the maintainers reserve the right to disclose immediately to protect users.

---

## Supported Versions

Only the `main` branch of THEORY receives security fixes. Released versions follow this support policy:

| Version | Status |
| --- | --- |
| Latest `main` | Active development, all fixes applied immediately |
| Most recent tagged release | Backported security fixes for 90 days after the next release |
| Older releases | Unsupported; please upgrade |

Users running forks or modified versions are responsible for porting fixes themselves.

---

## Security Practices in THEORY

For transparency, THEORY follows these practices in its own development:

- **No secrets in source.** API keys are loaded from `.env` files which are gitignored. Anything pushed accidentally is purged from history with `git filter-repo`. The `ABUSECH_API_KEY`, `GREYNOISE_API_KEY`, `ABUSEIPDB_API_KEY`, `VULDB_API_KEY`, `NVD_API_KEY`, and the optional `URLSCAN_API_KEY` are all loaded through the same `.env` mechanism as the older keys — no source code path holds them. `shodan_internetdb` needs no key at all.
- **Local research stays local.** The v2.0 personal-research feature (`--init-personal`) uses a gitignored two-layer redirect: `config/local_sources.yaml` (in-repo, gitignored) points to a private indicators file outside the repository entirely (default `~/.theory/personal_indicators.yaml`). Even an accidental commit of the redirect file leaks only a path, never the research content itself.
- **Pre-commit hooks.** Contributors are asked to install `pre-commit` before their first commit (`pip install pre-commit && pre-commit install`). The hook set runs on every commit and includes `gitleaks` for content-based secret scanning against ~150 known credential patterns (AWS, GCP, Anthropic, OpenAI, GitHub, Slack, Stripe, and others), `detect-private-key` for SSH/TLS material, and a name-based guard that blocks `.env`, `*.pem`, `*.key`, and similar filenames. See `.pre-commit-config.yaml` for the full list. The hooks can be bypassed with `git commit --no-verify` in genuine emergencies; the intent is that this is rare and deliberate.
- **Defanged output.** All URLs, domains, and IPs in markdown, HTML, and terminal output are defanged using `hxxp://` and `[.]` notation. Raw values are only present in the CSV IOC export, which exists specifically for SIEM ingestion where the platform handles defanging.
- **Prompt-injection defense.** All third-party content that reaches an LLM prompt (vendor RSS bodies, prior synthesis output re-ingested into dossier openers) is wrapped in `<untrusted_article>` or `<untrusted_vendor_intel>` XML tags. The system prompt explicitly instructs the model to treat fenced content as data to be analyzed, never as instructions. A defense-in-depth sanitizer (`_sanitize_for_prompt`) neutralizes fence-break attempts by replacing angle brackets in fence-tag patterns with square brackets, and strips control characters. Both layers are covered by offline tests in `tests/test_security_hardening.py`.
- **Hardened XML parsing.** RSS and Atom feeds are parsed with `defusedxml`, which refuses entity expansion (billion laughs, quadratic blowup) and external entity references (XXE). The stdlib `xml.etree.ElementTree` parser is not used on attacker-influenceable content.
- **Bounded, local-only tool-calling.** `theory ask` (v2.0) parses `TOOL: <name> <argument>` lines from LLM output, but only ever dispatches to a fixed registry of five pure, local, read-only lookup functions (`query_ioc`, `query_technique`, `query_actor`, `query_cve`, `query_personal`) against the correlation graph or personal notes. It never executes arbitrary code, shell commands, or file writes from model output, and an unrecognized tool name is reported back to the model as an error rather than attempted. A hard turn limit (`MAX_TOOL_TURNS`) bounds any runaway tool-calling loop.
- **Least-privilege CI.** The GitHub Actions workflow declares `permissions: contents: read` at the workflow level. Any job that needs to write must opt in explicitly.
- **Dependency vulnerability scanning.** `pip-audit` runs against the resolved dependency tree on every push and pull request, checking against the Python Packaging Advisory Database.
- **Canonical dependency source.** `pyproject.toml` is the single source of truth for dependencies. `requirements.txt` and `requirements-dev.txt` are pointer files retained only for tools that expect them (Dependabot ecosystem detection, IDE inspectors).
- **Local-only execution.** THEORY does not phone home, does not collect telemetry, and does not communicate with any server operated by the maintainers.
- **Public dependencies.** All dependencies are declared in `pyproject.toml`. There are no private package indexes.
- **Offline tests.** All tests run without network access or API keys. CI runs the full suite on every push and pull request against Python 3.11 and 3.12.
- **Public security audits.** Defense-in-depth reviews are conducted periodically and published. See [`docs/SECURITY_AUDIT_2026-06.md`](docs/SECURITY_AUDIT_2026-06.md) for the most recent.

---

## Hall of Fame

Researchers who report valid security issues will be listed here with their permission.

*No reports yet — be the first.*

---

## Questions

For general questions about THEORY's security posture that are not vulnerability reports, open a regular GitHub discussion or issue. This document is reserved for actual security disclosures.

---

*This security policy is maintained by [Threatcraft](https://github.com/threatcraft-co) and applies to all code in the `threatcraft-co/theory` repository.*
