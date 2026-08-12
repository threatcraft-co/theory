# Security Policy

THEORY is a tool used by security professionals. The maintainers take security issues in THEORY itself seriously and welcome responsible disclosure of any vulnerabilities found in the codebase or its dependencies.

This document describes what is in scope, how to report a vulnerability privately, and what to expect after you do.

---

## Threat Model

Before reporting an issue, it helps to understand what THEORY is and is not.

**What THEORY is:**

- A local command-line Python tool that runs on the user's machine.
- A client that makes outbound HTTPS requests to public threat intelligence APIs (MITRE ATT&CK, CISA, AlienVault OTX, Malpedia, ThreatFox, SigmaHQ, vendor RSS feeds).
- A file writer that produces dossiers in the user's local `output/dossiers/` directory.

**What THEORY is not:**

- A server. There is no hosted infrastructure to attack.
- A multi-user system. There are no accounts, no authentication, no session management.
- A data store. THEORY does not persist user data anywhere except local files the user explicitly generates.

The threat surface is therefore narrow and centers on:

1. **Code injection or arbitrary execution** through actor names, file paths, or configuration values.
2. **Path traversal** in file writes (cache, dossier output, Sigma clone).
3. **Supply chain risk** through dependencies declared in `pyproject.toml`.
4. **Prompt injection** in LLM-synthesized content where attacker-controlled text from a third-party source (a vendor blog, an OTX pulse) reaches an LLM prompt. Mitigated by fenced input, a trust-boundary system prompt, and input sanitization — see the June 2026 audit for details.
5. **XML parsing of attacker-influenceable feeds.** RSS/Atom sources are third-party content. Parsed with `defusedxml` to refuse entity expansion and external entity references.
6. **Sensitive data leakage** through unintended commits (cached API responses, dossiers, environment variables).
7. **Output integrity** — dossiers must accurately reflect their sources and must not be silently tampered with.

If your finding fits one of those categories, it is in scope.

---

## In Scope

The following are considered valid security issues:

- Arbitrary code execution from any input vector (actor names, file paths, configuration files, environment variables, API responses, RSS feed contents).
- Path traversal allowing writes outside `.cache/`, `output/dossiers/`, or the Sigma clone directory.
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

2. **Email** — send your report to **`threatcraft@proton.me`** with the subject line `SECURITY: <brief description>`. If the issue is sensitive enough that you want to encrypt the report, request a PGP key in your initial email and one will be provided.

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

- **No secrets in source.** API keys are loaded from `.env` files which are gitignored. Anything pushed accidentally is purged from history with `git filter-repo`.
- **Pre-commit hooks.** Contributors are asked to install `pre-commit` before their first commit (`pip install pre-commit && pre-commit install`). The hook set runs on every commit and includes `gitleaks` for content-based secret scanning against ~150 known credential patterns (AWS, GCP, Anthropic, OpenAI, GitHub, Slack, Stripe, and others), `detect-private-key` for SSH/TLS material, and a name-based guard that blocks `.env`, `*.pem`, `*.key`, and similar filenames. See `.pre-commit-config.yaml` for the full list. The hooks can be bypassed with `git commit --no-verify` in genuine emergencies; the intent is that this is rare and deliberate.
- **Defanged output.** All URLs, domains, and IPs in markdown, HTML, and terminal output are defanged using `hxxp://` and `[.]` notation. Raw values are only present in the CSV IOC export, which exists specifically for SIEM ingestion where the platform handles defanging.
- **Prompt-injection defense.** All third-party content that reaches an LLM prompt (vendor RSS bodies, prior synthesis output re-ingested into dossier openers) is wrapped in `<untrusted_article>` or `<untrusted_vendor_intel>` XML tags. The system prompt explicitly instructs the model to treat fenced content as data to be analyzed, never as instructions. A defense-in-depth sanitizer (`_sanitize_for_prompt`) neutralizes fence-break attempts by replacing angle brackets in fence-tag patterns with square brackets, and strips control characters. Both layers are covered by offline tests in `tests/test_security_hardening.py`.
- **Hardened XML parsing.** RSS and Atom feeds are parsed with `defusedxml`, which refuses entity expansion (billion laughs, quadratic blowup) and external entity references (XXE). The stdlib `xml.etree.ElementTree` parser is not used on attacker-influenceable content.
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
