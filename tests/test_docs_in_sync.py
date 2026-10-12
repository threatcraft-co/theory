"""
tests/test_docs_in_sync.py
--------------------------
Documentation that can go stale without anything failing, won't stay true.

The v2.0 audit found README.md claiming 20 sources "15 of which need no
API key" (the real figure had changed when abuse.ch began requiring an
Auth-Key), a source table still listing threatfox as keyless, a test count
quoted as 806 passing while 4 were failing, and examples for a `--output
exec` flag that raised NameError.

These tests make the drift fail the build instead.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"


@pytest.fixture(scope="module")
def readme() -> str:
    return README.read_text(encoding="utf-8")


class TestSourceTable:

    def test_table_matches_the_registry(self, readme):
        """The table between the generated markers must equal what
        theory.sources produces. Regenerate it rather than hand-editing."""
        from theory.sources import README_TABLE_END, README_TABLE_START, markdown_table

        assert README_TABLE_START in readme, "generated-table markers are missing"
        body = readme.split(README_TABLE_START, 1)[1].split(README_TABLE_END, 1)[0]
        assert body.strip() == markdown_table().strip(), (
            "README source table is out of date — run:\n"
            "  python -c \"from theory.sources import markdown_table; print(markdown_table())\""
        )

    def test_every_source_appears(self, readme):
        from theory.sources import SOURCES
        for spec in SOURCES:
            assert f"`{spec.key}`" in readme, f"{spec.key} is undocumented"


class TestQuotedCounts:

    def test_source_counts_are_current(self, readme):
        from theory.sources import counts

        c = counts()
        # Any "N sources" claim must use the real total.
        for match in re.finditer(r"(\d+)\s+(?:free\s+)?sources\b", readme):
            assert int(match.group(1)) == c["total"], (
                f"README says {match.group(1)} sources; the registry has {c['total']}"
            )

    def test_keyless_claims_are_current(self, readme):
        from theory.sources import counts

        c = counts()
        for match in re.finditer(r"(\d+)\s+of the\s+(\d+)\s+sources", readme):
            keyless, total = int(match.group(1)), int(match.group(2))
            assert total == c["total"]
            assert keyless == c["keyless"], (
                f"README claims {keyless} keyless sources; the registry has {c['keyless']}"
            )

    def test_no_hardcoded_test_counts(self):
        """A number like "806 tests pass" is wrong the moment a test is
        added. The CI badge carries this."""
        offenders = []
        for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md"):
            path = REPO / name
            if not path.is_file():
                continue
            for match in re.finditer(r"(\d{3,4})\s+(?:tests?|passing)", path.read_text()):
                offenders.append(f"{name}: {match.group(0)!r}")
        assert not offenders, (
            "hard-coded test counts go stale on the next commit: " + "; ".join(offenders)
        )


class TestDocumentedFlagsExist:
    """Every long flag shown in the README must be real. `--output exec`
    was documented in two examples and the help epilog while raising
    NameError for anyone who tried it."""

    def test_documented_flags_are_accepted(self, readme):
        from theory._cli import _build_parser

        parser = _build_parser()
        known = set()
        for action in parser._actions:
            known.update(action.option_strings)

        # Trailing "-" excluded so STIX relationship arrows written as
        # `--indicates-->` are not mistaken for flags.
        documented = set(re.findall(r"(?<![-\w])(--[a-z][a-z0-9-]*[a-z0-9])(?![-\w])", readme))
        # Flags belonging to subcommands, not the main parser.
        subcommand_flags = {"--from", "--to", "--host", "--port", "--no-open",
                            "--reload", "--expose-api-keys"}
        missing = sorted(f for f in documented - known - subcommand_flags)
        assert not missing, f"README documents flags that do not exist: {missing}"

    def test_documented_output_formats_are_accepted(self, readme):
        from theory._cli import _build_parser

        parser = _build_parser()
        choices = set(
            next(a for a in parser._actions if "--output" in a.option_strings).choices
        )
        for fmt in re.findall(r"--output\s+([a-z-]+)", readme):
            assert fmt in choices, f"README shows --output {fmt}, which is not a choice"


class TestSecurityClaims:

    def test_no_stdlib_xml_on_untrusted_input(self):
        """SECURITY.md states the stdlib parser is not used on
        attacker-influenceable content. Keep that true."""
        offenders = []
        for path in REPO.glob("collectors/*.py"):
            text = path.read_text()
            if re.search(r"^\s*import xml\.etree|^\s*from xml\.etree", text, re.MULTILINE):
                offenders.append(path.name)
        assert not offenders, (
            f"stdlib XML parser used in {offenders} — SECURITY.md claims otherwise"
        )

    def test_internet_scan_extra_is_gone(self):
        """It declared SDKs for collectors that do not exist.

        Parsed, not grepped — the file still mentions the name in a
        comment explaining why it was removed, which is worth keeping.
        """
        import tomllib

        data = tomllib.loads((REPO / "pyproject.toml").read_text())
        extras = data["project"].get("optional-dependencies", {})
        assert "internet-scan" not in extras

    def test_no_unimported_runtime_dependencies(self):
        """jinja2, click, watchdog, schedule and feedparser were all
        declared as runtime dependencies and imported nowhere."""
        import tomllib

        data = tomllib.loads((REPO / "pyproject.toml").read_text())
        declared = {
            re.split(r"[<>=!\[]", dep)[0].strip().lower()
            for dep in data["project"]["dependencies"]
        }

        source = "\n".join(
            path.read_text()
            for path in REPO.rglob("*.py")
            if "tests" not in path.parts and ".venv" not in path.parts
        )
        import_aliases = {"pyyaml": "yaml", "python-dateutil": "dateutil",
                          "python-dotenv": "dotenv"}
        unused = [
            dep for dep in sorted(declared)
            if not re.search(
                rf"^\s*(?:import|from)\s+{re.escape(import_aliases.get(dep, dep))}\b",
                source, re.MULTILINE,
            )
        ]
        assert not unused, f"declared but never imported: {unused}"
