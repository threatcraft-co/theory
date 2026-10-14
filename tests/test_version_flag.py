"""
tests/test_version_flag.py
--------------------------
SECURITY.md asks bug reporters to include `theory --version`, so it has to
exist, and it has to agree with the version the wheel is built with.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from theory import __version__
from theory._cli import _build_parser

REPO = Path(__file__).resolve().parent.parent


def test_version_flag_prints_the_package_version(capsys):
    with pytest.raises(SystemExit) as exc:
        _build_parser().parse_args(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"theory {__version__}"


def test_package_version_matches_pyproject():
    """Two places hold the version; a release must not ship them disagreeing."""
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert declared, "pyproject.toml has no version"
    assert declared.group(1) == __version__


def test_changelog_documents_the_current_version():
    """The newest CHANGELOG heading is the version in the package, and no
    version appears twice (v2.0.0 once had two headings)."""
    changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"(?m)^## \[([^\]]+)\] — (.+)$", changelog)
    assert headings, "CHANGELOG has no release headings"
    versions = [v for v, _ in headings]
    assert len(versions) == len(set(versions)), f"duplicate release headings: {versions}"
    assert versions[0] == __version__
