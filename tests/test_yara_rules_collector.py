"""
tests/test_yara_rules_collector.py
-----------------------------------
Unit tests for collectors/yara_rules.py — fully offline.

The YARA collector mirrors the Sigma pattern: a local git clone
searched with grep. Tests cover YARA file parsing, family-name
matching, deduplication, and the update_repo fetch-then-reset
force-push tolerance behaviour.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from collectors.yara_rules import (
    YaraRulesCollector,
    _parse_yara_file,
    _extract_metadata,
)


# ---------------------------------------------------------------------------
# Sample YARA rule content
# ---------------------------------------------------------------------------

SAMPLE_EMOTET_RULE = """
rule Emotet_Loader : trojan
{
    meta:
        description = "Detects Emotet loader binary"
        author = "JPCERT/CC"
        reference = "https://blogs.jpcert.or.jp/en/2019/12/emotet-analysis.html"
        date = "2019-12-01"
        hash1 = "abc123def456"
    strings:
        $s1 = "Emotet" ascii
        $s2 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        $s1 and $s2
}
"""

SAMPLE_MULTI_RULE_FILE = """
rule Emotet_Loader : trojan malware
{
    meta:
        description = "Detects Emotet loader"
        author = "Alice"
    strings:
        $s = "emotet"
    condition:
        $s
}

rule TrickBot_Beacon
{
    meta:
        description = "Detects TrickBot beacon"
        author = "Bob"
    strings:
        $s = "trickbot"
    condition:
        $s
}

rule Unrelated_Rule
{
    meta:
        description = "Nothing to see"
    condition:
        false
}
"""

RULE_NO_META = """
rule Simple_Detector
{
    condition:
        true
}
"""


# ---------------------------------------------------------------------------
# _extract_metadata tests
# ---------------------------------------------------------------------------

class TestExtractMetadata:

    def test_description_extracted(self):
        meta = _extract_metadata(SAMPLE_EMOTET_RULE)
        assert meta.get("description") == "Detects Emotet loader binary"

    def test_author_extracted(self):
        meta = _extract_metadata(SAMPLE_EMOTET_RULE)
        assert meta.get("author") == "JPCERT/CC"

    def test_reference_extracted(self):
        meta = _extract_metadata(SAMPLE_EMOTET_RULE)
        assert "jpcert" in meta.get("reference", "").lower()

    def test_date_extracted(self):
        meta = _extract_metadata(SAMPLE_EMOTET_RULE)
        assert meta.get("date") == "2019-12-01"

    def test_missing_meta_section_returns_empty_dict(self):
        assert _extract_metadata(RULE_NO_META) == {}

    def test_keys_lowercased(self):
        rule = """
        rule R {
            meta:
                DESCRIPTION = "upper case key"
            condition:
                true
        }
        """
        meta = _extract_metadata(rule)
        assert "description" in meta

    def test_first_occurrence_wins(self):
        rule = """
        rule R {
            meta:
                description = "first"
                description = "second"
            condition:
                true
        }
        """
        meta = _extract_metadata(rule)
        assert meta.get("description") == "first"


# ---------------------------------------------------------------------------
# _parse_yara_file tests
# ---------------------------------------------------------------------------

class TestParseYaraFile:

    def test_matching_rule_parsed(self, tmp_path, monkeypatch):
        import collectors.yara_rules as yr_module
        monkeypatch.setattr(yr_module, "YARA_REPO_PATH", tmp_path)

        rule_file = tmp_path / "emotet.yar"
        rule_file.write_text(SAMPLE_EMOTET_RULE)

        rules = _parse_yara_file(rule_file, "Emotet")
        assert len(rules) == 1
        assert rules[0]["rule_name"] == "Emotet_Loader"
        assert rules[0]["author"] == "JPCERT/CC"
        assert "trojan" in rules[0]["tags"]

    def test_family_name_case_insensitive(self, tmp_path, monkeypatch):
        import collectors.yara_rules as yr_module
        monkeypatch.setattr(yr_module, "YARA_REPO_PATH", tmp_path)

        rule_file = tmp_path / "emotet.yar"
        rule_file.write_text(SAMPLE_EMOTET_RULE)

        rules = _parse_yara_file(rule_file, "EMOTET")
        assert len(rules) == 1

    def test_only_matching_rules_returned(self, tmp_path, monkeypatch):
        import collectors.yara_rules as yr_module
        monkeypatch.setattr(yr_module, "YARA_REPO_PATH", tmp_path)

        rule_file = tmp_path / "multi.yar"
        rule_file.write_text(SAMPLE_MULTI_RULE_FILE)

        # Querying Emotet should return only the Emotet rule
        rules = _parse_yara_file(rule_file, "Emotet")
        names = [r["rule_name"] for r in rules]
        assert "Emotet_Loader" in names
        assert "Unrelated_Rule" not in names

    def test_url_constructed_from_rel_path(self, tmp_path, monkeypatch):
        import collectors.yara_rules as yr_module
        monkeypatch.setattr(yr_module, "YARA_REPO_PATH", tmp_path)

        rule_dir = tmp_path / "malware"
        rule_dir.mkdir()
        rule_file = rule_dir / "emotet.yar"
        rule_file.write_text(SAMPLE_EMOTET_RULE)

        rules = _parse_yara_file(rule_file, "Emotet")
        assert "github.com/Yara-Rules/rules" in rules[0]["url"]
        assert "malware/emotet.yar" in rules[0]["url"]

    def test_missing_file_returns_empty(self, tmp_path):
        rules = _parse_yara_file(tmp_path / "does-not-exist.yar", "Emotet")
        assert rules == []


# ---------------------------------------------------------------------------
# YaraRulesCollector — repo ready state
# ---------------------------------------------------------------------------

class TestYaraRulesCollectorRepoState:

    def test_collect_returns_empty_when_repo_unavailable(self):
        collector = YaraRulesCollector()
        with patch.object(collector, "_ensure_repo", return_value=False):
            result = collector.collect_for_malware_families(["Emotet"])
        assert result == {}

    def test_collect_deduplicates_family_names(self):
        collector = YaraRulesCollector()
        called_with = []

        def mock_find(family):
            called_with.append(family)
            return []

        with patch.object(collector, "_ensure_repo", return_value=True):
            with patch.object(collector, "_find_rules_for_family",
                              side_effect=mock_find):
                collector.collect_for_malware_families(
                    ["Emotet", "Emotet", "TrickBot"],
                )

        assert called_with.count("Emotet") == 1
        assert "TrickBot" in called_with

    def test_find_rules_deduplicates_by_rule_name(self, tmp_path):
        collector = YaraRulesCollector()
        with patch("collectors.yara_rules.YARA_REPO_PATH", tmp_path):
            tmp_path.mkdir(exist_ok=True)
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=str(tmp_path / "a.yar") + "\n" + str(tmp_path / "b.yar"),
                )
                # Both files return the same rule name
                dup_rule = [{
                    "rule_name": "Emotet_Loader", "description": "d",
                    "author": "a", "reference": "", "date": "",
                    "url": "https://x", "tags": [], "path": "a.yar",
                }]
                with patch("collectors.yara_rules._parse_yara_file",
                           return_value=dup_rule):
                    result = collector._find_rules_for_family("Emotet")
        assert len(result) == 1

    def test_cap_enforced(self, tmp_path, monkeypatch):
        import collectors.yara_rules as yr_module
        monkeypatch.setattr(yr_module, "MAX_RULES_PER_FAMILY", 3)

        collector = YaraRulesCollector()
        with patch("collectors.yara_rules.YARA_REPO_PATH", tmp_path):
            tmp_path.mkdir(exist_ok=True)
            with patch("subprocess.run") as mock_run:
                files = [str(tmp_path / f"r{i}.yar") for i in range(10)]
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="\n".join(files),
                )
                # Return one unique rule per file
                counter = {"n": 0}

                def fake_parse(path, family):
                    counter["n"] += 1
                    return [{
                        "rule_name":   f"Rule_{counter['n']}",
                        "description": "", "author": "", "reference": "",
                        "date": "", "url": "", "tags": [], "path": "",
                    }]

                with patch("collectors.yara_rules._parse_yara_file",
                           side_effect=fake_parse):
                    result = collector._find_rules_for_family("Emotet")
        assert len(result) == 3

    def test_grep_error_returns_empty(self, tmp_path):
        collector = YaraRulesCollector()
        with patch("collectors.yara_rules.YARA_REPO_PATH", tmp_path):
            tmp_path.mkdir(exist_ok=True)
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout="")
                result = collector._find_rules_for_family("NoSuchFamily")
        assert result == []


# ---------------------------------------------------------------------------
# update_repo
# ---------------------------------------------------------------------------

class TestUpdateRepo:

    def test_update_runs_fetch_then_reset(self, tmp_path):
        collector = YaraRulesCollector()
        with patch("collectors.yara_rules.YARA_REPO_PATH", tmp_path):
            tmp_path.mkdir(exist_ok=True)
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                result = collector.update_repo()

        assert result is True
        assert mock_run.call_count == 2

        fetch_cmd = mock_run.call_args_list[0][0][0]
        assert "fetch" in fetch_cmd
        assert "pull" not in fetch_cmd

        reset_cmd = mock_run.call_args_list[1][0][0]
        assert "reset" in reset_cmd
        assert "--hard" in reset_cmd
        assert "origin/HEAD" in reset_cmd

    def test_update_returns_false_when_fetch_fails(self, tmp_path):
        collector = YaraRulesCollector()
        with patch("collectors.yara_rules.YARA_REPO_PATH", tmp_path):
            tmp_path.mkdir(exist_ok=True)
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stderr="fetch error")
                result = collector.update_repo()
        assert result is False
        assert mock_run.call_count == 1

    def test_update_returns_false_when_reset_fails(self, tmp_path):
        collector = YaraRulesCollector()
        with patch("collectors.yara_rules.YARA_REPO_PATH", tmp_path):
            tmp_path.mkdir(exist_ok=True)
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = [
                    MagicMock(returncode=0, stderr=""),
                    MagicMock(returncode=1, stderr="reset error"),
                ]
                result = collector.update_repo()
        assert result is False
        assert mock_run.call_count == 2

    def test_update_clones_when_repo_missing(self, tmp_path, monkeypatch):
        # If the repo directory doesn't exist yet, update_repo should
        # delegate to _ensure_repo which performs the initial clone.
        import collectors.yara_rules as yr_module
        missing_path = tmp_path / "does-not-exist"
        monkeypatch.setattr(yr_module, "YARA_REPO_PATH", missing_path)

        collector = YaraRulesCollector()
        with patch.object(collector, "_ensure_repo", return_value=True) as mock_ensure:
            result = collector.update_repo()
        assert result is True
        mock_ensure.assert_called_once()
