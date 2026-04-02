"""
tests/test_sigma_collector.py
------------------------------
Unit tests for the Sigma collector — fully offline.
Tests the local-clone architecture: YAML parsing, rule filtering,
condition summarisation, and tag matching.
No real git clone or grep calls are made in tests.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from collectors.sigma_rules import (
    SigmaCollector,
    _parse_sigma_minimal,
    _summarise_condition,
    _rule_covers_technique,
    _build_rule_dict,
)


# ---------------------------------------------------------------------------
# Sample Sigma rule YAML content
# ---------------------------------------------------------------------------

SAMPLE_RULE_YAML = """\
title: Suspicious PowerShell Download
status: stable
level: high
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: downloadstring
    condition: selection
"""

SAMPLE_RULE_YAML_CRITICAL = """\
title: Antivirus Password Dumper Detection
status: stable
level: critical
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: antivirus
detection:
    selection:
        Signature|contains: dumper
    condition: selection
"""

SAMPLE_RULE_NO_TITLE = """\
status: stable
level: high
tags:
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    condition: selection
"""


# ---------------------------------------------------------------------------
# _parse_sigma_minimal tests
# ---------------------------------------------------------------------------

class TestParseSigmaMinimal:

    def test_valid_rule_parsed(self, tmp_path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(SAMPLE_RULE_YAML)
        # Patch SIGMA_REPO_PATH for relative path calculation
        with patch("collectors.sigma_rules.SIGMA_REPO_PATH", tmp_path):
            result = _parse_sigma_minimal(SAMPLE_RULE_YAML, rule_file)
        assert result is not None
        assert result["title"] == "Suspicious PowerShell Download"

    def test_level_extracted(self, tmp_path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(SAMPLE_RULE_YAML)
        with patch("collectors.sigma_rules.SIGMA_REPO_PATH", tmp_path):
            result = _parse_sigma_minimal(SAMPLE_RULE_YAML, rule_file)
        assert result["level"] == "high"

    def test_status_extracted(self, tmp_path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(SAMPLE_RULE_YAML)
        with patch("collectors.sigma_rules.SIGMA_REPO_PATH", tmp_path):
            result = _parse_sigma_minimal(SAMPLE_RULE_YAML, rule_file)
        assert result["status"] == "stable"

    def test_tags_extracted(self, tmp_path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(SAMPLE_RULE_YAML)
        with patch("collectors.sigma_rules.SIGMA_REPO_PATH", tmp_path):
            result = _parse_sigma_minimal(SAMPLE_RULE_YAML, rule_file)
        assert "attack.t1059.001" in result["tags"]

    def test_logsource_extracted(self, tmp_path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(SAMPLE_RULE_YAML)
        with patch("collectors.sigma_rules.SIGMA_REPO_PATH", tmp_path):
            result = _parse_sigma_minimal(SAMPLE_RULE_YAML, rule_file)
        assert "process_creation" in result["logsource"]
        assert "windows" in result["logsource"]

    def test_condition_extracted(self, tmp_path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(SAMPLE_RULE_YAML)
        with patch("collectors.sigma_rules.SIGMA_REPO_PATH", tmp_path):
            result = _parse_sigma_minimal(SAMPLE_RULE_YAML, rule_file)
        assert result["condition_summary"] == "selection"

    def test_url_constructed(self, tmp_path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(SAMPLE_RULE_YAML)
        with patch("collectors.sigma_rules.SIGMA_REPO_PATH", tmp_path):
            result = _parse_sigma_minimal(SAMPLE_RULE_YAML, rule_file)
        assert "github.com/SigmaHQ/sigma" in result["url"]

    def test_no_title_returns_none(self, tmp_path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(SAMPLE_RULE_NO_TITLE)
        with patch("collectors.sigma_rules.SIGMA_REPO_PATH", tmp_path):
            result = _parse_sigma_minimal(SAMPLE_RULE_NO_TITLE, rule_file)
        assert result is None

    def test_critical_level_parsed(self, tmp_path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(SAMPLE_RULE_YAML_CRITICAL)
        with patch("collectors.sigma_rules.SIGMA_REPO_PATH", tmp_path):
            result = _parse_sigma_minimal(SAMPLE_RULE_YAML_CRITICAL, rule_file)
        assert result["level"] == "critical"


# ---------------------------------------------------------------------------
# _summarise_condition tests
# ---------------------------------------------------------------------------

class TestSummariseCondition:

    def test_simple_condition(self):
        assert _summarise_condition("selection") == "selection"

    def test_and_not(self):
        assert "not" in _summarise_condition("selection and not filter")

    def test_all_of_them(self):
        assert _summarise_condition("all of them") == "all of them"

    def test_one_of_selection(self):
        assert _summarise_condition("1 of selection_*") == "1 of selection_*"

    def test_empty_returns_empty(self):
        assert _summarise_condition("") == ""

    def test_long_condition_truncated(self):
        long = "selection and " * 20
        result = _summarise_condition(long)
        assert len(result) <= 83   # 80 chars + "..."
        assert result.endswith("...")


# ---------------------------------------------------------------------------
# _rule_covers_technique tests
# ---------------------------------------------------------------------------

class TestRuleCoverstech:

    def test_exact_match(self):
        rule = {"tags": ["attack.t1059.001", "attack.execution"]}
        assert _rule_covers_technique(rule, "T1059.001") is True

    def test_no_match(self):
        rule = {"tags": ["attack.t1059.001"]}
        assert _rule_covers_technique(rule, "T1003") is False

    def test_case_insensitive(self):
        rule = {"tags": ["attack.t1059.001"]}
        assert _rule_covers_technique(rule, "T1059.001") is True

    def test_empty_tags(self):
        rule = {"tags": []}
        assert _rule_covers_technique(rule, "T1059.001") is False

    def test_parent_technique_not_matched_by_subtechnique(self):
        # T1059 tag should NOT match T1059.001 query — must be exact
        rule = {"tags": ["attack.t1059"]}
        assert _rule_covers_technique(rule, "T1059.001") is False


# ---------------------------------------------------------------------------
# SigmaCollector — repo ready state
# ---------------------------------------------------------------------------

class TestSigmaCollectorRepoState:

    def test_collect_returns_empty_when_repo_unavailable(self, tmp_path):
        collector = SigmaCollector()
        with patch("collectors.sigma_rules.RULES_DIR", tmp_path / "nonexistent"):
            with patch.object(collector, "_ensure_repo", return_value=False):
                result = collector.collect_for_techniques(["T1059.001"])
        assert result == {}

    def test_collect_deduplicates_technique_ids(self, tmp_path):
        collector = SigmaCollector()
        called_with = []

        def mock_find(tid):
            called_with.append(tid)
            return []

        with patch.object(collector, "_ensure_repo", return_value=True):
            with patch.object(collector, "_find_rules_for_technique", side_effect=mock_find):
                collector.collect_for_techniques(["T1059.001", "T1059.001", "T1003"])

        assert called_with.count("T1059.001") == 1
        assert "T1003" in called_with

    def test_rules_sorted_critical_first(self, tmp_path):
        collector = SigmaCollector()
        mock_rules = [
            {"title": "Low rule",      "level": "low",      "tags": ["attack.t1059.001"]},
            {"title": "Critical rule", "level": "critical", "tags": ["attack.t1059.001"]},
            {"title": "High rule",     "level": "high",     "tags": ["attack.t1059.001"]},
        ]

        with patch("collectors.sigma_rules.RULES_DIR", tmp_path):
            with patch.object(collector, "_ensure_repo", return_value=True):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(
                        returncode=0,
                        stdout="\n".join([str(tmp_path / f"rule{i}.yml") for i in range(3)]),
                    )
                    with patch("collectors.sigma_rules._parse_sigma_yaml",
                               side_effect=mock_rules):
                        with patch("collectors.sigma_rules._rule_covers_technique",
                                   return_value=True):
                            result = collector._find_rules_for_technique("T1059.001")

        if result:
            levels = [r["level"] for r in result]
            critical_idx = levels.index("critical") if "critical" in levels else -1
            high_idx     = levels.index("high")     if "high"     in levels else -1
            low_idx      = levels.index("low")      if "low"      in levels else -1
            if critical_idx >= 0 and high_idx >= 0:
                assert critical_idx < high_idx
            if high_idx >= 0 and low_idx >= 0:
                assert high_idx < low_idx


# ---------------------------------------------------------------------------
# Update repo
# ---------------------------------------------------------------------------

class TestUpdateRepo:

    def test_update_calls_git_pull(self, tmp_path):
        collector = SigmaCollector()
        with patch("collectors.sigma_rules.SIGMA_REPO_PATH", tmp_path):
            tmp_path.mkdir(exist_ok=True)
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                result = collector.update_repo()
        assert result is True
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "pull" in call_args

    def test_update_returns_false_on_failure(self, tmp_path):
        collector = SigmaCollector()
        with patch("collectors.sigma_rules.SIGMA_REPO_PATH", tmp_path):
            tmp_path.mkdir(exist_ok=True)
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stderr="error")
                result = collector.update_repo()
        assert result is False
