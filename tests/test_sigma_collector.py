"""
tests/test_sigma_collector.py
------------------------------
Unit tests for collectors/sigma_rules.py — fully offline.
Tests cover YAML parsing, cache logic, and condition summarisation.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path
from collectors.sigma_rules import (
    SigmaCollector,
    _extract_logsource,
    _extract_condition,
    _extract_tags,
    _summarise_condition,
)


# ---------------------------------------------------------------------------
# Sample Sigma rule YAML (realistic, no external dependency)
# ---------------------------------------------------------------------------

SAMPLE_RULE_YAML = """
title: Suspicious PowerShell Download Cradle
id: a7c3d9f1-1234-5678-abcd-ef0123456789
status: stable
description: Detects PowerShell download cradle used for payload delivery
references:
    - https://example.com/threat-report
author: THEORY Test
date: 2023/01/01
tags:
    - attack.t1059.001
    - attack.execution
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'WebClient'
    condition: selection
level: high
falsepositives:
    - Legitimate admin scripts
"""

SAMPLE_RULE_YAML_2 = """
title: Mimikatz Command Line
id: b8d4e0f2-2345-6789-bcde-f01234567890
status: test
description: Detects Mimikatz usage via command line
tags:
    - attack.t1003.001
    - attack.credential_access
logsource:
    product: windows
    service: security
detection:
    selection:
        CommandLine|contains: 'sekurlsa'
    filter:
        User: 'SYSTEM'
    condition: selection and not filter
level: critical
falsepositives:
    - None
"""

RULE_NO_TITLE = """
status: stable
tags:
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 'test'
    condition: selection
level: medium
"""


# ---------------------------------------------------------------------------
# YAML parsing tests
# ---------------------------------------------------------------------------

class TestExtractLogsource:

    def test_category_and_product(self):
        lines = SAMPLE_RULE_YAML.splitlines()
        assert _extract_logsource(lines) == "process_creation / windows"

    def test_product_and_service(self):
        lines = SAMPLE_RULE_YAML_2.splitlines()
        result = _extract_logsource(lines)
        assert "windows" in result
        assert "security" in result

    def test_missing_logsource_returns_unknown(self):
        lines = ["title: Test Rule", "status: stable"]
        assert _extract_logsource(lines) == "unknown"


class TestExtractCondition:

    def test_simple_condition(self):
        lines = SAMPLE_RULE_YAML.splitlines()
        assert _extract_condition(lines) == "selection"

    def test_compound_condition(self):
        lines = SAMPLE_RULE_YAML_2.splitlines()
        assert "selection" in _extract_condition(lines)
        assert "filter" in _extract_condition(lines)

    def test_no_detection_block(self):
        lines = ["title: Test", "status: stable"]
        assert _extract_condition(lines) == ""


class TestExtractTags:

    def test_attack_tags_extracted(self):
        lines = SAMPLE_RULE_YAML.splitlines()
        tags  = _extract_tags(lines)
        assert "attack.t1059.001"  in tags
        assert "attack.execution"  in tags

    def test_multiple_tags(self):
        lines = SAMPLE_RULE_YAML.splitlines()
        tags  = _extract_tags(lines)
        assert len(tags) >= 3

    def test_no_tags_returns_empty(self):
        lines = ["title: Test", "status: stable"]
        assert _extract_tags(lines) == []


class TestSummariseCondition:

    def test_simple_selection(self):
        result = _summarise_condition("selection")
        # "selection" → "selection filter" via regex, which is correct
        assert "selection" in result.lower()

    def test_and_not(self):
        result = _summarise_condition("selection and not filter")
        assert "excluding" in result.lower()

    def test_all_of_them(self):
        result = _summarise_condition("all of them")
        assert "all" in result.lower()

    def test_one_of_selection(self):
        result = _summarise_condition("1 of selection*")
        assert "any" in result.lower() or "selection" in result.lower()

    def test_empty_returns_empty(self):
        assert _summarise_condition("") == ""


# ---------------------------------------------------------------------------
# SigmaCollector._parse_sigma_yaml
# ---------------------------------------------------------------------------

class TestParseSigmaYaml:

    def test_valid_rule_parsed(self):
        rule = SigmaCollector._parse_sigma_yaml(SAMPLE_RULE_YAML, "https://example.com")
        assert rule is not None
        assert rule["title"] == "Suspicious PowerShell Download Cradle"
        assert rule["level"] == "high"
        assert rule["status"] == "stable"

    def test_logsource_extracted(self):
        rule = SigmaCollector._parse_sigma_yaml(SAMPLE_RULE_YAML, "")
        assert rule["logsource"] == "process_creation / windows"

    def test_tags_extracted(self):
        rule = SigmaCollector._parse_sigma_yaml(SAMPLE_RULE_YAML, "")
        assert "attack.t1059.001" in rule["tags"]

    def test_url_preserved(self):
        url  = "https://github.com/SigmaHQ/sigma/blob/master/rules/test.yml"
        rule = SigmaCollector._parse_sigma_yaml(SAMPLE_RULE_YAML, url)
        assert rule["url"] == url

    def test_condition_summarised(self):
        rule = SigmaCollector._parse_sigma_yaml(SAMPLE_RULE_YAML, "")
        assert rule["condition_summary"] != ""

    def test_no_title_returns_none(self):
        rule = SigmaCollector._parse_sigma_yaml(RULE_NO_TITLE, "")
        assert rule is None

    def test_critical_level_parsed(self):
        rule = SigmaCollector._parse_sigma_yaml(SAMPLE_RULE_YAML_2, "")
        assert rule["level"] == "critical"


# ---------------------------------------------------------------------------
# Cache logic
# ---------------------------------------------------------------------------

class TestSigmaCache:

    def test_save_and_load_cache(self, tmp_path, monkeypatch):
        import collectors.sigma_rules as sigma_module
        monkeypatch.setattr(sigma_module, "CACHE_DIR", tmp_path)

        collector = SigmaCollector()
        rules = [{"title": "Test Rule", "level": "high", "logsource": "process_creation / windows",
                  "condition_summary": "selection filter", "tags": ["attack.t1059.001"],
                  "status": "stable", "description": "", "url": ""}]

        collector._save_cache("T1059.001", rules)
        loaded = collector._load_cache("T1059.001")
        assert loaded is not None
        assert len(loaded) == 1
        assert loaded[0]["title"] == "Test Rule"

    def test_empty_cache_saved_and_loaded(self, tmp_path, monkeypatch):
        import collectors.sigma_rules as sigma_module
        monkeypatch.setattr(sigma_module, "CACHE_DIR", tmp_path)

        collector = SigmaCollector()
        collector._save_cache("T9999", [])
        loaded = collector._load_cache("T9999")
        assert loaded == []   # empty list, not None

    def test_missing_cache_returns_none(self, tmp_path, monkeypatch):
        import collectors.sigma_rules as sigma_module
        monkeypatch.setattr(sigma_module, "CACHE_DIR", tmp_path)

        collector = SigmaCollector()
        assert collector._load_cache("T0000") is None

    def test_stale_cache_returns_none(self, tmp_path, monkeypatch):
        import collectors.sigma_rules as sigma_module
        from datetime import datetime, timezone, timedelta

        monkeypatch.setattr(sigma_module, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(sigma_module, "CACHE_TTL_DAYS", 0)

        collector = SigmaCollector()
        collector._save_cache("T1059.001", [{"title": "Old Rule"}])

        # TTL = 0 days means immediately stale
        loaded = collector._load_cache("T1059.001")
        assert loaded is None


# ---------------------------------------------------------------------------
# collect_for_techniques with mocked GitHub API
# ---------------------------------------------------------------------------

class TestCollectForTechniques:

    def test_returns_empty_for_no_techniques(self, tmp_path, monkeypatch):
        import collectors.sigma_rules as sigma_module
        monkeypatch.setattr(sigma_module, "CACHE_DIR", tmp_path)

        collector = SigmaCollector()
        result = collector.collect_for_techniques([])
        assert result == {}

    def test_uses_cache_when_available(self, tmp_path, monkeypatch):
        import collectors.sigma_rules as sigma_module
        monkeypatch.setattr(sigma_module, "CACHE_DIR", tmp_path)

        collector = SigmaCollector()
        cached_rules = [{"title": "Cached Rule", "level": "high",
                         "logsource": "process_creation / windows",
                         "condition_summary": "selection", "tags": [],
                         "status": "stable", "description": "", "url": ""}]
        collector._save_cache("T1059.001", cached_rules)

        result = collector.collect_for_techniques(["T1059.001"])
        assert "T1059.001" in result
        assert result["T1059.001"][0]["title"] == "Cached Rule"

    def test_deduplicates_technique_ids(self, tmp_path, monkeypatch):
        import collectors.sigma_rules as sigma_module
        monkeypatch.setattr(sigma_module, "CACHE_DIR", tmp_path)

        # Pre-cache so no network call needed
        collector = SigmaCollector()
        collector._save_cache("T1059.001", [])

        # Passing duplicate IDs should only query once
        result = collector.collect_for_techniques(
            ["T1059.001", "T1059.001", "T1059.001"]
        )
        # Empty cache → not in results (only non-empty results returned)
        assert "T1059.001" not in result
