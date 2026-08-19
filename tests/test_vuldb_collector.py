"""
tests/test_vuldb_collector.py
------------------------------
Unit tests for collectors/vuldb.py — fully offline.

VulDB is a standard collector: query(actor_name) returns a
CommonSchema-compatible dict with populated cves list. Tests cover
entry parsing, cache, and the empty/missing-key paths.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch

from collectors.vuldb import VulDBCollector, _slugify


# ---------------------------------------------------------------------------
# Sample VulDB API responses
# ---------------------------------------------------------------------------

SAMPLE_ENTRY = {
    "id": "212043",
    "source": {
        "cve": {
            "id": "CVE-2022-12345",
        },
    },
    "vulnerability": {
        "class":  "SQL Injection",
        "risk":   {"name": "High"},
        "cvss3":  {"basescore": "9.8"},
    },
    "advisory": {
        "url":  "https://example.com/advisory/12345",
        "date": "1666562400",
    },
    "exploit": {
        "exploitability": "high",
        "price":          {"today": "$1k-$5k"},
    },
    "countermeasure": {
        "remediationlevel": "official fix",
        "name":             "Upgrade",
    },
}

SAMPLE_ENTRY_NO_PREFIX = {
    # VulDB sometimes returns bare numbers — the parser should prepend CVE-
    "id": "212044",
    "source": {"cve": {"id": "2023-9999"}},
    "vulnerability": {"class": "XSS", "risk": {"name": "Medium"}},
    "advisory": {},
    "exploit":  {},
    "countermeasure": {},
}

SAMPLE_ENTRY_NO_CVE = {
    # Entries without a CVE ID must be dropped
    "id": "212045",
    "source": {"cve": {}},
    "vulnerability": {},
    "advisory": {},
    "exploit":  {},
    "countermeasure": {},
}

SAMPLE_ENTRY_MINIMAL = {
    "id": "212046",
    "source": {"cve": {"id": "CVE-2024-0001"}},
}


# ---------------------------------------------------------------------------
# _parse_entry tests
# ---------------------------------------------------------------------------

class TestParseEntry:

    def test_cve_id_parsed(self):
        cve = VulDBCollector._parse_entry(SAMPLE_ENTRY)
        assert cve is not None
        assert cve["cve_id"] == "CVE-2022-12345"

    def test_cve_prefix_added_when_missing(self):
        cve = VulDBCollector._parse_entry(SAMPLE_ENTRY_NO_PREFIX)
        assert cve["cve_id"] == "CVE-2023-9999"

    def test_no_cve_id_returns_none(self):
        assert VulDBCollector._parse_entry(SAMPLE_ENTRY_NO_CVE) is None

    def test_cvss_score_parsed(self):
        cve = VulDBCollector._parse_entry(SAMPLE_ENTRY)
        assert cve["cvss_score"] == 9.8

    def test_missing_cvss_score_is_none(self):
        cve = VulDBCollector._parse_entry(SAMPLE_ENTRY_MINIMAL)
        assert cve["cvss_score"] is None

    def test_description_includes_class_and_risk(self):
        cve = VulDBCollector._parse_entry(SAMPLE_ENTRY)
        assert "SQL Injection" in cve["description"]
        assert "High" in cve["description"]

    def test_sources_lists_vuldb(self):
        cve = VulDBCollector._parse_entry(SAMPLE_ENTRY)
        assert "vuldb" in cve["sources"]

    def test_exploit_price_extracted(self):
        cve = VulDBCollector._parse_entry(SAMPLE_ENTRY)
        assert cve["exploit_price_today"] == "$1k-$5k"

    def test_remediation_extracted(self):
        cve = VulDBCollector._parse_entry(SAMPLE_ENTRY)
        assert "Upgrade" in cve["remediation"]
        assert "official fix" in cve["remediation"]

    def test_advisory_url_preserved(self):
        cve = VulDBCollector._parse_entry(SAMPLE_ENTRY)
        assert cve["advisory_url"] == "https://example.com/advisory/12345"

    def test_vuldb_id_preserved(self):
        cve = VulDBCollector._parse_entry(SAMPLE_ENTRY)
        assert cve["vuldb_id"] == "212043"

    def test_minimal_entry_still_parses(self):
        cve = VulDBCollector._parse_entry(SAMPLE_ENTRY_MINIMAL)
        assert cve is not None
        assert cve["cve_id"] == "CVE-2024-0001"


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------

class TestVulDBCache:

    def test_save_and_load(self, tmp_path, monkeypatch):
        import collectors.vuldb as vuldb_module
        monkeypatch.setattr(vuldb_module, "CACHE_DIR", tmp_path)

        collector = VulDBCollector(api_key="test")
        schema = {
            "actor_name": "APT28",
            "source_id":  "vuldb",
            "cves":       [{"cve_id": "CVE-2022-12345", "sources": ["vuldb"]}],
        }
        collector._save_cache("apt28", schema)
        loaded = collector._load_cache("apt28")
        assert loaded == schema

    def test_missing_returns_none(self, tmp_path, monkeypatch):
        import collectors.vuldb as vuldb_module
        monkeypatch.setattr(vuldb_module, "CACHE_DIR", tmp_path)

        collector = VulDBCollector(api_key="test")
        assert collector._load_cache("nonexistent") is None

    def test_stale_cache_returns_none(self, tmp_path, monkeypatch):
        import collectors.vuldb as vuldb_module
        monkeypatch.setattr(vuldb_module, "CACHE_DIR", tmp_path)
        monkeypatch.setattr(vuldb_module, "CACHE_TTL_DAYS", 0)

        collector = VulDBCollector(api_key="test")
        collector._save_cache("stale", {"actor_name": "APT28", "cves": []})
        assert collector._load_cache("stale") is None


# ---------------------------------------------------------------------------
# query() end-to-end
# ---------------------------------------------------------------------------

class TestQuery:

    def test_missing_api_key_returns_empty_schema(self):
        collector = VulDBCollector(api_key="")
        result = collector.query("APT28")
        # Empty schema has all required keys but empty CVE list
        assert result is not None
        assert result["actor_name"] == "APT28"
        assert result["source_id"] == "vuldb"
        assert result.get("cves", []) == []

    def test_uses_cache(self, tmp_path, monkeypatch):
        import collectors.vuldb as vuldb_module
        monkeypatch.setattr(vuldb_module, "CACHE_DIR", tmp_path)

        collector = VulDBCollector(api_key="test")
        cached = {
            "actor_name":      "APT28",
            "source_id":       "vuldb",
            "cves":            [{"cve_id": "CVE-2022-12345", "sources": ["vuldb"]}],
            "source_url":      "https://vuldb.com/?actor.apt28",
            "source_citation": "VulDB CTI (vuldb.com)",
            "aliases":         [],
            "retrieved_at":    "2026-08-18T00:00:00+00:00",
            "suspected_origin": None,
            "motivation":      [],
            "first_seen":      None,
            "sponsorship":     None,
            "target_sectors":  [],
            "target_countries": [],
            "techniques":      [],
            "malware":         [],
            "indicators":      [],
            "campaigns":       [],
        }
        collector._save_cache("apt28", cached)

        # Mock _search_actor so any cache miss would fail loudly
        with patch.object(collector, "_search_actor") as mock_search:
            result = collector.query("APT28")

        assert result["cves"][0]["cve_id"] == "CVE-2022-12345"
        mock_search.assert_not_called()

    def test_search_result_saved_to_cache(self, tmp_path, monkeypatch):
        import collectors.vuldb as vuldb_module
        monkeypatch.setattr(vuldb_module, "CACHE_DIR", tmp_path)

        collector = VulDBCollector(api_key="test")
        fake_cves = [{
            "cve_id":               "CVE-2022-12345",
            "sources":              ["vuldb"],
            "description":          "SQL Injection | Risk: High",
            "cvss_score":           9.8,
            "vuldb_id":             "212043",
            "exploitability":       "high",
            "exploit_price_today":  "$1k-$5k",
            "remediation":          "Upgrade: official fix",
            "advisory_url":         "https://example.com/advisory/12345",
            "advisory_date":        "1666562400",
        }]
        with patch.object(collector, "_search_actor", return_value=fake_cves):
            result = collector.query("APT28")

        assert result["cves"][0]["cve_id"] == "CVE-2022-12345"
        # Second call should hit cache and not re-search
        with patch.object(collector, "_search_actor") as mock_search:
            second = collector.query("APT28")
        assert second["cves"][0]["cve_id"] == "CVE-2022-12345"
        mock_search.assert_not_called()

    def test_empty_search_still_returns_valid_schema(self, tmp_path, monkeypatch):
        import collectors.vuldb as vuldb_module
        monkeypatch.setattr(vuldb_module, "CACHE_DIR", tmp_path)

        collector = VulDBCollector(api_key="test")
        with patch.object(collector, "_search_actor", return_value=[]):
            result = collector.query("Unknown Actor")
        assert result is not None
        assert result["cves"] == []
        assert result["actor_name"] == "Unknown Actor"


# ---------------------------------------------------------------------------
# _search_actor deduplication
# ---------------------------------------------------------------------------

class TestSearchActor:

    def test_deduplicates_cves(self):
        collector = VulDBCollector(api_key="test")
        dupe_data = {
            "result": [SAMPLE_ENTRY, SAMPLE_ENTRY],  # same entry twice
        }
        with patch.object(collector, "_api_post", return_value=dupe_data):
            cves = collector._search_actor("APT28")
        assert len(cves) == 1

    def test_max_results_capped(self, monkeypatch):
        import collectors.vuldb as vuldb_module
        monkeypatch.setattr(vuldb_module, "MAX_RESULTS", 3)

        collector = VulDBCollector(api_key="test")
        # 10 unique entries
        many_entries = [
            {**SAMPLE_ENTRY, "id": str(i),
             "source": {"cve": {"id": f"CVE-2024-{i:04d}"}}}
            for i in range(10)
        ]
        with patch.object(collector, "_api_post",
                          return_value={"result": many_entries}):
            cves = collector._search_actor("APT28")
        assert len(cves) == 3

    def test_malformed_response_returns_empty(self):
        collector = VulDBCollector(api_key="test")
        with patch.object(collector, "_api_post", return_value="not a dict"):
            assert collector._search_actor("APT28") == []


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------

class TestUtilities:

    def test_slugify_spaces(self):
        assert _slugify("Fancy Bear") == "fancy_bear"

    def test_slugify_special_chars(self):
        assert _slugify("APT28/Sofacy") == "apt28_sofacy"

    def test_slugify_truncates(self):
        assert len(_slugify("a" * 100)) <= 80
