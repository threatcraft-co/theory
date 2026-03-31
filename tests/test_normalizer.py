"""tests/test_normalizer.py — Full coverage for processors/normalizer.py"""
import pytest
from processors.normalizer import normalize, NormalizationError


def minimal(overrides=None):
    base = {"actor_name": "APT28", "source_id": "mitre_attack"}
    if overrides:
        base.update(overrides)
    return base


class TestRequiredFields:
    def test_missing_actor_name_raises(self):
        with pytest.raises(NormalizationError, match="actor_name"):
            normalize({"source_id": "mitre_attack"})
    def test_missing_source_id_raises(self):
        with pytest.raises(NormalizationError, match="source_id"):
            normalize({"actor_name": "APT28"})
    def test_non_dict_input_raises(self):
        with pytest.raises(NormalizationError):
            normalize(["not", "a", "dict"])
    def test_empty_actor_name_raises(self):
        with pytest.raises(NormalizationError):
            normalize({"actor_name": "", "source_id": "x"})
    def test_minimal_valid_schema_passes(self):
        r = normalize(minimal())
        assert r["actor_name"] == "APT28"
        assert r["source_id"] == "mitre_attack"


class TestActorNameNormalization:
    def test_strips_excess_whitespace(self):
        assert normalize(minimal({"actor_name": "  APT28  "}))["actor_name"] == "APT28"
    def test_collapses_internal_whitespace(self):
        assert normalize(minimal({"actor_name": "Scattered  Spider"}))["actor_name"] == "Scattered Spider"
    def test_preserves_casing(self):
        assert normalize(minimal({"actor_name": "FancyBear"}))["actor_name"] == "FancyBear"


class TestTimestampNormalization:
    def test_iso8601_string_passes(self):
        assert "2024-01-15" in normalize(minimal({"retrieved_at": "2024-01-15T10:00:00+00:00"}))["retrieved_at"]
    def test_unix_epoch_int_converted(self):
        assert "2023" in normalize(minimal({"retrieved_at": 1700000000}))["retrieved_at"]
    def test_mm_dd_yyyy_converted(self):
        assert "2024" in normalize(minimal({"retrieved_at": "03/15/2024"}))["retrieved_at"]
    def test_none_timestamp_uses_current_utc(self):
        assert normalize(minimal({"retrieved_at": None}))["retrieved_at"]
    def test_first_seen_year_only_preserved(self):
        assert normalize(minimal({"first_seen": "2022"}))["first_seen"] == "2022"
    def test_first_seen_none_returns_empty(self):
        assert normalize(minimal({"first_seen": None}))["first_seen"] == ""


class TestSectorNormalization:
    def test_finance_aliases_normalized(self):
        for alias in ["fin", "financial", "financial services", "banking"]:
            assert "Finance" in normalize(minimal({"target_sectors": [alias]}))["target_sectors"]
    def test_healthcare_aliases_normalized(self):
        for alias in ["health", "healthcare", "medical", "hospital"]:
            assert "Healthcare" in normalize(minimal({"target_sectors": [alias]}))["target_sectors"]
    def test_unknown_sector_title_cased(self):
        assert "Custom Sector" in normalize(minimal({"target_sectors": ["custom sector"]}))["target_sectors"]
    def test_duplicate_sectors_deduplicated(self):
        r = normalize(minimal({"target_sectors": ["Finance", "financial", "fin"]}))
        assert r["target_sectors"].count("Finance") == 1


class TestTechniqueIdNormalization:
    def test_valid_technique_passes(self):
        r = normalize(minimal({"techniques": [{"technique_id": "T1566", "name": "Phishing"}]}))
        assert len(r["techniques"]) == 1
        assert r["techniques"][0]["technique_id"] == "T1566"
    def test_valid_subtechnique_passes(self):
        r = normalize(minimal({"techniques": [{"technique_id": "T1566.001", "name": "x"}]}))
        assert r["techniques"][0]["technique_id"] == "T1566.001"
    def test_lowercase_uppercased(self):
        r = normalize(minimal({"techniques": [{"technique_id": "t1566", "name": "x"}]}))
        assert r["techniques"][0]["technique_id"] == "T1566"
    def test_malformed_rejected(self):
        r = normalize(minimal({"techniques": [{"technique_id": "INVALID-123", "name": "x"}]}))
        assert len(r["techniques"]) == 0
    def test_no_id_dropped(self):
        r = normalize(minimal({"techniques": [{"name": "Phishing", "tactic": "Initial Access"}]}))
        assert len(r["techniques"]) == 0
    def test_whitespace_stripped(self):
        r = normalize(minimal({"techniques": [{"technique_id": " T1566 ", "name": "x"}]}))
        assert r["techniques"][0]["technique_id"] == "T1566"


class TestIndicatorNormalization:
    def test_ipv4_mapped_to_ip(self):
        r = normalize(minimal({"indicators": [{"type": "ipv4", "value": "1.2.3.4"}]}))
        assert r["indicators"][0]["type"] == "ip"
    def test_filehash_md5_mapped(self):
        r = normalize(minimal({"indicators": [{"type": "FileHash-MD5", "value": "abc123"}]}))
        assert r["indicators"][0]["type"] == "hash_md5"
    def test_hostname_mapped_to_domain(self):
        r = normalize(minimal({"indicators": [{"type": "hostname", "value": "evil.example.com"}]}))
        assert r["indicators"][0]["type"] == "domain"
    def test_unknown_type_dropped(self):
        r = normalize(minimal({"indicators": [{"type": "registry_key", "value": "HKLM\\Evil"}]}))
        assert len(r["indicators"]) == 0
    def test_empty_value_dropped(self):
        r = normalize(minimal({"indicators": [{"type": "domain", "value": ""}]}))
        assert len(r["indicators"]) == 0


class TestMotivationNormalization:
    def test_valid_motivations_pass(self):
        for mot in ["financial", "espionage", "hacktivism", "destruction", "unknown"]:
            assert mot in normalize(minimal({"motivation": [mot]}))["motivation"]
    def test_unrecognized_mapped_to_unknown(self):
        assert "unknown" in normalize(minimal({"motivation": ["profit"]}))["motivation"]
    def test_duplicates_removed(self):
        r = normalize(minimal({"motivation": ["financial", "financial"]}))
        assert r["motivation"].count("financial") == 1


class TestMalwareNormalization:
    def test_valid_entry_passes(self):
        r = normalize(minimal({"malware": [{"name": "BlackCat", "type": "ransomware", "description": "x"}]}))
        assert len(r["malware"]) == 1
    def test_no_name_dropped(self):
        r = normalize(minimal({"malware": [{"type": "ransomware", "description": "x"}]}))
        assert len(r["malware"]) == 0


class TestAliasNormalization:
    def test_case_insensitive_dedup(self):
        r = normalize(minimal({"aliases": ["Fancy Bear", "fancy bear", "FANCY BEAR"]}))
        assert len(r["aliases"]) == 1
        assert r["aliases"][0] == "Fancy Bear"
    def test_empty_aliases_ignored(self):
        r = normalize(minimal({"aliases": ["", "  ", "APT28"]}))
        assert r["aliases"] == ["APT28"]
