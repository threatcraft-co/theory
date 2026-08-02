"""
tests/test_mitre_mapper.py
--------------------------
Unit tests for mappers/mitre.py (MitreMapper).

These tests are fully offline — no ATT&CK network calls.
"""

from __future__ import annotations

import pytest
from mappers.mitre import MitreMapper


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_RAW = {
    "actor_name": "APT28",
    "source_id":  "mitre_attack",
    "aliases":    ["Fancy Bear", "Sofacy"],
    "description": "Russian state-sponsored threat actor.",
    "origin":      "Russia",
    "first_seen":  "2004",
    "motivations": ["espionage"],
    "techniques":  [],
    "indicators":  [],
    "malware":     [],
    "campaigns":   [],
    "mitre_id":    "G0007",
}

FULL_RAW = {
    **MINIMAL_RAW,
    "techniques": [
        {
            "technique_id":   "T1566",
            "technique_name": "Phishing",
            "tactic":         "initial access",
            "tactics":        ["initial access"],
            "description":    "Spearphishing with malicious attachments.",
            "detection":      "Monitor email gateways for suspicious attachments.",
            "sources":        ["mitre_attack"],
        },
        {
            "technique_id":   "T1059.001",
            "technique_name": "PowerShell",
            "tactic":         "execution",
            "tactics":        ["execution"],
            "description":    "Adversary uses PowerShell for execution.",
            "detection":      "Enable PowerShell script block logging.",
            "sources":        ["mitre_attack"],
        },
        {
            "technique_id":   "",   # ← should be dropped
            "technique_name": "Empty",
            "tactic":         "execution",
            "tactics":        [],
            "description":    "",
            "detection":      "",
            "sources":        [],
        },
    ],
    "malware": [
        {"name": "X-Agent", "type": "malware", "description": "Custom implant."},
        {"name": "",        "type": "malware", "description": "No name — drop."},
    ],
    "campaigns": [
        {
            "name":        "Operation Pawn Storm",
            "description": "Long-running espionage campaign.",
            "first_seen":  "2014",
            "last_seen":   "2023",
        },
        {
            "name":        "",
            "description": "Nameless — drop.",
            "first_seen":  "",
            "last_seen":   "",
        },
    ],
}


# ---------------------------------------------------------------------------
# MitreMapper tests
# ---------------------------------------------------------------------------

class TestMitreMapperValidation:
    def test_non_dict_raises(self):
        with pytest.raises(ValueError, match="Expected dict"):
            MitreMapper().map("not a dict")

    def test_missing_actor_name_raises(self):
        with pytest.raises(ValueError, match="actor_name"):
            MitreMapper().map({"source_id": "mitre_attack"})

    def test_empty_actor_name_raises(self):
        with pytest.raises(ValueError, match="actor_name"):
            MitreMapper().map({"actor_name": "  ", "source_id": "mitre_attack"})


class TestMitreMapperMinimal:
    def test_minimal_maps_cleanly(self):
        result = MitreMapper().map(MINIMAL_RAW)
        assert result["actor_name"] == "APT28"
        assert result["source_id"]  == "mitre_attack"
        assert result["techniques"] == []
        assert result["indicators"] == []
        assert result["malware"]    == []
        assert result["campaigns"]  == []

    def test_mitre_group_id_preserved(self):
        result = MitreMapper().map(MINIMAL_RAW)
        assert result["mitre_group_id"] == "G0007"

    def test_aliases_deduped(self):
        raw = {**MINIMAL_RAW, "aliases": ["Fancy Bear", "fancy bear", "FANCY BEAR"]}
        result = MitreMapper().map(raw)
        # Only the first unique value should survive
        assert len(result["aliases"]) == 1
        assert result["aliases"][0] == "Fancy Bear"


class TestMitreMapperTechniques:
    def test_valid_technique_passes(self):
        result = MitreMapper().map(FULL_RAW)
        tids = [t["technique_id"] for t in result["techniques"]]
        assert "T1566" in tids
        assert "T1059.001" in tids

    def test_empty_technique_id_dropped(self):
        result = MitreMapper().map(FULL_RAW)
        tids = [t["technique_id"] for t in result["techniques"]]
        assert "" not in tids

    def test_tactic_slug_normalised(self):
        result = MitreMapper().map(FULL_RAW)
        tactics = {t["technique_id"]: t["tactic"] for t in result["techniques"]}
        assert tactics["T1566"]     == "Initial Access"
        assert tactics["T1059.001"] == "Execution"

    def test_detection_preserved(self):
        result = MitreMapper().map(FULL_RAW)
        t = next(t for t in result["techniques"] if t["technique_id"] == "T1566")
        assert "email gateways" in t["detection"]


class TestMitreMapperMalware:
    def test_valid_malware_passes(self):
        result = MitreMapper().map(FULL_RAW)
        names = [m["name"] for m in result["malware"]]
        assert "X-Agent" in names

    def test_empty_name_dropped(self):
        result = MitreMapper().map(FULL_RAW)
        names = [m["name"] for m in result["malware"]]
        assert "" not in names


class TestMitreMapperCampaigns:
    def test_valid_campaign_passes(self):
        result = MitreMapper().map(FULL_RAW)
        names = [c["name"] for c in result["campaigns"]]
        assert "Operation Pawn Storm" in names

    def test_empty_name_dropped(self):
        result = MitreMapper().map(FULL_RAW)
        names = [c["name"] for c in result["campaigns"]]
        assert "" not in names

    def test_dates_preserved(self):
        result = MitreMapper().map(FULL_RAW)
        campaign = result["campaigns"][0]
        assert campaign["first_seen"] == "2014"
        assert campaign["last_seen"]  == "2023"


class TestMitreMapperUnknownTactic:
    def test_unknown_tactic_title_cased(self):
        raw = {
            **MINIMAL_RAW,
            "techniques": [{
                "technique_id":   "T9999",
                "technique_name": "Weird Technique",
                "tactic":         "some new tactic",
                "tactics":        ["some new tactic"],
                "description":    "",
                "detection":      "",
                "sources":        ["mitre_attack"],
            }],
        }
        result = MitreMapper().map(raw)
        assert result["techniques"][0]["tactic"] == "Some New Tactic"
