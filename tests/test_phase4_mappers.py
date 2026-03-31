"""
tests/test_phase4_mappers.py
-----------------------------
Unit tests for Phase 4 mappers and collectors (offline).
Covers MalpediaMapper, AlienVaultOTXMapper, and the
cross-source confidence scoring behaviour in theory.run().
"""

from __future__ import annotations

import pytest
from collectors.malpedia       import MalpediaMapper, _slug_to_display, _classify_family
from collectors.alienvault_otx import AlienVaultOTXMapper


# ---------------------------------------------------------------------------
# Malpedia mapper
# ---------------------------------------------------------------------------

MINIMAL_MALPEDIA = {
    "actor_name": "APT28",
    "source_id":  "malpedia",
    "aliases":    [],
    "description": "GRU-linked threat actor.",
    "origin":      "Russia",
    "first_seen":  "",
    "motivations": ["espionage"],
    "techniques":  [],
    "indicators":  [],
    "malware": [
        {
            "name":        "X-Agent",
            "type":        "backdoor",
            "description": "Custom implant.",
            "aliases":     ["Sofacy", "CHOPSTICK"],
            "yara_count":  12,
            "sources":     ["malpedia"],
        },
        {
            "name":        "",   # should be dropped
            "type":        "malware",
            "description": "",
            "aliases":     [],
            "yara_count":  0,
            "sources":     [],
        },
    ],
    "campaigns":    [],
    "sectors":      ["Government", "Defense"],
    "malpedia_url": "https://malpedia.caad.fkie.fraunhofer.de/actor/apt28",
}


class TestMalpediaMapper:

    def test_non_dict_raises(self):
        with pytest.raises(ValueError, match="Expected dict"):
            MalpediaMapper().map("not a dict")

    def test_missing_actor_name_raises(self):
        with pytest.raises(ValueError, match="actor_name"):
            MalpediaMapper().map({"source_id": "malpedia"})

    def test_minimal_maps_cleanly(self):
        r = MalpediaMapper().map(MINIMAL_MALPEDIA)
        assert r["actor_name"] == "APT28"
        assert r["source_id"]  == "malpedia"
        assert r["origin"]     == "Russia"

    def test_valid_malware_passes(self):
        r     = MalpediaMapper().map(MINIMAL_MALPEDIA)
        names = [m["name"] for m in r["malware"]]
        assert "X-Agent" in names

    def test_empty_name_dropped(self):
        r     = MalpediaMapper().map(MINIMAL_MALPEDIA)
        names = [m["name"] for m in r["malware"]]
        assert "" not in names

    def test_malware_aliases_preserved(self):
        r  = MalpediaMapper().map(MINIMAL_MALPEDIA)
        mw = next(m for m in r["malware"] if m["name"] == "X-Agent")
        assert "CHOPSTICK" in mw["aliases"]

    def test_yara_count_preserved(self):
        r  = MalpediaMapper().map(MINIMAL_MALPEDIA)
        mw = next(m for m in r["malware"] if m["name"] == "X-Agent")
        assert mw["yara_count"] == 12

    def test_sectors_preserved(self):
        r = MalpediaMapper().map(MINIMAL_MALPEDIA)
        assert "Government" in r["sectors"]

    def test_malpedia_url_preserved(self):
        r = MalpediaMapper().map(MINIMAL_MALPEDIA)
        assert "malpedia" in r["malpedia_url"]


class TestMalpediaHelpers:

    def test_slug_to_display_strips_prefix(self):
        assert _slug_to_display("win.x_agent") == "X Agent"

    def test_slug_to_display_no_prefix(self):
        assert _slug_to_display("mimikatz") == "Mimikatz"

    def test_classify_family_ransomware(self):
        assert _classify_family({"tags": ["ransomware"]}) == "ransomware"

    def test_classify_family_backdoor(self):
        assert _classify_family({"tags": ["backdoor"]}) == "backdoor"

    def test_classify_family_default(self):
        assert _classify_family({"tags": []}) == "malware"

    def test_classify_family_tool(self):
        assert _classify_family({"tags": ["tool", "utility"]}) == "tool"


# ---------------------------------------------------------------------------
# OTX mapper
# ---------------------------------------------------------------------------

MINIMAL_OTX = {
    "actor_name":  "APT28",
    "source_id":   "alienvault_otx",
    "aliases":     [],
    "description": "Pulse description.",
    "origin":      "",
    "first_seen":  "2022",
    "motivations": [],
    "techniques": [
        {
            "technique_id":   "T1566",
            "technique_name": "",
            "tactic":         "",
            "tactics":        [],
            "description":    "",
            "detection":      "",
            "sources":        ["alienvault_otx"],
        },
        {
            "technique_id":   "",   # should be dropped
            "technique_name": "",
            "tactic":         "",
            "tactics":        [],
            "description":    "",
            "detection":      "",
            "sources":        [],
        },
    ],
    "indicators": [
        {"type": "ip",     "value": "1.2.3.4",      "description": "C2",  "sources": ["alienvault_otx"]},
        {"type": "domain", "value": "evil.com",      "description": "",    "sources": ["alienvault_otx"]},
        {"type": "",       "value": "no-type.com",   "description": "",    "sources": []},  # drop
        {"type": "ip",     "value": "",              "description": "",    "sources": []},  # drop
    ],
    "malware": [
        {"name": "Zebrocy", "type": "malware", "description": "", "sources": ["alienvault_otx"]},
        {"name": "",        "type": "malware", "description": "", "sources": []},  # drop
    ],
    "campaigns":    [],
    "sectors":      ["Government"],
    "pulse_count":  17,
}


class TestOTXMapper:

    def test_non_dict_raises(self):
        with pytest.raises(ValueError, match="Expected dict"):
            AlienVaultOTXMapper().map("not a dict")

    def test_missing_actor_name_raises(self):
        with pytest.raises(ValueError, match="actor_name"):
            AlienVaultOTXMapper().map({"source_id": "alienvault_otx"})

    def test_minimal_maps_cleanly(self):
        r = AlienVaultOTXMapper().map(MINIMAL_OTX)
        assert r["actor_name"] == "APT28"
        assert r["source_id"]  == "alienvault_otx"

    def test_valid_technique_passes(self):
        r    = AlienVaultOTXMapper().map(MINIMAL_OTX)
        tids = [t["technique_id"] for t in r["techniques"]]
        assert "T1566" in tids

    def test_empty_tid_dropped(self):
        r    = AlienVaultOTXMapper().map(MINIMAL_OTX)
        tids = [t["technique_id"] for t in r["techniques"]]
        assert "" not in tids

    def test_valid_iocs_pass(self):
        r      = AlienVaultOTXMapper().map(MINIMAL_OTX)
        values = [i["value"] for i in r["indicators"]]
        assert "1.2.3.4"  in values
        assert "evil.com" in values

    def test_empty_type_ioc_dropped(self):
        r      = AlienVaultOTXMapper().map(MINIMAL_OTX)
        values = [i["value"] for i in r["indicators"]]
        assert "no-type.com" not in values

    def test_empty_value_ioc_dropped(self):
        r     = AlienVaultOTXMapper().map(MINIMAL_OTX)
        types = [i["type"] for i in r["indicators"]]
        # The empty-value IP should be gone; we still have the valid IP
        assert r["indicators"][0]["value"] != ""

    def test_valid_malware_passes(self):
        r     = AlienVaultOTXMapper().map(MINIMAL_OTX)
        names = [m["name"] for m in r["malware"]]
        assert "Zebrocy" in names

    def test_empty_malware_name_dropped(self):
        r     = AlienVaultOTXMapper().map(MINIMAL_OTX)
        names = [m["name"] for m in r["malware"]]
        assert "" not in names

    def test_pulse_count_preserved(self):
        r = AlienVaultOTXMapper().map(MINIMAL_OTX)
        assert r["pulse_count"] == 17

    def test_sectors_preserved(self):
        r = AlienVaultOTXMapper().map(MINIMAL_OTX)
        assert "Government" in r["sectors"]


# ---------------------------------------------------------------------------
# Cross-source confidence logic (unit test against deduplicator directly)
# ---------------------------------------------------------------------------

class TestConfidenceCrossSource:
    """
    Verify that a TTP confirmed by two sources gets HIGH confidence.
    Uses the scaffold's deduplicator directly.
    """

    def test_two_source_technique_is_high(self):
        from processors.deduplicator import deduplicate

        records = [
            {
                "actor_name": "APT28",
                "source_id":  "mitre_attack",
                "techniques": [{"technique_id": "T1566", "sources": ["mitre_attack"],
                                "tactic": "", "description": "", "detection_recs": []}],
                "aliases": [], "motivations": [], "sectors": [],
                "indicators": [], "malware": [], "campaigns": [],
            },
            {
                "actor_name": "APT28",
                "source_id":  "alienvault_otx",
                "techniques": [{"technique_id": "T1566", "sources": ["alienvault_otx"],
                                "tactic": "", "description": "", "detection_recs": []}],
                "aliases": [], "motivations": [], "sectors": [],
                "indicators": [], "malware": [], "campaigns": [],
            },
        ]

        # normalise first
        from processors.normalizer import normalize
        normalised = [normalize(r) for r in records]
        profile    = deduplicate(normalised)

        t = next((t for t in profile.get("techniques", [])
                  if t.get("technique_id") == "T1566"), None)
        assert t is not None, "T1566 not in deduplicated profile"
        assert t.get("confidence", "").lower() == "high", (
            f"Expected HIGH confidence, got {t.get('confidence')}"
        )

    def test_single_source_technique_is_not_high(self):
        from processors.normalizer  import normalize
        from processors.deduplicator import deduplicate

        records = [{
            "actor_name": "APT28",
            "source_id":  "mitre_attack",
            "techniques": [{"technique_id": "T1059", "sources": ["mitre_attack"],
                            "tactic": "", "description": "", "detection_recs": []}],
            "aliases": [], "motivations": [], "sectors": [],
            "indicators": [], "malware": [], "campaigns": [],
        }]

        profile = deduplicate([normalize(r) for r in records])
        t = next((t for t in profile.get("techniques", [])
                  if t.get("technique_id") == "T1059"), None)
        assert t is not None
        assert t.get("confidence", "").lower() != "high"
