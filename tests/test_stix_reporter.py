"""
tests/test_stix_reporter.py
----------------------------
Unit tests for reporters/stix_reporter.py — fully offline.
"""

from __future__ import annotations

import json
import pytest
from reporters.stix_reporter import (
    StixReporter,
    THEORY_IDENTITY_ID,
    SPEC_VERSION,
    _map_motivation,
    _map_malware_type,
    _map_indicator_type,
    _year_to_stix,
    _date_to_stix,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_PROFILE = {
    "actor_name":     "APT28",
    "mitre_group_id": "G0007",
    "origin":         "Russia",
    "first_seen":     "2004",
    "motivations":    ["espionage"],
    "aliases":        ["Fancy Bear", "Sofacy"],
    "description":    "GRU-linked threat actor.",
    "techniques":     [],
    "indicators":     [],
    "malware":        [],
    "campaigns":      [],
    "sources_cited":  ["mitre_attack", "malpedia"],
    "sigma_rule_count": 47,
    "threatfox_ioc_count": 6,
}

FULL_PROFILE = {
    **MINIMAL_PROFILE,
    "techniques": [
        {
            "technique_id":   "T1566.001",
            "technique_name": "Spearphishing Attachment",
            "tactic":         "Initial Access",
            "description":    "APT28 uses spearphishing.",
            "detection":      "Monitor email gateways.",
            "confidence":     "medium",
        },
        {
            "technique_id":   "T1059.001",
            "technique_name": "PowerShell",
            "tactic":         "Execution",
            "description":    "",
            "detection":      "",
            "confidence":     "high",
        },
        {
            "technique_id":   "",   # should be skipped
            "technique_name": "Bad",
            "tactic":         "",
            "description":    "",
            "detection":      "",
            "confidence":     "",
        },
    ],
    "malware": [
        {
            "name":        "CHOPSTICK",
            "type":        "backdoor",
            "description": "Modular backdoor.",
            "aliases":     ["X-Agent", "Sofacy"],
        },
        {
            "name":        "",   # should be skipped
            "type":        "malware",
            "description": "",
        },
    ],
    "indicators": [
        {
            "type":           "ip",
            "value":          "185.10.58.170",
            "confidence":     100,
            "threat_type":    "botnet_cc",
            "threat_label":   "Botnet C2",
            "first_seen":     "2024-01-15",
            "malware_family": "CHOPSTICK",
            "sources":        ["threatfox"],
            "description":    "Botnet C2 — CHOPSTICK",
        },
        {
            "type":           "domain",
            "value":          "ssl-icloud.com",
            "confidence":     0,
            "threat_type":    "",
            "threat_label":   "",
            "first_seen":     "",
            "malware_family": "",
            "sources":        ["alienvault_otx"],
            "description":    "",
        },
        {
            "type":           "hash_md5",
            "value":          "8c4fa713c5e2b009114adda758adc445",
            "confidence":     75,
            "threat_type":    "payload",
            "threat_label":   "Payload Delivery",
            "first_seen":     "2023-06-01",
            "malware_family": "",
            "sources":        ["threatfox"],
            "description":    "",
        },
        {
            "type":           "unknown_type",   # should be skipped
            "value":          "something",
            "confidence":     0,
            "sources":        [],
            "description":    "",
        },
        {
            "type":           "ip",
            "value":          "",              # empty value — should be skipped
            "confidence":     0,
            "sources":        [],
            "description":    "",
        },
    ],
    "campaigns": [
        {
            "name":        "Operation Pawn Storm",
            "description": "Long-running espionage.",
            "first_seen":  "2014",
            "last_seen":   "2023",
        },
    ],
}


# ---------------------------------------------------------------------------
# Bundle structure tests
# ---------------------------------------------------------------------------

class TestBundleStructure:

    def test_bundle_type(self):
        bundle = StixReporter().build_bundle(MINIMAL_PROFILE)
        assert bundle["type"] == "bundle"

    def test_spec_version(self):
        bundle = StixReporter().build_bundle(MINIMAL_PROFILE)
        assert bundle["spec_version"] == SPEC_VERSION

    def test_bundle_id_format(self):
        bundle = StixReporter().build_bundle(MINIMAL_PROFILE)
        assert bundle["id"].startswith("bundle--")

    def test_objects_is_list(self):
        bundle = StixReporter().build_bundle(MINIMAL_PROFILE)
        assert isinstance(bundle["objects"], list)

    def test_theory_identity_present(self):
        bundle  = StixReporter().build_bundle(MINIMAL_PROFILE)
        ids     = [o["id"] for o in bundle["objects"]]
        assert THEORY_IDENTITY_ID in ids

    def test_all_objects_have_type(self):
        bundle = StixReporter().build_bundle(FULL_PROFILE)
        for obj in bundle["objects"]:
            assert "type" in obj, f"Object missing type: {obj}"

    def test_all_objects_have_id(self):
        bundle = StixReporter().build_bundle(FULL_PROFILE)
        for obj in bundle["objects"]:
            assert "id" in obj

    def test_all_objects_have_spec_version(self):
        bundle = StixReporter().build_bundle(FULL_PROFILE)
        for obj in bundle["objects"]:
            assert obj.get("spec_version") == SPEC_VERSION

    def test_bundle_is_json_serialisable(self):
        bundle = StixReporter().build_bundle(FULL_PROFILE)
        dumped = json.dumps(bundle)
        loaded = json.loads(dumped)
        assert loaded["type"] == "bundle"


# ---------------------------------------------------------------------------
# Intrusion Set
# ---------------------------------------------------------------------------

class TestIntrusionSet:

    def _get_actor(self, profile=MINIMAL_PROFILE):
        bundle = StixReporter().build_bundle(profile)
        return next(o for o in bundle["objects"] if o["type"] == "intrusion-set")

    def test_intrusion_set_present(self):
        assert self._get_actor() is not None

    def test_actor_name(self):
        assert self._get_actor()["name"] == "APT28"

    def test_aliases_present(self):
        actor = self._get_actor()
        assert "Fancy Bear" in actor["aliases"]

    def test_mitre_external_ref(self):
        actor = self._get_actor()
        refs  = actor.get("external_references", [])
        assert any(r.get("external_id") == "G0007" for r in refs)

    def test_motivation_mapped(self):
        actor = self._get_actor()
        assert actor.get("primary_motivation") == "espionage"

    def test_first_seen_year_converted(self):
        actor = self._get_actor()
        assert actor.get("first_seen", "").startswith("2004")

    def test_origin_custom_field(self):
        actor = self._get_actor()
        assert actor.get("x_theory_origin") == "Russia"


# ---------------------------------------------------------------------------
# Attack Patterns
# ---------------------------------------------------------------------------

class TestAttackPatterns:

    def _get_techniques(self):
        bundle = StixReporter().build_bundle(FULL_PROFILE)
        return [o for o in bundle["objects"] if o["type"] == "attack-pattern"]

    def test_techniques_present(self):
        assert len(self._get_techniques()) == 2   # empty TID skipped

    def test_technique_name(self):
        techs = {t["name"] for t in self._get_techniques()}
        assert "Spearphishing Attachment" in techs

    def test_mitre_external_ref(self):
        techs = self._get_techniques()
        for t in techs:
            refs = t.get("external_references", [])
            assert any(r.get("source_name") == "mitre-attack" for r in refs)

    def test_technique_url_correct(self):
        bundle = StixReporter().build_bundle(FULL_PROFILE)
        techs  = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        t1566  = next(
            t for t in techs
            if any("T1566" in str(r) for r in t.get("external_references", []))
        )
        refs = t1566["external_references"]
        url  = next(r["url"] for r in refs if r.get("source_name") == "mitre-attack")
        assert "T1566/001" in url or "T1566.001" in url or "T1566" in url

    def test_kill_chain_phase(self):
        techs = self._get_techniques()
        t     = next(t for t in techs if "Spearphishing" in t["name"])
        phases = t.get("kill_chain_phases", [])
        assert any(p.get("kill_chain_name") == "mitre-attack" for p in phases)

    def test_empty_tid_skipped(self):
        # FULL_PROFILE has one technique with empty technique_id
        assert len(self._get_techniques()) == 2   # not 3

    def test_detection_custom_field(self):
        techs = self._get_techniques()
        t     = next(t for t in techs if "Spearphishing" in t["name"])
        assert t.get("x_mitre_detection") == "Monitor email gateways."


# ---------------------------------------------------------------------------
# Malware
# ---------------------------------------------------------------------------

class TestMalware:

    def _get_malware(self):
        bundle = StixReporter().build_bundle(FULL_PROFILE)
        return [o for o in bundle["objects"] if o["type"] == "malware"]

    def test_malware_present(self):
        assert len(self._get_malware()) == 1   # empty name skipped

    def test_malware_name(self):
        assert self._get_malware()[0]["name"] == "CHOPSTICK"

    def test_malware_type_mapped(self):
        mw = self._get_malware()[0]
        assert "backdoor" in mw.get("malware_types", [])

    def test_is_family_true(self):
        assert self._get_malware()[0]["is_family"] is True

    def test_aliases_present(self):
        mw = self._get_malware()[0]
        assert "X-Agent" in mw.get("aliases", [])


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------

class TestIndicators:

    def _get_indicators(self):
        bundle = StixReporter().build_bundle(FULL_PROFILE)
        return [o for o in bundle["objects"] if o["type"] == "indicator"]

    def test_indicators_present(self):
        # ip, domain, hash_md5 → 3 valid; unknown_type and empty value skipped
        assert len(self._get_indicators()) == 3

    def test_ip_pattern(self):
        inds = self._get_indicators()
        ip   = next(i for i in inds if "ipv4-addr" in i["pattern"])
        assert "185.10.58.170" in ip["pattern"]

    def test_domain_pattern(self):
        inds = self._get_indicators()
        dom  = next(i for i in inds if "domain-name" in i["pattern"])
        assert "ssl-icloud.com" in dom["pattern"]

    def test_md5_pattern(self):
        inds = self._get_indicators()
        h    = next(i for i in inds if "MD5" in i["pattern"])
        assert "8c4fa713" in h["pattern"]

    def test_confidence_preserved(self):
        inds = self._get_indicators()
        ip   = next(i for i in inds if "ipv4-addr" in i["pattern"])
        assert ip.get("confidence") == 100

    def test_malware_family_custom_field(self):
        inds = self._get_indicators()
        ip   = next(i for i in inds if "ipv4-addr" in i["pattern"])
        assert ip.get("x_theory_malware_family") == "CHOPSTICK"

    def test_sources_custom_field(self):
        inds = self._get_indicators()
        ip   = next(i for i in inds if "ipv4-addr" in i["pattern"])
        assert "threatfox" in ip.get("x_theory_sources", [])


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------

class TestRelationships:

    def _get_rels(self, rel_type=None):
        bundle = StixReporter().build_bundle(FULL_PROFILE)
        rels   = [o for o in bundle["objects"] if o["type"] == "relationship"]
        if rel_type:
            rels = [r for r in rels if r["relationship_type"] == rel_type]
        return rels

    def test_uses_relationships_present(self):
        assert len(self._get_rels("uses")) > 0

    def test_indicates_relationships_present(self):
        assert len(self._get_rels("indicates")) > 0

    def test_attributed_to_relationship_present(self):
        assert len(self._get_rels("attributed-to")) > 0

    def test_relationship_refs_valid_ids(self):
        bundle    = StixReporter().build_bundle(FULL_PROFILE)
        all_ids   = {o["id"] for o in bundle["objects"]}
        rels      = [o for o in bundle["objects"] if o["type"] == "relationship"]
        for rel in rels:
            assert rel["source_ref"] in all_ids, f"source_ref not in bundle: {rel['source_ref']}"
            assert rel["target_ref"] in all_ids, f"target_ref not in bundle: {rel['target_ref']}"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class TestReport:

    def _get_report(self):
        bundle = StixReporter().build_bundle(FULL_PROFILE)
        return next(o for o in bundle["objects"] if o["type"] == "report")

    def test_report_present(self):
        assert self._get_report() is not None

    def test_report_name(self):
        assert "APT28" in self._get_report()["name"]

    def test_report_type(self):
        assert "threat-actor" in self._get_report()["report_types"]

    def test_report_refs_non_empty(self):
        assert len(self._get_report()["object_refs"]) > 0

    def test_report_refs_include_identity(self):
        assert THEORY_IDENTITY_ID in self._get_report()["object_refs"]

    def test_sigma_count_in_report(self):
        assert self._get_report().get("x_theory_sigma_rule_count") == 47


# ---------------------------------------------------------------------------
# Save to disk
# ---------------------------------------------------------------------------

class TestSave:

    def test_file_written(self, tmp_path, monkeypatch):
        import reporters.stix_reporter as stix_module
        monkeypatch.setattr(stix_module, "OUTPUT_DIR", tmp_path)

        path = StixReporter().save(MINIMAL_PROFILE)
        assert path.exists()

        bundle = json.loads(path.read_text(encoding="utf-8"))
        assert bundle["type"] == "bundle"

    def test_filename_slugified(self, tmp_path, monkeypatch):
        import reporters.stix_reporter as stix_module
        monkeypatch.setattr(stix_module, "OUTPUT_DIR", tmp_path)

        profile = {**MINIMAL_PROFILE, "actor_name": "Fancy Bear"}
        path    = StixReporter().save(profile)
        assert path.name == "fancy_bear.stix.json"


# ---------------------------------------------------------------------------
# Vocabulary mappers
# ---------------------------------------------------------------------------

class TestVocabMappers:

    def test_espionage_motivation(self):
        assert _map_motivation("espionage") == "espionage"

    def test_financial_motivation(self):
        assert _map_motivation("financial crime") == "financial-gain"

    def test_unknown_motivation(self):
        assert _map_motivation("something weird") == "unknown"

    def test_backdoor_type(self):
        assert "backdoor" in _map_malware_type("backdoor")

    def test_ransomware_type(self):
        assert "ransomware" in _map_malware_type("ransomware")

    def test_unknown_type_defaults_to_malware(self):
        assert "malware" in _map_malware_type("unknown_weird_type")

    def test_year_to_stix(self):
        assert _year_to_stix("2004") == "2004-01-01T00:00:00.000Z"

    def test_date_to_stix_full(self):
        assert _date_to_stix("2024-01-15") == "2024-01-15T00:00:00.000Z"

    def test_date_to_stix_year_only(self):
        assert _date_to_stix("2014") == "2014-01-01T00:00:00.000Z"

    def test_ip_indicator_type(self):
        types = _map_indicator_type("ip", "")
        assert "malicious-activity" in types

    def test_botnet_c2_indicator_type(self):
        types = _map_indicator_type("ip", "Botnet C2")
        assert "compromised" in types or "malicious-activity" in types
