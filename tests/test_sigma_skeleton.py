"""
tests/test_sigma_skeleton.py
-------------------------------
Unit tests for processors/sigma_skeleton.py — draft Sigma rule
generation for detection-coverage gaps. Fully offline, pure string/dict
work, no network and no real Sigma repo involved.
"""

from __future__ import annotations

import yaml

from processors.sigma_skeleton import generate_skeleton, generate_skeletons_for_gaps


GAP_TECHNIQUE = {
    "technique_id":   "t1566",
    "technique_name": "Phishing",
    "tactic":         "Initial Access",
    "confidence":     "HIGH",
}


class TestGenerateSkeleton:

    def test_technique_id_lowercased_in_tag(self):
        skeleton = generate_skeleton(GAP_TECHNIQUE, "APT28", rule_id="fixed-id", today="2026-01-01")
        parsed = yaml.safe_load(skeleton)
        assert "attack.t1566" in parsed["tags"]

    def test_technique_id_used_as_title_when_no_name_given(self):
        skeleton = generate_skeleton({"technique_id": "T1566", "confidence": "HIGH"}, "APT28")
        assert "T1566" in yaml.safe_load(skeleton)["title"]

    def test_is_valid_yaml(self):
        skeleton = generate_skeleton(GAP_TECHNIQUE, "APT28", rule_id="fixed-id", today="2026-01-01")
        parsed = yaml.safe_load(skeleton)
        assert parsed["id"] == "fixed-id"
        assert str(parsed["date"]) == "2026-01-01"
        assert parsed["status"] == "experimental"

    def test_level_follows_confidence_high(self):
        skeleton = generate_skeleton({**GAP_TECHNIQUE, "confidence": "HIGH"}, "APT28")
        assert yaml.safe_load(skeleton)["level"] == "high"

    def test_level_follows_confidence_low(self):
        skeleton = generate_skeleton({**GAP_TECHNIQUE, "confidence": "LOW"}, "APT28")
        assert yaml.safe_load(skeleton)["level"] == "low"

    def test_missing_confidence_defaults_low(self):
        # Matches the rest of the codebase's convention (e.g.
        # processors/correlator.py): an absent confidence defaults to
        # LOW, not MEDIUM — THEORY never assumes a higher confidence
        # than it's told.
        skeleton = generate_skeleton({**GAP_TECHNIQUE, "confidence": ""}, "APT28")
        assert yaml.safe_load(skeleton)["level"] == "low"

    def test_attack_technique_tag_present(self):
        skeleton = generate_skeleton(GAP_TECHNIQUE, "APT28")
        tags = yaml.safe_load(skeleton)["tags"]
        assert "attack.t1566" in tags

    def test_attack_tactic_tag_present_when_tactic_known(self):
        skeleton = generate_skeleton(GAP_TECHNIQUE, "APT28")
        tags = yaml.safe_load(skeleton)["tags"]
        assert "attack.initial_access" in tags

    def test_missing_tactic_omits_tactic_tag(self):
        skeleton = generate_skeleton({**GAP_TECHNIQUE, "tactic": ""}, "APT28")
        tags = yaml.safe_load(skeleton)["tags"]
        assert len(tags) == 1
        assert tags[0] == "attack.t1566"

    def test_actor_name_in_title(self):
        skeleton = generate_skeleton(GAP_TECHNIQUE, "Scattered Spider")
        assert "Scattered Spider" in yaml.safe_load(skeleton)["title"]

    def test_mitre_reference_url_uses_uppercase_tid(self):
        skeleton = generate_skeleton(GAP_TECHNIQUE, "APT28")
        refs = yaml.safe_load(skeleton)["references"]
        assert "https://attack.mitre.org/techniques/T1566/" in refs

    def test_todo_placeholders_present_and_not_fabricated(self):
        skeleton = generate_skeleton(GAP_TECHNIQUE, "APT28")
        parsed = yaml.safe_load(skeleton)
        assert parsed["logsource"]["category"].startswith("TODO")
        assert parsed["logsource"]["product"].startswith("TODO")
        assert "selection" in parsed["detection"]
        assert "TODO" in str(parsed["detection"]["selection"])

    def test_missing_technique_id_falls_back_to_unknown(self):
        skeleton = generate_skeleton({"technique_name": "Something"}, "APT28")
        assert "UNKNOWN" in skeleton


class TestGenerateSkeletonsForGaps:

    def _profile(self, gaps):
        return {
            "actor_name": "APT28",
            "correlations": {"coverage": {"gaps": gaps}},
        }

    def test_no_correlations_returns_empty(self):
        assert generate_skeletons_for_gaps({"actor_name": "APT28"}) == []

    def test_no_gaps_returns_empty(self):
        assert generate_skeletons_for_gaps(self._profile([])) == []

    def test_one_skeleton_per_gap(self):
        gaps = [
            {"technique_id": "T1566", "confidence": "HIGH"},
            {"technique_id": "T1078", "confidence": "MEDIUM"},
        ]
        results = generate_skeletons_for_gaps(self._profile(gaps))
        assert len(results) == 2
        assert {r["technique_id"] for r in results} == {"T1566", "T1078"}

    def test_gap_without_technique_id_skipped(self):
        gaps = [{"technique_id": "", "confidence": "HIGH"}, {"technique_id": "T1078", "confidence": "LOW"}]
        results = generate_skeletons_for_gaps(self._profile(gaps))
        assert len(results) == 1
        assert results[0]["technique_id"] == "T1078"

    def test_each_result_has_valid_yaml_skeleton(self):
        gaps = [{"technique_id": "T1566", "technique_name": "Phishing", "confidence": "HIGH"}]
        results = generate_skeletons_for_gaps(self._profile(gaps))
        parsed = yaml.safe_load(results[0]["skeleton"])
        assert parsed["id"]  # a real UUID was generated
        assert "APT28" in parsed["title"]
