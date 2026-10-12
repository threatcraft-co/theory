"""
tests/test_attribution.py
-------------------------
Attribution levels, and the shared-tooling exclusion they exist for.

Every indicator THEORY reported used to look the same regardless of how it
was obtained. An IP named by CISA in an advisory about APT28 and an IP
ThreatFox returned because APT28 is one of hundreds of groups using Cobalt
Strike both arrived as "APT28 indicators" — in the dossier, in the STIX
bundle as `indicator --indicates--> intrusion-set`, in the SIEM CSV, and as
an actor edge in the persistent graph.
"""

from __future__ import annotations

import pytest

from theory.attribution import (
    ACTOR,
    FAMILY,
    SHARED_TOOL,
    WEIGHTS,
    attribution_of,
    is_shared_tooling,
    shared_tooling_names,
    split_families,
    tag_indicators,
    weight_of,
)


class TestSharedToolingList:

    def test_list_loads(self):
        assert len(shared_tooling_names()) > 40

    @pytest.mark.parametrize("tool", [
        "Cobalt Strike", "cobalt strike", "COBALT STRIKE",
        "Mimikatz", "PsExec", "Impacket", "AdFind", "Rclone",
        "BloodHound", "ngrok", "AnyDesk", "Metasploit",
    ])
    def test_known_shared_tools_recognised(self, tool):
        assert is_shared_tooling(tool)

    @pytest.mark.parametrize("family", [
        "X-Agent", "FALLCHILL", "Zebrocy", "PlugX", "WannaCry", "Emotet",
    ])
    def test_actor_specific_malware_not_flagged(self, family):
        assert not is_shared_tooling(family)

    def test_empty_is_not_shared(self):
        assert not is_shared_tooling("")


class TestSplitFamilies:

    def test_tools_separated_from_malware(self):
        malware = [
            {"name": "X-Agent", "type": "malware"},
            {"name": "Cobalt Strike", "type": "tool"},
            {"name": "Mimikatz", "type": "tool"},
            {"name": "FALLCHILL", "type": "malware"},
        ]
        attributable, shared = split_families(malware)
        assert attributable == ["X-Agent", "FALLCHILL"]
        assert set(shared) == {"Cobalt Strike", "Mimikatz"}

    def test_mitre_tool_type_is_enough_on_its_own(self):
        """MITRE labels shared utilities 'tool'. That label alone means more
        than one group picked it up, even for something not on the list."""
        attributable, shared = split_families(
            [{"name": "SomeObscureUtility", "type": "tool"}]
        )
        assert attributable == []
        assert shared == ["SomeObscureUtility"]

    def test_include_shared_returns_everything(self):
        malware = [
            {"name": "X-Agent", "type": "malware"},
            {"name": "Cobalt Strike", "type": "tool"},
        ]
        attributable, shared = split_families(malware, include_shared=True)
        assert set(attributable) == {"X-Agent", "Cobalt Strike"}
        assert shared == []

    def test_accepts_bare_names(self):
        attributable, shared = split_families(["X-Agent", "Mimikatz"])
        assert attributable == ["X-Agent"]
        assert shared == ["Mimikatz"]


class TestAttributionOf:

    def test_explicit_level_wins(self):
        assert attribution_of({"attribution": "actor"}) == ACTOR
        assert attribution_of({"attribution": "family"}) == FAMILY
        assert attribution_of({"attribution": "shared_tool"}) == SHARED_TOOL

    def test_family_inferred_from_malware_family(self):
        assert attribution_of({"malware_family": "X-Agent"}) == FAMILY

    def test_shared_tool_inferred_for_commodity_family(self):
        assert attribution_of({"malware_family": "Cobalt Strike"}) == SHARED_TOOL

    def test_plain_indicator_defaults_to_actor(self):
        """Profiles saved before attribution existed stay readable."""
        assert attribution_of({"type": "ip", "value": "1.2.3.4"}) == ACTOR

    def test_weights_are_ordered(self):
        assert WEIGHTS[ACTOR] > WEIGHTS[FAMILY] > WEIGHTS[SHARED_TOOL]
        assert weight_of({"malware_family": "Cobalt Strike"}) == WEIGHTS[SHARED_TOOL]


class TestTagIndicators:

    def test_tags_requested_level(self):
        tagged = tag_indicators([{"value": "1.2.3.4"}], FAMILY, family="X-Agent")
        assert tagged[0]["attribution"] == FAMILY
        assert tagged[0]["malware_family"] == "X-Agent"

    def test_shared_tooling_cannot_be_promoted(self):
        """A caller asking for FAMILY on Cobalt Strike data still gets
        shared_tool — the point is that this cannot be bypassed by accident."""
        tagged = tag_indicators([{"value": "1.2.3.4"}], FAMILY, family="Cobalt Strike")
        assert tagged[0]["attribution"] == SHARED_TOOL

    def test_does_not_mutate_input(self):
        original = {"value": "1.2.3.4"}
        tag_indicators([original], FAMILY, family="X-Agent")
        assert "attribution" not in original

    def test_rejects_unknown_level(self):
        with pytest.raises(ValueError):
            tag_indicators([{"value": "1.2.3.4"}], "totally-made-up")


class TestReportersHonourAttribution:

    def test_stix_points_family_evidence_at_malware_not_actor(self):
        """The export that matters most: a family-level IOC must not be
        asserted to MISP/OpenCTI as an indicator OF THE ACTOR."""
        from reporters.stix_reporter import StixReporter

        profile = {
            "actor_name": "APT28", "techniques": [], "campaigns": [], "cves": [],
            "malware": [{"name": "X-Agent", "type": "malware"}],
            "indicators": [
                {"type": "ip", "value": "203.0.113.5", "attribution": "actor",
                 "sources": ["cisa"], "confidence": "HIGH"},
                {"type": "ip", "value": "198.51.100.9", "attribution": "family",
                 "malware_family": "X-Agent", "sources": ["threatfox"], "confidence": 90},
            ],
        }
        bundle = StixReporter().build_bundle(profile)
        objs = {o["id"]: o for o in bundle["objects"]}
        actor_id = next(o["id"] for o in bundle["objects"] if o["type"] == "intrusion-set")
        malware_id = next(o["id"] for o in bundle["objects"] if o["type"] == "malware")

        targets = {}
        for rel in (o for o in bundle["objects"] if o["type"] == "relationship"):
            src = objs.get(rel["source_ref"])
            if src and src.get("type") == "indicator":
                targets.setdefault(src["pattern"], set()).add(rel["target_ref"])

        actor_ioc = "[ipv4-addr:value = '203.0.113.5']"
        family_ioc = "[ipv4-addr:value = '198.51.100.9']"
        assert actor_id in targets[actor_ioc]
        assert actor_id not in targets[family_ioc], (
            "family-level IOC is still asserted as an indicator of the actor"
        )
        assert malware_id in targets[family_ioc]

    def test_csv_exposes_attribution_for_filtering(self):
        from reporters.csv_reporter import CsvReporter

        profile = {"actor_name": "APT28", "indicators": [
            {"type": "ip", "value": "203.0.113.5", "attribution": "actor", "sources": ["cisa"]},
            {"type": "ip", "value": "192.0.2.77", "attribution": "shared_tool",
             "malware_family": "Cobalt Strike", "sources": ["threatfox"]},
        ]}
        csv_text = CsvReporter().to_string(profile)
        assert "attribution" in csv_text.splitlines()[0]
        assert "shared_tool" in csv_text
        assert "actor" in csv_text
