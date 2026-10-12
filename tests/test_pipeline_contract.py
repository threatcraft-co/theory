"""
tests/test_pipeline_contract.py
-------------------------------
The contract between collect -> normalize -> deduplicate -> report.

Each stage used to disagree with its neighbours about field names, and the
pipeline papered over it by reaching back into the raw collector records
and overwriting what the earlier stages had produced. Two things got lost
in that shuffle, silently and in every single run:

  * the actor description, which never reached any reporter
  * indicator provenance — collector IOCs arrived at the deduplicator with
    no sources list, so corroboration between two sources was invisible
    and confidence was never assigned to them at all

These tests assert the contract directly, with stub collectors, so no
network and no API keys are involved.
"""

from __future__ import annotations

import pytest

import theory._cli as cli


MITRE_RECORD = {
    "actor_name": "APT28",
    "source_id": "mitre_attack",
    "description": "Russian military intelligence (GRU) unit 26165.",
    "origin": "Russia",
    "motivations": ["espionage"],
    "sectors": ["Government"],
    "techniques": [{
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "initial-access",
        "detection": "Alert on suspicious attachment types.",
        "sources": ["mitre_attack"],
    }],
    "malware": [{"name": "X-Agent", "type": "malware"}],
    "indicators": [],
    "cves": [{"cve_id": "CVE-2023-23397"}],
    "mitre_id": "G0007",
}

OTX_RECORD = {
    "actor_name": "APT28",
    "source_id": "alienvault_otx",
    "description": "",
    "techniques": [{"technique_id": "T1566", "sources": ["alienvault_otx"]}],
    "indicators": [{"type": "ip", "value": "203.0.113.5", "sources": ["alienvault_otx"]}],
    "malware": [],
}

PERSONAL_RECORD = {
    "actor_name": "APT28",
    "source_id": "personal",
    # Same indicator as OTX — this is the corroboration signal.
    "indicators": [{"type": "ip", "value": "203.0.113.5", "sources": ["personal"]}],
    "techniques": [],
    "malware": [],
}


@pytest.fixture
def stub_pipeline(monkeypatch, repo_config):
    """Run the real pipeline over fixed records, with no network or LLM."""
    records = {
        "mitre": MITRE_RECORD,
        "otx": OTX_RECORD,
        "personal": PERSONAL_RECORD,
    }
    monkeypatch.setattr(cli, "_collect_and_map", lambda actor, key: records.get(key))

    import collectors.intelligence_synthesizer as synth
    monkeypatch.setattr(synth, "load_provider", lambda: None)

    def run(sources=("mitre", "otx", "personal")):
        return cli.run(
            actor="APT28", sources=list(sources),
            output="json", save=False, quiet=True, no_graph=True,
        )
    return run


class TestNoFieldLoss:

    def test_description_survives(self, stub_pipeline):
        """The actor description reached no reporter before this fix — the
        normalizer never carried it and the merge never restored it."""
        profile = stub_pipeline()
        assert profile["description"] == MITRE_RECORD["description"]

    def test_origin_and_motivations_survive(self, stub_pipeline):
        profile = stub_pipeline()
        assert profile["origin"] == "Russia"
        assert profile["motivations"] == ["espionage"]

    def test_sectors_survive(self, stub_pipeline):
        profile = stub_pipeline()
        assert "Government" in profile["sectors"]

    def test_technique_name_and_detection_survive(self, stub_pipeline):
        profile = stub_pipeline()
        tech = {t["technique_id"]: t for t in profile["techniques"]}["T1566"]
        assert tech["technique_name"] == "Phishing"
        assert tech["tactic"] == "initial-access"
        assert "suspicious attachment" in tech["detection"]

    def test_cves_survive(self, stub_pipeline):
        profile = stub_pipeline()
        assert [c["cve_id"] for c in profile["cves"]] == ["CVE-2023-23397"]

    def test_mitre_group_id_survives(self, stub_pipeline):
        profile = stub_pipeline()
        assert profile.get("mitre_group_id") == "G0007"


class TestProvenanceAndConfidence:

    def test_indicator_keeps_every_reporting_source(self, stub_pipeline):
        """OTX and the analyst's personal notes both reported this IP. The
        merged indicator must remember both, or corroboration is invisible."""
        profile = stub_pipeline()
        ioc = {i["value"]: i for i in profile["indicators"]}["203.0.113.5"]
        assert set(ioc["sources"]) == {"alienvault_otx", "personal"}

    def test_corroborated_indicator_is_high_confidence(self, stub_pipeline):
        """Two independent sources -> HIGH. Previously the indicator arrived
        with no sources at all, so it was never scored."""
        profile = stub_pipeline()
        ioc = {i["value"]: i for i in profile["indicators"]}["203.0.113.5"]
        assert ioc.get("confidence") is not None, "indicator was never scored"
        assert ioc["confidence"] == "HIGH"

    def test_corroborated_technique_is_high_confidence(self, stub_pipeline):
        profile = stub_pipeline()
        tech = {t["technique_id"]: t for t in profile["techniques"]}["T1566"]
        assert tech["confidence"] == "HIGH"


class TestDeterminism:

    def test_sources_cited_is_sorted(self, stub_pipeline):
        """Built from a set() before, so ordering changed between runs on
        identical input."""
        profile = stub_pipeline()
        assert profile["sources_cited"] == sorted(profile["sources_cited"])

    def test_identical_input_produces_identical_output(self, stub_pipeline):
        """Same input, same intelligence out. Wall-clock fields (retrieved_at,
        and the _sources provenance block that carries them) legitimately
        differ run to run and are excluded."""
        import json

        def stable(profile):
            clean = dict(cli._sanitize_profile(profile))
            clean.pop("_sources", None)
            clean.pop("retrieved_at", None)
            return json.dumps(clean, sort_keys=True, default=str)

        assert stable(stub_pipeline()) == stable(stub_pipeline())

    def test_scalar_fields_ignore_source_order(self, stub_pipeline):
        """--sources otx,mitre and --sources mitre,otx must agree on origin;
        resolution is by source authority, not argument order."""
        forward = stub_pipeline(("mitre", "otx", "personal"))
        reverse = stub_pipeline(("personal", "otx", "mitre"))
        assert forward["origin"] == reverse["origin"] == "Russia"
        assert forward["description"] == reverse["description"]
