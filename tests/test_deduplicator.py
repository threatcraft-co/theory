"""tests/test_deduplicator.py — Full coverage for processors/deduplicator.py"""
import pytest
from processors.deduplicator import deduplicate


def make_result(source_id, **kwargs):
    base = {
        "actor_name": "APT28", "source_id": source_id,
        "source_citation": source_id.upper(),
        "source_url": f"https://example.com/{source_id}",
        "retrieved_at": "2024-01-01T00:00:00+00:00",
        "aliases": [], "motivation": [], "target_sectors": [],
        "target_countries": [], "techniques": [], "malware": [],
        "indicators": [], "campaigns": [],
        "suspected_origin": None, "first_seen": None, "sponsorship": None,
    }
    base.update(kwargs)
    return base

def make_technique(tid, name="", tactic="", description="", source="mitre_attack"):
    return {"technique_id": tid, "name": name or tid, "tactic": tactic,
            "description": description, "source": source, "detection_recs": []}

def make_indicator(itype, value, context="", first_seen=""):
    return {"type": itype, "value": value, "context": context,
            "first_seen": first_seen, "sources": []}


class TestBasicDeduplicate:
    def test_empty_returns_profile(self):
        assert deduplicate([])["actor_name"] == "unknown"
    def test_single_result_passes(self):
        r = deduplicate([make_result("mitre_attack", aliases=["Fancy Bear"])])
        assert "Fancy Bear" in r["aliases"]
    def test_actor_name_from_first_non_empty(self):
        r = deduplicate([make_result("src_a", **{"actor_name": ""}), make_result("src_b")])
        assert r["actor_name"] == "APT28"


class TestTechniqueDeduplicate:
    def test_same_technique_two_sources_merged(self):
        r1 = make_result("mitre_attack", techniques=[make_technique("T1566")])
        r2 = make_result("alienvault_otx", techniques=[make_technique("T1566")])
        result = deduplicate([r1, r2])
        assert len(result["techniques"]) == 1
        assert "mitre_attack" in result["techniques"][0]["_sources"]
        assert "alienvault_otx" in result["techniques"][0]["_sources"]
    def test_different_techniques_both_kept(self):
        r1 = make_result("mitre_attack", techniques=[make_technique("T1566")])
        r2 = make_result("cisa_advisories", techniques=[make_technique("T1078")])
        ids = [t["technique_id"] for t in deduplicate([r1, r2])["techniques"]]
        assert "T1566" in ids and "T1078" in ids
    def test_description_merged(self):
        r1 = make_result("mitre_attack", techniques=[make_technique("T1566", description="")])
        r2 = make_result("cisa_advisories", techniques=[make_technique("T1566", description="Phishing details")])
        assert deduplicate([r1, r2])["techniques"][0]["description"] == "Phishing details"
    def test_detection_recs_merged_without_dupes(self):
        t1 = make_technique("T1566"); t1["detection_recs"] = ["Alert on email attachments"]
        t2 = make_technique("T1566"); t2["detection_recs"] = ["Alert on email attachments", "Monitor DNS"]
        r1 = make_result("mitre_attack", techniques=[t1])
        r2 = make_result("cisa_advisories", techniques=[t2])
        recs = deduplicate([r1, r2])["techniques"][0]["detection_recs"]
        assert recs.count("Alert on email attachments") == 1
        assert "Monitor DNS" in recs


class TestConfidenceWeighting:
    def test_two_source_technique_is_high(self):
        r1 = make_result("mitre_attack", techniques=[make_technique("T1566")])
        r2 = make_result("alienvault_otx", techniques=[make_technique("T1566")])
        assert deduplicate([r1, r2])["techniques"][0]["confidence"] == "HIGH"
    def test_single_mitre_technique_is_medium(self):
        assert deduplicate([make_result("mitre_attack", techniques=[make_technique("T1566")])])["techniques"][0]["confidence"] == "MEDIUM"
    def test_single_community_technique_is_low(self):
        assert deduplicate([make_result("alienvault_otx", techniques=[make_technique("T1566")])])["techniques"][0]["confidence"] == "LOW"
    def test_two_source_indicator_is_high(self):
        r1 = make_result("mitre_attack", indicators=[make_indicator("domain", "evil.com")])
        r2 = make_result("cisa_advisories", indicators=[make_indicator("domain", "evil.com")])
        assert deduplicate([r1, r2])["indicators"][0]["confidence"] == "HIGH"
    def test_single_cisa_indicator_is_medium(self):
        assert deduplicate([make_result("cisa_advisories", indicators=[make_indicator("domain", "evil.com")])])["indicators"][0]["confidence"] == "MEDIUM"


class TestIndicatorDeduplicate:
    def test_same_indicator_two_sources_merged(self):
        r1 = make_result("mitre_attack", indicators=[make_indicator("domain", "evil.com")])
        r2 = make_result("alienvault_otx", indicators=[make_indicator("domain", "evil.com")])
        result = deduplicate([r1, r2])
        assert len(result["indicators"]) == 1
        assert "mitre_attack" in result["indicators"][0]["sources"]
    def test_same_value_different_type_kept_separately(self):
        r1 = make_result("src_a", indicators=[make_indicator("domain", "evil.com")])
        r2 = make_result("src_b", indicators=[make_indicator("url", "evil.com")])
        assert len(deduplicate([r1, r2])["indicators"]) == 2
    def test_case_insensitive_dedup(self):
        r1 = make_result("src_a", indicators=[make_indicator("domain", "Evil.com")])
        r2 = make_result("src_b", indicators=[make_indicator("domain", "evil.com")])
        assert len(deduplicate([r1, r2])["indicators"]) == 1


class TestMalwareDeduplicate:
    def test_same_malware_deduped(self):
        m = {"name": "BlackCat", "type": "ransomware", "description": ""}
        assert len(deduplicate([make_result("mitre_attack", malware=[m]), make_result("malpedia", malware=[m])])["malware"]) == 1
    def test_case_insensitive_dedup(self):
        r1 = make_result("src_a", malware=[{"name": "BlackCat", "type": "ransomware", "description": ""}])
        r2 = make_result("src_b", malware=[{"name": "blackcat", "type": "ransomware", "description": "ALPHV"}])
        assert len(deduplicate([r1, r2])["malware"]) == 1
    def test_description_filled_from_second(self):
        r1 = make_result("src_a", malware=[{"name": "BlackCat", "type": "ransomware", "description": ""}])
        r2 = make_result("src_b", malware=[{"name": "BlackCat", "type": "ransomware", "description": "ALPHV family."}])
        assert deduplicate([r1, r2])["malware"][0]["description"] == "ALPHV family."


class TestCampaignsNotDeduped:
    def test_all_campaigns_included(self):
        c1 = {"name": "Op Alpha", "date": "2023", "description": "A", "reference": "https://a.com"}
        c2 = {"name": "Op Beta", "date": "2024", "description": "B", "reference": "https://b.com"}
        r1 = make_result("cisa_advisories", campaigns=[c1])
        r2 = make_result("mitre_attack", campaigns=[c2])
        assert len(deduplicate([r1, r2])["campaigns"]) == 2


class TestScalarMerge:
    def test_first_non_empty_origin_wins(self):
        r = deduplicate([make_result("a", suspected_origin=None), make_result("b", suspected_origin="Russia"), make_result("c", suspected_origin="China")])
        assert r["suspected_origin"] == "Russia"
    def test_first_seen_first_non_empty_wins(self):
        r = deduplicate([make_result("a", first_seen=None), make_result("b", first_seen="2015")])
        assert r["first_seen"] == "2015"


class TestAliasDeduplicate:
    def test_same_alias_deduped(self):
        r1 = make_result("mitre_attack", aliases=["Fancy Bear"])
        r2 = make_result("alienvault_otx", aliases=["Fancy Bear", "Sofacy"])
        r = deduplicate([r1, r2])
        assert r["aliases"].count("Fancy Bear") == 1
        assert "Sofacy" in r["aliases"]


class TestSourceCitations:
    def test_all_sources_recorded(self):
        r = deduplicate([make_result("mitre_attack"), make_result("cisa_advisories")])
        ids = [s["source_id"] for s in r["_sources"]]
        assert "mitre_attack" in ids and "cisa_advisories" in ids
