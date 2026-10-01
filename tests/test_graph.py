"""
tests/test_graph.py
--------------------
Unit tests for processors/graph.py — the persistent cross-run correlation
graph. Fully offline, uses tmp_path for the on-disk store so tests never
touch output/graph/graph.json.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from processors.graph import (
    GraphStore,
    canonical_id,
    find_connection,
    ingest_profile,
    query_actor,
    query_attack_type,
    query_cve,
    query_ioc,
    query_technique,
)


# ---------------------------------------------------------------------------
# canonical_id
# ---------------------------------------------------------------------------

class TestCanonicalId:

    def test_ioc_lowercased(self):
        assert canonical_id("ioc", "  1.1.1.1  ") == "1.1.1.1"
        assert canonical_id("ioc", "EXAMPLE.COM") == "example.com"

    def test_technique_uppercased(self):
        assert canonical_id("technique", "t1566") == "T1566"

    def test_cve_uppercased(self):
        assert canonical_id("cve", "cve-2023-23397") == "CVE-2023-23397"

    def test_actor_resolves_alias(self):
        assert canonical_id("actor", "Fancy Bear") == "APT28"

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError, match="Unknown graph node type"):
            canonical_id("spaceship", "x")


# ---------------------------------------------------------------------------
# GraphStore persistence + upsert
# ---------------------------------------------------------------------------

class TestGraphStorePersistence:

    def test_save_and_load_round_trip(self, tmp_path):
        path  = tmp_path / "graph.json"
        store = GraphStore(path=path)
        actor_key = store.upsert_node("actor", "APT28", label="APT28", source="mitre")
        ioc_key   = store.upsert_node("ioc", "1.1.1.1", label="1.1.1.1")
        store.upsert_edge(actor_key, ioc_key, "reported_ioc", source="otx")
        store.save()

        loaded = GraphStore.load(path)
        assert "actor:APT28" in loaded.nodes
        assert "ioc:1.1.1.1" in loaded.nodes
        assert loaded.neighbors("actor:APT28")["ioc:1.1.1.1"]["relation"] == "reported_ioc"

    def test_load_missing_file_returns_empty_store(self, tmp_path):
        store = GraphStore.load(tmp_path / "does_not_exist.json")
        assert store.nodes == {}
        assert store.edges == {}

    def test_load_corrupt_file_returns_empty_store(self, tmp_path):
        path = tmp_path / "graph.json"
        path.write_text("{not valid json")
        store = GraphStore.load(path)
        assert store.nodes == {}


class TestUpsertNode:

    def test_repeated_upsert_unions_sources(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        store.upsert_node("ioc", "1.1.1.1", source="otx")
        store.upsert_node("ioc", "1.1.1.1", source="threatfox")
        store.upsert_node("ioc", "1.1.1.1", source="otx")  # duplicate, should not double up
        node = store.get_node("ioc", "1.1.1.1")
        assert sorted(node["sources"]) == ["otx", "threatfox"]

    def test_meta_merges_not_overwrites(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        store.upsert_node("ioc", "1.1.1.1", meta={"ioc_type": "ip"})
        store.upsert_node("ioc", "1.1.1.1", meta={"extra": "x"})
        node = store.get_node("ioc", "1.1.1.1")
        assert node["meta"]["ioc_type"] == "ip"
        assert node["meta"]["extra"] == "x"


class TestUpsertEdge:

    def test_edge_is_bidirectional(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        a = store.upsert_node("actor", "APT28")
        b = store.upsert_node("ioc", "1.1.1.1")
        store.upsert_edge(a, b, "reported_ioc", source="otx")
        assert b in store.neighbors(a)
        assert a in store.neighbors(b)

    def test_self_loop_ignored(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        a = store.upsert_node("actor", "APT28")
        store.upsert_edge(a, a, "reported_ioc")
        assert store.neighbors(a) == {}


# ---------------------------------------------------------------------------
# ingest_profile
# ---------------------------------------------------------------------------

SAMPLE_PROFILE = {
    "actor_name": "APT28",
    "indicators": [
        {"type": "ip", "value": "1.1.1.1", "sources": ["otx"], "malware_family": "X-Agent"},
    ],
    "techniques": [
        {"technique_id": "T1566", "technique_name": "Phishing", "sources": ["mitre"]},
    ],
    "malware": [
        {"name": "X-Agent", "type": "backdoor"},
    ],
    "cves": [
        {"cve_id": "CVE-2023-23397", "sources": ["cisa"], "kev_confirmed": True},
    ],
    "campaigns": [
        {"name": "Operation Ghost"},
    ],
}


class TestIngestProfile:

    def test_ingest_creates_actor_node(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        assert store.get_node("actor", "APT28") is not None

    def test_ingest_links_ioc_to_actor(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = query_ioc("1.1.1.1", store=store)
        assert result["found"] is True
        assert any(a["label"] == "APT28" for a in result["linked_actors"])

    def test_ingest_links_ioc_to_malware_family(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = query_ioc("1.1.1.1", store=store)
        assert any(m["label"] == "X-Agent" for m in result["linked_malware"])

    def test_ingest_links_technique_to_actor(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = query_technique("T1566", store=store)
        assert result["found"] is True
        assert any(a["label"] == "APT28" for a in result["linked_actors"])

    def test_ingest_is_idempotent(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = query_ioc("1.1.1.1", store=store)
        # Re-ingesting the same profile must not duplicate the actor link
        assert len([a for a in result["linked_actors"] if a["label"] == "APT28"]) == 1

    def test_ingest_without_actor_name_is_noop(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile({"indicators": []}, store=store)
        assert store.nodes == {}

    def test_ingest_without_store_loads_and_saves(self, tmp_path, monkeypatch):
        import processors.graph as graph_module
        monkeypatch.setattr(graph_module, "GRAPH_PATH", tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE)
        assert (tmp_path / "graph.json").exists()


# ---------------------------------------------------------------------------
# query_ioc / query_technique — standalone lookups
# ---------------------------------------------------------------------------

class TestQueryIoc:

    def test_unknown_ioc_not_found(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        result = query_ioc("9.9.9.9", store=store)
        assert result["found"] is False
        assert result["value"] == "9.9.9.9"

    def test_known_ioc_reports_type_and_dates(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = query_ioc("1.1.1.1", store=store)
        assert result["ioc_type"] == "ip"
        assert result["first_seen"] and result["last_seen"]


class TestQueryAttackType:

    def test_matches_actor_by_motivation(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile({"actor_name": "APT28", "motivations": ["espionage"]}, store=store)
        result = query_attack_type("espionage", store=store)
        assert any(a["id"] == "APT28" for a in result["matched_actors"])

    def test_matches_actor_via_malware_type(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(
            {"actor_name": "BlackCatGroup", "malware": [{"name": "BlackCat", "type": "ransomware"}]},
            store=store,
        )
        result = query_attack_type("ransomware", store=store)
        assert any(m["id"] == "blackcat" for m in result["matched_malware"])
        assert any(a["id"] == "BlackCatGroup" for a in result["matched_actors"])

    def test_substring_match_both_directions(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile({"actor_name": "APT28", "motivations": ["financial"]}, store=store)
        # "financ" is a substring of "financial" — should still match
        result = query_attack_type("financ", store=store)
        assert any(a["id"] == "APT28" for a in result["matched_actors"])

    def test_no_match_returns_empty_lists(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile({"actor_name": "APT28", "motivations": ["espionage"]}, store=store)
        result = query_attack_type("wiper", store=store)
        assert result["matched_actors"] == []
        assert result["matched_malware"] == []

    def test_empty_label_returns_empty_result(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        result = query_attack_type("   ", store=store)
        assert result["matched_actors"] == []
        assert result["matched_malware"] == []


class TestQueryActor:

    def test_unknown_actor_not_found(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        result = query_actor("Totally Unknown Actor", store=store)
        assert result["found"] is False

    def test_known_actor_reports_linked_entities(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = query_actor("APT28", store=store)
        assert result["found"] is True
        assert result["actor_name"] == "APT28"
        assert any(i["id"] == "1.1.1.1" for i in result["linked_iocs"])
        assert any(t["id"] == "T1566" for t in result["linked_techniques"])
        assert any(m["id"] == "x-agent" for m in result["linked_malware"])
        assert any(c["id"] == "CVE-2023-23397" for c in result["linked_cves"])
        assert any(c["id"] == "operation ghost" for c in result["linked_campaigns"])

    def test_actor_lookup_resolves_alias(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = query_actor("Fancy Bear", store=store)
        assert result["found"] is True
        assert result["actor_name"] == "APT28"


class TestQueryTechnique:

    def test_unknown_technique_not_found(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        result = query_technique("T9999", store=store)
        assert result["found"] is False
        assert result["technique_id"] == "T9999"

    def test_known_technique_reports_linked_cves(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        profile = {
            **SAMPLE_PROFILE,
            "cves": [{"cve_id": "CVE-2023-23397", "sources": ["cisa"]}],
        }
        ingest_profile(profile, store=store)
        # CVEs link to the actor, not directly to techniques in this profile,
        # so linked_cves is empty here — this asserts the shape, not a false link.
        result = query_technique("T1566", store=store)
        assert result["found"] is True
        assert result["linked_cves"] == []


class TestQueryCve:

    def test_unknown_cve_not_found(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        result = query_cve("CVE-9999-99999", store=store)
        assert result["found"] is False
        assert result["cve_id"] == "CVE-9999-99999"

    def test_known_cve_reports_linked_actor(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = query_cve("CVE-2023-23397", store=store)
        assert result["found"] is True
        assert result["cve_id"] == "CVE-2023-23397"
        assert any(a["label"] == "APT28" for a in result["linked_actors"])

    def test_kev_confirmed_flag_passed_through(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = query_cve("CVE-2023-23397", store=store)
        assert result["kev_confirmed"] is True

    def test_cve_lookup_is_case_insensitive(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = query_cve("cve-2023-23397", store=store)
        assert result["found"] is True

    def test_cve_without_kev_confirmed_defaults_false(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        profile = {
            "actor_name": "Turla",
            "cves": [{"cve_id": "CVE-2020-00001", "sources": ["nvd"]}],
        }
        ingest_profile(profile, store=store)
        result = query_cve("CVE-2020-00001", store=store)
        assert result["found"] is True
        assert result["kev_confirmed"] is False


# ---------------------------------------------------------------------------
# find_connection — cross-correlative / multi-axis query
# ---------------------------------------------------------------------------

class TestFindConnection:

    def test_direct_connection_found(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = find_connection(("actor", "APT28"), ("ioc", "1.1.1.1"), store=store)
        assert result["connected"] is True
        assert result["path"] == "direct"
        assert result["relation"] == "reported_ioc"

    def test_connection_resolves_actor_alias(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = find_connection(("actor", "Fancy Bear"), ("ioc", "1.1.1.1"), store=store)
        assert result["connected"] is True

    def test_shared_neighbor_connection_found(self, tmp_path):
        # Two different actors both linked to the same malware family —
        # neither reports the other's IOC directly, but the malware bridges them.
        store = GraphStore(path=tmp_path / "graph.json")
        profile_a = {
            "actor_name": "APT28",
            "malware": [{"name": "X-Agent", "type": "backdoor"}],
        }
        profile_b = {
            "actor_name": "Turla",
            "malware": [{"name": "X-Agent", "type": "backdoor"}],
        }
        ingest_profile(profile_a, store=store)
        ingest_profile(profile_b, store=store)
        result = find_connection(("actor", "APT28"), ("actor", "Turla"), store=store)
        assert result["connected"] is True
        assert result["path"] == "shared_neighbor"
        assert any(b["label"] == "X-Agent" for b in result["bridges"])

    def test_no_connection_between_unrelated_known_entities(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile({"actor_name": "APT28", "cves": [{"cve_id": "CVE-2023-23397"}]}, store=store)
        ingest_profile({"actor_name": "Turla", "cves": [{"cve_id": "CVE-2020-00000"}]}, store=store)
        result = find_connection(("actor", "APT28"), ("actor", "Turla"), store=store)
        assert result["connected"] is False
        assert result["reason"] == "no_path_found"

    def test_unknown_entity_reports_which_side(self, tmp_path):
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = find_connection(("actor", "APT28"), ("ioc", "9.9.9.9"), store=store)
        assert result["connected"] is False
        assert result["reason"] == "one_or_both_unknown"
        assert result["entity_a"]["known"] is True
        assert result["entity_b"]["known"] is False

    def test_actor_cve_direct_connection_found(self, tmp_path):
        # Symmetric with --ioc/--technique: `theory --actor X --cve Y`
        # is one combined question, backed by the same find_connection path.
        store = GraphStore(path=tmp_path / "graph.json")
        ingest_profile(SAMPLE_PROFILE, store=store)
        result = find_connection(("actor", "APT28"), ("cve", "CVE-2023-23397"), store=store)
        assert result["connected"] is True
        assert result["path"] == "direct"
