"""
tests/test_circl_misp_collector.py
------------------------------------
Unit tests for collectors/circl_misp.py — fully offline, no live
requests to circl.lu.

CIRCL MISP is an actor-centric collector: matches actor name/aliases
against the OSINT feed manifest (info + tags), then fetches matched
events for their attribute lists.
"""

from __future__ import annotations

from unittest.mock import patch

from collectors.circl_misp import CirclMispCollector, CirclMispMapper


SAMPLE_MANIFEST = {
    "event-uuid-1": {
        "info": "APT28 campaign targeting NATO member states",
        "date": "2026-08-01",
        "Tag": [{"name": 'misp-galaxy:threat-actor="APT28"'}],
    },
    "event-uuid-2": {
        "info": "Generic commodity phishing kit",
        "date": "2026-07-01",
        "Tag": [{"name": "tlp:white"}],
    },
    "event-uuid-3": {
        "info": "Fancy Bear infrastructure update",
        "date": "2026-08-15",
        "Tag": ["type:OSINT"],   # tags as plain strings, not dicts
    },
}

SAMPLE_EVENT = {
    "Event": {
        "info": "APT28 campaign targeting NATO member states",
        "date": "2026-08-01",
        "Attribute": [
            {"type": "ip-dst", "value": "1.1.1.1", "timestamp": "1690000000"},
            {"type": "domain", "value": "evil.example.com", "timestamp": "1690000000"},
            {"type": "sha256", "value": "a" * 64, "timestamp": "1690000000"},
            {"type": "unsupported-type", "value": "ignore-me"},
            {"type": "url", "value": ""},   # empty value — should be dropped
        ],
    }
}


def _collector() -> CirclMispCollector:
    return CirclMispCollector()


# ---------------------------------------------------------------------------
# Manifest matching
# ---------------------------------------------------------------------------

def test_match_events_finds_actor_by_info_text():
    c = _collector()
    matches = c._match_events(SAMPLE_MANIFEST, ["apt28"])
    uuids = [m[0] for m in matches]
    assert "event-uuid-1" in uuids
    assert "event-uuid-2" not in uuids


def test_match_events_finds_actor_by_tag():
    c = _collector()
    matches = c._match_events(SAMPLE_MANIFEST, ["apt28"])
    # event-uuid-1 matches via both info text AND tag — should appear once
    assert sum(1 for m in matches if m[0] == "event-uuid-1") == 1


def test_match_events_matches_alias_not_just_canonical():
    c = _collector()
    matches = c._match_events(SAMPLE_MANIFEST, ["fancy bear"])
    uuids = [m[0] for m in matches]
    assert "event-uuid-3" in uuids
    assert "event-uuid-1" not in uuids   # doesn't contain "fancy bear" text


def test_match_events_handles_string_tags_without_erroring():
    c = _collector()
    # event-uuid-3 has a plain-string tag, not a dict — must not raise
    matches = c._match_events(SAMPLE_MANIFEST, ["osint"])
    assert any(m[0] == "event-uuid-3" for m in matches)


def test_match_events_sorted_most_recent_first():
    c = _collector()
    matches = c._match_events(SAMPLE_MANIFEST, ["apt28", "fancy bear"])
    dates = [m[1]["date"] for m in matches]
    assert dates == sorted(dates, reverse=True)


def test_match_events_no_match_returns_empty():
    c = _collector()
    assert c._match_events(SAMPLE_MANIFEST, ["totally-unrelated-actor-xyz"]) == []


# ---------------------------------------------------------------------------
# Attribute -> indicator mapping
# ---------------------------------------------------------------------------

def test_map_attribute_known_type():
    c = _collector()
    ind = c._map_attribute({"type": "ip-dst", "value": "1.1.1.1", "timestamp": "1690000000"}, "context")
    assert ind["type"] == "ip"
    assert ind["value"] == "1.1.1.1"
    assert ind["sources"] == ["circl_misp"]
    assert ind["description"] == "context"


def test_map_attribute_unknown_type_returns_none():
    c = _collector()
    assert c._map_attribute({"type": "some-unmapped-type", "value": "x"}, "") is None


def test_map_attribute_empty_value_returns_none():
    c = _collector()
    assert c._map_attribute({"type": "url", "value": ""}, "") is None


def test_map_attribute_splits_composite_ip_port():
    c = _collector()
    ind = c._map_attribute({"type": "ip-dst|port", "value": "1.1.1.1|443"}, "")
    assert ind["value"] == "1.1.1.1"


def test_map_attribute_hash_types():
    c = _collector()
    for raw_type, expected in (("md5", "hash_md5"), ("sha1", "hash_sha1"), ("sha256", "hash_sha256")):
        ind = c._map_attribute({"type": raw_type, "value": "abc123"}, "")
        assert ind["type"] == expected


# ---------------------------------------------------------------------------
# query() end-to-end (network mocked)
# ---------------------------------------------------------------------------

def test_query_returns_indicators_and_campaign_for_matched_event():
    c = _collector()
    # Isolate this test from the real actors.yaml alias table (APT28's real
    # alias list includes "Fancy Bear", which would also match event-uuid-3
    # and is exercised separately in test_match_events_matches_alias_not_just_canonical).
    with patch.object(c, "_search_terms", return_value=["apt28"]), \
         patch.object(c, "_load_manifest", return_value=SAMPLE_MANIFEST), \
         patch.object(c, "_load_event", return_value=SAMPLE_EVENT):
        profile = c.query("APT28")

    assert profile["source_id"] == "circl_misp"
    assert len(profile["campaigns"]) == 1
    assert profile["campaigns"][0]["name"] == "APT28 campaign targeting NATO member states"
    values = {i["value"] for i in profile["indicators"]}
    assert "1.1.1.1" in values
    assert "evil.example.com" in values
    assert "ignore-me" not in values   # unmapped type excluded
    assert len(profile["indicators"]) == 3   # ip, domain, sha256 — url/unsupported dropped


def test_query_handles_no_matches_gracefully():
    c = _collector()
    with patch.object(c, "_load_manifest", return_value=SAMPLE_MANIFEST):
        profile = c.query("Totally Unrelated Actor XYZ")

    assert profile["indicators"] == []
    assert profile["campaigns"] == []


def test_query_returns_none_when_manifest_unavailable():
    c = _collector()
    with patch.object(c, "_load_manifest", return_value=None):
        assert c.query("APT28") is None


def test_query_caps_events_fetched(monkeypatch):
    import collectors.circl_misp as circl_mod
    monkeypatch.setattr(circl_mod, "MAX_EVENTS_FETCHED", 1)

    big_manifest = {
        f"uuid-{i}": {"info": f"APT28 event {i}", "date": f"2026-08-{i:02d}", "Tag": []}
        for i in range(1, 5)
    }
    c = _collector()
    with patch.object(c, "_load_manifest", return_value=big_manifest), \
         patch.object(c, "_load_event", return_value=SAMPLE_EVENT) as event_mock:
        c.query("APT28")

    assert event_mock.call_count == 1


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

def test_mapper_passthrough_valid_record():
    mapper = CirclMispMapper()
    record = {"actor_name": "APT28", "indicators": []}
    assert mapper.map(record) == record


def test_mapper_rejects_missing_actor_name():
    mapper = CirclMispMapper()
    try:
        mapper.map({"indicators": []})
        assert False, "expected ValueError"
    except ValueError:
        pass
