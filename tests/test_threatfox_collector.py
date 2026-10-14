"""
tests/test_threatfox_collector.py
-----------------------------------
Unit tests for collectors/threatfox.py — fully offline.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

import collectors.threatfox as tf_module
from collectors.threatfox import ThreatFoxCollector, _slugify, _threat_priority
from theory.disk_cache import DiskCache


def make_collector(tmp_path, clock=None):
    """A collector whose cache lives in tmp_path (never the real cache dir)."""
    collector = ThreatFoxCollector()
    kwargs = {"clock": clock} if clock else {}
    collector._cache = DiskCache(
        "threatfox", ttl=timedelta(hours=tf_module.CACHE_TTL_HOURS),
        root=tmp_path, **kwargs,
    )
    return collector


# ---------------------------------------------------------------------------
# Sample ThreatFox API responses
# ---------------------------------------------------------------------------

SAMPLE_TAGINFO_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "id":               "1",
            "ioc":              "185.220.101.1:443",
            "ioc_type":         "ip:port",
            "threat_type":      "botnet_cc",
            "malware":          "win.zebrocy",
            "malware_printable": "Zebrocy",
            "confidence_level": 100,
            "first_seen":       "2024-01-15 10:00:00",
            "last_seen":        "2024-03-01 00:00:00",
            "tags":             ["apt28", "russia"],
        },
        {
            "id":               "2",
            "ioc":              "evil-c2.example.com",
            "ioc_type":         "domain",
            "threat_type":      "botnet_cc",
            "malware":          "win.chopstick",
            "malware_printable": "CHOPSTICK",
            "confidence_level": 75,
            "first_seen":       "2024-02-01 00:00:00",
            "last_seen":        "2024-02-28 00:00:00",
            "tags":             ["apt28"],
        },
        {
            "id":               "3",
            "ioc":              "d41d8cd98f00b204e9800998ecf8427e",
            "ioc_type":         "md5_hash",
            "threat_type":      "payload",
            "malware":          "win.zebrocy",
            "malware_printable": "Zebrocy",
            "confidence_level": 50,
            "first_seen":       "2023-12-01 00:00:00",
            "last_seen":        "2023-12-31 00:00:00",
            "tags":             [],
        },
        {
            "id":               "4",
            "ioc":              "",           # empty value — should be dropped
            "ioc_type":         "domain",
            "threat_type":      "botnet_cc",
            "malware":          "win.zebrocy",
            "malware_printable": "Zebrocy",
            "confidence_level": 80,
            "first_seen":       "2024-01-01 00:00:00",
            "last_seen":        "",
            "tags":             [],
        },
        {
            "id":               "5",
            "ioc":              "something",
            "ioc_type":         "unknown_type",  # unmapped type — should be dropped
            "threat_type":      "botnet_cc",
            "malware":          "win.zebrocy",
            "malware_printable": "Zebrocy",
            "confidence_level": 90,
            "first_seen":       "2024-01-01 00:00:00",
            "last_seen":        "",
            "tags":             [],
        },
    ]
}

NO_RESULTS_RESPONSE = {
    "query_status": "no_results",
    "data": [],
}


# ---------------------------------------------------------------------------
# _parse_ioc tests
# ---------------------------------------------------------------------------

class TestParseIoc:

    def test_ip_port_parsed(self):
        raw = SAMPLE_TAGINFO_RESPONSE["data"][0]
        ioc = ThreatFoxCollector._parse_ioc(raw)
        assert ioc is not None
        assert ioc["type"]  == "ip"
        assert ioc["value"] == "185.220.101.1"   # port stripped

    def test_domain_parsed(self):
        raw = SAMPLE_TAGINFO_RESPONSE["data"][1]
        ioc = ThreatFoxCollector._parse_ioc(raw)
        assert ioc is not None
        assert ioc["type"]  == "domain"
        assert ioc["value"] == "evil-c2.example.com"

    def test_md5_parsed(self):
        raw = SAMPLE_TAGINFO_RESPONSE["data"][2]
        ioc = ThreatFoxCollector._parse_ioc(raw)
        assert ioc is not None
        assert ioc["type"] == "hash_md5"

    def test_empty_value_returns_none(self):
        raw = SAMPLE_TAGINFO_RESPONSE["data"][3]
        ioc = ThreatFoxCollector._parse_ioc(raw)
        assert ioc is None

    def test_unknown_type_returns_none(self):
        raw = SAMPLE_TAGINFO_RESPONSE["data"][4]
        ioc = ThreatFoxCollector._parse_ioc(raw)
        assert ioc is None

    def test_confidence_preserved(self):
        raw = SAMPLE_TAGINFO_RESPONSE["data"][0]
        ioc = ThreatFoxCollector._parse_ioc(raw)
        assert ioc["confidence"] == 100

    def test_threat_label_mapped(self):
        raw = SAMPLE_TAGINFO_RESPONSE["data"][0]
        ioc = ThreatFoxCollector._parse_ioc(raw)
        assert ioc["threat_label"] == "Botnet C2"

    def test_first_seen_truncated_to_date(self):
        raw = SAMPLE_TAGINFO_RESPONSE["data"][0]
        ioc = ThreatFoxCollector._parse_ioc(raw)
        assert ioc["first_seen"] == "2024-01-15"

    def test_tags_preserved(self):
        raw = SAMPLE_TAGINFO_RESPONSE["data"][0]
        ioc = ThreatFoxCollector._parse_ioc(raw)
        assert "apt28" in ioc["tags"]

    def test_source_is_threatfox(self):
        raw = SAMPLE_TAGINFO_RESPONSE["data"][0]
        ioc = ThreatFoxCollector._parse_ioc(raw)
        assert "threatfox" in ioc["sources"]


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------

class TestThreatFoxCache:

    def test_save_and_load(self, tmp_path):

        collector = make_collector(tmp_path)
        iocs = [{"type": "ip", "value": "1.2.3.4", "confidence": 100}]
        collector._cache.put("zebrocy", iocs)
        loaded = collector._cache.get("zebrocy")
        assert loaded.value == iocs

    def test_missing_returns_none(self, tmp_path):

        collector = make_collector(tmp_path)
        assert collector._cache.get("nonexistent") is None

    def test_empty_cache_returns_empty_list(self, tmp_path):

        collector = make_collector(tmp_path)
        collector._cache.put("no_results", [])
        loaded = collector._cache.get("no_results")
        assert loaded.value == []

    def test_stale_cache_returns_none(self, tmp_path):
        now = [1_000_000.0]
        collector = make_collector(tmp_path, clock=lambda: now[0])
        collector._cache.put("stale", [{"type": "ip", "value": "1.2.3.4"}])
        now[0] += 25 * 3600
        assert collector._cache.get("stale") is None


# ---------------------------------------------------------------------------
# collect_for_malware_families with mocked API
# ---------------------------------------------------------------------------

class TestCollectForMalwareFamilies:

    @pytest.fixture(autouse=True)
    def _abusech_key(self, monkeypatch):
        """abuse.ch has required an Auth-Key on every request since late 2026,
        and the collector correctly refuses to serve cached data without one
        (no key -> don't present stale abuse.ch data as if it were live).
        These tests predate that change and exercise the post-auth path, so
        they supply a key explicitly rather than inheriting one from the
        developer's environment."""
        monkeypatch.setenv("ABUSECH_API_KEY", "test-key-not-real")

    def test_empty_names_returns_none(self):
        collector = ThreatFoxCollector()
        result = collector.collect_for_malware_families([], "APT28")
        assert result is None

    def test_uses_cache(self, tmp_path):

        collector = make_collector(tmp_path)
        cached_iocs = [{
            "type": "ip", "value": "1.2.3.4", "confidence": 100,
            "threat_type": "botnet_cc", "threat_label": "Botnet C2",
            "first_seen": "2024-01-01", "last_seen": "", "tags": [],
            "malware": "Zebrocy", "description": "Botnet C2 — Zebrocy",
            "sources": ["threatfox"],
        }]
        collector._cache.put("zebrocy", cached_iocs)

        result = collector.collect_for_malware_families(["Zebrocy"], "APT28")
        assert result is not None
        assert len(result["indicators"]) == 1
        assert result["indicators"][0]["value"] == "1.2.3.4"

    def test_deduplicates_across_families(self, tmp_path):

        collector = make_collector(tmp_path)
        shared_ioc = [{
            "type": "ip", "value": "5.5.5.5", "confidence": 100,
            "threat_type": "botnet_cc", "threat_label": "Botnet C2",
            "first_seen": "2024-01-01", "last_seen": "", "tags": [],
            "malware": "Zebrocy", "description": "", "sources": ["threatfox"],
        }]
        # Same IP appears in both family caches
        collector._cache.put("zebrocy",   shared_ioc)
        collector._cache.put("x_agent",   shared_ioc)

        result = collector.collect_for_malware_families(["Zebrocy", "X-Agent"], "APT28")
        assert result is not None
        # Should appear only once
        values = [i["value"] for i in result["indicators"]]
        assert values.count("5.5.5.5") == 1

    def test_sorted_by_confidence_desc(self, tmp_path):

        collector = make_collector(tmp_path)
        iocs = [
            {"type": "ip", "value": "1.1.1.1", "confidence": 50,
             "threat_type": "botnet_cc", "threat_label": "Botnet C2",
             "first_seen": "", "last_seen": "", "tags": [],
             "malware": "X", "description": "", "sources": ["threatfox"]},
            {"type": "ip", "value": "2.2.2.2", "confidence": 100,
             "threat_type": "botnet_cc", "threat_label": "Botnet C2",
             "first_seen": "", "last_seen": "", "tags": [],
             "malware": "X", "description": "", "sources": ["threatfox"]},
        ]
        collector._cache.put("x_agent", iocs)

        result = collector.collect_for_malware_families(["X-Agent"], "APT28")
        assert result is not None
        # Highest confidence first
        assert result["indicators"][0]["confidence"] == 100

    def test_malware_family_tagged_on_ioc(self, tmp_path):

        collector = make_collector(tmp_path)
        iocs = [{"type": "domain", "value": "evil.com", "confidence": 80,
                 "threat_type": "botnet_cc", "threat_label": "Botnet C2",
                 "first_seen": "2024-01-01", "last_seen": "", "tags": [],
                 "malware": "CHOPSTICK", "description": "", "sources": ["threatfox"]}]
        collector._cache.put("chopstick", iocs)

        result = collector.collect_for_malware_families(["CHOPSTICK"], "APT28")
        assert result["indicators"][0]["malware_family"] == "CHOPSTICK"

    def test_returns_none_when_all_empty(self, tmp_path):

        collector = make_collector(tmp_path)
        collector._cache.put("obscure_malware", [])

        result = collector.collect_for_malware_families(["Obscure Malware"], "APT28")
        assert result is None


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------

class TestUtilities:

    def test_slugify_spaces(self):
        assert _slugify("X-Agent") == "x_agent"

    def test_slugify_special_chars(self):
        assert _slugify("Win32/Zebrocy.A!MTB") == "win32_zebrocy_a_mtb"

    def test_slugify_truncates(self):
        long_name = "a" * 100
        assert len(_slugify(long_name)) <= 80

    def test_threat_priority_botnet(self):
        assert _threat_priority("botnet_cc") < _threat_priority("reconnaissance")

    def test_threat_priority_unknown(self):
        assert _threat_priority("unknown_type") == 99
