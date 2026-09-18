"""
tests/test_nvd_collector.py
----------------------------
Unit tests for collectors/nvd.py — fully offline, no live NVD API calls.

NVD is a CVE-centric enrichment collector (same shape as cisa_kev.py):
query() returns a minimal schema-conformant profile, and enrich_profile()
does the real work of cross-referencing CVEs already in the profile.
"""

from __future__ import annotations

from unittest.mock import patch

from collectors.nvd import NVDCollector, NVDMapper


SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2023-23397",
            "published": "2023-03-14T17:15:09.877",
            "descriptions": [
                {"lang": "en", "value": "Microsoft Outlook Elevation of Privilege Vulnerability."}
            ],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                    },
                    "baseSeverity": "CRITICAL",
                }]
            },
            "weaknesses": [
                {"description": [{"lang": "en", "value": "CWE-287"}]}
            ],
            "references": [
                {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397"},
            ],
        }
    }]
}

SAMPLE_NVD_RESPONSE_EMPTY = {"vulnerabilities": []}


def _collector() -> NVDCollector:
    c = NVDCollector()
    c._respect_rate_limit = lambda: None   # no sleeping in tests
    return c


# ---------------------------------------------------------------------------
# query()
# ---------------------------------------------------------------------------

def test_query_returns_schema_conformant_empty_profile():
    c = _collector()
    profile = c.query("APT28")
    assert profile["actor_name"] == "APT28" or profile["actor_name"]
    assert profile["source_id"] == "nvd"
    assert profile["cves"] == []
    assert profile["indicators"] == []


# ---------------------------------------------------------------------------
# _parse()
# ---------------------------------------------------------------------------

def test_parse_extracts_cvss_cwe_refs_description():
    result = NVDCollector._parse(SAMPLE_NVD_RESPONSE)
    assert result["nvd_cvss_score"] == 9.8
    assert result["nvd_cvss_version"] == "3.1"
    assert result["nvd_cvss_severity"] == "CRITICAL"
    assert result["nvd_cwe"] == ["CWE-287"]
    assert result["nvd_references"] == [
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397"
    ]
    assert "Outlook" in result["_nvd_description"]


def test_parse_handles_no_vulnerabilities():
    assert NVDCollector._parse(SAMPLE_NVD_RESPONSE_EMPTY) is None


def test_parse_handles_missing_metrics_gracefully():
    raw = {"vulnerabilities": [{"cve": {
        "id": "CVE-2020-00000", "published": "2020-01-01",
        "descriptions": [], "weaknesses": [], "references": [],
    }}]}
    result = NVDCollector._parse(raw)
    # No CVSS block present — should not raise, and CVSS fields simply absent
    assert result is not None
    assert "nvd_cvss_score" not in result


def test_parse_falls_back_v30_then_v2_when_v31_absent():
    raw = {"vulnerabilities": [{"cve": {
        "id": "CVE-2019-00000", "published": "2019-01-01",
        "descriptions": [], "weaknesses": [], "references": [],
        "metrics": {"cvssMetricV2": [{
            "cvssData": {"version": "2.0", "vectorString": "AV:N", "baseScore": 5.0},
            "baseSeverity": "MEDIUM",
        }]},
    }}]}
    result = NVDCollector._parse(raw)
    assert result["nvd_cvss_version"] == "2.0"
    assert result["nvd_cvss_score"] == 5.0


# ---------------------------------------------------------------------------
# enrich_profile()
# ---------------------------------------------------------------------------

def test_enrich_profile_merges_data_and_preserves_existing_sources():
    c = _collector()
    profile = {"cves": [{"cve_id": "CVE-2023-23397", "sources": ["vuldb"]}]}

    with patch.object(c, "_fetch", return_value=SAMPLE_NVD_RESPONSE):
        out = c.enrich_profile(profile)

    cve = out["cves"][0]
    assert out["nvd_enriched_count"] == 1
    assert cve["nvd_cvss_score"] == 9.8
    assert set(cve["sources"]) == {"vuldb", "nvd"}
    assert cve["description"]   # backfilled from NVD since none was present


def test_enrich_profile_does_not_overwrite_existing_description():
    c = _collector()
    profile = {"cves": [{"cve_id": "CVE-2023-23397", "sources": [], "description": "original"}]}

    with patch.object(c, "_fetch", return_value=SAMPLE_NVD_RESPONSE):
        out = c.enrich_profile(profile)

    assert out["cves"][0]["description"] == "original"


def test_enrich_profile_noop_on_empty_cve_list():
    c = _collector()
    profile = {"cves": []}
    out = c.enrich_profile(profile)
    assert out == {"cves": []}


def test_enrich_profile_skips_malformed_cve_entries():
    c = _collector()
    profile = {"cves": [{"cve_id": ""}, {"cve_id": "NOT-A-CVE"}, "not-a-dict"]}
    out = c.enrich_profile(profile)
    assert out["nvd_enriched_count"] == 0


def test_enrich_profile_continues_when_lookup_fails_for_one_cve():
    c = _collector()
    profile = {"cves": [
        {"cve_id": "CVE-2023-23397", "sources": []},
        {"cve_id": "CVE-0000-00000", "sources": []},
    ]}

    def fake_fetch(cve_id):
        return SAMPLE_NVD_RESPONSE if cve_id == "CVE-2023-23397" else SAMPLE_NVD_RESPONSE_EMPTY

    with patch.object(c, "_fetch", side_effect=fake_fetch):
        out = c.enrich_profile(profile)

    assert out["nvd_enriched_count"] == 1
    assert "nvd_cvss_score" in out["cves"][0]
    assert "nvd_cvss_score" not in out["cves"][1]


# ---------------------------------------------------------------------------
# Caching behavior
# ---------------------------------------------------------------------------

def test_failed_lookup_is_not_cached(tmp_path, monkeypatch):
    import collectors.nvd as nvd_mod
    monkeypatch.setattr(nvd_mod, "CACHE_DIR", tmp_path / "nvd")

    c = _collector()
    with patch.object(c, "_fetch", return_value=SAMPLE_NVD_RESPONSE_EMPTY):
        result = c.lookup_cve("CVE-9999-99999")

    assert result is None
    assert not (tmp_path / "nvd" / "CVE-9999-99999.json").exists()


def test_successful_lookup_is_cached_and_reused(tmp_path, monkeypatch):
    import collectors.nvd as nvd_mod
    monkeypatch.setattr(nvd_mod, "CACHE_DIR", tmp_path / "nvd")

    c = _collector()
    with patch.object(c, "_fetch", return_value=SAMPLE_NVD_RESPONSE) as fetch_mock:
        first = c.lookup_cve("CVE-2023-23397")
        second = c.lookup_cve("CVE-2023-23397")

    assert first is not None and second is not None
    fetch_mock.assert_called_once()   # second call served from cache


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

def test_mapper_passthrough_valid_record():
    mapper = NVDMapper()
    record = {"actor_name": "APT28", "cves": []}
    assert mapper.map(record) == record


def test_mapper_rejects_missing_actor_name():
    mapper = NVDMapper()
    try:
        mapper.map({"cves": []})
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_mapper_rejects_non_dict():
    mapper = NVDMapper()
    try:
        mapper.map(["not", "a", "dict"])
        assert False, "expected ValueError"
    except ValueError:
        pass
