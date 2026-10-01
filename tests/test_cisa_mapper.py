"""
tests/test_cisa_mapper.py
--------------------------
Unit tests for mappers/cisa.py (CisaMapper) and the alias resolver
in collectors/cisa_advisories.py.  Fully offline — no network calls.
"""

from __future__ import annotations

import pytest
from mappers.cisa import CisaMapper
from collectors.cisa_advisories import resolve_canonical, all_aliases_for, ALIAS_TABLE


# ---------------------------------------------------------------------------
# Alias resolver tests
# ---------------------------------------------------------------------------

class TestAliasResolver:

    def test_canonical_name_resolves_to_itself(self):
        assert resolve_canonical("APT28") == "APT28"

    def test_alias_resolves_to_canonical(self):
        assert resolve_canonical("Fancy Bear") == "APT28"

    def test_case_insensitive(self):
        assert resolve_canonical("fancy bear")  == "APT28"
        assert resolve_canonical("FANCY BEAR")  == "APT28"
        assert resolve_canonical("fAnCy BeAr")  == "APT28"

    def test_microsoft_name_resolves(self):
        assert resolve_canonical("Strontium")      == "APT28"
        assert resolve_canonical("Forest Blizzard") == "APT28"

    def test_apt29_alias(self):
        assert resolve_canonical("Cozy Bear")  == "APT29"
        assert resolve_canonical("Nobelium")   == "APT29"
        assert resolve_canonical("Midnight Blizzard") == "APT29"

    def test_lazarus_alias(self):
        assert resolve_canonical("Hidden Cobra") == "Lazarus Group"
        assert resolve_canonical("ZINC")         == "Lazarus Group"

    def test_unknown_name_returns_itself(self):
        assert resolve_canonical("UnknownActorXYZ") == "UnknownActorXYZ"

    def test_multi_word_alias_without_spaces(self):
        # theory --actor scatteredspider (no space) should still resolve —
        # a multi-word actor name typed as one concatenated word on the
        # command line is a real, reported failure mode, not an edge case.
        assert resolve_canonical("scatteredspider") == "Scattered Spider"
        assert resolve_canonical("ScatteredSpider") == "Scattered Spider"

    def test_multi_word_alias_with_hyphen_or_underscore(self):
        assert resolve_canonical("scattered-spider") == "Scattered Spider"
        assert resolve_canonical("Scattered_Spider") == "Scattered Spider"

    def test_exact_match_still_takes_priority_over_normalized(self):
        # Sanity: the space-preserving exact match path isn't disturbed
        # by adding the normalized fallback.
        assert resolve_canonical("Scattered Spider") == "Scattered Spider"
        assert resolve_canonical("fancy bear") == "APT28"

    def test_normalized_fallback_does_not_create_false_positives(self):
        # A genuinely unknown, unrelated string must not accidentally
        # collapse onto some real actor's normalized form.
        result = resolve_canonical("totally not a real actor name xyz123")
        assert result == "totally not a real actor name xyz123"

    def test_all_aliases_for_returns_set(self):
        aliases = all_aliases_for("APT28")
        assert isinstance(aliases, frozenset)
        assert "fancy bear" in aliases
        assert "sofacy"     in aliases
        assert "strontium"  in aliases

    def test_all_aliases_for_alias_input(self):
        # Passing an alias should still return the full set
        aliases = all_aliases_for("Fancy Bear")
        assert "apt28"      in aliases
        assert "sofacy"     in aliases

    def test_all_aliases_for_unknown(self):
        aliases = all_aliases_for("RandomGroup99")
        assert "randomgroup99" in aliases


class TestSuggestSimilar:

    def test_typo_suggests_correct_actor(self):
        from collectors.cisa_advisories import suggest_similar
        suggestions = suggest_similar("scaterd spidr")
        assert "Scattered Spider" in suggestions

    def test_gibberish_returns_no_suggestions(self):
        from collectors.cisa_advisories import suggest_similar
        assert suggest_similar("zzznonexistentxyz123") == []

    def test_respects_limit(self):
        from collectors.cisa_advisories import suggest_similar
        suggestions = suggest_similar("apt", limit=2)
        assert len(suggestions) <= 2


class TestAliasTableIntegrity:

    def test_alias_table_has_no_duplicate_aliases(self):
        """Each alias string should map to exactly one canonical name."""
        seen: dict[str, str] = {}
        for canonical, aliases in ALIAS_TABLE.items():
            for alias in aliases:
                assert alias not in seen, (
                    f"Alias {alias!r} appears in both "
                    f"{seen[alias]!r} and {canonical!r}"
                )
                seen[alias] = canonical


class TestCveExtraction:
    """CVE attribution redesign: CVE IDs mentioned in the text of
    advisories already confirmed to be about a specific actor, cross-
    referenced against KEV by exact ID (not the old, unreliable
    substring-match of the actor's name against KEV's free-text notes
    field, which had no real actor-attribution basis)."""

    def test_extract_cve_ids_finds_and_dedups(self):
        from collectors.cisa_advisories import _extract_cve_ids
        text = "Exploited CVE-2023-3519 and cve-2024-1234, then CVE-2023-3519 again."
        assert _extract_cve_ids(text) == ["CVE-2023-3519", "CVE-2024-1234"]

    def test_extract_cve_ids_empty_text(self):
        from collectors.cisa_advisories import _extract_cve_ids
        assert _extract_cve_ids("") == []
        assert _extract_cve_ids("no cves mentioned here") == []

    def test_collect_enriches_advisory_cve_with_exact_kev_match(self):
        from collectors.cisa_advisories import CisaAdvisoriesCollector
        from unittest.mock import patch

        c = CisaAdvisoriesCollector()
        fake_advisories = [{
            "title": "Scattered Spider Advisory", "url": "https://cisa.gov/x", "date": "2026-01-01",
            "summary": "Scattered Spider exploited CVE-2023-3519.",
            "sectors": [], "techniques": [], "cves": ["CVE-2023-3519"],
        }]
        fake_kev = {"vulnerabilities": [
            {"cveID": "CVE-2023-3519", "product": "NetScaler", "vendorProject": "Citrix",
             "shortDescription": "Buffer overflow", "dueDate": "2023-08-09", "dateAdded": "2023-07-19"},
            {"cveID": "CVE-9999-00000", "product": "unrelated", "vendorProject": "x"},
        ]}
        with patch.object(c, "_fetch_advisories", return_value=fake_advisories), \
             patch("collectors.cisa_advisories._fetch_json", return_value=fake_kev):
            result = c.collect("Scattered Spider")

        assert len(result["cves"]) == 1   # the unrelated KEV entry must not leak in
        cve = result["cves"][0]
        assert cve["cve_id"] == "CVE-2023-3519"
        assert cve["product"] == "NetScaler"
        assert cve["vendor"] == "Citrix"
        assert "cisa_kev" in cve["sources"]

    def test_collect_surfaces_advisory_cve_not_in_kev(self):
        from collectors.cisa_advisories import CisaAdvisoriesCollector
        from unittest.mock import patch

        c = CisaAdvisoriesCollector()
        fake_advisories = [{
            "title": "X", "url": "y", "date": "2026-01-01",
            "summary": "x", "sectors": [], "techniques": [], "cves": ["CVE-2020-00000"],
        }]
        with patch.object(c, "_fetch_advisories", return_value=fake_advisories), \
             patch("collectors.cisa_advisories._fetch_json", return_value={"vulnerabilities": []}):
            result = c.collect("X")

        assert result["cves"][0]["cve_id"] == "CVE-2020-00000"
        assert result["cves"][0]["product"] == ""
        assert result["cves"][0]["sources"] == ["cisa"]   # no cisa_kev tag — not KEV-confirmed

    def test_collect_returns_none_with_no_advisories_and_no_cves(self):
        from collectors.cisa_advisories import CisaAdvisoriesCollector
        from unittest.mock import patch

        c = CisaAdvisoriesCollector()
        with patch.object(c, "_fetch_advisories", return_value=[]):
            assert c.collect("nonexistent-actor-xyz") is None


# ---------------------------------------------------------------------------
# CisaMapper tests
# ---------------------------------------------------------------------------

MINIMAL_RAW = {
    "actor_name": "APT28",
    "source_id":  "cisa",
    "aliases":    ["Fancy Bear", "Sofacy"],
    "description": "",
    "origin":      "",
    "first_seen":  "",
    "motivations": [],
    "techniques":  [],
    "indicators":  [],
    "malware":     [],
    "campaigns":   [],
    "sectors":     ["Government", "Defense"],
    "cves":        [],
    "advisories":  [],
    "raw_source":  "CISA KEV + Advisories",
}

FULL_RAW = {
    **MINIMAL_RAW,
    "techniques": [
        {
            "technique_id":   "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic":         "",
            "tactics":        [],
            "description":    "",
            "detection":      "",
            "sources":        ["cisa"],
        },
        {
            "technique_id":   "",   # should be dropped
            "technique_name": "Bad entry",
            "tactic":         "",
            "tactics":        [],
            "description":    "",
            "detection":      "",
            "sources":        [],
        },
    ],
    "cves": [
        {
            "cve_id":      "CVE-2023-23397",
            "product":     "Outlook",
            "vendor":      "Microsoft",
            "description": "Privilege escalation in Outlook.",
            "due_date":    "2023-04-04",
            "date_added":  "2023-03-14",
        },
    ],
    "advisories": [
        {
            "title": "Russian State-Sponsored Cyber Actors",
            "url":   "https://www.cisa.gov/uscert/ncas/advisories/aa22-110a",
            "date":  "2022-04-20",
        },
    ],
}


class TestCisaMapperValidation:

    def test_non_dict_raises(self):
        with pytest.raises(ValueError, match="Expected dict"):
            CisaMapper().map("not a dict")

    def test_missing_actor_name_raises(self):
        with pytest.raises(ValueError, match="actor_name"):
            CisaMapper().map({"source_id": "cisa"})

    def test_empty_actor_name_raises(self):
        with pytest.raises(ValueError, match="actor_name"):
            CisaMapper().map({"actor_name": "  "})


class TestCisaMapperMinimal:

    def test_minimal_maps_cleanly(self):
        r = CisaMapper().map(MINIMAL_RAW)
        assert r["actor_name"] == "APT28"
        assert r["source_id"]  == "cisa"
        assert r["techniques"] == []
        assert r["cves"]       == []

    def test_sectors_preserved(self):
        r = CisaMapper().map(MINIMAL_RAW)
        assert "Government" in r["sectors"]
        assert "Defense"    in r["sectors"]

    def test_aliases_deduped_case_insensitive(self):
        raw = {**MINIMAL_RAW, "aliases": ["Fancy Bear", "fancy bear", "FANCY BEAR"]}
        r   = CisaMapper().map(raw)
        assert len(r["aliases"]) == 1
        assert r["aliases"][0] == "Fancy Bear"


class TestCisaMapperTechniques:

    def test_valid_technique_passes(self):
        r    = CisaMapper().map(FULL_RAW)
        tids = [t["technique_id"] for t in r["techniques"]]
        assert "T1190" in tids

    def test_empty_tid_dropped(self):
        r    = CisaMapper().map(FULL_RAW)
        tids = [t["technique_id"] for t in r["techniques"]]
        assert "" not in tids

    def test_source_tag_preserved(self):
        r = CisaMapper().map(FULL_RAW)
        t = next(t for t in r["techniques"] if t["technique_id"] == "T1190")
        assert "cisa" in t["sources"]


class TestCisaMapperEnrichments:

    def test_cves_passed_through(self):
        r = CisaMapper().map(FULL_RAW)
        assert len(r["cves"]) == 1
        assert r["cves"][0]["cve_id"] == "CVE-2023-23397"

    def test_advisories_passed_through(self):
        r = CisaMapper().map(FULL_RAW)
        assert len(r["advisories"]) == 1
        assert "aa22-110a" in r["advisories"][0]["url"]
