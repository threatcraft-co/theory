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
