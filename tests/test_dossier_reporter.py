"""
tests/test_dossier_reporter.py
------------------------------
Unit tests for reporters/dossier.py (DossierReporter).

All tests are offline — no network calls, no disk writes by default.
"""

from __future__ import annotations

import pytest
from reporters.dossier import DossierReporter, _slugify, _now_utc


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_PROFILE = {
    "actor_name":     "APT28",
    "source_id":      "mitre_attack",
    "mitre_group_id": "G0007",
    "origin":         "Russia",
    "first_seen":     "2004",
    "motivations":    ["espionage"],
    "aliases":        ["Fancy Bear", "Sofacy"],
    "description":    "Russian GRU-linked threat actor.",
    "techniques":     [],
    "malware":        [],
    "campaigns":      [],
    "sources_cited":  ["mitre_attack"],
}

FULL_PROFILE = {
    **MINIMAL_PROFILE,
    "techniques": [
        {
            "technique_id":   "T1566",
            "technique_name": "Phishing",
            "tactic":         "Initial Access",
            "confidence":     "high",
            "detection":      "Monitor email gateways.",
        },
        {
            "technique_id":   "T1059.001",
            "technique_name": "PowerShell",
            "tactic":         "Execution",
            "confidence":     "medium",
            "detection":      "",
        },
    ],
    "malware": [
        {"name": "X-Agent", "type": "malware", "description": "Custom implant used by APT28."},
    ],
    "campaigns": [
        {"name": "Operation Pawn Storm", "description": "Long-running espionage.", "first_seen": "2014", "last_seen": "2023"},
    ],
}


# ---------------------------------------------------------------------------
# _slugify
# ---------------------------------------------------------------------------

class TestSlugify:
    def test_simple(self):
        assert _slugify("APT28") == "apt28"

    def test_spaces(self):
        assert _slugify("Fancy Bear") == "fancy_bear"

    def test_slash(self):
        assert _slugify("APT28/SOFACY") == "apt28_sofacy"


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

class TestBuildMarkdown:
    def test_contains_actor_name(self):
        reporter = DossierReporter()
        md = reporter._build_markdown(MINIMAL_PROFILE)
        assert "APT28" in md

    def test_contains_mitre_group_id(self):
        reporter = DossierReporter()
        md = reporter._build_markdown(MINIMAL_PROFILE)
        assert "G0007" in md

    def test_ttp_table_present(self):
        reporter = DossierReporter()
        md = reporter._build_markdown(FULL_PROFILE)
        assert "## TTP Table" in md
        assert "T1566" in md
        assert "T1059.001" in md

    def test_detection_opportunities_present_when_detections_exist(self):
        reporter = DossierReporter()
        md = reporter._build_markdown(FULL_PROFILE)
        assert "## Detection Opportunities" in md
        assert "Monitor email gateways" in md

    def test_no_detection_section_when_no_detections(self):
        profile = {
            **FULL_PROFILE,
            "techniques": [
                {
                    "technique_id":   "T1566",
                    "technique_name": "Phishing",
                    "tactic":         "Initial Access",
                    "confidence":     "high",
                    "detection":      "",    # no detection text
                },
            ],
        }
        reporter = DossierReporter()
        md = reporter._build_markdown(profile)
        assert "## Detection Opportunities" not in md

    def test_malware_section_present(self):
        reporter = DossierReporter()
        md = reporter._build_markdown(FULL_PROFILE)
        assert "## Associated Malware" in md
        assert "X-Agent" in md

    def test_campaigns_section_present(self):
        reporter = DossierReporter()
        md = reporter._build_markdown(FULL_PROFILE)
        assert "## Campaigns" in md
        assert "Operation Pawn Storm" in md

    def test_no_malware_section_when_empty(self):
        reporter = DossierReporter()
        md = reporter._build_markdown(MINIMAL_PROFILE)
        assert "## Associated Malware" not in md

    def test_techniques_sorted_by_id(self):
        reporter = DossierReporter()
        md = reporter._build_markdown(FULL_PROFILE)
        idx_t1059 = md.index("T1059.001")
        idx_t1566 = md.index("T1566")
        # T1059 comes before T1566 lexicographically
        assert idx_t1059 < idx_t1566

    def test_generated_timestamp_present(self):
        reporter = DossierReporter()
        md = reporter._build_markdown(MINIMAL_PROFILE)
        assert "Generated" in md

    def test_sources_cited_present(self):
        reporter = DossierReporter()
        md = reporter._build_markdown(MINIMAL_PROFILE)
        assert "mitre_attack" in md


# ---------------------------------------------------------------------------
# save_markdown (tmp path)
# ---------------------------------------------------------------------------

class TestSaveMarkdown:
    def test_file_written(self, tmp_path, monkeypatch):
        import reporters.dossier as dossier_module
        monkeypatch.setattr(dossier_module, "OUTPUT_DIR", tmp_path)

        reporter = DossierReporter()
        path = reporter.save_markdown(MINIMAL_PROFILE)

        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "APT28" in content

    def test_filename_slugified(self, tmp_path, monkeypatch):
        import reporters.dossier as dossier_module
        monkeypatch.setattr(dossier_module, "OUTPUT_DIR", tmp_path)

        profile = {**MINIMAL_PROFILE, "actor_name": "Fancy Bear"}
        reporter = DossierReporter()
        path = reporter.save_markdown(profile)

        assert path.name == "fancy_bear.md"
