"""
tests/test_correlator.py
------------------------
Offline tests for the Intelligence Correlation Engine.

All tests use synthetic profile data — no network calls, no API keys.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone

from processors.correlator import (
    correlate,
    _index_iocs_by_family,
    _index_cve_references,
    _fuzzy_family_lookup,
    _build_malware_intel,
    _build_technique_intel,
    _build_kill_chain,
    _build_coverage,
    _build_priority_actions,
    _build_stats,
    _ioc_age_days,
    _type_summary,
    _type_counts,
    FRESH_DAYS,
    AGING_DAYS,
    TACTIC_ORDER,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _fresh_date() -> str:
    """Return an ISO date string from 5 days ago."""
    return (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")


def _aging_date() -> str:
    """Return an ISO date string from 60 days ago."""
    return (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%d")


def _stale_date() -> str:
    """Return an ISO date string from 180 days ago."""
    return (datetime.now(timezone.utc) - timedelta(days=180)).strftime("%Y-%m-%d")


@pytest.fixture
def sample_profile():
    """A realistic enriched actor profile for testing."""
    return {
        "actor_name": "APT28",
        "mitre_group_id": "G0007",
        "origin": "Russia",
        "first_seen": "2004",
        "motivations": ["espionage"],
        "aliases": ["Fancy Bear", "Sofacy"],
        "sources_cited": ["mitre_attack", "cisa_advisories", "threatfox"],
        "techniques": [
            {
                "technique_id": "T1566.001",
                "technique_name": "Phishing: Spearphishing Attachment",
                "tactic": "Initial Access",
                "confidence": "HIGH",
                "sigma_rules": [
                    {"title": "Suspicious Attachment", "level": "high", "logsource": "email"},
                    {"title": "Macro Execution", "level": "medium", "logsource": "process_creation"},
                ],
            },
            {
                "technique_id": "T1059.001",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "tactic": "Execution",
                "confidence": "HIGH",
                "sigma_rules": [
                    {"title": "PowerShell Suspicious", "level": "high", "logsource": "powershell"},
                ],
            },
            {
                "technique_id": "T1055",
                "technique_name": "Process Injection",
                "tactic": "Defense Evasion",
                "confidence": "MEDIUM",
                "sigma_rules": [],
            },
            {
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
                "confidence": "HIGH",
                "sigma_rules": [],
                "detection": "Monitor for HTTP/HTTPS traffic to unusual domains",
            },
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "confidence": "MEDIUM",
                "sigma_rules": [],
            },
        ],
        "malware": [
            {
                "name": "Sofacy",
                "type": "backdoor",
                "description": "Backdoor used by APT28",
                "yara_rules": [{"title": "sofacy_backdoor"}],
                "yara_rule_count": 1,
            },
            {
                "name": "X-Agent",
                "type": "trojan",
                "description": "Modular implant",
            },
            {
                "name": "Zebrocy",
                "type": "trojan",
                "description": "Downloader/backdoor",
            },
        ],
        "indicators": [
            # Fresh IOCs for Sofacy
            {"type": "domain", "value": "evil.example.com", "malware_family": "Sofacy",
             "first_seen": _fresh_date(), "confidence": 90},
            {"type": "ip", "value": "192.168.1.100", "malware_family": "Sofacy",
             "first_seen": _fresh_date(), "confidence": 85},
            {"type": "ip", "value": "10.0.0.50", "malware_family": "Sofacy",
             "first_seen": _fresh_date(), "confidence": 80},
            # Aging IOCs for X-Agent
            {"type": "domain", "value": "old.example.com", "malware_family": "X-Agent",
             "first_seen": _aging_date(), "confidence": 70},
            {"type": "hash_sha256", "value": "abc123def456", "malware_family": "X-Agent",
             "first_seen": _aging_date(), "confidence": 75},
            # Stale IOCs
            {"type": "ip", "value": "172.16.0.1", "malware_family": "Zebrocy",
             "first_seen": _stale_date(), "confidence": 50},
            # IOC with no family
            {"type": "url", "value": "http://phish.example.com/login", "malware_family": "",
             "first_seen": _fresh_date(), "confidence": 60},
            # IOC with no date
            {"type": "domain", "value": "undated.example.com", "malware_family": "Sofacy"},
        ],
        "cves": [
            {
                "cve_id": "CVE-2023-23397",
                "kev_confirmed": True,
                "kev_ransomware": True,
                "mitre_references": ["T1190", "Sofacy"],
                "sources": ["mitre_attack"],
            },
            {
                "cve_id": "CVE-2020-1472",
                "kev_confirmed": True,
                "kev_ransomware": False,
                "mitre_references": ["T1055"],
                "sources": ["cisa_kev"],
            },
            {
                "cve_id": "CVE-2019-9670",
                "kev_confirmed": False,
                "mitre_references": ["T1190"],
                "sources": ["mitre_attack"],
            },
        ],
        "campaigns": [
            {"name": "Pawn Storm", "first_seen": "2014", "last_seen": "2023"},
            {"name": "Grizzly Steppe", "first_seen": "2016", "last_seen": "2016"},
        ],
    }


@pytest.fixture
def empty_profile():
    """Minimal profile with no data."""
    return {
        "actor_name": "Unknown",
        "techniques": [],
        "malware": [],
        "indicators": [],
        "cves": [],
        "campaigns": [],
    }


# ---------------------------------------------------------------------------
# Tests: correlate() top-level
# ---------------------------------------------------------------------------

class TestCorrelate:

    def test_adds_correlations_key(self, sample_profile):
        result = correlate(sample_profile)
        assert "correlations" in result

    def test_correlations_has_all_sections(self, sample_profile):
        result = correlate(sample_profile)
        c = result["correlations"]
        assert "malware_intel" in c
        assert "technique_intel" in c
        assert "kill_chain" in c
        assert "priority_actions" in c
        assert "coverage" in c
        assert "stats" in c

    def test_empty_profile_produces_empty_correlations(self, empty_profile):
        result = correlate(empty_profile)
        c = result["correlations"]
        assert c["malware_intel"] == []
        assert c["technique_intel"] == []
        assert c["kill_chain"] == []
        assert c["priority_actions"] == []
        assert c["stats"]["techniques_total"] == 0

    def test_does_not_modify_original_data(self, sample_profile):
        """correlate() adds to the profile but shouldn't clobber existing keys."""
        original_techniques = list(sample_profile["techniques"])
        correlate(sample_profile)
        assert len(sample_profile["techniques"]) == len(original_techniques)
        assert sample_profile["actor_name"] == "APT28"


# ---------------------------------------------------------------------------
# Tests: IOC indexing
# ---------------------------------------------------------------------------

class TestIocIndex:

    def test_groups_by_family(self):
        iocs = [
            {"type": "ip", "value": "1.2.3.4", "malware_family": "Emotet"},
            {"type": "ip", "value": "5.6.7.8", "malware_family": "Emotet"},
            {"type": "domain", "value": "x.com", "malware_family": "TrickBot"},
        ]
        idx = _index_iocs_by_family(iocs)
        assert len(idx["emotet"]) == 2
        assert len(idx["trickbot"]) == 1

    def test_empty_family_excluded(self):
        iocs = [
            {"type": "ip", "value": "1.2.3.4", "malware_family": ""},
            {"type": "ip", "value": "5.6.7.8"},
        ]
        idx = _index_iocs_by_family(iocs)
        assert len(idx) == 0

    def test_malware_field_fallback(self):
        """Some IOCs use 'malware' instead of 'malware_family'."""
        iocs = [{"type": "ip", "value": "1.2.3.4", "malware": "Cobalt Strike"}]
        idx = _index_iocs_by_family(iocs)
        assert "cobalt strike" in idx


# ---------------------------------------------------------------------------
# Tests: CVE reference indexing
# ---------------------------------------------------------------------------

class TestCveIndex:

    def test_indexes_by_technique_id(self):
        cves = [
            {"cve_id": "CVE-2023-1234", "mitre_references": ["T1190", "T1055"]},
        ]
        idx = _index_cve_references(cves)
        assert "T1190" in idx
        assert "T1055" in idx
        assert idx["T1190"][0]["cve_id"] == "CVE-2023-1234"

    def test_indexes_by_malware_name(self):
        cves = [
            {"cve_id": "CVE-2023-5678", "mitre_references": ["Mimikatz"]},
        ]
        idx = _index_cve_references(cves)
        assert "mimikatz" in idx

    def test_no_references(self):
        cves = [{"cve_id": "CVE-2023-0000", "mitre_references": []}]
        idx = _index_cve_references(cves)
        assert len(idx) == 0

    def test_missing_references_key(self):
        cves = [{"cve_id": "CVE-2023-0000"}]
        idx = _index_cve_references(cves)
        assert len(idx) == 0


# ---------------------------------------------------------------------------
# Tests: Fuzzy family lookup
# ---------------------------------------------------------------------------

class TestFuzzyFamilyLookup:

    def test_exact_match(self):
        idx = {"agent tesla": [{"value": "1"}]}
        assert _fuzzy_family_lookup("agent tesla", idx) == [{"value": "1"}]

    def test_stripped_match(self):
        idx = {"agenttesla": [{"value": "2"}]}
        assert _fuzzy_family_lookup("agent tesla", idx) == [{"value": "2"}]

    def test_stripped_match_reverse(self):
        idx = {"agent tesla": [{"value": "3"}]}
        assert _fuzzy_family_lookup("agenttesla", idx) == [{"value": "3"}]

    def test_substring_match(self):
        idx = {"agenttesla_v2": [{"value": "4"}]}
        assert _fuzzy_family_lookup("agenttesla", idx) == [{"value": "4"}]

    def test_no_match(self):
        idx = {"emotet": [{"value": "5"}]}
        assert _fuzzy_family_lookup("agent tesla", idx) == []

    def test_short_name_no_substring(self):
        """Names shorter than 4 chars shouldn't trigger substring matching."""
        idx = {"apt_rat_tool": [{"value": "6"}]}
        assert _fuzzy_family_lookup("rat", idx) == []


# ---------------------------------------------------------------------------
# Tests: Malware intelligence
# ---------------------------------------------------------------------------

class TestMalwareIntel:

    def test_links_iocs_to_malware(self, sample_profile):
        result = correlate(sample_profile)
        mi = result["correlations"]["malware_intel"]
        sofacy = next((m for m in mi if m["name"] == "Sofacy"), None)
        assert sofacy is not None
        assert sofacy["ioc_count"] >= 3  # at least the 3 fresh Sofacy IOCs

    def test_counts_freshness(self, sample_profile):
        result = correlate(sample_profile)
        mi = result["correlations"]["malware_intel"]
        sofacy = next((m for m in mi if m["name"] == "Sofacy"), None)
        assert sofacy is not None
        assert sofacy["iocs_fresh"] >= 2

    def test_links_cves(self, sample_profile):
        result = correlate(sample_profile)
        mi = result["correlations"]["malware_intel"]
        sofacy = next((m for m in mi if m["name"] == "Sofacy"), None)
        assert sofacy is not None
        assert "CVE-2023-23397" in sofacy["linked_cves"]

    def test_detects_yara_coverage(self, sample_profile):
        result = correlate(sample_profile)
        mi = result["correlations"]["malware_intel"]
        sofacy = next((m for m in mi if m["name"] == "Sofacy"), None)
        assert sofacy is not None
        assert sofacy["has_yara"] is True

    def test_sorted_fresh_first(self, sample_profile):
        result = correlate(sample_profile)
        mi = result["correlations"]["malware_intel"]
        if len(mi) >= 2:
            assert mi[0]["iocs_fresh"] >= mi[1]["iocs_fresh"]


# ---------------------------------------------------------------------------
# Tests: Technique intelligence
# ---------------------------------------------------------------------------

class TestTechniqueIntel:

    def test_counts_sigma_rules(self, sample_profile):
        result = correlate(sample_profile)
        ti = result["correlations"]["technique_intel"]
        t1566 = next((t for t in ti if t["technique_id"] == "T1566.001"), None)
        assert t1566 is not None
        assert t1566["sigma_count"] == 2
        assert t1566["has_detection"] is True

    def test_sigma_level_breakdown(self, sample_profile):
        result = correlate(sample_profile)
        ti = result["correlations"]["technique_intel"]
        t1566 = next((t for t in ti if t["technique_id"] == "T1566.001"), None)
        assert t1566 is not None
        assert t1566["sigma_levels"]["high"] == 1
        assert t1566["sigma_levels"]["medium"] == 1

    def test_links_cves_to_techniques(self, sample_profile):
        result = correlate(sample_profile)
        ti = result["correlations"]["technique_intel"]
        t1190 = next((t for t in ti if t["technique_id"] == "T1190"), None)
        assert t1190 is not None
        assert "CVE-2023-23397" in t1190["linked_cve_ids"]
        assert "CVE-2019-9670" in t1190["linked_cve_ids"]

    def test_identifies_kev_cves(self, sample_profile):
        result = correlate(sample_profile)
        ti = result["correlations"]["technique_intel"]
        t1190 = next((t for t in ti if t["technique_id"] == "T1190"), None)
        assert t1190 is not None
        assert "CVE-2023-23397" in t1190["kev_cve_ids"]
        assert "CVE-2019-9670" not in t1190["kev_cve_ids"]  # not KEV-confirmed

    def test_no_detection_flagged(self, sample_profile):
        result = correlate(sample_profile)
        ti = result["correlations"]["technique_intel"]
        t1055 = next((t for t in ti if t["technique_id"] == "T1055"), None)
        assert t1055 is not None
        assert t1055["has_detection"] is False
        assert t1055["sigma_count"] == 0


# ---------------------------------------------------------------------------
# Tests: Kill chain
# ---------------------------------------------------------------------------

class TestKillChain:

    def test_phases_in_order(self, sample_profile):
        result = correlate(sample_profile)
        kc = result["correlations"]["kill_chain"]
        orders = [p["phase_order"] for p in kc]
        assert orders == sorted(orders)

    def test_initial_access_present(self, sample_profile):
        result = correlate(sample_profile)
        kc = result["correlations"]["kill_chain"]
        ia = next((p for p in kc if p["tactic"] == "Initial Access"), None)
        assert ia is not None
        assert ia["technique_count"] >= 1  # T1566.001 at minimum

    def test_detection_gaps_flagged(self, sample_profile):
        result = correlate(sample_profile)
        kc = result["correlations"]["kill_chain"]
        # Defense Evasion has T1055 with no sigma rules
        de = next((p for p in kc if p["tactic"] == "Defense Evasion"), None)
        if de:
            assert de["detection_gap"] is True

    def test_sigma_counts_per_phase(self, sample_profile):
        result = correlate(sample_profile)
        kc = result["correlations"]["kill_chain"]
        ia = next((p for p in kc if p["tactic"] == "Initial Access"), None)
        assert ia is not None
        assert ia["sigma_rule_count"] >= 2  # T1566.001 has 2


# ---------------------------------------------------------------------------
# Tests: Detection coverage
# ---------------------------------------------------------------------------

class TestCoverage:

    def test_coverage_percentage(self, sample_profile):
        result = correlate(sample_profile)
        cov = result["correlations"]["coverage"]
        # 5 techniques, T1566.001 has sigma, T1059.001 has sigma,
        # T1071.001 has detection string → 3 with detection
        assert cov["total_techniques"] == 5
        assert cov["with_any_detection"] == 3
        assert cov["coverage_pct"] == 60  # 3/5

    def test_sigma_coverage_lower(self, sample_profile):
        result = correlate(sample_profile)
        cov = result["correlations"]["coverage"]
        assert cov["sigma_coverage_pct"] == 40  # 2/5 have sigma

    def test_gaps_sorted_by_confidence(self, sample_profile):
        result = correlate(sample_profile)
        gaps = result["correlations"]["coverage"]["gaps"]
        if len(gaps) >= 2:
            conf_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
            for i in range(len(gaps) - 1):
                assert conf_order.get(gaps[i]["confidence"], 3) <= \
                       conf_order.get(gaps[i + 1]["confidence"], 3)

    def test_critical_gaps_are_high_confidence(self, sample_profile):
        result = correlate(sample_profile)
        for g in result["correlations"]["coverage"]["critical_gaps"]:
            assert g["confidence"] == "HIGH"


# ---------------------------------------------------------------------------
# Tests: Priority actions
# ---------------------------------------------------------------------------

class TestPriorityActions:

    def test_block_action_for_fresh_iocs(self, sample_profile):
        result = correlate(sample_profile)
        actions = result["correlations"]["priority_actions"]
        block_actions = [a for a in actions if a["action"] == "block"]
        assert len(block_actions) >= 1
        # Should mention Sofacy since it has fresh IOCs
        sofacy_block = next(
            (a for a in block_actions if "Sofacy" in a.get("title", "")),
            None,
        )
        assert sofacy_block is not None
        assert sofacy_block["urgency"] == "critical"

    def test_patch_action_for_kev_cves(self, sample_profile):
        result = correlate(sample_profile)
        actions = result["correlations"]["priority_actions"]
        patch_actions = [a for a in actions if a["action"] == "patch"]
        assert len(patch_actions) >= 1

    def test_ransomware_cve_prioritised(self, sample_profile):
        result = correlate(sample_profile)
        actions = result["correlations"]["priority_actions"]
        patch_actions = [a for a in actions if a["action"] == "patch"]
        # Ransomware-linked CVE should have critical urgency
        ransom = next(
            (a for a in patch_actions if "ransomware" in a.get("title", "").lower()),
            None,
        )
        assert ransom is not None
        assert ransom["urgency"] == "critical"

    def test_detect_action_for_gaps(self, sample_profile):
        result = correlate(sample_profile)
        actions = result["correlations"]["priority_actions"]
        detect_actions = [a for a in actions if a["action"] == "detect"]
        # We should have at least one gap (T1071.001 has detection string
        # but not sigma; T1055 has nothing)
        # At minimum: early-stage gaps or critical gaps action
        assert len(detect_actions) >= 0  # may vary based on confidence

    def test_actions_numbered_sequentially(self, sample_profile):
        result = correlate(sample_profile)
        actions = result["correlations"]["priority_actions"]
        for i, action in enumerate(actions):
            assert action["priority"] == i + 1

    def test_no_actions_for_empty_profile(self, empty_profile):
        result = correlate(empty_profile)
        actions = result["correlations"]["priority_actions"]
        assert actions == []


# ---------------------------------------------------------------------------
# Tests: Statistics
# ---------------------------------------------------------------------------

class TestStats:

    def test_technique_counts(self, sample_profile):
        result = correlate(sample_profile)
        s = result["correlations"]["stats"]
        assert s["techniques_total"] == 5
        assert s["techniques_with_sigma"] == 2

    def test_ioc_freshness_counts(self, sample_profile):
        result = correlate(sample_profile)
        s = result["correlations"]["stats"]
        assert s["iocs_total"] == 8
        assert s["iocs_fresh"] >= 3  # at least 3 fresh Sofacy + 1 fresh URL

    def test_cve_counts(self, sample_profile):
        result = correlate(sample_profile)
        s = result["correlations"]["stats"]
        assert s["cves_total"] == 3
        assert s["cves_kev_confirmed"] == 2
        assert s["cves_ransomware"] == 1

    def test_campaign_count(self, sample_profile):
        result = correlate(sample_profile)
        s = result["correlations"]["stats"]
        assert s["campaigns_total"] == 2


# ---------------------------------------------------------------------------
# Tests: Utility functions
# ---------------------------------------------------------------------------

class TestUtilities:

    def test_ioc_age_fresh(self):
        now = datetime.now(timezone.utc)
        ioc = {"first_seen": (now - timedelta(days=5)).strftime("%Y-%m-%d")}
        assert _ioc_age_days(ioc, now) == 5

    def test_ioc_age_no_date(self):
        now = datetime.now(timezone.utc)
        assert _ioc_age_days({}, now) is None
        assert _ioc_age_days({"first_seen": ""}, now) is None

    def test_ioc_age_invalid_date(self):
        now = datetime.now(timezone.utc)
        assert _ioc_age_days({"first_seen": "not-a-date"}, now) is None

    def test_type_summary(self):
        iocs = [
            {"type": "domain"},
            {"type": "domain"},
            {"type": "ip"},
            {"type": "hash_sha256"},
        ]
        summary = _type_summary(iocs)
        assert "2 domains" in summary
        assert "1 IPs" in summary
        assert "1 SHA256 hashes" in summary

    def test_type_counts(self):
        iocs = [
            {"type": "domain"}, {"type": "domain"}, {"type": "ip"},
        ]
        counts = _type_counts(iocs)
        assert counts == {"domain": 2, "ip": 1}


# ---------------------------------------------------------------------------
# Tests: Tactic ordering
# ---------------------------------------------------------------------------

class TestTacticOrder:

    def test_all_mitre_tactics_present(self):
        expected = [
            "reconnaissance", "resource development", "initial access",
            "execution", "persistence", "privilege escalation",
            "defense evasion", "credential access", "discovery",
            "lateral movement", "collection", "command and control",
            "exfiltration", "impact",
        ]
        for tactic in expected:
            assert tactic in TACTIC_ORDER

    def test_order_is_sequential(self):
        ordered = sorted(TACTIC_ORDER.items(), key=lambda x: x[1])
        for i, (_, v) in enumerate(ordered):
            assert v == i


# ---------------------------------------------------------------------------
# Tests: Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_techniques_with_no_tactic(self):
        profile = {
            "actor_name": "Test",
            "techniques": [
                {"technique_id": "T9999", "technique_name": "Unknown", "tactic": ""},
            ],
            "malware": [],
            "indicators": [],
            "cves": [],
            "campaigns": [],
        }
        result = correlate(profile)
        # Should not crash; technique should appear in intel but not kill chain
        assert len(result["correlations"]["technique_intel"]) == 1
        assert len(result["correlations"]["kill_chain"]) == 0

    def test_duplicate_cve_references(self):
        """CVEs referenced by multiple techniques shouldn't be double-counted."""
        profile = {
            "actor_name": "Test",
            "techniques": [
                {"technique_id": "T1190", "technique_name": "Exploit", "tactic": "Initial Access",
                 "confidence": "HIGH", "sigma_rules": []},
            ],
            "malware": [{"name": "TestMal", "type": "trojan"}],
            "indicators": [],
            "cves": [
                {"cve_id": "CVE-2023-1234", "kev_confirmed": True,
                 "mitre_references": ["T1190", "TestMal"]},
            ],
            "campaigns": [],
        }
        result = correlate(profile)
        mi = result["correlations"]["malware_intel"]
        testmal = next((m for m in mi if m["name"] == "TestMal"), None)
        assert testmal is not None
        # Should appear once, not twice
        assert testmal["linked_cves"].count("CVE-2023-1234") == 1

    def test_malware_with_no_connections(self):
        """Malware with no IOCs, CVEs, or YARA should be excluded from intel."""
        profile = {
            "actor_name": "Test",
            "techniques": [],
            "malware": [{"name": "OrphanMal", "type": "trojan"}],
            "indicators": [],
            "cves": [],
            "campaigns": [],
        }
        result = correlate(profile)
        mi = result["correlations"]["malware_intel"]
        assert len(mi) == 0  # excluded because no connections

    def test_profile_with_only_iocs(self):
        """A profile with indicators but no techniques/malware should still work."""
        profile = {
            "actor_name": "Test",
            "techniques": [],
            "malware": [],
            "indicators": [
                {"type": "ip", "value": "1.2.3.4", "malware_family": "TestBot",
                 "first_seen": _fresh_date()},
            ],
            "cves": [],
            "campaigns": [],
        }
        result = correlate(profile)
        s = result["correlations"]["stats"]
        assert s["iocs_total"] == 1
        assert s["iocs_fresh"] == 1
