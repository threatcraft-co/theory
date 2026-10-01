"""
tests/test_diff.py
--------------------
Unit tests for processors/diff.py — the `theory diff` comparison engine.
Fully offline, pure dict comparisons, no files touched.
"""

from __future__ import annotations

from processors.diff import diff_profiles, has_changes


def tech(tid, confidence="MEDIUM"):
    return {"technique_id": tid, "technique_name": tid, "confidence": confidence}


def ioc(itype, value, confidence="LOW"):
    return {"type": itype, "value": value, "confidence": confidence}


def mal(name):
    return {"name": name, "type": "backdoor"}


def cve(cve_id):
    return {"cve_id": cve_id}


def camp(name):
    return {"name": name}


class TestFirstRun:

    def test_none_old_is_first_run(self):
        result = diff_profiles(None, {"actor_name": "APT28", "techniques": [tech("T1566")]})
        assert result["is_first_run"] is True
        assert result["techniques"]["added"][0]["technique_id"] == "T1566"

    def test_empty_dict_old_is_first_run(self):
        result = diff_profiles({}, {"actor_name": "APT28"})
        assert result["is_first_run"] is True

    def test_first_run_has_no_removed_or_confidence_changes(self):
        result = diff_profiles(None, {"actor_name": "APT28", "techniques": [tech("T1566")]})
        assert result["techniques"]["removed"] == []
        assert result["techniques"]["confidence_changes"] == []


class TestTechniqueDiff:

    def test_added_technique_detected(self):
        old = {"actor_name": "APT28", "techniques": [tech("T1566")]}
        new = {"actor_name": "APT28", "techniques": [tech("T1566"), tech("T1078")]}
        result = diff_profiles(old, new)
        assert [t["technique_id"] for t in result["techniques"]["added"]] == ["T1078"]
        assert result["techniques"]["removed"] == []

    def test_removed_technique_detected(self):
        old = {"actor_name": "APT28", "techniques": [tech("T1566"), tech("T1078")]}
        new = {"actor_name": "APT28", "techniques": [tech("T1566")]}
        result = diff_profiles(old, new)
        assert [t["technique_id"] for t in result["techniques"]["removed"]] == ["T1078"]

    def test_no_changes_when_identical(self):
        old = {"actor_name": "APT28", "techniques": [tech("T1566")]}
        new = {"actor_name": "APT28", "techniques": [tech("T1566")]}
        result = diff_profiles(old, new)
        assert result["techniques"]["added"] == []
        assert result["techniques"]["removed"] == []

    def test_confidence_change_detected(self):
        old = {"actor_name": "APT28", "techniques": [tech("T1566", confidence="LOW")]}
        new = {"actor_name": "APT28", "techniques": [tech("T1566", confidence="HIGH")]}
        result = diff_profiles(old, new)
        changes = result["techniques"]["confidence_changes"]
        assert len(changes) == 1
        assert changes[0] == {"key": "T1566", "from": "LOW", "to": "HIGH"}

    def test_case_insensitive_technique_id_matching(self):
        old = {"actor_name": "APT28", "techniques": [{"technique_id": "t1566", "confidence": "LOW"}]}
        new = {"actor_name": "APT28", "techniques": [{"technique_id": "T1566", "confidence": "LOW"}]}
        result = diff_profiles(old, new)
        assert result["techniques"]["added"] == []
        assert result["techniques"]["removed"] == []


class TestIndicatorDiff:

    def test_identity_is_type_plus_value(self):
        old = {"actor_name": "A", "indicators": [ioc("ip", "1.1.1.1")]}
        new = {"actor_name": "A", "indicators": [ioc("domain", "1.1.1.1")]}
        # Same value, different type — must be treated as two distinct IOCs
        result = diff_profiles(old, new)
        assert len(result["indicators"]["added"]) == 1
        assert len(result["indicators"]["removed"]) == 1

    def test_case_insensitive_value_matching(self):
        old = {"actor_name": "A", "indicators": [ioc("domain", "Evil.com")]}
        new = {"actor_name": "A", "indicators": [ioc("domain", "evil.com")]}
        result = diff_profiles(old, new)
        assert result["indicators"]["added"] == []
        assert result["indicators"]["removed"] == []

    def test_malformed_indicator_without_value_skipped(self):
        old = {"actor_name": "A", "indicators": []}
        new = {"actor_name": "A", "indicators": [{"type": "ip", "value": ""}]}
        result = diff_profiles(old, new)
        assert result["indicators"]["added"] == []


class TestOtherCategories:

    def test_malware_added(self):
        old = {"actor_name": "A", "malware": []}
        new = {"actor_name": "A", "malware": [mal("X-Agent")]}
        result = diff_profiles(old, new)
        assert result["malware"]["added"][0]["name"] == "X-Agent"

    def test_malware_case_insensitive(self):
        old = {"actor_name": "A", "malware": [mal("X-Agent")]}
        new = {"actor_name": "A", "malware": [mal("x-agent")]}
        result = diff_profiles(old, new)
        assert result["malware"]["added"] == []
        assert result["malware"]["removed"] == []

    def test_cve_added_and_removed(self):
        old = {"actor_name": "A", "cves": [cve("CVE-2023-0001")]}
        new = {"actor_name": "A", "cves": [cve("CVE-2024-0002")]}
        result = diff_profiles(old, new)
        assert result["cves"]["added"][0]["cve_id"] == "CVE-2024-0002"
        assert result["cves"]["removed"][0]["cve_id"] == "CVE-2023-0001"

    def test_campaign_added(self):
        old = {"actor_name": "A", "campaigns": []}
        new = {"actor_name": "A", "campaigns": [camp("Operation Ghost")]}
        result = diff_profiles(old, new)
        assert result["campaigns"]["added"][0]["name"] == "Operation Ghost"

    def test_malware_and_campaigns_have_no_confidence_changes_key_absent(self):
        old = {"actor_name": "A", "malware": [mal("X")]}
        new = {"actor_name": "A", "malware": [mal("X")]}
        result = diff_profiles(old, new)
        assert "confidence_changes" not in result["malware"]


class TestHasChanges:

    def test_no_changes_returns_false(self):
        profile = {"actor_name": "A", "techniques": [tech("T1566")]}
        result = diff_profiles(profile, profile)
        assert has_changes(result) is False

    def test_added_item_returns_true(self):
        old = {"actor_name": "A", "techniques": []}
        new = {"actor_name": "A", "techniques": [tech("T1566")]}
        result = diff_profiles(old, new)
        assert has_changes(result) is True

    def test_confidence_change_alone_counts_as_a_change(self):
        old = {"actor_name": "A", "techniques": [tech("T1566", confidence="LOW")]}
        new = {"actor_name": "A", "techniques": [tech("T1566", confidence="HIGH")]}
        result = diff_profiles(old, new)
        assert has_changes(result) is True
