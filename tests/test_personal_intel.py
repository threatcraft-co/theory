"""
tests/test_personal_intel.py
------------------------------
Unit tests for collectors/personal_intel.py — the gitignored personal
research redirect pattern. Fully offline; every test points REDIRECT_PATH
and DEFAULT_PERSONAL_PATH at tmp_path so nothing touches a real
config/local_sources.yaml or ~/.theory/.
"""

from __future__ import annotations

import pytest

import collectors.personal_intel as pi


@pytest.fixture(autouse=True)
def isolated_paths(tmp_path, monkeypatch):
    """Redirect both the redirect file and the default personal file into
    tmp_path for every test in this module."""
    monkeypatch.setattr(pi, "REDIRECT_PATH", tmp_path / "config" / "local_sources.yaml")
    monkeypatch.setattr(pi, "DEFAULT_PERSONAL_PATH", tmp_path / "home" / ".theory" / "personal_indicators.yaml")
    return tmp_path


class TestInitPersonal:

    def test_creates_redirect_and_default_file(self, isolated_paths):
        target = pi.init_personal()
        assert pi.REDIRECT_PATH.exists()
        assert target == pi.DEFAULT_PERSONAL_PATH.resolve()
        assert target.exists()

    def test_redirect_contains_resolved_path(self, isolated_paths):
        target = pi.init_personal()
        content = pi.REDIRECT_PATH.read_text()
        assert str(target) in content

    def test_custom_path_used_when_given(self, isolated_paths, tmp_path):
        custom = tmp_path / "custom" / "my_research.yaml"
        target = pi.init_personal(str(custom))
        assert target == custom.resolve()
        assert custom.exists()

    def test_does_not_overwrite_existing_personal_file(self, isolated_paths):
        pi.init_personal()
        target = pi.DEFAULT_PERSONAL_PATH
        target.write_text("indicators:\n  - type: ip\n    value: 1.2.3.4\n    actor: APT28\n")
        pi.init_personal()  # re-run — must not clobber what's there
        assert "1.2.3.4" in target.read_text()

    def test_rerun_can_repoint_redirect(self, isolated_paths, tmp_path):
        pi.init_personal()
        new_target = tmp_path / "elsewhere" / "notes.yaml"
        result = pi.init_personal(str(new_target))
        assert result == new_target.resolve()
        assert str(new_target.resolve()) in pi.REDIRECT_PATH.read_text()


class TestLoadRedirect:

    def test_not_set_up_returns_none(self, isolated_paths):
        assert pi._load_redirect() is None

    def test_returns_configured_path(self, isolated_paths):
        pi.init_personal()
        assert pi._load_redirect() == pi.DEFAULT_PERSONAL_PATH.resolve()

    def test_corrupt_redirect_returns_none(self, isolated_paths):
        pi.REDIRECT_PATH.parent.mkdir(parents=True, exist_ok=True)
        pi.REDIRECT_PATH.write_text("not: valid: yaml: [[[")
        assert pi._load_redirect() is None


class TestQuery:

    def test_not_set_up_returns_none(self, isolated_paths):
        collector = pi.PersonalIntelCollector()
        assert collector.query("APT28") is None

    def test_matches_indicator_by_exact_actor_name(self, isolated_paths):
        target = pi.init_personal()
        target.write_text(
            "indicators:\n"
            "  - type: ip\n"
            "    value: \"198.51.100.23\"\n"
            "    actor: \"APT28\"\n"
            "    context: \"lab finding\"\n"
        )
        result = pi.PersonalIntelCollector().query("APT28")
        assert result is not None
        assert result["source_id"] == "personal"
        assert result["indicators"][0]["value"] == "198.51.100.23"
        assert result["indicators"][0]["sources"] == ["personal"]

    def test_matches_via_alias_resolution(self, isolated_paths):
        target = pi.init_personal()
        target.write_text(
            "indicators:\n"
            "  - type: domain\n"
            "    value: \"evil-c2.example\"\n"
            "    actor: \"Fancy Bear\"\n"
        )
        # Querying under the canonical name must match an entry tagged
        # with an alias, and vice versa.
        result = pi.PersonalIntelCollector().query("APT28")
        assert result is not None
        assert result["indicators"][0]["value"] == "evil-c2.example"

    def test_unattributed_indicators_never_surface(self, isolated_paths):
        target = pi.init_personal()
        target.write_text(
            "indicators:\n"
            "  - type: ip\n"
            "    value: \"9.9.9.9\"\n"  # no actor tag
        )
        result = pi.PersonalIntelCollector().query("APT28")
        assert result is None

    def test_other_actors_indicators_not_matched(self, isolated_paths):
        target = pi.init_personal()
        target.write_text(
            "indicators:\n"
            "  - type: ip\n"
            "    value: \"1.1.1.1\"\n"
            "    actor: \"Lazarus Group\"\n"
        )
        result = pi.PersonalIntelCollector().query("APT28")
        assert result is None

    def test_malformed_entry_skipped_not_fatal(self, isolated_paths):
        target = pi.init_personal()
        target.write_text(
            "indicators:\n"
            "  - type: not_a_real_type\n"
            "    value: \"x\"\n"
            "    actor: \"APT28\"\n"
            "  - type: ip\n"
            "    value: \"2.2.2.2\"\n"
            "    actor: \"APT28\"\n"
        )
        result = pi.PersonalIntelCollector().query("APT28")
        assert result is not None
        assert len(result["indicators"]) == 1
        assert result["indicators"][0]["value"] == "2.2.2.2"

    def test_empty_indicators_list_returns_none(self, isolated_paths):
        pi.init_personal()  # writes the default empty-list template
        result = pi.PersonalIntelCollector().query("APT28")
        assert result is None

    def test_redirect_points_to_missing_file_returns_none(self, isolated_paths, tmp_path):
        pi.REDIRECT_PATH.parent.mkdir(parents=True, exist_ok=True)
        missing = tmp_path / "gone.yaml"
        pi.REDIRECT_PATH.write_text(f'personal_indicators_path: "{missing}"\n')
        result = pi.PersonalIntelCollector().query("APT28")
        assert result is None

    def test_indicators_not_a_list_returns_none(self, isolated_paths):
        target = pi.init_personal()
        target.write_text("indicators: \"not a list\"\n")
        result = pi.PersonalIntelCollector().query("APT28")
        assert result is None
