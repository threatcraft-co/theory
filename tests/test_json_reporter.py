"""
tests/test_json_reporter.py
-----------------------------
Unit tests for reporters/json_reporter.py — specifically the snapshot
rotation (.json -> .previous.json) that backs `theory diff`.
"""

from __future__ import annotations

import json

import reporters.json_reporter as jr
from reporters.json_reporter import JsonReporter


class TestSave:

    def test_writes_json_file_named_by_slug(self, tmp_path, monkeypatch):
        monkeypatch.setattr(jr, "OUTPUT_DIR", tmp_path)
        path = JsonReporter().save({"actor_name": "APT28", "techniques": []})
        assert path == tmp_path / "apt28.json"
        assert json.loads(path.read_text())["actor_name"] == "APT28"

    def test_slug_replaces_spaces(self, tmp_path, monkeypatch):
        monkeypatch.setattr(jr, "OUTPUT_DIR", tmp_path)
        path = JsonReporter().save({"actor_name": "Lazarus Group"})
        assert path.name == "lazarus_group.json"


class TestSnapshotRotation:

    def test_first_save_has_no_previous_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(jr, "OUTPUT_DIR", tmp_path)
        JsonReporter().save({"actor_name": "APT28", "techniques": []})
        assert not (tmp_path / "apt28.previous.json").exists()

    def test_second_save_rotates_first_into_previous(self, tmp_path, monkeypatch):
        monkeypatch.setattr(jr, "OUTPUT_DIR", tmp_path)
        reporter = JsonReporter()
        reporter.save({"actor_name": "APT28", "techniques": [{"technique_id": "T1566"}]})
        reporter.save({"actor_name": "APT28", "techniques": [{"technique_id": "T1566"}, {"technique_id": "T1078"}]})

        previous = json.loads((tmp_path / "apt28.previous.json").read_text())
        current  = json.loads((tmp_path / "apt28.json").read_text())

        assert len(previous["techniques"]) == 1
        assert len(current["techniques"]) == 2

    def test_third_save_rotates_second_not_first(self, tmp_path, monkeypatch):
        monkeypatch.setattr(jr, "OUTPUT_DIR", tmp_path)
        reporter = JsonReporter()
        reporter.save({"actor_name": "APT28", "techniques": [{"technique_id": "A"}]})
        reporter.save({"actor_name": "APT28", "techniques": [{"technique_id": "A"}, {"technique_id": "B"}]})
        reporter.save({"actor_name": "APT28", "techniques": [{"technique_id": "A"}, {"technique_id": "B"}, {"technique_id": "C"}]})

        previous = json.loads((tmp_path / "apt28.previous.json").read_text())
        assert len(previous["techniques"]) == 2  # the second save's content, not the first's
