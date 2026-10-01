"""
tests/test_watch.py
---------------------
Unit tests for theory._cli.run_watch — the `theory --actor X --watch`
loop. Fully offline and instant: a stub run_fn replaces the real
collection pipeline, and sleep_fn is a no-op, so no test actually waits
or hits the network.
"""

from __future__ import annotations

from theory._cli import run_watch


def make_profile(technique_ids):
    return {
        "actor_name": "APT28",
        "techniques": [{"technique_id": tid, "confidence": "MEDIUM"} for tid in technique_ids],
        "malware": [], "indicators": [], "cves": [], "campaigns": [],
    }


class TestRunWatchBasics:

    def test_calls_run_fn_max_iterations_times(self):
        calls = []
        def stub_run(**kwargs):
            calls.append(kwargs)
            return make_profile(["T1566"])

        run_watch("APT28", ["mitre"], interval=1, max_iterations=3,
                  sleep_fn=lambda s: None, run_fn=stub_run)
        assert len(calls) == 3

    def test_passes_actor_and_sources_through(self):
        received = {}
        def stub_run(**kwargs):
            received.update(kwargs)
            return make_profile([])

        run_watch("APT28", ["mitre", "cisa"], interval=1, max_iterations=1,
                  sleep_fn=lambda s: None, run_fn=stub_run)
        assert received["actor"] == "APT28"
        assert received["sources"] == ["mitre", "cisa"]

    def test_forces_json_output_and_quiet(self):
        received = {}
        def stub_run(**kwargs):
            received.update(kwargs)
            return make_profile([])

        run_watch("APT28", ["mitre"], interval=1, max_iterations=1,
                  sleep_fn=lambda s: None, run_fn=stub_run)
        assert received["output"] == "json"
        assert received["save"] is True
        assert received["quiet"] is True

    def test_sleeps_between_iterations_not_after_last(self):
        sleep_calls = []
        run_watch("APT28", ["mitre"], interval=42, max_iterations=3,
                  sleep_fn=lambda s: sleep_calls.append(s),
                  run_fn=lambda **kw: make_profile([]))
        # 3 iterations -> 2 sleeps (never sleeps after the final one)
        assert sleep_calls == [42, 42]

    def test_zero_iterations_calls_nothing(self):
        calls = []
        run_watch("APT28", ["mitre"], interval=1, max_iterations=0,
                  sleep_fn=lambda s: None, run_fn=lambda **kw: calls.append(1))
        assert calls == []


class TestRunWatchDiffing:

    def test_first_iteration_has_nothing_to_diff(self, capsys):
        run_watch("APT28", ["mitre"], interval=1, max_iterations=1,
                  sleep_fn=lambda s: None, run_fn=lambda **kw: make_profile(["T1566"]))
        out = capsys.readouterr().out
        assert "nothing to diff" in out or "First check" in out

    def test_second_iteration_reports_added_technique(self, capsys):
        results = [make_profile(["T1566"]), make_profile(["T1566", "T1078"])]
        def stub_run(**kwargs):
            return results.pop(0)

        run_watch("APT28", ["mitre"], interval=1, max_iterations=2,
                  sleep_fn=lambda s: None, run_fn=stub_run)
        out = capsys.readouterr().out
        assert "T1078" in out

    def test_no_change_between_iterations_reported_as_no_changes(self, capsys):
        profile = make_profile(["T1566"])
        run_watch("APT28", ["mitre"], interval=1, max_iterations=2,
                  sleep_fn=lambda s: None, run_fn=lambda **kw: profile)
        out = capsys.readouterr().out
        assert "No changes" in out

    def test_failed_run_handled_gracefully(self, capsys):
        def stub_run(**kwargs):
            raise RuntimeError("simulated collection failure")

        run_watch("APT28", ["mitre"], interval=1, max_iterations=2,
                  sleep_fn=lambda s: None, run_fn=stub_run)
        out = capsys.readouterr().out
        assert "Run failed" in out

    def test_run_returning_none_handled_gracefully(self, capsys):
        run_watch("APT28", ["mitre"], interval=1, max_iterations=1,
                  sleep_fn=lambda s: None, run_fn=lambda **kw: None)
        out = capsys.readouterr().out
        assert "Run failed or returned no data" in out
