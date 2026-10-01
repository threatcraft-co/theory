"""
tests/test_intelligence_agent.py
-----------------------------------
Unit tests for collectors/intelligence_agent.py — the provider-agnostic
tool-calling loop behind `theory ask`. Fully offline: every test uses a
StubProvider instead of a real LLM, and every tool call is backed by a
tmp_path graph/personal file, never the real output/graph.json or
~/.theory/.
"""

from __future__ import annotations

import pytest

import collectors.intelligence_agent as agent
import processors.graph as graph_module
from processors.graph import GraphStore, ingest_profile


class StubProvider:
    """Replays a scripted sequence of `complete()` responses, one per
    call, so a test can script an exact multi-turn tool-calling
    conversation without any network access."""

    def __init__(self, responses: list[str]):
        self._responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    @property
    def available(self) -> bool:
        return True

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if not self._responses:
            raise AssertionError("StubProvider ran out of scripted responses")
        return self._responses.pop(0)


class UnavailableProvider:
    available = False

    def complete(self, system: str, user: str) -> str:  # pragma: no cover
        raise AssertionError("should never be called when unavailable")


@pytest.fixture(autouse=True)
def isolated_graph(tmp_path, monkeypatch):
    path = tmp_path / "graph.json"
    monkeypatch.setattr(graph_module, "GRAPH_PATH", path)
    store = GraphStore(path=path)
    ingest_profile(
        {
            "actor_name": "APT28",
            "indicators": [{"type": "ip", "value": "1.1.1.1", "sources": ["otx"]}],
            "techniques": [{"technique_id": "T1566", "technique_name": "Phishing", "sources": ["mitre"]}],
        },
        store=store,
    )
    store.save()
    return store


class TestAskNoProvider:

    def test_unavailable_provider_returns_message_without_calling(self):
        result = agent.ask("anything", provider=UnavailableProvider())
        assert "No LLM provider" in result

    def test_none_provider_with_no_configured_provider(self, monkeypatch):
        import collectors.intelligence_synthesizer as synth
        monkeypatch.setattr(synth, "load_provider", lambda: None)
        result = agent.ask("anything", provider=None)
        assert "No LLM provider" in result


class TestAskDirectAnswer:

    def test_no_tool_call_returns_reply_immediately(self):
        stub = StubProvider(["This is not in THEORY's data."])
        result = agent.ask("something unrelated", provider=stub)
        assert result == "This is not in THEORY's data."
        assert len(stub.calls) == 1


class TestAskToolCalling:

    def test_single_tool_call_then_final_answer(self):
        stub = StubProvider([
            "TOOL: query_ioc 1.1.1.1",
            "1.1.1.1 is linked to APT28 (source: otx).",
        ])
        result = agent.ask("what do we know about 1.1.1.1?", provider=stub)
        assert result == "1.1.1.1 is linked to APT28 (source: otx)."
        assert len(stub.calls) == 2
        # The second call's transcript must contain the tool's JSON result
        assert "found" in stub.calls[1][1]
        assert "APT28" in stub.calls[1][1]

    def test_query_technique_tool(self):
        stub = StubProvider([
            "TOOL: query_technique T1566",
            "APT28 uses T1566 (Phishing).",
        ])
        result = agent.ask("who uses T1566?", provider=stub)
        assert result == "APT28 uses T1566 (Phishing)."

    def test_query_actor_tool(self):
        stub = StubProvider([
            "TOOL: query_actor APT28",
            "APT28 has one linked IOC and one linked technique.",
        ])
        result = agent.ask("summarize APT28", provider=stub)
        assert result == "APT28 has one linked IOC and one linked technique."

    def test_query_personal_tool_not_set_up(self, tmp_path, monkeypatch):
        import collectors.personal_intel as pi
        monkeypatch.setattr(pi, "REDIRECT_PATH", tmp_path / "config" / "local_sources.yaml")
        stub = StubProvider([
            "TOOL: query_personal APT28",
            "You have no personal notes on APT28 yet.",
        ])
        result = agent.ask("what are my own notes on APT28?", provider=stub)
        assert result == "You have no personal notes on APT28 yet."

    def test_multi_turn_tool_calls(self):
        stub = StubProvider([
            "TOOL: query_actor APT28",
            "TOOL: query_ioc 1.1.1.1",
            "APT28 is linked to 1.1.1.1 via otx.",
        ])
        result = agent.ask("is APT28 connected to 1.1.1.1?", provider=stub)
        assert result == "APT28 is linked to 1.1.1.1 via otx."
        assert len(stub.calls) == 3

    def test_unknown_tool_name_reported_back_to_model(self):
        stub = StubProvider([
            "TOOL: delete_everything oops",
            "I don't have that tool — final answer: no.",
        ])
        result = agent.ask("do something destructive", provider=stub)
        assert result == "I don't have that tool — final answer: no."
        assert "Unknown tool" in stub.calls[1][1]

    def test_missing_argument_reported_back_to_model(self):
        stub = StubProvider([
            "TOOL: query_ioc",
            "I need a value to look up.",
        ])
        result = agent.ask("look something up", provider=stub)
        assert result == "I need a value to look up."
        assert "requires an argument" in stub.calls[1][1]

    def test_tool_exception_does_not_crash_the_loop(self, monkeypatch):
        def _boom(arg):
            raise RuntimeError("simulated failure")
        monkeypatch.setitem(agent.TOOLS, "query_ioc", _boom)
        stub = StubProvider([
            "TOOL: query_ioc 1.1.1.1",
            "That tool failed, but I can still respond.",
        ])
        result = agent.ask("what about 1.1.1.1", provider=stub)
        assert result == "That tool failed, but I can still respond."
        assert "error" in stub.calls[1][1]

    def test_provider_exception_returns_error_message(self):
        class BrokenProvider:
            available = True
            def complete(self, system, user):
                raise RuntimeError("network down")
        result = agent.ask("anything", provider=BrokenProvider())
        assert "LLM request failed" in result

    def test_max_turns_exhausted_returns_limit_message(self):
        stub = StubProvider(["TOOL: query_ioc 1.1.1.1"] * 10)
        result = agent.ask("loop forever", provider=stub, max_turns=3)
        assert "tool-call limit" in result
        assert len(stub.calls) == 3

    def test_empty_reply_returns_fallback_message(self):
        stub = StubProvider([""])
        result = agent.ask("anything", provider=stub)
        assert "empty response" in result
