"""
collectors/intelligence_agent.py
----------------------------------
Tool-calling layer for THEORY's LLM synthesis — `theory ask "<question>"`.

collectors/intelligence_synthesizer.py gives THEORY three LLM providers
(Claude, OpenAI, Ollama), but each exposes `complete(system, user) -> str`
— plain text completion, no tool use. Building this against each
provider's NATIVE tool-calling API (Claude's tool_use blocks, OpenAI's
function-calling schema, Ollama's more limited and still-evolving
support) would mean three separate, mutually incompatible integrations —
a lot of surface area to get subtly wrong, and none of it exercisable in
an offline sandbox with no live API keys.

Instead this uses a provider-agnostic ReAct-style TEXT protocol, on top
of the `complete()` interface every provider already has:

  1. The system prompt tells the model which tools exist and the exact
     line format to request one: `TOOL: <name> <argument>`.
  2. THEORY parses that line, calls the matching local function, and
     feeds the result back as the next turn.
  3. The model either calls another tool or gives a final plain-prose
     answer (no TOOL: line) — that's the signal to stop.

Every tool here is a *local, offline lookup* — the persistent correlation
graph (processors/graph.py) and the user's own personal research file
(collectors/personal_intel.py). No tool call reaches the network. This
means `theory ask` only ever answers from what THEORY has actually
collected and recorded, never from the model's own training data passed
off as current threat intel — which matters a great deal for a tool
whose entire premise is grounded, sourced answers.

Tools:
  query_ioc <value>        -> processors.graph.query_ioc
  query_technique <id>     -> processors.graph.query_technique
  query_actor <name>       -> processors.graph.query_actor
  query_personal <name>    -> the user's own local research notes for that actor
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable

logger = logging.getLogger(__name__)

MAX_TOOL_TURNS = 5

_TOOL_LINE_RE = re.compile(r"^\s*TOOL:\s*(\S+)\s*(.*)$", re.IGNORECASE)

SYSTEM_PROMPT = """\
You are THEORY's research assistant. THEORY is a local, offline threat-
intelligence tool — you must answer ONLY from what it has actually
recorded, never from general knowledge, and say plainly when something
is not in its data rather than guessing.

You have four tools, each a local lookup against THEORY's own persistent
correlation graph or the user's personal research notes — not the
internet:

  query_ioc <value>       - what THEORY has recorded about an indicator
                             (IP, domain, hash, URL, email), and which
                             actors/malware/techniques/CVEs it links to.
  query_technique <id>    - which actors and CVEs THEORY has linked to
                             an ATT&CK technique ID (e.g. T1566).
  query_actor <name>      - everything THEORY's graph has recorded for
                             an actor: linked IOCs, techniques, malware,
                             CVEs, campaigns.
  query_personal <name>   - the user's own local research notes tagged
                             to that actor (private, local-only data).

To call a tool, respond with EXACTLY one line, nothing else:
  TOOL: <tool_name> <argument>

You will then be given that tool's result as plain JSON and can call
another tool, or give your final answer. When you have enough
information (or a tool says something was not found and that itself
answers the question), respond with your final answer as plain prose —
no TOOL: line — citing which tool(s) you used.
"""


# ---------------------------------------------------------------------------
# Tools — every one a local, offline lookup
# ---------------------------------------------------------------------------

def _tool_query_ioc(arg: str) -> dict[str, Any]:
    from processors.graph import query_ioc
    return query_ioc(arg)


def _tool_query_technique(arg: str) -> dict[str, Any]:
    from processors.graph import query_technique
    return query_technique(arg)


def _tool_query_actor(arg: str) -> dict[str, Any]:
    from processors.graph import query_actor
    return query_actor(arg)


def _tool_query_personal(arg: str) -> dict[str, Any]:
    from collectors.personal_intel import PersonalIntelCollector
    result = PersonalIntelCollector().query(arg)
    if result is None:
        return {"found": False, "actor_name": arg.strip()}
    return {
        "found":      True,
        "actor_name": result.get("actor_name", arg.strip()),
        "indicators": result.get("indicators", []),
    }


TOOLS: dict[str, Callable[[str], Any]] = {
    "query_ioc":       _tool_query_ioc,
    "query_technique": _tool_query_technique,
    "query_actor":     _tool_query_actor,
    "query_personal":  _tool_query_personal,
}


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------

def _format_tool_result(name: str, arg: str, result: Any) -> str:
    return f"[Result of {name} {arg!r}]\n{json.dumps(result, indent=2, default=str)}"


def ask(question: str, provider: Any = None, max_turns: int = MAX_TOOL_TURNS) -> str:
    """Run THEORY's tool-calling loop for a natural-language question.

    `provider` is anything with THEORY's LLMProvider interface
    (`.available` and `.complete(system, user) -> str`) — normally
    omitted, in which case the configured provider from
    collectors.intelligence_synthesizer.load_provider() is used. Tests
    pass a stub provider here instead of hitting a real API.
    """
    if provider is None:
        from collectors.intelligence_synthesizer import load_provider
        provider = load_provider()

    if provider is None or not getattr(provider, "available", False):
        return (
            "No LLM provider is configured, so `theory ask` can't run. "
            "Set ANTHROPIC_API_KEY or OPENAI_API_KEY in .env, or run Ollama locally."
        )

    transcript = question
    for turn in range(max_turns):
        try:
            reply = provider.complete(SYSTEM_PROMPT, transcript)
        except Exception as exc:
            logger.warning("ask: provider call failed on turn %d: %s", turn, exc)
            return f"LLM request failed: {exc}"

        reply = (reply or "").strip()
        first_line = reply.splitlines()[0] if reply else ""
        match = _TOOL_LINE_RE.match(first_line)

        if not match:
            return reply or "The model returned an empty response."

        tool_name = match.group(1).strip().lower()
        arg       = match.group(2).strip()
        tool_fn   = TOOLS.get(tool_name)

        if tool_fn is None:
            transcript = (
                f"{transcript}\n\n[Unknown tool {tool_name!r}. "
                f"Available tools: {', '.join(sorted(TOOLS))}]"
            )
            continue
        if not arg:
            transcript = f"{transcript}\n\n[Tool {tool_name!r} requires an argument — none was given.]"
            continue

        try:
            result = tool_fn(arg)
        except Exception as exc:
            logger.warning("ask: tool %r failed: %s", tool_name, exc)
            result = {"error": str(exc)}

        transcript = f"{transcript}\n\n{_format_tool_result(tool_name, arg, result)}"

    return (
        f"Reached the tool-call limit ({max_turns}) without a final answer. "
        "Try a narrower question."
    )
