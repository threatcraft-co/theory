"""
Pipeline bridge — runs the same pipeline the CLI uses, with progress callbacks.

INTEGRATION GUIDE
-----------------
This module is the single seam between the web UI and your existing pipeline.
Replace the stubbed steps below with real imports from your pipeline modules.

The callback signature is:
    callback(event: str, data: dict) -> None

Events emitted:
    "started"   — { actor, total_steps }
    "step"      — { step, total, id, description, status:"running" }
    "step_done" — { step, total, id, description, status:"done", duration_ms }
    "complete"  — { actor, output_dir, total_duration_ms, files }
    "error"     — { step_id, message, traceback }

To wire in a real step, replace:

    _stub_delay()

with something like:

    from collectors import otx
    raw = otx.collect(actor, api_key=os.getenv("OTX_API_KEY"))

Each step function receives the actor name, accumulated state from prior steps,
and the options dict from the API request. It returns whatever the next step
needs as input.
"""

from __future__ import annotations

import os
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# Typing alias for the progress callback
ProgressCallback = Callable[[str, dict[str, Any]], None]


# ---------------------------------------------------------------------------
# Step registry
# ---------------------------------------------------------------------------

@dataclass
class PipelineStep:
    """One step in the pipeline sequence."""
    id: str
    description: str
    fn: Callable  # (actor, state, options) -> Any


@dataclass
class PipelineState:
    """Accumulated state passed forward through the pipeline."""
    actor: str
    raw_intel: list[dict[str, Any]] = field(default_factory=list)
    normalized: list[dict[str, Any]] = field(default_factory=list)
    enriched: dict[str, Any] = field(default_factory=dict)
    analysis: dict[str, Any] = field(default_factory=dict)
    correlations: dict[str, Any] = field(default_factory=dict)
    reports: dict[str, str] = field(default_factory=dict)
    output_dir: str = ""


# ---------------------------------------------------------------------------
# Step implementations — replace stubs with real pipeline calls
# ---------------------------------------------------------------------------

def _stub_delay():
    """Simulate work. Remove entirely once real collectors are wired in."""
    time.sleep(1.5)


def step_collect(actor: str, state: PipelineState, options: dict) -> PipelineState:
    """
    Step 1: Collect raw intelligence from enabled sources.

    Integration point:
        from collectors import run_collectors
        from config import load_feeds

        enabled = options.get("sources", [])
        feeds = load_feeds()
        state.raw_intel = run_collectors(actor, enabled_sources=enabled, feeds=feeds)
    """
    _stub_delay()
    # Stub: pretend we got data from 13 sources
    state.raw_intel = [{"source": "stub", "actor": actor, "data": {}}]
    return state


def step_normalize(actor: str, state: PipelineState, options: dict) -> PipelineState:
    """
    Step 2: Normalize raw intelligence into a common schema.

    Integration point:
        from processors.normalizer import normalize
        state.normalized = normalize(state.raw_intel)
    """
    _stub_delay()
    state.normalized = state.raw_intel
    return state


def step_enrich(actor: str, state: PipelineState, options: dict) -> PipelineState:
    """
    Step 3: Enrich with ATT&CK technique mappings.

    Integration point:
        from processors.enricher import enrich
        state.enriched = enrich(state.normalized)
    """
    _stub_delay()
    state.enriched = {"techniques": [], "data": state.normalized}
    return state


def step_analyze(actor: str, state: PipelineState, options: dict) -> PipelineState:
    """
    Step 4: Run AI analysis (LLM pass).

    Integration point:
        from processors.analyzer import analyze
        state.analysis = analyze(state.enriched, model=options.get("model"))
    """
    _stub_delay()
    state.analysis = {"summary": "stub", "enriched": state.enriched}
    return state


def step_correlate(actor: str, state: PipelineState, options: dict) -> PipelineState:
    """
    Step 5.5: Cross-reference across sources (correlator pipeline).

    Integration point:
        from processors.correlator import correlate
        state.correlations = correlate(state.analysis)
    """
    _stub_delay()
    state.correlations = {"cross_refs": [], "analysis": state.analysis}
    return state


def step_report(actor: str, state: PipelineState, options: dict) -> PipelineState:
    """
    Step 6: Generate output reports in selected formats.

    Integration point:
        from reporters import generate_reports
        formats = options.get("formats", ["all"])
        output_dir = generate_reports(
            actor, state.correlations, state.analysis, formats=formats
        )
        state.output_dir = str(output_dir)
        state.reports = {f.name: str(f) for f in output_dir.iterdir() if f.is_file()}
    """
    _stub_delay()
    # Stub output directory
    project_root = Path(__file__).resolve().parent.parent
    output_dir = project_root / "output" / "dossiers" / actor.replace(" ", "_")
    output_dir.mkdir(parents=True, exist_ok=True)
    state.output_dir = str(output_dir)
    state.reports = {}
    return state


# Ordered pipeline. This matches the CLI's step sequence exactly.
PIPELINE_STEPS: list[PipelineStep] = [
    PipelineStep("collect",    "Collecting intelligence",         step_collect),
    PipelineStep("normalize",  "Normalizing collected data",      step_normalize),
    PipelineStep("enrich",     "Enriching with ATT&CK mappings",  step_enrich),
    PipelineStep("analyze",    "Running AI analysis",             step_analyze),
    PipelineStep("correlate",  "Cross-referencing sources",       step_correlate),
    PipelineStep("report",     "Generating output reports",       step_report),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_pipeline(
    actor: str,
    options: dict[str, Any],
    callback: ProgressCallback,
) -> PipelineState:
    """
    Execute the full pipeline with progress callbacks.

    This runs synchronously — the web server calls it inside
    asyncio.to_thread() so the event loop stays free.

    Args:
        actor:    Threat actor name (e.g. "APT28").
        options:  Dict from the API request body (sources, formats, etc.).
        callback: Progress callback — called with (event_type, data_dict).

    Returns:
        Final PipelineState with all accumulated results.

    Raises:
        Exception: Re-raises any step exception after sending an error event.
    """
    state = PipelineState(actor=actor)
    total = len(PIPELINE_STEPS)
    t_start = time.monotonic()

    callback("started", {"actor": actor, "total_steps": total})

    for i, step in enumerate(PIPELINE_STEPS, 1):
        callback("step", {
            "step": i,
            "total": total,
            "id": step.id,
            "description": step.description,
            "status": "running",
        })

        t_step = time.monotonic()
        try:
            state = step.fn(actor, state, options)
        except Exception as exc:
            callback("error", {
                "step_id": step.id,
                "message": str(exc),
                "traceback": traceback.format_exc(),
            })
            raise

        elapsed_ms = int((time.monotonic() - t_step) * 1000)
        callback("step_done", {
            "step": i,
            "total": total,
            "id": step.id,
            "description": step.description,
            "status": "done",
            "duration_ms": elapsed_ms,
        })

    total_ms = int((time.monotonic() - t_start) * 1000)
    output_files = []
    if state.output_dir:
        out = Path(state.output_dir)
        if out.is_dir():
            output_files = sorted(f.name for f in out.iterdir() if f.is_file())

    callback("complete", {
        "actor": actor,
        "output_dir": state.output_dir,
        "total_duration_ms": total_ms,
        "files": output_files,
    })

    return state
