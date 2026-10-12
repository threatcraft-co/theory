"""
Pipeline bridge — calls _cli.run() directly.

This is a thin wrapper that runs the same pipeline as the CLI
and pushes SSE events for the web UI. The real work happens
inside _cli.run(); this module just manages the async boundary
and progress events.
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Typing alias for the progress callback
ProgressCallback = Callable[[str, dict[str, Any]], None]


def _ensure_cli_importable() -> None:
    """Add project root to sys.path if not already there."""
    project_root = str(Path(__file__).resolve().parent.parent)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

def _resolve_source_key(ui_id: str) -> str | None:
    """Map a web UI source id to a canonical source key.

    Was a hand-maintained dict here; aliases now live with the source
    definition in theory.sources so there is one place to update.
    """
    from theory.sources import resolve
    spec = resolve(ui_id)
    return spec.key if spec else None


# Map of web UI format IDs → _cli.py --output values
FORMAT_ID_MAP: dict[str, str] = {
    "markdown":  "dossier",
    "stix":      "stix",
    "csv":       "csv",
    "json":      "json",
    "navigator": "navigator",
    "executive": "exec",
    "sigma":     "dossier",     # sigma gap is via --detection-path, not --output
    "playbook":  "playbook",
    "html":      "html",
    "all":       "all",
}


def _resolve_sources(ui_sources: list[str]) -> list[str]:
    """Map web UI source IDs to canonical source keys.

    An empty selection means "the defaults", not "no sources at all" —
    passing [] through produced a run with zero collectors and a
    misleading "No data found for actor" error.
    """
    from theory.sources import DEFAULT_SOURCES

    if not ui_sources:
        return list(DEFAULT_SOURCES)

    resolved: list[str] = []
    seen: set[str] = set()
    for sid in ui_sources:
        key = _resolve_source_key(sid)
        if key is None:
            logger.warning("Ignoring unknown source from the web UI: %r", sid)
            continue
        if key not in seen:
            seen.add(key)
            resolved.append(key)
    return resolved or list(DEFAULT_SOURCES)


def _resolve_output(ui_formats: list[str]) -> str:
    """Map web UI format selections to a single _cli.py --output value."""
    if "all" in ui_formats:
        return "all"
    if len(ui_formats) == 1:
        return FORMAT_ID_MAP.get(ui_formats[0], "dossier")
    # Multiple formats selected → use "all" (simplest correct behavior)
    return "all"


def _find_latest_dossier(actor: str, before_dirs: set[str]) -> str | None:
    """Find the dossier directory that appeared after the pipeline ran."""
    output_dir = Path("output/dossiers")
    if not output_dir.is_dir():
        return None
    current_dirs = {d.name for d in output_dir.iterdir() if d.is_dir()}
    new_dirs = current_dirs - before_dirs
    if new_dirs:
        # Return the newest one
        return str(output_dir / sorted(new_dirs)[-1])
    # Fallback: look for a directory matching the actor name
    actor_slug = actor.lower().replace(" ", "_")
    for d in sorted(output_dir.iterdir(), reverse=True):
        if d.is_dir() and actor_slug in d.name.lower():
            return str(d)
    return None


def run_pipeline(
    actor: str,
    options: dict[str, Any],
    callback: ProgressCallback,
) -> dict[str, Any] | None:
    """
    Execute the THEORY pipeline by calling _cli.run() directly.

    This runs synchronously — the web server calls it inside
    asyncio.to_thread() so the event loop stays free.

    Args:
        actor:    Threat actor name.
        options:  Dict from the API request body (sources, formats).
        callback: Progress callback for SSE events.

    Returns:
        The profile dict from _cli.run(), or None on failure.
    """
    _ensure_cli_importable()

    try:
        from theory._cli import run
    except ImportError as e:
        # Tracebacks are logged server-side, not streamed to the browser:
        # they carry absolute paths, environment details and sometimes
        # argument values, and this stream is reachable from a page the
        # user merely visited.
        logger.error("Pipeline import failed", exc_info=True)
        callback("error", {
            "step_id": "import",
            "message": f"Could not import theory._cli.run: {e}. Make sure THEORY is installed.",
        })
        raise RuntimeError(f"Pipeline import failed: {e}") from e

    ui_sources = options.get("sources", [])
    ui_formats = options.get("formats", ["all"])

    sources = _resolve_sources(ui_sources)
    output_format = _resolve_output(ui_formats)

    callback("started", {"actor": actor, "total_steps": 1})
    callback("step", {
        "step": 1,
        "total": 1,
        "id": "pipeline",
        "description": f"Running pipeline for {actor}",
        "status": "running",
    })

    # Snapshot existing dossier directories so we can detect the new one
    output_dir = Path("output/dossiers")
    before_dirs = set()
    if output_dir.is_dir():
        before_dirs = {d.name for d in output_dir.iterdir() if d.is_dir()}

    t_start = time.monotonic()

    try:
        logger.info("Running pipeline for actor=%r sources=%s format=%s",
                    actor, sources, output_format)
        profile = run(
            actor=actor,
            sources=sources,
            output=output_format,
            save=True,
            verbose=False,
        )
    except Exception as exc:
        logger.error("Pipeline failed for actor=%r", actor, exc_info=True)
        callback("error", {
            "step_id": "pipeline",
            "message": str(exc),
        })
        raise

    elapsed_ms = int((time.monotonic() - t_start) * 1000)

    if profile is None:
        callback("error", {
            "step_id": "pipeline",
            "message": f"No data found for actor: {actor}",
        })
        return None

    # Find the output directory and list files
    dossier_path = _find_latest_dossier(actor, before_dirs)
    output_files = []
    if dossier_path:
        p = Path(dossier_path)
        if p.is_dir():
            output_files = sorted(f.name for f in p.iterdir() if f.is_file())

    callback("step_done", {
        "step": 1,
        "total": 1,
        "id": "pipeline",
        "description": f"Running pipeline for {actor}",
        "status": "done",
        "duration_ms": elapsed_ms,
    })

    callback("complete", {
        "actor": actor,
        "output_dir": dossier_path or "",
        "total_duration_ms": elapsed_ms,
        "files": output_files,
    })

    return profile
