"""
THEORY Web UI — FastAPI backend.

Wraps the same pipeline functions the CLI uses.
Runs on localhost only; nothing leaves the machine except API calls
to the intelligence sources you've configured.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

from .pipeline import run_pipeline

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SERVER_DIR = Path(__file__).resolve().parent
STATIC_DIR = SERVER_DIR / "static"
PROJECT_ROOT = SERVER_DIR.parent
OUTPUT_DIR = PROJECT_ROOT / "output" / "dossiers"
CONFIG_DIR = PROJECT_ROOT / "config"
FEEDS_YAML = CONFIG_DIR / "feeds.yaml"
ENV_FILE = PROJECT_ROOT / ".env"

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="THEORY",
    description="Local threat-intelligence dossier generator",
    docs_url="/api/docs",
    redoc_url=None,
)

# ---------------------------------------------------------------------------
# In-memory job registry
#
# This is fine for a single-user localhost tool. Jobs are keyed by UUID and
# hold a queue of SSE events. Completed jobs stay in memory until the server
# restarts (they don't need persistence — the output files are on disk).
# ---------------------------------------------------------------------------

jobs: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_env() -> dict[str, str]:
    """Parse .env into an ordered dict. Handles quoting and comments."""
    env: dict[str, str] = {}
    if not ENV_FILE.is_file():
        return env
    for line in ENV_FILE.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, _, val = stripped.partition("=")
        key = key.strip()
        val = val.strip()
        # Strip surrounding quotes
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        env[key] = val
    return env


def _write_env(env: dict[str, str]) -> None:
    """Write env dict back to .env file."""
    lines: list[str] = []
    for k, v in env.items():
        # Quote values that contain spaces or special chars
        if " " in v or "#" in v or "'" in v:
            lines.append(f'{k}="{v}"')
        else:
            lines.append(f"{k}={v}")
    ENV_FILE.write_text("\n".join(lines) + "\n")


def _mask(value: str) -> str:
    """Mask an API key for display: show first 4 and last 4 chars."""
    if len(value) <= 8:
        return "\u2022" * len(value)
    return value[:4] + "\u2022" * (len(value) - 8) + value[-4:]


def _load_sources() -> list[dict[str, Any]]:
    """
    Build the source list from _cli.py's real registry + config/feeds.yaml.
    """
    sources: list[dict[str, Any]] = []

    try:
        from _cli import SUPPORTED_SOURCES, SOURCE_DESCRIPTIONS, ENRICHMENT_SOURCES

        for key, dotted in SUPPORTED_SOURCES.items():
            src_type = "enrichment" if key in ENRICHMENT_SOURCES else "collector"
            sources.append({
                "id": key,
                "name": SOURCE_DESCRIPTIONS.get(key, key),
                "enabled": True,
                "type": src_type,
            })
    except ImportError:
        # Fallback if _cli can't be imported (shouldn't happen in normal use)
        pass

    # RSS feeds from config/feeds.yaml
    if FEEDS_YAML.is_file():
        try:
            with open(FEEDS_YAML) as f:
                feeds_config = yaml.safe_load(f) or {}
            feeds = feeds_config.get("feeds", [])
            if isinstance(feeds, list):
                for feed in feeds:
                    sources.append({
                        "id": f"rss_{feed.get('id', feed.get('name', '').lower().replace(' ', '_'))}",
                        "name": feed.get("name", "Unknown Feed"),
                        "enabled": feed.get("enabled", True),
                        "type": "feed",
                        "url": feed.get("url", ""),
                    })
        except Exception:
            pass

    return sources


def _list_dossiers() -> list[dict[str, Any]]:
    """Scan output/dossiers/ for past runs, newest first."""
    if not OUTPUT_DIR.is_dir():
        return []
    results: list[dict[str, Any]] = []
    for entry in sorted(OUTPUT_DIR.iterdir(), reverse=True):
        if not entry.is_dir():
            continue
        files = sorted(f.name for f in entry.iterdir() if f.is_file())
        if not files:
            continue
        stat = entry.stat()
        results.append({
            "name": entry.name,
            "created": datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc
            ).isoformat(),
            "file_count": len(files),
            "files": files,
            "total_size": sum(f.stat().st_size for f in entry.iterdir() if f.is_file()),
        })
    return results


def _format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------------------
# SSE streaming
# ---------------------------------------------------------------------------

async def _sse_generator(job_id: str):
    """Yield SSE events as the pipeline runs."""
    timeout = 300  # 5 minute hard timeout
    started = asyncio.get_event_loop().time()

    while True:
        if asyncio.get_event_loop().time() - started > timeout:
            yield {"event": "error", "data": json.dumps({"message": "Timeout"})}
            return

        job = jobs.get(job_id)
        if job is None:
            yield {"event": "error", "data": json.dumps({"message": "Job not found"})}
            return

        queue: list[dict] = job.get("event_queue", [])
        while queue:
            evt = queue.pop(0)
            yield {"event": evt["event"], "data": json.dumps(evt["data"])}
            if evt["event"] in ("complete", "error"):
                return

        await asyncio.sleep(0.15)


def _enqueue(job_id: str, event: str, data: dict[str, Any]) -> None:
    """Thread-safe event push. Called from the pipeline thread."""
    job = jobs.get(job_id)
    if job is not None:
        job.setdefault("event_queue", []).append({"event": event, "data": data})


# ---------------------------------------------------------------------------
# Async pipeline launcher
# ---------------------------------------------------------------------------

async def _launch_pipeline(job_id: str, actor: str, options: dict[str, Any]) -> None:
    """Run the pipeline in a thread and push SSE events."""
    try:
        await asyncio.to_thread(
            run_pipeline,
            actor,
            options,
            callback=lambda evt, data: _enqueue(job_id, evt, data),
        )
        jobs[job_id]["status"] = "complete"
    except Exception as exc:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(exc)


# ---------------------------------------------------------------------------
# API: Sources & output formats
# ---------------------------------------------------------------------------

@app.get("/api/sources")
async def get_sources():
    """Available intelligence sources (collectors + RSS feeds)."""
    return {"sources": _load_sources()}


@app.get("/api/formats")
async def get_output_formats():
    """Available output formats. Matches the CLI's --output flag values."""
    return {
        "formats": [
            {"id": "markdown",   "label": "Markdown",            "ext": ".md"},
            {"id": "stix",       "label": "STIX 2.1",            "ext": ".json"},
            {"id": "csv",        "label": "CSV",                  "ext": ".csv"},
            {"id": "json",       "label": "JSON",                 "ext": ".json"},
            {"id": "navigator",  "label": "ATT&CK Navigator",    "ext": ".json"},
            {"id": "executive",  "label": "Executive Summary",    "ext": ".md"},
            {"id": "sigma",      "label": "Sigma Gap Analysis",   "ext": ".md"},
            {"id": "playbook",   "label": "Playbook",             "ext": ".md"},
            {"id": "html",       "label": "HTML Report",          "ext": ".html"},
            {"id": "all",        "label": "All Formats",          "ext": ""},
        ]
    }


@app.get("/api/pipeline-steps")
async def get_pipeline_steps():
    """Return the pipeline step(s) for the UI to pre-render."""
    return {
        "steps": [
            {"id": "pipeline", "description": "Running pipeline", "index": 1},
        ]
    }


# ---------------------------------------------------------------------------
# API: Dossier generation
# ---------------------------------------------------------------------------

@app.post("/api/dossier")
async def create_dossier(request: Request):
    """
    Start a dossier generation job.

    Request body:
        {
            "actor": "APT28",
            "sources": ["otx", "misp", "cisa_kev"],   // optional, defaults to all
            "formats": ["html", "stix"],               // optional, defaults to ["all"]
        }

    Returns:
        { "job_id": "..." }

    Subscribe to /api/dossier/{job_id}/progress for SSE events.
    """
    body = await request.json()
    actor = body.get("actor", "").strip()
    if not actor:
        raise HTTPException(status_code=400, detail="actor is required")

    job_id = uuid.uuid4().hex[:12]
    jobs[job_id] = {
        "id": job_id,
        "actor": actor,
        "options": body,
        "status": "running",
        "created": datetime.now(timezone.utc).isoformat(),
        "event_queue": [],
    }

    asyncio.create_task(_launch_pipeline(job_id, actor, body))
    return {"job_id": job_id}


@app.get("/api/dossier/{job_id}/progress")
async def dossier_progress(job_id: str):
    """SSE event stream for a running pipeline job."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return EventSourceResponse(_sse_generator(job_id))


@app.get("/api/dossier/{job_id}")
async def dossier_status(job_id: str):
    """Poll endpoint for job status (alternative to SSE)."""
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "id": job["id"],
        "actor": job["actor"],
        "status": job["status"],
        "created": job["created"],
        "error": job.get("error"),
    }


# ---------------------------------------------------------------------------
# API: History
# ---------------------------------------------------------------------------

@app.get("/api/history")
async def get_history():
    """List all past dossier runs from output/dossiers/."""
    return {"dossiers": _list_dossiers()}


@app.get("/api/history/{name}")
async def get_dossier_detail(name: str):
    """List files in a specific dossier output directory."""
    dossier_dir = OUTPUT_DIR / name
    if not dossier_dir.is_dir():
        raise HTTPException(status_code=404, detail="Dossier not found")

    files = []
    for f in sorted(dossier_dir.iterdir()):
        if not f.is_file():
            continue
        files.append({
            "name": f.name,
            "size": f.stat().st_size,
            "size_display": _format_bytes(f.stat().st_size),
            "ext": f.suffix.lower(),
        })

    return {"name": name, "files": files}


@app.get("/api/history/{name}/{filename}")
async def serve_dossier_file(name: str, filename: str):
    """
    Serve a specific output file from a past dossier.

    HTML files are served with text/html so the browser renders them.
    Everything else gets content-disposition: attachment for download.
    """
    file_path = OUTPUT_DIR / name / filename

    # Path traversal guard
    try:
        file_path = file_path.resolve()
        if not str(file_path).startswith(str(OUTPUT_DIR.resolve())):
            raise HTTPException(status_code=403, detail="Forbidden")
    except (OSError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid path")

    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    suffix = file_path.suffix.lower()
    media_map = {
        ".html": "text/html",
        ".json": "application/json",
        ".csv":  "text/csv",
        ".md":   "text/markdown; charset=utf-8",
        ".txt":  "text/plain; charset=utf-8",
        ".yaml": "text/yaml; charset=utf-8",
        ".yml":  "text/yaml; charset=utf-8",
        ".xml":  "application/xml",
    }
    media_type = media_map.get(suffix, "application/octet-stream")

    # HTML reports open in the browser; everything else downloads
    if suffix == ".html":
        return FileResponse(file_path, media_type=media_type)

    return FileResponse(
        file_path,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# API: Settings (.env key management)
# ---------------------------------------------------------------------------

@app.get("/api/settings")
async def get_settings():
    """Return .env keys with masked values. Never sends raw keys to the client."""
    raw = _read_env()
    return {
        "keys": [
            {"name": k, "masked": _mask(v), "length": len(v)}
            for k, v in raw.items()
        ]
    }


@app.put("/api/settings/{key}")
async def update_setting(key: str, request: Request):
    """Add or update a single .env key."""
    body = await request.json()
    value = body.get("value")
    if value is None:
        raise HTTPException(status_code=400, detail="value is required")

    # Basic key name validation
    if not key.replace("_", "").isalnum():
        raise HTTPException(status_code=400, detail="Invalid key name")

    env = _read_env()
    env[key] = str(value)
    _write_env(env)

    return {"key": key, "masked": _mask(str(value))}


@app.delete("/api/settings/{key}")
async def delete_setting(key: str):
    """Remove a key from .env."""
    env = _read_env()
    if key not in env:
        raise HTTPException(status_code=404, detail="Key not found")
    del env[key]
    _write_env(env)
    return {"deleted": key}


# ---------------------------------------------------------------------------
# Static frontend (SPA)
# ---------------------------------------------------------------------------

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    """Catch-all: serve the SPA index.html for any non-API route."""
    index = STATIC_DIR / "index.html"
    if index.is_file():
        return HTMLResponse(content=index.read_text())
    return HTMLResponse(
        content="<pre>THEORY\n\nFrontend not found.\nPlace index.html in server/static/</pre>",
        status_code=200,
    )
