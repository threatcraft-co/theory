"""
THEORY Web UI — FastAPI backend.

Wraps the same pipeline functions the CLI uses. Binds to localhost.

Security model
--------------
"Localhost only" is not by itself a security boundary for a browser-facing
service. Any page the user visits can issue requests to 127.0.0.1, and can
re-point its own hostname there (DNS rebinding) to get same-origin access.
This server holds the user's API keys in .env and can rewrite that file, so
three controls apply to every /api/ route:

  * TrustedHostMiddleware pins the Host header to loopback names, which is
    what actually defeats rebinding.
  * A per-process session token, handed to the SPA in the launch URL
    fragment, must be echoed in X-Theory-Token.
  * Mutating requests must be application/json, so a cross-site form post
    (a CORS "simple request", no preflight) cannot reach them.

Without these, a visited web page could enumerate key names, overwrite
THEORY_LLM_PROVIDER and OLLAMA_HOST to redirect every subsequent synthesis
prompt to an attacker, and start pipeline runs.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

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
# Access control
# ---------------------------------------------------------------------------

# Regenerated per process. The SPA reads it from the URL fragment at load
# and sends it back in X-Theory-Token; fragments are never sent to a server,
# so it does not leak through Referer or proxy logs.
SESSION_TOKEN = secrets.token_urlsafe(32)

# TrustedHostMiddleware strips the port before comparing, so bare
# hostnames cover every port. (Its wildcard syntax is only for *.domain.)
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "::1", "testserver"]

# Defeats DNS rebinding: an attacker-controlled hostname resolving to
# 127.0.0.1 still sends its own name in Host, and is rejected here.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


class _ApiGuard(BaseHTTPMiddleware):
    """Token, origin and content-type checks for /api/ routes."""

    _PUBLIC_PATHS = frozenset({"/api/docs", "/api/openapi.json"})

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith("/api/") or path in self._PUBLIC_PATHS:
            return await call_next(request)

        origin = request.headers.get("origin")
        if origin is not None and not _is_local_origin(origin):
            return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)

        if not secrets.compare_digest(
            request.headers.get("x-theory-token", ""), SESSION_TOKEN
        ):
            return JSONResponse(
                {"detail": "missing or invalid session token — open the URL "
                           "printed by `theory serve`"},
                status_code=401,
            )

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            media_type = (request.headers.get("content-type") or "").split(";")[0].strip()
            if media_type != "application/json":
                return JSONResponse(
                    {"detail": "expected application/json"}, status_code=415,
                )

        return await call_next(request)


def _is_local_origin(origin: str) -> bool:
    from urllib.parse import urlsplit
    try:
        host = (urlsplit(origin).hostname or "").lower()
    except ValueError:
        return False
    return host in {"127.0.0.1", "localhost", "::1"}


app.add_middleware(_ApiGuard)

# ---------------------------------------------------------------------------
# In-memory job registry
#
# This is fine for a single-user localhost tool. Jobs are keyed by UUID and
# hold a queue of SSE events. Completed jobs stay in memory until the server
# restarts (they don't need persistence — the output files are on disk).
# ---------------------------------------------------------------------------

jobs: dict[str, dict[str, Any]] = {}

# Strong references to in-flight pipeline tasks (see create_dossier).
_BACKGROUND_TASKS: set[asyncio.Task] = set()

# Completed jobs stay queryable but must not grow without bound in a
# long-running server.
_MAX_RETAINED_JOBS = 100


def _evict_finished_jobs() -> None:
    finished = [j for j in jobs.values() if j.get("status") != "running"]
    if len(finished) <= _MAX_RETAINED_JOBS:
        return
    finished.sort(key=lambda j: j.get("created", ""))
    for job in finished[: len(finished) - _MAX_RETAINED_JOBS]:
        jobs.pop(job["id"], None)


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


_ENV_KEY_RE = __import__("re").compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def _validate_env_value(value: str) -> str:
    """Reject values that would corrupt .env or smuggle in extra keys.

    A newline in a value let a single setting write arbitrary additional
    KEY=VALUE lines — enough to point OLLAMA_HOST at an attacker and
    receive every subsequent synthesis prompt.
    """
    text = str(value)
    if any(ch in text for ch in ("\n", "\r", "\0")):
        raise HTTPException(
            status_code=400,
            detail="value may not contain newlines or null bytes",
        )
    if len(text) > 4096:
        raise HTTPException(status_code=400, detail="value too long")
    return text


def _write_env(env: dict[str, str], *, preserve_from: Path | None = None) -> None:
    """Write .env, preserving comments and key order where possible.

    The previous version rebuilt the file from the parsed dict, silently
    deleting every comment and blank line in a file whose whole purpose is
    documenting which key is which. It also wrote with default permissions,
    leaving API keys world-readable on a multi-user host.
    """
    source = preserve_from if preserve_from is not None else ENV_FILE
    remaining = dict(env)
    lines: list[str] = []

    if source.is_file():
        for raw in source.read_text().splitlines():
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                lines.append(raw)          # comment or blank — keep verbatim
                continue
            key = stripped.partition("=")[0].strip()
            if key in remaining:
                lines.append(_env_line(key, remaining.pop(key)))
            # key absent from env -> deleted, so drop the line

    for key, value in remaining.items():   # newly added keys
        lines.append(_env_line(key, value))

    ENV_FILE.write_text("\n".join(lines).rstrip("\n") + "\n")
    try:
        ENV_FILE.chmod(0o600)
    except OSError:
        pass                                # best effort (e.g. Windows)


def _env_line(key: str, value: str) -> str:
    if value and (" " in value or "#" in value or "'" in value or '"' in value):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'{key}="{escaped}"'
    return f"{key}={value}"


_SAFE_NAME_RE = __import__("re").compile(r"^[A-Za-z0-9._-]+$")


def _safe_output_path(*parts: str) -> Path:
    """Resolve a path under OUTPUT_DIR, refusing anything that escapes it.

    The previous guard was `str(resolved).startswith(str(OUTPUT_DIR))`,
    which is a prefix test on strings rather than on path components: it
    accepts a sibling directory whose name merely starts with the same
    characters (output/dossiers_exfil passes a check for output/dossiers).
    One of the two history endpoints had no guard at all.
    """
    for part in parts:
        if not part or not _SAFE_NAME_RE.match(part) or part in {".", ".."}:
            raise HTTPException(status_code=400, detail="invalid path component")

    root = OUTPUT_DIR.resolve()
    candidate = root.joinpath(*parts).resolve()
    if not candidate.is_relative_to(root):
        raise HTTPException(status_code=403, detail="Forbidden")
    return candidate


def _mask(value: str) -> str:
    """Mask an API key for display: show first 4 and last 4 chars."""
    if len(value) <= 8:
        return "\u2022" * len(value)
    return value[:4] + "\u2022" * (len(value) - 8) + value[-4:]


def _load_sources() -> list[dict[str, Any]]:
    """
    Source list matching _cli.py SUPPORTED_SOURCES + ENRICHMENT_SOURCES.

    Hardcoded intentionally — avoids import-path issues when uvicorn
    loads server.app. Update this list when you add/remove a source
    in _cli.py.
    """
    sources: list[dict[str, Any]] = [
        # ── Collectors (have a collector class, do collect + map) ──
        {"id": "mitre",       "name": "MITRE ATT&CK",     "type": "collector",  "enabled": True},
        {"id": "cisa",        "name": "CISA Advisories",   "type": "collector",  "enabled": True},
        {"id": "cisa_kev",    "name": "CISA KEV",          "type": "collector",  "enabled": True},
        {"id": "malpedia",    "name": "Malpedia",          "type": "collector",  "enabled": True},
        {"id": "misp_galaxy", "name": "MISP Galaxy",       "type": "collector",  "enabled": True},
        {"id": "otx",         "name": "AlienVault OTX",    "type": "collector",  "enabled": True},
        {"id": "vuldb",       "name": "VulDB",             "type": "collector",  "enabled": True},
        # ── Enrichment sources (post-collection enrichment pass) ──
        {"id": "sigma",          "name": "Sigma Rules",       "type": "enrichment", "enabled": True},
        {"id": "yara",           "name": "YARA Rules",        "type": "enrichment", "enabled": True},
        {"id": "threatfox",      "name": "ThreatFox",         "type": "enrichment", "enabled": True},
        {"id": "malware_bazaar", "name": "MalwareBazaar",     "type": "enrichment", "enabled": True},
        {"id": "urlhaus",        "name": "URLhaus",           "type": "enrichment", "enabled": True},
        {"id": "greynoise",      "name": "GreyNoise",         "type": "enrichment", "enabled": True},
        {"id": "abuseipdb",      "name": "AbuseIPDB",         "type": "enrichment", "enabled": True},
        {"id": "vendor",         "name": "Vendor Intel (LLM)","type": "enrichment", "enabled": False},
    ]

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

    # Keep a reference: asyncio only holds a weak one, so a task with no
    # live reference can be garbage-collected mid-run.
    task = asyncio.create_task(_launch_pipeline(job_id, actor, body))
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)

    _evict_finished_jobs()
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
    dossier_dir = _safe_output_path(name)
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
    file_path = _safe_output_path(name, filename)

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

    # HTML reports open in the browser; everything else downloads.
    #
    # A report embeds third-party content (vendor article titles, advisory
    # links) and is served from the same origin as /api/settings, so it is
    # sandboxed: no scripts, no same-origin privileges. Without this, one
    # hostile feed item in a report could read the user's API key names and
    # drive the settings API.
    if suffix == ".html":
        return FileResponse(
            file_path,
            media_type=media_type,
            headers={
                "Content-Security-Policy":
                    "sandbox; default-src 'none'; style-src 'unsafe-inline'; "
                    "img-src data:; font-src data:",
                "X-Content-Type-Options": "nosniff",
            },
        )

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

    if not _ENV_KEY_RE.match(key):
        raise HTTPException(
            status_code=400,
            detail="key must be UPPER_SNAKE_CASE, starting with a letter",
        )

    env = _read_env()
    env[key] = _validate_env_value(value)
    _write_env(env)

    return {"key": key, "masked": _mask(str(value))}


@app.delete("/api/settings/{key}")
async def delete_setting(key: str):
    """Remove a key from .env."""
    if not _ENV_KEY_RE.match(key):
        raise HTTPException(status_code=400, detail="Invalid key name")
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
