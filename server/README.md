# THEORY Web UI — Integration Guide

## File placement

Copy the `server/` directory into your THEORY project root so the
structure looks like:

```
theory/
  cli.py              (your existing CLI entry point)
  server/
    __init__.py
    app.py             FastAPI application, all routes
    pipeline.py        Pipeline bridge (stubs → real imports)
    cli_serve.py       Click command for `theory serve`
    static/
      index.html       Self-contained SPA frontend
  processors/
    correlator.py      (existing)
    ...
  collectors/
    ...
  config/
    feeds.yaml         (existing, read by the web UI for source list)
  output/
    dossiers/          (existing, browsed by the history page)
  .env                 (existing, managed by the settings page)
```

## Wiring steps

### 1. Install dependencies

```bash
pip install fastapi uvicorn[standard] sse-starlette
```

### 2. Register the CLI command

In your main CLI file (e.g. `cli.py`), add:

```python
from theory.server.cli_serve import serve
cli.add_command(serve)
```

### 3. Replace pipeline stubs

Open `server/pipeline.py`. Each step function has an "Integration
point" comment showing exactly what import and call to make. Replace
the `_stub_delay()` calls with your real pipeline modules.

For example, `step_collect` might become:

```python
def step_collect(actor, state, options):
    from theory.collectors import run_collectors
    from theory.config import load_feeds

    enabled = options.get("sources", [])
    feeds = load_feeds()
    state.raw_intel = run_collectors(actor, enabled_sources=enabled, feeds=feeds)
    return state
```

### 4. Adjust the uvicorn import path

In `cli_serve.py`, the `uvicorn.run()` call uses:

```python
"theory.server.app:app"
```

Adjust this if your project's package name differs from `theory`.

### 5. Update source list

The `/api/sources` endpoint in `app.py` has a hardcoded collector
list matching your current confirmed set (OTX, MISP, CISA KEV, etc.).
If you add or remove collectors, update the `_load_sources()` function
to match.

Alternatively, refactor `_load_sources()` to dynamically discover
collectors from your collector modules.

RSS feeds are loaded from `config/feeds.yaml` automatically.

## Running

```bash
theory serve                     # localhost:8088, opens browser
theory serve --port 9000         # custom port
theory serve --reload            # dev mode (auto-reload on changes)
theory serve --no-open           # skip browser auto-open
```

## Architecture notes

- **Same tool, two front ends.** The web UI calls the exact same
  pipeline functions as the CLI. No logic is duplicated.

- **Pipeline progress via SSE.** The pipeline runs in a background
  thread. Progress events are pushed through Server-Sent Events to
  the frontend. The SSE protocol is documented in `pipeline.py`.

- **Single-user, localhost.** The job registry is in-memory. There's
  no database, no auth, no multi-user concerns. This is a local tool.

- **Self-contained frontend.** The entire SPA is one HTML file with
  embedded CSS and JS. No build step, no npm, no framework. Consistent
  with THEORY's philosophy of keeping things local and dependency-light.

- **Path traversal guard.** The file-serving endpoint resolves paths
  and confirms they stay within `output/dossiers/` before serving.

- **Settings never expose raw keys.** The `/api/settings` endpoint
  returns masked values. Raw values are only written to `.env`, never
  sent to the client.

## SSE event protocol

Events sent during a dossier generation job:

| Event       | Data fields                                          |
|-------------|------------------------------------------------------|
| `started`   | `actor`, `total_steps`                               |
| `step`      | `step`, `total`, `id`, `description`, `status`       |
| `step_done` | `step`, `total`, `id`, `description`, `duration_ms`  |
| `complete`  | `actor`, `output_dir`, `total_duration_ms`, `files`  |
| `error`     | `step_id`, `message`, `traceback`                    |
