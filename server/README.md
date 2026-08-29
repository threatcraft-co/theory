# THEORY Web UI — `theory serve`

## File placement

The `server/` directory goes at your THEORY project root as a peer to `theory/`, `collectors/`, `reporters/`, etc:

```
theory-repo/
  theory/
    __init__.py
    __main__.py
    _cli.py           ← The CLI entry point
    _version.py
  collectors/
  processors/
  reporters/
  server/            ← This entire directory
    __init__.py
    app.py
    pipeline.py
    cli_serve.py
    static/
      index.html
    README.md
  pyproject.toml
  .env
```

## Wiring steps

### 1. Install web UI dependencies

```bash
pip install -e ".[serve]"
```

This pulls `fastapi`, `uvicorn[standard]`, and `sse-starlette` from the optional group in `pyproject.toml`.

### 2. Wire the CLI command

In `_cli.py` (or wherever your CLI entry point `main()` is defined), add at the top of `main()` before `_print_banner()`:

```python
def main(argv: list[str] | None = None) -> None:
    # ── `theory serve` — intercept before argparse ────────────────────
    _args = argv if argv is not None else sys.argv[1:]
    if _args and _args[0] == "serve":
        from server.cli_serve import cmd_serve
        cmd_serve(_args[1:])
        return

    _print_banner()
    parser = _build_parser()
    args   = parser.parse_args(argv)
    # ... rest of main()
```

This intercepts `theory serve` before argparse, since `serve` is a separate subcommand, not a flag.

### 3. Verify the imports in pipeline.py

The file `server/pipeline.py` imports `from theory._cli import run` to call your actual pipeline. This should work as-is if THEORY is installed via `pip install -e .`.

## Running

```bash
theory serve                     # localhost:8088, opens browser
theory serve --port 9000         # custom port
theory serve --reload            # dev mode (auto-reload on code changes)
theory serve --no-open           # skip browser auto-open
```

## How it works

**Same pipeline, two UIs.** The web UI calls `theory._cli.run()` — the exact same function the CLI uses. No duplication.

- `app.py` is a FastAPI server with routes for `/api/sources`, `/api/dossier`, `/api/history`, `/api/settings`, and a catch-all for the SPA.
- `pipeline.py` wraps `theory._cli.run()` with progress callbacks and SSE events. It maps web UI source IDs and format names to the CLI's expected values.
- `cli_serve.py` is the argparse command that starts uvicorn.
- `static/index.html` is a self-contained SPA (one file, no build step) with 4 pages: Query, History, Settings, CVE.

**Progress via SSE.** While the pipeline runs in a background thread, it pushes progress events to the frontend via Server-Sent Events. The pipeline is treated as a single step since it's one monolithic function, but real-time updates let the user see it's working.

**Local only.** The server binds to `127.0.0.1` by default. Nothing leaves your machine except API calls to the intelligence sources you enable.

**Settings never expose keys.** API keys are stored in `.env` and managed via `/api/settings`, but the UI only sees masked values.

## Troubleshooting

**"Could not import theory._cli.run"**

Make sure THEORY is installed and `sys.path` includes the project root. The `_ensure_cli_importable()` function in `pipeline.py` should handle this, but if it doesn't:

```bash
cd /path/to/theory-repo
pip install -e .
```

**Dossier doesn't show up in History**

The UI looks in `output/dossiers/` for output. Make sure that directory exists and that `run()` is actually saving files (it does by default).

**Pipeline fails with "No data found for actor"**

Try the same actor on the CLI to confirm it's supported:

```bash
theory --actor APT28 --list-sources
```

If the CLI finds data, the web UI should too (they call the same function). If not, check your API keys in `.env` and enable the web UI's Settings page to verify they're set.
