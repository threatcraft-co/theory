"""
theory serve — local web UI.

Called from _cli.main() when the first argument is "serve".
Uses argparse to stay consistent with the rest of the CLI.
"""

from __future__ import annotations

import argparse
import sys


def cmd_serve(argv: list[str]) -> None:
    """Entry point for `theory serve [options]`."""

    p = argparse.ArgumentParser(
        prog="theory serve",
        description="Start the THEORY web UI on localhost.",
    )
    p.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default: 127.0.0.1).",
    )
    p.add_argument(
        "--port",
        type=int,
        default=8088,
        help="Port to listen on (default: 8088).",
    )
    p.add_argument(
        "--no-open",
        action="store_true",
        help="Don't auto-open the browser.",
    )
    p.add_argument(
        "--reload",
        action="store_true",
        help="Auto-reload on code changes (dev only).",
    )

    args = p.parse_args(argv)

    # Dependency check
    try:
        import uvicorn
    except ImportError:
        print(
            "\n  theory serve requires extra dependencies.\n"
            "  Install them with:\n\n"
            '    pip install -e ".[serve]"\n'
        )
        sys.exit(1)

    url = f"http://{args.host}:{args.port}"
    print(f"\n  THEORY web UI")
    print(f"  {url}")
    print(f"  API docs: {url}/api/docs\n")

    if not args.no_open and not args.reload:
        import threading
        import time
        import webbrowser

        def _open():
            time.sleep(1.2)
            webbrowser.open(url)

        threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(
        "server.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
        access_log=False,
    )
