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
        help="Bind address (default: 127.0.0.1). Non-loopback addresses "
             "require --expose-api-keys.",
    )
    p.add_argument(
        "--expose-api-keys",
        action="store_true",
        help=(
            "Permit binding to a non-loopback address. The settings API can "
            "read key names and rewrite .env, so this exposes your API keys "
            "to anyone who can reach the port. Almost never what you want."
        ),
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

    # Refuse to expose the settings API by accident.
    if args.host not in {"127.0.0.1", "localhost", "::1"} and not args.expose_api_keys:
        print(
            f"\n  Refusing to bind to {args.host}.\n\n"
            "  theory serve exposes a settings API that can read which API keys\n"
            "  are configured and rewrite your .env. On a non-loopback address\n"
            "  that is reachable by anyone who can reach the port.\n\n"
            "  Use the default (127.0.0.1), or pass --expose-api-keys if you\n"
            "  genuinely intend this.\n"
        )
        sys.exit(1)

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

    # The SPA reads this token from the URL fragment and echoes it in
    # X-Theory-Token. Fragments are never sent to a server, so it stays out
    # of Referer headers and proxy logs.
    from server.app import SESSION_TOKEN

    base = f"http://{args.host}:{args.port}"
    url  = f"{base}/#token={SESSION_TOKEN}"
    print(f"\n  THEORY web UI")
    print(f"  {url}")
    print(f"\n  This URL carries a one-session access token. The API refuses")
    print(f"  requests without it, which is what stops a web page you visit")
    print(f"  from driving this server.\n")

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
