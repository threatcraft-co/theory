"""
CLI integration for `theory serve`.

HOW TO WIRE THIS IN
--------------------
If your CLI uses Click, add this to your main CLI group:

    from theory.server.cli_serve import serve
    cli.add_command(serve)

If your CLI uses Typer, adapt accordingly:

    app.command()(serve)

This module is deliberately standalone so you can copy it into
your existing CLI file or import it.
"""

from __future__ import annotations

import click


@click.command()
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Bind address. Use 127.0.0.1 (default) to keep traffic local.",
)
@click.option(
    "--port",
    default=8088,
    show_default=True,
    type=int,
    help="Port to listen on.",
)
@click.option(
    "--reload",
    is_flag=True,
    default=False,
    help="Auto-reload on code changes (development only).",
)
@click.option(
    "--open/--no-open",
    "open_browser",
    default=True,
    show_default=True,
    help="Open the browser automatically on start.",
)
def serve(host: str, port: int, reload: bool, open_browser: bool) -> None:
    """Start the THEORY web UI.

    Launches a local web server that wraps the same pipeline the CLI uses.
    Nothing leaves your machine except API calls to the intelligence
    sources you've configured.

    \b
    Examples:
        theory serve                    # localhost:8088, opens browser
        theory serve --port 9000        # custom port
        theory serve --no-open          # don't open browser
        theory serve --reload           # dev mode with auto-reload
    """
    import uvicorn

    url = f"http://{host}:{port}"
    click.echo(f"\n  THEORY web UI")
    click.echo(f"  {url}")
    click.echo(f"  API docs: {url}/api/docs")
    click.echo()

    if open_browser and not reload:
        import threading
        import time
        import webbrowser

        def _open():
            time.sleep(1.2)  # Wait for server to be ready
            webbrowser.open(url)

        threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(
        "server.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
        access_log=False,
    )
