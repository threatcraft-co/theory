"""
tests/test_server_security.py
-----------------------------
`theory serve` is a browser-facing service that holds the user's API keys
in .env and can rewrite that file. "It only listens on localhost" is not a
boundary against a browser: any page the user visits can issue requests to
127.0.0.1, and can point its own hostname there to get same-origin access.

Each test here is one of the attacks that worked before these controls:

  * DNS rebinding — attacker.test resolves to 127.0.0.1, the page then
    reads /api/settings and rewrites .env same-origin.
  * CSRF via a simple form post — text/plain POST needs no preflight, so
    a visited page could start pipeline runs.
  * .env line injection — a newline in a value writes extra KEY=VALUE
    lines; setting OLLAMA_HOST redirects every later synthesis prompt.
  * Path traversal — a string-prefix guard accepts sibling directories,
    and one history endpoint had no guard at all.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    import server.app as app_module

    monkeypatch.setattr(app_module, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(app_module, "OUTPUT_DIR", tmp_path / "output" / "dossiers")
    (tmp_path / "output" / "dossiers").mkdir(parents=True)
    return TestClient(app_module.app, base_url="http://127.0.0.1:8088")


@pytest.fixture
def token():
    from server.app import SESSION_TOKEN
    return SESSION_TOKEN


def auth(token: str) -> dict[str, str]:
    return {"X-Theory-Token": token}


class TestSessionToken:

    def test_api_refuses_requests_without_a_token(self, client):
        assert client.get("/api/settings").status_code == 401

    def test_api_refuses_a_wrong_token(self, client):
        r = client.get("/api/settings", headers={"X-Theory-Token": "guessed"})
        assert r.status_code == 401

    def test_api_accepts_the_session_token(self, client, token):
        assert client.get("/api/settings", headers=auth(token)).status_code == 200

    def test_static_frontend_needs_no_token(self, client):
        """The SPA itself must load, or there is nowhere to read the token."""
        assert client.get("/").status_code == 200


class TestDnsRebinding:

    @pytest.mark.parametrize("host", [
        "attacker.test", "evil.example.com", "theory.attacker.test",
    ])
    def test_foreign_host_header_rejected(self, client, token, host):
        """The rebinding defence. The attacker's DNS points at 127.0.0.1,
        but the browser still sends the attacker's hostname in Host."""
        r = client.get("/api/settings", headers={**auth(token), "Host": host})
        assert r.status_code == 400

    @pytest.mark.parametrize("host", ["127.0.0.1:8088", "localhost:8088"])
    def test_loopback_host_accepted(self, client, token, host):
        r = client.get("/api/settings", headers={**auth(token), "Host": host})
        assert r.status_code == 200


class TestCrossOrigin:

    def test_foreign_origin_rejected(self, client, token):
        r = client.get("/api/settings",
                       headers={**auth(token), "Origin": "https://evil.example.com"})
        assert r.status_code == 403

    def test_local_origin_accepted(self, client, token):
        r = client.get("/api/settings",
                       headers={**auth(token), "Origin": "http://127.0.0.1:8088"})
        assert r.status_code == 200

    def test_simple_form_post_refused(self, client, token):
        """text/plain is a CORS "simple request" — no preflight, so a
        visited page could fire it cross-site. Mutations require JSON."""
        r = client.post("/api/dossier", content='{"actor":"APT28"}',
                        headers={**auth(token), "Content-Type": "text/plain"})
        assert r.status_code == 415


class TestEnvWrites:

    def test_newline_injection_refused(self, client, token):
        """A newline would append arbitrary extra settings — e.g.
        OLLAMA_HOST, redirecting every later LLM prompt to an attacker."""
        r = client.put("/api/settings/OTX_API_KEY",
                       json={"value": "abc\nOLLAMA_HOST=https://attacker.test"},
                       headers=auth(token))
        assert r.status_code == 400

    def test_carriage_return_refused(self, client, token):
        r = client.put("/api/settings/OTX_API_KEY",
                       json={"value": "abc\rEVIL=1"}, headers=auth(token))
        assert r.status_code == 400

    @pytest.mark.parametrize("key", [
        "lowercase", "WITH-DASH", "WITH SPACE", "9LEADING_DIGIT",
    ])
    def test_malformed_key_names_refused(self, client, token, key):
        r = client.put(f"/api/settings/{key}", json={"value": "x"}, headers=auth(token))
        assert r.status_code == 400

    def test_path_shaped_keys_never_write_anything(self, client, token):
        """These don't reach the settings route at all — the URL normalises
        and falls through to the SPA. Asserted at the only level that
        matters: nothing was written."""
        import server.app as app_module

        before = (app_module.ENV_FILE.read_text()
                  if app_module.ENV_FILE.is_file() else None)
        client.put("/api/settings/../ESCAPE", json={"value": "x"}, headers=auth(token))
        after = (app_module.ENV_FILE.read_text()
                 if app_module.ENV_FILE.is_file() else None)
        assert before == after

    def test_valid_write_succeeds_and_round_trips(self, client, token):
        assert client.put("/api/settings/OTX_API_KEY",
                          json={"value": "real-key-value"},
                          headers=auth(token)).status_code == 200
        names = [k["name"] for k in client.get("/api/settings", headers=auth(token)).json()["keys"]]
        assert "OTX_API_KEY" in names

    def test_raw_key_never_returned(self, client, token):
        client.put("/api/settings/OTX_API_KEY",
                   json={"value": "supersecretvalue"}, headers=auth(token))
        body = client.get("/api/settings", headers=auth(token)).text
        assert "supersecretvalue" not in body

    def test_comments_survive_a_write(self, client, token, tmp_path):
        """The old writer rebuilt .env from a dict, deleting every comment
        in a file whose purpose is documenting which key is which."""
        import server.app as app_module

        app_module.ENV_FILE.write_text(
            "# AlienVault OTX — free registration\nOTX_API_KEY=old\n\n# abuse.ch\nABUSECH_API_KEY=keep\n"
        )
        client.put("/api/settings/OTX_API_KEY", json={"value": "new"}, headers=auth(token))
        content = app_module.ENV_FILE.read_text()
        assert "# AlienVault OTX — free registration" in content
        assert "# abuse.ch" in content
        assert "OTX_API_KEY=new" in content
        assert "ABUSECH_API_KEY=keep" in content

    def test_env_file_is_not_world_readable(self, client, token):
        import os
        import stat

        import server.app as app_module

        client.put("/api/settings/OTX_API_KEY", json={"value": "x"}, headers=auth(token))
        mode = stat.S_IMODE(os.stat(app_module.ENV_FILE).st_mode)
        assert not (mode & stat.S_IROTH), f"world-readable .env: {oct(mode)}"
        assert not (mode & stat.S_IRGRP), f"group-readable .env: {oct(mode)}"


class TestPathTraversal:

    @pytest.mark.parametrize("parts", [
        ("..",), ("..", ".."), ("a", "..", ".."), ("../etc", "passwd"),
        (".",), ("", ), ("foo/bar",), ("..%2f..",),
    ])
    def test_guard_refuses_traversal_components(self, client, parts):
        """Unit-level, because URL normalisation strips `..` before routing
        — the HTTP layer cannot even express this attack, but any future
        caller of the guard can."""
        from fastapi import HTTPException

        from server.app import _safe_output_path

        with pytest.raises(HTTPException):
            _safe_output_path(*parts)

    def test_guard_refuses_sibling_directory_with_shared_prefix(self, client):
        """The old check was `str(resolved).startswith(str(OUTPUT_DIR))` — a
        string prefix test, so output/dossiers_exfil passed a check meant
        for output/dossiers."""
        import server.app as app_module
        from fastapi import HTTPException

        from server.app import _safe_output_path

        sibling = app_module.OUTPUT_DIR.parent / (app_module.OUTPUT_DIR.name + "_exfil")
        sibling.mkdir(parents=True, exist_ok=True)
        (sibling / "secret.txt").write_text("stolen")

        with pytest.raises(HTTPException):
            _safe_output_path("..", sibling.name, "secret.txt")

    def test_traversal_urls_leak_nothing_over_http(self, client, token):
        import server.app as app_module

        sibling = app_module.OUTPUT_DIR.parent / (app_module.OUTPUT_DIR.name + "_exfil")
        sibling.mkdir(parents=True, exist_ok=True)
        (sibling / "secret.txt").write_text("stolen-contents")

        for url in (
            f"/api/history/../{sibling.name}/secret.txt",
            f"/api/history/..%2f{sibling.name}/secret.txt",
            "/api/history/../../../../etc/passwd",
        ):
            r = client.get(url, headers=auth(token))
            assert "stolen-contents" not in r.text
            assert "root:" not in r.text

    def test_legitimate_file_still_served(self, client, token):
        import server.app as app_module

        d = app_module.OUTPUT_DIR / "apt28"
        d.mkdir(parents=True, exist_ok=True)
        (d / "dossier.md").write_text("# APT28")

        r = client.get("/api/history/apt28/dossier.md", headers=auth(token))
        assert r.status_code == 200
        assert "APT28" in r.text

    def test_html_report_is_sandboxed(self, client, token):
        """Reports embed third-party content and are served from the same
        origin as the settings API."""
        import server.app as app_module

        d = app_module.OUTPUT_DIR / "apt28"
        d.mkdir(parents=True, exist_ok=True)
        (d / "report.html").write_text("<html><body>hi</body></html>")

        r = client.get("/api/history/apt28/report.html", headers=auth(token))
        assert r.status_code == 200
        csp = r.headers.get("content-security-policy", "")
        assert "sandbox" in csp
        assert "script-src" not in csp or "'unsafe-inline'" not in csp.split("script-src")[1][:30]


class TestHistoryListing:
    """The History page listed only sub-directories of output/dossiers/,
    but every reporter writes flat files there — so it was always empty."""

    def _write_outputs(self, app_module):
        out = app_module.OUTPUT_DIR
        out.mkdir(parents=True, exist_ok=True)
        for name in ("apt28.md", "apt28.json", "apt28.html", "apt28_iocs.csv",
                     "apt28.stix.json", "apt28.navigator.json",
                     "lazarus_group.md", "lazarus_group_exec.md"):
            (out / name).write_text("x")

    def test_flat_files_are_grouped_by_actor(self, client, token):
        import server.app as app_module
        self._write_outputs(app_module)

        body = client.get("/api/history", headers=auth(token)).json()
        by_name = {d["name"]: d for d in body["dossiers"]}

        assert "apt28" in by_name, f"flat files not listed: {body}"
        assert "lazarus_group" in by_name
        assert by_name["apt28"]["file_count"] == 6
        assert "apt28_iocs.csv" in by_name["apt28"]["files"]
        assert by_name["lazarus_group"]["file_count"] == 2

    def test_detail_and_download_work_for_flat_files(self, client, token):
        import server.app as app_module
        self._write_outputs(app_module)

        detail = client.get("/api/history/apt28", headers=auth(token))
        assert detail.status_code == 200
        assert {f["name"] for f in detail.json()["files"]} >= {"apt28.md", "apt28.html"}

        served = client.get("/api/history/apt28/apt28.md", headers=auth(token))
        assert served.status_code == 200

    def test_legacy_directory_layout_still_listed(self, client, token):
        import server.app as app_module
        nested = app_module.OUTPUT_DIR / "old_actor"
        nested.mkdir(parents=True, exist_ok=True)
        (nested / "dossier.md").write_text("x")

        names = [d["name"] for d in client.get("/api/history", headers=auth(token)).json()["dossiers"]]
        assert "old_actor" in names
