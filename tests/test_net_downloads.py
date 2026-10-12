"""
tests/test_net_downloads.py
---------------------------
The bundle/catalog refreshes behind `theory --update-bundles` must never
replace a good cache with a bad response.

The old implementation shelled out to `curl -L -o <cache> <url>` without
--fail. curl exits 0 on an HTTP error and writes the error body to the
output file, so a 404 silently overwrote the ATT&CK bundle with a JSON
error message — after which the MITRE collector parsed nothing and quietly
vanished from every dossier.

Every test here asserts the same invariant from a different failure mode:
on failure, the destination file is byte-identical to what it was before.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from theory._net import (
    DownloadError,
    download_json,
    validate_attack_bundle,
    validate_kev_catalog,
    validate_misp_galaxy,
)

GOOD_BUNDLE = {"type": "bundle", "id": "bundle--x", "objects": [{"type": "x"}] * 1500}


@pytest.fixture
def existing_cache(tmp_path: Path) -> Path:
    """A destination that already holds a known-good payload."""
    dest = tmp_path / "enterprise-attack.json"
    dest.write_text(json.dumps(GOOD_BUNDLE), encoding="utf-8")
    return dest


def _patch_fetch(monkeypatch, payload=None, exc=None):
    """Replace the network layer with a canned response."""
    import theory._net as net

    def fake_fetch(url, **kwargs):
        if exc is not None:
            raise exc
        return payload

    monkeypatch.setattr(net, "fetch_bytes", fake_fetch)


class TestFailuresNeverClobber:

    def test_http_error_leaves_cache_intact(self, existing_cache, monkeypatch):
        before = existing_cache.read_bytes()
        _patch_fetch(monkeypatch, exc=DownloadError("HTTP 404 from example"))

        with pytest.raises(DownloadError):
            download_json("https://example.test/b.json", existing_cache,
                          validate=validate_attack_bundle)

        assert existing_cache.read_bytes() == before

    def test_html_error_page_leaves_cache_intact(self, existing_cache, monkeypatch):
        """The exact failure seen in the wild: a 200 response whose body is
        an HTML error page rather than the expected JSON."""
        before = existing_cache.read_bytes()
        _patch_fetch(monkeypatch, payload=b"<!doctype html><title>404</title>")

        with pytest.raises(DownloadError, match="did not return JSON"):
            download_json("https://example.test/b.json", existing_cache,
                          validate=validate_attack_bundle)

        assert existing_cache.read_bytes() == before

    def test_json_error_body_leaves_cache_intact(self, existing_cache, monkeypatch):
        """A 200 with valid JSON that isn't the catalog — e.g. GitHub's
        {"message": "Not Found"}. Parses fine, must still be rejected."""
        before = existing_cache.read_bytes()
        _patch_fetch(monkeypatch, payload=b'{"message": "Not Found"}')

        with pytest.raises(DownloadError, match="failed validation"):
            download_json("https://example.test/b.json", existing_cache,
                          validate=validate_attack_bundle)

        assert existing_cache.read_bytes() == before

    def test_truncated_bundle_leaves_cache_intact(self, existing_cache, monkeypatch):
        """A structurally valid but suspiciously small bundle is rejected —
        catches a partial transfer that still parsed."""
        before = existing_cache.read_bytes()
        tiny = json.dumps({"type": "bundle", "objects": [{"type": "x"}] * 3})
        _patch_fetch(monkeypatch, payload=tiny.encode())

        with pytest.raises(DownloadError, match="failed validation"):
            download_json("https://example.test/b.json", existing_cache,
                          validate=validate_attack_bundle)

        assert existing_cache.read_bytes() == before


class TestSuccessPath:

    def test_valid_payload_replaces_cache(self, existing_cache, monkeypatch):
        new = dict(GOOD_BUNDLE, id="bundle--new")
        _patch_fetch(monkeypatch, payload=json.dumps(new).encode())

        written, parsed = download_json(
            "https://example.test/b.json", existing_cache,
            validate=validate_attack_bundle,
        )

        assert parsed["id"] == "bundle--new"
        assert written > 0
        assert json.loads(existing_cache.read_text())["id"] == "bundle--new"

    def test_creates_destination_when_absent(self, tmp_path, monkeypatch):
        dest = tmp_path / "nested" / "dir" / "catalog.json"
        _patch_fetch(monkeypatch, payload=json.dumps(GOOD_BUNDLE).encode())

        download_json("https://example.test/b.json", dest,
                      validate=validate_attack_bundle)

        assert dest.is_file()

    def test_no_partial_files_left_behind(self, existing_cache, monkeypatch):
        _patch_fetch(monkeypatch, payload=b"not json")
        with pytest.raises(DownloadError):
            download_json("https://example.test/b.json", existing_cache,
                          validate=validate_attack_bundle)
        leftovers = list(existing_cache.parent.glob("*.part"))
        assert leftovers == [], f"temp files left behind: {leftovers}"


class TestSchemeEnforcement:

    @pytest.mark.parametrize("url", [
        "http://example.test/b.json",
        "file:///etc/passwd",
        "ftp://example.test/b.json",
    ])
    def test_non_https_refused(self, tmp_path, url):
        from theory._net import fetch_bytes
        with pytest.raises(DownloadError, match="non-https"):
            fetch_bytes(url)


class TestValidators:

    def test_misp_galaxy_requires_enough_actors(self):
        validate_misp_galaxy({"values": [{}] * 600})
        with pytest.raises(ValueError):
            validate_misp_galaxy({"values": [{}] * 10})
        with pytest.raises(ValueError):
            validate_misp_galaxy({"message": "Not Found"})

    def test_kev_requires_vulnerabilities(self):
        validate_kev_catalog({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]})
        with pytest.raises(ValueError):
            validate_kev_catalog({"vulnerabilities": []})
        with pytest.raises(ValueError):
            validate_kev_catalog({"count": 0})
