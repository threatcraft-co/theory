"""
tests/conftest.py
-----------------
Session-wide test isolation.

Two problems this solves:

  1. `theory._cli` calls load_dotenv() at import time, so a developer's real
     .env leaked into the test process. Tests then behaved differently on a
     configured laptop than in CI — which is exactly why four ThreatFox
     tests passed locally and failed in CI.

  2. Collectors read os.environ at construction time and write caches to
     relative paths (.cache/, output/). Without isolation, a test run
     scribbles into the repo and can make real API calls with real keys.

Every test now runs with a scrubbed environment in its own temp CWD.
A test that genuinely needs a key sets it explicitly with monkeypatch.
"""

from __future__ import annotations

import pytest

# Every environment variable THEORY reads anywhere. Keep in sync with
# .env.example — tests/test_env_isolation.py asserts this list covers it.
THEORY_ENV_VARS = (
    # LLM providers
    "THEORY_LLM_PROVIDER", "THEORY_LLM",
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    "OLLAMA_HOST", "OLLAMA_MODEL",
    # Intelligence sources
    "OTX_API_KEY",
    "ABUSECH_API_KEY",
    "GREYNOISE_API_KEY",
    "ABUSEIPDB_API_KEY",
    "URLSCAN_API_KEY",
    "VULDB_API_KEY",
    "NVD_API_KEY",
    "GITHUB_TOKEN",
    # Tuning knobs
    "THEORY_INTEL_LOOKBACK", "THEORY_INTEL_MAX_ITEMS", "THEORY_OTX_MAX_IOCS",
    # Paths
    "THEORY_HOME", "THEORY_CONFIG_DIR",
)


@pytest.fixture(autouse=True)
def hermetic_env(monkeypatch, tmp_path):
    """Scrub THEORY's environment and move to a throwaway CWD.

    Autouse: applies to every test whether it asks for it or not. A test
    that needs a key sets it itself, which also documents the dependency.
    """
    for var in THEORY_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    # Also neutralise any FEED_COOKIE_* left in the developer's environment
    import os
    for key in list(os.environ):
        if key.startswith("FEED_COOKIE_"):
            monkeypatch.delenv(key, raising=False)

    # Stop theory._cli's import-time load_dotenv() from reading a real .env
    monkeypatch.setenv("THEORY_DISABLE_DOTENV", "1")

    # Relative cache/output paths land here instead of in the repo
    monkeypatch.chdir(tmp_path)
    yield


@pytest.fixture
def repo_config(monkeypatch, tmp_path):
    """Make the real config/ directory visible from the temp CWD.

    Several collectors resolve `config/actors.yaml` relative to the working
    directory (see THY-H1 — fixed properly by the packaging change, but
    tests shouldn't depend on that landing first). Tests that need the real
    alias table request this fixture explicitly.
    """
    from pathlib import Path

    repo_root = Path(__file__).resolve().parent.parent
    link = tmp_path / "config"
    if not link.exists():
        link.symlink_to(repo_root / "config", target_is_directory=True)
    return link


@pytest.fixture
def attack_bundle_path():
    """Path to the trimmed ATT&CK fixture used by identity tests."""
    from pathlib import Path

    p = Path(__file__).resolve().parent / "fixtures" / "attack_groups.json"
    if not p.is_file():
        pytest.skip("ATT&CK fixture not generated — run tests/fixtures/build_fixture.py")
    return p
