"""
theory.paths
------------
Every filesystem location THEORY uses, resolved in one place.

Before this module, each collector and reporter built its own relative
Path(".cache/...") or Path("config/actors.yaml"). That worked only when
the process happened to be running from the repo root: a `pip install`
user running `theory` from anywhere else got no alias resolution (a log
warning, then silently degraded output), and caches/dossiers scattered
into whatever directory they happened to be in.

Resolution rules
----------------
Config (read-only, ships with the package):
    1. $THEORY_CONFIG_DIR            — explicit override, always wins
    2. ./config/<name>               — a repo checkout or a user's local
                                       edits sitting next to the CWD
    3. <package>/data/<name>         — the copy installed with the wheel

Runtime data (written):
    1. $THEORY_HOME                  — explicit override
    2. ./.cache and ./output         — when running inside a repo checkout,
                                       preserving the existing workflow
    3. platform user dirs            — for an installed package

Nothing else in THEORY should construct a relative Path.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = [
    "PACKAGE_DATA_DIR", "config_dir", "config_file",
    "cache_subdir", "cache_root", "output_dir", "dossier_dir", "graph_path",
    "user_config_dir", "is_repo_checkout",
]

_PACKAGE_ROOT = Path(__file__).resolve().parent
PACKAGE_DATA_DIR = _PACKAGE_ROOT / "data"
_REPO_ROOT = _PACKAGE_ROOT.parent


# ---------------------------------------------------------------------------
# Config — read-only, ships with the package
# ---------------------------------------------------------------------------

def config_dir() -> Path:
    """Directory that config lookups start from (override or packaged)."""
    override = os.environ.get("THEORY_CONFIG_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    return PACKAGE_DATA_DIR


def config_file(name: str) -> Path:
    """Locate a config file by name, honouring overrides and local edits.

    Returns the first candidate that exists. If none exist, returns the
    packaged path so the caller's error message names a sensible location.
    """
    override = os.environ.get("THEORY_CONFIG_DIR", "").strip()
    candidates: list[Path] = []
    if override:
        candidates.append(Path(override).expanduser() / name)
    # Local edits / repo checkout next to the current working directory
    candidates.append(Path("config") / name)
    # The repo's own config/ dir, for running from a subdirectory of a checkout
    candidates.append(_REPO_ROOT / "config" / name)
    # Installed package data
    candidates.append(PACKAGE_DATA_DIR / name)

    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return PACKAGE_DATA_DIR / name


# ---------------------------------------------------------------------------
# Runtime data — written
# ---------------------------------------------------------------------------

def is_repo_checkout() -> bool:
    """True when the current working directory looks like a THEORY checkout.

    Used to keep the familiar ./output and ./.cache layout for people
    working in the repo, while installed users get proper user dirs.
    """
    cwd = Path.cwd()
    return (cwd / "pyproject.toml").is_file() and (cwd / "collectors").is_dir()


def _user_data_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
        return Path(base) / "theory"
    if os.uname().sysname == "Darwin":
        return Path.home() / "Library" / "Application Support" / "theory"
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / "theory"


def _user_cache_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
        return Path(base) / "theory" / "cache"
    if os.uname().sysname == "Darwin":
        return Path.home() / "Library" / "Caches" / "theory"
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "theory"


def user_config_dir() -> Path:
    """Where user-owned config (the personal-research redirect) lives."""
    if os.name == "nt":
        base = os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming")
        return Path(base) / "theory"
    if os.uname().sysname == "Darwin":
        return Path.home() / "Library" / "Application Support" / "theory"
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "theory"


def _home() -> Path:
    override = os.environ.get("THEORY_HOME", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.cwd() if is_repo_checkout() else _user_data_dir()


def _cache_root() -> Path:
    override = os.environ.get("THEORY_HOME", "").strip()
    if override:
        return Path(override).expanduser() / ".cache"
    return Path.cwd() / ".cache" if is_repo_checkout() else _user_cache_dir()


# Deliberately functions, not module-level constants: the correct answer
# depends on the current working directory, and a constant captured at
# import time is wrong for anything that chdir()s afterwards (notably the
# test suite, and `theory serve` under uvicorn).

def cache_root() -> Path:
    """Root of the on-disk cache tree."""
    return _cache_root()


def output_dir() -> Path:
    """Root of the generated-output tree."""
    return _home() / "output"


def cache_subdir(name: str) -> Path:
    """A per-source cache directory, created on demand."""
    path = _cache_root() / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def dossier_dir() -> Path:
    path = _home() / "output" / "dossiers"
    path.mkdir(parents=True, exist_ok=True)
    return path


def graph_path() -> Path:
    return _home() / "output" / "graph" / "graph.json"
