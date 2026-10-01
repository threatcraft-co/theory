"""
collectors/personal_intel.py
-----------------------------
Personal research indicators — the gitignored redirect pattern.

THEORY is a shared, open-source tool, but analysts using it for their own
research (a lab sample, an incident they're personally tracking, an IOC a
colleague sent them off-platform) need somewhere to put that data that is
GUARANTEED to never end up in a commit, a PR diff, or a `git log`, however
it's used day to day.

A single gitignored file is one accident away from exposure — someone runs
`git add -A`, a pre-commit hook gets skipped, a fork's .gitignore doesn't
match. This module uses two layers instead of one:

  1. config/local_sources.yaml — a small REDIRECT file, gitignored, that
     lives inside the repo tree. It contains no indicators at all — only
     a path.
  2. The path it points to — the actual personal_indicators.yaml, which
     by default lives OUTSIDE the repo entirely (~/.theory/ in the user's
     home directory), so even a catastrophic .gitignore failure on the
     redirect file would expose a pointer, not the research itself. Users
     who want it can still point the redirect at a path inside the repo
     (under a gitignored directory) — the redirect supports any absolute
     path — but the default favors keeping personal research off the
     repo's disk footprint altogether.

Set up with:
    theory --init-personal                      # default: ~/.theory/personal_indicators.yaml
    theory --init-personal --personal-path /custom/path.yaml

Then query it like any other source:
    theory --actor APT28 --sources personal,mitre,cisa

Scope note: this collector matches personal indicators to an actor query
by the optional `actor` field on each indicator (resolved through THEORY's
existing alias table, so "Fancy Bear" matches indicators tagged "APT28").
Indicators with no `actor` tag are pure personal notes — they're never
pulled into an actor dossier automatically, by design; THEORY's query
model is actor-centric, and auto-surfacing unattributed personal notes
into unrelated actor reports would be more surprising than useful. They
still live in your personal file and are yours to reference directly.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover — PyYAML is already a hard dependency
    yaml = None

logger = logging.getLogger(__name__)

SOURCE_ID = "personal"

REDIRECT_PATH = Path("config/local_sources.yaml")
DEFAULT_PERSONAL_PATH = Path.home() / ".theory" / "personal_indicators.yaml"

CANONICAL_TYPES = frozenset({
    "domain", "ip", "hash_md5", "hash_sha256", "hash_sha1", "url", "email",
})

REDIRECT_TEMPLATE = """\
# config/local_sources.yaml
# ---------------------------------------------------------------------
# THEORY personal research redirect — THIS FILE IS GITIGNORED.
#
# It never leaves your machine and is never committed, by design. It
# holds no indicators itself — only a path to where your own research
# file actually lives. That target is yours to place anywhere: outside
# this repo entirely (the default), or inside it under a gitignored
# directory if you'd rather keep everything local to the project.
#
# Regenerate or repoint this file any time with:
#   theory --init-personal
#   theory --init-personal --personal-path /custom/path.yaml
# ---------------------------------------------------------------------
personal_indicators_path: "{path}"
"""

PERSONAL_TEMPLATE = """\
# Your personal threat-research indicators.
#
# This file lives outside THEORY's repo tree by default and is never
# read by anyone but you and your own local THEORY install — it is not
# shared, synced, or uploaded anywhere by THEORY itself.
#
# `actor` is optional. Leave it out for indicators you haven't
# attributed to anything yet (pure personal notes). Set it to an actor
# name or any known alias to have `theory --actor <name> --sources
# personal,...` fold this indicator into that actor's dossier and the
# persistent correlation graph.
#
# type must be one of: domain, ip, hash_md5, hash_sha256, hash_sha1, url, email
indicators: []
#  - type: ip
#    value: "198.51.100.23"
#    actor: "APT28"
#    context: "C2 observed during my own lab analysis"
#    first_seen: "2026-09-30"
"""


# ---------------------------------------------------------------------------
# Setup — theory --init-personal
# ---------------------------------------------------------------------------

def init_personal(path: str | None = None) -> Path:
    """`theory --init-personal` — create the redirect file (and a starter
    personal indicators file if one doesn't exist yet).

    Idempotent and non-destructive: re-running never overwrites an
    existing personal indicators file, so running this again (e.g. to
    repoint at a new --personal-path) never costs you research you've
    already recorded. The redirect file itself is always rewritten, since
    it holds nothing but the pointer.
    """
    target = Path(path).expanduser().resolve() if path else DEFAULT_PERSONAL_PATH.resolve()

    REDIRECT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REDIRECT_PATH.write_text(REDIRECT_TEMPLATE.format(path=str(target)))

    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_text(PERSONAL_TEMPLATE)

    return target


def _load_redirect() -> Path | None:
    """Read config/local_sources.yaml and return the configured personal
    indicators path, or None if it hasn't been set up."""
    if yaml is None or not REDIRECT_PATH.exists():
        return None
    try:
        data = yaml.safe_load(REDIRECT_PATH.read_text()) or {}
    except Exception as exc:
        logger.warning("personal: could not read %s: %s", REDIRECT_PATH, exc)
        return None
    raw_path = data.get("personal_indicators_path") if isinstance(data, dict) else None
    if not raw_path:
        return None
    return Path(raw_path).expanduser()


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class PersonalIntelCollector:
    """Reads the user's own local indicators file. Pure local file I/O —
    never touches the network, so it carries no rate limits, no API key,
    and no caching (the file is already on disk; reading it is cheap)."""

    SOURCE_ID = SOURCE_ID

    def query(self, actor_name: str) -> dict[str, Any] | None:
        path = _load_redirect()
        if path is None:
            logger.info(
                "personal: not set up yet. Run `theory --init-personal` to create "
                "the gitignored redirect at config/local_sources.yaml."
            )
            return None
        if not path.exists():
            logger.warning("personal: redirect points to %s, which doesn't exist.", path)
            return None
        if yaml is None:  # pragma: no cover
            logger.warning("personal: PyYAML not installed — cannot read personal indicators.")
            return None

        try:
            data = yaml.safe_load(path.read_text()) or {}
        except Exception as exc:
            logger.warning("personal: failed to parse %s: %s", path, exc)
            return None

        raw_indicators = data.get("indicators") if isinstance(data, dict) else None
        if not raw_indicators:
            return None
        if not isinstance(raw_indicators, list):
            logger.warning("personal: %s 'indicators' key must be a list.", path)
            return None

        try:
            from collectors.cisa_advisories import resolve_canonical
        except Exception:
            resolve_canonical = lambda n: n.strip()  # noqa: E731 — defensive fallback only

        actor_canon = resolve_canonical(actor_name)

        matched: list[dict[str, Any]] = []
        for entry in raw_indicators:
            if not isinstance(entry, dict):
                continue
            entry_actor = (entry.get("actor") or "").strip()
            if not entry_actor or resolve_canonical(entry_actor) != actor_canon:
                continue

            itype = (entry.get("type") or "").strip().lower()
            value = (entry.get("value") or "").strip()
            if itype not in CANONICAL_TYPES or not value:
                logger.warning(
                    "personal: skipping malformed entry (type=%r, value=%r) in %s",
                    itype, value, path,
                )
                continue

            matched.append({
                "type":       itype,
                "value":      value,
                "context":    entry.get("context", ""),
                "first_seen": entry.get("first_seen", ""),
                "sources":    [SOURCE_ID],
            })

        if not matched:
            return None

        return {
            "actor_name":       actor_name,
            "source_id":        SOURCE_ID,
            "source_citation":  "Personal research (local file — not shared, not uploaded)",
            "source_url":       "",
            "retrieved_at":     datetime.now(timezone.utc).isoformat(),
            "aliases":          [],
            "motivations":      [],
            "target_sectors":   [],
            "target_countries": [],
            "techniques":       [],
            "malware":          [],
            "indicators":       matched,
            "campaigns":        [],
            "cves":             [],
            "suspected_origin": None,
            "first_seen":       None,
            "sponsorship":      None,
        }
