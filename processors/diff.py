"""
processors/diff.py
-------------------
`theory diff` — what changed for an actor since the last run.

reporters/json_reporter.py's JsonReporter.save() always overwrites
output/dossiers/{slug}.json with the latest profile. This feature adds
one line to that: before overwriting, rotate the file that's about to be
replaced to output/dossiers/{slug}.previous.json. That gives every actor
exactly one step of history for free — no new storage format, no extra
flag on an ordinary run, nothing to opt into.

diff_profiles() compares two CommonSchema-shaped profiles and reports,
per category, what was added, removed, and (for the two categories that
carry a confidence field) what shifted confidence tier. This is pure,
offline, and has nothing to do with the persistent correlation graph in
processors/graph.py — the graph tracks identity and connectivity across
every actor ever queried; this tracks one actor's profile across its own
two most recent runs.

Identity per category — the key used to decide "is this the same item":
  techniques  -> technique_id (uppercased)
  malware     -> name (lowercased)
  indicators  -> f"{type}:{value}" (value lowercased)
  cves        -> cve_id (uppercased)
  campaigns   -> name (lowercased)
"""
from __future__ import annotations

from typing import Any, Callable


def _tech_key(t: dict) -> str:
    return (t.get("technique_id") or "").strip().upper()


def _mal_key(m: dict) -> str:
    return (m.get("name") or "").strip().lower()


def _ioc_key(i: dict) -> str:
    itype = (i.get("type") or "").strip().lower()
    value = (i.get("value") or "").strip().lower()
    if not itype or not value:
        return ""
    return f"{itype}:{value}"


def _cve_key(c: dict) -> str:
    return (c.get("cve_id") or "").strip().upper()


def _camp_key(c: dict) -> str:
    return (c.get("name") or "").strip().lower()


def _diff_category(
    old_items: list[dict] | None,
    new_items: list[dict] | None,
    key_fn: Callable[[dict], str],
    track_confidence: bool = False,
) -> dict[str, Any]:
    old_by_key = {key_fn(i): i for i in (old_items or []) if isinstance(i, dict) and key_fn(i)}
    new_by_key = {key_fn(i): i for i in (new_items or []) if isinstance(i, dict) and key_fn(i)}

    added   = [new_by_key[k] for k in sorted(new_by_key.keys() - old_by_key.keys())]
    removed = [old_by_key[k] for k in sorted(old_by_key.keys() - new_by_key.keys())]

    result: dict[str, Any] = {"added": added, "removed": removed}

    if track_confidence:
        changes = []
        for k in sorted(old_by_key.keys() & new_by_key.keys()):
            old_conf = old_by_key[k].get("confidence")
            new_conf = new_by_key[k].get("confidence")
            if old_conf and new_conf and old_conf != new_conf:
                changes.append({"key": k, "from": old_conf, "to": new_conf})
        result["confidence_changes"] = changes

    return result


def diff_profiles(old: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, Any]:
    """Compare two actor profiles.

    `old` may be None or empty (no prior snapshot — e.g. the first time
    this actor has ever been queried). In that case everything in `new`
    is reported as added and `is_first_run` is True, rather than treating
    an absent baseline as "nothing to compare."
    """
    old = old or {}

    return {
        "actor_name":   new.get("actor_name") or old.get("actor_name") or "unknown",
        "is_first_run": not bool(old),
        "techniques":   _diff_category(old.get("techniques"), new.get("techniques"), _tech_key, track_confidence=True),
        "malware":      _diff_category(old.get("malware"),    new.get("malware"),    _mal_key),
        "indicators":   _diff_category(old.get("indicators"), new.get("indicators"), _ioc_key, track_confidence=True),
        "cves":         _diff_category(old.get("cves"),       new.get("cves"),       _cve_key),
        "campaigns":    _diff_category(old.get("campaigns"),  new.get("campaigns"),  _camp_key),
    }


_CATEGORIES = ("techniques", "malware", "indicators", "cves", "campaigns")


def has_changes(diff: dict[str, Any]) -> bool:
    """True if diff_profiles() found anything added, removed, or
    confidence-shifted in any category."""
    for cat in _CATEGORIES:
        c = diff.get(cat, {})
        if c.get("added") or c.get("removed") or c.get("confidence_changes"):
            return True
    return False
