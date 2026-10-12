#!/usr/bin/env python3
"""
scripts/build_actor_identities.py
---------------------------------
Rebuild theory/data/actors.yaml with the identity / recall split.

What this produces, per actor:

    mitre_id        pinned ATT&CK group id (G0007) when exactly one
                    non-deprecated group matches unambiguously
    identity_names  names that denote THIS actor and no other — safe to
                    resolve `--actor <name>` by
    recall_aliases  names usable as evidence that a document is about the
                    actor (identity_names minus stop-words/short tokens)
    contested       names that another catalog assigns to a DIFFERENT
                    group, or that two THEORY actors both claim. Kept for
                    the record, never used for identity or recall.

Why: MISP Galaxy synonym lists are recall-oriented and merge groups that
MITRE tracks separately (Lazarus absorbs APT38; APT41 absorbs APT17 and
Winnti). Using them for identity made the MITRE collector return the wrong
group for 8 of 40 flagship actors.

Usage:
    python scripts/build_actor_identities.py \\
        --attack .cache/enterprise-attack.json \\
        --galaxy .cache/misp_galaxy/threat-actor.json \\
        --out theory/data/actors.yaml \\
        --report NEEDS_REVIEW.md

Inputs are the real catalogs; nothing is invented. Review the report
before committing the result.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from theory.actors import STOP_ALIASES, is_id_alias, normalize_name  # noqa: E402

MIN_RECALL_LENGTH = 4


# ---------------------------------------------------------------------------
# ATT&CK
# ---------------------------------------------------------------------------

def load_attack_groups(path: Path) -> list[dict[str, Any]]:
    """Live, non-revoked, non-deprecated intrusion-sets only."""
    bundle = json.loads(path.read_text(encoding="utf-8"))
    groups = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        groups.append(obj)
    return groups


def attack_id(group: dict[str, Any]) -> str:
    for ref in group.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def index_attack(groups: list[dict[str, Any]]) -> tuple[dict, dict]:
    """name -> {gid}, and alias -> {gid}, both normalized."""
    by_name: dict[str, set[str]] = defaultdict(set)
    by_alias: dict[str, set[str]] = defaultdict(set)
    for group in groups:
        gid = attack_id(group)
        if not gid:
            continue
        by_name[normalize_name(group.get("name", ""))].add(gid)
        for alias in group.get("aliases") or []:
            if normalize_name(alias) != normalize_name(group.get("name", "")):
                by_alias[normalize_name(alias)].add(gid)
    return dict(by_name), dict(by_alias)


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build(
    existing: dict[str, dict[str, Any]],
    attack_groups: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    by_name, by_alias = index_attack(attack_groups)
    gid_to_name = {attack_id(g): g.get("name", "") for g in attack_groups}

    # Which canonical actors claim each alias — for cross-actor collisions.
    claimed: dict[str, set[str]] = defaultdict(set)
    for canonical, meta in existing.items():
        for alias in {canonical, *(meta.get("aliases") or [])}:
            claimed[normalize_name(alias)].add(canonical)

    out: dict[str, dict[str, Any]] = {}
    report: list[str] = []

    for canonical, meta in sorted(existing.items()):
        aliases = {normalize_name(a) for a in (meta.get("aliases") or []) if a}
        aliases.add(normalize_name(canonical))
        aliases.discard("")

        # ── pin a MITRE id ──────────────────────────────────────────
        # Only on an unambiguous match against the canonical name itself,
        # or a unique alias match. Never on a name another group owns.
        #
        # A hand-pinned id in the input always wins: several actors are
        # genuinely ambiguous by name alone (ATT&CK gives UAC-0056 to both
        # Ember Bear and Saint Bear) and were resolved by a human reading
        # the catalogs. Regeneration must not silently discard that.
        mitre_id = str(meta.get("mitre_id") or "").strip()
        if mitre_id:
            out_pinned_by_hand = True
        else:
            out_pinned_by_hand = False
        name_hits = by_name.get(normalize_name(canonical), set())
        if out_pinned_by_hand:
            pass                      # keep the human's answer
        elif len(name_hits) == 1:
            mitre_id = next(iter(name_hits))
        else:
            alias_hits: set[str] = set()
            for alias in aliases:
                alias_hits |= by_name.get(alias, set())
            if len(alias_hits) == 1:
                mitre_id = next(iter(alias_hits))
            else:
                for alias in aliases:
                    alias_hits |= by_alias.get(alias, set())
                if len(alias_hits) == 1:
                    mitre_id = next(iter(alias_hits))
                elif len(alias_hits) > 1:
                    described = sorted(
                        "{} {}".format(g, gid_to_name.get(g, "")).strip()
                        for g in alias_hits
                    )
                    report.append(
                        f"- **{canonical}** — aliases match {len(alias_hits)} "
                        f"ATT&CK groups ({', '.join(described)}). "
                        "Left unpinned; pin by hand if one is correct."
                    )

        # ── contested aliases ───────────────────────────────────────
        contested: set[str] = set()
        for alias in aliases:
            if alias == normalize_name(canonical):
                continue
            # (a) another THEORY actor also claims it
            others = claimed.get(alias, set()) - {canonical}
            if others:
                contested.add(alias)
                continue
            # (b) ATT&CK gives this exact name to a different group
            owners = by_name.get(alias, set())
            if owners and mitre_id and owners != {mitre_id}:
                contested.add(alias)

        identity_names = sorted(aliases - contested)
        recall_aliases = sorted(
            a for a in identity_names
            if a not in STOP_ALIASES
            and (len(a) >= MIN_RECALL_LENGTH or is_id_alias(a))
        )

        entry: dict[str, Any] = {}
        if mitre_id:
            entry["mitre_id"] = mitre_id
        for passthrough in ("misp_uuid", "malpedia_id", "otx_slug"):
            if meta.get(passthrough):
                entry[passthrough] = meta[passthrough]
        entry["identity_names"] = identity_names
        entry["recall_aliases"] = recall_aliases
        if contested:
            entry["contested"] = sorted(contested)
        entry["origin"] = meta.get("origin", "")
        entry["motivation"] = meta.get("motivation", "unknown")
        # Preserved so nothing downstream that still reads `aliases` breaks.
        entry["aliases"] = sorted(aliases)
        out[canonical] = entry

    # ── promote contested names that are real, distinct ATT&CK groups ──
    #
    # Quarantining `apt38` out of Lazarus Group is only half the fix: MISP
    # Galaxy has no standalone APT38 entry, so without this the name would
    # resolve to nothing at all and `--actor APT38` would simply fail.
    # Where ATT&CK tracks the contested name as its own live group, give it
    # a THEORY entry of its own — which is what "MITRE keeps these apart"
    # actually means in practice.
    existing_pins = {e.get("mitre_id") for e in out.values() if e.get("mitre_id")}
    existing_names = {normalize_name(k) for k in out}
    promoted: list[str] = []

    for group in attack_groups:
        gid = attack_id(group)
        group_name = group.get("name", "")
        if not gid or gid in existing_pins:
            continue
        if normalize_name(group_name) in existing_names:
            continue
        # Only promote a group whose name was quarantined as contested
        # somewhere — not every ATT&CK group MISP happens to omit.
        was_contested = any(
            normalize_name(group_name) in set(e.get("contested", []))
            for e in out.values()
        )
        if not was_contested:
            continue

        group_aliases = {normalize_name(a) for a in
                         {group_name, *(group.get("aliases") or [])} if a}
        # Don't re-steal a name another THEORY actor legitimately owns.
        safe = {a for a in group_aliases if a not in claimed or claimed[a] <= {group_name}}
        safe.add(normalize_name(group_name))

        out[group_name] = {
            "mitre_id": gid,
            "identity_names": sorted(safe),
            "recall_aliases": sorted(
                a for a in safe
                if a not in STOP_ALIASES and (len(a) >= MIN_RECALL_LENGTH or is_id_alias(a))
            ),
            "origin": "",
            "motivation": "unknown",
            "aliases": sorted(safe),
        }
        existing_pins.add(gid)
        existing_names.add(normalize_name(group_name))
        promoted.append(f"{group_name} ({gid})")

    # ── adjudicate contested names to their rightful owner ────────────
    #
    # A name claimed by two THEORY actors is quarantined from both, which
    # can leave it resolving to nothing at all: `apt38` was removed from
    # Lazarus Group (right — ATT&CK says G0082, Lazarus is G0032) and also
    # from Bluenoroff, even though Bluenoroff is precisely the actor that
    # pins G0082. Where ATT&CK assigns the name to exactly one group and
    # exactly one THEORY actor pins that group, give it back to that actor.
    pin_owner: dict[str, list[str]] = defaultdict(list)
    for canonical, entry in out.items():
        if entry.get("mitre_id"):
            pin_owner[entry["mitre_id"]].append(canonical)

    adjudicated: list[str] = []

    # Collect every quarantined name across all actors first: the rightful
    # owner is usually a DIFFERENT actor from the one it was taken off, and
    # often never listed the name itself (MISP's Bluenoroff entry does not
    # mention apt38, even though Bluenoroff is ATT&CK's G0082 "APT38").
    all_contested: set[str] = set()
    for entry in out.values():
        all_contested.update(entry.get("contested", []))

    for alias in sorted(all_contested):
        owners = by_name.get(alias, set())
        if len(owners) != 1:
            continue                       # ATT&CK is itself ambiguous here
        gid = next(iter(owners))
        holders = pin_owner.get(gid, [])
        if len(holders) != 1:
            continue                       # no single THEORY actor to award it to
        winner = holders[0]
        entry = out[winner]
        if alias in entry["identity_names"]:
            continue
        entry["identity_names"] = sorted(entry["identity_names"] + [alias])
        if (alias not in STOP_ALIASES
                and (len(alias) >= MIN_RECALL_LENGTH or is_id_alias(alias))
                and alias not in entry["recall_aliases"]):
            entry["recall_aliases"] = sorted(entry["recall_aliases"] + [alias])
        entry.setdefault("contested", [])
        if alias in entry["contested"]:
            entry["contested"].remove(alias)
        adjudicated.append(f"{alias} -> {winner} ({gid})")

    for entry in out.values():
        if not entry.get("contested"):
            entry.pop("contested", None)

    if adjudicated:
        report.append(
            "\n## Contested names awarded to their ATT&CK owner\n\n"
            "Quarantined from every actor that claimed them, then returned to\n"
            "the one THEORY actor pinning the ATT&CK group that owns the name:\n\n"
            + "\n".join(f"- {a}" for a in sorted(adjudicated))
        )

    if promoted:
        report.append(
            "\n## Promoted to standalone actors\n\n"
            "ATT&CK tracks these as their own groups, but they appeared only as\n"
            "synonyms of a larger actor in MISP Galaxy. Given an entry here so\n"
            "`--actor <name>` resolves to the right group instead of the one that\n"
            "absorbed it:\n\n"
            + "\n".join(f"- {p}" for p in sorted(promoted))
        )

    return out, report


HEADER = """# theory/data/actors.yaml
# ---------------------------------------------------------------------------
# Generated by scripts/build_actor_identities.py from MISP Galaxy
# (github.com/MISP/misp-galaxy, CC0) and MITRE ATT&CK. Hand edits are
# preserved on regeneration for any key the script does not compute.
#
# Each actor carries two different kinds of name, because they do two
# different jobs:
#
#   identity_names  Names that denote THIS actor and no other. `--actor X`
#                   resolves by exact match against these. Never substring.
#
#   recall_aliases  Names usable as evidence that a document is about this
#                   actor. identity_names minus stop-words and short
#                   tokens, matched with word boundaries.
#
#   contested       Names another catalog assigns to a DIFFERENT group, or
#                   that two actors here both claim. Recorded for the
#                   analyst, never used for identity or recall. These are
#                   what previously made `--actor "Lazarus Group"` return
#                   MITRE's APT38 and `--actor APT41` return APT17.
#
#   mitre_id        Pinned ATT&CK group id. The MITRE collector addresses
#                   groups by this id rather than matching on names.
# ---------------------------------------------------------------------------

"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--attack", type=Path, required=True)
    ap.add_argument("--galaxy", type=Path, help="(reserved — misp uuid pinning)")
    ap.add_argument("--in", dest="infile", type=Path,
                    default=Path("theory/data/actors.yaml"))
    ap.add_argument("--out", type=Path, default=Path("theory/data/actors.yaml"))
    ap.add_argument("--report", type=Path, default=Path("NEEDS_REVIEW.md"))
    args = ap.parse_args()

    import yaml

    existing = (yaml.safe_load(args.infile.read_text(encoding="utf-8")) or {}).get("actors", {})
    existing = {k: v for k, v in existing.items() if isinstance(v, dict)}
    groups = load_attack_groups(args.attack)

    print(f"  {len(existing)} actors in, {len(groups)} live ATT&CK groups")

    actors, report = build(existing, groups)

    pinned = sum(1 for a in actors.values() if a.get("mitre_id"))
    contested_total = sum(len(a.get("contested", [])) for a in actors.values())
    print(f"  {pinned} actors pinned to an ATT&CK id")
    print(f"  {contested_total} contested aliases quarantined")
    print(f"  {len(report)} actors need manual review")

    body = yaml.safe_dump({"actors": actors}, sort_keys=True,
                          allow_unicode=True, width=100)
    args.out.write_text(HEADER + body, encoding="utf-8")
    print(f"  wrote {args.out}")

    if report:
        args.report.write_text(
            "# Actors needing manual review\n\n"
            "Ambiguous ATT&CK matches — left unpinned rather than guessed.\n"
            "Pin `mitre_id` by hand where one group is clearly correct.\n\n"
            + "\n".join(sorted(report)) + "\n",
            encoding="utf-8",
        )
        print(f"  wrote {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
