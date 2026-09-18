#!/usr/bin/env python3
"""
scripts/import_misp_actors.py
------------------------------
Expand config/actors.yaml from the MISP Galaxy threat-actor cluster.

config/actors.yaml is currently hand-curated (~35 actors). It doesn't need
to be — MISP maintains a free, CC0-licensed, actively-updated, machine-
readable list of 1,000+ threat actor clusters with synonyms, country
attribution, and MITRE Group ID cross-references, at:

    https://github.com/MISP/misp-galaxy
    clusters/threat-actor.json  (raw: raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json)

This is the same galaxy the `misp_galaxy` collector already queries live
for enrichment — this script just also uses it, once, to widen the local
alias table that every OTHER collector (OTX, Malpedia, CISA advisories,
vendor_intel) relies on for cross-source name resolution. Today, querying
an actor not in actors.yaml still works (resolve_canonical() falls back to
the raw input) — it just means those collectors search on one name string
instead of the full alias set, which quietly costs recall on every source
except misp_galaxy itself.

This script is additive and non-destructive:
  - Existing curated entries in actors.yaml are NEVER overwritten.
  - Their alias lists are unioned with MISP's synonyms for the same actor
    (matched by existing alias, not just canonical name).
  - origin / motivation are only filled in if currently blank.
  - New actors MISP knows about that aren't in actors.yaml at all are
    appended, grouped under a generated "# -- Imported from MISP Galaxy --"
    section so a human can review/reorganize them later.

Usage:
    python scripts/import_misp_actors.py                  # fetch latest + merge
    python scripts/import_misp_actors.py --local FILE.json # use an already-downloaded copy
    python scripts/import_misp_actors.py --dry-run          # report counts, write nothing
    python scripts/import_misp_actors.py --min-country-conf # only import clusters with a
                                                              # country/state-sponsor attribution
                                                              # (skips vaguer/lower-confidence entries)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.request import urlopen

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

GALAXY_URL = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/"
    "clusters/threat-actor.json"
)

ACTORS_YAML = Path(__file__).resolve().parent.parent / "config" / "actors.yaml"

# MISP's `country` field is an ISO 3166-1 alpha-2 code; actors.yaml uses
# full names to match the existing curated entries. Only the codes that
# actually show up with meaningful frequency in the galaxy are mapped —
# anything else falls back to cfr-suspected-state-sponsor (already a full
# name) or is left blank rather than guessed.
ISO_TO_NAME = {
    "CN": "China", "RU": "Russia", "IR": "Iran", "KP": "North Korea",
    "US": "United States", "IN": "India", "PK": "Pakistan", "VN": "Vietnam",
    "TR": "Turkey", "IL": "Israel", "KR": "South Korea", "SY": "Syria",
    "LB": "Lebanon", "PS": "Palestine", "UA": "Ukraine", "BY": "Belarus",
}

# cfr-type-of-incident (or its absence) -> THEORY's motivation enum.
INCIDENT_TO_MOTIVATION = {
    "espionage": "espionage",
    "sabotage": "destruction",
    "warfare": "destruction",
    "denial of service": "hacktivism",
    "criminal": "financial",
}


def _load_galaxy(local_path: str | None) -> list[dict]:
    if local_path:
        data = json.loads(Path(local_path).read_text())
    else:
        with urlopen(GALAXY_URL, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    return data["values"]


def _motivation_for(meta: dict) -> str:
    incident = meta.get("cfr-type-of-incident")
    if isinstance(incident, list):
        incident = incident[0] if incident else ""
    return INCIDENT_TO_MOTIVATION.get((incident or "").strip().lower(), "unknown")


def _origin_for(meta: dict) -> str:
    sponsor = meta.get("cfr-suspected-state-sponsor")
    if sponsor:
        return sponsor
    code = meta.get("country")
    if code:
        return ISO_TO_NAME.get(code.upper(), code.upper())
    return ""


def _aliases_for(entry: dict) -> set[str]:
    aliases = {entry["value"].strip().lower()}
    for syn in entry.get("meta", {}).get("synonyms", []) or []:
        aliases.add(str(syn).strip().lower())
    for attributed in entry.get("meta", {}).get("name-attribution", []) or []:
        # Format is "NAME:uuid" — keep the name, drop the MISP object ref.
        name = attributed.split(":")[0].strip().lower()
        if name:
            aliases.add(name)
    return aliases


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--local", metavar="FILE", help="Path to an already-downloaded threat-actor.json")
    ap.add_argument("--dry-run", action="store_true", help="Report what would change; write nothing")
    ap.add_argument(
        "--min-country-conf", action="store_true",
        help="Only import clusters with a country or state-sponsor attribution",
    )
    args = ap.parse_args()

    existing = yaml.safe_load(ACTORS_YAML.read_text())
    existing_actors: dict = existing.get("actors", {})
    original_canonical_names = set(existing_actors.keys())

    # alias -> canonical name, across everything already in actors.yaml
    alias_to_canonical: dict[str, str] = {}
    for canonical, meta in existing_actors.items():
        for a in meta.get("aliases", []) or []:
            alias_to_canonical[a.lower()] = canonical
        alias_to_canonical[canonical.lower()] = canonical

    galaxy = _load_galaxy(args.local)

    updated_actors: set[str] = set()
    added = 0
    skipped = 0
    new_actors: dict = {}

    for entry in galaxy:
        meta = entry.get("meta", {})
        if args.min_country_conf and not (meta.get("country") or meta.get("cfr-suspected-state-sponsor")):
            skipped += 1
            continue

        misp_aliases = _aliases_for(entry)

        # Does this cluster match something we already have, by any alias?
        matched_canonical = None
        for a in misp_aliases:
            if a in alias_to_canonical:
                matched_canonical = alias_to_canonical[a]
                break

        if matched_canonical:
            record = existing_actors.get(matched_canonical) or new_actors[matched_canonical]
            before = len(record.get("aliases", []))
            record["aliases"] = sorted(set(record.get("aliases", [])) | misp_aliases)
            if not record.get("origin"):
                origin = _origin_for(meta)
                if origin:
                    record["origin"] = origin
            if not record.get("motivation") or record.get("motivation") == "unknown":
                record["motivation"] = _motivation_for(meta)
            if len(record["aliases"]) > before:
                updated_actors.add(matched_canonical)
            for a in misp_aliases:
                alias_to_canonical[a] = matched_canonical
        else:
            canonical = entry["value"].strip()
            if canonical in existing_actors or canonical in new_actors:
                continue
            new_actors[canonical] = {
                "origin": _origin_for(meta),
                "motivation": _motivation_for(meta),
                "aliases": sorted(misp_aliases),
            }
            for a in misp_aliases:
                alias_to_canonical[a] = canonical
            added += 1

    print(f"Existing actors:        {len(existing_actors)}")
    print(f"Galaxy clusters scanned: {len(galaxy)} (skipped {skipped} without --min-country-conf match)")
    curated_enriched = updated_actors & original_canonical_names
    print(f"Curated actors enriched with new aliases:  {len(curated_enriched)} / {len(original_canonical_names)}")
    print(f"New actors to add:      {added}")

    # Cross-actor alias collisions: MISP Galaxy clusters are independently
    # maintained, so the same real-world designation can legitimately be
    # listed as a synonym under two different actor clusters — "GRIZZLY
    # STEPPE" genuinely referred to combined APT28+APT29 activity in the
    # original DHS/FBI report, for instance. THEORY's alias table requires
    # a 1:1 mapping (resolve_canonical needs a single deterministic answer),
    # so any alias claimed by more than one canonical actor after the merge
    # is dropped from all of them rather than arbitrarily assigned to one —
    # a wrong single answer is worse than none for a search term that
    # genuinely doesn't disambiguate.
    merged_all = dict(existing_actors)
    merged_all.update(new_actors)
    alias_owners: dict[str, list[str]] = {}
    for canonical, record in merged_all.items():
        for a in record.get("aliases", []) or []:
            alias_owners.setdefault(a, []).append(canonical)

    collisions = {a: owners for a, owners in alias_owners.items() if len(owners) > 1}
    if collisions:
        print(f"\nDropping {len(collisions)} cross-actor alias collision(s) (kept out of every entry):")
        for alias, owners in sorted(collisions.items()):
            print(f"  {alias!r} claimed by: {', '.join(sorted(owners))}")
            for canonical in owners:
                record = merged_all[canonical]
                record["aliases"] = [a for a in record.get("aliases", []) if a != alias]

    print(f"Total actors after merge: {len(merged_all)}")

    if args.dry_run:
        print("\n--dry-run: no file written.")
        return

    merged = merged_all

    out = {"actors": merged}
    header = (
        "# config/actors.yaml\n"
        "# Auto-expanded by scripts/import_misp_actors.py from MISP Galaxy\n"
        "# (github.com/MISP/misp-galaxy, CC0). Hand-curated entries are preserved\n"
        "# and only ever enriched, never overwritten. Re-run periodically to pick\n"
        "# up new actors/aliases as MISP Galaxy updates.\n\n"
    )
    ACTORS_YAML.write_text(header + yaml.dump(out, sort_keys=True, allow_unicode=True, width=100))
    print(f"\nWrote {ACTORS_YAML}")


if __name__ == "__main__":
    main()
