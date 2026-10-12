"""
theory.attribution
------------------
How strongly a piece of evidence belongs to the actor it is filed under.

Every indicator THEORY reports used to look identical regardless of how it
was obtained. An IP that CISA named in an advisory about APT28 and an IP
that ThreatFox returned because APT28 is one of hundreds of groups using
Cobalt Strike both arrived as "APT28 indicators" — in the dossier, in the
STIX bundle as `indicator --indicates--> intrusion-set`, in the SIEM CSV,
and as an `actor --reported_ioc--> ioc` edge in the persistent graph.

Three levels, set by whoever produces the indicator:

    ACTOR        A source explicitly ties this to the actor.
                 (CISA advisory about the actor, OTX pulse tagged to the
                 adversary, a CIRCL event naming them, the analyst's own
                 notes.)

    FAMILY       Tied to a malware family the actor uses, not to the actor.
                 (ThreatFox/MalwareBazaar/URLhaus by family name.) Other
                 operators of the same family will share these.

    SHARED_TOOL  Tied to software many unrelated actors use.
                 (Cobalt Strike, Mimikatz, PsExec.) Near-zero attribution
                 value; collected only on request.

Reporters use the level rather than guessing: STIX points FAMILY and
SHARED_TOOL evidence at the malware object instead of the actor, the CSV
export can be filtered before anything reaches a blocklist, and the graph
weights its edges accordingly.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any, Iterable

logger = logging.getLogger(__name__)

__all__ = [
    "ACTOR", "FAMILY", "SHARED_TOOL", "LEVELS", "WEIGHTS",
    "shared_tooling_names", "is_shared_tooling",
    "attribution_of", "weight_of", "tag_indicators",
    "split_families",
]

ACTOR = "actor"
FAMILY = "family"
SHARED_TOOL = "shared_tool"

LEVELS = (ACTOR, FAMILY, SHARED_TOOL)

# Graph edge weight per level. Used by processors.graph to decide whether a
# path between two entities is real evidence or an artefact of shared tools.
WEIGHTS: dict[str, float] = {
    ACTOR:       1.0,
    FAMILY:      0.4,
    SHARED_TOOL: 0.1,
}


def _normalize(name: str) -> str:
    return " ".join(str(name).strip().lower().split())


@lru_cache(maxsize=1)
def shared_tooling_names() -> frozenset[str]:
    """Normalised names of software too widely shared to attribute."""
    import yaml

    from theory.paths import config_file

    path = config_file("shared_tooling.yaml")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        logger.warning(
            "shared_tooling.yaml not found at %s — every malware family will "
            "be treated as actor-specific for IOC enrichment.", path,
        )
        return frozenset()
    except Exception as exc:
        logger.error("Failed to load %s: %s", path, exc)
        return frozenset()

    return frozenset(
        _normalize(n) for n in (data.get("shared_tooling") or []) if n
    )


def is_shared_tooling(name: str) -> bool:
    """True when this software is used by too many actors to attribute."""
    if not name:
        return False
    return _normalize(name) in shared_tooling_names()


def attribution_of(indicator: dict[str, Any]) -> str:
    """The attribution level recorded on an indicator.

    Falls back to FAMILY when an indicator carries a malware family but no
    explicit level (that is how it was obtained), and ACTOR otherwise —
    matching how pre-attribution data was implicitly treated, so older
    saved profiles still read sensibly.
    """
    level = str(indicator.get("attribution") or "").strip().lower()
    if level in LEVELS:
        return level
    if indicator.get("malware_family"):
        return SHARED_TOOL if is_shared_tooling(indicator["malware_family"]) else FAMILY
    return ACTOR


def weight_of(indicator: dict[str, Any]) -> float:
    return WEIGHTS.get(attribution_of(indicator), WEIGHTS[FAMILY])


def tag_indicators(
    indicators: Iterable[dict[str, Any]],
    level: str,
    *,
    family: str | None = None,
) -> list[dict[str, Any]]:
    """Stamp an attribution level onto freshly collected indicators.

    SHARED_TOOL wins over the requested level when the family is in the
    shared-tooling list, so a caller cannot accidentally promote Cobalt
    Strike infrastructure to actor-attributed evidence.
    """
    if level not in LEVELS:
        raise ValueError(f"unknown attribution level: {level!r}")

    out: list[dict[str, Any]] = []
    for indicator in indicators:
        tagged = dict(indicator)
        effective = level
        candidate_family = family or tagged.get("malware_family") or ""
        if candidate_family and is_shared_tooling(candidate_family):
            effective = SHARED_TOOL
        tagged["attribution"] = effective
        if family and not tagged.get("malware_family"):
            tagged["malware_family"] = family
        out.append(tagged)
    return out


def split_families(
    malware: Iterable[dict[str, Any] | str],
    *,
    include_shared: bool = False,
) -> tuple[list[str], list[str]]:
    """Partition malware names into (attributable, shared) for enrichment.

    `malware` accepts the profile's malware entries or bare names. MITRE's
    "software used by group" mixes tools in with malware, which is how
    Mimikatz and PsExec ended up driving abuse.ch IOC lookups whose results
    were then presented as the actor's own infrastructure.
    """
    attributable: list[str] = []
    shared: list[str] = []

    for entry in malware:
        if isinstance(entry, str):
            name, sw_type = entry, ""
        else:
            name = entry.get("name") or ""
            sw_type = str(entry.get("type") or "").strip().lower()
        if not name:
            continue

        # MITRE labels these "tool" rather than "malware"; a tool is by
        # definition something more than one group picked up.
        if is_shared_tooling(name) or sw_type == "tool":
            shared.append(name)
        else:
            attributable.append(name)

    if include_shared:
        return attributable + shared, []
    return attributable, shared
