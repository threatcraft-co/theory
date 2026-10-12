"""
theory.actors
-------------
One authoritative answer to "which actor is this?", and one matcher for
"does this text mention that actor?"

Why these are separate
----------------------
THEORY previously used a single alias list for both jobs. That list is
derived from MISP Galaxy, which is deliberately recall-oriented: it merges
names that other catalogs keep apart (Lazarus absorbs APT38 and Moonstone
Sleet; APT41 absorbs APT17 and Winnti; Charming Kitten absorbs CURIUM), and
it contains hundreds of short, ambiguous strings — `ups`, `lead`, `npu`,
`snake`, `zinc`, `sea`, `mask`.

Used for *identity*, that list made the MITRE collector return the wrong
group for 8 of 40 flagship actors: `--actor "Lazarus Group"` resolved to
APT38, `--actor APT41` to APT17. Used for *recall* with substring matching,
`ups` matched the word "groups" and attributed an unrelated ransomware
advisory to APT3.

So:

    identity  — exact match only, against the user's input and a curated
                set of names that unambiguously denote one actor, with a
                pinned MITRE/MISP/Malpedia id where one is known. Never
                substring. Ambiguity is an error, not a first-match guess.

    recall    — a compiled word-boundary regex over a filtered alias set,
                used to decide whether a document is about the actor.
                Never used to choose which actor a source is describing.

Public API
----------
    registry()                      -> ActorRegistry (cached)
    registry().resolve("apt28")     -> ActorIdentity | raises
    mentions(identity, text)        -> list of alias hits found in text
    text_matcher(identity)          -> compiled re.Pattern
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "ActorIdentity", "ActorRegistry", "ActorNotFound", "AmbiguousActor",
    "registry", "mentions", "text_matcher", "normalize_name",
    "STOP_ALIASES", "is_id_alias",
]


# ---------------------------------------------------------------------------
# Alias hygiene
# ---------------------------------------------------------------------------

# Aliases that are ordinary English words or otherwise too generic to be
# evidence that a document is about an actor. They stay usable as *identity*
# names (someone typing `--actor zinc` means Lazarus and nothing else), but
# are never used to decide that a piece of prose mentions the actor.
#
# Derived from the v2.0 audit's scan of config/actors.yaml: 335 aliases are
# <=5 characters and 154 collide across actors as substrings.
STOP_ALIASES = frozenset({
    "ups", "lead", "npu", "snake", "zinc", "gop", "basin", "sea", "mask",
    "venom", "thor", "lexus", "axiom", "boron", "dune", "tick", "nitro",
    "indra", "madi", "infy", "uca", "cca", "uuc", "tsb", "rtm", "sexi",
    "mimo", "pupa", "nian", "sima", "kazu", "hezb", "orova", "masan",
    "aiz", "cvnx", "frwl", "npu", "ups", "gref", "lurid", "karba", "nemim",
    "nemin", "man1", "procc", "qtfy", "uteus", "vovan", "zarya", "linkc",
    "luder", "danti", "sarit", "sayad", "huapi", "hagga", "smugx",
})

# Short identifier-style aliases (APT28, FIN7, TA505, G0007, UNC1234).
# These are safe for recall despite being short, because they are
# distinctive tokens rather than words — but only with a word boundary and
# an exact numeric match, so apt1 does not match apt10.
_ID_ALIAS_RE = re.compile(
    r"^(apt|fin|ta|unc|atk|itg|sig|gc|g|temp\.|dev-|storm-|uat|utc)\s*-?\d+$",
    re.IGNORECASE,
)

_MIN_RECALL_LENGTH = 4


def is_id_alias(alias: str) -> bool:
    """True for short identifier-style aliases like apt28, ta505, g0007."""
    return bool(_ID_ALIAS_RE.match(alias.strip()))


def normalize_name(name: str) -> str:
    """Case- and whitespace-insensitive key for exact identity lookup."""
    return " ".join(str(name).strip().lower().split())


def _loose_key(name: str) -> str:
    """Alphanumerics only, so 'Scattered Spider', 'scattered-spider' and
    'scatteredspider' share a key. Used only as a second exact pass — never
    as a substring search."""
    return "".join(ch for ch in str(name).lower() if ch.isalnum())


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ActorIdentity:
    """A resolved actor. `canonical` is THEORY's name for it; the pinned ids
    are how each source is addressed directly instead of by name match."""

    canonical: str
    mitre_id: str | None = None
    misp_uuid: str | None = None
    malpedia_id: str | None = None
    otx_slug: str | None = None
    origin: str = ""
    motivation: str = ""
    identity_names: frozenset[str] = field(default_factory=frozenset)
    recall_terms: frozenset[str] = field(default_factory=frozenset)
    contested: frozenset[str] = field(default_factory=frozenset)

    def __hash__(self) -> int:              # cached by text_matcher
        return hash((self.canonical, self.recall_terms))


class ActorNotFound(LookupError):
    def __init__(self, query: str, suggestions: list[str] | None = None):
        self.query = query
        self.suggestions = suggestions or []
        super().__init__(f"unknown actor: {query!r}")


class AmbiguousActor(LookupError):
    def __init__(self, query: str, candidates: list[str]):
        self.query = query
        self.candidates = candidates
        super().__init__(f"{query!r} matches several actors: {', '.join(candidates)}")


class ActorRegistry:
    """Exact-match actor lookup over the curated table in actors.yaml."""

    def __init__(self, entries: dict[str, dict[str, Any]]):
        self._entries = entries
        self._by_exact: dict[str, set[str]] = {}
        self._by_loose: dict[str, set[str]] = {}

        for canonical, meta in entries.items():
            names = {canonical, *(meta.get("identity_names") or [])}
            for name in names:
                if not name:
                    continue
                self._by_exact.setdefault(normalize_name(name), set()).add(canonical)
                self._by_loose.setdefault(_loose_key(name), set()).add(canonical)

    # ── lookup ──────────────────────────────────────────────────────
    def resolve(self, query: str) -> ActorIdentity:
        """Resolve a user-supplied name to exactly one actor.

        Raises AmbiguousActor when a name legitimately denotes more than one
        actor, and ActorNotFound (with suggestions) when nothing matches.
        Never falls back to substring matching: that is what turned
        `--actor a` into a confident APT1 dossier.
        """
        if not query or not query.strip():
            raise ActorNotFound(query, [])

        for index, key in ((self._by_exact, normalize_name(query)),
                           (self._by_loose, _loose_key(query))):
            hits = index.get(key)
            if not hits:
                continue
            if len(hits) == 1:
                return self.identity(next(iter(hits)))
            raise AmbiguousActor(query, sorted(hits))

        raise ActorNotFound(query, self.suggest(query))

    def get(self, query: str) -> ActorIdentity | None:
        """resolve() but returns None instead of raising."""
        try:
            return self.resolve(query)
        except LookupError:
            return None

    def identity(self, canonical: str) -> ActorIdentity:
        meta = self._entries.get(canonical, {})
        return ActorIdentity(
            canonical      = canonical,
            mitre_id       = meta.get("mitre_id") or None,
            misp_uuid      = meta.get("misp_uuid") or None,
            malpedia_id    = meta.get("malpedia_id") or None,
            otx_slug       = meta.get("otx_slug") or None,
            origin         = meta.get("origin") or "",
            motivation     = meta.get("motivation") or "",
            identity_names = frozenset(
                normalize_name(n) for n in
                {canonical, *(meta.get("identity_names") or [])} if n
            ),
            recall_terms   = frozenset(_build_recall_terms(canonical, meta)),
            contested      = frozenset(
                normalize_name(c) for c in (meta.get("contested") or [])
            ),
        )

    def suggest(self, query: str, limit: int = 3) -> list[str]:
        """Close canonical names, for a 'did you mean' hint."""
        import difflib

        matches = difflib.get_close_matches(
            normalize_name(query), list(self._by_exact), n=limit * 4, cutoff=0.7
        )
        out: list[str] = []
        for match in matches:
            for canonical in sorted(self._by_exact[match]):
                if canonical not in out:
                    out.append(canonical)
                if len(out) >= limit:
                    return out
        return out

    # ── introspection ───────────────────────────────────────────────
    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, canonical: str) -> bool:
        return canonical in self._entries

    def canonical_names(self) -> list[str]:
        return sorted(self._entries)

    def entry(self, canonical: str) -> dict[str, Any]:
        return self._entries.get(canonical, {})


def _build_recall_terms(canonical: str, meta: dict[str, Any]) -> set[str]:
    """Aliases usable as evidence that a document is about this actor.

    Drops stop-words and anything too short to be distinctive, unless it is
    an identifier-style alias (apt28, ta505) where the word boundary plus an
    exact numeric match makes it safe.
    """
    terms: set[str] = set()
    candidates = [canonical, *(meta.get("recall_aliases") or meta.get("identity_names") or [])]
    for alias in candidates:
        normalized = normalize_name(alias)
        if not normalized or normalized in STOP_ALIASES:
            continue
        if len(normalized) < _MIN_RECALL_LENGTH and not is_id_alias(normalized):
            continue
        terms.add(normalized)
    return terms


# ---------------------------------------------------------------------------
# Recall — "does this text mention the actor?"
# ---------------------------------------------------------------------------

def _term_pattern(term: str) -> str:
    """Regex fragment for one alias.

    Identifier-style aliases tolerate an internal separator so `apt41`,
    `APT 41` and `APT-41` all match, while the trailing digits must match
    exactly so `apt4` never matches `apt41`. Multi-word names tolerate a
    space, hyphen or underscore between words.
    """
    match = re.match(r"^([a-z.\-]+?)[\s\-_]*(\d+)$", term)
    if match and is_id_alias(term):
        stem = re.escape(match.group(1).rstrip("-_ "))
        return rf"{stem}[\s\-_]?{match.group(2)}"
    return re.escape(term).replace(r"\ ", r"[\s\-_]?")


@lru_cache(maxsize=512)
def text_matcher(identity: ActorIdentity) -> re.Pattern[str] | None:
    """Compiled word-boundary matcher for an actor's recall terms.

    Returns None when an actor has no usable recall terms (every alias was
    a stop-word or too short) — callers must treat that as "cannot match on
    text", not as "matches everything".
    """
    if not identity.recall_terms:
        return None
    # Longest first so the alternation reports the most specific hit.
    parts = sorted(
        (_term_pattern(t) for t in identity.recall_terms),
        key=len, reverse=True,
    )
    # (?<![a-z0-9]) / (?![a-z0-9]) rather than \b: \b would let "apt41"
    # match inside "apt415", since \b sits between a digit and a letter.
    return re.compile(
        r"(?<![a-z0-9])(?:" + "|".join(parts) + r")(?![a-z0-9])",
        re.IGNORECASE,
    )


def mentions(identity: ActorIdentity, *texts: str) -> list[str]:
    """Distinct alias hits across the given texts, lowercased.

    Callers decide how much evidence they need: one hit in a title is
    strong, one hit in a long body is weak.
    """
    matcher = text_matcher(identity)
    if matcher is None:
        return []
    blob = " ".join(t for t in texts if t)
    if not blob:
        return []
    return sorted({m.group(0).lower() for m in matcher.finditer(blob)})


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

_REGISTRY_CACHE: ActorRegistry | None = None


def load_entries() -> dict[str, dict[str, Any]]:
    """Read actors.yaml via theory.paths (packaged, overridable)."""
    import yaml

    from theory.paths import config_file

    path = config_file("actors.yaml")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        logger.warning(
            "actors.yaml not found at %s — actor resolution unavailable. "
            "Set THEORY_CONFIG_DIR to a directory containing it.", path,
        )
        return {}
    except Exception as exc:
        logger.error("Failed to load %s: %s", path, exc)
        return {}

    actors = data.get("actors") or {}
    return {k: v for k, v in actors.items() if isinstance(v, dict)}


def registry(*, reload: bool = False) -> ActorRegistry:
    """The process-wide actor registry."""
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is None or reload:
        _REGISTRY_CACHE = ActorRegistry(load_entries())
        text_matcher.cache_clear()
    return _REGISTRY_CACHE
