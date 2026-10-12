"""
tests/test_actor_identity.py
----------------------------
The regression suite for THEORY's single most important question:
given what the user typed, which actor is this?

Before the identity/recall split, resolution searched the full
MISP-derived alias set and took the first ATT&CK group that intersected
it. MISP synonym lists deliberately merge groups that MITRE tracks
separately, so that returned the wrong group for 8 of the 40 actors
below — `--actor "Lazarus Group"` produced an APT38 dossier, `--actor
APT41` produced APT17, and every downstream section (TTPs, malware,
Sigma coverage, IOC enrichment, the persistent graph) inherited the
error with no warning anywhere.

The golden table is the guardrail. Every expected id was read out of
ATT&CK's own name/alias lists, not out of THEORY's config, so this test
fails if a future alias import quietly re-merges two groups.
"""

from __future__ import annotations

import json

import pytest

from theory.actors import (
    ActorNotFound,
    AmbiguousActor,
    mentions,
)


# (user input, expected ATT&CK group id)
# None means "THEORY should not claim an ATT&CK group for this".
GOLDEN: list[tuple[str, str | None]] = [
    # Plain canonical names
    ("APT28",             "G0007"),
    ("APT29",             "G0016"),
    ("APT1",              "G0006"),
    ("APT3",              "G0022"),
    ("Turla",             "G0010"),
    ("FIN7",              "G0046"),
    ("Kimsuky",           "G0094"),
    ("MuddyWater",        "G0069"),
    ("Wizard Spider",     "G0102"),
    ("Volt Typhoon",      "G1017"),
    ("Scattered Spider",  "G1015"),
    ("TEMP.Veles",        "G0088"),

    # The eight that previously resolved to the WRONG group
    ("Lazarus Group",     "G0032"),   # was APT38 (G0082)
    ("APT41",             "G0096"),   # was APT17 (G0025)
    ("Winnti Group",      "G0044"),   # was APT17 (G0025)
    ("APT35",             "G0059"),   # was CURIUM (G1012)
    ("Charming Kitten",   "G0059"),   # was CURIUM (G1012)
    ("Carbanak",          "G0008"),   # was FIN7 (G0046)
    ("APT30",             "G0013"),   # was Naikon (G0019)
    ("Moonstone Sleet",   "G1036"),   # was APT38 (G0082)

    # Groups that must stay distinct from the ones that absorb them
    ("APT38",             "G0082"),
    ("Naikon",            "G0019"),
    ("Andariel",          "G0138"),
    ("APT17",             "G0025"),

    # Vendor naming schemes
    ("Fancy Bear",        "G0007"),
    ("Cozy Bear",         "G0016"),
    ("Midnight Blizzard", "G0016"),
    ("Forest Blizzard",   "G0007"),
    ("Sandworm",          "G0034"),
    ("APT44",             "G0034"),
    ("OilRig",            "G0049"),
    ("APT34",             "G0049"),
    ("Mustang Panda",     "G0129"),
    ("Gamaredon Group",   "G0047"),
    ("Dragonfly",         "G0035"),
    ("Cobalt Group",      "G0080"),
    ("APT42",             "G1044"),
    ("APT31",             "G0128"),
    ("Transparent Tribe", "G0134"),
    ("Equation",          "G0020"),

    # Case and separator tolerance
    ("apt28",             "G0007"),
    ("  APT28  ",         "G0007"),
    ("scatteredspider",   "G1015"),
    ("scattered-spider",  "G1015"),
    ("LAZARUS GROUP",     "G0032"),
]

# Input that must NOT resolve to anything. Every one of these previously
# produced a confident dossier for whichever actor matched first.
MUST_NOT_RESOLVE = [
    "a", "x", "APT", "APT123", "Spider", "Panda", "Kitten", "Bear",
    "Group", "Typhoon", "Blizzard", "NotARealActorName", "",
]


@pytest.fixture(scope="module")
def attack_index():
    """name/alias -> {group id}, from the trimmed ATT&CK fixture."""
    from pathlib import Path
    path = Path(__file__).resolve().parent / "fixtures" / "attack_groups.json"
    bundle = json.loads(path.read_text(encoding="utf-8"))
    index: dict[str, set[str]] = {}
    for obj in bundle["objects"]:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        gid = next((r["external_id"] for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not gid:
            continue
        for name in [obj.get("name", ""), *(obj.get("aliases") or [])]:
            index.setdefault(" ".join(name.lower().split()), set()).add(gid)
    return index


@pytest.fixture(scope="module")
def reg(request):
    import theory.actors as actors
    return actors.registry(reload=True)


class TestGoldenTable:
    """Resolution must agree with ATT&CK, for every actor, every time."""

    @pytest.mark.parametrize("query,expected_gid", GOLDEN)
    def test_resolves_to_expected_attack_group(self, reg, query, expected_gid):
        identity = reg.resolve(query)
        assert identity.mitre_id == expected_gid, (
            f"--actor {query!r} resolved to {identity.canonical} "
            f"({identity.mitre_id}), expected {expected_gid}"
        )

    @pytest.mark.parametrize("query,expected_gid", GOLDEN)
    def test_expectation_matches_attack_itself(self, attack_index, query, expected_gid):
        """Guards the guard: the expected ids above must be what ATT&CK's
        own name/alias lists say, not just what THEORY currently returns."""
        key = " ".join(query.lower().split())
        owners = attack_index.get(key)
        if owners is None:
            pytest.skip(f"{query!r} is not an ATT&CK name/alias (vendor or collapsed spelling)")
        assert expected_gid in owners, (
            f"ATT&CK assigns {query!r} to {sorted(owners)}, "
            f"but the golden table expects {expected_gid}"
        )


class TestUnknownInputIsRejected:

    @pytest.mark.parametrize("query", MUST_NOT_RESOLVE)
    def test_does_not_resolve(self, reg, query):
        with pytest.raises(LookupError):
            reg.resolve(query)

    def test_typo_suggests_the_real_actor(self, reg):
        with pytest.raises(ActorNotFound) as excinfo:
            reg.resolve("Lazarus Grop")
        assert "Lazarus Group" in excinfo.value.suggestions

    def test_get_returns_none_instead_of_raising(self, reg):
        assert reg.get("NotARealActorName") is None
        assert reg.get("APT28") is not None


class TestContestedNames:
    """Names another catalog gives to a different group must not be usable
    as identity for this one."""

    @pytest.mark.parametrize("contested,wrong_actor", [
        ("apt38",           "Lazarus Group"),
        ("moonstone sleet", "Lazarus Group"),
        ("apt17",           "APT41"),
        ("winnti group",    "APT41"),
        ("carbanak",        "FIN7"),
        ("apt30",           "Naikon"),
    ])
    def test_contested_name_does_not_resolve_to_absorbing_actor(
        self, reg, contested, wrong_actor
    ):
        identity = reg.get(contested)
        if identity is None:
            return      # not resolvable at all is also acceptable
        assert identity.canonical != wrong_actor, (
            f"{contested!r} still resolves to {wrong_actor} — the merge is back"
        )

    def test_ambiguity_raises_with_candidates(self, reg):
        """A name two actors legitimately share must be an error the user
        can act on, not a silent first-match."""
        import theory.actors as actors
        ambiguous = actors.ActorRegistry({
            "Group A": {"identity_names": ["shared name", "group a"]},
            "Group B": {"identity_names": ["shared name", "group b"]},
        })
        with pytest.raises(AmbiguousActor) as excinfo:
            ambiguous.resolve("shared name")
        assert excinfo.value.candidates == ["Group A", "Group B"]


class TestRecallMatching:
    """Text matching must need a word boundary, so ordinary prose does not
    look like an actor mention."""

    def test_unrelated_advisory_is_not_attributed(self, reg):
        """The reproduction case from the audit: an Akira ransomware
        advisory was attributed to APT3 (via alias 'ups' inside 'groups')
        and APT41 (via 'lead' inside 'leading')."""
        advisory = (
            "#StopRansomware: Akira Ransomware. CISA and partners release "
            "guidance. Threat groups target backups and leading organizations; "
            "apply updates promptly."
        )
        for actor in ("APT3", "APT41", "APT1", "Turla"):
            identity = reg.resolve(actor)
            assert mentions(identity, advisory) == [], (
                f"{actor} falsely matched an unrelated advisory"
            )

    @pytest.mark.parametrize("actor,text,should_match", [
        ("APT28", "Joint advisory: APT28 exploits routers",        True),
        ("APT28", "Fancy Bear phishing wave",                       True),
        ("APT28", "Fancy-Bear phishing wave",                       True),
        ("APT28", "APT 28 activity observed",                       True),
        ("APT28", "APT-28 activity observed",                       True),
        ("APT1",  "APT10 and APT12 activity",                       False),
        ("APT1",  "APT1 report published",                          True),
        ("APT4",  "APT41 and APT40 campaigns",                      False),
        ("APT2",  "APT28 and APT29 infrastructure",                 False),
        ("Turla", "Snake malware takedown by the FBI",              False),
        ("Turla", "Turla deployed a new backdoor",                  True),
    ])
    def test_word_boundary_matching(self, reg, actor, text, should_match):
        identity = reg.get(actor)
        if identity is None:
            pytest.skip(f"{actor} not in the actor table")
        hits = mentions(identity, text)
        assert bool(hits) is should_match, f"{actor} vs {text!r} -> {hits}"

    def test_stop_word_aliases_are_not_recall_terms(self, reg):
        """`ups`, `lead`, `snake` and friends stay usable for --actor but
        must never be evidence that prose is about the actor."""
        from theory.actors import STOP_ALIASES
        for actor in ("APT3", "APT41", "Turla", "Lazarus Group"):
            identity = reg.get(actor)
            if identity is None:
                continue
            leaked = identity.recall_terms & STOP_ALIASES
            assert not leaked, f"{actor} uses stop-words for recall: {leaked}"

    def test_short_aliases_excluded_unless_identifier_style(self, reg):
        for canonical in reg.canonical_names()[:200]:
            identity = reg.identity(canonical)
            for term in identity.recall_terms:
                from theory.actors import is_id_alias
                assert len(term) >= 4 or is_id_alias(term), (
                    f"{canonical}: {term!r} is too short to be a recall term"
                )


class TestRegistryIntegrity:

    def test_table_is_populated(self, reg):
        assert len(reg) > 1000

    def test_every_actor_resolves_to_itself(self, reg):
        """A canonical name must always resolve to its own entry, or the
        table is internally inconsistent."""
        failures = []
        for canonical in reg.canonical_names():
            try:
                if reg.resolve(canonical).canonical != canonical:
                    failures.append(canonical)
            except AmbiguousActor:
                failures.append(f"{canonical} (ambiguous)")
            except ActorNotFound:
                failures.append(f"{canonical} (not found)")
        assert failures == [], f"{len(failures)} actors do not resolve to themselves: {failures[:10]}"

    def test_pinned_ids_are_wellformed(self, reg):
        import re
        for canonical in reg.canonical_names():
            gid = reg.identity(canonical).mitre_id
            if gid:
                assert re.fullmatch(r"G\d{4}", gid), f"{canonical}: bad id {gid!r}"

    def test_shared_pins_are_attacks_own_merge(self, reg, attack_index):
        """Several THEORY actors may share one ATT&CK id — ATT&CK is
        coarser than MISP Galaxy in places (it folds RedDelta, Camaro
        Dragon and UNC6384 into Mustang Panda, G0129). That is fine.

        What is NOT fine is THEORY inventing a merge of its own. Every
        actor sharing an id must be a name ATT&CK itself lists on that
        group — otherwise we have re-created the bug where unrelated
        actors collapse onto one group's TTPs.
        """
        from collections import defaultdict

        owners = defaultdict(list)
        for canonical in reg.canonical_names():
            gid = reg.identity(canonical).mitre_id
            if gid:
                owners[gid].append(canonical)

        invented = []
        for gid, names in owners.items():
            if len(names) < 2:
                continue
            for name in names:
                attack_owners = attack_index.get(" ".join(name.lower().split()))
                if attack_owners is not None and gid not in attack_owners:
                    invented.append(f"{name} pinned to {gid}, but ATT&CK says {sorted(attack_owners)}")
        assert not invented, "THEORY invented a group merge: " + "; ".join(invented)
