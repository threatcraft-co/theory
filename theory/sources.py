"""
theory.sources
--------------
One description of every intelligence source THEORY can query.

This replaces five tables that had to be kept in sync by hand:

    theory/_cli.py   SUPPORTED_SOURCES, ENRICHMENT_SOURCES, MAPPER_REGISTRY,
                     SOURCE_DESCRIPTIONS, SOURCE_REQUIRES, and an inline
                     cache-TTL dict inside cmd_list_sources()
    server/pipeline  SOURCE_ID_MAP
    server/app       _load_sources()

They had already drifted: the server's copy was missing nvd, circl_misp,
personal, shodan_internetdb and urlscan_io, so those sources could not be
selected from the web UI at all, and the cache-TTL column in
`--list-sources` was maintained separately from the collectors that
actually set the TTLs.

Adding a source means adding one SourceSpec here. `--list-sources`, the
`--sources` validator, `--help`, the web UI's source list and the README
table all read from it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

__all__ = ["SourceSpec", "SOURCES", "BY_KEY", "DEFAULT_SOURCES",
           "collectors", "enrichers", "identity_sources", "source_keys"]


Kind = Literal["identity", "freetext", "enricher"]


@dataclass(frozen=True)
class SourceSpec:
    """One intelligence source.

    kind:
      identity  Can establish WHICH actor this is (resolves against a
                catalog). A dossier needs at least one of these to have
                produced data, or THEORY does not know who it is describing.
      freetext  Searches prose for mentions of an actor it was given. Can
                corroborate, cannot identify.
      enricher  Adds detail to a profile that already exists. Has no actor
                dimension of its own.
    """

    key: str
    kind: Kind
    description: str
    impl: str | None = None            # "module:ClassName"
    mapper: str | None = None          # "module:ClassName"
    key_env: str | None = None
    key_required: bool = False
    cache: str = "—"
    default: bool = False
    aliases: tuple[str, ...] = ()      # alternative keys (web UI, shorthand)

    @property
    def auth(self) -> str:
        if not self.key_env:
            return "none"
        return self.key_env if self.key_required else f"{self.key_env} (optional)"


SOURCES: tuple[SourceSpec, ...] = (
    # ── Identity sources ──────────────────────────────────────────────
    SourceSpec(
        key="mitre", kind="identity", default=True,
        impl="collectors.mitre_attack:MitreAttackCollector",
        mapper="mappers.mitre:MitreMapper",
        description="MITRE ATT&CK — techniques, software, campaigns (local bundle, offline)",
        cache="7 days (enterprise-attack.json)",
    ),
    SourceSpec(
        key="misp_galaxy", kind="identity", default=True, aliases=("misp",),
        impl="collectors.misp_galaxy:MispGalaxyCollector",
        mapper="collectors.misp_galaxy:MispGalaxyMapper",
        description="MISP Galaxy — 1000+ actors, aliases, attribution, target sectors (free, no auth)",
        cache="7 days",
    ),
    SourceSpec(
        key="malpedia", kind="identity", default=True,
        impl="collectors.malpedia:MalpediaCollector",
        mapper="collectors.malpedia:MalpediaMapper",
        description="Malpedia malware family database (free, no auth)",
        cache="per request",
    ),
    SourceSpec(
        key="personal", kind="identity",
        impl="collectors.personal_intel:PersonalIntelCollector",
        description="Your own local research indicators — never leaves your machine (--init-personal)",
        cache="none — read fresh every run",
    ),

    # ── Free-text sources ─────────────────────────────────────────────
    SourceSpec(
        key="cisa", kind="freetext", default=True,
        impl="collectors.cisa_advisories:CisaAdvisoriesCollector",
        mapper="mappers.cisa:CisaMapper",
        description="CISA cybersecurity advisories attributed to the actor (free, no auth)",
        cache="per request",
    ),
    SourceSpec(
        key="circl_misp", kind="freetext",
        impl="collectors.circl_misp:CirclMispCollector",
        mapper="collectors.circl_misp:CirclMispMapper",
        description="CIRCL OSINT MISP feed — event-level indicators and campaign context (free, no auth)",
        cache="24h manifest / 7 days per event",
    ),
    SourceSpec(
        key="otx", kind="freetext",
        impl="collectors.alienvault_otx:AlienVaultOTXCollector",
        mapper="collectors.alienvault_otx:AlienVaultOTXMapper",
        description="AlienVault OTX pulses and IOCs (free, requires a key)",
        key_env="OTX_API_KEY", key_required=True,
        cache="24 hours",
    ),
    SourceSpec(
        key="vendor", kind="freetext",
        impl="collectors.vendor_intel:VendorIntelCollector",
        description="Vendor research blogs, LLM-synthesised (requires an LLM provider)",
        key_env="ANTHROPIC_API_KEY / OPENAI_API_KEY / Ollama",
        cache="7 days per article",
    ),

    # ── Enrichers ─────────────────────────────────────────────────────
    SourceSpec(
        key="cisa_kev", kind="enricher", default=True,
        impl="collectors.cisa_kev:CisaKevCollector",
        mapper="collectors.cisa_kev:CisaKevMapper",
        description="CISA KEV — flags profile CVEs as confirmed-exploited, adds ransomware use",
        cache="24 hours",
    ),
    SourceSpec(
        key="nvd", kind="enricher",
        impl="collectors.nvd:NVDCollector",
        mapper="collectors.nvd:NVDMapper",
        description="NIST NVD — CVSS scores/vectors, CWE classification for profile CVEs",
        key_env="NVD_API_KEY", cache="30 days per CVE",
    ),
    SourceSpec(
        key="vuldb", kind="enricher",
        impl="collectors.vuldb:VulDBCollector",
        description="VulDB actor-CVE correlation and exploit intelligence (free tier)",
        key_env="VULDB_API_KEY", key_required=True, cache="7 days",
    ),
    SourceSpec(
        key="sigma", kind="enricher",
        impl="collectors.sigma_rules:SigmaCollector",
        description="SigmaHQ detection rules mapped to ATT&CK techniques (free, local clone)",
        key_env="GITHUB_TOKEN", cache="7 days",
    ),
    SourceSpec(
        key="yara", kind="enricher", aliases=("yara_rules",),
        impl="collectors.yara_rules:YaraRulesCollector",
        description="YARA rules matched to malware families (free, local clone)",
        cache="7 days",
    ),
    SourceSpec(
        key="threatfox", kind="enricher",
        impl="collectors.threatfox:ThreatFoxCollector",
        description="ThreatFox IOCs by malware family (free, requires an abuse.ch key)",
        key_env="ABUSECH_API_KEY", key_required=True, cache="24 hours",
    ),
    SourceSpec(
        key="malware_bazaar", kind="enricher", aliases=("malwarebazaar",),
        impl="collectors.malware_bazaar:MalwareBazaarCollector",
        description="MalwareBazaar sample hashes by malware family (free, requires an abuse.ch key)",
        key_env="ABUSECH_API_KEY", key_required=True, cache="24 hours",
    ),
    SourceSpec(
        key="urlhaus", kind="enricher",
        impl="collectors.urlhaus:URLhausCollector",
        description="URLhaus malware distribution URLs by family (free, requires an abuse.ch key)",
        key_env="ABUSECH_API_KEY", key_required=True, cache="24 hours",
    ),
    SourceSpec(
        key="greynoise", kind="enricher",
        impl="collectors.greynoise:GreyNoiseCollector",
        description="GreyNoise — separates targeted activity from internet background noise",
        key_env="GREYNOISE_API_KEY", key_required=True, cache="7 days",
    ),
    SourceSpec(
        key="abuseipdb", kind="enricher",
        impl="collectors.abuseipdb:AbuseIPDBCollector",
        description="AbuseIPDB community IP reputation scores",
        key_env="ABUSEIPDB_API_KEY", key_required=True, cache="3 days",
    ),
    SourceSpec(
        key="shodan_internetdb", kind="enricher",
        impl="collectors.shodan_internetdb:ShodanInternetDBCollector",
        description="Shodan InternetDB — open ports, hostnames, CPEs, known CVEs on an IP (free, no auth)",
        cache="24 hours",
    ),
    SourceSpec(
        key="urlscan_io", kind="enricher", aliases=("urlscan",),
        impl="collectors.urlscan_io:URLScanIOCollector",
        description="urlscan.io public scan history for domains/URLs (free, no auth)",
        key_env="URLSCAN_API_KEY", cache="24 hours",
    ),
)

BY_KEY: dict[str, SourceSpec] = {}
for _spec in SOURCES:
    BY_KEY[_spec.key] = _spec
    for _alias in _spec.aliases:
        BY_KEY[_alias] = _spec

DEFAULT_SOURCES: tuple[str, ...] = tuple(s.key for s in SOURCES if s.default)


def source_keys() -> list[str]:
    """Canonical keys, in declaration order."""
    return [s.key for s in SOURCES]


def collectors() -> list[SourceSpec]:
    """Sources that produce a profile (identity + free-text)."""
    return [s for s in SOURCES if s.kind in ("identity", "freetext")]


def enrichers() -> list[SourceSpec]:
    return [s for s in SOURCES if s.kind == "enricher"]


def identity_sources() -> list[SourceSpec]:
    return [s for s in SOURCES if s.kind == "identity"]


def resolve(key: str) -> SourceSpec | None:
    """Look up a source by canonical key or alias."""
    return BY_KEY.get(str(key).strip().lower())


# ---------------------------------------------------------------------------
# Documentation
# ---------------------------------------------------------------------------

README_TABLE_START = "<!-- BEGIN GENERATED SOURCE TABLE -->"
README_TABLE_END = "<!-- END GENERATED SOURCE TABLE -->"


def markdown_table() -> str:
    """The source table as it appears in README.md.

    Generated rather than hand-written: the hand-written version had
    drifted (it still listed threatfox as keyless after abuse.ch began
    requiring an Auth-Key on every request), and a reader has no way to
    tell a stale row from a current one. tests/test_docs_in_sync.py fails
    if README.md does not match this output.
    """
    rows = [
        "| Source | What it adds | Auth | Cache |",
        "|---|---|---|---|",
    ]
    for spec in SOURCES:
        auth = "None" if not spec.key_env else (
            f"`{spec.key_env}`" if spec.key_required
            else f"`{spec.key_env}` (optional)"
        )
        if spec.key == "vendor":
            auth = "LLM provider"
        rows.append(
            f"| `{spec.key}` | {spec.description} | {auth} | {spec.cache} |"
        )
    return "\n".join(rows)


def counts() -> dict[str, int]:
    """Figures quoted in prose, so they cannot drift either."""
    return {
        "total": len(SOURCES),
        "keyless": sum(1 for s in SOURCES if not s.key_required),
        "key_required": sum(1 for s in SOURCES if s.key_required),
        "defaults": sum(1 for s in SOURCES if s.default),
    }
