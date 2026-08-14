"""
collectors/misp_galaxy.py
-------------------------
Pulls threat actor intelligence from the MISP Galaxy threat-actor cluster.

Data source:
  https://github.com/MISP/misp-galaxy/blob/main/clusters/threat-actor.json

The MISP Galaxy threat-actor cluster is a community-maintained knowledge
base with 1000+ threat actor entries including extensive alias lists,
country attribution, motivation, target sectors/countries, and reference
links.  Licensed CC0 (public domain).

No authentication required.  The full cluster JSON (~1.2 MB) is downloaded
from GitHub and cached locally with a configurable TTL (default 7 days).

Key value for THEORY:
  - Alias depth: many actors carry 10-30 vendor-specific aliases
    (Microsoft, CrowdStrike, Mandiant, ESET, Kaspersky, Secureworks, etc.)
  - name-attribution entries provide additional vendor naming with UUIDs
  - CVE references extractable from descriptions and reference URLs
  - Country attribution with confidence scores
  - Related-actor links via UUID cross-references
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from collectors.base import BaseCollector

try:
    from collectors.cisa_advisories import resolve_canonical
except ImportError:
    def resolve_canonical(name: str) -> str:
        return name.strip()

logger = logging.getLogger(__name__)

SOURCE_ID = "misp_galaxy"

# Raw GitHub URL for the threat-actor cluster JSON
CLUSTER_URL = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy"
    "/main/clusters/threat-actor.json"
)

CACHE_DIR = Path(".cache/misp_galaxy")
CACHE_FILE = CACHE_DIR / "threat-actor.json"
CACHE_TTL_SECONDS = 7 * 24 * 3600   # 7 days

TIMEOUT = 30     # download timeout (file is ~1.2 MB)
RETRY_MAX = 2
RETRY_WAIT = 3

# Regex for extracting CVE identifiers from text
_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)

# ISO 3166-1 alpha-2 to full country name
_COUNTRY_MAP: dict[str, str] = {
    "AF": "Afghanistan", "AL": "Albania", "AM": "Armenia",
    "AZ": "Azerbaijan", "BD": "Bangladesh", "BR": "Brazil",
    "BY": "Belarus", "CN": "China", "CO": "Colombia",
    "CU": "Cuba", "DE": "Germany", "DZ": "Algeria",
    "EG": "Egypt", "ES": "Spain", "ET": "Ethiopia",
    "FR": "France", "GB": "United Kingdom", "GH": "Ghana",
    "GR": "Greece", "HK": "Hong Kong", "ID": "Indonesia",
    "IL": "Israel", "IN": "India", "IQ": "Iraq",
    "IR": "Iran", "JO": "Jordan", "JP": "Japan",
    "KE": "Kenya", "KG": "Kyrgyzstan", "KP": "North Korea",
    "KR": "South Korea", "KZ": "Kazakhstan", "LB": "Lebanon",
    "LK": "Sri Lanka", "LY": "Libya", "MA": "Morocco",
    "MM": "Myanmar", "MX": "Mexico", "MY": "Malaysia",
    "NG": "Nigeria", "NL": "Netherlands", "PK": "Pakistan",
    "PH": "Philippines", "PL": "Poland", "PS": "Palestine",
    "QA": "Qatar", "RO": "Romania", "RS": "Serbia",
    "RU": "Russia", "SA": "Saudi Arabia", "SD": "Sudan",
    "SG": "Singapore", "SY": "Syria", "TH": "Thailand",
    "TJ": "Tajikistan", "TN": "Tunisia", "TR": "Turkey",
    "TW": "Taiwan", "UA": "Ukraine", "US": "United States",
    "UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam",
    "YE": "Yemen", "ZA": "South Africa",
}

# Map MISP Galaxy cfr-type-of-incident / motive to THEORY canonical motivations
_MOTIVATION_MAP: dict[str, str] = {
    "espionage": "espionage",
    "cyber espionage": "espionage",
    "state-sponsored espionage": "espionage",
    "financial theft": "financial",
    "cybercrime": "financial",
    "financially motivated": "financial",
    "extortion": "financial",
    "business email compromise": "financial",
    "hacktivism": "hacktivism",
    "hacktivists-nationalists": "hacktivism",
    "defacement": "hacktivism",
    "sabotage": "destruction",
    "destruction": "destruction",
    "denial of service": "destruction",
    "information operations": "hacktivism",
}


class MispGalaxyCollector(BaseCollector):
    """Collector for the MISP Galaxy threat-actor cluster."""

    SOURCE_ID = SOURCE_ID
    REQUIRES_API_KEY = False

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._cluster_data: dict[str, Any] | None = None
        # Lookup indexes built on first use
        self._by_value: dict[str, dict] | None = None
        self._by_alias: dict[str, dict] | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def query(self, actor_name: str) -> dict[str, Any] | None:
        """Query the MISP Galaxy cluster for a threat actor.

        Searches by canonical value, synonyms, and name-attribution entries.
        Returns a CommonSchema-conformant dict, or None if not found.
        """
        cluster = self._load_cluster()
        if cluster is None:
            return None

        entry = self._find_actor(actor_name, cluster)
        if entry is None:
            logger.info(
                "MISP Galaxy: actor %r not found in cluster (%d entries).",
                actor_name, len(cluster.get("values", [])),
            )
            return None

        return self._entry_to_schema(entry, actor_name)

    # ------------------------------------------------------------------
    # Cluster loading + caching
    # ------------------------------------------------------------------

    def _load_cluster(self) -> dict[str, Any] | None:
        """Load the cluster JSON, using cache if fresh enough."""
        if self._cluster_data is not None:
            return self._cluster_data

        # Check cache
        if CACHE_FILE.exists():
            age = time.time() - CACHE_FILE.stat().st_mtime
            if age < CACHE_TTL_SECONDS:
                logger.debug(
                    "MISP Galaxy: using cached cluster (%.1f days old).",
                    age / 86400,
                )
                try:
                    self._cluster_data = json.loads(
                        CACHE_FILE.read_text(encoding="utf-8")
                    )
                    return self._cluster_data
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning("MISP Galaxy: cache read failed: %s", exc)

        # Download fresh
        logger.info("MISP Galaxy: downloading cluster from GitHub...")
        data = self._download_cluster()
        if data is None:
            # Fall back to stale cache if download fails
            if CACHE_FILE.exists():
                logger.warning(
                    "MISP Galaxy: download failed, using stale cache."
                )
                try:
                    self._cluster_data = json.loads(
                        CACHE_FILE.read_text(encoding="utf-8")
                    )
                    return self._cluster_data
                except Exception:
                    pass
            return None

        # Write cache
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            CACHE_FILE.write_text(
                json.dumps(data, ensure_ascii=False), encoding="utf-8"
            )
            logger.debug("MISP Galaxy: cluster cached to %s", CACHE_FILE)
        except OSError as exc:
            logger.warning("MISP Galaxy: cache write failed: %s", exc)

        self._cluster_data = data
        return data

    def _download_cluster(self) -> dict[str, Any] | None:
        """Download the threat-actor cluster JSON from GitHub."""
        req = Request(CLUSTER_URL, headers={
            "User-Agent": "THEORY/1.0 threat-intel-research",
            "Accept": "application/json",
        })
        for attempt in range(1, RETRY_MAX + 1):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    raw = resp.read()
                    data = json.loads(raw.decode("utf-8"))
                    actor_count = len(data.get("values", []))
                    logger.info(
                        "MISP Galaxy: downloaded cluster with %d actors "
                        "(%.1f KB).",
                        actor_count, len(raw) / 1024,
                    )
                    return data
            except HTTPError as exc:
                logger.warning(
                    "MISP Galaxy: HTTP %d on attempt %d/%d.",
                    exc.code, attempt, RETRY_MAX,
                )
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT * attempt)
            except (URLError, OSError, json.JSONDecodeError) as exc:
                logger.warning(
                    "MISP Galaxy: download error on attempt %d/%d: %s",
                    attempt, RETRY_MAX, exc,
                )
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT)
        return None

    # ------------------------------------------------------------------
    # Actor lookup
    # ------------------------------------------------------------------

    def _build_indexes(self, cluster: dict[str, Any]) -> None:
        """Build value and alias lookup indexes from the cluster."""
        self._by_value = {}
        self._by_alias = {}
        for entry in cluster.get("values", []):
            value = (entry.get("value") or "").strip()
            if not value:
                continue
            value_lower = value.lower()
            self._by_value[value_lower] = entry

            # Index synonyms
            meta = entry.get("meta", {}) or {}
            for syn in (meta.get("synonyms") or []):
                syn_lower = str(syn).strip().lower()
                if syn_lower:
                    self._by_alias[syn_lower] = entry

            # Index name-attribution entries (format: "AliasName:uuid")
            for na in (meta.get("name-attribution") or []):
                na_str = str(na)
                if ":" in na_str:
                    alias_part = na_str.rsplit(":", 1)[0].strip().lower()
                    if alias_part:
                        self._by_alias[alias_part] = entry

    def _find_actor(
        self, name: str, cluster: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Find an actor entry by name, synonym, or name-attribution.

        Lookup order matters: THEORY's canonical resolution runs before
        MISP Galaxy alias matching so that THEORY's alias table wins when
        MISP Galaxy splits overlapping groups into separate entries
        (e.g. UNC2452 vs APT29 both carry "Midnight Blizzard" / "NOBELIUM").
        """
        if self._by_value is None:
            self._build_indexes(cluster)

        lookup = name.strip().lower()

        # 1. Exact value match (highest priority)
        if lookup in self._by_value:
            return self._by_value[lookup]

        # 2. Canonical resolution via THEORY's alias table
        #    This ensures "Midnight Blizzard" -> APT29 (via actors.yaml)
        #    instead of UNC2452 (via MISP Galaxy synonyms).
        canonical = resolve_canonical(name)
        canonical_lower = canonical.lower()
        if canonical_lower != lookup:
            if canonical_lower in self._by_value:
                return self._by_value[canonical_lower]
            if canonical_lower in self._by_alias:
                return self._by_alias[canonical_lower]

        # 3. MISP Galaxy alias / synonym match
        if lookup in self._by_alias:
            return self._by_alias[lookup]

        # 4. Substring fallback for partial matches
        #    (e.g. "Lazarus" matching "Lazarus Group")
        for value_key, entry in self._by_value.items():
            if lookup in value_key or value_key in lookup:
                return entry

        return None

    # ------------------------------------------------------------------
    # Schema conversion
    # ------------------------------------------------------------------

    def _entry_to_schema(
        self, entry: dict[str, Any], queried_name: str
    ) -> dict[str, Any]:
        """Convert a MISP Galaxy actor entry to CommonSchema format."""
        meta = entry.get("meta", {}) or {}
        value = (entry.get("value") or "").strip()
        canonical = resolve_canonical(queried_name)
        actor_name = canonical if canonical != queried_name.strip() else value

        aliases = self._extract_aliases(entry, actor_name)
        motivations = self._extract_motivations(meta)
        origin = self._extract_origin(meta)
        sectors = self._extract_sectors(meta)
        victims = self._extract_victims(meta)
        cves = self._extract_cves(entry)

        return {
            "actor_name": actor_name,
            "source_id": SOURCE_ID,
            "source_url": f"https://misp-galaxy.org/{_slug(value)}",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "aliases": aliases,
            "description": (entry.get("description") or "").strip(),
            "suspected_origin": origin,
            "origin": origin,
            "motivation": motivations,
            "motivations": motivations,
            "first_seen": str(meta.get("since", "")) or None,
            "sponsorship": self._extract_sponsorship(meta),
            "target_sectors": sectors,
            "sectors": sectors,
            "target_countries": victims,
            "techniques": [],
            "malware": [],
            "indicators": [],
            "campaigns": [],
            "cves": [{"cve_id": c} for c in cves] if cves else [],
            "source_citation": SOURCE_ID,
            "raw_source": "MISP Galaxy",
            # MISP Galaxy specific fields
            "misp_galaxy_uuid": entry.get("uuid", ""),
            "misp_galaxy_related": self._extract_related(entry),
            "attribution_confidence": meta.get("attribution-confidence", ""),
        }

    # ------------------------------------------------------------------
    # Field extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_aliases(entry: dict, actor_name: str) -> list[str]:
        """Extract all aliases from synonyms + name-attribution.

        Deduplicates case-insensitively. Excludes the actor_name itself
        and MITRE group IDs (e.g. G0007) which are tracked separately.
        """
        meta = entry.get("meta", {}) or {}
        raw_aliases: list[str] = []

        # The cluster 'value' field (e.g. "APT28")
        value = (entry.get("value") or "").strip()
        if value:
            raw_aliases.append(value)

        # meta.synonyms (primary alias source)
        for syn in (meta.get("synonyms") or []):
            s = str(syn).strip()
            if s:
                raw_aliases.append(s)

        # meta.name-attribution (vendor-specific names with UUIDs)
        for na in (meta.get("name-attribution") or []):
            na_str = str(na)
            if ":" in na_str:
                alias_part = na_str.rsplit(":", 1)[0].strip()
                if alias_part:
                    raw_aliases.append(alias_part)

        # origin:* keys contain additional vendor naming
        # e.g. "origin:APT-C-20": "QiAnXin"
        for key in meta:
            if key.startswith("origin:"):
                # The key suffix is the alias
                alias = key.split(":", 1)[1].strip()
                if alias:
                    raw_aliases.append(alias)

        # Deduplicate case-insensitively, preserving first-seen casing
        seen: set[str] = set()
        exclude = {actor_name.lower()}
        result: list[str] = []
        for alias in raw_aliases:
            lower = alias.lower()
            if lower not in seen and lower not in exclude:
                seen.add(lower)
                result.append(alias)

        return result

    @staticmethod
    def _extract_origin(meta: dict) -> str:
        """Extract country of origin from meta fields."""
        # cfr-suspected-state-sponsor has the full name
        sponsor = meta.get("cfr-suspected-state-sponsor", "")
        if sponsor:
            return str(sponsor).strip()

        # Fall back to ISO country code
        code = (meta.get("country") or "").strip().upper()
        if code:
            return _COUNTRY_MAP.get(code, code)

        return ""

    @staticmethod
    def _extract_motivations(meta: dict) -> list[str]:
        """Map MISP Galaxy motivation/incident fields to THEORY canonical set."""
        raw_values: list[str] = []

        # cfr-type-of-incident (most common)
        incident = meta.get("cfr-type-of-incident", "")
        if isinstance(incident, str) and incident:
            raw_values.append(incident)
        elif isinstance(incident, list):
            raw_values.extend(str(v) for v in incident if v)

        # motive field
        motive = meta.get("motive", "")
        if isinstance(motive, str) and motive:
            raw_values.append(motive)
        elif isinstance(motive, list):
            raw_values.extend(str(v) for v in motive if v)

        # Map to canonical values
        seen: set[str] = set()
        result: list[str] = []
        for raw in raw_values:
            mapped = _MOTIVATION_MAP.get(raw.lower().strip(), "")
            if not mapped:
                # Try substring matching for compound values
                lower = raw.lower()
                if "espionage" in lower:
                    mapped = "espionage"
                elif "financial" in lower or "crime" in lower:
                    mapped = "financial"
                elif "hacktivis" in lower:
                    mapped = "hacktivism"
                elif "sabotage" in lower or "destruct" in lower:
                    mapped = "destruction"
                else:
                    mapped = "unknown"
            if mapped not in seen:
                seen.add(mapped)
                result.append(mapped)

        return result

    @staticmethod
    def _extract_sponsorship(meta: dict) -> str:
        """Infer sponsorship from available metadata."""
        # If there's a state sponsor, it's nation-state
        if meta.get("cfr-suspected-state-sponsor"):
            return "nation-state"

        # Check incident type
        incident = meta.get("cfr-type-of-incident", "")
        incident_lower = str(incident).lower() if isinstance(incident, str) else ""
        if "espionage" in incident_lower:
            return "nation-state"
        if "cybercrime" in incident_lower or "financial" in incident_lower:
            return "criminal"
        if "hacktiv" in incident_lower:
            return "hacktivist"

        # Check motive
        motive = meta.get("motive", "")
        motive_lower = str(motive).lower() if isinstance(motive, str) else ""
        if "state" in motive_lower:
            return "nation-state"
        if "crime" in motive_lower or "financial" in motive_lower:
            return "criminal"
        if "hacktivis" in motive_lower:
            return "hacktivist"

        return "unknown"

    @staticmethod
    def _extract_sectors(meta: dict) -> list[str]:
        """Extract target sectors from cfr-target-category or targeted-sector."""
        raw: list[str] = []

        for key in ("cfr-target-category", "targeted-sector", "sector"):
            val = meta.get(key)
            if isinstance(val, list):
                raw.extend(str(v).strip() for v in val if v)
            elif isinstance(val, str) and val:
                raw.append(val.strip())

        # Deduplicate
        seen: set[str] = set()
        result: list[str] = []
        for s in raw:
            if s.lower() not in seen:
                seen.add(s.lower())
                result.append(s)
        return result

    @staticmethod
    def _extract_victims(meta: dict) -> list[str]:
        """Extract target countries from cfr-suspected-victims."""
        victims = meta.get("cfr-suspected-victims") or \
                  meta.get("suspected-victims") or []
        if isinstance(victims, str):
            return [victims] if victims.strip() else []
        return [str(v).strip() for v in victims if str(v).strip()]

    @staticmethod
    def _extract_cves(entry: dict) -> list[str]:
        """Extract CVE identifiers from description and reference URLs."""
        meta = entry.get("meta", {}) or {}
        text_parts: list[str] = []

        # Description
        desc = entry.get("description", "")
        if desc:
            text_parts.append(str(desc))

        # Reference URLs (CVE IDs sometimes appear in the URL itself)
        for ref in (meta.get("refs") or []):
            text_parts.append(str(ref))

        combined = " ".join(text_parts)
        matches = _CVE_RE.findall(combined)

        # Deduplicate and normalize to uppercase
        seen: set[str] = set()
        result: list[str] = []
        for cve in matches:
            upper = cve.upper()
            if upper not in seen:
                seen.add(upper)
                result.append(upper)

        return result

    @staticmethod
    def _extract_related(entry: dict) -> list[dict[str, str]]:
        """Extract related actor links (UUID cross-references)."""
        result: list[dict[str, str]] = []
        for rel in (entry.get("related") or []):
            if not isinstance(rel, dict):
                continue
            result.append({
                "uuid": rel.get("dest-uuid", ""),
                "type": rel.get("type", ""),
            })
        return result


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

class MispGalaxyMapper:
    """Post-processing mapper for MISP Galaxy data."""

    def map(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize a MISP Galaxy record for the THEORY pipeline."""
        if not isinstance(raw, dict):
            raise ValueError(f"Expected dict, got {type(raw).__name__}")
        actor_name = (raw.get("actor_name") or "").strip()
        if not actor_name:
            raise ValueError("raw record missing 'actor_name'")
        return raw   # Already in schema-compatible format from _entry_to_schema


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _slug(value: str) -> str:
    """Convert an actor name to a URL-safe slug for misp-galaxy.org."""
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


# ---------------------------------------------------------------------------
# Standalone helper: dump all aliases for actors.yaml expansion
# ---------------------------------------------------------------------------

def dump_alias_table(output_path: str = "misp_galaxy_aliases.json") -> None:
    """Download the cluster and dump an alias table suitable for
    merging into config/actors.yaml.

    Run standalone:
        python -c "from collectors.misp_galaxy import dump_alias_table; dump_alias_table()"
    """
    collector = MispGalaxyCollector()
    cluster = collector._load_cluster()
    if cluster is None:
        print("Failed to load cluster.")
        return

    table: dict[str, list[str]] = {}
    for entry in cluster.get("values", []):
        value = (entry.get("value") or "").strip()
        if not value:
            continue
        aliases = collector._extract_aliases(entry, value)
        if aliases:
            table[value] = aliases

    Path(output_path).write_text(
        json.dumps(table, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Wrote {len(table)} actors with aliases to {output_path}")
    total_aliases = sum(len(v) for v in table.values())
    print(f"Total alias entries: {total_aliases}")
