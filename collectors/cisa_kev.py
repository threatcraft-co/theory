"""
collectors/cisa_kev.py
----------------------
Enriches actor profiles with CISA KEV (Known Exploited Vulnerabilities) data.

Data source:
  https://github.com/cisagov/kev-data
  (Official CISA mirror of https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

The KEV catalog is a CISA-maintained list of CVEs confirmed exploited
in the wild. It carries ~1600+ entries as of mid-2026, with vendor,
product, vulnerability name, date added, due date, and a ransomware flag.

No authentication required. CC0 license.

Why this is different from other collectors:
  Every other THEORY collector is actor-centric ("give me APT28's data").
  KEV is CVE-centric ("give me the metadata for CVE-XXXX-XXXXX"). It
  never attributes CVEs to actors directly. Its value to THEORY is:

    1. Confidence booster: when another source says APT28 uses
       CVE-2023-23397, KEV tells us "yes, that CVE is confirmed
       exploited in the wild" (raising confidence).

    2. Ransomware flag: KEV tags CVEs known to be used in ransomware
       campaigns, which is high-value context for defenders.

    3. Vendor/product metadata: enriches CVE entries with structured
       vendor and product data.

    4. v2.0 foundation: becomes the primary lookup table for
       `theory --cve CVE-XXXX-XXXXX` in v2.0.

Pipeline position:
  Runs in the collect phase like a standard collector, but its query()
  method takes a different path: it looks at CVEs already collected by
  other sources in the profile (via a lookup helper that other collectors
  can call) rather than searching by actor name.
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from collectors.base import BaseCollector

try:
    from collectors.cisa_advisories import resolve_canonical
except ImportError:
    def resolve_canonical(name: str) -> str:
        return name.strip()

logger = logging.getLogger(__name__)

SOURCE_ID = "cisa_kev"

# Primary source: CISA's official GitHub mirror (updated within minutes
# of the canonical cisa.gov catalog updating).
CATALOG_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)

# Fallback: canonical CISA URL if the GitHub mirror is unavailable.
FALLBACK_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

CACHE_DIR = Path(".cache/cisa_kev")
CACHE_FILE = CACHE_DIR / "known_exploited_vulnerabilities.json"
CACHE_TTL_SECONDS = 24 * 3600   # 24 hours (CISA updates on weekdays)

TIMEOUT = 30
RETRY_MAX = 2
RETRY_WAIT = 3

# Regex for CVE ID validation and extraction
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class CisaKevCollector(BaseCollector):
    """Collector for the CISA Known Exploited Vulnerabilities catalog.

    Unlike actor-centric collectors, this queries the KEV catalog for
    CVE-level metadata that enriches CVEs already present in the profile.

    When query(actor_name) is called with just an actor name, it returns
    an empty schema (KEV has no actor attribution). The real work happens
    via enrich_profile() which cross-references profile CVEs against KEV.
    """

    SOURCE_ID = SOURCE_ID
    REQUIRES_API_KEY = False

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._catalog: dict[str, Any] | None = None
        self._cve_index: dict[str, dict] | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def query(self, actor_name: str) -> dict[str, Any] | None:
        """Query interface for compatibility with the collector pipeline.

        KEV data has no actor attribution, so this returns a minimal
        profile with no CVEs. The pipeline should call enrich_profile()
        after other collectors have populated the CVE list.

        Returns None if the KEV catalog cannot be loaded (rather than
        an empty profile), so the pipeline skips this source cleanly.
        """
        catalog = self._load_catalog()
        if catalog is None:
            logger.warning("CISA KEV: catalog unavailable, skipping.")
            return None

        canonical = resolve_canonical(actor_name)
        logger.info(
            "CISA KEV: catalog loaded (%d CVEs). No direct actor lookup — "
            "CVE cross-referencing happens during enrichment.",
            catalog.get("count", 0),
        )

        # Return a minimal schema-conformant record so the pipeline knows
        # KEV data is available. The enrichment step will populate CVEs.
        return {
            "actor_name": canonical,
            "source_id": SOURCE_ID,
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "aliases": [],
            "description": "",
            "suspected_origin": None,
            "origin": "",
            "motivation": [],
            "motivations": [],
            "first_seen": None,
            "sponsorship": None,
            "target_sectors": [],
            "sectors": [],
            "target_countries": [],
            "techniques": [],
            "malware": [],
            "indicators": [],
            "campaigns": [],
            "cves": [],
            "source_citation": SOURCE_ID,
            "raw_source": "CISA KEV",
            # KEV catalog metadata for the reporter to surface
            "kev_catalog_version": catalog.get("catalogVersion", ""),
            "kev_catalog_date": catalog.get("dateReleased", ""),
            "kev_total_cves": catalog.get("count", 0),
        }

    def enrich_profile(self, profile: dict[str, Any]) -> dict[str, Any]:
        """Cross-reference profile CVEs against the KEV catalog.

        For each CVE already in profile['cves'], adds:
          - kev_confirmed: bool (in KEV catalog)
          - kev_date_added: str (when CISA confirmed exploitation)
          - kev_due_date: str (federal remediation deadline)
          - kev_ransomware: bool (used in ransomware campaigns)
          - kev_vendor: str (affected vendor)
          - kev_product: str (affected product)
          - kev_vulnerability_name: str (KEV's name for the vuln)

        Also adds top-level flags for quick access:
          - kev_confirmed_count: int
          - kev_ransomware_count: int
        """
        catalog = self._load_catalog()
        if catalog is None:
            return profile

        if self._cve_index is None:
            self._build_cve_index(catalog)

        existing_cves = profile.get("cves") or []
        if not existing_cves:
            logger.debug("CISA KEV: no CVEs in profile to enrich.")
            return profile

        confirmed_count = 0
        ransomware_count = 0

        for cve_entry in existing_cves:
            if not isinstance(cve_entry, dict):
                continue

            # Support both "cve_id" (new schema) and "cveID" (legacy)
            cve_id = (
                cve_entry.get("cve_id")
                or cve_entry.get("cveID")
                or ""
            ).upper().strip()
            if not cve_id or not _CVE_RE.match(cve_id):
                continue

            kev_entry = self._cve_index.get(cve_id)
            if not kev_entry:
                cve_entry["kev_confirmed"] = False
                continue

            cve_entry["kev_confirmed"] = True
            cve_entry["kev_date_added"] = kev_entry.get("dateAdded", "")
            cve_entry["kev_due_date"] = kev_entry.get("dueDate", "")
            cve_entry["kev_ransomware"] = (
                kev_entry.get("knownRansomwareCampaignUse", "") == "Known"
            )
            cve_entry["kev_vendor"] = kev_entry.get("vendorProject", "")
            cve_entry["kev_product"] = kev_entry.get("product", "").strip()
            cve_entry["kev_vulnerability_name"] = kev_entry.get(
                "vulnerabilityName", ""
            )
            # Only backfill description if it's missing
            if not cve_entry.get("description"):
                cve_entry["description"] = kev_entry.get("shortDescription", "")

            # Track KEV as a corroborating source
            sources = cve_entry.get("sources") or []
            if SOURCE_ID not in sources:
                sources.append(SOURCE_ID)
            cve_entry["sources"] = sources

            confirmed_count += 1
            if cve_entry["kev_ransomware"]:
                ransomware_count += 1

        profile["cves"] = existing_cves
        profile["kev_confirmed_count"] = confirmed_count
        profile["kev_ransomware_count"] = ransomware_count

        logger.info(
            "CISA KEV: enriched %d/%d CVEs (%d ransomware-flagged)",
            confirmed_count, len(existing_cves), ransomware_count,
        )
        return profile

    def lookup_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Look up a single CVE in the KEV catalog.

        Returns the full KEV entry (raw fields), or None if not in KEV.
        Used by the future v2.0 `theory --cve` command.
        """
        catalog = self._load_catalog()
        if catalog is None:
            return None
        if self._cve_index is None:
            self._build_cve_index(catalog)

        normalized = cve_id.upper().strip()
        return self._cve_index.get(normalized)

    def all_cves(self) -> list[dict[str, Any]]:
        """Return all KEV CVEs. Used by the future v2.0 index builder."""
        catalog = self._load_catalog()
        if catalog is None:
            return []
        return catalog.get("vulnerabilities", [])

    # ------------------------------------------------------------------
    # Catalog loading + caching
    # ------------------------------------------------------------------

    def _load_catalog(self) -> dict[str, Any] | None:
        """Load the KEV catalog, using cache if fresh enough."""
        if self._catalog is not None:
            return self._catalog

        # Check cache
        if CACHE_FILE.exists():
            age = time.time() - CACHE_FILE.stat().st_mtime
            if age < CACHE_TTL_SECONDS:
                logger.debug(
                    "CISA KEV: using cached catalog (%.1f hours old).",
                    age / 3600,
                )
                try:
                    self._catalog = json.loads(
                        CACHE_FILE.read_text(encoding="utf-8")
                    )
                    return self._catalog
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning("CISA KEV: cache read failed: %s", exc)

        # Download fresh
        logger.info("CISA KEV: downloading catalog from GitHub mirror...")
        data = self._download_catalog(CATALOG_URL)
        if data is None:
            logger.warning("CISA KEV: GitHub download failed, trying cisa.gov...")
            data = self._download_catalog(FALLBACK_URL)

        if data is None:
            # Fall back to stale cache
            if CACHE_FILE.exists():
                logger.warning("CISA KEV: all downloads failed, using stale cache.")
                try:
                    self._catalog = json.loads(
                        CACHE_FILE.read_text(encoding="utf-8")
                    )
                    return self._catalog
                except Exception:
                    pass
            return None

        # Write cache
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            CACHE_FILE.write_text(
                json.dumps(data, ensure_ascii=False), encoding="utf-8"
            )
            logger.debug("CISA KEV: catalog cached to %s", CACHE_FILE)
        except OSError as exc:
            logger.warning("CISA KEV: cache write failed: %s", exc)

        self._catalog = data
        return data

    def _download_catalog(self, url: str) -> dict[str, Any] | None:
        """Download the KEV catalog JSON from the given URL."""
        req = Request(url, headers={
            "User-Agent": "THEORY/1.0 threat-intel-research",
            "Accept": "application/json",
        })
        for attempt in range(1, RETRY_MAX + 1):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    raw = resp.read()
                    data = json.loads(raw.decode("utf-8"))
                    count = data.get("count", len(data.get("vulnerabilities", [])))
                    version = data.get("catalogVersion", "unknown")
                    logger.info(
                        "CISA KEV: downloaded catalog v%s with %d CVEs "
                        "(%.1f KB) from %s",
                        version, count, len(raw) / 1024,
                        "GitHub" if "github" in url else "cisa.gov",
                    )
                    return data
            except HTTPError as exc:
                logger.warning(
                    "CISA KEV: HTTP %d on attempt %d/%d for %s.",
                    exc.code, attempt, RETRY_MAX, url,
                )
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT * attempt)
            except (URLError, OSError, json.JSONDecodeError) as exc:
                logger.warning(
                    "CISA KEV: download error on attempt %d/%d: %s",
                    attempt, RETRY_MAX, exc,
                )
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT)
        return None

    def _build_cve_index(self, catalog: dict[str, Any]) -> None:
        """Build a CVE-ID lookup index from the catalog."""
        self._cve_index = {}
        for entry in catalog.get("vulnerabilities", []):
            cve_id = (entry.get("cveID") or "").upper().strip()
            if cve_id:
                self._cve_index[cve_id] = entry
        logger.debug("CISA KEV: indexed %d CVEs.", len(self._cve_index))


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

class CisaKevMapper:
    """Post-processing mapper for CISA KEV data.

    KEV records from the collector are already schema-conformant, so this
    mapper is a passthrough with light validation. It exists for pipeline
    consistency with other collectors.
    """

    def map(self, raw: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise ValueError(f"Expected dict, got {type(raw).__name__}")
        actor_name = (raw.get("actor_name") or "").strip()
        if not actor_name:
            raise ValueError("raw record missing 'actor_name'")
        return raw


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

_SHARED_COLLECTOR: CisaKevCollector | None = None


def _get_shared_collector() -> CisaKevCollector:
    """Return a module-level singleton collector to avoid re-downloading
    the catalog for every enrichment call."""
    global _SHARED_COLLECTOR
    if _SHARED_COLLECTOR is None:
        _SHARED_COLLECTOR = CisaKevCollector()
    return _SHARED_COLLECTOR


def enrich_profile_with_kev(profile: dict[str, Any]) -> dict[str, Any]:
    """Module-level convenience: enrich a profile with KEV data.

    Other collectors or the pipeline can call this without instantiating
    the collector themselves.
    """
    return _get_shared_collector().enrich_profile(profile)


def lookup_cve(cve_id: str) -> dict[str, Any] | None:
    """Module-level convenience: look up a single CVE in KEV.

    Used by v2.0 `theory --cve` command and by other collectors.
    """
    return _get_shared_collector().lookup_cve(cve_id)


def is_kev_confirmed(cve_id: str) -> bool:
    """Quick check: is this CVE in the KEV catalog?"""
    return lookup_cve(cve_id) is not None


def is_ransomware_cve(cve_id: str) -> bool:
    """Quick check: is this CVE flagged as used in ransomware campaigns?"""
    entry = lookup_cve(cve_id)
    if not entry:
        return False
    return entry.get("knownRansomwareCampaignUse", "") == "Known"
