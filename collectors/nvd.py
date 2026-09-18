"""
collectors/nvd.py
------------------
Enriches actor profiles with NIST NVD (National Vulnerability Database)
CVE detail: CVSS vectors/scores, CWE weakness classification, and
reference links.

Data source:
  https://services.nvd.nist.gov/rest/json/cves/2.0
  https://nvd.nist.gov/developers/vulnerabilities

No authentication required for basic use. An optional NVD_API_KEY
(free, https://nvd.nist.gov/developers/request-an-api-key) raises the
rate limit from 5 requests/30s to 50 requests/30s — worth having for
any actor profile with more than a handful of CVEs.

Why this is different from other collectors:
  Like CISA KEV, this is CVE-centric, not actor-centric — NVD has no
  actor attribution. Its value to THEORY is depth, not breadth: KEV
  tells you a CVE is confirmed exploited; NVD tells you what the CVE
  actually IS — CVSS base/exploitability/impact scores, the CVSS
  vector string, CWE weakness category, and vendor references. The
  correlator's CVE cross-refs are currently thin on exactly this.

Pipeline position:
  Same pattern as cisa_kev.py: query() returns a minimal schema-
  conformant record (no direct actor lookup possible), and the real
  work happens via enrich_profile(), called by the CLI after all
  collect-phase sources have populated profile['cves'].

Rate limiting:
  NVD's API is per-request rate limited (not bulk-catalog like KEV),
  so each CVE lookup is its own HTTP call. A short on-disk cache per
  CVE avoids re-fetching the same CVE across repeated runs, and a
  request-spacing delay keeps THEORY under NVD's public rate limit
  even without an API key.
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

SOURCE_ID = "nvd"

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CACHE_DIR = Path(".cache/nvd")
CACHE_TTL_SECONDS = 30 * 24 * 3600   # 30 days — CVE metadata rarely changes once published

TIMEOUT = 30
RETRY_MAX = 2
RETRY_WAIT = 4

# Without an API key: 5 requests/30s → space requests ~6.5s apart to stay
# safely under the limit. With a key: 50 requests/30s → ~0.7s is plenty.
DELAY_NO_KEY = 6.5
DELAY_WITH_KEY = 0.7

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class NVDCollector(BaseCollector):
    """Collector for NIST NVD CVE detail.

    Unlike actor-centric collectors, this has no actor lookup — CVE
    detail is fetched per-CVE via enrich_profile(), which cross-
    references CVEs already present in the profile (from vuldb,
    cisa_kev, or vendor synthesis) against the NVD API.
    """

    SOURCE_ID = SOURCE_ID
    REQUIRES_API_KEY = False   # optional — raises rate limit, not a hard requirement

    def __init__(self, api_key: str | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._api_key = api_key
        self._last_request_ts: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def query(self, actor_name: str) -> dict[str, Any] | None:
        """Query interface for pipeline compatibility.

        NVD has no actor attribution, so this returns a minimal
        schema-conformant profile. Real enrichment happens via
        enrich_profile() after other collectors have populated CVEs.
        """
        canonical = resolve_canonical(actor_name)
        logger.info(
            "NVD: no direct actor lookup — CVE detail is added during "
            "enrichment for any CVEs already in the profile."
        )
        return {
            "actor_name": canonical,
            "source_id": SOURCE_ID,
            "source_url": "https://nvd.nist.gov/",
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
            "raw_source": "NIST NVD",
        }

    def enrich_profile(self, profile: dict[str, Any]) -> dict[str, Any]:
        """Cross-reference profile CVEs against NVD for full CVE detail.

        For each CVE already in profile['cves'], adds (when available):
          - nvd_cvss_version: str  ("3.1", "3.0", "2.0")
          - nvd_cvss_score: float  (base score)
          - nvd_cvss_severity: str ("CRITICAL", "HIGH", "MEDIUM", "LOW")
          - nvd_cvss_vector: str   (e.g. "CVSS:3.1/AV:N/AC:L/...")
          - nvd_cwe: list[str]     (e.g. ["CWE-787"])
          - nvd_references: list[str] (vendor advisories, patches, etc.)
          - nvd_published: str     (NVD publish date)

        Also adds a top-level nvd_enriched_count for quick access.
        """
        existing_cves = profile.get("cves") or []
        if not existing_cves:
            logger.debug("NVD: no CVEs in profile to enrich.")
            return profile

        enriched_count = 0
        for cve_entry in existing_cves:
            if not isinstance(cve_entry, dict):
                continue
            cve_id = (
                cve_entry.get("cve_id") or cve_entry.get("cveID") or ""
            ).upper().strip()
            if not cve_id or not _CVE_RE.match(cve_id):
                continue

            detail = self._lookup(cve_id)
            if not detail:
                continue

            cve_entry.update(detail)
            sources = cve_entry.get("sources") or []
            if SOURCE_ID not in sources:
                sources.append(SOURCE_ID)
            cve_entry["sources"] = sources

            if not cve_entry.get("description") and detail.get("_nvd_description"):
                cve_entry["description"] = detail["_nvd_description"]
            cve_entry.pop("_nvd_description", None)

            enriched_count += 1

        profile["cves"] = existing_cves
        profile["nvd_enriched_count"] = enriched_count
        logger.info(
            "NVD: enriched %d/%d CVEs with CVSS/CWE detail",
            enriched_count, len(existing_cves),
        )
        return profile

    def lookup_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Look up a single CVE's NVD detail. Used by the v2.0 --technique
        correlation layer for CVE metadata on demand."""
        return self._lookup(cve_id.upper().strip())

    # ------------------------------------------------------------------
    # NVD API + caching
    # ------------------------------------------------------------------

    def _cache_path(self, cve_id: str) -> Path:
        return CACHE_DIR / f"{cve_id}.json"

    def _lookup(self, cve_id: str) -> dict[str, Any] | None:
        if not _CVE_RE.match(cve_id):
            return None

        cache_file = self._cache_path(cve_id)
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < CACHE_TTL_SECONDS:
                try:
                    raw = json.loads(cache_file.read_text(encoding="utf-8"))
                    return raw or None
                except (json.JSONDecodeError, OSError):
                    pass

        raw = self._fetch(cve_id)
        parsed = self._parse(raw) if raw else None

        # Only cache successful lookups. Caching a None/empty result would
        # mean a transient failure (rate limit, network blip) silently
        # blocks re-fetching this CVE for the full TTL — a real CVE that
        # legitimately isn't in NVD is rare enough that re-checking it on
        # the next run is cheap; wrongly caching a temporary miss isn't.
        if parsed:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            try:
                cache_file.write_text(
                    json.dumps(parsed, ensure_ascii=False), encoding="utf-8"
                )
            except OSError as exc:
                logger.debug("NVD: cache write failed for %s: %s", cve_id, exc)

        return parsed

    def _fetch(self, cve_id: str) -> dict[str, Any] | None:
        self._respect_rate_limit()

        headers = {
            "User-Agent": "THEORY/1.0 threat-intel-research",
            "Accept": "application/json",
        }
        if self._api_key:
            headers["apiKey"] = self._api_key

        url = f"{API_URL}?cveId={cve_id}"
        req = Request(url, headers=headers)

        for attempt in range(1, RETRY_MAX + 1):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    self._last_request_ts = time.time()
                    return data
            except HTTPError as exc:
                if exc.code == 429:
                    logger.warning(
                        "NVD: rate limited (429) on %s. Free tier is 5 req/30s "
                        "without a key, 50 req/30s with NVD_API_KEY set.", cve_id,
                    )
                    time.sleep(RETRY_WAIT * attempt * 2)
                elif exc.code == 404:
                    logger.debug("NVD: %s not found.", cve_id)
                    return None
                else:
                    logger.warning(
                        "NVD: HTTP %d on attempt %d/%d for %s.",
                        exc.code, attempt, RETRY_MAX, cve_id,
                    )
                    if attempt < RETRY_MAX:
                        time.sleep(RETRY_WAIT)
            except (URLError, OSError, json.JSONDecodeError) as exc:
                logger.warning(
                    "NVD: request error on attempt %d/%d for %s: %s",
                    attempt, RETRY_MAX, cve_id, exc,
                )
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT)
        return None

    def _respect_rate_limit(self) -> None:
        delay = DELAY_WITH_KEY if self._api_key else DELAY_NO_KEY
        elapsed = time.time() - self._last_request_ts
        if elapsed < delay:
            time.sleep(delay - elapsed)

    @staticmethod
    def _parse(raw: dict[str, Any]) -> dict[str, Any] | None:
        vulns = raw.get("vulnerabilities") or []
        if not vulns:
            return None
        cve = vulns[0].get("cve", {})

        out: dict[str, Any] = {}

        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                data = entries[0].get("cvssData", {})
                out["nvd_cvss_version"] = data.get("version", "")
                out["nvd_cvss_score"] = data.get("baseScore")
                out["nvd_cvss_vector"] = data.get("vectorString", "")
                out["nvd_cvss_severity"] = (
                    data.get("baseSeverity") or entries[0].get("baseSeverity", "")
                ).upper()
                break

        cwe_ids: list[str] = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)
        if cwe_ids:
            out["nvd_cwe"] = sorted(set(cwe_ids))

        refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
        if refs:
            out["nvd_references"] = refs[:10]   # cap — some CVEs have 50+ refs

        out["nvd_published"] = cve.get("published", "")

        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en" and desc.get("value"):
                out["_nvd_description"] = desc["value"]
                break

        return out or None


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

class NVDMapper:
    """Post-processing mapper for NVD data. Records are already
    schema-conformant coming out of the collector; this is a light
    validation passthrough for pipeline consistency."""

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

_SHARED_COLLECTOR: NVDCollector | None = None


def _get_shared_collector() -> NVDCollector:
    global _SHARED_COLLECTOR
    if _SHARED_COLLECTOR is None:
        import os
        _SHARED_COLLECTOR = NVDCollector(api_key=os.environ.get("NVD_API_KEY") or None)
    return _SHARED_COLLECTOR


def enrich_profile_with_nvd(profile: dict[str, Any]) -> dict[str, Any]:
    """Module-level convenience: enrich a profile with NVD CVE detail."""
    return _get_shared_collector().enrich_profile(profile)


def lookup_cve(cve_id: str) -> dict[str, Any] | None:
    """Module-level convenience: look up a single CVE's NVD detail."""
    return _get_shared_collector().lookup_cve(cve_id)
