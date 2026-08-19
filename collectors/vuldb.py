"""
collectors/vuldb.py
--------------------
Queries VulDB's Cyber Threat Intelligence (CTI) API for actor-CVE
associations.

VulDB uniquely associates threat actors with specific vulnerabilities,
providing the actor -> CVE correlation layer that seeds THEORY's v2.0
`theory --cve` roadmap. For the current actor-centric pipeline, this
adds an "Exploited Vulnerabilities" section to the dossier showing
which CVEs the actor is known to exploit.

API: POST https://vuldb.com/?api
Auth: VULDB_API_KEY (free tier: starts at 50 credits/day,
      decreases over time; CTI queries cost 5-10 credits each)
Docs: https://vuldb.com/?kb.api

Response includes:
  - CVE ID and description
  - CVSS scores (base + temporal)
  - Exploit availability and pricing
  - Affected products
  - Timeline (disclosure, patch, exploit)

Cache: .cache/vuldb/{actor_slug}.json, TTL 7 days
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from collectors.base import BaseCollector

logger = logging.getLogger(__name__)

SOURCE_ID        = "vuldb"
API_URL          = "https://vuldb.com/?api"
CACHE_DIR        = Path(".cache/vuldb")
CACHE_TTL_DAYS   = 7
TIMEOUT          = 15
RETRY_MAX        = 2
RETRY_WAIT       = 2
MAX_RESULTS      = 20


class VulDBCollector(BaseCollector):
    """
    Queries VulDB CTI for vulnerabilities associated with a threat actor.

    Returns CVE entries enriched with CVSS scores, exploit info, and
    affected products. These integrate into the dossier's CVE section
    and feed the v2.0 --cve correlation layer.
    """

    SOURCE_ID = SOURCE_ID
    REQUIRES_API_KEY = True

    def __init__(self, api_key: str | None = None, config: dict | None = None):
        super().__init__(api_key=api_key, config=config or {})
        # Fall back to env var so the collector works when instantiated
        # with no arguments (as _cli.py does during the collect phase).
        self._vuldb_key = api_key or os.environ.get("VULDB_API_KEY", "")

    def query(self, actor_name: str) -> dict[str, Any]:
        """
        Query VulDB for CVEs associated with the given actor.

        Returns a CommonSchema-compatible dict with populated cves field.
        """
        if not self._vuldb_key:
            logger.info(
                "VulDB: skipped -- no VULDB_API_KEY. "
                "Get one at https://vuldb.com/?register"
            )
            return self._empty_schema(actor_name)

        # Check cache first
        cache_key = _slugify(actor_name)
        cached = self._load_cache(cache_key)
        if cached is not None:
            logger.info("VulDB: using cached results for %s", actor_name)
            return cached

        logger.info("VulDB: querying actor CTI for %s", actor_name)

        # VulDB CTI search by actor name
        cves = self._search_actor(actor_name)

        schema = self._empty_schema(actor_name)
        schema["cves"] = cves
        schema["source_url"] = f"https://vuldb.com/?actor.{_slugify(actor_name)}"
        schema["source_citation"] = "VulDB CTI (vuldb.com)"

        self._save_cache(cache_key, schema)

        logger.info("VulDB: found %d CVEs for %s", len(cves), actor_name)
        return schema

    # ------------------------------------------------------------------
    # Actor search
    # ------------------------------------------------------------------

    def _search_actor(self, actor_name: str) -> list[dict]:
        """Search VulDB for vulnerabilities linked to a threat actor."""
        # VulDB API uses POST with form-encoded data
        form_data = urlencode({
            "apikey":  self._vuldb_key,
            "search":  actor_name,
            "details": "1",
        }).encode("utf-8")

        try:
            data = self._api_post(form_data)
        except Exception as exc:
            logger.debug("VulDB search failed for %r: %s", actor_name, exc)
            return []

        if not isinstance(data, dict):
            return []

        # VulDB returns {"response": {...}, "result": [...]}
        results = data.get("result", [])
        if not isinstance(results, list):
            return []

        cves: list[dict] = []
        seen_cves: set[str] = set()

        for entry in results[:MAX_RESULTS]:
            parsed = self._parse_entry(entry)
            if parsed:
                cve_id = parsed.get("cve_id", "")
                if cve_id and cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    cves.append(parsed)

        return cves

    # ------------------------------------------------------------------
    # Entry parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_entry(entry: dict) -> dict | None:
        """Parse a VulDB result into THEORY's CVEEntry schema."""
        # VulDB nests data under various sub-objects
        source = entry.get("source", {}) or {}
        cve_data = source.get("cve", {}) or {}
        cve_id = cve_data.get("id", "")

        if not cve_id:
            return None

        # Ensure proper CVE format
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        vulnerability = entry.get("vulnerability", {}) or {}
        advisory = entry.get("advisory", {}) or {}
        exploit_data = entry.get("exploit", {}) or {}
        countermeasure = entry.get("countermeasure", {}) or {}

        # Extract CVSS score
        cvss = vulnerability.get("cvss3", {}) or vulnerability.get("cvss2", {}) or {}
        cvss_score = None
        base_score = cvss.get("basescore")
        if base_score:
            try:
                cvss_score = float(base_score)
            except (ValueError, TypeError):
                pass

        # Build description
        desc_parts = []
        vuln_class = vulnerability.get("class", "")
        if vuln_class:
            desc_parts.append(vuln_class)

        risk_name = vulnerability.get("risk", {})
        if isinstance(risk_name, dict):
            risk_name = risk_name.get("name", "")
        if risk_name:
            desc_parts.append(f"Risk: {risk_name}")

        description = " | ".join(desc_parts) if desc_parts else ""

        # Extract exploit info
        exploitability = exploit_data.get("exploitability", "")
        exploit_price = exploit_data.get("price", {})
        if isinstance(exploit_price, dict):
            price_today = exploit_price.get("today", "")
        else:
            price_today = ""

        # Extract remediation
        remediation = countermeasure.get("remediationlevel", "")
        patch_name = countermeasure.get("name", "")

        return {
            "cve_id":       cve_id,
            "sources":      [SOURCE_ID],
            "description":  description,
            "cvss_score":   cvss_score,
            # VulDB-specific enrichment (beyond base CVEEntry schema)
            "vuldb_id":             entry.get("id", ""),
            "exploitability":       exploitability,
            "exploit_price_today":  price_today,
            "remediation":          f"{patch_name}: {remediation}" if patch_name else remediation,
            "advisory_url":         advisory.get("url", ""),
            "advisory_date":        advisory.get("date", ""),
        }

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _load_cache(self, cache_key: str) -> dict | None:
        cache_path = CACHE_DIR / f"{cache_key}.json"
        if not cache_path.exists():
            return None
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            cached_at = datetime.fromisoformat(data.get("cached_at", "2000-01-01"))
            age = datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc)
            if age > timedelta(days=CACHE_TTL_DAYS):
                logger.debug("VulDB cache stale for %s", cache_key)
                return None
            return data.get("schema")
        except Exception:
            return None

    def _save_cache(self, cache_key: str, schema: dict) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path = CACHE_DIR / f"{cache_key}.json"
        cache_path.write_text(
            json.dumps({
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "schema":    schema,
            }, indent=2),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _api_post(self, form_data: bytes) -> Any:
        """POST form-encoded data to VulDB API."""
        req = Request(
            API_URL,
            data=form_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent":   "THEORY/1.0 threat-intel-research",
            },
            method="POST",
        )
        for attempt in range(1, RETRY_MAX + 1):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except HTTPError as exc:
                if exc.code == 429 and attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT * attempt)
                elif exc.code == 403:
                    logger.warning(
                        "VulDB: API credits exhausted. Free tier provides "
                        "50 credits/day (CTI queries cost 5-10 each)."
                    )
                    return {}
                else:
                    raise
            except URLError:
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT)
                else:
                    raise
        return {}


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _slugify(name: str) -> str:
    """Convert actor name to a safe cache filename."""
    return re.sub(r"[^a-z0-9_]", "_", name.lower())[:80]
