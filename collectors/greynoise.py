"""
collectors/greynoise.py
------------------------
Enriches IP IOCs with GreyNoise Community data to distinguish
internet background noise from targeted activity.

GreyNoise is the single highest-value enrichment source for IP IOCs
because it answers the question every analyst asks when triaging an
IP indicator: "is this IP actually interesting, or is it just
Shodan/Censys/ZMap background radiation?"

The Community API returns three key fields:
  - noise:          True if the IP is mass-scanning the internet
  - riot:           True if the IP is a known benign service (CDN, DNS, etc.)
  - classification: "benign", "malicious", or "unknown"

An IP flagged as RIOT or benign noise is almost certainly a false
positive in an actor IOC list. THEORY uses this to annotate IOCs
so analysts can focus on what matters.

API: GET https://api.greynoise.io/v3/community/{ip}
Auth: GREYNOISE_API_KEY (free at greynoise.io, non-free-email required)
Rate: 50 lookups/week on Community tier

Cache: .cache/greynoise/, TTL 7 days (see theory.disk_cache). IP reputation
changes slowly, so a long TTL is safe, but only for real answers: a 429 or a
network error is never cached (see collectors/_enrich.py). The Community
quota is small enough that burning it and then caching "unknown" for a week
would be worse than useless.
"""

from __future__ import annotations

import logging
import os
from datetime import timedelta

from collectors._enrich import enrich_keys
from collectors._ip import is_public_ip
from collectors.base import BaseCollector

from theory.disk_cache import DiskCache
from theory.http_client import HttpClient, NotFound

logger = logging.getLogger(__name__)

SOURCE_ID        = "greynoise"
API_BASE         = "https://api.greynoise.io/v3/community"
CACHE_TTL_DAYS   = 7
TIMEOUT          = 10
RETRY_MAX        = 2
RETRY_WAIT       = 2

# Maximum IPs to enrich per run (Community tier = 50/week, be conservative)
MAX_IPS_PER_RUN  = 25


class GreyNoiseCollector(BaseCollector):
    """
    Enriches IP indicators with GreyNoise Community context.

    Post-processor: called after the main pipeline has aggregated
    all IOCs. Takes the list of IP indicators, queries GreyNoise
    for each, and annotates them with noise/riot/classification.
    """

    SOURCE_ID = SOURCE_ID
    REQUIRES_API_KEY = True

    def __init__(self, api_key: str | None = None, config: dict | None = None):
        super().__init__(api_key=api_key, config=config or {})
        # Fall back to env var so the collector works when instantiated
        # with no arguments.
        self._gn_key = api_key or os.environ.get("GREYNOISE_API_KEY", "")
        # The Community quota is weekly, so a 429 is not worth waiting out:
        # enrich_keys stops the run instead. Other transient errors retry.
        self._http = HttpClient(
            timeout=TIMEOUT, attempts=RETRY_MAX, backoff=RETRY_WAIT,
            headers={"key": self._gn_key},
            retry_statuses={500, 502, 503, 504},
        )
        self._cache = DiskCache(SOURCE_ID, ttl=timedelta(days=CACHE_TTL_DAYS))

    def query(self, actor_name: str) -> dict | None:
        """Standard interface stub -- GreyNoise is enrichment-only."""
        return None

    def enrich_ips(
        self,
        indicators: list[dict],
        actor_name: str,
    ) -> dict[str, dict]:
        """
        Enrich IP indicators with GreyNoise context.

        Args:
            indicators: Full IOC list from the actor profile.
            actor_name: Canonical actor name (for logging).

        Returns:
            Dict mapping IP address -> GreyNoise context, e.g.:
            {
                "1.2.3.4": {
                    "noise": True,
                    "riot": False,
                    "classification": "malicious",
                    "name": "unknown",
                    "last_seen": "2026-08-01",
                    "link": "https://viz.greynoise.io/ip/1.2.3.4",
                },
            }
        """
        if not self._gn_key:
            logger.info(
                "GreyNoise: skipped -- no GREYNOISE_API_KEY. "
                "Get one at https://www.greynoise.io/plans"
            )
            return {}

        # Extract unique IPs from indicators
        ip_set: set[str] = set()
        for ioc in indicators:
            if ioc.get("type") == "ip":
                ip_val = ioc.get("value", "").strip()
                if ip_val and is_public_ip(ip_val):
                    ip_set.add(ip_val)

        if not ip_set:
            logger.debug("GreyNoise: no public IPs to enrich")
            return {}

        ips = sorted(ip_set)[:MAX_IPS_PER_RUN]
        logger.info(
            "GreyNoise: enriching %d IPs (of %d total) for %s",
            len(ips), len(ip_set), actor_name,
        )

        results, stats = enrich_keys(
            ips, cache=self._cache, load=self._lookup_ip,
            source="GreyNoise", pace=0.5,
        )
        lookup_count = stats.live

        benign_count = sum(
            1 for r in results.values()
            if r.get("riot") or r.get("classification") == "benign"
        )
        noise_count = sum(1 for r in results.values() if r.get("noise"))

        logger.info(
            "GreyNoise: %d results (%d live lookups). "
            "%d benign/RIOT, %d noise.",
            len(results), lookup_count, benign_count, noise_count,
        )

        return results

    # ------------------------------------------------------------------
    # IP lookup
    # ------------------------------------------------------------------

    def _lookup_ip(self, ip: str) -> dict | None:
        """Query GreyNoise Community API for a single IP.

        Returns None when GreyNoise answered that it has nothing on this IP
        (a real answer, cacheable). Raises HttpError when the question could
        not be answered (429, timeout, 5xx, bad key); those are not cached.
        """
        try:
            data = self._http.get_json(f"{API_BASE}/{ip}")
        except NotFound:
            return None  # IP not in GreyNoise dataset

        if not isinstance(data, dict) or data.get("message") != "Success":
            return None
        return {
            "noise":          data.get("noise", False),
            "riot":           data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name":           data.get("name", ""),
            "last_seen":      data.get("last_seen", ""),
            "link":           data.get("link", ""),
        }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

