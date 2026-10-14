"""
collectors/abuseipdb.py
------------------------
Enriches IP IOCs with AbuseIPDB reputation scores.

AbuseIPDB provides a second independent confidence signal for IP
indicators. Where GreyNoise tells you whether an IP is background
noise, AbuseIPDB tells you how widely it has been reported as
abusive across the community.

The key field is abuseConfidenceScore (0-100): the percentage of
reporters who flagged this IP as abusive. A score of 100 means
every reporter considers it malicious; 0 means no reports.

API: GET https://api.abuseipdb.com/api/v2/check
Auth: ABUSEIPDB_API_KEY (free at abuseipdb.com, 1000 checks/day)

Cache: .cache/abuseipdb/, TTL 3 days (see theory.disk_cache). Only real answers
are cached. A 429 means the daily quota is spent: the run stops and nothing
is cached for the IPs it did not reach (see collectors/_enrich.py).
"""

from __future__ import annotations

import logging
import os
from datetime import timedelta

from collectors._enrich import enrich_keys
from collectors.base import BaseCollector

from theory.disk_cache import DiskCache
from theory.http_client import HttpClient, HttpError

logger = logging.getLogger(__name__)

SOURCE_ID        = "abuseipdb"
API_URL          = "https://api.abuseipdb.com/api/v2/check"
CACHE_TTL_DAYS   = 3
TIMEOUT          = 10
RETRY_MAX        = 2
RETRY_WAIT       = 2

# AbuseIPDB free tier: 1000 checks/day. Be conservative within
# a single dossier run -- leave budget for other runs.
MAX_IPS_PER_RUN  = 50


class AbuseIPDBCollector(BaseCollector):
    """
    Enriches IP indicators with AbuseIPDB reputation data.

    Post-processor: called after the main pipeline has aggregated
    all IOCs. Takes the list of IP indicators and annotates them
    with abuse confidence scores and report metadata.
    """

    SOURCE_ID = SOURCE_ID
    REQUIRES_API_KEY = True

    def __init__(self, api_key: str | None = None, config: dict | None = None):
        super().__init__(api_key=api_key, config=config or {})
        # Fall back to env var so the collector works when instantiated
        # with no arguments.
        self._abuseipdb_key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        # 1000 checks/day: a 429 means the quota is gone, not that waiting a
        # couple of seconds will help, so it is not retried. enrich_keys
        # stops the run on RateLimited. Other transient errors retry.
        self._http = HttpClient(
            timeout=TIMEOUT, attempts=RETRY_MAX, backoff=RETRY_WAIT,
            headers={"Key": self._abuseipdb_key},
            retry_statuses={500, 502, 503, 504},
        )
        self._cache = DiskCache(SOURCE_ID, ttl=timedelta(days=CACHE_TTL_DAYS))

    def query(self, actor_name: str) -> dict | None:
        """Standard interface stub -- AbuseIPDB is enrichment-only."""
        return None

    def enrich_ips(
        self,
        indicators: list[dict],
        actor_name: str,
    ) -> dict[str, dict]:
        """
        Enrich IP indicators with AbuseIPDB reputation data.

        Args:
            indicators: Full IOC list from the actor profile.
            actor_name: Canonical actor name (for logging).

        Returns:
            Dict mapping IP address -> AbuseIPDB context, e.g.:
            {
                "1.2.3.4": {
                    "abuse_confidence_score": 95,
                    "total_reports": 142,
                    "num_distinct_users": 38,
                    "country_code": "CN",
                    "isp": "Example ISP",
                    "domain": "example.com",
                    "usage_type": "Data Center/Web Hosting/Transit",
                    "is_whitelisted": False,
                    "last_reported_at": "2026-08-15T10:30:00+00:00",
                },
            }
        """
        if not self._abuseipdb_key:
            logger.info(
                "AbuseIPDB: skipped -- no ABUSEIPDB_API_KEY. "
                "Get one free at https://www.abuseipdb.com/account/api"
            )
            return {}

        # Extract unique IPs
        ip_set: set[str] = set()
        for ioc in indicators:
            if ioc.get("type") == "ip":
                ip_val = ioc.get("value", "").strip()
                if ip_val and not _is_private(ip_val):
                    ip_set.add(ip_val)

        if not ip_set:
            logger.debug("AbuseIPDB: no public IPs to enrich")
            return {}

        ips = sorted(ip_set)[:MAX_IPS_PER_RUN]
        logger.info(
            "AbuseIPDB: enriching %d IPs (of %d total) for %s",
            len(ips), len(ip_set), actor_name,
        )

        results, stats = enrich_keys(
            ips, cache=self._cache, load=self._check_ip,
            source="AbuseIPDB", pace=0.2,   # stay well under rate limits
        )
        lookup_count = stats.live

        high_abuse = sum(
            1 for r in results.values()
            if r.get("abuse_confidence_score", 0) >= 75
        )
        logger.info(
            "AbuseIPDB: %d results (%d live lookups). %d high-abuse (>=75%%).",
            len(results), lookup_count, high_abuse,
        )

        return results

    # ------------------------------------------------------------------
    # IP check
    # ------------------------------------------------------------------

    def _check_ip(self, ip: str) -> dict | None:
        """Query AbuseIPDB CHECK endpoint for a single IP.

        Returns None when AbuseIPDB has nothing for it (including 422, which
        it returns for addresses it will never score, such as non-routable
        ones: deterministic, so safe to remember). Raises HttpError when the
        question could not be answered (429, timeout, 5xx, bad key); those
        are not cached.
        """
        try:
            raw = self._http.get_json(
                API_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            )
        except HttpError as exc:
            if exc.status == 422:
                return None
            raise

        data = raw.get("data", {}) if isinstance(raw, dict) else {}
        if not data:
            return None
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports":          data.get("totalReports", 0),
            "num_distinct_users":     data.get("numDistinctUsers", 0),
            "country_code":           data.get("countryCode", ""),
            "isp":                    data.get("isp", ""),
            "domain":                 data.get("domain", ""),
            "usage_type":             data.get("usageType", ""),
            "is_whitelisted":         data.get("isWhitelisted", False),
            "last_reported_at":       data.get("lastReportedAt", ""),
        }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _is_private(ip: str) -> bool:
    """Quick check for RFC1918 / loopback / link-local addresses."""
    return (
        ip.startswith("10.")
        or ip.startswith("172.16.") or ip.startswith("172.17.")
        or ip.startswith("172.18.") or ip.startswith("172.19.")
        or ip.startswith("172.2") or ip.startswith("172.30.")
        or ip.startswith("172.31.")
        or ip.startswith("192.168.")
        or ip.startswith("127.")
        or ip.startswith("0.")
        or ip.startswith("169.254.")
        or ip == "::1"
        or ip.startswith("fe80:")
        or ip.startswith("fc00:")
        or ip.startswith("fd")
    )
