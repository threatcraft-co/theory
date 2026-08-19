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

Cache: .cache/abuseipdb/{ip_hash}.json, TTL 3 days
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from collectors.base import BaseCollector

logger = logging.getLogger(__name__)

SOURCE_ID        = "abuseipdb"
API_URL          = "https://api.abuseipdb.com/api/v2/check"
CACHE_DIR        = Path(".cache/abuseipdb")
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

        results: dict[str, dict] = {}
        lookup_count = 0

        for ip in ips:
            cached = self._load_cache(ip)
            if cached is not None:
                results[ip] = cached
                continue

            context = self._check_ip(ip)
            if context:
                results[ip] = context
                self._save_cache(ip, context)
                lookup_count += 1
            else:
                miss = {
                    "abuse_confidence_score": -1,
                    "total_reports": 0,
                    "num_distinct_users": 0,
                    "country_code": "",
                    "isp": "",
                    "domain": "",
                    "usage_type": "",
                    "is_whitelisted": False,
                    "last_reported_at": "",
                }
                self._save_cache(ip, miss)

            time.sleep(0.2)  # stay well under rate limits

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
        """Query AbuseIPDB CHECK endpoint for a single IP."""
        params = urlencode({
            "ipAddress":    ip,
            "maxAgeInDays": 90,
            "verbose":      "",
        })
        url = f"{API_URL}?{params}"

        req = Request(
            url,
            headers={
                "Key":        self._abuseipdb_key,
                "Accept":     "application/json",
                "User-Agent": "THEORY/1.0 threat-intel-research",
            },
            method="GET",
        )

        for attempt in range(1, RETRY_MAX + 1):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    raw = json.loads(resp.read().decode("utf-8"))
                    data = raw.get("data", {})
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
            except HTTPError as exc:
                if exc.code == 429:
                    logger.warning(
                        "AbuseIPDB: rate limited (1000 checks/day on free tier). "
                        "Stopping enrichment."
                    )
                    return None
                if exc.code == 422:
                    # Invalid IP (e.g. not routable)
                    return None
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT * attempt)
                else:
                    logger.debug("AbuseIPDB check failed for %s: HTTP %d", ip, exc.code)
                    return None
            except URLError:
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT)
                else:
                    return None
        return None

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _load_cache(self, ip: str) -> dict | None:
        cache_path = CACHE_DIR / f"{_ip_hash(ip)}.json"
        if not cache_path.exists():
            return None
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            cached_at = datetime.fromisoformat(data.get("cached_at", "2000-01-01"))
            age = datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc)
            if age > timedelta(days=CACHE_TTL_DAYS):
                return None
            return data.get("context")
        except Exception:
            return None

    def _save_cache(self, ip: str, context: dict) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path = CACHE_DIR / f"{_ip_hash(ip)}.json"
        cache_path.write_text(
            json.dumps({
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "ip":        ip,
                "context":   context,
            }, indent=2),
            encoding="utf-8",
        )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _ip_hash(ip: str) -> str:
    """Hash an IP to a safe cache filename."""
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


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
