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

Cache: .cache/greynoise/{ip_hash}.json, TTL 7 days
(IP reputation changes slowly; long cache is safe)
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from collectors.base import BaseCollector

logger = logging.getLogger(__name__)

SOURCE_ID        = "greynoise"
API_BASE         = "https://api.greynoise.io/v3/community"
CACHE_DIR        = Path(".cache/greynoise")
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
        self._gn_key = api_key or ""

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
                if ip_val and not _is_private(ip_val):
                    ip_set.add(ip_val)

        if not ip_set:
            logger.debug("GreyNoise: no public IPs to enrich")
            return {}

        ips = sorted(ip_set)[:MAX_IPS_PER_RUN]
        logger.info(
            "GreyNoise: enriching %d IPs (of %d total) for %s",
            len(ips), len(ip_set), actor_name,
        )

        results: dict[str, dict] = {}
        lookup_count = 0

        for ip in ips:
            # Check cache first
            cached = self._load_cache(ip)
            if cached is not None:
                results[ip] = cached
                continue

            # Live lookup
            context = self._lookup_ip(ip)
            if context:
                results[ip] = context
                self._save_cache(ip, context)
                lookup_count += 1
            else:
                # Cache the miss so we don't retry
                miss = {"noise": False, "riot": False, "classification": "unknown",
                        "name": "", "last_seen": "", "link": ""}
                self._save_cache(ip, miss)

            time.sleep(0.5)  # polite pacing

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
        """Query GreyNoise Community API for a single IP."""
        url = f"{API_BASE}/{ip}"
        req = Request(
            url,
            headers={
                "key":        self._gn_key,
                "Accept":     "application/json",
                "User-Agent": "THEORY/1.0 threat-intel-research",
            },
            method="GET",
        )

        for attempt in range(1, RETRY_MAX + 1):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    if data.get("message") == "Success":
                        return {
                            "noise":          data.get("noise", False),
                            "riot":           data.get("riot", False),
                            "classification": data.get("classification", "unknown"),
                            "name":           data.get("name", ""),
                            "last_seen":      data.get("last_seen", ""),
                            "link":           data.get("link", ""),
                        }
                    return None
            except HTTPError as exc:
                if exc.code == 404:
                    # IP not in GreyNoise dataset
                    return None
                if exc.code == 429:
                    logger.warning(
                        "GreyNoise: rate limited. Community tier allows "
                        "50 lookups/week. Stopping enrichment."
                    )
                    return None
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT * attempt)
                else:
                    logger.debug("GreyNoise lookup failed for %s: HTTP %d", ip, exc.code)
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
