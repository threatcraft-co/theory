"""
collectors/shodan_internetdb.py
---------------------------------
Enriches IP IOCs with Shodan InternetDB — open ports, hostnames, CPEs,
and known CVEs currently associated with the IP.

InternetDB is Shodan's free, keyless, no-rate-limit-published lookup
service — a deliberately stripped-down subset of full Shodan search
results, built for exactly this use case (quick automated enrichment,
not deep research). It answers a different question than GreyNoise or
AbuseIPDB: not "is this noisy/malicious," but "what does this
infrastructure currently look like" — which ports are open, what
software is likely running, and whether Shodan has it flagged against
any known CVEs right now. For a C2 or scanning IP in an actor profile,
that's immediately actionable: an exposed RDP/SSH port or a live CVE
flag on the IP itself is something an analyst can act on today.

API: GET https://internetdb.shodan.io/{ip}   (no auth, no key)
Response (when the IP has data):
    {
      "ip": "1.2.3.4", "ports": [22, 80, 443],
      "hostnames": ["example.com"], "cpes": ["cpe:/a:openssh:openssh:8.2"],
      "tags": ["cloud"], "vulns": ["CVE-2021-1234"]
    }
404 means Shodan has nothing on file for that IP — not an error, just
no data. It is remembered as a miss so a re-run doesn't keep re-querying a
dead end, and the IP is left out of the results. Timeouts, 5xx and 429 are
different: they say nothing about the IP and are never cached.

Cache: .cache/shodan_internetdb/, TTL 24 hours (see theory.disk_cache). Open
ports and exposed services can change day to day, unlike IP reputation which
GreyNoise/AbuseIPDB cache for longer.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from collectors._enrich import enrich_keys
from collectors._ip import is_public_ip
from collectors.base import BaseCollector

from theory.disk_cache import DiskCache
from theory.http_client import HttpClient, NotFound

logger = logging.getLogger(__name__)

SOURCE_ID       = "shodan_internetdb"
API_BASE        = "https://internetdb.shodan.io"
CACHE_TTL_HOURS = 24
TIMEOUT         = 10
RETRY_MAX       = 2
RETRY_WAIT      = 2

# Conservative cap — InternetDB publishes no documented rate limit, but
# THEORY doesn't lean on that; keeps one run's enrichment pass bounded.
MAX_IPS_PER_RUN = 40


class ShodanInternetDBCollector(BaseCollector):
    """Enriches IP indicators with Shodan InternetDB context. No API
    key, no auth — post-processor, called after the main pipeline has
    aggregated all IOCs, same shape as GreyNoiseCollector/AbuseIPDBCollector."""

    SOURCE_ID = SOURCE_ID
    REQUIRES_API_KEY = False

    def __init__(self, api_key: str | None = None, config: dict | None = None):
        super().__init__(api_key=api_key, config=config or {})
        self._http = HttpClient(timeout=TIMEOUT, attempts=RETRY_MAX, backoff=RETRY_WAIT)
        self._cache = DiskCache(SOURCE_ID, ttl=timedelta(hours=CACHE_TTL_HOURS))

    def query(self, actor_name: str) -> dict | None:
        """Standard interface stub — InternetDB is enrichment-only."""
        return None

    def enrich_ips(self, indicators: list[dict], actor_name: str) -> dict[str, dict]:
        """Enrich IP indicators with InternetDB context.

        Returns {ip: {"ports": [...], "hostnames": [...], "cpes": [...],
        "tags": [...], "vulns": [...]}}, one entry per public IP found
        in `indicators` (private/reserved/loopback addresses are never
        looked up — nothing useful would come back, and it would waste
        a lookup).
        """
        ip_set: set[str] = set()
        for ioc in indicators:
            if ioc.get("type") == "ip":
                ip_val = (ioc.get("value") or "").strip()
                if ip_val and is_public_ip(ip_val):
                    ip_set.add(ip_val)

        if not ip_set:
            logger.debug("Shodan InternetDB: no public IPs to enrich")
            return {}

        ips = sorted(ip_set)[:MAX_IPS_PER_RUN]
        logger.info(
            "Shodan InternetDB: enriching %d IPs (of %d total) for %s",
            len(ips), len(ip_set), actor_name,
        )

        results, stats = enrich_keys(
            ips, cache=self._cache, load=self._lookup_ip,
            source="Shodan InternetDB",
            pace=0.3,  # polite pacing: no documented limit, but still a shared free service
        )
        lookup_count = stats.live

        with_vulns = sum(1 for r in results.values() if r.get("vulns"))
        logger.info(
            "Shodan InternetDB: %d results (%d live lookups), %d with known CVEs.",
            len(results), lookup_count, with_vulns,
        )
        return results

    # ------------------------------------------------------------------
    # IP lookup
    # ------------------------------------------------------------------

    def _lookup_ip(self, ip: str) -> dict | None:
        """Query InternetDB for one IP.

        Returns None when InternetDB has nothing on file (404: a real answer,
        cacheable). Raises HttpError when the question could not be answered
        (timeout, 5xx, 429); those are not cached.
        """
        try:
            data = self._http.get_json(f"{API_BASE}/{ip}")
        except NotFound:
            return None  # nothing on file for this IP — not an error

        if not isinstance(data, dict):
            return None
        return {
            "ports":     sorted(data.get("ports", []) or []),
            "hostnames": data.get("hostnames", []) or [],
            "cpes":      data.get("cpes", []) or [],
            "tags":      data.get("tags", []) or [],
            "vulns":     sorted(data.get("vulns", []) or []),
        }
