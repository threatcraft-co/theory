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
no data, and is cached as a miss the same as a real empty result so a
re-run doesn't keep re-querying a dead end.

Cache: .cache/shodan_internetdb/{ip_hash}.json, TTL 24 hours (open ports
and exposed services can change day to day, unlike IP reputation which
GreyNoise/AbuseIPDB cache for longer).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from collectors.base import BaseCollector

logger = logging.getLogger(__name__)

SOURCE_ID       = "shodan_internetdb"
API_BASE        = "https://internetdb.shodan.io"
CACHE_DIR       = Path(".cache/shodan_internetdb")
CACHE_TTL_HOURS = 24
TIMEOUT         = 10
RETRY_MAX       = 2
RETRY_WAIT      = 2

# Conservative cap — InternetDB publishes no documented rate limit, but
# THEORY doesn't lean on that; keeps one run's enrichment pass bounded.
MAX_IPS_PER_RUN = 40

_EMPTY_RESULT = {"ports": [], "hostnames": [], "cpes": [], "tags": [], "vulns": []}


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return True  # not a parseable IP at all — don't waste a lookup on it


def _ip_hash(ip: str) -> str:
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()[:16]


class ShodanInternetDBCollector(BaseCollector):
    """Enriches IP indicators with Shodan InternetDB context. No API
    key, no auth — post-processor, called after the main pipeline has
    aggregated all IOCs, same shape as GreyNoiseCollector/AbuseIPDBCollector."""

    SOURCE_ID = SOURCE_ID
    REQUIRES_API_KEY = False

    def __init__(self, api_key: str | None = None, config: dict | None = None):
        super().__init__(api_key=api_key, config=config or {})

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
                if ip_val and not _is_private(ip_val):
                    ip_set.add(ip_val)

        if not ip_set:
            logger.debug("Shodan InternetDB: no public IPs to enrich")
            return {}

        ips = sorted(ip_set)[:MAX_IPS_PER_RUN]
        logger.info(
            "Shodan InternetDB: enriching %d IPs (of %d total) for %s",
            len(ips), len(ip_set), actor_name,
        )

        results: dict[str, dict] = {}
        lookup_count = 0

        for ip in ips:
            cached = self._load_cache(ip)
            if cached is not None:
                results[ip] = cached
                continue

            context = self._lookup_ip(ip)
            if context is not None:
                results[ip] = context
                self._save_cache(ip, context)
                lookup_count += 1
            else:
                self._save_cache(ip, dict(_EMPTY_RESULT))  # cache the miss

            time.sleep(0.3)  # polite pacing — no documented limit, but still a shared free service

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
        url = f"{API_BASE}/{ip}"
        req = Request(url, headers={"Accept": "application/json", "User-Agent": "THEORY/1.0 threat-intel-research"})

        for attempt in range(1, RETRY_MAX + 1):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return {
                        "ports":     sorted(data.get("ports", []) or []),
                        "hostnames": data.get("hostnames", []) or [],
                        "cpes":      data.get("cpes", []) or [],
                        "tags":      data.get("tags", []) or [],
                        "vulns":     sorted(data.get("vulns", []) or []),
                    }
            except HTTPError as exc:
                if exc.code == 404:
                    return None  # nothing on file for this IP — not an error
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT * attempt)
                else:
                    logger.debug("Shodan InternetDB lookup failed for %s: HTTP %d", ip, exc.code)
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
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

        cached_at = payload.get("_cached_at", 0)
        if time.time() - cached_at > CACHE_TTL_HOURS * 3600:
            return None  # stale

        return payload.get("data")

    def _save_cache(self, ip: str, data: dict) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path = CACHE_DIR / f"{_ip_hash(ip)}.json"
        try:
            cache_path.write_text(
                json.dumps({"_cached_at": time.time(), "data": data}),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Shodan InternetDB: failed to write cache for %s: %s", ip, exc)
