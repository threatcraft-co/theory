"""
collectors/threatfox.py
------------------------
Pulls IOCs from ThreatFox (abuse.ch) by malware family name.

ThreatFox is purpose-built for machine-readable IOC consumption:
  - Free, no auth required
  - Curated by abuse.ch with confidence scores
  - Tagged by malware family, threat type, and TLP
  - Updated continuously

Strategy: query by malware family name for each tool/malware in the
actor profile. This gives more precise attribution than actor-level
searches because every IOC is directly tied to a specific malware
family used by the actor.

API docs: https://threatfox.abuse.ch/api/
Endpoint: https://threatfox-api.abuse.ch/api/v1/

Confidence scoring:
  100     → HIGH (abuse.ch confirmed)
  75-99   → MEDIUM
  <75     → LOW

Cache: .cache/threatfox/{family_slug}.json, TTL 24 hours
(IOCs are time-sensitive — shorter TTL than Sigma/Malpedia)
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from collectors.base import BaseCollector

logger = logging.getLogger(__name__)

SOURCE_ID           = "threatfox"
API_URL             = "https://threatfox-api.abuse.ch/api/v1/"
CACHE_DIR           = Path(".cache/threatfox")
CACHE_TTL_HOURS     = 24
TIMEOUT             = 15
RETRY_MAX           = 2
RETRY_WAIT          = 2
MAX_IOCS_PER_FAMILY = 45

_IOC_TYPE_MAP: dict[str, str] = {
    "ip:port":     "ip",
    "domain":      "domain",
    "url":         "url",
    "md5_hash":    "hash_md5",
    "sha256_hash": "hash_sha256",
}

_THREAT_TYPE_LABELS: dict[str, str] = {
    "botnet_cc":        "Botnet C2",
    "payload":          "Payload Delivery",
    "payload_delivery": "Payload Delivery",
    "cc":               "Command & Control",
    "reconnaissance":   "Reconnaissance",
}

# Threat types ordered by operational priority for defenders
_THREAT_PRIORITY: dict[str, int] = {
    "botnet_cc":        0,
    "cc":               0,
    "payload_delivery": 1,
    "payload":          1,
    "reconnaissance":   2,
}


class ThreatFoxCollector(BaseCollector):
    """
    Queries ThreatFox by malware family name for each malware/tool
    in the actor profile.

    Registered in ENRICHMENT_SOURCES in theory.py — called after the
    main pipeline has built the profile with malware family names from
    MITRE and Malpedia.
    """

    SOURCE_ID = SOURCE_ID

    def query(self, actor_name: str) -> dict | None:
        """Standard interface stub — ThreatFox is enrichment-only."""
        return None

    def collect_for_malware_families(
        self,
        malware_names: list[str],
        actor_name:    str,
    ) -> dict[str, Any] | None:
        """
        Query ThreatFox for each malware family and aggregate IOCs.

        Args:
            malware_names: Malware/tool names from the actor profile.
            actor_name:    Canonical actor name (for schema output).

        Returns:
            CommonSchema-compatible dict, or None if no IOCs found.
        """
        if not malware_names:
            return None

        all_iocs:    list[dict] = []
        seen_values: set[str]   = set()
        family_hits: dict[str, int] = {}

        logger.info(
            "ThreatFox: querying %d malware families for %s",
            len(malware_names), actor_name,
        )

        for family_name in malware_names:
            iocs = self._fetch_family_iocs(family_name)
            if iocs:
                family_hits[family_name] = len(iocs)
                for ioc in iocs:
                    key = f"{ioc['type']}:{ioc['value'].lower()}"
                    if key not in seen_values:
                        seen_values.add(key)
                        ioc["malware_family"] = family_name
                        all_iocs.append(ioc)
            time.sleep(0.3)  # polite pacing — abuse.ch is a community resource

        if not all_iocs:
            logger.info("ThreatFox: no IOCs found for any malware family")
            return None

        # Sort: confidence desc, then threat type priority, then recency
        all_iocs.sort(key=lambda x: (
            -x.get("confidence", 0),
            _THREAT_PRIORITY.get(x.get("threat_type", ""), 99),
            x.get("first_seen", ""),
        ))

        logger.info(
            "ThreatFox: %d unique IOCs across %d families with hits: %s",
            len(all_iocs),
            len(family_hits),
            ", ".join(f"{k}({v})" for k, v in list(family_hits.items())[:5]),
        )

        return {
            "actor_name":    actor_name,
            "source_id":     SOURCE_ID,
            "aliases":       [],
            "description":   "",
            "origin":        "",
            "first_seen":    "",
            "motivations":   [],
            "techniques":    [],
            "indicators":    all_iocs,
            "malware":       [],
            "campaigns":     [],
            "sectors":       [],
            "family_hits":   family_hits,
            "raw_source":    "ThreatFox (abuse.ch)",
        }

    # ------------------------------------------------------------------
    # Per-family IOC fetch
    # ------------------------------------------------------------------

    def _fetch_family_iocs(self, family_name: str) -> list[dict]:
        """Query ThreatFox for IOCs tagged to a specific malware family."""
        cache_key  = _slugify(family_name)
        cached     = self._load_cache(cache_key)
        if cached is not None:
            return cached

        payload = json.dumps({
            "query":        "taginfo",
            "tag":          family_name,
            "limit":        MAX_IOCS_PER_FAMILY,
        }).encode("utf-8")

        try:
            data = self._post(API_URL, payload)
        except Exception as exc:
            logger.debug("ThreatFox fetch failed for %r: %s", family_name, exc)
            self._save_cache(cache_key, [])
            return []

        if not isinstance(data, dict):
            self._save_cache(cache_key, [])
            return []

        query_status = data.get("query_status", "")
        if query_status == "no_results":
            logger.debug("ThreatFox: no results for %r", family_name)
            self._save_cache(cache_key, [])
            return []

        raw_iocs = data.get("data", []) or []
        if not isinstance(raw_iocs, list):
            self._save_cache(cache_key, [])
            return []

        parsed = [self._parse_ioc(ioc) for ioc in raw_iocs]
        parsed = [ioc for ioc in parsed if ioc]  # drop None

        self._save_cache(cache_key, parsed)
        logger.debug("ThreatFox: %d IOCs for %r", len(parsed), family_name)
        return parsed

    # ------------------------------------------------------------------
    # IOC parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ioc(raw: dict) -> dict | None:
        """Parse a raw ThreatFox IOC record into THEORY's IOC schema."""
        ioc_type_raw = (raw.get("ioc_type") or "").lower()
        theory_type  = _IOC_TYPE_MAP.get(ioc_type_raw, "")
        if not theory_type:
            return None

        raw_value = (raw.get("ioc") or "").strip()
        if not raw_value:
            return None

        # ip:port → extract just the IP
        value = raw_value
        if ioc_type_raw == "ip:port":
            value = raw_value.split(":")[0].strip()
            if not value:
                return None

        confidence   = int(raw.get("confidence_level", 0) or 0)
        threat_type  = (raw.get("threat_type") or "").lower()
        threat_label = _THREAT_TYPE_LABELS.get(threat_type, threat_type.replace("_", " ").title())
        first_seen   = (raw.get("first_seen") or "")[:10]   # YYYY-MM-DD
        last_seen    = (raw.get("last_seen")  or "")[:10]
        tags         = raw.get("tags") or []
        malware_name = (raw.get("malware") or raw.get("malware_printable") or "")

        return {
            "type":          theory_type,
            "value":         value,
            "confidence":    confidence,
            "threat_type":   threat_type,
            "threat_label":  threat_label,
            "first_seen":    first_seen,
            "last_seen":     last_seen,
            "tags":          tags if isinstance(tags, list) else [],
            "malware":       malware_name,
            "description":   f"{threat_label} — {malware_name}" if malware_name else threat_label,
            "sources":       [SOURCE_ID],
        }

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _load_cache(self, cache_key: str) -> list[dict] | None:
        cache_path = CACHE_DIR / f"{cache_key}.json"
        if not cache_path.exists():
            return None
        try:
            data      = json.loads(cache_path.read_text(encoding="utf-8"))
            cached_at = datetime.fromisoformat(data.get("cached_at", "2000-01-01"))
            age       = datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc)
            if age > timedelta(hours=CACHE_TTL_HOURS):
                logger.debug("ThreatFox cache stale for %s", cache_key)
                return None
            return data.get("iocs", [])
        except Exception:
            return None

    def _save_cache(self, cache_key: str, iocs: list[dict]) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path = CACHE_DIR / f"{cache_key}.json"
        cache_path.write_text(
            json.dumps({
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "iocs":      iocs,
            }, indent=2),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    @staticmethod
    def _post(url: str, payload: bytes) -> Any:
        req = Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
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
    """Convert malware name to a safe cache filename."""
    return re.sub(r"[^a-z0-9_]", "_", name.lower())[:80]


def _threat_priority(threat_type: str) -> int:
    return _THREAT_PRIORITY.get((threat_type or "").lower(), 99)
