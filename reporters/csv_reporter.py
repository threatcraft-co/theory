"""
reporters/csv_reporter.py
--------------------------
Exports the IOC table from a THEORY profile as a CSV file.

Columns: type, value, confidence, threat_type, malware_family, first_seen, sources

Use case: detection engineers who need to ingest IOCs into a SIEM,
blocklist, or threat intel platform that accepts CSV lookup tables.
Compatible with Splunk, Chronicle, Elastic, QRadar, and most TI platforms.

Usage:
    python theory.py --actor APT28 --sources mitre,otx,threatfox --output csv
    # writes output/dossiers/apt28_iocs.csv
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("output/dossiers")

# Column order — matches what detection engineers expect
COLUMNS = [
    "type",
    "value",
    "confidence",
    "threat_type",
    "malware_family",
    "first_seen",
    "sources",
]

# IOC types that are meaningful for blocklisting/detection
# CVEs are excluded — they belong in vuln management, not IOC feeds
EXPORTABLE_TYPES = {
    "ip", "domain", "url", "hash_md5", "hash_sha1",
    "hash_sha256", "email", "filepath", "mutex", "registry",
}


class CsvReporter:
    """
    Exports IOC table to CSV.

    Skips CVEs and other non-IOC indicator types by default.
    Includes all IOCs regardless of source (OTX, ThreatFox, CISA, etc.)
    """

    def build_rows(self, profile: dict[str, Any]) -> list[dict]:
        """Build CSV rows from profile indicators."""
        rows: list[dict] = []
        seen: set[str] = set()

        for ioc in (profile.get("indicators") or []):
            ioc_type = (ioc.get("type") or "").lower().strip()
            value    = (ioc.get("value") or "").strip()

            if not value or not ioc_type:
                continue

            # Skip non-IOC types
            if ioc_type not in EXPORTABLE_TYPES:
                continue

            # Deduplicate
            dedup_key = f"{ioc_type}:{value.lower()}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Normalize confidence to integer
            conf = ioc.get("confidence", "")
            if isinstance(conf, (int, float)):
                conf_str = str(int(conf))
            elif isinstance(conf, str) and conf.strip():
                conf_str = conf.strip()
            else:
                conf_str = ""

            # Sources as pipe-separated string
            sources = ioc.get("sources", []) or []
            if isinstance(sources, list):
                sources_str = "|".join(str(s) for s in sources if s)
            else:
                sources_str = str(sources)

            rows.append({
                "type":           ioc_type,
                "value":          value,
                "confidence":     conf_str,
                "threat_type":    (ioc.get("threat_type") or ioc.get("threat_label") or "").strip(),
                "malware_family": (ioc.get("malware_family") or "").strip(),
                "first_seen":     (ioc.get("first_seen") or "").strip(),
                "sources":        sources_str,
            })

        # Sort: IPs first, then domains, URLs, hashes, emails
        type_order = ["ip", "domain", "url", "hash_md5", "hash_sha1",
                      "hash_sha256", "email", "filepath", "mutex", "registry"]
        rows.sort(key=lambda r: (
            type_order.index(r["type"]) if r["type"] in type_order else 99,
            r["value"],
        ))

        return rows

    def save(self, profile: dict[str, Any]) -> Path:
        """Write IOC CSV to output/dossiers/<actor>_iocs.csv."""
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        actor_slug = _slugify(profile.get("actor_name", "unknown"))
        path       = OUTPUT_DIR / f"{actor_slug}_iocs.csv"

        rows = self.build_rows(profile)

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

        logger.info("CSV IOC export saved → %s (%d rows)", path, len(rows))
        return path

    def to_string(self, profile: dict[str, Any]) -> str:
        """Return CSV as a string (for --no-save or piping)."""
        import io
        rows   = self.build_rows(profile)
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()


def _slugify(name: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]", "_", name.lower())
