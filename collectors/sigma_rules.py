"""
collectors/sigma_rules.py
--------------------------
Pulls Sigma detection rules from SigmaHQ and indexes them by ATT&CK
technique ID.

Strategy:
  1. Check .cache/sigma/{technique_id}.json — return immediately if fresh
  2. Query GitHub Contents API for rules tagged with that technique
  3. Parse YAML rule metadata (title, logsource, detection condition)
  4. Cache results to disk

No auth required for public GitHub API (60 req/hour unauthenticated).
Set GITHUB_TOKEN in .env for 5000 req/hour.

Cache freshness: 7 days. Refresh with: python theory.py --update-bundles

SigmaHQ rule structure:
  tags:
    - attack.t1059.001        ← technique tag (lowercase)
    - attack.execution        ← tactic tag
  logsource:
    category: process_creation
    product: windows
  detection:
    selection:
      CommandLine|contains: 'powershell'
    condition: selection
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
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote

from collectors.base import BaseCollector

logger = logging.getLogger(__name__)

SOURCE_ID       = "sigma"
CACHE_DIR       = Path(".cache/sigma")
CACHE_TTL_DAYS  = 7
TIMEOUT         = 12
RETRY_MAX       = 2
RETRY_WAIT      = 2
MAX_RULES_PER_TECHNIQUE = 5   # cap per technique to keep dossier focused

# SigmaHQ GitHub API base
GITHUB_API   = "https://api.github.com"
SIGMA_OWNER  = "SigmaHQ"
SIGMA_REPO   = "sigma"

# We search within the core rules directory — highest quality, curated
SIGMA_RULES_PATH = "rules"


class SigmaCollector(BaseCollector):
    """
    Collects Sigma detection rules for a set of ATT&CK technique IDs.

    Unlike other collectors, SigmaCollector takes a list of technique IDs
    (extracted from an already-built profile) rather than an actor name.
    It's called as an enrichment step in theory.py after MITRE collection.

    Usage in theory.py:
        sigma_collector = SigmaCollector()
        sigma_data = sigma_collector.collect_for_techniques(technique_ids)
        # Returns: {tid: [rule, rule, ...], ...}
    """

    SOURCE_ID = SOURCE_ID

    def __init__(self):
        self._token = self._load_token()
        self._request_count = 0

    def query(self, actor_name: str) -> dict | None:
        # Standard interface — not used for Sigma (enrichment only)
        return None

    def collect_for_techniques(
        self, technique_ids: list[str]
    ) -> dict[str, list[dict]]:
        """
        For each technique ID, return a list of matching Sigma rules.

        Returns:
            Dict mapping technique_id → list of rule dicts, e.g.:
            {
                "T1059.001": [
                    {
                        "title": "Suspicious PowerShell Download",
                        "logsource": "process_creation / windows",
                        "condition_summary": "CommandLine contains 'downloadstring'",
                        "level": "high",
                        "status": "stable",
                        "url": "https://github.com/SigmaHQ/sigma/blob/master/...",
                        "tags": ["attack.t1059.001", "attack.execution"],
                    },
                    ...
                ],
                "T1003.001": [...],
            }
        """
        results: dict[str, list[dict]] = {}
        unique_ids = list(dict.fromkeys(technique_ids))   # deduplicate, preserve order

        logger.info("Sigma: collecting rules for %d techniques", len(unique_ids))

        # GitHub code search API: 10 requests/minute secondary rate limit.
        # We enforce a minimum 6-second gap between API calls (10/min = 1 per 6s).
        # Cached results skip the delay entirely.
        SEARCH_DELAY = 6.5   # seconds between uncached requests

        for tid in unique_ids:
            cached = self._load_cache(tid)
            if cached is not None:
                if cached:   # non-empty cache
                    results[tid] = cached
                continue     # cached (even empty) = no API call needed

            rules = self._fetch_rules_for_technique(tid)
            self._save_cache(tid, rules)

            if rules:
                results[tid] = rules

            # Rate limit: wait between search requests
            time.sleep(SEARCH_DELAY)

        logger.info(
            "Sigma: found rules for %d/%d techniques",
            len(results), len(unique_ids),
        )
        return results

    # ------------------------------------------------------------------
    # GitHub API search
    # ------------------------------------------------------------------

    def _fetch_rules_for_technique(self, tid: str) -> list[dict]:
        """
        Search SigmaHQ for rules tagged with this technique ID.
        GitHub code search API: /search/code?q=attack.{tid}+repo:SigmaHQ/sigma
        """
        # Normalise: T1059.001 → attack.t1059.001
        tag = f"attack.{tid.lower()}"

        url = (
            f"{GITHUB_API}/search/code"
            f"?q={quote(tag)}+repo:{SIGMA_OWNER}/{SIGMA_REPO}"
            f"+extension:yml+path:{SIGMA_RULES_PATH}"
            f"&per_page=10"
        )

        try:
            data  = self._github_get(url)
            items = data.get("items", []) if isinstance(data, dict) else []
        except Exception as exc:
            logger.debug("Sigma GitHub search failed for %s: %s", tid, exc)
            return []

        rules: list[dict] = []
        for item in items[:MAX_RULES_PER_TECHNIQUE]:
            rule = self._fetch_and_parse_rule(item)
            if rule:
                rules.append(rule)

        return rules

    def _fetch_and_parse_rule(self, search_item: dict) -> dict | None:
        """Fetch raw rule YAML and parse key fields."""
        raw_url = search_item.get("url", "")   # GitHub API URL for file content
        html_url = search_item.get("html_url", "")

        if not raw_url:
            return None

        try:
            content_data = self._github_get(raw_url)
            # GitHub returns base64-encoded content
            import base64
            encoded = content_data.get("content", "")
            if not encoded:
                return None
            yaml_text = base64.b64decode(encoded.replace("\n", "")).decode("utf-8")
        except Exception as exc:
            logger.debug("Sigma rule fetch failed: %s", exc)
            return None

        return self._parse_sigma_yaml(yaml_text, html_url)

    # ------------------------------------------------------------------
    # YAML parser (no PyYAML dependency — targeted field extraction)
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_sigma_yaml(yaml_text: str, url: str) -> dict | None:
        """
        Extract key fields from Sigma rule YAML without a full YAML parser.
        We only need: title, status, level, logsource, detection, tags.
        """
        lines = yaml_text.splitlines()

        def _get_field(field: str) -> str:
            for line in lines:
                if line.startswith(f"{field}:"):
                    return line.split(":", 1)[1].strip().strip("'\"")
            return ""

        title  = _get_field("title")
        status = _get_field("status")
        level  = _get_field("level")

        if not title:
            return None

        # Extract logsource block
        logsource = _extract_logsource(lines)

        # Extract detection condition
        condition = _extract_condition(lines)

        # Extract ATT&CK tags
        tags = _extract_tags(lines)

        # Extract description (first non-empty line after "description:")
        description = _get_field("description")

        return {
            "title":             title,
            "status":            status,
            "level":             level,
            "logsource":         logsource,
            "condition_summary": _summarise_condition(condition),
            "description":       description[:200] if description else "",
            "tags":              tags,
            "url":               url,
        }

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _load_cache(self, tid: str) -> list[dict] | None:
        """Return cached rules, or None if cache is missing/stale."""
        cache_path = CACHE_DIR / f"{tid.replace('.', '_')}.json"
        if not cache_path.exists():
            return None

        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            cached_at = datetime.fromisoformat(data.get("cached_at", "2000-01-01"))
            age = datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc)
            if age > timedelta(days=CACHE_TTL_DAYS):
                logger.debug("Sigma cache stale for %s — refreshing", tid)
                return None
            return data.get("rules", [])
        except Exception:
            return None

    def _save_cache(self, tid: str, rules: list[dict]) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path = CACHE_DIR / f"{tid.replace('.', '_')}.json"
        cache_path.write_text(
            json.dumps({
                "technique_id": tid,
                "cached_at":    datetime.now(timezone.utc).isoformat(),
                "rules":        rules,
            }, indent=2),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # GitHub HTTP
    # ------------------------------------------------------------------

    def _github_get(self, url: str) -> Any:
        headers = {
            "Accept":           "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent":       "THEORY/1.0 threat-intel-research",
        }
        if self._token:
            # Try Bearer first (works for both classic and fine-grained PATs)
            headers["Authorization"] = f"Bearer {self._token}"

        req = Request(url, headers=headers)
        self._request_count += 1

        for attempt in range(1, RETRY_MAX + 1):
            try:
                with urlopen(req, timeout=TIMEOUT) as resp:
                    # Check rate limit headers
                    remaining = resp.headers.get("X-RateLimit-Remaining", "60")
                    if int(remaining) < 5:
                        logger.warning(
                            "GitHub API rate limit low (%s remaining) — "
                            "set GITHUB_TOKEN in .env for higher limits",
                            remaining,
                        )
                    return json.loads(resp.read().decode("utf-8"))
            except HTTPError as exc:
                if exc.code == 403:
                    logger.warning(
                        "GitHub API 403 — rate limited. "
                        "Set GITHUB_TOKEN in .env (free, 5000 req/hr vs 60)."
                    )
                    return {}
                if exc.code == 422:
                    # Search API returns 422 for some queries — treat as no results
                    return {}
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT * attempt)
                else:
                    raise
            except Exception:
                if attempt < RETRY_MAX:
                    time.sleep(RETRY_WAIT)
                else:
                    raise
        return {}

    @staticmethod
    def _load_token() -> str:
        token = os.environ.get("GITHUB_TOKEN", "").strip()
        if token:
            return token
        # Try .env file — handle BOM, Windows line endings, quoted values
        for env_path in (Path(".env"), Path("../.env")):
            if env_path.exists():
                try:
                    text = env_path.read_text(encoding="utf-8-sig")  # utf-8-sig strips BOM
                    for line in text.splitlines():
                        line = line.strip()
                        if line.startswith("GITHUB_TOKEN="):
                            val = line.split("=", 1)[1].strip().strip('"').strip("'")
                            if val:
                                return val
                except Exception:
                    pass
        return ""


# ---------------------------------------------------------------------------
# YAML field extraction utilities (no external dependencies)
# ---------------------------------------------------------------------------

def _extract_logsource(lines: list[str]) -> str:
    """Extract logsource as 'category / product' string."""
    in_block  = False
    category  = ""
    product   = ""
    service   = ""

    for line in lines:
        if line.startswith("logsource:"):
            in_block = True
            continue
        if in_block:
            if line and not line.startswith(" "):
                break
            stripped = line.strip()
            if stripped.startswith("category:"):
                category = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("product:"):
                product = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("service:"):
                service = stripped.split(":", 1)[1].strip()

    parts = [p for p in [category or service, product] if p]
    return " / ".join(parts) if parts else "unknown"


def _extract_condition(lines: list[str]) -> str:
    """Extract the condition field from the detection block."""
    in_detection = False
    for line in lines:
        if line.startswith("detection:"):
            in_detection = True
            continue
        if in_detection:
            if line and not line.startswith(" "):
                break
            stripped = line.strip()
            if stripped.startswith("condition:"):
                return stripped.split(":", 1)[1].strip()
    return ""


def _extract_tags(lines: list[str]) -> list[str]:
    """Extract the tags list."""
    in_tags = False
    tags: list[str] = []
    for line in lines:
        if line.startswith("tags:"):
            in_tags = True
            continue
        if in_tags:
            if line and not line.startswith(" ") and not line.startswith("-"):
                break
            stripped = line.strip()
            if stripped.startswith("- "):
                tags.append(stripped[2:].strip())
    return tags


def _summarise_condition(condition: str) -> str:
    """
    Convert Sigma condition syntax to plain English.
    E.g. "1 of selection*" → "any of selection filters"
         "all of them"      → "all filters match"
         "selection and not filter" → "selection and not filter"
    """
    if not condition:
        return ""
    c = condition.strip()
    # Common patterns → readable
    replacements = [
        (r"\b1 of selection\*?\b", "any selection filter matches"),
        (r"\ball of them\b",       "all filters must match"),
        (r"\b1 of them\b",        "any filter matches"),
        (r"\bselection\b",        "selection filter"),
        (r"\bfilter\b",           "exclusion filter"),
        (r"\band not\b",          "excluding"),
        (r"\| count\(\) > \d+",  "(threshold-based)"),
    ]
    result = c
    for pattern, replacement in replacements:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result.strip()
