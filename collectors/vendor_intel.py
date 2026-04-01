"""
collectors/vendor_intel.py
---------------------------
Fetches and filters vendor threat intelligence articles for a specific actor.

Pipeline:
  1. Load feed registry from config/feeds.yaml
  2. Fetch RSS/blog entries newer than THEORY_INTEL_LOOKBACK days
  3. Filter articles that mention the actor or any of its aliases
  4. Score relevance (0-100): primary subject vs. brief mention
  5. Return ranked list of articles for the synthesis engine

Relevance scoring:
  90-100  Actor is the primary subject (name in title + multiple body mentions)
  60-89   Actor is a major subject (name in title OR multiple body mentions)
  30-59   Actor is mentioned in context (1-2 body mentions)
  0-29    Tangential mention

Cache: .cache/vendor_intel/{feed_slug}/{date}.json, TTL 6 hours
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

CACHE_DIR     = Path(".cache/vendor_intel")
CACHE_TTL_HRS = 6
TIMEOUT       = 12
MAX_ARTICLES  = 5    # max articles per feed per actor
DEFAULT_LOOKBACK_DAYS = 365   # 12 months default

# Minimum relevance score to include in dossier
MIN_RELEVANCE = 30


class VendorIntelCollector:
    """
    Fetches threat intelligence articles from curated vendor feeds
    and scores their relevance to a specific actor.
    """

    def __init__(self, feeds_path: Path | None = None):
        self._feeds_path = feeds_path or Path("config/feeds.yaml")
        self._feeds:      list[dict] = []
        self._load_feeds()

    def collect(
        self,
        actor_name:  str,
        aliases:     list[str],
        lookback_days: int = DEFAULT_LOOKBACK_DAYS,
    ) -> list[dict]:
        """
        Fetch and score articles relevant to this actor.

        Returns:
            List of article dicts sorted by relevance desc, each containing:
            {title, url, source, date, relevance, summary, body_snippet}
        """
        if not self._feeds:
            logger.warning("No feeds loaded — check config/feeds.yaml")
            return []

        # Build search terms: canonical name + clean aliases
        search_terms = self._build_search_terms(actor_name, aliases)
        cutoff       = datetime.now(timezone.utc) - timedelta(days=lookback_days)

        all_articles: list[dict] = []

        for feed in self._feeds:
            if not feed.get("enabled", True):
                continue
            try:
                articles = self._fetch_feed(feed, search_terms, cutoff)
                all_articles.extend(articles)
            except Exception as exc:
                logger.debug("Feed %r failed: %s", feed.get("name"), exc)

        # Deduplicate by URL
        seen_urls: set[str] = set()
        unique: list[dict] = []
        for a in all_articles:
            if a["url"] not in seen_urls:
                seen_urls.add(a["url"])
                unique.append(a)

        # Sort by relevance desc, then date desc
        unique.sort(key=lambda a: (-a["relevance"], a["date"]), reverse=False)
        unique.sort(key=lambda a: -a["relevance"])

        logger.info(
            "VendorIntel: %d articles found across %d feeds for %r",
            len(unique), len(self._feeds), actor_name,
        )
        return unique

    # ------------------------------------------------------------------
    # Feed loading
    # ------------------------------------------------------------------

    def _load_feeds(self) -> None:
        if not self._feeds_path.exists():
            logger.warning("feeds.yaml not found at %s", self._feeds_path)
            return
        try:
            # Pure stdlib YAML parsing for simple key:value structure
            # We avoid PyYAML dependency — feeds.yaml uses simple format
            self._feeds = _parse_simple_yaml_feeds(self._feeds_path)
            # Add user custom feeds
            custom = _parse_custom_feeds(self._feeds_path)
            self._feeds.extend(custom)
            logger.info("VendorIntel: loaded %d feeds", len(self._feeds))
        except Exception as exc:
            logger.error("Failed to load feeds.yaml: %s", exc)

    # ------------------------------------------------------------------
    # Per-feed fetching
    # ------------------------------------------------------------------

    def _fetch_feed(
        self,
        feed:         dict,
        search_terms: set[str],
        cutoff:       datetime,
    ) -> list[dict]:
        """Fetch RSS feed and return articles matching search terms."""
        rss_url = feed.get("rss") or feed.get("url", "")
        if not rss_url:
            return []

        cache_key = _slugify(feed.get("name", rss_url))
        cached    = self._load_cache(cache_key)

        if cached is None:
            try:
                raw = self._fetch_rss(rss_url, feed)
                self._save_cache(cache_key, raw)
            except Exception as exc:
                logger.debug("RSS fetch failed for %r: %s", feed.get("name"), exc)
                return []
        else:
            raw = cached

        articles: list[dict] = []
        for entry in (raw or []):
            pub_date = _parse_date(entry.get("date", ""))
            if pub_date and pub_date < cutoff:
                continue

            title   = entry.get("title", "")
            summary = entry.get("summary", "")
            url     = entry.get("url", "")

            relevance = self._score_relevance(
                title, summary, search_terms, feed.get("apt_focus", False)
            )

            if relevance >= MIN_RELEVANCE:
                articles.append({
                    "title":        title,
                    "url":          url,
                    "source":       feed.get("name", ""),
                    "source_tier":  feed.get("tier", 3),
                    "date":         entry.get("date", ""),
                    "relevance":    relevance,
                    "summary":      summary[:500] if summary else "",
                    "tags":         feed.get("tags", []),
                })

        # Return top N articles from this feed
        articles.sort(key=lambda a: -a["relevance"])
        return articles[:MAX_ARTICLES]

    def _fetch_rss(self, url: str, feed: dict) -> list[dict]:
        """Fetch and parse an RSS/Atom feed. Returns list of entry dicts."""
        headers = {
            "User-Agent": "THEORY/1.0 threat-intel-research",
            "Accept":     "application/rss+xml, application/atom+xml, text/xml, */*",
        }

        # Load session cookie if configured
        feed_slug   = _slugify(feed.get("name", url)).upper()
        cookie_key  = f"FEED_COOKIE_{feed_slug}"
        cookie_val  = os.environ.get(cookie_key, "")
        if not cookie_val:
            # Try .env file
            env_path = Path(".env")
            if env_path.exists():
                for line in env_path.read_text().splitlines():
                    if line.startswith(f"{cookie_key}="):
                        cookie_val = line.split("=", 1)[1].strip().strip('"\'')
        if cookie_val:
            headers["Cookie"] = cookie_val

        req = Request(url, headers=headers)
        with urlopen(req, timeout=TIMEOUT) as resp:
            content = resp.read().decode("utf-8", errors="replace")

        return _parse_rss_xml(content)

    # ------------------------------------------------------------------
    # Relevance scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _score_relevance(
        title:        str,
        body:         str,
        search_terms: set[str],
        apt_focus:    bool,
    ) -> int:
        """
        Score 0-100 how relevant this article is to the actor.

        Factors:
          - Actor name/alias in title (high weight)
          - Frequency of mentions in body (medium weight)
          - Source is APT-focused (small bonus)
        """
        title_lower = title.lower()
        body_lower  = body.lower()

        title_hits = sum(1 for t in search_terms if t in title_lower)
        body_hits  = sum(
            body_lower.count(t) for t in search_terms
        )

        score = 0

        # Title match is strong signal
        if title_hits >= 2:
            score += 50
        elif title_hits == 1:
            score += 35

        # Body frequency
        if body_hits >= 5:
            score += 35
        elif body_hits >= 3:
            score += 25
        elif body_hits >= 1:
            score += 15

        # APT-focused source bonus
        if apt_focus and (title_hits > 0 or body_hits > 0):
            score += 10

        return min(score, 100)

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _load_cache(self, cache_key: str) -> list[dict] | None:
        path = CACHE_DIR / f"{cache_key}.json"
        if not path.exists():
            return None
        try:
            data      = json.loads(path.read_text(encoding="utf-8"))
            cached_at = datetime.fromisoformat(data.get("cached_at", "2000-01-01"))
            age       = datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc)
            if age > timedelta(hours=CACHE_TTL_HRS):
                return None
            return data.get("entries", [])
        except Exception:
            return None

    def _save_cache(self, cache_key: str, entries: list[dict]) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = CACHE_DIR / f"{cache_key}.json"
        path.write_text(
            json.dumps({
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "entries":   entries,
            }, indent=2),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _build_search_terms(actor_name: str, aliases: list[str]) -> set[str]:
        """Build lowercase search term set from actor name + aliases."""
        terms: set[str] = {actor_name.lower()}
        for alias in aliases:
            clean = alias.strip().lower()
            # Skip very short or generic aliases (G0007, TA422, etc.)
            if len(clean) > 4 and not re.match(r"^[gtu][a-z]?\d+$", clean):
                terms.add(clean)
        return terms



def _is_id_alias(alias: str) -> bool:
    """Return True for short ID-style aliases like g0007, ta422, unc123."""
    return bool(re.match(r'^[a-z]{1,3}[0-9]+$', alias.lower()))

# ---------------------------------------------------------------------------
# RSS/Atom parser (no external dependencies)
# ---------------------------------------------------------------------------

def _parse_rss_xml(content: str) -> list[dict]:
    """Parse RSS 2.0 or Atom feed XML into list of entry dicts."""
    entries: list[dict] = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        logger.debug("RSS XML parse error: %s", exc)
        return entries

    ns = {
        "atom":    "http://www.w3.org/2005/Atom",
        "content": "http://purl.org/rss/1.0/modules/content/",
        "dc":      "http://purl.org/dc/elements/1.1/",
    }

    # RSS 2.0
    for item in root.findall(".//item"):
        title   = _xml_text(item, "title")
        url     = _xml_text(item, "link") or _xml_text(item, "guid")
        date    = _xml_text(item, "pubDate") or _xml_text(item, "dc:date", ns)
        summary = (
            _xml_text(item, "description") or
            _xml_text(item, "content:encoded", ns) or ""
        )
        if title or url:
            entries.append({
                "title":   _strip_html(title),
                "url":     url or "",
                "date":    _normalise_date(date),
                "summary": _strip_html(summary[:1000]),
            })

    # Atom
    for entry in root.findall("atom:entry", ns):
        title   = _xml_text(entry, "atom:title", ns)
        link    = entry.find("atom:link", ns)
        url     = link.get("href", "") if link is not None else ""
        date    = _xml_text(entry, "atom:published", ns) or _xml_text(entry, "atom:updated", ns)
        summary = _xml_text(entry, "atom:summary", ns) or _xml_text(entry, "atom:content", ns) or ""
        if title or url:
            entries.append({
                "title":   _strip_html(title),
                "url":     url,
                "date":    _normalise_date(date),
                "summary": _strip_html(summary[:1000]),
            })

    return entries


def _xml_text(elem: ET.Element, tag: str, ns: dict | None = None) -> str:
    child = elem.find(tag, ns or {})
    if child is None:
        return ""
    return "".join(child.itertext()).strip()


def _strip_html(text: str) -> str:
    """Remove HTML tags from text."""
    if not text:
        return ""
    clean = re.sub(r"<[^>]+>", " ", text)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean


def _normalise_date(date_str: str) -> str:
    """Convert various date formats to ISO 8601 date string."""
    if not date_str:
        return ""
    try:
        # RFC 2822 (RSS pubDate)
        dt = parsedate_to_datetime(date_str)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        pass
    try:
        # ISO 8601
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except Exception:
        pass
    # Try extracting YYYY-MM-DD
    m = re.search(r"(\d{4}-\d{2}-\d{2})", date_str)
    return m.group(1) if m else date_str[:10]


def _parse_date(date_str: str) -> datetime | None:
    """Parse a date string to a timezone-aware datetime."""
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Minimal YAML parser (no PyYAML dependency)
# ---------------------------------------------------------------------------

def _parse_simple_yaml_feeds(path: Path) -> list[dict]:
    """
    Parse feeds.yaml sources list without PyYAML.
    Handles the specific structure of our feeds.yaml.
    Falls back to PyYAML if available.
    """
    try:
        import yaml  # type: ignore
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("sources", []) or []
    except ImportError:
        pass

    # Manual parser for our specific YAML structure
    feeds: list[dict] = []
    current: dict | None = None
    in_sources = False

    with open(path, encoding="utf-8") as f:
        for line in f:
            stripped = line.rstrip()

            if stripped.strip() == "sources:":
                in_sources = True
                continue

            if stripped.strip() in ("custom: []", "custom:"):
                in_sources = False
                continue

            if not in_sources:
                continue

            # New feed entry
            if stripped.startswith("  - name:"):
                if current:
                    feeds.append(current)
                current = {"name": stripped.split(":", 1)[1].strip()}

            elif current is not None and stripped.startswith("    "):
                key_val = stripped.strip()
                if ":" in key_val:
                    key, _, val = key_val.partition(":")
                    key = key.strip()
                    val = val.strip()
                    if val.lower() == "true":
                        current[key] = True
                    elif val.lower() == "false":
                        current[key] = False
                    elif val.startswith("[") and val.endswith("]"):
                        # Inline list
                        items = [
                            i.strip().strip("'\"")
                            for i in val[1:-1].split(",")
                            if i.strip()
                        ]
                        current[key] = items
                    else:
                        current[key] = val.strip("'\"")

    if current:
        feeds.append(current)

    return feeds


def _parse_custom_feeds(path: Path) -> list[dict]:
    """Parse the custom: section of feeds.yaml."""
    try:
        import yaml  # type: ignore
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("custom", []) or []
    except Exception:
        return []


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "_", name.lower())[:60]