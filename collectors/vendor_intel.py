"""
collectors/vendor_intel.py
---------------------------
Fetches and filters vendor threat intelligence articles for a specific actor.

Pipeline:
  1. Load feed registry from config/feeds.yaml
  2. Fetch RSS/blog entries newer than THEORY_INTEL_LOOKBACK days
     — feeds are fetched concurrently via ThreadPoolExecutor (no new deps)
  3. Filter articles that mention the actor or any of its aliases
  4. Score relevance (0-100): primary subject vs. brief mention
  5. Return ranked list of articles for the synthesis engine

Relevance scoring:
  90-100  Actor is the primary subject (name in title + multiple body mentions)
  60-89   Actor is a major subject (name in title OR multiple body mentions)
  30-59   Actor is mentioned in context (1-2 body mentions)
  0-29    Tangential mention

Cache: .cache/vendor_intel/{feed_slug}.json, TTL 24 hours per feed
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

CACHE_DIR          = Path(".cache/vendor_intel")
CACHE_TTL_HRS      = 24    # raised from 6 — feeds don't change that fast
TIMEOUT            = 15    # per-feed connect+read timeout (seconds)
MAX_ARTICLES       = 8     # max articles returned per feed per actor
MAX_WORKERS        = 12    # concurrent feed fetches
DEFAULT_LOOKBACK_DAYS = 365

# Minimum relevance score to include in dossier
MIN_RELEVANCE = 15

# Max summary chars stored in cache and scored against
# (was 1000 in parse → 500 at score — both fixed to 2000)
SUMMARY_CACHE_CHARS = 2000
SUMMARY_SCORE_CHARS = 2000   # score against same full content

# Path to the CyberMonitor APT campaign collection (cloned by --update-bundles)
APT_CAMPAIGNS_PATH = Path(".cache/apt-campaigns")


class VendorIntelCollector:
    """
    Fetches threat intelligence articles from curated vendor feeds
    and scores their relevance to a specific actor.

    All feeds are fetched concurrently (ThreadPoolExecutor) so wall time
    is bounded by the slowest responding feed rather than sum of all timeouts.
    """

    def __init__(self, feeds_path: Path | None = None):
        self._feeds_path = feeds_path or Path("config/feeds.yaml")
        self._feeds: list[dict] = []
        self._load_feeds()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect(
        self,
        actor_name:    str,
        aliases:       list[str],
        lookback_days: int = DEFAULT_LOOKBACK_DAYS,
    ) -> list[dict]:
        """
        Fetch and score articles relevant to this actor.

        Feeds are fetched in parallel (up to MAX_WORKERS concurrent).

        Returns:
            List of article dicts sorted by relevance desc, each containing:
            {title, url, source, date, relevance, summary, tags}
        """
        if not self._feeds:
            logger.warning("No feeds loaded — check config/feeds.yaml")
            return []

        search_terms = self._build_search_terms(actor_name, aliases)
        cutoff       = datetime.now(timezone.utc) - timedelta(days=lookback_days)

        enabled_feeds = [f for f in self._feeds if f.get("enabled", True)]

        logger.info(
            "VendorIntel: fetching %d feeds concurrently (max_workers=%d) for %r",
            len(enabled_feeds), MAX_WORKERS, actor_name,
        )

        # --- Concurrent fetch ---
        feed_results: dict[str, list[dict]] = {}   # feed_name → raw entries
        feed_errors:  dict[str, str]        = {}   # feed_name → error msg
        feed_hit_counts: dict[str, int]     = {}   # feed_name → matched articles

        # Use a wrapper so the method is resolved at call time (not submit time).
        # This allows monkeypatch to replace _fetch_feed_cached in tests.
        def _fetch(feed: dict) -> list[dict]:
            return self._fetch_feed_cached(feed)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_feed = {
                executor.submit(_fetch, feed): feed
                for feed in enabled_feeds
            }
            for future in as_completed(future_to_feed):
                feed = future_to_feed[future]
                name = feed.get("name", feed.get("rss", "?"))
                try:
                    entries = future.result()
                    feed_results[name] = entries
                except Exception as exc:
                    feed_errors[name] = str(exc)
                    logger.debug("Feed %r failed: %s", name, exc)

        # --- Filter and score ---
        all_articles: list[dict] = []

        for feed in enabled_feeds:
            name    = feed.get("name", feed.get("rss", "?"))
            entries = feed_results.get(name)
            if entries is None:
                # failed — already logged at debug
                feed_hit_counts[name] = -1   # sentinel for "error"
                continue

            articles = self._filter_and_score(feed, entries, search_terms, cutoff)
            feed_hit_counts[name] = len(articles)
            all_articles.extend(articles)

        # --- Feed health summary (visible at INFO / --verbose) ---
        self._log_feed_health(feed_hit_counts, feed_errors)

        # Deduplicate by URL
        seen_urls: set[str] = set()
        unique: list[dict] = []
        for a in all_articles:
            if a["url"] not in seen_urls:
                seen_urls.add(a["url"])
                unique.append(a)

        # Sort by relevance desc, then date desc
        unique.sort(key=lambda a: (-a["relevance"], a.get("date", "") or ""), reverse=False)
        unique.sort(key=lambda a: -a["relevance"])

        logger.info(
            "VendorIntel: %d relevant articles from %d feeds for %r",
            len(unique), len(enabled_feeds), actor_name,
        )

        # Augment with historical APT campaign context (local, no rate limits)
        apt_articles = self._load_apt_campaign_context(actor_name, aliases)
        for art in apt_articles:
            art.setdefault("relevance", 50)
        unique = unique + apt_articles

        return unique

    # ------------------------------------------------------------------
    # Feed loading
    # ------------------------------------------------------------------

    def _load_feeds(self) -> None:
        if not self._feeds_path.exists():
            logger.warning("feeds.yaml not found at %s", self._feeds_path)
            return
        try:
            self._feeds = _parse_simple_yaml_feeds(self._feeds_path)
            custom = _parse_custom_feeds(self._feeds_path)
            self._feeds.extend(custom)
            logger.info("VendorIntel: loaded %d feeds", len(self._feeds))
        except Exception as exc:
            logger.error("Failed to load feeds.yaml: %s", exc)

    # ------------------------------------------------------------------
    # Per-feed fetch (cache-aware, called from thread pool)
    # ------------------------------------------------------------------

    def _fetch_feed_cached(self, feed: dict) -> list[dict]:
        """
        Return cached entries if fresh, otherwise fetch and cache.
        Raises on network/parse errors (caller catches and records as error).
        """
        cache_key = _slugify(feed.get("name", feed.get("rss", "")))
        cached    = self._load_cache(cache_key)
        if cached is not None:
            return cached

        entries = self._fetch_rss(feed.get("rss") or feed.get("url", ""), feed)
        self._save_cache(cache_key, entries)
        return entries

    def _filter_and_score(
        self,
        feed:         dict,
        entries:      list[dict],
        search_terms: set[str],
        cutoff:       datetime,
    ) -> list[dict]:
        """Filter entries by date and relevance, return top MAX_ARTICLES."""
        articles: list[dict] = []
        for entry in (entries or []):
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
                    "title":       title,
                    "url":         url,
                    "source":      feed.get("name", ""),
                    "source_tier": feed.get("tier", 3),
                    "date":        entry.get("date", ""),
                    "relevance":   relevance,
                    "summary":     summary[:SUMMARY_SCORE_CHARS] if summary else "",
                    "tags":        feed.get("tags", []),
                })

        articles.sort(key=lambda a: -a["relevance"])
        return articles[:MAX_ARTICLES]

    def _fetch_rss(self, url: str, feed: dict) -> list[dict]:
        """Fetch and parse an RSS/Atom feed. Raises on error."""
        if not url:
            return []

        headers = {
            "User-Agent": "THEORY/1.0 threat-intel-research",
            "Accept":     "application/rss+xml, application/atom+xml, text/xml, */*",
        }

        # Load session cookie if configured
        feed_slug  = _slugify(feed.get("name", url)).upper()
        cookie_key = f"FEED_COOKIE_{feed_slug}"
        cookie_val = os.environ.get(cookie_key, "")
        if not cookie_val:
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
          - APT-focused source (small bonus when there is any hit)

        Body is scored against full SUMMARY_SCORE_CHARS, not a 500-char
        truncation — this was a primary cause of low/zero scores.
        """
        title_lower = title.lower()
        body_lower  = body.lower()[:SUMMARY_SCORE_CHARS]

        title_hits = sum(1 for t in search_terms if t in title_lower)
        body_hits  = sum(body_lower.count(t) for t in search_terms)

        score = 0

        # Title match is the strongest signal
        if title_hits >= 2:
            score += 55
        elif title_hits == 1:
            score += 40

        # Body frequency
        if body_hits >= 5:
            score += 35
        elif body_hits >= 3:
            score += 25
        elif body_hits >= 2:
            score += 18
        elif body_hits >= 1:
            score += 10

        # APT-focused source bonus (only when there's a real hit)
        if apt_focus and (title_hits > 0 or body_hits > 0):
            score += 10

        return min(score, 100)

    # ------------------------------------------------------------------
    # Feed health reporting
    # ------------------------------------------------------------------

    @staticmethod
    def _log_feed_health(
        hit_counts: dict[str, int],
        errors:     dict[str, str],
    ) -> None:
        """
        Log a feed health summary. Visible at INFO level (--verbose).
        Groups feeds into: returned hits / returned 0 hits / errored.
        """
        hits    = {n: c for n, c in hit_counts.items() if c > 0}
        zeroes  = {n: c for n, c in hit_counts.items() if c == 0}
        errored = {n: c for n, c in hit_counts.items() if c < 0}

        total_feeds   = len(hit_counts)
        total_errors  = len(errors)
        total_hits    = sum(hits.values())

        logger.info(
            "Feed health: %d/%d feeds returned data, %d produced hits (%d articles total), "
            "%d failed",
            total_feeds - total_errors, total_feeds,
            len(hits), total_hits,
            total_errors,
        )

        # Per-feed breakdown at DEBUG
        for name, count in sorted(hits.items(), key=lambda x: -x[1]):
            logger.debug("  ✓ %-45s  %d relevant article(s)", name, count)
        for name in sorted(zeroes):
            logger.debug("  · %-45s  0 relevant articles", name)
        for name, err in sorted(errors.items()):
            logger.debug("  ✗ %-45s  ERROR: %s", name, err[:80])

    # ------------------------------------------------------------------
    # APT Campaign Collection (local, offline)
    # ------------------------------------------------------------------

    def _load_apt_campaign_context(
        self, actor_name: str, aliases: list[str]
    ) -> list[dict]:
        """
        Search the local CyberMonitor APT Campaign Collection for reports
        matching this actor. Returns article-like dicts compatible with the
        vendor intel pipeline.
        """
        if not APT_CAMPAIGNS_PATH.exists():
            logger.debug("APT campaign collection not present — run --update-bundles to clone")
            return []

        results: list[dict] = []
        search_terms = [actor_name.lower()] + [a.lower() for a in aliases if len(a) > 4]

        try:
            for entry in APT_CAMPAIGNS_PATH.iterdir():
                if not entry.is_dir():
                    continue
                folder_lower = entry.name.lower()
                if not any(term in folder_lower for term in search_terms):
                    continue

                for report_file in sorted(entry.rglob("*.md"))[:10]:
                    try:
                        text  = report_file.read_text(encoding="utf-8", errors="replace")
                        title = report_file.stem.replace("_", " ").replace("-", " ")
                        for line in text.splitlines()[:5]:
                            if line.startswith("#"):
                                title = line.lstrip("#").strip()
                                break
                        summary = text[:800].strip()
                        results.append({
                            "title":   title,
                            "url": (
                                "https://github.com/CyberMonitor/"
                                "APT_CyberCriminal_Campagin_Collections"
                                f"/blob/master/{entry.name}/{report_file.name}"
                            ),
                            "source":  "CyberMonitor APT Collection",
                            "content": summary,
                            "date":    "",
                        })
                    except OSError:
                        continue
        except Exception as exc:
            logger.debug("APT campaign collection search error: %s", exc)

        if results:
            logger.info(
                "APT campaign collection: %d historical reports for %r",
                len(results), actor_name,
            )
        return results

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
            # Skip very short or ID-style aliases (G0007, TA422, etc.)
            if len(clean) > 4 and not re.match(r"^[gtu][a-z]?\d+$", clean):
                terms.add(clean)
        return terms


# ---------------------------------------------------------------------------
# Helpers (module-level, used by VendorIntelCollector)
# ---------------------------------------------------------------------------

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
        # Prefer content:encoded (fuller body) over description (snippet)
        summary = (
            _xml_text(item, "content:encoded", ns) or
            _xml_text(item, "description") or ""
        )
        if title or url:
            entries.append({
                "title":   _strip_html(title),
                "url":     url or "",
                "date":    _normalise_date(date),
                # Store up to SUMMARY_CACHE_CHARS — don't truncate early
                "summary": _strip_html(summary[:SUMMARY_CACHE_CHARS]),
            })

    # Atom
    for entry in root.findall("atom:entry", ns):
        title   = _xml_text(entry, "atom:title", ns)
        link    = entry.find("atom:link", ns)
        url     = link.get("href", "") if link is not None else ""
        date    = (
            _xml_text(entry, "atom:published", ns) or
            _xml_text(entry, "atom:updated", ns)
        )
        summary = (
            _xml_text(entry, "atom:content", ns) or
            _xml_text(entry, "atom:summary", ns) or ""
        )
        if title or url:
            entries.append({
                "title":   _strip_html(title),
                "url":     url,
                "date":    _normalise_date(date),
                "summary": _strip_html(summary[:SUMMARY_CACHE_CHARS]),
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
        dt = parsedate_to_datetime(date_str)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        pass
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except Exception:
        pass
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
