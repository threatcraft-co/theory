"""
tests/test_vendor_intel_sitemap.py
-----------------------------------
Offline tests for the sitemap-based feed collection.

All tests use synthetic XML/HTML and monkeypatched network calls.
No live URLs, no fixture files.

Save this as tests/test_vendor_intel_sitemap.py in the theory repo.
"""

from __future__ import annotations

import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

from collectors.vendor_intel import (
    VendorIntelCollector,
    _extract_html_title,
    _extract_html_summary,
    SITEMAP_NS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_SITEMAP = b"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/blog/apt28-new-campaign</loc>
    <lastmod>2026-08-20</lastmod>
  </url>
  <url>
    <loc>https://example.com/products/enterprise</loc>
    <lastmod>2026-07-01</lastmod>
  </url>
  <url>
    <loc>https://example.com/blog/lazarus-analysis</loc>
    <lastmod>2026-08-15</lastmod>
  </url>
  <url>
    <loc>https://example.com/blog/malware-report</loc>
    <lastmod>2026-06-01</lastmod>
  </url>
</urlset>
"""

SAMPLE_INDEX = b"""<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap>
    <loc>https://example.com/sitemap-posts.xml</loc>
    <lastmod>2026-08-20</lastmod>
  </sitemap>
</sitemapindex>
"""

SAMPLE_ARTICLE = """<!DOCTYPE html>
<html>
<head>
  <title>APT28 New Campaign Targets EU Ministries</title>
  <meta name="description" content="Researchers observed APT28 running a new spearphishing campaign targeting European foreign ministries in August 2026.">
</head>
<body>
<article>
<p>In August 2026, we observed a new campaign targeting European foreign ministries attributed to APT28 (Fancy Bear).</p>
<p>The campaign used spearphishing emails with malicious Excel attachments delivering a variant of the X-Agent implant.</p>
</article>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Helpers to mock urlopen for the sitemap fetcher
# ---------------------------------------------------------------------------

class _MockResponse:
    def __init__(self, data):
        self._data = data if isinstance(data, bytes) else data.encode()
    def read(self, size=None):
        return self._data if size is None else self._data[:size]
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False


def _mock_urlopen_factory(responses: dict):
    """Return a mock urlopen that returns different bodies per URL."""
    def _urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        for pattern, body in responses.items():
            if pattern in url:
                return _MockResponse(body)
        raise ValueError(f"No mock response for {url}")
    return _urlopen


# ---------------------------------------------------------------------------
# Tests: HTML extraction helpers
# ---------------------------------------------------------------------------

class TestHtmlExtraction:

    def test_extract_title(self):
        title = _extract_html_title(SAMPLE_ARTICLE)
        assert title == "APT28 New Campaign Targets EU Ministries"

    def test_extract_title_none(self):
        assert _extract_html_title("<html><body>no title</body></html>") == ""

    def test_extract_summary_from_meta(self):
        summary = _extract_html_summary(SAMPLE_ARTICLE)
        assert "APT28" in summary
        assert "spearphishing" in summary

    def test_extract_summary_from_paragraphs(self):
        # No meta description — should fall back to paragraphs
        html = """<html><body>
        <p>This is the first paragraph about APT28 activity in the wild.</p>
        <p>The second paragraph continues with more analytical detail here.</p>
        </body></html>"""
        summary = _extract_html_summary(html)
        assert "APT28" in summary
        assert "second paragraph" in summary

    def test_summary_skips_short_paragraphs(self):
        # Very short <p> tags (nav items etc.) should be skipped
        html = """<html><body>
        <p>Home</p>
        <p>Contact</p>
        <p>This is a proper article paragraph with substantive content about threat actors.</p>
        </body></html>"""
        summary = _extract_html_summary(html)
        assert "Home" not in summary
        assert "substantive content" in summary


# ---------------------------------------------------------------------------
# Tests: sitemap URL extraction
# ---------------------------------------------------------------------------

class TestSitemapUrlExtraction:

    def test_parses_urlset(self, tmp_path):
        collector = VendorIntelCollector(feeds_path=tmp_path / "empty.yaml")
        mock_urlopen = _mock_urlopen_factory({
            "example.com/sitemap.xml": SAMPLE_SITEMAP,
        })
        with patch("collectors.vendor_intel.urlopen", mock_urlopen):
            urls = collector._extract_sitemap_urls(
                "https://example.com/sitemap.xml", url_pattern=""
            )
        assert len(urls) == 4

    def test_filters_by_url_pattern(self, tmp_path):
        collector = VendorIntelCollector(feeds_path=tmp_path / "empty.yaml")
        mock_urlopen = _mock_urlopen_factory({
            "example.com/sitemap.xml": SAMPLE_SITEMAP,
        })
        with patch("collectors.vendor_intel.urlopen", mock_urlopen):
            urls = collector._extract_sitemap_urls(
                "https://example.com/sitemap.xml", url_pattern="/blog/"
            )
        assert len(urls) == 3
        assert all("/blog/" in u["loc"] for u in urls)

    def test_follows_sitemap_index(self, tmp_path):
        collector = VendorIntelCollector(feeds_path=tmp_path / "empty.yaml")
        mock_urlopen = _mock_urlopen_factory({
            "sitemap.xml":       SAMPLE_INDEX,
            "sitemap-posts.xml": SAMPLE_SITEMAP,
        })
        with patch("collectors.vendor_intel.urlopen", mock_urlopen):
            urls = collector._extract_sitemap_urls(
                "https://example.com/sitemap.xml", url_pattern="/blog/"
            )
        assert len(urls) == 3

    def test_stops_recursion_at_depth_2(self, tmp_path):
        collector = VendorIntelCollector(feeds_path=tmp_path / "empty.yaml")
        # depth=2 should return empty regardless of content
        urls = collector._extract_sitemap_urls(
            "https://example.com/sitemap.xml", "", depth=2
        )
        assert urls == []


# ---------------------------------------------------------------------------
# Tests: sitemap fetch end-to-end
# ---------------------------------------------------------------------------

class TestSitemapFetch:

    def test_fetch_sitemap_returns_entries(self, tmp_path, monkeypatch):
        # Isolate the article cache dir
        cache_dir = tmp_path / "articles"
        monkeypatch.setattr(
            "collectors.vendor_intel.SITEMAP_CACHE_DIR", cache_dir
        )

        collector = VendorIntelCollector(feeds_path=tmp_path / "empty.yaml")
        mock_urlopen = _mock_urlopen_factory({
            "sitemap.xml":                      SAMPLE_SITEMAP,
            "/blog/apt28-new-campaign":         SAMPLE_ARTICLE,
            "/blog/lazarus-analysis":           SAMPLE_ARTICLE,
            "/blog/malware-report":             SAMPLE_ARTICLE,
        })

        with patch("collectors.vendor_intel.urlopen", mock_urlopen):
            entries = collector._fetch_sitemap({
                "name":     "Test Vendor",
                "sitemap":  "https://example.com/sitemap.xml",
                "url_pattern": "/blog/",
            })

        assert len(entries) == 3
        # Sorted by lastmod desc — apt28 (2026-08-20) should be first
        assert "apt28-new-campaign" in entries[0]["url"]
        # Each entry has title, url, date, summary
        for e in entries:
            assert e["title"]
            assert e["url"]
            assert e["date"]
            assert e["summary"]

    def test_fetch_sitemap_missing_url(self, tmp_path):
        collector = VendorIntelCollector(feeds_path=tmp_path / "empty.yaml")
        assert collector._fetch_sitemap({"name": "x"}) == []


# ---------------------------------------------------------------------------
# Tests: article cache
# ---------------------------------------------------------------------------

class TestArticleCache:

    def test_cache_roundtrip(self, tmp_path, monkeypatch):
        cache_dir = tmp_path / "articles"
        monkeypatch.setattr(
            "collectors.vendor_intel.SITEMAP_CACHE_DIR", cache_dir
        )
        collector = VendorIntelCollector(feeds_path=tmp_path / "empty.yaml")

        entry = {"title": "T", "url": "u", "date": "d", "summary": "s"}
        collector._save_article_cache("test_key", entry)
        loaded = collector._load_article_cache("test_key")
        assert loaded == entry

    def test_cache_expires(self, tmp_path, monkeypatch):
        cache_dir = tmp_path / "articles"
        cache_dir.mkdir()
        monkeypatch.setattr(
            "collectors.vendor_intel.SITEMAP_CACHE_DIR", cache_dir
        )
        collector = VendorIntelCollector(feeds_path=tmp_path / "empty.yaml")

        # Manually write an expired cache file
        old_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        path = cache_dir / "expired.json"
        path.write_text(json.dumps({
            "cached_at": old_time,
            "entry":     {"title": "old", "url": "u", "date": "d", "summary": "s"},
        }))
        loaded = collector._load_article_cache("expired")
        assert loaded is None


# ---------------------------------------------------------------------------
# Tests: dispatch by type
# ---------------------------------------------------------------------------

class TestFeedTypeDispatch:

    def test_rss_type_uses_fetch_rss(self, tmp_path, monkeypatch):
        collector = VendorIntelCollector(feeds_path=tmp_path / "empty.yaml")
        # Prevent cache reads
        monkeypatch.setattr(collector, "_load_cache", lambda k: None)
        monkeypatch.setattr(collector, "_save_cache", lambda k, e: None)

        called = {}
        def fake_rss(url, feed):
            called["rss"] = True
            return []
        def fake_sitemap(feed):
            called["sitemap"] = True
            return []
        monkeypatch.setattr(collector, "_fetch_rss", fake_rss)
        monkeypatch.setattr(collector, "_fetch_sitemap", fake_sitemap)

        collector._fetch_feed_cached({"name": "X", "rss": "u", "type": "rss"})
        assert "rss" in called
        assert "sitemap" not in called

    def test_sitemap_type_uses_fetch_sitemap(self, tmp_path, monkeypatch):
        collector = VendorIntelCollector(feeds_path=tmp_path / "empty.yaml")
        monkeypatch.setattr(collector, "_load_cache", lambda k: None)
        monkeypatch.setattr(collector, "_save_cache", lambda k, e: None)

        called = {}
        def fake_rss(url, feed):
            called["rss"] = True
            return []
        def fake_sitemap(feed):
            called["sitemap"] = True
            return []
        monkeypatch.setattr(collector, "_fetch_rss", fake_rss)
        monkeypatch.setattr(collector, "_fetch_sitemap", fake_sitemap)

        collector._fetch_feed_cached({
            "name": "X", "sitemap": "u", "type": "sitemap"
        })
        assert "sitemap" in called
        assert "rss" not in called

    def test_default_type_is_rss(self, tmp_path, monkeypatch):
        collector = VendorIntelCollector(feeds_path=tmp_path / "empty.yaml")
        monkeypatch.setattr(collector, "_load_cache", lambda k: None)
        monkeypatch.setattr(collector, "_save_cache", lambda k, e: None)

        called = {}
        monkeypatch.setattr(collector, "_fetch_rss",
                            lambda u, f: called.setdefault("rss", True) or [])
        monkeypatch.setattr(collector, "_fetch_sitemap",
                            lambda f: called.setdefault("sitemap", True) or [])

        # No "type" field — should default to RSS
        collector._fetch_feed_cached({"name": "X", "rss": "u"})
        assert "rss" in called
