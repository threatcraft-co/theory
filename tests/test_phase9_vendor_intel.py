"""
tests/test_phase9_vendor_intel.py
----------------------------------
Unit tests for Phase 9 vendor intelligence layer — fully offline.
Tests cover RSS parsing, relevance scoring, provider loading,
cache logic, concurrent fetching, and synthesis prompt construction.
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch
from collectors.vendor_intel import (
    VendorIntelCollector,
    _parse_rss_xml,
    _strip_html,
    _normalise_date,
    _slugify,
    CACHE_TTL_HRS,
    MAX_WORKERS,
    SUMMARY_CACHE_CHARS,
    SUMMARY_SCORE_CHARS,
)
from collectors.intelligence_synthesizer import (
    IntelligenceSynthesizer,
    ClaudeProvider,
    OpenAIProvider,
    OllamaProvider,
    _article_hash,
    ACTOR_SYNTHESIS_PROMPT,
    LANDSCAPE_SYNTHESIS_PROMPT,
)


# ---------------------------------------------------------------------------
# RSS parser tests
# ---------------------------------------------------------------------------

SAMPLE_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <item>
      <title>APT28 Targets European Governments</title>
      <link>https://example.com/apt28-europe</link>
      <pubDate>Mon, 15 Jan 2024 10:00:00 +0000</pubDate>
      <description>Russian APT28 has been observed targeting government entities across Europe using spearphishing campaigns.</description>
    </item>
    <item>
      <title>New Malware Campaign Detected</title>
      <link>https://example.com/malware-campaign</link>
      <pubDate>Fri, 05 Jan 2024 08:00:00 +0000</pubDate>
      <description>A new malware campaign has been detected targeting financial institutions.</description>
    </item>
  </channel>
</rss>"""

SAMPLE_ATOM = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Test Atom Feed</title>
  <entry>
    <title>Fancy Bear Returns with New Implant</title>
    <link href="https://example.com/fancy-bear-new-implant"/>
    <published>2024-02-01T12:00:00Z</published>
    <summary>The Fancy Bear group, also known as APT28, has deployed a new implant targeting NATO allies.</summary>
  </entry>
</feed>"""

SAMPLE_RSS_CONTENT_ENCODED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <item>
      <title>APT28 Deep Dive</title>
      <link>https://example.com/apt28-deep</link>
      <pubDate>Mon, 15 Jan 2024 10:00:00 +0000</pubDate>
      <description>Short snippet only.</description>
      <content:encoded>APT28, also known as Fancy Bear, has conducted extensive campaigns. APT28 leverages spearphishing. APT28 targets government entities. APT28 uses custom implants. The Fancy Bear group continues to evolve.</content:encoded>
    </item>
  </channel>
</rss>"""


class TestRssParser:

    def test_rss_entries_parsed(self):
        entries = _parse_rss_xml(SAMPLE_RSS)
        assert len(entries) == 2

    def test_rss_title_extracted(self):
        entries = _parse_rss_xml(SAMPLE_RSS)
        assert entries[0]["title"] == "APT28 Targets European Governments"

    def test_rss_url_extracted(self):
        entries = _parse_rss_xml(SAMPLE_RSS)
        assert entries[0]["url"] == "https://example.com/apt28-europe"

    def test_rss_date_normalised(self):
        entries = _parse_rss_xml(SAMPLE_RSS)
        assert entries[0]["date"] == "2024-01-15"

    def test_rss_summary_extracted(self):
        entries = _parse_rss_xml(SAMPLE_RSS)
        assert "APT28" in entries[0]["summary"]

    def test_atom_entries_parsed(self):
        entries = _parse_rss_xml(SAMPLE_ATOM)
        assert len(entries) == 1

    def test_atom_title_extracted(self):
        entries = _parse_rss_xml(SAMPLE_ATOM)
        assert "Fancy Bear" in entries[0]["title"]

    def test_atom_url_extracted(self):
        entries = _parse_rss_xml(SAMPLE_ATOM)
        assert entries[0]["url"] == "https://example.com/fancy-bear-new-implant"

    def test_atom_date_normalised(self):
        entries = _parse_rss_xml(SAMPLE_ATOM)
        assert entries[0]["date"] == "2024-02-01"

    def test_invalid_xml_returns_empty(self):
        entries = _parse_rss_xml("not xml at all")
        assert entries == []

    def test_html_stripped_from_summary(self):
        rss = SAMPLE_RSS.replace(
            "Russian APT28",
            "<b>Russian</b> <a href='x'>APT28</a>"
        )
        entries = _parse_rss_xml(rss)
        assert "<b>" not in entries[0]["summary"]
        assert "Russian" in entries[0]["summary"]

    def test_content_encoded_preferred_over_description(self):
        """content:encoded has more body text and should be used when present."""
        entries = _parse_rss_xml(SAMPLE_RSS_CONTENT_ENCODED)
        assert len(entries) == 1
        # content:encoded has "Fancy Bear" — description doesn't
        assert "Fancy Bear" in entries[0]["summary"]

    def test_summary_not_double_truncated(self):
        """Summary stored in cache should be SUMMARY_CACHE_CHARS, not 500."""
        long_body = "APT28 " * 400   # ~2400 chars
        rss = f"""<?xml version="1.0"?>
<rss version="2.0"><channel><item>
  <title>Test</title>
  <link>https://example.com/test</link>
  <pubDate>Mon, 15 Jan 2024 10:00:00 +0000</pubDate>
  <description>{long_body}</description>
</item></channel></rss>"""
        entries = _parse_rss_xml(rss)
        # Should store up to SUMMARY_CACHE_CHARS, not 500
        assert len(entries[0]["summary"]) >= 500


# ---------------------------------------------------------------------------
# Relevance scoring tests
# ---------------------------------------------------------------------------

class TestRelevanceScoring:

    def test_actor_in_title_scores_high(self):
        score = VendorIntelCollector._score_relevance(
            title        = "APT28 Deploys New Backdoor in European Campaign",
            body         = "The group APT28, also known as Fancy Bear, has been observed...",
            search_terms = {"apt28", "fancy bear"},
            apt_focus    = True,
        )
        assert score >= 60

    def test_actor_not_mentioned_scores_zero(self):
        score = VendorIntelCollector._score_relevance(
            title        = "Ransomware Group Targets Healthcare",
            body         = "A new ransomware group has been targeting hospitals.",
            search_terms = {"apt28", "fancy bear"},
            apt_focus    = False,
        )
        assert score == 0

    def test_multiple_body_mentions_increases_score(self):
        score_low = VendorIntelCollector._score_relevance(
            title        = "Threat Intelligence Report",
            body         = "APT28 was briefly mentioned in the report.",
            search_terms = {"apt28"},
            apt_focus    = False,
        )
        score_high = VendorIntelCollector._score_relevance(
            title        = "Threat Intelligence Report",
            body         = "APT28 APT28 APT28 APT28 APT28 has been active APT28.",
            search_terms = {"apt28"},
            apt_focus    = False,
        )
        assert score_high > score_low

    def test_apt_focus_bonus_applied(self):
        score_no_focus = VendorIntelCollector._score_relevance(
            title        = "APT28 Campaign Analysis",
            body         = "APT28 was observed using spearphishing.",
            search_terms = {"apt28"},
            apt_focus    = False,
        )
        score_apt_focus = VendorIntelCollector._score_relevance(
            title        = "APT28 Campaign Analysis",
            body         = "APT28 was observed using spearphishing.",
            search_terms = {"apt28"},
            apt_focus    = True,
        )
        assert score_apt_focus > score_no_focus

    def test_score_capped_at_100(self):
        score = VendorIntelCollector._score_relevance(
            title        = "APT28 APT28 APT28",
            body         = " APT28" * 50,
            search_terms = {"apt28"},
            apt_focus    = True,
        )
        assert score <= 100

    def test_case_insensitive_matching(self):
        score = VendorIntelCollector._score_relevance(
            title        = "FANCY BEAR TARGETS NATO",
            body         = "Fancy Bear, also known as APT28...",
            search_terms = {"fancy bear", "apt28"},
            apt_focus    = False,
        )
        assert score >= 30

    def test_alias_in_title_scores_well(self):
        """Articles mentioning 'Forest Blizzard' (not 'APT28') should score high."""
        score = VendorIntelCollector._score_relevance(
            title        = "Forest Blizzard Targets Ukrainian Infrastructure",
            body         = "Forest Blizzard, a GRU-linked threat actor, has been observed...",
            search_terms = {"apt28", "fancy bear", "forest blizzard", "sofacy"},
            apt_focus    = True,
        )
        assert score >= 50

    def test_body_scored_against_full_content(self):
        """Body scoring should use full SUMMARY_SCORE_CHARS, not 500-char slice."""
        # Put all mentions after the 500-char mark
        padding = "x" * 600
        body = padding + " APT28 APT28 APT28 APT28 APT28"
        score = VendorIntelCollector._score_relevance(
            title        = "Security Report",
            body         = body,
            search_terms = {"apt28"},
            apt_focus    = False,
        )
        # If scoring only 500 chars, all mentions are missed → score 0
        # With full scoring, body_hits ≥ 5 → score += 35
        assert score >= 30


# ---------------------------------------------------------------------------
# Search term building
# ---------------------------------------------------------------------------

class TestSearchTerms:

    def test_actor_name_included(self):
        terms = VendorIntelCollector._build_search_terms("APT28", [])
        assert "apt28" in terms

    def test_aliases_included(self):
        terms = VendorIntelCollector._build_search_terms(
            "APT28", ["Fancy Bear", "Sofacy", "Forest Blizzard"]
        )
        assert "fancy bear" in terms
        assert "sofacy" in terms

    def test_short_aliases_excluded(self):
        terms = VendorIntelCollector._build_search_terms(
            "APT28", ["G0007", "TA422", "Fancy Bear"]
        )
        assert "g0007" not in terms
        assert "ta422" not in terms
        assert "fancy bear" in terms

    def test_terms_are_lowercase(self):
        terms = VendorIntelCollector._build_search_terms("APT28", ["FANCY BEAR"])
        for term in terms:
            assert term == term.lower()


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------

class TestUtilities:

    def test_strip_html_removes_tags(self):
        assert _strip_html("<b>Bold</b> text") == "Bold text"

    def test_strip_html_empty_string(self):
        assert _strip_html("") == ""

    def test_strip_html_no_html(self):
        assert _strip_html("plain text") == "plain text"

    def test_normalise_date_rfc2822(self):
        assert _normalise_date("Mon, 15 Jan 2024 10:00:00 +0000") == "2024-01-15"

    def test_normalise_date_iso(self):
        assert _normalise_date("2024-02-01T12:00:00Z") == "2024-02-01"

    def test_normalise_date_empty(self):
        assert _normalise_date("") == ""

    def test_slugify_spaces(self):
        assert _slugify("Mandiant Threat Intelligence") == "mandiant_threat_intelligence"

    def test_slugify_special_chars(self):
        assert _slugify("Unit 42 (Palo Alto)") == "unit_42__palo_alto_"


# ---------------------------------------------------------------------------
# Cache TTL and configuration tests
# ---------------------------------------------------------------------------

class TestCacheConfig:

    def test_cache_ttl_is_24_hours(self):
        """Cache TTL should be 24h — feeds don't change faster than this."""
        assert CACHE_TTL_HRS == 24

    def test_summary_cache_chars_at_least_1000(self):
        """Summary stored in cache must be significantly larger than old 500-char limit."""
        assert SUMMARY_CACHE_CHARS >= 1000

    def test_summary_score_chars_matches_cache(self):
        """Score chars should match cache chars — no point storing more than we score."""
        assert SUMMARY_SCORE_CHARS >= SUMMARY_CACHE_CHARS

    def test_max_workers_reasonable(self):
        """ThreadPoolExecutor worker count should be positive and bounded."""
        assert 1 <= MAX_WORKERS <= 32

    def test_cache_stale_after_ttl(self, tmp_path, monkeypatch):
        """Entries older than CACHE_TTL_HRS should not be returned."""
        import collectors.vendor_intel as vi_module
        monkeypatch.setattr(vi_module, "CACHE_DIR", tmp_path)

        from datetime import datetime, timezone, timedelta
        collector = VendorIntelCollector.__new__(VendorIntelCollector)
        collector._feeds = []

        stale_time = (
            datetime.now(timezone.utc) - timedelta(hours=CACHE_TTL_HRS + 1)
        ).isoformat()

        cache_file = tmp_path / "test_key.json"
        cache_file.write_text(json.dumps({
            "cached_at": stale_time,
            "entries":   [{"title": "old article", "url": "x", "date": "2024-01-01", "summary": ""}],
        }))

        result = collector._load_cache("test_key")
        assert result is None   # expired

    def test_cache_fresh_returned(self, tmp_path, monkeypatch):
        """Entries younger than CACHE_TTL_HRS should be returned."""
        import collectors.vendor_intel as vi_module
        monkeypatch.setattr(vi_module, "CACHE_DIR", tmp_path)

        from datetime import datetime, timezone, timedelta
        collector = VendorIntelCollector.__new__(VendorIntelCollector)

        fresh_time = datetime.now(timezone.utc).isoformat()

        cache_file = tmp_path / "test_key.json"
        cache_file.write_text(json.dumps({
            "cached_at": fresh_time,
            "entries":   [{"title": "fresh article", "url": "x", "date": "2024-01-01", "summary": ""}],
        }))

        result = collector._load_cache("test_key")
        assert result is not None
        assert result[0]["title"] == "fresh article"


# ---------------------------------------------------------------------------
# Concurrent fetch tests
# ---------------------------------------------------------------------------

class TestConcurrentFetch:

    def test_collect_uses_all_feeds(self, tmp_path, monkeypatch):
        """collect() should attempt all enabled feeds."""
        import collectors.vendor_intel as vi_module
        monkeypatch.setattr(vi_module, "CACHE_DIR", tmp_path)

        fetch_calls = []

        def mock_fetch_cached(feed):
            fetch_calls.append(feed["name"])
            return []

        collector = VendorIntelCollector.__new__(VendorIntelCollector)
        collector._feeds_path = tmp_path / "feeds.yaml"
        collector._feeds = [
            {"name": "Feed A", "rss": "https://a.example.com/rss", "enabled": True, "tier": 2, "apt_focus": True, "tags": []},
            {"name": "Feed B", "rss": "https://b.example.com/rss", "enabled": True, "tier": 2, "apt_focus": False, "tags": []},
            {"name": "Feed C", "rss": "https://c.example.com/rss", "enabled": False, "tier": 3, "apt_focus": False, "tags": []},
        ]

        monkeypatch.setattr(collector, "_fetch_feed_cached", mock_fetch_cached)
        monkeypatch.setattr(collector, "_load_apt_campaign_context", lambda *a, **k: [])

        results = collector.collect("APT28", ["Fancy Bear"])

        # Only enabled feeds should be fetched
        assert "Feed A" in fetch_calls
        assert "Feed B" in fetch_calls
        assert "Feed C" not in fetch_calls

    def test_failed_feed_does_not_abort_others(self, tmp_path, monkeypatch):
        """A timeout on one feed should not prevent results from others."""
        import collectors.vendor_intel as vi_module
        from datetime import datetime, timezone, timedelta
        monkeypatch.setattr(vi_module, "CACHE_DIR", tmp_path)

        # Use a recent date so articles pass the lookback cutoff filter
        recent_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")

        def mock_fetch_cached(feed):
            if feed["name"] == "Slow Feed":
                raise TimeoutError("connection timed out")
            return [{
                "title":   "APT28 New Campaign",
                "url":     "https://good.example.com/apt28",
                "date":    recent_date,
                "summary": "APT28 targets European governments using spearphishing.",
            }]

        collector = VendorIntelCollector.__new__(VendorIntelCollector)
        collector._feeds = [
            {"name": "Slow Feed",  "rss": "https://slow.example.com/rss",
             "enabled": True, "tier": 2, "apt_focus": True, "tags": []},
            {"name": "Good Feed",  "rss": "https://good.example.com/rss",
             "enabled": True, "tier": 2, "apt_focus": True, "tags": []},
        ]

        monkeypatch.setattr(collector, "_fetch_feed_cached", mock_fetch_cached)
        monkeypatch.setattr(collector, "_load_apt_campaign_context", lambda *a, **k: [])

        results = collector.collect("APT28", ["Fancy Bear"])
        assert len(results) >= 1
        assert any("APT28" in r["title"] for r in results)

    def test_deduplication_by_url(self, tmp_path, monkeypatch):
        """Same URL from two feeds should appear only once."""
        import collectors.vendor_intel as vi_module
        from datetime import datetime, timezone, timedelta
        monkeypatch.setattr(vi_module, "CACHE_DIR", tmp_path)

        recent_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")

        shared_entry = {
            "title":   "APT28 Analysis",
            "url":     "https://shared.example.com/article",
            "date":    recent_date,
            "summary": "APT28 has been conducting campaigns against NATO allies.",
        }

        def mock_fetch_cached(feed):
            return [shared_entry]

        collector = VendorIntelCollector.__new__(VendorIntelCollector)
        collector._feeds = [
            {"name": "Feed X", "rss": "x", "enabled": True, "tier": 2, "apt_focus": True, "tags": []},
            {"name": "Feed Y", "rss": "y", "enabled": True, "tier": 2, "apt_focus": True, "tags": []},
        ]

        monkeypatch.setattr(collector, "_fetch_feed_cached", mock_fetch_cached)
        monkeypatch.setattr(collector, "_load_apt_campaign_context", lambda *a, **k: [])

        results = collector.collect("APT28", [])
        urls = [r["url"] for r in results]
        assert urls.count("https://shared.example.com/article") == 1

    def test_results_sorted_by_relevance(self, tmp_path, monkeypatch):
        """Results should be sorted highest relevance first."""
        import collectors.vendor_intel as vi_module
        from datetime import datetime, timezone, timedelta
        monkeypatch.setattr(vi_module, "CACHE_DIR", tmp_path)

        recent_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")

        def mock_fetch_cached(feed):
            return [
                {
                    "title":   "APT28 Primary Subject Article",
                    "url":     "https://example.com/high",
                    "date":    recent_date,
                    "summary": "APT28 APT28 APT28 APT28 APT28 APT28 deployed backdoors.",
                },
                {
                    "title":   "Brief Mention of APT28",
                    "url":     "https://example.com/low",
                    "date":    recent_date,
                    "summary": "APT28 was mentioned briefly in context of nation-state threats.",
                },
            ]

        collector = VendorIntelCollector.__new__(VendorIntelCollector)
        collector._feeds = [
            {"name": "Feed", "rss": "x", "enabled": True, "tier": 2, "apt_focus": True, "tags": []},
        ]

        monkeypatch.setattr(collector, "_fetch_feed_cached", mock_fetch_cached)
        monkeypatch.setattr(collector, "_load_apt_campaign_context", lambda *a, **k: [])

        results = collector.collect("APT28", [])
        assert len(results) >= 2
        assert results[0]["relevance"] >= results[-1]["relevance"]


# ---------------------------------------------------------------------------
# Feed health logging
# ---------------------------------------------------------------------------

class TestFeedHealth:

    def test_log_feed_health_does_not_raise(self):
        """_log_feed_health should handle all sentinel values without error."""
        VendorIntelCollector._log_feed_health(
            hit_counts={"Feed A": 3, "Feed B": 0, "Feed C": -1},
            errors={"Feed C": "timeout"},
        )

    def test_log_feed_health_empty(self):
        """Empty inputs should not raise."""
        VendorIntelCollector._log_feed_health(hit_counts={}, errors={})


# ---------------------------------------------------------------------------
# LLM provider tests (offline — no real API calls)
# ---------------------------------------------------------------------------

class TestLLMProviders:

    def test_claude_unavailable_without_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        p = ClaudeProvider()
        p._api_key = ""
        assert not p.available

    def test_openai_unavailable_without_key(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        p = OpenAIProvider()
        p._api_key = ""
        assert not p.available

    def test_claude_available_with_key(self):
        p = ClaudeProvider()
        p._api_key = "sk-ant-test-key-12345"
        assert p.available

    def test_openai_available_with_key(self):
        p = OpenAIProvider()
        p._api_key = "sk-test-key-12345"
        assert p.available

    def test_provider_names(self):
        assert ClaudeProvider().name  == "claude"
        assert OpenAIProvider().name  == "openai"
        assert OllamaProvider().name  == "ollama"


# ---------------------------------------------------------------------------
# Article hash
# ---------------------------------------------------------------------------

class TestArticleHash:

    def test_same_article_same_hash(self):
        article = {"url": "https://example.com/apt28", "title": "APT28 Report"}
        assert _article_hash(article) == _article_hash(article)

    def test_different_url_different_hash(self):
        a1 = {"url": "https://example.com/a", "title": "APT28"}
        a2 = {"url": "https://example.com/b", "title": "APT28"}
        assert _article_hash(a1) != _article_hash(a2)

    def test_hash_is_string(self):
        assert isinstance(_article_hash({"url": "x", "title": "y"}), str)

    def test_hash_length(self):
        assert len(_article_hash({"url": "x", "title": "y"})) == 16


# ---------------------------------------------------------------------------
# Synthesis cache tests
# ---------------------------------------------------------------------------

class TestSynthesisCache:

    def test_save_and_load(self, tmp_path, monkeypatch):
        import collectors.intelligence_synthesizer as synth_module
        monkeypatch.setattr(synth_module, "CACHE_DIR", tmp_path)

        mock_provider = MagicMock()
        mock_provider.name = "claude"
        mock_provider.available = True

        synth = IntelligenceSynthesizer(mock_provider)
        result = {
            "actor_summary":     "APT28 was observed targeting EU governments.",
            "landscape_summary": "Broader trend of identity-based attacks.",
            "relevance":         85,
            "source":            "Mandiant",
            "date":              "2024-01-15",
            "title":             "Test Article",
            "url":               "https://example.com/test",
            "provider":          "claude",
        }

        cache_key = "test_cache_key_abc123ef"
        synth._save_cache(cache_key, result)
        loaded = synth._load_cache(cache_key)
        assert loaded is not None
        assert loaded["actor_summary"] == result["actor_summary"]

    def test_missing_cache_returns_none(self, tmp_path, monkeypatch):
        import collectors.intelligence_synthesizer as synth_module
        monkeypatch.setattr(synth_module, "CACHE_DIR", tmp_path)

        mock_provider = MagicMock()
        synth = IntelligenceSynthesizer(mock_provider)
        assert synth._load_cache("nonexistent_key") is None


# ---------------------------------------------------------------------------
# Synthesis with mocked provider
# ---------------------------------------------------------------------------

class TestSynthesisWithMock:

    def test_synthesize_returns_result(self, tmp_path, monkeypatch):
        import collectors.intelligence_synthesizer as synth_module
        monkeypatch.setattr(synth_module, "CACHE_DIR", tmp_path)

        mock_provider = MagicMock()
        mock_provider.name      = "claude"
        mock_provider.available = True
        mock_provider.complete  = MagicMock(
            side_effect=[
                "APT28 deployed a new backdoor targeting EU governments in January 2024.",
                "This reflects a broader trend of nation-state actors targeting democratic institutions.",
            ]
        )

        synth   = IntelligenceSynthesizer(mock_provider)
        article = {
            "title":       "APT28 Targets European Governments",
            "url":         "https://example.com/apt28",
            "source":      "Mandiant",
            "source_tier": 2,
            "date":        "2024-01-15",
            "relevance":   85,
            "summary":     "APT28 has been observed targeting government entities across Europe.",
        }

        result = synth.synthesize(article, "APT28", ["Fancy Bear", "Sofacy"])
        assert result is not None
        assert "actor_summary" in result
        assert "landscape_summary" in result
        assert result["source"] == "Mandiant"

    def test_no_actor_intel_returns_none(self, tmp_path, monkeypatch):
        import collectors.intelligence_synthesizer as synth_module
        monkeypatch.setattr(synth_module, "CACHE_DIR", tmp_path)

        mock_provider = MagicMock()
        mock_provider.name      = "claude"
        mock_provider.available = True
        mock_provider.complete  = MagicMock(return_value="NO_ACTOR_SPECIFIC_INTEL")

        synth   = IntelligenceSynthesizer(mock_provider)
        article = {
            "title":   "Generic Security Report",
            "url":     "https://example.com/generic",
            "source":  "SomeVendor",
            "date":    "2024-01-15",
            "relevance": 35,
            "summary": "A brief mention of various threat actors including APT28.",
        }

        result = synth.synthesize(article, "APT28", [])
        assert result is None

    def test_unavailable_provider_returns_none(self):
        mock_provider = MagicMock()
        mock_provider.available = False

        synth   = IntelligenceSynthesizer(mock_provider)
        article = {"title": "Test", "url": "x", "source": "y",
                   "date": "2024-01-01", "relevance": 80, "summary": "APT28..."}

        result = synth.synthesize(article, "APT28", [])
        assert result is None
