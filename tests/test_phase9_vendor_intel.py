"""
tests/test_phase9_vendor_intel.py
----------------------------------
Unit tests for Phase 9 vendor intelligence layer — fully offline.
Tests cover RSS parsing, relevance scoring, provider loading,
cache logic, and synthesis prompt construction.
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
        # G0007 and TA422 match ^[gt]\d+$ pattern — should be excluded
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
# LLM provider tests (offline — no real API calls)
# ---------------------------------------------------------------------------

class TestLLMProviders:

    def test_claude_unavailable_without_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        p = ClaudeProvider()
        # Mock _load_key to return empty
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
        # 16 hex chars
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
