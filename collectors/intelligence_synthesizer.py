"""
collectors/intelligence_synthesizer.py
----------------------------------------
LLM-powered synthesis engine for vendor threat intelligence articles.

Produces two types of synthesis per dossier:

  1. Actor-specific synthesis
     "What does this article tell us about THIS actor specifically?"
     → 2-3 sentences, past/recent activity, TTPs, targeting

  2. Landscape synthesis
     "What broader threat trends does this article reflect?"
     → 1-2 sentences, how this fits the wider threat environment

Provider abstraction:
  Reads THEORY_LLM_PROVIDER from .env (claude | openai | ollama)
  Falls back to claude if ANTHROPIC_API_KEY is present,
  then openai if OPENAI_API_KEY is present,
  then ollama if running locally.

.env configuration:
  THEORY_LLM_PROVIDER=claude        # or openai, ollama
  ANTHROPIC_API_KEY=sk-ant-...
  OPENAI_API_KEY=sk-...
  OLLAMA_HOST=http://localhost:11434  # default
  OLLAMA_MODEL=llama3.2              # default

Cache: .cache/intel_synthesis/{article_hash}.json, TTL 7 days
(Synthesis is expensive — cache aggressively)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError

logger = logging.getLogger(__name__)

CACHE_DIR    = Path(".cache/intel_synthesis")
CACHE_TTL    = 7   # days
MAX_TOKENS   = 400
MAX_SYNTH_ITEMS = 15  # max articles to synthesize per run
TIMEOUT      = 30


# ---------------------------------------------------------------------------
# Provider abstraction
# ---------------------------------------------------------------------------

class LLMProvider(ABC):
    """Base class for all LLM providers."""

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Send a prompt and return the completion text."""
        ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def available(self) -> bool:
        """True if this provider is configured and reachable."""
        ...


class ClaudeProvider(LLMProvider):
    """Anthropic Claude via API."""

    MODEL = "claude-haiku-4-5-20251001"   # fast + cheap for synthesis

    def __init__(self):
        self._api_key = self._load_key()

    @staticmethod
    def _load_key() -> str:
        key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if key:
            return key
        env_path = Path(".env")
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8-sig").splitlines():
                if line.strip().startswith("ANTHROPIC_API_KEY="):
                    return line.split("=", 1)[1].strip().strip("\"'")
        return ""

    @property
    def name(self) -> str:
        return "claude"

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def complete(self, system: str, user: str) -> str:
        if not self._api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")

        payload = json.dumps({
            "model":      self.MODEL,
            "max_tokens": MAX_TOKENS,
            "system":     system,
            "messages":   [{"role": "user", "content": user}],
        }).encode("utf-8")

        req = Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type":      "application/json",
                "x-api-key":         self._api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )

        with urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        return data["content"][0]["text"].strip()


class OpenAIProvider(LLMProvider):
    """OpenAI GPT-4o-mini via API."""

    MODEL = "gpt-4o-mini"

    def __init__(self):
        self._api_key = self._load_key()

    @staticmethod
    def _load_key() -> str:
        key = os.environ.get("OPENAI_API_KEY", "").strip()
        if key:
            return key
        env_path = Path(".env")
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8-sig").splitlines():
                if line.strip().startswith("OPENAI_API_KEY="):
                    return line.split("=", 1)[1].strip().strip("\"'")
        return ""

    @property
    def name(self) -> str:
        return "openai"

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def complete(self, system: str, user: str) -> str:
        if not self._api_key:
            raise RuntimeError("OPENAI_API_KEY not set")

        payload = json.dumps({
            "model":      self.MODEL,
            "max_tokens": MAX_TOKENS,
            "messages": [
                {"role": "system",  "content": system},
                {"role": "user",    "content": user},
            ],
        }).encode("utf-8")

        req = Request(
            "https://api.openai.com/v1/chat/completions",
            data=payload,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )

        with urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        return data["choices"][0]["message"]["content"].strip()


class OllamaProvider(LLMProvider):
    """Local Ollama instance (fully offline, no API costs)."""

    def __init__(self):
        self._host  = self._load_config("OLLAMA_HOST",  "http://localhost:11434")
        self._model = self._load_config("OLLAMA_MODEL", "llama3.2")

    @staticmethod
    def _load_config(key: str, default: str) -> str:
        val = os.environ.get(key, "").strip()
        if val:
            return val
        env_path = Path(".env")
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8-sig").splitlines():
                if line.strip().startswith(f"{key}="):
                    return line.split("=", 1)[1].strip().strip("\"'")
        return default

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def available(self) -> bool:
        try:
            req = Request(f"{self._host}/api/tags",
                          headers={"User-Agent": "THEORY/1.0"})
            with urlopen(req, timeout=3):
                return True
        except Exception:
            return False

    def complete(self, system: str, user: str) -> str:
        payload = json.dumps({
            "model":  self._model,
            "prompt": f"{system}\n\n{user}",
            "stream": False,
            "options": {"num_predict": MAX_TOKENS},
        }).encode("utf-8")

        req = Request(
            f"{self._host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        return data.get("response", "").strip()


def load_provider() -> LLMProvider | None:
    """
    Load the configured LLM provider from .env.
    Returns None if no provider is available.

    Priority:
      1. THEORY_LLM_PROVIDER env var (explicit choice)
      2. Auto-detect: Claude → OpenAI → Ollama
    """
    # Load explicit preference
    preferred = os.environ.get("THEORY_LLM_PROVIDER", "").lower().strip()
    if not preferred:
        env_path = Path(".env")
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8-sig").splitlines():
                if line.strip().startswith("THEORY_LLM_PROVIDER="):
                    preferred = line.split("=", 1)[1].strip().strip("\"'").lower()

    providers = {
        "claude": ClaudeProvider,
        "openai": OpenAIProvider,
        "ollama": OllamaProvider,
    }

    if preferred and preferred in providers:
        p = providers[preferred]()
        if p.available:
            logger.info("LLM provider: %s (explicit)", preferred)
            return p
        else:
            logger.warning(
                "Preferred provider %r is not available — "
                "check your API key in .env", preferred
            )

    # Auto-detect
    for name, cls in providers.items():
        p = cls()
        if p.available:
            logger.info("LLM provider: %s (auto-detected)", name)
            return p

    logger.warning(
        "No LLM provider available. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, "
        "or start Ollama to enable vendor intelligence synthesis."
    )
    return None


# ---------------------------------------------------------------------------
# Synthesis engine
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a senior threat intelligence analyst at a top-tier \
security research firm. You write concise, precise intelligence assessments \
grounded in the source material. You never fabricate details not present in \
the article. You write for an audience of fellow analysts, threat hunters, \
and detection engineers — no fluff, no filler."""

ACTOR_SYNTHESIS_PROMPT = """Article source: {source}
Article date: {date}
Article title: {title}

Article content:
{body}

---

Actor being profiled: {actor_name}
Known aliases: {aliases}

Task: Write 2-3 sentences of actor-specific intelligence.
Focus ONLY on what this article reveals about {actor_name}'s:
- Recent activity, campaigns, or operations
- Tactics, techniques, or tools
- Targeting (sectors, countries, organizations)
- Evolution or changes from previous behavior

If the article only mentions {actor_name} briefly in passing, note that \
and extract whatever is relevant. If there is nothing specific to \
{actor_name}, respond with exactly: NO_ACTOR_SPECIFIC_INTEL

Write in past or present tense as appropriate. Be specific. Cite dates \
or timeframes if mentioned in the article.

CRITICAL FORMATTING RULES — your response must follow these exactly:
- Plain prose only. No markdown of any kind.
- No headers, no bold (**), no italic (*), no bullet points, no numbered lists.
- No label or preamble before your answer — start directly with the intelligence.
- Maximum 3 sentences."""

LANDSCAPE_SYNTHESIS_PROMPT = """Article source: {source}
Article date: {date}
Article title: {title}

Article content:
{body}

---

Actor being profiled: {actor_name}

Task: Write 1-2 sentences of threat landscape context.
What broader trend, pattern, or shift does this article reflect that is \
relevant to the threat environment {actor_name} operates in?

Examples of good landscape context:
- "This represents a broader trend of nation-state actors adopting \
  commercial offensive tooling to complicate attribution."
- "The technique described aligns with a wider shift toward \
  identity-based attacks that bypass traditional endpoint controls."

Be specific to what the article actually covers. No generic statements.

CRITICAL FORMATTING RULES — your response must follow these exactly:
- Plain prose only. No markdown of any kind.
- No headers, no bold (**), no italic (*), no bullet points.
- No label like "Threat Landscape Context:" — start directly with the sentence.
- Maximum 2 sentences."""


class IntelligenceSynthesizer:
    """
    Synthesizes vendor threat intelligence articles into analyst-ready summaries.
    """

    def __init__(self, provider: LLMProvider | None = None):
        self._provider = provider or load_provider()

    @property
    def available(self) -> bool:
        return self._provider is not None and self._provider.available

    def synthesize(
        self,
        article:    dict,
        actor_name: str,
        aliases:    list[str],
    ) -> dict | None:
        """
        Synthesize a single article into actor-specific + landscape summaries.

        Returns:
            {
                actor_summary:     "2-3 sentence actor-specific intel",
                landscape_summary: "1-2 sentence landscape context",
                relevance:         int (0-100),
                source:            str,
                date:              str,
                title:             str,
                url:               str,
            }
            or None if synthesis fails or no relevant intel found.
        """
        if not self.available:
            return None

        # Check cache first
        cache_key = _article_hash(article)
        cached    = self._load_cache(cache_key)
        if cached is not None:
            return cached

        body = article.get("summary", "")
        if not body:
            return None

        alias_str = ", ".join(aliases[:10]) if aliases else "none"

        # Actor-specific synthesis
        actor_prompt = ACTOR_SYNTHESIS_PROMPT.format(
            source     = article.get("source", ""),
            date       = article.get("date", ""),
            title      = article.get("title", ""),
            body       = body[:3000],   # token budget
            actor_name = actor_name,
            aliases    = alias_str,
        )

        try:
            actor_summary = self._provider.complete(SYSTEM_PROMPT, actor_prompt)
        except Exception as exc:
            logger.warning("Actor synthesis failed: %s", exc)
            return None

        if "NO_ACTOR_SPECIFIC_INTEL" in actor_summary:
            return None

        # Landscape synthesis
        landscape_prompt = LANDSCAPE_SYNTHESIS_PROMPT.format(
            source     = article.get("source", ""),
            date       = article.get("date", ""),
            title      = article.get("title", ""),
            body       = body[:2000],
            actor_name = actor_name,
        )

        try:
            landscape_summary = self._provider.complete(SYSTEM_PROMPT, landscape_prompt)
        except Exception as exc:
            logger.warning("Landscape synthesis failed: %s", exc)
            landscape_summary = ""

        result = {
            "actor_summary":     actor_summary,
            "landscape_summary": landscape_summary,
            "relevance":         article.get("relevance", 50),
            "source":            article.get("source", ""),
            "source_tier":       article.get("source_tier", 3),
            "date":              article.get("date", ""),
            "title":             article.get("title", ""),
            "url":               article.get("url", ""),
            "provider":          self._provider.name if self._provider else "unknown",
        }

        self._save_cache(cache_key, result)
        return result

    def synthesize_batch(
        self,
        articles:   list[dict],
        actor_name: str,
        aliases:    list[str],
        max_items:  int = 10,
    ) -> list[dict]:
        """
        Synthesize multiple articles. Returns list sorted by relevance.
        Caps at max_items to control API costs.
        """
        results: list[dict] = []

        # Sort by relevance + tier before capping
        ranked = sorted(
            articles,
            key=lambda a: (-a.get("relevance", 0), a.get("source_tier", 3)),
        )[:max_items]

        for article in ranked:
            result = self.synthesize(article, actor_name, aliases)
            if result:
                results.append(result)

        results.sort(key=lambda r: -r.get("relevance", 0))
        return results

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _load_cache(self, cache_key: str) -> dict | None:
        path = CACHE_DIR / f"{cache_key}.json"
        if not path.exists():
            return None
        try:
            data      = json.loads(path.read_text(encoding="utf-8"))
            cached_at = datetime.fromisoformat(data.get("cached_at", "2000-01-01"))
            age       = datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc)
            if age > timedelta(days=CACHE_TTL):
                return None
            return data.get("result")
        except Exception:
            return None

    def _save_cache(self, cache_key: str, result: dict) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = CACHE_DIR / f"{cache_key}.json"
        path.write_text(
            json.dumps({
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "result":    result,
            }, indent=2),
            encoding="utf-8",
        )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _article_hash(article: dict) -> str:
    """Stable cache key from article URL + title."""
    key = f"{article.get('url','')}{article.get('title','')}".encode("utf-8")
    return hashlib.sha256(key).hexdigest()[:16]
