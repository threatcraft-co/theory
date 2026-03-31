"""
collectors/base.py

Abstract base class for all Theory collector modules.

Every collector must:
  - Inherit from BaseCollector
  - Set SOURCE_ID as a class-level string (e.g. "alienvault_otx")
  - Set REQUIRES_API_KEY = False if the source is keyless
  - Implement query(actor_name) returning a valid CommonSchema dict
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

THEORY_USER_AGENT = (
    "Theory-ThreatIntel/1.0 (github.com/threatcraft-co/theory; "
    "open-source threat actor intelligence framework)"
)


class CollectorError(Exception):
    """Raised by collectors to signal a non-recoverable data collection failure."""


class BaseCollector(ABC):
    """Abstract base class for all Theory intelligence source collectors."""

    SOURCE_ID: str = ""
    REQUIRES_API_KEY: bool = True

    def __init__(
        self,
        api_key: Optional[str] = None,
        config: Optional[dict[str, Any]] = None,
    ) -> None:
        if not self.SOURCE_ID:
            raise NotImplementedError(
                f"{self.__class__.__name__} must define SOURCE_ID."
            )
        self.api_key = api_key
        self.config = config or {}
        self.logger = logging.getLogger(f"theory.collectors.{self.SOURCE_ID}")
        self._session = self._build_session()

    @abstractmethod
    def query(self, actor_name: str) -> dict[str, Any]:
        """Query the source for intelligence on the given threat actor.

        Returns a CommonSchema-conformant dict, or an empty schema if the
        actor is not found. Must not raise for handled failure conditions.
        """
        ...

    def is_available(self) -> bool:
        """Return True if this collector can run in the current environment."""
        if self.REQUIRES_API_KEY and not self.api_key:
            self.logger.info(
                "Collector %s skipped — no API key. Set %s in .env.",
                self.SOURCE_ID,
                self.config.get("api_key_env", f"{self.SOURCE_ID.upper()}_API_KEY"),
            )
            return False
        return True

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=2, connect=2, read=1, backoff_factor=1,
                      status_forcelist=[], raise_on_status=False)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        self._timeout = self.config.get("timeout_seconds", 30)
        session.headers.update({
            "User-Agent": THEORY_USER_AGENT,
            "Accept": "application/json",
        })
        return session

    def _get(self, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self._timeout)
        kwargs.setdefault("verify", True)
        self.logger.debug("GET %s", url)
        return self._session.get(url, **kwargs)

    def _post(self, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self._timeout)
        kwargs.setdefault("verify", True)
        self.logger.debug("POST %s", url)
        return self._session.post(url, **kwargs)

    def _empty_schema(self, actor_name: str) -> dict[str, Any]:
        """Return a minimal valid empty CommonSchema dict."""
        return {
            "actor_name": actor_name,
            "aliases": [],
            "source_id": self.SOURCE_ID,
            "source_url": self.config.get("base_url", ""),
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "suspected_origin": None,
            "motivation": [],
            "first_seen": None,
            "sponsorship": None,
            "target_sectors": [],
            "target_countries": [],
            "techniques": [],
            "malware": [],
            "indicators": [],
            "campaigns": [],
            "source_citation": self.SOURCE_ID,
        }
