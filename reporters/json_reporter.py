"""
reporters/json_reporter.py
--------------------------
Saves a merged CommonSchema profile as a JSON file.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("output/dossiers")


class JsonReporter:
    def save(self, profile: dict[str, Any]) -> Path:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        actor_slug = profile.get("actor_name", "unknown").lower().replace(" ", "_")
        path = OUTPUT_DIR / f"{actor_slug}.json"
        path.write_text(json.dumps(profile, indent=2, default=str), encoding="utf-8")
        logger.info("JSON saved → %s", path)
        return path
