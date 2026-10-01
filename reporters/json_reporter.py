"""
reporters/json_reporter.py
--------------------------
Saves a merged CommonSchema profile as a JSON file.

Before overwriting an existing {slug}.json, the file about to be
replaced is rotated to {slug}.previous.json. This gives `theory diff`
(processors/diff.py) one step of history for every actor, for free, on
every ordinary run — no new storage format, nothing to opt into.
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
        actor_slug    = profile.get("actor_name", "unknown").lower().replace(" ", "_")
        path          = OUTPUT_DIR / f"{actor_slug}.json"
        previous_path = OUTPUT_DIR / f"{actor_slug}.previous.json"

        if path.exists():
            try:
                previous_path.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            except OSError as exc:
                logger.warning("Could not rotate previous snapshot for %s: %s", actor_slug, exc)

        path.write_text(json.dumps(profile, indent=2, default=str), encoding="utf-8")
        logger.info("JSON saved → %s", path)
        return path
