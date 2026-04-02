"""
collectors/sigma_rules.py
--------------------------
Fetches Sigma detection rules mapped to ATT&CK technique IDs.

Architecture: local clone (fast) vs GitHub Search API (slow)
--------------------------------------------------------------
THEORY uses a LOCAL CLONE of the SigmaHQ/sigma repository stored at
.cache/sigma-repo/. This means:

  - Zero API rate limits
  - Instant results (grep on local files vs HTTP requests)
  - Works fully offline after initial clone
  - No GitHub token required
  - Full rule coverage (no 5-rule cap per technique)

Initial clone: ~2 minutes, ~500MB disk space (one time only)
Subsequent runs: instant (grep on local files)
Update: python3 theory.py --update-bundles (runs git pull)

If the local clone is not present, THEORY will clone it automatically
on first use. This replaces the previous GitHub Search API approach
which required 6.5s delays per technique due to rate limiting.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SIGMA_REPO_URL  = "https://github.com/SigmaHQ/sigma.git"
SIGMA_REPO_PATH = Path(".cache/sigma-repo")
RULES_DIR       = SIGMA_REPO_PATH / "rules"
MAX_RULES_PER_TECHNIQUE = 10   # raised from 5 — no cost to go higher now

# Rule levels in priority order for sorting
LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


class SigmaCollector:
    """
    Queries the local SigmaHQ repo clone for rules matching ATT&CK technique IDs.

    On first use, clones the SigmaHQ/sigma repo to .cache/sigma-repo/.
    Subsequent uses grep the local clone — no network required, no rate limits.
    """

    def __init__(self):
        self._repo_ready = False

    def _ensure_repo(self) -> bool:
        """Clone the SigmaHQ repo if not present. Return True if ready."""
        if self._repo_ready:
            return True

        if RULES_DIR.exists() and any(RULES_DIR.iterdir()):
            self._repo_ready = True
            return True

        # Clone needed
        self._print_clone_notice()
        SIGMA_REPO_PATH.parent.mkdir(parents=True, exist_ok=True)

        try:
            result = subprocess.run(
                [
                    "git", "clone",
                    "--depth", "1",          # shallow clone — much faster, ~150MB vs ~500MB
                    "--filter=blob:none",    # skip blobs until needed
                    "--no-tags",
                    SIGMA_REPO_URL,
                    str(SIGMA_REPO_PATH),
                ],
                capture_output=True,
                text=True,
                timeout=300,   # 5 min timeout
            )

            if result.returncode != 0:
                logger.error("Sigma clone failed: %s", result.stderr)
                self._print_clone_failed(result.stderr)
                return False

            self._repo_ready = True
            self._print_clone_success()
            return True

        except subprocess.TimeoutExpired:
            logger.error("Sigma clone timed out")
            return False
        except FileNotFoundError:
            logger.error("git not found — cannot clone SigmaHQ repo")
            print(
                "\n  [Sigma] git is required to clone the SigmaHQ repo.\n"
                "  Install git and run again, or run: python3 theory.py --update-bundles\n",
                file=sys.stderr,
            )
            return False

    def update_repo(self) -> bool:
        """Pull latest changes from SigmaHQ. Called by --update-bundles."""
        if not SIGMA_REPO_PATH.exists():
            return self._ensure_repo()

        try:
            from rich.console import Console
            Console(stderr=True).print("[dim]  Updating Sigma rules (git pull)…[/dim]")
        except ImportError:
            print("  Updating Sigma rules…", file=sys.stderr)

        result = subprocess.run(
            ["git", "-C", str(SIGMA_REPO_PATH), "pull", "--depth=1"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            try:
                from rich.console import Console
                Console(stderr=True).print("[green]  ✓ Sigma rules updated[/green]")
            except ImportError:
                print("  ✓ Sigma rules updated", file=sys.stderr)
            return True
        else:
            logger.error("Sigma pull failed: %s", result.stderr)
            return False

    def collect_for_techniques(
        self, technique_ids: list[str]
    ) -> dict[str, list[dict]]:
        """
        For each technique ID, return a list of matching Sigma rules.

        Uses local grep on the cloned SigmaHQ repo — instant, no rate limits.

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
        if not self._ensure_repo():
            logger.warning("Sigma repo not available — skipping detection enrichment")
            return {}

        results: dict[str, list[dict]] = {}
        unique_ids = list(dict.fromkeys(technique_ids))

        logger.info("Sigma: querying local repo for %d techniques", len(unique_ids))

        for tid in unique_ids:
            rules = self._find_rules_for_technique(tid)
            if rules:
                results[tid] = rules

        total = sum(len(v) for v in results.values())
        logger.info(
            "Sigma: found %d rules across %d techniques",
            total, len(results),
        )
        return results

    def _find_rules_for_technique(self, technique_id: str) -> list[dict]:
        """
        Grep the local Sigma repo for rules tagged with this technique ID.
        Returns sorted list of rule dicts (critical/high first).
        """
        if not RULES_DIR.exists():
            return []

        # Build grep pattern — technique IDs appear as tags like:
        # "attack.t1059.001" or "attack.t1059"
        tag_pattern = f"attack.{technique_id.lower()}"

        try:
            result = subprocess.run(
                [
                    "grep",
                    "-rl",                    # recursive, list filenames only
                    "--include=*.yml",
                    tag_pattern,
                    str(RULES_DIR),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Sigma grep timed out for %s", technique_id)
            return []
        except FileNotFoundError:
            logger.error("grep not found")
            return []

        if result.returncode != 0 or not result.stdout.strip():
            return []

        rule_files = [
            Path(f) for f in result.stdout.strip().splitlines()
            if f.strip()
        ]

        rules: list[dict] = []
        for rule_file in rule_files:
            parsed = _parse_sigma_yaml(rule_file)
            if parsed:
                # Verify this rule actually covers our technique
                if _rule_covers_technique(parsed, technique_id):
                    rules.append(parsed)

        # Sort by level (critical first) then title
        rules.sort(key=lambda r: (
            LEVEL_ORDER.get(r.get("level", ""), 99),
            r.get("title", ""),
        ))

        return rules[:MAX_RULES_PER_TECHNIQUE]

    # ------------------------------------------------------------------
    # User messaging
    # ------------------------------------------------------------------

    @staticmethod
    def _print_clone_notice() -> None:
        msg = (
            "\n  ℹ  Sigma rules: cloning SigmaHQ/sigma repository (one time only).\n"
            "     This takes ~1-2 minutes and uses ~150MB of disk space.\n"
            "     After this, all Sigma queries run instantly with no rate limits.\n"
            "     Location: .cache/sigma-repo/\n"
        )
        try:
            from rich.console import Console
            Console(stderr=True).print(f"[cyan]{msg}[/cyan]")
        except ImportError:
            print(msg, file=sys.stderr)

    @staticmethod
    def _print_clone_success() -> None:
        msg = "  ✓ SigmaHQ repo cloned — Sigma queries are now instant.\n"
        try:
            from rich.console import Console
            Console(stderr=True).print(f"[green]{msg}[/green]")
        except ImportError:
            print(msg, file=sys.stderr)

    @staticmethod
    def _print_clone_failed(error: str) -> None:
        msg = (
            f"\n  ✗ Sigma clone failed: {error[:200]}\n"
            "    Run manually: git clone --depth 1 "
            "https://github.com/SigmaHQ/sigma.git .cache/sigma-repo\n"
        )
        try:
            from rich.console import Console
            Console(stderr=True).print(f"[red]{msg}[/red]")
        except ImportError:
            print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# YAML parsing (stdlib only — no PyYAML dependency)
# ---------------------------------------------------------------------------

def _parse_sigma_yaml(path: Path) -> dict | None:
    """
    Parse a Sigma rule YAML file into a structured dict.
    Uses stdlib only — no PyYAML required.
    Falls back to PyYAML if available for better accuracy.
    """
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    # Try PyYAML first if available
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(content)
        if not isinstance(data, dict) or not data.get("title"):
            return None
        return _build_rule_dict(data, path, content)
    except ImportError:
        pass
    except Exception:
        return None

    # Fallback: minimal line-by-line parser for key fields
    return _parse_sigma_minimal(content, path)


def _build_rule_dict(data: dict, path: Path, content: str) -> dict | None:
    """Build a standardised rule dict from parsed YAML data."""
    title = (data.get("title") or "").strip()
    if not title:
        return None

    level      = (data.get("level") or "").lower().strip()
    status     = (data.get("status") or "").lower().strip()
    tags       = data.get("tags") or []
    logsource  = data.get("logsource") or {}
    detection  = data.get("detection") or {}

    ls_parts = [
        v for k, v in logsource.items()
        if k in ("category", "product", "service") and v
    ]
    logsource_str = " / ".join(ls_parts) if ls_parts else "unknown"

    condition_raw = detection.get("condition", "")
    condition_str = _summarise_condition(str(condition_raw)) if condition_raw else ""

    # Build GitHub URL from file path
    rel = path.relative_to(SIGMA_REPO_PATH)
    url = f"https://github.com/SigmaHQ/sigma/blob/master/{rel}"

    return {
        "title":             title,
        "level":             level,
        "status":            status,
        "logsource":         logsource_str,
        "condition_summary": condition_str,
        "tags":              [str(t).lower() for t in tags],
        "url":               url,
        "path":              str(rel),
    }


def _parse_sigma_minimal(content: str, path: Path) -> dict | None:
    """Minimal stdlib YAML parser for Sigma rules."""
    fields: dict[str, Any] = {}
    tags: list[str] = []
    logsource_parts: list[str] = []
    in_tags = False
    in_logsource = False
    in_detection = False
    condition = ""

    for line in content.splitlines():
        stripped = line.strip()

        if stripped.startswith("title:"):
            fields["title"] = stripped[6:].strip().strip("'\"")
            in_tags = in_logsource = in_detection = False
        elif stripped.startswith("level:"):
            fields["level"] = stripped[6:].strip().strip("'\"").lower()
            in_tags = in_logsource = in_detection = False
        elif stripped.startswith("status:"):
            fields["status"] = stripped[7:].strip().strip("'\"").lower()
            in_tags = in_logsource = in_detection = False
        elif stripped == "tags:":
            in_tags = True
            in_logsource = in_detection = False
        elif stripped == "logsource:":
            in_logsource = True
            in_tags = in_detection = False
        elif stripped == "detection:":
            in_detection = True
            in_tags = in_logsource = False
        elif in_tags and stripped.startswith("- "):
            tags.append(stripped[2:].strip().lower())
        elif in_logsource and ":" in stripped and not stripped.startswith("-"):
            key, _, val = stripped.partition(":")
            if key.strip() in ("category", "product", "service") and val.strip():
                logsource_parts.append(val.strip().strip("'\""))
        elif in_detection and stripped.startswith("condition:"):
            condition = stripped[10:].strip().strip("'\"")
        elif not line.startswith(" ") and not line.startswith("	") and stripped and not stripped.startswith("-"):
            if stripped.endswith(":") and stripped[:-1] not in (
                "tags", "logsource", "detection"
            ):
                in_tags = in_logsource = in_detection = False

    title = fields.get("title", "").strip()
    if not title:
        return None

    rel = path.relative_to(SIGMA_REPO_PATH)
    url = f"https://github.com/SigmaHQ/sigma/blob/master/{rel}"

    return {
        "title":             title,
        "level":             fields.get("level", ""),
        "status":            fields.get("status", ""),
        "logsource":         " / ".join(logsource_parts) if logsource_parts else "unknown",
        "condition_summary": _summarise_condition(condition),
        "tags":              tags,
        "url":               url,
        "path":              str(rel),
    }


def _rule_covers_technique(rule: dict, technique_id: str) -> bool:
    """Check that the rule's tags include this specific technique."""
    tag_target = f"attack.{technique_id.lower()}"
    return any(tag_target == tag for tag in rule.get("tags", []))


def _summarise_condition(condition: str) -> str:
    """Shorten a Sigma condition expression for display."""
    if not condition:
        return ""
    c = re.sub(r"\s+", " ", condition).strip()
    if len(c) > 80:
        c = c[:77] + "..."
    return c
