"""
collectors/yara_rules.py
--------------------------
Fetches YARA detection rules matched to actor malware families.

Architecture: local clone, mirrors the SigmaHQ pattern
--------------------------------------------------------------
THEORY uses a LOCAL CLONE of the Yara-Rules/rules repository
stored at .cache/yara-rules-repo/. This means:

  - Zero API rate limits
  - Instant results (grep on local files vs HTTP requests)
  - Works fully offline after initial clone
  - No auth required

Where Sigma provides log/network-based detection rules mapped by
ATT&CK technique ID, YARA provides file/memory-based detection
rules matched by malware family name. Together they give the
dossier complete detection coverage: network AND endpoint.

Initial clone: ~1 minute, ~50MB disk space (one time only)
Subsequent runs: instant (grep on local files)
Update: theory --update-bundles (runs git pull)

Matching strategy:
  1. For each malware family name, grep YARA rule files for the
     family name in rule names, metadata, and string identifiers
  2. Parse matching rules for title, description, author, tags
  3. Build a GitHub URL for each rule file

Repo: https://github.com/Yara-Rules/rules
License: GNU-GPLv2
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

YARA_REPO_URL  = "https://github.com/Yara-Rules/rules.git"
YARA_REPO_PATH = Path(".cache/yara-rules-repo")
MAX_RULES_PER_FAMILY = 10


class YaraRulesCollector:
    """
    Searches the local Yara-Rules/rules clone for rules matching
    malware family names from the actor profile.

    On first use, clones the repo to .cache/yara-rules-repo/.
    Subsequent uses grep the local clone.
    """

    def __init__(self):
        self._repo_ready = False

    def _ensure_repo(self) -> bool:
        """Clone the Yara-Rules repo if not present. Return True if ready."""
        if self._repo_ready:
            return True

        if YARA_REPO_PATH.exists() and any(YARA_REPO_PATH.iterdir()):
            self._repo_ready = True
            return True

        self._print_clone_notice()
        YARA_REPO_PATH.parent.mkdir(parents=True, exist_ok=True)

        try:
            result = subprocess.run(
                [
                    "git", "clone",
                    "--depth", "1",
                    "--filter=blob:none",
                    "--no-tags",
                    YARA_REPO_URL,
                    str(YARA_REPO_PATH),
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                logger.error("YARA rules clone failed: %s", result.stderr)
                self._print_clone_failed(result.stderr)
                return False

            self._repo_ready = True
            self._print_clone_success()
            return True

        except subprocess.TimeoutExpired:
            logger.error("YARA rules clone timed out")
            return False
        except FileNotFoundError:
            logger.error("git not found -- cannot clone Yara-Rules repo")
            print(
                "\n  [YARA] git is required to clone the Yara-Rules repo.\n"
                "  Install git and run again, or run: theory --update-bundles\n",
                file=sys.stderr,
            )
            return False

    def update_repo(self) -> bool:
        """Pull latest changes. Called by --update-bundles."""
        if not YARA_REPO_PATH.exists():
            return self._ensure_repo()

        try:
            from rich.console import Console
            console = Console(stderr=True)
            console.print("[dim]  Updating YARA rules (git fetch + reset)...[/dim]")
        except ImportError:
            console = None
            print("  Updating YARA rules...", file=sys.stderr)

        fetch_result = subprocess.run(
            [
                "git", "-C", str(YARA_REPO_PATH),
                "fetch", "--depth=1", "--no-tags", "origin",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if fetch_result.returncode != 0:
            logger.error("YARA rules fetch failed: %s", fetch_result.stderr)
            return False

        reset_result = subprocess.run(
            [
                "git", "-C", str(YARA_REPO_PATH),
                "reset", "--hard", "origin/HEAD",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if reset_result.returncode != 0:
            logger.error("YARA rules reset failed: %s", reset_result.stderr)
            return False

        if console:
            console.print("[green]  ✓ YARA rules updated[/green]")
        else:
            print("  ✓ YARA rules updated", file=sys.stderr)
        return True

    def collect_for_malware_families(
        self,
        malware_names: list[str],
    ) -> dict[str, list[dict]]:
        """
        For each malware family name, return matching YARA rules.

        Returns:
            Dict mapping family_name -> list of rule dicts, e.g.:
            {
                "Emotet": [
                    {
                        "rule_name": "Emotet_Loader",
                        "description": "Detects Emotet loader binary",
                        "author": "JPCERT/CC",
                        "reference": "https://...",
                        "url": "https://github.com/Yara-Rules/rules/blob/master/...",
                        "tags": ["malware", "trojan"],
                        "path": "malware/Emotet_Loader.yar",
                    },
                ],
            }
        """
        if not self._ensure_repo():
            logger.warning("YARA rules repo not available -- skipping")
            return {}

        results: dict[str, list[dict]] = {}
        unique_names = list(dict.fromkeys(malware_names))

        logger.info("YARA: searching local repo for %d malware families", len(unique_names))

        for family in unique_names:
            rules = self._find_rules_for_family(family)
            if rules:
                results[family] = rules

        total = sum(len(v) for v in results.values())
        logger.info(
            "YARA: found %d rules across %d families",
            total, len(results),
        )
        return results

    def _find_rules_for_family(self, family_name: str) -> list[dict]:
        """
        Grep the local YARA repo for rules matching a malware family.
        Searches rule names, metadata strings, and identifiers.
        """
        if not YARA_REPO_PATH.exists():
            return []

        # Build grep pattern -- case-insensitive match on family name
        # Escape special regex chars in family names
        pattern = re.escape(family_name)

        try:
            result = subprocess.run(
                [
                    "grep",
                    "-rli",                    # recursive, list filenames, case-insensitive
                    "--include=*.yar",
                    "--include=*.yara",
                    pattern,
                    str(YARA_REPO_PATH),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            logger.warning("YARA grep timed out for %s", family_name)
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
            parsed_rules = _parse_yara_file(rule_file, family_name)
            rules.extend(parsed_rules)

        # Deduplicate by rule name
        seen_names: set[str] = set()
        unique_rules: list[dict] = []
        for rule in rules:
            name = rule.get("rule_name", "")
            if name and name not in seen_names:
                seen_names.add(name)
                unique_rules.append(rule)

        return unique_rules[:MAX_RULES_PER_FAMILY]

    # ------------------------------------------------------------------
    # User messaging
    # ------------------------------------------------------------------

    @staticmethod
    def _print_clone_notice() -> None:
        msg = (
            "\n  ℹ  YARA rules: cloning Yara-Rules/rules repository (one time only).\n"
            "     This takes ~1 minute and uses ~50MB of disk space.\n"
            "     After this, all YARA queries run instantly offline.\n"
            "     Location: .cache/yara-rules-repo/\n"
        )
        try:
            from rich.console import Console
            Console(stderr=True).print(f"[cyan]{msg}[/cyan]")
        except ImportError:
            print(msg, file=sys.stderr)

    @staticmethod
    def _print_clone_success() -> None:
        msg = "  ✓ Yara-Rules repo cloned -- YARA queries are now instant.\n"
        try:
            from rich.console import Console
            Console(stderr=True).print(f"[green]{msg}[/green]")
        except ImportError:
            print(msg, file=sys.stderr)

    @staticmethod
    def _print_clone_failed(error: str) -> None:
        msg = (
            f"\n  ✗ YARA rules clone failed: {error[:200]}\n"
            "    Run manually: git clone --depth 1 "
            "https://github.com/Yara-Rules/rules.git .cache/yara-rules-repo\n"
        )
        try:
            from rich.console import Console
            Console(stderr=True).print(f"[red]{msg}[/red]")
        except ImportError:
            print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# YARA file parsing (stdlib only)
# ---------------------------------------------------------------------------

def _parse_yara_file(path: Path, family_name: str) -> list[dict]:
    """
    Parse a YARA rule file and extract rules mentioning the family.

    Returns a list of rule dicts for rules whose name or metadata
    references the family name.
    """
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    rules: list[dict] = []
    family_lower = family_name.lower()

    # Split into individual rules by matching 'rule <name>' blocks
    # YARA rules start with: rule <name> [: <tags>] {
    rule_pattern = re.compile(
        r'^rule\s+(\w+)\s*(?::\s*([^\{]+))?\s*\{',
        re.MULTILINE,
    )

    for match in rule_pattern.finditer(content):
        rule_name = match.group(1)
        rule_tags_raw = (match.group(2) or "").strip()
        rule_tags = [t.strip() for t in rule_tags_raw.split() if t.strip()]

        # Find the rule's body (from { to matching })
        start = match.end()
        brace_count = 1
        pos = start
        while pos < len(content) and brace_count > 0:
            if content[pos] == '{':
                brace_count += 1
            elif content[pos] == '}':
                brace_count -= 1
            pos += 1
        rule_body = content[start:pos]

        # Check if this specific rule references the family
        if family_lower not in rule_name.lower() and family_lower not in rule_body.lower():
            continue

        # Extract metadata
        meta = _extract_metadata(rule_body)

        # Build GitHub URL
        try:
            rel = path.relative_to(YARA_REPO_PATH)
        except ValueError:
            rel = path.name
        url = f"https://github.com/Yara-Rules/rules/blob/master/{rel}"

        rules.append({
            "rule_name":   rule_name,
            "description": meta.get("description", ""),
            "author":      meta.get("author", ""),
            "reference":   meta.get("reference", meta.get("url", "")),
            "date":        meta.get("date", meta.get("last_modified", "")),
            "url":         url,
            "tags":        rule_tags,
            "path":        str(rel),
        })

    return rules


def _extract_metadata(rule_body: str) -> dict[str, str]:
    """
    Extract key-value pairs from a YARA rule's meta: section.

    Handles both quoted and unquoted values:
        description = "Detects something"
        author = "Somebody"
        hash1 = "abc123"
    """
    meta: dict[str, str] = {}

    meta_match = re.search(r'meta\s*:', rule_body)
    if not meta_match:
        return meta

    # Find the meta section (ends at 'strings:', 'condition:', or another section)
    meta_start = meta_match.end()
    section_end = re.search(r'\b(strings|condition)\s*:', rule_body[meta_start:])
    if section_end:
        meta_text = rule_body[meta_start:meta_start + section_end.start()]
    else:
        meta_text = rule_body[meta_start:]

    # Parse key = value pairs
    kv_pattern = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
    for m in kv_pattern.finditer(meta_text):
        key = m.group(1).lower()
        val = m.group(2).strip()
        if key not in meta:  # first occurrence wins
            meta[key] = val

    return meta
