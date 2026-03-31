"""
collectors/mitre_attack.py
--------------------------
Fetches threat actor data from MITRE ATT&CK.

Resolution order (stops at first success):
  1. Local bundle  — .cache/enterprise-attack.json
  2. TAXII 2.1     — attack-taxii.mitre.org (live, may 429)

To pre-populate the local bundle:
  curl -L https://github.com/mitre-attack/attack-stix-data/raw/master/enterprise-attack/enterprise-attack.json \
       -o .cache/enterprise-attack.json
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from collectors.base import BaseCollector

logger = logging.getLogger(__name__)

try:
    from attackcti import attack_client  # type: ignore
    _ATTACKCTI_AVAILABLE = True
except ImportError:
    _ATTACKCTI_AVAILABLE = False
    logger.warning("attackcti not installed. Provide a local bundle or install attackcti.")

SOURCE_ID   = "mitre_attack"
BUNDLE_PATH = Path(".cache/enterprise-attack.json")
MAX_RETRIES = 2
RETRY_DELAY = 3

# ---------------------------------------------------------------------------
# Known first-seen dates and motivations per group (supplements STIX data)
# STIX intrusion-set objects don't reliably carry these fields.
# Sources: MITRE ATT&CK group pages, public threat reports.
# ---------------------------------------------------------------------------
_GROUP_METADATA: dict[str, dict] = {
    "G0007": {"first_seen": "2004", "motivations": ["espionage"],          "origin": "Russia"},
    "G0016": {"first_seen": "2008", "motivations": ["espionage"],          "origin": "Russia"},
    "G0032": {"first_seen": "2009", "motivations": ["espionage", "financial crime"], "origin": "North Korea"},
    "G0045": {"first_seen": "2009", "motivations": ["espionage"],          "origin": "China"},
    "G0096": {"first_seen": "2012", "motivations": ["espionage", "financial crime"], "origin": "China"},
    "G0034": {"first_seen": "2009", "motivations": ["espionage", "destructive"], "origin": "Russia"},
    "G0010": {"first_seen": "2004", "motivations": ["espionage"],          "origin": "Russia"},
    "G0064": {"first_seen": "2013", "motivations": ["espionage"],          "origin": "Iran"},
    "G0049": {"first_seen": "2014", "motivations": ["espionage"],          "origin": "Iran"},
    "G0094": {"first_seen": "2012", "motivations": ["espionage"],          "origin": "North Korea"},
    "G0046": {"first_seen": "2013", "motivations": ["financial crime"],    "origin": "Eastern Europe"},
    "G1017": {"first_seen": "2021", "motivations": ["espionage"],          "origin": "China"},
}


class MitreAttackCollector(BaseCollector):

    SOURCE_ID = SOURCE_ID

    def query(self, actor_name: str) -> dict | None:
        return self.collect(actor_name)

    def collect(self, actor_name: str) -> dict[str, Any] | None:
        client = self._get_client()
        if client is None:
            return None

        actor_obj = self._resolve_actor(client, actor_name)
        if actor_obj is None:
            logger.warning("Actor %r not found in MITRE ATT&CK.", actor_name)
            return None

        logger.info("Resolved: %s (%s)", actor_obj.name, actor_obj.id)

        techniques = self._retry(self._get_techniques, client, actor_obj)
        malware    = self._retry(self._get_malware,    client, actor_obj)
        campaigns  = self._retry(self._get_campaigns,  client, actor_obj)

        return self._build_schema(actor_obj, techniques, malware, campaigns)

    # ------------------------------------------------------------------
    # Client init
    # ------------------------------------------------------------------

    def _get_client(self):
        if BUNDLE_PATH.exists():
            logger.info("Loading ATT&CK from local bundle: %s", BUNDLE_PATH)
            try:
                return _LocalBundleClient(BUNDLE_PATH)
            except Exception as exc:
                logger.warning("Local bundle load failed: %s — falling back to TAXII.", exc)

        if not _ATTACKCTI_AVAILABLE:
            logger.error("No local bundle and attackcti not installed.")
            return None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                return attack_client()
            except Exception as exc:
                if "429" in str(exc) and attempt < MAX_RETRIES:
                    logger.warning("TAXII 429 — retrying in %ds…", RETRY_DELAY)
                    time.sleep(RETRY_DELAY)
                else:
                    logger.error("ATT&CK client init failed: %s", exc)
                    return None
        return None

    @staticmethod
    def _retry(fn, client, actor_obj, retries: int = MAX_RETRIES) -> list:
        for attempt in range(1, retries + 1):
            try:
                return fn(client, actor_obj)
            except Exception as exc:
                if "429" in str(exc) and attempt < retries:
                    logger.warning("%s 429 — retry %d/%d…", fn.__name__, attempt, retries)
                    time.sleep(RETRY_DELAY)
                else:
                    logger.warning("%s failed: %s", fn.__name__, exc)
                    return []
        return []

    # ------------------------------------------------------------------
    # Actor resolution
    # ------------------------------------------------------------------

    def _resolve_actor(self, client, name: str):
        name_lower = name.strip().lower()
        try:
            groups = client.get_groups()
        except Exception as exc:
            logger.error("get_groups() failed: %s", exc)
            return None

        for group in groups:
            if (getattr(group, "name", "") or "").lower() == name_lower:
                return group
            aliases = getattr(group, "aliases", []) or []
            if any((a or "").lower() == name_lower for a in aliases):
                return group
        return None

    # ------------------------------------------------------------------
    # Data hydration
    # ------------------------------------------------------------------

    @staticmethod
    def _get_techniques(client, actor_obj) -> list[dict]:
        results: list[dict] = []
        raw = client.get_techniques_used_by_group(actor_obj)
        for entry in raw:
            t   = entry.get("object", entry) if isinstance(entry, dict) else entry
            tid = MitreAttackCollector._extract_tid(t)
            if not tid:
                continue

            # Pull detection from the technique object directly
            detection = ""
            for attr in ("x_mitre_detection", "detection"):
                val = None
                try:
                    val = getattr(t, attr, None)
                except Exception:
                    pass
                if not val and isinstance(t, _Obj):
                    val = t._d.get(attr)
                if val:
                    detection = str(val)
                    break

            results.append({
                "technique_id":   tid,
                "technique_name": getattr(t, "name", "") or "",
                "tactic":         (MitreAttackCollector._extract_tactics(t) or [""])[0],
                "tactics":        MitreAttackCollector._extract_tactics(t),
                "description":    _truncate(getattr(t, "description", "") or "", 800),
                "detection":      _truncate(detection, 600),
                "sources":        [SOURCE_ID],
            })
        return results

    @staticmethod
    def _get_malware(client, actor_obj) -> list[dict]:
        results: list[dict] = []
        raw = client.get_software_used_by_group(actor_obj)
        for entry in raw:
            sw   = entry.get("object", entry) if isinstance(entry, dict) else entry
            name = getattr(sw, "name", "") or ""
            if not name:
                continue
            desc = getattr(sw, "description", "") or ""
            results.append({
                "name":        name,
                "type":        (getattr(sw, "labels", None) or ["malware"])[0],
                "description": _truncate(_strip_markdown_links(desc), 400),
            })
        return results

    @staticmethod
    def _get_campaigns(client, actor_obj) -> list[dict]:
        results: list[dict] = []
        try:
            raw = client.get_campaigns_used_by_group(actor_obj)
        except AttributeError:
            return results
        for entry in raw:
            c    = entry.get("object", entry) if isinstance(entry, dict) else entry
            name = getattr(c, "name", "") or ""
            if not name:
                continue
            results.append({
                "name":        name,
                "description": _truncate(getattr(c, "description", "") or "", 400),
                "first_seen":  getattr(c, "first_seen", None),
                "last_seen":   getattr(c, "last_seen", None),
            })
        return results

    # ------------------------------------------------------------------
    # Schema builder
    # ------------------------------------------------------------------

    def _build_schema(self, actor_obj, techniques, malware, campaigns) -> dict:
        actor_name = getattr(actor_obj, "name", "") or ""
        aliases    = [a for a in (getattr(actor_obj, "aliases", []) or [])
                      if (a or "").lower() != actor_name.lower()]
        gid        = self._extract_mitre_group_id(actor_obj)

        # Pull enriched metadata from the supplement table if available
        meta       = _GROUP_METADATA.get(gid, {})

        return {
            "actor_name":  actor_name,
            "source_id":   SOURCE_ID,
            "aliases":     aliases,
            "description": _truncate(_strip_markdown_links(
                               getattr(actor_obj, "description", "") or ""), 1200),
            "origin":      meta.get("origin") or self._infer_origin(actor_obj),
            "first_seen":  meta.get("first_seen") or self._extract_first_seen(actor_obj),
            "motivations": meta.get("motivations") or self._extract_motivations(actor_obj),
            "techniques":  techniques,
            "indicators":  [],
            "malware":     malware,
            "campaigns":   campaigns,
            "sectors":     [],
            "raw_source":  "MITRE ATT&CK Enterprise",
            "mitre_id":    gid,
        }

    # ------------------------------------------------------------------
    # Attribute utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_tid(t) -> str:
        for ref in (getattr(t, "external_references", []) or []):
            ext_id = getattr(ref, "external_id", "") or (
                ref.get("external_id", "") if isinstance(ref, dict) else "")
            if re.match(r"^T\d{4}(\.\d{3})?$", ext_id):
                return ext_id
        return ""

    @staticmethod
    def _extract_tactics(t) -> list[str]:
        tactics = []
        for phase in (getattr(t, "kill_chain_phases", []) or []):
            name = (getattr(phase, "phase_name", "")
                    or (phase.get("phase_name", "") if isinstance(phase, dict) else ""))
            if name:
                tactics.append(name.replace("-", " ").title())
        return tactics

    @staticmethod
    def _extract_first_seen(actor_obj) -> str:
        # Scan description for earliest 4-digit year
        desc  = getattr(actor_obj, "description", "") or ""
        years = re.findall(r"\b(19|20)\d{2}\b", desc)
        return min(years) if years else ""

    @staticmethod
    def _extract_motivations(actor_obj) -> list[str]:
        m = []
        primary = getattr(actor_obj, "primary_motivation", "") or ""
        if primary:
            m.append(primary)
        m.extend(getattr(actor_obj, "secondary_motivations", []) or [])
        return list(dict.fromkeys(m))

    @staticmethod
    def _infer_origin(actor_obj) -> str:
        hints = {
            "russia": "Russia", "soviet": "Russia",
            "china":  "China",  "prc": "China",
            "iran":   "Iran",
            "dprk":   "North Korea", "north korea": "North Korea",
        }
        for contrib in (getattr(actor_obj, "x_mitre_contributors", []) or []):
            for hint, country in hints.items():
                if hint in (contrib or "").lower():
                    return country
        desc = (getattr(actor_obj, "description", "") or "").lower()
        for hint, country in hints.items():
            if hint in desc:
                return country
        return ""

    @staticmethod
    def _extract_mitre_group_id(actor_obj) -> str:
        for ref in (getattr(actor_obj, "external_references", []) or []):
            ext_id = getattr(ref, "external_id", "") or (
                ref.get("external_id", "") if isinstance(ref, dict) else "")
            if re.match(r"^G\d{4}$", ext_id):
                return ext_id
        return ""


# ---------------------------------------------------------------------------
# Local bundle client
# ---------------------------------------------------------------------------

class _LocalBundleClient:
    """
    Reads enterprise-attack.json from disk.
    Duck-typed to match attackcti's interface.
    """

    def __init__(self, path: Path):
        raw  = json.loads(path.read_text(encoding="utf-8"))
        objs = raw.get("objects", [])
        self._by_id:   dict[str, _Obj]        = {o["id"]: _Obj(o) for o in objs}
        self._by_type: dict[str, list[_Obj]]  = {}
        for o in self._by_id.values():
            self._by_type.setdefault(o.type, []).append(o)
        # Relationship index: source_ref → list[_Obj]
        self._rels: dict[str, list[_Obj]] = {}
        for r in self._by_type.get("relationship", []):
            self._rels.setdefault(r.source_ref, []).append(r)

    def get_groups(self) -> list:
        return self._by_type.get("intrusion-set", [])

    def get_techniques_used_by_group(self, group) -> list[dict]:
        return self._related(group, "uses", {"attack-pattern"})

    def get_software_used_by_group(self, group) -> list[dict]:
        return self._related(group, "uses", {"tool", "malware"})

    def get_campaigns_used_by_group(self, group) -> list[dict]:
        return self._related(group, "attributed-to", {"campaign"}, reverse=True)

    def _related(self, source_obj, rel_type: str,
                 target_types: set[str], reverse: bool = False) -> list[dict]:
        results = []
        if reverse:
            for rel in self._by_type.get("relationship", []):
                if rel.relationship_type != rel_type:
                    continue
                if rel.target_ref != source_obj.id:
                    continue
                obj = self._by_id.get(rel.source_ref)
                if obj and obj.type in target_types and not getattr(obj, "revoked", False):
                    results.append({"object": obj, "relationship": rel})
        else:
            for rel in self._rels.get(source_obj.id, []):
                if rel.relationship_type != rel_type:
                    continue
                obj = self._by_id.get(rel.target_ref)
                if obj and obj.type in target_types and not getattr(obj, "revoked", False):
                    results.append({"object": obj, "relationship": rel})
        return results


class _Obj:
    """Attribute-access wrapper around a raw STIX dict."""

    __slots__ = ("_d",)

    def __init__(self, d: dict):
        object.__setattr__(self, "_d", d)

    def __getattr__(self, name: str):
        try:
            return object.__getattribute__(self, "_d")[name]
        except KeyError:
            raise AttributeError(name)

    def get(self, key, default=None):
        return object.__getattribute__(self, "_d").get(key, default)

    def __repr__(self):
        d = object.__getattribute__(self, "_d")
        return f"<_Obj type={d.get('type')} name={d.get('name')}>"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def _strip_markdown_links(text: str) -> str:
    """Convert [label](url) → label and bare (url) fragments → ''."""
    # [label](url) → label
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    # Leftover bare (url) at start of description (malformed STIX)
    text = re.sub(r"^\s*\(https?://[^)]+\)\s*", "", text)
    return text.strip()
