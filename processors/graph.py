"""
processors/graph.py
--------------------
Persistent correlation graph.

Every `theory --actor X` run produces a fully correlated profile for ONE
actor (see processors/correlator.py) — but that profile lives for the
length of one process and is then serialized to a report and discarded.
There is no memory *across* runs: if last week's APT28 query reported the
IP 1.2.3.4, and today's Scattered Spider query reports that same IP from a
different source, THEORY has no way to know the two runs ever touched the
same infrastructure — and no way to answer a standalone question like
"what do we know about 1.2.3.4?" without re-running every actor by hand.

This module is that memory. It is a small, local, JSON-persisted graph of
typed nodes (actor / ioc / technique / malware / cve / campaign) and the
edges between them, built up incrementally as `theory --actor` runs happen.
It is append-only in spirit — every write is an upsert that unions sources
and advances last_seen rather than overwriting history.

It backs three CLI query modes:
  - `theory --ioc VALUE`         -> query_ioc()        standalone lookup
  - `theory --technique ID`      -> query_technique()  standalone lookup
  - `theory --actor X --ioc Y`   -> find_connection()  cross-correlative /
    `theory --actor X --technique T`                   multi-axis query:
                                     is there a KNOWN connection between
                                     X and Y, and through what — not two
                                     independent reports stapled together.

Design notes
------------
- Nodes are identified by (node_type, canonical_id). Actor canonical names
  reuse collectors.cisa_advisories.resolve_canonical so the graph agrees
  with the identity the rest of THEORY already uses; IOC/technique/
  malware/CVE ids are case- and whitespace-normalized.
- Edges are stored both directions (A->B and B->A) for O(1) neighbor
  lookups, each carrying a `relation` label and provenance: which
  source(s) ever reported the link, and first/last seen dates.
- This is *not* a replacement for processors/correlator.py. The
  correlator builds rich, same-run intelligence (kill chains, priority
  actions, coverage). The graph is cross-run identity + connectivity
  only: "have we ever seen these two things together, and how."
- Pure stdlib (json + pathlib + dataclasses). No new dependency, and
  nothing here talks to the network. Stored at output/graph/graph.json —
  output/ is already a gitignored runtime-artifact directory, so no new
  .gitignore entry is needed. Flat JSON is plenty for the hundreds-to-low-
  thousands of actor runs a single analyst accumulates; if this ever
  needs to scale past that, the on-disk format can move to sqlite
  without changing any of the public functions below.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

GRAPH_PATH = Path("output/graph/graph.json")

NODE_TYPES = frozenset({"actor", "ioc", "technique", "malware", "cve", "campaign"})


# ---------------------------------------------------------------------------
# Canonicalization — every node type gets one agreed-upon identity string
# ---------------------------------------------------------------------------

def _canon_actor(name: str) -> str:
    try:
        from collectors.cisa_advisories import resolve_canonical
        return resolve_canonical(name)
    except Exception:
        return name.strip()


def _canon_ioc(value: str) -> str:
    return value.strip().lower()


def _canon_technique(tid: str) -> str:
    return tid.strip().upper()


def _canon_malware(name: str) -> str:
    return name.strip().lower()


def _canon_cve(cve_id: str) -> str:
    return cve_id.strip().upper()


def _canon_campaign(name: str) -> str:
    return name.strip().lower()


_CANON = {
    "actor":     _canon_actor,
    "ioc":       _canon_ioc,
    "technique": _canon_technique,
    "malware":   _canon_malware,
    "cve":       _canon_cve,
    "campaign":  _canon_campaign,
}


def canonical_id(node_type: str, raw_id: str) -> str:
    if node_type not in NODE_TYPES:
        raise ValueError(f"Unknown graph node type: {node_type!r} (expected one of {sorted(NODE_TYPES)})")
    return _CANON[node_type](raw_id)


def _node_key(node_type: str, canonical: str) -> str:
    return f"{node_type}:{canonical}"


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# GraphStore
# ---------------------------------------------------------------------------

@dataclass
class GraphStore:
    """A small, flat, JSON-persisted node/edge graph.

    nodes: {node_key: {"type", "id", "label", "first_seen", "last_seen",
                        "sources": [...], "meta": {...}}}
    edges: {node_key: {other_node_key: {"relation", "sources": [...],
                                         "first_seen", "last_seen"}}}
    """
    path:  Path                        = field(default_factory=lambda: GRAPH_PATH)
    nodes: dict[str, dict[str, Any]]   = field(default_factory=dict)
    edges: dict[str, dict[str, dict]]  = field(default_factory=dict)

    # ── persistence ──────────────────────────────────────────────────
    @classmethod
    def load(cls, path: Path | None = None) -> "GraphStore":
        path = path or GRAPH_PATH
        if not path.exists():
            return cls(path=path)
        try:
            raw = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Graph store at %s unreadable (%s) — starting fresh", path, exc)
            return cls(path=path)
        return cls(path=path, nodes=raw.get("nodes", {}), edges=raw.get("edges", {}))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"nodes": self.nodes, "edges": self.edges}, indent=2, sort_keys=True))
        tmp.replace(self.path)  # atomic on POSIX; avoids a half-written graph on crash

    # ── mutation (always upsert — never destroys prior provenance) ────
    def upsert_node(
        self,
        node_type: str,
        raw_id:    str,
        label:     str = "",
        source:    str = "",
        meta:      dict[str, Any] | None = None,
    ) -> str:
        cid   = canonical_id(node_type, raw_id)
        key   = _node_key(node_type, cid)
        today = _today()

        node = self.nodes.get(key)
        if node is None:
            node = {
                "type":       node_type,
                "id":         cid,
                "label":      label or raw_id,
                "first_seen": today,
                "last_seen":  today,
                "sources":    [],
                "meta":       dict(meta or {}),
            }
            self.nodes[key] = node
        else:
            node["last_seen"] = today
            if label and not node.get("label"):
                node["label"] = label
            if meta:
                node["meta"].update(meta)

        if source and source not in node["sources"]:
            node["sources"].append(source)

        return key

    def upsert_edge(self, key_a: str, key_b: str, relation: str, source: str = "") -> None:
        if key_a == key_b:
            return
        today = _today()
        for a, b in ((key_a, key_b), (key_b, key_a)):
            bucket = self.edges.setdefault(a, {})
            edge   = bucket.get(b)
            if edge is None:
                edge = {"relation": relation, "sources": [], "first_seen": today, "last_seen": today}
                bucket[b] = edge
            else:
                edge["last_seen"] = today
            if source and source not in edge["sources"]:
                edge["sources"].append(source)

    # ── reads ───────────────────────────────────────────────────────
    def get_node(self, node_type: str, raw_id: str) -> dict[str, Any] | None:
        return self.nodes.get(_node_key(node_type, canonical_id(node_type, raw_id)))

    def neighbors(self, key: str) -> dict[str, dict]:
        return self.edges.get(key, {})


# ---------------------------------------------------------------------------
# Ingestion — fold one correlated actor profile into the graph
# ---------------------------------------------------------------------------

def ingest_profile(profile: dict[str, Any], store: GraphStore | None = None) -> GraphStore:
    """Fold one correlated actor profile into the persistent graph.

    Call this once per successful `theory --actor` run, after
    processors.correlator.correlate() has already run. Safe to call
    repeatedly for the same actor/data — every write is an upsert, so
    re-ingesting only unions sources and advances last_seen, it never
    duplicates nodes or edges.

    Owns (loads + saves) its own GraphStore when none is passed in, so
    callers can simply do: `from processors.graph import ingest_profile;
    ingest_profile(profile)` and not think about persistence at all.
    """
    owns_store = store is None
    store = store or GraphStore.load()

    actor_name = (profile.get("actor_name") or "").strip()
    if not actor_name:
        return store
    motivations = [m for m in (profile.get("motivations") or []) if m]
    actor_key = store.upsert_node(
        "actor", actor_name, label=actor_name,
        meta={"motivations": motivations} if motivations else None,
    )

    for ioc in (profile.get("indicators") or []):
        value = (ioc.get("value") or "").strip()
        if not value:
            continue
        ioc_sources = ioc.get("sources") or []
        ioc_key = ""
        for src in (ioc_sources or [""]):
            ioc_key = store.upsert_node(
                "ioc", value, label=value, source=src,
                meta={"ioc_type": ioc.get("type", "")},
            )
        for src in ioc_sources:
            store.upsert_edge(actor_key, ioc_key, "reported_ioc", source=src)
        if not ioc_sources:
            store.upsert_edge(actor_key, ioc_key, "reported_ioc")

        family = (ioc.get("malware_family") or ioc.get("malware") or "").strip()
        if family:
            mal_key = store.upsert_node("malware", family, label=family)
            store.upsert_edge(ioc_key, mal_key, "associated_with")

    for t in (profile.get("techniques") or []):
        tid = (t.get("technique_id") or "").strip()
        if not tid:
            continue
        tech_sources = t.get("sources") or []
        tech_key = ""
        for src in (tech_sources or [""]):
            tech_key = store.upsert_node(
                "technique", tid, source=src,
                label=t.get("technique_name") or t.get("name") or tid,
            )
        for src in tech_sources:
            store.upsert_edge(actor_key, tech_key, "uses_technique", source=src)
        if not tech_sources:
            store.upsert_edge(actor_key, tech_key, "uses_technique")

    for m in (profile.get("malware") or []):
        name = (m.get("name") or "").strip()
        if not name:
            continue
        mal_key = store.upsert_node("malware", name, label=name, meta={"malware_type": m.get("type", "")})
        store.upsert_edge(actor_key, mal_key, "uses_malware")

    for cve in (profile.get("cves") or []):
        cid = (cve.get("cve_id") or "").strip()
        if not cid:
            continue
        cve_sources = cve.get("sources") or []
        cve_key = ""
        for src in (cve_sources or [""]):
            cve_key = store.upsert_node(
                "cve", cid, label=cid, source=src,
                meta={"kev_confirmed": bool(cve.get("kev_confirmed"))},
            )
        for src in cve_sources:
            store.upsert_edge(actor_key, cve_key, "attributed_cve", source=src)
        if not cve_sources:
            store.upsert_edge(actor_key, cve_key, "attributed_cve")

    for c in (profile.get("campaigns") or []):
        name = (c.get("name") or "").strip()
        if not name:
            continue
        camp_key = store.upsert_node("campaign", name, label=name)
        store.upsert_edge(actor_key, camp_key, "ran_campaign")

    if owns_store:
        store.save()
    return store


# ---------------------------------------------------------------------------
# Standalone queries — theory --ioc / theory --technique
# ---------------------------------------------------------------------------

def _linked_entry(store: GraphStore, other_key: str, edge: dict) -> dict[str, Any] | None:
    other = store.nodes.get(other_key)
    if not other:
        return None
    return {
        "type":       other["type"],
        "id":         other["id"],
        "label":      other.get("label", other["id"]),
        "relation":   edge["relation"],
        "sources":    edge["sources"],
        "first_seen": edge["first_seen"],
        "last_seen":  edge["last_seen"],
    }


def query_ioc(value: str, store: GraphStore | None = None) -> dict[str, Any]:
    """Standalone lookup: what does THEORY know about this indicator,
    across every actor run that has ever touched it?"""
    store = store or GraphStore.load()
    node = store.get_node("ioc", value)
    if node is None:
        return {"found": False, "value": value.strip()}

    key = _node_key("ioc", node["id"])
    buckets: dict[str, list[dict]] = {"actor": [], "malware": [], "technique": [], "cve": [], "campaign": []}
    for other_key, edge in store.neighbors(key).items():
        entry = _linked_entry(store, other_key, edge)
        if entry and entry["type"] in buckets:
            buckets[entry["type"]].append(entry)

    return {
        "found":              True,
        "value":              node["id"],
        "ioc_type":           node.get("meta", {}).get("ioc_type", ""),
        "first_seen":         node["first_seen"],
        "last_seen":          node["last_seen"],
        "sources":            node["sources"],
        "linked_actors":      buckets["actor"],
        "linked_malware":     buckets["malware"],
        "linked_techniques":  buckets["technique"],
        "linked_cves":        buckets["cve"],
    }


def query_attack_type(label: str, store: GraphStore | None = None) -> dict[str, Any]:
    """Standalone lookup: which actors and malware families does THEORY
    have on record for a given attack-type label?

    Deliberately grounded in only two fields THEORY already collects
    reliably, rather than a separate, hand-built attack-type taxonomy
    mapping attack types to techniques/CVEs — that kind of mapping is
    fuzzy and easy to get subtly wrong, which matters a lot for a tool
    people use operationally. Instead:

      - actor.motivations  (CommonSchema's canonical field: financial,
        espionage, hacktivism, destruction, unknown)
      - malware.type       (freeform, but consistently populated by
        collectors: ransomware, backdoor, trojan, loader, wiper, ...)

    Matching is case-insensitive substring on both, so "ransom" matches
    malware typed "ransomware", and "espionage" matches an actor whose
    motivations list contains "espionage".
    """
    store = store or GraphStore.load()
    needle = label.strip().lower()
    if not needle:
        return {"label": label, "matched_actors": [], "matched_malware": []}

    matched_actors:  list[dict[str, Any]] = []
    matched_malware: list[dict[str, Any]] = []

    for key, node in store.nodes.items():
        if node["type"] == "actor":
            motivations = [m.lower() for m in (node.get("meta", {}).get("motivations") or [])]
            if any(needle in m or m in needle for m in motivations):
                matched_actors.append({"id": node["id"], "label": node.get("label", node["id"])})
        elif node["type"] == "malware":
            mtype = (node.get("meta", {}).get("malware_type") or "").lower()
            if mtype and needle in mtype:
                entry = {"id": node["id"], "label": node.get("label", node["id"]), "malware_type": mtype}
                matched_malware.append(entry)
                # Pull in actors linked to this malware too — an actor whose
                # only signal for this attack type is "uses ransomware X",
                # not a motivation tag, still belongs in the answer.
                for other_key, edge in store.neighbors(key).items():
                    other = store.nodes.get(other_key)
                    if other and other["type"] == "actor" and not any(
                        a["id"] == other["id"] for a in matched_actors
                    ):
                        matched_actors.append({"id": other["id"], "label": other.get("label", other["id"])})

    return {
        "label":           label.strip(),
        "matched_actors":  matched_actors,
        "matched_malware": matched_malware,
    }


def query_actor(actor_name: str, store: GraphStore | None = None) -> dict[str, Any]:
    """Standalone lookup: everything THEORY's persistent graph has ever
    recorded for this actor, across every past run — the graph-backed
    counterpart to a full `theory --actor` dossier, but instant (no
    collection) and scoped to whatever has already been ingested."""
    store = store or GraphStore.load()
    node = store.get_node("actor", actor_name)
    if node is None:
        return {"found": False, "actor_name": canonical_id("actor", actor_name)}

    key = _node_key("actor", node["id"])
    buckets: dict[str, list[dict]] = {"ioc": [], "technique": [], "malware": [], "cve": [], "campaign": []}
    for other_key, edge in store.neighbors(key).items():
        entry = _linked_entry(store, other_key, edge)
        if entry and entry["type"] in buckets:
            buckets[entry["type"]].append(entry)

    return {
        "found":            True,
        "actor_name":       node["id"],
        "first_seen":       node["first_seen"],
        "last_seen":        node["last_seen"],
        "linked_iocs":       buckets["ioc"],
        "linked_techniques": buckets["technique"],
        "linked_malware":    buckets["malware"],
        "linked_cves":       buckets["cve"],
        "linked_campaigns":  buckets["campaign"],
    }


def query_technique(technique_id: str, store: GraphStore | None = None) -> dict[str, Any]:
    """Standalone lookup: which actors (and which CVEs) does THEORY have
    on record for this ATT&CK technique, across every past run?"""
    store = store or GraphStore.load()
    node = store.get_node("technique", technique_id)
    if node is None:
        return {"found": False, "technique_id": technique_id.strip().upper()}

    key = _node_key("technique", node["id"])
    buckets: dict[str, list[dict]] = {"actor": [], "cve": [], "malware": []}
    for other_key, edge in store.neighbors(key).items():
        entry = _linked_entry(store, other_key, edge)
        if entry and entry["type"] in buckets:
            buckets[entry["type"]].append(entry)

    return {
        "found":          True,
        "technique_id":   node["id"],
        "label":          node.get("label", node["id"]),
        "first_seen":     node["first_seen"],
        "last_seen":      node["last_seen"],
        "linked_actors":  buckets["actor"],
        "linked_cves":    buckets["cve"],
        "linked_malware": buckets["malware"],
    }


def query_cve(cve_id: str, store: GraphStore | None = None) -> dict[str, Any]:
    """Standalone lookup: which actors (and techniques) does THEORY have
    on record as attributed to this CVE, across every past run?

    Symmetric with query_ioc/query_technique/query_actor — completes the
    multi-axis query set (`--ioc`/`--technique`/`--attack-type`/`--cve`)
    so a CVE can be looked up the same way an indicator or technique can,
    without re-running collection."""
    store = store or GraphStore.load()
    node = store.get_node("cve", cve_id)
    if node is None:
        return {"found": False, "cve_id": canonical_id("cve", cve_id)}

    key = _node_key("cve", node["id"])
    buckets: dict[str, list[dict]] = {"actor": [], "technique": [], "malware": [], "campaign": []}
    for other_key, edge in store.neighbors(key).items():
        entry = _linked_entry(store, other_key, edge)
        if entry and entry["type"] in buckets:
            buckets[entry["type"]].append(entry)

    return {
        "found":             True,
        "cve_id":            node["id"],
        "kev_confirmed":     bool(node.get("meta", {}).get("kev_confirmed")),
        "first_seen":        node["first_seen"],
        "last_seen":         node["last_seen"],
        "sources":           node["sources"],
        "linked_actors":     buckets["actor"],
        "linked_techniques": buckets["technique"],
        "linked_malware":    buckets["malware"],
        "linked_campaigns":  buckets["campaign"],
    }


# ---------------------------------------------------------------------------
# Cross-correlative / multi-axis query — theory --actor X --ioc Y
# ---------------------------------------------------------------------------

def find_connection(
    entity_a: tuple[str, str],
    entity_b: tuple[str, str],
    store: GraphStore | None = None,
) -> dict[str, Any]:
    """Is there a KNOWN connection between two entities, and through what?

    This backs multi-flag queries like `theory --actor APT28 --ioc
    1.1.1.1`: the point of that command is not two independent reports
    stapled together (the actor dossier, and a separate IOC lookup) — the
    user is asking a single question, "is this IOC connected to this
    actor in anything THEORY has ever recorded." This checks, in order:

      1. A direct edge between the two entities (e.g. the actor's profile
         itself reported this exact IOC).
      2. A shared one-hop neighbor — a "bridge" node both entities connect
         to (e.g. actor --uses_malware--> X, ioc --associated_with--> X).

    entity_a / entity_b: (node_type, raw_id) tuples, e.g.
    ("actor", "APT28"), ("ioc", "1.1.1.1"), ("technique", "T1566").
    """
    store = store or GraphStore.load()
    type_a, id_a = entity_a
    type_b, id_b = entity_b

    node_a = store.get_node(type_a, id_a)
    node_b = store.get_node(type_b, id_b)
    if node_a is None or node_b is None:
        return {
            "connected": False,
            "reason":    "one_or_both_unknown",
            "entity_a":  {"type": type_a, "id": canonical_id(type_a, id_a), "known": node_a is not None},
            "entity_b":  {"type": type_b, "id": canonical_id(type_b, id_b), "known": node_b is not None},
        }

    key_a = _node_key(type_a, node_a["id"])
    key_b = _node_key(type_b, node_b["id"])

    direct = store.neighbors(key_a).get(key_b)
    if direct:
        return {
            "connected":  True,
            "path":       "direct",
            "relation":   direct["relation"],
            "sources":    direct["sources"],
            "first_seen": direct["first_seen"],
            "last_seen":  direct["last_seen"],
            "entity_a":   {"type": type_a, "id": node_a["id"]},
            "entity_b":   {"type": type_b, "id": node_b["id"]},
        }

    neighbors_a = set(store.neighbors(key_a).keys())
    neighbors_b = set(store.neighbors(key_b).keys())
    shared      = neighbors_a & neighbors_b
    if shared:
        bridges = []
        for shared_key in sorted(shared):
            bridge = store.nodes.get(shared_key)
            if bridge:
                bridges.append({
                    "type":  bridge["type"],
                    "id":    bridge["id"],
                    "label": bridge.get("label", bridge["id"]),
                })
        return {
            "connected": True,
            "path":      "shared_neighbor",
            "bridges":   bridges,
            "entity_a":  {"type": type_a, "id": node_a["id"]},
            "entity_b":  {"type": type_b, "id": node_b["id"]},
        }

    return {
        "connected": False,
        "reason":    "no_path_found",
        "entity_a":  {"type": type_a, "id": node_a["id"]},
        "entity_b":  {"type": type_b, "id": node_b["id"]},
    }
