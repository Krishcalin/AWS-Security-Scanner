#!/usr/bin/env python3
"""aws_graph.py — minimal, dependency-free security graph for the AWS CNAPP.

An ARN-keyed typed property graph (nodes + directed edges) that the live scanner
projects its findings onto. Phase 1 populates the *identity subgraph* — IAM
principals, ``CAN_ASSUME`` trust edges, and ``CAN_PRIVESC_TO`` capability edges —
and runs bounded traversals to surface transitive privilege-escalation chains
(``userA → assume roleB → escalate to admin``).

Design goals:
  * **Zero third-party dependencies.** A deliberately networkx-shaped subset
    (``add_node`` / ``add_edge`` / ``out_edges`` / bounded ``reachable`` traversal /
    node-link serialization) so a later swap to networkx + Amazon Neptune is a
    drop-in rather than a rewrite.
  * **MERGE semantics** (Cartography-style): re-adding a node or edge updates it
    in place instead of duplicating, so repeated collection passes converge.
  * **graph.json is the Neptune migration seed** — ``to_dict()`` emits standard
    node-link JSON.

Node ``id`` is the resource ARN wherever one exists; synthetic ids (``Internet``,
``capability:admin:<account>``, ``principal:*``) cover the nodes AWS has no ARN for.
"""
from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Dict, List, Optional, Iterable


class SecurityGraph:
    """A directed, typed property graph. Not thread-safe (single-pass build)."""

    def __init__(self):
        self._nodes: Dict[str, Dict] = {}                       # id -> {id, kind, props}
        self._out: Dict[str, List[Dict]] = defaultdict(list)    # src -> [edge, ...]
        self._edge_index: set = set()                           # (src, dst, kind) dedupe

    # ── mutation (MERGE) ──────────────────────────────────────────────────────
    def add_node(self, node_id: str, kind: str, **props) -> Optional[str]:
        """Insert or update a node. A later concrete ``kind`` upgrades an earlier
        ``Unknown`` placeholder; non-None props are merged in."""
        if not node_id:
            return None
        n = self._nodes.get(node_id)
        if n is None:
            n = {"id": node_id, "kind": kind or "Unknown", "props": {}}
            self._nodes[node_id] = n
        elif kind and kind != "Unknown":
            n["kind"] = kind
        for k, v in props.items():
            if v is not None:
                n["props"][k] = v
        return node_id

    def add_edge(self, src: str, dst: str, kind: str, **props) -> bool:
        """Insert or update a directed edge ``src -[kind]-> dst``. Returns True
        only for a newly-created edge; a duplicate merges its props and returns
        False. Endpoints are auto-created as ``Unknown`` if absent."""
        if not src or not dst:
            return False
        if src not in self._nodes:
            self.add_node(src, "Unknown")
        if dst not in self._nodes:
            self.add_node(dst, "Unknown")
        key = (src, dst, kind)
        clean = {k: v for k, v in props.items() if v is not None}
        if key in self._edge_index:
            for e in self._out[src]:
                if e["dst"] == dst and e["kind"] == kind:
                    e["props"].update(clean)
                    break
            return False
        self._edge_index.add(key)
        self._out[src].append({"src": src, "dst": dst, "kind": kind, "props": clean})
        return True

    def merge(self, other: "SecurityGraph") -> None:
        """Fold another graph into this one (used to union per-account graphs)."""
        for n in other._nodes.values():
            self.add_node(n["id"], n["kind"], **n["props"])
        for lst in other._out.values():
            for e in lst:
                self.add_edge(e["src"], e["dst"], e["kind"], **e["props"])

    # ── queries ───────────────────────────────────────────────────────────────
    def node(self, node_id: str) -> Optional[Dict]:
        return self._nodes.get(node_id)

    def nodes(self, kind: Optional[str] = None) -> List[Dict]:
        return [n for n in self._nodes.values() if kind is None or n["kind"] == kind]

    def edges(self, kind: Optional[str] = None) -> List[Dict]:
        return [e for lst in self._out.values() for e in lst
                if kind is None or e["kind"] == kind]

    def out_edges(self, node_id: str, kinds: Optional[Iterable[str]] = None) -> List[Dict]:
        ks = set(kinds) if kinds else None
        return [e for e in self._out.get(node_id, []) if ks is None or e["kind"] in ks]

    def has_out_edge(self, node_id: str, kind: str) -> bool:
        return any(e["kind"] == kind for e in self._out.get(node_id, []))

    def reachable(self, start: str, edge_kinds: Optional[Iterable[str]],
                  max_hops: int = 4, edge_filter=None) -> Dict[str, List[str]]:
        """Bounded BFS from ``start`` over edges whose kind is in ``edge_kinds``
        (all kinds if None). ``edge_filter``, if given, is called with each edge
        dict and must return truthy for the edge to be traversed — used to walk
        only *unconditioned* edges (ignoring condition-guarded privesc/trust).
        Returns ``{node_id: shortest_path}`` (list of node ids ``start .. node``
        inclusive); ``start`` is excluded. Cycle-safe, capped at ``max_hops`` edges."""
        ks = set(edge_kinds) if edge_kinds else None
        seen = {start}
        out: Dict[str, List[str]] = {}
        q = deque([(start, [start])])
        while q:
            cur, path = q.popleft()
            if len(path) - 1 >= max_hops:
                continue
            for e in self._out.get(cur, []):
                if ks is not None and e["kind"] not in ks:
                    continue
                if edge_filter is not None and not edge_filter(e):
                    continue
                nxt = e["dst"]
                if nxt in seen:
                    continue
                seen.add(nxt)
                npath = path + [nxt]
                out[nxt] = npath
                q.append((nxt, npath))
        return out

    # ── serialization (node-link; the Neptune seed) ───────────────────────────
    def to_dict(self) -> Dict:
        return {
            "directed": True,
            "multigraph": False,
            # Reserved structural keys are written LAST so a stray prop named
            # id/kind/source/target can never clobber an endpoint (node-link format).
            "nodes": [{**n["props"], "id": n["id"], "kind": n["kind"]}
                      for n in self._nodes.values()],
            "edges": [{**e["props"], "source": e["src"], "target": e["dst"], "kind": e["kind"]}
                      for lst in self._out.values() for e in lst],
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "SecurityGraph":
        """Reconstruct a graph from node-link JSON — the exact inverse of
        :meth:`to_dict`. ``to_dict`` writes the reserved keys (``id``/``kind`` on
        nodes; ``source``/``target``/``kind`` on edges) LAST, so popping them here
        is loss-safe by construction: ``from_dict(to_dict(g)).to_dict() ==
        to_dict(g)``. ``add_node``/``add_edge`` MERGE semantics make re-loading
        idempotent. Tolerant of malformed rows (missing id/endpoints are skipped
        by the underlying mutators)."""
        g = cls()
        for n in d.get("nodes", []):
            props = {k: v for k, v in n.items() if k not in ("id", "kind")}
            g.add_node(n.get("id"), n.get("kind", "Unknown"), **props)
        for e in d.get("edges", []):
            props = {k: v for k, v in e.items() if k not in ("source", "target", "kind")}
            g.add_edge(e.get("source"), e.get("target"), e.get("kind", ""), **props)
        return g

    def save_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    def stats(self) -> Dict:
        nk: Dict[str, int] = defaultdict(int)
        ek: Dict[str, int] = defaultdict(int)
        for n in self._nodes.values():
            nk[n["kind"]] += 1
        edge_total = 0
        for lst in self._out.values():
            for e in lst:
                ek[e["kind"]] += 1
                edge_total += 1
        return {
            "nodes": len(self._nodes),
            "edges": edge_total,
            "node_kinds": dict(sorted(nk.items())),
            "edge_kinds": dict(sorted(ek.items())),
        }

    def __len__(self) -> int:
        return len(self._nodes)
