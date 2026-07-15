#!/usr/bin/env python3
"""
aws_graph_neptune.py — Amazon Neptune export for the CNAPP SecurityGraph
(Phase 6). PURE and stdlib-only: reads the in-memory graph through its public API
(``to_dict()``) and NEVER mutates it; ``aws_graph.py`` and ``aws_correlate.py``
are untouched. Emitting load files needs no boto3 — a box without boto3/gremlin
still produces valid Neptune load artifacts, exactly like ``--graph`` today.

Two mutually-incompatible load formats (never mix in one load job):
  * **Gremlin bulk CSV** (default) — one type-homogeneous CSV per node label and
    per edge label; headers ``~id,~label,prop:Type`` (vertices) and
    ``~id,~from,~to,~label,prop:Type`` (edges).
  * **openCypher UNWIND/MERGE** — idempotent upsert batches (nodes MERGE on
    ``~id``, edges MERGE on ``(src)-[:KIND]->(dst)``), params carrying native
    JSON types so CSV typing is sidestepped entirely.

Type fidelity is load-bearing, not cosmetic: ``aws_correlate.is_unconditioned``
reads ``conditioned``/``has_condition`` (Bool), ``_path_exploitability`` reads
``kev`` (Bool), ``exploit_available`` ("YES" String), ``epss`` (Double). The #1
exporter bug is that ``bool`` is a subclass of ``int`` — :func:`neptune_type`
tests ``bool`` FIRST so KEV never exports as an Int 0/1.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# The single list-valued property in the graph (CAN_PRIVESC_TO.rules) is
# scalarized to a ";"-joined String in BOTH dialects (arrays are illegal on
# Gremlin edges and awkward in openCypher CSV).
_LIST_PROPS = {"rules"}


def neptune_type(v) -> str:
    if isinstance(v, bool):              # MUST precede int (bool is a subclass)
        return "Bool"
    if isinstance(v, int):
        return "Long" if abs(v) > 2**31 - 1 else "Int"
    if isinstance(v, float):
        return "Double"
    return "String"


def fmt_scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def csv_field(v) -> str:
    """RFC-4180: quote and double internal quotes if the value contains a comma,
    quote, or newline."""
    s = fmt_scalar(v)
    if any(c in s for c in (",", '"', "\n", "\r")):
        return '"' + s.replace('"', '""') + '"'
    return s


def edge_id(src: str, kind: str, dst: str) -> str:
    h = hashlib.sha1(f"{src}\x1f{kind}\x1f{dst}".encode("utf-8")).hexdigest()
    return "e:" + h[:20]


def _scalarize(prop: str, value):
    if prop in _LIST_PROPS and isinstance(value, (list, tuple)):
        return ";".join(str(x) for x in value)
    return value


@dataclass(frozen=True)
class Col:
    prop: str
    type: str
    is_list: bool


@dataclass(frozen=True)
class GremlinBundle:
    vertex_files: Dict[str, str]     # label -> CSV text
    edge_files: Dict[str, str]       # label -> CSV text
    manifest: Dict


def _group(elements: List[dict], label_key: str) -> Dict[str, List[dict]]:
    groups: Dict[str, List[dict]] = {}
    for el in elements:
        groups.setdefault(el.get(label_key, "Unknown"), []).append(el)
    return groups


def plan_columns(elems: List[dict]) -> Dict[str, List[Col]]:
    """For a set of element dicts already grouped nowhere, return {label: [Col]}
    with ONE type per column. A prop whose values disagree on type across a label
    is coerced to String; the single list prop is scalarized to String."""
    by_label: Dict[str, Dict[str, str]] = {}
    reserved = {"id", "kind", "source", "target", "~id", "~label", "~from", "~to"}
    for el in elems:
        label = el.get("kind", "Unknown")
        cols = by_label.setdefault(label, {})
        for k, v in el.items():
            if k in reserved:
                continue
            v = _scalarize(k, v)
            t = "String" if k in _LIST_PROPS else neptune_type(v)
            if k in cols and cols[k] != t:
                cols[k] = "String"          # mixed types -> String
            else:
                cols.setdefault(k, t)
    return {label: [Col(p, t, p in _LIST_PROPS) for p, t in sorted(cols.items())]
            for label, cols in by_label.items()}


def to_gremlin_csv(graph, per_label: bool = True) -> GremlinBundle:
    """One type-homogeneous CSV per node kind and per edge kind. Deterministic:
    nodes sorted by id, edges by (src,kind,dst), columns alphabetical."""
    d = graph.to_dict()
    nodes = sorted(d["nodes"], key=lambda n: n["id"])
    edges = sorted(d["edges"], key=lambda e: (e["source"], e["kind"], e["target"]))

    node_cols = plan_columns(nodes)
    vertex_files: Dict[str, str] = {}
    for label, group in sorted(_group(nodes, "kind").items()):
        cols = node_cols.get(label, [])
        buf = io.StringIO()
        header = ["~id", "~label"] + [f"{c.prop}:{c.type}" for c in cols]
        buf.write(",".join(header) + "\n")
        for n in sorted(group, key=lambda x: x["id"]):
            row = [csv_field(n["id"]), csv_field(label)]
            for c in cols:
                v = _scalarize(c.prop, n.get(c.prop))
                row.append("" if v is None else csv_field(v))
            buf.write(",".join(row) + "\n")
        vertex_files[label] = buf.getvalue()

    edge_cols = plan_columns(edges)
    edge_files: Dict[str, str] = {}
    for label, group in sorted(_group(edges, "kind").items()):
        cols = edge_cols.get(label, [])
        buf = io.StringIO()
        header = ["~id", "~from", "~to", "~label"] + [f"{c.prop}:{c.type}" for c in cols]
        buf.write(",".join(header) + "\n")
        for e in sorted(group, key=lambda x: (x["source"], x["target"])):
            eid = edge_id(e["source"], label, e["target"])
            row = [csv_field(eid), csv_field(e["source"]), csv_field(e["target"]), csv_field(label)]
            for c in cols:
                v = _scalarize(c.prop, e.get(c.prop))
                row.append("" if v is None else csv_field(v))
            buf.write(",".join(row) + "\n")
        edge_files[label] = buf.getvalue()

    manifest = {"format": "gremlin-csv", "node_labels": sorted(vertex_files),
                "edge_labels": sorted(edge_files),
                "node_count": len(nodes), "edge_count": len(edges),
                "loader_hint": "updateSingleCardinalityProperties=true for idempotent reload"}
    return GremlinBundle(vertex_files=vertex_files, edge_files=edge_files, manifest=manifest)


def _props_of(el: dict, label_key: str) -> Dict:
    reserved = {"id", "kind", "source", "target"}
    return {k: _scalarize(k, v) for k, v in el.items()
            if k not in reserved and v is not None}


def to_opencypher_upsert(graph, batch: int = 200) -> List[Tuple[str, dict]]:
    """Idempotent openCypher UNWIND/MERGE upsert batches. Nodes MERGE on ~id then
    SET the label + props; edges MERGE both endpoints then the relationship.
    JSON params carry native bool/int/float/str, so no CSV typing is needed."""
    d = graph.to_dict()
    plan: List[Tuple[str, dict]] = []

    for label, group in sorted(_group(sorted(d["nodes"], key=lambda n: n["id"]), "kind").items()):
        rows = [{"id": n["id"], "props": _props_of(n, "kind")} for n in group]
        q = (f"UNWIND $rows AS row MERGE (n {{`~id`: row.id}}) "
             f"SET n:`{label}`, n += row.props")
        for i in range(0, len(rows), batch):
            plan.append((q, {"rows": rows[i:i + batch]}))

    edges_sorted = sorted(d["edges"], key=lambda e: (e["source"], e["kind"], e["target"]))
    for label, group in sorted(_group(edges_sorted, "kind").items()):
        rows = [{"src": e["source"], "dst": e["target"], "props": _props_of(e, "kind")}
                for e in group]
        q = (f"UNWIND $rows AS row MERGE (s {{`~id`: row.src}}) "
             f"MERGE (d {{`~id`: row.dst}}) MERGE (s)-[r:`{label}`]->(d) "
             f"SET r += row.props")
        for i in range(0, len(rows), batch):
            plan.append((q, {"rows": rows[i:i + batch]}))
    return plan


def load_graph(d: dict):
    """Reconstruct a SecurityGraph from node-link dict (round-trip inverse of
    ``to_dict``): ``load_graph(g.to_dict()).to_dict() == g.to_dict()``."""
    from aws_graph import SecurityGraph
    g = SecurityGraph()
    for n in d.get("nodes", []):
        props = {k: v for k, v in n.items() if k not in ("id", "kind")}
        g.add_node(n["id"], n.get("kind", "Unknown"), **props)
    for e in d.get("edges", []):
        props = {k: v for k, v in e.items() if k not in ("source", "target", "kind")}
        g.add_edge(e["source"], e["target"], e.get("kind", ""), **props)
    return g


# ── correlation query templates (DOCUMENTATION / exploration only) ────────────
# aws_correlate remains the source of truth for ranking (gated-multiplicative
# score, KEV>=90 hard-floor, MAX-per-jewel, dominator choke points are NOT
# expressible as a single query). These help explore the graph inside Neptune.
CYPHER_ATTACK_PATHS = (
    "MATCH p = (i {`~id`:'internet'})-[:EXPOSED_TO|ATTACHED_TO|HAS_INSTANCE_PROFILE|"
    "HAS_ROLE|CAN_ASSUME|CAN_PRIVESC_TO|CAN_READ_DATA*1..8]->(t) "
    "WHERE t:AdminCapability OR t:S3Bucket RETURN p LIMIT 200"
)
