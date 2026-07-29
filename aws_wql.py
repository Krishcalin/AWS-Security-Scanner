#!/usr/bin/env python3
"""aws_wql.py — WQL: a typed, bounded JSON query language over the security graph.

WQL gives OverWatch's graph a queryable surface WITHOUT free Gremlin or a Neptune backend
(both would break the self-hosted / air-gap charter). A query is a closed, typed JSON object
compiled to the existing ``aws_graph.SecurityGraph`` traversal primitives — there is no user
regex, no ``eval``, no free-text parse path. It imports the byte-frozen ``aws_correlate``
(E_PATH, crown_nodes) READ-ONLY and never mutates it; all new logic lives here.

Two entry points:
  parse(obj)         -> a validated, normalized query dict (raises WQLError on any unknown
                        field / op / predicate). This is the security boundary.
  evaluate(obj, g)   -> a deterministic list of node rows {id, kind, label, props}, sorted by
                        (kind, id) code-point (matching Python str< and the TS cmpId mirror).

The engine is MIRRORED byte-for-byte in frontend/src/lib/wql.ts for SAMPLE==LIVE parity
(guarded by a shared cross-language fixture). Keep the two in lockstep.
"""
from __future__ import annotations

from typing import Dict, List, Optional

import aws_correlate
from aws_state import _glob

WQL_MAX_HOPS = 12
WQL_DEFAULT_LIMIT = 500
WQL_MAX_LIMIT = 5000
WQL_MAX_DEPTH = 32          # predicate-tree nesting cap — a deep boolean tree is rejected with
                            # WQLError (400), never a RecursionError (500). Mirrored in wql.ts.
WQL_MAX_PREDS = 128         # total predicate count cap — bounds a wide boolean 'of' so evaluate
                            # stays O(nodes * PREDS) at worst (no CPU-amplification). Mirrored.

_BOOL_OPS = frozenset({"and", "or", "not"})
_LEAF_PREDS = frozenset({"kind", "has_prop", "prop", "prop_glob", "has_edge",
                         "reachable_from", "reaches", "crown_jewel"})
_CMP_OPS = frozenset({"eq", "neq", "in", "gt", "gte", "lt", "lte", "exists", "contains"})
_TOP_KEYS = frozenset({"select", "kind", "kind_in", "where", "limit", "max_hops"})
# props a WQL author may filter on (arbitrary prop paths are rejected — a stable, documented
# surface + it keeps the TS mirror finite). Expands additively per demand.
_WHERE_PROPS = frozenset({
    "crown_jewel", "DataStore", "public", "encrypted", "sensitivity", "name", "account",
    "external", "cidr", "runtime_monitored", "severity", "kev", "epss", "exploit_available",
    "cve", "reachable_service", "conditioned", "verified", "scan_source", "digest", "region",
    "data_types", "sensitivity_tier", "classifier",       # DSPM read-time enrichment (aws_dspm)
})


class WQLError(ValueError):
    """A malformed / unsafe WQL query (unknown field, op, predicate, or prop)."""


# ── seg / label (mirror cnapp_service._seg: rsplit('/') then rsplit(':')) ──────
def _seg(nid: str) -> str:
    return nid.rsplit("/", 1)[-1].rsplit(":", 1)[-1]


# ── parse (typecheck + normalize; the security boundary) ──────────────────────
def parse(obj) -> dict:
    if not isinstance(obj, dict):
        raise WQLError("query must be an object")
    unknown = set(obj) - _TOP_KEYS
    if unknown:
        raise WQLError(f"unknown query field(s): {sorted(unknown)}")
    if obj.get("select", "node") != "node":
        raise WQLError("select must be 'node' (v1)")
    kind = obj.get("kind")
    if kind is not None and not isinstance(kind, str):
        raise WQLError("kind must be a string")
    kind_in = obj.get("kind_in")
    if kind_in is not None and not (isinstance(kind_in, list) and all(isinstance(k, str) for k in kind_in)):
        raise WQLError("kind_in must be a list of strings")
    where = _parse_pred(obj["where"], 0, [0]) if obj.get("where") is not None else None
    lim = obj.get("limit", WQL_DEFAULT_LIMIT)
    if not isinstance(lim, int) or isinstance(lim, bool) or lim <= 0:
        raise WQLError("limit must be a positive integer")
    mh = obj.get("max_hops", WQL_MAX_HOPS)
    if not isinstance(mh, int) or isinstance(mh, bool) or mh <= 0:
        raise WQLError("max_hops must be a positive integer")
    return {"select": "node", "kind": kind, "kind_in": kind_in, "where": where,
            "limit": min(lim, WQL_MAX_LIMIT), "max_hops": min(mh, WQL_MAX_HOPS)}


def _parse_pred(p, depth: int = 0, counter=None) -> dict:
    if counter is None:
        counter = [0]
    if depth > WQL_MAX_DEPTH:
        raise WQLError(f"predicate nesting exceeds {WQL_MAX_DEPTH}")
    counter[0] += 1
    if counter[0] > WQL_MAX_PREDS:
        raise WQLError(f"query has more than {WQL_MAX_PREDS} predicates")
    if not isinstance(p, dict):
        raise WQLError("predicate must be an object")
    op = p.get("op")
    if op in _BOOL_OPS:
        of = p.get("of")
        if not isinstance(of, list) or not of:
            raise WQLError(f"boolean '{op}' needs a non-empty 'of' list")
        if op == "not" and len(of) != 1:
            raise WQLError("'not' takes exactly one child predicate")
        return {"op": op, "of": [_parse_pred(c, depth + 1, counter) for c in of]}
    pred = p.get("pred")
    if pred not in _LEAF_PREDS:
        raise WQLError(f"unknown predicate: {pred!r}")
    if pred == "kind":
        kop = p.get("op", "eq")
        if kop not in ("eq", "in"):
            raise WQLError("kind pred op must be eq|in")
        if kop == "eq" and not isinstance(p.get("value"), str):
            raise WQLError("kind eq needs a string value")
        if kop == "in" and not (isinstance(p.get("value"), list) and all(isinstance(v, str) for v in p["value"])):
            raise WQLError("kind in needs a list of strings")
        return {"pred": "kind", "op": kop, "value": p["value"]}
    if pred in ("has_prop", "prop", "prop_glob"):
        field = p.get("field")
        if field not in _WHERE_PROPS:
            raise WQLError(f"prop {field!r} not queryable (allowed: {sorted(_WHERE_PROPS)})")
        if pred == "prop":
            pop = p.get("op")
            if pop not in _CMP_OPS:
                raise WQLError(f"prop op must be one of {sorted(_CMP_OPS)}")
            if pop == "in" and not isinstance(p.get("value"), list):
                raise WQLError("prop 'in' needs a list value")
            return {"pred": "prop", "field": field, "op": pop, "value": p.get("value")}
        if pred == "prop_glob":
            if not isinstance(p.get("value"), str):
                raise WQLError("prop_glob needs a string pattern")
            return {"pred": "prop_glob", "field": field, "value": p["value"]}
        return {"pred": "has_prop", "field": field, "value": p.get("value")}  # value optional
    if pred == "has_edge":
        if not isinstance(p.get("kind"), str):
            raise WQLError("has_edge needs a string 'kind'")
        d = p.get("dir", "out")
        if d not in ("out", "in"):
            raise WQLError("has_edge dir must be out|in")
        return {"pred": "has_edge", "kind": p["kind"], "dir": d}
    if pred == "reachable_from":
        if p.get("target") != "internet":
            raise WQLError("reachable_from target must be 'internet' (v1)")
        return {"pred": "reachable_from", "target": "internet"}
    if pred == "reaches":
        t = p.get("target")
        if t not in ("crown", "admin"):
            raise WQLError("reaches target must be crown|admin")
        return {"pred": "reaches", "target": t}
    return {"pred": "crown_jewel"}


# ── evaluate ──────────────────────────────────────────────────────────────────
class _Ctx:
    """Per-query precomputed sets (built at most once, only when a predicate needs them)."""
    def __init__(self, g, max_hops: int):
        self.g = g
        self.max_hops = max_hops
        self._exposed = self._reach_crown = self._reach_admin = self._crowns = self._rev = None

    def crowns(self):
        if self._crowns is None:
            self._crowns = aws_correlate.crown_nodes(self.g)
        return self._crowns

    def exposed(self):
        if self._exposed is None:
            s: set = set()
            for n in self.g.nodes("InternetSource"):
                s |= set(self.g.reachable(n["id"], aws_correlate.E_PATH, max_hops=self.max_hops))
            self._exposed = s
        return self._exposed

    def reaches_crown(self):
        if self._reach_crown is None:
            s: set = set()
            for cid in self.crowns():
                s |= set(self.g.reverse_reachable(cid, aws_correlate.E_PATH, max_hops=self.max_hops))
            self._reach_crown = s
        return self._reach_crown

    def reaches_admin(self):
        if self._reach_admin is None:
            s: set = set()
            for n in self.g.nodes("AdminCapability"):
                s |= set(self.g.reverse_reachable(n["id"], aws_correlate.E_PATH, max_hops=self.max_hops))
            self._reach_admin = s
        return self._reach_admin

    def rev_has_edge(self, node_id: str, kind: str) -> bool:
        if self._rev is None:
            idx: set = set()
            for e in self.g.edges():
                idx.add((e["dst"], e["kind"]))
            self._rev = idx
        return (node_id, kind) in self._rev


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _eval_pred(pred: dict, node: dict, g, ctx: _Ctx) -> bool:
    op = pred.get("op")
    if op in _BOOL_OPS:
        if op == "and":
            return all(_eval_pred(c, node, g, ctx) for c in pred["of"])
        if op == "or":
            return any(_eval_pred(c, node, g, ctx) for c in pred["of"])
        return not _eval_pred(pred["of"][0], node, g, ctx)     # not
    p = pred["pred"]
    props = node.get("props") or {}
    if p == "kind":
        return node["kind"] == pred["value"] if pred["op"] == "eq" else node["kind"] in pred["value"]
    if p == "has_prop":
        if "value" in pred and pred["value"] is not None:
            return props.get(pred["field"]) == pred["value"]
        return bool(props.get(pred["field"]))
    if p == "prop":
        return _cmp(props.get(pred["field"], _MISSING), pred["op"], pred.get("value"),
                    pred["field"] in props)
    if p == "prop_glob":
        return _glob(pred["value"], str(props.get(pred["field"], "")))
    if p == "has_edge":
        return (g.has_out_edge(node["id"], pred["kind"]) if pred["dir"] == "out"
                else ctx.rev_has_edge(node["id"], pred["kind"]))
    if p == "reachable_from":
        return node["id"] in ctx.exposed()
    if p == "reaches":
        return node["id"] in (ctx.reaches_crown() if pred["target"] == "crown" else ctx.reaches_admin())
    return bool(props.get("crown_jewel")) or node["id"] in ctx.crowns()   # crown_jewel


_MISSING = object()


def _cmp(actual, op: str, value, present: bool) -> bool:
    if op == "exists":
        return present
    if not present:
        return op == "neq"                                     # absent != value → True; all else False
    if op == "eq":
        return actual == value
    if op == "neq":
        return actual != value
    if op == "in":
        return actual in value
    if op == "contains":
        try:
            return value in actual
        except TypeError:
            return False
    a, b = _num(actual), _num(value)                           # gt/gte/lt/lte — numeric
    if a is None or b is None:
        return False
    return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]


def _row(node: dict) -> dict:
    props = node.get("props") or {}
    return {"id": node["id"], "kind": node["kind"],
            "label": props.get("name") or _seg(node["id"]), "props": props}


def evaluate(obj, g) -> List[dict]:
    """Run a WQL query against a SecurityGraph, returning deterministic node rows."""
    q = parse(obj)
    if q["kind"] is not None:
        candidates = g.nodes(q["kind"])
    elif q["kind_in"] is not None:
        kset = set(q["kind_in"])
        candidates = [n for n in g.nodes() if n["kind"] in kset]
    else:
        candidates = g.nodes()
    ctx = _Ctx(g, q["max_hops"])
    where = q["where"]
    matched = [n for n in candidates if where is None or _eval_pred(where, n, g, ctx)]
    matched.sort(key=lambda n: (n["kind"], n["id"]))           # code-point, matches the TS mirror
    return [_row(n) for n in matched[:q["limit"]]]
