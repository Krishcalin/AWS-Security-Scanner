#!/usr/bin/env python3
"""aws_segmentation.py — Phase 5 · slice 5.4: segmentation derived from attack paths.

OverWatch already ranks **choke points**: nodes that many attack paths run through. The
trouble with a choke point is that you usually cannot delete it. It is a production role,
an instance that serves traffic, a load balancer somebody depends on. "This node is
central" is a true observation that converts into no action at all.

This slice asks the adjacent question that *does* convert: **which network boundary would
you cut, and what would actually die if you cut it?** A network hop is a thing an operator
can change on a Tuesday afternoon — a security-group rule, a subnet's routing, an endpoint
policy — without deleting anything.

WHAT IS CUTTABLE, AND WHAT IS NOT
----------------------------------
Of the traversable edge kinds, exactly two are network reachability:

    EXPOSED_TO   an internet source reaching an ENI/front door
    TARGETS      an internet-facing L7 front (LB/CloudFront/API-GW) reaching a workload

The rest — ``CAN_ASSUME``, ``CAN_PRIVESC_TO``, ``HAS_ROLE``, ``HAS_INSTANCE_PROFILE``,
``ATTACHED_TO``, ``CAN_READ_DATA`` — are identity and attachment relationships. **No
firewall rule severs an IAM trust policy.** A path made only of those is not a
segmentation problem, and this module says so explicitly rather than quietly leaving it
out of the denominator. Reporting "cutting X severs 8 of 10 paths" while the other two are
IAM-only and permanently untouched by segmentation is the kind of true-but-misleading
number this codebase treats as a defect.

VERIFY THE CUT; DO NOT ASSERT IT
---------------------------------
The naive version counts the paths a candidate edge appears in and calls that the number
severed. That over-claims whenever a parallel route exists: remove the edge and the same
terminal is still reachable another way, so the "severed" path was never severed. So every
candidate here is **re-evaluated against the full path set** — a path counts as severed
only when *no* surviving path reaches the same (entry, terminal) pair without the cut
edge. The difference between the naive count and the verified one is kept and reported,
because it is exactly the over-claim the operator would otherwise inherit.

A recommendation is a recommendation. Nothing here applies a change, and no string this
module emits says a cut *will* block, prevent, or stop anything — it says what the
evidence supports: these paths, in this graph, at this scan time, no longer have a route.

Pure functions over dicts and tuples. No boto3, no network, no I/O.
"""
from __future__ import annotations

from typing import Dict, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "NETWORK_EDGE_KINDS", "IDENTITY_EDGE_KINDS", "INTERNET",
    "network_hops", "is_segmentable", "cut_candidates", "evaluate_cut",
    "recommend", "describe_cut", "summarize", "SCOPE_NOTE",
]

#: The only traversable edges a network control can sever.
NETWORK_EDGE_KINDS = frozenset({"EXPOSED_TO", "TARGETS"})

#: Identity/attachment edges. Listed to be explicit that they are NOT cuttable here —
#: no firewall rule severs an IAM trust policy.
IDENTITY_EDGE_KINDS = frozenset({
    "ATTACHED_TO", "HAS_INSTANCE_PROFILE", "HAS_ROLE",
    "CAN_ASSUME", "CAN_PRIVESC_TO", "CAN_READ_DATA",
})

INTERNET = "internet"

SCOPE_NOTE = (
    "A segmentation cut is a RECOMMENDATION derived from the paths in this scan, not an "
    "applied change and not a prediction: it says these paths have no remaining route in "
    "this graph once the hop is removed. Paths whose every hop is an identity "
    "relationship are reported separately, because no network control severs them"
)


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


def _edges(path) -> List[tuple]:
    """The (src, dst, kind) triples of a path, from a dataclass or a plain dict."""
    if path is None:
        return []
    raw = getattr(path, "edges", None)
    if raw is None:
        raw = _d(path).get("edges") or []
    out = []
    for e in raw:
        if isinstance(e, (list, tuple)) and len(e) >= 3:
            out.append((str(e[0]), str(e[1]), str(e[2])))
    return out


def _attr(path, name, default=None):
    v = getattr(path, name, None)
    if v is None:
        v = _d(path).get(name, default)
    return default if v is None else v


def network_hops(path) -> List[tuple]:
    """Every network edge in a path, in traversal order."""
    return [e for e in _edges(path) if e[2] in NETWORK_EDGE_KINDS]


def is_segmentable(path) -> bool:
    """Whether any network control could sever this path at all.

    A path made only of identity edges — role assumption into privilege escalation into a
    data read — is a permissions problem wearing a path's clothes. Segmentation will never
    touch it, and counting it in a 'paths severed' denominator would flatter the cut."""
    return bool(network_hops(path))


def _pair(path) -> tuple:
    return (str(_attr(path, "entry", "")), str(_attr(path, "terminal", "")))


def cut_candidates(paths: Optional[Sequence]) -> Dict[tuple, List]:
    """Candidate cuts: every distinct network edge, mapped to the paths crossing it."""
    out: Dict[tuple, List] = {}
    for p in (paths or []):
        for e in network_hops(p):
            out.setdefault(e, []).append(p)
    return out


def evaluate_cut(edge: tuple, paths: Optional[Sequence]) -> dict:
    """What removing ONE network edge actually severs.

    A path is severed only when, with the edge gone, no surviving path reaches the same
    (entry, terminal) pair. The naive count — "paths this edge appears in" — is kept
    alongside as ``claimed``, because the gap between the two is the over-claim an
    operator would otherwise inherit."""
    allp = [p for p in (paths or []) if p is not None]
    crossing = [p for p in allp if edge in network_hops(p)]
    survivors = [p for p in allp if edge not in network_hops(p)]
    reachable_pairs = {_pair(p) for p in survivors}

    severed = [p for p in crossing if _pair(p) not in reachable_pairs]
    surviving = [p for p in crossing if _pair(p) in reachable_pairs]
    return {
        "edge": edge,
        "claimed": len(crossing),
        "severed": len(severed),
        "still_reachable": len(surviving),
        "over_claim": len(crossing) - len(severed),
        "severed_paths": tuple(severed),
        "severed_terminals": tuple(sorted({_pair(p)[1] for p in severed})),
        "weighted": float(sum(int(_attr(p, "score", 0) or 0) for p in severed)),
    }


def _node_facts(node_id: str, nodes: Optional[Mapping]) -> dict:
    return _d(_d(nodes).get(node_id))


def recommend(paths: Optional[Sequence],
              nodes: Optional[Mapping] = None,
              edge_props: Optional[Mapping] = None,
              top: int = 10) -> List[dict]:
    """Ranked segmentation recommendations, each verified rather than asserted.

    ``nodes`` maps node id -> its graph props (``subnet_id``, ``vpc_id``, ``sg_ids``);
    ``edge_props`` maps a (src, dst, kind) triple -> that edge's props (``ports``,
    ``family``). Both are optional: without them the cut is still named by its endpoints,
    just less concretely. Nothing is invented to fill a gap."""
    cands = cut_candidates(paths)
    rows = []
    for edge in cands:
        ev = evaluate_cut(edge, paths)
        if not ev["severed"]:
            continue                      # a cut that severs nothing is not advice
        src, dst, kind = edge
        props = _d(_d(edge_props).get(edge))
        dstf = _node_facts(dst, nodes)
        rows.append({
            **ev,
            "kind": kind,
            "src": src,
            "dst": dst,
            "from_internet": src == INTERNET,
            "ports": props.get("ports") or "",
            "family": props.get("family") or "",
            "sg_ids": tuple(dstf.get("sg_ids") or ()),
            "subnet_id": dstf.get("subnet_id") or "",
            "vpc_id": dstf.get("vpc_id") or "",
        })
    rows.sort(key=lambda r: (-r["weighted"], -r["severed"], r["dst"], r["src"]))
    for r in rows:
        r["statement"] = describe_cut(r)
    return rows[:max(0, int(top or 0))] if top else rows


def describe_cut(rec: Optional[dict]) -> str:
    """One line naming the cut concretely, and only as concretely as the evidence."""
    r = _d(rec)
    if not r:
        return ""
    where = []
    if r.get("sg_ids"):
        where.append("security group(s) " + ", ".join(r["sg_ids"]))
    if r.get("subnet_id"):
        where.append(f"subnet {r['subnet_id']}")
    if r.get("vpc_id"):
        where.append(f"VPC {r['vpc_id']}")
    loc = f" ({'; '.join(where)})" if where else ""
    ports = f" on {r['ports']}" if r.get("ports") else ""
    origin = ("internet reachability of" if r.get("from_internet")
              else f"the {r.get('kind', '')} hop from {r.get('src', '')} to")
    n, w = r["severed"], int(r.get("weighted", 0))
    s = (f"Removing {origin} {r.get('dst', '')}{ports}{loc} leaves {n} attack path(s) "
         f"with no remaining route in this graph (severity-weighted {w})")
    if r.get("over_claim"):
        s += (f"; a further {r['over_claim']} path(s) cross the same hop but reach the "
              f"same target another way, so they are NOT counted as severed")
    return s


def summarize(paths: Optional[Sequence],
              recs: Optional[Sequence] = None) -> dict:
    """The estate's segmentation position.

    ``identity_only`` is the number the naive version drops. Those paths reach their
    terminal without crossing a single network hop, so no segmentation change touches
    them however aggressive it is — and an operator who cuts every recommendation here
    still has them."""
    allp = [p for p in (paths or []) if p is not None]
    seg = [p for p in allp if is_segmentable(p)]
    ident = [p for p in allp if not is_segmentable(p)]
    recs = list(recs or [])
    best = recs[0] if recs else None
    return {
        "paths": len(allp),
        "segmentable": len(seg),
        "identity_only": len(ident),
        "recommendations": len(recs),
        "top_severed": int(best["severed"]) if best else 0,
        "statement": _summary_statement(len(allp), len(seg), len(ident), best),
    }


def _summary_statement(total, seg, ident, best) -> str:
    if not total:
        return "no attack paths to segment"
    bits = [f"{seg} of {total} attack path(s) cross at least one network hop and are "
            f"candidates for a segmentation change"]
    if ident:
        bits.append(f"{ident} reach their target entirely through identity relationships "
                    f"(role assumption, privilege escalation, data-read grants) and no "
                    f"network control severs them — they need a permissions change, not "
                    f"a firewall change")
    if best:
        bits.append(f"the highest-value single cut leaves {best['severed']} path(s) with "
                    f"no remaining route")
    return "; ".join(bits) + f". {SCOPE_NOTE}"
