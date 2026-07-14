#!/usr/bin/env python3
"""aws_correlate.py — attack-path correlation & prioritization engine (CNAPP Phase 4).

The "ship the product" layer: it reads the security graph that Phases 1-3 built
(identity + exposure + vulnerability + data + threat edges) and collapses it into
the ranked handful of end-to-end attack paths that actually matter, then computes
CHOKE POINTS — "remediate this one node and sever N attack paths to M crown jewels."

Design (grounded in a verified methodology research pass):
  * **Score the PATH, not the finding** — the unit of ranking is an entry→target
    chain, which is what collapses thousands of flat findings into a ranked few.
  * **Gated-multiplicative scoring** — a toxic combination is a CONJUNCTION
    (exposure AND exploitability AND privilege/reach AND a path to crown-jewel
    data). Multiply across dimensions so any missing factor collapses the path;
    this kills the classic "high-CVSS but unexposed, no data path" false positive
    that a weighted sum would surface as critical.
  * **MAX-per-jewel aggregation, never SUM** — summing shared hops/paths inflates
    benign infrastructure to fake-critical (the #1 documented failure mode).
  * **Explainable** — every 0-100 score decomposes into its hop factors and the
    driving findings; a path with no renderable rationale is a bug.
  * **Choke points by severity-weighted path-frequency** with a `is_true_choke`
    dominator flag (every path to a target passes through the node).

Pure/stdlib and boto3-free: the graph predicates (`is_unconditioned`,
`is_exploitable`, `node_has_threat`) are INJECTED as callables, so the engine is
unit-testable against a hand-built graph and can never diverge from the ad-hoc
ATTACK-01/02 emitters on "confirmed-vs-conditioned" or "exploitable pivot".
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

# ── traversable "attack" edges (lateral movement); everything else is annotation ─
E_PATH = frozenset({
    "EXPOSED_TO", "ATTACHED_TO", "HAS_INSTANCE_PROFILE", "HAS_ROLE",
    "CAN_ASSUME", "CAN_PRIVESC_TO", "CAN_READ_DATA",
})
# node kinds that must never rank as a choke (they ARE the endpoints being cut between)
EXCLUDE_KINDS = frozenset({"InternetSource", "AdminCapability", "S3Bucket"})

MAX_HOPS = 8
TOP_N = 200
PER_PAIR_CAP = 25       # keep up to K parallel routes per (entry,terminal) — enough
                        # for choke analysis to see shared nodes, bounded vs explosion
ENUM_BUDGET = 4000      # hard stop on total materialized paths (dense-clique guard)
STEP_BUDGET = 250000    # hard stop on DFS edge-EXPANSIONS — the materialized-path caps
                        # don't bound traversal cost on a dense IAM clique (O(N!) simple
                        # paths); backtracking makes each expansion O(1) so this aborts fast.
                        # Far above any real graph's path count; only trips on cliques.

# All tunable weights live here for auditability (not scattered magic numbers).
WEIGHTS = {
    "te_structural": 1.0,
    "te_exposed_eni": 0.95, "te_exposed_s3_auth": 1.0,
    "te_can_assume": 0.90, "te_can_assume_cond": 0.40,
    "te_can_privesc": 0.70, "te_can_privesc_cond": 0.30,
    "te_can_read_data": 0.90, "te_can_read_data_cond": 0.50,
    "E_auth": 1.0, "E_computed": 0.90,
    "X_kev": 1.0, "X_exploit": 0.90, "X_epss_base": 0.55, "X_epss_scale": 0.45,
    "X_epss_missing": 0.10, "X_none": 0.15,
    "P_admin": 1.0, "P_data": 0.6,
    "I_crown_public": 1.0, "I_crown_private": 0.9, "I_admin": 0.85,
    "T_kev": 1.25, "T_threat": 1.5,
    "floor_unconditioned": 80, "cap_conditioned": 55, "hard_floor_kev_data": 90,
    "band_critical": 80, "band_high": 60, "band_medium": 40,
}

Edge = Tuple[str, str, str]   # (src, dst, kind)


@dataclass(frozen=True)
class AttackPath:
    entry: str
    terminal: str
    terminal_kind: str                       # 'admin' | 'data'
    nodes: Tuple[str, ...]
    edges: Tuple[Edge, ...]
    hop_factors: Tuple[Tuple[str, float, str], ...]   # (edge_kind, t_e, reason)
    conditioned: bool
    vuln_pivot: bool
    kev: bool
    active_threat: bool
    direct_public_crown: bool
    exposure: float
    exploitability: float
    privilege: float
    impact: float
    reach: float
    boost: float
    score: int
    severity: str
    hard_floor_applied: bool
    driving_findings: Tuple[str, ...]
    rationale: str

    def to_dict(self) -> dict:
        return {
            "entry": self.entry, "terminal": self.terminal,
            "terminal_kind": self.terminal_kind,
            "nodes": list(self.nodes),
            "edges": [list(e) for e in self.edges],
            "score": self.score, "severity": self.severity,
            "conditioned": self.conditioned, "vuln_pivot": self.vuln_pivot,
            "kev": self.kev, "active_threat": self.active_threat,
            "direct_public_crown": self.direct_public_crown,
            "hard_floor_applied": self.hard_floor_applied,
            "factors": {"exposure": self.exposure, "exploitability": self.exploitability,
                        "privilege": self.privilege, "impact": self.impact,
                        "reach": round(self.reach, 4), "boost": self.boost},
            "driving_findings": list(self.driving_findings),
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ChokePoint:
    node_id: str
    node_kind: Optional[str]
    label: str
    paths_severed: int
    total_paths: int
    weighted_score: float
    targets_fully_blocked: Tuple[str, ...]
    is_true_choke: bool
    severed_terminals: Tuple[str, ...]
    remediation_hint: str

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id, "node_kind": self.node_kind, "label": self.label,
            "paths_severed": self.paths_severed, "total_paths": self.total_paths,
            "weighted_score": round(self.weighted_score, 1),
            "targets_fully_blocked": list(self.targets_fully_blocked),
            "is_true_choke": self.is_true_choke,
            "remediation_hint": self.remediation_hint,
        }


# ─── helpers ─────────────────────────────────────────────────────────────────
def _label(g, node_id: str) -> str:
    nd = g.node(node_id)
    if nd:
        name = (nd.get("props") or {}).get("name")
        if name:
            return name
    return node_id.split("/")[-1].split(":::")[-1]


def _edge_te(edge: dict, is_unconditioned: Callable[[dict], bool], g) -> Tuple[float, str]:
    kind = edge["kind"]
    uncond = is_unconditioned(edge)
    if kind in ("ATTACHED_TO", "HAS_INSTANCE_PROFILE", "HAS_ROLE"):
        return WEIGHTS["te_structural"], "structural"
    if kind == "EXPOSED_TO":
        dst = g.node(edge["dst"])
        if dst and dst.get("kind") == "S3Bucket":
            return WEIGHTS["te_exposed_s3_auth"], "authoritative internet->S3"
        return WEIGHTS["te_exposed_eni"], "internet-reachable ENI"
    if kind == "CAN_ASSUME":
        return (WEIGHTS["te_can_assume"], "assume-role") if uncond \
            else (WEIGHTS["te_can_assume_cond"], "conditioned assume-role")
    if kind == "CAN_PRIVESC_TO":
        return (WEIGHTS["te_can_privesc"], "privilege escalation") if uncond \
            else (WEIGHTS["te_can_privesc_cond"], "conditioned privesc")
    if kind == "CAN_READ_DATA":
        return (WEIGHTS["te_can_read_data"], "data read") if uncond \
            else (WEIGHTS["te_can_read_data_cond"], "conditioned data read")
    return WEIGHTS["te_structural"], kind


def _path_exploitability(nodes, g, is_exploitable) -> Tuple[float, Optional[str], bool]:
    """Strongest exploit signal across EC2 hosts on the path (max, for explainability)."""
    best_x, best_cve, kev = 0.0, None, False
    for n in nodes:
        nd = g.node(n)
        if not nd or nd.get("kind") != "EC2Instance":
            continue
        for e in g.out_edges(n, {"HAS_VULN"}):
            p = e["props"]
            if p.get("kev"):
                x = WEIGHTS["X_kev"]; kev = True
            elif str(p.get("exploit_available", "")).upper() == "YES":
                x = WEIGHTS["X_exploit"]
            else:
                epss = p.get("epss")
                if isinstance(epss, (int, float)):
                    x = WEIGHTS["X_epss_base"] + WEIGHTS["X_epss_scale"] * float(epss)
                else:
                    x = WEIGHTS["X_epss_missing"]
            if x > best_x or (p.get("kev") and not best_cve):
                best_x, best_cve = x, p.get("cve")
    return best_x, best_cve, kev


def is_direct_public_crown(edges: List[Edge], g) -> bool:
    if not edges:
        return False
    src, dst, kind = edges[0]
    if kind != "EXPOSED_TO":
        return False
    nd = g.node(dst)
    return bool(nd and nd.get("kind") == "S3Bucket")


def _severity(score: int) -> str:
    if score >= WEIGHTS["band_critical"]:
        return "CRITICAL"
    if score >= WEIGHTS["band_high"]:
        return "HIGH"
    if score >= WEIGHTS["band_medium"]:
        return "MEDIUM"
    return "LOW"


def _make_path(entry, terminal, terminal_kind, nodes, edges, hop_factors,
               conditioned, active_threat, direct_public_crown, g, is_exploitable) -> AttackPath:
    reach = 1.0
    for _, te, _ in hop_factors:
        reach *= te

    # E — first-hop exposure confidence
    exposure = WEIGHTS["E_computed"]
    if edges:
        e0 = g.node(edges[0][1])
        if e0 and e0.get("kind") == "S3Bucket":
            exposure = WEIGHTS["E_auth"]

    # X — exploitability
    X, driving_cve, kev = _path_exploitability(nodes, g, is_exploitable)
    driving = []
    if direct_public_crown:
        X = max(X, 1.0)
        driving.append("EXTACCESS-01")
    elif X <= 0.0:
        X = 1.0 if terminal_kind == "admin" else WEIGHTS["X_none"]
    if driving_cve:
        driving.append(("VULN-02" if kev else "VULN-01") + f":{driving_cve}")

    privilege = WEIGHTS["P_admin"] if terminal_kind == "admin" else WEIGHTS["P_data"]

    if terminal_kind == "admin":
        impact = WEIGHTS["I_admin"]
        driving.append("ATTACK-01")
    else:
        tnode = g.node(terminal) or {}
        public = bool((tnode.get("props") or {}).get("public"))
        impact = WEIGHTS["I_crown_public"] if public else WEIGHTS["I_crown_private"]
        driving.append("ATTACK-02")

    boost = (WEIGHTS["T_kev"] if kev else 1.0) * (WEIGHTS["T_threat"] if active_threat else 1.0)
    if active_threat:
        driving.append("THREAT-01")

    risk_raw = exposure * X * max(privilege, impact) * reach * boost
    score = max(0, min(100, round(100 * min(1.0, risk_raw))))

    hard_floor = False
    if not conditioned and terminal_kind in ("admin", "data"):
        score = max(score, WEIGHTS["floor_unconditioned"])
    if conditioned:
        score = min(score, WEIGHTS["cap_conditioned"])
    if terminal_kind == "data" and kev and not conditioned:
        score = max(score, WEIGHTS["hard_floor_kev_data"])
        hard_floor = True

    severity = "CRITICAL" if hard_floor else _severity(score)
    cond_note = " [capped: condition-guarded hop]" if conditioned else ""
    rationale = (f"score {score} = exposure {exposure:.2f} x exploit {X:.2f} x "
                 f"impact {max(privilege, impact):.2f} x reach {reach:.2f} x boost {boost:.2f}"
                 f"{cond_note}")

    return AttackPath(
        entry=entry, terminal=terminal, terminal_kind=terminal_kind,
        nodes=tuple(nodes), edges=tuple(edges), hop_factors=tuple(hop_factors),
        conditioned=conditioned, vuln_pivot=bool(driving_cve), kev=kev,
        active_threat=active_threat, direct_public_crown=direct_public_crown,
        exposure=exposure, exploitability=round(X, 3), privilege=privilege,
        impact=impact, reach=reach, boost=boost, score=score, severity=severity,
        hard_floor_applied=hard_floor, driving_findings=tuple(dict.fromkeys(driving)),
        rationale=rationale)


# ─── enumeration ─────────────────────────────────────────────────────────────
def enumerate_paths(g, sources, admin_id, crown_ids,
                    is_unconditioned: Callable[[dict], bool],
                    is_exploitable: Callable[[dict], bool],
                    node_has_threat: Callable[[str], bool],
                    max_hops: int = MAX_HOPS, top_n: int = TOP_N) -> List[AttackPath]:
    """Bounded simple-path DFS from entry seeds to sinks (crown-jewel S3 + admin
    capability). Preserves the ATTACK-02 gate: a DATA terminal is only recorded
    when the chain owns an exploitable/KEV host OR is a direct authoritative
    public-crown exposure. Admin terminals need no vuln (ATTACK-01 semantics).
    Deterministic, cycle-safe, and bounded (hop cap + per-(entry,terminal) dedup
    keeping MAX score + TOP_N)."""
    targets: Dict[str, str] = {}
    if admin_id:
        targets[admin_id] = "admin"
    for c in crown_ids:
        targets[c] = "data"
    if not targets or not sources:
        return []

    # Backtracking DFS (append/pop — no per-edge list copies) with cached, sorted
    # out-edges and a hard edge-EXPANSION budget, so a dense CAN_ASSUME/CAN_PRIVESC
    # clique (O(N!) simple paths) can never blow up scan time. Keep parallel routes
    # (needed for choke analysis) bounded by PER_PAIR_CAP + the path budget.
    paths: List[AttackPath] = []
    pair_counts: Dict[Tuple[str, str], int] = defaultdict(int)
    budget = [STEP_BUDGET]
    sorted_out: Dict[str, list] = {}
    npath: List[str] = []
    epath: List[Edge] = []
    hf: List[Tuple[str, float, str]] = []
    visited: set = set()

    def souts(node):
        s = sorted_out.get(node)
        if s is None:
            s = sorted(g.out_edges(node, E_PATH), key=lambda x: (x["kind"], x["dst"]))
            sorted_out[node] = s
        return s

    def dfs(node, entry, cond, exp, threat):
        if budget[0] < 0 or len(epath) >= max_hops or len(paths) >= ENUM_BUDGET:
            return
        for e in souts(node):
            budget[0] -= 1
            if budget[0] < 0:
                return
            nxt = e["dst"]
            if nxt in visited:
                continue                                     # simple paths only
            te, reason = _edge_te(e, is_unconditioned, g)
            cond2 = cond or (not is_unconditioned(e))
            nd = g.node(nxt)
            ex = exp
            if not ex and nd and nd.get("kind") == "EC2Instance":
                ex = any(is_exploitable(v["props"]) for v in g.out_edges(nxt, {"HAS_VULN"}))
            threat2 = threat or node_has_threat(nxt)
            visited.add(nxt)
            npath.append(nxt)
            epath.append((e["src"], nxt, e["kind"]))
            hf.append((e["kind"], te, reason))
            if nxt in targets:
                kind = targets[nxt]
                dpc = is_direct_public_crown(epath, g)
                k = (entry, nxt)
                if (kind == "admin" or ex or dpc) and pair_counts[k] < PER_PAIR_CAP:
                    paths.append(_make_path(entry, nxt, kind, list(npath), list(epath),
                                            list(hf), cond2, threat2, dpc, g, is_exploitable))
                    pair_counts[k] += 1
            dfs(nxt, entry, cond2, ex, threat2)
            visited.discard(nxt)
            npath.pop()
            epath.pop()
            hf.pop()

    for s in sorted(sources):
        if not g.node(s):
            continue
        visited.clear(); visited.add(s)
        npath.clear(); npath.append(s)
        epath.clear(); hf.clear()
        dfs(s, s, False, False, node_has_threat(s))
    return rank(paths)[:top_n]


def rank(paths: List[AttackPath]) -> List[AttackPath]:
    return sorted(paths, key=lambda p: (-p.score, -p.impact, len(p.edges), p.terminal))


# ─── choke points ────────────────────────────────────────────────────────────
def remediation_by_kind(node_kind: Optional[str]) -> str:
    return {
        "NetworkInterface": "Revoke the public ingress feeding this interface (aws ec2 revoke-security-group-ingress ...).",
        "EC2Instance": "Patch the exploitable CVE to its fixed version (or isolate the host) to break every path through it.",
        "IAMRole": "Scope this role to least privilege / apply a permissions boundary (aws iam put-role-permissions-boundary ...).",
        "InstanceProfile": "Detach or re-scope this instance profile so the workload no longer inherits the privileged role.",
    }.get(node_kind or "", "Remediate this node to sever the attack paths that traverse it.")


def choke_points(ranked_paths: List[AttackPath],
                 node_kind: Callable[[str], Optional[str]],
                 label_of: Callable[[str], str] = None,
                 exclude_kinds: frozenset = EXCLUDE_KINDS,
                 dominates: Callable[[str, str], bool] = None) -> List[ChokePoint]:
    """Rank intermediate nodes by "remediating this severs the most (highest-value)
    attack paths". Severity-weighted path-frequency over the enumerated set. A node
    is `is_true_choke` when it dominates some target (every route to it passes
    through the node). If ``dominates(node, terminal)`` is supplied (graph-backed,
    removal-reachability), it certifies dominance AUTHORITATIVELY — the enumerated
    path set is bounded (MAX_HOPS/caps), so a longer alternate route could otherwise
    yield a false dominator. Without it, the (bounded) enumerated-set heuristic is
    used and is only a best-effort hint. Entry/target kinds are excluded structurally."""
    total = len(ranked_paths)
    cover: Dict[str, List[AttackPath]] = defaultdict(list)
    for p in ranked_paths:
        for n in set(p.nodes[1:-1]):                         # drop entry + terminal
            if node_kind(n) not in exclude_kinds:
                cover[n].append(p)

    by_term: Dict[str, List[AttackPath]] = defaultdict(list)
    for p in ranked_paths:
        by_term[p.terminal].append(p)

    out: List[ChokePoint] = []
    for n, paths in cover.items():
        severed = len(paths)
        if severed == 1 and not any(pp.severity in ("CRITICAL", "HIGH") for pp in paths):
            continue                                         # drop trivial single low-sev choke
        weighted = sum(pp.score for pp in paths)
        cand_terms = {pp.terminal for pp in paths}           # targets reached via n (enumerated)
        if dominates is not None:
            fully = tuple(sorted(t for t in cand_terms if dominates(n, t)))
        else:
            fully = tuple(sorted(
                t for t, ps in by_term.items()
                if ps and all(n in set(pp.nodes[1:-1]) for pp in ps)))
        out.append(ChokePoint(
            node_id=n, node_kind=node_kind(n),
            label=(label_of(n) if label_of else n),
            paths_severed=severed, total_paths=total, weighted_score=float(weighted),
            targets_fully_blocked=fully, is_true_choke=bool(fully),
            severed_terminals=tuple(sorted({pp.terminal for pp in paths})),
            remediation_hint=remediation_by_kind(node_kind(n))))
    out.sort(key=lambda c: (c.weighted_score, len(c.targets_fully_blocked),
                            c.paths_severed, c.node_id), reverse=True)
    return out


def minimal_cut(ranked_paths: List[AttackPath],
                node_kind: Callable[[str], Optional[str]],
                exclude_kinds: frozenset = EXCLUDE_KINDS) -> List[str]:
    """Greedy set-cover: the smallest-ish set of nodes whose remediation covers
    every CRITICAL/HIGH path. The graph is tiny, so greedy is fine."""
    remaining = [p for p in ranked_paths if p.severity in ("CRITICAL", "HIGH")]
    chosen: List[str] = []
    while remaining:
        counts: Dict[str, int] = defaultdict(int)
        for p in remaining:
            for n in set(p.nodes[1:-1]):
                if node_kind(n) not in exclude_kinds:
                    counts[n] += 1
        if not counts:
            break
        best = max(sorted(counts), key=lambda n: counts[n])
        chosen.append(best)
        remaining = [p for p in remaining if best not in set(p.nodes[1:-1])]
    return chosen


def summarize(paths: List[AttackPath]) -> dict:
    n_crit = sum(1 for p in paths if p.severity == "CRITICAL")
    n_cond = sum(1 for p in paths if p.conditioned)
    per_jewel: Dict[str, int] = {}
    for p in paths:
        per_jewel[p.terminal] = max(per_jewel.get(p.terminal, 0), p.score)
    top = paths[0] if paths else None
    return {
        "total": len(paths), "n_critical": n_crit, "n_conditioned": n_cond,
        "env_risk": sum(per_jewel.values()),      # MAX-per-jewel, then SUM across jewels
        "top_score": top.score if top else 0,
        "top_chain": " -> ".join(top.nodes) if top else "",
    }


def to_json(paths: List[AttackPath], chokes: List[ChokePoint]) -> dict:
    return {"attack_paths": [p.to_dict() for p in paths],
            "choke_points": [c.to_dict() for c in chokes]}
