#!/usr/bin/env python3
"""aws_policy.py — policy-as-code engine (the in-charter custom-rule / "Rego" substitute).

A literal Rego/OPA engine is NOT charter-viable: OPA is a Go binary (shelling to it needs a
network/process primitive banned outside the 3-file egress allowlist), and a pure-Python Rego
interpreter is a heavy foreign dependency that breaks the air-gap wheelhouse. So this is a
CLOSED, TYPED, pure-Python policy DSL — the same discipline as aws_wql (no user regex, no eval,
no free-text parse path) — that EXTENDS the saved-WQL Control with two genuinely new surfaces:

  * a FINDING-catalog predicate (compliance-as-code) — match by check_id glob / section /
    severity / status / compliance framework+control. This is the big new value: a policy like
    "every check mapped to PCI-DSS 3.4 must PASS" that Controls (graph-only) can't express.
  * a CROSS-DOMAIN boolean — combine a graph condition (reuse aws_wql.evaluate) AND/OR a finding
    condition in one rule.

A policy that MATCHES (its condition is met) overlays a synthetic POLICY-xx finding, status
always WARN — read-time + display-only, so it can NEVER perturb the FAIL-only posture score
(baked at scan time) or the compliance scorecard. Config-driven (CNAPP_POLICIES). Mirrored in
frontend/src/lib/policy.ts (SAMPLE==LIVE), guarded by the shared cross-language parity fixture.
Imports aws_wql (which imports byte-frozen aws_correlate) READ-ONLY; no network, no aws_correlate
edit.
"""
from __future__ import annotations

from typing import List, Optional

import aws_wql
from aws_state import _glob

POLICY_SECTION = "Policy"
POLICY_PREFIX = "POLICY-"
_SEV = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_FINDING_FIELDS = frozenset({"check_id_glob", "section", "severity", "severity_op", "status",
                             "compliance_framework", "compliance_control"})
_SEV_OPS = frozenset({"eq", "gte", "lte"})
_MATCH_KEYS = frozenset({"op", "graph", "finding"})


class PolicyError(ValueError):
    """A malformed policy rule (unknown field / bad shape). The config boundary."""


def policy_severity(policy: dict) -> str:
    s = policy.get("severity")
    return s if s in _SEV else "MEDIUM"


# ── parse / validate (typecheck the closed shape; the config boundary) ─────────
def parse(policy) -> dict:
    if not isinstance(policy, dict):
        raise PolicyError("policy must be an object")
    if not policy.get("id"):
        raise PolicyError("policy needs an id")
    match = policy.get("match")
    if not isinstance(match, dict):
        raise PolicyError("policy needs a 'match' object")
    unknown = set(match) - _MATCH_KEYS
    if unknown:
        raise PolicyError(f"unknown match field(s): {sorted(unknown)}")
    op = match.get("op", "any")
    if op not in ("any", "all"):
        raise PolicyError("match op must be any|all")
    graph = match.get("graph")
    if graph is not None:
        try:
            aws_wql.parse(graph)                              # reuse the WQL security boundary
        except aws_wql.WQLError as e:
            raise PolicyError(f"invalid graph clause: {e}")   # uniform policy-config boundary
    finding = match.get("finding")
    if finding is not None:
        _parse_finding(finding)
    if graph is None and finding is None:
        raise PolicyError("policy match needs a 'graph' and/or a 'finding' clause")
    return policy


def _parse_finding(f) -> dict:
    if not isinstance(f, dict) or not f:
        raise PolicyError("finding predicate must be a non-empty object")
    unknown = set(f) - _FINDING_FIELDS
    if unknown:
        raise PolicyError(f"unknown finding field(s): {sorted(unknown)}")
    for k in ("check_id_glob", "section", "status", "compliance_framework", "compliance_control"):
        if k in f and not isinstance(f[k], str):
            raise PolicyError(f"finding.{k} must be a string")
    if "severity" in f and f["severity"] not in _SEV_RANK:
        raise PolicyError("finding.severity must be a known severity")
    if f.get("severity_op", "eq") not in _SEV_OPS:
        raise PolicyError("finding.severity_op must be eq|gte|lte")
    if "compliance_control" in f and "compliance_framework" not in f:
        raise PolicyError("finding.compliance_control needs a compliance_framework")
    return f


# ── evaluate ────────────────────────────────────────────────────────────────
def _eval_finding(pred: dict, finding: dict) -> bool:
    """A finding matches the predicate when ALL specified conditions hold (conjunction)."""
    if "check_id_glob" in pred and not _glob(pred["check_id_glob"], str(finding.get("check_id", ""))):
        return False
    if "section" in pred and finding.get("section") != pred["section"]:
        return False
    if "status" in pred and str(finding.get("status", "")).upper() != pred["status"].upper():
        return False
    if "severity" in pred:
        want = _SEV_RANK[pred["severity"]]
        got = _SEV_RANK.get(str(finding.get("severity", "")).upper())
        if got is None:
            return False
        op = pred.get("severity_op", "eq")
        if not (got == want if op == "eq" else got >= want if op == "gte" else got <= want):
            return False
    if "compliance_framework" in pred:
        comp = finding.get("compliance") or {}
        # framework key matched case-insensitively (CIS / PCI-DSS / "NIST 800-53")
        fw = pred["compliance_framework"].lower()
        key = next((k for k in comp if str(k).lower() == fw), None)
        if key is None:
            return False
        if "compliance_control" in pred and str(comp.get(key)) != pred["compliance_control"]:
            return False
    return True


def evaluate(policy: dict, graph, catalog: List[dict]) -> Optional[dict]:
    """Run a policy: returns ``{"nodes":[...], "findings":[...]}`` of the matched (violating) items
    when the policy FIRES, else None. ``graph`` is a rehydrated SecurityGraph (or None — a
    finding-only policy needs no graph). ``catalog`` is the account's finding_catalog. A graph
    clause reuses aws_wql.evaluate verbatim; a finding clause scans the catalog. The ``op`` (any|
    all) combines the two clauses; a single-clause policy fires on that clause alone."""
    match = policy.get("match") or {}
    gq, fp, op = match.get("graph"), match.get("finding"), match.get("op", "any")
    nodes = aws_wql.evaluate(gq, graph) if (gq is not None and graph is not None) else []
    findings = [f for f in (catalog or []) if _eval_finding(fp, f)] if fp is not None else []

    if gq is not None and fp is not None:
        fired = (bool(nodes) and bool(findings)) if op == "all" else (bool(nodes) or bool(findings))
    else:
        fired = bool(nodes) or bool(findings)
    if not fired:
        return None
    return {"nodes": nodes, "findings": findings}


def policy_finding(policy: dict, account_id: str, matched: dict) -> dict:
    """The synthetic POLICY-xx WARN finding for a fired policy. affected = the violating node ids
    plus ``finding:<check_id>`` for matched findings. status is always WARN (display-only)."""
    nodes = matched.get("nodes") or []
    findings = matched.get("findings") or []
    affected = [n["id"] for n in nodes] + [f"finding:{f.get('check_id')}" for f in findings]
    name = policy.get("name") or policy.get("id")
    n = len(affected)
    return {
        "check_id": POLICY_PREFIX + str(policy.get("id")),
        "section": policy.get("section") or POLICY_SECTION,
        "severity": policy_severity(policy),
        "status": "WARN",                                     # display-only; never FAIL
        "compliance": policy.get("compliance") or {},
        "remediation_cmd": policy.get("remediation_cmd") or "",
        "risk": policy.get("description") or f"Policy '{name}' matched {n} item(s).",
        "impact": policy.get("impact") or "",
        "steps": policy.get("steps") or [],
        "affected": affected[:500],
        "count": n,
        "distinct": len(set(affected)),
        "account": account_id,
    }


def policy_meta(policy: dict) -> dict:
    """The normalized descriptor for the /policies list (no roll-up)."""
    return {
        "id": str(policy.get("id")),
        "name": policy.get("name") or str(policy.get("id")),
        "severity": policy_severity(policy),
        "section": policy.get("section") or POLICY_SECTION,
        "pack": policy.get("pack") or "",
        "description": policy.get("description") or "",
        "match": policy.get("match"),
    }


def needs_graph(policy: dict) -> bool:
    """Whether a policy has a graph clause (so the service rehydrates the graph only when needed).
    Defensive: a malformed policy (non-dict ``match``) is NOT graph-needing — it must reach the
    per-policy parse() where it is rejected inertly, never crash this pre-pass."""
    m = (policy or {}).get("match")
    return isinstance(m, dict) and m.get("graph") is not None
