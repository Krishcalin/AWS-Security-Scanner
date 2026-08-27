#!/usr/bin/env python3
"""
aws_effperm.py — Pure AWS IAM effective-permissions solver (Phase 5A).

Given a normalized statement view of a principal's identity policy, plus the
OPTIONAL permission-boundary and Service-Control-Policy (SCP) ceilings that apply
to it, decide whether a control-plane pivot action (e.g. ``iam:PassRole``,
``sts:AssumeRole``, ``*``) survives the AWS evaluation chain — and therefore
whether the corresponding graph edge (``CAN_PRIVESC_TO`` / ``CAN_ASSUME``) should
be KEPT, DOWNGRADED to conditional, or DROPPED.

Design invariants
-----------------
* **Pure** — stdlib ``fnmatch`` + plain dict statements only; NO boto3, NO I/O,
  NO print. Unit-testable against hand-built statement lists.
* **Mirrors** ``aws_live_scanner._action_allowed`` (case-insensitive fnmatch) so
  the two engines can never diverge on action matching.
* **Fail-open to prior behavior** — the load-bearing rule. When BOTH ``boundary``
  and ``scp_levels`` are ``None`` (the caller could not read the ceiling data, or
  none applies), :func:`pivot_effective` can **never** return ``DROP`` for an
  identity-allowed pivot. The graph is then byte-for-byte identical to today.
* **Explicit-deny-wins, everywhere** — an unconditional explicit ``Deny`` matching
  the action at ANY scope collapses to ``DROP`` before any ``Allow`` is weighed.
* **Only PROVABLE unconditional denial prunes.** A grant or deny that is gated by
  a policy ``Condition`` we cannot evaluate offline downgrades the edge to
  CONDITIONED (WARN) — it is never silently dropped.

Evaluation order modeled (single-account, single-principal — the chain that
governs a control-plane pivot; session/resource policies are Phase 6):

    1. explicit unconditional Deny in the identity policy        -> DROP
    2. permission boundary is a *ceiling* (intersection): the action must be
       ALLOWED there; an EXPLICIT_DENY or IMPLICIT_DENY in the boundary -> DROP
    3. SCP path root -> OU.. -> account (AND-across-levels, OR-within-level): any
       level that does not allow the action (EXPLICIT_DENY / IMPLICIT_DENY) -> DROP
    4. session policy  -> DEFERRED (Phase 6)
    5. resource-based policy union -> out of scope for identity pivots

A CONDITIONAL verdict anywhere in the surviving chain propagates upward: the
final edge is CONDITIONED (never dropped) if any scope allowed/denied only under
a Condition.

Statement shape (produced by ``aws_live_scanner._policy_to_statements``)::

    {"effect": "Allow"|"Deny",
     "actions": set[str],          # lowercased fnmatch patterns; may be empty
     "not_actions": set[str],      # lowercased; inverse match (NotAction), optional
     "resources": set[str],        # unused here (action-level ceiling); optional
     "not_resources": set[str],    # optional
     "condition": dict|None}
"""

from __future__ import annotations

import fnmatch
from typing import Dict, List, Optional

# ── Edge verdicts (return of pivot_effective) ────────────────────────────────
KEEP = "keep"                 # ceiling permits it unconditionally -> hard edge
CONDITIONED = "conditioned"   # permitted only under a Condition -> WARN edge
DROP = "drop"                 # provably neutralized -> remove the edge

# ── Per-scope verdicts (return of eval_scope / eval_scp_level) ───────────────
ALLOWED = "allowed"                    # unconditional Allow present
ALLOWED_COND = "allowed_cond"          # only a conditioned Allow present
IMPLICIT_DENY = "implicit"             # nothing matched -> deny-by-default
EXPLICIT_DENY = "explicit"             # unconditional explicit Deny
EXPLICIT_DENY_COND = "explicit_cond"   # only a conditioned Deny, no Allow


def _action_matches(st: Dict, a: str) -> bool:
    """True if statement ``st`` applies to action ``a`` (already lowercased).

    Honors ``NotAction`` as an *inverse* match (the statement applies when the
    action is NOT in the ``not_actions`` list) while still carrying the
    statement's Effect — the common ``Deny NotAction:[...]`` /
    ``Allow NotAction:[...]`` guardrail shape. A ``NotAction`` statement is
    detected by a non-empty ``not_actions`` set, so a synthetic ``actions`` value
    kept for backward compatibility is ignored here.
    """
    nacts = st.get("not_actions") or set()
    if nacts:
        return not any(fnmatch.fnmatch(a, p) for p in nacts)
    return any(fnmatch.fnmatch(a, p) for p in (st.get("actions") or set()))


def eval_scope(action: str, statements: List[Dict]) -> str:
    """Evaluate ONE action against a flat statement list (one policy scope).

    Returns one of ``ALLOWED`` / ``ALLOWED_COND`` / ``IMPLICIT_DENY`` /
    ``EXPLICIT_DENY`` / ``EXPLICIT_DENY_COND``. Deny-wins: an unconditional
    explicit Deny short-circuits every Allow.
    """
    a = action.lower()
    ed = edc = al = alc = False
    for st in statements or ():
        if not _action_matches(st, a):
            continue
        cond = bool(st.get("condition"))
        if st.get("effect") == "Deny":
            if cond:
                edc = True
            else:
                ed = True
        elif st.get("effect") == "Allow":
            if cond:
                alc = True
            else:
                al = True
    if ed:
        return EXPLICIT_DENY          # unconditional deny always wins
    if al:
        return ALLOWED                # unconditional allow present
    if alc:
        return ALLOWED_COND           # only conditioned allow
    if edc:
        return EXPLICIT_DENY_COND     # only conditioned deny, no allow -> gated block
    return IMPLICIT_DENY              # nothing matched -> deny-by-default


def eval_scp_level(action: str, level_docs: List[List[Dict]]) -> str:
    """Evaluate one Organizations node (root, an OU, or the account) that may
    carry several SCPs. Within a level the SCPs are OR-ed for Allow but any
    single explicit Deny still wins. Returns ``ALLOWED`` / ``ALLOWED_COND`` /
    ``IMPLICIT_DENY`` / ``EXPLICIT_DENY``.

    A level with no SCP that allows the action is ``IMPLICIT_DENY`` — an SCP
    guardrail blocks by default (there is always at least ``FullAWSAccess`` in a
    healthy org, so an implicit deny here means the action was carved out).
    """
    saw = saw_c = False
    for scp in level_docs or ():
        r = eval_scope(action, scp)
        if r == EXPLICIT_DENY:
            return EXPLICIT_DENY       # deny wins within a level too
        if r == ALLOWED:
            saw = True
        elif r == ALLOWED_COND:
            saw_c = True
    if saw:
        return ALLOWED
    if saw_c:
        return ALLOWED_COND
    return IMPLICIT_DENY               # no SCP at this level allows -> guardrail blocks


def pivot_effective(
    action: str,
    identity_stmts: List[Dict],
    boundary: Optional[List[Dict]] = None,
    scp_levels: Optional[List[List[List[Dict]]]] = None,
) -> str:
    """Decide the fate of a pivot edge whose granting action is ``action``.

    Returns ``DROP`` | ``CONDITIONED`` | ``KEEP``.

    * ``boundary`` — the flat statement list of the principal's permission
      boundary, or ``None`` if it has none / could not be resolved (fail open).
    * ``scp_levels`` — ordered list of Organizations levels, each a list of that
      level's SCP statement-lists: ``[[stmts_scp1, stmts_scp2], ...]`` from root
      down to the account. ``None`` / empty means the SCP layer is not evaluated
      (management account, non-org, or unreadable) -> fail open.

    Fail-open guarantee: with ``boundary is None`` AND no ``scp_levels`` the
    function returns ``KEEP`` (or ``CONDITIONED`` only if the identity grant was
    already conditioned by the caller) and can never return ``DROP`` — identical
    to pre-Phase-5 behavior.
    """
    conditioned = False

    # 1. Identity — only a PROVABLE unconditional explicit Deny prunes here.
    if eval_scope(action, identity_stmts) == EXPLICIT_DENY:
        return DROP

    # 2. Permission boundary — a ceiling (intersection). Must ALLOW the action.
    # A boundary that only conditionally-denies with no Allow (EXPLICIT_DENY_COND)
    # still grants nothing, so the ceiling implicitly denies -> DROP. Only a real
    # conditioned Allow (ALLOWED_COND) keeps the edge as conditioned.
    if boundary is not None:
        b = eval_scope(action, boundary)
        if b in (EXPLICIT_DENY, IMPLICIT_DENY, EXPLICIT_DENY_COND):
            return DROP                       # boundary caps the action out
        if b == ALLOWED_COND:
            conditioned = True

    # 3. SCP path — AND across every level from root to the account.
    if scp_levels:
        for level in scp_levels:
            s = eval_scp_level(action, level)
            if s in (EXPLICIT_DENY, IMPLICIT_DENY):
                return DROP                   # a guardrail level blocks it
            if s == ALLOWED_COND:
                conditioned = True

    return CONDITIONED if conditioned else KEEP


# ── Reasons (surfaced as pruning evidence in aws_live_scanner) ───────────────
def drop_reason(
    action: str,
    identity_stmts: List[Dict],
    boundary: Optional[List[Dict]] = None,
    scp_levels: Optional[List[List[List[Dict]]]] = None,
) -> Optional[str]:
    """If :func:`pivot_effective` would DROP, return WHY (for audit / drift
    evidence); otherwise ``None``. Mirrors the precedence in pivot_effective."""
    if eval_scope(action, identity_stmts) == EXPLICIT_DENY:
        return "explicit_deny"
    if boundary is not None:
        b = eval_scope(action, boundary)
        if b == EXPLICIT_DENY:
            return "boundary_explicit_deny"
        if b in (IMPLICIT_DENY, EXPLICIT_DENY_COND):
            return "boundary_implicit_deny"
    if scp_levels:
        for level in scp_levels:
            s = eval_scp_level(action, level)
            if s == EXPLICIT_DENY:
                return "scp_explicit_deny"
            if s == IMPLICIT_DENY:
                return "scp_no_allow"
    return None
