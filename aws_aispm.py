#!/usr/bin/env python3
"""aws_aispm.py — AI-SPM (AI Security Posture Management) pure classifiers.

Boto3-free. Consumes the dicts the live scanner's AI sections already fetch
(SageMaker notebooks/Studio domains, Bedrock agents) plus the parsed IAM
statement shape produced by ``aws_live_scanner._policy_to_statements`` — the same
shape ``aws_deepplane`` consumes: each statement is::

    {"effect": "Allow"|"Deny", "actions": set[str], "resources": set[str],
     "not_resources": set[str], "condition": dict|None}

with actions/resources lowercased.

Why a separate pillar. The existing per-resource checks (BDR-*/AGT-*/SM-*) audit
the *configuration* of an AI resource — KMS on the volume, a Guardrail on the
agent, the notebook's direct-internet flag. None of them ask the CNAPP question:
what is the blast radius of the identity the model/agent RUNS AS? An AI execution
role that can escalate privilege or read crown-jewel data turns the model endpoint
into a high-value compromise anchor. This module supplies those two identity
classifiers (``role_privesc_capable`` / ``role_reaches_crown``) plus a
network-isolation test and a crown-asset test, all offline-testable, and the
scanner fuses their results onto the attack-path graph in the DATA section
(post-clobber) with NO change to ``aws_correlate`` — reusing the existing
``HAS_ROLE`` / ``CAN_READ_DATA`` edge kinds and the prop-based ``crown_nodes``.
"""
from __future__ import annotations

from fnmatch import fnmatch
from typing import Dict, List, Optional, Tuple

import aws_effperm


# Identity actions that let a principal escalate toward administrative control.
# Lowercased; matched wildcard-aware so ``iam:*`` / ``*`` subsume the specific
# entries. Deliberately conservative — only the well-known privilege-escalation
# primitives, evaluated against an UNSCOPED (``*``) resource, so a tightly scoped
# grant (e.g. PassRole to one service role ARN) is not flagged.
AI_PRIVESC_ACTIONS = (
    "iam:passrole",
    "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:attachrolepolicy", "iam:attachuserpolicy", "iam:attachgrouppolicy",
    "iam:putrolepolicy", "iam:putuserpolicy", "iam:putgrouppolicy",
    "iam:createaccesskey", "iam:createloginprofile", "iam:updateloginprofile",
    "iam:updateassumerolepolicy", "iam:addusertogroup",
    "sts:assumerole",
)


def _actions_match(action_patterns, action: str) -> bool:
    """True if ``action`` is granted by any (wildcard-aware) pattern in the set."""
    return any(fnmatch(action, p) for p in (action_patterns or set()))


def _unscoped(resources) -> bool:
    """A statement's Resource is unscoped iff it contains the bare ``*``. A
    partially-wildcarded ARN (``…:role/*``) is NOT treated as unscoped here — a
    documented conservative false-negative that mirrors ``role_can_read_store``'s
    coarse-but-safe stance and avoids over-flagging narrowly-targeted grants."""
    return any(p == "*" for p in (resources or set()))


def _privesc_grants(statements: List[dict]) -> List[Tuple[str, str]]:
    """Every ``(action, reason)`` the identity statements grant on an unscoped
    resource, in the order ``role_privesc_capable`` would have reported them.

    A bare ``*`` on ``*`` expands to the whole of ``AI_PRIVESC_ACTIONS`` rather than
    to a single synthetic action, because a ceiling that neutralises one escalation
    route has NOT neutralised administrative access — the other routes must each be
    tested against it before the capability can be called gone."""
    out: List[Tuple[str, str]] = []
    for st in statements or []:
        if st.get("effect") != "Allow":
            continue
        acts = st.get("actions", set())
        if not _unscoped(st.get("resources", set())):
            continue
        if "*" in acts:
            reason = "grants * on * (full administrative access)"
            out.extend((a, reason) for a in AI_PRIVESC_ACTIONS)
            continue
        for pa in AI_PRIVESC_ACTIONS:
            if _actions_match(acts, pa):
                out.append((pa, f"grants {pa} on an unscoped (*) resource"))
    return out


def role_privesc_capable(statements: List[dict]) -> Optional[str]:
    """Return a short reason string if the role's *identity* statements let it
    escalate privilege — a full ``*`` on ``*`` (administrative), or a known
    privilege-escalation action on an unscoped resource — else ``None``.

    This is a posture SIGNAL, not an authorization decision: a broad Allow that a
    narrow Deny might claw back is still surfaced (conservative, matching the
    existing WARN-on-broad intent of AGT-02/BDR-05). Deny/Condition are not
    modelled; the caller treats the result as "worth a human's attention".

    Prefer :func:`role_privesc_effective` where a permission boundary or SCP context
    is available — this function deliberately ignores both."""
    hits = _privesc_grants(statements)
    return hits[0][1] if hits else None


def role_privesc_effective(
    statements: List[dict],
    boundary: Optional[List[dict]] = None,
    scp_levels: Optional[List] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """``(verdict, reason)`` for the role's escalation capability AFTER the
    permission-boundary and SCP ceiling are applied.

    ``verdict`` is :data:`aws_effperm.KEEP` (survives unconditionally),
    :data:`aws_effperm.CONDITIONED` (survives only under a Condition), or ``None``
    (the ceiling provably neutralises every escalation route this role had).

    WHY THIS EXISTS. ``role_privesc_capable`` reads identity statements alone: no
    permission boundary, no SCP, no explicit Deny, no Condition. Enterprises put
    boundaries on AI execution roles *precisely because* those roles are new and
    unproven — so the raw signal over-reports on exactly the accounts most likely to
    be evaluating the product, and it contradicts the CIEM verdict OverWatch already
    computes for the very same role. Two parts of one product disagreeing about one
    role is worse than either answer alone.

    The fail-open guarantee is inherited from :func:`aws_effperm.pivot_effective`:
    with no boundary and no SCP levels this can never return ``None``, so an account
    whose ceiling we cannot read keeps the old, conservative behaviour."""
    hits = _privesc_grants(statements)
    if not hits:
        return None, None
    reason = hits[0][1]
    best: Optional[str] = None
    for action, _ in hits:
        v = aws_effperm.pivot_effective(action, statements, boundary, scp_levels)
        if v == aws_effperm.KEEP:
            return aws_effperm.KEEP, reason
        if v == aws_effperm.CONDITIONED:
            best = aws_effperm.CONDITIONED
    return best, reason


def role_reaches_crown(graph, role_arn: str) -> Optional[str]:
    """Return the crown datastore's label if the role node already has a
    ``CAN_READ_DATA`` edge to a ``crown_jewel`` datastore in the graph — the very
    edges the Macie/DSPM passes emit earlier in the DATA section — else ``None``.

    A GRAPH query, not a policy re-parse: AISPM's data-reachability verdict is
    therefore identical to the one the correlate/flagship engine uses, so the two
    can never disagree."""
    if graph is None or not role_arn:
        return None
    for e in graph.out_edges(role_arn, ["CAN_READ_DATA"]):
        dst = graph.node(e.get("dst"))
        props = (dst or {}).get("props") or {}
        if props.get("crown_jewel"):
            return props.get("name") or e.get("dst")
    return None


def ai_network_exposed(resource: dict) -> bool:
    """True if an AI resource lacks network isolation, from the normalized
    ``network`` sub-dict recorded at stash time: SageMaker direct-internet egress
    on, or not attached to a VPC subnet, or a Studio domain with public-internet
    egress. Resources with no network surface (``network_checkable=False``, e.g.
    Bedrock agents) are never passed here."""
    if not resource:
        return False
    net = resource.get("network") or {}
    if net.get("direct_internet") is True:
        return True
    if net.get("public_egress") is True:
        return True
    if net.get("in_vpc") is False:
        return True
    return False


def ai_exposure_basis(resource: dict) -> Optional[str]:
    """WHY the resource counts as exposed, for the ``basis`` prop on the EXPOSED_TO
    edge. Mirrors :func:`ai_network_exposed` clause for clause, so the edge can never
    claim an exposure the classifier did not find — a reader can then tell a notebook
    with direct internet egress from a Studio domain with public egress from a
    resource simply never attached to a VPC, which are three different fixes."""
    net = (resource or {}).get("network") or {}
    if net.get("direct_internet") is True:
        return "sagemaker-direct-internet"
    if net.get("public_egress") is True:
        return "sagemaker-public-egress"
    if net.get("in_vpc") is False:
        return "not-vpc-attached"
    return None


def is_ai_crown(resource: dict) -> bool:
    """A data-bearing AI asset worth protecting as a crown terminal (its storage
    holds notebooks/source/cached credentials or training data) — flagged
    ``data_bearing`` at stash time (SageMaker Studio domains today). Notebooks and
    agents are compromise ANCHORS, not data terminals, so they are not marked
    crowns themselves."""
    return bool(resource and resource.get("data_bearing"))
