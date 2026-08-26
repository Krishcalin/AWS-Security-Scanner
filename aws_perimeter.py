#!/usr/bin/env python3
"""aws_perimeter.py — Phase 5 · slice 5.2: data-perimeter posture.

OverWatch already *recommends* ``aws:PrincipalOrgID`` in some twenty remediation
strings. It has never once **checked** whether the estate has a data perimeter. This
slice closes that gap: it reads the policies that would constitute one and reports which
of AWS's three perimeter objectives the estate actually has controls for.

THE MODEL, FROM AWS RATHER THAN FROM INTUITION
-----------------------------------------------
Source: *Building a Data Perimeter on AWS* (AWS whitepaper, "Perimeter implementation"),
cross-checked against the IAM global condition keys reference. The matrix is **not** the
symmetric 3x3 an intuition would draw, and getting it wrong would produce confident
nonsense — so it is recorded here as data, with the asymmetry called out:

    Only trusted IDENTITIES  ->  RCPs + VPC endpoint policies      (NOT SCPs)
    Only trusted RESOURCES   ->  SCPs + VPC endpoint policies      (NOT RCPs)
    Only expected NETWORKS   ->  SCPs + RCPs

The asymmetry follows from what each policy type governs. An SCP bounds what *your*
principals may do, so it cannot say who may reach your resources — that is an RCP's job.
An RCP bounds who may reach *your* resources, so it cannot say which foreign resources
your principals may call — that is an SCP's job. A control in the wrong place is not a
weaker perimeter; it is not that perimeter at all, and this module reports it as such.

WHAT THIS CAN AND CANNOT CLAIM
-------------------------------
It reads **presence and shape**, never effect. Establishing that a perimeter actually
holds requires evaluating an authorization decision against every principal, resource and
path — which is not a configuration read, and claiming it from one would be the phantom
this codebase keeps catching. So the honest verb is *"a policy requiring X is attached"*,
never *"X is enforced"* / *"prevented"* / *"blocked"*. A test asserts those three words
never appear in any string this module emits.

Four consequences of AWS's own model bound the claims further, and each is stated in the
output rather than left for the reader to know:

  * **SCPs do not apply to the management account**, nor to service-linked roles or AWS
    service principals. A perimeter resting on SCPs has those holes by design.
  * **VPC endpoint policies only apply to same-Region calls.** A cross-Region request
    does not traverse the endpoint, so the policy never evaluates — an endpoint policy
    alone is not a Region-wide claim.
  * **`aws:PrincipalIsAWSService` and `aws:SourceOrgID` exceptions are expected**, not
    weaknesses. You cannot write ``NotPrincipal`` against a service principal, so this is
    the documented way to exempt one from a Deny. Flagging it would punish correctness.
  * **Unreadable is not absent.** Organizations reads fail from a member account. An
    unread policy layer is reported as unevaluated, never as a clean pass.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import json
from typing import Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import unquote

__all__ = [
    "SOURCE", "OBJ_IDENTITY", "OBJ_RESOURCE", "OBJ_NETWORK", "OBJECTIVES",
    "PERIMETER_MODEL", "SCP", "RCP", "VPCE",
    "MET", "PARTIAL", "UNMET", "UNREADABLE",
    "parse_policy", "statement_keys", "assess_objective", "assess_estate",
    "describe_objective", "SCOPE_NOTES",
]

SOURCE = ("AWS whitepaper 'Building a Data Perimeter on AWS' (Perimeter implementation) "
          "+ IAM global condition keys reference")

# ── the three objectives, in AWS's wording ──────────────────────────────────
OBJ_IDENTITY = "only-trusted-identities"
OBJ_RESOURCE = "only-trusted-resources"
OBJ_NETWORK = "only-expected-networks"
OBJECTIVES = (OBJ_IDENTITY, OBJ_RESOURCE, OBJ_NETWORK)

# ── policy types ────────────────────────────────────────────────────────────
SCP = "SCP"
RCP = "RCP"
VPCE = "VPCEndpointPolicy"

# ── posture verdicts ────────────────────────────────────────────────────────
MET = "met"                 # a policy of a type AWS names, carrying a primary key
PARTIAL = "partial"         # only a granular/narrower key, or only one of two types
UNMET = "unmet"             # readable, and nothing implements this objective
UNREADABLE = "unreadable"   # the policy layer could not be read — NEVER a pass

#: The matrix. Every key below was verified verbatim against a primary source.
#: ``aws:VpcSourceIp`` is deliberately ABSENT: verification against the condition-keys
#: reference came back inconclusive, and asserting a key on a failed verification is
#: exactly the phantom this module exists to avoid. Excluding it costs a little recall.
PERIMETER_MODEL: Dict[str, Dict] = {
    OBJ_IDENTITY: {
        "question": "can only trusted identities reach my resources and use my networks?",
        # NOT SCP — an SCP bounds what my principals may do, not who may reach me.
        "policy_types": (RCP, VPCE),
        "primary": ("aws:principalorgid",),
        "granular": ("aws:principalaccount", "aws:principalorgpaths"),
        "expected_exceptions": ("aws:principalisawsservice", "aws:sourceorgid",
                                "aws:sourceorgpaths", "aws:sourceaccount"),
    },
    OBJ_RESOURCE: {
        "question": "can my principals and networks reach only trusted resources?",
        # NOT RCP — an RCP bounds who reaches me, not which foreign resource I call.
        "policy_types": (SCP, VPCE),
        "primary": ("aws:resourceorgid",),
        "granular": ("aws:resourceaccount", "aws:resourceorgpaths"),
        "expected_exceptions": ("aws:calledvia", "aws:viaawsservice"),
    },
    OBJ_NETWORK: {
        "question": "can requests reach my resources only from expected networks?",
        "policy_types": (SCP, RCP),
        "primary": ("aws:sourceip", "aws:sourcevpc"),
        "granular": ("aws:sourcevpce", "aws:vpceorgid"),
        "expected_exceptions": ("aws:viaawsservice", "aws:principalisawsservice"),
    },
}

#: Limits AWS's own model imposes. Emitted with the findings rather than assumed known.
SCOPE_NOTES = {
    SCP: ("SCPs do not apply to the management account, to service-linked roles, or to "
          "AWS service principals — a perimeter resting on SCPs has those holes by design"),
    VPCE: ("a VPC endpoint policy only evaluates on same-Region calls; a cross-Region "
           "request does not traverse the endpoint, so an endpoint policy alone is not a "
           "Region-wide claim"),
    RCP: ("RCPs apply to resources in the organization and are evaluated in addition to "
          "resource-based policies, not instead of them"),
}


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


def _as_list(v) -> list:
    if v is None:
        return []
    return [v] if isinstance(v, (str, bytes)) else (list(v) if isinstance(v, (list, tuple)) else [v])


def parse_policy(doc) -> List[Dict]:
    """Parse a policy document, KEEPING the condition block and the principal.

    The scanner's own ``_policy_to_statements`` drops ``Principal``, and the condition is
    the entire subject here — so this module parses for itself rather than inheriting a
    normalizer shaped for a different question. Accepts a dict, a JSON string, or a
    URL-encoded JSON string (Organizations returns policy content as a string)."""
    if not doc:
        return []
    if isinstance(doc, (bytes, bytearray)):
        try:
            doc = doc.decode("utf-8")
        except Exception:
            return []
    if isinstance(doc, str):
        for candidate in (doc, unquote(doc)):
            try:
                doc = json.loads(candidate)
                break
            except Exception:
                continue
        if isinstance(doc, str):
            return []
    stmts = _d(doc).get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    out: List[Dict] = []
    for st in (stmts or []):
        if not isinstance(st, dict):
            continue
        effect = st.get("Effect")
        if effect not in ("Allow", "Deny"):
            continue
        out.append({
            "effect": effect,
            "actions": {str(a).lower() for a in _as_list(st.get("Action"))},
            "not_actions": {str(a).lower() for a in _as_list(st.get("NotAction"))},
            "resources": {str(r).lower() for r in _as_list(st.get("Resource"))},
            "principals": st.get("Principal"),
            "not_principals": st.get("NotPrincipal"),
            "condition": _d(st.get("Condition")) or None,
        })
    return out


def statement_keys(stmt: Optional[dict]) -> set:
    """Every condition key a statement tests, lowercased.

    A condition block is ``{operator: {key: value}}``, and both levels vary in case. The
    operator may carry ``IfExists`` / ``ForAnyValue:`` / ``ForAllValues:`` decoration,
    which does not change which key is being tested."""
    cond = _d(_d(stmt).get("condition"))
    keys = set()
    for _op, mapping in cond.items():
        for k in _d(mapping):
            keys.add(str(k).lower())
    return keys


def _policy_keys(policies: Optional[Sequence]) -> set:
    """Union of condition keys across a list of parsed-or-raw policy documents."""
    keys = set()
    for pol in (policies or []):
        stmts = pol if isinstance(pol, list) else parse_policy(pol)
        for st in (stmts or []):
            keys |= statement_keys(st)
    return keys


def assess_objective(objective: str,
                     layers: Optional[Mapping] = None) -> dict:
    """Posture for one perimeter objective.

    ``layers`` maps a policy type (SCP/RCP/VPCEndpointPolicy) to either a list of policy
    documents, or ``None`` meaning THAT LAYER WAS NOT READABLE. The distinction is the
    whole point: an unreadable layer can never contribute a pass, and an objective whose
    only relevant layer is unreadable is ``unreadable``, not ``unmet``.

    Only the policy types AWS names for this objective are consulted. An SCP carrying
    ``aws:PrincipalOrgID`` does not make the identity perimeter met — an SCP cannot
    constrain who reaches your resources, so the control is in a place where it does not
    do that job."""
    spec = PERIMETER_MODEL.get(objective)
    if not spec:
        return {"objective": objective, "verdict": UNREADABLE, "evidence": (),
                "unreadable_types": (), "statement": "unknown objective"}
    lay = _d(layers)
    primary, granular = set(spec["primary"]), set(spec["granular"])

    evidence: List[Tuple[str, str]] = []
    granular_hits: List[Tuple[str, str]] = []
    unreadable: List[str] = []
    readable: List[str] = []
    for ptype in spec["policy_types"]:
        docs = lay.get(ptype, None) if ptype in lay else None
        if docs is None:
            unreadable.append(ptype)
            continue
        readable.append(ptype)
        keys = _policy_keys(docs)
        for k in sorted(keys & primary):
            evidence.append((ptype, k))
        for k in sorted(keys & granular):
            granular_hits.append((ptype, k))

    # A primary key in ANY readable named type is the control being present. An
    # unread OTHER layer is a limit on the VIEW, not a downgrade of the control:
    # AWS's objectives have two clauses ("trusted identities can access my RESOURCES"
    # -> RCP, "...are allowed from my NETWORKS" -> endpoint policy), and endpoint
    # policies are per-Region, so requiring both would mean no estate could ever score.
    # The unread layer is carried as `partial_view` and said out loud instead.
    if evidence:
        verdict = MET
    elif granular_hits:
        verdict = PARTIAL
    elif unreadable:
        # ASYMMETRY, and it is deliberate. Positive evidence from ONE layer proves the
        # control is present. Claiming it is ABSENT requires having read EVERY policy
        # type AWS names for the objective -- the key might be sitting in the layer that
        # was denied. A member-account scan reads the (empty) endpoint layer and is
        # denied Organizations; reporting that as "no perimeter" would be a finding
        # manufactured out of a permission error.
        verdict = UNREADABLE
    else:
        verdict = UNMET

    return {
        "objective": objective,
        "question": spec["question"],
        "verdict": verdict,
        "policy_types": tuple(spec["policy_types"]),
        "evidence": tuple(evidence),
        "granular_evidence": tuple(granular_hits),
        "unreadable_types": tuple(unreadable),
        "readable_types": tuple(readable),
        "partial_view": bool(unreadable),
        "statement": _statement(objective, spec, verdict, evidence, granular_hits,
                                unreadable, readable),
    }


def _keylist(pairs) -> str:
    return ", ".join(sorted({f"{k} in a {p}" for p, k in pairs}))


def _statement(objective, spec, verdict, evidence, granular, unreadable, readable) -> str:
    types = "/".join(spec["policy_types"])
    if verdict == UNREADABLE:
        return (f"The {objective} perimeter was NOT assessed: none of the policy types "
                f"AWS names for it ({types}) could be read. Not assessed is not clean")
    if verdict == MET:
        s = (f"A policy requiring {_keylist(evidence)} is attached, which is how AWS "
             f"describes implementing '{spec['question']}'")
        if unreadable:
            s += (f"; the {'/'.join(unreadable)} layer could not be read, so this is a "
                  f"partial VIEW of a control that is present, not a partial control")
    elif verdict == PARTIAL:
        s = (f"A narrower control is attached ({_keylist(granular)}) rather than the "
             f"primary key AWS names ({', '.join(sorted(spec['primary']))}); it bounds "
             f"the same objective more tightly but only for what it names")
    else:
        s = (f"No {types} policy read carries any of the condition keys AWS names for "
             f"'{spec['question']}' ({', '.join(sorted(spec['primary']))})")
    notes = [SCOPE_NOTES[p] for p in spec["policy_types"] if p in SCOPE_NOTES
             and (p in readable or verdict == UNMET)]
    return s + (". " + "; ".join(notes) if notes else "")


def assess_estate(layers: Optional[Mapping] = None) -> dict:
    """All three objectives plus a counted summary.

    ``met`` counts only objectives with a primary key in a policy type AWS names for
    them. ``unreadable`` is counted apart from ``unmet`` throughout — an estate whose
    Organizations layer is unreadable has an unknown perimeter, not a missing one, and
    folding the two together would turn a coverage gap into a finding."""
    rows = [assess_objective(o, layers) for o in OBJECTIVES]
    by = {r["objective"]: r for r in rows}
    met = [r for r in rows if r["verdict"] == MET]
    partial = [r for r in rows if r["verdict"] == PARTIAL]
    unmet = [r for r in rows if r["verdict"] == UNMET]
    unread = [r for r in rows if r["verdict"] == UNREADABLE]
    return {
        "objectives": tuple(rows),
        "by_objective": by,
        "met": len(met),
        "partial": len(partial),
        "unmet": len(unmet),
        "unreadable": len(unread),
        "total": len(rows),
        "complete": len(met) == len(rows),
        "statement": _estate_statement(len(met), len(partial), len(unmet), len(unread),
                                       len(rows)),
    }


def _estate_statement(met, partial, unmet, unread, total) -> str:
    if unread == total:
        return ("None of AWS's three data-perimeter objectives could be assessed: for "
                "each, at least one of the policy types AWS names for it could not be "
                "read. Not assessed is not clean")
    bits = [f"{met} of {total} AWS data-perimeter objectives have a policy of the type "
            f"AWS names for them carrying the primary condition key"]
    if partial:
        bits.append(f"{partial} have partial coverage")
    if unmet:
        bits.append(f"{unmet} have none")
    if unread:
        bits.append(f"{unread} could not be assessed and are reported as unknown rather "
                    f"than as absent")
    return ("; ".join(bits) + ". This reads the PRESENCE and SHAPE of the policies, not "
            "their effect: establishing that a perimeter holds requires evaluating "
            "authorization for every principal, resource and path, which no "
            "configuration read can do")


def describe_objective(posture: Optional[dict]) -> str:
    """One line for an objective that has no primary control — empty otherwise."""
    p = _d(posture)
    if p.get("verdict") in (MET, UNREADABLE, None):
        return ""
    spec = PERIMETER_MODEL.get(p.get("objective")) or {}
    if not spec:
        return ""
    return (f"The '{spec.get('question')}' perimeter has no "
            f"{'/'.join(spec.get('policy_types', ()))} policy carrying "
            f"{' or '.join(sorted(spec.get('primary', ())))} — "
            f"{p.get('statement', '')}")
