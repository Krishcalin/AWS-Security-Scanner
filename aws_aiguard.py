"""Phase 2 · slice 2.1 — grade a Bedrock guardrail, and decide from IAM text alone
whether it is actually mandatory.

Every CNAPP checks a guardrail as a boolean: attached, or not. `BDR-02` in this scanner
does exactly that today and PASSes any guardrail that exists. The boolean is satisfied by
configurations that block nothing at all, which is the gap this module closes.

Two questions, both answerable from configuration the scanner may already read:

**Is it graded?** A guardrail carries per-category content filters, each with an input and
output strength (``NONE | LOW | MEDIUM | HIGH``) and an action (``BLOCK | NONE``). The
AWS reference is explicit about what ``NONE`` means as an action: *"Take no action but
return detection information in the trace response."* A guardrail whose filters all carry
``NONE`` is a monitoring device wearing the name of a control — and it satisfies every
"has a guardrail" check in the market. Separately, one filter type matters more than the
other five for agentic workloads: ``PROMPT_ATTACK``. Its absence, or its presence at
``NONE`` strength, means the guardrail is not addressing the threat that makes agents
different from APIs.

**Is it mandatory?** Attaching a guardrail to an agent does not stop a caller invoking the
model without one. AWS documents the enforcement mechanism as the ``bedrock:GuardrailIdentifier``
condition key, and every example in the reference pairs an ``Allow`` (``StringEquals`` /
``ArnLike``) with an explicit ``Deny`` (``StringNotEquals`` / ``ArnNotLike``). The reason
the pair is needed is stated there verbatim:

    The explicit deny keeps the user request from calling the listed actions with any
    other GuardrailIdentifier and guardrail version no matter what other permissions the
    user might have.

So an Allow-with-condition ALONE does not make a guardrail mandatory — it merely declines
to grant when the condition is unmet, and any other statement granting inference lets the
caller proceed with no guardrail at all. A policy carrying the Allow half and not the Deny
half is the specific shape of a team that believes it has enforced a guardrail and has
not. Detecting it requires no new permission: the statements are already collected.

WHAT THIS MODULE DELIBERATELY DOES NOT CLAIM
--------------------------------------------
*That a bare guardrail ID in a Condition never matches.* Every AWS example uses the full
ARN, and ``GetGuardrail`` says its own ``guardrailIdentifier`` parameter "can be an ID or
the ARN" — but the reference does not state which form the CONDITION KEY resolves to at
evaluation time. Flagging a bare ID as broken would be an inference about IAM internals
dressed as a reading of the policy, so it is left unflagged rather than guessed.

*That enforcement is absolute.* The same reference records a bypass verbatim: *"A user can
bypass applying a guardrail in their prompt by using guardrail input tags. However, the
guardrail is always applied on the response."* Enforcement here means the request cannot
omit the guardrail; it does not mean every input is inspected.

Pure functions over dicts — no boto3, no I/O — so the scanner supplies data and this
module supplies verdicts, the same split as ``aws_aispm.py``.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

# ── the vocabulary, from the Bedrock API reference (verified, not recalled) ──
CONTENT_FILTER_TYPES = ("SEXUAL", "VIOLENCE", "HATE", "INSULTS", "MISCONDUCT",
                        "PROMPT_ATTACK")
STRENGTHS = ("NONE", "LOW", "MEDIUM", "HIGH")
STRENGTH_RANK = {s: i for i, s in enumerate(STRENGTHS)}
ACTIONS = ("BLOCK", "NONE")

#: The filter that addresses the threat specific to agentic workloads. The other five
#: are content-safety categories; this one is the injection defence.
INJECTION_FILTER = "PROMPT_ATTACK"

#: Inference actions the guardrail condition key can be attached to. From
#: "Enforce the use of specific guardrails in model inference requests" — these four and
#: no others, so a Deny on some unrelated Bedrock action is not enforcement.
INFERENCE_ACTIONS = (
    "bedrock:invokemodel",
    "bedrock:invokemodelwithresponsestream",
    "bedrock:converse",
    "bedrock:conversestream",
)
GUARDRAIL_CONDITION_KEY = "bedrock:guardrailidentifier"

#: Condition operators that pin the request TO a guardrail (used in the Allow half).
POSITIVE_OPS = ("stringequals", "arnequals", "arnlike", "stringlike")
#: Condition operators that exclude everything else (used in the Deny half). Only these
#: make the guardrail mandatory.
NEGATIVE_OPS = ("stringnotequals", "arnnotequals", "arnnotlike", "stringnotlike")

#: APIs that make InvokeModel calls on the caller's behalf. The reference warns that a
#: role carrying the guardrail Deny should not also hold these, because those internal
#: calls do not all carry a guardrail and will be denied.
DELEGATING_ACTIONS = (
    "bedrock:invokeagent",
    "bedrock:invokeinlineagent",
    "bedrock:retrieveandgenerate",
)

# grades, weakest first
UNGRADED = "UNGRADED"           # nothing configured to grade
DETECT_ONLY = "DETECT_ONLY"     # configured, blocks nothing
PARTIAL = "PARTIAL"             # blocks, but not the injection threat
BLOCKING = "BLOCKING"           # blocks, including injection, at real strength
GRADES = (UNGRADED, DETECT_ONLY, PARTIAL, BLOCKING)

# enforcement verdicts
NOT_APPLICABLE = "NOT_APPLICABLE"   # this principal cannot invoke a model at all
UNENFORCED = "UNENFORCED"           # invokes models, no guardrail condition anywhere
ALLOW_ONLY = "ALLOW_ONLY"           # the Allow half without the Deny half
ENFORCED = "ENFORCED"               # explicit Deny present
VERDICTS = (NOT_APPLICABLE, UNENFORCED, ALLOW_ONLY, ENFORCED)


# ── helpers ─────────────────────────────────────────────────────────────────
def _filters(detail: Optional[dict]) -> List[dict]:
    if not detail:
        return []
    pol = detail.get("contentPolicy") or {}
    return [f for f in (pol.get("filters") or []) if isinstance(f, dict)]


def _acts(f: dict, side: str) -> Optional[str]:
    """The configured action for one side, upper-cased, or None if absent.

    Absent is NOT treated as ``NONE``: the reference marks inputAction/outputAction
    "Required: No" without stating the default, so reading absence as detect-only would
    invent a behaviour. Callers must treat None as unknown."""
    v = f.get(f"{side}Action")
    return v.upper() if isinstance(v, str) and v else None


def _enabled(f: dict, side: str) -> Optional[bool]:
    v = f.get(f"{side}Enabled")
    return v if isinstance(v, bool) else None


def _strength(f: dict, side: str) -> str:
    v = f.get(f"{side}Strength")
    return v.upper() if isinstance(v, str) and v else "NONE"


def blocks(f: dict, side: str) -> bool:
    """True when this side of the filter would actually stop content.

    Requires a non-NONE strength AND an action that is not explicitly NONE AND the side
    not explicitly disabled. Absent action counts as blocking, because absence is
    unknown and the conservative reading of unknown here is that the control works —
    claiming a guardrail is inert needs positive evidence, not a missing key."""
    if _enabled(f, side) is False:
        return False
    if STRENGTH_RANK.get(_strength(f, side), 0) == 0:
        return False
    return _acts(f, side) != "NONE"


def detect_only_filters(detail: Optional[dict]) -> List[dict]:
    """Filters that are switched on and explicitly set to take no action.

    Only an explicit ``NONE`` counts — see ``_acts``. Each entry names the type and the
    side(s), so the finding can say which."""
    out = []
    for f in _filters(detail):
        sides = [s for s in ("input", "output")
                 if _acts(f, s) == "NONE"
                 and STRENGTH_RANK.get(_strength(f, s), 0) > 0
                 and _enabled(f, s) is not False]
        if sides:
            out.append({"type": (f.get("type") or "?").upper(), "sides": sides})
    return out


def injection_posture(detail: Optional[dict]) -> dict:
    """The PROMPT_ATTACK filter's posture, which for an agent is the whole point.

    ``present`` False means no such filter is configured at all — the guardrail may be
    a perfectly good content-safety filter and still do nothing about injection."""
    for f in _filters(detail):
        if (f.get("type") or "").upper() == INJECTION_FILTER:
            return {
                "present": True,
                "input_strength": _strength(f, "input"),
                "output_strength": _strength(f, "output"),
                "input_blocks": blocks(f, "input"),
                # NB: PROMPT_ATTACK is an INPUT-side concern — an injection arrives in
                # the prompt — so the input side is what decides the posture.
                "effective": blocks(f, "input")
                and STRENGTH_RANK[_strength(f, "input")] >= STRENGTH_RANK["MEDIUM"],
            }
    return {"present": False, "input_strength": "NONE", "output_strength": "NONE",
            "input_blocks": False, "effective": False}


def grade_guardrail(detail: Optional[dict]) -> dict:
    """Grade one guardrail from its GetGuardrail response.

    Rule-based rather than scored: a number invites "where did 73 come from", while a
    grade plus the named weaknesses that produced it can be argued with."""
    fl = _filters(detail)
    inj = injection_posture(detail)
    detect_only = detect_only_filters(detail)
    any_blocking = any(blocks(f, "input") or blocks(f, "output") for f in fl)

    other = {}
    if detail:
        other = {
            "denied_topics": len(((detail.get("topicPolicy") or {}).get("topics")) or []),
            "pii_entities": len(((detail.get("sensitiveInformationPolicy") or {})
                                 .get("piiEntities")) or []),
            "regexes": len(((detail.get("sensitiveInformationPolicy") or {})
                            .get("regexes")) or []),
            "grounding": len(((detail.get("contextualGroundingPolicy") or {})
                              .get("filters")) or []),
            "word_lists": len(((detail.get("wordPolicy") or {})
                               .get("managedWordLists")) or []),
        }

    weaknesses: List[str] = []
    if not fl and not any(other.values()):
        grade = UNGRADED
        weaknesses.append("no content filters, denied topics, PII rules or grounding "
                          "checks are configured")
    elif fl and not any_blocking:
        grade = DETECT_ONLY
        weaknesses.append("every content filter is set to detect without blocking")
    elif not inj["effective"]:
        grade = PARTIAL
        if not inj["present"]:
            weaknesses.append(f"no {INJECTION_FILTER} filter — content safety is graded, "
                              f"prompt injection is not addressed")
        elif not inj["input_blocks"]:
            weaknesses.append(f"{INJECTION_FILTER} is configured but does not block on "
                              f"input")
        else:
            weaknesses.append(f"{INJECTION_FILTER} input strength is "
                              f"{inj['input_strength']}, below MEDIUM")
    else:
        grade = BLOCKING

    if detect_only and grade != DETECT_ONLY:
        weaknesses.append(
            "detect-only filters: " +
            ", ".join(f"{d['type']} ({'+'.join(d['sides'])})" for d in detect_only))

    version = (detail or {}).get("version") or ""
    status = ((detail or {}).get("status") or "").upper()
    return {
        "grade": grade,
        "weaknesses": weaknesses,
        "injection": inj,
        "detect_only": detect_only,
        "filters": len(fl),
        "other": other,
        "version": version,
        "draft_only": version.upper() == "DRAFT",
        "status": status,
        "ready": status in ("", "READY"),
    }


# ── enforcement, read out of the identity policy ────────────────────────────
def _matches_action(granted: Iterable[str], target: str) -> bool:
    """Wildcard-aware action match, on already-lowercased policy actions."""
    t = target.lower()
    svc = t.split(":", 1)[0]
    for a in granted:
        a = (a or "").lower()
        if a in ("*", f"{svc}:*") or a == t:
            return True
        if a.endswith("*") and t.startswith(a[:-1]):
            return True
    return False


def _guardrail_condition(stmt: dict, ops: Sequence[str]) -> Optional[Any]:
    """The guardrail condition value under any of `ops`, or None."""
    cond = stmt.get("condition") or {}
    if not isinstance(cond, dict):
        return None
    for op, kv in cond.items():
        if (op or "").lower().replace("ifexists", "") not in ops:
            continue
        if not isinstance(kv, dict):
            continue
        for key, val in kv.items():
            if (key or "").lower() == GUARDRAIL_CONDITION_KEY:
                return val
    return None


def enforcement_verdict(statements: Optional[Sequence[dict]]) -> dict:
    """Decide whether this principal's policy makes a guardrail MANDATORY.

    Reads only statements already collected for every principal, so it costs no new
    permission. The distinction that matters is ALLOW_ONLY vs ENFORCED: both look like
    "we enforce guardrails" to a human reading the policy, and only one of them does."""
    stmts = [s for s in (statements or []) if isinstance(s, dict)]
    inference = [s for s in stmts
                 if any(_matches_action(s.get("actions") or (), a)
                        for a in INFERENCE_ACTIONS)]
    if not inference:
        return {"verdict": NOT_APPLICABLE, "guardrails": [], "reason":
                "principal cannot invoke a model", "delegating": []}

    def _vals(v):
        return [x for x in (v if isinstance(v, (list, tuple)) else [v]) if x]

    denies, allows = [], []
    for s in inference:
        eff = (s.get("effect") or "").lower()
        if eff == "deny":
            v = _guardrail_condition(s, NEGATIVE_OPS)
            if v is not None:
                denies.extend(_vals(v))
        elif eff == "allow":
            v = _guardrail_condition(s, POSITIVE_OPS)
            if v is not None:
                allows.extend(_vals(v))

    delegating = sorted({a for s in stmts if (s.get("effect") or "").lower() == "allow"
                         for a in DELEGATING_ACTIONS
                         if _matches_action(s.get("actions") or (), a)})

    if denies:
        return {"verdict": ENFORCED, "guardrails": sorted(set(denies)),
                "reason": "an explicit Deny excludes every other guardrail",
                "delegating": delegating}
    if allows:
        return {"verdict": ALLOW_ONLY, "guardrails": sorted(set(allows)),
                "reason": ("the Allow half is present without the explicit Deny, so any "
                           "other statement granting inference lets the caller invoke "
                           "with no guardrail"),
                "delegating": delegating}
    return {"verdict": UNENFORCED, "guardrails": [],
            "reason": "inference is granted with no guardrail condition on any statement",
            "delegating": delegating}
