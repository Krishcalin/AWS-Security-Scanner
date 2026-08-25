"""Phase 2 · slice 2.6 — GuardDuty AI Protection, re-ranked.

GuardDuty AI Protection ships three finding types, and **all three carry a default
severity of Low**::

    Impact:IAMUser/AnomalousModelInvocation   AML.T0040  AI Model Inference API Access
    Impact:IAMUser/CostHarvesting             AML.T0034  Cost Harvesting
    Impact:IAMUser/PromptInjection.Direct     AML.T0051  LLM Prompt Injection

That is not a criticism of GuardDuty. Low is the right default for a detector that holds
the event and not the environment: an anomalous invocation by a scoped read-only identity
genuinely is low. The same event by an identity that can escalate privilege and read a
crown-jewel bucket is not, and nothing in the finding says which one you have.

So this module does not re-detect anything. It recognises the three types, reads the two
facts GuardDuty already puts in the finding that change the answer, and hands the result
to the identity-reach join that ``aws_airules.rerank`` already performs.

THE TWO FACTS WORTH READING
---------------------------
**Whether the guardrail actually blocked it.** ``PromptInjection.Direct`` carries
``contentPolicyFilters[].action``, which AWS documents as ``BLOCKED`` if the guardrail
blocked the content or ``NONE`` if the guardrail "detected the prompt attack but was
configured only to report it". A detected-and-allowed injection is a materially different
event from a detected-and-blocked one, and it is the same defect ``AIGRD-02`` reports
from the other direction — there as a configuration, here as an outcome that already
happened.

**Which models were touched.** ``resource.modelDetails[].modelId`` names them, which is
what makes "an anomalous invocation" answerable as "of what".

The ATLAS technique on each line is AWS's own mapping, quoted from the finding-type
documentation rather than assigned here.

Pure functions over dicts — no boto3, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

#: The three AI Protection finding types, their ATLAS technique (AWS's own mapping) and
#: what the finding actually asserts. Default severity is Low for all three.
AI_PROTECTION: Dict[str, Dict[str, str]] = {
    "Impact:IAMUser/AnomalousModelInvocation": {
        "atlas": "AML.T0040",
        "atlas_name": "AI Model Inference API Access",
        "asserts": ("an identity invoked a model in a way that deviates from its own "
                    "baseline — a new IP, a new user agent, or a model it has never "
                    "called"),
    },
    "Impact:IAMUser/CostHarvesting": {
        "atlas": "AML.T0034",
        "atlas_name": "Cost Harvesting",
        "asserts": ("token volumes far above the identity's baseline — inflating the "
                    "bill rather than taking the data"),
    },
    "Impact:IAMUser/PromptInjection.Direct": {
        "atlas": "AML.T0051",
        "atlas_name": "LLM Prompt Injection",
        "asserts": ("a Bedrock guardrail detected a prompt attack with HIGH confidence "
                    "in a live invocation"),
    },
}

#: GuardDuty's documented default for every AI Protection finding.
DEFAULT_SEVERITY_BAND = "Low"

# guardrail outcomes, from resource.bedrockGuardrailDetails
BLOCKED = "BLOCKED"
REPORTED_ONLY = "REPORTED_ONLY"
OUTCOME_UNKNOWN = "UNKNOWN"


def _ci(d: Optional[dict], *names: str) -> Any:
    """Case-insensitive member lookup.

    Not defensive padding — a real inconsistency in the source. GuardDuty's finding
    object is PascalCase (``Type``, ``Resource``, ``Severity``), while the AI Protection
    documentation writes the new nested paths in lowercase (``resource.modelDetails``,
    ``resource.bedrockGuardrailDetails``). Picking one casing and being wrong does not
    raise; it silently matches nothing, which is the failure mode that looks like a clean
    account. Accepting either is the only reading that cannot be quietly wrong."""
    if not isinstance(d, dict):
        return None
    lowered = {str(k).lower(): v for k, v in d.items()}
    for n in names:
        if n in d:
            return d[n]
        v = lowered.get(n.lower())
        if v is not None:
            return v
    return None


def is_ai_protection(finding: Optional[dict]) -> bool:
    return bool(finding) and (_ci(finding, "Type", "type") or "") in AI_PROTECTION


def technique(finding_type: str) -> dict:
    """AWS's own ATLAS mapping for a finding type, or an empty dict."""
    return dict(AI_PROTECTION.get(finding_type or "", {}))


def models_touched(finding: Optional[dict]) -> List[str]:
    """``resource.modelDetails[].modelId`` — what was actually invoked."""
    res = _ci(finding, "Resource", "resource") or {}
    details = _ci(res, "modelDetails") or []
    if not isinstance(details, (list, tuple)):
        return []
    return sorted({_ci(d, "modelId") for d in details
                   if isinstance(d, dict) and _ci(d, "modelId")})


def guardrail_outcome(finding: Optional[dict]) -> dict:
    """Did the guardrail block the injection, or only notice it?

    AWS documents the field precisely: ``action`` is ``BLOCKED`` if the guardrail blocked
    the content, or ``NONE`` if it "detected the prompt attack but was configured only to
    report it". ``REPORTED_ONLY`` is therefore an event where an attack was recognised and
    allowed through — the runtime counterpart of the detect-only configuration AIGRD-02
    reports.

    Absent details give ``UNKNOWN`` rather than either verdict: a finding type that
    carries no guardrail block at all is not evidence that nothing blocked."""
    res = _ci(finding, "Resource", "resource") or {}
    gd = _ci(res, "bedrockGuardrailDetails")
    if not isinstance(gd, dict) or not gd:
        return {"outcome": OUTCOME_UNKNOWN, "guardrails": [], "source": ""}

    filters = _ci(gd, "contentPolicyFilters") or []
    actions = {str(_ci(f, "action") or "").upper()
               for f in filters if isinstance(f, dict)}
    if "NONE" in actions:
        outcome = REPORTED_ONLY
    elif "BLOCKED" in actions:
        outcome = BLOCKED
    else:
        # GUARDRAIL_INTERVENED without a readable filter action still means it acted.
        outcome = (BLOCKED
                   if str(_ci(gd, "guardrailAction") or "").upper()
                   == "GUARDRAIL_INTERVENED"
                   else OUTCOME_UNKNOWN)
    return {
        "outcome": outcome,
        "guardrails": sorted({_ci(g, "arn") for g in (_ci(gd, "guardrails") or [])
                              if isinstance(g, dict) and _ci(g, "arn")}),
        "source": str(_ci(gd, "guardrailSource") or ""),
    }


def assess(finding: Optional[dict], reach: Optional[dict] = None) -> dict:
    """One AI Protection finding, with the two things GuardDuty could not weigh.

    ``reach`` is ``{"privesc": str|None, "crown": str|None}`` — exactly what
    ``aws_aispm.role_privesc_effective`` and ``role_reaches_crown`` already produce, and
    what ``aws_airules.rerank`` already threads through. An identity we could not resolve
    leaves ``escalated`` False: an unknown blast radius is not a large one."""
    ftype = _ci(finding, "Type", "type") or ""
    if ftype not in AI_PROTECTION:
        return {"applicable": False}

    r = reach or {}
    privesc, crown = r.get("privesc"), r.get("crown")
    outcome = guardrail_outcome(finding)
    return {
        "applicable": True,
        "type": ftype,
        **technique(ftype),
        "models": models_touched(finding),
        "outcome": outcome["outcome"],
        "guardrails": outcome["guardrails"],
        # The two independent reasons this is not a Low.
        "escalated": bool(privesc or crown),
        "privesc": privesc,
        "crown": crown,
        "unblocked_injection": (ftype == "Impact:IAMUser/PromptInjection.Direct"
                                and outcome["outcome"] == REPORTED_ONLY),
    }


def summarize(a: Optional[dict]) -> str:
    """One sentence naming why this is not the Low that GuardDuty assigned."""
    if not a or not a.get("applicable"):
        return ""
    bits = []
    if a.get("unblocked_injection"):
        bits.append("the guardrail detected the prompt attack and did NOT block it")
    if a.get("privesc"):
        bits.append(f"the acting identity can escalate privilege ({a['privesc']})")
    if a.get("crown"):
        bits.append(f"the acting identity can read crown-jewel data ({a['crown']})")
    if not bits:
        return ""
    return "; ".join(bits)
