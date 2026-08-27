"""Phase 2 · slice 2.6 — GuardDuty AI Protection, re-ranked.

Fixtures follow the GuardDuty AI Protection finding-type documentation: the three types,
their `resource.modelDetails` / `resource.bedrockGuardrailDetails` payloads, and the
`contentPolicyFilters[].action` values AWS documents as `BLOCKED` (the guardrail blocked
the content) or `NONE` (it "detected the prompt attack but was configured only to report
it").

The slice's claim is narrow and worth keeping narrow: GuardDuty's Low is the *right*
default for a detector holding the event and not the environment. This does not re-detect
anything and does not second-guess the detection. It reads two facts already inside the
finding, joins the identity reach OverWatch already computes, and says why the Low is
wrong *for this account* — which is the one thing a log cannot carry.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_aiprotect as P

ANOMALOUS = "Impact:IAMUser/AnomalousModelInvocation"
HARVEST = "Impact:IAMUser/CostHarvesting"
INJECTION = "Impact:IAMUser/PromptInjection.Direct"
GR = "arn:aws:bedrock:us-east-1:123456789012:guardrail/gr1"


def finding(ftype, *, models=None, filters=None, action=None, source="INPUT"):
    f = {"type": ftype, "resource": {}}
    if models:
        f["resource"]["modelDetails"] = [{"modelId": m} for m in models]
    if filters is not None or action is not None:
        gd = {"guardrails": [{"arn": GR, "version": "1"}],
              "guardrailSource": source}
        if action is not None:
            gd["guardrailAction"] = action
        if filters is not None:
            gd["contentPolicyFilters"] = filters
        f["resource"]["bedrockGuardrailDetails"] = gd
    return f


# ── the content pack ────────────────────────────────────────────────────────
def test_all_three_finding_types_are_recognised():
    for t in (ANOMALOUS, HARVEST, INJECTION):
        assert P.is_ai_protection({"type": t}), t


def test_an_unrelated_guardduty_finding_is_not_claimed():
    assert not P.is_ai_protection({"type": "UnauthorizedAccess:IAMUser/TorIPCaller"})
    assert P.assess({"type": "Recon:EC2/Portscan"})["applicable"] is False


def test_the_atlas_mapping_is_awss_own():
    """AWS states the technique on each finding-type page. Assigning our own would be
    inventing a mapping and calling it a standard."""
    assert P.technique(ANOMALOUS)["atlas"] == "AML.T0040"
    assert P.technique(HARVEST)["atlas"] == "AML.T0034"
    assert P.technique(INJECTION)["atlas"] == "AML.T0051"


def test_the_documented_default_severity_is_recorded():
    """The whole premise of the slice: all three ship as Low."""
    assert P.DEFAULT_SEVERITY_BAND == "Low"


def test_models_touched_are_named():
    a = P.assess(finding(ANOMALOUS, models=["anthropic.claude-3", "amazon.titan"]))
    assert a["models"] == ["amazon.titan", "anthropic.claude-3"]


# ── the guardrail outcome ───────────────────────────────────────────────────
def test_a_blocked_injection_is_blocked():
    o = P.guardrail_outcome(finding(INJECTION, filters=[
        {"type": "PROMPT_ATTACK", "confidence": "HIGH", "action": "BLOCKED"}]))
    assert o["outcome"] == P.BLOCKED
    assert o["guardrails"] == [GR]


def test_action_none_means_detected_and_allowed_through():
    """AWS: NONE means the guardrail "detected the prompt attack but was configured only
    to report it". That is a materially different event from a blocked one, and it is
    AIGRD-02's configuration showing up as an outcome that already happened."""
    o = P.guardrail_outcome(finding(INJECTION, filters=[
        {"type": "PROMPT_ATTACK", "confidence": "HIGH", "action": "NONE"}]))
    assert o["outcome"] == P.REPORTED_ONLY


def test_intervened_without_a_readable_filter_still_counts_as_blocked():
    o = P.guardrail_outcome(finding(INJECTION, filters=[],
                                    action="GUARDRAIL_INTERVENED"))
    assert o["outcome"] == P.BLOCKED


def test_absent_guardrail_details_are_unknown_not_unblocked():
    """The other two finding types carry no guardrail block at all. Reading that as
    "nothing blocked" would manufacture the slice's worst finding out of a field that
    was never going to be there."""
    assert P.guardrail_outcome(finding(ANOMALOUS))["outcome"] == P.OUTCOME_UNKNOWN
    assert P.assess(finding(ANOMALOUS))["unblocked_injection"] is False


# ── the re-rank ─────────────────────────────────────────────────────────────
def test_a_scoped_identity_leaves_the_low_alone():
    """GuardDuty's Low is correct here, and saying so is the point. A tool that escalated
    every AI finding would be no more useful than one that escalated none."""
    a = P.assess(finding(ANOMALOUS), {"privesc": None, "crown": None})
    assert a["escalated"] is False
    assert P.summarize(a) == ""


def test_an_identity_that_can_escalate_changes_the_answer():
    a = P.assess(finding(ANOMALOUS), {"privesc": "iam:PassRole on *", "crown": None})
    assert a["escalated"] is True
    assert "escalate privilege" in P.summarize(a)


def test_an_identity_that_reaches_crown_data_changes_the_answer():
    a = P.assess(finding(HARVEST), {"crown": "arn:aws:s3:::prod-pii"})
    assert a["escalated"] is True
    assert "crown-jewel data" in P.summarize(a)


def test_an_unresolvable_identity_is_not_escalated():
    """An unknown blast radius is not a large one — the same rule aws_airules.rerank
    already applies."""
    a = P.assess(finding(ANOMALOUS), None)
    assert a["escalated"] is False


def test_an_unblocked_injection_escalates_on_its_own():
    """It needs no identity reach to matter: an attack was recognised and allowed."""
    a = P.assess(finding(INJECTION, filters=[
        {"type": "PROMPT_ATTACK", "confidence": "HIGH", "action": "NONE"}]), None)
    assert a["unblocked_injection"] is True
    assert "did NOT block it" in P.summarize(a)


def test_a_blocked_injection_by_a_scoped_identity_says_nothing_extra():
    a = P.assess(finding(INJECTION, filters=[
        {"type": "PROMPT_ATTACK", "confidence": "HIGH", "action": "BLOCKED"}]),
        {"privesc": None, "crown": None})
    assert a["unblocked_injection"] is False
    assert P.summarize(a) == "", (
        "a blocked attack against a scoped identity is the control working; escalating "
        "it teaches operators that the escalation means nothing")


def test_both_reasons_appear_when_both_hold():
    a = P.assess(finding(INJECTION, filters=[{"action": "NONE"}]),
                 {"privesc": "sts:AssumeRole on *", "crown": "arn:aws:s3:::pii"})
    s = P.summarize(a)
    assert "did NOT block" in s and "escalate privilege" in s and "crown-jewel" in s


# ── robustness ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, {}, {"type": None},
                                 {"type": ANOMALOUS, "resource": None},
                                 {"type": ANOMALOUS, "resource": {"modelDetails": "x"}},
                                 {"type": INJECTION,
                                  "resource": {"bedrockGuardrailDetails": []}}])
def test_nothing_raises_on_malformed_findings(bad):
    P.is_ai_protection(bad)
    P.guardrail_outcome(bad)
    P.models_touched(bad)
    a = P.assess(bad)
    P.summarize(a)


def test_the_module_re_detects_nothing():
    """It reads a detection AWS already made. A regex over prompt text here would be a
    second detector with none of GuardDuty's baseline, and would also be the content
    read that decision D2 forbids."""
    import inspect
    src = inspect.getsource(P)
    for word in ("re.compile", "re.search", "re.match"):
        assert word not in src, f"{word} suggests re-detection rather than re-ranking"


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    bad = re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests|urllib)\b",
                     inspect.getsource(P), re.M)
    assert not bad, f"pure classifier imports I/O: {bad}"
