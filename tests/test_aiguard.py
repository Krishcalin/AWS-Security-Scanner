"""Phase 2 · slice 2.1 — guardrail grading and IAM-bound enforcement.

Fixtures are shaped from the Bedrock API reference (GetGuardrail response syntax and
GuardrailContentFilter), not from memory. The enums that drive every verdict here —
strength ``NONE|LOW|MEDIUM|HIGH``, action ``BLOCK|NONE``, filter type including
``PROMPT_ATTACK`` — were read off the reference before the module was written, because a
grading scale built on invented field names grades nothing.

The two properties worth the slice:

*Detect-only is not protection.* The reference defines action ``NONE`` as "Take no action
but return detection information in the trace response." Every "has a guardrail" check in
the market passes on that configuration.

*The Allow half is not enforcement.* All five policy examples in "Enforce the use of
specific guardrails in model inference requests" pair an Allow with an explicit Deny, and
the reference states the Deny is what holds "no matter what other permissions the user
might have". A policy with the Allow and not the Deny reads, to a human, exactly like one
that enforces.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_aiguard as G


# ── fixtures shaped from the API reference ──────────────────────────────────
def cfilter(ftype, *, i="HIGH", o="HIGH", ia=None, oa=None, ie=None, oe=None):
    f = {"type": ftype, "inputStrength": i, "outputStrength": o}
    if ia is not None:
        f["inputAction"] = ia
    if oa is not None:
        f["outputAction"] = oa
    if ie is not None:
        f["inputEnabled"] = ie
    if oe is not None:
        f["outputEnabled"] = oe
    return f


def guardrail(filters=(), *, version="1", status="READY", **policies):
    d = {"guardrailId": "gr1", "name": "prod", "version": version, "status": status,
         "contentPolicy": {"filters": list(filters)}}
    d.update(policies)
    return d


def stmt(effect, actions, *, cond=None, resources=("*",)):
    return {"effect": effect, "actions": set(actions), "resources": set(resources),
            "not_resources": set(), "condition": cond}


ARN = "arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123:1"


# ── grading ─────────────────────────────────────────────────────────────────
def test_a_guardrail_that_blocks_injection_at_strength_is_the_top_grade():
    g = G.grade_guardrail(guardrail([cfilter("PROMPT_ATTACK", ia="BLOCK")]))
    assert g["grade"] == G.BLOCKING
    assert g["weaknesses"] == []


def test_detect_only_is_the_finding_a_boolean_check_cannot_make():
    """The reference: action NONE means "Take no action but return detection
    information". A boolean "is a guardrail attached" passes here."""
    g = G.grade_guardrail(guardrail([
        cfilter("PROMPT_ATTACK", ia="NONE", oa="NONE"),
        cfilter("HATE", ia="NONE", oa="NONE")]))
    assert g["grade"] == G.DETECT_ONLY
    assert "detect without blocking" in g["weaknesses"][0]


def test_content_safety_without_an_injection_filter_is_only_partial():
    """A guardrail can be a good content-safety filter and do nothing about the threat
    that makes agents different from APIs."""
    g = G.grade_guardrail(guardrail([cfilter("HATE", ia="BLOCK"),
                                     cfilter("VIOLENCE", ia="BLOCK")]))
    assert g["grade"] == G.PARTIAL
    assert not g["injection"]["present"]
    assert "PROMPT_ATTACK" in g["weaknesses"][0]


def test_injection_filter_below_medium_does_not_count_as_effective():
    g = G.grade_guardrail(guardrail([cfilter("PROMPT_ATTACK", i="LOW", ia="BLOCK")]))
    assert g["grade"] == G.PARTIAL
    assert "below MEDIUM" in g["weaknesses"][0]


def test_injection_filter_at_none_strength_is_not_present_protection():
    g = G.grade_guardrail(guardrail([cfilter("PROMPT_ATTACK", i="NONE", ia="BLOCK")]))
    assert g["injection"]["present"] is True
    assert g["injection"]["effective"] is False


def test_a_disabled_side_does_not_block_even_at_high_strength():
    g = G.grade_guardrail(guardrail([cfilter("PROMPT_ATTACK", ia="BLOCK", ie=False)]))
    assert g["grade"] != G.BLOCKING


def test_an_empty_guardrail_is_ungraded_not_merely_weak():
    """Nothing configured and "configured to do nothing" are different facts; reporting
    the first as the second would misdescribe an account that has not started."""
    assert G.grade_guardrail(guardrail([]))["grade"] == G.UNGRADED
    assert G.grade_guardrail(None)["grade"] == G.UNGRADED


def test_non_filter_policies_count_as_configuration():
    g = G.grade_guardrail(guardrail(
        [], sensitiveInformationPolicy={"piiEntities": [{"type": "EMAIL"}]}))
    assert g["grade"] != G.UNGRADED
    assert g["other"]["pii_entities"] == 1


def test_a_missing_action_key_is_not_read_as_detect_only():
    """inputAction is "Required: No" and the reference does not state its default.
    Treating absence as NONE would invent a behaviour and call a working guardrail inert."""
    g = G.grade_guardrail(guardrail([cfilter("PROMPT_ATTACK")]))   # no action keys
    assert g["detect_only"] == []
    assert g["grade"] == G.BLOCKING


def test_detect_only_names_the_filter_and_side():
    g = G.grade_guardrail(guardrail([cfilter("PROMPT_ATTACK", ia="BLOCK", oa="NONE")]))
    assert g["detect_only"] == [{"type": "PROMPT_ATTACK", "sides": ["output"]}]


def test_draft_and_status_are_reported():
    g = G.grade_guardrail(guardrail([cfilter("PROMPT_ATTACK", ia="BLOCK")],
                                    version="DRAFT", status="FAILED"))
    assert g["draft_only"] is True
    assert g["ready"] is False


# ── enforcement ─────────────────────────────────────────────────────────────
def test_the_allow_half_alone_is_not_enforcement():
    """The slice's headline. This policy reads like enforcement and is not: any other
    statement granting inference lets the caller invoke with no guardrail at all."""
    v = G.enforcement_verdict([
        stmt("Allow", {"bedrock:invokemodel"},
             cond={"StringEquals": {"bedrock:GuardrailIdentifier": ARN}})])
    assert v["verdict"] == G.ALLOW_ONLY
    assert v["guardrails"] == [ARN]


def test_the_explicit_deny_is_what_enforces():
    v = G.enforcement_verdict([
        stmt("Allow", {"bedrock:invokemodel"},
             cond={"StringEquals": {"bedrock:GuardrailIdentifier": ARN}}),
        stmt("Deny", {"bedrock:invokemodel"},
             cond={"StringNotEquals": {"bedrock:GuardrailIdentifier": ARN}})])
    assert v["verdict"] == G.ENFORCED


def test_the_arn_operator_family_enforces_too():
    """Examples 3 and 4 use ArnLike/ArnNotLike for version wildcards. Recognising only
    the string operators would report correct policies as unenforced."""
    v = G.enforcement_verdict([
        stmt("Deny", {"bedrock:invokemodel"},
             cond={"ArnNotLike": {"bedrock:GuardrailIdentifier": ARN[:-2] + ":*"}})])
    assert v["verdict"] == G.ENFORCED


def test_inference_with_no_guardrail_condition_anywhere():
    v = G.enforcement_verdict([stmt("Allow", {"bedrock:invokemodel"})])
    assert v["verdict"] == G.UNENFORCED


def test_a_principal_that_cannot_invoke_a_model_is_not_a_finding():
    """Silence is right here — there is nothing to enforce a guardrail on."""
    v = G.enforcement_verdict([stmt("Allow", {"s3:getobject"})])
    assert v["verdict"] == G.NOT_APPLICABLE


def test_a_wildcard_grant_still_counts_as_inference():
    for act in ("*", "bedrock:*", "bedrock:Invoke*"):
        v = G.enforcement_verdict([stmt("Allow", {act.lower()})])
        assert v["verdict"] == G.UNENFORCED, act


def test_a_deny_on_an_unrelated_bedrock_action_is_not_enforcement():
    """The condition key applies to four inference APIs. A Deny on something else does
    not stop an unguarded InvokeModel, however much it looks like a guardrail control."""
    v = G.enforcement_verdict([
        stmt("Allow", {"bedrock:invokemodel"}),
        stmt("Deny", {"bedrock:listguardrails"},
             cond={"StringNotEquals": {"bedrock:GuardrailIdentifier": ARN}})])
    assert v["verdict"] == G.UNENFORCED


def test_condition_keys_are_matched_case_insensitively():
    """IAM condition keys are case-insensitive; a policy written GuardrailIdentifier or
    guardrailidentifier enforces identically and must grade identically."""
    for key in ("bedrock:GuardrailIdentifier", "BEDROCK:GUARDRAILIDENTIFIER",
                "bedrock:guardrailidentifier"):
        v = G.enforcement_verdict([
            stmt("Deny", {"bedrock:invokemodel"},
                 cond={"StringNotEquals": {key: ARN}})])
        assert v["verdict"] == G.ENFORCED, key


def test_ifexists_operator_suffix_is_recognised():
    v = G.enforcement_verdict([
        stmt("Deny", {"bedrock:invokemodel"},
             cond={"StringNotEqualsIfExists": {"bedrock:GuardrailIdentifier": ARN}})])
    assert v["verdict"] == G.ENFORCED


def test_a_list_of_guardrails_is_kept():
    """Example 5 pins a set of guardrail/version pairs."""
    other = ARN.replace("abc123", "def456")
    v = G.enforcement_verdict([
        stmt("Deny", {"bedrock:invokemodel"},
             cond={"StringNotEquals": {"bedrock:GuardrailIdentifier": [ARN, other]}})])
    assert v["verdict"] == G.ENFORCED
    assert v["guardrails"] == sorted([ARN, other])


def test_the_documented_delegation_conflict_is_surfaced():
    """The reference warns that a role carrying the guardrail Deny should not also hold
    InvokeAgent / RetrieveAndGenerate, because those make internal InvokeModel calls that
    do not all carry a guardrail and will be denied. It is the reason teams switch
    enforcement back off, so it is worth naming rather than discovering in production."""
    v = G.enforcement_verdict([
        stmt("Deny", {"bedrock:invokemodel"},
             cond={"StringNotEquals": {"bedrock:GuardrailIdentifier": ARN}}),
        stmt("Allow", {"bedrock:invokeagent", "bedrock:retrieveandgenerate"})])
    assert v["verdict"] == G.ENFORCED
    assert v["delegating"] == ["bedrock:invokeagent", "bedrock:retrieveandgenerate"]


def test_delegation_is_only_counted_on_allow():
    v = G.enforcement_verdict([
        stmt("Allow", {"bedrock:invokemodel"}),
        stmt("Deny", {"bedrock:invokeagent"})])
    assert v["delegating"] == []


# ── robustness ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, [], [{}], [{"effect": None}],
                                 [{"actions": None, "effect": "Allow"}]])
def test_enforcement_never_raises_on_malformed_input(bad):
    assert G.enforcement_verdict(bad)["verdict"] in G.VERDICTS


@pytest.mark.parametrize("bad", [None, {}, {"contentPolicy": None},
                                 {"contentPolicy": {"filters": None}},
                                 {"contentPolicy": {"filters": ["not a dict"]}}])
def test_grading_never_raises_on_malformed_input(bad):
    assert G.grade_guardrail(bad)["grade"] in G.GRADES


def test_the_module_makes_no_aws_calls():
    """Pure classifiers, same contract as aws_aispm: the scanner fetches, this decides.
    An import of boto3 here would put I/O behind a function that reads as arithmetic."""
    import inspect
    import re
    src = inspect.getsource(G)
    # Match import STATEMENTS, not the word: the module docstring says "no boto3", and a
    # substring check turns that promise into the thing that breaks the test.
    bad = re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests|urllib)\b",
                     src, re.M)
    assert not bad, f"pure classifier module imports I/O: {bad}"
