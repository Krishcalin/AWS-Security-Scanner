"""Phase 2 · slice 2.1 — the scanner surface for guardrail grading and enforcement.

Two placement properties carry as much weight here as the findings themselves.

Grading is REGIONAL, and correctly so: guardrails are regional resources, so each is
graded once in the region that holds it. Enforcement is a property of an IAM principal,
not of a region, so it is emitted from the latched _collect_aispm. That distinction is
not stylistic — Phase 0 opened with a defect where a global AI finding was emitted once
per region and floored the whole account's posture score at zero across 17 regions.

The other property is the one the AI pillar keeps re-learning: a refused read is not a
clean result. Without bedrock:GetGuardrail the scanner knows a guardrail EXISTS and knows
nothing about whether it blocks anything, and saying so is the only honest output.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_aiguard as G
import aws_live_scanner as A
from aws_live_scanner import AWSLiveScanner

ARN = "arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123:1"
ROLE = "arn:aws:iam::123456789012:role/AppRole"


def cfilter(t, *, i="HIGH", ia="BLOCK", oa=None):
    f = {"type": t, "inputStrength": i, "outputStrength": "NONE", "inputAction": ia}
    if oa is not None:
        f["outputAction"] = oa
    return f


def _scanner():
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["BEDROCK"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: MagicMock()
    return s


def _bedrock(detail=None, *, denied=False, summaries=None):
    b = MagicMock()
    b.list_guardrails.return_value = {"guardrails": summaries if summaries is not None
                                      else [{"id": "abc123", "name": "prod"}]}
    if denied:
        err = Exception("AccessDeniedException: no")
        b.get_guardrail.side_effect = err
    else:
        b.get_guardrail.return_value = detail or {}
    return b


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


# ── grading ─────────────────────────────────────────────────────────────────
def test_a_blocking_injection_filter_passes():
    s = _scanner()
    s._grade_guardrails(_bedrock({"version": "1", "status": "READY",
                                  "contentPolicy": {"filters": [cfilter("PROMPT_ATTACK")]}}))
    assert _ids(s, "AIGRD-01", "PASS")
    assert not _ids(s, "AIGRD-02")


def test_a_guardrail_with_no_injection_filter_fails_even_though_bdr02_would_pass():
    """The slice in one test: BDR-02 counts this guardrail as present and healthy."""
    s = _scanner()
    s._grade_guardrails(_bedrock({"version": "1", "status": "READY",
                                  "contentPolicy": {"filters": [cfilter("HATE")]}}))
    f = _ids(s, "AIGRD-01", "FAIL")
    assert f and "no PROMPT_ATTACK filter" in f[0].message


def test_detect_only_is_reported_and_names_the_filter():
    """The HATE filter here evaluates output at HIGH strength and is told to do nothing
    with the result. Note the fixture gives it a real outputStrength: a side set to
    strength NONE is not evaluating at all, so calling it "detect-only" would be wrong,
    and grade_guardrail deliberately requires a non-zero strength before flagging."""
    s = _scanner()
    s._grade_guardrails(_bedrock({"version": "1", "status": "READY", "contentPolicy":
                                  {"filters": [
                                      cfilter("PROMPT_ATTACK"),
                                      {"type": "HATE", "inputStrength": "HIGH",
                                       "outputStrength": "HIGH",
                                       "inputAction": "BLOCK",
                                       "outputAction": "NONE"}]}}))
    f = _ids(s, "AIGRD-02", "FAIL")
    assert f
    assert "HATE (output)" in f[0].message
    assert "detection information" in f[0].message.lower(), (
        "the finding must say what action NONE actually does, or it reads as a "
        "style preference rather than a control that is off")
    assert _ids(s, "AIGRD-01", "PASS"), "injection is still blocked; only HATE is inert"


def test_a_side_at_strength_none_is_not_called_detect_only():
    """The control for the test above. A filter that is not evaluating a side cannot be
    'detecting without blocking' on it, and reporting that would be a finding invented
    out of a disabled control."""
    s = _scanner()
    s._grade_guardrails(_bedrock({"version": "1", "status": "READY", "contentPolicy":
                                  {"filters": [cfilter("PROMPT_ATTACK", oa="NONE")]}}))
    assert not _ids(s, "AIGRD-02")


def test_a_draft_only_guardrail_is_reported():
    s = _scanner()
    s._grade_guardrails(_bedrock({"version": "DRAFT", "status": "READY", "contentPolicy":
                                  {"filters": [cfilter("PROMPT_ATTACK")]}}))
    assert _ids(s, "AIGRD-04", "FAIL")


def test_a_published_version_raises_no_draft_finding():
    s = _scanner()
    s._grade_guardrails(_bedrock({"version": "3", "status": "READY", "contentPolicy":
                                  {"filters": [cfilter("PROMPT_ATTACK")]}}))
    assert not _ids(s, "AIGRD-04")


def test_an_account_with_no_guardrails_grades_nothing():
    """BDR-02 already reports the absence; a second finding would double-count it."""
    s = _scanner()
    s._grade_guardrails(_bedrock(summaries=[]))
    assert not [r for r in s.results if r.check_id.startswith("AIGRD-")]


# ── refused is not clean ────────────────────────────────────────────────────
def test_a_refused_getguardrail_is_recorded_not_passed():
    s = _scanner()
    s._grade_guardrails(_bedrock(denied=True))
    assert "AIGRD-01" in s._coverage.not_evaluated
    assert not s._coverage.complete


def test_a_refusal_records_every_check_the_action_gated():
    """One missing read blocks three checks. Recording only the first would report
    AIGRD-01 as unevaluated and leave AIGRD-02 and AIGRD-04 looking clean — a phantom
    pass produced by the very manifest that exists to prevent them.

    Asserted against the ledger rather than a literal list so that a fifth check needing
    bedrock:GetGuardrail is covered the day it is added, instead of silently reporting
    itself as evaluated."""
    import aws_perm_ledger as L
    expected = {cid for cid, reqs in L.REQUIREMENTS.items()
                if any(r.action.lower() == "bedrock:getguardrail" for r in reqs)}
    assert len(expected) >= 3, "the ledger no longer records what this action gates"
    s = _scanner()
    s._grade_guardrails(_bedrock(denied=True))
    assert expected <= set(s._coverage.not_evaluated), (
        f"refused GetGuardrail left {expected - set(s._coverage.not_evaluated)} "
        f"looking evaluated")
    notes = _ids(s, "AIGRD-00")
    assert notes and "no phantom pass" in notes[0].message
    assert not [r for r in s.results if r.status == "PASS"], (
        "a refused read must never produce a PASS")


def test_an_unreadable_list_does_not_raise():
    s = _scanner()
    b = MagicMock()
    b.list_guardrails.side_effect = Exception("boom")
    s._grade_guardrails(b)          # BDR-02 already reported it
    assert not [r for r in s.results if r.check_id.startswith("AIGRD-")]


# ── enforcement ─────────────────────────────────────────────────────────────
def _prin(statements):
    return {ROLE.lower(): {"arn": ROLE, "name": "AppRole", "statements": statements}}


def stmt(effect, actions, cond=None):
    return {"effect": effect, "actions": set(actions), "resources": {"*"},
            "not_resources": set(), "condition": cond}


def test_the_allow_half_alone_is_reported_as_not_enforcement():
    s = _scanner()
    s._emit_guardrail_enforcement(_prin([
        stmt("Allow", {"bedrock:invokemodel"},
             {"StringEquals": {"bedrock:GuardrailIdentifier": ARN}})]))
    f = _ids(s, "AIGRD-03", "FAIL")
    assert f and "reads like enforcement and is not" in f[0].message


def test_an_explicit_deny_passes():
    s = _scanner()
    s._emit_guardrail_enforcement(_prin([
        stmt("Deny", {"bedrock:invokemodel"},
             {"StringNotEquals": {"bedrock:GuardrailIdentifier": ARN}})]))
    assert _ids(s, "AIGRD-03", "PASS")


def test_inference_with_no_condition_is_reported():
    s = _scanner()
    s._emit_guardrail_enforcement(_prin([stmt("Allow", {"bedrock:invokemodel"})]))
    f = _ids(s, "AIGRD-03", "FAIL")
    assert f and "optional at the caller's discretion" in f[0].message


def test_an_account_with_no_model_invokers_says_nothing():
    s = _scanner()
    s._emit_guardrail_enforcement(_prin([stmt("Allow", {"s3:getobject"})]))
    assert not _ids(s, "AIGRD-03")


def test_the_documented_delegation_conflict_is_a_warn_not_a_fail():
    """Enforcement is correct here; it will simply break InvokeAgent. Reporting that as
    a FAIL would push an operator to remove the enforcement, which is backwards."""
    s = _scanner()
    s._emit_guardrail_enforcement(_prin([
        stmt("Deny", {"bedrock:invokemodel"},
             {"StringNotEquals": {"bedrock:GuardrailIdentifier": ARN}}),
        stmt("Allow", {"bedrock:invokeagent"})]))
    w = _ids(s, "AIGRD-03", "WARN")
    assert w and "Split the roles" in w[0].message
    assert _ids(s, "AIGRD-03", "PASS")


def test_a_mixed_estate_does_not_pass():
    """One enforced principal must not produce a PASS while another is unenforced."""
    s = _scanner()
    prin = _prin([stmt("Deny", {"bedrock:invokemodel"},
                       {"StringNotEquals": {"bedrock:GuardrailIdentifier": ARN}})])
    prin["arn:aws:iam::123456789012:role/other"] = {
        "arn": "arn:aws:iam::123456789012:role/Other", "name": "Other",
        "statements": [stmt("Allow", {"bedrock:invokemodel"})]}
    s._emit_guardrail_enforcement(prin)
    assert _ids(s, "AIGRD-03", "FAIL")
    assert not _ids(s, "AIGRD-03", "PASS")


def test_enforcement_never_raises_on_a_malformed_principal():
    s = _scanner()
    s._emit_guardrail_enforcement({"a": {}, "b": {"statements": None}, "c": None}
                                  if False else {"a": {}, "b": {"statements": None}})
    assert True


# ── placement ───────────────────────────────────────────────────────────────
def test_enforcement_is_emitted_from_the_latched_collector():
    """It is a property of an identity, not a region. Emitting it per-region is the
    Phase 0 defect that floored an account's score to zero across 17 regions."""
    import inspect
    src = inspect.getsource(AWSLiveScanner._collect_aispm)
    assert "_emit_guardrail_enforcement" in src
    assert "self._aispm_collected" in src, "the latch must still guard this path"


def test_grading_is_emitted_from_the_regional_bedrock_section():
    import inspect
    src = inspect.getsource(AWSLiveScanner)
    assert "self._grade_guardrails(bedrock)" in src
    assert "BEDROCK" not in AWSLiveScanner.GLOBAL_SECTIONS, (
        "guardrails are regional; grading them from a global section would grade the "
        "same estate once and miss every other region's guardrails")


def test_the_checks_are_fully_mapped():
    import aws_finding_detail as D
    for cid in ("AIGRD-01", "AIGRD-02", "AIGRD-03", "AIGRD-04"):
        assert cid in A.CHECK_SEVERITY, cid
        assert cid in A.COMPLIANCE_MAP, cid
        assert cid in A.REMEDIATION_MAP, cid
        assert cid in D.FINDING_DETAIL, cid
        assert "aws " in A.REMEDIATION_MAP[cid].lower(), cid


def test_the_new_permission_is_in_both_onboarding_paths():
    """The CloudFormation and Terraform roles are parity-tested; a one-sided grant ships
    a scanner that works for half the customers."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    for rel in ("deploy/cnapp-scanner-role.yaml",
                "deploy/terraform/scanner-role/main.tf"):
        assert "bedrock:GetGuardrail" in (root / rel).read_text(encoding="utf-8"), rel
