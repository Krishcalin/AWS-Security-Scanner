"""Phase 2 · slice 2.6 — the scanner surface for GuardDuty AI Protection.

The load-bearing test is `test_the_main_threat_query_cannot_see_these_findings`. THREAT
already fetches GuardDuty findings and filters them at `severity >= 4`; GuardDuty's Low
band is severity < 4.0; and all three AI Protection types ship at a default severity of
Low. So the ingest existed and structurally excluded exactly the findings this slice is
about — a gap that only surfaces if you read the filter rather than the fact that a
fetch exists.

The second property is the stash ordering. The identity join needs the CAN_READ_DATA
edges DATA builds, and THREAT runs BEFORE DATA, so the findings are collected where the
detector is and assessed where the graph is.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_aiprotect as P
from engine import aws_live_scanner as A
from engine.aws_live_scanner import AWSLiveScanner

PRINCIPAL = "arn:aws:iam::123456789012:role/AppRole"


def gd_finding(ftype, *, action=None, models=("anthropic.claude-3",), sev=2.0):
    f = {"Id": f"f-{ftype}", "Type": ftype, "Severity": sev,
         "Service": {"Archived": False},
         "Resource": {"ResourceType": "AccessKey",
                      "AccessKeyDetails": {"PrincipalId": "AIDA123",
                                           "UserName": "app-user",
                                           "PrincipalArn": PRINCIPAL}}}
    if models:
        f["Resource"]["modelDetails"] = [{"modelId": m} for m in models]
    if action is not None:
        f["Resource"]["bedrockGuardrailDetails"] = {
            "guardrails": [{"arn": "arn:aws:bedrock:::guardrail/g", "version": "1"}],
            "guardrailAction": "GUARDRAIL_INTERVENED", "guardrailSource": "INPUT",
            "contentPolicyFilters": [{"type": "PROMPT_ATTACK", "confidence": "HIGH",
                                      "action": action}]}
    return f


def _scanner(reach=None):
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["AI_THREAT"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: MagicMock()
    s._identity_reach = lambda arn: (reach or {})
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


# ── the reason the slice exists ─────────────────────────────────────────────
def test_the_main_threat_query_cannot_see_these_findings():
    """THREAT filters at severity >= 4, GuardDuty's Low is < 4.0, and every AI
    Protection type ships at Low. The ingest existed and excluded exactly these."""
    import inspect
    src = inspect.getsource(AWSLiveScanner._check_threat)
    assert '"severity": {"GreaterThanOrEqual": 4}' in src
    from engine import aws_deepplane as D
    band = D.map_guardduty_finding(gd_finding(
        "Impact:IAMUser/AnomalousModelInvocation", sev=2.0))["band"]
    assert band == "Low", "the premise moved: AI Protection findings are no longer Low"


def test_the_collector_filters_by_type_not_by_severity():
    """Widening the general floor would pull in every Low finding in the account. A
    type-filtered second query gets these three and nothing else."""
    import inspect
    src = inspect.getsource(AWSLiveScanner._collect_ai_protection)
    assert '"type": {"Eq": list(aws_aiprotect.AI_PROTECTION)}' in src
    assert "GreaterThanOrEqual" not in src, "a severity floor here would refute the point"


def test_collection_happens_in_threat_and_assessment_after_data():
    """The identity join needs the CAN_READ_DATA edges DATA builds, and THREAT runs
    before DATA. Same stash pattern as the AgentCore runtimes in slice 2.2."""
    idx = {s: i for i, s in enumerate(A.SECTIONS)}
    assert idx["THREAT"] < idx["DATA"] < idx["AI_THREAT"]
    import inspect
    assert "_collect_ai_protection" in inspect.getsource(AWSLiveScanner._check_threat)
    assert "_emit_ai_protection" in inspect.getsource(AWSLiveScanner._check_ai_threat)


# ── the re-rank ─────────────────────────────────────────────────────────────
def test_a_scoped_identity_leaves_the_low_standing_and_says_so():
    """Reporting that GuardDuty was right is what makes the escalations mean something.
    A tool that escalated every AI finding would be no more useful than one that
    escalated none."""
    s = _scanner(reach={"privesc": None, "crown": None})
    s._ai_protection = [gd_finding("Impact:IAMUser/AnomalousModelInvocation")]
    s._emit_ai_protection()
    info = _ids(s, "AITHR-03", "INFO")
    assert info and "the Low stands" in info[0].message
    assert not _ids(s, "AITHR-03", "FAIL")


def test_an_identity_that_can_escalate_raises_the_finding():
    s = _scanner(reach={"privesc": "iam:PassRole on *", "crown": None})
    s._ai_protection = [gd_finding("Impact:IAMUser/AnomalousModelInvocation")]
    s._emit_ai_protection()
    f = _ids(s, "AITHR-03", "FAIL")
    assert f and "escalate privilege" in f[0].message
    assert "rated Low by GuardDuty" in f[0].message
    assert "AML.T0040" in f[0].message, "AWS's own ATLAS mapping should travel with it"


def test_cost_harvesting_carries_its_own_atlas_technique():
    s = _scanner(reach={"crown": "arn:aws:s3:::prod-pii"})
    s._ai_protection = [gd_finding("Impact:IAMUser/CostHarvesting")]
    s._emit_ai_protection()
    f = _ids(s, "AITHR-03", "FAIL")
    assert f and "AML.T0034" in f[0].message


def test_an_unblocked_prompt_injection_is_critical_on_its_own():
    """It needs no identity reach: an attack was recognised and allowed through."""
    s = _scanner(reach={"privesc": None, "crown": None})
    s._ai_protection = [gd_finding("Impact:IAMUser/PromptInjection.Direct",
                                   action="NONE")]
    s._emit_ai_protection()
    f = _ids(s, "AITHR-04", "FAIL")
    assert f and "only to REPORT it" in f[0].message
    assert f[0].severity == "CRITICAL"


def test_a_blocked_prompt_injection_is_not_the_critical():
    s = _scanner(reach={"privesc": None, "crown": None})
    s._ai_protection = [gd_finding("Impact:IAMUser/PromptInjection.Direct",
                                   action="BLOCKED")]
    s._emit_ai_protection()
    assert not _ids(s, "AITHR-04")
    assert _ids(s, "AITHR-03", "INFO"), "still surfaced, just not escalated"


def test_an_unblocked_injection_by_a_reaching_identity_raises_both():
    s = _scanner(reach={"privesc": "sts:AssumeRole on *", "crown": None})
    s._ai_protection = [gd_finding("Impact:IAMUser/PromptInjection.Direct",
                                   action="NONE")]
    s._emit_ai_protection()
    assert _ids(s, "AITHR-04", "FAIL") and _ids(s, "AITHR-03", "FAIL")


def test_no_findings_emits_nothing():
    s = _scanner()
    s._ai_protection = []
    s._emit_ai_protection()
    assert not [r for r in s.results if r.check_id.startswith("AITHR-0")]


def test_a_non_ai_finding_in_the_stash_is_ignored():
    s = _scanner(reach={"privesc": "x"})
    s._ai_protection = [{"Type": "Recon:EC2/Portscan", "Resource": {}}]
    s._emit_ai_protection()
    assert not [r for r in s.results if r.check_id.startswith("AITHR-0")]


def test_the_emitter_never_raises_on_malformed_findings():
    s = _scanner()
    s._ai_protection = [{}, {"Type": None}, {"Type": "Impact:IAMUser/CostHarvesting"}]
    s._emit_ai_protection()      # must not raise


# ── a refused read is not a clean one ───────────────────────────────────────
def test_a_refused_list_findings_is_recorded():
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["THREAT"])
        s.account = "123456789012"
    gd = MagicMock()
    gd.get_paginator.side_effect = Exception("AccessDeniedException")
    s._collect_ai_protection(gd, "det-1")
    assert {"AITHR-03", "AITHR-04"} <= set(s._coverage.not_evaluated)
    assert s._ai_protection == []


def test_the_checks_are_fully_mapped():
    from engine import aws_finding_detail as D
    for cid in ("AITHR-03", "AITHR-04"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP
        assert cid in A.REMEDIATION_MAP and cid in D.FINDING_DETAIL
        assert "aws " in A.REMEDIATION_MAP[cid].lower()


def test_the_slice_needs_no_new_grant():
    """SecurityAudit already grants guardduty:Get*/List*, which the THREAT section has
    always relied on. If that changes, the slice's cost changes with it."""
    from engine import aws_perm_ledger as L
    need = {r.action for c in ("AITHR-03", "AITHR-04") for r in L.REQUIREMENTS[c]}
    assert need == {"guardduty:ListFindings", "guardduty:GetFindings"}
    granted = [{"effect": "Allow", "actions": {"guardduty:get*", "guardduty:list*"},
                "resources": {"*"}, "not_resources": set(), "condition": None}]
    assert all(L.granted(granted, a) for a in need)
