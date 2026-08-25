"""Phase 1 · slice 1.3 — the AI_THREAT section.

Two properties carry weight here beyond "it runs".

It must be GLOBAL. The quota-dodging rule fires on one access key invoking across three
or more regions inside an hour; a per-region section sees one region per invocation and
could never observe that, however blatant the abuse.

And it must run AFTER DATA, because the severity join calls role_reaches_crown, which
reads the CAN_READ_DATA edges DATA builds. Ordered before it, the join would silently
return "reaches nothing" for every identity and the whole differentiator would evaporate
without failing anything.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_graph
import aws_live_scanner as A
from aws_live_scanner import AWSLiveScanner

T0 = datetime(2026, 8, 25, 12, 0, 0, tzinfo=timezone.utc)
ROLE = "arn:aws:iam::123456789012:role/SageMakerExecutionRole"


def _ct_row(name, *, at=T0, agent="axios/1.6.0", region="us-east-1", error=None):
    ev = {"eventName": name, "eventTime": at.isoformat(), "awsRegion": region,
          "sourceIPAddress": "203.0.113.7", "userAgent": agent,
          "userIdentity": {"arn": ROLE, "accessKeyId": "AKIASTOLEN"},
          "eventID": f"{name}-{at.isoformat()}"}
    if error:
        ev["errorCode"] = error
    return {"CloudTrailEvent": json.dumps(ev)}


def _scanner(*, rows=None, ct_raises=False):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["AI_THREAT"])
        s.account = "123456789012"

    ct = MagicMock()
    if ct_raises:
        ct.get_paginator.side_effect = Exception("AccessDenied")
    else:
        ct.get_paginator.return_value.paginate.return_value = [
            {"Events": list(rows or [])}]
    s._client = lambda svc, region=None: ct if svc == "cloudtrail" else MagicMock()
    s._get_iam_principals = lambda: []
    s._get_scp_context = lambda: None
    return s


# ── registration ────────────────────────────────────────────────────────────
def test_the_section_is_registered_and_global():
    assert "AI_THREAT" in A.SECTIONS
    assert "AI_THREAT" in AWSLiveScanner.GLOBAL_SECTIONS, (
        "AI_THREAT must be global: the quota-dodging rule needs every region at once")


def test_it_runs_after_data_and_before_correlate():
    """The severity join reads CAN_READ_DATA edges that DATA builds. Ordered earlier,
    the join would return 'reaches nothing' for every identity — silently, and without
    failing anything."""
    idx = {s: i for i, s in enumerate(A.SECTIONS)}
    assert idx["DATA"] < idx["AI_THREAT"] < idx["CORRELATE"]


def test_its_checks_are_fully_mapped():
    import aws_finding_detail as D
    for cid in ("AITHR-01", "AITHR-02"):
        assert cid in A.CHECK_SEVERITY
        assert cid in A.COMPLIANCE_MAP
        assert cid in A.REMEDIATION_MAP
        assert cid in D.FINDING_DETAIL
        assert "aws " in A.REMEDIATION_MAP[cid].lower()


# ── behaviour ───────────────────────────────────────────────────────────────
def test_a_clean_estate_reports_a_pass_not_silence():
    s = _scanner(rows=[_ct_row("InvokeModel", agent="aws-cli/2.15.0")])
    s._check_ai_threat()
    passes = [r for r in s.results if r.check_id == "AITHR-01" and r.status == "PASS"]
    assert passes, "a clean result must be stated, not implied by an empty list"


def test_llmjacking_is_reported_and_folded_onto_the_graph():
    s = _scanner(rows=[
        _ct_row("ListFoundationModels", agent="aws-cli/2.15.0"),
        _ct_row("InvokeModel", at=T0 + timedelta(minutes=3)),
    ])
    s.graph = aws_graph.SecurityGraph()
    s._check_ai_threat()
    fails = [r for r in s.results if r.check_id == "AITHR-01" and r.status == "FAIL"]
    assert fails
    kinds = {n["kind"] for n in s.graph.nodes()}
    assert "CdrDetection" in kinds, "the detection was not folded onto the graph"


def test_control_tampering_is_reported_as_its_own_check():
    s = _scanner(rows=[_ct_row("DeleteGuardrail", agent="aws-cli/2.15.0")])
    s._check_ai_threat()
    assert any(r.check_id == "AITHR-02" and r.status == "FAIL" for r in s.results)


def test_a_terraform_apply_does_not_raise_a_tamper_finding():
    s = _scanner(rows=[_ct_row("DeleteGuardrail",
                               agent="APN/1.0 HashiCorp/1.0 Terraform/1.9.5")])
    s._check_ai_threat()
    assert not [r for r in s.results if r.status == "FAIL"]


# ── refused is not clean ────────────────────────────────────────────────────
def test_an_unreadable_trail_is_recorded_as_not_evaluated():
    """The Phase 0 discipline applied to a Phase 1 feature: an absence of evidence is
    not evidence of absence, and the coverage manifest is where that is recorded."""
    s = _scanner(ct_raises=True)
    s._check_ai_threat()
    assert "AITHR-01" in s._coverage.not_evaluated
    assert not s._coverage.complete
    notes = [r for r in s.results if r.check_id == "AITHR-00"]
    assert notes and "not the same as no abuse" in notes[0].message
    assert not [r for r in s.results if r.status == "PASS"], (
        "a refused read must never produce a PASS")


def test_the_section_never_raises_on_malformed_events():
    s = _scanner(rows=[{"CloudTrailEvent": "not json"}, {}, {"CloudTrailEvent": None}])
    s._check_ai_threat()          # must not raise
    assert any(r.check_id.startswith("AITHR-") for r in s.results)
