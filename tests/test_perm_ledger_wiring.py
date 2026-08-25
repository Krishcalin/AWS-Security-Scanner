"""Phase 1 · slice 1.1 — the ledger and manifest reach the scan output.

A library nothing calls changes nothing. These pin the three joins: the scanner
computes its own ledger BEFORE scanning, records what it could not evaluate as it
goes, and both travel with the scan result rather than beside it.

The fail-open assertions matter as much as the positive ones. A scan must never depend
on being able to read its own policies — we may be a federated session, or a role in
another account — and a preflight that could abort a scan would be a worse defect than
the blind spot it reports.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_perm_ledger as L
import cnapp_service
from aws_live_scanner import AWSLiveScanner

ROLE_NAME = "CnappScannerRole"
ROLE_ARN = f"arn:aws:iam::123456789012:role/{ROLE_NAME}"
ASSUMED = f"arn:aws:sts::123456789012:assumed-role/{ROLE_NAME}/overwatch-scan"

# what our shipped role really grants for the AI pillar (SecurityAudit v92)
GRANTED = {
    "bedrock:getagent", "bedrock:getcustommodel",
    "bedrock:getmodelinvocationloggingconfiguration", "bedrock:listagents",
    "bedrock:listagentactiongroups", "bedrock:listcustommodels",
    "bedrock:listdatasources", "bedrock:listguardrails", "bedrock:listknowledgebases",
    "sagemaker:describe*", "sagemaker:list*", "lambda:getpolicy",
}


def _scanner(*, caller_arn=ASSUMED, principals=None, sts_raises=False):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["DATA"])
        s.account = "123456789012"

    sts = MagicMock()
    if sts_raises:
        sts.get_caller_identity.side_effect = Exception("STS unavailable")
    else:
        sts.get_caller_identity.return_value = {"Arn": caller_arn,
                                                "Account": "123456789012"}
    s._client = lambda svc, region=None: sts if svc == "sts" else MagicMock()
    if principals is not None:
        s._get_iam_principals = lambda: principals
    return s


def _me(actions=GRANTED, name=ROLE_NAME):
    return [{"arn": ROLE_ARN, "name": name, "type": "role",
             "statements": [{"effect": "Allow", "actions": set(actions),
                             "resources": {"*"}, "not_resources": set(),
                             "condition": None}]}]


# ── the manifest exists on every scan ───────────────────────────────────────
def test_a_scanner_always_carries_a_coverage_manifest():
    s = _scanner()
    assert isinstance(s._coverage, L.CoverageManifest)
    assert s._coverage.complete, "a fresh manifest withholds nothing"


# ── the predictive half ─────────────────────────────────────────────────────
def test_preflight_computes_the_ledger_from_our_own_role():
    s = _scanner(principals=_me())
    s._preflight_permissions()
    assert s._perm_ledger is not None
    assert s._perm_ledger.missing_actions == (
        "bedrock-agentcore:GetAgentRuntime",
        "bedrock-agentcore:GetGateway",
        "bedrock-agentcore:ListAgentRuntimes",
        "bedrock-agentcore:ListApiKeyCredentialProviders",
        "bedrock-agentcore:ListBrowsers",
        "bedrock-agentcore:ListCodeInterpreters",
        "bedrock-agentcore:ListGatewayTargets",
        "bedrock-agentcore:ListGateways",
        "bedrock-agentcore:ListMemories",
        "bedrock-agentcore:ListOauth2CredentialProviders",
        "bedrock-agentcore:ListWorkloadIdentities",
        "bedrock:GetAgentActionGroup", "bedrock:GetDataSource",
        "bedrock:GetGuardrail",
        "bedrock:GetKnowledgeBase")


def test_preflight_says_what_will_not_be_evaluated_before_it_runs():
    """The point of doing this first: the operator learns the gap from the report,
    not from inferring it out of a check that quietly says nothing."""
    s = _scanner(principals=_me())
    s._preflight_permissions()
    notes = [r for r in s.results if r.check_id == "AISPM-00"]
    assert notes, "preflight produced no coverage note"
    text = " ".join(r.message for r in notes)
    assert "AGT-03" in text and "AGT-04" in text
    assert "bedrock:GetKnowledgeBase" in text
    assert "absence of evidence, not a pass" in text


def test_preflight_records_the_blocked_checks_as_not_evaluated():
    s = _scanner(principals=_me())
    s._preflight_permissions()
    # Slice 2.1: one more missing action (bedrock:GetGuardrail) blocking three more
    # checks. The preflight derives this set from the ledger, so it picked all three
    # up without being told - which is the behaviour the runtime denial path in
    # _grade_guardrails was corrected to match.
    assert set(s._coverage.not_evaluated) == {"AGT-03", "AGT-04",
                                              "AIGRD-01", "AIGRD-02", "AIGRD-04",
                                              "AGC-01", "AGC-02", "AGC-03",
                                              "AGC-04", "AGC-05", "AGC-06"}
    assert not s._coverage.complete


def test_a_fully_granted_role_produces_no_coverage_noise():
    """An admin scanner must not be told about gaps it does not have."""
    s = _scanner(principals=_me(actions={"*"}))
    s._preflight_permissions()
    assert s._perm_ledger.missing_actions == ()
    assert not s._coverage.not_evaluated
    assert not [r for r in s.results if r.check_id == "AISPM-00"]


# ── fail-open, in every direction ───────────────────────────────────────────
def test_an_unreadable_identity_does_not_stop_the_scan():
    s = _scanner(sts_raises=True, principals=_me())
    s._preflight_permissions()          # must not raise
    assert s._perm_ledger is None


def test_a_principal_we_cannot_find_does_not_stop_the_scan():
    """A federated session, or a role that lives in another account."""
    s = _scanner(principals=_me(name="SomeOtherRole"))
    s._preflight_permissions()
    assert s._perm_ledger is None
    assert s._coverage.complete, "an unknown role is not a known gap"


def test_an_unparseable_caller_arn_does_not_stop_the_scan():
    s = _scanner(caller_arn="not-an-arn", principals=_me())
    s._preflight_permissions()
    assert s._perm_ledger is None


def test_unreadable_iam_does_not_stop_the_scan():
    s = _scanner()
    s._get_iam_principals = MagicMock(side_effect=Exception("iam: AccessDenied"))
    s._preflight_permissions()
    assert s._perm_ledger is None


# ── the observed half ───────────────────────────────────────────────────────
def test_the_region_note_records_what_was_not_scanned():
    s = _scanner()
    s.sections = ["BEDROCK"]
    s._all_regions = ["us-east-1", "us-west-2", "eu-west-1"]
    s._aispm_region_coverage_note()
    assert s._coverage.scanned_regions == ["us-east-1"]
    assert s._coverage.unscanned_regions == ["eu-west-1", "us-west-2"]
    assert not s._coverage.complete


# ── both travel with the scan ───────────────────────────────────────────────
def test_the_scan_result_carries_coverage_and_the_ledger():
    """A consumer reading posture_score without this is reading a number whose
    denominator it does not know."""
    s = _scanner(principals=_me())
    s._preflight_permissions()
    s.graph = None
    s.attack_paths = []
    s.choke_points = []
    payload = cnapp_service.serialize_scanner(s)
    assert payload["coverage"] is not None
    assert payload["coverage"]["complete"] is False
    assert "AGT-03" in payload["coverage"]["not_evaluated"]
    assert payload["permission_ledger"] is not None
    assert payload["permission_ledger"]["missing_actions"] == [
        "bedrock-agentcore:GetAgentRuntime",
        "bedrock-agentcore:GetGateway",
        "bedrock-agentcore:ListAgentRuntimes",
        "bedrock-agentcore:ListApiKeyCredentialProviders",
        "bedrock-agentcore:ListBrowsers",
        "bedrock-agentcore:ListCodeInterpreters",
        "bedrock-agentcore:ListGatewayTargets",
        "bedrock-agentcore:ListGateways",
        "bedrock-agentcore:ListMemories",
        "bedrock-agentcore:ListOauth2CredentialProviders",
        "bedrock-agentcore:ListWorkloadIdentities",
        "bedrock:GetAgentActionGroup", "bedrock:GetDataSource",
        "bedrock:GetGuardrail",
        "bedrock:GetKnowledgeBase"]


def test_a_scan_that_never_ran_preflight_still_serializes():
    """Backward compatibility: an older code path that never calls preflight must not
    produce a broken payload."""
    s = _scanner()
    s.graph = None
    s.attack_paths = []
    s.choke_points = []
    payload = cnapp_service.serialize_scanner(s)
    assert payload["permission_ledger"] is None
    assert payload["coverage"]["complete"] is True


def test_the_annotated_policy_reaches_the_payload():
    """The wizard renders this: action, reason, and what declining costs."""
    s = _scanner(principals=_me())
    s._preflight_permissions()
    s.graph = None
    s.attack_paths = []
    s.choke_points = []
    rows = cnapp_service.serialize_scanner(s)["permission_ledger"]["annotated_policy"]
    # 13: the four Bedrock config reads plus nine for AgentCore, a separate
    # service SecurityAudit predates entirely.
    # 15: slice 2.3 added GetGateway and ListGatewayTargets, which are what let
    # AGC-05 grade inbound authorization against the OUTBOUND configuration
    # rather than reporting authorizerType as a boolean.
    assert len(rows) == 15
    for row in rows:
        assert row["why"] and row["enables"] and row["forfeited_if_declined"]
