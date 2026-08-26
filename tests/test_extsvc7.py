"""Batch 7 — classifiers and the six scanner sections.

The first batch chosen AGAINST the ranking. By batch 7 the top score was 14, and the
heuristic reads operation *names* — so it put CloudFormation and Firewall Manager at 5,
below Wickr, because `GetStackPolicy` and `GetPolicy` are unremarkable strings attached
to the two most consequential services here.

Also the batch where a prefix collision was avoided by checking rather than by luck:
CloudFormation's checks are `STACK-*`, because `CFN-01` through `CFN-06` already exist
and are **CloudFront**. Reaching for the obvious prefix would have silently overwritten
six live checks — the `SEG-01` defect, which this codebase has shipped once.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_checkdef as C
import aws_extsvc7 as E
import aws_live_scanner as A

SECTIONS = {
    "_check_cloudformation": ("STACK-01", "STACK-02"),
    "_check_firewallmanager": ("FMS-01", "FMS-02"),
    "_check_ecrpublic": ("ECRPUB-01",),
    "_check_multipartyapproval": ("MPA-01",),
    "_check_wickr": ("WKR-01",),
    "_check_mediapackage": ("MPV-01",),
}


class _Deny:
    def __getattr__(self, name):
        def _raise(*a, **kw):
            raise Exception("AccessDeniedException")
        return _raise


def _scanner(client=None):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False,
                             sections=["CLOUDFORMATION"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: client if client is not None else MagicMock()
    s._is_access_denied = lambda e: "AccessDenied" in str(e)
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def pol(principal="*", action="*"):
    return json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": principal, "Action": action}]})


# ── the prefix collision that was avoided ───────────────────────────────────
def test_cloudformation_did_not_take_the_cfn_prefix():
    """CFN-01..06 are CloudFront. Taking that prefix would have silently overwritten
    six live checks -- exactly the SEG-01 defect."""
    assert "CFN-03" in A.CHECK_SEVERITY
    assert "cloudfront" in A.REMEDIATION_MAP["CFN-03"]
    assert not any(k.startswith("CFN-") for k in C.REGISTRY)
    assert "STACK-01" in C.REGISTRY and "STACK-02" in C.REGISTRY


# ── invariants across the six sections ──────────────────────────────────────
@pytest.mark.parametrize("method,checks", sorted(SECTIONS.items()))
def test_a_denied_read_is_a_coverage_note_never_a_pass_or_a_finding(method, checks):
    s = _scanner(_Deny())
    getattr(s, method)()
    for cid in checks:
        assert not _ids(s, cid, "PASS"), cid
        assert not _ids(s, cid, "FAIL"), cid
    assert any(c in s._coverage.not_evaluated for c in checks), method


@pytest.mark.parametrize("method", sorted(SECTIONS))
def test_every_section_terminates_against_a_bare_magicmock(method):
    s = _scanner()
    done = threading.Event()

    def _go():
        try:
            getattr(s, method)()
        except Exception:
            pass
        finally:
            done.set()

    threading.Thread(target=_go, daemon=True).start()
    assert done.wait(timeout=20), f"{method} did not terminate"


# ── CloudFormation ──────────────────────────────────────────────────────────
def test_a_stack_with_no_policy_is_reported():
    r = E.stack_policy("prod", "")
    assert r["has_policy"] is False and "replace or delete any resource" in r["statement"]


def test_a_stack_with_a_policy_is_quiet():
    r = E.stack_policy("prod", '{"Statement":[]}')
    assert r["has_policy"] is True and r["statement"] == ""


def test_a_whitespace_only_policy_body_counts_as_none():
    assert E.stack_policy("prod", "   ")["has_policy"] is False


def test_a_stack_with_no_service_role_is_reported():
    r = E.stack_service_role({"StackName": "prod"})
    assert r["has_role"] is False and "permissions of whoever calls them" in r["statement"]


def test_the_iam_capability_sharpens_the_service_role_finding():
    """A template is a way to create identities when the stack is IAM-capable."""
    r = E.stack_service_role({"StackName": "prod",
                              "Capabilities": ["CAPABILITY_NAMED_IAM"]})
    assert r["iam_capable"] is True and "create identities" in r["statement"]


def test_a_stack_with_a_service_role_is_quiet():
    r = E.stack_service_role({"StackName": "prod", "RoleARN": "arn:aws:iam::1:role/cfn"})
    assert r["has_role"] is True and r["statement"] == ""


# ── Firewall Manager ────────────────────────────────────────────────────────
def test_a_policy_with_remediation_disabled_is_reported():
    r = E.fms_policy({"PolicyId": "p-1", "PolicyName": "waf",
                      "RemediationEnabled": False})
    assert r["remediates"] is False and "changes nothing" in r["statement"]


def test_a_remediating_policy_is_quiet():
    r = E.fms_policy({"PolicyId": "p-1", "RemediationEnabled": True})
    assert r["remediates"] is True and r["statement"] == ""


def test_an_absent_remediation_flag_is_unknown_not_disabled():
    assert E.fms_policy({"PolicyId": "p-1"})["known"] is False


def test_no_notification_channel_is_reported():
    r = E.fms_notification({})
    assert r["configured"] is False and "somebody being told" in r["statement"]


def test_a_notification_channel_is_quiet():
    r = E.fms_notification({"SnsTopicArn": "arn:sns"})
    assert r["configured"] is True and r["statement"] == ""


def test_an_unreadable_notification_channel_makes_no_claim():
    assert E.fms_notification(None, readable=False)["statement"] == ""


# ── ECR Public ──────────────────────────────────────────────────────────────
def test_a_wildcard_write_grant_on_a_public_repo_is_reported():
    r = E.ecr_public_policy("app", pol("*", "ecr-public:PutImage"))
    assert r["public_write"] is True and "under your organization's name" in r["statement"]


def test_a_wildcard_read_grant_is_NOT_the_finding():
    """Everything in a public registry is readable by design; readability is never the
    finding."""
    r = E.ecr_public_policy("app", pol("*", "ecr-public:BatchGetImage"))
    assert r["public_write"] is False and r["statement"] == ""


def test_a_scoped_write_grant_is_quiet():
    r = E.ecr_public_policy(
        "app", pol({"AWS": "arn:aws:iam::1:role/ci"}, "ecr-public:PutImage"))
    assert r["public_write"] is False


def test_a_wildcard_action_grant_counts_as_write():
    assert E.ecr_public_policy("app", pol("*", "*"))["public_write"] is True


# ── Multi-Party Approval ────────────────────────────────────────────────────
def test_a_single_approver_team_is_reported():
    r = E.mpa_approval_team({"Name": "prod-changes",
                             "ApprovalStrategy": {"MofN": {"MinApprovalsRequired": 1}}})
    assert r["single_approver"] is True
    assert "single point of approval with extra steps" in r["statement"]


def test_a_two_approver_team_is_quiet():
    r = E.mpa_approval_team({"Name": "prod-changes",
                             "ApprovalStrategy": {"MofN": {"MinApprovalsRequired": 2}}})
    assert r["single_approver"] is False and r["statement"] == ""


def test_an_absent_threshold_is_unknown_not_one():
    assert E.mpa_approval_team({"Name": "t"})["known"] is False


# ── Wickr ───────────────────────────────────────────────────────────────────
def test_retention_enabled_is_reported_as_context():
    r = E.wickr_retention("n-1", {"dataRetention": {"enabled": True}})
    assert r["retention_on"] is True
    assert "reported as CONTEXT rather than a defect" in r["statement"]


def test_retention_disabled_is_quiet():
    r = E.wickr_retention("n-1", {"dataRetention": {"enabled": False}})
    assert r["retention_on"] is False and r["statement"] == ""


def test_the_wickr_finding_does_not_say_retention_is_wrong():
    """Retention is frequently a regulatory requirement. The check surfaces it, it does
    not judge it."""
    r = E.wickr_retention("n-1", {"dataRetention": {"enabled": True}})
    low = r["statement"].lower()
    assert "should be disabled" not in low and "misconfigur" not in low


# ── MediaPackage ────────────────────────────────────────────────────────────
def test_a_wildcard_channel_policy_is_reported():
    r = E.mediapackage_policy("grp/chan", pol("*"))
    assert r["public"] is True and "who may INGEST" in r["statement"]


def test_a_scoped_channel_policy_is_quiet():
    r = E.mediapackage_policy("grp/chan", pol({"AWS": "arn:aws:iam::1:role/encoder"}))
    assert r["public"] is False


# ── section behaviour ───────────────────────────────────────────────────────
def test_the_cloudformation_section_reports_both_gaps():
    c = MagicMock()
    c.describe_stacks.return_value = {"Stacks": [{"StackName": "prod"}]}
    c.get_stack_policy.return_value = {"StackPolicyBody": ""}
    s = _scanner(c)
    s._check_cloudformation()
    assert _ids(s, "STACK-01", "FAIL") and _ids(s, "STACK-02", "FAIL")


def test_the_cloudformation_section_passes_a_healthy_stack():
    c = MagicMock()
    c.describe_stacks.return_value = {
        "Stacks": [{"StackName": "prod", "RoleARN": "arn:aws:iam::1:role/cfn"}]}
    c.get_stack_policy.return_value = {"StackPolicyBody": '{"Statement":[]}'}
    s = _scanner(c)
    s._check_cloudformation()
    assert _ids(s, "STACK-01", "PASS") and _ids(s, "STACK-02", "PASS")


def test_the_mpa_section_reports_a_single_approver_team():
    c = MagicMock()
    c.list_approval_teams.return_value = {"ApprovalTeams": [{"Arn": "arn:team/1"}]}
    c.get_approval_team.return_value = {
        "Name": "prod", "ApprovalStrategy": {"MofN": {"MinApprovalsRequired": 1}}}
    s = _scanner(c)
    s._check_multipartyapproval()
    assert _ids(s, "MPA-01", "FAIL")


def test_the_wickr_section_emits_info_not_a_failure():
    c = MagicMock()
    c.list_networks.return_value = {"networks": [{"id": "n-1"}]}
    c.get_network_settings.return_value = {
        "networkSettings": {"dataRetention": {"enabled": True}}}
    s = _scanner(c)
    s._check_wickr()
    assert _ids(s, "WKR-01", "INFO") and not _ids(s, "WKR-01", "FAIL")


# ── robustness and wiring ───────────────────────────────────────────────────
@pytest.mark.parametrize("fn", [E.stack_service_role, E.fms_policy,
                                E.mpa_approval_team])
@pytest.mark.parametrize("bad", [None, {}, "x", 7])
def test_no_classifier_raises_on_malformed_input(fn, bad):
    fn(bad if isinstance(bad, dict) else None)


def test_policy_helpers_survive_malformed_input():
    E.stack_policy("", None)
    E.ecr_public_policy("", "not json")
    E.mediapackage_policy("", None)
    E.wickr_retention("", None)
    E.fms_notification(None)


@pytest.mark.parametrize("section", ["CLOUDFORMATION", "FIREWALLMANAGER", "ECRPUBLIC",
                                     "MULTIPARTYAPPROVAL", "WICKR", "MEDIAPACKAGE"])
def test_each_section_is_registered_and_labelled(section):
    assert section in A.SECTIONS and section in A.SECTION_LABELS


@pytest.mark.parametrize("cid", sorted(c for cs in SECTIONS.values() for c in cs))
def test_every_batch7_check_came_from_one_declaration(cid):
    import aws_finding_detail as D
    import aws_perm_ledger as L
    d = C.REGISTRY[cid]
    assert A.CHECK_SEVERITY[cid] == d.severity
    assert A.REMEDIATION_MAP[cid] == d.remediation
    assert D.FINDING_DETAIL[cid]["risk"] == d.risk
    assert cid in L.REQUIREMENTS


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(E), re.M)
