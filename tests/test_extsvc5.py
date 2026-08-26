"""Batch 5 — classifiers and the five scanner sections.

First batch authored after the SDK pin moved to botocore 1.43.51, so for the first time
the models these checks were verified against are the models the product ships.

Two client-name/IAM-prefix traps in this batch — Mail Manager signs as `ses`, and
CodeGuru Profiler's prefix is `codeguru-profiler` with a hyphen — and both were validated
automatically by `test_iam_surface` rather than caught by hand, which is the fourth and
fifth instances of a mistake that had needed a human every previous time.
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
import aws_extsvc5 as E
import aws_live_scanner as A

SECTIONS = {
    "_check_workmail": ("WM-01", "WM-02", "WM-03"),
    "_check_sitewise": ("SW-01", "SW-02"),
    "_check_iotmanagedint": ("IMI-01",),
    "_check_mailmanager": ("MM-01",),
    "_check_codeguruprofiler": ("CGP-01",),
}


class _Deny:
    def __getattr__(self, name):
        def _raise(*a, **kw):
            raise Exception("AccessDeniedException")
        return _raise


def _scanner(client=None):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["WORKMAIL"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: client if client is not None else MagicMock()
    s._is_access_denied = lambda e: "AccessDenied" in str(e)
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


# ── invariants across all five sections ─────────────────────────────────────
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


# ── WorkMail ────────────────────────────────────────────────────────────────
def test_no_access_control_rules_is_reported():
    r = E.workmail_access_rules("m-1", [])
    assert r["unrestricted"] is True and "credential store" in r["statement"]


def test_a_deny_rule_counts_as_restrictive():
    r = E.workmail_access_rules("m-1", [{"Name": "no-legacy", "Effect": "DENY"}])
    assert r["unrestricted"] is False


def test_an_ip_scoped_allow_rule_counts_as_restrictive():
    r = E.workmail_access_rules("m-1", [{"Name": "corp", "Effect": "ALLOW",
                                         "IpRanges": ["10.0.0.0/8"]}])
    assert r["unrestricted"] is False


def test_an_allow_rule_that_restricts_nothing_is_not_restrictive():
    """A rule that allows everything from everywhere is not a control."""
    r = E.workmail_access_rules("m-1", [{"Name": "all", "Effect": "ALLOW"}])
    assert r["unrestricted"] is True


def test_no_retention_policy_is_reported():
    r = E.workmail_retention("m-1", None)
    assert r["has_policy"] is False and "kept indefinitely" in r["statement"]


def test_a_retention_policy_is_quiet():
    r = E.workmail_retention("m-1", {"Id": "p-1", "FolderConfigurations": [
        {"Name": "INBOX", "Action": "DELETE", "Period": 1095}]})
    assert r["has_policy"] is True and r["statement"] == ""


def test_an_unreadable_retention_policy_makes_no_claim():
    """Denied is not absent -- the section passes readable=False on a denial."""
    r = E.workmail_retention("m-1", None, readable=False)
    assert r["statement"] == ""


def test_no_mobile_device_rules_is_reported():
    r = E.workmail_device_rules("m-1", [])
    assert r["unrestricted"] is True
    assert "outlives the session" in r["statement"]


def test_mobile_device_rules_present_is_quiet():
    r = E.workmail_device_rules("m-1", [{"MobileDeviceAccessRuleId": "r-1"}])
    assert r["unrestricted"] is False and r["statement"] == ""


# ── IoT SiteWise ────────────────────────────────────────────────────────────
def test_sitewise_default_encryption_is_reported():
    r = E.sitewise_encryption({"encryptionType": "SITEWISE_DEFAULT_ENCRYPTION"})
    assert r["cmk"] is False and "industrial telemetry" in r["statement"]


def test_sitewise_kms_encryption_is_quiet():
    r = E.sitewise_encryption({"encryptionType": "KMS_BASED_ENCRYPTION",
                               "kmsKeyArn": "arn:key"})
    assert r["cmk"] is True and r["statement"] == ""


def test_an_absent_sitewise_encryption_type_is_unknown():
    assert E.sitewise_encryption({})["known"] is False


def test_sitewise_logging_off_is_reported():
    r = E.sitewise_logging({"loggingOptions": {"level": "OFF"}})
    assert r["off"] is True and "ingestion anomaly" in r["statement"]


def test_sitewise_logging_on_is_quiet():
    r = E.sitewise_logging({"loggingOptions": {"level": "INFO"}})
    assert r["off"] is False and r["statement"] == ""


def test_an_absent_logging_level_is_unknown_not_off():
    assert E.sitewise_logging({})["known"] is False


# ── IoT Managed Integrations ────────────────────────────────────────────────
def test_imi_default_encryption_is_reported():
    r = E.imi_encryption(
        {"encryptionType": "MANAGED_INTEGRATIONS_DEFAULT_ENCRYPTION"})
    assert r["cmk"] is False and "third-party device clouds" in r["statement"]


def test_imi_customer_key_is_quiet():
    r = E.imi_encryption({"encryptionType": "CUSTOMER_KEY_ENCRYPTION",
                          "kmsKeyArn": "arn:key"})
    assert r["cmk"] is True and r["statement"] == ""


# ── SES Mail Manager ────────────────────────────────────────────────────────
def test_a_traffic_policy_defaulting_to_allow_fails_open():
    r = E.mailmanager_policy("inbound", {"DefaultAction": "ALLOW",
                                         "PolicyStatements": [{"Action": "DENY"}]})
    assert r["fails_open"] is True and "DELIVERED rather than rejected" in r["statement"]


def test_a_traffic_policy_defaulting_to_deny_is_quiet():
    r = E.mailmanager_policy("inbound", {"DefaultAction": "DENY"})
    assert r["fails_open"] is False and r["statement"] == ""


def test_an_absent_default_action_is_unknown_not_allow():
    assert E.mailmanager_policy("inbound", {})["known"] is False


# ── CodeGuru Profiler ───────────────────────────────────────────────────────
def test_a_wildcard_profiler_policy_is_reported():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*",
                                     "Action": "*"}]})
    r = E.codeguru_policy("prod", doc)
    assert r["public"] is True and "stack traces" in r["statement"]


def test_a_scoped_profiler_policy_is_quiet():
    doc = json.dumps({"Statement": [{"Effect": "Allow",
                                     "Principal": {"AWS": "arn:aws:iam::1:role/x"},
                                     "Action": "codeguru-profiler:GetProfile"}]})
    assert E.codeguru_policy("prod", doc)["public"] is False


def test_no_profiler_policy_is_not_a_finding():
    assert E.codeguru_policy("prod", None)["has_policy"] is False


# ── section behaviour ───────────────────────────────────────────────────────
def test_the_workmail_section_reports_all_three_gaps():
    c = MagicMock()
    c.list_organizations.return_value = {
        "OrganizationSummaries": [{"OrganizationId": "m-1"}]}
    c.list_access_control_rules.return_value = {"Rules": []}
    c.get_default_retention_policy.return_value = {}
    c.list_mobile_device_access_rules.return_value = {"Rules": []}
    s = _scanner(c)
    s._check_workmail()
    for cid in ("WM-01", "WM-02", "WM-03"):
        assert _ids(s, cid, "FAIL"), cid


def test_the_sitewise_section_reports_default_encryption_and_logging_off():
    c = MagicMock()
    c.describe_default_encryption_configuration.return_value = {
        "encryptionType": "SITEWISE_DEFAULT_ENCRYPTION"}
    c.describe_logging_options.return_value = {"loggingOptions": {"level": "OFF"}}
    s = _scanner(c)
    s._check_sitewise()
    assert _ids(s, "SW-01", "FAIL") and _ids(s, "SW-02", "FAIL")


def test_the_mailmanager_section_reports_a_fail_open_policy():
    c = MagicMock()
    c.list_traffic_policies.return_value = {
        "TrafficPolicies": [{"TrafficPolicyId": "tp-1", "TrafficPolicyName": "in"}]}
    c.get_traffic_policy.return_value = {"TrafficPolicyName": "in",
                                         "DefaultAction": "ALLOW",
                                         "PolicyStatements": []}
    s = _scanner(c)
    s._check_mailmanager()
    assert _ids(s, "MM-01", "FAIL")


# ── robustness and the prefix traps ─────────────────────────────────────────
@pytest.mark.parametrize("fn", [E.sitewise_encryption, E.sitewise_logging,
                                E.imi_encryption])
@pytest.mark.parametrize("bad", [None, {}, "x", 7])
def test_no_classifier_raises_on_malformed_input(fn, bad):
    fn(bad if isinstance(bad, dict) else None)


def test_sequence_helpers_survive_malformed_input():
    E.workmail_access_rules("", None)
    E.workmail_device_rules("", ["not-a-dict"])
    E.workmail_retention("", None)
    E.mailmanager_policy("", None)
    E.codeguru_policy("", "not json")


def test_mail_manager_signs_as_ses_not_its_client_name():
    """The fourth client-name trap. The boto3 client is `mailmanager`; the IAM prefix is
    `ses`. Caught automatically by test_iam_surface rather than by hand this time."""
    actions = [p.action for p in C.REGISTRY["MM-01"].permissions]
    assert actions and all(a.startswith("ses:") for a in actions)
    assert not any(a.startswith("mailmanager:") for a in actions)


def test_codeguru_profiler_iam_prefix_is_hyphenated():
    """The fifth. Client `codeguruprofiler`, IAM prefix `codeguru-profiler`."""
    actions = [p.action for p in C.REGISTRY["CGP-01"].permissions]
    assert actions and all(a.startswith("codeguru-profiler:") for a in actions)
    assert not any(a.startswith("codeguruprofiler:") for a in actions)


@pytest.mark.parametrize("section", ["WORKMAIL", "SITEWISE", "IOTMANAGEDINT",
                                     "MAILMANAGER", "CODEGURUPROFILER"])
def test_each_section_is_registered_and_labelled(section):
    assert section in A.SECTIONS and section in A.SECTION_LABELS


@pytest.mark.parametrize("cid", sorted(c for cs in SECTIONS.values() for c in cs))
def test_every_batch5_check_came_from_one_declaration(cid):
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
