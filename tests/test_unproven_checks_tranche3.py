"""Third tranche: the LOGGING section, which no test had ever called.

WHERE THIS CAME FROM. `docs/CHECK_FIRING.md` lists 88 checks that no test ever made
emit anything -- not a FAIL, not even a PASS. Grouping them by the method that emits
them (not by the section argument, which is a literal in only some call sites) splits
them into two populations needing opposite work:

  * 34 sit in methods NO test calls, where one fixture reaches a whole cluster;
  * 54 sit in methods tests do call, where the fixture never satisfies the branch.

`_check_logging` is the best of the first kind: four checks, two of them among the
five CRITICALs in the whole never-observed set, and not one line of it had ever run
under test. These are the account's alarm system -- CloudTrail off, Config not
recording, GuardDuty disabled, Security Hub with no standards. A scanner that cannot
report those is failing at the thing it exists for.

EVERY ASSERTION PINS THE CONDITION, not just the check id. All four checks sit inside
`try` blocks whose `except` ALSO emits a FAIL for the same id, so "did it FAIL?" is
satisfied by any fixture that merely throws -- the check would look driven while the
condition it is named for never ran. Tranche 2 established this; here it matters for
all four rather than two.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_live_scanner import make_scanner, MockClientError


@pytest.fixture(autouse=True)
def _client_error():
    """`ClientError` is imported inside `try: import boto3`; without boto3 the name
    does not exist and `except ClientError` raises NameError before the handler runs.
    LOG-05 catches it explicitly."""
    with patch("engine.aws_live_scanner.ClientError", MockClientError,
               create=True):
        yield


def fails_on(scanner, check_id, resource=None, message_startswith=None):
    rows = [r for r in scanner.results
            if r.check_id == check_id and r.status == "FAIL"]
    assert rows, "%s never reached FAIL; emitted %s" % (
        check_id,
        sorted({r.status for r in scanner.results
                if r.check_id == check_id}) or ["nothing"])
    if resource is not None:
        narrowed = [r for r in rows if r.resource == resource]
        assert narrowed, "%s failed, but not on resource %r - got %r" % (
            check_id, resource, [r.resource for r in rows])
        rows = narrowed
    if message_startswith is not None:
        assert [r for r in rows if r.message.startswith(message_startswith)], (
            "%s failed, but not with the named condition (%r) - got %r"
            % (check_id, message_startswith, [r.message for r in rows]))
    return rows


def logging_scanner(*, trails, recorders, detectors, standards,
                    detector_status="DISABLED"):
    """One scanner with all four LOGGING services mocked.

    `_check_logging` resolves each service through `_client(...)`, and an unmocked
    service returns a bare MagicMock whose `.get(...)` is itself a truthy MagicMock --
    which silently reads as "everything is fine" and is how a fixture can make a
    broken account look clean. Every service the section touches is set explicitly.
    """
    s = make_scanner(["LOGGING"])

    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": trails}
    ct.get_trail_status.return_value = {"IsLogging": False}
    s._clients["cloudtrail:us-east-1"] = ct

    cfg = MagicMock()
    cfg.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": recorders}
    s._clients["config:us-east-1"] = cfg

    gd = MagicMock()
    gd.list_detectors.return_value = {"DetectorIds": detectors}
    gd.get_detector.return_value = {"Status": detector_status}
    s._clients["guardduty:us-east-1"] = gd

    sh = MagicMock()
    sh.get_enabled_standards.return_value = {"StandardsSubscriptions": standards}
    s._clients["securityhub:us-east-1"] = sh
    return s


# ── the four conditions, one account that has all of them ───────────────────

@pytest.fixture()
def blind_account():
    """An account with its alarm system switched off in four different ways."""
    return logging_scanner(
        trails=[{"Name": "single-region-trail",
                 "IsMultiRegionTrail": False,
                 "LogFileValidationEnabled": False}],
        recorders=[{"name": "default", "recording": False}],
        detectors=["det-abc123"],
        standards=[],
    )


def test_the_four_logging_checks_report_a_blind_account(blind_account):
    """CloudTrail misconfigured, Config not recording, GuardDuty disabled and
    Security Hub carrying no standards. None of these four had ever been driven to a
    FAIL, so none had ever rendered its catalogue severity or remediation."""
    blind_account._check_logging()

    fails_on(blind_account, "LOG-01", resource="single-region-trail",
             message_startswith="Trail 'single-region-trail' issues:")
    fails_on(blind_account, "LOG-03", resource="default",
             message_startswith="AWS Config NOT recording")
    fails_on(blind_account, "LOG-04", resource="det-abc123",
             message_startswith="GuardDuty DISABLED")
    fails_on(blind_account, "LOG-05", resource="securityhub",
             message_startswith="Security Hub enabled but no standards")


def test_the_trail_finding_names_every_misconfiguration_it_found(blind_account):
    """The message is the whole value of LOG-01: an operator reading 'issues: ...'
    must be told WHICH of the three, because the fixes differ."""
    blind_account._check_logging()
    row = fails_on(blind_account, "LOG-01", resource="single-region-trail")[0]
    for expected in ("not multi-region", "log validation OFF", "LOGGING IS OFF"):
        assert expected in row.message, (
            "LOG-01 message omits %r: %r" % (expected, row.message))


def test_two_of_these_are_critical_and_carry_their_remediation(blind_account):
    """`_add` reads severity, compliance and remediation from the catalogue ONLY on
    the FAIL branch. Until this tranche neither CRITICAL had ever taken that branch,
    so neither had ever rendered CRITICAL to a customer."""
    blind_account._check_logging()
    for cid in ("LOG-01", "LOG-04"):
        row = [r for r in blind_account.results
               if r.check_id == cid and r.status == "FAIL"][0]
        assert row.severity == "CRITICAL", "%s rendered %r" % (cid, row.severity)
        assert row.remediation_cmd, "%s FAILed with no remediation text" % cid
        assert row.compliance, "%s FAILed with no compliance mapping" % cid


# ── the empty-estate variants, which take a different branch ────────────────

def test_an_account_with_no_trails_and_no_detectors_still_reports():
    """Absence is the more dangerous shape: no trail and no detector means nothing
    is watching, and both checks take a branch the populated fixture never reaches.
    Pinned by message because the empty branch shares its resource name with the
    exception handler."""
    s = logging_scanner(trails=[], recorders=[], detectors=[], standards=[])
    s._check_logging()

    fails_on(s, "LOG-01", resource="cloudtrail",
             message_startswith="No CloudTrail trails configured")
    fails_on(s, "LOG-03", resource="config",
             message_startswith="No AWS Config recorders found")
    fails_on(s, "LOG-04", resource="guardduty",
             message_startswith="GuardDuty NOT enabled")


def test_a_healthy_account_passes_all_four():
    """The anchor. Without it every assertion above is satisfied by a section that
    fails unconditionally, which is the failure mode a scanner cannot afford: an
    alarm that is always ringing is the same as no alarm."""
    s = logging_scanner(
        trails=[{"Name": "org-trail", "IsMultiRegionTrail": True,
                 "LogFileValidationEnabled": True}],
        recorders=[{"name": "default", "recording": True}],
        detectors=["det-abc123"],
        standards=[{"StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws/v/1.2.0",
                    "StandardsStatus": "READY"}],
        detector_status="ENABLED",
    )
    s._clients["cloudtrail:us-east-1"].get_trail_status.return_value = {
        "IsLogging": True}
    s._check_logging()

    for cid in ("LOG-01", "LOG-03", "LOG-04", "LOG-05"):
        statuses = {r.status for r in s.results if r.check_id == cid}
        assert "FAIL" not in statuses, (
            "%s FAILed on a healthy account: %r" % (cid, [
                r.message for r in s.results
                if r.check_id == cid and r.status == "FAIL"]))
        assert "PASS" in statuses, "%s emitted %r, no PASS" % (cid, statuses)
