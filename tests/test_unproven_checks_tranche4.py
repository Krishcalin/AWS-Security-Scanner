"""Fourth tranche: the IAM privilege-escalation rules, driven end to end.

WHY THESE WERE UNPROVEN DESPITE BEING WELL TESTED. `evaluate_privesc_scoped` -- the
function that decides which escalation primitives a principal holds -- already has
direct unit tests, and good ones. But they call the pure function and inspect its
return value, so no finding is ever constructed: `_add` is never reached, and the
recorder in `tests/conftest.py` never sees these ids. Fourteen IAMPE checks sat in
`docs/CHECK_FIRING.md` as never observed, including two CRITICALs, while the logic
behind them was covered. Tested logic and a proven finding are different claims, and
only the second one is what a customer receives.

WHERE THE FIXTURE GOES IN. At the AWS API boundary -- one mocked
`iam:GetAccountAuthorizationDetails` page -- not at `_privesc`. That matters: the test
authors POLICY STATEMENTS and production decides which rules match, so a broken
matcher fails the test. Feeding pre-built finding dicts would assert only that a list
survives a loop.

THE POLICY IS DERIVED FROM THE RULE TABLE, one action per `all_of` group, so a rule
added later is driven by this test on the day it is added rather than joining the
never-observed backlog. `Action: "*"` is deliberately NOT granted: a `*` megapivot
short-circuits to IAMPE-19 and returns nothing else, which would leave every granular
rule exactly as unproven as before.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.aws_live_scanner import (
    IAM_PRIVESC_ASSUMEROLE, IAM_PRIVESC_FULL_ADMIN, IAM_PRIVESC_RULES,
    CHECK_SEVERITY,
)
from test_live_scanner import make_scanner


class OnePage:
    """`get_account_authorization_details` is read through a paginator, and one page
    carries every list at once (users, groups, roles, managed policy documents)."""

    def __init__(self, page):
        self._page = page

    def paginate(self, *a, **kw):
        return [self._page]


def privesc_actions():
    """One action from each `all_of` group of every rule: the minimum grant that
    satisfies the whole table. IAMPE-10..14 need two or three groups each (PassRole
    plus a compute-launch action), which is why this is not simply a flat list."""
    actions = []
    for rule in IAM_PRIVESC_RULES:
        for group in rule["all_of"]:
            actions.append(group[0])
    return sorted(set(actions))


def scanner_with_policy(statements, *, name="deployer"):
    s = make_scanner(["IAMPRIVESC"])
    # The SCP ceiling is fail-open and cached; pinning it to "not evaluated" keeps
    # the fixture from depending on what a MagicMock organizations client returns.
    s._scp_fetched = True
    s._scp_context = None

    iam = MagicMock()
    iam.get_paginator.return_value = OnePage({
        "UserDetailList": [{
            "UserName": name,
            "Arn": "arn:aws:iam::123456789012:user/%s" % name,
            "UserPolicyList": [{
                "PolicyName": "inline",
                "PolicyDocument": {"Version": "2012-10-17",
                                   "Statement": statements},
            }],
        }],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    })
    s._clients["iam:us-east-1"] = iam
    return s


def failed_ids(scanner):
    return {r.check_id for r in scanner.results if r.status == "FAIL"}


def rows_for(scanner, check_id):
    return [r for r in scanner.results if r.check_id == check_id]


# ── the whole rule table, from one over-permissioned user ───────────────────

@pytest.fixture()
def over_permissioned():
    return scanner_with_policy([{
        "Effect": "Allow",
        "Action": privesc_actions(),
        "Resource": "*",
    }])


def test_every_privesc_rule_in_the_table_reaches_a_finding(over_permissioned):
    """The point of the tranche. Thirteen of these ids had never been emitted at all,
    so none had ever rendered its catalogue severity or carried its remediation."""
    over_permissioned._check_iam_privesc()
    failed = failed_ids(over_permissioned)
    missing = sorted(r["id"] for r in IAM_PRIVESC_RULES if r["id"] not in failed)
    assert not missing, (
        "rules the table defines but no finding reported: %s (emitted %s)"
        % (missing, sorted(failed)))


def test_the_finding_names_the_principal_and_the_primitive(over_permissioned):
    """A privesc finding whose message is just an id is unactionable: the operator
    needs to know WHO can escalate and by WHICH primitive."""
    over_permissioned._check_iam_privesc()
    row = rows_for(over_permissioned, "IAMPE-01")[0]
    assert "deployer" in row.resource, row.resource
    assert IAM_PRIVESC_RULES[0]["name"] in row.message, row.message


def test_the_two_criticals_render_critical_with_their_remediation(
        over_permissioned):
    """`_add` reads severity, compliance and remediation from the catalogue only on
    the FAIL branch, so an id that has never failed has never rendered any of them."""
    over_permissioned._check_iam_privesc()
    for cid in ("IAMPE-01", "IAMPE-04"):
        assert CHECK_SEVERITY[cid] == "CRITICAL", "catalogue changed under this test"
        fails = [r for r in rows_for(over_permissioned, cid) if r.status == "FAIL"]
        assert fails, "%s did not FAIL" % cid
        assert fails[0].severity == "CRITICAL", fails[0].severity
        assert fails[0].remediation_cmd, "%s carries no remediation" % cid
        assert fails[0].compliance, "%s carries no compliance mapping" % cid


# ── precision: a rule must not fire on permissions it does not require ──────

def test_one_granted_action_fires_exactly_one_rule():
    """Guards the direction the bulk test cannot: that the matcher is selective.
    `iam:CreatePolicyVersion` is IAMPE-01's whole requirement and nothing else's, so
    a second IAMPE FAIL here would mean rules match permissions they never asked
    for -- every over-permissioned account would then look identical."""
    s = scanner_with_policy([{"Effect": "Allow",
                              "Action": ["iam:CreatePolicyVersion"],
                              "Resource": "*"}])
    s._check_iam_privesc()
    fired = {c for c in failed_ids(s) if c.startswith("IAMPE-")}
    assert fired == {"IAMPE-01"}, fired


def test_a_multi_group_rule_needs_every_group():
    """IAMPE-10 is iam:PassRole AND ec2:RunInstances. PassRole alone is ordinary and
    must not be reported as an escalation path, or the check becomes noise."""
    s = scanner_with_policy([{"Effect": "Allow", "Action": ["iam:PassRole"],
                              "Resource": "*"}])
    s._check_iam_privesc()
    assert "IAMPE-10" not in failed_ids(s), [
        r.message for r in rows_for(s, "IAMPE-10")]

    s2 = scanner_with_policy([{"Effect": "Allow",
                               "Action": ["iam:PassRole", "ec2:RunInstances"],
                               "Resource": "*"}])
    s2._check_iam_privesc()
    assert "IAMPE-10" in failed_ids(s2)


def test_an_explicit_deny_neutralizes_the_grant_it_names():
    """A wildcard grant carved out by an explicit Deny is the standard way real
    accounts fence off dangerous IAM actions. Reporting IAMPE-01 anyway would flag
    precisely the accounts that did the right thing, while the sibling rules must
    still fire or the Deny would be suppressing more than it names.

    THE DENY IS ENFORCED TWICE, INDEPENDENTLY, and this test is the record of it:
    once in `_action_allowed`, and again in the effective-permissions solver, which
    prunes the pivot with reason `explicit_deny`. Deleting either one alone leaves
    this test passing -- verified by mutation, and a genuine redundancy rather than a
    hole in the test. Deleting BOTH does fail it, which is what makes the assertion
    worth having."""
    s = scanner_with_policy([
        {"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"},
        {"Effect": "Deny", "Action": ["iam:CreatePolicyVersion"], "Resource": "*"},
    ])
    s._check_iam_privesc()
    fired = failed_ids(s)
    assert "IAMPE-01" not in fired, [
        r.message for r in rows_for(s, "IAMPE-01")]
    # the carve-out is narrow: sibling iam: rules are untouched by it
    assert "IAMPE-02" in fired, sorted(fired)
    assert "IAMPE-04" in fired, sorted(fired)


def test_unrestricted_assume_role_is_reported_but_a_scoped_one_is_not():
    """IAMPE-20 fires only when sts:AssumeRole is account-wide; scoped to one role
    ARN it is how every well-run account works, and reporting it would be a false
    positive on the most common pattern in AWS."""
    wide = scanner_with_policy([{"Effect": "Allow", "Action": ["sts:AssumeRole"],
                                 "Resource": "*"}])
    wide._check_iam_privesc()
    assert IAM_PRIVESC_ASSUMEROLE["id"] in failed_ids(wide)

    scoped = scanner_with_policy([{
        "Effect": "Allow", "Action": ["sts:AssumeRole"],
        "Resource": "arn:aws:iam::123456789012:role/build"}])
    scoped._check_iam_privesc()
    assert IAM_PRIVESC_ASSUMEROLE["id"] not in failed_ids(scoped)


def test_full_admin_short_circuits_to_one_finding():
    """Action '*' on Resource '*' is the megapivot: it returns IAMPE-19 alone rather
    than every granular rule it technically implies. Documented here because it is
    also the reason the bulk fixture must enumerate actions instead of granting '*'."""
    s = scanner_with_policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}])
    s._check_iam_privesc()
    fired = {c for c in failed_ids(s) if c.startswith("IAMPE-")}
    assert fired == {IAM_PRIVESC_FULL_ADMIN["id"]}, fired


# ── the anchor ──────────────────────────────────────────────────────────────

def test_an_ordinary_principal_reports_no_escalation_path():
    """Without this every assertion above is satisfied by a section that reports
    escalation for everyone. A read-only user holds no privesc primitive, and a
    scanner that says otherwise is worse than one that says nothing."""
    s = scanner_with_policy([{
        "Effect": "Allow",
        "Action": ["s3:GetObject", "cloudwatch:GetMetricData"],
        "Resource": "*"}])
    s._check_iam_privesc()
    fired = {c for c in failed_ids(s) if c.startswith("IAMPE-")}
    assert not fired, fired
