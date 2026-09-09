"""A read we could not make is not a security finding.

THE DEFECT. Ten checks answered a failed AWS call with
``_add("FAIL", <id>, ..., str(e))`` — the exception's text, as the finding. That is
wrong twice over:

  1. A denied or throttled call rendered as a FAIL carrying that check's remediation.
     The operator is told to fix a misconfiguration nobody observed, when their actual
     problem is a missing grant.
  2. For all ten, that error path was the check's ONLY literal FAIL. `_add` reads
     severity, compliance and remediation from the catalogue for no other status, so a
     check declared HIGH could reach HIGH only by the call failing, while the
     misconfiguration it exists to find emitted WARN — forced to LOW, no remediation.
     The catalogue was describing the error handler.

HOW IT SURVIVED. Nothing asserted it. Removing the whole shape broke no existing test,
which is the same reason `docs/CHECK_FIRING.md` had to be built in the first place: a
check that only ever emits the wrong thing looks identical, from the suite, to one
nobody wrote a test for.

WHAT THIS FILE PINS. The two checks whose condition earned a real FAIL, the behaviour of
the replacement helper, and two tripwires so the shape cannot come back.
"""
from __future__ import annotations

import ast
import glob
import io
import json
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.aws_live_scanner import CHECK_SEVERITY                  # noqa: E402
from test_live_scanner import make_scanner                          # noqa: E402
from test_unproven_checks_tranche5 import _ids, _renders            # noqa: E402

OWN = "123456789012"
OTHER = "999988887777"
REGION = "us-east-1"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _scanner(section, service, client):
    s = make_scanner(sections=[section])
    s.account = OWN
    s._clients[f"{service}:{REGION}"] = client
    return s


# ══════════════════════════════════════════════════════════════════════════════
# BDR-05 — the condition, not the error handler
# ══════════════════════════════════════════════════════════════════════════════
def _bedrock_with_policies(statements):
    b = MagicMock()
    b.get_model_invocation_logging_configuration.return_value = {
        "loggingConfig": {"cloudWatchConfig": {"logGroupName": "/aws/bedrock"},
                          "textDataDeliveryEnabled": True}}
    b.list_guardrails.return_value = {"guardrails": [
        {"name": "g", "id": "gr-1", "status": "READY"}]}
    s = _scanner("BEDROCK", "bedrock", b)
    iam = MagicMock()
    iam.get_paginator.return_value.paginate.return_value = [
        {"Policies": [{"Arn": "arn:aws:iam::%s:policy/p" % OWN, "PolicyName": "p",
                       "DefaultVersionId": "v1"}]}]
    iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Statement": statements}}}
    s._clients[f"iam:{REGION}"] = iam
    s._clients[f"ec2:{REGION}"] = MagicMock(**{
        "describe_vpc_endpoints.return_value": {"VpcEndpoints": []}})
    return s


def test_bdr05_wildcard_bedrock_permission_now_fails():
    """Before this change BDR-05's only FAIL was `str(e)` on the IAM read, so a policy
    granting bedrock:* on * — the thing the check exists for — rendered at LOW with no
    remediation while the catalogue said HIGH."""
    s = _bedrock_with_policies([
        {"Effect": "Allow", "Action": "bedrock:*", "Resource": "*"}])
    s._check_bedrock()
    _renders(s, "BDR-05", "HIGH", contains="Overly broad Bedrock permission")


def test_bdr05_broad_invoke_on_star_also_fails():
    s = _bedrock_with_policies([
        {"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": "*"}])
    s._check_bedrock()
    _renders(s, "BDR-05", "HIGH", contains="bedrock:InvokeModel")


def test_bdr05_a_scoped_bedrock_policy_passes():
    s = _bedrock_with_policies([
        {"Effect": "Allow", "Action": "bedrock:InvokeModel",
         "Resource": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2"}])
    s._check_bedrock()
    assert not _ids(s, "BDR-05", "FAIL") and _ids(s, "BDR-05", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# SNS-04 — a cross-account subscription, gated on the trusted-account list
# ══════════════════════════════════════════════════════════════════════════════
def _sns(subscription_endpoint, trusted=()):
    """The section paginates list_topics AND list_subscriptions off the same client, so
    the mock has to route by operation — a single paginate() return value satisfies one
    and makes the other look like an empty account."""
    topic_arn = f"arn:aws:sns:{REGION}:{OWN}:alerts"
    pages = {
        "list_topics": {"Topics": [{"TopicArn": topic_arn}]},
        "list_subscriptions": {"Subscriptions": [
            {"TopicArn": topic_arn, "Endpoint": subscription_endpoint}]},
    }

    def _pager(op):
        p = MagicMock()
        p.paginate.return_value = [pages.get(op, {})]
        return p

    sns = MagicMock()
    sns.get_paginator.side_effect = _pager
    sns.get_topic_attributes.return_value = {"Attributes": {
        "KmsMasterKeyId": "alias/aws/sns", "Policy": json.dumps({"Statement": []})}}
    sns.list_subscriptions_by_topic.return_value = {"Subscriptions": []}
    s = _scanner("SNS", "sns", sns)
    s.trusted_accounts = set(trusted)
    return s


def test_sns04_subscription_to_an_unknown_account_now_fails():
    s = _sns(f"arn:aws:sqs:{REGION}:{OTHER}:inbox")
    s._check_sns()
    _renders(s, "SNS-04", "MEDIUM", contains=OTHER)


def test_sns04_subscription_to_a_trusted_account_is_silent():
    """The allowlist is what makes this a finding rather than noise: a subscription to a
    partner account somebody named is a decision, not a leak."""
    s = _sns(f"arn:aws:sqs:{REGION}:{OTHER}:inbox", trusted={OTHER})
    s._check_sns()
    assert not _ids(s, "SNS-04", "FAIL")


def test_sns04_same_account_subscription_is_silent():
    s = _sns(f"arn:aws:sqs:{REGION}:{OWN}:inbox")
    s._check_sns()
    assert not _ids(s, "SNS-04", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# The replacement helper's behaviour
# ══════════════════════════════════════════════════════════════════════════════
class _Denied(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "AccessDeniedException",
                                   "Message": "not authorized"}}
        super().__init__("AccessDeniedException: not authorized")


def test_a_denied_read_warns_rather_than_failing():
    """The whole point. A denied dynamodb:ListTables used to produce a DDB-01 FAIL
    carrying DDB-01's encryption remediation — advice for a problem never observed."""
    ddb = MagicMock()
    ddb.get_paginator.side_effect = _Denied()
    ddb.list_tables.side_effect = _Denied()
    s = _scanner("DYNAMODB", "dynamodb", ddb)
    s._check_dynamodb()
    assert not _ids(s, "DDB-01", "FAIL"), "a failed read is not a finding"
    warns = _ids(s, "DDB-01", "WARN")
    assert warns, "and it is not silence either"
    assert "NOT EVALUATED" in warns[0].message
    assert "not assessed, not clean" in warns[0].message.lower()


def test_a_denied_read_is_recorded_in_the_coverage_ledger():
    """So the report can say which grant would answer the question."""
    ddb = MagicMock()
    ddb.get_paginator.side_effect = _Denied()
    ddb.list_tables.side_effect = _Denied()
    s = _scanner("DYNAMODB", "dynamodb", ddb)
    s._check_dynamodb()
    assert "DDB-01" in s._coverage.not_evaluated, (
        "the denial was not recorded, so the report cannot distinguish 'we could not "
        "look' from 'we looked and it was fine'")
    assert "dynamodb:ListTables" in s._coverage.missing_actions, (
        "the ledger has to name the grant that would answer the question")


def test_a_non_denial_failure_still_warns_and_names_the_action():
    """Throttling is not a denial, so nothing goes in the ledger — but the operator
    still has to be told the check did not run."""
    ddb = MagicMock()
    ddb.get_paginator.side_effect = RuntimeError("ThrottlingException: slow down")
    ddb.list_tables.side_effect = RuntimeError("ThrottlingException: slow down")
    s = _scanner("DYNAMODB", "dynamodb", ddb)
    s._check_dynamodb()
    warns = _ids(s, "DDB-01", "WARN")
    assert warns and "dynamodb:ListTables" in warns[0].message
    assert not _ids(s, "DDB-01", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# The tripwires
# ══════════════════════════════════════════════════════════════════════════════
def _scanner_source():
    return io.open(os.path.join(ROOT, "engine", "aws_live_scanner.py"),
                   encoding="utf-8").read()


def _except_linenos(tree):
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ExceptHandler):
            for m in ast.walk(n):
                if hasattr(m, "lineno"):
                    out.add(m.lineno)
    return out


#: The one check for which the exception IS the detection, not an error path.
#: `s3api get-bucket-encryption` raises ServerSideEncryptionConfigurationNotFoundError
#: when a bucket has no default encryption, so there is no non-exception branch to
#: write. It is exempt from the structural rule and NOT exempt from the other defect in
#: the same handler: it does not yet distinguish that response from AccessDenied, which
#: is the S3-07 defect the bucket-B pass fixed. That is recorded, not resolved here.
EXCEPTION_IS_THE_SIGNAL = {"S3-03"}


def test_no_check_above_low_can_only_fail_when_the_read_fails():
    """THE STRUCTURAL RATCHET. A check whose only FAIL sits in an except handler cannot
    render its declared severity for the condition it describes — only for the call
    breaking. Ten checks were in that state; the remaining one is justified above."""
    tree = ast.parse(_scanner_source())
    in_except = _except_linenos(tree)
    sites = {}
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "_add" and len(n.args) >= 2):
            continue
        st, cid = n.args[0], n.args[1]
        if not (isinstance(st, ast.Constant) and st.value == "FAIL"):
            continue
        if not isinstance(cid, ast.Constant):
            continue
        rec = sites.setdefault(cid.value, {"real": 0, "except": 0})
        rec["except" if n.lineno in in_except else "real"] += 1
    offenders = sorted(
        c for c, v in sites.items()
        if v["except"] and not v["real"]
        and c not in EXCEPTION_IS_THE_SIGNAL
        and CHECK_SEVERITY.get(c) not in (None, "LOW", "INFO"))
    assert not offenders, (
        "these checks are declared above LOW and can only FAIL when the AWS read "
        "throws, so their catalogue entry describes their error handler: %s. Either "
        "give the condition a FAIL path, or declare the check LOW to match what it "
        "can render." % offenders)


#: `_add("FAIL", ..., str(e))` — an exception's text presented as a security finding.
#: Every one of these produces, on a denied or throttled read, a FAIL carrying that
#: check's remediation: advice for a problem nobody observed. The ten whose ONLY FAIL
#: had this shape are fixed (see `_read_failed`); these 22 also have real FAIL paths, so
#: their severity is at least reachable honestly, and they are the remaining debt.
#: SHRINK-ONLY. Lower this when sites are converted; never raise it.
MAX_EXCEPTION_TEXT_AS_A_FAILURE = 22


def test_reporting_an_exception_as_a_finding_can_only_decrease():
    count = 0
    for path in sorted(glob.glob(os.path.join(ROOT, "engine", "*.py"))):
        for n in ast.walk(ast.parse(io.open(path, encoding="utf-8").read())):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "_add" and len(n.args) >= 5):
                continue
            st = n.args[0]
            if not (isinstance(st, ast.Constant) and st.value == "FAIL"):
                continue
            msg = n.args[4]
            if (isinstance(msg, ast.Call) and isinstance(msg.func, ast.Name)
                    and msg.func.id == "str" and len(msg.args) == 1
                    and isinstance(msg.args[0], ast.Name)):
                count += 1
    assert count <= MAX_EXCEPTION_TEXT_AS_A_FAILURE, (
        "%d FAIL findings report an exception's text as the finding, ceiling is %d. A "
        "failed read is not a misconfiguration — use _read_failed rather than raising "
        "this." % (count, MAX_EXCEPTION_TEXT_AS_A_FAILURE))


def test_the_ceiling_is_not_stale():
    """A bound left far from the real number stops being a ratchet."""
    count = 0
    for path in sorted(glob.glob(os.path.join(ROOT, "engine", "*.py"))):
        for n in ast.walk(ast.parse(io.open(path, encoding="utf-8").read())):
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "_add" and len(n.args) >= 5
                    and isinstance(n.args[0], ast.Constant)
                    and n.args[0].value == "FAIL"):
                msg = n.args[4]
                if (isinstance(msg, ast.Call) and isinstance(msg.func, ast.Name)
                        and msg.func.id == "str" and len(msg.args) == 1
                        and isinstance(msg.args[0], ast.Name)):
                    count += 1
    assert MAX_EXCEPTION_TEXT_AS_A_FAILURE - count <= 3, (
        "the ceiling (%d) is well above the actual (%d); lower it"
        % (MAX_EXCEPTION_TEXT_AS_A_FAILURE, count))


def test_the_six_corrected_severities_match_what_their_code_can_render():
    """Each of these had its declared severity reachable only through the error path.
    The code was right and the catalogue was not, so the catalogue moved."""
    for cid in ("BDR-04", "DDB-01", "EC2-05", "R53-02", "SNS-01", "SQS-03"):
        assert CHECK_SEVERITY[cid] == "LOW", (
            f"{cid} was lowered to LOW because its only non-error finding is a WARN; "
            f"raising it again requires giving the condition a FAIL path first")
