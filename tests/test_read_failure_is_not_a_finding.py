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

There were 32 sites in all: those ten, and 22 more in checks that also had real FAIL
paths — five of them CRITICAL, so a throttled `DescribeTrails` produced a CRITICAL
"LOG-01: <boto error text>". All 32 now go through `_read_failed`.

HOW IT SURVIVED. Nothing asserted it. Removing the whole shape broke exactly one test,
and that test was asserting the defect. It is the same reason `docs/CHECK_FIRING.md` had
to be built: a check that only ever emits the wrong thing looks identical, from the
suite, to one nobody wrote a test for.

TWO FALSE PROOFS FELL OUT OF IT. `EC2-05` and then `VPC-01` left CHECK_FIRING's
proven-failing set when their error paths stopped being FAILs — both had been certified
by a test that made the AWS call throw. VPC-01 is the product's most recognisable check
(a security group opening SSH to the world) and had a perfectly good detection path that
nothing had ever driven. It is driven at the bottom of this file.

ABSENCE IS NOT REFUSAL. Three sites signalled both by raising and reported the first for
both: `S3-01` ("No BPA config"), `S3-03` ("No default encryption") and `LOG-05`
("Security Hub not enabled in this region"). Each asserted a fact about the account that
had never been established — the S3-07 defect, in three more places. All three now split
on the error code.

WHAT THIS FILE PINS. The conditions that earned a real FAIL, the replacement helper's
behaviour, the three absence/refusal splits, the retry policy every client is built
with, and the tripwires that stop the shape returning.
"""
from __future__ import annotations

import ast
import glob
import io
import json
import os
import sys
from unittest.mock import MagicMock, patch

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
#: Each produced, on a denied or throttled read, a FAIL carrying that check's
#: remediation: advice for a problem nobody observed. There were 32 — ten whose ONLY
#: FAIL had this shape (fixed first, see `_read_failed`) and 22 more that also had real
#: FAIL paths, five of them CRITICAL. All 32 are converted, so the floor is now zero and
#: this ratchet is at its end state: the shape must never reappear.
MAX_EXCEPTION_TEXT_AS_A_FAILURE = 0


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


# ══════════════════════════════════════════════════════════════════════════════
# Absence and refusal are different answers
#
# Three call sites signalled both by raising, and reported the first for both. Each
# stated a fact about the account that had never been established — the S3-07 defect
# the bucket-B pass fixed, in three more places.
# ══════════════════════════════════════════════════════════════════════════════
class _Coded(Exception):
    def __init__(self, code, msg="x"):
        self.response = {"Error": {"Code": code, "Message": msg}}
        super().__init__(f"{code}: {msg}")


def _s3(bpa_error=None, enc_error=None):
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "b1"}]}
    s3.get_bucket_location.return_value = {"LocationConstraint": None}
    if bpa_error:
        s3.get_public_access_block.side_effect = bpa_error
    else:
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}
    if enc_error:
        s3.get_bucket_encryption.side_effect = enc_error
    else:
        s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {"Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}
    s3.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "logs"}}
    s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
    s3.get_bucket_policy.side_effect = _Coded("NoSuchBucketPolicy")
    s3.get_bucket_acl.return_value = {"Grants": []}
    s3.get_bucket_tagging.side_effect = _Coded("NoSuchTagSet")
    s3.get_bucket_lifecycle_configuration.side_effect = _Coded(
        "NoSuchLifecycleConfiguration")
    return _scanner("S3", "s3", s3)


def test_s3_01_genuinely_absent_bpa_still_fails():
    """NoSuchPublicAccessBlockConfiguration is the bucket telling us it has none. That
    is a real finding and must stay one."""
    s = _s3(bpa_error=_Coded("NoSuchPublicAccessBlockConfiguration"))
    s._check_s3()
    hits = _ids(s, "S3-01", "FAIL")
    assert hits and "No BPA config" in hits[0].message


def test_s3_01_denied_bpa_read_is_not_reported_as_absent():
    """A bucket owned by another account routinely refuses this read. Saying 'No BPA
    config' asserts something about that bucket we were never told."""
    s = _s3(bpa_error=_Coded("AccessDenied"))
    s._check_s3()
    assert not _ids(s, "S3-01", "FAIL")
    warns = _ids(s, "S3-01", "WARN")
    assert warns and "NOT EVALUATED" in warns[0].message


def test_s3_03_genuinely_absent_encryption_still_fails():
    """S3 has no other way to say 'no default encryption' than to raise, so here the
    exception IS the detection — which is why S3-03 is the one exemption in the
    structural tripwire below."""
    s = _s3(enc_error=_Coded("ServerSideEncryptionConfigurationNotFoundError"))
    s._check_s3()
    hits = _ids(s, "S3-03", "FAIL")
    assert hits and "No default encryption" in hits[0].message


def test_s3_03_denied_encryption_read_is_not_reported_as_unencrypted():
    s = _s3(enc_error=_Coded("AccessDenied"))
    s._check_s3()
    assert not _ids(s, "S3-03", "FAIL")
    assert _ids(s, "S3-03", "WARN")


def _securityhub(error):
    sh = MagicMock()
    sh.get_enabled_standards.side_effect = error
    s = make_scanner(sections=["LOGGING"])
    s.account = OWN
    s._clients[f"securityhub:{REGION}"] = sh
    for svc in ("cloudtrail", "config", "guardduty", "logs", "accessanalyzer",
                "iam", "s3", "ec2", "sns"):
        s._clients[f"{svc}:{REGION}"] = MagicMock()
    return s


def test_log_05_not_subscribed_still_fails():
    """InvalidAccessException means Security Hub genuinely is not enabled here."""
    s = _securityhub(_Coded("InvalidAccessException"))
    s._check_logging()
    hits = _ids(s, "LOG-05", "FAIL")
    assert hits and any("not enabled in this region" in h.message for h in hits)


def test_log_05_denied_read_is_not_reported_as_not_subscribed():
    """AccessDenied and 'not subscribed' were treated as the same finding. They are
    opposites: one says the control is missing, the other says we cannot tell."""
    s = _securityhub(_Coded("AccessDeniedException"))
    s._check_logging()
    assert not any("not enabled in this region" in r.message
                   for r in _ids(s, "LOG-05", "FAIL"))
    warns = _ids(s, "LOG-05", "WARN")
    assert warns and "NOT EVALUATED" in warns[0].message


# ══════════════════════════════════════════════════════════════════════════════
# Every client is built with a retry and identification policy
# ══════════════════════════════════════════════════════════════════════════════
class _FakeBotoConfig:
    """Stand-in for botocore.config.Config.

    BOTO3 IS NOT INSTALLED IN THE TEST ENVIRONMENT, so `HAS_BOTO3` is False, `boto3` and
    `BotoConfig` are not module attributes at all, and `_client` has never been executed
    by any of the ~6000 tests — every AWS client in the suite is a MagicMock injected
    straight into `_clients`. That is why nothing caught the missing retry policy, and it
    is worth stating rather than working around silently: these tests exercise the
    factory by supplying the two names the real import would have bound."""

    def __init__(self, **kw):
        self.retries = kw.get("retries")
        self.user_agent_extra = kw.get("user_agent_extra")


def _capture_client_kwargs(via_session: bool):
    import engine.aws_live_scanner as A
    captured = {}

    def _client(service, region_name=None, config=None):
        captured.update(service=service, region_name=region_name, config=config)
        return MagicMock()

    factory = MagicMock(client=_client)
    with patch.object(A, "HAS_BOTO3", True), \
            patch.object(A, "BotoConfig", _FakeBotoConfig, create=True), \
            patch.object(A, "boto3", factory, create=True):
        s = A.AWSLiveScanner(region="eu-west-1", sections=["IAM"])
        s._session = factory if via_session else None
        s._client("ec2")
    return captured


def test_clients_are_built_with_adaptive_retries_and_a_named_user_agent():
    """94 sections, each enumerating a service, times every region under --all-regions.
    botocore's default `legacy` retry mode is sized for an application making a handful
    of calls, and the account most likely to throttle is the large one whose posture
    matters most — and, until the rest of this file's change, the one most likely to be
    handed fabricated findings when it did."""
    cfg = _capture_client_kwargs(via_session=False)["config"]
    assert cfg is not None, "clients are still built with botocore's defaults"
    assert cfg.retries["mode"] == "adaptive", (
        "adaptive adds the client-side rate limiter that slows down BEFORE being "
        "throttled; raising max_attempts alone just spends the budget faster")
    assert cfg.retries["max_attempts"] >= 10
    assert "OverWatch/" in (cfg.user_agent_extra or ""), (
        "an operator reviewing their own CloudTrail has to be able to tell our reads "
        "from anything else using the same role")


def test_the_config_reaches_the_assumed_role_session_too():
    """Ambient credentials and an assumed-role session go through the same factory, so a
    config attached to only one would be a per-deployment difference nobody notices
    until a multi-account scan throttles."""
    cfg = _capture_client_kwargs(via_session=True)["config"]
    assert cfg is not None and cfg.retries["mode"] == "adaptive"


def test_the_region_is_still_passed():
    """The config argument is new; the argument that was already load-bearing must not
    have been displaced by it."""
    got = _capture_client_kwargs(via_session=False)
    assert got["service"] == "ec2" and got["region_name"] == "eu-west-1"


# ══════════════════════════════════════════════════════════════════════════════
# VPC-01 — the false proof this change exposed
#
# Removing the error-path FAIL took VPC-01 OUT of docs/CHECK_FIRING.md's proven set.
# It had a perfectly good detection path -- a security group opening a risky port to
# 0.0.0.0/0 -- and nothing had ever driven it. What certified the product's single most
# recognisable check was a test that made DescribeSecurityGroups throw.
# ══════════════════════════════════════════════════════════════════════════════
def _vpc(security_groups):
    ec2 = MagicMock()

    def _pager(op):
        p = MagicMock()
        p.paginate.return_value = [{"SecurityGroups": list(security_groups)}]
        return p

    ec2.get_paginator.side_effect = _pager
    ec2.describe_vpcs.return_value = {"Vpcs": []}
    ec2.describe_flow_logs.return_value = {"FlowLogs": []}
    return _scanner("VPC", "ec2", ec2)


def _sg(gid, from_port, to_port, cidr="0.0.0.0/0", name="app", ipv6=False):
    perm = {"FromPort": from_port, "ToPort": to_port, "IpProtocol": "tcp",
            "IpRanges": [] if ipv6 else [{"CidrIp": cidr}],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}] if ipv6 else []}
    return {"GroupId": gid, "GroupName": name, "VpcId": "vpc-1",
            "IpPermissions": [perm], "IpPermissionsEgress": []}


def test_vpc01_ssh_open_to_the_world_fails():
    s = _vpc([_sg("sg-1", 22, 22)])
    s._check_vpc()
    _renders(s, "VPC-01", "HIGH", contains="port 22/SSH")


def test_vpc01_a_port_range_that_swallows_a_risky_port_fails():
    """0-65535 names no risky port explicitly and exposes all of them, which is the
    version an operator is most likely to have opened 'temporarily'."""
    s = _vpc([_sg("sg-1", 0, 65535)])
    s._check_vpc()
    hits = _ids(s, "VPC-01", "FAIL")
    assert len(hits) >= 5, "a range covering every risky port should name each"
    assert any("3389/RDP" in h.message for h in hits)


def test_vpc01_ipv6_only_exposure_fails():
    """::/0 is the half people forget, and the check has always covered it."""
    s = _vpc([_sg("sg-1", 3306, 3306, ipv6=True)])
    s._check_vpc()
    _renders(s, "VPC-01", "HIGH", contains="::/0")


def test_vpc01_a_scoped_cidr_is_silent():
    s = _vpc([_sg("sg-1", 22, 22, cidr="10.0.0.0/8")])
    s._check_vpc()
    assert not _ids(s, "VPC-01", "FAIL") and _ids(s, "VPC-01", "PASS")


def test_vpc01_a_world_open_non_risky_port_is_silent():
    """443 open to the world is what a load balancer looks like. VPC-01 is deliberately
    a risky-port check, not a public-port check."""
    s = _vpc([_sg("sg-1", 443, 443)])
    s._check_vpc()
    assert not _ids(s, "VPC-01", "FAIL") and _ids(s, "VPC-01", "PASS")
