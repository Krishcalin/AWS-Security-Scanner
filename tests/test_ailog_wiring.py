"""Phase 4 · slice 4.3 — the scanner surface for AI logging depth.

The slice completes advice OverWatch already gives. `BDR-01` says turn model invocation
logging on and names the destination; this asks whether that destination is safe, because
with `textDataDeliveryEnabled` it receives every prompt and every completion in the
account. `LOG-08` says a trail records data events; this asks whether any of them is
`AWS::Bedrock::Model`, without which no one can say who invoked which model.

Four behaviours are load-bearing:

**Silence where the question was not asked.** A CloudWatch destination gets no `AILOG-01`
at all — a log group has no public-access concept, and a PASS would be a clean answer to
a question nobody asked.

**A refused read is never a clean bill.** A prompt-log bucket owned by another account
can't be assessed from here, which is a coverage fact, not a pass and not a failure.

**No AgentCore, no AgentCore finding.** Telling an operator they lack logs for a service
they do not run is noise, and noise is how a category gets ignored.

**Metrics-shaped logging is still reported.** An operator who believes they have an audit
trail of prompts should learn that they do not.
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_ailog as AL
import aws_perm_ledger as L
from aws_live_scanner import AWSLiveScanner

ACCT = "123456789012"


def _scanner(clients):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["AI_LOGGING"])
        s.account = ACCT
    s._client = lambda svc, region=None: clients.get(svc, MagicMock())
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _bedrock(text=True, s3=None, cw=None, large=None):
    c = MagicMock()
    cfg = {"textDataDeliveryEnabled": text, "imageDataDeliveryEnabled": False,
           "embeddingDataDeliveryEnabled": not text, "videoDataDeliveryEnabled": False}
    if s3:
        cfg["s3Config"] = {"bucketName": s3}
    if cw or large:
        cfg["cloudWatchConfig"] = {"logGroupName": cw or "/aws/bedrock"}
        if large:
            cfg["cloudWatchConfig"]["largeDataDeliveryS3Config"] = {"bucketName": large}
    c.get_model_invocation_logging_configuration.return_value = {"loggingConfig": cfg}
    return c


def _s3(blocked=True, policy=None, cmk=True):
    c = MagicMock()
    c.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": blocked, "IgnorePublicAcls": blocked,
            "BlockPublicPolicy": blocked, "RestrictPublicBuckets": blocked}}
    if policy is None:
        c.get_bucket_policy.side_effect = Exception("NoSuchBucketPolicy")
    else:
        c.get_bucket_policy.return_value = {"Policy": policy}
    c.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {
        "Rules": [{"ApplyServerSideEncryptionByDefault":
                   {"KMSMasterKeyID": "arn:aws:kms:::key/k"} if cmk else
                   {"SSEAlgorithm": "AES256"}}]}}
    return c


def _logs(group="/aws/bedrock", cmk=True, retention=90):
    c = MagicMock()
    lg = {"logGroupName": group}
    if cmk:
        lg["kmsKeyId"] = "arn:aws:kms:::key/k"
    if retention:
        lg["retentionInDays"] = retention
    c.describe_log_groups.return_value = {"logGroups": [lg]}
    return c


# ── the prompt-log destination ──────────────────────────────────────────────
def test_a_public_prompt_log_bucket_is_critical():
    pol = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*",
                                     "Action": "s3:GetObject",
                                     "Resource": "arn:aws:s3:::prompt-logs/*"}]})
    s = _scanner({"bedrock": _bedrock(s3="prompt-logs"),
                  "s3": _s3(blocked=False, policy=pol)})
    s._check_prompt_log_destinations()
    f = _ids(s, "AILOG-01", "FAIL")
    assert len(f) == 1 and f[0].severity == "CRITICAL"
    assert "every prompt users sent" in f[0].message


def test_a_blocked_prompt_log_bucket_passes():
    s = _scanner({"bedrock": _bedrock(s3="prompt-logs"), "s3": _s3(blocked=True)})
    s._check_prompt_log_destinations()
    assert _ids(s, "AILOG-01", "PASS") and not _ids(s, "AILOG-01", "FAIL")


def test_a_bucket_in_another_account_is_a_coverage_note_not_a_verdict():
    """Same discipline as LOG-09: a centralized-logging bucket cannot be assessed from
    here, and guessing either way would be wrong."""
    s3 = _s3()
    s3.get_public_access_block.side_effect = Exception("AccessDeniedException")
    s = _scanner({"bedrock": _bedrock(s3="prompt-logs"), "s3": s3})
    with patch.object(s, "_is_access_denied", return_value=True):
        s._check_prompt_log_destinations()
    assert not _ids(s, "AILOG-01", "FAIL") and not _ids(s, "AILOG-01", "PASS")
    assert "AILOG-01" in s._coverage.not_evaluated


def test_the_large_payload_overflow_bucket_is_assessed_too():
    """It receives the biggest prompts — the pasted documents — and is the destination
    operators forget they configured."""
    s = _scanner({"bedrock": _bedrock(cw="/aws/bedrock", large="overflow"),
                  "s3": _s3(blocked=True), "logs": _logs()})
    s._check_prompt_log_destinations()
    assert any("overflow" in r.resource for r in _ids(s, "AILOG-01"))


def test_an_unencrypted_bucket_raises_the_custody_finding():
    s = _scanner({"bedrock": _bedrock(s3="prompt-logs"),
                  "s3": _s3(blocked=True, cmk=False)})
    s._check_prompt_log_destinations()
    f = _ids(s, "AILOG-02", "FAIL")
    assert f and "no key you can disable" in f[0].message


# ── the CloudWatch destination ──────────────────────────────────────────────
def test_a_log_group_gets_no_public_access_finding():
    """A log group has no public-access concept. A PASS would be a clean answer to a
    question nobody asked."""
    s = _scanner({"bedrock": _bedrock(cw="/aws/bedrock"), "logs": _logs()})
    s._check_prompt_log_destinations()
    assert not _ids(s, "AILOG-01")


def test_an_unretained_log_group_raises_ailog03():
    s = _scanner({"bedrock": _bedrock(cw="/aws/bedrock"),
                  "logs": _logs(retention=None)})
    s._check_prompt_log_destinations()
    f = _ids(s, "AILOG-03", "FAIL")
    assert f and "growing liability" in f[0].message


def test_a_retained_log_group_passes():
    s = _scanner({"bedrock": _bedrock(cw="/aws/bedrock"), "logs": _logs(retention=30)})
    s._check_prompt_log_destinations()
    assert _ids(s, "AILOG-03", "PASS")


def test_a_configured_but_absent_log_group_is_reported():
    """Bedrock names a group that does not exist here — logging may be silently
    failing, which is worse than logging being off because the operator believes it is
    working."""
    logs = _logs()
    logs.describe_log_groups.return_value = {"logGroups": []}
    s = _scanner({"bedrock": _bedrock(cw="/aws/bedrock"), "logs": logs})
    s._check_prompt_log_destinations()
    assert any("silently failing" in r.message for r in _ids(s, "AILOG-00"))


# ── metrics-shaped logging ──────────────────────────────────────────────────
def test_logging_without_payloads_is_reported_not_ignored():
    """An operator who believes they have an audit trail of prompts should learn they
    do not."""
    s = _scanner({"bedrock": _bedrock(text=False, s3="metrics")})
    s._check_prompt_log_destinations()
    info = _ids(s, "AILOG-00", "INFO")
    assert any("no record of what was actually asked" in r.message for r in info)
    assert not _ids(s, "AILOG-01")


def test_the_summary_says_contents_were_not_read():
    s = _scanner({"bedrock": _bedrock(s3="prompt-logs"), "s3": _s3()})
    s._check_prompt_log_destinations()
    assert any("never the logs" in r.message for r in _ids(s, "AILOG-00"))


# ── data event coverage ─────────────────────────────────────────────────────
def _ct(types=(), trails=("t1",)):
    c = MagicMock()
    c.describe_trails.return_value = {"trailList": [
        {"Name": n, "TrailARN": f"arn:aws:cloudtrail:::trail/{n}"} for n in trails]}
    c.get_event_selectors.return_value = {"AdvancedEventSelectors": [
        {"Name": "ai", "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]},
            {"Field": "resources.type", "Equals": list(types)}]}]}
    return c


def test_no_model_data_events_raises_ailog04():
    s = _scanner({"cloudtrail": _ct(types=["AWS::S3::Object"])})
    s._check_ai_data_events()
    f = _ids(s, "AILOG-04", "FAIL")
    assert f and "no record of who invoked which model" in f[0].message
    assert "ADVANCED selector" in f[0].message


def test_model_data_events_pass():
    s = _scanner({"cloudtrail": _ct(types=["AWS::Bedrock::Model"])})
    s._check_ai_data_events()
    assert _ids(s, "AILOG-04", "PASS")


def test_partial_bedrock_coverage_warns_rather_than_fails():
    s = _scanner({"cloudtrail": _ct(types=["AWS::Bedrock::Model"])})
    s._check_ai_data_events()
    w = _ids(s, "AILOG-05", "WARN")
    assert w and "AWS::Bedrock::KnowledgeBase" in w[0].message


def test_no_ai_coverage_at_all_reports_once_not_three_times():
    """AILOG-04 is the finding. Repeating it as AILOG-05 and AILOG-06 is noise rather
    than depth."""
    s = _scanner({"cloudtrail": _ct(types=["AWS::S3::Object"])})
    s._check_ai_data_events()
    assert _ids(s, "AILOG-04", "FAIL")
    assert not _ids(s, "AILOG-05") and not _ids(s, "AILOG-06")


def test_agentcore_gaps_are_silent_without_an_agentcore_estate():
    """Telling an operator they lack logs for a service they do not run is noise."""
    s = _scanner({"cloudtrail": _ct(types=["AWS::Bedrock::Model"])})
    s._aispm_resources = [{"kind": "BedrockAgent"}]
    s._check_ai_data_events()
    assert not _ids(s, "AILOG-06")


def test_agentcore_gaps_are_reported_when_the_estate_exists():
    s = _scanner({"cloudtrail": _ct(types=["AWS::Bedrock::Model"])})
    s._aispm_resources = [{"kind": "AgentCoreRuntime", "name": "r1"}]
    s._check_ai_data_events()
    w = _ids(s, "AILOG-06", "WARN")
    assert w and "prompt injection" in w[0].message


def test_coverage_is_a_union_so_a_second_trail_satisfies_it():
    ct = _ct(trails=("mgmt", "ai"))
    calls = {"n": 0}

    def _sel(TrailName):
        calls["n"] += 1
        types = ["AWS::S3::Object"] if calls["n"] == 1 else ["AWS::Bedrock::Model"]
        return {"AdvancedEventSelectors": [{"Name": "x", "FieldSelectors": [
            {"Field": "resources.type", "Equals": types}]}]}

    ct.get_event_selectors.side_effect = _sel
    s = _scanner({"cloudtrail": ct})
    s._check_ai_data_events()
    assert _ids(s, "AILOG-04", "PASS")


def test_unreadable_selectors_are_a_coverage_note_not_a_pass():
    ct = _ct()
    ct.get_event_selectors.side_effect = Exception("AccessDeniedException")
    s = _scanner({"cloudtrail": ct})
    with patch.object(s, "_is_access_denied", return_value=True):
        s._check_ai_data_events()
    assert "AILOG-04" in s._coverage.not_evaluated
    assert not _ids(s, "AILOG-04", "PASS")


# ── the ledger ──────────────────────────────────────────────────────────────
def test_the_event_selector_action_is_now_in_the_ledger():
    """The scanner has called GetEventSelectors for LOG-08 since before this slice, and
    it was never in the ledger — so declining it silently cost a check nobody was told
    about. That is the gap the ledger exists to close."""
    actions = {r.action for reqs in L.REQUIREMENTS.values() for r in reqs}
    assert "cloudtrail:GetEventSelectors" in actions


def test_every_ailog_check_is_in_the_ledger():
    import aws_live_scanner as A
    ail = {c for c in A.CHECK_SEVERITY if c.startswith("AILOG-")}
    assert ail <= set(L.REQUIREMENTS), ail - set(L.REQUIREMENTS)
