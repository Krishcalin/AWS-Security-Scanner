"""Phase 1 · slice 1.3 — LLMjacking and AI control-tampering rules.

Golden CloudTrail sequences, one per rule, and — carrying equal weight — the negative
cases. A detection that fires during a Terraform apply is a detection an operator mutes
within a week, and a muted rule protects nothing. Every rule here has at least one test
proving it stays quiet when it should.

The severity join has its own section. It is the part no log-analytics vendor can copy,
because it needs the graph rather than the event stream, and it is the reason GuardDuty
rates its own AI findings Low while we do not.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_airules as R

T0 = datetime(2026, 8, 25, 12, 0, 0, tzinfo=timezone.utc)
KEY = "AKIAEXAMPLESTOLEN01"
ROLE = "arn:aws:iam::123456789012:role/SageMakerExecutionRole"


def ev(name, *, at=T0, key=KEY, arn=ROLE, region="us-east-1",
       agent="aws-cli/2.15.0", error=None, params=None, eid=None):
    e = {
        "eventName": name,
        "eventTime": at.isoformat(),
        "awsRegion": region,
        "sourceIPAddress": "203.0.113.7",
        "userAgent": agent,
        "userIdentity": {"arn": arn, "accessKeyId": key},
        "eventID": eid or f"{name}-{at.isoformat()}",
    }
    if error:
        e["errorCode"] = error
    if params is not None:
        e["requestParameters"] = params
    return e


def rules(dets):
    return {d.evidence.get("rule") for d in dets}


# ── LLMjacking ──────────────────────────────────────────────────────────────
def test_model_enumeration_followed_by_invocation_fires():
    dets = R.detect([
        ev("ListFoundationModels"),
        ev("InvokeModel", at=T0 + timedelta(minutes=4)),
    ])
    assert "llmjacking-recon-to-abuse" in rules(dets)


def test_enumeration_long_before_invocation_does_not_fire():
    """Enumerating models is ordinary. Only the tight sequence is a signal."""
    dets = R.detect([
        ev("ListFoundationModels"),
        ev("InvokeModel", at=T0 + timedelta(hours=6)),
    ])
    assert "llmjacking-recon-to-abuse" not in rules(dets)


def test_invocation_with_no_prior_enumeration_does_not_fire():
    assert "llmjacking-recon-to-abuse" not in rules(R.detect([ev("InvokeModel")]))


def test_a_validation_probe_then_a_success_fires():
    """An invalid-parameter call confirms a live key WITHOUT producing AccessDenied,
    which is what most alerting watches for."""
    dets = R.detect([
        ev("InvokeModel", error="ValidationException"),
        ev("InvokeModel", at=T0 + timedelta(minutes=2)),
    ])
    assert "llmjacking-validation-probe" in rules(dets)


def test_a_validation_error_alone_does_not_fire():
    """Developers send malformed requests constantly. Only probe-then-succeed counts."""
    dets = R.detect([ev("InvokeModel", error="ValidationException")])
    assert "llmjacking-validation-probe" not in rules(dets)


def test_a_generic_http_client_invoking_bedrock_fires():
    dets = R.detect([ev("InvokeModel", agent="python-aiohttp/3.9.1")])
    assert "llmjacking-proxy-client" in rules(dets)


@pytest.mark.parametrize("agent", ["aws-cli/2.15.0", "Boto3/1.34.0 md/Botocore#1.34",
                                   "console.amazonaws.com", "aws-sdk-go/1.50"])
def test_the_real_sdks_and_console_do_not_fire(agent):
    assert "llmjacking-proxy-client" not in rules(R.detect([ev("InvokeModel", agent=agent)]))


def test_one_key_across_three_regions_in_an_hour_fires():
    dets = R.detect([
        ev("InvokeModel", region="us-east-1"),
        ev("InvokeModel", at=T0 + timedelta(minutes=10), region="eu-west-1"),
        ev("InvokeModel", at=T0 + timedelta(minutes=20), region="ap-southeast-1"),
    ])
    assert "llmjacking-quota-dodging" in rules(dets)
    det = next(d for d in dets if d.evidence.get("rule") == "llmjacking-quota-dodging")
    assert len(det.evidence["regions"]) == 3


def test_two_regions_does_not_fire():
    """Multi-region is normal. Three inside an hour on one key is quota-spreading."""
    dets = R.detect([
        ev("InvokeModel", region="us-east-1"),
        ev("InvokeModel", at=T0 + timedelta(minutes=5), region="eu-west-1"),
    ])
    assert "llmjacking-quota-dodging" not in rules(dets)


def test_three_regions_spread_over_a_day_does_not_fire():
    dets = R.detect([
        ev("InvokeModel", region="us-east-1"),
        ev("InvokeModel", at=T0 + timedelta(hours=8), region="eu-west-1"),
        ev("InvokeModel", at=T0 + timedelta(hours=16), region="ap-southeast-1"),
    ])
    assert "llmjacking-quota-dodging" not in rules(dets)


# ── control tampering ───────────────────────────────────────────────────────
def test_deleting_a_guardrail_fires_critical():
    dets = R.detect([ev("DeleteGuardrail")])
    det = next(d for d in dets if d.evidence["rule"] == "ai-guardrail-deleted")
    assert det.severity >= 9.0 and det.band == "Critical"


def test_a_terraform_apply_deleting_a_guardrail_does_not_fire():
    """THE NEGATIVE CASE THAT MATTERS. IaC churns resources constantly; a rule that
    fires on every apply is a rule an operator mutes, and a muted rule protects
    nothing."""
    for agent in ("APN/1.0 HashiCorp/1.0 Terraform/1.9.5",
                  "cloudformation.amazonaws.com", "aws-cdk/2.150.0"):
        assert not rules(R.detect([ev("DeleteGuardrail", agent=agent)]))


def test_a_denied_delete_is_not_a_tamper():
    """An attempt that AWS refused did not change anything."""
    assert not rules(R.detect([ev("DeleteGuardrail", error="AccessDeniedException")]))


def test_weakening_a_guardrail_fires_but_a_neutral_update_does_not():
    weak = R.detect([ev("UpdateGuardrail", params={
        "contentPolicyConfig": {"filtersConfig": [{"type": "PROMPT_ATTACK",
                                                   "inputStrength": "NONE"}]}})])
    assert "ai-guardrail-weakened" in rules(weak)

    rename = R.detect([ev("UpdateGuardrail", params={"name": "prod-guardrail-v2"})])
    assert "ai-guardrail-weakened" not in rules(rename)


def test_disabling_invocation_logging_fires_critical():
    dets = R.detect([ev("DeleteModelInvocationLoggingConfiguration")])
    det = next(d for d in dets if d.evidence["rule"] == "ai-logging-disabled")
    assert det.severity >= 9.0


def test_reading_the_logging_config_before_changing_it_raises_severity():
    """An attacker checking whether they will be recorded, then changing where the
    record goes. The read is what makes the write deliberate."""
    quiet = R.detect([ev("PutModelInvocationLoggingConfiguration")])
    loud = R.detect([
        ev("GetModelInvocationLoggingConfiguration"),
        ev("PutModelInvocationLoggingConfiguration", at=T0 + timedelta(minutes=3)),
    ])
    q = next(d for d in quiet if d.evidence["rule"] == "ai-logging-redirected")
    l = next(d for d in loud if d.evidence["rule"] == "ai-logging-redirected")
    assert l.severity > q.severity
    assert l.evidence.get("preceded_by_config_read") is True


def test_a_lambda_deploy_outside_the_action_group_allowlist_does_not_fire():
    """Without an allowlist the rule would fire on every Lambda deploy in the account."""
    allow = {"bedrock-agent-tool"}
    assert "ai-agent-lambda-changed" not in rules(R.detect(
        [ev("UpdateFunctionCode", params={"functionName": "unrelated-etl"})],
        lambda_allowlist=allow))
    assert "ai-agent-lambda-changed" in rules(R.detect(
        [ev("UpdateFunctionCode", params={"functionName": "bedrock-agent-tool"})],
        lambda_allowlist=allow))


def test_with_no_allowlist_the_lambda_rule_stays_silent():
    assert "ai-agent-lambda-changed" not in rules(
        R.detect([ev("UpdateFunctionCode", params={"functionName": "anything"})]))


# ── the severity join ───────────────────────────────────────────────────────
def test_reach_raises_severity_and_says_why():
    """The part that cannot be computed from the log. GuardDuty rates its AI findings
    Low because it does not know what the identity reaches."""
    dets = R.detect([ev("InvokeModel", agent="axios/1.6.0")])
    joined = R.rerank(dets, reach=lambda arn: {
        "privesc": "grants iam:passrole on an unscoped (*) resource",
        "crown": "prod-payments-pii"})
    d = joined[0]
    assert d.severity > dets[0].severity
    assert "escalate privilege" in d.title and "crown-jewel data" in d.title
    assert d.evidence["severity_before_join"] == dets[0].severity


def test_an_identity_that_reaches_nothing_is_left_alone():
    dets = R.detect([ev("InvokeModel", agent="axios/1.6.0")])
    same = R.rerank(dets, reach=lambda arn: {"privesc": None, "crown": None})
    assert same[0].severity == dets[0].severity
    assert same[0].title == dets[0].title


def test_an_unresolvable_identity_is_not_escalated():
    """An unknown blast radius is not a large one."""
    dets = R.detect([ev("InvokeModel", agent="axios/1.6.0")])

    def explode(_arn):
        raise RuntimeError("graph unavailable")

    assert R.rerank(dets, reach=explode)[0].severity == dets[0].severity


def test_severity_is_capped_at_ten():
    dets = R.detect([ev("DeleteGuardrail")])
    joined = R.rerank(dets, reach=lambda a: {"privesc": "admin", "crown": "pii"})
    assert joined[0].severity <= 10.0


# ── shape and charter ───────────────────────────────────────────────────────
def test_the_module_is_boto3_free():
    src = open(R.__file__, encoding="utf-8").read()
    assert "import boto3" not in src and "boto3." not in src


def test_every_detection_names_the_acting_principal():
    """A detection that resolves to cdr:unmapped is a detection nobody can action."""
    dets = R.detect([ev("DeleteGuardrail"), ev("InvokeModel", agent="axios/1.0")])
    for d in dets:
        assert d.resource_arn == ROLE
        assert d.node_kind == "IAMPrincipal"


def test_no_detection_carries_prompt_or_completion_content():
    """Management events do not contain prompts, and this module must never start
    reading them if a future event shape does. Section F of the zero-telemetry
    tripwire enforces the same thing statically."""
    dets = R.detect([ev("InvokeModel", agent="axios/1.0",
                        params={"prompt": "SHOULD NEVER APPEAR",
                                "body": "SHOULD NEVER APPEAR"})])
    blob = str([d.evidence for d in dets])
    assert "SHOULD NEVER APPEAR" not in blob


def test_detections_are_ranked_most_severe_first():
    dets = R.detect([ev("UpdateAgent"), ev("DeleteGuardrail")])
    assert [d.severity for d in dets] == sorted((d.severity for d in dets), reverse=True)


def test_empty_and_malformed_input_are_safe():
    assert R.detect([]) == []
    assert R.detect(None) == []
    assert R.detect([{}, {"eventName": None}]) == []
