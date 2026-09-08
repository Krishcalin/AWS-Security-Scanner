"""Driving the first tranche of checks that no test had ever made emit anything.

WHY THIS FILE EXISTS. `docs/CHECK_FIRING.md` records that 103 of 458 registered
checks are never observed in the whole suite: registered in all four metadata maps,
counted in the published catalogue, carrying a severity and a written remediation,
and never once driven to a finding by any test. That is not proof they are broken —
most are simply untested — but it is where a genuinely dead check hides, and
`THREAT-02` proves at least one exists.

FOUR SECTIONS, ONE CLIENT EACH, chosen because they share a fixture shape: SNS, SQS,
Route53 and Glacier — 14 checks that had never emitted anything.

WHAT DRIVING THEM REVEALED, which is the part worth reading. Exactly half reach FAIL
on a genuinely bad configuration:

    SNS-02  wildcard access policy       SQS-01  unencrypted queue
    SNS-03  unencrypted HTTP subscriber  SQS-02  wildcard access policy
    R53-01  public zone, no query log    R53-05  resolver, no firewall or logging
    GLC-01  vault policy granting *

The other seven CANNOT reach FAIL through the condition they are named for. A topic
with no CMK is precisely what SNS-01 describes, and it emits WARN; a queue with no
dead-letter queue is precisely SQS-03, and it emits WARN. `_add` reads severity,
compliance and remediation from the catalogue ONLY for a FAIL — a WARN is forced to
severity LOW and carries no remediation — so for those seven the MEDIUM the catalogue
advertises is reachable only by making the AWS call throw. Their declared severity
describes an API error, not the security condition in their name.

That is seven of the 60 checks `docs/CHECK_FIRING.md` records as never having
rendered their declared severity, and it is RECORDED HERE, NOT FIXED: whether a
missing DLQ should be a MEDIUM finding or a LOW warning is a product decision, and
changing it would move real customers' severity counts.
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_live_scanner import make_scanner, MockClientError, MockPaginator

WILDCARD_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sns:Publish",
                   "Resource": "*"}],
})


def statuses(scanner, check_id):
    return {r.status for r in scanner.results if r.check_id == check_id}


def failed(scanner, check_id):
    return "FAIL" in statuses(scanner, check_id)


# ── SNS ─────────────────────────────────────────────────────────────────────

@pytest.fixture()
def sns_scanner():
    s = make_scanner(["SNS"])
    arn = "arn:aws:sns:us-east-1:123456789012:alerts"
    sns = MagicMock()
    sns.get_paginator.side_effect = lambda op: {
        "list_topics": MockPaginator("Topics", [{"TopicArn": arn}]),
        "list_subscriptions": MockPaginator("Subscriptions", [
            {"TopicArn": arn, "Protocol": "http",
             "Endpoint": "http://example.com/hook", "SubscriptionArn": "sub-1"}]),
    }[op]
    sns.get_topic_attributes.return_value = {
        "Attributes": {"Policy": WILDCARD_POLICY}}          # no KmsMasterKeyId
    sns.list_subscriptions_by_topic.return_value = {"Subscriptions": [
        {"Protocol": "http", "Endpoint": "http://example.com/hook",
         "SubscriptionArn": "sub-1"}]}
    s._clients["sns:us-east-1"] = sns
    return s


def test_sns_reaches_a_real_failure(sns_scanner):
    """A wildcard access policy and an unencrypted HTTP subscription are the ordinary
    shape of what SNS-02 and SNS-03 describe, and both reach FAIL on them."""
    sns_scanner._check_sns()
    for cid in ("SNS-02", "SNS-03"):
        assert failed(sns_scanner, cid), "%s did not reach FAIL: %s" % (
            cid, statuses(sns_scanner, cid))


def test_sns_01_and_04_emit_but_can_only_fail_on_an_api_error(sns_scanner):
    """RECORDED, NOT FIXED. A topic with no CMK is exactly what SNS-01 is named for,
    and it emits WARN \u2014 which `_add` forces to severity LOW and gives no
    remediation, so the MEDIUM the catalogue advertises for SNS-01 is reachable only
    by making get_topic_attributes throw. Same shape for SNS-04. They are two of the
    60 checks docs/CHECK_FIRING.md records as never having rendered their declared
    severity; whether that is the right design is a product call, not a test fix."""
    sns_scanner._check_sns()
    assert statuses(sns_scanner, "SNS-01") == {"WARN"}
    assert "FAIL" not in statuses(sns_scanner, "SNS-04")


# ── SQS ─────────────────────────────────────────────────────────────────────

@pytest.fixture()
def sqs_scanner():
    s = make_scanner(["SQS"])
    url = "https://sqs.us-east-1.amazonaws.com/123456789012/jobs"
    sqs = MagicMock()
    sqs.list_queues.return_value = {"QueueUrls": [url]}
    sqs.get_queue_attributes.return_value = {"Attributes": {
        "QueueArn": "arn:aws:sqs:us-east-1:123456789012:jobs",
        "Policy": WILDCARD_POLICY,          # wildcard principal
        # no KmsMasterKeyId and no SqsManagedSseEnabled -> unencrypted
        # no RedrivePolicy -> no dead-letter queue
    }}
    s._clients["sqs:us-east-1"] = sqs
    return s


def test_sqs_reaches_a_real_failure(sqs_scanner):
    """An unencrypted queue and a wildcard access policy."""
    sqs_scanner._check_sqs()
    for cid in ("SQS-01", "SQS-02"):
        assert failed(sqs_scanner, cid), "%s did not reach FAIL: %s" % (
            cid, statuses(sqs_scanner, cid))


def test_sqs_03_and_04_emit_but_can_only_fail_on_an_api_error(sqs_scanner):
    """A queue with no dead-letter queue is what SQS-03 is named for and produces
    WARN, so its declared MEDIUM is unreachable except through an exception."""
    sqs_scanner._check_sqs()
    assert "FAIL" not in statuses(sqs_scanner, "SQS-03")
    assert "FAIL" not in statuses(sqs_scanner, "SQS-04")


# ── Route53 ─────────────────────────────────────────────────────────────────

@pytest.fixture()
def r53_scanner():
    s = make_scanner(["ROUTE53"])
    r53 = MagicMock()
    r53.list_hosted_zones.return_value = {"HostedZones": [
        {"Id": "/hostedzone/Z1", "Name": "example.com.",
         "Config": {"PrivateZone": False}}]}
    r53.get_dnssec.return_value = {"Status": {"ServeSignature": "NOT_SIGNING"}}
    r53.list_query_logging_configs.return_value = {"QueryLoggingConfigs": []}
    r53.list_health_checks.return_value = {"HealthChecks": []}
    s._clients["route53:us-east-1"] = r53
    for extra in ("route53domains", "route53resolver"):
        c = MagicMock()
        c.list_domains.side_effect = MockClientError("AccessDenied")
        c.list_resolver_query_log_configs.return_value = {
            "ResolverQueryLogConfigs": []}
        s._clients["%s:us-east-1" % extra] = c
    return s


def test_route53_reaches_a_real_failure(r53_scanner):
    """A public zone with no query logging, and a resolver with neither DNS Firewall
    nor query logging."""
    r53_scanner._check_route53()
    for cid in ("R53-01", "R53-05"):
        assert failed(r53_scanner, cid), "%s did not reach FAIL: %s" % (
            cid, statuses(r53_scanner, cid))


def test_route53_02_to_04_emit_but_can_only_fail_on_an_api_error(r53_scanner):
    """DNSSEC not signing, no transfer lock and no health checks are each exactly
    what these checks are named for, and each produces WARN."""
    r53_scanner._check_route53()
    for cid in ("R53-02", "R53-03", "R53-04"):
        assert statuses(r53_scanner, cid), "%s emitted nothing at all" % cid
        assert "FAIL" not in statuses(r53_scanner, cid)


# ── Glacier ─────────────────────────────────────────────────────────────────

@pytest.fixture()
def glacier_scanner():
    s = make_scanner(["GLACIER"])
    gl = MagicMock()
    gl.list_vaults.return_value = {"VaultList": [
        {"VaultName": "archive", "VaultARN":
         "arn:aws:glacier:us-east-1:123456789012:vaults/archive"}]}
    gl.get_vault_access_policy.return_value = {"policy": {"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*",
                       "Action": "glacier:GetJobOutput", "Resource": "*"}]})}}
    # The Glacier section catches `glacier.exceptions.ResourceNotFoundException`,
    # a CLIENT-specific exception class. On a MagicMock that attribute is another
    # MagicMock, and `except <MagicMock>` raises TypeError before the handler runs —
    # so the fixture has to supply a real class, not just a raising side_effect.
    class ResourceNotFoundException(Exception):
        pass

    gl.exceptions.ResourceNotFoundException = ResourceNotFoundException
    gl.get_vault_lock.side_effect = ResourceNotFoundException()
    gl.get_vault_notifications.side_effect = ResourceNotFoundException()
    s._clients["glacier:us-east-1"] = gl
    return s


def test_glacier_vault_policy_reaches_a_failure(glacier_scanner):
    """GLC-01 fires on a vault access policy granting a wildcard principal."""
    glacier_scanner._check_glacier()
    assert failed(glacier_scanner, "GLC-01"), (
        "GLC-01 did not reach FAIL: %s" % statuses(glacier_scanner, "GLC-01"))
