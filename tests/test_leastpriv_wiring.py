"""Slice 1 · Batch 8 — _least_priv_recommendation host helper (ACTION_LEVEL SLAD job ->
aws_leastpriv). Offline: a MagicMock iam client drives the async job. No boto3, no sleep."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_live_scanner as A

NOW = 1_000_000_000


def _principal(statements):
    return {"type": "role", "name": "app", "arn": "arn:aws:iam::111:role/app",
            "statements": statements}


def _iam(services, status="COMPLETED"):
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": status, "ServicesLastAccessed": services}
    return iam


def test_recommendation_from_completed_job():
    stmts = [{"effect": "Allow", "actions": {"s3:getobject", "sqs:sendmessage"}, "resources": {"*"}}]
    iam = _iam([{"ServiceNamespace": "s3", "LastAuthenticated": NOW - 5 * 86400}])
    rec = A._least_priv_recommendation(iam, _principal(stmts), NOW, sleep=lambda s: None)
    assert rec and rec["recommended"] and rec["delta"]["removed_services"] == ["sqs"]
    assert rec["policy"]["Version"] == "2012-10-17"


def test_denied_job_returns_none():
    iam = MagicMock()
    iam.generate_service_last_accessed_details.side_effect = RuntimeError("AccessDenied")
    assert A._least_priv_recommendation(iam, _principal([{"effect": "Allow",
        "actions": {"s3:*"}, "resources": {"*"}}]), NOW, sleep=lambda s: None) is None


def test_failed_job_returns_none_for_ciem00():
    # a FAILED (or timed-out) job is 'unavailable' -> None -> _run_ciem fires CIEM-00,
    # never a deny-all and never a silently-dropped reason (adversarial-verify regression).
    iam = _iam([], status="FAILED")
    rec = A._least_priv_recommendation(iam, _principal([{"effect": "Allow",
        "actions": {"s3:*"}, "resources": {"*"}}]), NOW, sleep=lambda s: None)
    assert rec is None


def test_no_statements_returns_none():
    assert A._least_priv_recommendation(_iam([]), _principal([]), NOW, sleep=lambda s: None) is None


def test_action_level_narrowing_end_to_end():
    stmts = [{"effect": "Allow", "actions": {"s3:*"}, "resources": {"*"}}]
    iam = _iam([{"ServiceNamespace": "s3", "LastAuthenticated": NOW - 1 * 86400,
                 "TrackedActionsLastAccessed": [
                     {"ActionName": "GetObject", "LastAccessedTime": NOW - 1 * 86400}]}])
    rec = A._least_priv_recommendation(iam, _principal(stmts), NOW, sleep=lambda s: None)
    assert rec["policy"]["Statement"][0]["Action"] == ["s3:getobject"]   # wildcard narrowed
