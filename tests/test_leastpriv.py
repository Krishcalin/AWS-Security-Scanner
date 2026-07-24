"""Slice 1 · Batch 7 — pure least-privilege policy generator (aws_leastpriv). No boto3."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_leastpriv as L


def _allow(*actions, resources=("*",)):
    return {"effect": "Allow", "actions": set(actions), "resources": set(resources)}


def test_service_of():
    assert L.service_of("s3:GetObject") == "s3" and L.service_of("*") == "*"


def test_drops_never_used_service():
    stmts = [_allow("s3:getobject", "dynamodb:getitem", "sqs:sendmessage")]
    pol, delta = L.rightsize_policy(stmts, used_services={"s3", "dynamodb"})
    acts = pol["Statement"][0]["Action"]
    assert "s3:getobject" in acts and "dynamodb:getitem" in acts
    assert "sqs:sendmessage" not in acts               # sqs never used -> dropped
    assert delta["removed_services"] == ["sqs"]
    assert delta["surface_reduction_pct"] > 0


def test_narrows_wildcard_when_action_usage_known():
    stmts = [_allow("s3:*")]
    pol, delta = L.rightsize_policy(stmts, {"s3"}, used_actions={"s3": {"s3:getobject", "s3:listbucket"}})
    assert set(pol["Statement"][0]["Action"]) == {"s3:getobject", "s3:listbucket"}
    assert delta["narrowed_services"] == ["s3"]


def test_keeps_wildcard_when_only_service_level_usage():
    stmts = [_allow("s3:*")]
    pol, _ = L.rightsize_policy(stmts, {"s3"}, used_actions={})   # no action-level data
    assert pol["Statement"][0]["Action"] == ["s3:*"]              # not over-narrowed


def test_admin_star_narrowed_to_used_services():
    pol, delta = L.rightsize_policy([_allow("*")], {"s3", "kms"})
    assert set(pol["Statement"][0]["Action"]) == {"s3:*", "kms:*"}
    assert delta["admin_narrowed"] is True


def test_empty_usage_never_deny_all():
    rec = L.recommendation([_allow("s3:*")], used_services=set())
    assert rec["recommended"] is False and "policy" not in rec


def test_incomplete_slad_not_recommended():
    rec = L.recommendation([_allow("s3:getobject")], {"s3"}, slad_complete=False)
    assert rec["recommended"] is False


def test_recommendation_carries_policy_and_honesty_note():
    rec = L.recommendation([_allow("s3:getobject", "sqs:sendmessage")], {"s3"}, window_days=90)
    assert rec["recommended"] and rec["auto_apply"] is False
    assert "90" in rec["note"] and rec["delta"]["removed_services"] == ["sqs"]


def test_deterministic_json():
    stmts = [_allow("s3:getobject", "s3:listbucket", "ec2:describeinstances")]
    a = json.dumps(L.rightsize_policy(stmts, {"s3", "ec2"})[0], sort_keys=True)
    b = json.dumps(L.rightsize_policy(stmts, {"s3", "ec2"})[0], sort_keys=True)
    assert a == b                                          # byte-identical across runs


def test_deny_statements_preserved_not_regranted():
    # adversarial-verify regression: narrowing admin '*' to a used service must NOT re-grant an
    # explicitly denied action. The source Deny is preserved so the generated policy is never
    # broader than the source's effective grant.
    stmts = [_allow("*"), {"effect": "Deny", "actions": {"s3:deletebucket"}, "resources": {"*"}}]
    pol, _ = L.rightsize_policy(stmts, {"s3"})
    allows = [s for s in pol["Statement"] if s["Effect"] == "Allow"]
    denies = [s for s in pol["Statement"] if s["Effect"] == "Deny"]
    assert any("s3:*" in s["Action"] for s in allows)           # narrowed admin
    assert any("s3:deletebucket" in s["Action"] for s in denies)  # still denied → not broader


def test_admin_narrow_delta_reports_used_services():
    _, delta = L.rightsize_policy([_allow("*")], {"s3", "kms"})
    assert delta["admin_narrowed"] and delta["admin_narrowed_to"] == ["kms", "s3"]


def test_parse_slad_usage_window():
    now = 1_000_000_000
    sla = [{"ServiceNamespace": "s3", "LastAuthenticated": now - 10 * 86400},
           {"ServiceNamespace": "glacier", "LastAuthenticated": now - 200 * 86400}]
    assert L.parse_slad_usage(sla, now, window_days=90) == {"s3"}   # glacier out of window


def test_parse_action_usage():
    now = 1_000_000_000
    sla = [{"ServiceNamespace": "s3", "TrackedActionsLastAccessed": [
        {"ActionName": "GetObject", "LastAccessedTime": now - 5 * 86400},
        {"ActionName": "DeleteObject", "LastAccessedTime": now - 300 * 86400}]}]
    assert L.parse_action_usage(sla, now, window_days=90) == {"s3": {"s3:getobject"}}
