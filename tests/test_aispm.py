"""Slice 3 · Batch 1 — AI-SPM pure classifiers (aws_aispm). No boto3."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_aispm as AI
from aws_graph import SecurityGraph


def _stmt(actions, resources, effect="Allow", condition=None):
    return {"effect": effect, "actions": set(actions), "resources": set(resources),
            "not_resources": set(), "condition": condition}


# ── role_privesc_capable ─────────────────────────────────────────────────────
def test_privesc_admin_star():
    r = AI.role_privesc_capable([_stmt({"*"}, {"*"})])
    assert r and "administrative" in r


def test_privesc_passrole_unscoped():
    r = AI.role_privesc_capable([_stmt({"iam:passrole"}, {"*"})])
    assert r and "iam:passrole" in r


def test_privesc_iam_wildcard_matches_specific():
    # iam:* subsumes the specific privesc primitives (wildcard-aware match)
    assert AI.role_privesc_capable([_stmt({"iam:*"}, {"*"})])


def test_privesc_scoped_resource_not_flagged():
    # PassRole scoped to one role ARN is NOT privesc-capable (documented conservative FN)
    assert AI.role_privesc_capable(
        [_stmt({"iam:passrole"}, {"arn:aws:iam::111:role/svc"})]) is None


def test_privesc_star_action_on_single_resource_not_admin():
    # * on a specific resource is not administrative (mirrors the IAM-solver stance)
    assert AI.role_privesc_capable([_stmt({"*"}, {"arn:aws:s3:::b/*"})]) is None


def test_privesc_read_only_role_none():
    assert AI.role_privesc_capable([_stmt({"s3:getobject"}, {"*"})]) is None


def test_privesc_ignores_deny():
    # a Deny statement never grants privesc, even if broad
    assert AI.role_privesc_capable([_stmt({"*"}, {"*"}, effect="Deny")]) is None


def test_privesc_empty_statements():
    assert AI.role_privesc_capable([]) is None
    assert AI.role_privesc_capable(None) is None


# ── role_reaches_crown (graph query over CAN_READ_DATA) ──────────────────────
def test_reaches_crown_true():
    g = SecurityGraph()
    role = "arn:aws:iam::111:role/ai"
    db = "arn:aws:dynamodb:us-east-1:111:table/customers"
    g.add_node(role, "IAMRole")
    g.add_node(db, "DynamoDBTable", name="customers", crown_jewel=True, DataStore=True)
    g.add_edge(role, db, "CAN_READ_DATA")
    assert AI.role_reaches_crown(g, role) == "customers"


def test_reaches_crown_non_crown_target_none():
    g = SecurityGraph()
    role = "arn:aws:iam::111:role/ai"
    tbl = "arn:aws:dynamodb:us-east-1:111:table/logs"
    g.add_node(role, "IAMRole")
    g.add_node(tbl, "DynamoDBTable", name="logs")          # not crown
    g.add_edge(role, tbl, "CAN_READ_DATA")
    assert AI.role_reaches_crown(g, role) is None


def test_reaches_crown_no_edge_none():
    g = SecurityGraph()
    g.add_node("arn:aws:iam::111:role/ai", "IAMRole")
    assert AI.role_reaches_crown(g, "arn:aws:iam::111:role/ai") is None


def test_reaches_crown_falls_back_to_id_when_unnamed():
    g = SecurityGraph()
    role, db = "arn:aws:iam::111:role/ai", "arn:aws:s3:::secret"
    g.add_node(db, "S3Bucket", crown_jewel=True)           # no name prop
    g.add_edge(role, db, "CAN_READ_DATA")
    assert AI.role_reaches_crown(g, role) == db


def test_reaches_crown_none_graph():
    assert AI.role_reaches_crown(None, "arn:aws:iam::111:role/ai") is None


# ── ai_network_exposed ───────────────────────────────────────────────────────
def test_network_exposed_direct_internet():
    assert AI.ai_network_exposed({"network": {"direct_internet": True, "in_vpc": True}})


def test_network_exposed_not_in_vpc():
    assert AI.ai_network_exposed({"network": {"direct_internet": False, "in_vpc": False}})


def test_network_exposed_public_egress():
    assert AI.ai_network_exposed({"network": {"public_egress": True}})


def test_network_isolated_false():
    assert not AI.ai_network_exposed(
        {"network": {"direct_internet": False, "in_vpc": True, "public_egress": False}})


# ── is_ai_crown ──────────────────────────────────────────────────────────────
def test_is_ai_crown():
    assert AI.is_ai_crown({"data_bearing": True})
    assert not AI.is_ai_crown({"data_bearing": False})
    assert not AI.is_ai_crown({})
