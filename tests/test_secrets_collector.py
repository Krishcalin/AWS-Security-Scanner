"""Slice 1 · Batch 5+6 — _collect_secrets_dspm: SSM posture (SECRET-01/02), the crown
Secret node + CAN_READ_DATA reader path (SECRET-05), and fail-open (SECRET-00). Offline."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner
from aws_graph import SecurityGraph

ACCT = "123456789012"


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def _pager(key, items):
    p = MagicMock()
    p.paginate.return_value = [{key: items}]
    return p


def _stmt(actions, resources):
    return {"effect": "Allow", "actions": set(actions), "resources": set(resources),
            "not_resources": set(), "condition": None}


def _role(name, statements):
    return {"type": "role", "name": name, "arn": f"arn:aws:iam::{ACCT}:role/{name}",
            "statements": statements}


def _svc(roles=None, params=None, secrets=None):
    s = make_scanner(sections=["DATA"])
    s.account = ACCT
    g = SecurityGraph()
    s.graph = g
    s._iam_principals = roles or []
    ssm = MagicMock()
    ssm.get_paginator.return_value = _pager("Parameters", params or [])
    sm = MagicMock()
    sm.get_paginator.return_value = _pager("SecretList", secrets or [])
    s._clients["ssm:us-east-1"] = ssm
    s._clients["secretsmanager:us-east-1"] = sm
    return s, g


SEC_ARN = f"arn:aws:secretsmanager:us-east-1:{ACCT}:secret:prod/db-AbCdEf"


def test_secret01_plaintext_ssm_param():
    s, g = _svc(params=[{"Name": "/app/db_password", "Type": "String",
                         "ARN": f"arn:aws:ssm:us-east-1:{ACCT}:parameter/app/db_password"}])
    s._collect_secrets_dspm(g)
    assert "FAIL" in _status(s, "SECRET-01")


def test_non_secret_string_param_no_finding():
    s, g = _svc(params=[{"Name": "/app/region", "Type": "String"}])
    s._collect_secrets_dspm(g)
    assert not _status(s, "SECRET-01")


def test_secret02_managed_key_securestring():
    s, g = _svc(params=[{"Name": "/app/token", "Type": "SecureString"}])
    s._collect_secrets_dspm(g)
    assert "WARN" in _status(s, "SECRET-02")


def test_secret_crown_node_and_reader_edge():
    reader = _role("app", [_stmt({"secretsmanager:getsecretvalue"}, {SEC_ARN.lower()})])
    s, g = _svc(roles=[reader], secrets=[{"ARN": SEC_ARN, "Name": "prod/db"}])
    s._collect_secrets_dspm(g)
    node = g.node(SEC_ARN)
    assert node and node["kind"] == "Secret" and node["props"]["crown_jewel"]
    assert any(e["kind"] == "CAN_READ_DATA" and e["dst"] == SEC_ARN
               for e in g.out_edges(f"arn:aws:iam::{ACCT}:role/app"))
    assert "FAIL" in _status(s, "SECRET-05")


def test_secret_with_no_reader_not_materialized():
    # a secret no role can read is not added to the graph (no clutter, no phantom path)
    s, g = _svc(roles=[_role("x", [_stmt({"s3:getobject"}, {"*"})])],
                secrets=[{"ARN": SEC_ARN, "Name": "prod/db"}])
    s._collect_secrets_dspm(g)
    assert g.node(SEC_ARN) is None
    assert not _status(s, "SECRET-05")


def test_secret00_fail_open_on_denied_reads():
    s, g = _svc()
    s._clients["ssm:us-east-1"].get_paginator.side_effect = RuntimeError("AccessDenied")
    s._clients["secretsmanager:us-east-1"].get_paginator.side_effect = RuntimeError("AccessDenied")
    s._collect_secrets_dspm(g)
    assert "INFO" in _status(s, "SECRET-00")            # never a phantom all-clear
    assert not _status(s, "SECRET-01") and not _status(s, "SECRET-05")


def test_conditioned_reader_is_warn():
    reader = _role("cond", [{"effect": "Allow", "actions": {"secretsmanager:getsecretvalue"},
                             "resources": {SEC_ARN.lower()}, "not_resources": set(),
                             "condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}])
    s, g = _svc(roles=[reader], secrets=[{"ARN": SEC_ARN, "Name": "prod/db"}])
    s._collect_secrets_dspm(g)
    assert "WARN" in _status(s, "SECRET-05") and "FAIL" not in _status(s, "SECRET-05")
