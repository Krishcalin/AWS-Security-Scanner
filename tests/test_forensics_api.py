"""Slice 3 · Batch 6 — cloud-forensics timeline API route + seam wiring + FORENSIC-00
fail-open. Skips if fastapi is absent."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_api
import cnapp_connectors as cc

pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI,
                                reason="fastapi not installed (deploy-time dep)")

import aws_state
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"
INST = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"


def _svc(trail_reader=None):
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be)
    results = InMemoryResultStore()
    g = SecurityGraph()
    g.add_node(INST, "EC2Instance", instance_id="i-1")
    results.put(ACCT, {"account": ACCT, "graph_full": g.to_dict(), "attack_paths": [],
                       "finding_catalog": [{"check_id": "VPC-01", "affected": ["i-1"]}],
                       "results": []})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state, trail_reader=trail_reader,
        clock=lambda: 5000)


def _client(role="viewer", svc=None):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc or _svc(), current_role=lambda: role))


def _ev():
    return {"eventID": "e1", "eventTime": "2026-01-01T00:00:00Z", "eventName": "RunInstances",
            "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCT}:user/bob",
                             "userName": "bob"},
            "sourceIPAddress": "1.2.3.4", "awsRegion": "us-east-1", "readOnly": False}


def test_fail_open_when_no_seam():
    r = _client("viewer").get(f"/accounts/{ACCT}/forensics/timeline?resource={INST}")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "unavailable" and body["finding_id"] == "FORENSIC-00"


def test_timeline_with_seam_and_correlation():
    svc = _svc(trail_reader=lambda a, arn, s, e, lim: [_ev()])
    body = _client("viewer", svc=svc).get(
        f"/accounts/{ACCT}/forensics/timeline?resource={INST}").json()
    assert body["status"] == "ok" and body["count"] == 1
    assert body["on_graph"] is True and "VPC-01" in body["related_findings"]


def test_seam_error_fails_open():
    def boom(*a):
        raise RuntimeError("denied")
    body = _client("viewer", svc=_svc(trail_reader=boom)).get(
        f"/accounts/{ACCT}/forensics/timeline?resource={INST}").json()
    assert body["status"] == "unavailable" and body["finding_id"] == "FORENSIC-00"


def test_resource_query_required():
    r = _client("viewer").get(f"/accounts/{ACCT}/forensics/timeline")
    assert r.status_code == 422           # FastAPI validation: ?resource is required
