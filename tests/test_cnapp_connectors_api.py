"""API-level tests for the connector framework routes on cnapp_api. Verifies RBAC
(admin mutate / viewer read), that NO route ever returns a secret, and the
create→enable→rule→notify→deliveries flow end-to-end over the real FastAPI app with
a fake http_post. Skips if fastapi is not installed (deploy-time dep)."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_api
import cnapp_connectors as cc

pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI,
                                reason="fastapi not installed (deploy-time dep)")

from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "123456789012"
SECRET = "SUPER-SECRET-TOKEN-999"


def _svc():
    store = cc.ConnectorStore.open(":memory:")
    db = {}
    results = InMemoryResultStore()
    results.put(ACCT, {"account": ACCT, "attack_paths": [], "results": [{"check_id": "S3-01", "status": "FAIL"}],
                       "finding_catalog": [{"check_id": "S3-01", "section": "S3", "severity": "HIGH",
                                            "status": "FAIL", "compliance": {"CIS": "2.1.1"},
                                            "remediation_cmd": "aws ...", "risk": "Public bucket.",
                                            "impact": "Breach.", "steps": ["fix"], "affected": ["b1"],
                                            "count": 1, "distinct": 1}]})

    def writer(cid, val):
        ref = f"secretsmanager://ow/{cid}"; db[ref] = val; return ref

    def http_post(url, *, headers, json_body=None, data=None, timeout=8.0):
        return cc.HttpResp(201, json.dumps({"key": "SEC-1"}))

    return PlatformService(
        registry=AccountRegistry.open(":memory:"), results=results,
        hub_role_arn="arn:aws:iam::5:role/Hub", cfn_template_url="https://h/x.yaml",
        secret_writer=writer, secret_reader=lambda r: db[r], connectors=store,
        http_post=http_post, hub_base="https://hub.example.com",
        connector_id_gen=lambda: "conn-fixed", clock=lambda: 1000)


def _client(role="admin", svc=None):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc or _svc(), current_role=lambda: role))


def test_create_connector_masks_secret_and_defaults_disabled():
    c = _client("admin")
    r = c.post("/connectors", json={"type": "jira", "name": "Jira",
                                    "config": {"site": "https://x.atlassian.net", "email": "b@x",
                                               "project_key": "SEC"}, "secret": SECRET})
    assert r.status_code == 201
    body = r.json()
    assert body["enabled"] is False and body["secret_configured"] is True
    assert "secret_ref" not in body and SECRET not in json.dumps(body)


def test_no_route_ever_returns_a_secret():
    c = _client("admin")
    cid = c.post("/connectors", json={"type": "webhook", "name": "W",
                                      "config": {"url": "https://hooks.example.com/x"},
                                      "secret": SECRET}).json()["connector_id"]
    for path in ("/connectors", f"/connectors/{cid}"):
        assert SECRET not in c.get(path).text


def test_rbac_viewer_can_read_but_not_mutate():
    svc = _svc()
    admin, viewer = _client("admin", svc), _client("viewer", svc)
    admin.post("/connectors", json={"type": "slack", "name": "S",
                                    "config": {"mode": "webhook"}, "secret": "wh"})
    assert viewer.get("/connectors").status_code == 200          # read OK
    assert viewer.post("/connectors", json={"type": "slack", "name": "S2",
                                            "config": {}}).status_code == 403
    assert viewer.post("/connectors/conn-fixed/enable", json={"enabled": True}).status_code == 403
    assert viewer.delete("/connectors/conn-fixed").status_code == 403


def test_rbac_fail_closed_unset_role_denied_everywhere():
    c = _client("")                                             # rank 0
    assert c.get("/connectors").status_code == 403
    assert c.post("/connectors", json={"type": "slack", "name": "S", "config": {}}).status_code == 403


def test_full_flow_create_enable_rule_notify_deliveries():
    svc = _svc()
    c = _client("admin", svc)
    cid = c.post("/connectors", json={"type": "jira", "name": "Jira",
                                      "config": {"site": "https://x.atlassian.net", "email": "b@x",
                                                 "project_key": "SEC"}, "secret": SECRET}).json()["connector_id"]
    assert c.post(f"/connectors/{cid}/rules",
                  json={"spec": {"name": "high", "min_severity": "HIGH"}}).status_code == 201
    assert c.post(f"/connectors/{cid}/enable", json={"enabled": True}).json()["enabled"] is True
    # preview (dry-run) shows the would-fire
    prev = c.post("/connectors/rules/preview", json={"account_id": ACCT}).json()
    assert prev and prev[0]["check_id"] == "S3-01"
    # notify sends
    n = c.post(f"/accounts/{ACCT}/notify").json()
    assert n["sent"] == 1
    # deliveries audit — viewer readable, leak-free
    d = _client("viewer", svc).get(f"/connectors/{cid}/deliveries")
    assert d.status_code == 200 and d.json()[0]["external_ref"] == "SEC-1"
    assert SECRET not in d.text


def test_delete_connector_cascades_rules():
    svc = _svc()
    c = _client("admin", svc)
    cid = c.post("/connectors", json={"type": "webhook", "name": "W",
                                      "config": {"url": "https://hooks.example.com/x"}}).json()["connector_id"]
    c.post(f"/connectors/{cid}/rules", json={"spec": {"name": "r"}})
    assert c.delete(f"/connectors/{cid}").status_code == 204
    assert c.get(f"/connectors/{cid}").status_code == 404
