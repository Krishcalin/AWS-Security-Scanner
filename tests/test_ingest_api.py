"""B6 — ingest API routes on cnapp_api: RBAC (admin upload / viewer read), the
upload→own→rank flow over the real FastAPI app, and error mapping (400 unparseable,
404 unknown CVE). Skips if fastapi is absent."""
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
ROLE = f"arn:aws:iam::{ACCT}:role/r-1"
PROF = f"arn:aws:iam::{ACCT}:instance-profile/p-1"
BUCKET = "arn:aws:s3:::crown-data"
BUNDLE = {"records": [{"id": "CVE-2021-44228", "database_specific": {"severity": "CRITICAL"},
                       "severity": [{"score": 10.0}]}],
          "epss": {"CVE-2021-44228": 0.975}, "kev": {"CVE-2021-44228"},
          "exploits": {"CVE-2021-44228"}}


def _graph():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("eni-1", "NetworkInterface")
    g.add_node(INST, "EC2Instance", instance_id="i-1")
    g.add_edge("internet", "eni-1", "EXPOSED_TO")
    g.add_edge("eni-1", INST, "ATTACHED_TO")
    g.add_node(PROF, "InstanceProfile"); g.add_edge(INST, PROF, "HAS_INSTANCE_PROFILE")
    g.add_node(ROLE, "IAMRole"); g.add_edge(PROF, ROLE, "HAS_ROLE")
    g.add_node(BUCKET, "S3Bucket", crown_jewel=True)
    g.add_edge(ROLE, BUCKET, "CAN_READ_DATA", conditioned=False)
    return g


def _svc():
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be)
    results = InMemoryResultStore()
    results.put(ACCT, {"account": ACCT, "graph_full": _graph().to_dict(),
                       "attack_paths": [], "finding_catalog": [], "results": []})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state, vuln_bundle=BUNDLE,
        clock=lambda: 5000)


def _client(role="admin", svc=None):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc or _svc(), current_role=lambda: role))


def _sarif():
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Trivy", "rules": [{
            "id": "CVE-2021-44228", "properties": {"security-severity": "10.0"}}]}},
        "results": [{"ruleId": "CVE-2021-44228", "level": "error",
                     "message": {"text": "Package: log4j-core\nInstalled Version: 2.14.1"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": INST}}}]}]}]}


def test_viewer_cannot_ingest():
    c = _client("viewer")
    r = c.post(f"/accounts/{ACCT}/ingest", json={"doc": _sarif(), "target_resource": INST})
    assert r.status_code == 403


def test_admin_ingest_then_viewer_reads_ranked_inventory():
    svc = _svc()
    admin = _client("admin", svc)
    r = admin.post(f"/accounts/{ACCT}/ingest", json={"doc": _sarif(), "target_resource": INST})
    assert r.status_code == 200
    body = r.json()
    assert body["mapping_status"] == "resolved" and body["finding_count"] == 1

    viewer = _client("viewer", svc)
    rows = viewer.get(f"/accounts/{ACCT}/vulns").json()
    assert rows[0]["cve"] == "CVE-2021-44228" and rows[0]["priority_band"] == "CRITICAL"
    assert rows[0]["on_attack_path"] is True
    # facets
    assert viewer.get(f"/accounts/{ACCT}/vulns", params={"kev": True}).json()[0]["kev"] is True
    assert viewer.get(f"/accounts/{ACCT}/vulns", params={"on_path": True}).json()
    # detail + docs ledger
    assert viewer.get(f"/accounts/{ACCT}/vulns/CVE-2021-44228").status_code == 200
    assert len(viewer.get(f"/accounts/{ACCT}/ingest/docs").json()) == 1
    # org roll-up
    assert viewer.get("/org/vulns").json()[0]["account"] == ACCT


def test_unparseable_doc_is_400():
    c = _client("admin")
    r = c.post(f"/accounts/{ACCT}/ingest", json={"doc": {"nope": 1}})
    assert r.status_code == 400


def test_unknown_cve_detail_is_404():
    c = _client("viewer")
    r = c.get(f"/accounts/{ACCT}/vulns/CVE-9999-1")
    assert r.status_code == 404


def test_refresh_requires_admin():
    assert _client("viewer").post(f"/accounts/{ACCT}/vulns/refresh").status_code == 403
    assert _client("admin").post(f"/accounts/{ACCT}/vulns/refresh").status_code == 200
