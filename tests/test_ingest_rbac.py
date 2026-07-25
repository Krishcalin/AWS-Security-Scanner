"""Phase-4 Slice-4 · B7 — the below-admin `ingest` RBAC tier: a CI/CD token can POST an
SBOM/scan to /ingest but CANNOT onboard/delete accounts or run scans (fixes the
over-privileged CI-admin token). viewer < ingest < admin."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_api
from cnapp_api import Principal, DEFAULT_WORKSPACE

pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI, reason="fastapi not installed")

import aws_state
import cnapp_connectors as cc
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"


def test_authorize_ranks_place_ingest_between_viewer_and_admin():
    a = cnapp_api._authorize
    assert a("ingest", "ingest") and a("ingest", "viewer")     # can ingest + read
    assert not a("ingest", "admin")                            # cannot admin-mutate
    assert a("admin", "ingest") and not a("viewer", "ingest")  # admin can ingest; viewer cannot


def _svc():
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be)
    results = InMemoryResultStore()
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    results.put(ACCT, {"account": ACCT, "graph_full": {}, "attack_paths": [],
                       "finding_catalog": [], "results": []})
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state,
        vuln_bundle={"records": [], "epss": {}, "kev": set(), "exploits": set()}, clock=lambda: 5000)


def _client(principal, svc):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc, current_principal=lambda: principal))


def _sarif():
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Trivy", "rules": [{"id": "CVE-2021-1"}]}},
        "results": [{"ruleId": "CVE-2021-1", "level": "error",
                     "message": {"text": "Package: x\nInstalled Version: 1\nFixed Version: 2"}}]}]}


def test_ingest_tier_can_ingest_read_but_not_admin():
    svc = _svc()
    c = _client(Principal(subject="ci", memberships={DEFAULT_WORKSPACE: "ingest"}), svc)
    assert c.post(f"/accounts/{ACCT}/ingest", json={"doc": _sarif()}).status_code == 200   # gate passes
    assert c.get(f"/accounts/{ACCT}/vulns").status_code == 200                              # viewer-level read
    assert c.post(f"/accounts/{ACCT}/vulns/refresh").status_code == 403                     # admin-only
    assert c.post("/scans", json={"account_ids": [ACCT]}).status_code == 403               # admin-only


def test_viewer_cannot_ingest():
    svc = _svc()
    c = _client(Principal(subject="v", memberships={DEFAULT_WORKSPACE: "viewer"}), svc)
    assert c.post(f"/accounts/{ACCT}/ingest", json={"doc": _sarif()}).status_code == 403
