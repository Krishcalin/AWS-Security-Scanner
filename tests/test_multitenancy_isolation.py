"""Phase-4 Slice-1 · B4 — tenant isolation end-to-end (a wired WorkspaceStore):
cross-tenant 404, scoped list/org, onboarding binds workspace, superadmin all-view.
Skips if fastapi absent."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_api
from cnapp_api import Principal

pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI, reason="fastapi not installed")

import aws_state
import cnapp_connectors as cc
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService
from cnapp_workspace import WorkspaceStore

A_ACCT = "111111111111"
B_ACCT = "222222222222"


def _svc():
    reg = AccountRegistry.open(":memory:")
    ws = WorkspaceStore(reg._be)
    results = InMemoryResultStore()
    svc = PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=aws_state.StateStore(reg._be),
        workspaces=ws, id_gen=lambda: "ext-fixed", clock=lambda: 5000)
    ws.create_workspace("ws-a", name="Acme", now_epoch=1)
    ws.create_workspace("ws-b", name="Beta", now_epoch=1)
    for acct, w in ((A_ACCT, "ws-a"), (B_ACCT, "ws-b")):
        reg.upsert_account(acct, now_epoch=1)
        reg.set_onboarding_status(acct, "active", 1)
        reg.bind_account(acct, w, now_epoch=1)
        results.put(acct, {"account": acct, "posture_score": 90, "posture_grade": "A",
                           "finding_catalog": [], "attack_paths": [], "results": []})
    return svc


def _client(principal, svc):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc, current_principal=lambda: principal))


def _member(ws, role="admin"):
    return Principal(subject="u@x", memberships={ws: role})


def test_tenant_sees_only_own_account_in_list():
    ca = _client(_member("ws-a"), _svc())
    rows = ca.get("/accounts", headers={"X-Workspace-Id": "ws-a"}).json()
    assert [r["account_id"] for r in rows] == [A_ACCT]


def test_cross_tenant_account_is_404_not_403():
    ca = _client(_member("ws-a"), _svc())
    assert ca.get(f"/accounts/{B_ACCT}", headers={"X-Workspace-Id": "ws-a"}).status_code == 404
    assert ca.get(f"/accounts/{A_ACCT}", headers={"X-Workspace-Id": "ws-a"}).status_code == 200


def test_cross_tenant_ingest_denied():
    ca = _client(_member("ws-a"), _svc())
    r = ca.post(f"/accounts/{B_ACCT}/detections", json={"events": {}, "source": "guardduty"},
                headers={"X-Workspace-Id": "ws-a"})
    assert r.status_code == 404


def test_org_and_list_scoped_to_workspace():
    ca = _client(_member("ws-a", role="viewer"), _svc())
    assert len(ca.get("/accounts", headers={"X-Workspace-Id": "ws-a"}).json()) == 1
    # org overview only rolls up ws-a's account (non-empty, scoped)
    assert ca.get("/org/overview", headers={"X-Workspace-Id": "ws-a"}).status_code == 200


def test_superadmin_sees_all_accounts():
    csa = _client(Principal(subject="root", is_superadmin=True), _svc())
    rows = csa.get("/accounts").json()                      # no header -> all-workspaces
    assert {r["account_id"] for r in rows} == {A_ACCT, B_ACCT}
    assert csa.get(f"/accounts/{A_ACCT}").status_code == 200
    assert csa.get(f"/accounts/{B_ACCT}").status_code == 200


def test_superadmin_can_drill_into_one_workspace():
    csa = _client(Principal(subject="root", is_superadmin=True), _svc())
    rows = csa.get("/accounts", headers={"X-Workspace-Id": "ws-b"}).json()
    assert [r["account_id"] for r in rows] == [B_ACCT]


def test_onboarding_binds_caller_workspace():
    svc = _svc()
    ca = _client(_member("ws-a"), svc)
    r = ca.post("/accounts", json={"account_id": "333333333333"},
                headers={"X-Workspace-Id": "ws-a"})
    assert r.status_code == 201
    assert svc.workspaces.workspace_of_account("333333333333") == "ws-a"


def test_cross_tenant_reonboard_is_409():
    cb = _client(_member("ws-b"), _svc())
    r = cb.post("/accounts", json={"account_id": A_ACCT}, headers={"X-Workspace-Id": "ws-b"})
    assert r.status_code == 409


def test_scan_all_scoped_to_workspace():
    svc = _svc()
    ca = _client(_member("ws-a"), svc)
    jobs = ca.post("/scans", json={"all": True}, headers={"X-Workspace-Id": "ws-a"}).json()
    # exactly one job (only ws-a's active account), and it targets A_ACCT
    assert len(jobs["job_ids"]) == 1
    assert svc.registry.get_scan_job(jobs["job_ids"][0])["account_id"] == A_ACCT


# ── adversarial-verify regressions ────────────────────────────────────────────
def test_cross_tenant_scan_job_is_404():
    # a scan job carries account_id -> it must be tenant-isolated even though {job_id}
    # is not an {account_id} path (verify finding #1)
    svc = _svc()
    ca = _client(_member("ws-a"), svc)
    jid = ca.post("/scans", json={"account_ids": [A_ACCT]},
                  headers={"X-Workspace-Id": "ws-a"}).json()["job_ids"][0]
    assert ca.get(f"/scans/{jid}", headers={"X-Workspace-Id": "ws-a"}).status_code == 200
    cb = _client(_member("ws-b"), svc)
    assert cb.get(f"/scans/{jid}", headers={"X-Workspace-Id": "ws-b"}).status_code == 404


def test_cross_tenant_preview_rules_is_404():
    # account_id in the BODY must still be tenant-isolated (verify finding #2)
    ca = _client(_member("ws-a"), _svc())
    r = ca.post("/connectors/rules/preview", json={"account_id": B_ACCT},
                headers={"X-Workspace-Id": "ws-a"})
    assert r.status_code == 404


def test_schedule_tick_scoped_to_workspace():
    # a tenant admin's schedule-tick sweeps only their own workspace (verify finding #5)
    svc = _svc()
    svc.registry.upsert_account(A_ACCT, now_epoch=1, scan_schedule="daily")
    svc.registry.upsert_account(B_ACCT, now_epoch=1, scan_schedule="daily")
    ca = _client(_member("ws-a"), svc)
    jobs = ca.post("/scans/schedule-tick", headers={"X-Workspace-Id": "ws-a"}).json()["job_ids"]
    assert len(jobs) == 1
    assert svc.registry.get_scan_job(jobs[0])["account_id"] == A_ACCT
