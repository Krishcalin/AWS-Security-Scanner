"""Phase-4 Slice-1 · B6 — usage metering (billable: accounts under management):
onboard/scan hooks, idempotent monthly gauge, per-workspace isolation, fail-open, reconcile."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
from cnapp_metering import MeteringStore
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService
from cnapp_workspace import WorkspaceStore


def _svc(clock=lambda: 1_700_000_000):          # 2023-11
    reg = AccountRegistry.open(":memory:")
    ws = WorkspaceStore(reg._be)
    m = MeteringStore(reg._be)
    svc = PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        state=aws_state.StateStore(reg._be), workspaces=ws, metering=m,
        id_gen=lambda: "ext", clock=clock)
    ws.create_workspace("ws-a", now_epoch=1)
    return svc, ws, m


def _summary(m, ws, period=None):
    return {r["metric"]: r["event_count"] for r in m.usage_summary(ws, period=period)}


def test_onboard_emits_account_onboarded_once():
    svc, ws, m = _svc()
    svc.init_onboarding("111122223333", workspace_id="ws-a")
    svc.init_onboarding("111122223333", workspace_id="ws-a")   # idempotent (same account)
    assert _summary(m, "ws-a").get("account.onboarded") == 1


def test_scan_completed_emits_active_gauge_and_scan_event():
    svc, ws, m = _svc()
    svc.init_onboarding("111122223333", workspace_id="ws-a")
    svc.meter_scan_completed("111122223333", "job-1", findings=3, resources=42)
    s = _summary(m, "ws-a")
    assert s.get("scan.completed") == 1 and s.get("account.active") == 1
    # a second scan SAME month -> account.active deduped (monthly gauge); scan.completed is a new key
    svc.meter_scan_completed("111122223333", "job-2", findings=1, resources=40)
    s = _summary(m, "ws-a")
    assert s.get("account.active") == 1 and s.get("scan.completed") == 2


def test_metering_fail_open_never_breaks_caller():
    svc, ws, m = _svc()

    class Boom:
        def execute(self, *a, **k):
            raise RuntimeError("db down")
    svc.metering = MeteringStore(Boom())
    out = svc.init_onboarding("111122223333", workspace_id="ws-a")   # onboarding still succeeds
    assert out["account_id"] == "111122223333"


def test_usage_isolated_per_workspace_and_rollup():
    svc, ws, m = _svc()
    ws.create_workspace("ws-b", now_epoch=1)
    svc.init_onboarding("111122223333", workspace_id="ws-a")
    svc.init_onboarding("444455556666", workspace_id="ws-b")
    assert _summary(m, "ws-a").get("account.onboarded") == 1
    assert _summary(m, "ws-b").get("account.onboarded") == 1
    roll = {(r["workspace_id"], r["metric"]): r["event_count"] for r in m.usage_rollup_all()}
    assert roll.get(("ws-a", "account.onboarded")) == 1
    assert roll.get(("ws-b", "account.onboarded")) == 1


def test_reconcile_rederives_active_idempotently():
    svc, ws, m = _svc()
    # an active bound account with NO metering events (simulate a dropped fail-open write)
    svc.registry.upsert_account("111122223333", now_epoch=1)
    svc.registry.set_onboarding_status("111122223333", "active", 1)
    svc.registry.bind_account("111122223333", "ws-a", now_epoch=1)
    assert _summary(m, "ws-a").get("account.active") is None
    assert svc.reconcile_usage()["active"] == 1
    assert _summary(m, "ws-a").get("account.active") == 1
    svc.reconcile_usage()                                        # second run adds nothing
    assert _summary(m, "ws-a").get("account.active") == 1


# ── route surface (fastapi) ───────────────────────────────────────────────────
def test_usage_routes():
    import cnapp_api
    if not cnapp_api._HAVE_FASTAPI:
        pytest.skip("fastapi not installed")
    from cnapp_api import Principal
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    svc, ws, m = _svc()
    svc.init_onboarding("111122223333", workspace_id="ws-a")
    admin = Principal(subject="a@x", memberships={"ws-a": "admin"})
    ca = TestClient(cnapp_api.create_app(svc, current_principal=lambda: admin))
    usage = ca.get("/workspaces/ws-a/usage").json()
    assert any(r["metric"] == "account.onboarded" for r in usage)
    # a viewer of another workspace cannot read ws-a usage (ws_admin_gate)
    other = Principal(subject="o@x", memberships={"ws-b": "admin"})
    co = TestClient(cnapp_api.create_app(svc, current_principal=lambda: other))
    assert co.get("/workspaces/ws-a/usage").status_code == 403
    # superadmin cross-workspace rollup + reconcile
    csa = TestClient(cnapp_api.create_app(svc, current_principal=lambda: Principal(
        subject="root", is_superadmin=True)))
    assert csa.get("/admin/usage").status_code == 200
    assert csa.post("/admin/usage/reconcile").status_code == 200
