"""Phase-4 Slice-1 · B5 — control-plane routes: workspaces CRUD + members + platform admins.
Skips if fastapi absent."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_api
from cnapp_api import Principal

pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI, reason="fastapi not installed")

import aws_state
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService
from cnapp_workspace import WorkspaceStore

SUPER = Principal(subject="root", is_superadmin=True)


def _svc():
    reg = AccountRegistry.open(":memory:")
    return PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        state=aws_state.StateStore(reg._be), workspaces=WorkspaceStore(reg._be), clock=lambda: 5000)


def _client(principal, svc=None):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc or _svc(), current_principal=lambda: principal))


def test_superadmin_workspace_crud():
    c = _client(SUPER)
    assert c.post("/workspaces", json={"workspace_id": "ws-a", "name": "Acme"}).status_code == 201
    assert {w["workspace_id"] for w in c.get("/workspaces").json()} >= {"ws-default", "ws-a"}
    assert c.put("/workspaces/ws-a", json={"status": "suspended"}).status_code == 200
    assert c.get("/workspaces/ws-a").json()["status"] == "suspended"
    assert c.delete("/workspaces/ws-a").status_code == 204


def test_non_superadmin_cannot_manage_workspaces():
    c = _client(Principal(subject="u", memberships={"ws-a": "admin"}))
    assert c.post("/workspaces", json={"workspace_id": "ws-x"}).status_code == 403
    assert c.get("/workspaces").status_code == 403


def test_ws_admin_manages_members():
    svc = _svc()
    svc.create_workspace("ws-a", name="Acme")
    c = _client(Principal(subject="a@x", memberships={"ws-a": "admin"}), svc)
    assert c.post("/workspaces/ws-a/members",
                  json={"principal": "b@x", "role": "viewer"}).status_code == 201
    assert {m["principal"] for m in c.get("/workspaces/ws-a/members").json()} == {"b@x"}
    assert c.delete("/workspaces/ws-a/members/b@x").status_code == 204


def test_viewer_cannot_manage_members():
    svc = _svc()
    svc.create_workspace("ws-a")
    c = _client(Principal(subject="v@x", memberships={"ws-a": "viewer"}), svc)
    assert c.post("/workspaces/ws-a/members", json={"principal": "z@x"}).status_code == 403


def test_member_views_own_workspace_only():
    svc = _svc()
    svc.create_workspace("ws-a")
    svc.create_workspace("ws-b")
    c = _client(Principal(subject="u@x", memberships={"ws-a": "viewer"}), svc)
    assert c.get("/workspaces/ws-a").status_code == 200
    assert c.get("/workspaces/ws-b").status_code == 404          # existence-hiding


def test_platform_admin_management():
    c = _client(SUPER)
    assert c.post("/admin/platform-admins", json={"principal": "root2@x"}).status_code == 201
    assert "root2@x" in c.get("/admin/platform-admins").json()
    assert c.delete("/admin/platform-admins/root2@x").status_code == 204


def test_delete_default_workspace_refused():
    assert _client(SUPER).delete("/workspaces/ws-default").status_code == 400


# ── adversarial-verify regressions ────────────────────────────────────────────
def test_duplicate_slug_is_409_not_500():
    c = _client(SUPER)
    assert c.post("/workspaces", json={"workspace_id": "ws-a", "slug": "acme"}).status_code == 201
    assert c.post("/workspaces", json={"workspace_id": "ws-b", "slug": "acme"}).status_code == 409


def test_add_member_to_missing_workspace_is_404_not_500():
    assert _client(SUPER).post("/workspaces/ws-nope/members",
                               json={"principal": "x@y"}).status_code == 404
