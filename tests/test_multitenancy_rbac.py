"""Phase-4 Slice-1 · B3 — workspace-scoped RBAC: back-compat shim, principal path,
X-Workspace-Id resolution, superadmin gate. Skips if fastapi absent."""
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


def _svc():
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be)
    return PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state, clock=lambda: 5000)


def _client(*, role=None, principal=None, svc=None):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    kw = {}
    if principal is not None:
        kw["current_principal"] = lambda: principal
    elif role is not None:
        kw["current_role"] = lambda: role
    return TestClient(cnapp_api.create_app(svc or _svc(), **kw))


# ── back-compat shim: legacy role string behaves exactly as before ────────────
def test_shim_admin_and_viewer():
    assert _client(role="viewer").get("/accounts").status_code == 200
    assert _client(role="viewer").post("/scans", json={"all": True}).status_code == 403
    assert _client(role="admin").post("/scans", json={"all": True}).status_code == 202


def test_no_hook_denies_all():
    assert _client().get("/accounts").status_code == 403        # unset -> "" -> deny


def test_principal_from_role_helper():
    p = cnapp_api._principal_from_role("admin")
    assert p.subject == "admin" and p.memberships == {DEFAULT_WORKSPACE: "admin"}
    assert cnapp_api._principal_from_role("").memberships == {}


# ── principal path (IdP-claims) + X-Workspace-Id resolution ───────────────────
def test_principal_member_of_default_workspace():
    p = Principal(subject="u@x", memberships={DEFAULT_WORKSPACE: "admin"})
    assert _client(principal=p).get("/accounts").status_code == 200


def test_principal_non_member_denied():
    p = Principal(subject="u@x", memberships={"ws-other": "admin"})
    c = _client(principal=p)
    # no header, sole membership ws-other -> role_in(ws-other)=admin -> ok for that ws;
    # but /accounts resolves to ws-other (sole membership) and passes admin gate
    assert c.get("/accounts").status_code == 200
    # header for a workspace the principal is NOT in -> 403 at workspace_ctx
    assert c.get("/accounts", headers={"X-Workspace-Id": "ws-nope"}).status_code == 403


def test_empty_membership_denied_everywhere():
    p = Principal(subject="u@x", memberships={})
    assert _client(principal=p).get("/accounts").status_code == 403


def test_header_selects_workspace_for_member():
    p = Principal(subject="u@x", memberships={"ws-a": "admin", "ws-b": "viewer"})
    c = _client(principal=p)
    # viewer in ws-b -> can GET but not POST /scans
    assert c.get("/accounts", headers={"X-Workspace-Id": "ws-b"}).status_code == 200
    assert c.post("/scans", json={"all": True},
                  headers={"X-Workspace-Id": "ws-b"}).status_code == 403
    # admin in ws-a -> can POST /scans
    assert c.post("/scans", json={"all": True},
                  headers={"X-Workspace-Id": "ws-a"}).status_code == 202


def test_multi_membership_no_header_defaults():
    # two memberships, no header -> defaults to ws-default; not a member there -> 403
    p = Principal(subject="u@x", memberships={"ws-a": "admin", "ws-b": "admin"})
    assert _client(principal=p).get("/accounts").status_code == 403


# ── superadmin ────────────────────────────────────────────────────────────────
def test_superadmin_acts_anywhere():
    p = Principal(subject="root@x", memberships={}, is_superadmin=True)
    c = _client(principal=p)
    assert c.get("/accounts", headers={"X-Workspace-Id": "any-ws"}).status_code == 200
    assert c.post("/scans", json={"all": True},
                  headers={"X-Workspace-Id": "any-ws"}).status_code == 202
