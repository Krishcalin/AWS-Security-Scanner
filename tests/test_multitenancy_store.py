"""Phase-4 Slice-1 · B2 — WorkspaceStore + AccountRegistry binding/filter. Offline."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cnapp_registry import AccountRegistry
from cnapp_workspace import WorkspaceStore


def _fx():
    r = AccountRegistry.open(":memory:")
    return r, WorkspaceStore(r._be)


def test_create_get_list_workspace():
    r, ws = _fx()
    ws.create_workspace("ws-a", name="Acme", slug="acme", now_epoch=1)
    w = ws.get_workspace("ws-a")
    assert w["name"] == "Acme" and w["status"] == "active"
    assert {"ws-default", "ws-a"} <= {x["workspace_id"] for x in ws.list_workspaces()}


def test_create_is_create_once_update_changes():
    r, ws = _fx()
    ws.create_workspace("ws-a", name="Acme", now_epoch=1)
    ws.create_workspace("ws-a", name="Changed", now_epoch=2)      # DO NOTHING
    assert ws.get_workspace("ws-a")["name"] == "Acme"
    ws.update_workspace("ws-a", name="Changed", status="suspended", now_epoch=3)
    w = ws.get_workspace("ws-a")
    assert w["name"] == "Changed" and w["status"] == "suspended"


def test_members_and_roles():
    r, ws = _fx()
    ws.create_workspace("ws-a", now_epoch=1)
    ws.add_member("ws-a", "alice@x", role="admin", added_by="root", now_epoch=1)
    ws.add_member("ws-a", "bob@x", role="viewer", now_epoch=1)
    assert ws.member_role("ws-a", "alice@x") == "admin"
    assert ws.member_role("ws-a", "bob@x") == "viewer"
    assert ws.member_role("ws-a", "ghost@x") is None
    assert ws.principal_memberships("alice@x") == {"ws-a": "admin"}
    ws.remove_member("ws-a", "bob@x")
    assert ws.member_role("ws-a", "bob@x") is None


def test_disabled_member_has_no_role():
    r, ws = _fx()
    ws.create_workspace("ws-a", now_epoch=1)
    ws.add_member("ws-a", "carol@x", role="admin", status="disabled", now_epoch=1)
    assert ws.member_role("ws-a", "carol@x") is None
    assert ws.principal_memberships("carol@x") == {}


def test_platform_admins():
    r, ws = _fx()
    assert not ws.is_platform_admin("root@x")
    ws.add_platform_admin("root@x", now_epoch=1)
    assert ws.is_platform_admin("root@x") and "root@x" in ws.list_platform_admins()
    ws.remove_platform_admin("root@x")
    assert not ws.is_platform_admin("root@x")


def test_bind_account_and_lookups():
    r, ws = _fx()
    ws.create_workspace("ws-a", now_epoch=1)
    r.upsert_account("111122223333", now_epoch=1)
    r.bind_account("111122223333", "ws-a", now_epoch=1)
    assert ws.workspace_of_account("111122223333") == "ws-a"
    assert ws.accounts_in_workspace("ws-a") == ["111122223333"]


def test_rebind_to_different_workspace_refused():
    r, ws = _fx()
    ws.create_workspace("ws-a", now_epoch=1)
    ws.create_workspace("ws-b", now_epoch=1)
    r.upsert_account("111122223333", now_epoch=1)
    r.bind_account("111122223333", "ws-a", now_epoch=1)
    r.bind_account("111122223333", "ws-a", now_epoch=2)          # same ws -> idempotent
    with pytest.raises(ValueError):
        r.bind_account("111122223333", "ws-b", now_epoch=3)      # cross-tenant move refused


def test_list_accounts_workspace_filter():
    r, ws = _fx()
    ws.create_workspace("ws-a", now_epoch=1)
    ws.create_workspace("ws-b", now_epoch=1)
    for acct, w in (("111122223333", "ws-a"), ("444455556666", "ws-b")):
        r.upsert_account(acct, now_epoch=1)
        r.set_onboarding_status(acct, "active", 1)
        r.bind_account(acct, w, now_epoch=1)
    assert [a["account_id"] for a in r.list_accounts(workspace_id="ws-a")] == ["111122223333"]
    assert [a["account_id"] for a in r.list_accounts(workspace_id="ws-b")] == ["444455556666"]
    assert len(r.list_accounts()) == 2                           # None => global
    assert len(r.list_accounts(onboarding_status="active", workspace_id="ws-a")) == 1


def test_delete_workspace_guards():
    r, ws = _fx()
    ws.create_workspace("ws-a", now_epoch=1)
    r.upsert_account("111122223333", now_epoch=1)
    r.bind_account("111122223333", "ws-a", now_epoch=1)
    with pytest.raises(ValueError):
        ws.delete_workspace("ws-a")             # still owns an account
    with pytest.raises(ValueError):
        ws.delete_workspace("ws-default")       # protected
