#!/usr/bin/env python3
"""cnapp_workspace.py — multi-tenancy control plane store (Phase-4 Slice-1).

A ``WorkspaceStore`` over the shared ``cnapp_backend.Backend`` (sqlite | Postgres),
parallel to ``AccountRegistry`` / ``ConnectorStore``. Owns the ``workspaces`` /
``workspace_members`` / ``platform_admins`` tables plus the read helpers the RBAC
isolation gate needs (``workspace_of_account`` / ``principal_memberships`` /
``is_platform_admin``). The account<->workspace binding (``workspace_accounts``) is
WRITTEN by ``AccountRegistry.bind_account`` (so onboarding binds in the same txn as the
account upsert) and READ here for isolation.

It is NOT the request-time RBAC authority — the injected ``current_principal`` hook (IdP
claims) is. This store backs member management, the workspace registry, and a DB
fallback. Pure + dual-dialect + offline-testable over an injected Backend.
"""
from __future__ import annotations

from typing import Dict, List, Optional

_ROLES = ("viewer", "admin")
_WS_STATUS = ("active", "suspended", "archived")
_MEMBER_STATUS = ("active", "invited", "disabled")


class WorkspaceStore:
    def __init__(self, backend):
        self._be = backend

    # ── workspaces ────────────────────────────────────────────────────────────
    def _slug_taken(self, slug: Optional[str], *, exclude_ws: Optional[str] = None) -> bool:
        """Is ``slug`` already used by a DIFFERENT workspace? Pre-checks the UNIQUE(slug)
        index so a duplicate raises a clean ValueError instead of a dialect-specific
        IntegrityError (a 500) at the DB layer."""
        if not slug:
            return False
        r = self._be.query_one("SELECT workspace_id FROM workspaces WHERE slug=?", (slug,))
        return r is not None and dict(r)["workspace_id"] != exclude_ws

    def create_workspace(self, workspace_id: str, *, name: str = "", slug: Optional[str] = None,
                         plan: Optional[str] = None, now_epoch: int) -> Optional[Dict]:
        """Create a workspace (create-once: ON CONFLICT DO NOTHING). Use
        ``update_workspace`` to change an existing one."""
        if not workspace_id:
            raise ValueError("workspace_id required")
        if self._slug_taken(slug):
            raise ValueError(f"slug {slug!r} already in use")
        self._be.upsert(
            "workspaces",
            ["workspace_id", "name", "slug", "status", "plan", "created_at", "updated_at"],
            ["workspace_id"], [],       # empty update_cols -> ON CONFLICT DO NOTHING
            (workspace_id, name or "", slug, "active", plan, int(now_epoch), int(now_epoch)))
        return self.get_workspace(workspace_id)

    def get_workspace(self, workspace_id: str) -> Optional[Dict]:
        r = self._be.query_one("SELECT * FROM workspaces WHERE workspace_id=?", (workspace_id,))
        return dict(r) if r else None

    def list_workspaces(self) -> List[Dict]:
        return [dict(r) for r in
                self._be.query_all("SELECT * FROM workspaces ORDER BY workspace_id")]

    def update_workspace(self, workspace_id: str, *, name: Optional[str] = None,
                        slug: Optional[str] = None, status: Optional[str] = None,
                        plan: Optional[str] = None, now_epoch: int) -> Optional[Dict]:
        if slug is not None and self._slug_taken(slug, exclude_ws=workspace_id):
            raise ValueError(f"slug {slug!r} already in use")
        sets, params = [], []
        if name is not None:
            sets.append("name=?"); params.append(name)
        if slug is not None:
            sets.append("slug=?"); params.append(slug)
        if status is not None:
            if status not in _WS_STATUS:
                raise ValueError(f"invalid workspace status {status!r}")
            sets.append("status=?"); params.append(status)
        if plan is not None:
            sets.append("plan=?"); params.append(plan)
        sets.append("updated_at=?"); params.append(int(now_epoch))
        params.append(workspace_id)
        self._be.execute(f"UPDATE workspaces SET {', '.join(sets)} WHERE workspace_id=?", params)
        return self.get_workspace(workspace_id)

    def delete_workspace(self, workspace_id: str) -> None:
        """Refuse to delete a workspace that still owns accounts (isolation integrity —
        an orphaned account would be unreachable). Reassign/offboard its accounts first."""
        if workspace_id == "ws-default":
            raise ValueError("the default workspace cannot be deleted")
        n = dict(self._be.query_one(
            "SELECT COUNT(*) c FROM workspace_accounts WHERE workspace_id=?", (workspace_id,)))["c"]
        if n:
            raise ValueError(f"workspace {workspace_id} still has {n} account(s); "
                             "reassign or offboard them first")
        with self._be.transaction():
            self._be.execute("DELETE FROM workspace_members WHERE workspace_id=?", (workspace_id,))
            self._be.execute("DELETE FROM workspaces WHERE workspace_id=?", (workspace_id,))

    # ── members ───────────────────────────────────────────────────────────────
    def add_member(self, workspace_id: str, principal: str, *, role: str = "viewer",
                   status: str = "active", added_by: Optional[str] = None,
                   now_epoch: int) -> Optional[Dict]:
        if role not in _ROLES:
            raise ValueError(f"invalid role {role!r}")
        if status not in _MEMBER_STATUS:
            raise ValueError(f"invalid member status {status!r}")
        self._be.upsert(
            "workspace_members",
            ["workspace_id", "principal", "role", "status", "added_by", "created_at", "updated_at"],
            ["workspace_id", "principal"],
            ["role", "status", "added_by", "updated_at"],
            (workspace_id, principal, role, status, added_by, int(now_epoch), int(now_epoch)))
        return self.member(workspace_id, principal)

    def remove_member(self, workspace_id: str, principal: str) -> None:
        self._be.execute("DELETE FROM workspace_members WHERE workspace_id=? AND principal=?",
                         (workspace_id, principal))

    def member(self, workspace_id: str, principal: str) -> Optional[Dict]:
        r = self._be.query_one(
            "SELECT * FROM workspace_members WHERE workspace_id=? AND principal=?",
            (workspace_id, principal))
        return dict(r) if r else None

    def list_members(self, workspace_id: str) -> List[Dict]:
        return [dict(r) for r in self._be.query_all(
            "SELECT * FROM workspace_members WHERE workspace_id=? ORDER BY principal", (workspace_id,))]

    def member_role(self, workspace_id: str, principal: str) -> Optional[str]:
        m = self.member(workspace_id, principal)
        return m["role"] if m and m.get("status") == "active" else None

    def principal_memberships(self, principal: str) -> Dict[str, str]:
        """{workspace_id: role} for every ACTIVE membership of a principal — the DB-side
        auth fallback / directory (production RBAC comes from the injected hook)."""
        return {dict(r)["workspace_id"]: dict(r)["role"] for r in self._be.query_all(
            "SELECT workspace_id, role FROM workspace_members "
            "WHERE principal=? AND status='active'", (principal,))}

    # ── platform admins (MSSP operators; transcend tenants) ───────────────────
    def add_platform_admin(self, principal: str, *, now_epoch: int) -> None:
        self._be.upsert("platform_admins", ["principal", "created_at"], ["principal"], [],
                        (principal, int(now_epoch)))

    def remove_platform_admin(self, principal: str) -> None:
        self._be.execute("DELETE FROM platform_admins WHERE principal=?", (principal,))

    def is_platform_admin(self, principal: str) -> bool:
        return self._be.query_one("SELECT 1 FROM platform_admins WHERE principal=?",
                                  (principal,)) is not None

    def list_platform_admins(self) -> List[str]:
        return [dict(r)["principal"] for r in
                self._be.query_all("SELECT principal FROM platform_admins ORDER BY principal")]

    # ── account<->workspace binding (READ; writes via AccountRegistry.bind_account) ──
    def workspace_of_account(self, account_id: str) -> Optional[str]:
        r = self._be.query_one("SELECT workspace_id FROM workspace_accounts WHERE account_id=?",
                               (account_id,))
        return dict(r)["workspace_id"] if r else None

    def accounts_in_workspace(self, workspace_id: str) -> List[str]:
        return [dict(r)["account_id"] for r in self._be.query_all(
            "SELECT account_id FROM workspace_accounts WHERE workspace_id=? ORDER BY account_id",
            (workspace_id,))]
