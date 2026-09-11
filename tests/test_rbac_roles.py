"""The four-tier RBAC, and the bug that made the old one partly imaginary.

`ingest` was ranked in cnapp_api, allowed by cnapp_workspace.ACCEPTED_ROLES, and
REJECTED by workspace_members' CHECK constraint — so the tier was grantable in
code and impossible in the database. Nothing caught it because every RBAC test
built `Principal(memberships={ws: "ingest"})` in memory and never called
`add_member`, so the storage layer was never exercised.

Most of what follows exists so that cannot happen again: the roles are checked
against the DDL, not only against the rank table.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from store import aws_state
from store import aws_state_dialect
from hub import cnapp_api
from hub import cnapp_workspace as ws

from _layout import module_path


# ── the ordering is the authorisation model ─────────────────────────────────
def test_the_four_roles_are_strictly_ordered():
    """Each role is a superset of the one below. That is what makes a single
    rank comparison a sound test — a role able to do something a lower role
    cannot NOT do would need a capability set instead."""
    ranks = [ws.ROLE_RANK[r] for r in (ws.AUDITOR, ws.INGEST, ws.ANALYST, ws.ADMIN)]
    assert ranks == sorted(ranks) and len(set(ranks)) == 4


@pytest.mark.parametrize("role,can,cannot", [
    (ws.AUDITOR, [ws.AUDITOR], [ws.INGEST, ws.ANALYST, ws.ADMIN]),
    (ws.INGEST, [ws.AUDITOR, ws.INGEST], [ws.ANALYST, ws.ADMIN]),
    (ws.ANALYST, [ws.AUDITOR, ws.INGEST, ws.ANALYST], [ws.ADMIN]),
    (ws.ADMIN, [ws.AUDITOR, ws.INGEST, ws.ANALYST, ws.ADMIN], []),
])
def test_each_role_reaches_exactly_what_it_should(role, can, cannot):
    for target in can:
        assert cnapp_api._authorize(role, target), f"{role} should reach {target}"
    for target in cannot:
        assert not cnapp_api._authorize(role, target), f"{role} reached {target}"


def test_an_unknown_role_reaches_nothing():
    """Fail-closed. A typo in a membership row must deny, not default to read."""
    for target in ws.ASSIGNABLE_ROLES:
        assert not cnapp_api._authorize("wizard", target)


def test_the_api_rank_is_the_stores_rank():
    """They disagreed once and the tier that fell through the gap was
    ungrantable for a whole release."""
    assert cnapp_api._ROLE_RANK == ws.ROLE_RANK


# ── viewer stays readable, and stays out of the picker ──────────────────────
def test_viewer_and_auditor_are_the_same_authority():
    assert ws.ROLE_RANK[ws.LEGACY_VIEWER] == ws.ROLE_RANK[ws.AUDITOR]
    assert cnapp_api._authorize("viewer", ws.AUDITOR)
    assert cnapp_api._authorize("auditor", "viewer")


def test_viewer_is_accepted_on_write_but_never_offered():
    """Rows written before the rename exist, and rewriting a live authorisation
    column is not a migration worth risking. But nothing new should be granted
    that name."""
    assert ws.LEGACY_VIEWER in ws.ACCEPTED_ROLES
    assert ws.LEGACY_VIEWER not in ws.ASSIGNABLE_ROLES


def test_normalise_maps_viewer_to_auditor():
    assert ws.normalise_role("viewer") == ws.AUDITOR
    for role in ws.ASSIGNABLE_ROLES:
        assert ws.normalise_role(role) == role


# ── THE BUG: a role the code allows and the database refuses ────────────────
def _role_check_clause(source: str) -> str:
    """The CREATE TABLE for workspace_members, not the first mention of it.

    `source.index("workspace_members")` lands in a COMMENT — which is how this
    test first passed against the wrong text.
    """
    marker = "CREATE TABLE IF NOT EXISTS workspace_members"
    start = source.index(marker)
    return source[start:start + 700]


def test_every_assignable_role_is_permitted_by_the_ddl():
    """THE ONE THAT WOULD HAVE CAUGHT `ingest`.

    Read from the DDL text rather than from a list restated here — the two
    lists is exactly the shape that let them drift apart.
    """
    for source in (aws_state._DDL, "\n".join(aws_state_dialect.POSTGRES_DDL)):
        window = _role_check_clause(source)
        for role in ws.ASSIGNABLE_ROLES:
            assert f"'{role}'" in window, f"{role} missing from the role CHECK"


def test_the_legacy_name_is_still_permitted_by_the_ddl():
    """Existing rows hold it. A CHECK that excluded `viewer` would make every
    pre-rename membership unwritable on the next update."""
    for source in (aws_state._DDL, "\n".join(aws_state_dialect.POSTGRES_DDL)):
        assert "'viewer'" in _role_check_clause(source)


def test_a_role_stores_and_reads_back_on_sqlite(tmp_path):
    """Exercises the STORE, not the rank table. Every previous RBAC test built
    a Principal in memory, which is why the constraint bug survived."""
    from store import cnapp_backend

    be = cnapp_backend.backend_for(f"sqlite:///{tmp_path/'rbac.db'}")
    store = ws.WorkspaceStore(be)
    store.create_workspace("w1", name="n", slug="s", now_epoch=1)
    for role in ws.ASSIGNABLE_ROLES:
        store.add_member("w1", f"{role}@example", role=role, now_epoch=1)
    stored = {m["principal"]: m["role"] for m in store.list_members("w1")}
    assert set(stored.values()) == set(ws.ASSIGNABLE_ROLES)


def test_an_invalid_role_is_refused_before_it_reaches_the_database(tmp_path):
    from store import cnapp_backend

    be = cnapp_backend.backend_for(f"sqlite:///{tmp_path/'rbac2.db'}")
    store = ws.WorkspaceStore(be)
    store.create_workspace("w1", name="n", slug="s", now_epoch=1)
    with pytest.raises(ValueError):
        store.add_member("w1", "x@example", role="wizard", now_epoch=1)


# ── the migration, because CREATE TABLE IF NOT EXISTS never alters ──────────
def test_a_pre_v14_sqlite_database_is_detected_and_rebuilt():
    """`CREATE TABLE IF NOT EXISTS` is a no-op on an existing table, so a
    widened CHECK reaches a fresh database and no existing one. Without this
    the new roles would be grantable in code and impossible in the database —
    the same fault, one release later."""
    path = os.path.join(tempfile.mkdtemp(), "old.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY, name TEXT,"
        " slug TEXT, status TEXT, plan TEXT, created_at INTEGER,"
        " updated_at INTEGER);"
        "CREATE TABLE workspace_members(workspace_id TEXT NOT NULL,"
        " principal TEXT NOT NULL,"
        " role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('viewer','admin')),"
        " status TEXT NOT NULL DEFAULT 'active',"
        " added_by TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,"
        " PRIMARY KEY(workspace_id, principal));"
        "INSERT INTO workspaces VALUES('w1','n','s','active',NULL,1,1);"
        "INSERT INTO workspace_members VALUES('w1','old@x','admin','active',"
        "NULL,1,1);")
    conn.commit()

    assert aws_state_dialect.sqlite_needs_role_upgrade(conn) is True
    for statement in aws_state_dialect.SQLITE_ROLE_REBUILD:
        conn.execute(statement)
    conn.commit()

    assert aws_state_dialect.sqlite_needs_role_upgrade(conn) is False
    # The existing membership survived the rebuild — losing one would lock a
    # real administrator out of their own workspace.
    assert conn.execute(
        "SELECT role FROM workspace_members WHERE principal='old@x'"
    ).fetchone()[0] == "admin"
    conn.execute("INSERT INTO workspace_members VALUES('w1','a@x','analyst',"
                 "'active',NULL,1,1)")
    conn.close()


def test_the_upgrade_probe_reads_the_schema_not_a_version_number():
    """A database stamped v14 by a partly-applied migration would otherwise be
    skipped forever, and the symptom — a role that cannot be granted — is
    silent."""
    import inspect

    source = inspect.getsource(aws_state_dialect.sqlite_needs_role_upgrade)
    assert "sqlite_master" in source
    assert "user_version" not in source


def test_the_postgres_upgrade_is_idempotent():
    """`migrate()` runs on every open, so a DROP without IF EXISTS would fail
    the second time and take the whole startup with it."""
    joined = " ".join(aws_state_dialect.POSTGRES_ALTERS)
    assert "DROP CONSTRAINT IF EXISTS" in joined
    assert "ADD CONSTRAINT" in joined


# ── the analyst/admin boundary ──────────────────────────────────────────────
def _gate_of(route: str) -> str:
    """The role a route is gated on, read from the source."""
    import re

    with open(module_path("cnapp_api.py"), encoding="utf-8") as fh:
        source = fh.read()
    index = source.index(f'"{route}"')
    window = source[index:index + 600]
    found = re.search(r'(?:require|account_gate)\("([a-z]+)"\)', window)
    return found.group(1) if found else ""


@pytest.mark.parametrize("route", [
    "/accounts",                              # onboarding: what we are pointed at
    "/accounts/{account_id}/schedule",         # when we point at it
    "/connectors",                             # where findings are SENT
    "/accounts/{account_id}/notify",           # sending one
])
def test_configuration_and_outbound_stay_admin(route):
    """The analyst/admin line is not read-vs-write. Admin owns the two powers
    that reach outside the workspace: what the product is POINTED AT, and where
    its findings GO. A leaked analyst credential must not be able to exfiltrate
    findings to a webhook."""
    assert _gate_of(route) == ws.ADMIN, route


@pytest.mark.parametrize("route", [
    "/scans",                                  # costs compute, changes nothing
    "/accounts/{account_id}/vulns/refresh",
    "/accounts/{account_id}/detections/refresh",
])
def test_operating_the_product_is_analyst(route):
    assert _gate_of(route) == ws.ANALYST, route


def test_reading_is_auditor():
    for route in ("/accounts/{account_id}/findings", "/accounts/{account_id}/paths"):
        assert _gate_of(route) == ws.AUDITOR, route


def test_only_admin_can_grant_a_role():
    """The requirement the whole feature exists for: an admin creates other
    admins, and nobody below can."""
    source = open(module_path("cnapp_api.py"), encoding="utf-8").read()
    index = source.index('@app.post("/workspaces/{ws_id}/members"')
    assert "ws_admin_gate" in source[index:index + 400]


def test_the_roles_endpoint_offers_exactly_the_assignable_roles():
    """Served rather than hard-coded in the console, so a role added here
    cannot be missing from the picker used to grant it."""
    source = open(module_path("cnapp_api.py"), encoding="utf-8").read()
    assert '@app.get("/roles")' in source
    assert "ASSIGNABLE_ROLES" in source


def test_every_role_has_a_description():
    """It is shown to whoever is granting it. A role nobody can explain is one
    that gets granted by rank."""
    for role in ws.ASSIGNABLE_ROLES:
        assert ws.ROLE_DESCRIPTIONS.get(role, "").strip()


# ── offered ≠ grantable: the second copy of the role list ───────────────────
#
# GET /roles offered four roles. The store accepted five. The request model in
# between validated against a hand-written `^(viewer|ingest|admin)$`, so
# `auditor` and `analyst` 422'd — and the DDL test above could not see it,
# because it reads the DDL and the rank table, never the request schema.
#
# Everything above proved the role list agreed with itself in three places.
# The fourth was the one an administrator actually posts through.
_needs_fastapi = pytest.mark.skipif(
    not cnapp_api._HAVE_FASTAPI, reason="fastapi not installed")


def _members_client():
    """A real app over a real store — the 422 lived in the request model, so an
    in-memory Principal proves nothing about it."""
    from hub.cnapp_registry import AccountRegistry
    from hub.cnapp_service import InMemoryResultStore, PlatformService

    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    reg = AccountRegistry.open(":memory:")
    svc = PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="a",
        cfn_template_url="b", secret_writer=lambda a, v: "ssm://x",
        secret_reader=lambda r: "x", state=aws_state.StateStore(reg._be),
        workspaces=ws.WorkspaceStore(reg._be), clock=lambda: 5000)
    svc.create_workspace("w1", name="n")
    admin = cnapp_api.Principal(subject="a@x", memberships={"w1": ws.ADMIN})
    return TestClient(cnapp_api.create_app(svc, current_principal=lambda: admin))


def _granted_role(client, principal):
    return {m["principal"]: m["role"]
            for m in client.get("/workspaces/w1/members").json()}.get(principal)


@_needs_fastapi
@pytest.mark.parametrize("role", list(ws.ASSIGNABLE_ROLES))
def test_every_offered_role_is_actually_grantable_through_the_endpoint(role):
    """THE DEFECT. /roles advertised it, the store accepted it, and the POST
    refused it — so the picker listed two roles that could not be granted."""
    c = _members_client()
    r = c.post("/workspaces/w1/members", json={"principal": f"{role}@x", "role": role})
    assert r.status_code == 201, (
        f"{role} is offered by GET /roles but the members endpoint returned "
        f"{r.status_code}: {r.text}")
    assert _granted_role(c, f"{role}@x") == role, "granted a role other than the one asked for"


@_needs_fastapi
def test_the_legacy_name_is_still_accepted_by_the_endpoint():
    """A client that reads a pre-rename member's role and writes it back must
    not be rejected — the store still accepts it, so the API must too."""
    c = _members_client()
    r = c.post("/workspaces/w1/members",
               json={"principal": "old@x", "role": ws.LEGACY_VIEWER})
    assert r.status_code == 201, r.text


@_needs_fastapi
def test_an_unknown_role_is_still_refused_by_the_endpoint():
    """Widening the pattern must not have widened it to everything."""
    c = _members_client()
    assert c.post("/workspaces/w1/members",
                  json={"principal": "z@x", "role": "wizard"}).status_code == 422


@_needs_fastapi
def test_an_omitted_role_does_not_grant_the_deprecated_alias():
    """The default was `viewer`: the one name GET /roles documents as the thing
    new grants should not use. Storage does not normalise, so an unspecified
    role wrote a legacy row that would outlive the alias."""
    c = _members_client()
    assert c.post("/workspaces/w1/members", json={"principal": "d@x"}).status_code == 201
    stored = _granted_role(c, "d@x")
    assert stored == ws.AUDITOR, f"default grant stored {stored!r}"
    assert stored in ws.ASSIGNABLE_ROLES


def test_the_request_pattern_is_derived_rather_than_restated():
    """The structural guard. A fourth hand-kept copy is the only way this comes
    back, so pin that the model builds its pattern from the store's tuple.

    Reads the FIELDS, not the class text: the docstring quotes the old regex on
    purpose, and a guard that scanned prose would fire on its own explanation.
    """
    import ast

    source = open(module_path("cnapp_api.py"), encoding="utf-8").read()
    cls = next(n for n in ast.walk(ast.parse(source))
               if isinstance(n, ast.ClassDef) and n.name == "MemberReq")
    fields = "\n".join(
        ast.unparse(n) for n in cls.body
        if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)))
    assert "ACCEPTED_ROLES" in fields, (
        "MemberReq no longer derives its role pattern from cnapp_workspace")
    for role in ws.ACCEPTED_ROLES:
        assert f"|{role}" not in fields and f"({role}|" not in fields, (
            f"a role alternation naming {role!r} is written out in MemberReq again")


def test_the_accepted_set_is_the_offered_set_plus_only_legacy_aliases():
    """What makes deriving the pattern from ACCEPTED_ROLES safe: the extra names
    it carries are aliases, not a wider authority."""
    extra = set(ws.ACCEPTED_ROLES) - set(ws.ASSIGNABLE_ROLES)
    assert extra == {ws.LEGACY_VIEWER}
    for alias in extra:
        assert ws.normalise_role(alias) in ws.ASSIGNABLE_ROLES
