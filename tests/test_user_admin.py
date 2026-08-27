"""Creating a local account and granting it a role — the half that was missing.

Before this, a role could be granted to any principal string and that principal
had no way to sign in: nothing exposed `UserStore.create_user`, and
`bootstrap_admin` runs once against an empty table. Authorisation was complete
and identity was a dead end, so the RBAC granted authority to people who could
not arrive.
"""
from __future__ import annotations

import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from store import aws_state
from hub import cnapp_api
from hub import cnapp_authn
from hub import cnapp_authn_api
from store import cnapp_backend
from hub import cnapp_registry
from hub import cnapp_service
from hub import cnapp_workspace

ROOT_USER, ROOT_PASSWORD = "root@example", "CorrectHorseBattery9"


@pytest.fixture()
def hub(monkeypatch):
    path = os.path.join(tempfile.mkdtemp(), "users.db")
    be = cnapp_backend.backend_for(f"sqlite:///{path}", check_same_thread=False)
    store = cnapp_authn.UserStore(be)
    workspaces = cnapp_workspace.WorkspaceStore(be)
    unavailable = lambda *a, **k: None                        # noqa: E731
    service = cnapp_service.PlatformService(
        registry=cnapp_registry.AccountRegistry(be),
        results=cnapp_service.InMemoryResultStore(),
        hub_role_arn="", cfn_template_url="",
        secret_writer=unavailable, secret_reader=unavailable,
        state=aws_state.StateStore(be), workspaces=workspaces)

    monkeypatch.setenv("OVERWATCH_BOOTSTRAP_USER", ROOT_USER)
    monkeypatch.setenv("OVERWATCH_BOOTSTRAP_PASSWORD", ROOT_PASSWORD)
    cnapp_authn.bootstrap_admin(store, workspaces)

    app = cnapp_api.create_hosted_app(
        service, static_dir=None,
        current_principal=cnapp_authn_api.session_principal_dependency(
            store, workspaces),
        configure_api=lambda api: cnapp_authn_api.add_auth_routes(
            api, store, workspaces))
    return app, store, workspaces


def _admin(app) -> TestClient:
    client = TestClient(app)
    assert client.post("/api/auth/login", json={
        "username": ROOT_USER, "password": ROOT_PASSWORD}).status_code == 200
    return client


# ── the whole point: an account AND a role, in one act ──────────────────────
def test_creating_a_person_grants_the_role_in_the_same_call(hub):
    app, _store, _ws = hub
    client = _admin(app)
    r = client.post("/api/auth/users", json={
        "username": "priya@acme.example", "role": "analyst",
        "display_name": "Priya"})
    assert r.status_code == 201
    body = r.json()
    assert body["role"] == "analyst"
    assert body["must_change_password"] is True
    assert body["password"]


def test_the_new_person_can_actually_sign_in(hub):
    """THE GAP THIS CLOSES. A role granted to somebody who cannot authenticate
    is authority handed to nobody."""
    app, _store, _ws = hub
    created = _admin(app).post("/api/auth/users", json={
        "username": "priya@acme.example", "role": "analyst"}).json()

    theirs = TestClient(app)
    assert theirs.post("/api/auth/login", json={
        "username": "priya@acme.example",
        "password": created["password"]}).status_code == 200
    me = theirs.get("/api/auth/me").json()
    assert me["memberships"] == {"ws-default": "analyst"}
    assert me["must_change_password"] is True


def test_the_new_person_has_exactly_their_role(hub):
    app, _store, _ws = hub
    created = _admin(app).post("/api/auth/users", json={
        "username": "priya@acme.example", "role": "analyst"}).json()
    theirs = TestClient(app)
    theirs.post("/api/auth/login", json={"username": "priya@acme.example",
                                         "password": created["password"]})
    assert theirs.get("/api/roles").status_code == 200          # can read
    # cannot create users: that is admin, and this is the boundary the whole
    # feature turns on.
    assert theirs.post("/api/auth/users", json={
        "username": "someone@else.example", "role": "admin"}).status_code == 403


# ── the instance-wide username hazard ───────────────────────────────────────
def test_creating_an_existing_username_is_refused_not_upserted(hub):
    """`UserStore.create_user` is an UPSERT keyed on username, and usernames are
    INSTANCE-WIDE while workspaces are not. Reusing it here would let one
    workspace's admin silently RESET another workspace's user's password and
    take their account."""
    app, _store, _ws = hub
    client = _admin(app)
    first = client.post("/api/auth/users", json={
        "username": "priya@acme.example", "role": "analyst"}).json()
    again = client.post("/api/auth/users", json={
        "username": "priya@acme.example", "role": "admin"})
    assert again.status_code == 409
    assert "already exists" in again.json()["detail"]

    # and the original password still works — nothing was overwritten
    theirs = TestClient(app)
    assert theirs.post("/api/auth/login", json={
        "username": "priya@acme.example",
        "password": first["password"]}).status_code == 200


def test_create_new_user_refuses_a_duplicate_at_the_store(hub):
    app, store, _ws = hub
    store.create_new_user("dup@example", "AVeryLongPassword12")
    with pytest.raises(ValueError):
        store.create_new_user("dup@example", "AnotherLongPassword12")


# ── half-states are rolled back, not left behind ────────────────────────────
def test_a_failed_grant_rolls_the_account_back(hub, monkeypatch):
    """No transaction spans the two stores, and the half-state is the worse
    one: an account with no role signs in and sees nothing, while the
    operator's obvious retry hits the duplicate-username refusal and reads as a
    different fault entirely."""
    app, store, workspaces = hub

    def explode(*_a, **_k):
        raise RuntimeError("workspace store is down")

    monkeypatch.setattr(workspaces, "add_member", explode)
    r = _admin(app).post("/api/auth/users", json={
        "username": "ghost@acme.example", "role": "analyst"})
    assert r.status_code == 500
    assert "rolled back" in r.json()["detail"]
    assert store.get_user("ghost@acme.example") is None


# ── validation and the self-lockout guards ──────────────────────────────────
def test_an_unknown_role_is_refused_with_the_options(hub):
    r = _admin(hub[0]).post("/api/auth/users", json={
        "username": "x@y.example", "role": "wizard"})
    assert r.status_code == 400
    assert "auditor" in r.json()["detail"]


def test_a_username_is_required(hub):
    assert _admin(hub[0]).post("/api/auth/users", json={
        "username": "  ", "role": "auditor"}).status_code == 400


def test_you_cannot_disable_your_own_account(hub):
    """The API would allow it and the result is an administrator who cannot
    sign in to undo it."""
    r = _admin(hub[0]).post(f"/api/auth/users/{ROOT_USER}/status",
                            json={"status": "disabled"})
    assert r.status_code == 400
    assert "your own account" in r.json()["detail"]


def test_disabling_someone_else_works_and_stops_their_login(hub):
    app, _store, _ws = hub
    client = _admin(app)
    created = client.post("/api/auth/users", json={
        "username": "priya@acme.example", "role": "auditor"}).json()
    assert client.post("/api/auth/users/priya@acme.example/status",
                       json={"status": "disabled"}).status_code == 200
    assert TestClient(app).post("/api/auth/login", json={
        "username": "priya@acme.example",
        "password": created["password"]}).status_code != 200


def test_status_must_be_active_or_disabled(hub):
    assert _admin(hub[0]).post(f"/api/auth/users/{ROOT_USER}/status",
                               json={"status": "banished"}).status_code == 400


def test_an_unknown_user_is_a_404_not_a_silent_success(hub):
    assert _admin(hub[0]).post("/api/auth/users/nobody@example/status",
                               json={"status": "disabled"}).status_code == 404


# ── password reset ──────────────────────────────────────────────────────────
def test_a_reset_issues_a_working_password_that_must_be_changed(hub):
    app, store, _ws = hub
    client = _admin(app)
    client.post("/api/auth/users", json={"username": "priya@acme.example",
                                         "role": "auditor"})
    reset = client.post("/api/auth/users/priya@acme.example/password").json()

    theirs = TestClient(app)
    assert theirs.post("/api/auth/login", json={
        "username": "priya@acme.example",
        "password": reset["password"]}).status_code == 200
    # An administrator has SEEN this credential, so it is not yet the user's
    # own account. set_password clears the flag; the admin path puts it back.
    assert theirs.get("/api/auth/me").json()["must_change_password"] is True


def test_a_reset_revokes_the_users_existing_sessions(hub):
    """A password is reset because it may be known to somebody else. Leaving
    that somebody's session alive makes the reset theatre."""
    app, _store, _ws = hub
    admin = _admin(app)
    created = admin.post("/api/auth/users", json={
        "username": "priya@acme.example", "role": "auditor"}).json()
    theirs = TestClient(app)
    theirs.post("/api/auth/login", json={"username": "priya@acme.example",
                                         "password": created["password"]})
    assert theirs.get("/api/auth/me").status_code == 200

    admin.post("/api/auth/users/priya@acme.example/password")
    assert theirs.get("/api/auth/me").status_code == 401


# ── who may do any of this ──────────────────────────────────────────────────
def test_an_unauthenticated_caller_is_refused(hub):
    client = TestClient(hub[0])
    assert client.get("/api/auth/users").status_code in (401, 403)
    assert client.post("/api/auth/users", json={
        "username": "x@y.example", "role": "admin"}).status_code in (401, 403)


def test_the_listing_shows_who_has_no_role_here(hub):
    """An account with no membership can sign in and see nothing. That is a
    real state and the screen should show it rather than hide the row."""
    app, store, _ws = hub
    store.create_new_user("orphan@acme.example", "AVeryLongPassword12")
    rows = {u["username"]: u["role"] for u in
            _admin(app).get("/api/auth/users").json()}
    assert rows["orphan@acme.example"] is None


def test_a_generated_password_satisfies_the_policy():
    """It is fed straight into create_user, which enforces the policy — a
    generator that produced a rejected password would fail at creation."""
    from engine import aws_authn

    for _ in range(20):
        aws_authn.check_password_policy(cnapp_authn.issue_initial_password())


def test_generated_passwords_avoid_ambiguous_characters():
    """A credential an administrator reads aloud or copies from a terminal
    should not fail on a character nobody can tell apart."""
    joined = "".join(cnapp_authn.issue_initial_password() for _ in range(40))
    for ambiguous in "O0lI1":
        assert ambiguous not in joined


def test_two_generated_passwords_differ():
    assert cnapp_authn.issue_initial_password() != cnapp_authn.issue_initial_password()
