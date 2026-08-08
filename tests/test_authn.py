"""
Local authentication: credentials, sessions, and the Principal it resolves to.

WHAT THESE TESTS ARE REALLY DEFENDING
Adding a login to a product whose whole security model was "the API is fail-closed
and an IdP decides who you are" is the moment you can accidentally make everything
worse. Each test below is one specific way that happens: a username oracle, a role
frozen into a cookie, a session that outlives the password, a token sitting in a
table in the clear, or a gate that a network blip fails OPEN.
"""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_authn                                                    # noqa: E402
import cnapp_authn                                                  # noqa: E402
import cnapp_backend                                                # noqa: E402
import cnapp_workspace                                              # noqa: E402

GOOD = "correct-horse-battery"


def _stores():
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    be = cnapp_backend.backend_for(f"sqlite:///{db}")
    return cnapp_authn.UserStore(be), cnapp_workspace.WorkspaceStore(be), be


# ── credential core ──────────────────────────────────────────────────────────

def test_a_password_is_never_stored_in_a_recoverable_form():
    h = aws_authn.hash_password(GOOD)
    assert GOOD not in h
    assert h.startswith("pbkdf2_sha256$")
    assert aws_authn.verify_password(GOOD, h)
    assert not aws_authn.verify_password(GOOD + "x", h)


def test_the_same_password_hashes_differently_every_time():
    """Per-password salt. Identical hashes would let anyone with the table see which
    accounts share a password, and would make one rainbow table serve all of them."""
    assert aws_authn.hash_password(GOOD) != aws_authn.hash_password(GOOD)


def test_a_corrupt_hash_reads_as_a_wrong_password_not_a_crash():
    """A 500 on a malformed row distinguishes a real account from a broken one, and
    it does it before any password is even checked."""
    for junk in ("", "nonsense", "pbkdf2_sha256$notanint$aa$bb", "md5$1$aa$bb"):
        assert aws_authn.verify_password(GOOD, junk) is False


def test_raising_the_cost_upgrades_on_next_login_rather_than_locking_people_out():
    old = aws_authn.hash_password(GOOD, iterations=1000)
    assert aws_authn.verify_password(GOOD, old), "an old hash must still verify"
    assert aws_authn.needs_rehash(old), "but it must be flagged for upgrade"
    assert not aws_authn.needs_rehash(aws_authn.hash_password(GOOD))


def test_a_short_password_is_refused_at_the_source():
    with pytest.raises(aws_authn.WeakPassword):
        aws_authn.hash_password("short")


# ── the username oracle ──────────────────────────────────────────────────────

def test_an_unknown_user_and_a_wrong_password_are_indistinguishable():
    """THE ONE MOST WORTH KEEPING. A distinct "no such user" turns the login form
    into a directory: an attacker enumerates valid accounts first and only then
    starts guessing passwords, which is a different and much cheaper problem."""
    store, _ws, _be = _stores()
    store.create_user("real", GOOD)
    errs = []
    for user, pw in (("real", "wrong-password-x"), ("ghost", "wrong-password-x")):
        with pytest.raises(cnapp_authn.AuthError) as exc:
            store.authenticate(user, pw)
        errs.append(str(exc.value))
    assert errs[0] == errs[1], f"the two failures are distinguishable: {errs}"


# ── sessions ─────────────────────────────────────────────────────────────────

def test_the_session_table_holds_a_fingerprint_not_the_token():
    """A dump of app_session — a backup, a support export, a read-only SQL grant —
    must yield nothing anyone can present as a live session."""
    store, _ws, be = _stores()
    store.create_user("u", GOOD)
    token = store.authenticate("u", GOOD)
    assert be.query_one("SELECT 1 FROM app_session WHERE fingerprint=?", (token,)) is None
    assert be.query_one("SELECT 1 FROM app_session WHERE fingerprint=?",
                        (aws_authn.token_fingerprint(token),)) is not None


def test_changing_a_password_kills_every_existing_session():
    """A password is usually changed because somebody else may know it. Leaving
    their session alive makes the change theatre."""
    store, _ws, _be = _stores()
    store.create_user("u", GOOD)
    a, b = store.authenticate("u", GOOD), store.authenticate("u", GOOD)
    store.set_password("u", "a-brand-new-password")
    assert store.resolve_session(a) is None
    assert store.resolve_session(b) is None


def test_disabling_an_account_kills_its_live_session_immediately():
    store, _ws, _be = _stores()
    store.create_user("u", GOOD)
    token = store.authenticate("u", GOOD)
    store.set_status("u", "disabled")
    assert store.resolve_session(token) is None, \
        "a disabled account with a live session is not disabled"


def test_an_expired_session_does_not_resolve():
    clock = {"t": 1_000_000}
    store, _ws, be = _stores()
    store = cnapp_authn.UserStore(be, now=lambda: clock["t"])
    store.create_user("u", GOOD)
    token = store.authenticate("u", GOOD)
    assert store.resolve_session(token) == "u"
    clock["t"] += cnapp_authn.SESSION_TTL_SECONDS + 1
    assert store.resolve_session(token) is None


def test_a_sliding_session_cannot_outrun_the_absolute_cap():
    """Extending on use is a convenience; without a ceiling it is a permanent grant
    for anyone who keeps a tab open."""
    clock = {"t": 1_000_000}
    _s, _ws, be = _stores()
    store = cnapp_authn.UserStore(be, now=lambda: clock["t"])
    store.create_user("u", GOOD)
    token = store.authenticate("u", GOOD)
    for _ in range(30):                       # stay active for a month
        clock["t"] += cnapp_authn.SESSION_TTL_SECONDS // 2
        resolved = store.resolve_session(token)
        if resolved is None:
            break
    assert resolved is None, "a continuously-used session never forced re-auth"


# ── bootstrap ────────────────────────────────────────────────────────────────

def test_the_first_admin_comes_from_the_environment_and_only_once():
    store, ws, _be = _stores()
    env = {"OVERWATCH_BOOTSTRAP_USER": "admin", "OVERWATCH_BOOTSTRAP_PASSWORD": GOOD}
    assert cnapp_authn.bootstrap_admin(store, ws, env=env) == "admin"
    assert ws.is_platform_admin("admin")
    # Re-running with the variables still set must NOT reset a password that has
    # since been changed — otherwise leaving them in a manifest hands the account
    # back to anyone who ever saw them.
    store.set_password("admin", "operator-chosen-password")
    assert cnapp_authn.bootstrap_admin(store, ws, env=env) is None
    assert store.authenticate("admin", "operator-chosen-password")


def test_there_is_no_default_credential():
    """An empty environment creates nobody. A well-known default would be a
    published credential on every install that forgot to change it."""
    store, ws, _be = _stores()
    assert cnapp_authn.bootstrap_admin(store, ws, env={}) is None
    assert store.user_count() == 0


def test_a_weak_bootstrap_password_creates_nothing():
    store, ws, _be = _stores()
    assert cnapp_authn.bootstrap_admin(store, ws, env={
        "OVERWATCH_BOOTSTRAP_USER": "admin",
        "OVERWATCH_BOOTSTRAP_PASSWORD": "admin"}) is None
    assert store.user_count() == 0


# ── the HTTP surface ─────────────────────────────────────────────────────────

def _client():
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    import cnapp_server
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    os.environ.update({"CNAPP_DB_URL": f"sqlite:///{db}",
                       "OVERWATCH_BOOTSTRAP_USER": "admin",
                       "OVERWATCH_BOOTSTRAP_PASSWORD": GOOD})
    return TestClient(cnapp_server.create_app_with_local_auth())


def test_an_unauthenticated_request_is_still_denied_everything():
    """Adding a login must not weaken the fail-closed default: no session resolves
    to an empty Principal, which is deny-all."""
    c = _client()
    assert c.get("/api/accounts").status_code == 403
    assert c.get("/api/auth/me").status_code == 401


def test_signing_in_grants_access_and_signing_out_removes_it():
    c = _client()
    assert c.post("/api/auth/login",
                  json={"username": "admin", "password": GOOD}).status_code == 200
    assert c.get("/api/accounts").status_code == 200
    c.post("/api/auth/logout")
    assert c.get("/api/accounts").status_code == 403


def test_the_session_cookie_is_httponly():
    """JavaScript must not be able to read it: an XSS bug in the console would
    otherwise be a session-exfiltration bug."""
    c = _client()
    r = c.post("/api/auth/login", json={"username": "admin", "password": GOOD})
    cookie = r.headers.get("set-cookie", "")
    assert "httponly" in cookie.lower()
    assert "samesite=lax" in cookie.lower().replace(" ", "")


def test_a_bad_login_says_nothing_useful():
    c = _client()
    for body in ({"username": "admin", "password": "wrong-password-x"},
                 {"username": "ghost", "password": "wrong-password-x"}):
        r = c.post("/api/auth/login", json=body)
        assert r.status_code == 401
        assert r.json()["detail"] == "invalid username or password"


def test_changing_a_password_requires_the_current_one():
    """The route is CREDENTIAL-based, not session-based, so the form can live on the
    sign-in screen — the usual reason to change a password is that you were handed a
    temporary one and cannot get in with it yet. The check is unchanged: a live
    session was never what protected this, since an unattended browser would have
    been enough to lock the real owner out permanently."""
    c = _client()
    assert c.post("/api/auth/password",
                  json={"username": "admin", "current_password": "not-it",
                        "new_password": "a-new-long-password"}).status_code == 401


def test_changing_a_password_works_without_a_session():
    c = _client()
    assert c.post("/api/auth/password",
                  json={"username": "admin", "current_password": GOOD,
                        "new_password": "a-new-long-password"}).status_code == 200
    assert c.post("/api/auth/login",
                  json={"username": "admin",
                        "password": "a-new-long-password"}).status_code == 200
