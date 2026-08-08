"""
The second factor: RFC 6238 conformance, replay resistance, and recovery.

THE FIRST TEST IS THE ONE THAT MATTERS MOST. A hand-rolled OTP scheme that agrees
with itself passes every test you can write about it and still fails against
Microsoft Authenticator, where the user experiences it as "the app is broken and I
am locked out". RFC 6238 Appendix B publishes (time, expected code) pairs for a
known seed; matching them is proof of interoperability with every conforming app,
which no amount of round-tripping our own implementation could give.
"""
from __future__ import annotations

import base64
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_totp                                                     # noqa: E402
import cnapp_authn                                                  # noqa: E402
import cnapp_backend                                                # noqa: E402

GOOD = "correct-horse-battery"

#: RFC 6238 Appendix B, SHA-1, seed = ASCII "12345678901234567890", 8 digits.
RFC_SEED = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
RFC_VECTORS = [
    (59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130"),
]


def _store():
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    return cnapp_authn.UserStore(cnapp_backend.backend_for(f"sqlite:///{db}"))


# ── conformance ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("unix_time,expected", RFC_VECTORS)
def test_rfc6238_published_test_vectors(unix_time, expected):
    """Interoperability with every conforming authenticator, proven rather than
    assumed. If this fails, enrolment appears broken to real users."""
    assert aws_totp.code_at(RFC_SEED, unix_time // aws_totp.PERIOD, digits=8) == expected


def test_the_provisioning_uri_advertises_sha1():
    """Microsoft and Google Authenticator ignore `algorithm=` and assume SHA-1.
    Advertising SHA-256 produces codes that never match, and the failure looks like
    a broken product rather than a mismatched parameter."""
    uri = aws_totp.provisioning_uri("ABCDEFGH", "admin")
    assert uri.startswith("otpauth://totp/")
    assert "algorithm=SHA1" in uri and "digits=6" in uri and "period=30" in uri
    assert "secret=ABCDEFGH" in uri and "issuer=OverWatch" in uri


def test_a_typed_secret_survives_human_formatting():
    """People retype the setup key with spaces and in lower case."""
    secret = aws_totp.new_secret()
    spaced = aws_totp.format_secret(secret).lower()
    assert aws_totp.normalise_secret(spaced) == aws_totp.normalise_secret(secret)


def test_a_malformed_code_is_rejected_without_raising():
    secret = aws_totp.new_secret()
    for junk in ("", "12345", "1234567", "abcdef", "12 34 56", None):
        assert aws_totp.verify(secret, junk) is None


def test_clock_drift_is_tolerated_but_bounded():
    secret = aws_totp.new_secret()
    now = aws_totp.counter_at()
    assert aws_totp.verify(secret, aws_totp.code_at(secret, now - 1)) is not None
    assert aws_totp.verify(secret, aws_totp.code_at(secret, now + 1)) is not None
    # Two steps out is 90s of replay surface for a code read over a shoulder.
    assert aws_totp.verify(secret, aws_totp.code_at(secret, now + 5)) is None


# ── replay ───────────────────────────────────────────────────────────────────

def test_a_code_cannot_be_used_twice():
    """A TOTP code stays valid for its whole time step, so without recording the
    counter the same six digits work again for up to 90 seconds — long enough for
    someone who read them over a shoulder."""
    store = _store()
    store.create_user("u", GOOD)
    enrol = store.begin_totp_enrolment("u")
    store.confirm_totp_enrolment("u", aws_totp.code_now(enrol["secret"]))

    code = aws_totp.code_at(enrol["secret"], aws_totp.counter_at() + 1)
    assert store.authenticate("u", GOOD, totp_code=code)
    with pytest.raises(cnapp_authn.AuthError):
        store.authenticate("u", GOOD, totp_code=code)


def test_the_confirming_code_is_itself_consumed():
    """Enrolment spends a code like any other use; otherwise the code on screen at
    setup time remains a valid login for the rest of its window."""
    store = _store()
    store.create_user("u", GOOD)
    enrol = store.begin_totp_enrolment("u")
    code = aws_totp.code_now(enrol["secret"])
    store.confirm_totp_enrolment("u", code)
    with pytest.raises(cnapp_authn.AuthError):
        store.authenticate("u", GOOD, totp_code=code)


# ── enrolment ────────────────────────────────────────────────────────────────

def test_enrolment_is_not_active_until_a_code_is_proven():
    """Two-step on purpose. A one-step enable locks out anyone whose transcription
    was wrong or whose phone clock is skewed — most damagingly the first
    administrator, who has nobody to ask for a reset."""
    store = _store()
    store.create_user("u", GOOD)
    store.begin_totp_enrolment("u")
    assert store.totp_enabled("u") is False
    assert store.authenticate("u", GOOD), "a pending enrolment must not block login"


def test_a_wrong_confirmation_code_does_not_enable_anything():
    store = _store()
    store.create_user("u", GOOD)
    store.begin_totp_enrolment("u")
    with pytest.raises(cnapp_authn.AuthError):
        store.confirm_totp_enrolment("u", "000000")
    assert store.totp_enabled("u") is False


def test_password_alone_stops_working_once_enrolled():
    store = _store()
    store.create_user("u", GOOD)
    enrol = store.begin_totp_enrolment("u")
    store.confirm_totp_enrolment("u", aws_totp.code_now(enrol["secret"]))
    with pytest.raises(cnapp_authn.SecondFactorRequired):
        store.authenticate("u", GOOD)


def test_a_wrong_code_is_indistinguishable_from_a_wrong_password():
    """"Password right, code wrong" would confirm a guessed password to someone
    holding only half the credential."""
    store = _store()
    store.create_user("u", GOOD)
    enrol = store.begin_totp_enrolment("u")
    store.confirm_totp_enrolment("u", aws_totp.code_now(enrol["secret"]))
    with pytest.raises(cnapp_authn.AuthError) as bad_code:
        store.authenticate("u", GOOD, totp_code="000000")
    with pytest.raises(cnapp_authn.AuthError) as bad_pw:
        store.authenticate("u", "wrong-password-x", totp_code="000000")
    assert str(bad_code.value) == str(bad_pw.value)


# ── recovery ─────────────────────────────────────────────────────────────────

def test_recovery_codes_work_once_each():
    """Without these, a lost or wiped phone is a permanently locked account — and
    for the first administrator there is nobody to ask."""
    store = _store()
    store.create_user("u", GOOD)
    enrol = store.begin_totp_enrolment("u")
    codes = store.confirm_totp_enrolment("u", aws_totp.code_now(enrol["secret"]))
    assert len(codes) == aws_totp.RECOVERY_CODE_COUNT

    assert store.authenticate("u", GOOD, totp_code=codes[0])
    assert store.unused_recovery_code_count("u") == len(codes) - 1
    with pytest.raises(cnapp_authn.AuthError):
        store.authenticate("u", GOOD, totp_code=codes[0])


def test_recovery_codes_are_stored_only_as_fingerprints():
    store = _store()
    store.create_user("u", GOOD)
    enrol = store.begin_totp_enrolment("u")
    codes = store.confirm_totp_enrolment("u", aws_totp.code_now(enrol["secret"]))
    row = store._be.query_one(
        "SELECT 1 FROM app_recovery_code WHERE fingerprint=?", (codes[0],))
    assert row is None, "a recovery code is stored in the clear"


def test_disabling_the_factor_removes_its_secret_and_codes():
    store = _store()
    store.create_user("u", GOOD)
    enrol = store.begin_totp_enrolment("u")
    store.confirm_totp_enrolment("u", aws_totp.code_now(enrol["secret"]))
    store.disable_totp("u")
    assert store.totp_enabled("u") is False
    assert store.unused_recovery_code_count("u") == 0
    assert store.authenticate("u", GOOD), "password alone must work again"


# ── HTTP ─────────────────────────────────────────────────────────────────────

def _client():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    import cnapp_server
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    os.environ.update({"CNAPP_DB_URL": f"sqlite:///{db}",
                       "OVERWATCH_BOOTSTRAP_USER": "admin",
                       "OVERWATCH_BOOTSTRAP_PASSWORD": GOOD})
    return TestClient(cnapp_server.create_app_with_local_auth())


def _enrol(c):
    c.post("/api/auth/login", json={"username": "admin", "password": GOOD})
    begin = c.post("/api/auth/totp/begin").json()
    codes = c.post("/api/auth/totp/confirm",
                   json={"totp_code": aws_totp.code_now(begin["secret"])}
                   ).json()["recovery_codes"]
    c.post("/api/auth/logout")
    return begin["secret"], codes


def test_login_reports_that_a_second_factor_is_needed():
    """A distinct reply is safe HERE: the password has already been proven, so it
    discloses nothing to anyone who could not already sign in. The UI has to branch
    on it to show the code field at all."""
    c = _client()
    _enrol(c)
    r = c.post("/api/auth/login", json={"username": "admin", "password": GOOD})
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "totp_required"


def test_a_full_two_factor_login_grants_access():
    c = _client()
    secret, _codes = _enrol(c)
    code = aws_totp.code_at(secret, aws_totp.counter_at() + 1)
    assert c.post("/api/auth/login",
                  json={"username": "admin", "password": GOOD,
                        "totp_code": code}).status_code == 200
    assert c.get("/api/accounts").status_code == 200


def test_changing_a_password_needs_no_session_but_does_need_the_second_factor():
    """The form lives on the SIGN-IN screen, because the usual reason to change a
    password is that you were handed a temporary one and cannot get in yet."""
    c = _client()
    _secret, codes = _enrol(c)
    body = {"username": "admin", "current_password": GOOD,
            "new_password": "a-brand-new-password"}
    r = c.post("/api/auth/password", json=body)
    assert r.status_code == 401 and r.json()["detail"]["error"] == "totp_required"

    r = c.post("/api/auth/password", json={**body, "totp_code": codes[0]})
    assert r.status_code == 200
    assert c.post("/api/auth/login",
                  json={"username": "admin", "password": "a-brand-new-password",
                        "totp_code": codes[1]}).status_code == 200


def test_turning_the_factor_off_requires_both_factors():
    """A live session is not enough: removing 2FA from a borrowed unlocked browser
    would otherwise be trivial, and it weakens every future sign-in."""
    c = _client()
    secret, _codes = _enrol(c)
    code = aws_totp.code_at(secret, aws_totp.counter_at() + 1)
    c.post("/api/auth/login",
           json={"username": "admin", "password": GOOD, "totp_code": code})
    assert c.post("/api/auth/totp/disable", json={}).status_code == 403
    assert c.post("/api/auth/totp/disable",
                  json={"password": GOOD, "totp_code": "000000"}).status_code == 403
