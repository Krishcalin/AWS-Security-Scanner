"""
Local authentication store — users and sessions over the existing Backend.

`aws_authn` owns the cryptography and knows nothing about storage; this module owns
the storage and knows nothing about HTTP. The HTTP layer (`cnapp_api`) turns a
resolved username into a `Principal` using the directory that already exists —
`workspace_members` and `platform_admins` — so logging in adds an identity check and
changes NOTHING about what any identity is permitted to do.

────────────────────────────────────────────────────────────────────────────────
WHY LOGIN IS A PROVIDER, NOT A REPLACEMENT FOR THE IdP HOOK
────────────────────────────────────────────────────────────────────────────────
`cnapp_server.create_app_from_env` leaves `current_principal` unset and every route
403s, with the instruction that a real deployment MUST inject a hook mapping the
authenticated caller to a Principal. This module is one such hook — the built-in one,
for a self-hosted install with no IdP in front of it. The contract is unchanged: an
operator who fronts OverWatch with their own IdP injects theirs instead and never
creates a local user.

That is why local auth is not wired into `create_app_from_env` by default. The
fail-closed posture holds; `create_app_with_local_auth` is an explicit opt-in.

────────────────────────────────────────────────────────────────────────────────
THE BOOTSTRAP PROBLEM, AND WHY THERE IS NO DEFAULT PASSWORD
────────────────────────────────────────────────────────────────────────────────
A fresh database has no users, and a console nobody can log into is useless. The two
common answers are both wrong:

  * A well-known default (`admin`/`admin`) is a published credential on every
    install that forgets to change it, which is most of them.
  * Auto-generating one and printing it to stdout puts a live credential in
    container logs, which are aggregated, shipped and retained.

So the first administrator comes from `OVERWATCH_BOOTSTRAP_USER` /
`OVERWATCH_BOOTSTRAP_PASSWORD`, applied ONCE against an empty user table and
ignored entirely thereafter. The operator chooses the secret, it never appears in a
log line, and re-running with the variables still set cannot silently reset a
password that has since been changed.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import aws_authn
import aws_qr
import aws_totp

#: How long a session survives without being re-issued. Twelve hours is a working
#: day: long enough not to interrupt an investigation, short enough that a forgotten
#: browser on a shared machine is not a standing grant.
SESSION_TTL_SECONDS = 12 * 3600

#: Sessions are extended on use, but never past this from first issue, so a
#: continuously-active session still forces a fresh authentication eventually.
SESSION_ABSOLUTE_MAX_SECONDS = 7 * 24 * 3600


class AuthError(Exception):
    """Authentication failed. Deliberately carries no detail about WHY."""


class SecondFactorRequired(Exception):
    """The password was correct and a TOTP code is still needed.

    A DISTINCT exception because this one IS safe to disclose: by the time it is
    raised the password has already been proven, so it tells nothing to anyone who
    could not already log in. `AuthError` stays undifferentiated.
    """


class UserStore:
    """Users and sessions. All timestamps are integer epoch seconds, matching every
    other table in this schema."""

    def __init__(self, backend, *, now=None):
        self._be = backend
        self._now = now or (lambda: int(time.time()))

    # ── users ────────────────────────────────────────────────────────────────
    def create_user(self, username: str, password: str, *, display_name: str = "",
                    must_change_password: bool = False) -> Dict[str, Any]:
        username = (username or "").strip().lower()
        if not username:
            raise ValueError("username is required")
        aws_authn.check_password_policy(password)
        now = self._now()
        self._be.upsert(
            "app_user",
            ["username", "password_hash", "display_name", "status",
             "must_change_password", "created_at", "updated_at", "last_login_at"],
            ["username"],
            ["password_hash", "display_name", "must_change_password", "updated_at"],
            (username, aws_authn.hash_password(password), display_name or username,
             "active", 1 if must_change_password else 0, now, now, None))
        return self.get_user(username)

    def create_new_user(self, username: str, password: str, *,
                        display_name: str = "") -> Dict[str, Any]:
        """Create a user that does not exist yet. REFUSES to overwrite one.

        WHY THIS EXISTS BESIDE `create_user`. That one is an UPSERT keyed on
        username, and usernames are instance-wide while workspaces are not — so
        a workspace admin "creating" a username that already belongs to another
        workspace's user would silently RESET THAT USER'S PASSWORD and hand
        control of their account across a tenant boundary.

        Bootstrapping still wants the upsert (`create_user` is called once
        against an empty table), so it is left alone. Everything reachable from
        an API uses this.
        """
        username = (username or "").strip().lower()
        if not username:
            raise ValueError("username is required")
        if self.get_user(username) is not None:
            raise ValueError(
                f"{username!r} already exists on this instance. Usernames are "
                "instance-wide; grant that user a role instead of recreating "
                "them.")
        return self.create_user(username, password, display_name=display_name,
                                must_change_password=True)

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        row = self._be.query_one(
            "SELECT username, password_hash, display_name, status, "
            "must_change_password, created_at, updated_at, last_login_at "
            "FROM app_user WHERE username=?", ((username or "").strip().lower(),))
        return dict(row) if row else None

    def list_users(self) -> List[Dict[str, Any]]:
        return [{k: v for k, v in dict(r).items() if k != "password_hash"}
                for r in self._be.query_all(
                    "SELECT username, display_name, status, must_change_password, "
                    "created_at, updated_at, last_login_at FROM app_user "
                    "ORDER BY username")]

    def user_count(self) -> int:
        row = self._be.query_one("SELECT COUNT(*) AS n FROM app_user")
        return int(dict(row)["n"]) if row else 0

    def set_password(self, username: str, password: str, *,
                     revoke_sessions: bool = True) -> None:
        """Change a password and, by default, kill every existing session for it.

        REVOKING THE OTHER SESSIONS IS THE POINT. A password is usually changed
        because it may be known to someone else; leaving that someone else's session
        alive makes the change theatre. The caller's own browser re-authenticates,
        which is a small cost for the guarantee.
        """
        aws_authn.check_password_policy(password)
        self._be.execute(
            "UPDATE app_user SET password_hash=?, must_change_password=0, updated_at=? "
            "WHERE username=?",
            (aws_authn.hash_password(password), self._now(),
             (username or "").strip().lower()))
        if revoke_sessions:
            self.close_all_sessions(username)

    def delete_user(self, username: str) -> None:
        """Remove an account and its sessions.

        Exists for ONE caller: rolling back a create whose role grant failed.
        Deliberately not exposed as an endpoint — disabling is the reversible
        operation an administrator wants, and a delete that removes the audit
        trail of who existed is not something a UI should offer casually.
        """
        username = (username or "").strip().lower()
        self.close_all_sessions(username)
        self._be.execute("DELETE FROM app_user WHERE username=?", (username,))

    def require_password_change(self, username: str) -> None:
        """Mark an account as holding a credential somebody else has seen.

        `set_password` CLEARS must_change_password, which is right when the
        owner set it and wrong when an administrator did. Rather than give
        set_password a flag every caller has to remember, the administrative
        path sets it back explicitly.
        """
        self._be.execute(
            "UPDATE app_user SET must_change_password=1, updated_at=? "
            "WHERE username=?",
            (self._now(), (username or "").strip().lower()))

    def set_status(self, username: str, status: str) -> None:
        if status not in ("active", "disabled"):
            raise ValueError(f"invalid status {status!r}")
        self._be.execute("UPDATE app_user SET status=?, updated_at=? WHERE username=?",
                         (status, self._now(), (username or "").strip().lower()))
        if status == "disabled":
            # Disabling an account that keeps a live session disables nothing.
            self.close_all_sessions(username)

    # ── authentication ───────────────────────────────────────────────────────
    def authenticate(self, username: str, password: str, *,
                     totp_code: str = "") -> str:
        """Verify a credential and open a session. Returns the bearer token.

        Every failure raises the SAME `AuthError` with the same message. A distinct
        "no such user" reply is a username oracle: it turns a login form into a
        directory an attacker can enumerate before they start guessing passwords.
        """
        user = self.get_user(username)
        if user is None or user.get("status") != "active":
            # Still burn the work factor. Returning early on an unknown user makes
            # "does this account exist" measurable on a stopwatch even when the
            # RESPONSE is identical.
            aws_authn.verify_password(password or "", aws_authn.hash_password("x" * 16))
            raise AuthError("invalid username or password")
        if not aws_authn.verify_password(password or "", user["password_hash"]):
            raise AuthError("invalid username or password")

        # Password proven. If a second factor is enrolled it must be satisfied
        # BEFORE any session exists -- an early session would be a complete
        # login that merely looks unfinished to the UI.
        if self.totp_enabled(user["username"]):
            if not totp_code:
                raise SecondFactorRequired(user["username"])
            if not self.verify_totp(user["username"], totp_code):
                raise AuthError("invalid username or password")

        now = self._now()
        if aws_authn.needs_rehash(user["password_hash"]):
            # Free upgrade on a correct password: raising PBKDF2_ITERATIONS later
            # would otherwise only ever protect accounts created after the change.
            self._be.execute(
                "UPDATE app_user SET password_hash=?, updated_at=? WHERE username=?",
                (aws_authn.hash_password(password), now, user["username"]))
        self._be.execute("UPDATE app_user SET last_login_at=? WHERE username=?",
                         (now, user["username"]))
        return self.open_session(user["username"])

    # -- second factor (TOTP) ------------------------------------------------
    def totp_state(self, username):
        row = self._be.query_one(
            "SELECT username, secret, enabled, last_counter, enrolled_at "
            "FROM app_totp WHERE username=?", ((username or "").strip().lower(),))
        return dict(row) if row else None

    def totp_enabled(self, username) -> bool:
        st = self.totp_state(username)
        return bool(st and st.get("enabled"))

    def begin_totp_enrolment(self, username):
        """Mint a secret and return it with its provisioning URI. NOT yet active.

        Enrolment is two-step on purpose: this hands out a secret, and `confirm`
        only switches the factor on once the user has typed back a code it
        generates. A one-step enable locks out anyone whose transcription was wrong
        or whose phone clock is skewed -- and the person most likely to be hit is the
        first administrator, who has nobody to ask for a reset.
        """
        username = (username or "").strip().lower()
        secret, now = aws_totp.new_secret(), self._now()
        self._be.upsert(
            "app_totp",
            ["username", "secret", "enabled", "last_counter", "enrolled_at",
             "created_at", "updated_at"],
            ["username"], ["secret", "enabled", "last_counter", "updated_at"],
            (username, secret, 0, -1, None, now, now))
        uri = aws_totp.provisioning_uri(secret, username)
        # The QR carries no attacker-controlled text: `to_svg` emits only <rect>
        # elements at numeric coordinates, so the URI (which contains the username)
        # never reaches the markup. That is what makes it safe for the console to
        # inline.
        try:
            qr = aws_qr.to_svg(uri)
        except Exception:
            qr = ""                       # a QR failure must not block enrolment
        return {"secret": secret,
                "formatted_secret": aws_totp.format_secret(secret),
                "uri": uri, "qr_svg": qr}

    def confirm_totp_enrolment(self, username, code):
        """Verify a code from the pending secret, switch the factor on, and return
        freshly-minted recovery codes. They are shown ONCE -- only fingerprints are
        stored, so they can never be re-displayed, only replaced."""
        st = self.totp_state(username)
        if st is None:
            raise AuthError("no enrolment in progress")
        counter = aws_totp.verify(st["secret"], code,
                                  after_counter=int(st.get("last_counter", -1)))
        if counter is None:
            raise AuthError("that code is not valid")
        now = self._now()
        self._be.execute(
            "UPDATE app_totp SET enabled=1, last_counter=?, enrolled_at=?, updated_at=? "
            "WHERE username=?", (counter, now, now, (username or "").strip().lower()))
        return self.reset_recovery_codes(username)

    def verify_totp(self, username, code) -> bool:
        """Check a code AND consume its counter, so it cannot be replayed. Falls
        back to a recovery code. Both paths are single-use -- that is exactly what
        `last_counter` and `used_at` are for."""
        st = self.totp_state(username)
        if not st or not st.get("enabled"):
            return False
        counter = aws_totp.verify(st["secret"], code,
                                  after_counter=int(st.get("last_counter", -1)))
        if counter is not None:
            self._be.execute(
                "UPDATE app_totp SET last_counter=?, updated_at=? WHERE username=?",
                (counter, self._now(), st["username"]))
            return True
        return self._consume_recovery_code(username, code)

    def disable_totp(self, username) -> None:
        username = (username or "").strip().lower()
        self._be.execute("DELETE FROM app_totp WHERE username=?", (username,))
        self._be.execute("DELETE FROM app_recovery_code WHERE username=?", (username,))

    # -- recovery codes ------------------------------------------------------
    def reset_recovery_codes(self, username):
        username = (username or "").strip().lower()
        self._be.execute("DELETE FROM app_recovery_code WHERE username=?", (username,))
        codes, now = aws_totp.new_recovery_codes(), self._now()
        for code in codes:
            self._be.upsert(
                "app_recovery_code",
                ["fingerprint", "username", "used_at", "created_at"],
                ["fingerprint"], [],
                (aws_totp.recovery_fingerprint(code), username, None, now))
        return codes

    def unused_recovery_code_count(self, username) -> int:
        row = self._be.query_one(
            "SELECT COUNT(*) AS n FROM app_recovery_code "
            "WHERE username=? AND used_at IS NULL",
            ((username or "").strip().lower(),))
        return int(dict(row)["n"]) if row else 0

    def _consume_recovery_code(self, username, code) -> bool:
        row = self._be.query_one(
            "SELECT fingerprint FROM app_recovery_code "
            "WHERE username=? AND fingerprint=? AND used_at IS NULL",
            ((username or "").strip().lower(), aws_totp.recovery_fingerprint(code)))
        if row is None:
            return False
        self._be.execute("UPDATE app_recovery_code SET used_at=? WHERE fingerprint=?",
                         (self._now(), dict(row)["fingerprint"]))
        return True

    # ── sessions ─────────────────────────────────────────────────────────────
    def open_session(self, username: str, *, ttl: int = SESSION_TTL_SECONDS) -> str:
        token = aws_authn.new_session_token()
        now = self._now()
        self._be.upsert(
            "app_session",
            ["fingerprint", "username", "created_at", "expires_at", "last_seen_at"],
            ["fingerprint"], ["expires_at", "last_seen_at"],
            (aws_authn.token_fingerprint(token), (username or "").strip().lower(),
             now, now + int(ttl), now))
        return token

    def resolve_session(self, token: str) -> Optional[str]:
        """Username for a live session token, or None. Extends the sliding window.

        The lookup is BY FINGERPRINT, so the presented token is never compared
        against stored material in the database — there is no stored material to
        compare it against.
        """
        if not token:
            return None
        now = self._now()
        row = self._be.query_one(
            "SELECT s.username AS username, s.expires_at AS expires_at, "
            "s.created_at AS created_at, u.status AS status "
            "FROM app_session s JOIN app_user u ON u.username = s.username "
            "WHERE s.fingerprint=?", (aws_authn.token_fingerprint(token),))
        if row is None:
            return None
        rec = dict(row)
        if rec.get("status") != "active":
            return None                       # disabled mid-session ⇒ dead immediately
        if int(rec["expires_at"]) <= now:
            return None
        if now - int(rec["created_at"]) > SESSION_ABSOLUTE_MAX_SECONDS:
            return None                       # sliding window cannot outrun this
        self._be.execute(
            "UPDATE app_session SET last_seen_at=?, expires_at=? WHERE fingerprint=?",
            (now, now + SESSION_TTL_SECONDS, aws_authn.token_fingerprint(token)))
        return rec["username"]

    def close_session(self, token: str) -> None:
        self._be.execute("DELETE FROM app_session WHERE fingerprint=?",
                         (aws_authn.token_fingerprint(token or ""),))

    def close_all_sessions(self, username: str) -> None:
        self._be.execute("DELETE FROM app_session WHERE username=?",
                         ((username or "").strip().lower(),))

    def purge_expired(self) -> int:
        """Housekeeping. Expired rows are already refused by `resolve_session`, so
        this is hygiene rather than a security control."""
        now = self._now()
        self._be.execute("DELETE FROM app_session WHERE expires_at <= ?", (now,))
        return 0


#: Groups of five from an unambiguous alphabet — no O/0, no l/1/I. A credential
#: an administrator reads aloud or copies out of a terminal should not fail on a
#: character nobody can tell apart.
_PW_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"


def issue_initial_password(groups: int = 4, group_len: int = 5) -> str:
    """A one-time credential for a new account.

    GENERATED, NEVER CHOSEN BY THE ADMINISTRATOR. An administrator picking
    passwords picks a house pattern, and a house pattern means every account on
    the instance shares a guessable prefix. It is still a credential somebody
    else has seen, which is why every account created with it carries
    `must_change_password` and is not the user's own account until they have
    changed it.
    """
    import secrets

    return "-".join("".join(secrets.choice(_PW_ALPHABET)
                            for _ in range(group_len))
                    for _ in range(groups))


def bootstrap_admin(store: UserStore, workspaces=None, *,
                    env: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Create the first administrator from the environment, ONCE, on an empty table.

    Returns the username created, or None when it did not apply — which is the normal
    case on every start after the first. Never logs the password. See the module
    docstring for why there is no default credential and nothing is printed.
    """
    env = env if env is not None else os.environ
    username = (env.get("OVERWATCH_BOOTSTRAP_USER") or "").strip().lower()
    password = env.get("OVERWATCH_BOOTSTRAP_PASSWORD") or ""
    if not username or not password:
        return None
    if store.user_count() > 0:
        # Deliberately NOT an upsert. If this ran on a populated table, leaving the
        # variables set in a manifest would silently reset the admin password on
        # every restart — and would hand it back to anyone who had once seen them.
        return None
    try:
        aws_authn.check_password_policy(password)
    except aws_authn.WeakPassword:
        return None
    store.create_user(username, password, display_name=username)
    if workspaces is not None:
        # The first user is a platform admin: superadmin acts as admin in every
        # workspace, so a single-tenant install needs no membership rows at all.
        try:
            workspaces.add_platform_admin(username, now_epoch=int(time.time()))
        except Exception:
            pass                              # a directory hiccup must not block login
    return username
