"""
HTTP surface for local authentication: the `/api/auth/*` routes and the
`current_principal` dependency that turns a session cookie into a `Principal`.

Kept out of `cnapp_api.py` on purpose. That file is the API contract and is heavily
tested; authentication is a pluggable provider, and an operator fronting OverWatch
with their own IdP replaces this module wholesale without touching the contract.

────────────────────────────────────────────────────────────────────────────────
THE PRINCIPAL IS RESOLVED FROM THE DIRECTORY, NOT FROM THE SESSION
────────────────────────────────────────────────────────────────────────────────
A session says WHO you are. What you may do is read fresh, on every request, from
`workspace_members` / `platform_admins`. Nothing about a role is copied into the
session or the cookie.

That is what makes a permission change take effect immediately. If the role were
baked into the cookie at login, revoking someone's admin rights would leave them
admin until their session happened to expire — up to twelve hours of access that the
audit trail would show as legitimate.

COOKIE FLAGS. HttpOnly (JavaScript cannot read the token, so an XSS bug in the
console cannot exfiltrate a session), SameSite=Lax (a cross-site POST cannot carry
it, which is CSRF cover for the state-changing routes), Path=/ and Secure whenever
the request arrived over TLS. Secure is conditional rather than always-on precisely
so the local http://127.0.0.1 stack still works — a hardcoded Secure flag would make
the cookie silently vanish there and the login would appear to succeed and do
nothing.
"""
from typing import Optional

from engine import aws_authn
from hub import cnapp_authn

# Imported at MODULE level, not inside the route factories. FastAPI resolves a
# handler's annotations with `get_type_hints` against the module namespace, so a
# `Request`/`Response` imported inside a function is invisible to it — the parameter
# silently degrades to a required QUERY parameter and every call 422s. That failure
# looks like a client bug, not an import-scope bug, which is why it is worth a note.
from fastapi import Body, Header, HTTPException, Request, Response

from hub import cnapp_workspace
import time
from hub.cnapp_api import Principal

SESSION_COOKIE = "overwatch_session"


def session_principal_dependency(store, workspaces):
    """Build the `current_principal` dependency for `cnapp_api.create_app`.

    Returns an EMPTY Principal when there is no valid session. Empty memberships and
    not-superadmin is deny-all, so an unauthenticated request falls back to exactly
    the fail-closed behaviour the server has without any auth wired.
    """
    def current_principal(cookie: Optional[str] = Header(default=None, alias="Cookie")):
        token = aws_authn.split_cookie(cookie or "", SESSION_COOKIE)
        username = store.resolve_session(token) if token else None
        if not username:
            return Principal()
        return Principal(
            subject=username,
            memberships=workspaces.principal_memberships(username),
            is_superadmin=workspaces.is_platform_admin(username),
        )

    return current_principal


def add_auth_routes(api, store, workspaces):
    """Mount `/auth/login`, `/auth/logout`, `/auth/me` and `/auth/password` on the API
    sub-app (so they serve at `/api/auth/...`)."""
    def _principal(cookie: Optional[str]) -> Principal:
        username = store.resolve_session(
            aws_authn.split_cookie(cookie or "", SESSION_COOKIE) or "")
        if not username:
            return Principal()
        return Principal(subject=username,
                         memberships=workspaces.principal_memberships(username),
                         is_superadmin=workspaces.is_platform_admin(username))


    # ── user administration ──────────────────────────────────────────────────
    # THE PIECE THAT MAKES THE RBAC USABLE. Before this, a role could be granted
    # to a principal string and that principal had no way to sign in: there was
    # no endpoint that created a local user at all, and bootstrap_admin runs
    # once against an empty table. Authorisation was complete and identity was
    # a dead end.
    #
    # AUTHORISED BY WORKSPACE ADMIN, NOT PLATFORM ADMIN. A workspace admin has
    # to be able to onboard their own colleagues or the role model is decorative
    # — but usernames are INSTANCE-WIDE while workspaces are not, so the
    # dangerous move is creating a username that already belongs to somebody
    # else's tenant. `create_new_user` refuses that outright rather than
    # upserting, which is what `create_user` would have done: silently resetting
    # another workspace's user's password.

    def _require_ws_admin(cookie: Optional[str], workspace_id: str) -> Principal:
        principal = _principal(cookie)
        if not principal.subject:
            raise HTTPException(status_code=401, detail="not signed in")
        if not (principal.is_superadmin
                or principal.role_in(workspace_id) == "admin"):
            raise HTTPException(status_code=403,
                                detail="requires workspace admin")
        return principal

    @api.get("/auth/users")
    def list_users(cookie: Optional[str] = Header(default=None, alias="Cookie"),
                   workspace_id: str = "ws-default"):
        """Local accounts, with the role each holds in this workspace.

        Joined here rather than left to the console: a user list without roles
        and a role list without accounts are the two halves that did not meet,
        and showing them apart is how somebody grants a role to a principal who
        cannot sign in.
        """
        _require_ws_admin(cookie, workspace_id)
        roles = {}
        for member in workspaces.list_members(workspace_id):
            roles[str(member.get("principal", "")).lower()] = member.get("role")
        out = []
        for user in store.list_users():
            row = dict(user)
            row["role"] = roles.get(str(user.get("username", "")).lower())
            out.append(row)
        return out

    @api.post("/auth/users", status_code=201)
    def create_user(response: Response,
                    cookie: Optional[str] = Header(default=None, alias="Cookie"),
                    body: dict = Body(...)):
        """Create a local account AND grant it a role, in one operation.

        ONE OPERATION ON PURPOSE. Two calls can half-succeed, and both halves
        fail badly on their own: an account with no role can sign in and see
        nothing, and a role with no account is an authorisation grant to
        somebody who cannot arrive. `add "Priya as an analyst"` is one act, so
        it is one endpoint.

        The password is GENERATED and returned exactly once. It is never stored
        in the clear and never logged, and the account carries
        must_change_password so it is not the user's own account until they
        have changed it.
        """
        workspace_id = str(body.get("workspace_id") or "ws-default").strip()
        actor = _require_ws_admin(cookie, workspace_id)

        username = str(body.get("username") or "").strip().lower()
        role = str(body.get("role") or "auditor").strip()
        display_name = str(body.get("display_name") or "").strip()
        if not username:
            raise HTTPException(status_code=400, detail="a username is required")
        if role not in cnapp_workspace.ASSIGNABLE_ROLES:
            raise HTTPException(
                status_code=400,
                detail=f"unknown role {role!r}; expected one of "
                       f"{', '.join(cnapp_workspace.ASSIGNABLE_ROLES)}")

        password = cnapp_authn.issue_initial_password()
        try:
            store.create_new_user(username, password, display_name=display_name)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

        try:
            workspaces.add_member(workspace_id, username, role=role,
                                  added_by=actor.subject,
                                  now_epoch=int(time.time()))
        except Exception as exc:                              # noqa: BLE001
            # ROLL THE ACCOUNT BACK. There is no transaction spanning the two
            # stores, and the half-state is the worse one: an account with no
            # role can sign in and see nothing, and the operator's obvious
            # retry then hits the duplicate-username refusal and reads as a
            # different fault entirely. Undoing leaves them where they started.
            try:
                store.delete_user(username)
            except Exception:                                 # noqa: BLE001
                raise HTTPException(
                    status_code=500,
                    detail=(f"the account {username!r} was created, the {role} "
                            f"role could not be granted ({exc}), AND the "
                            f"account could not be removed. Grant the role "
                            f"from Roles & Access, or disable the account."))
            raise HTTPException(
                status_code=500,
                detail=(f"the {role} role could not be granted ({exc}); "
                        f"the account {username!r} was rolled back with it. "
                        f"Nothing was created."))
        return {"username": username, "role": role,
                "workspace_id": workspace_id,
                "password": password,
                "must_change_password": True,
                "note": ("This password is shown once and is not recoverable. "
                         "The account is locked to the change form until its "
                         "owner picks their own.")}

    @api.post("/auth/users/{username}/status")
    def set_user_status(username: str,
                        cookie: Optional[str] = Header(default=None, alias="Cookie"),
                        body: dict = Body(...)):
        """Enable or disable an account. Disabling closes its sessions."""
        workspace_id = str(body.get("workspace_id") or "ws-default").strip()
        actor = _require_ws_admin(cookie, workspace_id)
        status = str(body.get("status") or "").strip()
        if status not in ("active", "disabled"):
            raise HTTPException(status_code=400,
                                detail="status must be active or disabled")
        if username.strip().lower() == actor.subject and status == "disabled":
            # The API would allow it. The result is an administrator who cannot
            # sign in to undo it.
            raise HTTPException(status_code=400,
                                detail="you cannot disable your own account")
        if store.get_user(username) is None:
            raise HTTPException(status_code=404, detail="no such user")
        store.set_status(username, status)
        return {"username": username.strip().lower(), "status": status}

    @api.post("/auth/users/{username}/password")
    def reset_user_password(username: str,
                            cookie: Optional[str] = Header(default=None, alias="Cookie"),
                            body: dict = Body(default=None)):
        """Issue a new one-time password. Every session for it is revoked.

        Revoking is the point: a password is reset because it may be known to
        somebody else, and leaving that somebody's session alive makes the reset
        theatre.
        """
        workspace_id = str((body or {}).get("workspace_id") or "ws-default").strip()
        _require_ws_admin(cookie, workspace_id)
        if store.get_user(username) is None:
            raise HTTPException(status_code=404, detail="no such user")
        password = cnapp_authn.issue_initial_password()
        store.set_password(username, password)
        # set_password clears must_change_password, so put it back: this is a
        # credential an administrator has seen.
        store.require_password_change(username)
        return {"username": username.strip().lower(), "password": password,
                "must_change_password": True}

    @api.post("/auth/login")
    def login(request: Request, response: Response, body: dict = Body(...)):
        try:
            token = store.authenticate(str(body.get("username") or ""),
                                       str(body.get("password") or ""),
                                       totp_code=str(body.get("totp_code") or ""))
        except cnapp_authn.SecondFactorRequired:
            # A DIFFERENT reply, and safe to give: the password has already been
            # proven correct, so this discloses nothing to anyone who could not
            # already log in. 401 (not 200) because no session exists yet — a 200
            # here would let a careless client treat a half-finished login as done.
            raise HTTPException(status_code=401, detail={
                "error": "totp_required",
                "message": "Enter the 6-digit code from your authenticator app."})
        except cnapp_authn.AuthError:
            # 401 with the store's single undifferentiated message. Never echo the
            # username back: a reflected value is one more thing a login page can be
            # tricked into rendering. A WRONG TOTP CODE lands here too, deliberately
            # — "password right, code wrong" would confirm the password to someone
            # who has only guessed it.
            raise HTTPException(status_code=401,
                                detail="invalid username or password")
        response.set_cookie(
            SESSION_COOKIE, token,
            httponly=True, samesite="lax", path="/",
            # Only when the request actually arrived over TLS — see the module
            # docstring for why this is not unconditional.
            secure=(request.url.scheme == "https"),
            max_age=cnapp_authn.SESSION_TTL_SECONDS,
        )
        user = store.get_user(str(body.get("username") or "")) or {}
        p = _principal(f"{SESSION_COOKIE}={token}")
        return {"username": p.subject, "display_name": user.get("display_name", ""),
                "must_change_password": bool(user.get("must_change_password")),
                "is_superadmin": p.is_superadmin, "memberships": p.memberships}

    @api.post("/auth/logout")
    def logout(response: Response,
               cookie: Optional[str] = Header(default=None, alias="Cookie")):
        token = aws_authn.split_cookie(cookie or "", SESSION_COOKIE)
        if token:
            store.close_session(token)        # server-side kill, not just a cleared cookie
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}

    @api.get("/auth/me")
    def me(cookie: Optional[str] = Header(default=None, alias="Cookie")):
        """Who am I? 401 when unauthenticated — this is what the SPA calls on load to
        decide whether to show the console or the login page."""
        p = _principal(cookie)
        if not p.subject:
            raise HTTPException(status_code=401, detail="not authenticated")
        user = store.get_user(p.subject) or {}
        return {"username": p.subject, "display_name": user.get("display_name", ""),
                "must_change_password": bool(user.get("must_change_password")),
                "is_superadmin": p.is_superadmin, "memberships": p.memberships}

    @api.post("/auth/password")
    def change_password(body: dict = Body(...)):
        """Change a password using CREDENTIALS, not a session.

        Deliberately not session-authenticated, because the change-password form
        lives on the sign-in screen: the common reason to change a password is that
        you have been handed a temporary one and cannot get in with it yet. Asking
        for a session first would make the feature unreachable exactly when it is
        needed.

        The security is unchanged either way — the caller proves the CURRENT
        password and, where enrolled, the second factor. A live session was never
        the thing protecting this: an unattended browser would have been enough to
        lock the real owner out permanently.
        """
        username = str(body.get("username") or "")
        try:
            # Full re-authentication, second factor included. This is the whole
            # check; everything below it is bookkeeping.
            store.authenticate(username, str(body.get("current_password") or ""),
                               totp_code=str(body.get("totp_code") or ""))
        except cnapp_authn.SecondFactorRequired:
            raise HTTPException(status_code=401, detail={
                "error": "totp_required",
                "message": "Enter the 6-digit code from your authenticator app."})
        except cnapp_authn.AuthError:
            raise HTTPException(status_code=401,
                                detail="invalid username or password")
        try:
            store.set_password(username, str(body.get("new_password") or ""))
        except aws_authn.WeakPassword as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        # set_password revoked every session for this user, including the one that
        # authenticate() just opened. That is the point — see UserStore.set_password.
        return {"ok": True, "reauthenticate": True}

    # ── second-factor enrolment (authenticated) ──────────────────────────────
    @api.get("/auth/totp/status")
    def totp_status(cookie: Optional[str] = Header(default=None, alias="Cookie")):
        p = _principal(cookie)
        if not p.subject:
            raise HTTPException(status_code=401, detail="not authenticated")
        return {"enabled": store.totp_enabled(p.subject),
                "recovery_codes_left": store.unused_recovery_code_count(p.subject)}

    @api.post("/auth/totp/begin")
    def totp_begin(cookie: Optional[str] = Header(default=None, alias="Cookie")):
        """Mint a pending secret. The factor is NOT active until /confirm succeeds,
        so a mistyped secret or a skewed phone clock cannot lock anyone out."""
        p = _principal(cookie)
        if not p.subject:
            raise HTTPException(status_code=401, detail="not authenticated")
        if store.totp_enabled(p.subject):
            raise HTTPException(status_code=409, detail="already enrolled")
        return store.begin_totp_enrolment(p.subject)

    @api.post("/auth/totp/confirm")
    def totp_confirm(cookie: Optional[str] = Header(default=None, alias="Cookie"),
                     body: dict = Body(...)):
        """Prove the app is generating matching codes, then switch the factor on and
        return recovery codes. They are shown ONCE — only fingerprints are stored, so
        they cannot be redisplayed, only regenerated."""
        p = _principal(cookie)
        if not p.subject:
            raise HTTPException(status_code=401, detail="not authenticated")
        try:
            codes = store.confirm_totp_enrolment(p.subject,
                                                 str(body.get("totp_code") or ""))
        except cnapp_authn.AuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"enabled": True, "recovery_codes": codes}

    @api.post("/auth/totp/disable")
    def totp_disable(cookie: Optional[str] = Header(default=None, alias="Cookie"),
                     body: dict = Body(...)):
        """Turning the second factor OFF re-proves BOTH factors.

        A live session is not enough. Removing 2FA from a borrowed unlocked browser
        would otherwise be trivial, and it is the one action that makes every future
        login weaker.
        """
        p = _principal(cookie)
        if not p.subject:
            raise HTTPException(status_code=401, detail="not authenticated")
        try:
            store.authenticate(p.subject, str(body.get("password") or ""),
                               totp_code=str(body.get("totp_code") or ""))
        except (cnapp_authn.AuthError, cnapp_authn.SecondFactorRequired):
            raise HTTPException(status_code=403,
                                detail="password and current code are required")
        store.disable_totp(p.subject)
        return {"enabled": False}
