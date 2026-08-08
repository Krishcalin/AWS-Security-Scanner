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

import aws_authn
import cnapp_authn

# Imported at MODULE level, not inside the route factories. FastAPI resolves a
# handler's annotations with `get_type_hints` against the module namespace, so a
# `Request`/`Response` imported inside a function is invisible to it — the parameter
# silently degrades to a required QUERY parameter and every call 422s. That failure
# looks like a client bug, not an import-scope bug, which is why it is worth a note.
from fastapi import Body, Header, HTTPException, Request, Response

from cnapp_api import Principal

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
