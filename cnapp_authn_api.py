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
                                       str(body.get("password") or ""))
        except cnapp_authn.AuthError:
            # 401 with the store's single undifferentiated message. Never echo the
            # username back: a reflected value is one more thing a login page can be
            # tricked into rendering.
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
    def change_password(cookie: Optional[str] = Header(default=None, alias="Cookie"),
                        body: dict = Body(...)):
        """Change your OWN password. Requires the current one — a live session is not
        sufficient, because an unattended browser would otherwise be enough to lock
        the real owner out permanently."""
        p = _principal(cookie)
        if not p.subject:
            raise HTTPException(status_code=401, detail="not authenticated")
        try:
            store.authenticate(p.subject, str(body.get("current_password") or ""))
        except cnapp_authn.AuthError:
            raise HTTPException(status_code=403, detail="current password is incorrect")
        try:
            store.set_password(p.subject, str(body.get("new_password") or ""))
        except aws_authn.WeakPassword as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        # set_password revoked every session INCLUDING this one, on purpose: see
        # UserStore.set_password. The client is expected to send the user to /login.
        return {"ok": True, "reauthenticate": True}
