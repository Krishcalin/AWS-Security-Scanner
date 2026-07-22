#!/usr/bin/env python3
"""
cnapp_api.py — FastAPI surface for the hosted CNAPP (Phase 8).

Thin HTTP layer: every route body is a one-line delegation to PlatformService
(cnapp_service.py), so there is NO business logic here and the whole backend is
testable through PlatformService without ever importing FastAPI. RBAC is a single
``require(min_role)`` dependency (viewer < admin): all reads are viewer; onboarding,
validation, and scan-triggering are admin and MUST sit behind the private hub
control plane (they wield hub credentials).

FastAPI/pydantic are optional deploy-time deps. Importing this module without them
raises a clear error rather than breaking test collection of the pure backend.
"""

from typing import List, Optional
# NOTE: deliberately NO `from __future__ import annotations` here — with PEP 563
# the route annotations become strings and FastAPI's get_type_hints cannot resolve
# the request models defined inside create_app(), which silently demotes the body
# to a query param (422). Real annotations keep the Pydantic body binding intact.

try:
    from fastapi import Depends, FastAPI, HTTPException, Query
    from pydantic import BaseModel, Field
    _HAVE_FASTAPI = True
except Exception as _e:                              # pragma: no cover - deploy-only
    _HAVE_FASTAPI = False
    _IMPORT_ERROR = _e


# ── RBAC ──────────────────────────────────────────────────────────────────────
_ROLE_RANK = {"viewer": 1, "admin": 2}


def _authorize(principal_role: str, min_role: str) -> bool:
    return _ROLE_RANK.get(principal_role, 0) >= _ROLE_RANK.get(min_role, 99)


def create_app(service, *, current_role=lambda: ""):
    """Build the FastAPI app bound to a PlatformService. ``current_role`` is the
    auth hook (swap for a real SSO/JWT dependency in production); it returns the
    caller's role for the RBAC gate.

    FAIL-CLOSED default: if left unset the hook returns "" (rank 0), which denies
    EVERY route — a forgotten auth wiring must never silently grant admin. A real
    deployment MUST pass a current_role that authenticates the caller."""
    if not _HAVE_FASTAPI:                            # pragma: no cover - deploy-only
        raise RuntimeError(
            "cnapp_api requires fastapi + pydantic (deploy-time): "
            f"{_IMPORT_ERROR}. The backend is fully usable via cnapp_service."
            " Install with: pip install 'fastapi[standard]'")

    app = FastAPI(title="KIZEN CNAPP", version="1.0.0",
                  description="Hosted multi-account CNAPP control plane")

    def require(min_role: str):
        def dep(role: str = Depends(current_role)):
            if not _authorize(role, min_role):
                raise HTTPException(status_code=403,
                                    detail=f"requires {min_role} role")
            return role
        return dep

    class OnboardReq(BaseModel):
        account_id: str = Field(pattern=r"^[0-9]{12}$")     # 422 on a malformed id
        region: str = "us-east-1"
        method: str = "single"
        alias: str = ""

    class ScanReq(BaseModel):
        account_ids: Optional[List[str]] = None
        all: bool = False

    # ── onboarding / validation (admin, private control plane) ────────────────
    @app.post("/accounts", status_code=201, dependencies=[Depends(require("admin"))])
    def onboard(body: OnboardReq):
        try:
            return service.init_onboarding(body.account_id, region=body.region,
                                           method=body.method, alias=body.alias)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/accounts/{account_id}/validate", dependencies=[Depends(require("admin"))])
    def validate(account_id: str, org_mode: bool = Query(False)):
        try:
            return service.validate_account(account_id, org_mode=org_mode)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # ── inventory (viewer) ────────────────────────────────────────────────────
    @app.get("/accounts", dependencies=[Depends(require("viewer"))])
    def list_accounts(onboarding_status: Optional[str] = None,
                      health: Optional[str] = None):
        return service.list_accounts(onboarding_status=onboarding_status, health=health)

    @app.get("/accounts/{account_id}", dependencies=[Depends(require("viewer"))])
    def get_account(account_id: str):
        a = service.get_account(account_id)
        if not a:
            raise HTTPException(status_code=404, detail="account not found")
        return a

    # ── scanning (admin) ──────────────────────────────────────────────────────
    @app.post("/scans", status_code=202, dependencies=[Depends(require("admin"))])
    def trigger_scan(body: ScanReq):
        return {"job_ids": service.trigger_scan(body.account_ids, all=body.all)}

    @app.get("/scans/{job_id}", dependencies=[Depends(require("viewer"))])
    def get_scan(job_id: str):
        j = service.get_scan_job(job_id)
        if not j:
            raise HTTPException(status_code=404, detail="job not found")
        return j

    # ── results (viewer) ──────────────────────────────────────────────────────
    @app.get("/accounts/{account_id}/issues", dependencies=[Depends(require("viewer"))])
    def issues(account_id: str, severity: Optional[str] = None,
               status: Optional[str] = None):
        return service.get_issues(account_id, severity=severity, status=status)

    @app.get("/accounts/{account_id}/paths", dependencies=[Depends(require("viewer"))])
    def paths(account_id: str):
        return service.get_paths(account_id)

    @app.get("/accounts/{account_id}/graph", dependencies=[Depends(require("viewer"))])
    def graph(account_id: str):
        return service.get_graph(account_id)

    @app.get("/accounts/{account_id}/summary", dependencies=[Depends(require("viewer"))])
    def account_summary(account_id: str):
        s = service.get_account_summary(account_id)
        if not s:
            raise HTTPException(status_code=404, detail="no scan results for account")
        return s

    @app.get("/org/overview", dependencies=[Depends(require("viewer"))])
    def org_overview():
        return service.org_overview()

    return app


def create_hosted_app(service, *, static_dir: Optional[str] = None, current_role=lambda: ""):
    """Production single-deployable: the JSON API under ``/api`` and (if the React
    build exists) the SPA at ``/`` with a history-API fallback so client-side deep
    links resolve to index.html. The pure API stays reachable/testable via
    ``create_app`` — this only wraps it for hosting, so it never affects tests."""
    if not _HAVE_FASTAPI:                                # pragma: no cover - deploy-only
        raise RuntimeError("cnapp_api requires fastapi + pydantic (deploy-time)")
    import os
    from fastapi.staticfiles import StaticFiles
    from starlette.responses import FileResponse

    api = create_app(service, current_role=current_role)
    root = FastAPI(title="OverWatch CNAPP", version="1.0.0")
    root.mount("/api", api)

    if static_dir and os.path.isdir(static_dir):
        index = os.path.join(static_dir, "index.html")

        class _SPAStatics(StaticFiles):
            # a missing asset that is a client-side route -> serve index.html
            async def get_response(self, path, scope):
                resp = await super().get_response(path, scope)
                if resp.status_code == 404 and os.path.isfile(index):
                    return FileResponse(index)
                return resp

        root.mount("/", _SPAStatics(directory=static_dir, html=True), name="spa")
    return root
