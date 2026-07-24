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

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union
# NOTE: deliberately NO `from __future__ import annotations` here — with PEP 563
# the route annotations become strings and FastAPI's get_type_hints cannot resolve
# the request models defined inside create_app(), which silently demotes the body
# to a query param (422). Real annotations keep the Pydantic body binding intact.

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Query
    from pydantic import BaseModel, Field
    _HAVE_FASTAPI = True
except Exception as _e:                              # pragma: no cover - deploy-only
    _HAVE_FASTAPI = False
    _IMPORT_ERROR = _e


# ── RBAC ──────────────────────────────────────────────────────────────────────
_ROLE_RANK = {"viewer": 1, "admin": 2}
DEFAULT_WORKSPACE = "ws-default"


def _authorize(principal_role: str, min_role: str) -> bool:
    return _ROLE_RANK.get(principal_role, 0) >= _ROLE_RANK.get(min_role, 99)


# ── multi-tenancy principal (Phase-4 Slice-1) ─────────────────────────────────
@dataclass(frozen=True)
class Principal:
    """The authenticated caller: an opaque subject + their ``{workspace_id: role}``
    memberships + a platform-superadmin flag. Produced by the injected
    ``current_principal`` hook (IdP claims in production) or synthesized from the legacy
    ``current_role`` string. Empty memberships + not-superadmin ⇒ deny-all (fail-closed)."""
    subject: str = ""
    memberships: Dict[str, str] = field(default_factory=dict)
    is_superadmin: bool = False

    def role_in(self, workspace_id: str) -> Optional[str]:
        if self.is_superadmin:
            return "admin"                       # superadmin acts as admin in any workspace
        return self.memberships.get(workspace_id)

    def workspaces(self) -> set:
        return set(self.memberships.keys())


@dataclass(frozen=True)
class Scope:
    """The resolved request context returned by ``require(...)``: who, which workspace,
    and their effective role there."""
    principal: Principal
    workspace_id: str
    role: Optional[str]


def _principal_from_role(role: str) -> Principal:
    """Back-compat shim: map the legacy single-role string onto a Principal in the default
    workspace. Empty role ⇒ no memberships ⇒ deny-all (preserves the fail-closed default)."""
    return Principal(subject=role or "",
                     memberships=({DEFAULT_WORKSPACE: role} if role else {}),
                     is_superadmin=False)


def create_app(service, *, current_role=lambda: "", current_principal=None):
    """Build the FastAPI app bound to a PlatformService.

    Auth hooks (both optional, both fail-closed):
    - ``current_principal`` (preferred, multi-tenant): a dependency returning a
      ``Principal`` (subject + ``{workspace_id: role}`` memberships + superadmin flag),
      typically decoded from IdP/JWT claims. May itself have FastAPI sub-dependencies.
    - ``current_role`` (legacy, single-tenant): returns a role STRING; when
      ``current_principal`` is unset it is wrapped into a Principal in the default
      workspace, so every pre-tenancy caller/test behaves identically.

    FAIL-CLOSED default: unset ⇒ empty role ⇒ no memberships ⇒ deny EVERY route. A real
    deployment MUST pass one that authenticates the caller. The target workspace comes
    from the ``X-Workspace-Id`` header (or the caller's sole membership, else the default
    workspace), and RBAC is evaluated for the principal's role IN that workspace."""
    if not _HAVE_FASTAPI:                            # pragma: no cover - deploy-only
        raise RuntimeError(
            "cnapp_api requires fastapi + pydantic (deploy-time): "
            f"{_IMPORT_ERROR}. The backend is fully usable via cnapp_service."
            " Install with: pip install 'fastapi[standard]'")

    app = FastAPI(title="KIZEN CNAPP", version="1.0.0",
                  description="Hosted multi-account CNAPP control plane")

    # The effective principal dependency: the injected hook (may carry its own sub-deps)
    # or the legacy-role shim. Registered AS a dependency so FastAPI resolves it per-request.
    def _default_principal(role: str = Depends(current_role)):
        return _principal_from_role(role)
    _effective_principal = current_principal or _default_principal

    def workspace_ctx(principal: Principal = Depends(_effective_principal),
                      x_workspace_id: Optional[str] = Header(default=None)):
        """Resolve the request's target workspace, fail-closed: an explicit
        ``X-Workspace-Id`` only if the caller may act there; else a sole membership; else
        the default workspace (into which every legacy account is backfilled)."""
        if x_workspace_id:
            if principal.is_superadmin or x_workspace_id in principal.workspaces():
                return x_workspace_id
            raise HTTPException(status_code=403,
                                detail="not a member of the requested workspace")
        if principal.is_superadmin:
            return None                     # superadmin, no selection -> all-workspaces view
        ms = principal.workspaces()
        if len(ms) == 1:
            return next(iter(ms))
        return DEFAULT_WORKSPACE

    def require(min_role: str):
        def dep(principal: Principal = Depends(_effective_principal),
                ws: str = Depends(workspace_ctx)):
            role = principal.role_in(ws)            # None for a non-member -> rank 0 -> 403
            if not _authorize(role, min_role):
                raise HTTPException(status_code=403,
                                    detail=f"requires {min_role} role")
            return Scope(principal=principal, workspace_id=ws, role=role)
        return dep

    def require_superadmin():
        def dep(principal: Principal = Depends(_effective_principal)):
            if not principal.is_superadmin:
                raise HTTPException(status_code=403, detail="requires platform superadmin")
            return principal
        return dep

    def account_gate(min_role: str):
        """Role gate + tenant isolation for an account-scoped route: the caller must have
        ``min_role`` in the resolved workspace AND the ``{account_id}`` must belong to that
        workspace (or the caller is a superadmin). A cross-tenant / unknown account ⇒ 404
        (existence-hiding), never 403 — a tenant must not even learn another's account exists."""
        def dep(account_id: str, scope: Scope = Depends(require(min_role))):
            if not service.account_in_scope(account_id, workspace_id=scope.workspace_id,
                                            is_superadmin=scope.principal.is_superadmin):
                raise HTTPException(status_code=404, detail="account not found")
            return scope
        return dep

    class OnboardReq(BaseModel):
        account_id: str = Field(pattern=r"^[0-9]{12}$")     # 422 on a malformed id
        region: str = "us-east-1"
        method: str = "single"
        alias: str = ""

    class ScanReq(BaseModel):
        account_ids: Optional[List[str]] = None
        all: bool = False

    class ScheduleReq(BaseModel):
        schedule: str = "off"       # off | hourly | daily | weekly | interval:<seconds>

    class ConnectorReq(BaseModel):
        type: str = Field(pattern=r"^(jira|slack|pagerduty|splunk|webhook)$")
        name: str
        config: dict = Field(default_factory=dict)
        secret: Optional[str] = None       # one-time plaintext; stored ONLY as a ref

    class ConnectorUpdateReq(BaseModel):
        name: Optional[str] = None
        config: Optional[dict] = None       # NON-secret fields only

    class EnableReq(BaseModel):
        enabled: bool

    class SecretReq(BaseModel):
        secret: str

    class RuleReq(BaseModel):
        spec: dict = Field(default_factory=dict)

    class PreviewReq(BaseModel):
        account_id: str

    class IngestReq(BaseModel):
        doc: dict                                    # SARIF / CycloneDX / SPDX object
        source_tool: Optional[str] = None            # override the sniffed producer
        target_resource: Optional[str] = None        # explicit owner (EC2/Lambda ARN / image ref)

    class CopilotReq(BaseModel):
        question: str = Field(min_length=1, max_length=2000)

    class DetectionReq(BaseModel):
        events: Union[dict, List[dict]]              # one raw detection or a batch
        source: str = Field(min_length=1)            # guardduty | securityhub | cloudtrail

    class WorkspaceReq(BaseModel):
        workspace_id: str = Field(min_length=1, max_length=64)
        name: str = ""
        slug: Optional[str] = None
        plan: Optional[str] = None

    class WorkspaceUpdateReq(BaseModel):
        name: Optional[str] = None
        slug: Optional[str] = None
        status: Optional[str] = None
        plan: Optional[str] = None

    class MemberReq(BaseModel):
        principal: str = Field(min_length=1)
        role: str = Field(default="viewer", pattern=r"^(viewer|admin)$")

    class PlatformAdminReq(BaseModel):
        principal: str = Field(min_length=1)

    # ── multi-tenancy control-plane gates ──────────────────────────────────────
    def ws_admin_gate(ws_id: str, principal: Principal = Depends(_effective_principal)):
        """A platform superadmin, or an admin member of ``{ws_id}`` — for managing a
        workspace's members/usage. A non-admin/non-member ⇒ 403; an authorized caller on a
        non-existent workspace ⇒ 404 (existence-hiding + avoids a FK IntegrityError 500 on
        a member write to a missing workspace)."""
        if not (principal.is_superadmin or principal.memberships.get(ws_id) == "admin"):
            raise HTTPException(status_code=403, detail="requires workspace admin")
        if service.get_workspace(ws_id) is None:
            raise HTTPException(status_code=404, detail="workspace not found")
        return principal

    def ws_member_gate(ws_id: str, principal: Principal = Depends(_effective_principal)):
        """A superadmin or any member of ``{ws_id}`` — for reading a workspace. A
        non-member ⇒ 404 (existence-hiding)."""
        if principal.is_superadmin or ws_id in principal.workspaces():
            return principal
        raise HTTPException(status_code=404, detail="workspace not found")

    # ── onboarding / validation (admin, private control plane) ────────────────
    @app.post("/accounts", status_code=201)
    def onboard(body: OnboardReq, scope: Scope = Depends(require("admin"))):
        try:
            return service.init_onboarding(body.account_id, region=body.region,
                                           method=body.method, alias=body.alias,
                                           workspace_id=scope.workspace_id)
        except ValueError as e:
            # a cross-tenant re-onboard (account already bound to another workspace) is a
            # conflict, not a bad request
            code = 409 if "already bound to workspace" in str(e) else 400
            raise HTTPException(status_code=code, detail=str(e))

    @app.post("/accounts/{account_id}/validate", dependencies=[Depends(account_gate("admin"))])
    def validate(account_id: str, org_mode: bool = Query(False)):
        try:
            return service.validate_account(account_id, org_mode=org_mode)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # ── inventory (viewer) ────────────────────────────────────────────────────
    @app.get("/accounts")
    def list_accounts(onboarding_status: Optional[str] = None, health: Optional[str] = None,
                      scope: Scope = Depends(require("viewer"))):
        return service.list_accounts(onboarding_status=onboarding_status, health=health,
                                     workspace_id=scope.workspace_id)

    @app.get("/accounts/{account_id}", dependencies=[Depends(account_gate("viewer"))])
    def get_account(account_id: str):
        a = service.get_account(account_id)
        if not a:
            raise HTTPException(status_code=404, detail="account not found")
        return a

    # ── scanning (admin) ──────────────────────────────────────────────────────
    @app.post("/scans", status_code=202)
    def trigger_scan(body: ScanReq, scope: Scope = Depends(require("admin"))):
        return {"job_ids": service.trigger_scan(
            body.account_ids, all=body.all, workspace_id=scope.workspace_id,
            is_superadmin=scope.principal.is_superadmin)}

    @app.get("/scans/{job_id}")
    def get_scan(job_id: str, scope: Scope = Depends(require("viewer"))):
        # a scan job is account-scoped (carries account_id); isolate on its owner and
        # 404 (existence-hiding) when the job is unknown OR belongs to another tenant
        j = service.get_scan_job(job_id)
        if not j or not service.account_in_scope(
                j["account_id"], workspace_id=scope.workspace_id,
                is_superadmin=scope.principal.is_superadmin):
            raise HTTPException(status_code=404, detail="job not found")
        return j

    # ── continuous scheduling + lifecycle/drift readers ───────────────────────
    @app.post("/scans/schedule-tick")
    def schedule_tick(scope: Scope = Depends(require("admin"))):
        # a tenant admin sweeps only their own workspace's due accounts; a superadmin (no
        # workspace selected) sweeps every tenant — the platform-wide cron behaviour
        return {"job_ids": service.schedule_due_scans(workspace_id=scope.workspace_id)}

    @app.put("/accounts/{account_id}/schedule", dependencies=[Depends(account_gate("admin"))])
    def set_schedule(account_id: str, body: ScheduleReq):
        try:
            return service.set_scan_schedule(account_id, body.schedule)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/accounts/{account_id}/trend", dependencies=[Depends(account_gate("viewer"))])
    def trend(account_id: str):
        return service.get_trend(account_id)

    @app.get("/accounts/{account_id}/mttr", dependencies=[Depends(account_gate("viewer"))])
    def mttr(account_id: str):
        return service.get_mttr(account_id)

    @app.get("/accounts/{account_id}/drift", dependencies=[Depends(account_gate("viewer"))])
    def drift(account_id: str):
        return service.get_drift(account_id)

    # ── results (viewer) ──────────────────────────────────────────────────────
    @app.get("/accounts/{account_id}/issues", dependencies=[Depends(account_gate("viewer"))])
    def issues(account_id: str, severity: Optional[str] = None,
               status: Optional[str] = None):
        return service.get_issues(account_id, severity=severity, status=status)

    @app.get("/accounts/{account_id}/paths", dependencies=[Depends(account_gate("viewer"))])
    def paths(account_id: str):
        return service.get_paths(account_id)

    @app.get("/accounts/{account_id}/graph", dependencies=[Depends(account_gate("viewer"))])
    def graph(account_id: str):
        return service.get_graph(account_id)

    @app.get("/accounts/{account_id}/summary", dependencies=[Depends(account_gate("viewer"))])
    def account_summary(account_id: str):
        s = service.get_account_summary(account_id)
        if not s:
            raise HTTPException(status_code=404, detail="no scan results for account")
        return s

    @app.get("/accounts/{account_id}/findings", dependencies=[Depends(account_gate("viewer"))])
    def findings(account_id: str):
        return service.get_finding_catalog(account_id)

    @app.get("/org/overview")
    def org_overview(scope: Scope = Depends(require("viewer"))):
        return service.org_overview(workspace_id=scope.workspace_id)

    @app.get("/org/findings")
    def org_findings(scope: Scope = Depends(require("viewer"))):
        return service.org_findings(workspace_id=scope.workspace_id)

    # ── grounded copilot (viewer; answers only from the account's own scan) ────
    @app.post("/accounts/{account_id}/copilot", dependencies=[Depends(account_gate("viewer"))])
    def copilot(account_id: str, body: CopilotReq):
        a = service.copilot_answer(account_id, body.question)
        if a is None:
            raise HTTPException(status_code=404, detail="no scan results for account")
        return a

    @app.post("/org/copilot")
    def org_copilot(body: CopilotReq, scope: Scope = Depends(require("viewer"))):
        return service.org_copilot_answer(body.question, workspace_id=scope.workspace_id)

    # ── external-vuln ingest + reachability-ranked inventory ──────────────────
    @app.post("/accounts/{account_id}/ingest", dependencies=[Depends(account_gate("admin"))])
    def ingest(account_id: str, body: IngestReq):
        try:
            return service.ingest_document(
                account_id, doc=body.doc, source_tool=body.source_tool,
                target_resource=body.target_resource)
        except ValueError as e:                     # unparseable doc / cross-account ARN
            raise HTTPException(status_code=400, detail=str(e))
        except RuntimeError as e:                   # ingest requires a state store
            raise HTTPException(status_code=503, detail=str(e))

    @app.get("/accounts/{account_id}/vulns", dependencies=[Depends(account_gate("viewer"))])
    def vulns(account_id: str, min_band: Optional[str] = None, kev: Optional[bool] = None,
              on_path: Optional[bool] = None, source: Optional[str] = None,
              node: Optional[str] = None, include_suppressed: bool = True,
              sort: str = "priority", limit: int = 2000):
        return service.list_vulns(
            account_id, min_band=min_band, kev=kev, on_path=on_path, source=source,
            node=node, include_suppressed=include_suppressed, sort=sort, limit=limit)

    @app.get("/accounts/{account_id}/vulns/{cve}", dependencies=[Depends(account_gate("viewer"))])
    def vuln_detail(account_id: str, cve: str):
        rows = service.get_vuln(account_id, cve)
        if not rows:
            raise HTTPException(status_code=404, detail="no ingested rows for this CVE")
        return rows

    @app.get("/accounts/{account_id}/ingest/docs", dependencies=[Depends(account_gate("viewer"))])
    def ingest_docs(account_id: str, limit: int = 200):
        return service.list_ingest_docs(account_id, limit)

    @app.post("/accounts/{account_id}/vulns/refresh", dependencies=[Depends(account_gate("admin"))])
    def vulns_refresh(account_id: str):
        try:
            return service.refresh_vuln_reachability(account_id)
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=str(e))

    @app.get("/org/vulns")
    def org_vulns(min_band: Optional[str] = None, kev: Optional[bool] = None,
                  on_path: Optional[bool] = None, limit: int = 2000,
                  scope: Scope = Depends(require("viewer"))):
        return service.org_vulns(min_band=min_band, kev=kev, on_path=on_path, limit=limit,
                                 workspace_id=scope.workspace_id)

    # ── CDR-lite: streaming detection ingest + reachability-ranked incidents ────
    @app.post("/accounts/{account_id}/detections", dependencies=[Depends(account_gate("admin"))])
    def detections_ingest(account_id: str, body: DetectionReq):
        try:
            return service.ingest_detection(account_id, events=body.events, source=body.source)
        except ValueError as e:                     # unknown source / cross-account ARN
            raise HTTPException(status_code=400, detail=str(e))
        except RuntimeError as e:                   # detection ingest requires a state store
            raise HTTPException(status_code=503, detail=str(e))

    @app.get("/accounts/{account_id}/detections", dependencies=[Depends(account_gate("viewer"))])
    def detections_list(account_id: str, source: Optional[str] = None,
                        incidents_only: bool = False, limit: int = 2000):
        return service.list_detections(account_id, source=source,
                                       incidents_only=incidents_only, limit=limit)

    @app.get("/accounts/{account_id}/incidents", dependencies=[Depends(account_gate("viewer"))])
    def incidents_list(account_id: str, limit: int = 200):
        return service.list_incidents(account_id, limit=limit)

    @app.post("/accounts/{account_id}/detections/refresh",
              dependencies=[Depends(account_gate("admin"))])
    def detections_refresh(account_id: str):
        return service.refresh_detection_escalation(account_id)

    @app.get("/org/incidents")
    def org_incidents(limit: int = 200, scope: Scope = Depends(require("viewer"))):
        return service.org_incidents(limit=limit, workspace_id=scope.workspace_id)

    # ── cloud-forensics timeline (viewer; read-only CloudTrail, correlated) ─────
    @app.get("/accounts/{account_id}/forensics/timeline",
             dependencies=[Depends(account_gate("viewer"))])
    def forensics_timeline(account_id: str, resource: str, limit: int = 200):
        return service.forensics_timeline(account_id, resource, limit=limit)

    # ── compliance breadth (viewer; reference data + derived scorecards) ───────
    @app.get("/compliance/frameworks", dependencies=[Depends(require("viewer"))])
    def compliance_frameworks():
        return service.list_compliance_frameworks()

    @app.get("/compliance/crosswalk", dependencies=[Depends(require("viewer"))])
    def compliance_crosswalk(framework: Optional[str] = None):
        return service.get_crosswalk(framework)

    @app.get("/accounts/{account_id}/compliance", dependencies=[Depends(account_gate("viewer"))])
    def account_compliance(account_id: str, min_confidence: Optional[str] = None,
                           frameworks: Optional[str] = None):
        fw = [f for f in frameworks.split(",") if f] if frameworks else None
        c = service.get_account_compliance(account_id, min_confidence=min_confidence, frameworks=fw)
        if c is None:
            raise HTTPException(status_code=404, detail="no scan results for account")
        return c

    @app.get("/org/compliance")
    def org_compliance(min_confidence: Optional[str] = None,
                       scope: Scope = Depends(require("viewer"))):
        return service.org_compliance(min_confidence=min_confidence,
                                      workspace_id=scope.workspace_id)

    # ── connectors (admin mutate, viewer read) ────────────────────────────────
    # The connector control plane wields outbound HTTP + operator secrets, so every
    # mutation is admin; reads are viewer and NEVER return a secret (masked shape).
    @app.post("/connectors", status_code=201, dependencies=[Depends(require("admin"))])
    def create_connector(body: ConnectorReq, principal: Principal = Depends(_effective_principal)):
        try:
            return service.create_connector(type=body.type, name=body.name,
                                            config=body.config, secret=body.secret,
                                            created_by=principal.subject)
        except (ValueError, RuntimeError) as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/connectors", dependencies=[Depends(require("viewer"))])
    def list_connectors():
        return service.list_connectors()

    @app.get("/connectors/{connector_id}", dependencies=[Depends(require("viewer"))])
    def get_connector(connector_id: str):
        c = service.get_connector(connector_id)
        if not c:
            raise HTTPException(status_code=404, detail="connector not found")
        return c

    @app.put("/connectors/{connector_id}", dependencies=[Depends(require("admin"))])
    def update_connector(connector_id: str, body: ConnectorUpdateReq):
        try:
            return service.update_connector(connector_id, name=body.name, config=body.config)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.post("/connectors/{connector_id}/enable", dependencies=[Depends(require("admin"))])
    def enable_connector(connector_id: str, body: EnableReq):
        try:
            return service.set_connector_enabled(connector_id, body.enabled)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.post("/connectors/{connector_id}/rotate-secret", dependencies=[Depends(require("admin"))])
    def rotate_secret(connector_id: str, body: SecretReq):
        try:
            return service.rotate_connector_secret(connector_id, body.secret)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/connectors/{connector_id}/test", dependencies=[Depends(require("admin"))])
    def test_connector(connector_id: str):
        try:
            return service.test_connector(connector_id)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.delete("/connectors/{connector_id}", status_code=204,
                dependencies=[Depends(require("admin"))])
    def delete_connector(connector_id: str):
        service.delete_connector(connector_id)

    # ── rules (admin mutate, viewer read) ─────────────────────────────────────
    @app.post("/connectors/rules/preview")
    def preview_rules(body: PreviewReq, scope: Scope = Depends(require("admin"))):
        # account_id arrives in the BODY (so path-based account_gate can't apply) — isolate
        # explicitly, else a tenant admin could preview another tenant's scan findings
        if not service.account_in_scope(body.account_id, workspace_id=scope.workspace_id,
                                        is_superadmin=scope.principal.is_superadmin):
            raise HTTPException(status_code=404, detail="account not found")
        return service.preview_rules(body.account_id)

    @app.get("/connectors/{connector_id}/rules", dependencies=[Depends(require("viewer"))])
    def list_rules(connector_id: str):
        return service.list_rules(connector_id)

    @app.post("/connectors/{connector_id}/rules", status_code=201,
              dependencies=[Depends(require("admin"))])
    def create_rule(connector_id: str, body: RuleReq,
                    principal: Principal = Depends(_effective_principal)):
        try:
            return service.create_rule(connector_id, body.spec, created_by=principal.subject)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.put("/connectors/{connector_id}/rules/{rule_id}",
             dependencies=[Depends(require("admin"))])
    def update_rule(connector_id: str, rule_id: int, body: RuleReq):
        try:
            return service.update_rule(connector_id, rule_id, body.spec)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.delete("/connectors/{connector_id}/rules/{rule_id}", status_code=204,
                dependencies=[Depends(require("admin"))])
    def delete_rule(connector_id: str, rule_id: int):
        service.delete_rule(connector_id, rule_id)

    # ── notify + delivery audit ───────────────────────────────────────────────
    @app.post("/accounts/{account_id}/notify", dependencies=[Depends(account_gate("admin"))])
    def notify_account(account_id: str):
        return service.notify_account(account_id)

    @app.get("/connectors/{connector_id}/deliveries", dependencies=[Depends(require("viewer"))])
    def deliveries(connector_id: str, account: Optional[str] = None,
                   status: Optional[str] = None):
        return service.list_deliveries(connector_id, account=account, status=status)

    @app.get("/notifications", dependencies=[Depends(require("viewer"))])
    def notifications(account: Optional[str] = None, status: Optional[str] = None):
        return service.list_deliveries(None, account=account, status=status)

    # ── drift-digest delivery audit + preview ─────────────────────────────────
    @app.get("/connectors/{connector_id}/digests", dependencies=[Depends(require("viewer"))])
    def connector_digests(connector_id: str, account: Optional[str] = None,
                          status: Optional[str] = None):
        return service.list_digests(connector_id, account=account, status=status)

    @app.get("/digests", dependencies=[Depends(require("viewer"))])
    def digests(account: Optional[str] = None, status: Optional[str] = None):
        return service.list_digests(None, account=account, status=status)

    @app.post("/accounts/{account_id}/digest/preview", dependencies=[Depends(account_gate("admin"))])
    def digest_preview(account_id: str):
        d = service.preview_digest(account_id)
        if d is None:
            raise HTTPException(status_code=404, detail="no drift state for account")
        return d

    # ── multi-tenancy control plane (workspaces + members + platform admins) ────
    @app.post("/workspaces", status_code=201, dependencies=[Depends(require_superadmin())])
    def create_workspace(body: WorkspaceReq):
        try:
            return service.create_workspace(body.workspace_id, name=body.name,
                                            slug=body.slug, plan=body.plan)
        except (ValueError, RuntimeError) as e:
            code = 409 if "already in use" in str(e) else 400
            raise HTTPException(status_code=code, detail=str(e))

    @app.get("/workspaces", dependencies=[Depends(require_superadmin())])
    def list_workspaces():
        return service.list_workspaces()

    @app.get("/workspaces/{ws_id}")
    def get_workspace(ws_id: str, _=Depends(ws_member_gate)):
        w = service.get_workspace(ws_id)
        if not w:
            raise HTTPException(status_code=404, detail="workspace not found")
        return w

    @app.put("/workspaces/{ws_id}", dependencies=[Depends(require_superadmin())])
    def update_workspace(ws_id: str, body: WorkspaceUpdateReq):
        try:
            return service.update_workspace(ws_id, name=body.name, slug=body.slug,
                                            status=body.status, plan=body.plan)
        except (ValueError, RuntimeError) as e:
            code = 409 if "already in use" in str(e) else 400
            raise HTTPException(status_code=code, detail=str(e))

    @app.delete("/workspaces/{ws_id}", status_code=204,
                dependencies=[Depends(require_superadmin())])
    def delete_workspace(ws_id: str):
        try:
            service.delete_workspace(ws_id)
        except (ValueError, RuntimeError) as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/workspaces/{ws_id}/members")
    def list_members(ws_id: str, _=Depends(ws_admin_gate)):
        return service.list_members(ws_id)

    @app.post("/workspaces/{ws_id}/members", status_code=201)
    def add_member(ws_id: str, body: MemberReq,
                   principal: Principal = Depends(ws_admin_gate)):
        try:
            return service.add_member(ws_id, body.principal, role=body.role,
                                      added_by=principal.subject)
        except (ValueError, RuntimeError) as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.delete("/workspaces/{ws_id}/members/{member}", status_code=204)
    def remove_member(ws_id: str, member: str, _=Depends(ws_admin_gate)):
        service.remove_member(ws_id, member)

    @app.get("/admin/platform-admins", dependencies=[Depends(require_superadmin())])
    def list_platform_admins():
        return service.list_platform_admins()

    @app.post("/admin/platform-admins", status_code=201,
              dependencies=[Depends(require_superadmin())])
    def add_platform_admin(body: PlatformAdminReq):
        try:
            service.add_platform_admin(body.principal)
            return {"principal": body.principal}
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=str(e))

    @app.delete("/admin/platform-admins/{principal}", status_code=204,
                dependencies=[Depends(require_superadmin())])
    def remove_platform_admin(principal: str):
        service.remove_platform_admin(principal)

    # ── usage metering (billable: accounts under management) ───────────────────
    @app.get("/workspaces/{ws_id}/usage")
    def workspace_usage(ws_id: str, period: Optional[str] = None,
                        _=Depends(ws_admin_gate)):
        return service.usage_summary(ws_id, period=period)

    @app.get("/admin/usage", dependencies=[Depends(require_superadmin())])
    def admin_usage(period: Optional[str] = None):
        return service.usage_rollup_all(period=period)

    @app.post("/admin/usage/reconcile", dependencies=[Depends(require_superadmin())])
    def admin_usage_reconcile():
        return service.reconcile_usage()

    return app


def create_hosted_app(service, *, static_dir: Optional[str] = None, current_role=lambda: "",
                      current_principal=None):
    """Production single-deployable: the JSON API under ``/api`` and (if the React
    build exists) the SPA at ``/`` with a history-API fallback so client-side deep
    links resolve to index.html. The pure API stays reachable/testable via
    ``create_app`` — this only wraps it for hosting, so it never affects tests."""
    if not _HAVE_FASTAPI:                                # pragma: no cover - deploy-only
        raise RuntimeError("cnapp_api requires fastapi + pydantic (deploy-time)")
    import os
    from fastapi.staticfiles import StaticFiles
    from starlette.responses import FileResponse

    api = create_app(service, current_role=current_role, current_principal=current_principal)
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
