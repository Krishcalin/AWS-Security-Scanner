#!/usr/bin/env python3
"""
cnapp_service.py — the PlatformService facade for the hosted CNAPP (Phase 8).

One dependency-injected class that every web route delegates to in a single line,
so the whole backend is unit-testable with dict fakes and the FastAPI layer
(cnapp_api.py) carries zero business logic. It orchestrates the existing pieces —
cnapp_onboarding (mint ExternalId + CFN URL), cnapp_validate (connection health),
cnapp_registry (persistence), and the UNCHANGED aws_live_scanner engine
(assume_role_session, AWSLiveScanner, aggregate_results) — and never re-implements
scanning or scoring.

Pure/offline-testable: all AWS access and persistence arrive as injected
collaborators (session_factory, assume_role_fn, client_factory, org_lister,
scan_runner, registry, results store, secret reader/writer, id generators, clock).
Production defaults wire to boto3 lazily; tests inject fakes and never import it.
"""

from __future__ import annotations

import secrets
from collections import namedtuple
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Protocol

import aws_copilot
import aws_correlate
import aws_graph
import aws_ingest
import aws_cdr
import aws_dspm
import aws_edr
import aws_forensics
import aws_malware
import aws_policy
import aws_registry_connectors
import aws_license
import aws_sbom_diff
import aws_sidescan
import aws_state
import aws_vex
import cnapp_connectors as cc
import cnapp_onboarding
import cnapp_validate
from cnapp_validate import ConnectionHealth

# Lightweight result row reconstructed from the serialized payload — enough for the
# StateStore lifecycle fold (status/check_id/section/resource/message/severity), so the
# lifecycle path is decoupled from the engine's mutable object model + dict-fake testable.
_LR = namedtuple("_LR", "status check_id section resource message severity")

ROLE_NAME = "CnappScannerRole"
SLA_DAYS = 30                # open-finding SLA window for MTTR / drift-digest breaches
HOSTED_REGION = "all"        # byte-stable lifecycle partition label for a full multi-region hosted scan


# ── scan spec + result store protocol ────────────────────────────────────────
@dataclass(frozen=True)
class ScanSpec:
    region: str = "us-east-1"
    sections: Optional[List[str]] = None
    all_regions: bool = True


DEFAULT_SPEC = ScanSpec()
DEFAULT_WORKSPACE = "ws-default"      # the tenant every pre-multitenancy account is bound to


class ResultStore(Protocol):
    def put(self, account_id: str, payload: dict) -> None: ...
    def get_latest(self, account_id: str) -> Optional[dict]: ...
    def list_latest(self) -> List[dict]: ...


class InMemoryResultStore:
    """Dev/test result store: keeps the most recent serialized scan per account."""

    def __init__(self):
        self._latest: Dict[str, dict] = {}

    def put(self, account_id: str, payload: dict) -> None:
        self._latest[account_id] = payload

    def get_latest(self, account_id: str) -> Optional[dict]:
        return self._latest.get(account_id)

    def list_latest(self) -> List[dict]:
        return list(self._latest.values())


# ── serialization: mirror save_json's field expressions, return a dict ────────
def serialize_scanner(sc) -> dict:
    """Project a run AWSLiveScanner into a JSON-able dict, mirroring
    ``AWSLiveScanner.save_json`` field-for-field, plus ``graph_full`` (the full
    node-link graph, needed to rebuild an org-wide graph later)."""
    import aws_live_scanner as als
    score = als.compute_risk_score(sc.results)
    return {
        "account": sc.account,
        "region": sc.region,
        "posture_score": score,
        "posture_grade": als.score_to_grade(score),
        "summary": {
            "PASS": sum(1 for r in sc.results if r.status == "PASS"),
            "FAIL": sum(1 for r in sc.results if r.status == "FAIL"),
            "WARN": sum(1 for r in sc.results if r.status == "WARN"),
            "INFO": sum(1 for r in sc.results if r.status == "INFO"),
        },
        **als.compliance_payload(sc.results),
        "graph": sc.graph.stats() if sc.graph else None,
        "graph_full": sc.graph.to_dict() if sc.graph else None,
        "attack_paths": [p.to_dict() for p in sc.attack_paths],
        "choke_points": [c.to_dict() for c in sc.choke_points],
        "finding_catalog": sc._build_finding_catalog(),
        "results": [
            {"status": r.status, "check_id": r.check_id, "section": r.section,
             "resource": r.resource, "message": r.message, "severity": r.severity,
             "compliance": getattr(r, "compliance", {}),
             "remediation_cmd": getattr(r, "remediation_cmd", "")}
            for r in sc.results
        ],
    }


def default_scan_runner(session, spec: ScanSpec):
    """Production scan runner: build + run the engine with the assumed-role session.
    Imported lazily so tests never need boto3."""
    import aws_live_scanner as als
    sc = als.AWSLiveScanner(region=spec.region, verbose=False, sections=spec.sections,
                            session=session, all_regions=spec.all_regions)
    sc.run()                      # cnapp_worker traps the engine's sys.exit(2)
    return sc


# ── the service ───────────────────────────────────────────────────────────────
class PlatformService:
    def __init__(self, *, registry, results: ResultStore, hub_role_arn: str,
                 cfn_template_url: str, secret_writer: cnapp_onboarding.SecretWriter,
                 secret_reader: cnapp_onboarding.SecretReader,
                 session_factory: Optional[Callable] = None,
                 assume_role_fn: Optional[cnapp_validate.AssumeRoleFn] = None,
                 client_factory: Optional[cnapp_validate.ClientFactory] = None,
                 org_lister: Optional[Callable] = None,
                 scan_runner: Callable = default_scan_runner,
                 id_gen: Callable[[], str] = cnapp_onboarding.default_id_gen,
                 job_id_gen: Callable[[], str] = lambda: "job-" + secrets.token_hex(8),
                 connectors=None, http_post: Optional[Callable] = None, hub_base: str = "",
                 connector_id_gen: Callable[[], str] = lambda: "conn-" + secrets.token_hex(6),
                 crosswalk=None, state=None, vuln_bundle=None, workspaces=None, metering=None,
                 copilot_llm: Optional[Callable] = None,
                 trail_reader: Optional[Callable] = None,
                 projects: Optional[List[dict]] = None,
                 controls: Optional[List[dict]] = None,
                 policies: Optional[List[dict]] = None,
                 registry_connectors: Optional[List[dict]] = None,
                 registry_request: Optional[Callable] = None,
                 registry_blob_get: Optional[Callable] = None,
                 clock: Callable[[], int] = None):
        import time
        # Optional grounded-copilot LLM seam (system, question, context) -> str. None (default)
        # -> the offline EXTRACTIVE answerer (no network, no hallucination). Inject a Claude/
        # Bedrock caller to get fluent answers; the context is always the retrieved scan corpus.
        self._copilot_llm = copilot_llm
        # Optional cloud-forensics seam (account_id, resource_arn, start, end, limit) -> list of
        # CloudTrail event dicts | None. None (default) -> the timeline is dormant (FORENSIC-00),
        # never a phantom clean timeline. A deployment wires aws_forensics.default_trail_lookup
        # behind its injected client_factory (read-only cloudtrail:LookupEvents, mgmt events only).
        self._trail_reader = trail_reader
        self.registry = registry
        self.results = results
        self.hub_role_arn = hub_role_arn
        self.cfn_template_url = cfn_template_url
        self.secret_writer = secret_writer
        self.secret_reader = secret_reader
        self.session_factory = session_factory
        self.assume_role_fn = assume_role_fn
        self.client_factory = client_factory
        self.org_lister = org_lister
        self.scan_runner = scan_runner
        self.id_gen = id_gen
        self.job_id_gen = job_id_gen
        # ── connector framework (Phase-2 workflow plane) ──────────────────────
        self.connectors = connectors            # a cnapp_connectors.ConnectorStore (or None)
        self.hub_base = hub_base
        self.connector_id_gen = connector_id_gen
        self._crosswalk = crosswalk             # None -> lazy bundled compliance_crosswalk
        self.state = state                      # an aws_state.StateStore (or None) — lifecycle/drift/trend
        self.workspaces = workspaces            # a cnapp_workspace.WorkspaceStore (or None -> single-tenant)
        self.metering = metering                # a cnapp_metering.MeteringStore (or None -> no metering)
        # ── external-vuln ingest plane (Phase-2 capstone) ─────────────────────
        # The SAME {records/osv, epss, kev, exploits} bundle the native side-scan
        # uses, so an ingested CVE gets byte-identical KEV/EPSS. Fail-open: None →
        # CVEs are owned but enrichment is empty (reachability surfaced honestly).
        self._vuln_bundle_data = vuln_bundle
        self._osv_feed_cache = None
        self._http_post = http_post             # None -> lazy urllib default (see http_post)
        # ── Projects (LBI/MBI/HBI business-impact grouping) ───────────────────
        # Read-only, config-driven resource groupings ({id,name,tier,match:{accounts,resource_globs}}).
        # DISPLAY-ONLY: a project rolls up its EXISTING findings; the tier NEVER feeds the posture
        # or attack-path score (aws_correlate stays byte-frozen). No DB table (no schema churn).
        self.projects = projects or []
        # ── Controls (saved-WQL-query-as-Control) ─────────────────────────────
        # Read-only, config-driven saved queries ({id,name,query,severity?,section?,description?}).
        # DISPLAY-ONLY: a matching control overlays a synthetic WARN finding into the catalog at
        # READ time; it never re-runs scoring (compute_risk_score counts FAIL only, baked at scan
        # time → aws_correlate stays byte-frozen). No DB table (no schema churn). Fail-safe per
        # control: a bad/unsafe saved query is inert, never an error.
        self.controls = controls or []
        # ── Policies (policy-as-code; the custom-rule engine) ─────────────────
        # Read-only, config-driven rules ({id,name,match:{op?,graph?,finding?},...}) that combine a
        # graph condition (WQL) and/or a finding-catalog condition (compliance-as-code). Same
        # DISPLAY-ONLY discipline as Controls: a firing policy overlays a synthetic WARN POLICY-xx
        # finding at read time; never re-runs scoring. Fail-safe per policy (a malformed rule is inert).
        self.policies = policies or []
        # ── Non-AWS registry connectors (Batch 6) ─────────────────────────────
        # Operator-declared GHCR/Docker Hub/Harbor/ACR registries to agentlessly pull + side-scan,
        # reusing the SAME SBOM/OSV engine as ECR. Config-driven (no DB schema — like Controls/
        # Policies/Projects). The pull's egress lives ENTIRELY in aws_layer_fetch (the sole
        # allowlisted file); the two seams below default-bind to it lazily so tests inject fakes and
        # never touch a socket. Results are cached in-memory (last scan), never fed to the posture
        # score or the frozen attack-path graph.
        self.registry_connectors = aws_registry_connectors.load_connectors(registry_connectors or [])
        self._registry_request = registry_request
        self._registry_blob_get = registry_blob_get
        self._registry_scan_cache: Dict[str, dict] = {}
        self.clock = clock or (lambda: int(time.time()))

    @property
    def http_post(self):
        """The outbound seam. Lazily bound to the urllib impl (with the SSRF guard)
        so tests can inject a fake and never import it."""
        if self._http_post is None:
            self._http_post = cc.default_http_post
        return self._http_post

    def _role_arn(self, account_id: str) -> str:
        return f"arn:aws:iam::{account_id}:role/{ROLE_NAME}"

    # ── onboarding ────────────────────────────────────────────────────────────
    def init_onboarding(self, account_id: str, *, region: str = "us-east-1",
                        method: str = "single", alias: str = "",
                        workspace_id: Optional[str] = None) -> dict:
        """Mint the ExternalId (stored only as a secret ref), register the account
        as 'pending', bind it to the caller's workspace, and return the CloudFormation
        launch URL + CLI.

        IDEMPOTENT: re-onboarding an account that already has an ExternalId REUSES
        it (never rotates) — rotating would invalidate the already-deployed CFN
        trust and silently break a live connection. Only a dedicated rotate flow
        should mint a new ExternalId. The upsert + workspace binding are atomic; a
        second tenant onboarding the same real AWS account raises ValueError (the API
        maps it to 409) — one account belongs to exactly one workspace."""
        now = self.clock()
        ws = workspace_id or DEFAULT_WORKSPACE
        existing = self.registry.get_account(account_id)
        if existing and existing.get("external_id_ref"):
            ref = existing["external_id_ref"]
            external_id = cnapp_onboarding.resolve_external_id(
                ref, secret_reader=self.secret_reader, region=region) or ""
            # refresh only non-secret config; preserve lifecycle + the ExternalId
            with self.registry._be.transaction():
                self.registry.upsert_account(account_id, now_epoch=now, alias=(alias or None),
                                             onboarding_method=method, enabled_regions=[region])
                self.registry.bind_account(account_id, ws, now)
            self._meter("account.onboarded", event_key=account_id, account_id=account_id,
                        workspace_id=ws, meta={"method": method})
            return {"account_id": account_id, "role_name": cnapp_onboarding.ROLE_NAME,
                    "external_id_ref": ref, "reused": True,
                    "cfn_launch_url": cnapp_onboarding.build_launch_url(
                        self.cfn_template_url, self.hub_role_arn, external_id, region),
                    "cli": cnapp_onboarding.build_cli(
                        self.cfn_template_url, self.hub_role_arn, external_id, region)}
        init = cnapp_onboarding.init_onboarding(
            account_id, region, id_gen=self.id_gen, secret_writer=self.secret_writer,
            hub_role_arn=self.hub_role_arn, cfn_template_url=self.cfn_template_url)
        with self.registry._be.transaction():
            self.registry.upsert_account(
                account_id, now_epoch=now, alias=alias, onboarding_method=method,
                role_arn=self._role_arn(account_id), external_id_ref=init.external_id_ref,
                enabled_regions=[region])
            self.registry.bind_account(account_id, ws, now)
        self._meter("account.onboarded", event_key=account_id, account_id=account_id,
                    workspace_id=ws, meta={"method": method})
        return {"account_id": account_id, "role_name": init.role_name,
                "external_id_ref": init.external_id_ref, "reused": False,
                "cfn_launch_url": init.cfn_launch_url, "cli": init.cli}

    # ── validation ────────────────────────────────────────────────────────────
    def validate_account(self, account_id: str, *, org_mode: bool = False,
                         region: str = "us-east-1") -> dict:
        """Assume the role and confirm read access, persist the health verdict, and
        flip onboarding_status: healthy -> active, unauthorized -> denied."""
        acct = self.registry.get_account(account_id)
        if not acct:
            raise KeyError(f"account {account_id} is not onboarded")
        role_arn = acct.get("role_arn") or self._role_arn(account_id)
        external_id = cnapp_onboarding.resolve_external_id(
            acct.get("external_id_ref"), secret_reader=self.secret_reader, region=region)
        now = self.clock()
        result = cnapp_validate.validate_connection(
            expected_account_id=account_id, role=role_arn, now_epoch=now,
            assume_role_fn=self.assume_role_fn, client_factory=self.client_factory,
            external_id=external_id, region=region, org_mode=org_mode)
        self.registry.record_health(account_id, role_arn, result, now,
                                    region=region, org_mode=org_mode)
        if result.health == ConnectionHealth.HEALTHY:
            self.registry.set_onboarding_status(account_id, "active", now)
        elif result.health == ConnectionHealth.UNAUTHORIZED:
            self.registry.set_onboarding_status(account_id, "denied", now)
        # VALIDATING / DEGRADED leave the status as-is (still pending / previously active)
        return result.to_dict()

    # ── inventory ─────────────────────────────────────────────────────────────
    def _scoped_ws(self, workspace_id: Optional[str]) -> Optional[str]:
        """Workspace filtering only engages when a WorkspaceStore is wired (multi-tenant).
        Single-tenant deployments (and every pre-tenancy test) pass no store ⇒ the filter is
        dropped ⇒ global, byte-identical behavior."""
        return workspace_id if self.workspaces is not None else None

    def account_in_scope(self, account_id: str, *, workspace_id: Optional[str] = None,
                         is_superadmin: bool = False) -> bool:
        """Tenant-isolation gate: may a caller scoped to ``workspace_id`` touch this
        account? A platform superadmin, an unscoped/single-tenant call (``workspace_id``
        None, or no WorkspaceStore wired), always may. Otherwise the account's bound
        workspace must equal the caller's — a legacy/unbound account counts as
        ``ws-default``. The API maps a False here to a 404 (existence-hiding)."""
        if is_superadmin or workspace_id is None or self.workspaces is None:
            return True
        acct_ws = self.workspaces.workspace_of_account(account_id) or DEFAULT_WORKSPACE
        return acct_ws == workspace_id

    def connector_in_scope(self, connector_id: str, *, workspace_id: Optional[str] = None,
                           is_superadmin: bool = False) -> bool:
        """Tenant-isolation gate for a connector — the connector twin of
        ``account_in_scope``. A superadmin, or an unscoped/single-tenant call (workspace_id
        None, or no WorkspaceStore wired), always may. Otherwise the connector's bound
        workspace must equal the caller's — a legacy/unbound connector counts as
        ``ws-default``. The API maps a False here to a 404 (existence-hiding)."""
        if is_superadmin or workspace_id is None or self.workspaces is None:
            return True
        conn_ws = self.workspaces.workspace_of_connector(connector_id) or DEFAULT_WORKSPACE
        return conn_ws == workspace_id

    def _account_ws(self, account_id: str) -> Optional[str]:
        """The workspace an account's notifications may be delivered through: single-tenant /
        no WorkspaceStore ⇒ None (global, byte-identical); else the account's bound workspace
        (an unbound/legacy account counts as ws-default). A scan of this account then fires
        ONLY that workspace's connectors — never another tenant's."""
        if self.workspaces is None:
            return None
        return self.workspaces.workspace_of_account(account_id) or DEFAULT_WORKSPACE

    def list_accounts(self, *, onboarding_status=None, health=None,
                      workspace_id: Optional[str] = None) -> List[dict]:
        rows = [_mask_account(a) for a in
                self.registry.list_accounts(onboarding_status=onboarding_status, health=health,
                                            workspace_id=self._scoped_ws(workspace_id))]
        # Enrich each row with the latest scan's posture (the registry holds only
        # lifecycle/health metadata). The console's accounts list shows a posture
        # column, drawn from the SAME source get_account_summary/org_overview use;
        # None until the account has a first scan.
        for row in rows:
            p = self.results.get_latest(row.get("account_id"))
            row["posture_score"] = p.get("posture_score") if p else None
            row["posture_grade"] = p.get("posture_grade") if p else None
        return rows

    def get_account(self, account_id: str) -> Optional[dict]:
        a = self.registry.get_account(account_id)
        return _mask_account(a) if a else None

    # ── scanning ──────────────────────────────────────────────────────────────
    def trigger_scan(self, account_ids: Optional[List[str]] = None, *, all: bool = False,
                     spec: ScanSpec = DEFAULT_SPEC, workspace_id: Optional[str] = None,
                     is_superadmin: bool = False) -> List[str]:
        """Enqueue scan jobs for ACTIVE accounts only. Returns the new job ids.
        (The worker drains the queue; this never blocks on a scan.) Tenant-scoped: an
        ``all`` sweep covers only the caller's workspace; explicit ids outside the
        caller's workspace are silently skipped (never scan another tenant's account)."""
        if all:
            targets = [a["account_id"] for a in
                       self.registry.list_accounts(onboarding_status="active",
                                                   workspace_id=self._scoped_ws(workspace_id))]
        else:
            targets = []
            for aid in (account_ids or []):
                if not self.account_in_scope(aid, workspace_id=workspace_id,
                                             is_superadmin=is_superadmin):
                    continue
                a = self.registry.get_account(aid)
                if a and a.get("onboarding_status") == "active":
                    targets.append(aid)
        now = self.clock()
        job_ids = []
        for aid in targets:
            jid = self.job_id_gen()
            self.registry.record_scan_job(aid, jid, "queued", now_epoch=now)
            job_ids.append(jid)
        return job_ids

    def get_scan_job(self, job_id: str) -> Optional[dict]:
        return self.registry.get_scan_job(job_id)

    def pending_jobs(self) -> List[dict]:
        return self.registry.list_scan_jobs(status="queued")

    # ── continuous scheduling (cadence) ─────────────────────────────────────────
    def set_scan_schedule(self, account_id: str, schedule: Optional[str]) -> dict:
        """Set an account's scan cadence (off | hourly | daily | weekly | interval:N).
        Validates the grammar (fail-loud) before persisting to accounts.scan_schedule."""
        import cnapp_validate
        cnapp_validate.scan_interval(schedule)      # raises ValueError on a bad grammar
        if not self.registry.get_account(account_id):
            raise KeyError(f"account {account_id} not found")
        self.registry.upsert_account(account_id, now_epoch=self.clock(),
                                     scan_schedule=(schedule or "off"))
        return _mask_account(self.registry.get_account(account_id))

    def schedule_due_scans(self, *, workspace_id: Optional[str] = None) -> List[str]:
        """Enqueue a scan for every active account whose cadence has elapsed and which
        has no queued/running job. Returns the new job ids. The whole read+enqueue is
        one transaction so a concurrent tick can't double-enqueue (single-process).
        ``workspace_id`` scopes the sweep to one tenant (None => every tenant — the
        platform cron); the filter only engages when a WorkspaceStore is wired."""
        now = self.clock()
        job_ids: List[str] = []
        with self.registry._be.transaction():
            for a in self.registry.scans_due(now, workspace_id=self._scoped_ws(workspace_id)):
                jid = self.job_id_gen()
                self.registry.record_scan_job(a["account_id"], jid, "queued", now_epoch=now)
                job_ids.append(jid)
        return job_ids

    # ── lifecycle / drift readers (fail-open when no state store) ────────────────
    def get_trend(self, account_id: str) -> List[dict]:
        return self.state.trend(account_id) if self.state is not None else []

    def get_mttr(self, account_id: str) -> dict:
        if self.state is None:
            return {}
        return self.state.mttr(account_id, by_severity=True, sla_days=SLA_DAYS,
                               now_epoch=self.clock())

    def get_drift(self, account_id: str) -> dict:
        """The latest scan row's drift counters (populated by record_posture)."""
        if self.state is None:
            return {}
        rows = self.state.trend(account_id)
        return rows[-1] if rows else {}

    def record_lifecycle(self, account_id: str, payload: dict, *, scan_id: str,
                        scan_epoch: int) -> dict:
        """Fold a completed scan's results into the shared StateStore (drift / trend /
        MTTR). Mirrors the CLI's ``--state`` pipeline (record_scan → classify_and_diff →
        record_posture). Region is pinned to ``HOSTED_REGION`` ('all') for a full
        multi-region hosted scan — a byte-stable coverage partition, never
        ``payload['region']`` (the engine mutates self.region during iteration).
        Returns the drift dict."""
        import aws_live_scanner as als
        ts = aws_state.make_scan_ts(scan_epoch)
        rows = [_LR(r.get("status", ""), r.get("check_id", ""), r.get("section", ""),
                    r.get("resource", ""), r.get("message", ""), r.get("severity", ""))
                for r in payload.get("results", [])]
        counts = aws_state.severity_counts(rows)
        self.state.record_scan(account_id, scan_id, ts, payload.get("posture_score", 0.0),
                               counts, region=HOSTED_REGION, scanner_version=als.VERSION)
        drift = self.state.classify_and_diff(account_id, scan_id, ts, rows, region=HOSTED_REGION,
                                             global_sections=als.AWSLiveScanner.GLOBAL_SECTIONS)
        self.state.record_posture(account_id, scan_id, drift)
        return drift

    # ── results ───────────────────────────────────────────────────────────────
    def get_paths(self, account_id: str) -> List[dict]:
        p = self.results.get_latest(account_id)
        return (p or {}).get("attack_paths", [])

    def get_graph(self, account_id: str) -> Optional[dict]:
        p = self.results.get_latest(account_id)
        return (p or {}).get("graph_full")

    def get_blast_radius(self, account_id: str, node: str,
                         *, max_hops: int = 8) -> Optional[dict]:
        """Blast radius of a graph node, computed ON DEMAND from the account's persisted
        ``graph_full`` (read-only; zero AWS calls). Over the attack-edge universe
        (``aws_correlate.E_PATH``) it answers: what crown-jewel / admin can ``node`` REACH
        (forward), and what can REACH ``node`` (reverse). Returns None when the account has
        no scan (→404). ``max_hops`` is clamped to a sane bound. Imports-and-calls the
        byte-frozen ``aws_correlate`` (E_PATH, crown_nodes) — never edits it."""
        gd = self.get_graph(account_id)
        if gd is None:
            return None
        hops = max(1, min(int(max_hops or 8), 12))
        g = aws_graph.SecurityGraph.from_dict(gd)

        def _seg(nid: str) -> str:
            return nid.rsplit("/", 1)[-1].rsplit(":", 1)[-1]

        def _row(nid: str, path: List[str], terminal: Optional[str] = None) -> dict:
            nd = g.node(nid) or {}
            props = nd.get("props") or {}
            return {"id": nid, "kind": nd.get("kind", "Unknown"),
                    "label": props.get("name") or _seg(nid),
                    "path": path, "terminal": terminal}

        if g.node(node) is None:
            return {"node": node, "exists": False, "kind": None, "label": _seg(node),
                    "reaches": [], "reached_by": [], "internet_reachable": False,
                    "max_hops": hops, "counts": {"crowns": 0, "admins": 0, "sources": 0}}

        E = aws_correlate.E_PATH
        fwd = g.reachable(node, E, max_hops=hops)
        rev = g.reverse_reachable(node, E, max_hops=hops)
        crowns = aws_correlate.crown_nodes(g)
        admins = {n["id"] for n in g.nodes("AdminCapability")}

        reaches: List[dict] = []
        for nid, path in fwd.items():
            term = "data" if nid in crowns else ("admin" if nid in admins else None)
            if term:
                reaches.append(_row(nid, path, term))
        # crowns first, then shortest path, then id — a stable, most-critical-first order
        reaches.sort(key=lambda r: (r["terminal"] != "data", len(r["path"]), r["id"]))

        reached_by = [_row(nid, path) for nid, path in rev.items()]
        reached_by.sort(key=lambda r: (len(r["path"]), r["id"]))
        internet = any((g.node(nid) or {}).get("kind") == "InternetSource" for nid in rev)

        nd = g.node(node)
        return {"node": node, "exists": True, "kind": nd.get("kind", "Unknown"),
                "label": (nd.get("props") or {}).get("name") or _seg(node),
                "reaches": reaches, "reached_by": reached_by,
                "internet_reachable": internet, "max_hops": hops,
                "counts": {"crowns": sum(1 for r in reaches if r["terminal"] == "data"),
                           "admins": sum(1 for r in reaches if r["terminal"] == "admin"),
                           "sources": len(reached_by)}}

    def _graph_with_runtime(self, account_id: str, graph_dict: dict):
        """Rehydrate ``graph_dict`` and apply the READ-TIME overlays that make the enrichment
        props WQL/Control-queryable — runtime_monitored (EDR coverage) + DSPM data_types/
        sensitivity_tier — WITHOUT mutating graph_full (the pristine native seed) or aws_correlate."""
        g = aws_graph.SecurityGraph.from_dict(graph_dict)
        if self.state is not None:
            aws_edr.apply_runtime_monitored(g, self._edr_sensor_records(account_id), account=account_id)
        aws_dspm.apply_dspm(g)                                # data_types / sensitivity_tier (pure)
        return g

    def run_wql(self, account_id: str, query: dict) -> Optional[dict]:
        """Run a WQL query against the account's persisted graph (read-only; on-demand — never
        stored). None when the account has no scan (→404). Raises ValueError on a malformed /
        unsafe query (→400). The graph is runtime_monitored-overlaid so the endpoint-security
        queries are live. Imports-and-calls aws_wql (which imports frozen aws_correlate)."""
        gd = self.get_graph(account_id)
        if gd is None:
            return None
        import aws_wql
        g = self._graph_with_runtime(account_id, gd)
        try:
            rows = aws_wql.evaluate(query, g)
        except aws_wql.WQLError as e:
            raise ValueError(str(e))
        return {"count": len(rows), "nodes": rows}

    def get_issues(self, account_id: str, *, severity: Optional[str] = None,
                   status: Optional[str] = None) -> List[dict]:
        p = self.results.get_latest(account_id) or {}
        out = []
        for r in p.get("results", []):
            if r.get("status") not in ("FAIL", "WARN"):
                continue
            if severity and r.get("severity") != severity:
                continue
            if status and r.get("status") != status:
                continue
            out.append(r)
        return out

    def get_finding_catalog(self, account_id: str) -> List[dict]:
        """The deduped, severity-ranked finding_catalog (risk / business impact /
        step-by-step remediation / compliance / affected resources) for an account's
        latest scan — the data source for the Findings workspace + detail panel. When
        Controls are configured, their synthetic WARN entries are appended (display-only)."""
        base = list((self.results.get_latest(account_id) or {}).get("finding_catalog", []))
        return (base + self._controls_for_account(account_id)
                + self._edr_coverage_findings(account_id) + self._dspm_coverage_findings(account_id)
                + self._policies_for_account(account_id))

    # ── grounded copilot (Slice 2) ────────────────────────────────────────────
    def copilot_answer(self, account_id: str, question: str) -> Optional[dict]:
        """Answer a natural-language question grounded STRICTLY in this account's latest
        scan (finding_catalog + attack_paths + choke_points). None if the account has no
        scan. Offline-safe (extractive) unless a copilot LLM seam was injected."""
        p = self.results.get_latest(account_id)
        if not p:
            return None
        corpus = aws_copilot.build_corpus(findings=p.get("finding_catalog", []),
                                          paths=p.get("attack_paths", []),
                                          chokes=p.get("choke_points", []))
        return aws_copilot.answer(question, corpus, llm=self._copilot_llm)

    def org_copilot_answer(self, question: str, *, workspace_id: Optional[str] = None) -> dict:
        """Copilot grounded in the merged corpus across ACTIVE accounts (portfolio view).
        Scoped to ``workspace_id`` (a tenant); None => every workspace (superadmin/single-tenant)."""
        findings, paths, chokes = [], [], []
        for a in self.registry.list_accounts(onboarding_status="active", workspace_id=self._scoped_ws(workspace_id)):
            p = self.results.get_latest(a["account_id"])
            if not p:
                continue
            findings += p.get("finding_catalog", [])
            paths += p.get("attack_paths", [])
            chokes += p.get("choke_points", [])
        corpus = aws_copilot.build_corpus(findings=findings, paths=paths, chokes=chokes)
        return aws_copilot.answer(question, corpus, llm=self._copilot_llm)

    def get_account_summary(self, account_id: str) -> Optional[dict]:
        """Dashboard-shaped slice of an account's latest scan — posture + compliance
        + top attack paths/choke points + a severity histogram. Feeds the per-account
        Overview screen (the registry row alone has no compliance/paths)."""
        p = self.results.get_latest(account_id)
        if not p:
            return None
        sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for e in p.get("finding_catalog", []):
            s = e.get("severity", "")
            if s in sev:
                sev[s] += 1
        return {
            "account": p.get("account"), "region": p.get("region"),
            "posture_score": p.get("posture_score"), "posture_grade": p.get("posture_grade"),
            "summary": p.get("summary", {}), "severity_counts": sev,
            "compliance_scorecard": p.get("compliance_scorecard", {}),
            "graph": p.get("graph"),
            "attack_paths": p.get("attack_paths", [])[:10],
            "choke_points": p.get("choke_points", [])[:10],
        }

    def org_overview(self, *, workspace_id: Optional[str] = None) -> dict:
        """Roll every active account's latest scan into an org posture summary.
        (Metadata aggregation across per-account results; cross-account graph-union
        correlation is a separate follow-on — see docs.)"""
        payloads = [self.results.get_latest(a["account_id"])
                    for a in self.registry.list_accounts(onboarding_status="active", workspace_id=self._scoped_ws(workspace_id))]
        return aggregate_overview([p for p in payloads if p])

    def org_findings(self, *, workspace_id: Optional[str] = None,
                     include_controls: bool = True) -> List[dict]:
        """Flat, severity-ranked finding_catalog across all active accounts, each entry tagged
        with its account — the org-wide Findings queue. Control WARN overlays are included by
        default (the Findings queue shows them); ``include_controls=False`` returns ONLY real
        scan findings so the Projects business-impact roll-up is not inflated by display-only
        controls (and so it matches the SAMPLE Projects path, which reads raw findings)."""
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "": 4}
        out: List[dict] = []
        for a in self.registry.list_accounts(onboarding_status="active", workspace_id=self._scoped_ws(workspace_id)):
            p = self.results.get_latest(a["account_id"]) or {}
            for e in p.get("finding_catalog", []):
                tagged = dict(e)
                tagged["account"] = a["account_id"]
                out.append(tagged)
            if include_controls:
                out.extend(self._controls_for_account(a["account_id"]))   # display-only WARN overlay
                out.extend(self._edr_coverage_findings(a["account_id"]))   # EDR-01 coverage gap (WARN)
                out.extend(self._dspm_coverage_findings(a["account_id"]))  # DSPM-GAP classification (WARN)
                out.extend(self._policies_for_account(a["account_id"]))    # POLICY-xx policy-as-code (WARN)
        out.sort(key=lambda e: (order.get(e.get("severity", ""), 4), e.get("check_id", "")))
        return out

    # ── Projects (LBI/MBI/HBI business-impact grouping; read-only, display-only) ─
    @staticmethod
    def _finding_in_project(entry: dict, proj: dict) -> bool:
        """A finding belongs to a project when its account is in ``match.accounts`` (if given)
        AND one of its ``affected`` resources matches a ``match.resource_globs`` (if given). A
        project with neither an account nor a glob matches NOTHING (never everything)."""
        m = proj.get("match") or {}
        accts = set(m.get("accounts") or [])
        globs = m.get("resource_globs") or []
        if accts and entry.get("account") not in accts:
            return False
        if globs:
            from aws_state import _glob
            return any(_glob(g, str(r)) for r in (entry.get("affected") or []) for g in globs)
        return bool(accts)                       # account-only project (globs omitted)

    @staticmethod
    def _project_rollup(proj: dict, matched: List[dict]) -> dict:
        sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for e in matched:
            s = e.get("severity", "")
            if s in sev:
                sev[s] += 1
        return {"id": proj.get("id"), "name": proj.get("name", proj.get("id")),
                "tier": proj.get("tier", ""), "match": proj.get("match") or {},
                "severity_counts": sev, "finding_count": len(matched)}

    def list_projects(self, *, workspace_id: Optional[str] = None) -> List[dict]:
        """All configured projects with a per-project severity roll-up over the CURRENT
        finding catalog (scoped to a tenant). Empty when no projects are configured."""
        if not self.projects:
            return []
        findings = self.org_findings(workspace_id=workspace_id, include_controls=False)
        return [self._project_rollup(p, [f for f in findings if self._finding_in_project(f, p)])
                for p in self.projects]

    def project_summary(self, project_id: str, *, workspace_id: Optional[str] = None) -> Optional[dict]:
        """One project's roll-up PLUS its matched findings (for the project detail view).
        None when the project id is unknown (→404)."""
        proj = next((p for p in self.projects if p.get("id") == project_id), None)
        if proj is None:
            return None
        matched = [f for f in self.org_findings(workspace_id=workspace_id, include_controls=False)
                   if self._finding_in_project(f, proj)]
        return {**self._project_rollup(proj, matched), "findings": matched}

    # ── Controls (saved-WQL-query-as-Control; read-only, display-only) ──────────
    def _controls_for_account(self, account_id: str) -> List[dict]:
        """Synthetic WARN finding_catalog entries for every configured control whose saved WQL
        matches >=1 node in this account's graph. Read-time + display-only (status=WARN → never
        touches the FAIL-only posture score). The graph is rehydrated ONCE and every control is
        evaluated against it. Fail-safe per control: a bad/unsafe saved query is inert, never an
        error. Empty when no controls, no scan, or nothing matches."""
        if not self.controls:
            return []
        gd = self.get_graph(account_id)
        if gd is None:
            return []
        import aws_controls
        import aws_wql
        g = self._graph_with_runtime(account_id, gd)         # runtime_monitored-aware for EDR controls
        out: List[dict] = []
        for ctrl in self.controls:
            try:
                rows = aws_wql.evaluate(ctrl.get("query"), g)
            except aws_wql.WQLError:
                continue                                    # inert control (never crashes findings)
            if rows:
                out.append(aws_controls.control_finding(ctrl, account_id, rows))
        return out

    def list_controls(self, *, workspace_id: Optional[str] = None) -> List[dict]:
        """All configured controls with an org-wide roll-up: how many nodes each matches and in
        which active accounts. ``status`` is WARN when a control matches anything, else PASS (the
        control is satisfied). Empty when no controls are configured. Read-only; scoped to a tenant."""
        if not self.controls:
            return []
        import aws_controls
        import aws_wql
        agg = {str(c.get("id")): {"count": 0, "accounts": []} for c in self.controls}
        for a in self.registry.list_accounts(onboarding_status="active", workspace_id=self._scoped_ws(workspace_id)):
            gd = self.get_graph(a["account_id"])
            if gd is None:
                continue
            g = self._graph_with_runtime(a["account_id"], gd)
            for ctrl in self.controls:
                try:
                    rows = aws_wql.evaluate(ctrl.get("query"), g)
                except aws_wql.WQLError:
                    continue
                if rows:
                    slot = agg[str(ctrl.get("id"))]
                    slot["count"] += len(rows)
                    slot["accounts"].append(a["account_id"])
        out: List[dict] = []
        for ctrl in self.controls:
            slot = agg[str(ctrl.get("id"))]
            out.append({**aws_controls.control_meta(ctrl),
                        "match_count": slot["count"], "accounts_matched": slot["accounts"],
                        "status": "WARN" if slot["count"] else "PASS"})
        return out

    # ── Policies (policy-as-code; read-only, display-only) ──────────────────────
    def _policies_for_account(self, account_id: str) -> List[dict]:
        """Synthetic WARN POLICY-xx entries for every configured policy that FIRES for this account.
        A policy combines a graph condition (WQL over the runtime/DSPM-overlaid graph) and/or a
        finding-catalog condition (compliance-as-code) over the account's REAL scan findings (the
        stored catalog, not the overlays). The graph is rehydrated ONCE and only when some policy
        needs it. Read-time + display-only. Fail-safe per policy (a malformed rule is inert)."""
        if not self.policies:
            return []
        p = self.results.get_latest(account_id)
        if not p:
            return []
        catalog = p.get("finding_catalog", [])
        g = None
        gd = p.get("graph_full")
        if gd is not None and any(aws_policy.needs_graph(pol) for pol in self.policies):
            g = self._graph_with_runtime(account_id, gd)
        out: List[dict] = []
        for pol in self.policies:
            try:
                aws_policy.parse(pol)
                matched = aws_policy.evaluate(pol, g, catalog)
            except aws_policy.PolicyError:
                continue                                    # inert policy (never crashes findings)
            if matched:
                out.append(aws_policy.policy_finding(pol, account_id, matched))
        return out

    def list_policies(self, *, workspace_id: Optional[str] = None) -> List[dict]:
        """All configured policies with an org-wide roll-up: how many items each matches and in
        which active accounts. ``status`` is WARN when a policy fires anywhere, else PASS (the
        policy holds). Empty when no policies are configured. Read-only; scoped to a tenant."""
        if not self.policies:
            return []
        agg = {str(pol.get("id")): {"count": 0, "accounts": []} for pol in self.policies}
        need_graph = any(aws_policy.needs_graph(pol) for pol in self.policies)
        for a in self.registry.list_accounts(onboarding_status="active", workspace_id=self._scoped_ws(workspace_id)):
            p = self.results.get_latest(a["account_id"])
            if not p:
                continue
            catalog = p.get("finding_catalog", [])
            g = None
            gd = p.get("graph_full")
            if need_graph and gd is not None:
                g = self._graph_with_runtime(a["account_id"], gd)
            for pol in self.policies:
                try:
                    aws_policy.parse(pol)
                    matched = aws_policy.evaluate(pol, g, catalog)
                except aws_policy.PolicyError:
                    continue
                if matched:
                    slot = agg[str(pol.get("id"))]
                    slot["count"] += len(matched["nodes"]) + len(matched["findings"])
                    slot["accounts"].append(a["account_id"])
        out: List[dict] = []
        for pol in self.policies:
            slot = agg[str(pol.get("id"))]
            out.append({**aws_policy.policy_meta(pol),
                        "match_count": slot["count"], "accounts_matched": slot["accounts"],
                        "status": "WARN" if slot["count"] else "PASS"})
        return out

    # ── external-vuln ingest plane (SARIF/CycloneDX/SPDX) ───────────────────────
    def _require_state(self):
        if self.state is None:
            raise RuntimeError("ingest requires a state store; none configured")
        return self.state

    def _vuln_bundle(self) -> dict:
        b = self._vuln_bundle_data
        if callable(b):
            b = b()
        if not b:
            return {"records": [], "epss": {}, "kev": set(), "exploits": set()}
        return {"records": b.get("records") or b.get("osv") or [],
                "epss": b.get("epss") or {}, "kev": set(b.get("kev") or ()),
                "exploits": set(b.get("exploits") or ())}

    def _osv_feed(self, bundle: dict):
        # Key the cache on the records-list identity so a refreshed bundle (vuln_bundle
        # may be a callable returning a new records list) rebuilds the feed instead of
        # serving a stale one — the inventory lane tracks refreshes like the findings lane.
        records = bundle["records"]
        if self._osv_feed_cache is None or self._osv_feed_cache[0] is not records:
            self._osv_feed_cache = (records, aws_sidescan.OSVFeed.from_records(records))
        return self._osv_feed_cache[1]

    @staticmethod
    def _row_to_owned(r: dict) -> dict:
        """Rebuild the (node, EnrichedMatch, suppressed) owned item from a stored
        row — the verdict recompute runs off the DURABLE owned facts, so it works
        identically for a fresh doc and a graph-only refresh."""
        m = aws_sidescan.EnrichedMatch(
            cve=r["cve"], osv_id="", package=r.get("package") or "",
            installed_version=r.get("installed_version") or "",
            fixed_version=r.get("fixed_version"), severity=r.get("severity") or "",
            cvss_base=r.get("cvss_base"), epss=r.get("epss"), kev=bool(r.get("kev")),
            exploit_available=r.get("exploit_available"), ecosystem="")
        return {"node_id": r["node_id"], "node_kind": r.get("node_kind") or "Unknown",
                "match": m, "suppressed": bool(r.get("suppressed")),
                "tool": "", "doc_id": r.get("doc_id") or ""}

    def _recompute_account_verdicts(self, account_id: str, graph_dict):
        """Rebuild reachability verdicts for EVERY owned row of an account against
        the latest ``graph_full`` and persist them. Returns the per-CVE deltas
        (became_reachable / became_unreachable), annotated with kev/severity."""
        state = self.state
        rows = state.account_ingested_rows(account_id)
        owned = [self._row_to_owned(r) for r in rows]
        verdicts, _ = aws_ingest.compute_reachability_verdicts(graph_dict, owned)
        for (node, cve), v in verdicts.items():
            state.write_ingested_verdict(account_id, node, cve, v)
        became, gone = aws_ingest.diff_reachability(rows, verdicts)
        by_key = {(r["node_id"], r["cve"]): r for r in rows}

        def _annot(items):
            out = []
            for it in items:
                r = by_key.get((it["node_id"], it["cve"]), {})
                out.append({**it, "kev": bool(r.get("kev")),
                            "severity": r.get("severity")})
            return out
        return _annot(became), _annot(gone)

    def ingest_document(self, account_id: str, *, doc: dict,
                        source_tool: Optional[str] = None,
                        target_resource: Optional[str] = None) -> dict:
        """Parse an uploaded SARIF/CycloneDX/SPDX doc → own its CVEs against the
        account's graph → enrich from OverWatch's own bundle → persist → re-run
        reachability. Read-only on the scanned account (works off the uploaded doc
        + stored graph_full only). Raises ValueError on an unparseable doc or a
        cross-account target ARN (→ 400)."""
        state = self._require_state()
        now = self.clock()
        parsed = aws_ingest.parse_document(doc)                 # ValueError → 400
        doc_id = aws_ingest.doc_content_id(doc)

        graph_dict = self.get_graph(account_id)
        g = aws_ingest.SecurityGraph.from_dict(graph_dict or {})
        if parsed.lane == "vex":                                # a standalone VEX doc
            return self._ingest_vex(account_id, parsed, doc_id, target_resource, g, graph_dict, now)

        bundle = self._vuln_bundle()
        epss, kev, exploits = bundle["epss"], bundle["kev"], bundle["exploits"]
        node_id, node_kind, mapping_status = aws_ingest.resolve_owner(
            g, account_id, target_resource, parsed.subject_locator)

        owned = []
        if parsed.lane == "findings":
            cve_index = aws_ingest.build_cve_index(bundle["records"])
            for f in parsed.findings:
                m = aws_ingest.enrich_finding(f, cve_index, epss, kev, exploits)
                owned.append((m, aws_ingest.vex_suppressed(f.vex_state)))
        else:                                                   # inventory lane
            feed = self._osv_feed(bundle)
            for m in aws_sidescan.match_vulns(parsed.packages, feed, epss, kev, exploits):
                owned.append((m, False))

        tool = source_tool or parsed.source_tool
        with state._be.transaction():
            # an embedded CycloneDX analysis.state=not_affected is recorded into the SAME
            # durable ledger as standalone VEX, so suppression has ONE source of truth and a
            # later standalone doc can't order-dependently clobber it.
            if parsed.lane == "findings":
                for f in parsed.findings:
                    if aws_ingest.vex_suppressed(f.vex_state):
                        state.upsert_vex_statement({
                            "account": account_id, "node_id": node_id, "cve": f.cve,
                            "purl_identity": "*", "status": "not_affected",
                            "justification": f.vex_state, "vex_format": "cyclonedx",
                            "doc_id": doc_id, "last_seen_epoch": now})
            state.upsert_ingest_doc(
                account_id, doc_id, parsed.source_format, tool, target_resource,
                node_id, len(owned),
                "unmapped" if mapping_status == "unmapped" else "ingested", None, now)
            for m, suppressed in owned:
                # a durable VEX that arrived BEFORE this scan suppresses the new row too
                suppressed = suppressed or self._vex_suppresses(account_id, node_id, m.cve)
                state.upsert_ingested_vuln({
                    "account": account_id, "node_id": node_id, "cve": m.cve,
                    "node_kind": node_kind, "package": m.package,
                    "installed_version": m.installed_version, "fixed_version": m.fixed_version,
                    "severity": m.severity, "cvss_base": m.cvss_base, "epss": m.epss,
                    "kev": m.kev, "exploit_available": m.exploit_available,
                    "sources": [f"ingest:{tool}"], "suppressed": suppressed,
                    "mapping_status": mapping_status, "last_seen_epoch": now,
                    "doc_id": doc_id})
            if parsed.lane == "inventory":                      # an SBOM → durable snapshot
                self._persist_sbom_snapshot(state, account_id, node_id, node_kind,
                                            parsed, owned, doc_id, tool, now)
            became, _ = self._recompute_account_verdicts(account_id, graph_dict)

        return {"doc_id": doc_id, "resolved_node": node_id, "node_kind": node_kind,
                "mapping_status": mapping_status, "lane": parsed.lane,
                "finding_count": len(owned), "notes": parsed.notes,
                "newly_reachable_kev": [x for x in became if x.get("kev")],
                "top": state.list_ingested_vulns(account_id, limit=10)}

    # ── supply chain: SBOM snapshot persistence + license verdicts (Phase 4 S4) ──
    @property
    def license_policy(self) -> dict:
        """The license policy (allow/review/deny by category). Defaults to the strict
        shipped policy; an operator may override via ``service._license_policy`` (from
        settings.yaml). Verdicts are computed ON READ so a change needs no re-ingest."""
        return getattr(self, "_license_policy", None) or aws_license.DEFAULT_POLICY

    def _persist_sbom_snapshot(self, state, account_id: str, node_id: str, node_kind: str,
                               parsed, owned, doc_id: str, tool: str, now: int) -> None:
        """Persist an inventory-lane SBOM as a durable, diffable snapshot: header + FULL
        component set (with normalized license) + this scan's immutable CVE set. Called
        inside the ingest transaction; read-only (derived from the uploaded doc only)."""
        policy = self.license_policy
        # dedup by purl_identity (the storage PK) so component_count matches the rows that
        # persist (two versions of one package share a version-stripped identity).
        comps: dict = {}
        for c in parsed.components:
            if c.purl_identity in comps:
                continue
            a = aws_license.assess(c.license_raw, policy)
            comps[c.purl_identity] = {"purl_identity": c.purl_identity, "name": c.name, "version": c.version,
                                      "ecosystem": c.ecosystem, "origin": c.origin, "purl": c.purl,
                                      "license_raw": c.license_raw, "license_spdx": a["spdx_id"],
                                      "license_category": a["category"]}
        comp_list = list(comps.values())
        # attribute each matched CVE to a component identity (name+version → name → '*')
        by_nv = {(c.name, c.version): c.purl_identity for c in parsed.components}
        by_name: dict = {}
        for c in parsed.components:
            by_name.setdefault(c.name, c.purl_identity)
        cves, seen = [], set()
        for m, _sup in owned:
            pid = by_nv.get((m.package, m.installed_version)) or by_name.get(m.package) or "*"
            if (m.cve, pid) in seen:
                continue
            seen.add((m.cve, pid))
            cves.append({"cve": m.cve, "purl_identity": pid, "fixed_version": m.fixed_version})
        # account-scope the snapshot identity so two tenants uploading the same SBOM content
        # never collide on the content-hash primary key.
        snap_id = f"{account_id}:{doc_id}"
        state.record_sbom_snapshot({
            "snapshot_id": snap_id, "account": account_id, "node_id": node_id,
            "subject_key": aws_ingest.subject_key(node_id, node_kind),
            "source_format": parsed.source_format, "source_tool": tool,
            "component_count": len(comp_list), "ingested_epoch": now})
        state.insert_sbom_components(snap_id, comp_list)
        state.insert_snapshot_cves(snap_id, cves)

    def list_license_findings(self, account_id: str) -> List[dict]:
        """Read-time license verdicts over the account's LATEST SBOM components: every
        deny/review row per the (overridable) policy. Fail-open (no state / no SBOM = [])."""
        if self.state is None:
            return []
        policy = self.license_policy
        out = []
        for c in self.state.list_components(account_id):
            cat = c.get("license_category") or "unknown"
            spdx = c.get("license_spdx") or "UNKNOWN"
            verdict = aws_license.evaluate_license(spdx, cat, policy)
            if verdict == "allow":
                continue
            deny = verdict == "deny"
            out.append({
                "purl_identity": c.get("purl_identity"), "name": c.get("name"),
                "version": c.get("version"), "purl": c.get("purl"), "license_spdx": spdx,
                "license_category": cat, "verdict": verdict,
                "check_id": "LIC-DENY" if deny else "LIC-REVIEW",
                "severity": "HIGH" if deny else "MEDIUM",
                # display-only chips (NOT the crosswalk scorecard) — in the frozen 38-control
                # universe: CM-7 (least functionality / unauthorized software) for a deny,
                # CM-8 (component inventory) for a review.
                "compliance": {"NIST 800-53": "CM-7" if deny else "CM-8"},
            })
        return out

    # ── supply chain: SBOM subjects / snapshots / diff / components (read) ───────
    def list_sbom_subjects(self, account_id: str) -> List[dict]:
        return [] if self.state is None else self.state.list_sbom_subjects(account_id)

    def list_sbom_snapshots(self, account_id: str, subject: Optional[str] = None) -> List[dict]:
        return [] if self.state is None else self.state.list_sbom_snapshots(account_id, subject_key=subject)

    def list_sbom_components(self, account_id: str, snapshot: Optional[str] = None,
                            license: Optional[str] = None) -> List[dict]:
        return ([] if self.state is None
                else self.state.list_components(account_id, snapshot_id=snapshot, license_category=license))

    # ── Slice-5: agentless ECR registry views (derived from the persisted scan) ──
    def list_registry_images(self, account_id: str, repo: Optional[str] = None) -> List[dict]:
        """ECR registry images from the latest scan graph — each with its repo, digest, the
        scan_source(s) that found its CVEs (ecr-native-scan / ecr-sidescan / ingest:<tool>), a
        **deployed** vs **registry-only** flag (an inbound RUNS_IMAGE edge marks a deployed
        image), CVE counts, and its ``subject_key`` for deep-linking into the SBOM diff /
        components / VEX tabs. Read-only — works purely off the persisted ``graph_full``."""
        g = self.get_graph(account_id) or {}
        runners: set = set()
        vulns: dict = {}
        for e in g.get("edges", []):
            k = e.get("kind")
            if k == "RUNS_IMAGE":
                runners.add(e.get("target"))
            elif k == "HAS_VULN":
                v = vulns.setdefault(e.get("source"),
                                     {"sources": set(), "count": 0, "critical": 0, "high": 0})
                if e.get("scan_source"):
                    v["sources"].add(e["scan_source"])
                v["count"] += 1
                sev = (e.get("severity") or "").upper()
                if sev == "CRITICAL":
                    v["critical"] += 1
                elif sev == "HIGH":
                    v["high"] += 1
        out = []
        for n in g.get("nodes", []):
            if n.get("kind") != "ECRImage":
                continue
            if not (n.get("digest") or ""):
                continue                              # skip tag-only placeholder nodes (dedupe)
            nid = n.get("id") or ""
            rname, ruri = n.get("repository") or "", n.get("image_uri") or ""
            if repo and repo not in (rname, ruri):
                continue
            v = vulns.get(nid, {})
            out.append({
                "node_id": nid, "repository": rname, "image_uri": ruri,
                "digest": n.get("digest") or "",
                "subject_key": aws_ingest.subject_key(nid, "ECRImage"),
                "deployed": nid in runners,
                "scan_sources": sorted(v.get("sources", set())),
                "vuln_count": v.get("count", 0),
                "critical": v.get("critical", 0), "high": v.get("high", 0),
            })
        out.sort(key=lambda x: (x["repository"], x["digest"]))
        return out

    # per-repo posture checks (NOT CNT-02, which is a per-CVE finding, and NOT the
    # registry-wide CNT-06 whose resource is 'registry'/'ecr').
    _REPO_POSTURE = ("CNT-01", "CNT-03", "CNT-04", "CNT-05")

    def list_registry_repos(self, account_id: str) -> List[dict]:
        """ECR repositories with image count, deployed/registry-only split, aggregate CVE
        counts, and per-repo posture findings (CNT-01/03/04/05). A repo with a bad posture
        but no CVE-enriched image node still surfaces (seeded from the posture keys), so the
        worst-misconfigured repos are never hidden. Read-only."""
        imgs = self.list_registry_images(account_id)
        p = self.results.get_latest(account_id) or {}
        posture: dict = {}
        for r in p.get("results", []):
            if (r.get("check_id") or "") not in self._REPO_POSTURE or r.get("status") not in ("FAIL", "WARN"):
                continue
            rn = (r.get("resource") or "").split(":")[0]
            if rn in ("", "registry", "ecr"):         # registry-wide, not attributable to one repo
                continue
            posture.setdefault(rn, []).append(
                {"check_id": r["check_id"], "status": r["status"],
                 "severity": r.get("severity"), "message": r.get("message")})
        repos: dict = {}
        for im in imgs:
            rn = im["repository"]
            d = repos.setdefault(rn, {"repository": rn, "image_uri": im["image_uri"],
                                      "images": 0, "deployed": 0,
                                      "critical": 0, "high": 0, "vuln_count": 0})
            d["images"] += 1
            d["deployed"] += 1 if im["deployed"] else 0
            d["critical"] += im["critical"]
            d["high"] += im["high"]
            d["vuln_count"] += im["vuln_count"]
        for rn in posture:                            # posture-only repos (no image node) still surface
            repos.setdefault(rn, {"repository": rn, "image_uri": "", "images": 0,
                                  "deployed": 0, "critical": 0, "high": 0, "vuln_count": 0})
        out = []
        for rn, d in sorted(repos.items()):
            d["findings"] = posture.get(rn, [])
            out.append(d)
        return out

    # ── Batch 6: non-AWS registry connectors (org-level, config-driven, no schema) ──
    def _get_registry_connector(self, connector_id: str):
        for rc in self.registry_connectors:
            if rc.connector_id == connector_id:
                return rc
        return None

    @property
    def registry_request(self):
        """The Registry v2 control seam (token/manifest). Lazily bound to aws_layer_fetch (the sole
        allowlisted egress file) so offline tests inject a fake and never import it."""
        if self._registry_request is None:
            import aws_layer_fetch
            self._registry_request = aws_layer_fetch.registry_request
        return self._registry_request

    @property
    def registry_blob_get(self):
        """The Registry v2 layer-blob seam. Lazily bound to aws_layer_fetch (SSRF-guarded redirect)."""
        if self._registry_blob_get is None:
            import aws_layer_fetch
            self._registry_blob_get = aws_layer_fetch.registry_blob_get
        return self._registry_blob_get

    def list_registry_connectors(self) -> List[dict]:
        """The declared non-AWS registries (SECRET-MASKED), each annotated with its last-scan
        summary from the in-memory cache. Read-only + config-driven — no network, no scan."""
        out = []
        for rc in self.registry_connectors:
            row = aws_registry_connectors.mask_connector(rc)
            cached = self._registry_scan_cache.get(rc.connector_id)
            row["last_scan"] = (
                {"scanned_epoch": cached["scanned_epoch"], "images": len(cached["images"]),
                 "ok": sum(1 for im in cached["images"] if im["ok"]),
                 "critical": sum(im["critical"] for im in cached["images"]),
                 "high": sum(im["high"] for im in cached["images"]),
                 "notes": cached["notes"][:20]}
                if cached else None)
            out.append(row)
        return out

    def scan_registry_connector(self, connector_id: str, *, request=None, blob_get=None) -> dict:
        """Agentlessly pull + side-scan every image an ENABLED connector declares/enumerates,
        reusing the shared SBOM/OSV engine. The only impure registry entrypoint: it binds the real
        egress seams (or injected fakes) + the existing secret_reader + the same vuln bundle the
        native side-scan uses. Results are cached (last scan) and returned as source-agnostic image
        rows. NEVER touches posture/attack-path (aws_correlate stays frozen). A disabled/unknown
        connector returns an empty result rather than an error (safe-by-default)."""
        rc = self._get_registry_connector(connector_id)
        if rc is None or not rc.enabled:
            return {"connector_id": connector_id, "images": [], "notes": [
                "unknown connector" if rc is None else "connector disabled"], "scanned_epoch": self.clock()}
        bundle = self._vuln_bundle()
        feed = self._osv_feed(bundle)
        notes: List[str] = []
        results = aws_registry_connectors.scan_connector(
            rc, request=(request or self.registry_request),
            blob_get=(blob_get or self.registry_blob_get),
            secret_reader=self.secret_reader, feed=feed, epss=bundle["epss"],
            kev=bundle["kev"], exploits=bundle["exploits"], notes=notes)
        images = [aws_registry_connectors.registry_image_view(rc, ref, res) for ref, res in results]
        entry = {"connector_id": connector_id, "images": images, "notes": notes,
                 "scanned_epoch": self.clock()}
        self._registry_scan_cache[connector_id] = entry
        return entry

    def list_registry_connector_images(self, connector_id: Optional[str] = None) -> List[dict]:
        """The cached image rows from the last connector scan(s). Read-only — returns [] until a
        scan has been triggered (never blocks on a live pull)."""
        cids = [connector_id] if connector_id else [rc.connector_id for rc in self.registry_connectors]
        out: List[dict] = []
        for cid in cids:
            cached = self._registry_scan_cache.get(cid)
            if cached:
                out.extend(cached["images"])
        return out

    def sbom_diff(self, account_id: str, from_id: Optional[str] = None,
                  to_id: Optional[str] = None, subject: Optional[str] = None) -> Optional[dict]:
        """Diff two SBOM snapshots (A=from/older, B=to/newer). Explicit ids win; else the
        latest two of ``subject`` (or of the account's most-recent subject). Account-scoped:
        a snapshot id from another account never diffs (→ None → 404). Fail-open: < 2
        snapshots → None."""
        if self.state is None:
            return None
        if not (from_id and to_id):
            if not subject:
                recent = self.state.list_sbom_snapshots(account_id, limit=1)
                if not recent:
                    return None
                subject = recent[0]["subject_key"]
            snaps = self.state.list_sbom_snapshots(account_id, subject_key=subject)
            if len(snaps) < 2:
                return None
            to_id = to_id or snaps[0]["snapshot_id"]        # newest-first
            from_id = from_id or snaps[1]["snapshot_id"]
        a = self.state.get_sbom_snapshot(from_id)
        b = self.state.get_sbom_snapshot(to_id)
        if not a or not b or a["account"] != account_id or b["account"] != account_id:
            return None                                     # cross-account / missing → isolate
        d = aws_sbom_diff.diff_snapshots(
            self.state.get_snapshot_components(from_id), self.state.get_snapshot_cves(from_id),
            self.state.get_snapshot_components(to_id), self.state.get_snapshot_cves(to_id),
            account=account_id, subject_key=b.get("subject_key", ""),
            from_snapshot=from_id, to_snapshot=to_id,
            from_epoch=a.get("ingested_epoch", 0), to_epoch=b.get("ingested_epoch", 0))
        return aws_sbom_diff.to_dict(d)

    # ── standalone VEX (OpenVEX / CSAF) — durable, bidirectional suppression ─────
    def _vex_for(self, account_id: str, node_id: str, cve: str) -> Optional[dict]:
        """The governing VEX statement for an owned (node, cve) row. ingested_vulns is keyed
        (account,node,cve) with NO purl dimension, so ONLY a PRODUCT-WIDE ('*') statement
        auto-suppresses — a subcomponent-scoped statement is recorded + shown but never
        over-suppresses an unrelated finding on the same node. Among product-wide statements,
        a suppressing one (not_affected/fixed) wins, so the verdict is order-independent."""
        stmts = [s for s in self.state.list_vex_statements(account_id, node_id, cve)
                 if s.get("purl_identity") == "*"]
        supp = [s for s in stmts if s["status"] in aws_vex.SUPPRESSING]
        return supp[0] if supp else (stmts[0] if stmts else None)

    def _vex_suppresses(self, account_id: str, node_id: str, cve: str) -> bool:
        gov = self._vex_for(account_id, node_id, cve)
        return bool(gov and gov["status"] in aws_vex.SUPPRESSING)

    def _ingest_vex(self, account_id: str, parsed, doc_id: str,
                    target_resource: Optional[str], g, graph_dict, now: int) -> dict:
        """Own a standalone VEX doc: resolve each statement's product to an owned node,
        persist the durable statement, then RE-APPLY suppression to any already-ingested
        (node, cve) rows and re-run reachability. Read-only on the scanned account."""
        state = self._require_state()
        affected = set()
        with state._be.transaction():
            for st in parsed.vex_statements:
                node_id, _kind, _ms = aws_ingest.resolve_owner(
                    g, account_id, target_resource, st.product)
                pid = aws_ingest.purl_identity(st.purl) if st.purl else "*"
                state.upsert_vex_statement({
                    "account": account_id, "node_id": node_id, "cve": st.cve,
                    "purl_identity": pid, "status": st.status, "justification": st.justification,
                    "vex_format": parsed.source_format, "doc_id": doc_id, "last_seen_epoch": now})
                affected.add((node_id, st.cve))
            suppressed = 0
            for node_id, cve in affected:
                supp = self._vex_suppresses(account_id, node_id, cve)
                state.set_ingested_suppressed(account_id, node_id, cve, supp)   # bidirectional
                suppressed += int(supp)
            self._recompute_account_verdicts(account_id, graph_dict)
        return {"doc_id": doc_id, "resolved_node": None, "node_kind": "vex",
                "mapping_status": "resolved", "lane": "vex", "finding_count": len(parsed.vex_statements),
                "vex_applied": len(parsed.vex_statements), "vex_suppressed": suppressed,
                "notes": parsed.notes, "newly_reachable_kev": [], "top": []}

    def list_vex_statements(self, account_id: str) -> List[dict]:
        return [] if self.state is None else self.state.list_vex_statements(account_id)

    def list_vulns(self, account_id: str, **filters) -> List[dict]:
        # Reads fail OPEN: no state store yet = nothing ingested (empty), never a 500.
        return [] if self.state is None else self.state.list_ingested_vulns(account_id, **filters)

    def get_vuln(self, account_id: str, cve: str) -> List[dict]:
        return [] if self.state is None else self.state.get_ingested_cve(account_id, cve)

    def list_ingest_docs(self, account_id: str, limit: int = 200) -> List[dict]:
        return [] if self.state is None else self.state.list_ingest_docs(account_id, limit)

    def refresh_vuln_reachability(self, account_id: str) -> dict:
        """Force a verdict re-run against the latest graph_full (no new doc) — the
        cadence hook after a native scan lands a fresh graph. Returns the deltas."""
        state = self._require_state()
        graph_dict = self.get_graph(account_id)
        with state._be.transaction():
            became, gone = self._recompute_account_verdicts(account_id, graph_dict)
        return {"became_reachable": became, "became_unreachable": gone}

    def org_vulns(self, *, workspace_id: Optional[str] = None, **filters) -> List[dict]:
        """Org-wide ranked owned inventory, each row account-tagged."""
        if self.state is None:
            return []
        out: List[dict] = []
        for a in self.registry.list_accounts(onboarding_status="active", workspace_id=self._scoped_ws(workspace_id)):
            for r in self.state.list_ingested_vulns(a["account_id"], **filters):
                r["account"] = a["account_id"]
                out.append(r)
        out.sort(key=lambda r: -(r.get("priority_score") or 0))
        return out

    # ── CDR-lite: streaming detection ingest (GuardDuty / ASFF / CloudTrail) ─────
    # The runtime-sensor (EDR/CWPP) normalizers register alongside the cloud ones, so a
    # runtime detection flows through the IDENTICAL fold->reachability->incident path.
    _CDR_NORMALIZERS = {"guardduty": aws_cdr.normalize_guardduty,
                        "securityhub": aws_cdr.normalize_asff,
                        "cloudtrail": aws_cdr.normalize_cloudtrail_anomaly,
                        **aws_edr.NORMALIZERS, **aws_malware.NORMALIZERS}

    def ingest_detection(self, account_id: str, *, events, source: str) -> dict:
        """Fold live detection events onto the account's stored ``graph_full`` as
        THREAT_ON annotations and rank each by ACTUAL attack-path reachability. A
        detection ON an internet→crown/admin path or directly on a crown store is
        escalated to an incident. PUSH-only and read-only on the scanned account
        (works off the uploaded events + stored graph). ``source`` picks the
        normalizer. A malformed event is noted, never crashes. Raises ValueError on
        a cross-account detection ARN (→ 400)."""
        state = self._require_state()
        now = self.clock()
        norm = self._CDR_NORMALIZERS.get(source)
        if norm is None:
            raise ValueError(f"unknown detection source {source!r}")
        raw = events if isinstance(events, list) else [events]
        detections, notes = [], []
        for ev in raw:
            try:
                d = norm(ev)
            except Exception as e:                       # malformed row -> note, never crash
                notes.append(f"skipped malformed {source} event: {e}")
                continue
            if d is not None:
                detections.append(d)
        graph_dict = self.get_graph(account_id)
        # cross-account ARN -> ValueError -> 400 (one account can't fold onto another's node)
        verdicts, incidents, _ = aws_cdr.compute_detection_verdicts(
            graph_dict, detections, account=account_id)
        with state._be.transaction():
            for v in verdicts.values():
                state.upsert_cdr_detection(account_id, v, now)
        return {"accepted": len(raw), "normalized": len(detections),
                "mapped": sum(1 for v in verdicts.values()
                              if v["mapping_status"] == "resolved"),
                "incident_count": len(incidents), "incidents": incidents[:20],
                "notes": notes, "top": state.list_cdr_detections(account_id, limit=10)}

    def ingest_malware(self, account_id: str, *, source: str, events) -> dict:
        """Ingest a malware-scan finding batch (GuardDuty Malware Protection / ClamAV / YARA) →
        fold as THREAT_ON → reachability-rank → escalate a malware hit on a reachable/crown-bound
        resource to an incident (MAL-xx). PUSH-only + read-only; reuses the shared detection
        verdict path. Raises ValueError (→400) on an unknown malware source / cross-account ARN."""
        if source not in aws_malware.MALWARE_SOURCES:
            raise ValueError(f"unknown malware source {source!r} "
                             f"(known: {sorted(aws_malware.MALWARE_SOURCES)})")
        return self.ingest_detection(account_id, events=events, source=source)

    def list_detections(self, account_id: str, **filters) -> List[dict]:
        # Reads fail OPEN: no state store yet = nothing streamed (empty), never a 500.
        return [] if self.state is None else self.state.list_cdr_detections(account_id, **filters)

    def list_incidents(self, account_id: str, limit: int = 200) -> List[dict]:
        return ([] if self.state is None
                else self.state.list_cdr_detections(account_id, incidents_only=True, limit=limit))

    def org_incidents(self, limit: int = 200, *, workspace_id: Optional[str] = None) -> List[dict]:
        """Org-wide ranked incidents, each row account-tagged (portfolio SOC view)."""
        if self.state is None:
            return []
        out: List[dict] = []
        for a in self.registry.list_accounts(onboarding_status="active", workspace_id=self._scoped_ws(workspace_id)):
            for r in self.state.list_cdr_detections(a["account_id"], incidents_only=True,
                                                     limit=limit):
                r["account"] = a["account_id"]
                out.append(r)
        out.sort(key=lambda r: -(r.get("priority_score") or 0))
        return out[:limit]

    def refresh_detection_escalation(self, account_id: str) -> dict:
        """Re-run detection reachability against the latest ``graph_full`` (after a
        native scan lands a fresh graph) — re-escalates / de-escalates stored
        detections without re-POSTing events. Fail-open on no state / no detections."""
        if self.state is None:
            return {"reevaluated": 0}
        state = self.state
        rows = state.list_cdr_detections(account_id, limit=100000)
        if not rows:
            return {"reevaluated": 0}
        dets = [aws_cdr.NormalizedDetection(
                    id=r["detection_id"], source=r["source"], type=r.get("type") or "",
                    title=r.get("title") or "", severity=r.get("severity") or 0.0,
                    band=r.get("band") or "Unknown", node_kind=r.get("node_kind"),
                    node_key=r.get("node_key"),      # restored so unmapped GuardDuty/EC2/IAM
                    resource_arn=(r["node_id"]       # detections can re-map once the graph grows
                                  if str(r.get("node_id") or "").startswith("arn:") else None))
                for r in rows]
        graph_dict = self.get_graph(account_id)
        verdicts, incidents, _ = aws_cdr.compute_detection_verdicts(
            graph_dict, dets, account=account_id)
        now = self.clock()
        with state._be.transaction():
            for v in verdicts.values():
                state.upsert_cdr_detection(account_id, v, now)
        return {"reevaluated": len(verdicts), "incident_count": len(incidents)}

    def _detection_finding_entries(self, account_id: str) -> List[dict]:
        """Two synthetic finding_catalog entries from the account's escalated CDR
        incidents — ``THREAT-ING-KEV`` (CRITICAL) / ``THREAT-ING`` (HIGH) — so live
        detections route through the existing on_attack_path connector rules + the
        Findings UI. Check-level (per-detection detail rides ``affected``); the
        ``NIST 800-53`` compliance key is intentionally OUTSIDE COMPLIANCE_MAP, so it
        is exempt from the frozen-universe test (like the vuln-ingest entries)."""
        if self.state is None:
            return []
        incidents = self.state.list_cdr_detections(account_id, incidents_only=True, limit=5000)
        if not incidents:
            return []
        # segment by source class so each is labeled honestly: MALWARE (aws_malware) → MAL-xx
        # "Malware" section, RUNTIME (aws_edr) → EDR-02 "Runtime", the rest → THREAT-ING cloud.
        malware = [r for r in incidents if r.get("source") in aws_malware.MALWARE_SOURCES]
        runtime = [r for r in incidents if r.get("source") in aws_edr.RUNTIME_SOURCES]
        cloud = [r for r in incidents if r.get("source") not in aws_malware.MALWARE_SOURCES
                 and r.get("source") not in aws_edr.RUNTIME_SOURCES]
        crit = [r for r in cloud if (r.get("priority_band") or "").upper() == "CRITICAL"]
        rest = [r for r in cloud if (r.get("priority_band") or "").upper() != "CRITICAL"]
        buckets = (("THREAT-ING-KEV", "CRITICAL", crit,
                    "on a critical internet→crown attack path"),
                   ("THREAT-ING", "HIGH", rest, "on an attack path or a crown datastore"))
        out: List[dict] = []
        if malware:
            # MAL-03 (malware IN a crown/sensitive store — the malware∩DSPM win) > MAL-01
            # (malware on a critical-path workload) > MAL-02 (malware on a reachable workload).
            mal_crown = [r for r in malware if r.get("hits_crown")]
            mal_crit = [r for r in malware if not r.get("hits_crown")
                        and (r.get("priority_band") or "").upper() == "CRITICAL"]
            mal_rest = [r for r in malware if not r.get("hits_crown")
                        and (r.get("priority_band") or "").upper() != "CRITICAL"]
            for check_id, band, rows, blurb in (
                    ("MAL-03", "CRITICAL", mal_crown,
                     "a malicious object detected IN a crown-jewel / sensitive-data store"),
                    ("MAL-01", "CRITICAL", mal_crit,
                     "malware on a workload on a critical internet→crown/admin attack path"),
                    ("MAL-02", "HIGH", mal_rest, "confirmed malware on a reachable workload")):
                if not rows:
                    continue
                out.append({
                    "check_id": check_id, "section": "Malware", "severity": band, "status": "FAIL",
                    "compliance": {"NIST 800-53": "SI-3"},
                    "remediation_cmd": ("Isolate/quarantine the affected resource, snapshot it for "
                                        "forensics, remove the malicious file, and rotate any "
                                        "credentials it held; re-scan to confirm."),
                    "risk": (f"{len(rows)} confirmed malware detection(s) {blurb} — an attacker "
                             f"already has code execution on a resource that matters, fused onto "
                             f"the attack-path graph by reachability."),
                    "impact": "Confirmed malware on a reachable, crown-bound resource is an active "
                              "compromise, not a hypothetical misconfiguration.",
                    "steps": [f"Open /accounts/{account_id}/incidents (malware rows, ranked by reachability).",
                              "Isolate the resource and snapshot it for forensics.",
                              "Remove the malware, rotate credentials, and re-scan to confirm."],
                    "affected": [f"{r['source']}:{str(r.get('node_id') or '').split('/')[-1]}"
                                 for r in rows][:200],
                    "count": len(rows), "distinct": len(rows),
                })
        if runtime:
            r_crit = any((r.get("priority_band") or "").upper() == "CRITICAL" for r in runtime)
            out.append({
                "check_id": "EDR-02", "section": "Runtime",
                "severity": "CRITICAL" if r_crit else "HIGH", "status": "FAIL",
                "compliance": {"NIST 800-53": "SI-4"},
                "remediation_cmd": ("Triage the runtime detection on the affected workload, "
                                    "contain/isolate the host, and rotate any credentials it "
                                    "held; re-scan to confirm the attack path is severed."),
                "risk": (f"{len(runtime)} live runtime detection(s) from your endpoint sensor "
                         f"landed on a reachable, attack-path workload — an in-progress "
                         f"incident on a host an attacker can pivot through."),
                "impact": "A runtime alert on an internet-reachable, crown-bound workload is an "
                          "active incident, correlated onto the attack-path graph by reachability.",
                "steps": [f"Open /accounts/{account_id}/incidents (runtime rows, ranked by reachability).",
                          "Contain the affected workload and rotate its credentials.",
                          "Re-scan to confirm the attack path is severed."],
                "affected": [f"{r['source']}:{str(r.get('node_id') or '').split('/')[-1]}"
                             for r in runtime][:200],
                "count": len(runtime), "distinct": len(runtime),
            })
        for check_id, band, rows, blurb in buckets:
            if not rows:
                continue
            out.append({
                "check_id": check_id, "section": "Threats", "severity": band,
                "status": "FAIL", "compliance": {"NIST 800-53": "SI-4"},
                "remediation_cmd": ("Triage the live detection, contain the affected resource, "
                                    "and rotate any credentials it held; re-run the scan to "
                                    "confirm the path is severed."),
                "risk": (f"{len(rows)} live detection(s) {blurb} — active adversary signal fused "
                         f"onto the attack-path graph, demanding triage now."),
                "impact": "A live detection on a reachable, crown-bound resource is an in-progress "
                          "incident, not a hypothetical misconfiguration.",
                "steps": [f"Open /accounts/{account_id}/incidents (ranked by reachability).",
                          "Contain the affected resource and rotate its credentials.",
                          "Re-scan to confirm the attack path is severed."],
                "affected": [f"{r['source']}:{str(r.get('node_id') or '').split('/')[-1]}"
                             for r in rows][:200],
                "count": len(rows), "distinct": len(rows),
            })
        return out

    # ── EDR / runtime-sensor ingest + coverage ──────────────────────────────────
    _EDR_FRESH_SECONDS = 7 * 24 * 3600     # a sensor not re-reported within 7d is treated as gone

    @staticmethod
    def _sensor_key(s: dict) -> Optional[str]:
        """A stable per-workload identity key for the coverage row (strongest first)."""
        ns, pod = s.get("pod_namespace"), s.get("pod_name")
        return (s.get("instance_id") or s.get("ecs_task_arn") or s.get("resource_arn")
                or (f"{ns}/{pod}" if pod else None) or s.get("hostname") or s.get("sensor_id"))

    def _edr_sensor_records(self, account_id: str) -> List:
        """Fresh sensor inventory as aws_edr.SensorRecord[] (freshness-gated so a fleet that
        stopped reporting ages out of coverage)."""
        if self.state is None:
            return []
        fresh_since = self.clock() - self._EDR_FRESH_SECONDS
        return [aws_edr.SensorRecord(
                    vendor=r.get("vendor", ""), instance_id=r.get("instance_id"),
                    resource_arn=r.get("resource_arn"), ecs_task_arn=r.get("ecs_task_arn"),
                    pod_name=r.get("pod_name"), pod_namespace=r.get("pod_namespace"),
                    hostname=r.get("hostname"), sensor_id=r.get("sensor_id"),
                    status=r.get("status"), last_seen=r.get("reported_last_seen"))
                for r in self.state.list_edr_sensors(account_id, fresh_since_epoch=fresh_since)]

    def ingest_edr(self, account_id: str, *, vendor: str, sensors=None, detections=None) -> dict:
        """Ingest a runtime-sensor push: ``sensors`` (inventory → coverage / runtime_monitored)
        and/or ``detections`` (threats → THREAT_ON → ranked incidents, via the SHARED CDR verdict
        path). PUSH-only + read-only on the scanned account. ``vendor`` must be a known runtime
        source. Raises ValueError (→400) on an unknown vendor or a cross-account detection ARN."""
        state = self._require_state()
        if vendor not in aws_edr.RUNTIME_SOURCES:
            raise ValueError(f"unknown runtime vendor {vendor!r} "
                             f"(known: {sorted(aws_edr.RUNTIME_SOURCES)})")
        now = self.clock()
        upserted = 0
        with state._be.transaction():
            for s in (sensors or []):
                if not isinstance(s, dict):
                    continue
                key = self._sensor_key(s)
                if not key:
                    continue                                # a sensor row with no identity is dropped
                state.upsert_edr_sensor(account_id, str(key), vendor, s, now)
                upserted += 1
        det = (self.ingest_detection(account_id, events=detections, source=vendor)
               if detections else {"accepted": 0, "normalized": 0, "mapped": 0, "incident_count": 0})
        cov = self.edr_coverage(account_id) or {}
        return {"vendor": vendor, "sensors_upserted": upserted,
                "detections": {k: det.get(k) for k in ("accepted", "normalized", "mapped", "incident_count")},
                "coverage": cov.get("overall")}

    def _edr_coverage_findings(self, account_id: str) -> List[dict]:
        """A synthetic WARN finding (EDR-01) for the expected-runtime workloads with no sensor
        coverage — DISPLAY-ONLY (never touches the FAIL-only posture score). Only surfaced once
        the customer has actually pushed a sensor feed (else EVERY workload is 'uncovered' — noise,
        not signal). Empty when no scan / no sensors / full coverage."""
        if self.state is None:
            return []
        if not self.state.list_edr_sensors(account_id, limit=1):
            return []                                        # no sensor feed wired -> not a finding
        cov = self.edr_coverage(account_id)
        gaps = (cov or {}).get("gaps") or []
        if not gaps:
            return []
        exposed = sum(1 for g in gaps if g.get("exposure_rank"))
        return [{
            "check_id": "EDR-01", "section": "Runtime", "severity": "MEDIUM", "status": "WARN",
            "compliance": {"NIST 800-53": "SI-4"},
            "remediation_cmd": ("Deploy your runtime/endpoint sensor to the uncovered workloads "
                                "(or exclude intentionally sensor-less workloads from the baseline)."),
            "risk": (f"{len(gaps)} runtime-hostable workload(s) have no endpoint/runtime sensor "
                     f"reporting ({exposed} of them internet-reachable or crown-bound) — an "
                     f"attacker's actions there would be invisible to your EDR."),
            "impact": "An unmonitored workload that is internet-reachable and on a path to crown "
                      "data is a runtime blind spot on your most exposed asset.",
            "steps": ["Open /accounts/" + account_id + "/runtime for the ranked coverage gaps.",
                      "Roll out the sensor to the exposed, crown-bound workloads first.",
                      "Re-push the sensor inventory to confirm coverage."],
            "affected": [g["node_id"] for g in gaps][:500],
            "count": len(gaps), "distinct": len(gaps), "account": account_id,
        }]

    def edr_coverage(self, account_id: str) -> Optional[dict]:
        """Runtime sensor-coverage for an account: overall + per-kind monitored/total/pct + the
        UNMONITORED workloads ranked by attack-path exposure. None when there is no scan (→404).
        Read-only; reuses aws_correlate reachability UNCHANGED."""
        gd = self.get_graph(account_id)
        if gd is None:
            return None
        g = aws_graph.SecurityGraph.from_dict(gd)
        return aws_edr.compute_coverage(g, self._edr_sensor_records(account_id), account=account_id)

    def org_edr_coverage(self, *, workspace_id: Optional[str] = None) -> dict:
        """Org-wide runtime coverage roll-up, each account tagged (portfolio view)."""
        mon = tot = 0
        accounts: List[dict] = []
        for a in self.registry.list_accounts(onboarding_status="active", workspace_id=self._scoped_ws(workspace_id)):
            cov = self.edr_coverage(a["account_id"])
            if cov is None:
                continue
            o = cov["overall"]
            mon += o["monitored"]; tot += o["total"]
            accounts.append({"account": a["account_id"], **o, "gap_count": len(cov["gaps"])})
        return {"overall": {"monitored": mon, "total": tot,
                            "pct": round(100.0 * mon / tot, 1) if tot else None},
                "accounts": accounts}

    # ── DSPM: data inventory + classification coverage (read-time over the stored graph) ──
    def data_inventory(self, account_id: str) -> Optional[dict]:
        """The crown-jewel data inventory for an account: each sensitive datastore with its
        normalized data_types / tier / encryption / public / reader-count / attack-path exposure,
        a per-type + per-tier roll-up, and the classification-gap list. None when there is no scan
        (→404). Read-only over the stored graph; reuses aws_correlate reachability UNCHANGED."""
        gd = self.get_graph(account_id)
        if gd is None:
            return None
        g = aws_graph.SecurityGraph.from_dict(gd)
        return aws_dspm.compute_inventory(g, account=account_id)

    def org_data_inventory(self, *, workspace_id: Optional[str] = None) -> dict:
        """Org-wide sensitive-data roll-up, each account tagged."""
        tot = exposed = unenc = 0
        by_type: dict = {}
        accounts: List[dict] = []
        for a in self.registry.list_accounts(onboarding_status="active", workspace_id=self._scoped_ws(workspace_id)):
            inv = self.data_inventory(a["account_id"])
            if inv is None:
                continue
            tot += inv["total"]; exposed += inv["exposed"]; unenc += inv["unencrypted"]
            for t, c in inv["by_type"].items():
                by_type[t] = by_type.get(t, 0) + c
            accounts.append({"account": a["account_id"], "total": inv["total"],
                             "exposed": inv["exposed"], "unencrypted": inv["unencrypted"],
                             "gap_count": len(inv["classification_gaps"])})
        return {"overall": {"total": tot, "exposed": exposed, "unencrypted": unenc},
                "by_type": by_type, "accounts": accounts}

    def _dspm_coverage_findings(self, account_id: str) -> List[dict]:
        """A synthetic WARN finding (DSPM-GAP) for crown-jewel stores whose data TYPE is unknown
        (Macie-scored-but-untyped, or unclassified) — the honest 'enable Macie sensitive-data
        discovery / tag the store' signal in place of a byte-level content scan (which stays gated
        on the deferred EBS filesystem parse). Display-only (never touches the FAIL-only posture
        score). Empty when no scan / no crown stores / every store is typed."""
        inv = self.data_inventory(account_id)
        if inv is None:
            return []
        gaps = inv.get("classification_gaps") or []
        if not gaps:
            return []
        exposed = sum(1 for g in gaps if g.get("reachable_from_internet") or g.get("public"))
        return [{
            "check_id": "DSPM-GAP", "section": "Data", "severity": "MEDIUM", "status": "WARN",
            "compliance": {"NIST 800-53": "RA-2"},
            "remediation_cmd": ("Enable Amazon Macie sensitive-data discovery on these stores (or "
                                "apply a data-classification tag) so their data type is known — a "
                                "byte-level content scan is deferred to the EBS filesystem parse."),
            "risk": (f"{len(gaps)} crown-jewel data store(s) hold sensitive data but their data "
                     f"TYPE is unclassified ({exposed} of them public or internet-reachable) — you "
                     f"can't prioritize protection for data you haven't categorized."),
            "impact": "An unclassified, internet-reachable sensitive store is a data-breach blind "
                      "spot: the exposure is known but the regulated-data type (PII/PCI/PHI) is not.",
            "steps": ["Open /accounts/" + account_id + "/data for the classification gaps.",
                      "Enable Macie (or tag the store) on the exposed stores first.",
                      "Re-scan to confirm the data type is resolved."],
            "affected": [g["node_id"] for g in gaps][:500],
            "count": len(gaps), "distinct": len(gaps), "account": account_id,
        }]

    # ── multi-tenancy control plane (Phase-4 Slice-1) ───────────────────────────
    def _require_workspaces(self):
        if self.workspaces is None:
            raise RuntimeError("workspace management requires a WorkspaceStore; none configured")
        return self.workspaces

    def create_workspace(self, workspace_id: str, *, name: str = "", slug: Optional[str] = None,
                         plan: Optional[str] = None) -> dict:
        return self._require_workspaces().create_workspace(
            workspace_id, name=name, slug=slug, plan=plan, now_epoch=self.clock())

    def list_workspaces(self) -> List[dict]:
        return [] if self.workspaces is None else self.workspaces.list_workspaces()

    def get_workspace(self, workspace_id: str) -> Optional[dict]:
        return None if self.workspaces is None else self.workspaces.get_workspace(workspace_id)

    def update_workspace(self, workspace_id: str, **fields) -> dict:
        return self._require_workspaces().update_workspace(
            workspace_id, now_epoch=self.clock(), **fields)

    def delete_workspace(self, workspace_id: str) -> None:
        self._require_workspaces().delete_workspace(workspace_id)

    def list_members(self, workspace_id: str) -> List[dict]:
        return [] if self.workspaces is None else self.workspaces.list_members(workspace_id)

    def add_member(self, workspace_id: str, principal: str, *, role: str = "viewer",
                   added_by: str = "") -> dict:
        return self._require_workspaces().add_member(
            workspace_id, principal, role=role, added_by=added_by, now_epoch=self.clock())

    def remove_member(self, workspace_id: str, principal: str) -> None:
        self._require_workspaces().remove_member(workspace_id, principal)

    def list_platform_admins(self) -> List[str]:
        return [] if self.workspaces is None else self.workspaces.list_platform_admins()

    def add_platform_admin(self, principal: str) -> None:
        self._require_workspaces().add_platform_admin(principal, now_epoch=self.clock())

    def remove_platform_admin(self, principal: str) -> None:
        self._require_workspaces().remove_platform_admin(principal)

    # ── usage metering (billable = accounts under management) ───────────────────
    def _meter(self, metric: str, *, event_key: str, account_id: Optional[str] = None,
               workspace_id: Optional[str] = None, quantity: int = 1,
               meta: Optional[dict] = None) -> None:
        """Record one usage event, fail-open + no-op when no MeteringStore is wired.
        Resolves the billing workspace from the account when not supplied."""
        if self.metering is None:
            return
        ws = workspace_id
        if ws is None and account_id and self.workspaces is not None:
            ws = self.workspaces.workspace_of_account(account_id)
        self.metering.record(ws or DEFAULT_WORKSPACE, metric, event_key=event_key,
                             now_epoch=self.clock(), account_id=account_id,
                             quantity=quantity, meta=meta)

    def meter_scan_completed(self, account_id: str, job_id: str, *, findings: int = 0,
                             resources: int = 0) -> None:
        """Metering hook the worker calls after a 'done' scan (fail-open): the billable
        ``account.active`` gauge (this account was under management this period) plus a
        ``scan.completed`` observability event."""
        if self.metering is None:
            return
        period = aws_state.make_scan_ts(self.clock()).iso[:7]
        self._meter("scan.completed", event_key=job_id, account_id=account_id,
                    meta={"findings": findings, "resources": resources})
        self._meter("account.active", event_key=f"{account_id}:{period}", account_id=account_id)

    def usage_summary(self, workspace_id: str, *, period: Optional[str] = None) -> List[dict]:
        return [] if self.metering is None else self.metering.usage_summary(
            workspace_id, period=period)

    def usage_history(self, workspace_id: str, *, from_period=None, to_period=None) -> List[dict]:
        return [] if self.metering is None else self.metering.usage_history(
            workspace_id, from_period=from_period, to_period=to_period)

    def usage_rollup_all(self, *, period: Optional[str] = None) -> List[dict]:
        return [] if self.metering is None else self.metering.usage_rollup_all(period=period)

    def reconcile_usage(self) -> dict:
        """Re-derive billable events from durable tables (revenue integrity under
        fail-open). No-op when metering/workspaces aren't wired."""
        if self.metering is None:
            return {"reconciled": False}
        import cnapp_metering
        return cnapp_metering.reconcile(self.metering, self.registry, self.workspaces,
                                        now_epoch=self.clock())

    # ── cloud-forensics timeline (read-only CloudTrail, correlated) ─────────────
    def forensics_timeline(self, account_id: str, resource_arn: str, *,
                           start=None, end=None, limit: int = 200) -> dict:
        """Reconstruct the who-did-what-when timeline around ``resource_arn`` from
        read-only CloudTrail management events and correlate it with the account's
        attack-path graph, findings, and live CDR detections. Fail-open: no seam
        wired / seam error → a FORENSIC-00 'unavailable' result (never a phantom
        clean timeline). Read-only of config + management-event lookup only."""
        events = None
        if self._trail_reader is not None:
            try:
                events = self._trail_reader(account_id, resource_arn, start, end, limit)
            except Exception:
                events = None
        return aws_forensics.build_timeline(
            events, resource_arn=resource_arn, graph_dict=self.get_graph(account_id),
            catalog=self.get_finding_catalog(account_id),
            detections=self.list_detections(account_id))

    # ── connector framework (Phase-2 workflow plane) ────────────────────────────
    def _require_connectors(self):
        if self.connectors is None:
            raise RuntimeError("connector store not configured on this service")
        return self.connectors

    def create_connector(self, *, type: str, name: str, config: dict,
                         secret: Optional[str] = None, created_by: str = "",
                         workspace_id: Optional[str] = None) -> dict:
        """Create a connector. The one-time plaintext ``secret`` is handed to the
        injected secret_writer and only the returned ref is persisted; the response
        is masked (secret_configured bool). enabled defaults to 0 (safe by default).
        In a multi-tenant hub the connector is BOUND to the caller's workspace in the
        same transaction (single-tenant / no WorkspaceStore ⇒ unbound, global)."""
        store = self._require_connectors()
        now = self.clock()
        cid = self.connector_id_gen()
        ref = cc.store_secret(cid, secret, secret_writer=self.secret_writer) if secret else None
        try:
            with store._be.transaction():
                store.upsert_connector(cid, now_epoch=now, type=type, name=name, config=config or {},
                                       secret_ref=ref, enabled=False, created_by=created_by)
                if self.workspaces is not None:
                    self.workspaces.bind_connector(cid, workspace_id or DEFAULT_WORKSPACE, now)
        except Exception as e:
            # connectors.name is GLOBALLY unique (a pre-tenancy constraint). A collision — even
            # against another tenant's name — must surface as a clean 400 "name already in use",
            # NEVER an opaque 500 and never disclosing WHICH tenant holds it. (Per-workspace name
            # uniqueness is a follow-up: it needs a migration that drops the global ix_conn_name.)
            if cc._is_unique_violation(e):
                raise ValueError("connector name already in use")
            raise
        return cc.ConnectorStore._mask_connector(store.get_connector(cid))

    def list_connectors(self, *, workspace_id: Optional[str] = None) -> List[dict]:
        store = self._require_connectors()
        return [cc.ConnectorStore._mask_connector(c)
                for c in store.list_connectors(workspace_id=self._scoped_ws(workspace_id))]

    def get_connector(self, connector_id: str) -> Optional[dict]:
        c = self._require_connectors().get_connector(connector_id)
        return cc.ConnectorStore._mask_connector(c) if c else None

    def update_connector(self, connector_id: str, *, name: Optional[str] = None,
                        config: Optional[dict] = None) -> dict:
        """Partial update of NON-secret fields only. Never accepts/rotates the secret."""
        store = self._require_connectors()
        if not store.get_connector(connector_id):
            raise KeyError(f"connector {connector_id} not found")
        store.upsert_connector(connector_id, now_epoch=self.clock(), name=name, config=config)
        return cc.ConnectorStore._mask_connector(store.get_connector(connector_id))

    def set_connector_enabled(self, connector_id: str, enabled: bool) -> dict:
        store = self._require_connectors()
        if not store.get_connector(connector_id):
            raise KeyError(f"connector {connector_id} not found")
        store.set_enabled(connector_id, enabled, self.clock())
        return cc.ConnectorStore._mask_connector(store.get_connector(connector_id))

    def rotate_connector_secret(self, connector_id: str, secret: str) -> dict:
        store = self._require_connectors()
        if not store.get_connector(connector_id):
            raise KeyError(f"connector {connector_id} not found")
        ref = cc.store_secret(connector_id, secret, secret_writer=self.secret_writer)
        store.rotate_secret(connector_id, ref, self.clock())
        return cc.ConnectorStore._mask_connector(store.get_connector(connector_id))

    def delete_connector(self, connector_id: str) -> None:
        self._require_connectors().delete_connector(connector_id)

    def test_connector(self, connector_id: str) -> dict:
        """Send the one harmless test through the injected http_post; record the
        outcome. Surfaces the raw operator error (invalid_auth/channel_not_found/…)
        but never a secret."""
        store = self._require_connectors()
        c = store.get_connector(connector_id)
        if not c:
            raise KeyError(f"connector {connector_id} not found")
        now = self.clock()
        res = cc.test_ping(c, http_post=self.http_post, secret_reader=self.secret_reader,
                           now_epoch=now)
        store.record_test(connector_id, "ok" if res.ok else "failed",
                          res.detail or res.error or "", now)
        return {"ok": res.ok, "http_status": res.http_status, "detail": res.detail,
                "error": res.error, "external_ref": res.external_ref}

    # ── rules ───────────────────────────────────────────────────────────────────
    def list_rules(self, connector_id: str) -> List[dict]:
        return [_rule_dict(r) for r in self._require_connectors().list_rules(connector_id)]

    def create_rule(self, connector_id: str, spec: dict, *, created_by: str = "") -> dict:
        store = self._require_connectors()
        if not store.get_connector(connector_id):
            raise KeyError(f"connector {connector_id} not found")
        spec = dict(spec or {}); spec["created_by"] = created_by
        rid = store.upsert_rule(connector_id, now_epoch=self.clock(), spec=spec)
        return _rule_dict(store.get_rule(rid))

    def update_rule(self, connector_id: str, rule_id: int, spec: dict) -> dict:
        store = self._require_connectors()
        rule = store.get_rule(rule_id)
        # the rule MUST belong to this connector — else the scoped UPDATE below matches 0 rows
        # yet the trailing get_rule would return the OTHER connector's rule body (a cross-read).
        if not rule or rule.connector_id != connector_id:
            raise KeyError(f"rule {rule_id} not found")
        store.upsert_rule(connector_id, now_epoch=self.clock(), rule_id=rule_id, spec=spec or {})
        return _rule_dict(store.get_rule(rule_id))

    def delete_rule(self, connector_id: str, rule_id: int) -> None:
        self._require_connectors().delete_rule(connector_id, rule_id)

    # ── notify + preview + deliveries ───────────────────────────────────────────
    def _enriched_findings(self, account_id: str):
        """Latest catalog → EnrichedFinding[], plus real scan coverage (every check
        that emitted any result) and the on-attack-path check-id overlay."""
        p = self.results.get_latest(account_id) or {}
        onpath = set()
        for ap in p.get("attack_paths", []):
            for df in ap.get("driving_findings", []):
                onpath.add(str(df).split(":")[0])
        findings = [cc.to_finding(e, account_id, e.get("check_id") in onpath)
                    for e in p.get("finding_catalog", [])]
        # Append the ingest plane's reachable survivors as two CHECK-LEVEL aggregates
        # (VULN-ING-KEV / VULN-ING) so they route through the existing VULN-* +
        # on_attack_path rules — SEPARATE check_ids so ingested/native never mix.
        for e in self._ingested_finding_entries(account_id):
            findings.append(cc.to_finding(e, account_id, True))
        # CDR-lite: escalated live detections ride the same on_attack_path rule engine
        for e in self._detection_finding_entries(account_id):
            findings.append(cc.to_finding(e, account_id, True))
        coverage = {(account_id, r.get("check_id")) for r in p.get("results", [])
                    if r.get("check_id")}
        coverage |= {(account_id, f.check_id) for f in findings}
        return findings, coverage

    def _ingested_finding_entries(self, account_id: str) -> List[dict]:
        """Two synthetic finding_catalog entries from the account's REACHABLE,
        non-suppressed ingested survivors: ``VULN-ING-KEV`` (CRITICAL, reachable KEV)
        and ``VULN-ING`` (HIGH, reachable non-KEV). Per-CVE detail rides ``affected``;
        per-CVE notifications are deliberately not sent (the plane is check-level)."""
        if self.state is None:
            return []
        survivors = self.state.list_ingested_vulns(
            account_id, on_path=True, include_suppressed=False, limit=5000)
        buckets = (("VULN-ING-KEV", "CRITICAL", [r for r in survivors if r.get("kev")],
                    "known-exploited (KEV)"),
                   ("VULN-ING", "HIGH", [r for r in survivors if not r.get("kev")],
                    "exploitable"))
        out: List[dict] = []
        for check_id, band, rows, blurb in buckets:
            if not rows:
                continue
            out.append({
                "check_id": check_id, "section": "Vulnerabilities", "severity": band,
                "status": "FAIL", "compliance": {"NIST 800-53": "RA-5", "CIS": "7.x"},
                "remediation_cmd": ("Upgrade the affected package to its fixed version and "
                                    "rebuild/redeploy the image; re-scan to confirm the path "
                                    "is severed."),
                "risk": (f"{len(rows)} externally-reported {blurb} CVE(s) on internet-reachable "
                         f"resources with a path to crown-jewel data."),
                "impact": "Reachable, exploitable vulnerability on an attack path to sensitive data.",
                "steps": [f"Open /accounts/{account_id}/vulns (ranked by reachability).",
                          "Patch to fixed_version; re-scan to confirm the path is severed."],
                "affected": [f"{r['cve']}@{str(r['node_id']).split('/')[-1]}" for r in rows][:200],
                "count": len(rows), "distinct": len(rows),
            })
        return out

    def preview_rules(self, account_id: str) -> List[dict]:
        """Dry-run: which findings WOULD fire which connectors — zero outbound HTTP,
        zero AWS contact. The safe way to author rules. SCOPED to the account's workspace
        exactly like the real send path (run_rules) — else the dry-run would leak another
        tenant's connector ids/names + rule ids."""
        store = self._require_connectors()
        ws = self._account_ws(account_id)
        connectors = {c.connector_id: c for c in store.list_connectors(workspace_id=ws)}
        rules = store.list_rules(enabled_only=True, workspace_id=ws)
        findings, _ = self._enriched_findings(account_id)
        out = []
        for f in findings:
            for a in cc.match_finding(rules, f, connectors):
                c = connectors.get(a.connector_id)
                out.append({"connector_id": a.connector_id,
                            "connector_name": c.name if c else a.connector_id,
                            "rule_id": a.rule_id, "check_id": a.check_id,
                            "account": a.account, "severity": a.severity})
        return out

    def notify_account(self, account_id: str) -> dict:
        """Fire the rule engine over the account's latest scan → real outbound sends
        to the operator's tools (admin). Idempotent per (connector, finding)."""
        store = self._require_connectors()
        findings, coverage = self._enriched_findings(account_id)
        res = cc.run_rules(store, findings, coverage, http_post=self.http_post,
                           secret_reader=self.secret_reader, now_epoch=self.clock(),
                           hub_base=self.hub_base, workspace_id=self._account_ws(account_id))
        return {"sent": res.sent, "suppressed": res.suppressed, "resolved": res.resolved,
                "failed": res.failed, "digested": res.digested}

    def list_deliveries(self, connector_id: Optional[str] = None, *,
                       account: Optional[str] = None, status: Optional[str] = None,
                       workspace_id: Optional[str] = None) -> List[dict]:
        return self._require_connectors().list_deliveries(
            connector_id, account=account, status=status,
            workspace_id=self._scoped_ws(workspace_id))

    # ── drift digests ───────────────────────────────────────────────────────────
    def _build_digest(self, account_id: str, drift: dict, *, scan_id: str, scan_epoch: int,
                     prev_payload: Optional[dict] = None, frequency: str = "per_scan",
                     became_reachable: Optional[List[dict]] = None) -> dict:
        """Assemble the pure drift-digest inputs from the stored payload + the state
        store (trend/mttr) + the crosswalk-native compliance delta. Pure builder call.
        ``became_reachable`` (from the ingest reachability re-run) is shaped into the
        digest's ``newly_on_path`` per-CVE signal."""
        p = self.results.get_latest(account_id) or {}
        onpath = {str(df).split(":")[0] for ap in p.get("attack_paths", [])
                  for df in ap.get("driving_findings", [])}
        mttr = (self.state.mttr(account_id, by_severity=True, sla_days=SLA_DAYS,
                                now_epoch=scan_epoch) if self.state is not None else {})
        trend = self.state.trend(account_id) if self.state is not None else []
        return cc.build_drift_digest(
            account=account_id, scan_id=scan_id, scan_epoch=scan_epoch, drift=drift,
            trend=trend, mttr=mttr,
            catalog_by_check={e.get("check_id"): e for e in p.get("finding_catalog", [])},
            onpath=onpath,
            compliance_delta=cc.compliance_delta((prev_payload or {}).get("compliance_scorecard"),
                                                 p.get("compliance_scorecard")),
            extra_newly_on_path=_ingest_digest_items(became_reachable or []),
            window_id=cc.digest_window(frequency, scan_id, scan_epoch), hub_base=self.hub_base)

    def notify_digest(self, account_id: str, drift: dict, *, scan_id: str, scan_epoch: int,
                     prev_payload: Optional[dict] = None, frequency: str = "per_scan",
                     became_reachable: Optional[List[dict]] = None) -> dict:
        """Deliver ONE drift digest per (account, window) through the opted-in connectors
        (real outbound). Idempotent per window. A no-op when no connectors/state wired."""
        if self.connectors is None or self.state is None:
            return {"digested": 0}
        digest = self._build_digest(account_id, drift, scan_id=scan_id, scan_epoch=scan_epoch,
                                    prev_payload=prev_payload, frequency=frequency,
                                    became_reachable=became_reachable)
        res = cc.run_digest(self.connectors, digest, http_post=self.http_post,
                            secret_reader=self.secret_reader, now_epoch=self.clock(),
                            hub_base=self.hub_base, workspace_id=self._account_ws(account_id))
        return {"digested": res.digested, "failed": res.failed}

    def preview_digest(self, account_id: str) -> Optional[dict]:
        """Build (do NOT send) the drift digest from the account's latest persisted
        drift — the safe way to see what a digest would say. None if no scan/state."""
        if self.state is None:
            return None
        drift = self._latest_drift(account_id)
        if drift is None:
            return None
        return self._build_digest(account_id, drift, scan_id="preview", scan_epoch=self.clock())

    def _latest_drift(self, account_id: str) -> Optional[dict]:
        """Reconstruct the classify_and_diff-shaped drift for the latest scan from the
        stored scan-row counters + open findings (preview only)."""
        rows = self.state.trend(account_id)
        if not rows:
            return None
        r = rows[-1]
        return {"new": [], "resolved": [], "reopened": [], "mutated": [],
                "still_open": r.get("total_open", 0), "suppressed_count": r.get("suppressed_count", 0),
                "posture_delta": r.get("delta")}

    def list_digests(self, connector_id: Optional[str] = None, *,
                    account: Optional[str] = None, status: Optional[str] = None,
                    workspace_id: Optional[str] = None) -> List[dict]:
        return self._require_connectors().list_digests(
            connector_id, account=account, status=status,
            workspace_id=self._scoped_ws(workspace_id))

    # ── compliance breadth (crosswalk from the NIST 800-53 spine) ───────────────
    def _get_crosswalk(self):
        """(CROSSWALK, FRAMEWORKS, digest). Injected for tests, else the memoized
        bundled reference data (fail-open to empty)."""
        if getattr(self, "_crosswalk", None) is not None:
            return self._crosswalk
        import compliance_crosswalk
        return compliance_crosswalk.get_crosswalk()

    def list_compliance_frameworks(self) -> dict:
        """The framework catalog (5 native + 30+ crosswalk-derived) with authority,
        family, version, sources, and the crosswalk_version stamp. Reference data."""
        _xw, frameworks, digest = self._get_crosswalk()
        fams = sorted(frameworks.values(),
                      key=lambda m: (not m.get("native"), m.get("family", ""), m.get("id", "")))
        return {"crosswalk_version": digest, "spine": "NIST-800-53-Rev5", "frameworks": fams}

    def get_crosswalk(self, framework: Optional[str] = None) -> List[dict]:
        """The resolved crosswalk edges ({nist, framework, targets, confidence, note,
        sources}), optionally filtered to one framework — the 'show your work' surface."""
        crosswalk, _fw, _d = self._get_crosswalk()
        rows: List[dict] = []
        for _nist, fwmap in crosswalk.items():
            for fid, edge in fwmap.items():
                if framework and fid != framework:
                    continue
                rows.append(edge)
        rows.sort(key=lambda e: (e["framework"], e["nist"]))
        return rows

    def get_account_compliance(self, account_id: str, *, min_confidence: Optional[str] = None,
                              frameworks: Optional[List[str]] = None) -> Optional[dict]:
        """Native (5 hand-tagged) + derived (30+ crosswalked) scorecards for an
        account's latest scan. ``min_confidence`` RE-DERIVES the crosswalk at that
        tier (dropping lower-confidence mappings from the universe, failures, and
        pass_rate) — precise, not a lossy post-filter. The native card comes from the
        stored payload; the crosswalk fold is pure + cheap so it re-runs per call."""
        import aws_live_scanner as als
        p = self.results.get_latest(account_id)
        if not p:
            return None
        native = p.get("compliance_scorecard", {})
        crosswalk, fw, digest = self._get_crosswalk()
        derived = als.crosswalk_scorecard(native, crosswalk, fw, min_confidence=min_confidence)
        if frameworks:
            keep = set(frameworks)
            derived = {k: v for k, v in derived.items() if k in keep}
        return {"account": account_id, "native": native, "derived": derived,
                "crosswalk_version": digest, "generated_from": "NIST-800-53-Rev5",
                "min_confidence": min_confidence}

    def org_compliance(self, *, min_confidence: Optional[str] = None,
                       workspace_id: Optional[str] = None) -> dict:
        """Portfolio roll-up of native + derived scorecards across active accounts
        (a SUM of controls, mirroring the console's existing org merge — read org
        numbers as portfolio totals, not a dedup)."""
        merged_native: Dict[str, dict] = {}
        merged_derived: Dict[str, dict] = {}
        for a in self.registry.list_accounts(onboarding_status="active", workspace_id=self._scoped_ws(workspace_id)):
            comp = self.get_account_compliance(a["account_id"], min_confidence=min_confidence)
            if not comp:
                continue
            _merge_scorecard(merged_native, comp["native"])
            _merge_scorecard(merged_derived, comp["derived"])
        _xw, _fw, digest = self._get_crosswalk()
        return {"native": merged_native, "derived": merged_derived,
                "crosswalk_version": digest, "min_confidence": min_confidence}


def _merge_scorecard(acc: Dict[str, dict], card: Dict[str, dict]) -> None:
    """Portfolio SUM of a per-framework scorecard into an accumulator (in place) —
    mirrors the console's mergeScorecards, incl. the derived-only confidence_mix +
    control_provenance so org numbers carry the same provenance as per-account ones."""
    for fw, c in (card or {}).items():
        cur = acc.setdefault(fw, {"controls_total": 0, "controls_passed": 0,
                                  "controls_failed": 0, "failed_controls": []})
        cur["controls_total"] += c.get("controls_total", 0)
        cur["controls_passed"] += c.get("controls_passed", 0)
        cur["controls_failed"] += c.get("controls_failed", 0)
        cur["failed_controls"] = sorted(set(cur["failed_controls"]) | set(c.get("failed_controls", [])))
        for k in ("derived", "via", "min_confidence"):
            if k in c:
                cur[k] = c[k]
        if c.get("confidence_mix"):
            mix = cur.setdefault("confidence_mix", {"high": 0, "medium": 0, "low": 0})
            for tier in ("high", "medium", "low"):
                mix[tier] += c["confidence_mix"].get(tier, 0)
        if c.get("control_provenance"):
            cur.setdefault("control_provenance", {}).update(c["control_provenance"])
        t = cur["controls_total"]
        cur["pass_rate"] = round(100 * cur["controls_passed"] / t, 1) if t else 100.0


def _ingest_digest_items(became_reachable: List[dict]) -> List[dict]:
    """Shape ingest ``became_reachable`` deltas into digest ``newly_on_path`` items —
    ``{check_id: "VULN-ING[-KEV]:<cve>", severity, on_attack_path: True}`` — so a
    newly-REACHABLE KEV renders in every digest with zero new renderer code."""
    out = []
    for it in became_reachable or []:
        kev = bool(it.get("kev"))
        out.append({
            "check_id": f"{'VULN-ING-KEV' if kev else 'VULN-ING'}:{it.get('cve', '')}",
            "severity": "CRITICAL" if kev else (it.get("severity") or "HIGH"),
            "resource": str(it.get("node_id", "")).split("/")[-1],
            "on_attack_path": True,
        })
    return out


def _rule_dict(r) -> dict:
    """Serialize a ConnectorRule for the API (no secrets involved — rules are config)."""
    if r is None:
        return {}
    return {
        "id": r.id, "connector_id": r.connector_id, "name": r.name, "enabled": r.enabled,
        "priority": r.priority, "min_severity": r.min_severity, "severities": r.severities,
        "sections": r.sections, "check_globs": r.check_globs, "not_check_globs": r.not_check_globs,
        "account_globs": r.account_globs, "on_attack_path": r.on_attack_path,
        "statuses": r.statuses, "frameworks": r.frameworks, "controls": r.controls,
        "min_count": r.min_count, "min_distinct": r.min_distinct, "dedup_mode": r.dedup_mode,
        "throttle_seconds": r.throttle_seconds, "renotify_on_escalation": r.renotify_on_escalation,
        "notify_on_resolve": r.notify_on_resolve, "stop_on_match": r.stop_on_match,
        "connector_ids": r.connector_ids, "tags": r.tags, "message_template": r.message_template,
        "severity_override": r.severity_override, "created_by": r.created_by,
    }


def aggregate_overview(payloads: List[dict]) -> dict:
    """Pure fold over per-account serialized scans -> org dashboard numbers."""
    totals = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0}
    accounts, all_paths, all_chokes = [], [], []
    crown_terminals = set()
    for p in payloads:
        s = p.get("summary", {})
        for k in totals:
            totals[k] += int(s.get(k, 0) or 0)
        accounts.append({"account": p.get("account"), "region": p.get("region"),
                         "posture_score": p.get("posture_score"),
                         "critical_paths": sum(1 for ap in p.get("attack_paths", [])
                                               if ap.get("severity") == "CRITICAL")})
        for ap in p.get("attack_paths", []):
            tagged = dict(ap); tagged["account"] = p.get("account")
            all_paths.append(tagged)
            if ap.get("terminal_kind") == "data":
                crown_terminals.add(ap.get("terminal"))
        for c in p.get("choke_points", []):
            tagged = dict(c); tagged["account"] = p.get("account")
            all_chokes.append(tagged)
    all_paths.sort(key=lambda x: (-int(x.get("score", 0)), str(x.get("terminal", ""))))
    all_chokes.sort(key=lambda x: -float(x.get("weighted_score", 0)))
    n_critical = sum(1 for ap in all_paths if ap.get("severity") == "CRITICAL")
    scores = [a["posture_score"] for a in accounts if a["posture_score"] is not None]
    return {
        "accounts_scanned": len(payloads),
        "summary": totals,
        "org_posture_score": round(sum(scores) / len(scores), 1) if scores else 100.0,
        "critical_attack_paths": n_critical,
        "crown_jewels_at_risk": len(crown_terminals),
        "accounts": sorted(accounts, key=lambda a: -(a["critical_paths"] or 0)),
        "top_attack_paths": all_paths[:10],
        "top_choke_points": all_chokes[:10],
    }


def _mask_account(a: dict) -> dict:
    """Never leak the secret ref over the API; expose only that one is set."""
    d = dict(a)
    ref = d.pop("external_id_ref", None)
    d["external_id_configured"] = bool(ref)
    return d
