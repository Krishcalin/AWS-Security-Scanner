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
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Protocol

import cnapp_onboarding
import cnapp_validate
from cnapp_validate import ConnectionHealth

ROLE_NAME = "CnappScannerRole"


# ── scan spec + result store protocol ────────────────────────────────────────
@dataclass(frozen=True)
class ScanSpec:
    region: str = "us-east-1"
    sections: Optional[List[str]] = None
    all_regions: bool = True


DEFAULT_SPEC = ScanSpec()


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
        "compliance_scorecard": als.compliance_scorecard(sc.results),
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
                 clock: Callable[[], int] = None):
        import time
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
        self.clock = clock or (lambda: int(time.time()))

    def _role_arn(self, account_id: str) -> str:
        return f"arn:aws:iam::{account_id}:role/{ROLE_NAME}"

    # ── onboarding ────────────────────────────────────────────────────────────
    def init_onboarding(self, account_id: str, *, region: str = "us-east-1",
                        method: str = "single", alias: str = "") -> dict:
        """Mint the ExternalId (stored only as a secret ref), register the account
        as 'pending', and return the CloudFormation launch URL + CLI.

        IDEMPOTENT: re-onboarding an account that already has an ExternalId REUSES
        it (never rotates) — rotating would invalidate the already-deployed CFN
        trust and silently break a live connection. Only a dedicated rotate flow
        should mint a new ExternalId."""
        now = self.clock()
        existing = self.registry.get_account(account_id)
        if existing and existing.get("external_id_ref"):
            ref = existing["external_id_ref"]
            external_id = cnapp_onboarding.resolve_external_id(
                ref, secret_reader=self.secret_reader, region=region) or ""
            # refresh only non-secret config; preserve lifecycle + the ExternalId
            self.registry.upsert_account(account_id, now_epoch=now, alias=(alias or None),
                                         onboarding_method=method, enabled_regions=[region])
            return {"account_id": account_id, "role_name": cnapp_onboarding.ROLE_NAME,
                    "external_id_ref": ref, "reused": True,
                    "cfn_launch_url": cnapp_onboarding.build_launch_url(
                        self.cfn_template_url, self.hub_role_arn, external_id, region),
                    "cli": cnapp_onboarding.build_cli(
                        self.cfn_template_url, self.hub_role_arn, external_id, region)}
        init = cnapp_onboarding.init_onboarding(
            account_id, region, id_gen=self.id_gen, secret_writer=self.secret_writer,
            hub_role_arn=self.hub_role_arn, cfn_template_url=self.cfn_template_url)
        self.registry.upsert_account(
            account_id, now_epoch=now, alias=alias, onboarding_method=method,
            role_arn=self._role_arn(account_id), external_id_ref=init.external_id_ref,
            enabled_regions=[region])
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
    def list_accounts(self, *, onboarding_status=None, health=None) -> List[dict]:
        return [_mask_account(a) for a in
                self.registry.list_accounts(onboarding_status=onboarding_status, health=health)]

    def get_account(self, account_id: str) -> Optional[dict]:
        a = self.registry.get_account(account_id)
        return _mask_account(a) if a else None

    # ── scanning ──────────────────────────────────────────────────────────────
    def trigger_scan(self, account_ids: Optional[List[str]] = None, *, all: bool = False,
                     spec: ScanSpec = DEFAULT_SPEC) -> List[str]:
        """Enqueue scan jobs for ACTIVE accounts only. Returns the new job ids.
        (The worker drains the queue; this never blocks on a scan.)"""
        if all:
            targets = [a["account_id"] for a in
                       self.registry.list_accounts(onboarding_status="active")]
        else:
            targets = []
            for aid in (account_ids or []):
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

    # ── results ───────────────────────────────────────────────────────────────
    def get_paths(self, account_id: str) -> List[dict]:
        p = self.results.get_latest(account_id)
        return (p or {}).get("attack_paths", [])

    def get_graph(self, account_id: str) -> Optional[dict]:
        p = self.results.get_latest(account_id)
        return (p or {}).get("graph_full")

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

    def org_overview(self) -> dict:
        """Roll every active account's latest scan into an org posture summary.
        (Metadata aggregation across per-account results; cross-account graph-union
        correlation is a separate follow-on — see docs.)"""
        payloads = [self.results.get_latest(a["account_id"])
                    for a in self.registry.list_accounts(onboarding_status="active")]
        return aggregate_overview([p for p in payloads if p])


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
