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

import aws_ingest
import aws_sidescan
import aws_state
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
                 crosswalk=None, state=None, vuln_bundle=None,
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
        # ── connector framework (Phase-2 workflow plane) ──────────────────────
        self.connectors = connectors            # a cnapp_connectors.ConnectorStore (or None)
        self.hub_base = hub_base
        self.connector_id_gen = connector_id_gen
        self._crosswalk = crosswalk             # None -> lazy bundled compliance_crosswalk
        self.state = state                      # an aws_state.StateStore (or None) — lifecycle/drift/trend
        # ── external-vuln ingest plane (Phase-2 capstone) ─────────────────────
        # The SAME {records/osv, epss, kev, exploits} bundle the native side-scan
        # uses, so an ingested CVE gets byte-identical KEV/EPSS. Fail-open: None →
        # CVEs are owned but enrichment is empty (reachability surfaced honestly).
        self._vuln_bundle_data = vuln_bundle
        self._osv_feed_cache = None
        self._http_post = http_post             # None -> lazy urllib default (see http_post)
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
        rows = [_mask_account(a) for a in
                self.registry.list_accounts(onboarding_status=onboarding_status, health=health)]
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

    def schedule_due_scans(self) -> List[str]:
        """Enqueue a scan for every active account whose cadence has elapsed and which
        has no queued/running job. Returns the new job ids. The whole read+enqueue is
        one transaction so a concurrent tick can't double-enqueue (single-process)."""
        now = self.clock()
        job_ids: List[str] = []
        with self.registry._be.transaction():
            for a in self.registry.scans_due(now):
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
        latest scan — the data source for the Findings workspace + detail panel."""
        return list((self.results.get_latest(account_id) or {}).get("finding_catalog", []))

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

    def org_findings(self) -> List[dict]:
        """Flat, severity-ranked finding_catalog across all active accounts, each
        entry tagged with its account — the org-wide Findings queue."""
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "": 4}
        out: List[dict] = []
        for a in self.registry.list_accounts(onboarding_status="active"):
            p = self.results.get_latest(a["account_id"]) or {}
            for e in p.get("finding_catalog", []):
                tagged = dict(e)
                tagged["account"] = a["account_id"]
                out.append(tagged)
        out.sort(key=lambda e: (order.get(e.get("severity", ""), 4), e.get("check_id", "")))
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
        bundle = self._vuln_bundle()
        epss, kev, exploits = bundle["epss"], bundle["kev"], bundle["exploits"]

        graph_dict = self.get_graph(account_id)
        g = aws_ingest.SecurityGraph.from_dict(graph_dict or {})
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
            state.upsert_ingest_doc(
                account_id, doc_id, parsed.source_format, tool, target_resource,
                node_id, len(owned),
                "unmapped" if mapping_status == "unmapped" else "ingested", None, now)
            for m, suppressed in owned:
                state.upsert_ingested_vuln({
                    "account": account_id, "node_id": node_id, "cve": m.cve,
                    "node_kind": node_kind, "package": m.package,
                    "installed_version": m.installed_version, "fixed_version": m.fixed_version,
                    "severity": m.severity, "cvss_base": m.cvss_base, "epss": m.epss,
                    "kev": m.kev, "exploit_available": m.exploit_available,
                    "sources": [f"ingest:{tool}"], "suppressed": suppressed,
                    "mapping_status": mapping_status, "last_seen_epoch": now,
                    "doc_id": doc_id})
            became, _ = self._recompute_account_verdicts(account_id, graph_dict)

        return {"doc_id": doc_id, "resolved_node": node_id, "node_kind": node_kind,
                "mapping_status": mapping_status, "lane": parsed.lane,
                "finding_count": len(owned), "notes": parsed.notes,
                "newly_reachable_kev": [x for x in became if x.get("kev")],
                "top": state.list_ingested_vulns(account_id, limit=10)}

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

    def org_vulns(self, **filters) -> List[dict]:
        """Org-wide ranked owned inventory, each row account-tagged."""
        if self.state is None:
            return []
        out: List[dict] = []
        for a in self.registry.list_accounts(onboarding_status="active"):
            for r in self.state.list_ingested_vulns(a["account_id"], **filters):
                r["account"] = a["account_id"]
                out.append(r)
        out.sort(key=lambda r: -(r.get("priority_score") or 0))
        return out

    # ── connector framework (Phase-2 workflow plane) ────────────────────────────
    def _require_connectors(self):
        if self.connectors is None:
            raise RuntimeError("connector store not configured on this service")
        return self.connectors

    def create_connector(self, *, type: str, name: str, config: dict,
                         secret: Optional[str] = None, created_by: str = "") -> dict:
        """Create a connector. The one-time plaintext ``secret`` is handed to the
        injected secret_writer and only the returned ref is persisted; the response
        is masked (secret_configured bool). enabled defaults to 0 (safe by default)."""
        store = self._require_connectors()
        now = self.clock()
        cid = self.connector_id_gen()
        ref = cc.store_secret(cid, secret, secret_writer=self.secret_writer) if secret else None
        store.upsert_connector(cid, now_epoch=now, type=type, name=name, config=config or {},
                               secret_ref=ref, enabled=False, created_by=created_by)
        return cc.ConnectorStore._mask_connector(store.get_connector(cid))

    def list_connectors(self) -> List[dict]:
        store = self._require_connectors()
        return [cc.ConnectorStore._mask_connector(c) for c in store.list_connectors()]

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
        if not store.get_rule(rule_id):
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
        zero AWS contact. The safe way to author rules."""
        store = self._require_connectors()
        connectors = {c.connector_id: c for c in store.list_connectors()}
        rules = store.list_rules(enabled_only=True)
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
                           hub_base=self.hub_base)
        return {"sent": res.sent, "suppressed": res.suppressed, "resolved": res.resolved,
                "failed": res.failed, "digested": res.digested}

    def list_deliveries(self, connector_id: Optional[str] = None, *,
                       account: Optional[str] = None, status: Optional[str] = None) -> List[dict]:
        return self._require_connectors().list_deliveries(connector_id, account=account,
                                                          status=status)

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
                            hub_base=self.hub_base)
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
                    account: Optional[str] = None, status: Optional[str] = None) -> List[dict]:
        return self._require_connectors().list_digests(connector_id, account=account, status=status)

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

    def org_compliance(self, *, min_confidence: Optional[str] = None) -> dict:
        """Portfolio roll-up of native + derived scorecards across active accounts
        (a SUM of controls, mirroring the console's existing org merge — read org
        numbers as portfolio totals, not a dedup)."""
        merged_native: Dict[str, dict] = {}
        merged_derived: Dict[str, dict] = {}
        for a in self.registry.list_accounts(onboarding_status="active"):
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
