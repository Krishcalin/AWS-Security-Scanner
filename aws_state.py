#!/usr/bin/env python3
"""
aws_state.py — Persistent finding lifecycle, drift, waivers & posture history
(Phase 5B). Pure stdlib ``sqlite3`` — NO boto3, NO print.

Gives the scanner *memory*: across runs it tracks each finding's lifecycle
(open -> resolved -> reopened), records config drift (severity bump / message
change = MUTATED), computes MTTR and a posture trend, and lets an operator waive
a finding (approver + expiry) so it stops failing the build without being hidden
or deleted.

Design invariants
-----------------
* **Pure** — stdlib sqlite3 only; every timestamp is *caller-supplied* UTC
  (``ScanTs``) so behavior is deterministic and testable (``:memory:``).
* **Two-axis lifecycle** (AWS Security Hub model): the stored ``status`` is only
  ``open`` | ``resolved``. ``NEW`` is a read-time projection (first seen this
  scan) and ``SUPPRESSED`` is a *live* overlay computed from waivers at gate/score
  time — nothing is stored as suppressed, which is what gives free
  auto-reactivation the instant a waiver expires (zero DB mutation).
* **Coverage-gated resolve** — a finding is only auto-resolved if THIS scan
  actually inspected its (account, region, check_id). A ``--sections`` /
  single-region run therefore never mass-resolves everything it did not look at.
* **Fail-open** — when no state DB is supplied the scanner runs exactly as before;
  this module is only engaged behind an explicit ``--state`` flag.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from collections import namedtuple
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SCHEMA_VERSION = 4   # v4: + drift-digest delivery ledger (digest_log)
KEY_VERSION = 1

# Caller-injected scan timestamp (one per run). epoch = arithmetic column,
# iso = display column.
ScanTs = namedtuple("ScanTs", ["epoch", "iso"])


def make_scan_ts(epoch: int) -> ScanTs:
    """Build a ScanTs from an injected UTC epoch (seconds)."""
    iso = datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()
    return ScanTs(int(epoch), iso)


def canonicalize_resource(resource: str) -> str:
    """Stabilize a resource identifier so the finding key is reproducible across
    scans. Intentionally minimal (strip only) — the key must stay stable, and a
    lossy normalization would collapse distinct resources."""
    return (resource or "").strip()


def finding_key(check_id: str, resource: str) -> str:
    """Stable finding identity — mirrors ``aws_live_scanner.finding_key`` format
    (``check_id|resource``) with a canonicalized resource. ``KEY_VERSION`` is
    persisted so any future canonicalization change is a migration, never an
    in-place hash swap."""
    return f"{check_id}|{canonicalize_resource(resource)}"


def _fingerprint(severity: str, message: str) -> str:
    """Hash of the mutable finding attributes — a change means config drift on an
    existing exposure (severity bump / policy widened), emitted as MUTATED rather
    than resolve+recreate."""
    h = hashlib.sha1(f"{severity or ''}||{message or ''}".encode("utf-8", "replace"))
    return h.hexdigest()


def severity_counts(results: Sequence) -> Dict[str, int]:
    """Count FAIL results by severity for a scan-summary row."""
    c = {"crit": 0, "high": 0, "med": 0, "low": 0, "info": 0}
    bucket = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med",
              "LOW": "low", "INFO": "info"}
    for r in results:
        if getattr(r, "status", "") == "FAIL":
            k = bucket.get(getattr(r, "severity", ""), None)
            if k:
                c[k] += 1
    return c


_DDL = """
CREATE TABLE IF NOT EXISTS findings(
  account TEXT NOT NULL, finding_key TEXT NOT NULL, key_version INTEGER NOT NULL DEFAULT 1,
  region TEXT NOT NULL DEFAULT 'global', check_id TEXT NOT NULL, section TEXT,
  resource TEXT NOT NULL, message TEXT, severity TEXT NOT NULL, result_status TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved')),
  first_seen_scan TEXT, first_seen_epoch INTEGER NOT NULL, first_seen_iso TEXT NOT NULL,
  last_seen_scan  TEXT, last_seen_epoch  INTEGER NOT NULL, last_seen_iso  TEXT NOT NULL,
  resolved_epoch INTEGER, times_seen INTEGER NOT NULL DEFAULT 1, reopen_count INTEGER NOT NULL DEFAULT 0,
  last_scan_id TEXT NOT NULL, fingerprint TEXT,
  PRIMARY KEY(account, finding_key));
CREATE INDEX IF NOT EXISTS ix_find_status ON findings(account,status);
CREATE INDEX IF NOT EXISTS ix_find_scope  ON findings(account,region,check_id);

CREATE TABLE IF NOT EXISTS finding_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL, finding_key TEXT NOT NULL,
  scan_id TEXT NOT NULL, ts_epoch INTEGER NOT NULL, from_status TEXT, to_status TEXT NOT NULL,
  severity TEXT, note TEXT);
CREATE INDEX IF NOT EXISTS ix_evt_key ON finding_events(account,finding_key,ts_epoch);

CREATE TABLE IF NOT EXISTS waivers(
  id INTEGER PRIMARY KEY AUTOINCREMENT, match_type TEXT NOT NULL CHECK(match_type IN ('exact','glob')),
  finding_key TEXT, account TEXT NOT NULL DEFAULT '*', region TEXT NOT NULL DEFAULT '*',
  check_glob TEXT, resource_glob TEXT, approver TEXT NOT NULL, reason TEXT NOT NULL,
  created_epoch INTEGER NOT NULL, expires_epoch INTEGER, revoked INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_waiver_live ON waivers(revoked,expires_epoch);

CREATE TABLE IF NOT EXISTS scans(
  scan_id TEXT PRIMARY KEY, account TEXT NOT NULL, region TEXT, ts_epoch INTEGER NOT NULL, ts_iso TEXT NOT NULL,
  posture_score REAL NOT NULL, grade TEXT, crit INTEGER DEFAULT 0, high INTEGER DEFAULT 0,
  med INTEGER DEFAULT 0, low INTEGER DEFAULT 0, info INTEGER DEFAULT 0, total_open INTEGER DEFAULT 0,
  new_count INTEGER DEFAULT 0, resolved_count INTEGER DEFAULT 0, reopened_count INTEGER DEFAULT 0,
  suppressed_count INTEGER DEFAULT 0, scanner_version TEXT);

CREATE TABLE IF NOT EXISTS scan_coverage(
  scan_id TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, check_id TEXT NOT NULL,
  PRIMARY KEY(scan_id,account,region,check_id));

CREATE TABLE IF NOT EXISTS principal_usage(
  account TEXT NOT NULL, arn TEXT NOT NULL, source TEXT,
  last_used_epoch INTEGER, last_used_iso TEXT, dormant INTEGER,
  granted_services INTEGER, used_services INTEGER, unused_services_json TEXT, unused_actions_json TEXT,
  window_days INTEGER, collected_epoch INTEGER, slad_job_status TEXT, error_json TEXT,
  PRIMARY KEY(account,arn));

-- ── onboarding plane (Phase 8): the hosted multi-account control plane ────────
-- These hold METADATA ONLY (never customer workload data) and are managed by
-- cnapp_registry.AccountRegistry, not StateStore. All *_at/*_epoch are epoch
-- seconds (BIGINT twins in aws_state_dialect.POSTGRES_DDL).
CREATE TABLE IF NOT EXISTS accounts(
  account_id TEXT PRIMARY KEY CHECK(length(account_id)=12),
  alias TEXT NOT NULL DEFAULT '', org_id TEXT,
  onboarding_method TEXT NOT NULL DEFAULT 'manual' CHECK(onboarding_method IN ('single','org','manual')),
  onboarding_status TEXT NOT NULL DEFAULT 'pending' CHECK(onboarding_status IN ('pending','active','denied','disabled')),
  role_arn TEXT NOT NULL DEFAULT '', external_id_ref TEXT,
  enabled_regions TEXT NOT NULL DEFAULT '[]', scan_schedule TEXT,
  health TEXT NOT NULL DEFAULT 'unknown' CHECK(health IN ('unknown','validating','healthy','degraded','unauthorized')),
  health_detail TEXT,
  last_scan_at INTEGER, first_seen_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_acct_org ON accounts(org_id);
CREATE INDEX IF NOT EXISTS ix_acct_health ON accounts(health);

CREATE TABLE IF NOT EXISTS scan_jobs(
  job_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(account_id),
  status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','done','error')),
  started_at INTEGER, finished_at INTEGER, findings_count INTEGER NOT NULL DEFAULT 0, error TEXT);
CREATE INDEX IF NOT EXISTS ix_job_acct ON scan_jobs(account_id, started_at);
CREATE INDEX IF NOT EXISTS ix_job_status ON scan_jobs(status);

CREATE TABLE IF NOT EXISTS connection_health(
  account TEXT NOT NULL, role_arn TEXT NOT NULL, region TEXT NOT NULL DEFAULT 'us-east-1',
  org_mode INTEGER NOT NULL DEFAULT 0,
  health TEXT NOT NULL CHECK(health IN ('validating','healthy','degraded','unauthorized')),
  observed_account TEXT, last_error_code TEXT, last_detail TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  last_validated_epoch INTEGER NOT NULL, last_validated_iso TEXT NOT NULL, next_due_epoch INTEGER NOT NULL,
  PRIMARY KEY(account, role_arn));
CREATE INDEX IF NOT EXISTS ix_conn_due ON connection_health(next_due_epoch);

-- ── connector framework (Phase-2 workflow plane): outbound notifications to the ──
-- OPERATOR'S OWN tools (Jira/Slack/PagerDuty/Splunk/webhook). Metadata ONLY —
-- connector settings + a secret REFERENCE (never plaintext) + a delivery audit
-- log. Makes NO AWS call against any scanned account (read-only-on-targets holds).
-- Managed by cnapp_connectors.ConnectorStore. BIGINT twins in POSTGRES_DDL.
CREATE TABLE IF NOT EXISTS connectors(
  connector_id TEXT PRIMARY KEY,
  type TEXT NOT NULL CHECK(type IN ('jira','slack','pagerduty','splunk','webhook')),
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  config_json TEXT NOT NULL DEFAULT '{}',
  secret_ref TEXT,
  created_by TEXT,
  last_test_at INTEGER, last_test_status TEXT, last_test_detail TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ix_conn_name ON connectors(name);

CREATE TABLE IF NOT EXISTS connector_rules(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  connector_id TEXT NOT NULL REFERENCES connectors(connector_id) ON DELETE CASCADE,
  name TEXT, enabled INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 100,
  min_severity TEXT NOT NULL DEFAULT 'HIGH' CHECK(min_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  check_glob TEXT, section TEXT, account_glob TEXT NOT NULL DEFAULT '*',
  on_attack_path INTEGER, status_filter TEXT NOT NULL DEFAULT 'FAIL',
  dedup_window_sec INTEGER, options_json TEXT NOT NULL DEFAULT '{}',
  created_by TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_rule_conn ON connector_rules(connector_id, enabled);

CREATE TABLE IF NOT EXISTS notification_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  connector_id TEXT NOT NULL REFERENCES connectors(connector_id),
  dedup_key TEXT NOT NULL, rule_id INTEGER, account TEXT NOT NULL, check_id TEXT,
  finding_key TEXT,
  state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','resolved')),
  kind TEXT, fingerprint TEXT,
  first_notified_epoch INTEGER, last_notified_epoch INTEGER,
  notify_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sent','failed','skipped')),
  attempts INTEGER NOT NULL DEFAULT 0, http_status INTEGER, error TEXT, external_ref TEXT,
  created_at INTEGER NOT NULL, sent_at INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS ix_notify_dedup ON notification_log(connector_id, dedup_key);
CREATE INDEX IF NOT EXISTS ix_notify_status ON notification_log(connector_id, status);
CREATE INDEX IF NOT EXISTS ix_notify_acct ON notification_log(account);
CREATE INDEX IF NOT EXISTS ix_notify_created ON notification_log(created_at);

-- ── drift-digest delivery ledger (continuous scheduled scanning) ──────────────
-- One row per (connector, account, window) summary sent — exactly-once via the
-- UNIQUE index (claim-then-send), SEPARATE from the per-finding notification_log so
-- its hot queries (plan/resolve_stale) stay digest-unaware. BIGINT twins in POSTGRES_DDL.
CREATE TABLE IF NOT EXISTS digest_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  connector_id TEXT NOT NULL REFERENCES connectors(connector_id),
  digest_key TEXT NOT NULL, account TEXT NOT NULL, scan_id TEXT NOT NULL, window_id TEXT NOT NULL,
  new_count INTEGER NOT NULL DEFAULT 0, resolved_count INTEGER NOT NULL DEFAULT 0,
  reopened_count INTEGER NOT NULL DEFAULT 0, posture_delta REAL, material INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sent','failed','skipped')),
  attempts INTEGER NOT NULL DEFAULT 0, http_status INTEGER, error TEXT, external_ref TEXT,
  created_at INTEGER NOT NULL, sent_at INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS ix_digest_dedup ON digest_log(connector_id, digest_key);
CREATE INDEX IF NOT EXISTS ix_digest_acct ON digest_log(account);
CREATE INDEX IF NOT EXISTS ix_digest_created ON digest_log(created_at);
"""


# ── upsert column sets (Phase 9: routed through the Backend abstraction) ──────
# scans: the 13 columns record_scan writes. The 5 drift counters are OMITTED from
# the insert and therefore DEFAULT to 0 — INSERT OR REPLACE (sqlite) resets them
# on a re-scan, and reset_cols replicates that explicitly on Postgres.
SCAN_COLS = ["scan_id", "account", "region", "ts_epoch", "ts_iso", "posture_score",
             "grade", "crit", "high", "med", "low", "info", "scanner_version"]
SCAN_UPDATE = SCAN_COLS[1:]
SCAN_COUNTER_RESET = {"total_open": "0", "new_count": "0", "resolved_count": "0",
                      "reopened_count": "0", "suppressed_count": "0"}
COVERAGE_COLS = ["scan_id", "account", "region", "check_id"]
USAGE_COLS = ["account", "arn", "source", "last_used_epoch", "last_used_iso", "dormant",
              "granted_services", "used_services", "unused_services_json",
              "unused_actions_json", "window_days", "collected_epoch", "slad_job_status",
              "error_json"]
USAGE_UPDATE = USAGE_COLS[2:]


class StateStore:
    """Finding lifecycle / drift / waiver / posture store, over a `cnapp_backend`
    Backend (sqlite by default, Postgres when opened with a ``postgresql://`` URL)."""

    def __init__(self, backend):
        # Tolerant of a legacy raw sqlite3.Connection (wrapped in a SqliteBackend)
        # so any old ``StateStore(conn)`` caller keeps working.
        import cnapp_backend
        self._be = (backend if isinstance(backend, cnapp_backend.Backend)
                    else cnapp_backend.SqliteBackend(backend))
        self._c = self._be.raw          # compat alias — keeps ``store._c.execute`` working

    # ── lifecycle: open / migrate ─────────────────────────────────────────────
    @classmethod
    def open(cls, path: str) -> "StateStore":
        """Open (creating if needed) a state DB at ``path``. ``':memory:'`` for
        tests. A bare path or ``sqlite:///...`` opens the sqlite store (default,
        0700 dir / 0600 file); a ``postgresql://`` URL selects the live Postgres
        backend (Phase 9) — if the driver is absent or the server is unreachable it
        raises ``StateBackendUnavailable`` so the scanner cleanly runs stateless and
        NEVER silently falls back to a local sqlite file."""
        import cnapp_backend
        return cls(cnapp_backend.backend_for(path))

    def _migrate(self) -> None:
        self._be.migrate()

    def close(self) -> None:
        self._be.close()

    # ── scan + coverage rows ──────────────────────────────────────────────────
    def record_scan(self, account: str, scan_id: str, ts: ScanTs, score: float,
                    counts: Dict[str, int], region: str = "global",
                    scanner_version: str = "") -> str:
        """Insert the scan-summary row (score + severity counts). Drift-derived
        columns are filled later by :meth:`record_posture`."""
        c = counts or {}
        self._be.upsert(
            "scans", SCAN_COLS, ["scan_id"], SCAN_UPDATE,
            (scan_id, account, region, ts.epoch, ts.iso, float(score),
             _grade(score), c.get("crit", 0), c.get("high", 0), c.get("med", 0),
             c.get("low", 0), c.get("info", 0), scanner_version),
            reset_cols=SCAN_COUNTER_RESET)
        return scan_id

    def record_coverage(self, scan_id: str, account: str,
                        tuples: Iterable[Tuple[str, str, str]]) -> None:
        """Record which (account, region, check_id) triples this scan inspected —
        the gate that scopes auto-resolution to what was actually looked at.
        The account column is forced to ``account`` regardless of each tuple's
        first element, so coverage always partitions by the scanning account."""
        rows = {(account, t[1], t[2]) for t in tuples}
        self._be.upsert_many(
            "scan_coverage", COVERAGE_COLS, COVERAGE_COLS, None,
            [(scan_id, a, r, cid) for (a, r, cid) in rows])

    def record_posture(self, account: str, scan_id: str, drift: Dict) -> None:
        """Fill the scan row's drift columns from a completed classify pass."""
        self._be.execute(
            "UPDATE scans SET total_open=?, new_count=?, resolved_count=?, "
            "reopened_count=?, suppressed_count=? WHERE scan_id=?",
            (drift.get("still_open", 0) + len(drift.get("new", [])),
             len(drift.get("new", [])), len(drift.get("resolved", [])),
             len(drift.get("reopened", [])), drift.get("suppressed_count", 0),
             scan_id))

    # ── classification / drift ────────────────────────────────────────────────
    def classify_and_diff(self, account: str, scan_id: str, ts: ScanTs,
                          results: Sequence, region: str = "global",
                          global_sections: Optional[set] = None) -> Dict:
        """Fold this scan's FAIL/WARN results into the lifecycle table and return
        a drift dict: ``{new, resolved, reopened, mutated, still_open,
        suppressed, suppressed_count, posture_delta}``.

        ``global_sections`` — sections whose resources are region-independent
        (IAM, S3, …); their findings are stored under a stable ``'global'`` region
        so they resolve regardless of which region label the scan carried. All
        other findings keep the scan's ``region`` (region-gated resolve, so a
        single-region scan never mass-resolves another region's findings).

        Deterministic & idempotent: re-running an unchanged scan yields empty
        new/resolved/reopened/mutated (only STILL_OPEN events)."""
        gsecs = global_sections or set()

        def _region_of(r) -> str:
            return "global" if getattr(r, "section", "") in gsecs else region

        cur: Dict[str, object] = {}
        for r in results:
            if getattr(r, "status", "") not in ("FAIL", "WARN"):
                continue
            k = finding_key(r.check_id, r.resource)
            cur[k] = r  # last-write-wins on duplicate key within a scan

        # Coverage: every (account, region, check_id) this scan inspected. A
        # check that ran emits at least one result (PASS/INFO included), so the
        # set of check_ids present == the checks that executed. Region is per
        # section so a global finding is covered under 'global'.
        cov = {(account, _region_of(r), r.check_id)
               for r in results if getattr(r, "check_id", "")}
        self.record_coverage(scan_id, account, cov)

        # One atomic transaction (BEGIN IMMEDIATE on sqlite / a psycopg txn on PG);
        # transaction() commits on clean exit, rolls back + re-raises on error.
        with self._be.transaction():
            new_keys, reopened, mutated = [], [], []
            for k, r in cur.items():
                fp = _fingerprint(r.severity, r.message)
                row = self._be.query_one(
                    "SELECT status, fingerprint, first_seen_epoch, first_seen_iso, "
                    "first_seen_scan FROM findings WHERE account=? AND finding_key=?",
                    (account, k))
                if row is None:
                    self._be.execute(
                        "INSERT INTO findings(account,finding_key,key_version,region,"
                        "check_id,section,resource,message,severity,result_status,status,"
                        "first_seen_scan,first_seen_epoch,first_seen_iso,last_seen_scan,"
                        "last_seen_epoch,last_seen_iso,times_seen,reopen_count,last_scan_id,"
                        "fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?,'open',?,?,?,?,?,?,1,0,?,?)",
                        (account, k, KEY_VERSION, _region_of(r), r.check_id,
                         getattr(r, "section", ""), r.resource, r.message,
                         r.severity, r.status, scan_id, ts.epoch, ts.iso, scan_id,
                         ts.epoch, ts.iso, scan_id, fp))
                    new_keys.append(k)
                    self._event(account, k, scan_id, ts.epoch, None, "NEW", r.severity)
                elif row["status"] == "resolved":
                    self._be.execute(
                        "UPDATE findings SET status='open', resolved_epoch=NULL, "
                        "last_seen_scan=?, last_seen_epoch=?, last_seen_iso=?, "
                        "times_seen=times_seen+1, reopen_count=reopen_count+1, "
                        "severity=?, message=?, result_status=?, last_scan_id=?, "
                        "fingerprint=?, region=? WHERE account=? AND finding_key=?",
                        (scan_id, ts.epoch, ts.iso, r.severity, r.message, r.status,
                         scan_id, fp, _region_of(r), account, k))
                    reopened.append(k)
                    self._event(account, k, scan_id, ts.epoch, "resolved", "REOPENED", r.severity)
                else:  # already open
                    self._be.execute(
                        "UPDATE findings SET last_seen_scan=?, last_seen_epoch=?, "
                        "last_seen_iso=?, times_seen=times_seen+1, severity=?, "
                        "message=?, result_status=?, last_scan_id=?, fingerprint=?, "
                        "region=? WHERE account=? AND finding_key=?",
                        (scan_id, ts.epoch, ts.iso, r.severity, r.message, r.status,
                         scan_id, fp, _region_of(r), account, k))
                    self._event(account, k, scan_id, ts.epoch, "open", "STILL_OPEN", r.severity)
                    if row["fingerprint"] and row["fingerprint"] != fp:
                        mutated.append(k)
                        self._event(account, k, scan_id, ts.epoch, "open", "MUTATED",
                                    r.severity, note="config drift")

            # Coverage-gated resolve: open findings this scan covered but did not
            # re-observe. The coverage join is what prevents a partial scan from
            # mass-resolving checks it never ran.
            resolved = []
            open_rows = self._be.query_all(
                "SELECT f.finding_key, f.severity FROM findings f "
                "JOIN scan_coverage sc ON sc.scan_id=? AND sc.account=f.account "
                "AND sc.region=f.region AND sc.check_id=f.check_id "
                "WHERE f.account=? AND f.status='open'",
                (scan_id, account))
            for orow in open_rows:
                k = orow["finding_key"]
                if k in cur:
                    continue
                self._be.execute(
                    "UPDATE findings SET status='resolved', resolved_epoch=?, "
                    "last_scan_id=? WHERE account=? AND finding_key=?",
                    (ts.epoch, scan_id, account, k))
                resolved.append(k)
                self._event(account, k, scan_id, ts.epoch, "open", "RESOLVED", orow["severity"])

            # Suppression overlay (live waivers) — logged once per scan, finding
            # stays 'open'.
            suppressed = []
            for k, r in cur.items():
                wid = self._match_waiver(account, region, k, r.check_id, r.resource, ts.epoch)
                if wid is not None:
                    suppressed.append(k)
                    self._event(account, k, scan_id, ts.epoch, "open", "SUPPRESSED",
                                r.severity, note=f"waiver:{wid}")

            still_open = self._be.scalar(
                "SELECT COUNT(*) FROM findings WHERE account=? AND status='open'",
                (account,))
            prev = self._be.query_one(
                "SELECT posture_score FROM scans WHERE account=? AND scan_id!=? "
                "ORDER BY ts_epoch DESC LIMIT 1", (account, scan_id))
            this = self._be.query_one(
                "SELECT posture_score FROM scans WHERE scan_id=?", (scan_id,))
            posture_delta = None
            if prev is not None and this is not None:
                posture_delta = round(this["posture_score"] - prev["posture_score"], 1)

        return {
            "new": sorted(new_keys),
            "resolved": sorted(resolved),
            "reopened": sorted(reopened),
            "mutated": sorted(mutated),
            "still_open": still_open - len(new_keys),  # STILL_OPEN excludes brand-new
            "suppressed": sorted(suppressed),
            "suppressed_count": len(suppressed),
            "posture_delta": posture_delta,
        }

    def _event(self, account: str, key: str, scan_id: str, ts_epoch: int,
               from_status: Optional[str], to_status: str,
               severity: str = "", note: str = "") -> None:
        self._be.execute(
            "INSERT INTO finding_events(account,finding_key,scan_id,ts_epoch,"
            "from_status,to_status,severity,note) VALUES(?,?,?,?,?,?,?,?)",
            (account, key, scan_id, ts_epoch, from_status, to_status, severity, note))

    # ── waivers / suppression ─────────────────────────────────────────────────
    def apply_waiver(self, match: Dict, approver: str, reason: str,
                     created_epoch: int, expires_epoch: Optional[int] = None) -> int:
        """Insert a waiver. ``match`` is either
        ``{'type':'exact','finding_key':..,'account':..,'region':..}`` or
        ``{'type':'glob','check_glob':..,'resource_glob':..,'account':..,'region':..}``.
        Returns the waiver id."""
        mt = match.get("type", "exact")
        return self._be.insert_returning_id(
            "INSERT INTO waivers(match_type,finding_key,account,region,check_glob,"
            "resource_glob,approver,reason,created_epoch,expires_epoch,revoked) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,0)",
            (mt, match.get("finding_key"), match.get("account", "*"),
             match.get("region", "*"), match.get("check_glob"),
             match.get("resource_glob"), approver, reason, created_epoch,
             expires_epoch), id_col="id")

    def revoke_waiver(self, waiver_id: int) -> None:
        self._be.execute("UPDATE waivers SET revoked=1 WHERE id=?", (waiver_id,))

    def list_waivers(self, account: str, scan_epoch: Optional[int] = None) -> List[Dict]:
        """All waivers applicable to ``account`` (or global '*'), annotated with a
        live/expired/revoked state (relative to ``scan_epoch`` if given)."""
        rows = self._be.query_all(
            "SELECT * FROM waivers WHERE account='*' OR account=? ORDER BY id",
            (account,))
        out = []
        for w in rows:
            d = dict(w)
            if w["revoked"]:
                d["state"] = "revoked"
            elif (scan_epoch is not None and w["expires_epoch"] is not None
                  and w["expires_epoch"] <= scan_epoch):
                d["state"] = "expired"
            else:
                d["state"] = "active"
            out.append(d)
        return out

    def _match_waiver(self, account: str, region: str, key: str, check_id: str,
                      resource: str, scan_epoch: int) -> Optional[int]:
        """Return the id of a LIVE waiver matching this finding, else None.
        Expiry is evaluated against the scan-supplied epoch, so an expired waiver
        deterministically stops matching (auto-reactivation is a pure predicate)."""
        row = self._be.query_all(
            "SELECT id, match_type, finding_key, check_glob, resource_glob "
            "FROM waivers WHERE revoked=0 "
            "AND (expires_epoch IS NULL OR expires_epoch > ?) "
            "AND (account='*' OR account=?) AND (region='*' OR region=?)",
            (scan_epoch, account, region))
        for w in row:
            if w["match_type"] == "exact":
                if w["finding_key"] == key:
                    return w["id"]
            else:  # glob
                cg = w["check_glob"] or "*"
                rg = w["resource_glob"] or "*"
                if _glob(cg, check_id) and _glob(rg, canonicalize_resource(resource)):
                    return w["id"]
        return None

    def filter_suppressed(self, account: str, results: Sequence, scan_epoch: int,
                          region: str = "global") -> Tuple[List, List]:
        """Split ``results`` into (gating, suppressed). A FAIL/WARN result matched
        by a live waiver moves to ``suppressed`` (still open & tracked in the DB);
        everything else stays in ``gating``. Pure read — no DB mutation, so an
        expired waiver re-enters gating automatically on the next scan."""
        gating, suppressed = [], []
        for r in results:
            if getattr(r, "status", "") in ("FAIL", "WARN"):
                k = finding_key(r.check_id, r.resource)
                if self._match_waiver(account, region, k, r.check_id, r.resource,
                                      scan_epoch) is not None:
                    suppressed.append(r)
                    continue
            gating.append(r)
        return gating, suppressed

    # ── reporting: MTTR / trend / open findings ───────────────────────────────
    def mttr(self, account: str, by_severity: bool = False,
             sla_days: Optional[int] = None, now_epoch: Optional[int] = None) -> Dict:
        """Mean-time-to-remediate over resolved findings. Episode-based: pairs
        each NEW/REOPENED event with its next RESOLVED per key (so a reopen does
        not span the dormant gap). Returns mean/median seconds overall and, when
        ``by_severity``, per severity; plus ``open_over_sla`` when ``sla_days``
        and ``now_epoch`` are given."""
        events = self._be.query_all(
            "SELECT finding_key, ts_epoch, to_status, severity FROM finding_events "
            "WHERE account=? AND to_status IN ('NEW','REOPENED','RESOLVED') "
            "ORDER BY finding_key, ts_epoch, id", (account,))
        durations: List[int] = []
        by_sev: Dict[str, List[int]] = {}
        open_start: Dict[str, Tuple[int, str]] = {}
        for e in events:
            k = e["finding_key"]
            if e["to_status"] in ("NEW", "REOPENED"):
                if k not in open_start:  # first open of the current episode
                    open_start[k] = (e["ts_epoch"], e["severity"] or "")
            elif e["to_status"] == "RESOLVED" and k in open_start:
                start, sev = open_start.pop(k)
                dur = max(0, e["ts_epoch"] - start)
                durations.append(dur)
                by_sev.setdefault(sev, []).append(dur)

        out: Dict[str, object] = {
            "resolved_count": len(durations),
            "mean_seconds": round(sum(durations) / len(durations), 1) if durations else None,
            "median_seconds": _median(durations),
        }
        if by_severity:
            out["by_severity"] = {
                s: {"count": len(v), "mean_seconds": round(sum(v) / len(v), 1),
                    "median_seconds": _median(v)}
                for s, v in sorted(by_sev.items())}
        if sla_days is not None and now_epoch is not None:
            cutoff = now_epoch - sla_days * 86400
            out["open_over_sla"] = self._be.scalar(
                "SELECT COUNT(*) FROM findings WHERE account=? AND status='open' "
                "AND first_seen_epoch < ?", (account, cutoff))
            out["sla_days"] = sla_days
        return out

    def trend(self, account: str) -> List[Dict]:
        """Posture history for ``account``, oldest first, each row annotated with
        the score delta from the previous scan."""
        rows = self._be.query_all(
            "SELECT scan_id,ts_epoch,ts_iso,posture_score,grade,crit,high,med,low,"
            "info,total_open,new_count,resolved_count,reopened_count,suppressed_count "
            "FROM scans WHERE account=? ORDER BY ts_epoch, scan_id", (account,))
        out, prev = [], None
        for row in rows:
            d = dict(row)
            d["delta"] = None if prev is None else round(d["posture_score"] - prev, 1)
            prev = d["posture_score"]
            out.append(d)
        return out

    def open_findings(self, account: str) -> List[Dict]:
        rows = self._be.query_all(
            "SELECT * FROM findings WHERE account=? AND status='open' "
            "ORDER BY severity, finding_key", (account,))
        return [dict(r) for r in rows]

    # ── unused-access persistence (Phase 5C) ──────────────────────────────────
    def record_usage(self, account: str, arn: str, sig: Dict, collected_epoch: int) -> None:
        """Persist a right-sizing signal (24h TTL keyed by collected_epoch)."""
        self._be.upsert(
            "principal_usage", USAGE_COLS, ["account", "arn"], USAGE_UPDATE,
            (account, arn, sig.get("source"), sig.get("last_used_epoch"),
             sig.get("last_used_iso"),
             None if sig.get("dormant") is None else int(bool(sig.get("dormant"))),
             sig.get("granted_services"), sig.get("used_services"),
             sig.get("unused_services_json"), sig.get("unused_actions_json"),
             sig.get("window_days"), collected_epoch, sig.get("slad_job_status"),
             sig.get("error_json")))

    def get_usage(self, account: str, arn: str, fresh_after_epoch: int) -> Optional[Dict]:
        """Return a cached usage row if collected at/after ``fresh_after_epoch``
        (TTL gate), else None so the caller re-collects."""
        row = self._be.query_one(
            "SELECT * FROM principal_usage WHERE account=? AND arn=? "
            "AND collected_epoch >= ?", (account, arn, fresh_after_epoch))
        return dict(row) if row else None


# ── module helpers ───────────────────────────────────────────────────────────
def _grade(score: float) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def _glob(pattern: str, value: str) -> bool:
    """SQLite-GLOB-style case-sensitive glob (via fnmatch translate would be
    case-insensitive on some platforms, so use fnmatchcase)."""
    import fnmatch as _fn
    return _fn.fnmatchcase(value or "", pattern or "*")


def _median(xs: Sequence[int]):
    if not xs:
        return None
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    return float(s[mid]) if n % 2 else round((s[mid - 1] + s[mid]) / 2, 1)


def open(path: str) -> StateStore:  # noqa: A001 - deliberate module-level facade
    """Module-level convenience: ``aws_state.open(path)`` -> StateStore."""
    return StateStore.open(path)
