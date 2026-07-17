#!/usr/bin/env python3
"""
cnapp_registry.py — onboarding-plane persistence for the hosted CNAPP (Phase 8).

The multi-account control plane: which accounts are connected, how they were
onboarded, their connection health + re-validation schedule, and the scan-job
queue. It lives in the SAME state store as findings (aws_state) and reuses its
dual-dialect machinery verbatim (build_upsert ON CONFLICT, the schema migration,
epoch-int/text columns) so a later Postgres cutover is a URL change.

READ-ONLY of customer workloads: this stores METADATA ONLY (account ids, role
ARNs, secret *references* — never the ExternalId value, never workload data).

Design invariants
-----------------
* **Preserve-on-reonboard** — ``upsert_account`` uses ``ON CONFLICT DO UPDATE`` with
  ``onboarding_status`` / ``health`` / ``first_seen_at`` / ``last_scan_at`` EXCLUDED
  from the update set, so re-running onboarding for an existing account refreshes
  its config without resetting its lifecycle (never ``INSERT OR REPLACE``, which
  delete+reinserts and wipes those columns).
* **Injected clock** — every ``*_at`` / ``*_epoch`` is a caller-supplied
  ``now_epoch``, so the whole module is deterministic on ``:memory:``.
* **Postgres-deferred, fail-loud** — a ``postgresql://`` URL raises
  ``StateBackendUnavailable`` (like StateStore) rather than silently using sqlite.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Dict, List, Optional

from aws_state import make_scan_ts
from aws_state_dialect import StateBackendUnavailable, parse_state_url
from cnapp_validate import ConnectionHealth, cadence

# ── column orders (single source of truth; update sets EXCLUDE preserved cols) ──
ACCT_COLS = ["account_id", "alias", "org_id", "onboarding_method", "onboarding_status",
             "role_arn", "external_id_ref", "enabled_regions", "scan_schedule",
             "health", "health_detail", "last_scan_at", "first_seen_at", "updated_at"]
# preserved by omission: onboarding_status, health, health_detail, last_scan_at, first_seen_at
ACCT_UPDATE = ["alias", "org_id", "onboarding_method", "role_arn", "external_id_ref",
               "enabled_regions", "scan_schedule", "updated_at"]

JOB_COLS = ["job_id", "account_id", "status", "started_at", "finished_at",
            "findings_count", "error"]
JOB_UPDATE = ["status", "started_at", "finished_at", "findings_count", "error"]

CONN_COLS = ["account", "role_arn", "region", "org_mode", "health", "observed_account",
             "last_error_code", "last_detail", "consecutive_failures",
             "last_validated_epoch", "last_validated_iso", "next_due_epoch"]
CONN_UPDATE = CONN_COLS[2:]     # everything except the (account, role_arn) PK

_ONBOARDING_STATUSES = {"pending", "active", "denied", "disabled"}
_ACCOUNT_HEALTHS = {"unknown", "validating", "healthy", "degraded", "unauthorized"}


class AccountRegistry:
    """Registry for accounts, scan jobs, and connection health, over a
    `cnapp_backend` Backend (sqlite by default, Postgres via ``postgresql://``).
    The backend owns the connection + the reentrant lock that serializes all
    access (FastAPI serves sync routes from a threadpool), so each multi-statement
    write is wrapped in ``self._be.transaction()`` to stay atomic."""

    def __init__(self, backend):
        self._be = backend
        self._c = backend.raw          # compat alias (tests use r._c.execute(sqlite_master))

    # ── lifecycle ─────────────────────────────────────────────────────────────
    @classmethod
    def open(cls, url: str = ":memory:") -> "AccountRegistry":
        """Open (creating + migrating if needed) the registry DB. Shares the schema
        + migration with StateStore via `cnapp_backend.backend_for`. A
        ``postgresql://`` URL selects the live Postgres backend; if the driver is
        absent or the server unreachable it raises `StateBackendUnavailable`."""
        import cnapp_backend
        scheme, _ = parse_state_url(url)
        # ON CONFLICT ... DO UPDATE (the preserve-on-reonboard guarantee) needs
        # SQLite >= 3.24 (2018). Python 3.10+ bundles newer, but verify loudly.
        if scheme == "sqlite" and sqlite3.sqlite_version_info < (3, 24, 0):
            raise StateBackendUnavailable(
                f"AccountRegistry needs SQLite >= 3.24 for upsert; found "
                f"{sqlite3.sqlite_version}")
        # check_same_thread=False: the sqlite connection is touched from the
        # FastAPI threadpool; the backend lock serializes every access.
        return cls(cnapp_backend.backend_for(url, check_same_thread=False))

    def close(self) -> None:
        self._be.close()

    # ── connection helpers (delegate to the lock-owning backend) ──────────────
    def _write(self, sql: str, params=()) -> None:
        self._be.execute(sql, params)

    def _one(self, sql: str, params=()):
        return self._be.query_one(sql, params)

    def _all(self, sql: str, params=()):
        return self._be.query_all(sql, params)

    # ── accounts ──────────────────────────────────────────────────────────────
    def upsert_account(self, account_id: str, *, now_epoch: int, alias: Optional[str] = None,
                       org_id: Optional[str] = None, onboarding_method: Optional[str] = None,
                       role_arn: Optional[str] = None, external_id_ref: Optional[str] = None,
                       enabled_regions: Optional[List[str]] = None,
                       scan_schedule: Optional[str] = None) -> None:
        """Insert or refresh an account.

        On conflict, ONLY the config columns the caller actually supplied are
        updated (plus ``updated_at``); every unmentioned column — including the
        lifecycle set (onboarding_status, health, first_seen_at, last_scan_at) AND
        untouched config (e.g. enabled_regions when you only change the alias) — is
        preserved. A first insert fills sensible defaults for anything omitted."""
        provided: Dict[str, object] = {}
        if alias is not None:
            provided["alias"] = alias
        if org_id is not None:
            provided["org_id"] = org_id
        if onboarding_method is not None:
            provided["onboarding_method"] = onboarding_method
        if role_arn is not None:
            provided["role_arn"] = role_arn
        if external_id_ref is not None:
            provided["external_id_ref"] = external_id_ref
        if enabled_regions is not None:
            provided["enabled_regions"] = json.dumps(list(enabled_regions))
        if scan_schedule is not None:
            provided["scan_schedule"] = scan_schedule

        insert = {
            "account_id": account_id,
            "alias": provided.get("alias", ""),
            "org_id": provided.get("org_id"),
            "onboarding_method": provided.get("onboarding_method", "manual"),
            "onboarding_status": "pending",
            "role_arn": provided.get("role_arn", ""),
            "external_id_ref": provided.get("external_id_ref"),
            "enabled_regions": provided.get("enabled_regions", "[]"),
            "scan_schedule": provided.get("scan_schedule"),
            "health": "unknown", "health_detail": None, "last_scan_at": None,
            "first_seen_at": int(now_epoch), "updated_at": int(now_epoch),
        }
        update_cols = list(provided.keys()) + ["updated_at"]
        self._be.upsert("accounts", ACCT_COLS, ["account_id"], update_cols,
                        [insert[c] for c in ACCT_COLS])

    def get_account(self, account_id: str) -> Optional[Dict]:
        return _account_row(self._one("SELECT * FROM accounts WHERE account_id=?",
                                      (account_id,)))

    def list_accounts(self, *, onboarding_status: Optional[str] = None,
                      health: Optional[str] = None) -> List[Dict]:
        sql = "SELECT * FROM accounts"
        clauses, params = [], []
        if onboarding_status:
            clauses.append("onboarding_status=?"); params.append(onboarding_status)
        if health:
            clauses.append("health=?"); params.append(health)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY account_id"
        return [_account_row(r) for r in self._all(sql, params)]

    def set_onboarding_status(self, account_id: str, status: str, now_epoch: int) -> None:
        if status not in _ONBOARDING_STATUSES:
            raise ValueError(f"invalid onboarding_status {status!r}")
        self._write("UPDATE accounts SET onboarding_status=?, updated_at=? WHERE account_id=?",
                    (status, int(now_epoch), account_id))

    def set_health(self, account_id: str, health: str, health_detail: Optional[str],
                   now_epoch: int) -> None:
        if health not in _ACCOUNT_HEALTHS:
            raise ValueError(f"invalid account health {health!r}")
        self._write("UPDATE accounts SET health=?, health_detail=?, updated_at=? "
                    "WHERE account_id=?", (health, health_detail, int(now_epoch), account_id))

    # ── connection health (validation cadence) ────────────────────────────────
    def record_health(self, account: str, role_arn: str, result, now_epoch: int, *,
                      region: str = "us-east-1", org_mode: bool = False) -> Dict:
        """Persist a ValidationResult into connection_health, computing the
        consecutive-failure backoff, denormalize health onto the accounts row, and
        publish the authoritative next-due back onto the result so the API response
        and the scheduler agree. The whole read-modify-write is atomic (locked)."""
        health = result.health
        ts = make_scan_ts(now_epoch)
        err_code = next((c.error_code for c in result.checks
                         if c.status == "fail" and c.error_code), None)
        with self._be.transaction():        # atomic read-modify-write (locked)
            prev = self._be.query_one("SELECT consecutive_failures FROM connection_health "
                                      "WHERE account=? AND role_arn=?", (account, role_arn))
            prev_cf = int(prev["consecutive_failures"]) if prev else 0
            if health == ConnectionHealth.HEALTHY:
                cf = 0
            elif health == ConnectionHealth.UNAUTHORIZED:
                cf = prev_cf + 1
            else:                               # validating / degraded — hold prior count
                cf = prev_cf
            next_due = int(now_epoch) + cadence(health, cf)
            vals = [account, role_arn, region, 1 if org_mode else 0, health.value,
                    result.observed_account_id, err_code, result.summary, cf,
                    ts.epoch, ts.iso, next_due]
            self._be.upsert("connection_health", CONN_COLS, ["account", "role_arn"],
                            CONN_UPDATE, vals)
            # denormalize onto the accounts row (best-effort; UPDATE no-ops if absent)
            self._be.execute("UPDATE accounts SET health=?, health_detail=?, updated_at=? "
                             "WHERE account_id=?", (health.value, result.summary, ts.epoch, account))
        # the persisted schedule is authoritative — align the returned result to it
        try:
            result.next_revalidation_epoch = next_due
        except Exception:
            pass
        return {k: v for k, v in zip(CONN_COLS, vals)}

    def health_due(self, now_epoch: int) -> List[Dict]:
        """Every connection due for re-validation (next_due_epoch <= now), soonest
        first — the scheduler's whole query."""
        return [dict(r) for r in self._all(
            "SELECT * FROM connection_health WHERE next_due_epoch<=? ORDER BY next_due_epoch",
            (int(now_epoch),))]

    # ── scan jobs ─────────────────────────────────────────────────────────────
    def record_scan_job(self, account_id: str, job_id: str, status: str, *,
                        now_epoch: int, started_at: Optional[int] = None,
                        finished_at: Optional[int] = None, findings_count: int = 0,
                        error: Optional[str] = None) -> None:
        """Insert/advance a scan job (atomic with the account stamp). On a
        SUCCESSFUL terminal status (done) the parent account's last_scan_at is
        stamped — last_scan_at means 'last successful scan', so a failing scan does
        NOT refresh it (an errored attempt is visible on the job row itself)."""
        vals = [job_id, account_id, status, started_at, finished_at,
                int(findings_count or 0), error]
        with self._be.transaction():
            self._be.upsert("scan_jobs", JOB_COLS, ["job_id"], JOB_UPDATE, vals)
            if status == "done":
                stamp = int(finished_at if finished_at is not None else now_epoch)
                self._be.execute("UPDATE accounts SET last_scan_at=?, updated_at=? "
                                 "WHERE account_id=?", (stamp, int(now_epoch), account_id))

    def get_scan_job(self, job_id: str) -> Optional[Dict]:
        row = self._one("SELECT * FROM scan_jobs WHERE job_id=?", (job_id,))
        return dict(row) if row else None

    def list_scan_jobs(self, *, account_id: Optional[str] = None,
                       status: Optional[str] = None) -> List[Dict]:
        where, params = "", []
        clauses = []
        if account_id:
            clauses.append("account_id=?"); params.append(account_id)
        if status:
            clauses.append("status=?"); params.append(status)
        if clauses:
            where = " WHERE " + " AND ".join(clauses)
        base = "SELECT * FROM scan_jobs" + where
        try:
            rows = self._be.query_all(
                base + " ORDER BY started_at DESC NULLS LAST, job_id", params)
        except self._be.OperationalError:
            # older sqlite lacks NULLS LAST — emulate it while PRESERVING DESC
            # (a naive strip of 'DESC NULLS LAST' would invert to ascending).
            rows = self._be.query_all(
                base + " ORDER BY (started_at IS NULL), started_at DESC, job_id", params)
        return [dict(r) for r in rows]


def _account_row(row) -> Optional[Dict]:
    """sqlite Row -> plain dict with enabled_regions parsed back to a list."""
    if row is None:
        return None
    d = dict(row)
    raw = d.get("enabled_regions")
    try:
        d["enabled_regions"] = json.loads(raw) if raw else []
    except (TypeError, ValueError):
        d["enabled_regions"] = []
    return d
