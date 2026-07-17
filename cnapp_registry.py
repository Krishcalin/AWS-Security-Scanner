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
import os
import sqlite3
from typing import Dict, List, Optional

import aws_state
import aws_state_dialect
from aws_state import make_scan_ts
from aws_state_dialect import StateBackendUnavailable, build_upsert, parse_state_url
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
    """SQLite-backed registry for accounts, scan jobs, and connection health."""

    def __init__(self, conn: sqlite3.Connection):
        self._c = conn

    # ── lifecycle ─────────────────────────────────────────────────────────────
    @classmethod
    def open(cls, url: str = ":memory:") -> "AccountRegistry":
        """Open (creating + migrating if needed) the registry DB. Shares the schema
        + migration with StateStore. ``postgresql://`` is deferred (raises)."""
        scheme, dsn = parse_state_url(url)
        if scheme == "postgres":
            raise StateBackendUnavailable(
                "postgresql:// registry backend is deferred (needs psycopg + a live "
                "server); the DDL/upsert generators ship + are tested now")
        # ON CONFLICT ... DO UPDATE (the preserve-on-reonboard guarantee) needs
        # SQLite >= 3.24 (2018). Python 3.10+ bundles newer, but verify loudly.
        if sqlite3.sqlite_version_info < (3, 24, 0):
            raise StateBackendUnavailable(
                f"AccountRegistry needs SQLite >= 3.24 for upsert; found "
                f"{sqlite3.sqlite_version}")
        path = dsn
        if path != ":memory:":
            d = os.path.dirname(os.path.abspath(path))
            try:
                os.makedirs(d, mode=0o700, exist_ok=True)
            except Exception:
                pass
        # check_same_thread=False: the web layer serves routes from a threadpool,
        # so the single registry connection is touched from worker threads. Safe
        # here — writes are short + committed and busy_timeout serializes them.
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")     # enforce scan_jobs.account_id FK
        conn.execute("PRAGMA busy_timeout=5000")
        # reuse StateStore's migration (creates ALL v2 tables idempotently)
        aws_state.StateStore(conn)._migrate()
        if path != ":memory:":
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
        return cls(conn)

    def close(self) -> None:
        try:
            self._c.close()
        except Exception:
            pass

    def _exec(self, sql: str, params=()):
        return self._c.execute(sql, params)

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
        sql = build_upsert("accounts", ACCT_COLS, ["account_id"], update_cols, ph="?")
        self._exec(sql, [insert[c] for c in ACCT_COLS])
        self._c.commit()

    def get_account(self, account_id: str) -> Optional[Dict]:
        row = self._exec("SELECT * FROM accounts WHERE account_id=?",
                         (account_id,)).fetchone()
        return _account_row(row)

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
        return [_account_row(r) for r in self._exec(sql, params).fetchall()]

    def set_onboarding_status(self, account_id: str, status: str, now_epoch: int) -> None:
        if status not in _ONBOARDING_STATUSES:
            raise ValueError(f"invalid onboarding_status {status!r}")
        self._exec("UPDATE accounts SET onboarding_status=?, updated_at=? WHERE account_id=?",
                   (status, int(now_epoch), account_id))
        self._c.commit()

    def set_health(self, account_id: str, health: str, health_detail: Optional[str],
                   now_epoch: int) -> None:
        if health not in _ACCOUNT_HEALTHS:
            raise ValueError(f"invalid account health {health!r}")
        self._exec("UPDATE accounts SET health=?, health_detail=?, updated_at=? "
                   "WHERE account_id=?", (health, health_detail, int(now_epoch), account_id))
        self._c.commit()

    # ── connection health (validation cadence) ────────────────────────────────
    def record_health(self, account: str, role_arn: str, result, now_epoch: int, *,
                      region: str = "us-east-1", org_mode: bool = False) -> Dict:
        """Persist a ValidationResult into connection_health, computing the
        consecutive-failure backoff, and denormalize health onto the accounts row.
        Returns the stored connection_health record."""
        prev = self._exec("SELECT consecutive_failures FROM connection_health "
                          "WHERE account=? AND role_arn=?", (account, role_arn)).fetchone()
        prev_cf = int(prev["consecutive_failures"]) if prev else 0
        health = result.health
        if health == ConnectionHealth.HEALTHY:
            cf = 0
        elif health == ConnectionHealth.UNAUTHORIZED:
            cf = prev_cf + 1
        else:                                   # validating / degraded — hold prior count
            cf = prev_cf
        ts = make_scan_ts(now_epoch)
        next_due = int(now_epoch) + cadence(health, cf)
        err_code = next((c.error_code for c in result.checks
                         if c.status == "fail" and c.error_code), None)
        vals = [account, role_arn, region, 1 if org_mode else 0, health.value,
                result.observed_account_id, err_code, result.summary, cf,
                ts.epoch, ts.iso, next_due]
        sql = build_upsert("connection_health", CONN_COLS, ["account", "role_arn"],
                           CONN_UPDATE, ph="?")
        self._exec(sql, vals)
        # denormalize onto the accounts row (best-effort; UPDATE no-ops if absent)
        self._exec("UPDATE accounts SET health=?, health_detail=?, updated_at=? "
                   "WHERE account_id=?", (health.value, result.summary, ts.epoch, account))
        self._c.commit()
        return {k: v for k, v in zip(CONN_COLS, vals)}

    def health_due(self, now_epoch: int) -> List[Dict]:
        """Every connection due for re-validation (next_due_epoch <= now), soonest
        first — the scheduler's whole query."""
        rows = self._exec("SELECT * FROM connection_health WHERE next_due_epoch<=? "
                          "ORDER BY next_due_epoch", (int(now_epoch),)).fetchall()
        return [dict(r) for r in rows]

    # ── scan jobs ─────────────────────────────────────────────────────────────
    def record_scan_job(self, account_id: str, job_id: str, status: str, *,
                        now_epoch: int, started_at: Optional[int] = None,
                        finished_at: Optional[int] = None, findings_count: int = 0,
                        error: Optional[str] = None) -> None:
        """Insert/advance a scan job. On a terminal status (done|error) the parent
        account's last_scan_at is stamped."""
        vals = [job_id, account_id, status, started_at, finished_at,
                int(findings_count or 0), error]
        sql = build_upsert("scan_jobs", JOB_COLS, ["job_id"], JOB_UPDATE, ph="?")
        self._exec(sql, vals)
        if status in ("done", "error"):
            stamp = int(finished_at if finished_at is not None else now_epoch)
            self._exec("UPDATE accounts SET last_scan_at=?, updated_at=? WHERE account_id=?",
                       (stamp, int(now_epoch), account_id))
        self._c.commit()

    def get_scan_job(self, job_id: str) -> Optional[Dict]:
        row = self._exec("SELECT * FROM scan_jobs WHERE job_id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def list_scan_jobs(self, *, account_id: Optional[str] = None,
                       status: Optional[str] = None) -> List[Dict]:
        sql = "SELECT * FROM scan_jobs"
        clauses, params = [], []
        if account_id:
            clauses.append("account_id=?"); params.append(account_id)
        if status:
            clauses.append("status=?"); params.append(status)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY started_at DESC NULLS LAST, job_id"
        try:
            return [dict(r) for r in self._exec(sql, params).fetchall()]
        except sqlite3.OperationalError:
            # older sqlite lacks NULLS LAST — fall back to a portable ordering
            sql = sql.replace(" DESC NULLS LAST", "")
            return [dict(r) for r in self._exec(sql, params).fetchall()]


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
