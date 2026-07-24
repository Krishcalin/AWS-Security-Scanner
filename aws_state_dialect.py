#!/usr/bin/env python3
"""
aws_state_dialect.py — Postgres/SQLite dialect layer for the aws_state finding-
lifecycle store (CNAPP Phase 6). PURE (string -> string): the SQL is already
~95% ANSI-portable, so this module isolates the handful of sqlite-specific
constructs and renders the Postgres translation as a TESTED ARTIFACT without
requiring psycopg in CI. The live PostgresBackend + the StateStore refactor are
DEFERRED (Phase 7); only the DDL/upsert/dialect generators + URL parsing + the
migration skeleton ship here.

Keep epoch=BIGINT and iso=TEXT and flags=INTEGER 0/1 (NEVER timestamptz/BOOLEAN)
so ``dict(row)`` / JSON / MTTR output stays byte-identical across backends. The
waiver glob stays in Python (fnmatchcase) — a GLOB->regex translation risks a
false suppression (the worst class), so it is NEVER pushed into SQL.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple


class StateBackendUnavailable(RuntimeError):
    """A requested state backend (e.g. postgresql://) cannot be served — the
    driver is missing or the DB is unreachable. The scanner catches this and runs
    stateless; a postgresql:// URL MUST NEVER silently fall back to a local
    sqlite file (that would split a shared team store)."""


# ── URL parsing ───────────────────────────────────────────────────────────────
def parse_state_url(url: str) -> Tuple[str, str]:
    """('postgres'|'sqlite', dsn). A bare path or sqlite:/// stays sqlite (today's
    behavior); postgresql:// | postgres:// selects the Postgres backend."""
    if not url:
        return ("sqlite", url)
    low = url.lower()
    if low.startswith("postgresql://") or low.startswith("postgres://"):
        return ("postgres", url)
    if low.startswith("sqlite:///"):
        return ("sqlite", url[len("sqlite:///"):])
    if low.startswith("sqlite://"):
        return ("sqlite", url[len("sqlite://"):])
    return ("sqlite", url)   # bare path or ':memory:'


# ── qmark ('?') -> pyformat ('%s') conversion (string-literal aware) ─────────
def qmark_to_pyformat(sql: str) -> str:
    """Convert sqlite '?' placeholders to psycopg '%s', doubling any literal '%'
    (psycopg treats '%' specially). Skips characters inside string literals."""
    out: List[str] = []
    in_str: Optional[str] = None
    for ch in sql:
        if in_str is not None:
            out.append("%%" if ch == "%" else ch)
            if ch == in_str:
                in_str = None
        else:
            if ch in ("'", '"'):
                in_str = ch
                out.append(ch)
            elif ch == "?":
                out.append("%s")
            elif ch == "%":
                out.append("%%")
            else:
                out.append(ch)
    return "".join(out)


# ── upsert builder ────────────────────────────────────────────────────────────
def build_upsert(table: str, cols: List[str], conflict_cols: List[str],
                 update_cols: Optional[List[str]], reset_cols: Optional[Dict[str, str]] = None,
                 returning: Optional[str] = None, ph: str = "%s") -> str:
    """Postgres ON CONFLICT upsert.

    * ``update_cols=None`` -> ``ON CONFLICT DO NOTHING`` (== sqlite INSERT OR IGNORE).
    * else ``ON CONFLICT(pk) DO UPDATE SET col=EXCLUDED.col`` (== INSERT OR REPLACE).

    ``reset_cols`` resets columns to a literal on conflict — CRITICAL for the
    ``scans`` row: sqlite INSERT OR REPLACE deletes+reinserts and thus resets the
    5 drift counters to their DEFAULT 0; a naive DO UPDATE would leave STALE
    counts, so those columns must be passed here as ``{col: '0'}``.
    """
    placeholders = ",".join([ph] * len(cols))
    sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})"
    # None OR an empty list -> DO NOTHING. (An empty update list must not render
    # "DO UPDATE SET " with nothing after SET, which is invalid SQL.)
    if not update_cols and not reset_cols:
        sql += f" ON CONFLICT ({', '.join(conflict_cols)}) DO NOTHING"
    else:
        sets = [f"{c}=EXCLUDED.{c}" for c in update_cols]
        for c, v in (reset_cols or {}).items():
            sets.append(f"{c}={v}")
        sql += (f" ON CONFLICT ({', '.join(conflict_cols)}) DO UPDATE SET "
                + ", ".join(sets))
    if returning:
        sql += f" RETURNING {returning}"
    return sql


# ── hybrid row (mimics sqlite3.Row: positional AND by-name AND dict()) ───────
class _Row:
    """Supports row[0], row['col'], row.get('col'), row.keys(), dict(row) — the
    single most load-bearing compatibility piece, since aws_state uses BOTH
    positional (COUNT(*).fetchone()[0]) and by-name access."""

    __slots__ = ("_cols", "_vals", "_map")

    def __init__(self, cols, vals):
        self._cols = list(cols)
        self._vals = list(vals)
        self._map = {c: i for i, c in enumerate(self._cols)}

    def __getitem__(self, k):
        if isinstance(k, int):
            return self._vals[k]
        return self._vals[self._map[k]]

    def get(self, k, d=None):
        i = self._map.get(k)
        return self._vals[i] if i is not None else d

    def keys(self):
        return list(self._cols)

    def __len__(self):
        return len(self._vals)

    def __iter__(self):
        return iter(self._vals)


def hybrid_row_factory(cur) -> Callable:
    """psycopg row_factory: build _Row from the cursor description."""
    cols = [c.name for c in (cur.description or [])]

    def make(values):
        return _Row(cols, values)
    return make


# ── DDL translation (Postgres) ────────────────────────────────────────────────
# Rendered per-dialect. Epoch=BIGINT (avoids the 2038 int32 problem), flags/counts
# INTEGER, posture_score DOUBLE PRECISION, AUTOINCREMENT -> GENERATED BY DEFAULT AS
# IDENTITY (BY DEFAULT so a migration can copy historical ids verbatim), PRAGMA
# user_version -> a schema_migrations table.
POSTGRES_DDL: List[str] = [
    """CREATE TABLE IF NOT EXISTS schema_migrations(
       version INTEGER PRIMARY KEY, applied_epoch BIGINT)""",
    """CREATE TABLE IF NOT EXISTS findings(
       account TEXT NOT NULL, finding_key TEXT NOT NULL, key_version INTEGER NOT NULL DEFAULT 1,
       region TEXT NOT NULL DEFAULT 'global', check_id TEXT NOT NULL, section TEXT,
       resource TEXT NOT NULL, message TEXT, severity TEXT NOT NULL, result_status TEXT NOT NULL,
       status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved')),
       first_seen_scan TEXT, first_seen_epoch BIGINT NOT NULL, first_seen_iso TEXT NOT NULL,
       last_seen_scan TEXT, last_seen_epoch BIGINT NOT NULL, last_seen_iso TEXT NOT NULL,
       resolved_epoch BIGINT, times_seen INTEGER NOT NULL DEFAULT 1,
       reopen_count INTEGER NOT NULL DEFAULT 0, last_scan_id TEXT NOT NULL, fingerprint TEXT,
       PRIMARY KEY(account, finding_key))""",
    "CREATE INDEX IF NOT EXISTS ix_find_status ON findings(account,status)",
    "CREATE INDEX IF NOT EXISTS ix_find_scope ON findings(account,region,check_id)",
    """CREATE TABLE IF NOT EXISTS finding_events(
       id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, account TEXT NOT NULL,
       finding_key TEXT NOT NULL, scan_id TEXT NOT NULL, ts_epoch BIGINT NOT NULL,
       from_status TEXT, to_status TEXT NOT NULL, severity TEXT, note TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_evt_key ON finding_events(account,finding_key,ts_epoch)",
    """CREATE TABLE IF NOT EXISTS waivers(
       id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       match_type TEXT NOT NULL CHECK(match_type IN ('exact','glob')),
       finding_key TEXT, account TEXT NOT NULL DEFAULT '*', region TEXT NOT NULL DEFAULT '*',
       check_glob TEXT, resource_glob TEXT, approver TEXT NOT NULL, reason TEXT NOT NULL,
       created_epoch BIGINT NOT NULL, expires_epoch BIGINT, revoked INTEGER NOT NULL DEFAULT 0)""",
    "CREATE INDEX IF NOT EXISTS ix_waiver_live ON waivers(revoked,expires_epoch)",
    """CREATE TABLE IF NOT EXISTS scans(
       scan_id TEXT PRIMARY KEY, account TEXT NOT NULL, region TEXT, ts_epoch BIGINT NOT NULL,
       ts_iso TEXT NOT NULL, posture_score DOUBLE PRECISION NOT NULL, grade TEXT,
       crit INTEGER DEFAULT 0, high INTEGER DEFAULT 0, med INTEGER DEFAULT 0,
       low INTEGER DEFAULT 0, info INTEGER DEFAULT 0, total_open INTEGER DEFAULT 0,
       new_count INTEGER DEFAULT 0, resolved_count INTEGER DEFAULT 0,
       reopened_count INTEGER DEFAULT 0, suppressed_count INTEGER DEFAULT 0, scanner_version TEXT)""",
    """CREATE TABLE IF NOT EXISTS scan_coverage(
       scan_id TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, check_id TEXT NOT NULL,
       PRIMARY KEY(scan_id,account,region,check_id))""",
    """CREATE TABLE IF NOT EXISTS principal_usage(
       account TEXT NOT NULL, arn TEXT NOT NULL, source TEXT, last_used_epoch BIGINT,
       last_used_iso TEXT, dormant INTEGER, granted_services INTEGER, used_services INTEGER,
       unused_services_json TEXT, unused_actions_json TEXT, window_days INTEGER,
       collected_epoch BIGINT, slad_job_status TEXT, error_json TEXT,
       PRIMARY KEY(account,arn))""",
    # ── onboarding plane (Phase 8) — sqlite twins in aws_state._DDL. Only diff:
    # the *_at / *_epoch columns are BIGINT here (INTEGER on sqlite). ────────────
    """CREATE TABLE IF NOT EXISTS accounts(
       account_id TEXT PRIMARY KEY CHECK(length(account_id)=12),
       alias TEXT NOT NULL DEFAULT '', org_id TEXT,
       onboarding_method TEXT NOT NULL DEFAULT 'manual' CHECK(onboarding_method IN ('single','org','manual')),
       onboarding_status TEXT NOT NULL DEFAULT 'pending' CHECK(onboarding_status IN ('pending','active','denied','disabled')),
       role_arn TEXT NOT NULL DEFAULT '', external_id_ref TEXT,
       enabled_regions TEXT NOT NULL DEFAULT '[]', scan_schedule TEXT,
       health TEXT NOT NULL DEFAULT 'unknown' CHECK(health IN ('unknown','validating','healthy','degraded','unauthorized')),
       health_detail TEXT,
       last_scan_at BIGINT, first_seen_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS ix_acct_org ON accounts(org_id)",
    "CREATE INDEX IF NOT EXISTS ix_acct_health ON accounts(health)",
    """CREATE TABLE IF NOT EXISTS scan_jobs(
       job_id TEXT PRIMARY KEY,
       account_id TEXT NOT NULL REFERENCES accounts(account_id),
       status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','done','error')),
       started_at BIGINT, finished_at BIGINT, findings_count INTEGER NOT NULL DEFAULT 0, error TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_job_acct ON scan_jobs(account_id, started_at)",
    "CREATE INDEX IF NOT EXISTS ix_job_status ON scan_jobs(status)",
    """CREATE TABLE IF NOT EXISTS connection_health(
       account TEXT NOT NULL, role_arn TEXT NOT NULL, region TEXT NOT NULL DEFAULT 'us-east-1',
       org_mode INTEGER NOT NULL DEFAULT 0,
       health TEXT NOT NULL CHECK(health IN ('validating','healthy','degraded','unauthorized')),
       observed_account TEXT, last_error_code TEXT, last_detail TEXT,
       consecutive_failures INTEGER NOT NULL DEFAULT 0,
       last_validated_epoch BIGINT NOT NULL, last_validated_iso TEXT NOT NULL, next_due_epoch BIGINT NOT NULL,
       PRIMARY KEY(account, role_arn))""",
    "CREATE INDEX IF NOT EXISTS ix_conn_due ON connection_health(next_due_epoch)",
    # ── connector framework (Phase-2 workflow plane) — sqlite twins in aws_state._DDL.
    # Only diff: *_at/*_epoch are BIGINT here and AUTOINCREMENT -> IDENTITY. ─────────
    """CREATE TABLE IF NOT EXISTS connectors(
       connector_id TEXT PRIMARY KEY,
       type TEXT NOT NULL CHECK(type IN ('jira','slack','pagerduty','splunk','webhook')),
       name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
       config_json TEXT NOT NULL DEFAULT '{}', secret_ref TEXT, created_by TEXT,
       last_test_at BIGINT, last_test_status TEXT, last_test_detail TEXT,
       created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)""",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_conn_name ON connectors(name)",
    """CREATE TABLE IF NOT EXISTS connector_rules(
       id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       connector_id TEXT NOT NULL REFERENCES connectors(connector_id) ON DELETE CASCADE,
       name TEXT, enabled INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 100,
       min_severity TEXT NOT NULL DEFAULT 'HIGH' CHECK(min_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
       check_glob TEXT, section TEXT, account_glob TEXT NOT NULL DEFAULT '*',
       on_attack_path INTEGER, status_filter TEXT NOT NULL DEFAULT 'FAIL',
       dedup_window_sec INTEGER, options_json TEXT NOT NULL DEFAULT '{}',
       created_by TEXT, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS ix_rule_conn ON connector_rules(connector_id, enabled)",
    """CREATE TABLE IF NOT EXISTS notification_log(
       id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       connector_id TEXT NOT NULL REFERENCES connectors(connector_id),
       dedup_key TEXT NOT NULL, rule_id BIGINT, account TEXT NOT NULL, check_id TEXT,
       finding_key TEXT,
       state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','resolved')),
       kind TEXT, fingerprint TEXT,
       first_notified_epoch BIGINT, last_notified_epoch BIGINT,
       notify_count INTEGER NOT NULL DEFAULT 0,
       status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sent','failed','skipped')),
       attempts INTEGER NOT NULL DEFAULT 0, http_status INTEGER, error TEXT, external_ref TEXT,
       created_at BIGINT NOT NULL, sent_at BIGINT)""",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_notify_dedup ON notification_log(connector_id, dedup_key)",
    "CREATE INDEX IF NOT EXISTS ix_notify_status ON notification_log(connector_id, status)",
    "CREATE INDEX IF NOT EXISTS ix_notify_acct ON notification_log(account)",
    "CREATE INDEX IF NOT EXISTS ix_notify_created ON notification_log(created_at)",
    # ── drift-digest delivery ledger — sqlite twin in aws_state._DDL ──────────────
    """CREATE TABLE IF NOT EXISTS digest_log(
       id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
       connector_id TEXT NOT NULL REFERENCES connectors(connector_id),
       digest_key TEXT NOT NULL, account TEXT NOT NULL, scan_id TEXT NOT NULL, window_id TEXT NOT NULL,
       new_count INTEGER NOT NULL DEFAULT 0, resolved_count INTEGER NOT NULL DEFAULT 0,
       reopened_count INTEGER NOT NULL DEFAULT 0, posture_delta DOUBLE PRECISION,
       material INTEGER NOT NULL DEFAULT 0,
       status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sent','failed','skipped')),
       attempts INTEGER NOT NULL DEFAULT 0, http_status INTEGER, error TEXT, external_ref TEXT,
       created_at BIGINT NOT NULL, sent_at BIGINT)""",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_digest_dedup ON digest_log(connector_id, digest_key)",
    "CREATE INDEX IF NOT EXISTS ix_digest_acct ON digest_log(account)",
    "CREATE INDEX IF NOT EXISTS ix_digest_created ON digest_log(created_at)",
    # ── external-vuln ingest plane — sqlite twins in aws_state._DDL ───────────────
    """CREATE TABLE IF NOT EXISTS ingest_docs(
       doc_id TEXT PRIMARY KEY, account TEXT NOT NULL,
       source_format TEXT NOT NULL CHECK(source_format IN ('sarif','cyclonedx','spdx')),
       source_tool TEXT, target_resource TEXT, resolved_node TEXT,
       finding_count INTEGER NOT NULL DEFAULT 0,
       status TEXT NOT NULL DEFAULT 'ingested'
         CHECK(status IN ('ingested','unmapped','rejected')),
       error TEXT, ingested_epoch BIGINT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS ix_ingdoc_acct ON ingest_docs(account, ingested_epoch)",
    """CREATE TABLE IF NOT EXISTS ingested_vulns(
       account TEXT NOT NULL, node_id TEXT NOT NULL, cve TEXT NOT NULL,
       node_kind TEXT, package TEXT, installed_version TEXT, fixed_version TEXT,
       severity TEXT, cvss_base DOUBLE PRECISION, epss DOUBLE PRECISION,
       kev INTEGER NOT NULL DEFAULT 0,
       exploit_available TEXT, sources_json TEXT NOT NULL DEFAULT '[]',
       suppressed INTEGER NOT NULL DEFAULT 0,
       reachable_from_internet INTEGER NOT NULL DEFAULT 0,
       on_attack_path INTEGER NOT NULL DEFAULT 0,
       reaches_crown INTEGER NOT NULL DEFAULT 0,
       terminal_kinds_json TEXT NOT NULL DEFAULT '[]',
       priority_score INTEGER NOT NULL DEFAULT 0, priority_band TEXT,
       driving_path TEXT, mapping_status TEXT NOT NULL DEFAULT 'resolved',
       first_ingested_epoch BIGINT NOT NULL, last_seen_epoch BIGINT NOT NULL, doc_id TEXT,
       PRIMARY KEY(account, node_id, cve))""",
    "CREATE INDEX IF NOT EXISTS ix_ingv_rank    ON ingested_vulns(account, priority_score)",
    "CREATE INDEX IF NOT EXISTS ix_ingv_kevpath ON ingested_vulns(account, kev, on_attack_path)",
    """CREATE TABLE IF NOT EXISTS cdr_detections(
       account TEXT NOT NULL, detection_id TEXT NOT NULL,
       source TEXT NOT NULL, type TEXT, title TEXT,
       node_id TEXT, node_kind TEXT, node_key TEXT,
       mapping_status TEXT NOT NULL DEFAULT 'resolved',
       severity DOUBLE PRECISION, band TEXT,
       on_attack_path INTEGER NOT NULL DEFAULT 0,
       reaches_crown INTEGER NOT NULL DEFAULT 0,
       hits_crown INTEGER NOT NULL DEFAULT 0,
       reachable_from_internet INTEGER NOT NULL DEFAULT 0,
       incident INTEGER NOT NULL DEFAULT 0,
       priority_score INTEGER NOT NULL DEFAULT 0, priority_band TEXT,
       driving_path TEXT, archived INTEGER NOT NULL DEFAULT 0,
       first_seen_epoch BIGINT NOT NULL, last_seen_epoch BIGINT NOT NULL,
       PRIMARY KEY(account, detection_id))""",
    "CREATE INDEX IF NOT EXISTS ix_cdr_rank     ON cdr_detections(account, priority_score)",
    "CREATE INDEX IF NOT EXISTS ix_cdr_incident ON cdr_detections(account, incident)",
]

# Per-account advisory lock replacing sqlite's whole-DB BEGIN IMMEDIATE (different
# accounts scan in parallel — strictly better than sqlite).
PG_ADVISORY_LOCK = "SELECT pg_advisory_xact_lock(%s, hashtext(%s))"
PG_LOCK_CLASS = 0x434E   # 'CN'


class PostgresDialect:
    """Renders the aws_state SQL for Postgres. paramstyle 'pyformat'."""
    paramstyle = "pyformat"

    def ddl(self) -> List[str]:
        return list(POSTGRES_DDL)

    def convert(self, sql: str) -> str:
        return qmark_to_pyformat(sql)

    def upsert(self, table, cols, conflict_cols, update_cols, reset_cols=None,
               returning=None) -> str:
        return build_upsert(table, cols, conflict_cols, update_cols, reset_cols,
                            returning, ph="%s")


class SqliteDialect:
    """Identity dialect: today's sqlite SQL is passed through unchanged."""
    paramstyle = "qmark"

    def ddl(self) -> List[str]:
        import aws_state
        return [s.strip() for s in aws_state._DDL.split(";") if s.strip()]

    def convert(self, sql: str) -> str:
        return sql

    def upsert(self, table, cols, conflict_cols, update_cols, reset_cols=None,
               returning=None) -> str:
        # sqlite path uses INSERT OR REPLACE / OR IGNORE inline in aws_state today;
        # provided for API symmetry.
        verb = "INSERT OR IGNORE" if update_cols is None else "INSERT OR REPLACE"
        placeholders = ",".join(["?"] * len(cols))
        return f"{verb} INTO {table} ({', '.join(cols)}) VALUES ({placeholders})"


def dialect_for(scheme: str):
    if scheme == "postgres":
        return PostgresDialect()
    return SqliteDialect()


# ── migration skeleton (DEFERRED live path) ──────────────────────────────────
def migrate_sqlite_to_postgres(sqlite_path: str, pg_url: str, batch: int = 1000) -> None:
    """Copy an existing sqlite state.db into a fresh Postgres store (pure row copy;
    GENERATED BY DEFAULT AS IDENTITY lets historical ids be inserted verbatim, then
    setval past MAX(id)). Requires psycopg — raises StateBackendUnavailable if it
    is absent, so this is a no-op on a CI box without the driver."""
    try:
        import psycopg  # noqa: F401
    except Exception as e:   # pragma: no cover - exercised only where psycopg absent
        raise StateBackendUnavailable(
            f"migration requires psycopg (postgresql:// backend): {e}")
    raise NotImplementedError(
        "live sqlite->postgres migration is deferred to Phase 7 (needs a live PG)")
