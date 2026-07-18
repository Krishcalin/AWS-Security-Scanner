"""Offline tests for cnapp_backend — the dual-dialect Backend. The sqlite path's
byte-identity is guarded by the full existing suite; here we exercise the Postgres
path with an injected fake psycopg3 connection (no live server), the
StateBackendUnavailable contract, and the drift-reset self-check."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # for fake_psycopg

import aws_state as S
import aws_state_dialect as D
import cnapp_backend as B
from cnapp_registry import (ACCT_COLS, ACCT_UPDATE, AccountRegistry)
from cnapp_validate import CheckResult, ConnectionHealth, ValidationResult, cadence
from fake_psycopg import FakeConn

ACCT = "210987654321"


def _pg(fc=None):
    return B.PostgresBackend(fc or FakeConn())


# ── PostgresBackend primitives ───────────────────────────────────────────────
def test_qmark_converted_to_pyformat():
    fc = FakeConn()
    _pg(fc).execute("SELECT x FROM t WHERE a=? AND b=?", ("1", "k"))
    sql, params = fc.execute_log[-1]
    assert "%s" in sql and "?" not in sql and params == ("1", "k")


def test_upsert_is_on_conflict_with_pyformat_and_resets():
    fc = FakeConn()
    _pg(fc).upsert("scans", S.SCAN_COLS, ["scan_id"], S.SCAN_UPDATE,
                   tuple(range(len(S.SCAN_COLS))), reset_cols=S.SCAN_COUNTER_RESET)
    sql = fc.execute_log[-1][0]
    assert "ON CONFLICT (scan_id) DO UPDATE SET" in sql
    assert "posture_score=EXCLUDED.posture_score" in sql
    for counter in S.SCAN_COUNTER_RESET:
        assert f"{counter}=0" in sql
    assert "%s" in sql and "?" not in sql


def test_upsert_many_do_nothing():
    fc = FakeConn()
    _pg(fc).upsert_many("scan_coverage", S.COVERAGE_COLS, S.COVERAGE_COLS, None,
                        [("s", ACCT, "global", "S3-01")])
    sql = fc.execute_log[-1][0]
    assert "ON CONFLICT (scan_id, account, region, check_id) DO NOTHING" in sql


def test_scalar_and_hybrid_rows():
    fc = FakeConn()
    fc.stub("COUNT(*)", ["count"], [(7,)])
    assert _pg(fc).scalar("SELECT COUNT(*) FROM findings WHERE a=?", ("x",)) == 7
    fc.stub("FROM accounts", ["account_id", "alias"], [(ACCT, "prod")])
    row = _pg(fc).query_one("SELECT * FROM accounts WHERE account_id=?", (ACCT,))
    assert row[0] == ACCT and row["alias"] == "prod" and dict(row)["alias"] == "prod"


def test_migrate_runs_postgres_ddl_not_pragma():
    fc = FakeConn()
    fc.stub("MAX(version)", ["m"], [(0,)])
    _pg(fc).migrate()
    log = fc.sql_log
    assert sum(1 for s in log if "CREATE TABLE" in s) >= 9
    assert any("schema_migrations" in s and "INSERT" in s for s in log)
    assert not any("PRAGMA" in s or "executescript" in s for s in log)


def test_insert_returning_id_appends_returning():
    fc = FakeConn()
    fc.stub("RETURNING id", ["id"], [(42,)])
    wid = _pg(fc).insert_returning_id(
        "INSERT INTO waivers(match_type) VALUES(?)", ("exact",), id_col="id")
    assert wid == 42 and fc.execute_log[-1][0].rstrip().endswith("RETURNING id")


def test_transaction_commit_and_rollback():
    fc = FakeConn()
    be = _pg(fc)
    c0 = fc.commits
    with be.transaction():
        be.execute("UPDATE t SET a=? WHERE b=?", ("x", "y"))
        assert fc.commits == c0                 # not committed mid-transaction
    assert fc.commits == c0 + 1                  # one commit on clean exit
    c1, r0 = fc.commits, fc.rollbacks
    with pytest.raises(RuntimeError):
        with be.transaction():
            be.execute("UPDATE t SET a=?", ("z",))
            raise RuntimeError("boom")
    assert fc.rollbacks == r0 + 1 and fc.commits == c1     # rolled back, no commit


# ── StateBackendUnavailable contract (never silent sqlite fallback) ──────────
def test_driver_absent_raises_backend_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "psycopg", None)       # -> import psycopg fails
    with pytest.raises(D.StateBackendUnavailable):
        B.PostgresBackend.connect("postgresql://cnapp-nohost.invalid/cnapp")


def test_unreachable_server_raises_backend_unavailable():
    # no PG listening in the test env -> connect fails -> StateBackendUnavailable
    with pytest.raises(D.StateBackendUnavailable):
        B.PostgresBackend.connect("postgresql://cnapp-nohost.invalid:5432/cnapp", connect_timeout=1)


def test_state_open_postgres_raises():
    with pytest.raises(D.StateBackendUnavailable):
        S.StateStore.open("postgresql://cnapp-nohost.invalid:5432/cnapp")


# ── AccountRegistry driven on a Postgres backend (fake) ──────────────────────
def _registry_on(fc):
    """AccountRegistry over an injected PostgresBackend — no migrate (fake)."""
    return AccountRegistry(B.PostgresBackend(fc))


def test_registry_upsert_account_preserves_via_on_conflict():
    fc = FakeConn()
    _registry_on(fc).upsert_account(ACCT, now_epoch=1, alias="prod",
                                    enabled_regions=["us-east-1"])
    sql = fc.execute_log[-1][0]
    assert "ON CONFLICT (account_id) DO UPDATE SET" in sql
    # preserve-on-reonboard: lifecycle columns must NOT be in the SET list
    for preserved in ("onboarding_status", "health", "first_seen_at", "last_scan_at"):
        assert f"{preserved}=EXCLUDED" not in sql
    assert "%s" in sql and "?" not in sql


def test_registry_record_health_pyformat_and_txn():
    fc = FakeConn()
    fc.stub("consecutive_failures FROM connection_health", ["consecutive_failures"], [(0,)])
    reg = _registry_on(fc)
    res = ValidationResult(expected_account_id=ACCT, role_arn="r", region="us-east-1",
                           org_mode=False, observed_account_id=ACCT,
                           checks=[CheckResult("assume_role", "ok", "x")],
                           health=ConnectionHealth.HEALTHY, summary="ok")
    reg.record_health(ACCT, "r", res, 100)
    assert all("?" not in s for s in fc.sql_log)             # all converted
    assert any("ON CONFLICT (account, role_arn) DO UPDATE SET" in s for s in fc.sql_log)
    assert fc.commits == 1                                   # single txn commit
    assert res.next_revalidation_epoch == 100 + cadence(ConnectionHealth.HEALTHY)


def test_registry_list_scan_jobs_uses_backend_operational_error():
    """The NULLS-LAST fallback must catch self._be.OperationalError (psycopg's), not
    a hardcoded sqlite3 class — else PG would never fall back."""
    fc = FakeConn()
    fc.stub("FROM scan_jobs", ["job_id", "started_at"], [("j1", 100)])
    reg = _registry_on(fc)
    rows = reg.list_scan_jobs()
    assert rows and rows[0]["job_id"] == "j1"
    assert reg._be.OperationalError is __import__("psycopg").errors.OperationalError


# ── drift-reset self-check (the one PG/sqlite divergence risk) ───────────────
def test_scan_counter_reset_matches_defaulted_columns():
    """SCAN_COUNTER_RESET must equal exactly the `scans` columns that carry a
    DEFAULT and are OMITTED from the 13-col insert — so the PG ON CONFLICT reset
    replicates sqlite's INSERT OR REPLACE. Fails loudly if a defaulted column is
    added without being reset."""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.executescript(S._DDL)
    cols = conn.execute("PRAGMA table_info(scans)").fetchall()
    defaulted = {c[1] for c in cols if c[4] is not None}    # dflt_value not null
    omitted = set(defaulted) - set(S.SCAN_COLS)
    assert set(S.SCAN_COUNTER_RESET.keys()) == omitted


# ── regression (adversarial): autocommit=True + real transaction() ───────────
def test_connect_uses_autocommit_true(monkeypatch):
    """A shared psycopg conn MUST be autocommit=True — else reads leak
    'idle in transaction' and a failed statement poisons the connection."""
    import psycopg
    captured = {}
    def fake_connect(dsn, **kw):
        captured.update(kw); captured["dsn"] = dsn
        return FakeConn()
    monkeypatch.setattr(psycopg, "connect", fake_connect)
    B.PostgresBackend.connect("postgresql://u@h/db")
    assert captured["autocommit"] is True


def test_transaction_goes_through_psycopg_transaction_cm():
    """Atomic blocks use conn.transaction() (explicit BEGIN/COMMIT under
    autocommit), never a manual BEGIN — proven via the fake's counter."""
    fc = FakeConn()
    be = _pg(fc)
    with be.transaction():
        be.execute("UPDATE t SET a=? WHERE b=?", ("x", "y"))
    assert fc.transactions == 1
    assert not any("BEGIN" in s for s in fc.sql_log)     # no manual BEGIN emitted


def test_reads_do_not_open_a_transaction():
    """query_* at depth 0 must not open a transaction (autocommit handles it)."""
    fc = FakeConn()
    fc.stub("FROM accounts", ["account_id"], [(ACCT,)])
    _pg(fc).query_one("SELECT * FROM accounts WHERE account_id=?", (ACCT,))
    assert fc.transactions == 0 and fc.rollbacks == 0


# ── regression: SQLite >= 3.24 guard is centralized in backend_for ───────────
def test_backend_for_guards_old_sqlite(monkeypatch):
    monkeypatch.setattr(B.sqlite3, "sqlite_version_info", (3, 23, 0))
    with pytest.raises(D.StateBackendUnavailable):
        B.backend_for(":memory:")


# ── regression: wrapping a raw sqlite3.Connection sets row_factory ───────────
def test_sqlite_backend_wrap_sets_row_factory():
    import sqlite3
    raw = sqlite3.connect(":memory:")
    be = B.SqliteBackend(raw)
    assert raw.row_factory is sqlite3.Row
    be.migrate()
    be.execute("INSERT INTO accounts(account_id,alias,onboarding_method,onboarding_status,"
               "role_arn,enabled_regions,health,first_seen_at,updated_at) "
               "VALUES('210987654321','p','single','pending','','[]','unknown',1,1)")
    row = be.query_one("SELECT * FROM accounts WHERE account_id=?", (ACCT,))
    assert row["alias"] == "p" and dict(row)["account_id"] == ACCT


def test_statestore_legacy_raw_conn_path_works():
    """The advertised StateStore(raw_conn) compat path must yield by-name rows."""
    import sqlite3
    st = S.StateStore(sqlite3.connect(":memory:"))
    st._migrate()
    assert st.open_findings("acct") == []          # dict(row) access must not raise
