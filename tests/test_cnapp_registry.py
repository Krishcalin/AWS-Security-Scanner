"""Offline tests for cnapp_registry.AccountRegistry — schema parity, the preserve-
on-reonboard upsert guarantee, connection-health cadence rows, scan jobs + the
account FK, all on :memory: sqlite with an injected clock."""
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import aws_state_dialect
from cnapp_registry import (ACCT_COLS, ACCT_UPDATE, AccountRegistry)
from cnapp_validate import ConnectionHealth, ValidationResult, CheckResult, cadence

ACCT = "210987654321"


def _reg():
    return AccountRegistry.open(":memory:")


def test_new_tables_created():
    r = _reg()
    tabs = {row[0] for row in r._c.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"accounts", "scan_jobs", "connection_health"} <= tabs


def test_ddl_dialect_parity():
    """The sqlite DDL and its Postgres twin describe the same 3 tables; the only
    difference on the epoch/*_at columns is INTEGER -> BIGINT."""
    sq = " ".join(aws_state_dialect.SqliteDialect().ddl())
    pg = " ".join(aws_state_dialect.PostgresDialect().ddl())
    for tbl in ("accounts", "scan_jobs", "connection_health"):
        assert f"CREATE TABLE IF NOT EXISTS {tbl}" in sq
        assert f"CREATE TABLE IF NOT EXISTS {tbl}" in pg
    assert "first_seen_at BIGINT" in pg and "first_seen_at INTEGER" in sq
    assert "next_due_epoch BIGINT" in pg and "next_due_epoch INTEGER" in sq


def test_upsert_preserves_lifecycle_on_reonboard():
    r = _reg()
    r.upsert_account(ACCT, now_epoch=1000, alias="prod", onboarding_method="org",
                     enabled_regions=["us-east-1", "us-west-2"])
    r.set_onboarding_status(ACCT, "active", 1500)
    r.set_health(ACCT, "healthy", "ok", 1500)
    # re-onboard: refresh config, advance clock
    r.upsert_account(ACCT, now_epoch=3000, alias="prod-renamed")
    a = r.get_account(ACCT)
    assert a["alias"] == "prod-renamed"                 # updated column changed
    assert a["updated_at"] == 3000
    assert a["onboarding_status"] == "active"           # preserved
    assert a["health"] == "healthy"                     # preserved
    assert a["first_seen_at"] == 1000                   # preserved (NOT reset)
    assert a["enabled_regions"] == ["us-east-1", "us-west-2"]


def test_upsert_uses_on_conflict_do_update_not_replace():
    """Guard the exact SQL: build_upsert must render ON CONFLICT DO UPDATE (which
    preserves omitted cols), never INSERT OR REPLACE (which resets them)."""
    sql = aws_state_dialect.build_upsert("accounts", ACCT_COLS, ["account_id"],
                                         ACCT_UPDATE, ph="?")
    assert "ON CONFLICT (account_id) DO UPDATE SET" in sql
    assert "INSERT OR REPLACE" not in sql
    # preserved columns must NOT appear in the SET list
    for preserved in ("onboarding_status", "health", "first_seen_at", "last_scan_at"):
        assert f"{preserved}=EXCLUDED" not in sql


def _vr(health, *, observed=ACCT, err=None):
    checks = [CheckResult("assume_role", "fail" if err else "ok", "x", error_code=err)]
    return ValidationResult(expected_account_id=ACCT, role_arn="r", region="us-east-1",
                            org_mode=False, observed_account_id=observed, checks=checks,
                            health=health, summary="s")


def test_record_health_cadence_and_backoff():
    r = _reg()
    r.upsert_account(ACCT, now_epoch=100)
    # healthy -> cf 0, due in 6h
    rec = r.record_health(ACCT, "r", _vr(ConnectionHealth.HEALTHY), 100)
    assert rec["consecutive_failures"] == 0
    assert rec["next_due_epoch"] == 100 + cadence(ConnectionHealth.HEALTHY)
    # two unauthorized in a row -> cf increments, backoff grows
    r.record_health(ACCT, "r", _vr(ConnectionHealth.UNAUTHORIZED, err="AccessDenied"), 200)
    rec2 = r.record_health(ACCT, "r", _vr(ConnectionHealth.UNAUTHORIZED, err="AccessDenied"), 300)
    assert rec2["consecutive_failures"] == 2
    assert rec2["next_due_epoch"] == 300 + cadence(ConnectionHealth.UNAUTHORIZED, 2)
    # denormalized onto the account row
    assert r.get_account(ACCT)["health"] == "unauthorized"


def test_health_due_filters_and_orders():
    r = _reg()
    for aid, due_now in [("111111111111", 50), ("222222222222", 5000)]:
        r.upsert_account(aid, now_epoch=10)
    # one due (validating, 60s from t=0 -> due 60), one far future
    r.record_health("111111111111", "r", _vr(ConnectionHealth.VALIDATING, err="Throttling"), 0)
    r.record_health("222222222222", "r", _vr(ConnectionHealth.HEALTHY), 0)
    due = r.health_due(100)
    assert [d["account"] for d in due] == ["111111111111"]
    assert r.health_due(10 ** 9)[0]["next_due_epoch"] <= r.health_due(10 ** 9)[-1]["next_due_epoch"]


def test_scan_job_lifecycle_and_last_scan_stamp():
    r = _reg()
    r.upsert_account(ACCT, now_epoch=10)
    r.record_scan_job(ACCT, "job-1", "queued", now_epoch=20)
    r.record_scan_job(ACCT, "job-1", "running", now_epoch=30, started_at=30)
    r.record_scan_job(ACCT, "job-1", "done", now_epoch=90, finished_at=88, findings_count=7)
    j = r.get_scan_job("job-1")
    assert j["status"] == "done" and j["findings_count"] == 7
    assert r.get_account(ACCT)["last_scan_at"] == 88     # stamped from finished_at


def test_scan_job_fk_requires_account():
    r = _reg()
    with pytest.raises(sqlite3.IntegrityError):
        r.record_scan_job("999999999999", "job-x", "queued", now_epoch=1)


def test_list_accounts_filters():
    r = _reg()
    r.upsert_account("111111111111", now_epoch=1)
    r.upsert_account("222222222222", now_epoch=1)
    r.set_onboarding_status("222222222222", "active", 2)
    assert [a["account_id"] for a in r.list_accounts(onboarding_status="active")] == ["222222222222"]
    assert len(r.list_accounts()) == 2


def test_postgres_url_deferred():
    with pytest.raises(aws_state_dialect.StateBackendUnavailable):
        AccountRegistry.open("postgresql://localhost/cnapp")


# ── regression: record_health publishes the authoritative next_due to result ──
def test_record_health_aligns_result_next_revalidation():
    r = _reg()
    r.upsert_account(ACCT, now_epoch=100)
    res = _vr(ConnectionHealth.UNAUTHORIZED, err="AccessDenied")
    r.record_health(ACCT, "role", res, 200)                    # cf -> 1
    res2 = _vr(ConnectionHealth.UNAUTHORIZED, err="AccessDenied")
    rec = r.record_health(ACCT, "role", res2, 300)             # cf -> 2
    # the ValidationResult's field now matches the persisted schedule (not cf=0)
    assert res2.next_revalidation_epoch == rec["next_due_epoch"] == 300 + cadence(
        ConnectionHealth.UNAUTHORIZED, 2)


# ── regression: last_scan_at stamped only on a successful (done) scan ─────────
def test_last_scan_at_not_stamped_on_error():
    r = _reg()
    r.upsert_account(ACCT, now_epoch=10)
    r.record_scan_job(ACCT, "job-e", "error", now_epoch=50, finished_at=50, error="boom")
    assert r.get_account(ACCT)["last_scan_at"] is None         # failed attempt doesn't count
    r.record_scan_job(ACCT, "job-d", "done", now_epoch=90, finished_at=88)
    assert r.get_account(ACCT)["last_scan_at"] == 88


# ── regression: list_scan_jobs is newest-first ───────────────────────────────
def test_list_scan_jobs_newest_first():
    r = _reg()
    r.upsert_account(ACCT, now_epoch=1)
    for jid, t in [("old", 100), ("new", 300), ("mid", 200)]:
        r.record_scan_job(ACCT, jid, "running", now_epoch=t, started_at=t)
    assert [j["job_id"] for j in r.list_scan_jobs()] == ["new", "mid", "old"]


# ── regression: partial re-upsert with NO config is still valid SQL ──────────
def test_noconfig_reupsert_is_valid():
    r = _reg()
    r.upsert_account(ACCT, now_epoch=1, alias="a", enabled_regions=["us-east-1"])
    r.upsert_account(ACCT, now_epoch=2)                        # nothing but updated_at
    a = r.get_account(ACCT)
    assert a["alias"] == "a" and a["enabled_regions"] == ["us-east-1"] and a["updated_at"] == 2


# ── regression: concurrent same-account record_health serializes the backoff ──
def test_concurrent_record_health_counts_every_failure():
    import threading
    r = _reg()
    r.upsert_account(ACCT, now_epoch=0)
    N = 25
    barrier = threading.Barrier(N)

    def worker(i):
        barrier.wait()                                        # maximize contention
        r.record_health(ACCT, "role", _vr(ConnectionHealth.UNAUTHORIZED, err="AccessDenied"),
                        now_epoch=1000 + i)
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    row = r._one("SELECT consecutive_failures FROM connection_health WHERE account=?", (ACCT,))
    assert row["consecutive_failures"] == N                   # no lost update under the lock


def test_concurrent_distinct_account_writes_all_persist():
    import threading
    r = _reg()
    ids = [f"{i:012d}" for i in range(1, 41)]

    def worker(aid):
        r.upsert_account(aid, now_epoch=1)
        r.record_scan_job(aid, "job-" + aid, "done", now_epoch=2, finished_at=2)
    threads = [threading.Thread(target=worker, args=(a,)) for a in ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(r.list_accounts()) == 40
    assert len(r.list_scan_jobs()) == 40
