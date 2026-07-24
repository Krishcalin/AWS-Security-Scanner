"""Slice 3 · Batch 3 — CDR detection persistence (cdr_detections v6 twin).

Migration creates the table (v5→v6 gate), dedup-by-id upsert preserving first_seen,
incident/rank reads, and POSTGRES_DDL parity. Pure/offline sqlite :memory:."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import aws_state_dialect as dia
from aws_state import StateStore

ACCT = "111122223333"


def _store():
    return StateStore.open(":memory:")


def _verdict(did="d1", incident=True, band="CRITICAL", score=95, node="arn:aws:s3:::crown"):
    return {"id": did, "source": "guardduty", "type": "Backdoor:EC2", "title": "c2",
            "node_id": node, "node_kind": "S3Bucket", "mapping_status": "resolved",
            "severity": 8.0, "band": band, "on_attack_path": incident, "reaches_crown": True,
            "hits_crown_node": True, "reachable_from_internet": True, "incident": incident,
            "priority_score": score, "priority_band": band, "driving_path": "internet -> x"}


# ── migration ────────────────────────────────────────────────────────────────
def test_migration_creates_cdr_table():
    s = _store()
    tbls = {r[0] for r in s._be.query_all(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "cdr_detections" in tbls
    assert s._be.raw.execute("PRAGMA user_version").fetchone()[0] == aws_state.SCHEMA_VERSION


# ── upsert / dedup / first_seen ──────────────────────────────────────────────
def test_upsert_and_list():
    s = _store()
    s.upsert_cdr_detection(ACCT, _verdict(), epoch=1000)
    rows = s.list_cdr_detections(ACCT)
    assert len(rows) == 1 and rows[0]["detection_id"] == "d1"
    assert rows[0]["incident"] is True and rows[0]["priority_band"] == "CRITICAL"


def test_restream_preserves_first_seen_bumps_last_seen():
    s = _store()
    s.upsert_cdr_detection(ACCT, _verdict(), epoch=1000)
    s.upsert_cdr_detection(ACCT, _verdict(), epoch=2000)          # same id, later
    rows = s.list_cdr_detections(ACCT)
    assert len(rows) == 1                                          # deduped by id
    row = s._be.query_one("SELECT first_seen_epoch, last_seen_epoch FROM cdr_detections "
                          "WHERE account=? AND detection_id=?", (ACCT, "d1"))
    r = dict(row)
    assert r["first_seen_epoch"] == 1000 and r["last_seen_epoch"] == 2000


def test_incidents_only_filter():
    s = _store()
    s.upsert_cdr_detection(ACCT, _verdict(did="hot", incident=True, score=90), epoch=1)
    s.upsert_cdr_detection(ACCT, _verdict(did="cold", incident=False, band="MEDIUM", score=30),
                           epoch=1)
    assert {r["detection_id"] for r in s.list_cdr_detections(ACCT)} == {"hot", "cold"}
    inc = s.list_cdr_detections(ACCT, incidents_only=True)
    assert {r["detection_id"] for r in inc} == {"hot"}


def test_ranked_by_priority():
    s = _store()
    s.upsert_cdr_detection(ACCT, _verdict(did="lo", score=40), epoch=1)
    s.upsert_cdr_detection(ACCT, _verdict(did="hi", score=95), epoch=1)
    rows = s.list_cdr_detections(ACCT)
    assert [r["detection_id"] for r in rows] == ["hi", "lo"]


def test_node_key_roundtrips():
    # node_key is persisted so refresh can rebuild (node_kind, node_key) for GuardDuty detections
    s = _store()
    v = _verdict()
    v["node_key"] = "i-1"
    s.upsert_cdr_detection(ACCT, v, epoch=1)
    row = dict(s._be.query_one(
        "SELECT node_key FROM cdr_detections WHERE account=? AND detection_id=?", (ACCT, "d1")))
    assert row["node_key"] == "i-1"


def test_source_filter():
    s = _store()
    v = _verdict(did="sh1"); v["source"] = "securityhub"
    s.upsert_cdr_detection(ACCT, v, epoch=1)
    s.upsert_cdr_detection(ACCT, _verdict(did="gd1"), epoch=1)
    assert {r["detection_id"] for r in s.list_cdr_detections(ACCT, source="securityhub")} == {"sh1"}


# ── postgres DDL parity ──────────────────────────────────────────────────────
def test_postgres_ddl_has_cdr_twin():
    ddl = "\n".join(dia.POSTGRES_DDL)
    assert "CREATE TABLE IF NOT EXISTS cdr_detections" in ddl
    seg = ddl.split("cdr_detections", 1)[1].split(")")[0]
    assert "first_seen_epoch BIGINT" in ddl and "severity DOUBLE PRECISION" in ddl
    assert "BOOLEAN" not in seg
    assert "PRIMARY KEY(account, detection_id)" in ddl
