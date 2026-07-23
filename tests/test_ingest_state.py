"""B4 — ingest persistence: ingest_docs + ingested_vulns twins.

Migration creates both tables (v4->v5 gate), sources set-union upsert, verdict
write, ranked/faceted reads, doc idempotency, and POSTGRES_DDL parity (string
artifact — no psycopg needed). Pure/offline sqlite :memory:."""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import aws_state_dialect as dia
from aws_state import StateStore


def _store():
    return StateStore.open(":memory:")


def _acct(s, acct="111122223333"):
    # ingest_docs.account has no FK, but seat an account row for realism.
    return acct


def _vuln_row(node="arn:img", cve="CVE-2021-44228", sources=("ingest:trivy",),
              kev=True, on_path=False, band="HIGH", epoch=1000, suppressed=False):
    return {
        "account": "111122223333", "node_id": node, "cve": cve, "node_kind": "ECRImage",
        "package": "log4j-core", "installed_version": "2.14.1", "fixed_version": "2.17.1",
        "severity": band, "cvss_base": 10.0, "epss": 0.975, "kev": kev,
        "exploit_available": "YES", "sources": list(sources), "suppressed": suppressed,
        "mapping_status": "resolved", "last_seen_epoch": epoch, "doc_id": "sha256:d1",
    }


# ── migration ────────────────────────────────────────────────────────────────
def test_migration_creates_ingest_tables():
    s = _store()
    tbls = {r[0] for r in s._be.query_all(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "ingest_docs" in tbls and "ingested_vulns" in tbls
    assert s._be.raw.execute("PRAGMA user_version").fetchone()[0] == aws_state.SCHEMA_VERSION


def test_v4_db_migrates_to_v5():
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA user_version=4")                 # pretend an old v4 DB
    s = StateStore(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 4   # not yet migrated
    s._migrate()                                          # the real open()/backend_for path
    tbls = {r[0] for r in s._be.query_all(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "ingested_vulns" in tbls
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 5


# ── docs ledger ──────────────────────────────────────────────────────────────
def test_ingest_doc_upsert_idempotent():
    s = _store()
    for _ in range(2):                                     # same doc_id twice = no dup
        s.upsert_ingest_doc("111122223333", "sha256:abc", "sarif", "trivy",
                            "img:1", "arn:img", 3, "ingested", None, 1000)
    docs = s.list_ingest_docs("111122223333")
    assert len(docs) == 1 and docs[0]["finding_count"] == 3
    assert s.get_ingest_doc("sha256:abc")["source_tool"] == "trivy"


# ── owned vulns: set-union + verdict ─────────────────────────────────────────
def test_upsert_unions_sources_and_keeps_min_first_epoch():
    s = _store()
    s.upsert_ingested_vuln(_vuln_row(sources=("ingest:trivy",), epoch=1000))
    s.upsert_ingested_vuln(_vuln_row(sources=("ingest:grype", "inspector"), epoch=2000))
    rows = s.account_ingested_rows("111122223333")
    assert len(rows) == 1                                  # one owned row (account,node,cve)
    r = rows[0]
    assert set(r["sources"]) == {"ingest:trivy", "ingest:grype", "inspector"}
    assert r["first_ingested_epoch"] == 1000              # MIN preserved
    assert r["last_seen_epoch"] == 2000


def test_verdict_write_is_separate_from_owned_upsert():
    s = _store()
    s.upsert_ingested_vuln(_vuln_row())
    s.write_ingested_verdict("111122223333", "arn:img", "CVE-2021-44228",
                             {"reachable_from_internet": True, "on_attack_path": True,
                              "reaches_crown": True, "terminal_kinds": ["data"],
                              "priority_score": 92, "priority_band": "CRITICAL",
                              "driving_path": "internet -> arn:img -> bucket"})
    r = s.get_ingested_cve("111122223333", "CVE-2021-44228")[0]
    assert r["on_attack_path"] is True and r["priority_score"] == 92
    assert r["priority_band"] == "CRITICAL" and r["terminal_kinds"] == ["data"]
    # a subsequent owned re-upsert must NOT clobber the verdict
    s.upsert_ingested_vuln(_vuln_row(sources=("ingest:snyk",), epoch=3000))
    r2 = s.get_ingested_cve("111122223333", "CVE-2021-44228")[0]
    assert r2["priority_score"] == 92 and r2["on_attack_path"] is True


def test_list_filters_and_sort():
    s = _store()
    s.upsert_ingested_vuln(_vuln_row(cve="CVE-1", kev=True))
    s.write_ingested_verdict("111122223333", "arn:img", "CVE-1",
                             {"on_attack_path": True, "priority_score": 90,
                              "priority_band": "CRITICAL"})
    s.upsert_ingested_vuln(_vuln_row(cve="CVE-2", kev=False))
    s.write_ingested_verdict("111122223333", "arn:img", "CVE-2",
                             {"on_attack_path": False, "priority_score": 20,
                              "priority_band": "LOW"})
    ranked = s.list_ingested_vulns("111122223333")
    assert [r["cve"] for r in ranked] == ["CVE-1", "CVE-2"]        # priority desc
    assert [r["cve"] for r in s.list_ingested_vulns("111122223333", kev=True)] == ["CVE-1"]
    assert [r["cve"] for r in s.list_ingested_vulns("111122223333", on_path=True)] == ["CVE-1"]
    assert [r["cve"] for r in s.list_ingested_vulns("111122223333", min_band="HIGH")] == ["CVE-1"]
    assert [r["cve"] for r in s.list_ingested_vulns(
        "111122223333", source="ingest:trivy")] == ["CVE-1", "CVE-2"]


def test_suppressed_flag_roundtrips():
    s = _store()
    s.upsert_ingested_vuln(_vuln_row(cve="CVE-SUP", suppressed=True))
    r = s.get_ingested_cve("111122223333", "CVE-SUP")[0]
    assert r["suppressed"] is True
    assert s.list_ingested_vulns("111122223333", include_suppressed=False) == []


# ── postgres DDL parity (string artifact) ────────────────────────────────────
def test_postgres_ddl_has_ingest_twins():
    ddl = "\n".join(dia.POSTGRES_DDL)
    assert "CREATE TABLE IF NOT EXISTS ingest_docs" in ddl
    assert "CREATE TABLE IF NOT EXISTS ingested_vulns" in ddl
    # house rules: epoch = BIGINT, scores = DOUBLE PRECISION, no BOOLEAN
    assert "first_ingested_epoch BIGINT" in ddl and "cvss_base DOUBLE PRECISION" in ddl
    assert "BOOLEAN" not in ddl.split("ingested_vulns", 1)[1].split(")")[0]
    assert "PRIMARY KEY(account, node_id, cve)" in ddl
