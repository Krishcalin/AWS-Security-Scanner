"""Phase-4 Slice-4 · B1 — supply-chain schema (SCHEMA 7->8) + state helpers.

Adds sbom_snapshots / sbom_components / sbom_snapshot_cves / vex_statements. Offline
sqlite :memory:; POSTGRES_DDL parity checked as a string artifact (no live PG needed)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import aws_state_dialect as dia

SUPPLY_TABLES = {"sbom_snapshots", "sbom_components", "sbom_snapshot_cves", "vex_statements"}


def _store():
    return aws_state.StateStore.open(":memory:")


def _sqlite_tables(be):
    return {r[0] for r in be.query_all("SELECT name FROM sqlite_master WHERE type='table'")}


def _tables_in(text):
    return set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", text))


def test_schema_version_is_8():
    assert aws_state.SCHEMA_VERSION == 10


def test_migration_creates_supply_chain_tables():
    s = _store()
    assert SUPPLY_TABLES <= _sqlite_tables(s._be)
    assert s._be.raw.execute("PRAGMA user_version").fetchone()[0] == 10


def test_sqlite_postgres_twin_parity():
    sqlite_tables = _tables_in(aws_state._DDL)
    pg_tables = _tables_in("\n".join(dia.POSTGRES_DDL))
    for t in SUPPLY_TABLES:
        assert t in sqlite_tables, f"{t} missing from sqlite _DDL"
        assert t in pg_tables, f"{t} missing from POSTGRES_DDL"


def test_migration_replay_is_nondestructive():
    s = _store()
    s.record_sbom_snapshot({"snapshot_id": "snap1", "account": "a", "node_id": "n",
                            "subject_key": "sub", "source_format": "cyclonedx",
                            "source_tool": "trivy", "component_count": 1, "ingested_epoch": 1000})
    s._be.migrate()          # replay — all IF NOT EXISTS, must not drop data
    assert s.get_sbom_snapshot("snap1") is not None


def test_fk_cascade_removes_children():
    s = _store()
    s.record_sbom_snapshot({"snapshot_id": "snap1", "account": "a", "node_id": "n",
                            "subject_key": "sub", "source_format": "cyclonedx",
                            "component_count": 2, "ingested_epoch": 1000})
    s.insert_sbom_components("snap1", [{"purl_identity": "pkg:pypi/x", "name": "x", "version": "1.0"},
                                       {"purl_identity": "pkg:pypi/y", "name": "y", "version": "2.0"}])
    s.insert_snapshot_cves("snap1", [{"cve": "CVE-2021-1", "purl_identity": "pkg:pypi/x"}])
    assert len(s.get_snapshot_components("snap1")) == 2
    assert len(s.get_snapshot_cves("snap1")) == 1
    s._be.execute("DELETE FROM sbom_snapshots WHERE snapshot_id=?", ("snap1",))
    assert s.get_snapshot_components("snap1") == []      # ON DELETE CASCADE (foreign_keys=ON)
    assert s.get_snapshot_cves("snap1") == []


def test_snapshot_idempotent_and_subjects():
    s = _store()
    for ep in (1000, 2000):
        s.record_sbom_snapshot({"snapshot_id": f"snap{ep}", "account": "a", "node_id": "img@d",
                                "subject_key": "repo", "source_format": "cyclonedx",
                                "component_count": 1, "ingested_epoch": ep})
    # re-upload snap1000 is idempotent (PK = snapshot_id) — subject count stays 2
    s.record_sbom_snapshot({"snapshot_id": "snap1000", "account": "a", "node_id": "img@d",
                            "subject_key": "repo", "source_format": "cyclonedx",
                            "component_count": 1, "ingested_epoch": 1000})
    subs = s.list_sbom_subjects("a")
    assert len(subs) == 1 and subs[0]["subject_key"] == "repo" and subs[0]["snapshots"] == 2
    snaps = s.list_sbom_snapshots("a", subject_key="repo")
    assert [x["snapshot_id"] for x in snaps] == ["snap2000", "snap1000"]   # newest first


def test_vex_lookup_exact_beats_wildcard():
    s = _store()
    s.upsert_vex_statement({"account": "a", "node_id": "n", "cve": "CVE-1", "purl_identity": "*",
                            "status": "under_investigation", "vex_format": "openvex",
                            "doc_id": "d1", "last_seen_epoch": 1000})
    s.upsert_vex_statement({"account": "a", "node_id": "n", "cve": "CVE-1", "purl_identity": "pkg:pypi/x",
                            "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path",
                            "vex_format": "openvex", "doc_id": "d1", "last_seen_epoch": 1000})
    assert s.vex_lookup("a", "n", "CVE-1", "pkg:pypi/x")["status"] == "not_affected"   # exact wins
    wide = s.vex_lookup("a", "n", "CVE-1")                                             # product-wide
    assert wide["purl_identity"] == "*" and wide["status"] == "under_investigation"
    assert s.vex_lookup("a", "n", "CVE-1", "pkg:pypi/other")["purl_identity"] == "*"    # falls back to '*'
    assert s.vex_lookup("a", "n", "CVE-2") is None


def test_vex_first_seen_preserved():
    s = _store()
    for ep in (1000, 2000):
        s.upsert_vex_statement({"account": "a", "node_id": "n", "cve": "CVE-1", "status": "not_affected",
                                "vex_format": "openvex", "doc_id": "d", "last_seen_epoch": ep})
    row = s.vex_lookup("a", "n", "CVE-1")
    assert row["first_seen_epoch"] == 1000 and row["last_seen_epoch"] == 2000


def test_list_components_snapshot_path_is_account_scoped():
    # regression (#5): a snapshot id from another account must read NO components.
    s = _store()
    s.record_sbom_snapshot({"snapshot_id": "A:snap", "account": "A", "node_id": "n", "subject_key": "sub",
                            "source_format": "cyclonedx", "component_count": 1, "ingested_epoch": 1000})
    s.insert_sbom_components("A:snap", [{"purl_identity": "pkg:npm/x", "name": "x"}])
    assert len(s.list_components("A", snapshot_id="A:snap")) == 1
    assert s.list_components("B", snapshot_id="A:snap") == []      # cross-account → nothing


def test_list_components_latest_per_subject_breaks_epoch_ties():
    # regression (#1): two distinct snapshots sharing a (second-resolution) epoch must not merge.
    s = _store()
    for sid in ("s-a", "s-b"):                                     # same subject, same epoch
        s.record_sbom_snapshot({"snapshot_id": sid, "account": "A", "node_id": "n", "subject_key": "sub",
                                "source_format": "cyclonedx", "component_count": 1, "ingested_epoch": 1000})
    s.insert_sbom_components("s-a", [{"purl_identity": "pkg:npm/a", "name": "a"}])
    s.insert_sbom_components("s-b", [{"purl_identity": "pkg:npm/b", "name": "b"}])
    latest = s.list_components("A")                                # exactly one snapshot, not a union
    assert len(latest) == 1


def test_list_components_by_license_category():
    s = _store()
    s.record_sbom_snapshot({"snapshot_id": "snap1", "account": "a", "node_id": "n", "subject_key": "sub",
                            "source_format": "cyclonedx", "component_count": 2, "ingested_epoch": 1000})
    s.insert_sbom_components("snap1", [
        {"purl_identity": "pkg:pypi/x", "name": "x", "license_category": "network_copyleft"},
        {"purl_identity": "pkg:pypi/y", "name": "y", "license_category": "permissive"}])
    denied = s.list_components("a", snapshot_id="snap1", license_category="network_copyleft")
    assert len(denied) == 1 and denied[0]["name"] == "x"
    assert len(s.list_components("a")) == 2               # latest snapshot per subject
