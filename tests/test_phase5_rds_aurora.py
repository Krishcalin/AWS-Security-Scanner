"""Phase 5 Batch B2 — RDS instance engine EOL (RDS-12) + Aurora cluster checks
(AUR-01 encryption, AUR-02 deletion-protection, AUR-03 engine EOL, AUR-04 public
cluster snapshot, AUR-05 cluster-snapshot encryption). Offline: MagicMock rds client,
injected scan date. No AWS."""
import os
import sys
from datetime import date
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner, MockPaginator


def _rds_scanner(instances=(), clusters=(), csnaps=(), snap_attrs=None):
    """Wire a MagicMock rds client with the paginators + attr calls RDS/AUR use."""
    s = make_scanner(sections=["RDS"])
    s._today = date(2026, 7, 20)
    rds = MagicMock()

    pag = {
        "describe_db_instances": MockPaginator("DBInstances", list(instances)),
        "describe_db_clusters": MockPaginator("DBClusters", list(clusters)),
        "describe_db_cluster_snapshots": MockPaginator("DBClusterSnapshots", list(csnaps)),
        "describe_db_snapshots": MockPaginator("DBSnapshots", []),
    }
    rds.get_paginator.side_effect = lambda name: pag[name]
    rds.describe_db_snapshot_attributes.return_value = {
        "DBSnapshotAttributesResult": {"DBSnapshotAttributes": []}}

    def _cluster_attrs(DBClusterSnapshotIdentifier):
        a = (snap_attrs or {}).get(DBClusterSnapshotIdentifier, [])
        return {"DBClusterSnapshotAttributesResult": {"DBClusterSnapshotAttributes": a}}
    rds.describe_db_cluster_snapshot_attributes.side_effect = _cluster_attrs

    s._clients["rds:us-east-1"] = rds
    return s


def _by(s, check_id):
    return [r for r in s.results if r.check_id == check_id]


def _status(s, check_id):
    return {r.status for r in _by(s, check_id)}


# ── RDS-12 instance engine EOL ────────────────────────────────────────────────
def test_rds12_eol_instance_fails_and_stashes_edge():
    s = _rds_scanner(instances=[
        {"DBInstanceIdentifier": "legacy", "DBInstanceArn": "arn:aws:rds:us-east-1:1:db:legacy",
         "Engine": "mysql", "EngineVersion": "5.7.44"}])
    s._check_rds()
    assert "FAIL" in _status(s, "RDS-12")
    # graph edge is STASHED (not emitted inline) for late replay
    assert len(s._eol_graph_payloads) == 1
    node_id, kind, matches, props = s._eol_graph_payloads[0]
    assert kind == "RDSInstance" and node_id.endswith(":db:legacy")
    assert matches[0].cve == "EOL-mysql-5.7" and props["engine"] == "mysql"


def test_rds12_supported_instance_passes_no_edge():
    s = _rds_scanner(instances=[
        {"DBInstanceIdentifier": "modern", "DBInstanceArn": "arn:...:modern",
         "Engine": "postgres", "EngineVersion": "16.3"}])
    s._check_rds()
    assert _status(s, "RDS-12") == {"PASS"}
    assert s._eol_graph_payloads == []


def test_rds12_aurora_instance_skipped_here():
    # Aurora engine instances are covered by AUR-03 at cluster level, not RDS-12
    s = _rds_scanner(instances=[
        {"DBInstanceIdentifier": "aur1", "DBInstanceArn": "arn:...:aur1",
         "Engine": "aurora-mysql", "EngineVersion": "5.7.mysql_aurora.2.11.4"}])
    s._check_rds()
    assert _by(s, "RDS-12") == [] or all(r.resource != "aur1" for r in _by(s, "RDS-12"))


def test_rds12_no_instances_is_info_not_pass():
    s = _rds_scanner(instances=[])
    s._check_rds()
    assert _status(s, "RDS-12") == {"INFO"}


def test_rds12_describe_error_warns_not_pass():
    s = _rds_scanner()
    rds = s._clients["rds:us-east-1"]
    def _boom(name):
        if name == "describe_db_instances":
            raise RuntimeError("AccessDenied")
        return MockPaginator("X", [])
    rds.get_paginator.side_effect = _boom
    s._check_rds()
    assert "WARN" in _status(s, "RDS-12") and "PASS" not in _status(s, "RDS-12")


# ── AUR-01/02/03 cluster config + EOL ─────────────────────────────────────────
def test_aur_cluster_encryption_deletion_and_eol():
    s = _rds_scanner(clusters=[
        {"DBClusterIdentifier": "c1", "DBClusterArn": "arn:aws:rds:us-east-1:1:cluster:c1",
         "Engine": "aurora-mysql", "EngineVersion": "5.7.mysql_aurora.2.11.4",
         "StorageEncrypted": False, "DeletionProtection": False}])
    s._check_rds()
    assert "FAIL" in _status(s, "AUR-01")   # unencrypted cluster
    assert "FAIL" in _status(s, "AUR-02")   # no deletion protection
    assert "FAIL" in _status(s, "AUR-03")   # Aurora MySQL v2 EOL
    kinds = {p[1] for p in s._eol_graph_payloads}
    assert "RDSCluster" in kinds


def test_aur_healthy_cluster_passes():
    s = _rds_scanner(clusters=[
        {"DBClusterIdentifier": "c2", "DBClusterArn": "arn:...:c2",
         "Engine": "aurora-postgresql", "EngineVersion": "16.1",
         "StorageEncrypted": True, "DeletionProtection": True}])
    s._check_rds()
    assert _status(s, "AUR-01") == {"PASS"}
    assert _status(s, "AUR-02") == {"PASS"}
    assert _status(s, "AUR-03") == {"PASS"}
    assert s._eol_graph_payloads == []


def test_aur_no_clusters_is_info():
    s = _rds_scanner(clusters=[])
    s._check_rds()
    assert _status(s, "AUR-01") == {"INFO"}


# ── AUR-04/05 cluster snapshots ───────────────────────────────────────────────
def test_aur04_public_cluster_snapshot_fails():
    s = _rds_scanner(
        csnaps=[{"DBClusterSnapshotIdentifier": "snap-pub", "StorageEncrypted": True}],
        snap_attrs={"snap-pub": [{"AttributeName": "restore", "AttributeValues": ["all"]}]})
    s._check_rds()
    assert "FAIL" in _status(s, "AUR-04")


def test_aur04_private_snapshot_passes_aur05_encrypted():
    s = _rds_scanner(
        csnaps=[{"DBClusterSnapshotIdentifier": "snap-priv", "StorageEncrypted": True}],
        snap_attrs={"snap-priv": [{"AttributeName": "restore", "AttributeValues": ["123456789012"]}]})
    s._check_rds()
    assert _status(s, "AUR-04") == {"PASS"}
    assert _status(s, "AUR-05") == {"PASS"}


def test_aur05_unencrypted_cluster_snapshot_fails():
    s = _rds_scanner(
        csnaps=[{"DBClusterSnapshotIdentifier": "snap-plain", "StorageEncrypted": False}],
        snap_attrs={"snap-plain": []})
    s._check_rds()
    assert "FAIL" in _status(s, "AUR-05")


def test_aur04_attr_read_error_warns_not_silent():
    s = _rds_scanner(csnaps=[{"DBClusterSnapshotIdentifier": "snap-x", "StorageEncrypted": True}])
    rds = s._clients["rds:us-east-1"]
    rds.describe_db_cluster_snapshot_attributes.side_effect = RuntimeError("AccessDenied")
    s._check_rds()
    assert "WARN" in _status(s, "AUR-04")   # surfaced, not silently passed


# ── map lockstep ──────────────────────────────────────────────────────────────
def test_new_ids_in_all_three_maps():
    import aws_live_scanner as A
    for cid in ("RDS-12", "AUR-01", "AUR-02", "AUR-03", "AUR-04", "AUR-05"):
        assert cid in A.CHECK_SEVERITY, cid
        assert cid in A.COMPLIANCE_MAP, cid
        assert cid in A.REMEDIATION_MAP, cid
        assert "aws " in A.REMEDIATION_MAP[cid].lower(), cid
