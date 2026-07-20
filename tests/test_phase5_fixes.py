"""Regressions for the Phase 5 adversarial-verify findings:
1 (major) AUR-04 emitted a false 'no public snapshots' PASS when the per-snapshot
  describe_db_cluster_snapshot_attributes read was denied/throttled (public_c stayed 0).
2 (minor) managed-EOL HAS_VULN edges were dropped when a graph-building scan omitted VULN.
3 (hardening) managed_engine_cve returned [] (=> PASS) for a wholesale-legacy engine whose
  version string would not parse, disagreeing with evaluable()==True."""
import os
import sys
from datetime import date
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_engine_eol as eol
from aws_graph import SecurityGraph
from test_live_scanner import make_scanner, MockPaginator


# ── Fix 1: AUR-04 no false PASS on a denied attribute read ────────────────────
def _rds_with_csnaps(csnaps, attr_side_effect):
    s = make_scanner(sections=["RDS"])
    s._today = date(2026, 7, 20)
    rds = MagicMock()
    pag = {
        "describe_db_instances": MockPaginator("DBInstances", []),
        "describe_db_clusters": MockPaginator("DBClusters", []),
        "describe_db_cluster_snapshots": MockPaginator("DBClusterSnapshots", list(csnaps)),
        "describe_db_snapshots": MockPaginator("DBSnapshots", []),
    }
    rds.get_paginator.side_effect = lambda n: pag[n]
    rds.describe_db_snapshot_attributes.return_value = {
        "DBSnapshotAttributesResult": {"DBSnapshotAttributes": []}}
    rds.describe_db_cluster_snapshot_attributes.side_effect = attr_side_effect
    s._clients["rds:us-east-1"] = rds
    return s


def _aur04(s):
    return {r.status for r in s.results if r.check_id == "AUR-04"}


def test_aur04_no_false_pass_when_attribute_read_denied():
    # a genuinely-public snapshot whose attribute read is DENIED must NOT yield an all-clear
    def _attrs(DBClusterSnapshotIdentifier):
        raise RuntimeError("AccessDenied: rds:DescribeDBClusterSnapshotAttributes")
    s = _rds_with_csnaps(
        [{"DBClusterSnapshotIdentifier": "csnap-secretly-public", "StorageEncrypted": True}],
        _attrs)
    s._check_rds()
    assert "PASS" not in _aur04(s)          # the false all-clear is gone
    assert "WARN" in _aur04(s)              # undetermined visibility surfaced


def test_aur04_partial_denied_no_pass():
    # one read succeeds (private), one denied -> still no aggregate PASS
    def _attrs(DBClusterSnapshotIdentifier):
        if DBClusterSnapshotIdentifier == "ok":
            return {"DBClusterSnapshotAttributesResult":
                    {"DBClusterSnapshotAttributes":
                     [{"AttributeName": "restore", "AttributeValues": ["123456789012"]}]}}
        raise RuntimeError("RequestLimitExceeded")
    s = _rds_with_csnaps(
        [{"DBClusterSnapshotIdentifier": "ok", "StorageEncrypted": True},
         {"DBClusterSnapshotIdentifier": "denied", "StorageEncrypted": True}], _attrs)
    s._check_rds()
    assert "PASS" not in _aur04(s)
    warn_msgs = [r.message for r in s.results if r.check_id == "AUR-04" and r.status == "WARN"
                 and r.resource == "cluster-snapshots"]
    assert warn_msgs and "UNDETERMINED" in warn_msgs[0]


def test_aur04_all_reads_succeed_still_passes():
    # regression guard: the happy path (all reads succeed, none public) still PASSes
    def _attrs(DBClusterSnapshotIdentifier):
        return {"DBClusterSnapshotAttributesResult":
                {"DBClusterSnapshotAttributes":
                 [{"AttributeName": "restore", "AttributeValues": ["123456789012"]}]}}
    s = _rds_with_csnaps(
        [{"DBClusterSnapshotIdentifier": "a", "StorageEncrypted": True},
         {"DBClusterSnapshotIdentifier": "b", "StorageEncrypted": True}], _attrs)
    s._check_rds()
    assert _aur04(s) == {"PASS"}
    msg = [r.message for r in s.results if r.check_id == "AUR-04" and r.status == "PASS"][0]
    assert "2 manual checked" in msg        # count reflects successfully-read snapshots


# ── Fix 2: EOL edges flushed by the run() epilogue even without a VULN section ─
def test_eol_edges_flushed_without_vuln_section():
    s = make_scanner(sections=["RDS"])   # NO VULN section
    s._today = date(2026, 7, 20)
    rds = MagicMock()
    pag = {
        "describe_db_instances": MockPaginator("DBInstances", [
            {"DBInstanceIdentifier": "legacy", "DBInstanceArn": "arn:...:db:legacy",
             "Engine": "mysql", "EngineVersion": "5.7.44"}]),
        "describe_db_clusters": MockPaginator("DBClusters", []),
        "describe_db_cluster_snapshots": MockPaginator("DBClusterSnapshots", []),
        "describe_db_snapshots": MockPaginator("DBSnapshots", []),
    }
    rds.get_paginator.side_effect = lambda n: pag[n]
    rds.describe_db_snapshot_attributes.return_value = {
        "DBSnapshotAttributesResult": {"DBSnapshotAttributes": []}}
    s._clients["rds:us-east-1"] = rds
    s.graph = SecurityGraph()            # a graph exists (built elsewhere) but VULN won't run
    s._check_rds()
    assert len(s._eol_graph_payloads) == 1 and s.graph.edges("HAS_VULN") == []  # stashed only
    # run()'s epilogue must flush it (simulate the post-loop epilogue directly)
    if s.graph is not None and s._eol_graph_payloads:
        s._replay_eol_edges()
    assert len(s.graph.edges("HAS_VULN")) == 1


def test_epilogue_flush_is_in_run_source():
    # guard that the epilogue flush actually exists in run() (not only exercised via helper)
    import inspect, aws_live_scanner
    src = inspect.getsource(aws_live_scanner.AWSLiveScanner.run)
    assert "_replay_eol_edges" in src and "_eol_graph_payloads" in src


# ── Fix 3: wholesale-legacy engine flags even with an unparseable version ──────
def test_elasticsearch_unparseable_version_still_eol():
    # evaluable() is True for elasticsearch; managed_engine_cve must agree (not return [])
    assert eol.evaluable("opensearch", "elasticsearch", "Elasticsearch") is True
    m = eol.managed_engine_cve("opensearch", "elasticsearch", "Elasticsearch",
                               today=date(2026, 7, 20))
    assert len(m) == 1 and m[0].cve == "EOL-elasticsearch-0"


def test_elasticsearch_normal_version_unchanged():
    m = eol.managed_engine_cve("opensearch", "elasticsearch", "7.10", today=date(2026, 7, 20))
    assert len(m) == 1 and m[0].cve == "EOL-elasticsearch-7.10"
