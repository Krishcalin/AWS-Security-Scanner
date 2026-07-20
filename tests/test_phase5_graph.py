"""Phase 5 Batch B6 — clobber-safe deferred graph replay of managed-engine-EOL HAS_VULN
edges. The service sections STASH payloads; _check_vuln replays them AFTER IAMPRIVESC has
hard-replaced the graph, so they land and survive. Offline: injected SecurityGraph."""
import os
import sys
from datetime import date
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_graph import SecurityGraph
from test_live_scanner import make_scanner, MockPaginator


def _scanner_with_graph():
    s = make_scanner(sections=["RDS", "VULN"])
    s._today = date(2026, 7, 20)
    s.graph = SecurityGraph()
    return s


def _stash_eol_rds(s):
    """Run _check_rds with one EOL RDS instance -> stashes a payload."""
    rds = MagicMock()
    pag = {
        "describe_db_instances": MockPaginator("DBInstances", [
            {"DBInstanceIdentifier": "legacy", "DBInstanceArn": "arn:aws:rds:us-east-1:1:db:legacy",
             "Engine": "mysql", "EngineVersion": "5.7.44"}]),
        "describe_db_clusters": MockPaginator("DBClusters", []),
        "describe_db_cluster_snapshots": MockPaginator("DBClusterSnapshots", []),
        "describe_db_snapshots": MockPaginator("DBSnapshots", []),
    }
    rds.get_paginator.side_effect = lambda n: pag[n]
    rds.describe_db_snapshot_attributes.return_value = {
        "DBSnapshotAttributesResult": {"DBSnapshotAttributes": []}}
    s._clients["rds:us-east-1"] = rds
    s._check_rds()


def _has_vuln_edges(g):
    return [e for e in g.edges("HAS_VULN")]


def test_replay_emits_has_vuln_edge_with_managed_eol_label():
    s = _scanner_with_graph()
    _stash_eol_rds(s)
    assert len(s._eol_graph_payloads) == 1          # stashed, not yet emitted
    assert _has_vuln_edges(s.graph) == []           # nothing in the graph yet
    s._replay_eol_edges()
    edges = _has_vuln_edges(s.graph)
    assert len(edges) == 1
    e = edges[0]
    assert e["dst"] == "EOL-mysql-5.7"
    assert e["props"]["scan_source"] == "managed-eol"     # label sharpened
    assert e["props"]["fixed_version"] == "8.0"           # full edge shape preserved
    assert s.graph.node("arn:aws:rds:us-east-1:1:db:legacy")["kind"] == "RDSInstance"
    assert s.graph.node("EOL-mysql-5.7")["kind"] == "Vulnerability"


def test_replay_survives_identity_graph_clobber():
    # THE regression: IAMPRIVESC does self.graph = SecurityGraph() (a hard replace). Stashed
    # payloads must be replayed AFTER that, into the new graph.
    s = _scanner_with_graph()
    _stash_eol_rds(s)
    # simulate IAMPRIVESC rebuilding/replacing the graph
    s._build_identity_graph([])
    assert _has_vuln_edges(s.graph) == []           # clobbered graph has no EOL edge
    assert len(s._eol_graph_payloads) == 1          # payload preserved across the clobber
    # replay (as _check_vuln does) lands in the post-clobber graph
    s._replay_eol_edges()
    assert len(_has_vuln_edges(s.graph)) == 1


def test_check_vuln_replays_even_when_inspector_disabled():
    # _check_vuln returns early when Inspector is disabled — the replay must run BEFORE that.
    s = _scanner_with_graph()
    _stash_eol_rds(s)
    insp = MagicMock()
    insp.batch_get_account_status.return_value = {
        "accounts": [{"resourceState": {"ec2": {"status": "DISABLED"},
                                        "ecr": {"status": "DISABLED"},
                                        "lambda": {"status": "DISABLED"}}}]}
    s._clients["inspector2:us-east-1"] = insp
    s._check_vuln()
    assert len(_has_vuln_edges(s.graph)) == 1       # EOL edge emitted despite Inspector off


def test_replay_idempotent():
    s = _scanner_with_graph()
    _stash_eol_rds(s)
    s._replay_eol_edges()
    s._replay_eol_edges()                            # second call must not duplicate
    assert len(_has_vuln_edges(s.graph)) == 1


def test_no_payloads_no_op():
    s = _scanner_with_graph()
    s._replay_eol_edges()
    assert _has_vuln_edges(s.graph) == []
