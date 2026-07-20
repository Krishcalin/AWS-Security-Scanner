"""Phase 5 Batch B3 — ElastiCache engine EOL (ELC-05, via describe_cache_clusters) +
Redis/Valkey RBAC (ELC-06, UserGroupIds on replication groups). Offline: MagicMock."""
import os
import sys
from datetime import date
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner, MockPaginator


def _ec_scanner(rgs=None, cache_clusters=(), rg_error=False, cc_error=False):
    s = make_scanner(sections=["ELASTICACHE"])
    s._today = date(2026, 7, 20)
    ec = MagicMock()
    if rg_error:
        ec.describe_replication_groups.side_effect = RuntimeError("AccessDenied")
    else:
        ec.describe_replication_groups.return_value = {"ReplicationGroups": list(rgs or [])}
    if cc_error:
        ec.get_paginator.side_effect = RuntimeError("AccessDenied")
    else:
        ec.get_paginator.side_effect = lambda name: MockPaginator("CacheClusters", list(cache_clusters))
    s._clients["elasticache:us-east-1"] = ec
    return s


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


# ── ELC-05 engine EOL ─────────────────────────────────────────────────────────
def test_elc05_redis5_eol_dedup_one_edge():
    # two nodes of the same replication group -> ONE finding + ONE edge
    s = _ec_scanner(cache_clusters=[
        {"CacheClusterId": "rg-0001-001", "ReplicationGroupId": "rg", "ARN": "arn:...:rg-0001-001",
         "Engine": "redis", "EngineVersion": "5.0.6"},
        {"CacheClusterId": "rg-0001-002", "ReplicationGroupId": "rg", "ARN": "arn:...:rg-0001-002",
         "Engine": "redis", "EngineVersion": "5.0.6"}])
    s._check_elasticache()
    fails = [r for r in s.results if r.check_id == "ELC-05" and r.status == "FAIL"]
    assert len(fails) == 1
    edges = [p for p in s._eol_graph_payloads if p[1] == "ElastiCacheCluster"]
    assert len(edges) == 1 and edges[0][3]["replication_group_id"] == "rg"


def test_elc05_memcached_covered_even_without_replication_group():
    s = _ec_scanner(rgs=[], cache_clusters=[
        {"CacheClusterId": "mc", "ARN": "arn:...:mc", "Engine": "memcached", "EngineVersion": "1.5.16"}])
    s._check_elasticache()
    assert "FAIL" in _status(s, "ELC-05")   # ELC-05 ran despite zero replication groups


def test_elc05_supported_passes():
    s = _ec_scanner(cache_clusters=[
        {"CacheClusterId": "r7", "ReplicationGroupId": "r7g", "ARN": "arn:...:r7",
         "Engine": "redis", "EngineVersion": "7.1"}])
    s._check_elasticache()
    assert _status(s, "ELC-05") == {"PASS"}
    assert s._eol_graph_payloads == []


def test_elc05_describe_error_warns_not_pass():
    s = _ec_scanner(cc_error=True)
    s._check_elasticache()
    assert "WARN" in _status(s, "ELC-05") and "PASS" not in _status(s, "ELC-05")


def test_elc05_no_clusters_info():
    s = _ec_scanner(cache_clusters=[])
    s._check_elasticache()
    assert _status(s, "ELC-05") == {"INFO"}


# ── ELC-06 RBAC ───────────────────────────────────────────────────────────────
def test_elc06_no_user_group_fails():
    s = _ec_scanner(rgs=[{"ReplicationGroupId": "norbac", "Engine": "redis"}])
    s._check_elasticache()
    assert "FAIL" in _status(s, "ELC-06")


def test_elc06_with_user_group_passes():
    s = _ec_scanner(rgs=[{"ReplicationGroupId": "rbac", "Engine": "redis",
                          "UserGroupIds": ["ug-1"]}])
    s._check_elasticache()
    assert _status(s, "ELC-06") == {"PASS"}


def test_elc06_default_engine_treated_as_redis():
    # replication groups with no explicit Engine are Redis -> RBAC still evaluated
    s = _ec_scanner(rgs=[{"ReplicationGroupId": "noeng"}])
    s._check_elasticache()
    assert "FAIL" in _status(s, "ELC-06")


def test_elc01_still_works_and_no_early_return_regression():
    # empty replication groups: ELC-01 INFO but ELC-05 must STILL run (no early return)
    s = _ec_scanner(rgs=[], cache_clusters=[
        {"CacheClusterId": "x", "ARN": "arn:...:x", "Engine": "redis", "EngineVersion": "7.1"}])
    s._check_elasticache()
    assert "INFO" in _status(s, "ELC-01")
    assert "PASS" in _status(s, "ELC-05")


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("ELC-05", "ELC-06"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()
