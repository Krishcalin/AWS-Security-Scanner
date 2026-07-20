"""Phase 5 Batch B5 — Redshift provisioned require_ssl (RS-06) + version-upgrade (RS-07)
+ Redshift Serverless (RSS-01 public, RSS-02 CMK gap, RSS-03 require_ssl, RSS-04 enhanced
VPC). Offline: MagicMock redshift + redshift-serverless clients."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner


def _rs_scanner(clusters=(), params=None, cluster_error=False,
                workgroups=None, namespaces=None, no_serverless=False,
                wg_error=False, ns_error=False):
    s = make_scanner(sections=["REDSHIFT"])
    rs = MagicMock()
    if cluster_error:
        rs.describe_clusters.side_effect = RuntimeError("AccessDenied")
    else:
        rs.describe_clusters.return_value = {"Clusters": list(clusters)}
    rs.describe_logging_status.return_value = {"LoggingEnabled": True}
    rs.describe_cluster_parameters.return_value = {"Parameters": params or []}
    s._clients["redshift:us-east-1"] = rs

    if not no_serverless:
        rss = MagicMock()
        if wg_error:
            rss.list_workgroups.side_effect = RuntimeError("EndpointConnectionError")
        else:
            rss.list_workgroups.return_value = {"workgroups": list(workgroups or [])}
        if ns_error:
            rss.list_namespaces.side_effect = RuntimeError("EndpointConnectionError")
        else:
            rss.list_namespaces.return_value = {"namespaces": list(namespaces or [])}
        s._clients["redshift-serverless:us-east-1"] = rss
    return s


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def _cluster(cid="c1", pg="default.redshift-1.0", allow_upgrade=True):
    return {"ClusterIdentifier": cid, "Encrypted": True, "PubliclyAccessible": False,
            "EnhancedVpcRouting": True, "MasterUsername": "admin",
            "AllowVersionUpgrade": allow_upgrade,
            "ClusterParameterGroups": [{"ParameterGroupName": pg}]}


# ── RS-06 require_ssl ─────────────────────────────────────────────────────────
def test_rs06_require_ssl_false_fails():
    s = _rs_scanner(clusters=[_cluster()],
                    params=[{"ParameterName": "require_ssl", "ParameterValue": "false"}])
    s._check_redshift()
    assert "FAIL" in _status(s, "RS-06")


def test_rs06_require_ssl_true_passes():
    s = _rs_scanner(clusters=[_cluster()],
                    params=[{"ParameterName": "require_ssl", "ParameterValue": "true"}])
    s._check_redshift()
    assert _status(s, "RS-06") == {"PASS"}


def test_rs06_param_read_error_warns_not_pass():
    s = _rs_scanner(clusters=[_cluster()])
    s._clients["redshift:us-east-1"].describe_cluster_parameters.side_effect = RuntimeError("denied")
    s._check_redshift()
    assert "WARN" in _status(s, "RS-06") and "PASS" not in _status(s, "RS-06")


def test_rs06_param_group_cached_across_clusters():
    s = _rs_scanner(clusters=[_cluster("a"), _cluster("b")],   # same param group
                    params=[{"ParameterName": "require_ssl", "ParameterValue": "true"}])
    s._check_redshift()
    # describe_cluster_parameters called once despite two clusters sharing the PG
    assert s._clients["redshift:us-east-1"].describe_cluster_parameters.call_count == 1


# ── RS-07 version upgrade ─────────────────────────────────────────────────────
def test_rs07_pinned_warns():
    s = _rs_scanner(clusters=[_cluster(allow_upgrade=False)],
                    params=[{"ParameterName": "require_ssl", "ParameterValue": "true"}])
    s._check_redshift()
    assert "WARN" in _status(s, "RS-07")


def test_rs07_default_on_passes():
    s = _rs_scanner(clusters=[_cluster(allow_upgrade=True)],
                    params=[{"ParameterName": "require_ssl", "ParameterValue": "true"}])
    s._check_redshift()
    assert _status(s, "RS-07") == {"PASS"}


# ── RSS Serverless ────────────────────────────────────────────────────────────
def test_rss01_public_workgroup_fails():
    s = _rs_scanner(workgroups=[{"workgroupName": "wg", "publiclyAccessible": True,
                                 "enhancedVpcRouting": True,
                                 "configParameters": [{"parameterKey": "require_ssl",
                                                       "parameterValue": "true"}]}])
    s._check_redshift()
    assert "FAIL" in _status(s, "RSS-01")


def test_rss03_require_ssl_false_fails_rss04_no_vpc_warns():
    s = _rs_scanner(workgroups=[{"workgroupName": "wg", "publiclyAccessible": False,
                                 "enhancedVpcRouting": False,
                                 "configParameters": [{"parameterKey": "require_ssl",
                                                       "parameterValue": "false"}]}])
    s._check_redshift()
    assert "FAIL" in _status(s, "RSS-03")
    assert "WARN" in _status(s, "RSS-04")


def test_rss02_aws_owned_key_warns_cmk_present_passes():
    s = _rs_scanner(namespaces=[{"namespaceName": "ns1", "kmsKeyId": "AWS_OWNED_KMS_KEY"},
                                {"namespaceName": "ns2", "kmsKeyId": "arn:aws:kms:...:key/abc"}])
    s._check_redshift()
    assert "WARN" in _status(s, "RSS-02")
    assert "PASS" in _status(s, "RSS-02")


def test_rss_runs_even_with_no_provisioned_clusters():
    # no clusters at all: RS-01 INFO, but Serverless RSS-01 must still run
    s = _rs_scanner(clusters=[], workgroups=[{"workgroupName": "wg", "publiclyAccessible": False,
                                              "enhancedVpcRouting": True,
                                              "configParameters": []}])
    s._check_redshift()
    assert "INFO" in _status(s, "RS-01")
    assert "PASS" in _status(s, "RSS-01")


def test_rss_region_unsupported_warns_not_crash():
    s = _rs_scanner(wg_error=True, ns_error=True)
    s._check_redshift()   # must not raise
    assert "WARN" in _status(s, "RSS-01")


def test_rss01_empty_workgroups_info():
    s = _rs_scanner(workgroups=[])
    s._check_redshift()
    assert _status(s, "RSS-01") == {"INFO"}


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("RS-06", "RS-07", "RSS-01", "RSS-02", "RSS-03", "RSS-04"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()
