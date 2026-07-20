"""Phase 6 Batch B6 — EKS-06 worker-nodegroup SSH exposed to the internet. Own try/except
so a denied call or a bare mock cannot break EKS-01..05. Offline: MagicMock eks."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner


def _cluster():
    return {"resourcesVpcConfig": {"endpointPublicAccess": False, "securityGroupIds": ["sg-1"]},
            "logging": {"clusterLogging": [{"enabled": True,
                        "types": ["api", "audit", "authenticator", "controllerManager", "scheduler"]}]},
            "encryptionConfig": [{"resources": ["secrets"]}], "version": "1.29"}


def _eks_scanner(nodegroups=None, ng_details=None, list_error=False, describe_error=None):
    s = make_scanner(sections=["EKS"])
    eks = MagicMock()
    eks.list_clusters.return_value = {"clusters": ["prod"]}
    eks.describe_cluster.return_value = {"cluster": _cluster()}
    if list_error:
        eks.list_nodegroups.side_effect = RuntimeError("AccessDenied")
    else:
        eks.list_nodegroups.return_value = {"nodegroups": nodegroups if nodegroups is not None else []}

    def _dng(clusterName, nodegroupName):
        if describe_error and nodegroupName in describe_error:
            raise RuntimeError("AccessDenied")
        return {"nodegroup": (ng_details or {}).get(nodegroupName, {})}
    eks.describe_nodegroup.side_effect = _dng
    s._clients["eks:us-east-1"] = eks
    return s


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def test_eks06_world_open_ssh_fails():
    s = _eks_scanner(nodegroups=["ng1"],
                     ng_details={"ng1": {"remoteAccess": {"ec2SshKey": "mykey"}}})
    s._check_eks()
    assert "FAIL" in _status(s, "EKS-06")


def test_eks06_scoped_ssh_info_not_fail():
    s = _eks_scanner(nodegroups=["ng1"],
                     ng_details={"ng1": {"remoteAccess": {"ec2SshKey": "mykey",
                                 "sourceSecurityGroups": ["sg-bastion"]}}})
    s._check_eks()
    assert "FAIL" not in _status(s, "EKS-06")
    assert "PASS" in _status(s, "EKS-06")   # no world-open, all read


def test_eks06_no_remote_access_passes():
    s = _eks_scanner(nodegroups=["ng1"], ng_details={"ng1": {}})  # managed nodegroup, no SSH
    s._check_eks()
    assert "PASS" in _status(s, "EKS-06")


def test_eks06_fargate_only_is_info():
    s = _eks_scanner(nodegroups=[])
    s._check_eks()
    assert _status(s, "EKS-06") == {"INFO"}


def test_eks06_list_denied_warns_no_pass_no_break():
    s = _eks_scanner(list_error=True)
    s._check_eks()
    assert "WARN" in _status(s, "EKS-06") and "PASS" not in _status(s, "EKS-06")
    # EKS-01..05 must still have run despite EKS-06's error
    assert any(r.check_id == "EKS-02" for r in s.results)


def test_eks06_describe_error_blocks_aggregate_pass():
    s = _eks_scanner(nodegroups=["ng1", "ng2"],
                     ng_details={"ng2": {}}, describe_error={"ng1"})
    s._check_eks()
    assert "WARN" in _status(s, "EKS-06") and "PASS" not in _status(s, "EKS-06")


def test_eks06_bare_mock_does_not_crash_eks_1_to_5():
    # generic MagicMock: list_nodegroups().get returns a non-list mock -> treated as empty
    s = make_scanner(sections=["EKS"])
    eks = MagicMock()
    eks.list_clusters.return_value = {"clusters": ["prod"]}
    eks.describe_cluster.return_value = {"cluster": _cluster()}
    s._clients["eks:us-east-1"] = eks
    s._check_eks()   # must not raise
    assert any(r.check_id == "EKS-02" for r in s.results)


def test_maps_lockstep():
    import aws_live_scanner as A
    assert "EKS-06" in A.CHECK_SEVERITY and "EKS-06" in A.COMPLIANCE_MAP
    assert "EKS-06" in A.REMEDIATION_MAP and "aws " in A.REMEDIATION_MAP["EKS-06"].lower()
