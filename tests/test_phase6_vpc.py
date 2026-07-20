"""Phase 6 Batch B9 — VPC-05 NACL admin-port internet ingress (stateless, RuleNumber
first-match-wins) + VPC-06 active cross-account VPC peering. Offline: MagicMock ec2."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner, MockPaginator


def _vpc_scanner(nacls=None, peerings=None, nacl_error=False):
    s = make_scanner(sections=["VPC"])
    s.account = "111111111111"
    ec2 = MagicMock()
    # VPC-01/03/04 use direct calls; return empties so they don't interfere
    ec2.describe_security_groups.return_value = {"SecurityGroups": []}
    ec2.describe_vpcs.return_value = {"Vpcs": []}
    ec2.describe_flow_logs.return_value = {"FlowLogs": []}

    pag = {
        "describe_network_acls": ("NetworkAcls", nacls or []),
        "describe_vpc_peering_connections": ("VpcPeeringConnections", peerings or []),
    }

    def _get_paginator(name):
        if nacl_error and name == "describe_network_acls":
            raise RuntimeError("AccessDenied")
        return MockPaginator(*pag[name])
    ec2.get_paginator.side_effect = _get_paginator
    s._clients["ec2:us-east-1"] = ec2
    return s


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def _entry(rule_num, action, port=None, cidr="0.0.0.0/0", proto="6", egress=False):
    e = {"RuleNumber": rule_num, "RuleAction": action, "Protocol": proto,
         "CidrBlock": cidr, "Egress": egress}
    if port is not None:
        e["PortRange"] = {"From": port, "To": port}
    return e


# ── VPC-05 NACL ───────────────────────────────────────────────────────────────
def test_vpc05_world_open_rdp_custom_nacl_fails():
    s = _vpc_scanner(nacls=[{"NetworkAclId": "acl-1", "IsDefault": False,
                             "Entries": [_entry(100, "allow", 3389)]}])
    s._check_vpc()
    assert "FAIL" in _status(s, "VPC-05")


def test_vpc05_low_deny_before_allow_all_wins_no_fail():
    # RuleNumber first-match: a deny-all at 90 before an allow-all at 100 protects both ports
    s = _vpc_scanner(nacls=[{"NetworkAclId": "acl-2", "IsDefault": False, "Entries": [
        _entry(100, "allow", None, proto="-1"),
        _entry(90, "deny", None, proto="-1")]}])
    s._check_vpc()
    assert "FAIL" not in _status(s, "VPC-05")


def test_vpc05_default_nacl_allow_all_is_warn_not_fail():
    s = _vpc_scanner(nacls=[{"NetworkAclId": "acl-def", "IsDefault": True,
                             "Entries": [_entry(100, "allow", None, proto="-1")]}])
    s._check_vpc()
    assert "WARN" in _status(s, "VPC-05") and "FAIL" not in _status(s, "VPC-05")


def test_vpc05_scoped_nacl_passes():
    s = _vpc_scanner(nacls=[{"NetworkAclId": "acl-ok", "IsDefault": False,
                             "Entries": [_entry(100, "allow", 443)]}])  # 443, not admin
    s._check_vpc()
    assert "PASS" in _status(s, "VPC-05")


def test_vpc05_read_error_warns_no_pass():
    s = _vpc_scanner(nacl_error=True)
    s._check_vpc()
    assert "WARN" in _status(s, "VPC-05") and "PASS" not in _status(s, "VPC-05")


def test_vpc05_all_ports_protocol_covers_admin():
    # Protocol '-1' (all) with no PortRange must cover 22/3389
    s = _vpc_scanner(nacls=[{"NetworkAclId": "acl-x", "IsDefault": False,
                             "Entries": [_entry(100, "allow", None, proto="-1")]}])
    s._check_vpc()
    assert "FAIL" in _status(s, "VPC-05")


# ── VPC-06 peering ────────────────────────────────────────────────────────────
def test_vpc06_cross_account_active_warns():
    s = _vpc_scanner(peerings=[{"VpcPeeringConnectionId": "pcx-1",
                                "Status": {"Code": "active"},
                                "AccepterVpcInfo": {"OwnerId": "999999999999"},
                                "RequesterVpcInfo": {"OwnerId": "111111111111"}}])
    s._check_vpc()
    assert "WARN" in _status(s, "VPC-06")


def test_vpc06_same_account_passes():
    s = _vpc_scanner(peerings=[{"VpcPeeringConnectionId": "pcx-2",
                                "Status": {"Code": "active"},
                                "AccepterVpcInfo": {"OwnerId": "111111111111"},
                                "RequesterVpcInfo": {"OwnerId": "111111111111"}}])
    s._check_vpc()
    assert "PASS" in _status(s, "VPC-06")


def test_vpc06_pending_ignored():
    s = _vpc_scanner(peerings=[{"VpcPeeringConnectionId": "pcx-3",
                                "Status": {"Code": "pending-acceptance"},
                                "AccepterVpcInfo": {"OwnerId": "999999999999"},
                                "RequesterVpcInfo": {"OwnerId": "111111111111"}}])
    s._check_vpc()
    assert _status(s, "VPC-06") == {"INFO"}   # no active peerings


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("VPC-05", "VPC-06"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()
