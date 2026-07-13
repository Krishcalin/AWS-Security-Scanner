#!/usr/bin/env python3
"""FP/FN catalog for the pure internet-reachability core (aws_exposure.py).

Every scenario from the Phase 2 research spec's false-positive/false-negative
catalog is reproduced here against boto3-shaped inputs — no AWS, no boto3. These
are the tests that make the "SG allows 0.0.0.0/0 but NACL/route/no-public-IP
blocks it" false positive impossible to reintroduce.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_exposure import (
    classify_public_ip, is_public_cidr, sg_public_ports,
    find_effective_route_table, has_igw_default_route,
    find_governing_nacl, nacl_allowed_subranges, nacl_range_fully_allowed,
    nacl_permits_service, compute_exposure, iter_exposed_ports, SENSITIVE_PORTS,
)


# ─── builders (exact boto3 response shapes) ──────────────────────────────────
def eni(ipv4="auto", ipv6=False, sg=("sg-1",), subnet="subnet-1", vpc="vpc-1",
        itype="interface"):
    return {"eni_id": "eni-1", "subnet_id": subnet, "vpc_id": vpc,
            "interface_type": itype, "ipv4_public": ipv4, "ipv6_public": ipv6,
            "security_group_ids": list(sg)}


def rt(routes, subnet="subnet-1", vpc="vpc-1", main=False):
    assoc = {"AssociationState": {"State": "associated"}}
    if main:
        assoc["Main"] = True
    else:
        assoc["SubnetId"] = subnet
    return {"VpcId": vpc, "Associations": [assoc], "Routes": routes}


IGW_V4 = [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1", "State": "active"}]
IGW_V6 = [{"DestinationIpv6CidrBlock": "::/0", "GatewayId": "igw-1", "State": "active"}]
NAT_V4 = [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1", "State": "active"}]


def perm(proto="tcp", frm=None, to=None, cidr="0.0.0.0/0", cidr6=None, sgref=None, pl=None):
    p = {"IpProtocol": proto, "IpRanges": [], "Ipv6Ranges": [],
         "UserIdGroupPairs": [], "PrefixListIds": []}
    if frm is not None:
        p["FromPort"] = frm
    if to is not None:
        p["ToPort"] = to
    if cidr:
        p["IpRanges"] = [{"CidrIp": cidr}]
    if cidr6:
        p["Ipv6Ranges"] = [{"CidrIpv6": cidr6}]
    if sgref:
        p["UserIdGroupPairs"] = [{"GroupId": sgref}]
    if pl:
        p["PrefixListIds"] = [{"PrefixListId": pl}]
    return p


_PROTO_NUM = {"tcp": "6", "udp": "17", "icmp": "1", "-1": "-1", "6": "6", "17": "17"}


def entry(num, egress, action, proto="-1", frm=None, to=None, v6=False):
    # describe_network_acls returns Protocol as an IANA number STRING, not a name
    e = {"RuleNumber": num, "Egress": egress, "RuleAction": action,
         "Protocol": _PROTO_NUM.get(proto, proto)}
    e["Ipv6CidrBlock" if v6 else "CidrBlock"] = "::/0" if v6 else "0.0.0.0/0"
    if frm is not None:
        e["PortRange"] = {"From": frm, "To": to if to is not None else frm}
    return e


def nacl(entries, is_default=False, subnet="subnet-1", vpc="vpc-1"):
    return {"NetworkAclId": "acl-1", "IsDefault": is_default, "VpcId": vpc,
            "Associations": [{"SubnetId": subnet}], "Entries": entries}


def default_nacl():
    # mirrors a real AWS default NACL: allow-all for BOTH families, in and out
    return nacl([
        entry(100, False, "allow"), entry(101, False, "allow", v6=True),
        entry(32767, False, "deny"),
        entry(100, True, "allow"),  entry(101, True, "allow", v6=True),
        entry(32767, True, "deny"),
    ], is_default=True)


def edited_default_nacl_deny(port):
    # an admin-edited default NACL that DENIES a port inbound (IsDefault stays True)
    return nacl([
        entry(90, False, "deny", "tcp", port),
        entry(100, False, "allow"), entry(101, False, "allow", v6=True),
        entry(32767, False, "deny"),
        entry(100, True, "allow"),  entry(101, True, "allow", v6=True),
    ], is_default=True)


def custom_nacl(inbound, outbound):
    return nacl(inbound + outbound, is_default=False)


# outbound that allows the full ephemeral return window
EPH_OUT = [entry(100, True, "allow", "tcp", 1024, 65535),
           entry(105, True, "allow", "udp", 1024, 65535),
           entry(32767, True, "deny")]


def exposed(eni_d, route_table, nacl_d, perms):
    return compute_exposure(eni_d, route_table, nacl_d, perms)


# ─── the 14-case FP/FN catalog ───────────────────────────────────────────────
class TestExposureCatalog(unittest.TestCase):

    def test_01_sg_ref_only_not_exposed(self):
        # ingress allows all, but sourced ONLY from an sg-reference → not public
        p = perm(proto="-1", cidr=None, sgref="sg-abc")
        self.assertEqual(exposed(eni(), rt(IGW_V4), default_nacl(), [p]), {})

    def test_02_permissive_sg_but_deny_nacl_not_exposed(self):
        n = custom_nacl([entry(100, False, "deny", "tcp", 443)], EPH_OUT)
        self.assertEqual(exposed(eni(), rt(IGW_V4), n, [perm("tcp", 443, 443)]), {})

    def test_03_no_public_ip_not_exposed(self):
        self.assertEqual(
            exposed(eni(ipv4=None, ipv6=False), rt(IGW_V4), default_nacl(),
                    [perm("tcp", 443, 443)]), {})

    def test_04_inbound_ok_outbound_blocks_ephemeral_not_exposed(self):
        # inbound allows 443, but outbound has no ephemeral allow (only deny)
        n = custom_nacl([entry(100, False, "allow", "tcp", 443)],
                        [entry(32767, True, "deny")])
        self.assertEqual(exposed(eni(), rt(IGW_V4), n, [perm("tcp", 443, 443)]), {})

    def test_07_ipv6_exposure_with_private_ipv4(self):
        # global IPv6, no public IPv4; ::/0 route + ::/0 SG on 22
        e = eni(ipv4=None, ipv6=True)
        p = perm("tcp", 22, 22, cidr=None, cidr6="::/0")
        res = exposed(e, rt(IGW_V6), default_nacl(), [p])
        self.assertIn("ipv6", res)
        self.assertNotIn("ipv4", res)
        self.assertIn(("tcp", 22, 22), res["ipv6"])

    def test_08_proto_all_opens_all_ports(self):
        p = perm(proto="-1")   # FromPort/ToPort absent
        res = exposed(eni(), rt(IGW_V4), default_nacl(), [p])
        self.assertIn(("tcp", 0, 65535), res["ipv4"])
        self.assertIn(("udp", 0, 65535), res["ipv4"])

    def test_09_default_route_to_nat_not_exposed(self):
        self.assertEqual(exposed(eni(), rt(NAT_V4), default_nacl(),
                                 [perm("tcp", 443, 443)]), {})

    def test_10_no_explicit_rt_association_uses_main_table(self):
        main = rt(IGW_V4, main=True)                     # VPC main table has IGW
        other = rt([], subnet="subnet-999")              # unrelated explicit table
        eff = find_effective_route_table("subnet-1", "vpc-1", [other, main])
        self.assertIs(eff, main)
        self.assertTrue(has_igw_default_route(eff, "ipv4"))

    def test_11_idle_eip_no_public_ip_not_exposed(self):
        # ENI itself has no public IP (idle EIP is unassociated) → gate 1 fails
        self.assertEqual(exposed(eni(ipv4=None), rt(IGW_V4), default_nacl(),
                                 [perm("tcp", 443, 443)]), {})

    def test_12_full_path_default_nacl_exposed(self):
        res = exposed(eni(), rt(IGW_V4), default_nacl(), [perm("tcp", 443, 443)])
        self.assertEqual(res["ipv4"], {("tcp", 443, 443)})

    def test_14_wide_tcp_range_all_ports(self):
        res = exposed(eni(), rt(IGW_V4), default_nacl(), [perm("tcp", 0, 65535)])
        self.assertEqual(res["ipv4"], {("tcp", 0, 65535)})


# ─── deeper unit tests on the tricky pieces ──────────────────────────────────
class TestNaclEvaluation(unittest.TestCase):

    def test_low_deny_shadows_high_allow(self):
        n = custom_nacl(
            [entry(100, False, "deny", "tcp", 443),
             entry(200, False, "allow", "tcp", 443)], EPH_OUT)
        self.assertEqual(nacl_allowed_subranges(n, False, "tcp", "ipv4", 443, 443), [])

    def test_low_allow_wins_over_high_deny(self):
        n = custom_nacl(
            [entry(100, False, "allow", "tcp", 443),
             entry(200, False, "deny", "tcp", 443)], EPH_OUT)
        self.assertEqual(nacl_allowed_subranges(n, False, "tcp", "ipv4", 443, 443),
                         [(443, 443)])

    def test_nacl_intersects_wide_sg_range(self):
        # SG opens all TCP, but NACL inbound only allows 443 → only 443 reachable
        n = custom_nacl([entry(100, False, "allow", "tcp", 443)], EPH_OUT)
        res = compute_exposure(eni(), rt(IGW_V4), n, [perm("tcp", 0, 65535)])
        self.assertEqual(res["ipv4"], {("tcp", 443, 443)})

    def test_ephemeral_partial_deny_blocks_return(self):
        # outbound allows only 1024-40000, so full 1024-65535 return not guaranteed
        out = [entry(100, True, "allow", "tcp", 1024, 40000), entry(32767, True, "deny")]
        n = custom_nacl([entry(100, False, "allow", "tcp", 443)], out)
        self.assertFalse(nacl_range_fully_allowed(n, True, "tcp", "ipv4", 1024, 65535))
        self.assertEqual(nacl_permits_service(n, "tcp", "ipv4", 443, 443), [])

    def test_default_nacl_none_allows_all(self):
        self.assertEqual(nacl_allowed_subranges(None, False, "tcp", "ipv4", 22, 22),
                         [(22, 22)])

    def test_edited_default_nacl_deny_is_enforced(self):
        # regression: an admin-edited default NACL (IsDefault=True) with a DENY
        # must NOT be blanket-treated as allow-all (adversarial-verify false positive)
        n = edited_default_nacl_deny(443)
        self.assertEqual(nacl_allowed_subranges(n, False, "tcp", "ipv4", 443, 443), [])
        self.assertEqual(
            compute_exposure(eni(), rt(IGW_V4), n, [perm("tcp", 443, 443)]), {})
        # a different port on the same edited default NACL is still allowed
        self.assertEqual(nacl_allowed_subranges(n, False, "tcp", "ipv4", 22, 22), [(22, 22)])

    def test_ipv6_entries_dont_match_ipv4_flow(self):
        n = custom_nacl([entry(100, False, "allow", "tcp", 443, v6=True)], EPH_OUT)
        # v4 flow sees no matching v4 entry → implicit deny
        self.assertEqual(nacl_allowed_subranges(n, False, "tcp", "ipv4", 443, 443), [])


class TestSgPublicPorts(unittest.TestCase):

    def test_ignores_prefix_list_and_sgref(self):
        self.assertEqual(sg_public_ports([perm(proto="-1", cidr=None, pl="pl-1")], "ipv4"), set())
        self.assertEqual(sg_public_ports([perm(proto="-1", cidr=None, sgref="sg-x")], "ipv4"), set())

    def test_private_cidr_not_public(self):
        self.assertEqual(sg_public_ports([perm("tcp", 22, 22, cidr="10.0.0.0/8")], "ipv4"), set())

    def test_gre_proto_opens_no_service_port(self):
        self.assertEqual(sg_public_ports([perm(proto="47", cidr="0.0.0.0/0")], "ipv4"), set())

    def test_union_across_rules(self):
        got = sg_public_ports([perm("tcp", 22, 22), perm("tcp", 443, 443)], "ipv4")
        self.assertEqual(got, {("tcp", 22, 22), ("tcp", 443, 443)})


class TestRouteAndIp(unittest.TestCase):

    def test_blackhole_igw_route_rejected(self):
        r = rt([{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1", "State": "blackhole"}])
        self.assertFalse(has_igw_default_route(r, "ipv4"))

    def test_egress_only_igw_rejected(self):
        r = rt([{"DestinationIpv6CidrBlock": "::/0", "EgressOnlyInternetGatewayId": "eigw-1", "State": "active"}])
        self.assertFalse(has_igw_default_route(r, "ipv6"))

    def test_classify_eip_vs_auto(self):
        self.assertEqual(classify_public_ip({"PublicIp": "1.2.3.4", "AllocationId": "eipalloc-1"}, [])["ipv4"], "eip")
        self.assertEqual(classify_public_ip({"PublicIp": "1.2.3.4", "IpOwnerId": "amazon"}, [])["ipv4"], "auto")
        self.assertIsNone(classify_public_ip(None, [])["ipv4"])
        self.assertTrue(classify_public_ip(None, ["2600:1f18::1"])["ipv6"])

    def test_is_public_cidr(self):
        self.assertTrue(is_public_cidr("0.0.0.0/0", "ipv4"))
        self.assertTrue(is_public_cidr("::/0", "ipv6"))
        self.assertFalse(is_public_cidr("0.0.0.0/1", "ipv4"))


class TestSensitivePorts(unittest.TestCase):

    def test_summary_and_sensitive_hits(self):
        summary, hits = iter_exposed_ports({("tcp", 22, 22), ("tcp", 443, 443)})
        self.assertIn("tcp/22", summary)
        names = {n for _, _, n in hits}
        self.assertIn("SSH", names)

    def test_wide_range_flags_contained_sensitive(self):
        _, hits = iter_exposed_ports({("tcp", 0, 65535)})
        ports = {p for _, p, _ in hits}
        self.assertIn(3389, ports)   # RDP inside the wide range


# ─── collector integration (mocked EC2) + first attack path ──────────────────
from unittest.mock import MagicMock, patch
from aws_live_scanner import AWSLiveScanner

ACCT = "123456789012"


class _Pager:
    def __init__(self, key, items):
        self.key, self.items = key, items

    def paginate(self, **kw):
        return [{self.key: self.items}]


def _mock_ec2(enis, rtbs, nacls, sgs, reservations):
    m = MagicMock()
    table = {
        "describe_network_interfaces": ("NetworkInterfaces", enis),
        "describe_route_tables": ("RouteTables", rtbs),
        "describe_network_acls": ("NetworkAcls", nacls),
        "describe_security_groups": ("SecurityGroups", sgs),
        "describe_instances": ("Reservations", reservations),
    }
    m.get_paginator.side_effect = lambda name: _Pager(*table[name])
    return m


def _sg(gid, perms):
    return {"GroupId": gid, "IpPermissions": perms}


def _eni(nid, iid, gid, itype="interface", public=True, ipv6=False):
    assoc = {"PublicIp": "52.0.0.1", "IpOwnerId": "amazon"} if public else None
    return {"NetworkInterfaceId": nid, "SubnetId": "subnet-1", "VpcId": "vpc-1",
            "InterfaceType": itype, "Association": assoc,
            "Ipv6Addresses": [{"Ipv6Address": "2600::1"}] if ipv6 else [],
            "Groups": [{"GroupId": gid}],
            "Attachment": {"InstanceId": iid} if iid else {}}


RTBS = [rt(IGW_V4)]
NACLS = [{"NetworkAclId": "acl-1", "IsDefault": True, "VpcId": "vpc-1",
          "Associations": [{"SubnetId": "subnet-1"}], "Entries": []}]


def _role(name, actions, profiles, condition=None):
    return {"type": "role", "name": name, "arn": f"arn:aws:iam::{ACCT}:role/{name}",
            "statements": [{"effect": "Allow", "actions": set(actions),
                            "resources": {"*"}, "condition": condition}],
            "allow": set(actions), "deny": set(), "trust": [],
            "instance_profiles": profiles, "path": "/"}


class TestExposureCollector(unittest.TestCase):

    def _run(self, enis, sgs, reservations, principals):
        with patch("aws_live_scanner.HAS_BOTO3", True):
            sc = AWSLiveScanner(sections=["EXPOSURE"])
        sc.account = ACCT
        sc._client = lambda service, region=None: _mock_ec2(enis, RTBS, NACLS, sgs, reservations)
        sc._iam_principals = principals
        with patch("builtins.print"):
            sc._check_exposure()
        return sc

    def test_exposed_instance_and_attack_path(self):
        enis = [_eni("eni-1", "i-1", "sg-open")]
        sgs = [_sg("sg-open", [perm("tcp", 22, 22)])]
        res = [{"Instances": [{"InstanceId": "i-1", "VpcId": "vpc-1",
                "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCT}:instance-profile/app"}}]}]
        principals = [_role("app-role", {"iam:attachrolepolicy"},
                            [f"arn:aws:iam::{ACCT}:instance-profile/app"])]
        sc = self._run(enis, sgs, res, principals)
        ids = {r.check_id for r in sc.results if r.status == "FAIL"}
        self.assertIn("EXPOSURE-01", ids)     # SSH is sensitive
        self.assertIn("ATTACK-01", ids)       # exposed -> role -> admin
        attack = [r for r in sc.results if r.check_id == "ATTACK-01"][0]
        self.assertEqual(attack.severity, "CRITICAL")
        self.assertIn("app-role", attack.message)
        # graph chain complete
        ek = sc.graph.stats()["edge_kinds"]
        for e in ("EXPOSED_TO", "ATTACHED_TO", "HAS_INSTANCE_PROFILE", "HAS_ROLE", "CAN_PRIVESC_TO"):
            self.assertIn(e, ek)

    def test_sg_ref_only_instance_not_exposed(self):
        enis = [_eni("eni-2", "i-2", "sg-ref")]
        sgs = [_sg("sg-ref", [perm(proto="-1", cidr=None, sgref="sg-open")])]
        res = [{"Instances": [{"InstanceId": "i-2", "VpcId": "vpc-1",
                "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCT}:instance-profile/x"}}]}]
        sc = self._run(enis, sgs, res, [_role("x-role", {"*"}, [f"arn:aws:iam::{ACCT}:instance-profile/x"])])
        self.assertFalse([r for r in sc.results if r.status == "FAIL"])

    def test_conditioned_admin_attack_path_is_warn_not_critical(self):
        # regression (adversarial-verify FP): admin reachable ONLY via a
        # Condition-guarded privesc must be WARN, not a confirmed CRITICAL path
        enis = [_eni("eni-c", "i-c", "sg-open")]
        sgs = [_sg("sg-open", [perm("tcp", 22, 22)])]
        res = [{"Instances": [{"InstanceId": "i-c", "VpcId": "vpc-1",
                "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCT}:instance-profile/c"}}]}]
        principals = [_role("cond-role", {"*"}, [f"arn:aws:iam::{ACCT}:instance-profile/c"],
                            condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})]
        sc = self._run(enis, sgs, res, principals)
        attacks = [r for r in sc.results if r.check_id == "ATTACK-01"]
        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0].status, "WARN")           # NOT FAIL/CRITICAL
        self.assertIn("conditioned", attacks[0].message.lower())

    def test_unconditioned_admin_attack_path_is_critical(self):
        enis = [_eni("eni-u", "i-u", "sg-open")]
        sgs = [_sg("sg-open", [perm("tcp", 22, 22)])]
        res = [{"Instances": [{"InstanceId": "i-u", "VpcId": "vpc-1",
                "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCT}:instance-profile/u"}}]}]
        principals = [_role("admin-role", {"*"}, [f"arn:aws:iam::{ACCT}:instance-profile/u"])]
        sc = self._run(enis, sgs, res, principals)
        attacks = [r for r in sc.results if r.check_id == "ATTACK-01"]
        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0].status, "FAIL")
        self.assertEqual(attacks[0].severity, "CRITICAL")

    def test_exposed_but_readonly_role_no_attack_path(self):
        enis = [_eni("eni-3", "i-3", "sg-open")]
        sgs = [_sg("sg-open", [perm("tcp", 8080, 8080)])]   # non-sensitive port
        res = [{"Instances": [{"InstanceId": "i-3", "VpcId": "vpc-1",
                "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCT}:instance-profile/ro"}}]}]
        principals = [_role("ro-role", {"s3:getobject"}, [f"arn:aws:iam::{ACCT}:instance-profile/ro"])]
        sc = self._run(enis, sgs, res, principals)
        ids = {r.check_id for r in sc.results}
        self.assertIn("EXPOSURE-02", ids)          # exposed (non-sensitive)
        self.assertNotIn("ATTACK-01", ids)         # role can't escalate

    def test_managed_lb_eni_skipped(self):
        enis = [_eni("eni-lb", "", "sg-open", itype="load_balancer")]
        sgs = [_sg("sg-open", [perm("tcp", 443, 443)])]
        sc = self._run(enis, sgs, [{"Instances": []}], [])
        self.assertFalse([r for r in sc.results if r.status == "FAIL"])

    def test_no_enis_reports_info(self):
        sc = self._run([], [], [{"Instances": []}], [])
        self.assertTrue([r for r in sc.results if r.status == "INFO"])


if __name__ == "__main__":
    unittest.main()
