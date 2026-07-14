#!/usr/bin/env python3
"""FP/FN catalog for the pure deep-plane core (aws_deepplane.py).

Covers the traps from the Phase 3 research spec against boto3-shaped inputs — no
AWS, no boto3. In particular the CAN_READ_DATA object-probe (List-vs-Get, Deny
precedence), the Macie score-semantics traps, KEV≠exploitAvailable, and the
GuardDuty SAMPLE/archived/ResourceType handling.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_deepplane import (
    parse_inspector_finding, finding_kev, is_exploitable, vuln_finding_id,
    is_crown_jewel, role_can_read_bucket, map_guardduty_finding, severity_band,
    classify_external_access, EPSS_HIGH,
)


def stmt(effect, actions, resources, condition=None, not_resources=None):
    a = {actions} if isinstance(actions, str) else set(actions)
    r = {resources} if isinstance(resources, str) else set(resources)
    nr = ({not_resources} if isinstance(not_resources, str)
          else set(not_resources or []))
    return {"effect": effect, "actions": {x.lower() for x in a},
            "resources": {x.lower() for x in r},
            "not_resources": {x.lower() for x in nr}, "condition": condition}


# ─── Inspector2 parsing + KEV/exploit ────────────────────────────────────────
class TestInspectorParsing(unittest.TestCase):

    def _finding(self, **kw):
        base = {
            "findingArn": "arn:aws:inspector2:us-east-1:1:finding/abc",
            "severity": "CRITICAL",
            "exploitAvailable": "YES",
            "fixAvailable": "YES",
            "epss": {"score": 0.94},
            "packageVulnerabilityDetails": {
                "vulnerabilityId": "cve-2021-44228",
                "cvss": [{"baseScore": 10.0}],
                "vulnerablePackages": [{"name": "log4j", "fixedInVersion": "2.17.0"}],
            },
            "resources": [{"id": "i-0abc", "type": "AWS_EC2_INSTANCE"}],
        }
        base.update(kw)
        return base

    def test_parse_basic(self):
        v = parse_inspector_finding(self._finding())
        self.assertEqual(v["cve"], "CVE-2021-44228")        # upper-cased
        self.assertEqual(v["epss"], 0.94)
        self.assertEqual(v["exploit_available"], "YES")
        self.assertEqual(v["fixed_in"], "2.17.0")
        self.assertEqual(v["resource_id"], "i-0abc")
        self.assertEqual(v["resource_type"], "AWS_EC2_INSTANCE")

    def test_no_cve_returns_none(self):
        f = self._finding()
        f["packageVulnerabilityDetails"] = {}
        self.assertIsNone(parse_inspector_finding(f))

    def test_missing_epss_is_none_not_zero(self):
        f = self._finding()
        del f["epss"]
        self.assertIsNone(parse_inspector_finding(f)["epss"])

    def test_kev_only_from_finding_details(self):
        self.assertTrue(finding_kev({"cisaData": {"dateAdded": "2021-12-10"}}))
        self.assertFalse(finding_kev({"cisaData": {}}))
        self.assertFalse(finding_kev(None))

    def test_is_exploitable(self):
        self.assertTrue(is_exploitable({"kev": True}))
        self.assertTrue(is_exploitable({"exploit_available": "YES"}))
        self.assertTrue(is_exploitable({"epss": EPSS_HIGH}))
        self.assertFalse(is_exploitable({"exploit_available": "NO", "epss": 0.01}))
        self.assertFalse(is_exploitable({}))

    def test_vuln_finding_id_kev_is_critical(self):
        self.assertEqual(vuln_finding_id({"kev": True}), "VULN-02")
        self.assertEqual(vuln_finding_id({"kev": False, "exploit_available": "YES"}), "VULN-01")


# ─── Macie crown-jewel score traps ───────────────────────────────────────────
class TestCrownJewel(unittest.TestCase):

    def _bucket(self, score, cnt=100, **kw):
        b = {"sensitivityScore": score, "classifiableObjectCount": cnt}
        b.update(kw)
        return b

    def test_real_high_score_is_crown_jewel(self):
        cj = is_crown_jewel(self._bucket(78))
        self.assertTrue(cj["crown_jewel"])
        self.assertEqual(cj["sensitivity"], 78)

    def test_default_50_is_not_crown_jewel(self):
        self.assertIsNone(is_crown_jewel(self._bucket(50)))

    def test_error_score_minus1_and_empty_1_not_crown_jewel(self):
        self.assertIsNone(is_crown_jewel(self._bucket(-1)))
        self.assertIsNone(is_crown_jewel(self._bucket(1)))

    def test_zero_classifiable_objects_not_crown_jewel(self):
        self.assertIsNone(is_crown_jewel(self._bucket(90, cnt=0)))

    def test_sensitive_finding_overrides_score(self):
        cj = is_crown_jewel(self._bucket(50, cnt=0), has_sensitive_finding=True)
        self.assertTrue(cj["crown_jewel"])

    def test_props_public_shared_encrypted(self):
        b = self._bucket(80, publicAccess={"effectivePermission": "PUBLIC"},
                         sharedAccess="EXTERNAL",
                         serverSideEncryption={"type": "NONE"})
        cj = is_crown_jewel(b)
        self.assertTrue(cj["public"])
        self.assertTrue(cj["shared"])
        self.assertFalse(cj["encrypted"])


# ─── CAN_READ_DATA object-probe (the correctness crux) ───────────────────────
class TestCanReadData(unittest.TestCase):
    BARN = "arn:aws:s3:::crown-data"

    def test_getobject_on_object_namespace_grants(self):
        s = [stmt("Allow", "s3:GetObject", "arn:aws:s3:::crown-data/*")]
        self.assertEqual(role_can_read_bucket(s, self.BARN), {"conditioned": False})

    def test_listbucket_on_bare_bucket_arn_is_not_data_read(self):
        # the List-vs-Get trap: s3:ListBucket scoped to the bucket ARN must NOT grant read
        s = [stmt("Allow", "s3:ListBucket", "arn:aws:s3:::crown-data")]
        self.assertIsNone(role_can_read_bucket(s, self.BARN))

    def test_getobject_on_bare_bucket_arn_does_not_match_objects(self):
        # GetObject with the wrong resource (bucket ARN, not bucket/*) → no grant
        s = [stmt("Allow", "s3:GetObject", "arn:aws:s3:::crown-data")]
        self.assertIsNone(role_can_read_bucket(s, self.BARN))

    def test_s3_star_and_star_resource_grant(self):
        self.assertIsNotNone(role_can_read_bucket([stmt("Allow", "s3:*", "*")], self.BARN))
        self.assertIsNotNone(role_can_read_bucket([stmt("Allow", "*", "*")], self.BARN))

    def test_deny_precedence(self):
        s = [stmt("Allow", "s3:GetObject", "arn:aws:s3:::crown-data/*"),
             stmt("Deny", "s3:GetObject", "arn:aws:s3:::crown-data/*")]
        self.assertIsNone(role_can_read_bucket(s, self.BARN))

    def test_conditioned_grant_flagged(self):
        s = [stmt("Allow", "s3:GetObject", "arn:aws:s3:::crown-data/*",
                  condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})]
        self.assertEqual(role_can_read_bucket(s, self.BARN), {"conditioned": True})

    def test_unrelated_bucket_no_grant(self):
        s = [stmt("Allow", "s3:GetObject", "arn:aws:s3:::other-bucket/*")]
        self.assertIsNone(role_can_read_bucket(s, self.BARN))

    def test_notresource_excluding_crown_jewel_is_not_a_grant(self):
        # regression (adversarial FP): "allow all objects EXCEPT crown-data" must NOT
        # produce a CAN_READ_DATA edge to crown-data
        s = [stmt("Allow", "s3:GetObject", "*", not_resources="arn:aws:s3:::crown-data/*")]
        self.assertIsNone(role_can_read_bucket(s, self.BARN))

    def test_notresource_excluding_other_bucket_still_grants(self):
        s = [stmt("Allow", "s3:GetObject", "*", not_resources="arn:aws:s3:::other/*")]
        self.assertIsNotNone(role_can_read_bucket(s, self.BARN))

    def test_empty_resource_grants_nothing(self):
        # a malformed empty Resource set must not read as "all objects"
        s = [stmt("Allow", "s3:GetObject", [])]
        self.assertIsNone(role_can_read_bucket(s, self.BARN))

    def test_case_insensitive_match(self):
        s = [stmt("Allow", "s3:GetObject", "ARN:AWS:S3:::Crown-Data/*")]
        self.assertIsNotNone(role_can_read_bucket(s, "ARN:AWS:S3:::Crown-Data"))


# ─── GuardDuty mapping ───────────────────────────────────────────────────────
class TestGuardDutyMapping(unittest.TestCase):

    def _f(self, rtype, **res):
        return {"Id": "gd1", "Type": "UnauthorizedAccess:EC2/x", "Severity": 8.0,
                "Title": "t", "Service": {"Archived": False},
                "Resource": {"ResourceType": rtype, **res}}

    def test_instance_mapping(self):
        m = map_guardduty_finding(self._f("Instance", InstanceDetails={"InstanceId": "i-9"}))
        self.assertEqual((m["node_kind"], m["node_key"]), ("EC2Instance", "i-9"))
        self.assertEqual(m["band"], "High")

    def test_s3_mapping(self):
        m = map_guardduty_finding(self._f("S3Bucket", S3BucketDetails=[{"Name": "b1"}]))
        self.assertEqual((m["node_kind"], m["node_key"]), ("S3Bucket", "b1"))

    def test_accesskey_mapping(self):
        m = map_guardduty_finding(self._f("AccessKey", AccessKeyDetails={"UserName": "alice"}))
        self.assertEqual((m["node_kind"], m["node_key"]), ("IAMPrincipal", "alice"))

    def test_archived_filtered(self):
        f = self._f("Instance", InstanceDetails={"InstanceId": "i-9"})
        f["Service"]["Archived"] = True
        self.assertIsNone(map_guardduty_finding(f))

    def test_sample_filtered(self):
        f = self._f("Instance", InstanceDetails={"InstanceId": "i-9"})
        f["Title"] = "[SAMPLE] test finding"
        self.assertIsNone(map_guardduty_finding(f))

    def test_unmappable_type_keeps_context_no_edge(self):
        m = map_guardduty_finding(self._f("Unknown"))
        self.assertIsNone(m["node_kind"])       # kept as context, no THREAT_ON

    def test_severity_bands(self):
        self.assertEqual(severity_band(9.5), "Critical")
        self.assertEqual(severity_band(7.0), "High")
        self.assertEqual(severity_band(4.0), "Medium")
        self.assertEqual(severity_band(2.0), "Low")


# ─── Access Analyzer external access ─────────────────────────────────────────
class TestExternalAccess(unittest.TestCase):

    def test_public_via_isPublic(self):
        d = {"externalAccessDetails": {"isPublic": True, "action": ["s3:GetObject"]}}
        self.assertTrue(classify_external_access(d)["is_public"])

    def test_public_via_principal_star(self):
        d = {"externalAccessDetails": {"isPublic": False, "principal": {"AWS": "*"}}}
        self.assertTrue(classify_external_access(d)["is_public"])

    def test_cross_account_not_public(self):
        d = {"externalAccessDetails": {"isPublic": False,
             "principal": {"AWS": "arn:aws:iam::999:root"}, "action": ["s3:GetObject"]}}
        r = classify_external_access(d)
        self.assertFalse(r["is_public"])
        self.assertEqual(r["principal"], {"AWS": "arn:aws:iam::999:root"})

    def test_no_external_details(self):
        self.assertIsNone(classify_external_access({"unusedAccessDetails": {}}))


# ─── collector integration (mocked services) + flagship ATTACK-02 ────────────
from unittest.mock import MagicMock, patch
from aws_live_scanner import AWSLiveScanner
from aws_graph import SecurityGraph

ACCT = "123456789012"


class _P:
    def __init__(self, key, items):
        self.key, self.items = key, items

    def paginate(self, **kw):
        return [{self.key: self.items}]


def _scanner(clients):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        sc = AWSLiveScanner(region="us-east-1", sections=["VULN"])
    sc.account = ACCT
    sc._client = lambda service, region=None: clients.get(service, MagicMock())
    sc._iam_principals = []
    return sc


def _role(name, actions, profiles, condition=None):
    return {"type": "role", "name": name, "arn": f"arn:aws:iam::{ACCT}:role/{name}",
            "statements": [{"effect": "Allow", "actions": set(actions),
                            "resources": {"*"}, "condition": condition}],
            "allow": set(actions), "deny": set(), "trust": [],
            "instance_profiles": profiles, "path": "/"}


class TestVulnCollector(unittest.TestCase):

    def _inspector(self, ec2="ENABLED", findings=None, kev=False):
        m = MagicMock()
        m.batch_get_account_status.return_value = {
            "accounts": [{"resourceState": {"ec2": {"status": ec2}, "ecr": {"status": "DISABLED"}}}]}
        m.get_paginator.return_value = _P("findings", findings or [])
        m.batch_get_finding_details.return_value = {
            "findingDetails": [{"findingArn": (findings or [{}])[0].get("findingArn"),
                                "cisaData": {"dateAdded": "2021-12-10"} if kev else {}}]}
        return m

    def test_inspector_disabled_is_info_noop(self):
        sc = _scanner({"inspector2": self._inspector(ec2="DISABLED")})
        with patch("builtins.print"):
            sc._check_vuln()
        self.assertFalse([r for r in sc.results if r.status == "FAIL"])
        self.assertTrue([r for r in sc.results if r.status == "INFO"])

    def test_kev_finding_fires_vuln02_and_edge(self):
        f = {"findingArn": "arn:finding/1", "severity": "CRITICAL",
             "exploitAvailable": "YES", "fixAvailable": "YES", "epss": {"score": 0.9},
             "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2021-44228"},
             "resources": [{"id": "i-0abc", "type": "AWS_EC2_INSTANCE"}]}
        sc = _scanner({"inspector2": self._inspector(findings=[f], kev=True)})
        with patch("builtins.print"):
            sc._check_vuln()
        ids = {r.check_id for r in sc.results if r.status == "FAIL"}
        self.assertIn("VULN-02", ids)
        self.assertIn("HAS_VULN", sc.graph.stats()["edge_kinds"])


class TestThreatCollector(unittest.TestCase):

    def test_guardduty_disabled_is_info_noop(self):
        gd = MagicMock()
        gd.list_detectors.return_value = {"DetectorIds": []}
        sc = _scanner({"guardduty": gd})
        with patch("builtins.print"):
            sc._check_threat()
        self.assertFalse([r for r in sc.results if r.status == "FAIL"])
        self.assertTrue([r for r in sc.results if r.status == "INFO"])


class TestDataCollector(unittest.TestCase):

    def test_macie_disabled_returns_empty_crown_noop(self):
        mac = MagicMock()
        mac.get_macie_session.return_value = {"status": "PAUSED"}
        sc = _scanner({"macie2": mac})
        with patch("builtins.print"):
            crown = sc._collect_macie(sc._ensure_graph())
        self.assertEqual(crown, set())
        self.assertTrue([r for r in sc.results if r.status == "INFO"])

    def test_macie_crown_jewel_fires_data01(self):
        mac = MagicMock()
        mac.get_macie_session.return_value = {"status": "ENABLED"}
        mac.get_paginator.return_value = _P("buckets", [
            {"bucketName": "crown-data", "sensitivityScore": 85, "classifiableObjectCount": 100,
             "publicAccess": {"effectivePermission": "NOT_PUBLIC"},
             "serverSideEncryption": {"type": "aws:kms"}}])
        sc = _scanner({"macie2": mac})
        with patch("builtins.print"):
            crown = sc._collect_macie(sc._ensure_graph())
        self.assertIn("arn:aws:s3:::crown-data", crown)
        self.assertIn("DATA-01", {r.check_id for r in sc.results if r.status == "FAIL"})


class TestFlagshipAttackPath(unittest.TestCase):
    """ATTACK-02: Internet -> exposed EC2 -> exploitable CVE -> role -> crown-jewel data."""

    def _wire(self, sc, kev=True, read_condition=None,
              exploit_available="YES", epss=None):
        g = sc._ensure_graph()
        internet, eni = "internet", "eni-1"
        inst = sc._instance_arn("i-1")
        prof = f"arn:aws:iam::{ACCT}:instance-profile/app"
        role = f"arn:aws:iam::{ACCT}:role/app-role"
        bucket = "arn:aws:s3:::crown-data"
        g.add_node(internet, "InternetSource")
        g.add_node(eni, "NetworkInterface")
        g.add_node(inst, "EC2Instance", instance_id="i-1")
        g.add_edge(internet, eni, "EXPOSED_TO", family="ipv4", ports="tcp/22")
        g.add_edge(eni, inst, "ATTACHED_TO")
        g.add_node(prof, "InstanceProfile")
        g.add_edge(inst, prof, "HAS_INSTANCE_PROFILE")
        g.add_node(role, "IAMRole", name="app-role")
        g.add_edge(prof, role, "HAS_ROLE")
        g.add_node("CVE-2021-44228", "Vulnerability", kev=kev)
        g.add_edge(inst, "CVE-2021-44228", "HAS_VULN", cve="CVE-2021-44228",
                   kev=kev, exploit_available=exploit_available, epss=epss)
        g.add_node(bucket, "S3Bucket", name="crown-data", crown_jewel=True)
        g.add_edge(role, bucket, "CAN_READ_DATA", conditioned=bool(read_condition))
        return g

    def test_full_flagship_fires_critical(self):
        sc = _scanner({})
        self._wire(sc, kev=True)
        with patch("builtins.print"):
            sc._correlate_flagship(sc.graph)
        atk = [r for r in sc.results if r.check_id == "ATTACK-02"]
        self.assertEqual(len(atk), 1)
        self.assertEqual(atk[0].status, "FAIL")
        self.assertEqual(atk[0].severity, "CRITICAL")
        self.assertIn("crown-data", atk[0].message)
        self.assertIn("CVE-2021-44228", atk[0].message)

    def test_high_epss_pivot_fires(self):
        # regression (adversarial FN): high EPSS alone (not KEV, exploit_available NO)
        # must satisfy the pivot — consistent with is_exploitable / VULN-01 labeling
        sc = _scanner({})
        self._wire(sc, kev=False, exploit_available="NO", epss=0.94)
        with patch("builtins.print"):
            sc._correlate_flagship(sc.graph)
        atk = [r for r in sc.results if r.check_id == "ATTACK-02"]
        self.assertEqual(len(atk), 1)
        self.assertEqual(atk[0].status, "FAIL")

    def test_non_exploitable_vuln_no_flagship(self):
        sc = _scanner({})
        self._wire(sc, kev=False, exploit_available="NO", epss=0.02)
        with patch("builtins.print"):
            sc._correlate_flagship(sc.graph)
        self.assertFalse([r for r in sc.results if r.check_id == "ATTACK-02"])

    def test_conditioned_data_grant_is_warn(self):
        sc = _scanner({})
        self._wire(sc, kev=True, read_condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})
        with patch("builtins.print"):
            sc._correlate_flagship(sc.graph)
        atk = [r for r in sc.results if r.check_id == "ATTACK-02"]
        self.assertEqual(len(atk), 1)
        self.assertEqual(atk[0].status, "WARN")

    def test_no_vuln_pivot_no_flagship(self):
        sc = _scanner({})
        g = self._wire(sc, kev=True)
        # remove the HAS_VULN edge's exploitability by rebuilding without it
        sc2 = _scanner({})
        g2 = sc2._ensure_graph()
        # wire everything EXCEPT a vuln edge
        internet, eni = "internet", "eni-2"
        inst = sc2._instance_arn("i-2")
        prof = f"arn:aws:iam::{ACCT}:instance-profile/p2"
        role = f"arn:aws:iam::{ACCT}:role/r2"
        bucket = "arn:aws:s3:::crown-data"
        g2.add_node(internet, "InternetSource")
        g2.add_edge(internet, eni, "EXPOSED_TO")
        g2.add_edge(eni, inst, "ATTACHED_TO")
        g2.add_node(inst, "EC2Instance", instance_id="i-2")
        g2.add_edge(inst, prof, "HAS_INSTANCE_PROFILE")
        g2.add_edge(prof, role, "HAS_ROLE")
        g2.add_node(bucket, "S3Bucket", crown_jewel=True)
        g2.add_edge(role, bucket, "CAN_READ_DATA", conditioned=False)
        with patch("builtins.print"):
            sc2._correlate_flagship(g2)
        self.assertFalse([r for r in sc2.results if r.check_id == "ATTACK-02"])


if __name__ == "__main__":
    unittest.main()
