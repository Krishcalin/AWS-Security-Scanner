#!/usr/bin/env python3
"""Unit tests for the Phase 0/1 CNAPP work on aws_live_scanner.py:

  * aws_graph.SecurityGraph — nodes/edges MERGE, bounded cycle-safe traversal,
    node-link serialization, union merge.
  * parse_trust_policy — wildcard / AWS-list / service / condition / url-encoded.
  * Identity graph — CAN_ASSUME + CAN_PRIVESC_TO edges, transitive chains
    (IAMPE-21), dangerous wildcard trust (IAMPE-22), condition-downgraded paths.
  * compliance_scorecard — per-framework control pass/fail rollup.
  * Multi-account — assume_role_session, list_org_accounts, aggregate_results.
  * Region iterator — global vs regional sections under --all-regions.
  * GetAccountAuthorizationDetails principal collection.

No AWS credentials or boto3 required (boto3 is patched where a real call would occur).
"""
import os
import sys
import json
import unittest
import urllib.parse
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_graph import SecurityGraph
from aws_live_scanner import (
    AWSLiveScanner, Result, VERSION,
    parse_trust_policy, compliance_scorecard, COMPLIANCE_FRAMEWORKS,
    COMPLIANCE_MAP, CHECK_SEVERITY,
    assume_role_session, list_org_accounts, aggregate_results,
)

ACCT = "123456789012"


def make_scanner(sections=None, account=ACCT):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        sc = AWSLiveScanner(region="us-east-1", sections=sections or ["IAMPRIVESC"])
    sc.account = account
    return sc


def stmt(effect, actions, resources="*", condition=None):
    acts = {actions} if isinstance(actions, str) else set(actions)
    res = {resources} if isinstance(resources, str) else set(resources)
    return {"effect": effect, "actions": {a.lower() for a in acts},
            "resources": {r.lower() for r in res}, "condition": condition}


def principal(ptype, name, statements, trust=None, arn=None):
    p = {"type": ptype, "name": name,
         "arn": arn or f"arn:aws:iam::{ACCT}:{'user' if ptype=='user' else 'role'}/{name}",
         "statements": statements, "allow": set(), "deny": set()}
    for s in statements:
        (p["allow"] if s["effect"] == "Allow" else p["deny"]).update(s["actions"])
    if ptype == "role":
        p["trust"] = trust or []
        p["instance_profiles"] = []
        p["path"] = "/"
    else:
        p["groups"] = []
    return p


# ─── SecurityGraph ───────────────────────────────────────────────────────────
class TestSecurityGraph(unittest.TestCase):

    def test_add_node_merges_props_and_upgrades_kind(self):
        g = SecurityGraph()
        g.add_node("n1", "Unknown", a=1)
        g.add_node("n1", "IAMRole", b=2)          # upgrade kind, merge prop
        n = g.node("n1")
        self.assertEqual(n["kind"], "IAMRole")
        self.assertEqual(n["props"], {"a": 1, "b": 2})

    def test_add_edge_dedupes(self):
        g = SecurityGraph()
        self.assertTrue(g.add_edge("a", "b", "CAN_ASSUME"))
        self.assertFalse(g.add_edge("a", "b", "CAN_ASSUME"))   # dupe merges
        self.assertEqual(len(g.edges("CAN_ASSUME")), 1)

    def test_reachable_is_bounded_and_cycle_safe(self):
        g = SecurityGraph()
        for a, b in [("A", "B"), ("B", "C"), ("C", "D"), ("D", "A")]:  # cycle
            g.add_edge(a, b, "CAN_ASSUME")
        r = g.reachable("A", {"CAN_ASSUME"}, max_hops=2)
        self.assertEqual(set(r), {"B", "C"})       # D is 3 hops, excluded
        self.assertEqual(r["C"], ["A", "B", "C"])
        # unbounded still terminates on the cycle
        self.assertEqual(set(g.reachable("A", {"CAN_ASSUME"}, max_hops=10)),
                         {"B", "C", "D"})

    def test_reachable_filters_edge_kind(self):
        g = SecurityGraph()
        g.add_edge("A", "B", "CAN_ASSUME")
        g.add_edge("B", "X", "OTHER")
        self.assertEqual(set(g.reachable("A", {"CAN_ASSUME"}, 5)), {"B"})

    def test_to_dict_roundtrips(self):
        g = SecurityGraph()
        g.add_node("r", "IAMRole", name="r")
        g.add_edge("r", "cap", "CAN_PRIVESC_TO", rules=["IAMPE-19"])
        d = g.to_dict()
        self.assertTrue(d["directed"])
        self.assertEqual({n["id"] for n in d["nodes"]}, {"r", "cap"})
        edge = [e for e in d["edges"] if e["kind"] == "CAN_PRIVESC_TO"][0]
        self.assertEqual(edge["source"], "r")
        self.assertEqual(edge["target"], "cap")
        # JSON-serializable
        json.loads(json.dumps(d))

    def test_merge_unions_two_graphs(self):
        g1 = SecurityGraph(); g1.add_edge("a", "b", "CAN_ASSUME")
        g2 = SecurityGraph(); g2.add_edge("b", "c", "CAN_ASSUME")
        g1.merge(g2)
        self.assertEqual(set(g1.reachable("a", {"CAN_ASSUME"}, 5)), {"b", "c"})

    def test_stats(self):
        g = SecurityGraph()
        g.add_node("u", "IAMUser"); g.add_node("r", "IAMRole")
        g.add_edge("u", "r", "CAN_ASSUME")
        s = g.stats()
        self.assertEqual(s["nodes"], 2)
        self.assertEqual(s["edges"], 1)
        self.assertEqual(s["edge_kinds"]["CAN_ASSUME"], 1)


# ─── Trust-policy parsing ────────────────────────────────────────────────────
class TestTrustParsing(unittest.TestCase):

    def test_wildcard_principal(self):
        t = parse_trust_policy({"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]})
        self.assertTrue(t[0]["wildcard"])

    def test_wildcard_via_aws_star(self):
        t = parse_trust_policy({"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]})
        self.assertTrue(t[0]["wildcard"])
        self.assertEqual(t[0]["aws"], [])

    def test_aws_list_and_service_and_condition(self):
        t = parse_trust_policy({"Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": ["arn:aws:iam::111:root", "arn:aws:iam::222:role/x"],
                          "Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "abc"}}}]})
        self.assertEqual(len(t[0]["aws"]), 2)
        self.assertEqual(t[0]["service"], ["ec2.amazonaws.com"])
        self.assertTrue(t[0]["has_condition"])
        self.assertFalse(t[0]["wildcard"])

    def test_url_encoded_document(self):
        raw = json.dumps({"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111:root"},
             "Action": "sts:AssumeRole"}]})
        t = parse_trust_policy(urllib.parse.quote(raw))
        self.assertEqual(t[0]["aws"], ["arn:aws:iam::111:root"])

    def test_empty_or_garbage(self):
        self.assertEqual(parse_trust_policy(None), [])
        self.assertEqual(parse_trust_policy("not-json"), [])


# ─── Identity graph + graph-derived findings ─────────────────────────────────
class TestIdentityGraph(unittest.TestCase):

    def _run(self, principals):
        sc = make_scanner(["IAMPRIVESC"])
        sc._iam_principals = principals
        with patch.object(sc, "_section_header"), patch.object(sc, "_log"), \
             patch("builtins.print"):
            sc._check_iam_privesc()
        return sc

    def _ids(self, sc, status=None):
        return [r.check_id for r in sc.results
                if status is None or r.status == status]

    def test_privesc_and_assume_edges_built(self):
        esc_trust = parse_trust_policy({"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:user/alice"},
            "Action": "sts:AssumeRole"}]})
        principals = [
            principal("user", "alice", [stmt("Allow", "s3:GetObject")]),
            principal("role", "escalator",
                      [stmt("Allow", "iam:AttachRolePolicy")], trust=esc_trust),
        ]
        sc = self._run(principals)
        st = sc.graph.stats()
        self.assertEqual(st["edge_kinds"].get("CAN_ASSUME"), 1)
        self.assertEqual(st["edge_kinds"].get("CAN_PRIVESC_TO"), 1)

    def test_transitive_chain_detected(self):
        esc_trust = parse_trust_policy({"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:user/alice"},
            "Action": "sts:AssumeRole"}]})
        principals = [
            principal("user", "alice", [stmt("Allow", "s3:GetObject")]),
            principal("role", "escalator",
                      [stmt("Allow", "iam:AttachRolePolicy")], trust=esc_trust),
        ]
        sc = self._run(principals)
        chains = [r for r in sc.results if r.check_id == "IAMPE-21"]
        self.assertEqual(len(chains), 1)
        self.assertIn("alice", chains[0].resource)
        self.assertEqual(chains[0].severity, "HIGH")

    def test_no_chain_when_target_cannot_escalate(self):
        # role is only readonly → no CAN_PRIVESC_TO → no chain even though assumable
        trust = parse_trust_policy({"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:user/alice"},
            "Action": "sts:AssumeRole"}]})
        principals = [
            principal("user", "alice", [stmt("Allow", "s3:GetObject")]),
            principal("role", "readonly-role", [stmt("Allow", "s3:GetObject")], trust=trust),
        ]
        sc = self._run(principals)
        self.assertNotIn("IAMPE-21", self._ids(sc))

    def test_wildcard_trust_no_condition_fails(self):
        trust = parse_trust_policy({"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]})
        sc = self._run([principal("role", "public", [stmt("Allow", "s3:GetObject")], trust=trust)])
        fails = [r for r in sc.results if r.check_id == "IAMPE-22" and r.status == "FAIL"]
        self.assertEqual(len(fails), 1)
        self.assertEqual(fails[0].severity, "HIGH")

    def test_wildcard_trust_with_condition_warns(self):
        trust = parse_trust_policy({"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole",
             "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}}}]})
        sc = self._run([principal("role", "guarded", [stmt("Allow", "s3:GetObject")], trust=trust)])
        warns = [r for r in sc.results if r.check_id == "IAMPE-22" and r.status == "WARN"]
        self.assertEqual(len(warns), 1)
        self.assertFalse([r for r in sc.results if r.check_id == "IAMPE-22" and r.status == "FAIL"])

    def test_conditioned_privesc_downgraded_to_warn(self):
        principals = [principal("user", "bob", [
            stmt("Allow", "iam:CreateAccessKey", condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})])]
        sc = self._run(principals)
        rows = [r for r in sc.results if r.check_id == "IAMPE-06"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, "WARN")   # not FAIL

    def test_unconditioned_privesc_is_fail(self):
        principals = [principal("user", "carol", [stmt("Allow", "iam:CreateAccessKey")])]
        sc = self._run(principals)
        rows = [r for r in sc.results if r.check_id == "IAMPE-06"]
        self.assertEqual(rows[0].status, "FAIL")

    def test_new_check_ids_have_severity(self):
        for cid in ("IAMPE-21", "IAMPE-22"):
            self.assertIn(cid, CHECK_SEVERITY)
            self.assertIn(cid, COMPLIANCE_MAP)


# ─── GetAccountAuthorizationDetails collection ───────────────────────────────
class TestGAADCollection(unittest.TestCase):

    def _scanner_with_gaad(self, page):
        sc = make_scanner(["IAMPRIVESC"])
        iam = MagicMock()
        pager = MagicMock()
        pager.paginate.return_value = [page]
        iam.get_paginator.return_value = pager
        sc._clients = {"iam:us-east-1": iam}
        sc._client = lambda service, region=None: sc._clients[f"{service}:{region or sc.region}"]
        return sc

    def test_managed_and_inline_and_trust_parsed(self):
        page = {
            "UserDetailList": [{
                "UserName": "dave", "Arn": f"arn:aws:iam::{ACCT}:user/dave",
                "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}],
                "UserPolicyList": [], "GroupList": [],
            }],
            "GroupDetailList": [],
            "RoleDetailList": [{
                "RoleName": "app", "Arn": f"arn:aws:iam::{ACCT}:role/app", "Path": "/",
                "AttachedManagedPolicies": [], "RolePolicyList": [],
                "AssumeRolePolicyDocument": {"Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                     "Action": "sts:AssumeRole"}]},
                "InstanceProfileList": [{"Arn": f"arn:aws:iam::{ACCT}:instance-profile/app"}],
            }],
            "Policies": [{
                "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "DefaultVersionId": "v1",
                "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True,
                                       "Document": {"Statement": [
                                           {"Effect": "Allow", "Action": "*", "Resource": "*"}]}}],
            }],
        }
        sc = self._scanner_with_gaad(page)
        principals = sc._get_iam_principals()
        dave = [p for p in principals if p["name"] == "dave"][0]
        self.assertIn("*", dave["allow"])                       # admin from managed policy
        app = [p for p in principals if p["name"] == "app"][0]
        self.assertEqual(app["trust"][0]["service"], ["ec2.amazonaws.com"])
        self.assertEqual(app["instance_profiles"], [f"arn:aws:iam::{ACCT}:instance-profile/app"])

    def test_service_linked_roles_skipped(self):
        page = {
            "UserDetailList": [], "GroupDetailList": [], "Policies": [],
            "RoleDetailList": [{
                "RoleName": "AWSServiceRoleForX",
                "Arn": f"arn:aws:iam::{ACCT}:role/aws-service-role/x/AWSServiceRoleForX",
                "Path": "/aws-service-role/x/", "AttachedManagedPolicies": [],
                "RolePolicyList": [], "AssumeRolePolicyDocument": {"Statement": []},
                "InstanceProfileList": [],
            }],
        }
        sc = self._scanner_with_gaad(page)
        self.assertEqual(sc._get_iam_principals(), [])


# ─── Compliance scorecard ────────────────────────────────────────────────────
class TestComplianceScorecard(unittest.TestCase):

    def test_universe_from_map_and_failed_control(self):
        results = [Result("FAIL", "IAM-01", "IAM", "root", "m",
                           severity="CRITICAL", compliance=COMPLIANCE_MAP["IAM-01"])]
        card = compliance_scorecard(results)
        cis = card["CIS"]
        self.assertIn("1.5", cis["failed_controls"])     # IAM-01 -> CIS 1.5
        self.assertGreater(cis["controls_total"], 20)
        self.assertEqual(cis["controls_passed"],
                         cis["controls_total"] - cis["controls_failed"])
        self.assertLess(cis["pass_rate"], 100.0)

    def test_clean_scan_is_100(self):
        card = compliance_scorecard([Result("PASS", "IAM-01", "IAM", "root", "ok")])
        for f in COMPLIANCE_FRAMEWORKS:
            self.assertEqual(card[f]["pass_rate"], 100.0)
            self.assertEqual(card[f]["controls_failed"], 0)

    def test_warn_counts_as_failed_control(self):
        results = [Result("WARN", "S3-05", "S3", "b", "m",
                           severity="LOW", compliance=COMPLIANCE_MAP["S3-05"])]
        card = compliance_scorecard(results)
        self.assertGreater(card["CIS"]["controls_failed"], 0)


# ─── Multi-account orchestration ─────────────────────────────────────────────
class TestMultiAccount(unittest.TestCase):

    def test_list_org_accounts_filters_active(self):
        base = MagicMock()
        org = MagicMock()
        pager = MagicMock()
        pager.paginate.return_value = [{"Accounts": [
            {"Id": "111", "Status": "ACTIVE"},
            {"Id": "222", "Status": "SUSPENDED"},
            {"Id": "333", "Status": "ACTIVE"}]}]
        org.get_paginator.return_value = pager
        base.client.return_value = org
        self.assertEqual(list_org_accounts(base_session=base), ["111", "333"])

    def test_assume_role_session_builds_session(self):
        base = MagicMock()
        sts = MagicMock()
        sts.assume_role.return_value = {"Credentials": {
            "AccessKeyId": "AKIA", "SecretAccessKey": "s", "SessionToken": "t"}}
        base.client.return_value = sts
        fake_boto3 = MagicMock()
        with patch("aws_live_scanner.boto3", fake_boto3, create=True):
            assume_role_session("444", "MyRole", external_id="xid",
                                region="eu-west-1", base_session=base)
        # role name resolved to full ARN, ExternalId passed
        _, kwargs = sts.assume_role.call_args
        self.assertEqual(kwargs["RoleArn"], "arn:aws:iam::444:role/MyRole")
        self.assertEqual(kwargs["ExternalId"], "xid")
        fake_boto3.Session.assert_called_once()

    def test_aggregate_prefixes_resource_and_unions_graph(self):
        sc1 = make_scanner(["IAMPRIVESC"], account="111")
        sc1.results = [Result("FAIL", "IAM-01", "IAM", "root", "m", severity="CRITICAL")]
        sc1.graph = SecurityGraph(); sc1.graph.add_edge("a", "b", "CAN_ASSUME")
        sc2 = make_scanner(["IAMPRIVESC"], account="222")
        sc2.results = [Result("FAIL", "S3-03", "S3", "bucket", "m", severity="HIGH")]
        sc2.graph = SecurityGraph(); sc2.graph.add_edge("c", "d", "CAN_ASSUME")

        agg = aggregate_results([sc1, sc2])
        resources = {r.resource for r in agg.results}
        self.assertEqual(resources, {"111/root", "222/bucket"})
        self.assertEqual(agg.graph.stats()["edges"], 2)
        self.assertIn("2-accounts", agg.account)


# ─── Region iterator ─────────────────────────────────────────────────────────
class TestRegionIterator(unittest.TestCase):

    def test_default_single_region(self):
        sc = make_scanner(["EC2"])
        self.assertEqual(sc._regions_for_section("EC2"), ["us-east-1"])

    def test_all_regions_sweeps_regional_not_global(self):
        sc = make_scanner(["EC2"])
        sc.all_regions_scan = True
        sc._all_regions = ["us-east-1", "eu-west-1", "ap-south-1"]
        self.assertEqual(sc._regions_for_section("EC2"),
                         ["us-east-1", "eu-west-1", "ap-south-1"])
        # global sections still run once
        self.assertEqual(sc._regions_for_section("IAM"), ["us-east-1"])
        self.assertEqual(sc._regions_for_section("IAMPRIVESC"), ["us-east-1"])

    def test_run_calls_regional_check_once_per_region_and_restores(self):
        sc = make_scanner(["EC2"])
        sc._session = MagicMock()
        sc._session.client.return_value.get_caller_identity.return_value = {"Account": "123"}
        sc.all_regions_scan = True
        sc._all_regions = ["us-east-1", "eu-west-1"]
        seen = []
        sc._check_ec2 = lambda: seen.append(sc.region)
        with patch("aws_live_scanner.HAS_BOTO3", True), patch("builtins.print"):
            sc.run()
        self.assertEqual(seen, ["us-east-1", "eu-west-1"])
        self.assertEqual(sc.region, "us-east-1")   # base region restored


class TestGraphSerialization(unittest.TestCase):

    def test_save_json_writes_node_link_file(self):
        import tempfile
        g = SecurityGraph()
        g.add_node("u", "IAMUser", name="u")
        g.add_edge("u", "cap", "CAN_PRIVESC_TO", rules=["IAMPE-19"])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            path = tf.name
        try:
            g.save_json(path)
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(len(data["nodes"]), 2)
            self.assertEqual(len(data["edges"]), 1)
            self.assertEqual(data["edges"][0]["kind"], "CAN_PRIVESC_TO")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
