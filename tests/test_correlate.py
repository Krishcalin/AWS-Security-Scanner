#!/usr/bin/env python3
"""Tests for the pure attack-path correlation engine (aws_correlate.py).

Validates the Phase 4 methodology against hand-built graphs (no AWS, no boto3):
gated-multiplicative scoring, the preserved ATTACK-02 vuln-pivot gate, the
direct-public-crown exception, the conditioned floor/cap, the KEV hard floor,
choke-point ranking (exclude entry/target, diamond #1-choke, is_true_choke), the
additive-combiner false-positive regression, empty-graph no-op, and determinism.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_graph import SecurityGraph
from aws_deepplane import is_exploitable
import aws_correlate as C

ACCT = "123456789012"
ADMIN = f"capability:admin:{ACCT}"
BUCKET = "arn:aws:s3:::crown-data"


def is_unconditioned(e):
    p = e.get("props", {})
    return not p.get("conditioned") and not p.get("has_condition")


def threat_fn(g):
    # O(1) precomputed set — the enumerator calls this per edge expansion
    threatened = {e["dst"] for e in g.edges("THREAT_ON")}
    return lambda nid: nid in threatened


def enum(g, crown=(BUCKET,), admin=ADMIN):
    return C.enumerate_paths(g, {"internet"}, admin, set(crown),
                             is_unconditioned, is_exploitable, threat_fn(g))


def flagship_graph(kev=True, exploit="YES", epss=None, privesc_cond=False,
                   read_cond=False, with_admin=True, with_data=True,
                   with_vuln=True, iid="i-1"):
    g = SecurityGraph()
    inst = f"arn:aws:ec2:us-east-1:{ACCT}:instance/{iid}"
    eni = f"eni-{iid}"
    prof = f"arn:aws:iam::{ACCT}:instance-profile/p-{iid}"
    role = f"arn:aws:iam::{ACCT}:role/r-{iid}"
    g.add_node("internet", "InternetSource")
    g.add_node(eni, "NetworkInterface")
    g.add_node(inst, "EC2Instance", instance_id=iid)
    g.add_edge("internet", eni, "EXPOSED_TO", family="ipv4", ports="tcp/22")
    g.add_edge(eni, inst, "ATTACHED_TO")
    g.add_node(prof, "InstanceProfile")
    g.add_edge(inst, prof, "HAS_INSTANCE_PROFILE")
    g.add_node(role, "IAMRole", name=f"r-{iid}")
    g.add_edge(prof, role, "HAS_ROLE")
    if with_vuln:
        g.add_node("CVE-2021-44228", "Vulnerability", kev=kev)
        g.add_edge(inst, "CVE-2021-44228", "HAS_VULN", cve="CVE-2021-44228",
                   kev=kev, exploit_available=exploit, epss=epss)
    if with_admin:
        g.add_node(ADMIN, "AdminCapability")
        g.add_edge(role, ADMIN, "CAN_PRIVESC_TO", conditioned=privesc_cond)
    if with_data:
        g.add_node(BUCKET, "S3Bucket", name="crown-data", crown_jewel=True)
        g.add_edge(role, BUCKET, "CAN_READ_DATA", conditioned=read_cond)
    return g


class TestEnumeration(unittest.TestCase):

    def test_full_flagship_two_critical_paths(self):
        paths = enum(flagship_graph())
        self.assertEqual(len(paths), 2)                     # admin + data
        self.assertTrue(all(p.severity == "CRITICAL" for p in paths))
        self.assertEqual({p.terminal_kind for p in paths}, {"admin", "data"})

    def test_attack02_gate_no_vuln_no_data_path(self):
        # exposed instance with NO vuln, role can read crown data but not admin
        g = flagship_graph(with_vuln=False, with_admin=False)
        self.assertEqual(enum(g), [])                       # data terminal gated out

    def test_admin_path_needs_no_vuln(self):
        g = flagship_graph(with_vuln=False, with_data=False)
        paths = enum(g)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].terminal_kind, "admin")

    def test_direct_public_crown_exception(self):
        g = SecurityGraph()
        g.add_node("internet", "InternetSource")
        g.add_node(BUCKET, "S3Bucket", name="crown-data", crown_jewel=True, public=True)
        g.add_edge("internet", BUCKET, "EXPOSED_TO", basis="access-analyzer", authoritative=True)
        paths = enum(g)
        self.assertEqual(len(paths), 1)
        self.assertTrue(paths[0].direct_public_crown)
        self.assertEqual(paths[0].severity, "CRITICAL")

    def test_unexposed_high_cvss_is_not_critical(self):
        # additive-combiner regression: a KEV vuln host with NO internet exposure
        g = flagship_graph()
        # sever the exposure edge by rebuilding without internet->eni
        g2 = SecurityGraph()
        for n in g.nodes():
            g2.add_node(n["id"], n["kind"], **n["props"])
        for e in g.edges():
            if e["kind"] == "EXPOSED_TO":
                continue
            g2.add_edge(e["src"], e["dst"], e["kind"], **e["props"])
        self.assertEqual(enum(g2), [])                      # nothing reachable from internet


class TestScoring(unittest.TestCase):

    def test_conditioned_privesc_caps_admin_path(self):
        paths = enum(flagship_graph(privesc_cond=True, with_data=False))
        admin = [p for p in paths if p.terminal_kind == "admin"][0]
        self.assertTrue(admin.conditioned)
        self.assertLessEqual(admin.score, 55)
        self.assertNotEqual(admin.severity, "CRITICAL")

    def test_kev_data_hard_floor(self):
        paths = enum(flagship_graph(kev=True, with_admin=False))
        data = [p for p in paths if p.terminal_kind == "data"][0]
        self.assertTrue(data.hard_floor_applied)
        self.assertGreaterEqual(data.score, 90)

    def test_threat_boost_raises_score(self):
        base = enum(flagship_graph(with_admin=False))[0].score
        g = flagship_graph(with_admin=False)
        g.add_node("threat:x", "ThreatFinding")
        inst = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
        g.add_edge("threat:x", inst, "THREAT_ON")
        boosted = enum(g)[0]
        self.assertTrue(boosted.active_threat)
        self.assertGreaterEqual(boosted.score, base)

    def test_rationale_is_explainable(self):
        p = enum(flagship_graph())[0]
        self.assertIn("score", p.rationale)
        self.assertTrue(p.driving_findings)

    def test_deterministic_order(self):
        g = flagship_graph()
        self.assertEqual([p.nodes for p in enum(g)], [p.nodes for p in enum(g)])


class TestChokePoints(unittest.TestCase):

    def _diamond(self):
        # two exposed instances whose roles both assume ONE admin-capable role
        g = SecurityGraph()
        g.add_node("internet", "InternetSource")
        g.add_node(ADMIN, "AdminCapability")
        shared = f"arn:aws:iam::{ACCT}:role/shared-admin"
        g.add_node(shared, "IAMRole", name="shared-admin")
        g.add_edge(shared, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
        for i in ("a", "b"):
            eni, inst = f"eni-{i}", f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-{i}"
            prof = f"arn:aws:iam::{ACCT}:instance-profile/p-{i}"
            role = f"arn:aws:iam::{ACCT}:role/r-{i}"
            g.add_node(eni, "NetworkInterface")
            g.add_node(inst, "EC2Instance", instance_id=f"i-{i}")
            g.add_edge("internet", eni, "EXPOSED_TO")
            g.add_edge(eni, inst, "ATTACHED_TO")
            g.add_node(prof, "InstanceProfile")
            g.add_edge(inst, prof, "HAS_INSTANCE_PROFILE")
            g.add_node(role, "IAMRole", name=f"r-{i}")
            g.add_edge(prof, role, "HAS_ROLE")
            g.add_node("CVE-x", "Vulnerability", kev=True)
            g.add_edge(inst, "CVE-x", "HAS_VULN", cve="CVE-x", kev=True, exploit_available="YES")
            g.add_edge(role, shared, "CAN_ASSUME", conditioned=False)
        return g, shared

    def test_shared_node_is_top_choke(self):
        g, shared = self._diamond()
        paths = enum(g, crown=())
        self.assertEqual(len(paths), 2)                     # two entry paths to admin
        chokes = C.choke_points(paths, node_kind=lambda n: (g.node(n) or {}).get("kind"))
        self.assertTrue(chokes)
        top = chokes[0]
        self.assertEqual(top.node_id, shared)               # on both paths -> #1
        self.assertEqual(top.paths_severed, 2)
        self.assertTrue(top.is_true_choke)                  # every path to admin goes through it

    def test_internet_and_target_never_choke(self):
        g, _ = self._diamond()
        chokes = C.choke_points(enum(g, crown=()), node_kind=lambda n: (g.node(n) or {}).get("kind"))
        kinds = {c.node_kind for c in chokes}
        self.assertNotIn("InternetSource", kinds)
        self.assertNotIn("AdminCapability", kinds)

    def test_is_true_choke_uses_authoritative_dominates(self):
        # regression (adversarial FP): is_true_choke must reflect the graph-backed
        # dominance check, not the bounded enumerated-path heuristic
        g = flagship_graph()
        paths = enum(g)
        nk = lambda n: (g.node(n) or {}).get("kind")
        none = C.choke_points(paths, node_kind=nk, dominates=lambda n, t: False)
        self.assertTrue(all(not c.is_true_choke for c in none))
        alld = C.choke_points(paths, node_kind=nk, dominates=lambda n, t: True)
        self.assertTrue(any(c.is_true_choke for c in alld))

    def test_dense_clique_terminates_fast(self):
        # regression (adversarial SCALE, HIGH): a dense CAN_ASSUME clique made the
        # DFS explore O(N!) simple paths (minutes-long scan-time DoS) even though
        # materialization was capped. The step budget must bound EXPLORATION cost.
        import time
        g = SecurityGraph()
        g.add_node("internet", "InternetSource")
        g.add_node(ADMIN, "AdminCapability")
        eni, inst = "eni0", f"arn:aws:ec2:us-east-1:{ACCT}:instance/i0"
        prof = f"arn:aws:iam::{ACCT}:instance-profile/p0"
        g.add_node(eni, "NetworkInterface")
        g.add_node(inst, "EC2Instance", instance_id="i0")
        g.add_edge("internet", eni, "EXPOSED_TO")
        g.add_edge(eni, inst, "ATTACHED_TO")
        g.add_node(prof, "InstanceProfile")
        g.add_edge(inst, prof, "HAS_INSTANCE_PROFILE")
        g.add_node("CVE", "Vulnerability", kev=True)
        g.add_edge(inst, "CVE", "HAS_VULN", kev=True, exploit_available="YES", cve="CVE")
        roles = [f"arn:aws:iam::{ACCT}:role/role{i}" for i in range(40)]   # large clique
        for r in roles:
            g.add_node(r, "IAMRole", name=r)
        g.add_edge(prof, roles[0], "HAS_ROLE")
        for a in roles:                                  # full clique of assume edges
            for b in roles:
                if a != b:
                    g.add_edge(a, b, "CAN_ASSUME", conditioned=False)
        g.add_edge(roles[-1], ADMIN, "CAN_PRIVESC_TO", conditioned=False)
        t = time.time()
        paths = enum(g, crown=())
        elapsed = time.time() - t
        self.assertLess(elapsed, 5.0)                    # was minutes without the step budget
        self.assertLessEqual(len(paths), C.PER_PAIR_CAP)  # one (internet,admin) pair

    def test_no_terminal_clique_terminates_fast(self):
        # worst case: mutually-assumable roles with NO admin/crown -> 0 paths ever
        # materialized, so only the step budget can stop the O(N!) walk.
        import time
        g = SecurityGraph()
        g.add_node("internet", "InternetSource")
        g.add_node("eni", "NetworkInterface")
        inst = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i0"
        prof = f"arn:aws:iam::{ACCT}:instance-profile/p0"
        g.add_node(inst, "EC2Instance", instance_id="i0")
        g.add_edge("internet", "eni", "EXPOSED_TO")
        g.add_edge("eni", inst, "ATTACHED_TO")
        g.add_node(prof, "InstanceProfile")
        g.add_edge(inst, prof, "HAS_INSTANCE_PROFILE")
        roles = [f"arn:aws:iam::{ACCT}:role/r{i}" for i in range(50)]
        for r in roles:
            g.add_node(r, "IAMRole", name=r)
        g.add_edge(prof, roles[0], "HAS_ROLE")
        for a in roles:
            for b in roles:
                if a != b:
                    g.add_edge(a, b, "CAN_ASSUME", conditioned=False)
        t = time.time()
        paths = enum(g, crown=())                        # no sink -> []
        self.assertEqual(paths, [])
        self.assertLess(time.time() - t, 5.0)

    def test_minimal_cut_covers_critical_paths(self):
        g, shared = self._diamond()
        cut = C.minimal_cut(enum(g, crown=()), node_kind=lambda n: (g.node(n) or {}).get("kind"))
        self.assertIn(shared, cut)                          # one node covers both crit paths
        self.assertEqual(len(cut), 1)


class TestEdgeCases(unittest.TestCase):

    def test_empty_graph_no_paths(self):
        self.assertEqual(C.enumerate_paths(SecurityGraph(), {"internet"}, ADMIN, set(),
                                           is_unconditioned, is_exploitable, lambda n: False), [])

    def test_no_sources_no_paths(self):
        g = flagship_graph()
        self.assertEqual(C.enumerate_paths(g, set(), ADMIN, {BUCKET},
                                           is_unconditioned, is_exploitable, threat_fn(g)), [])

    def test_summarize_env_risk_is_max_per_jewel(self):
        s = C.summarize(enum(flagship_graph()))
        self.assertEqual(s["total"], 2)
        self.assertGreaterEqual(s["n_critical"], 2)
        self.assertGreater(s["env_risk"], 0)

    def test_to_json_shape(self):
        paths = enum(flagship_graph())
        chokes = C.choke_points(paths, node_kind=lambda n: "IAMRole")
        d = C.to_json(paths, chokes)
        self.assertIn("attack_paths", d)
        self.assertIn("choke_points", d)
        import json
        json.loads(json.dumps(d))                           # JSON-serializable


# ─── integration: the CORRELATE section over a wired scanner graph ───────────
from unittest.mock import patch
from aws_live_scanner import AWSLiveScanner


class TestCorrelateSection(unittest.TestCase):

    def _scanner_with_graph(self, g):
        with patch("aws_live_scanner.HAS_BOTO3", True):
            sc = AWSLiveScanner(region="us-east-1", sections=["CORRELATE"])
        sc.account = ACCT
        sc._iam_principals = []
        sc.graph = g                         # pre-built attack graph; _ensure_graph returns it
        return sc

    def test_section_emits_chokepoint_and_paths_and_json(self):
        sc = self._scanner_with_graph(flagship_graph())
        with patch("builtins.print"):
            sc._check_correlate()
        ids = {r.check_id for r in sc.results}
        self.assertIn("CHOKEPOINT-01", ids)
        self.assertIn("PATHS-01", ids)
        self.assertTrue(sc.attack_paths)
        # save_json carries the ranked blocks
        import tempfile, os, json
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            path = tf.name
        try:
            with patch("builtins.print"):
                sc.save_json(path)
            data = json.load(open(path, encoding="utf-8"))
            self.assertIn("attack_paths", data)
            self.assertIn("choke_points", data)
            self.assertTrue(data["attack_paths"])
        finally:
            os.unlink(path)

    def test_section_no_internet_is_info_noop(self):
        g = SecurityGraph()
        g.add_node(f"arn:aws:iam::{ACCT}:role/x", "IAMRole", name="x")
        sc = self._scanner_with_graph(g)
        with patch("builtins.print"):
            sc._check_correlate()
        self.assertFalse([r for r in sc.results if r.status == "FAIL"])
        self.assertTrue([r for r in sc.results if r.status == "INFO"])


# ══════════════════════════════════════════════════════════════════════════════
# Phase 7 — attack-path FUSION (L7 TARGETS traversal, image/Lambda + RUNS_IMAGE
# exploit inheritance, reachable_service boost, multi-kind crown terminals).
# Pure-engine tests on hand-built graphs; no scanner, no AWS.
# ══════════════════════════════════════════════════════════════════════════════
LB = f"lb/arn:aws:elasticloadbalancing:us-east-1:{ACCT}:loadbalancer/app/x/abc"


def lb_fronted_graph(kev=True):
    """internet -EXPOSED_TO-> LoadBalancer -TARGETS-> EC2 -> profile -> role -> admin."""
    g = SecurityGraph()
    iid = "i-lb1"
    inst = f"arn:aws:ec2:us-east-1:{ACCT}:instance/{iid}"
    prof = f"arn:aws:iam::{ACCT}:instance-profile/p-{iid}"
    role = f"arn:aws:iam::{ACCT}:role/r-{iid}"
    g.add_node("internet", "InternetSource")
    g.add_node(LB, "LoadBalancer", name="app-lb", scheme="internet-facing")
    g.add_node(inst, "EC2Instance", instance_id=iid)
    g.add_node(prof, "InstanceProfile")
    g.add_node(role, "IAMRole", name=f"r-{iid}")
    g.add_node(ADMIN, "AdminCapability")
    g.add_edge("internet", LB, "EXPOSED_TO", basis="l7-elbv2", ports="443")
    g.add_edge(LB, inst, "TARGETS", basis="l7-elbv2", target_type="instance")
    g.add_edge(inst, prof, "HAS_INSTANCE_PROFILE")
    g.add_edge(prof, role, "HAS_ROLE")
    g.add_edge(role, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
    return g


class TestPhase7Fusion(unittest.TestCase):

    def test_lb_targets_traversal_reaches_admin(self):
        # (a) TARGETS must be traversable so a LB-fronted host chains into admin
        paths = enum(lb_fronted_graph(), crown=())
        self.assertTrue(paths)
        top = paths[0]
        self.assertEqual(top.terminal, ADMIN)
        self.assertIn("TARGETS", {e[2] for e in top.edges})
        self.assertEqual(top.severity, "CRITICAL")   # unconditioned admin floor

    def test_targets_out_of_e_path_would_not_chain(self):
        # sanity: TARGETS is now IN E_PATH (guards against an accidental removal)
        self.assertIn("TARGETS", C.E_PATH)

    def test_runs_image_kev_inheritance_data_hard_floor(self):
        # (b) an EC2 that RUNS_IMAGE a KEV ECRImage inherits the exploit signal,
        # unlocking the ATTACK-02 data terminal + KEV hard floor — even with NO
        # host-native HAS_VULN edge.
        g = flagship_graph(with_vuln=False)              # host has no own vuln
        inst = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
        img = f"111111111111.dkr.ecr.us-east-1.amazonaws.com/app@sha256:deadbeef"
        g.add_node(img, "ECRImage")
        g.add_node("CVE-2021-44228", "Vulnerability", kev=True)
        g.add_edge(inst, img, "RUNS_IMAGE", repository="app")
        g.add_edge(img, "CVE-2021-44228", "HAS_VULN", cve="CVE-2021-44228",
                   kev=True, exploit_available="YES")
        data = [p for p in enum(g) if p.terminal == BUCKET]
        self.assertTrue(data, "image-inherited KEV should unlock the data terminal")
        self.assertTrue(data[0].kev)
        self.assertTrue(data[0].hard_floor_applied)
        self.assertEqual(data[0].severity, "CRITICAL")

    def test_reachable_service_boost_raises_nonkev_score(self):
        # (c) reachable_service sharpens a non-KEV exploit path; absent leaves it as-is.
        # exploit_available=YES is exploitable (X=0.90) with headroom below the KEV clamp.
        base = enum(flagship_graph(kev=False, exploit="YES"))
        base_data = [p for p in base if p.terminal == BUCKET][0]

        g = flagship_graph(kev=False, exploit="YES")
        # re-tag the existing HAS_VULN edge as network-reachable
        for e in g.out_edges(f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1", {"HAS_VULN"}):
            e["props"]["reachable_service"] = True
        boosted = enum(g)
        boosted_data = [p for p in boosted if p.terminal == BUCKET][0]
        self.assertGreater(boosted_data.exploitability, base_data.exploitability)
        self.assertLessEqual(boosted_data.exploitability, 1.0)

    def test_reachable_service_cannot_exceed_kev(self):
        # clamp: boosting a KEV (X=1.0) is a no-op, never >1.0
        g = flagship_graph(kev=True)
        for e in g.out_edges(f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1", {"HAS_VULN"}):
            e["props"]["reachable_service"] = True
        p = [x for x in enum(g) if x.terminal == BUCKET][0]
        self.assertLessEqual(p.exploitability, 1.0)

    def test_rds_crown_terminal_ranks_and_excluded_from_choke(self):
        # (d) a non-S3 crown datastore ranks as a data terminal; it is a terminal,
        # so it must be excluded from choke ranking.
        g = flagship_graph(with_data=False)
        rds = f"arn:aws:rds:us-east-1:{ACCT}:db:crown-db"
        role = f"arn:aws:iam::{ACCT}:role/r-i-1"
        g.add_node(rds, "RDSInstance", name="crown-db", crown_jewel=True, public=False)
        g.add_edge(role, rds, "CAN_READ_DATA", conditioned=False)
        paths = enum(g, crown=(rds,))
        data = [p for p in paths if p.terminal == rds]
        self.assertTrue(data, "RDSInstance crown must rank as a data terminal")
        node_kind = lambda nid: (g.node(nid) or {}).get("kind")
        chokes = C.choke_points(paths, node_kind=node_kind)
        self.assertNotIn(rds, {c.node_id for c in chokes})   # terminal, not a choke

    def test_crown_nodes_helper_multi_kind(self):
        g = flagship_graph()
        rds = f"arn:aws:rds:us-east-1:{ACCT}:db:crown-db"
        g.add_node(rds, "RDSInstance", crown_jewel=True)
        g.add_node("arn:aws:s3:::not-crown", "S3Bucket")     # no crown_jewel prop
        crowns = C.crown_nodes(g)
        self.assertIn(BUCKET, crowns)
        self.assertIn(rds, crowns)
        self.assertNotIn("arn:aws:s3:::not-crown", crowns)

    def test_loadbalancer_can_be_a_choke(self):
        # (e) a LoadBalancer is an intermediate node -> eligible as a choke point.
        g = lb_fronted_graph()
        # add a second fronted host so the LB severs >1 path (non-trivial choke)
        iid2 = "i-lb2"
        inst2 = f"arn:aws:ec2:us-east-1:{ACCT}:instance/{iid2}"
        prof2 = f"arn:aws:iam::{ACCT}:instance-profile/p-{iid2}"
        role2 = f"arn:aws:iam::{ACCT}:role/r-{iid2}"
        g.add_node(inst2, "EC2Instance", instance_id=iid2)
        g.add_node(prof2, "InstanceProfile")
        g.add_node(role2, "IAMRole", name=f"r-{iid2}")
        g.add_edge(LB, inst2, "TARGETS", basis="l7-elbv2", target_type="instance")
        g.add_edge(inst2, prof2, "HAS_INSTANCE_PROFILE")
        g.add_edge(prof2, role2, "HAS_ROLE")
        g.add_edge(role2, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
        paths = enum(g, crown=())
        node_kind = lambda nid: (g.node(nid) or {}).get("kind")
        chokes = C.choke_points(paths, node_kind=node_kind)
        self.assertIn(LB, {c.node_id for c in chokes})
        self.assertEqual(node_kind(LB), "LoadBalancer")


if __name__ == "__main__":
    unittest.main()
