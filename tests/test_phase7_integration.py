"""Phase 7 integration — the remediation/code-to-cloud wiring through the REAL
scanner, and the default-path invariant (no new flags => JSON byte-for-byte v2.7)."""
import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_correlate as C
from aws_deepplane import is_exploitable
from aws_graph import SecurityGraph
from aws_live_scanner import AWSLiveScanner, _run_remediation

ACCT = "111122223333"
ADMIN = f"capability:admin:{ACCT}"
BUCKET = f"arn:aws:s3:::crown-{ACCT}"


def _scanner_with_paths():
    sc = AWSLiveScanner(region="us-east-1", sections=["CORRELATE"])
    sc.account = ACCT
    g = SecurityGraph()
    inst = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
    eni, prof = "eni-1", f"arn:aws:iam::{ACCT}:instance-profile/p-1"
    role = f"arn:aws:iam::{ACCT}:role/app-role"
    g.add_node("internet", "InternetSource")
    g.add_node(eni, "NetworkInterface")
    g.add_node(inst, "EC2Instance", instance_id="i-1")
    g.add_edge("internet", eni, "EXPOSED_TO", ports="tcp/22")
    g.add_edge(eni, inst, "ATTACHED_TO")
    g.add_node(prof, "InstanceProfile")
    g.add_edge(inst, prof, "HAS_INSTANCE_PROFILE")
    g.add_node(role, "IAMRole", name="app-role")
    g.add_edge(prof, role, "HAS_ROLE")
    g.add_node("CVE-2021-44228", "Vulnerability", kev=True)
    g.add_edge(inst, "CVE-2021-44228", "HAS_VULN", cve="CVE-2021-44228", kev=True,
               exploit_available="YES")
    g.add_node(ADMIN, "AdminCapability")
    g.add_edge(role, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
    g.add_node(BUCKET, "S3Bucket", name="crown-data", crown_jewel=True)
    g.add_edge(role, BUCKET, "CAN_READ_DATA", conditioned=False)
    sc.graph = g
    threatened = {e["dst"] for e in g.edges("THREAT_ON")}
    paths = C.enumerate_paths(g, {"internet"}, ADMIN, {BUCKET},
                              lambda e: not e["props"].get("conditioned"),
                              is_exploitable, lambda nid: nid in threatened)
    nk = lambda nid: (g.node(nid) or {}).get("kind")
    def dom(node, terminal):
        reach = g.reachable("internet", C.E_PATH, max_hops=64,
                            edge_filter=lambda e: e["src"] != node and e["dst"] != node)
        return terminal not in reach
    sc.attack_paths = paths
    sc.choke_points = C.choke_points(paths, node_kind=nk,
                                     label_of=lambda nid: C._label(g, nid), dominates=dom)
    return sc


class Args:
    remediate = False
    remediate_out = None
    remediate_format = "md,json"
    remediate_min_severity = "MEDIUM"
    iac_dir = None
    graph_neptune_load = False


class TestRemediationWiring(unittest.TestCase):

    def test_remediate_produces_report_and_json_block(self):
        sc = _scanner_with_paths()
        a = Args()
        a.remediate = True
        _run_remediation(sc, a)
        assert sc._remediation_report is not None
        assert sc._remediation_report["headline"].startswith("Fix 1 item")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.json")
            sc.save_json(p)
            data = json.loads(open(p, encoding="utf-8").read())
        assert "remediation" in data
        assert data["remediation"]["actions"][0]["is_true_choke"] is True

    def test_remediate_writes_artifacts(self):
        sc = _scanner_with_paths()
        a = Args()
        a.remediate = True
        with tempfile.TemporaryDirectory() as d:
            a.remediate_out = d
            a.remediate_format = "md,json,issue,pr"
            _run_remediation(sc, a)
            files = set(os.listdir(d))
        assert "remediation_runbook.md" in files
        assert "remediation_plan.json" in files
        assert "remediation_issue.md" in files

    def test_remediate_with_iac_dir_sets_code_to_cloud(self):
        sc = _scanner_with_paths()
        a = Args()
        a.remediate = True
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "main.tf"), "w", encoding="utf-8") as f:
                f.write('resource "aws_iam_role" "app" { name = "app-role" }')
            a.iac_dir = [d]
            _run_remediation(sc, a)
        assert sc._code_to_cloud_meta is not None
        assert sc._code_to_cloud_meta["resources_indexed"] == 1


class TestDefaultPathUnchanged(unittest.TestCase):

    def test_no_remediation_key_without_flag(self):
        sc = _scanner_with_paths()
        _run_remediation(sc, Args())          # remediate=False -> no-op
        assert sc._remediation_report is None
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.json")
            sc.save_json(p)
            data = json.loads(open(p, encoding="utf-8").read())
        assert "remediation" not in data and "code_to_cloud" not in data


if __name__ == "__main__":
    unittest.main()
