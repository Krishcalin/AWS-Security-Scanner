"""Phase-4 Slice-4 · B6 — aws_correlate.py is BYTE-FROZEN by this slice.

VEX suppression rides the *existing* ingested_vulns.suppressed column + the empty-path
invariant (a suppressed CVE emits no HAS_VULN edge → no path), so path enumeration is
untouched. This test fails the instant aws_correlate.py is edited, and independently
proves the suppress→empty-path behavior through the unchanged enumerator."""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import cnapp_connectors as cc
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

# Pin recorded when Slice-4 landed. If aws_correlate.py legitimately changes, update this
# hash IN THE SAME COMMIT and explain why in the message — never silently.
CORRELATE_SHA256 = "e5afca6be008e0f2ca68d511781e6b5fd3a89fdf11636887bce63c5738cc723c"

ACCT = "111122223333"
INST = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
ROLE = f"arn:aws:iam::{ACCT}:role/r-1"
PROF = f"arn:aws:iam::{ACCT}:instance-profile/p-1"
BUCKET = "arn:aws:s3:::crown-data"
BUNDLE = {"records": [{"id": "CVE-2021-44228", "aliases": ["CVE-2021-44228"],
                       "database_specific": {"severity": "CRITICAL"}, "severity": [{"score": 10.0}]}],
          "epss": {"CVE-2021-44228": 0.97}, "kev": {"CVE-2021-44228"}, "exploits": {"CVE-2021-44228"}}


def test_aws_correlate_is_byte_frozen():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "aws_correlate.py")
    got = hashlib.sha256(open(path, "rb").read()).hexdigest()
    assert got == CORRELATE_SHA256, (
        "aws_correlate.py changed — Slice-4 must not touch it. If the change is intended, "
        "update CORRELATE_SHA256 in the same commit with a justification.")


def _svc():
    reg = AccountRegistry.open(":memory:")
    results = InMemoryResultStore()
    g = SecurityGraph()
    g.add_node("internet", "InternetSource"); g.add_node("eni-1", "NetworkInterface")
    g.add_node(INST, "EC2Instance", instance_id="i-1")
    g.add_edge("internet", "eni-1", "EXPOSED_TO", ports="tcp/443"); g.add_edge("eni-1", INST, "ATTACHED_TO")
    g.add_node(PROF, "InstanceProfile"); g.add_edge(INST, PROF, "HAS_INSTANCE_PROFILE")
    g.add_node(ROLE, "IAMRole", name="r-1"); g.add_edge(PROF, ROLE, "HAS_ROLE")
    g.add_node(BUCKET, "S3Bucket", crown_jewel=True); g.add_edge(ROLE, BUCKET, "CAN_READ_DATA", conditioned=False)
    results.put(ACCT, {"account": ACCT, "graph_full": g.to_dict(),
                       "attack_paths": [], "finding_catalog": [], "results": []})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=aws_state.StateStore(reg._be),
        vuln_bundle=BUNDLE, clock=lambda: 5000)


def _sarif():
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Trivy", "rules": [{"id": "CVE-2021-44228"}]}},
        "results": [{"ruleId": "CVE-2021-44228", "level": "error",
                     "message": {"text": "Package: log4j-core\nInstalled Version: 2.14.1\nFixed Version: 2.17.1"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": INST}}}]}]}]}


def _openvex():
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "vex-1",
            "statements": [{"vulnerability": {"name": "CVE-2021-44228"},
                            "products": [{"@id": "pkg:oci/app"}], "status": "not_affected",
                            "justification": "vulnerable_code_not_in_execute_path"}]}


def test_vex_suppression_yields_empty_path_via_unchanged_correlate():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_sarif(), target_resource=INST)
    assert svc.list_vulns(ACCT)[0]["on_attack_path"] is True             # correlate found the path
    svc.ingest_document(ACCT, doc=_openvex(), target_resource=INST)      # owner says not_affected
    row = svc.list_vulns(ACCT)[0]
    assert row["suppressed"] is True and row["on_attack_path"] is False  # same enumerator, no edge → no path
