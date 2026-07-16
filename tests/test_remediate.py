"""Unit tests for aws_remediate — the pure remediation engine. Reuses the
test_correlate flagship graph (2 CRITICAL paths, admin+data through one IAMRole)
so the plan is built from the REAL aws_correlate ranking (minimal_cut/choke_points),
and asserts prioritization, codegen, exports, determinism, and the empty case."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_correlate as C
import aws_remediate as R
from aws_deepplane import is_exploitable
from aws_graph import SecurityGraph

ACCT = "111122223333"
ADMIN = f"capability:admin:{ACCT}"
BUCKET = f"arn:aws:s3:::crown-{ACCT}"


def _flagship():
    """internet -> exposed EC2 -> profile -> role -> {admin, crown S3}, with a KEV
    CVE on the instance (both paths CRITICAL, both pass through the one IAMRole)."""
    g = SecurityGraph()
    inst = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
    eni, prof = "eni-1", f"arn:aws:iam::{ACCT}:instance-profile/p-1"
    role = f"arn:aws:iam::{ACCT}:role/app-role"
    g.add_node("internet", "InternetSource")
    g.add_node(eni, "NetworkInterface")
    g.add_node(inst, "EC2Instance", instance_id="i-1")
    g.add_edge("internet", eni, "EXPOSED_TO", ports="tcp/22", sg_id="sg-abc")
    g.add_edge(eni, inst, "ATTACHED_TO")
    g.add_node(prof, "InstanceProfile")
    g.add_edge(inst, prof, "HAS_INSTANCE_PROFILE")
    g.add_node(role, "IAMRole", name="app-role")
    g.add_edge(prof, role, "HAS_ROLE")
    g.add_node("CVE-2021-44228", "Vulnerability", kev=True)
    g.add_edge(inst, "CVE-2021-44228", "HAS_VULN", cve="CVE-2021-44228", kev=True,
               exploit_available="YES", fixed_version="2.17", package="log4j")
    g.add_node(ADMIN, "AdminCapability")
    g.add_edge(role, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
    g.add_node(BUCKET, "S3Bucket", name="crown-data", crown_jewel=True)
    g.add_edge(role, BUCKET, "CAN_READ_DATA", conditioned=False)
    return g, role


def _correlate(g):
    threatened = {e["dst"] for e in g.edges("THREAT_ON")}
    paths = C.enumerate_paths(g, {"internet"}, ADMIN, {BUCKET},
                              lambda e: not e["props"].get("conditioned")
                              and not e["props"].get("has_condition"),
                              is_exploitable, lambda nid: nid in threatened)
    nk = lambda nid: (g.node(nid) or {}).get("kind")

    def dom(node, terminal):
        reach = g.reachable("internet", C.E_PATH, max_hops=64,
                            edge_filter=lambda e: e["src"] != node and e["dst"] != node)
        return terminal not in reach
    chokes = C.choke_points(paths, node_kind=nk,
                            label_of=lambda nid: C._label(g, nid), dominates=dom)
    return paths, chokes


def _plan(g, results=()):
    paths, chokes = _correlate(g)
    nk = lambda nid: (g.node(nid) or {}).get("kind")
    return R.build_plan(results, paths, chokes, node_kind=nk,
                        label_of=lambda nid: C._label(g, nid),
                        node_props=lambda nid: (g.node(nid) or {}).get("props", {}),
                        out_edges=g.out_edges, account=ACCT, region="us-east-1")


def _result(status, check_id, section, resource, message, severity):
    return types.SimpleNamespace(status=status, check_id=check_id, section=section,
                                 resource=resource, message=message, severity=severity,
                                 remediation_cmd="")


def _shared_role_graph():
    """Two internet-exposed instances that both use ONE admin role — the role is
    the UNIQUE choke (each instance is on only its own path)."""
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node(ADMIN, "AdminCapability")
    role = f"arn:aws:iam::{ACCT}:role/shared-admin"
    g.add_node(role, "IAMRole", name="shared-admin")
    g.add_edge(role, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
    for i in (1, 2):
        inst = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-{i}"
        eni, prof = f"eni-{i}", f"arn:aws:iam::{ACCT}:instance-profile/p-{i}"
        g.add_node(eni, "NetworkInterface")
        g.add_node(inst, "EC2Instance", instance_id=f"i-{i}")
        g.add_edge("internet", eni, "EXPOSED_TO", ports="tcp/22")
        g.add_edge(eni, inst, "ATTACHED_TO")
        g.add_node(prof, "InstanceProfile")
        g.add_edge(inst, prof, "HAS_INSTANCE_PROFILE")
        g.add_edge(prof, role, "HAS_ROLE")
    return g, role


# ── prioritization: a minimal cut severs all critical paths, fixed first ─────
def test_top_action_is_a_true_choke_severing_all_critical():
    g, _ = _flagship()
    plan = _plan(g)
    a0 = plan.actions[0]
    assert a0.rank == 1 and a0.is_choke and a0.is_true_choke
    assert a0.paths_severed == 2                      # one node covers both CRITICAL paths
    assert BUCKET in a0.jewels_protected
    assert a0.code.cli                                # a concrete fix is generated
    assert plan.n_choke_actions == 1                  # minimal cut = 1 node


def test_shared_role_is_the_unique_choke_with_boundary_fix():
    g, role = _shared_role_graph()
    plan = _plan(g)
    a0 = plan.actions[0]
    assert a0.target_kind == "IAMRole" and a0.target_node == role
    assert a0.fix_key == "iam_boundary"
    assert a0.paths_severed == 2 and a0.admin_paths_severed == 2
    assert "put-role-permissions-boundary" in a0.code.cli
    assert "shared-admin" in a0.code.cli             # role name substituted


def test_headline_cut_100pct():
    g, _ = _flagship()
    plan = _plan(g)
    assert plan.headline() == "Fix 1 item to cut 100% of critical attack paths (2/2)"
    assert plan.total_critical_paths == 2


def test_render_iam_boundary_template():
    art = R.render("iam_boundary", {"role_name": "app-role", "boundary_arn": "arn:b"})
    assert "put-role-permissions-boundary" in art.cli and "app-role" in art.cli
    assert "permissions_boundary" in art.terraform


def test_codegen_never_raises_on_missing_params():
    # a fix template referencing $cidr with no cidr known -> renders <CIDR>, never raises
    art = R.render("sg_scope_ingress", {"sg_id": "sg-1", "port": "22"})
    assert "<CIDR>" in art.cli and "sg-1" in art.cli


# ── regression (adversarial rank 5): no patch_cve without a vuln ─────────────
def test_select_fix_key_ec2_without_vuln_is_not_patch():
    # an exposed instance whose severed path is privesc-driven (no HAS_VULN) must
    # NOT get a nonsensical "patch <CVE>" fix
    assert R._select_fix_key("EC2Instance", {"HAS_INSTANCE_PROFILE"}, set()) == "iam_boundary"
    assert R._select_fix_key("EC2Instance", set(), set()) != "patch_cve"
    # a genuinely vuln-gated instance still patches
    assert R._select_fix_key("EC2Instance", {"HAS_VULN"}, set()) == "patch_cve"


# ── regression (adversarial rank 7): _safe_format never raises ───────────────
def test_safe_format_passes_through_non_identifier_dollars():
    assert R._safe_format("id = ${aws_s3_bucket.b.id}", {}) == "id = ${aws_s3_bucket.b.id}"
    assert R._safe_format("exit $? cost $5", {}) == "exit $? cost $5"
    assert R._safe_format("cfn !Sub ${AWS::Region}", {}) == "cfn !Sub ${AWS::Region}"
    assert R._safe_format("x=$foo", {}) == "x=<FOO>"     # missing convention preserved


def test_render_terraform_with_braces_never_raises():
    # the s3_block_public terraform template has literal { } — must render clean
    art = R.render("s3_block_public", {"bucket": "b"})
    assert "aws_s3_bucket_public_access_block" in art.terraform


# ── posture long-tail ────────────────────────────────────────────────────────
def test_posture_action_for_standalone_finding():
    g, _ = _flagship()
    results = [_result("FAIL", "S3-03", "S3", "arn:aws:s3:::other-bucket",
                       "Bucket not encrypted | arn:aws:s3:::other-bucket", "MEDIUM")]
    plan = _plan(g, results)
    # the choke action ranks first; the unrelated S3-03 becomes a lower-rank posture fix
    assert plan.actions[0].is_choke
    posture = [a for a in plan.actions if not a.is_choke]
    assert any(a.fix_key == "encrypt_at_rest" and a.effort == "low" for a in posture)
    assert plan.n_posture_actions >= 1


def test_posture_dedup_by_rootcause():
    g = SecurityGraph()          # no attack paths -> all posture
    results = [
        _result("FAIL", "DATA-02", "DATA", "arn:aws:s3:::b", "public | arn:aws:s3:::b", "HIGH"),
        _result("FAIL", "EXTACCESS-01", "DATA", "arn:aws:s3:::b", "ext | arn:aws:s3:::b", "HIGH"),
    ]
    plan = R.build_plan(results, [], [], node_kind=lambda n: None)
    # both fold into one s3_block_public action on the same bucket
    s3 = [a for a in plan.actions if a.fix_key == "s3_block_public"]
    assert len(s3) == 1
    assert set(s3[0].resolved_check_ids) == {"DATA-02", "EXTACCESS-01"}


# ── determinism + empty ──────────────────────────────────────────────────────
def test_deterministic():
    g, _ = _flagship()
    r = [_result("FAIL", "S3-03", "S3", "arn:aws:s3:::x", "m | arn:aws:s3:::x", "LOW")]
    assert _plan(g, r).to_dict() == _plan(g, r).to_dict()
    assert R.to_markdown(_plan(g, r)) == R.to_markdown(_plan(g, r))


def test_empty_plan():
    plan = R.build_plan([], [], [], node_kind=lambda n: None)
    assert plan.actions == () and plan.headline() == "No findings to remediate"


def test_exports_shape():
    g, _ = _flagship()
    plan = _plan(g)
    md = R.to_markdown(plan)
    assert md.startswith("# Remediation Runbook") and "CHOKE" in md
    assert plan.actions[0].code.cli.split("\n")[0] in md
    issue = R.to_github_issue(plan)
    assert "- [ ]" in issue
    j = R.plan_to_json(plan)
    assert j["headline"].startswith("Fix 1 item") and j["actions"][0]["is_true_choke"] is True


def test_pr_body_from_shared_role():
    g, _ = _shared_role_graph()
    pr = R.to_github_pr_body(_plan(g), iac="terraform")
    assert "permissions_boundary" in pr
