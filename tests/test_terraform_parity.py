"""Phase-4 Slice-2 · B5 — the Terraform scanner-role module stays byte-equivalent (in
effect) to the CloudFormation deploy/cnapp-scanner-role.yaml. Parses the CFN (authoritative)
and asserts the TF grants the SAME managed policies + inline extras + ExternalId trust, and
keeps every write/data action opt-in. Structural (no terraform binary needed)."""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

yaml = pytest.importorskip("yaml")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFN = os.path.join(ROOT, "deploy", "cnapp-scanner-role.yaml")
TF_MAIN = os.path.join(ROOT, "deploy", "terraform", "scanner-role", "main.tf")
TF_VARS = os.path.join(ROOT, "deploy", "terraform", "scanner-role", "variables.tf")


class _CfnLoader(yaml.SafeLoader):
    pass


def _scalar(loader, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_CfnLoader.add_multi_constructor("!", lambda l, s, n: _scalar(l, n))


def _cfn_props():
    with open(CFN, encoding="utf-8") as f:
        return yaml.load(f, Loader=_CfnLoader)["Resources"]["CnappScannerRole"]["Properties"]


def _cfn_extras_actions():
    actions = []
    for pol in _cfn_props().get("Policies", []):
        for s in pol["PolicyDocument"]["Statement"]:
            act = s["Action"]
            actions += act if isinstance(act, list) else [act]
    return actions


def _tf():
    return open(TF_MAIN, encoding="utf-8").read()


# ── parity: identity + trust ─────────────────────────────────────────────────
def test_tf_role_identity_matches_cfn():
    tf = _tf()
    props = _cfn_props()
    assert '"CnappScannerRole"' in tf
    assert f"max_session_duration = {props['MaxSessionDuration']}" in tf
    assert '"cnapp:managed"' in tf and '"true"' in tf


def test_tf_trust_is_hub_role_under_externalid():
    tf = _tf()
    assert "sts:AssumeRole" in tf
    assert "sts:ExternalId" in tf and "var.external_id" in tf
    assert "var.hub_role_arn" in tf                 # hub role, never account-root
    assert ":root" not in tf


# ── parity: managed policies (read-only, never ReadOnlyAccess) ────────────────
def test_tf_managed_policies_match_cfn():
    tf = _tf()
    mp = [str(m) for m in _cfn_props()["ManagedPolicyArns"]]
    assert any("SecurityAudit" in m for m in mp) and "arn:aws:iam::aws:policy/SecurityAudit" in tf
    assert (any("ViewOnlyAccess" in m for m in mp)
            and "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess" in tf)
    assert "policy/ReadOnlyAccess" not in tf        # workload DATA reads — never


_ACTION_RE = re.compile(r'"([a-z][a-z0-9-]*:[A-Za-z0-9*]+)"')


def _tf_always_on():
    return _tf().split("# ── OPT-IN")[0]


def _tf_block(resource_name):
    """The text of one `resource ... "<name>" { ... }` block (brace-balanced)."""
    tf = _tf()
    start = tf.index(f'"{resource_name}"')
    depth, i = 0, tf.index("{", start)
    for j in range(i, len(tf)):
        depth += tf[j] == "{"
        depth -= tf[j] == "}"
        if depth == 0:
            return tf[start:j + 1]
    return tf[start:]


# ── parity: the always-on inline extras action set matches the CFN EXACTLY ────
def test_tf_extras_actions_match_cfn_exactly():
    # scope to the 'extras' policy-document block (the first "extras" is the data source),
    # so the trust condition (sts:ExternalId) + tag (cnapp:managed) aren't mistaken for
    # actions; assert set-equality so a dropped OR added action fails
    tf_actions = set(_ACTION_RE.findall(_tf_block("extras")))
    assert tf_actions == set(_cfn_extras_actions()), (
        f"always-on extras drift: TF-only={tf_actions - set(_cfn_extras_actions())}, "
        f"CFN-only={set(_cfn_extras_actions()) - tf_actions}")


# ── parity: the four opt-in policies match the CFN's (commented) opt-in blocks ─
# Canonical action sets — the single source of truth the TF resources AND the CFN comment
# blocks must both contain (the CFN keeps these commented-out, so they're compared as text).
_OPTIN = {
    # read-only key (pre-existing snapshots): the default side-scan mode; NO write actions.
    "sidescan_read": ["ebs:ListSnapshotBlocks", "ebs:ListChangedBlocks", "ebs:GetSnapshotBlock",
                      "ec2:DescribeSnapshots"],
    # create-mode superset: the read actions PLUS the snapshot-lifecycle writes.
    "sidescan": ["ebs:ListSnapshotBlocks", "ebs:ListChangedBlocks", "ebs:GetSnapshotBlock",
                 "ec2:DescribeSnapshots", "ec2:CreateSnapshot", "ec2:CreateTags",
                 "ec2:CopySnapshot", "ec2:ModifySnapshotAttribute", "ec2:DeleteSnapshot"],
    "flowlog_insights": ["logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery"],
    "dspm_surfaces": ["kinesis:ListStreams", "kinesis:DescribeStreamSummary",
                      "kinesis:ListTagsForStream", "memorydb:DescribeClusters", "memorydb:ListTags",
                      "fsx:DescribeFileSystems", "timestream:ListDatabases",
                      "timestream:ListTables", "timestream:ListTagsForResource"],
    "cdr_forensics": ["cloudtrail:LookupEvents", "securityhub:GetFindings",
                      "guardduty:ListDetectors", "guardduty:GetDetector",
                      "guardduty:ListFindings", "guardduty:GetFindings"],
    "image_layer_pull": ["ecr:GetAuthorizationToken", "ecr:BatchGetImage",
                         "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"],
}


# CFN opt-in comment blocks are keyed by PolicyName; actions there are UNQUOTED YAML flow,
# so the CFN side is compared by block-scoped substring membership + a foreign-action guard
# (together == set-equality) rather than the quoted-action regex used on the TF side.
_CFN_POLICYNAME = {
    "sidescan_read": "CnappSideScanReadOnly",
    "sidescan": "CnappSideScanSnapshotOps",
    "flowlog_insights": "CnappFlowLogInsights",
    "dspm_surfaces": "CnappDspmSurfaces",
    "cdr_forensics": "CnappCdrForensicsRead",
    "image_layer_pull": "CnappImageLayerPull",
}


def _cfn_optin_block(policy_name):
    """The commented CFN block text for one opt-in PolicyName (bounded at the next
    PolicyName / the Outputs section) so checks are block-scoped, not whole-file."""
    text = open(CFN, encoding="utf-8").read()
    start = text.index(f"PolicyName: {policy_name}")
    rest = text[start + len(f"PolicyName: {policy_name}"):]
    ends = [i for i in (rest.find("PolicyName:"), rest.find("Outputs:")) if i >= 0]
    return rest[:min(ends)] if ends else rest


def test_tf_optin_blocks_match_cfn():
    # TF side: exact set-equality (quoted actions -> _ACTION_RE). CFN side: substring
    # membership (actions are UNQUOTED YAML flow, and explanatory prose between blocks
    # mentions other actions, so a per-block foreign-action guard is not reliable).
    cfn_text = open(CFN, encoding="utf-8").read()
    for res, actions in _OPTIN.items():
        block = _tf_block(res)                          # the count-gated TF resource
        tf_actions = set(_ACTION_RE.findall(block))
        assert tf_actions == set(actions), (
            f"opt-in {res} TF drift: TF-only={tf_actions - set(actions)}, "
            f"expected-only={set(actions) - tf_actions}")
        for a in actions:                              # …and the CFN comment carries the same actions
            assert a in cfn_text, f"opt-in {res}: CFN comment missing {a!r} (drift vs TF)"


def test_tf_sidescan_read_is_pure_read_no_writes():
    # the DEFAULT side-scan mode (pre-existing snapshots) must be provably write-free: the
    # read-only grant carries ONLY EBS-direct reads + DescribeSnapshots, never a snapshot write.
    block = _tf_block("sidescan_read")
    for write in ("CreateSnapshot", "CopySnapshot", "ModifySnapshotAttribute",
                  "DeleteSnapshot", "CreateTags"):
        assert write not in block, f"read-only side-scan grant must not include {write}"
    assert "CnappSideScanReadOnly" in block and "var.enable_sidescan_read" in _tf()
    # the CFN comment carries the same read-only PolicyName
    assert "CnappSideScanReadOnly" in open(CFN, encoding="utf-8").read()


def test_tf_image_layer_pull_is_repo_and_tag_scoped():
    # the byte-read grant MUST stay scoped to ECR repos AND gated on the cnapp:imagescan tag,
    # in BOTH the TF resource and the CFN comment — broadening the resource or dropping the tag
    # (a real least-privilege regression) now fails CI.
    for text, where in ((_tf_block("image_layer_pull"), "TF"),
                        (_cfn_optin_block("CnappImageLayerPull"), "CFN")):
        assert "arn:aws:ecr:*:*:repository/*" in text, f"{where}: layer-pull must be repo-scoped"
        assert "aws:ResourceTag/cnapp:imagescan" in text, f"{where}: layer-pull must be tag-scoped"


def test_tf_eks_access_entry_matches_cfn_intent():
    tf = _tf()
    assert "aws_eks_access_entry" in tf and "aws_eks_access_policy_association" in tf
    assert "AmazonEKSViewPolicy" in tf                  # the read-only cluster-view policy
    assert "var.enable_eks_kspm" in tf                  # gated
    # the CFN documents the same EKS view-policy onboarding
    assert "AmazonEKSViewPolicy" in open(CFN, encoding="utf-8").read()


# ── isolation: every write/data action is opt-in (count/for_each gated) ───────
def test_tf_default_role_has_no_write_or_data_actions():
    tf = _tf()
    # the always-on section (up to the first opt-in resource), with comment lines stripped
    # so an explanatory comment ("never grant s3:GetObject") isn't mistaken for a grant
    always_on = "\n".join(ln for ln in tf.split("# ── OPT-IN")[0].splitlines()
                          if not ln.lstrip().startswith("#"))
    for forbidden in ("CreateSnapshot", "DeleteSnapshot", "ModifySnapshotAttribute",
                      "CopySnapshot", "GetObject", "StartQuery", "LookupEvents",
                      "GetDownloadUrlForLayer", "BatchGetImage"):
        assert forbidden not in always_on, f"default TF role must not grant {forbidden}"
    # and each opt-in policy is guarded by a default-false toggle
    for res, var in (("sidescan_read", "enable_sidescan_read"),
                     ("sidescan", "enable_sidescan"),
                     ("flowlog_insights", "enable_flowlog_insights"),
                     ("dspm_surfaces", "enable_dspm_surfaces"),
                     ("cdr_forensics", "enable_cdr_forensics"),
                     ("image_layer_pull", "enable_image_layer_pull")):
        assert re.search(rf'resource "aws_iam_role_policy" "{res}"\s*{{\s*\n\s*count\s*=\s*var\.{var}',
                         tf), f"{res} must be count-gated by var.{var}"
    vars_src = open(TF_VARS, encoding="utf-8").read()
    for var in ("enable_sidescan_read", "enable_sidescan", "enable_flowlog_insights",
                "enable_dspm_surfaces", "enable_cdr_forensics", "enable_eks_kspm",
                "enable_image_layer_pull"):
        assert re.search(rf'variable "{var}"[\s\S]*?default\s*=\s*false', vars_src), \
            f"{var} must default to false"
