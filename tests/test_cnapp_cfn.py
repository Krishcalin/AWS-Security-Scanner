"""Static validation of the deploy/ CloudFormation artifacts — the security-load-
bearing guarantees: read-only managed policies (NEVER ReadOnlyAccess), the trust
principal is the hub ROLE under an ExternalId condition, and the EBS side-scan
WRITE actions are NOT in the default role."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

yaml = pytest.importorskip("yaml")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER = os.path.join(ROOT, "deploy", "cnapp-scanner-role.yaml")
HUB = os.path.join(ROOT, "deploy", "cnapp-hub-role.yaml")


class _CfnLoader(yaml.SafeLoader):
    pass


def _scalar(loader, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_CfnLoader.add_multi_constructor("!", lambda l, s, n: _scalar(l, n))


def _load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.load(f, Loader=_CfnLoader)


def test_scanner_role_parses():
    doc = _load(SCANNER)
    assert "CnappScannerRole" in doc["Resources"]


def test_managed_policies_are_read_only_not_readonlyaccess():
    props = _load(SCANNER)["Resources"]["CnappScannerRole"]["Properties"]
    mp = [str(m) for m in props["ManagedPolicyArns"]]
    assert any("SecurityAudit" in m for m in mp)
    assert any("ViewOnlyAccess" in m for m in mp)
    # ReadOnlyAccess grants workload DATA reads (s3:GetObject, ...) — must be absent
    assert not any("policy/ReadOnlyAccess" in m for m in mp)


def test_trust_is_hub_role_with_external_id():
    props = _load(SCANNER)["Resources"]["CnappScannerRole"]["Properties"]
    stmt = props["AssumeRolePolicyDocument"]["Statement"][0]
    assert stmt["Action"] == "sts:AssumeRole"
    # ExternalId condition present (confused-deputy guard)
    assert "sts:ExternalId" in stmt["Condition"]["StringEquals"]
    # principal references the HubRoleArn parameter, not account-root
    principal = str(stmt["Principal"])
    assert "HubRoleArn" in principal or ":role/" in principal
    assert ":root" not in principal


def test_default_role_has_no_snapshot_write_actions():
    """The inline policies attached by default must contain NO write/snapshot
    actions — the side-scan lifecycle is opt-in only (commented out)."""
    props = _load(SCANNER)["Resources"]["CnappScannerRole"]["Properties"]
    actions = []
    for pol in props.get("Policies", []):
        for s in pol["PolicyDocument"]["Statement"]:
            act = s["Action"]
            actions += act if isinstance(act, list) else [act]
    joined = " ".join(actions)
    for forbidden in ("CreateSnapshot", "DeleteSnapshot", "ModifySnapshotAttribute",
                      "CopySnapshot", ":Put", ":Create", ":Delete", ":Update", "GetObject"):
        assert forbidden not in joined, f"default role must not grant {forbidden}"
    # it SHOULD grant the harmless CIEM last-accessed reads
    assert any("GenerateServiceLastAccessedDetails" in a for a in actions)


def test_hub_role_assume_is_org_and_name_scoped():
    doc = _load(HUB)
    stmts = doc["Resources"]["CnappHubRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assume = next(s for s in stmts if s.get("Sid") == "AssumeScannerRoleInOrg")
    assert assume["Action"] == "sts:AssumeRole"
    assert "role/CnappScannerRole" in str(assume["Resource"])       # fixed role NAME only
    assert "aws:ResourceOrgID" in str(assume["Condition"])          # scoped to the org
