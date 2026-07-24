"""Slice 3 · Batch 2 — AI-SPM graph fusion (_collect_aispm) + AIPATH-01 + the
aws_correlate no-change invariant + B1 metadata lockstep. Offline: hand-built graph,
no boto3 (principals injected via s._iam_principals)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner
from aws_graph import SecurityGraph
import aws_correlate
import aws_live_scanner as A

ACCT = "123456789012"
AI_ROLE = f"arn:aws:iam::{ACCT}:role/ai-exec"
NB_ID = f"arn:aws:sagemaker:us-east-1:{ACCT}:notebook-instance/nb1"


def _stmt(actions, resources, effect="Allow", condition=None):
    return {"effect": effect, "actions": set(actions), "resources": set(resources),
            "not_resources": set(), "condition": condition}


def _principal(arn, statements):
    return {"type": "role", "name": arn.split("/")[-1], "arn": arn, "statements": statements}


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def _svc(resources, principals=None, crown_db=None):
    s = make_scanner(sections=["DATA"])
    s.account = ACCT
    g = SecurityGraph()
    g.add_node(AI_ROLE, "IAMRole")
    if crown_db:                              # as the DSPM pass would have emitted earlier
        g.add_node(crown_db, "DynamoDBTable", name="customers", crown_jewel=True, DataStore=True)
        g.add_edge(AI_ROLE, crown_db, "CAN_READ_DATA")
    s._iam_principals = principals or []
    s._aispm_resources = resources
    return s, g


def _notebook(exposed=True, role=AI_ROLE):
    return {"kind": "SageMakerNotebook", "name": "nb1", "arn": NB_ID,
            "role_arn": role, "network_checkable": True,
            "network": {"direct_internet": exposed, "in_vpc": not exposed, "public_egress": False},
            "data_bearing": False}


def test_aispm01_privesc_role():
    s, g = _svc([_notebook(exposed=False)],
                principals=[_principal(AI_ROLE, [_stmt({"*"}, {"*"})])])
    s._collect_aispm(g)
    assert "FAIL" in _status(s, "AISPM-01")


def test_aispm02_reaches_crown():
    db = f"arn:aws:dynamodb:us-east-1:{ACCT}:table/customers"
    s, g = _svc([_notebook(exposed=False)],
                principals=[_principal(AI_ROLE, [_stmt({"dynamodb:getitem"}, {"*"})])],
                crown_db=db)
    s._collect_aispm(g)
    assert "FAIL" in _status(s, "AISPM-02")


def test_aispm03_network_exposed_fail_then_isolated_pass():
    s, g = _svc([_notebook(exposed=True)],
                principals=[_principal(AI_ROLE, [_stmt({"s3:getobject"}, {"arn:aws:s3:::x/*"})])])
    s._collect_aispm(g)
    assert "FAIL" in _status(s, "AISPM-03")
    s2, g2 = _svc([_notebook(exposed=False)], principals=[_principal(AI_ROLE, [])])
    s2._collect_aispm(g2)
    assert "PASS" in _status(s2, "AISPM-03")


def test_has_role_edge_emitted():
    s, g = _svc([_notebook(exposed=False)], principals=[_principal(AI_ROLE, [])])
    s._collect_aispm(g)
    assert any(e["kind"] == "HAS_ROLE" and e["dst"] == AI_ROLE for e in g.out_edges(NB_ID))


def test_aipath01_fused_when_exposed_and_privesc():
    s, g = _svc([_notebook(exposed=True)],
                principals=[_principal(AI_ROLE, [_stmt({"*"}, {"*"})])])
    s._collect_aispm(g)
    assert "FAIL" in _status(s, "AIPATH-01")


def test_aipath01_not_fired_when_isolated():
    # isolated -> even a privesc role does not fuse an AIPATH (no egress leg)
    s, g = _svc([_notebook(exposed=False)],
                principals=[_principal(AI_ROLE, [_stmt({"*"}, {"*"})])])
    s._collect_aispm(g)
    assert not _status(s, "AIPATH-01")


def test_aipath01_not_fired_when_role_benign():
    # exposed but the role neither escalates nor reaches crown -> no fused path (honest)
    s, g = _svc([_notebook(exposed=True)],
                principals=[_principal(AI_ROLE, [_stmt({"s3:getobject"}, {"arn:aws:s3:::x/*"})])])
    s._collect_aispm(g)
    assert not _status(s, "AIPATH-01")


def test_domain_marked_crown_and_picked_up_post_clobber():
    dom = {"kind": "SageMakerDomain", "name": "studio",
           "arn": f"arn:aws:sagemaker:us-east-1:{ACCT}:domain/d-1", "role_arn": AI_ROLE,
           "network_checkable": True,
           "network": {"direct_internet": False, "in_vpc": True, "public_egress": False},
           "data_bearing": True}
    s, g = _svc([dom], principals=[_principal(AI_ROLE, [])])
    s._collect_aispm(g)
    dom_id = f"arn:aws:sagemaker:us-east-1:{ACCT}:domain/d-1"
    assert dom_id in aws_correlate.crown_nodes(g)        # prop-based pickup, no correlate edit


def test_unresolvable_role_info_no_phantom_pass():
    s, g = _svc([_notebook(exposed=False, role=f"arn:aws:iam::{ACCT}:role/ghost")], principals=[])
    s._collect_aispm(g)
    assert "INFO" in _status(s, "AISPM-00")
    assert not _status(s, "AISPM-01") and not _status(s, "AISPM-02")


def test_no_resources_noop():
    s, g = _svc([], principals=[])
    s._collect_aispm(g)
    assert not [r for r in s.results if r.check_id.startswith(("AISPM", "AIPATH"))]


# ── aws_correlate no-change invariant (AISPM must not special-case any AI kind) ──
def test_correlate_edge_kinds_unchanged():
    assert "HAS_ROLE" in aws_correlate.E_PATH
    assert "CAN_READ_DATA" in aws_correlate.E_PATH
    assert "THREAT_ON" not in aws_correlate.E_PATH


def test_correlate_has_no_ai_special_casing():
    src = open(aws_correlate.__file__, encoding="utf-8").read().lower()
    for token in ("aispm", "aipath", "sagemaker", "bedrock", "ai_resource"):
        assert token not in src, f"aws_correlate special-cases {token!r}"


# ── B1 metadata lockstep: every AISPM FAIL-able id in all 3 maps + finding_detail ──
def test_aispm_maps_lockstep():
    import aws_finding_detail as D
    allowed = {"CIS", "PCI-DSS", "HIPAA", "SOC2", "NIST"}
    for cid in ("AISPM-01", "AISPM-02", "AISPM-03", "AIPATH-01"):
        assert cid in A.CHECK_SEVERITY
        assert cid in A.COMPLIANCE_MAP
        assert cid in A.REMEDIATION_MAP
        assert set(A.COMPLIANCE_MAP[cid]) <= allowed
        assert "aws " in A.REMEDIATION_MAP[cid].lower()
        assert cid in D.FINDING_DETAIL
