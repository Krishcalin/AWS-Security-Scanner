"""Phase 2 marquee-misconfig checks (OverWatch vuln roadmap): KMS-02/04 key-policy
public/cross-account, SEC-05 secret policy, IAMPE-23 federated trust, R53-06 dangling
DNS, CW-01..16 CloudWatch CIS §4, LOG-07..10 CloudTrail depth, COG-05/06 Cognito
identity pools. Reuses the mocked-boto3 harness from test_live_scanner; no AWS creds."""
import json
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aws_live_scanner as A
from test_live_scanner import MockClientError, MockPaginator, make_scanner

OWN = "123456789012"       # make_scanner sets scanner.account to this
EXT = "999999999999"


# ── classify_resource_policy_stmt (shared public/cross-account classifier) ────
def _c(stmt, own=OWN):
    return A.classify_resource_policy_stmt(stmt, own)


def test_classify_public_wildcard():
    assert _c({"Effect": "Allow", "Principal": "*", "Action": "kms:*"})["kind"] == "public"
    assert _c({"Effect": "Allow", "Principal": {"AWS": "*"}})["kind"] == "public"
    assert _c({"Effect": "Allow", "Principal": {"AWS": ["*", f"arn:aws:iam::{OWN}:root"]}})["kind"] == "public"


def test_classify_public_conditioned():
    r = _c({"Effect": "Allow", "Principal": "*",
            "Condition": {"StringEquals": {"aws:username": "bob"}}})
    assert r["kind"] == "public_conditioned"


def test_classify_wildcard_scoped_to_own_is_private():
    # Principal "*" + kms:CallerAccount == own -> NOT public (the #1 FP trap)
    assert _c({"Effect": "Allow", "Principal": "*",
               "Condition": {"StringEquals": {"kms:CallerAccount": OWN}}}) is None


def test_classify_wildcard_scoped_to_other_account():
    r = _c({"Effect": "Allow", "Principal": "*",
            "Condition": {"StringEquals": {"aws:SourceAccount": EXT}}})
    assert r["kind"] == "cross_account" and r["external_accounts"] == [EXT]


def test_classify_org_scoped():
    r = _c({"Effect": "Allow", "Principal": "*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}})
    assert r["kind"] == "org" and r["org_id"] == "o-abc123"


def test_classify_cross_account_explicit():
    assert _c({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"}})["kind"] == "cross_account"
    assert _c({"Effect": "Allow", "Principal": {"AWS": EXT}})["external_accounts"] == [EXT]  # bare 12-digit id


def test_classify_own_and_service_and_deny_are_none():
    assert _c({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OWN}:root"}}) is None
    assert _c({"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}}) is None
    assert _c({"Effect": "Deny", "Principal": "*"}) is None
    assert _c({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OWN}:role/app"}}) is None


def test_classify_notprincipal_is_public():
    assert _c({"Effect": "Allow", "NotPrincipal": {"AWS": f"arn:aws:iam::{OWN}:root"},
               "Action": "kms:*"})["kind"] == "public"


# ── KMS-02 / KMS-04 integration ──────────────────────────────────────────────
def _kms_scanner(meta, policies):
    s = make_scanner(["KMS"])
    kms = MagicMock()
    kms.get_paginator.return_value = MockPaginator("Keys", [{"KeyId": k} for k in meta])
    kms.describe_key.side_effect = lambda KeyId: {"KeyMetadata": meta[KeyId]}
    kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
    kms.get_key_policy.side_effect = lambda KeyId, PolicyName: {"Policy": policies.get(KeyId, "{}")}
    s._clients["kms:us-east-1"] = kms
    return s


def _cmk(arn_suffix):
    return {"KeyManager": "CUSTOMER", "KeyState": "Enabled",
            "Arn": f"arn:aws:kms:us-east-1:{OWN}:key/{arn_suffix}", "MultiRegion": False}


def test_kms_02_public_and_kms_04_crossaccount():
    pub = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*",
                                     "Action": "kms:*", "Resource": "*"}]})
    root = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OWN}:root"},
                                      "Action": "kms:*", "Resource": "*"}]})
    cross = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"},
                                       "Action": "kms:Decrypt", "Resource": "*"}]})
    s = _kms_scanner({"k-pub": _cmk("k-pub"), "k-clean": _cmk("k-clean"), "k-cross": _cmk("k-cross")},
                     {"k-pub": pub, "k-clean": root, "k-cross": cross})
    s._check_kms()
    assert any(r.check_id == "KMS-02" and r.status == "FAIL" and r.resource == "k-pub" for r in s.results)
    assert any(r.check_id == "KMS-04" and r.status == "FAIL" and r.resource == "k-cross"
               and EXT in r.message for r in s.results)
    # the default root-only key policy is benign — no FAIL
    assert not any(r.check_id in ("KMS-02", "KMS-04") and r.status == "FAIL" and r.resource == "k-clean"
                   for r in s.results)
    st = s.graph.stats()
    assert "PUBLIC_KMS" in st["edge_kinds"] and "SHARED_KMS" in st["edge_kinds"]


def test_kms_02_skips_aws_managed_keys():
    aws_key = {"KeyManager": "AWS", "KeyState": "Enabled", "Arn": "arn:...:key/aws"}
    s = _kms_scanner({"k-aws": aws_key},
                     {"k-aws": json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*"}]})})
    s._check_kms()
    assert not any(r.check_id in ("KMS-02", "KMS-04") for r in s.results)   # AWS-managed skipped


def test_kms_02_org_share_warns_not_fails():
    org = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"},
                                     "Action": "kms:Decrypt", "Resource": "*",
                                     "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-xyz"}}}]})
    s = _kms_scanner({"k-org": _cmk("k-org")}, {"k-org": org})
    s._check_kms()
    assert any(r.check_id == "KMS-04" and r.status == "WARN" and "o-xyz" in r.message for r in s.results)
    assert not any(r.check_id == "KMS-04" and r.status == "FAIL" for r in s.results)


def test_kms_02_get_key_policy_denied_warns():
    s = _kms_scanner({"k-deny": _cmk("k-deny")}, {})
    s._clients["kms:us-east-1"].get_key_policy.side_effect = RuntimeError("AccessDeniedException")
    s._check_kms()
    assert any(r.check_id == "KMS-02" and r.status == "WARN" and "could not evaluate" in r.message
               for r in s.results)


def test_kms_02_trusted_account_suppressed():
    cross = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"},
                                       "Action": "kms:Decrypt", "Resource": "*"}]})
    s = _kms_scanner({"k-t": _cmk("k-t")}, {"k-t": cross})
    s.trusted_accounts = {EXT}
    s._check_kms()
    assert not any(r.check_id == "KMS-04" and r.status == "FAIL" for r in s.results)


def test_kms_02_04_map_entries_complete():
    for cid in ("KMS-02", "KMS-04"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP
        assert "aws " in A.REMEDIATION_MAP.get(cid, "").lower()


# ── SEC-05 — Secrets Manager resource policy public / cross-account ───────────
def _secrets_scanner(secrets, policies):
    s = make_scanner(["SECRETS"])
    sm = MagicMock()
    sm.get_paginator.return_value = MockPaginator("SecretList", secrets)
    sm.get_resource_policy.side_effect = lambda SecretId: (
        {"ResourcePolicy": policies[SecretId]} if SecretId in policies else {})
    s._clients["secretsmanager:us-east-1"] = sm
    return s


def _sec(arn, name):
    return {"ARN": arn, "Name": name, "RotationEnabled": True,
            "RotationRules": {"AutomaticallyAfterDays": 30}, "KmsKeyId": "arn:aws:kms:::key/cmk"}


def test_sec_05_public_and_crossaccount():
    pub = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*",
                                     "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]})
    cross = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"},
                                       "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]})
    own = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OWN}:root"},
                                     "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]})
    secrets = [_sec("arn:pub", "pub"), _sec("arn:cross", "cross"),
               _sec("arn:own", "own"), _sec("arn:nopol", "nopol")]
    s = _secrets_scanner(secrets, {"arn:pub": pub, "arn:cross": cross, "arn:own": own})
    s._check_secrets()
    assert any(r.check_id == "SEC-05" and r.status == "FAIL" and r.resource == "pub" for r in s.results)
    assert any(r.check_id == "SEC-05" and r.status == "FAIL" and r.resource == "cross"
               and EXT in r.message for r in s.results)
    # own-account-only policy and no-policy secret -> no SEC-05 noise
    assert not any(r.check_id == "SEC-05" and r.resource in ("own", "nopol") for r in s.results)
    assert "SHARED_SECRET" in s.graph.stats()["edge_kinds"]


def test_sec_05_denied_policy_is_silent():
    s = _secrets_scanner([_sec("arn:x", "x")], {})
    s._clients["secretsmanager:us-east-1"].get_resource_policy.side_effect = RuntimeError("AccessDenied")
    s._check_secrets()
    assert not any(r.check_id == "SEC-05" for r in s.results)   # per-secret error is swallowed, not a crash


def test_sec_05_map_complete():
    assert A.CHECK_SEVERITY.get("SEC-05") == "CRITICAL" and "SEC-05" in A.COMPLIANCE_MAP
    assert "aws " in A.REMEDIATION_MAP.get("SEC-05", "").lower()


# ── IAMPE-23 — federated OIDC/SAML wildcard trust ────────────────────────────
import aws_graph


def _role(name, trust):
    return {"type": "role", "name": name, "_node": f"arn:aws:iam::{OWN}:role/{name}", "trust": trust}


def _oidc(sub=None, host="token.actions.githubusercontent.com", aud="sts.amazonaws.com"):
    se = {}
    if aud is not None:
        se[f"{host}:aud"] = aud
    if sub is not None:
        se[f"{host}:sub"] = sub
    return {"effect": "Allow", "aws": [], "service": [],
            "federated": [f"arn:aws:iam::{OWN}:oidc-provider/{host}"],
            "actions": {"sts:assumerolewithwebidentity"}, "wildcard": False,
            "has_condition": bool(se), "condition": {"StringEquals": se} if se else None}


def _fed_scanner():
    s = make_scanner(["IAMPRIVESC"])
    s.graph = aws_graph.SecurityGraph()
    return s


def test_oidc_sub_scope_classification():
    f = A.AWSLiveScanner._oidc_sub_scope
    assert f([]) == "open"
    assert f(["*"]) == "open"
    assert f(["repo:my-org/*"]) == "org-wildcard"
    assert f(["repo:my-org/my-repo:*"]) == "branch-wildcard"
    assert f(["repo:my-org/my-repo:ref:refs/heads/main"]) == "concrete"
    # most-permissive wins across a list
    assert f(["repo:a/b:ref:refs/heads/main", "repo:a/*"]) == "org-wildcard"


def test_iampe_23_github_open_and_orgwildcard_fail():
    s = _fed_scanner()
    assert s._check_federated_trust(_role("gha", [_oidc(sub=None)])) is True    # aud only, no sub
    assert any(r.check_id == "IAMPE-23" and r.status == "FAIL" for r in s.results)
    s2 = _fed_scanner()
    s2._check_federated_trust(_role("gha2", [_oidc(sub="repo:my-org/*")]))
    assert any(r.check_id == "IAMPE-23" and r.status == "FAIL" for r in s2.results)


def test_iampe_23_concrete_sub_passes():
    s = _fed_scanner()
    assert s._check_federated_trust(
        _role("gha", [_oidc(sub="repo:my-org/my-repo:ref:refs/heads/main")])) is False
    assert not any(r.check_id == "IAMPE-23" for r in s.results)


def test_iampe_23_branch_wildcard_warns():
    s = _fed_scanner()
    s._check_federated_trust(_role("gha", [_oidc(sub="repo:my-org/my-repo:*")]))
    assert any(r.check_id == "IAMPE-23" and r.status == "WARN" for r in s.results)


def test_iampe_23_private_oidc_open_warns_not_critical():
    s = _fed_scanner()
    s._check_federated_trust(_role("eks", [_oidc(sub=None, host="oidc.eks.us-east-1.amazonaws.com/id/ABC")]))
    w = [r for r in s.results if r.check_id == "IAMPE-23"]
    assert w and all(r.status == "WARN" for r in w)   # private issuer -> WARN, never CRITICAL FAIL


def test_iampe_23_graph_edge_emitted():
    s = _fed_scanner()
    s._check_federated_trust(_role("gha", [_oidc(sub=None)]))
    st = s.graph.stats()
    assert "FederatedPrincipal" in st["node_kinds"] and "FEDERATED_CAN_ASSUME" in st["edge_kinds"]


def test_parse_trust_policy_carries_condition():
    doc = {"Statement": [{"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::1:oidc-provider/x"},
                          "Action": "sts:AssumeRoleWithWebIdentity",
                          "Condition": {"StringEquals": {"x:sub": "repo:o/r"}}}]}
    stmts = A.parse_trust_policy(doc)
    assert stmts[0]["condition"] == {"StringEquals": {"x:sub": "repo:o/r"}}


def test_iampe_23_map_complete():
    assert A.CHECK_SEVERITY.get("IAMPE-23") == "CRITICAL" and "IAMPE-23" in A.COMPLIANCE_MAP
    assert "aws " in A.REMEDIATION_MAP.get("IAMPE-23", "").lower()
