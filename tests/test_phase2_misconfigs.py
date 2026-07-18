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
