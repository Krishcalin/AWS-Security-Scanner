"""Phase 6 Batch B3 — S3 bucket-policy exposure: S3-09 public grant (BPA-neutralization
aware) + S3-10 cross-account/org grant (NOT BPA-neutralized). One get_bucket_policy call
feeds S3-07/09/10. Offline: MagicMock s3 + s3control."""
import json
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner

FULL_BPA = {"BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
NO_BPA = {"BlockPublicAcls": False, "IgnorePublicAcls": False,
          "BlockPublicPolicy": False, "RestrictPublicBuckets": False}


def _s3_scanner(policy, acct_bpa=NO_BPA, bucket_bpa=NO_BPA, policy_error=None, trusted=None):
    s = make_scanner(sections=["S3"])
    s.account = "111111111111"
    if trusted:
        s.trusted_accounts = set(trusted)
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "data"}]}
    s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": bucket_bpa}
    s3.get_bucket_encryption.side_effect = Exception("none")
    s3.get_bucket_logging.return_value = {}
    s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
    if policy_error:
        s3.get_bucket_policy.side_effect = policy_error
    else:
        s3.get_bucket_policy.return_value = {"Policy": json.dumps(policy)}
    s3c = MagicMock()
    s3c.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": acct_bpa}
    s._clients["s3:us-east-1"] = s3
    s._clients["s3control:us-east-1"] = s3c
    return s


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def _pub_stmt():
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::data/*"}]}


def _xacct_stmt(acct="999999999999"):
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:root"},
         "Action": "s3:GetObject", "Resource": "arn:aws:s3:::data/*"}]}


# ── S3-09 public grant ────────────────────────────────────────────────────────
def test_s3_09_public_no_bpa_fails():
    s = _s3_scanner(_pub_stmt(), acct_bpa=NO_BPA, bucket_bpa=NO_BPA)
    s._check_s3()
    assert "FAIL" in _status(s, "S3-09")


def test_s3_09_public_neutralized_by_bucket_bpa_warns():
    s = _s3_scanner(_pub_stmt(), acct_bpa=NO_BPA, bucket_bpa=FULL_BPA)
    s._check_s3()
    assert "WARN" in _status(s, "S3-09") and "FAIL" not in _status(s, "S3-09")


def test_s3_09_public_neutralized_by_account_bpa_warns():
    s = _s3_scanner(_pub_stmt(), acct_bpa=FULL_BPA, bucket_bpa=NO_BPA)
    s._check_s3()
    assert "WARN" in _status(s, "S3-09") and "FAIL" not in _status(s, "S3-09")


def test_s3_09_access_denied_policy_warns_not_silent():
    s = _s3_scanner(None, policy_error=Exception("AccessDenied when calling GetBucketPolicy"))
    s._check_s3()
    assert "WARN" in _status(s, "S3-09")


# ── S3-10 cross-account (NOT BPA-neutralized) ─────────────────────────────────
def test_s3_10_cross_account_fails_even_with_full_bpa():
    # a NAMED external account survives Block Public Access
    s = _s3_scanner(_xacct_stmt(), acct_bpa=FULL_BPA, bucket_bpa=FULL_BPA)
    s._check_s3()
    assert "FAIL" in _status(s, "S3-10")


def test_s3_10_trusted_account_suppressed():
    s = _s3_scanner(_xacct_stmt("999999999999"), trusted={"999999999999"})
    s._check_s3()
    assert "FAIL" not in _status(s, "S3-10")


def test_s3_10_org_share_warns():
    pol = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                          "Resource": "arn:aws:s3:::data/*",
                          "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}}]}
    s = _s3_scanner(pol)
    s._check_s3()
    assert "WARN" in _status(s, "S3-10")


def test_own_account_policy_no_exposure_finding():
    pol = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                          "Action": "s3:GetObject", "Resource": "arn:aws:s3:::data/*"}]}
    s = _s3_scanner(pol)
    s._check_s3()
    assert "FAIL" not in _status(s, "S3-09") and "FAIL" not in _status(s, "S3-10")


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("S3-09", "S3-10"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()
