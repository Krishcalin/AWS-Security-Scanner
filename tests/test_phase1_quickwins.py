"""Phase 1 quick-win checks (OverWatch vuln/misconfig roadmap): EC2-08 (SSRF choke),
IAM-07/08 (root recent-use + unused-credential-45d), KMS-03 (pending-deletion/disabled
CMK), ACM-04/05 (unhealthy status + renewal risk). Reuses the mocked-boto3 harness
from test_live_scanner; no AWS credentials, no network."""
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aws_live_scanner as A
from test_live_scanner import MockClientError, MockPaginator, make_scanner


def _ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _ids(results, status=None):
    return [r for r in results if (status is None or r.status == status)]


# ── module-level credential-age helpers ──────────────────────────────────────
def test_cred_age_days():
    assert A._cred_age_days("N/A") is None
    assert A._cred_age_days("no_information") is None
    assert A._cred_age_days("") is None
    assert A._cred_age_days("garbage") is None
    assert A._cred_age_days(_ago(10)) in (9, 10, 11)


def test_cred_idle_days_prefers_last_used_then_created():
    assert A._cred_idle_days("N/A", _ago(100)) in (99, 100, 101)   # never used -> since created
    assert A._cred_idle_days(_ago(3), _ago(100)) in (2, 3, 4)      # used -> since last use
    assert A._cred_idle_days("N/A", "N/A") is None                 # nothing usable -> skip


# ── EC2-08 — SSRF-to-credential choke (public IP + IMDSv1) ───────────────────
def _ec2_scanner(instances):
    s = make_scanner(["EC2"])
    ec2 = MagicMock()
    ec2.get_paginator.return_value = MockPaginator("Reservations", [{"Instances": instances}])
    ec2.describe_volumes.return_value = {"Volumes": []}
    s._clients["ec2:us-east-1"] = ec2
    return s


def test_ec2_08_flags_only_public_imdsv1():
    s = _ec2_scanner([
        {"InstanceId": "i-1", "PublicIpAddress": "1.2.3.4",
         "MetadataOptions": {"HttpTokens": "optional"}, "Tags": [{"Key": "Name", "Value": "web"}]},
        {"InstanceId": "i-2", "PublicIpAddress": "5.6.7.8",
         "MetadataOptions": {"HttpTokens": "required"}},       # IMDSv2 -> safe
        {"InstanceId": "i-3", "MetadataOptions": {"HttpTokens": "optional"}},  # no public IP -> safe
    ])
    s._check_ec2()
    fails = [r for r in s.results if r.check_id == "EC2-08" and r.status == "FAIL"]
    assert len(fails) == 1 and "web" in fails[0].resource
    assert fails[0].severity == "HIGH"


def test_ec2_08_clean_when_imdsv2():
    s = _ec2_scanner([{"InstanceId": "i-9", "PublicIpAddress": "9.9.9.9",
                       "MetadataOptions": {"HttpTokens": "required"}}])
    s._check_ec2()
    assert not any(r.check_id == "EC2-08" for r in s.results)


# ── IAM-07 / IAM-08 (credential report) ──────────────────────────────────────
def _iam_scanner():
    s = make_scanner(["IAM"])
    iam = MagicMock()
    iam.get_account_summary.return_value = {
        "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}}
    iam.get_account_password_policy.return_value = {"PasswordPolicy": {
        "MinimumPasswordLength": 14, "RequireSymbols": True, "RequireNumbers": True,
        "RequireUppercaseCharacters": True, "MaxPasswordAge": 90,
        "PreventPasswordReuse": True, "PasswordReusePrevention": 24}}
    s._clients["iam:us-east-1"] = iam
    s._all_regions = ["us-east-1"]
    aa = MagicMock(); aa.list_analyzers.return_value = {"analyzers": [{"arn": "x"}]}
    s._clients["accessanalyzer:us-east-1"] = aa
    return s


_ROOT_IDLE = {"user": "<root_account>", "password_last_used": "N/A",
              "access_key_1_last_used_date": "N/A", "access_key_2_last_used_date": "N/A"}


@patch("aws_live_scanner.ClientError", MockClientError, create=True)
def test_iam_07_root_recent_use_fails():
    s = _iam_scanner()
    s._cred_report = [{"user": "<root_account>", "password_last_used": _ago(3),
                       "access_key_1_last_used_date": "N/A", "access_key_2_last_used_date": "N/A"}]
    s._check_iam()
    assert any(r.check_id == "IAM-07" and r.status == "FAIL" for r in s.results)


@patch("aws_live_scanner.ClientError", MockClientError, create=True)
def test_iam_07_root_idle_passes():
    s = _iam_scanner()
    s._cred_report = [{"user": "<root_account>", "password_last_used": _ago(200),
                       "access_key_1_last_used_date": "no_information",
                       "access_key_2_last_used_date": "N/A"}]
    s._check_iam()
    assert any(r.check_id == "IAM-07" and r.status == "PASS" for r in s.results)
    assert not any(r.check_id == "IAM-07" and r.status == "FAIL" for r in s.results)


@patch("aws_live_scanner.ClientError", MockClientError, create=True)
def test_iam_08_unused_key_and_password_fail():
    s = _iam_scanner()
    s._cred_report = [_ROOT_IDLE,
        {"user": "alice", "password_enabled": "false", "access_key_1_active": "true",
         "access_key_1_last_used_date": _ago(90), "access_key_1_last_rotated": _ago(90),
         "access_key_2_active": "false"},
        {"user": "carol", "password_enabled": "true", "password_last_used": _ago(120),
         "user_creation_time": _ago(200), "access_key_1_active": "false", "access_key_2_active": "false"}]
    s._check_iam()
    f = [r for r in s.results if r.check_id == "IAM-08" and r.status == "FAIL"]
    res = {r.resource for r in f}
    assert any("alice" in x for x in res) and "carol" in res


@patch("aws_live_scanner.ClientError", MockClientError, create=True)
def test_iam_08_active_credentials_not_flagged():
    s = _iam_scanner()
    s._cred_report = [_ROOT_IDLE,
        {"user": "bob", "password_enabled": "true", "password_last_used": _ago(5),
         "user_creation_time": _ago(5), "access_key_1_active": "true",
         "access_key_1_last_used_date": _ago(2), "access_key_1_last_rotated": _ago(2),
         "access_key_2_active": "false"}]
    s._check_iam()
    assert not any(r.check_id == "IAM-08" for r in s.results)


# ── KMS-03 — pending-deletion / disabled CMK ─────────────────────────────────
def test_kms_03_pending_deletion_and_disabled():
    s = make_scanner(["KMS"])
    kms = MagicMock()
    kms.get_paginator.return_value = MockPaginator(
        "Keys", [{"KeyId": "k-del"}, {"KeyId": "k-dis"}, {"KeyId": "k-ok"}])
    meta = {"k-del": {"KeyManager": "CUSTOMER", "KeyState": "PendingDeletion",
                      "DeletionDate": "2026-09-01"},
            "k-dis": {"KeyManager": "CUSTOMER", "KeyState": "Disabled"},
            "k-ok": {"KeyManager": "CUSTOMER", "KeyState": "Enabled", "Description": "prod"}}
    kms.describe_key.side_effect = lambda KeyId: {"KeyMetadata": meta[KeyId]}
    kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
    s._clients["kms:us-east-1"] = kms
    s._check_kms()
    k3 = [r for r in s.results if r.check_id == "KMS-03" and r.status == "FAIL"]
    assert {r.resource for r in k3} == {"k-del", "k-dis"}
    assert all(r.severity == "HIGH" for r in k3)
    # the enabled key still runs its rotation check, unaffected
    assert any(r.check_id == "ENC-03" for r in s.results)


# ── ACM-04 / ACM-05 — unhealthy status + renewal risk ────────────────────────
def test_acm_04_failed_and_05_imported():
    s = make_scanner(["ACM"])
    acm = MagicMock()
    acm.list_certificates.return_value = {"CertificateSummaryList": [
        {"CertificateArn": "arn:failed"}, {"CertificateArn": "arn:imported"},
        {"CertificateArn": "arn:ineligible"}]}
    certs = {
        "arn:failed": {"DomainName": "bad.example", "Status": "FAILED", "Type": "AMAZON_ISSUED"},
        "arn:imported": {"DomainName": "imp.example", "Status": "ISSUED", "Type": "IMPORTED",
                         "InUseBy": ["x"]},
        "arn:ineligible": {"DomainName": "elig.example", "Status": "ISSUED",
                           "Type": "AMAZON_ISSUED", "RenewalEligibility": "INELIGIBLE"}}
    acm.describe_certificate.side_effect = lambda CertificateArn: {"Certificate": certs[CertificateArn]}
    s._clients["acm:us-east-1"] = acm
    s._check_acm()
    assert any(r.check_id == "ACM-04" and r.status == "FAIL" and "bad.example" in r.resource
               for r in s.results)
    a5 = [r for r in s.results if r.check_id == "ACM-05" and r.status == "WARN"]
    assert {r.resource for r in a5} == {"imp.example", "elig.example"}
    # exactly one ACM-04 (the FAILED cert); the healthy imported/eligible certs don't fire it
    a4 = [r for r in s.results if r.check_id == "ACM-04"]
    assert len(a4) == 1 and a4[0].resource == "bad.example"


# ── VULN-04 — Lambda dependency vuln un-dropped (was `continue # defer Lambda`) ─
class _P:
    def __init__(self, items):
        self.items = items
    def paginate(self, **kw):
        return [{"findings": self.items}]


def _inspector(findings, ec2="ENABLED", ecr="ENABLED"):
    m = MagicMock()
    m.batch_get_account_status.return_value = {
        "accounts": [{"resourceState": {"ec2": {"status": ec2}, "ecr": {"status": ecr}}}]}
    m.get_paginator.return_value = _P(findings)
    m.batch_get_finding_details.return_value = {"findingDetails": []}   # no KEV
    return m


def test_vuln_04_lambda_dependency_undropped():
    f = {"findingArn": "arn:finding/lam", "severity": "HIGH", "exploitAvailable": "NO",
         "fixAvailable": "YES", "epss": {"score": 0.3},
         "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2024-0001"},
         "resources": [{"id": "arn:aws:lambda:us-east-1:1:function:pay",
                        "type": "AWS_LAMBDA_FUNCTION"}]}
    s = make_scanner(["VULN"])
    s._clients["inspector2:us-east-1"] = _inspector([f])
    with patch("builtins.print"):
        s._check_vuln()
    fails = {r.check_id for r in s.results if r.status == "FAIL"}
    assert "VULN-04" in fails                          # was silently dropped before
    st = s.graph.stats()
    assert "LambdaFunction" in st["node_kinds"] and "HAS_VULN" in st["edge_kinds"]


def test_vuln_04_map_entries_complete():
    assert A.CHECK_SEVERITY.get("VULN-04") == "HIGH"
    assert "VULN-04" in A.COMPLIANCE_MAP
    assert "aws " in A.REMEDIATION_MAP.get("VULN-04", "").lower()
