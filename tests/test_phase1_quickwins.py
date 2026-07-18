"""Phase 1 quick-win checks (OverWatch vuln/misconfig roadmap): EC2-08 (SSRF choke),
IAM-07/08 (root recent-use + unused-credential-45d), KMS-03 (pending-deletion/disabled
CMK), ACM-04/05 (unhealthy status + renewal risk). Reuses the mocked-boto3 harness
from test_live_scanner; no AWS credentials, no network."""
import base64
import json
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


_PROF = {"Arn": "arn:aws:iam::1:instance-profile/web"}


def test_ec2_08_flags_only_public_imdsv1():
    s = _ec2_scanner([
        {"InstanceId": "i-1", "PublicIpAddress": "1.2.3.4", "IamInstanceProfile": _PROF,
         "MetadataOptions": {"HttpTokens": "optional"}, "Tags": [{"Key": "Name", "Value": "web"}]},
        {"InstanceId": "i-2", "PublicIpAddress": "5.6.7.8", "IamInstanceProfile": _PROF,
         "MetadataOptions": {"HttpTokens": "required"}},       # IMDSv2 -> safe
        {"InstanceId": "i-3", "IamInstanceProfile": _PROF,
         "MetadataOptions": {"HttpTokens": "optional"}},       # no public IP -> safe
    ])
    s._check_ec2()
    fails = [r for r in s.results if r.check_id == "EC2-08" and r.status == "FAIL"]
    assert len(fails) == 1 and "web" in fails[0].resource
    assert fails[0].severity == "HIGH"


def test_ec2_08_not_flagged_when_imds_endpoint_disabled():
    # public + IMDSv1 tokens, but the IMDS endpoint is off -> no SSRF-to-cred path
    s = _ec2_scanner([{"InstanceId": "i-x", "PublicIpAddress": "1.2.3.4",
                       "IamInstanceProfile": _PROF,
                       "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "disabled"}}])
    s._check_ec2()
    assert not any(r.check_id == "EC2-08" for r in s.results)


def test_ec2_08_not_flagged_without_role():
    # public + IMDSv1 but NO instance profile -> no role credentials to steal
    s = _ec2_scanner([{"InstanceId": "i-y", "PublicIpAddress": "1.2.3.4",
                       "MetadataOptions": {"HttpTokens": "optional"}}])
    s._check_ec2()
    assert not any(r.check_id == "EC2-08" for r in s.results)


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
    acm.get_paginator.return_value = MockPaginator("CertificateSummaryList", [
        {"CertificateArn": "arn:failed"}, {"CertificateArn": "arn:imported"},
        {"CertificateArn": "arn:ineligible"}])
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


# ── AMI-01 — self-owned AMI shared publicly / cross-account ──────────────────
def _ami_scanner(images, attrs=None):
    s = make_scanner(["AMI"])
    ec2 = MagicMock()
    ec2.describe_images.return_value = {"Images": images}
    attrs = attrs or {}
    ec2.describe_image_attribute.side_effect = lambda ImageId, Attribute: {
        "LaunchPermissions": attrs.get(ImageId, [])}
    s._clients["ec2:us-east-1"] = ec2
    return s


def test_ami_01_public_fails_and_shared_warns():
    s = _ami_scanner(
        [{"ImageId": "ami-pub", "Name": "golden", "Public": True},
         {"ImageId": "ami-share", "Name": "app", "Public": False},
         {"ImageId": "ami-priv", "Name": "internal", "Public": False}],
        attrs={"ami-share": [{"UserId": "999988887777"}], "ami-priv": []})
    s._check_ami()
    fails = [r for r in s.results if r.check_id == "AMI-01" and r.status == "FAIL"]
    warns = [r for r in s.results if r.check_id == "AMI-01" and r.status == "WARN"]
    assert len(fails) == 1 and "ami-pub" in fails[0].resource
    assert fails[0].severity == "HIGH"
    assert len(warns) == 1 and "999988887777" in warns[0].message
    # a mixed estate never emits the all-clear PASS
    assert not any(r.check_id == "AMI-01" and r.status == "PASS" for r in s.results)


def test_ami_01_group_all_launch_permission_fails():
    s = _ami_scanner([{"ImageId": "ami-x", "Name": "x", "Public": False}],
                     attrs={"ami-x": [{"Group": "all"}]})
    s._check_ami()
    assert any(r.check_id == "AMI-01" and r.status == "FAIL" and "ami-x" in r.resource
               for r in s.results)


def test_ami_01_all_private_passes():
    s = _ami_scanner([{"ImageId": "ami-a", "Name": "a", "Public": False},
                      {"ImageId": "ami-b", "Name": "b", "Public": False}],
                     attrs={"ami-a": [], "ami-b": []})
    s._check_ami()
    assert any(r.check_id == "AMI-01" and r.status == "PASS" for r in s.results)
    assert not any(r.check_id == "AMI-01" and r.status in ("FAIL", "WARN") for r in s.results)


def test_ami_01_no_images_is_info():
    s = _ami_scanner([])
    s._check_ami()
    assert any(r.check_id == "AMI-01" and r.status == "INFO" for r in s.results)


def test_ami_01_map_entries_complete():
    assert A.CHECK_SEVERITY.get("AMI-01") == "HIGH"
    assert "AMI-01" in A.COMPLIANCE_MAP
    assert "aws " in A.REMEDIATION_MAP.get("AMI-01", "").lower()


# ── CNT-02 — ECR native-scan CVE ingest (works even when Inspector is off) ────
def _ecr_scanner(repos, images=None, findings=None, findings_exc=None):
    s = make_scanner(["ECR"])
    ecr = MagicMock()
    ecr.describe_repositories.return_value = {"repositories": repos}
    ecr.get_paginator.return_value = MockPaginator("imageDetails", images or [])
    if findings_exc is not None:
        ecr.describe_image_scan_findings.side_effect = findings_exc
    else:
        ecr.describe_image_scan_findings.return_value = {
            "imageScanFindings": findings or {}}
    s._clients["ecr:us-east-1"] = ecr
    return s


_REPO = {"repositoryName": "app",
         "repositoryUri": "1.dkr.ecr.us-east-1.amazonaws.com/app",
         "imageScanningConfiguration": {"scanOnPush": True},
         "encryptionConfiguration": {"encryptionType": "AES256"}}


def test_cnt_02_ingests_high_critical_from_newest_image():
    s = _ecr_scanner(
        [_REPO],
        images=[{"imageDigest": "sha256:new", "imagePushedAt": 100, "imageTags": ["v2"]},
                {"imageDigest": "sha256:old", "imagePushedAt": 50, "imageTags": ["v1"]}],
        findings={"findings": [
            {"name": "CVE-2024-1", "severity": "CRITICAL"},
            {"name": "CVE-2024-2", "severity": "HIGH"},
            {"name": "CVE-2024-3", "severity": "MEDIUM"}]})   # filtered out
    s._check_ecr()
    c2 = [r for r in s.results if r.check_id == "CNT-02" and r.status == "FAIL"]
    assert len(c2) == 2 and all("app:v2" == r.resource for r in c2)
    st = s.graph.stats()
    assert "ECRImage" in st["node_kinds"] and "HAS_VULN" in st["edge_kinds"]
    # the newest image (by imagePushedAt) is the one scanned
    assert any("sha256:new" in (e.get("dst", "") + e.get("src", ""))
               for e in s.graph.edges("HAS_VULN"))


def test_cnt_02_enhanced_findings_shape():
    s = _ecr_scanner(
        [_REPO],
        images=[{"imageDigest": "sha256:e", "imagePushedAt": 1, "imageTags": []}],
        findings={"enhancedFindings": [
            {"severity": "HIGH",
             "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2025-9"}}]})
    s._check_ecr()
    assert any(r.check_id == "CNT-02" and "CVE-2025-9" in r.message for r in s.results)


def test_cnt_02_scan_not_found_is_silent():
    s = _ecr_scanner([_REPO],
                     images=[{"imageDigest": "sha256:z", "imagePushedAt": 1}],
                     findings_exc=RuntimeError("ScanNotFoundException"))
    s._check_ecr()
    assert not any(r.check_id == "CNT-02" for r in s.results)
    # CNT-01 still ran and passed
    assert any(r.check_id == "CNT-01" for r in s.results)


def test_cnt_02_no_images_no_findings():
    s = _ecr_scanner([_REPO], images=[])
    s._check_ecr()
    assert not any(r.check_id == "CNT-02" for r in s.results)


def test_cnt_02_map_entries_complete():
    assert A.CHECK_SEVERITY.get("CNT-02") == "HIGH"
    assert "CNT-02" in A.COMPLIANCE_MAP
    assert "aws " in A.REMEDIATION_MAP.get("CNT-02", "").lower()


# ── RDS-08 (IAM DB auth) / RDS-11 (unencrypted snapshot) ─────────────────────
def _rds_scanner(instances=None, snaps=None, snap_attrs=None):
    s = make_scanner(["RDS"])
    rds = MagicMock()

    def _pag(op):
        if op == "describe_db_snapshots":
            return MockPaginator("DBSnapshots", snaps or [])
        return MockPaginator("DBInstances", instances or [])
    rds.get_paginator.side_effect = _pag
    snap_attrs = snap_attrs or {}
    rds.describe_db_snapshot_attributes.side_effect = lambda DBSnapshotIdentifier: {
        "DBSnapshotAttributesResult": {
            "DBSnapshotAttributes": snap_attrs.get(DBSnapshotIdentifier, [])}}
    s._clients["rds:us-east-1"] = rds
    return s


def test_rds_08_iam_auth_only_supported_engines():
    s = _rds_scanner(instances=[
        {"DBInstanceIdentifier": "db-on", "Engine": "postgres",
         "IAMDatabaseAuthenticationEnabled": True},
        {"DBInstanceIdentifier": "db-off", "Engine": "mysql",
         "IAMDatabaseAuthenticationEnabled": False},
        {"DBInstanceIdentifier": "db-oracle", "Engine": "oracle-se2",
         "IAMDatabaseAuthenticationEnabled": False}])   # engine has no IAM auth -> skipped
    s._check_rds()
    warns = [r for r in s.results if r.check_id == "RDS-08" and r.status == "WARN"]
    assert {r.resource for r in warns} == {"db-off"}
    assert any(r.check_id == "RDS-08" and r.status == "PASS" and r.resource == "db-on"
               for r in s.results)
    assert not any(r.check_id == "RDS-08" and r.resource == "db-oracle" for r in s.results)
    assert A.CHECK_SEVERITY.get("RDS-08") == "MEDIUM"


def test_rds_11_unencrypted_snapshot_fails():
    s = _rds_scanner(snaps=[{"DBSnapshotIdentifier": "snap-enc", "Encrypted": True},
                            {"DBSnapshotIdentifier": "snap-plain", "Encrypted": False}])
    s._check_rds()
    f = [r for r in s.results if r.check_id == "RDS-11" and r.status == "FAIL"]
    assert {r.resource for r in f} == {"snap-plain"} and f[0].severity == "HIGH"
    # not an all-clear PASS because one snapshot is unencrypted
    assert not any(r.check_id == "RDS-11" and r.status == "PASS" for r in s.results)


def test_rds_11_all_encrypted_passes():
    s = _rds_scanner(snaps=[{"DBSnapshotIdentifier": "s1", "Encrypted": True},
                            {"DBSnapshotIdentifier": "s2", "Encrypted": True}])
    s._check_rds()
    assert any(r.check_id == "RDS-11" and r.status == "PASS" for r in s.results)
    assert not any(r.check_id == "RDS-11" and r.status == "FAIL" for r in s.results)


def test_rds_08_11_map_entries_complete():
    for cid in ("RDS-08", "RDS-11"):
        assert cid in A.COMPLIANCE_MAP
        assert "aws " in A.REMEDIATION_MAP.get(cid, "").lower()


# ── ELB-07 — HTTP desync mitigation mode (request-smuggling defense) ─────────
def _elb_scanner(lbs, attrs_by_arn=None, listeners=None):
    s = make_scanner(["ELB"])
    elb = MagicMock()
    elb.get_paginator.return_value = MockPaginator("LoadBalancers", lbs)
    attrs_by_arn = attrs_by_arn or {}
    elb.describe_load_balancer_attributes.side_effect = lambda LoadBalancerArn: {
        "Attributes": [{"Key": k, "Value": v}
                       for k, v in attrs_by_arn.get(LoadBalancerArn, {}).items()]}
    elb.describe_listeners.return_value = {"Listeners": listeners or []}
    s._clients["elbv2:us-east-1"] = elb
    return s


def test_elb_07_flags_monitor_mode_only():
    s = _elb_scanner(
        [{"LoadBalancerArn": "arn:mon", "LoadBalancerName": "mon-lb", "Type": "application"},
         {"LoadBalancerArn": "arn:str", "LoadBalancerName": "str-lb", "Type": "application"},
         {"LoadBalancerArn": "arn:def", "LoadBalancerName": "def-lb", "Type": "application"}],
        attrs_by_arn={"arn:mon": {"routing.http.desync_mitigation_mode": "monitor"},
                      "arn:str": {"routing.http.desync_mitigation_mode": "strictest"}})
                      # def-lb: attribute absent -> defaults to 'defensive' -> PASS
    s._check_elb()
    warns = [r for r in s.results if r.check_id == "ELB-07" and r.status == "WARN"]
    passes = [r for r in s.results if r.check_id == "ELB-07" and r.status == "PASS"]
    assert {r.resource for r in warns} == {"mon-lb"}
    assert {r.resource for r in passes} == {"str-lb", "def-lb"}


def test_elb_07_not_emitted_for_network_lb():
    s = _elb_scanner(
        [{"LoadBalancerArn": "arn:n", "LoadBalancerName": "net-lb", "Type": "network"}],
        attrs_by_arn={"arn:n": {"routing.http.desync_mitigation_mode": "monitor"}})
    s._check_elb()
    assert not any(r.check_id == "ELB-07" for r in s.results)
    assert A.CHECK_SEVERITY.get("ELB-07") == "MEDIUM"
    assert "ELB-07" in A.COMPLIANCE_MAP
    assert "aws " in A.REMEDIATION_MAP.get("ELB-07", "").lower()


# ── S3-07 (TLS-only policy) / S3-08 (versioning) ─────────────────────────────
def _s3_scanner(buckets, policies=None, versioning=None):
    s = make_scanner(["S3"])
    s3, s3c = MagicMock(), MagicMock()
    ok_bpa = {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}
    s3c.get_public_access_block.return_value = ok_bpa
    s3.get_public_access_block.return_value = ok_bpa
    s3.list_buckets.return_value = {"Buckets": [{"Name": b} for b in buckets]}
    s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}
    s3.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "x"}}
    policies = policies or {}

    def _pol(Bucket):
        if Bucket in policies:
            return {"Policy": policies[Bucket]}
        raise RuntimeError("NoSuchBucketPolicy")
    s3.get_bucket_policy.side_effect = _pol
    versioning = versioning or {}
    s3.get_bucket_versioning.side_effect = lambda Bucket: {"Status": versioning.get(Bucket)}
    s._clients["s3:us-east-1"] = s3
    s._clients["s3control:us-east-1"] = s3c
    return s


_TLS_POLICY = json.dumps({"Statement": [
    {"Effect": "Deny", "Principal": "*", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::with-tls", "arn:aws:s3:::with-tls/*"],
     "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]})


def _full_deny(**kw):
    base = {"Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": "arn:aws:s3:::b/*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
    base.update(kw)
    return base


def test_stmt_denies_insecure_transport():
    f = A.AWSLiveScanner._stmt_denies_insecure_transport
    # effective full-coverage denies
    assert f(_full_deny(), "b")
    assert f(_full_deny(Condition={"BoolIfExists": {"aws:SecureTransport": ["false"]}}), "b")
    assert f(_full_deny(Resource="*"), "b")
    assert f(_full_deny(Principal={"AWS": "*"}), "b")
    assert f(_full_deny(Action=["s3:*"]), "b")
    # ineffective / narrowly-scoped -> NOT full TLS enforcement
    assert not f(_full_deny(Effect="Allow"), "b")
    assert not f(_full_deny(Condition={"Bool": {"aws:SecureTransport": "true"}}), "b")
    assert not f(_full_deny(Action="s3:PutObject"), "b")                    # single action
    assert not f(_full_deny(Principal={"AWS": "arn:aws:iam::1:role/x"}), "b")  # single principal
    assert not f(_full_deny(Resource="arn:aws:s3:::b"), "b")                # bucket only, not objects
    assert not f({"Effect": "Deny"}, "b")                                   # no condition


def test_s3_07_tls_policy_present_vs_absent():
    s = _s3_scanner(["with-tls", "no-tls"], policies={"with-tls": _TLS_POLICY},
                    versioning={"with-tls": "Enabled", "no-tls": "Enabled"})
    s._check_s3()
    p = {r.resource for r in s.results if r.check_id == "S3-07" and r.status == "PASS"}
    w = {r.resource for r in s.results if r.check_id == "S3-07" and r.status == "WARN"}
    assert p == {"with-tls"} and w == {"no-tls"}


def test_s3_07_narrow_deny_is_not_pass():
    narrow = json.dumps({"Statement": [
        {"Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
         "Resource": "arn:aws:s3:::partial/*",
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]})
    s = _s3_scanner(["partial"], policies={"partial": narrow},
                    versioning={"partial": "Enabled"})
    s._check_s3()
    w = {r.resource for r in s.results if r.check_id == "S3-07" and r.status == "WARN"}
    assert w == {"partial"}   # a PutObject-only deny still leaves HTTP GET -> WARN, not PASS


def test_s3_08_versioning():
    s = _s3_scanner(["v-on", "v-off"], versioning={"v-on": "Enabled"})   # v-off -> None
    s._check_s3()
    p = {r.resource for r in s.results if r.check_id == "S3-08" and r.status == "PASS"}
    w = {r.resource for r in s.results if r.check_id == "S3-08" and r.status == "WARN"}
    assert p == {"v-on"} and w == {"v-off"}


def test_s3_07_08_map_entries_complete():
    for cid in ("S3-07", "S3-08"):
        assert cid in A.COMPLIANCE_MAP
        assert "aws " in A.REMEDIATION_MAP.get(cid, "").lower()


# ── VPC-04 — default Security Group must restrict all traffic (CIS 5.4) ──────
def _vpc_scanner(sgs, vpcs=None, flow_logs=None):
    s = make_scanner(["VPC"])
    ec2 = MagicMock()
    ec2.get_paginator.return_value = MockPaginator("SecurityGroups", sgs)
    ec2.describe_vpcs.return_value = {"Vpcs": vpcs or []}
    ec2.describe_flow_logs.return_value = {"FlowLogs": flow_logs or []}
    s._clients["ec2:us-east-1"] = ec2
    return s


def test_vpc_04_default_sg_with_rules_warns():
    s = _vpc_scanner([
        {"GroupId": "sg-def", "GroupName": "default", "VpcId": "vpc-1",
         "IpPermissions": [{"IpProtocol": "-1"}], "IpPermissionsEgress": [{"IpProtocol": "-1"}]},
        {"GroupId": "sg-app", "GroupName": "app", "VpcId": "vpc-1",
         "IpPermissions": [], "IpPermissionsEgress": []}])
    s._check_vpc()
    w = [r for r in s.results if r.check_id == "VPC-04" and r.status == "WARN"]
    assert len(w) == 1 and "sg-def" in w[0].resource
    assert not any(r.check_id == "VPC-04" and r.status == "PASS" for r in s.results)


def test_vpc_04_hardened_default_sg_passes():
    s = _vpc_scanner([{"GroupId": "sg-def", "GroupName": "default", "VpcId": "vpc-1",
                       "IpPermissions": [], "IpPermissionsEgress": []}])
    s._check_vpc()
    assert any(r.check_id == "VPC-04" and r.status == "PASS" for r in s.results)
    assert not any(r.check_id == "VPC-04" and r.status == "WARN" for r in s.results)


def test_vpc_04_no_default_sg_no_finding():
    s = _vpc_scanner([{"GroupId": "sg-app", "GroupName": "app", "VpcId": "vpc-1",
                       "IpPermissions": [], "IpPermissionsEgress": []}])
    s._check_vpc()
    assert not any(r.check_id == "VPC-04" for r in s.results)   # no default SG seen -> no PASS/WARN
    assert A.CHECK_SEVERITY.get("VPC-04") == "MEDIUM"
    assert "VPC-04" in A.COMPLIANCE_MAP
    assert "aws " in A.REMEDIATION_MAP.get("VPC-04", "").lower()


# ── EC2-07 — plaintext secret in instance user-data ──────────────────────────
def test_ec2_07_secret_in_user_data_fails():
    ud = base64.b64encode(
        b"#!/bin/bash\nexport K=-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n").decode()
    s = _ec2_scanner([{"InstanceId": "i-secret",
                       "MetadataOptions": {"HttpTokens": "required"},
                       "Tags": [{"Key": "Name", "Value": "boot"}]}])
    s._clients["ec2:us-east-1"].describe_instance_attribute.return_value = {
        "UserData": {"Value": ud}}
    s._check_ec2()
    f = [r for r in s.results if r.check_id == "EC2-07" and r.status == "FAIL"]
    assert len(f) == 1 and "boot" in f[0].resource and f[0].severity == "HIGH"


def test_ec2_07_gzip_user_data_fails():
    import gzip as _gz
    ud = base64.b64encode(_gz.compress(
        b"AKIAIOSFODNN7REALKEY\ntoken=ghp_" + b"a" * 36 + b"\n")).decode()
    s = _ec2_scanner([{"InstanceId": "i-gz", "MetadataOptions": {"HttpTokens": "required"}}])
    s._clients["ec2:us-east-1"].describe_instance_attribute.return_value = {
        "UserData": {"Value": ud}}
    s._check_ec2()
    assert any(r.check_id == "EC2-07" and r.status == "FAIL" for r in s.results)


def test_ec2_07_clean_user_data_no_finding():
    ud = base64.b64encode(b"#!/bin/bash\nyum update -y\n").decode()
    s = _ec2_scanner([{"InstanceId": "i-clean", "MetadataOptions": {"HttpTokens": "required"}}])
    s._clients["ec2:us-east-1"].describe_instance_attribute.return_value = {
        "UserData": {"Value": ud}}
    s._check_ec2()
    assert not any(r.check_id == "EC2-07" for r in s.results)


def test_ec2_07_no_user_data_no_finding():
    s = _ec2_scanner([{"InstanceId": "i-none", "MetadataOptions": {"HttpTokens": "required"}}])
    s._clients["ec2:us-east-1"].describe_instance_attribute.return_value = {"UserData": {}}
    s._check_ec2()
    assert not any(r.check_id == "EC2-07" for r in s.results)
    assert A.CHECK_SEVERITY.get("EC2-07") == "HIGH"
    assert "EC2-07" in A.COMPLIANCE_MAP
    assert "aws " in A.REMEDIATION_MAP.get("EC2-07", "").lower()


# ── LOG-06 — GuardDuty protection plans ──────────────────────────────────────
def test_log_06_guardduty_features():
    s = make_scanner(["LOGGING"])
    detector = {"Status": "ENABLED", "Features": [
        {"Name": "S3_DATA_EVENTS", "Status": "ENABLED"},
        {"Name": "RUNTIME_MONITORING", "Status": "DISABLED"},
        {"Name": "RDS_LOGIN_EVENTS", "Status": "DISABLED"},
        {"Name": "SOME_UNKNOWN_FEATURE", "Status": "DISABLED"}]}   # unknown -> ignored
    s._check_guardduty_features("det-1", detector)
    warns = {r.resource.split(":")[-1] for r in s.results
             if r.check_id == "LOG-06" and r.status == "WARN"}
    passes = {r.resource.split(":")[-1] for r in s.results
              if r.check_id == "LOG-06" and r.status == "PASS"}
    assert warns == {"RUNTIME_MONITORING", "RDS_LOGIN_EVENTS"}
    assert passes == {"S3_DATA_EVENTS"}


def test_log_06_legacy_api_silent():
    s = make_scanner(["LOGGING"])
    s._check_guardduty_features("det-1", {"Status": "ENABLED"})   # no Features key
    assert not any(r.check_id == "LOG-06" for r in s.results)


def test_log_06_map_entries_complete():
    assert A.CHECK_SEVERITY.get("LOG-06") == "MEDIUM"
    assert "LOG-06" in A.COMPLIANCE_MAP
    assert "aws " in A.REMEDIATION_MAP.get("LOG-06", "").lower()


# ── CVSS v3 vector-string base-score fix (aws_sidescan._cvss_base) ────────────
import aws_sidescan as SS


def test_cvss3_base_from_vector_known_scores():
    cases = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,   # critical RCE
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,   # unauth DoS
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,   # info leak
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,   # local privesc
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,   # reflected XSS (scope changed)
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,   # v3.0 also supported
    }
    for vec, want in cases.items():
        assert SS._cvss3_base_from_vector(vec) == want, vec


def test_cvss3_base_from_vector_rejects_non_v3():
    assert SS._cvss3_base_from_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None   # v2
    assert SS._cvss3_base_from_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N") is None  # v4
    assert SS._cvss3_base_from_vector("garbage") is None
    assert SS._cvss3_base_from_vector("") is None
    assert SS._cvss3_base_from_vector("CVSS:3.1/AV:X/AC:L") is None            # bad metric


def test_cvss_base_prefers_numeric_then_vector():
    # numeric score used directly
    assert SS._cvss_base({"severity": [{"type": "CVSS_V3", "score": "8.1"}]}) == 8.1
    # vector string computed (was previously dropped -> None -> wrong MEDIUM band)
    rec = {"severity": [{"type": "CVSS_V3",
                         "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert SS._cvss_base(rec) == 9.8
    assert SS._band(SS._cvss_base(rec)) == "CRITICAL"   # not the old MEDIUM fallback
    # no severity at all -> None
    assert SS._cvss_base({"severity": []}) is None


def test_scan_text_secrets_preview_only():
    """scan_text_secrets returns findings but never the raw secret (preview only)."""
    data = b"AKIAIOSFODNN7REALKEYX\n-----BEGIN RSA PRIVATE KEY-----\n"
    finds = SS.scan_text_secrets(data, source="userdata:i-1")
    kinds = {f.kind for f in finds}
    assert "private-key" in kinds
    for f in finds:
        assert "…" in f.match_preview and f.path == "userdata:i-1"


# ══════════════════════════════════════════════════════════════════════════════
# Regressions for the adversarial-verify fixes (17 confirmed defects)
# ══════════════════════════════════════════════════════════════════════════════
import aws_graph
from datetime import datetime as _dt, timezone as _tz


# EC2-07 AKIA entropy-gate fix — a realistic (sub-4.0-entropy) AWS key is now caught
def test_ec2_07_realistic_aws_key_detected():
    finds = SS.scan_text_secrets(b"AWS_ACCESS_KEY_ID=AKIAZ3XYK7QWMNBVCXZ2\n")
    assert any(f.kind == "aws-access-key" for f in finds)   # was dropped by the 4.0 gate


# CNT-02 max() datetime-vs-missing-field crash fix + scan_source (not 'source') prop
def test_cnt_02_datetime_pushed_at_no_crash_and_scan_source():
    imgs = [{"imageDigest": "sha256:new", "imageTags": ["v2"],
             "imagePushedAt": _dt(2026, 6, 1, tzinfo=_tz.utc)},
            {"imageDigest": "sha256:mid",                          # missing imagePushedAt
             "imageTags": ["v1"]},
            {"imageDigest": "sha256:old",
             "imagePushedAt": _dt(2026, 1, 1, tzinfo=_tz.utc)}]
    s = _ecr_scanner([_REPO], images=imgs,
                     findings={"findings": [{"name": "CVE-2026-1", "severity": "CRITICAL"}]})
    s._check_ecr()   # must not raise TypeError comparing datetime with int
    assert any(r.check_id == "CNT-02" and r.status == "FAIL" for r in s.results)
    edges = s.graph.to_dict()["edges"]
    hv = [e for e in edges if e["kind"] == "HAS_VULN"]
    assert hv, "HAS_VULN edge should serialize"
    # the reserved 'source' endpoint is the ECRImage node, NOT the literal scan tag
    assert hv[0]["source"].startswith(_REPO["repositoryUri"])
    assert hv[0]["source"] != "ecr-native-scan"
    assert hv[0].get("scan_source") == "ecr-native-scan"
    assert "sha256:new" in hv[0]["source"]   # newest image chosen despite the missing field


# aws_graph.to_dict hardening — a stray edge prop can't clobber the endpoint keys
def test_graph_to_dict_reserved_keys_win_over_props():
    g = aws_graph.SecurityGraph()
    g.add_node("img", "ECRImage")
    g.add_node("cve", "Vulnerability")
    g.add_edge("img", "cve", "HAS_VULN", source="SHOULD_NOT_WIN")
    e = [x for x in g.to_dict()["edges"] if x["kind"] == "HAS_VULN"][0]
    assert e["source"] == "img" and e["target"] == "cve"


# ACM fix — list is paginated AND passes an Includes.keyTypes filter (EC + RSA_3072/4096)
def test_acm_passes_keytypes_and_paginates():
    s = make_scanner(["ACM"])
    acm = MagicMock()
    pag = MagicMock()
    pag.paginate.return_value = [{"CertificateSummaryList": [{"CertificateArn": "arn:ec"}]}]
    acm.get_paginator.return_value = pag
    acm.describe_certificate.side_effect = lambda CertificateArn: {"Certificate": {
        "DomainName": "ec.example", "Status": "FAILED", "Type": "AMAZON_ISSUED"}}
    s._clients["acm:us-east-1"] = acm
    s._check_acm()
    acm.get_paginator.assert_called_with("list_certificates")
    kt = pag.paginate.call_args.kwargs["Includes"]["keyTypes"]
    assert "EC_prime256v1" in kt and "RSA_4096" in kt
    assert any(r.check_id == "ACM-04" for r in s.results)   # the EC cert is now evaluated


# RDS-11 pagination — an unencrypted snapshot on page 2 is still flagged
def test_rds_11_second_page_snapshot_flagged():
    s = make_scanner(["RDS"])
    rds = MagicMock()

    def _pag(op):
        if op == "describe_db_snapshots":
            p = MagicMock()
            p.paginate.return_value = [
                {"DBSnapshots": [{"DBSnapshotIdentifier": "s1", "Encrypted": True}]},
                {"DBSnapshots": [{"DBSnapshotIdentifier": "s2", "Encrypted": False}]}]
            return p
        return MockPaginator("DBInstances", [])
    rds.get_paginator.side_effect = _pag
    rds.describe_db_snapshot_attributes.return_value = {
        "DBSnapshotAttributesResult": {"DBSnapshotAttributes": []}}
    s._clients["rds:us-east-1"] = rds
    s._check_rds()
    f = [r for r in s.results if r.check_id == "RDS-11" and r.status == "FAIL"]
    assert {r.resource for r in f} == {"s2"}   # page-2 snapshot seen


# VULN-04 gate fix — Inspector Lambda-only account still emits VULN-04
def test_vuln_04_lambda_only_inspector_enabled():
    f = {"findingArn": "arn:finding/lam", "severity": "HIGH", "exploitAvailable": "NO",
         "fixAvailable": "YES", "epss": {"score": 0.3},
         "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2026-2"},
         "resources": [{"id": "arn:aws:lambda:us-east-1:1:function:pay",
                        "type": "AWS_LAMBDA_FUNCTION"}]}
    m = MagicMock()
    m.batch_get_account_status.return_value = {"accounts": [{"resourceState": {
        "ec2": {"status": "DISABLED"}, "ecr": {"status": "DISABLED"},
        "lambda": {"status": "ENABLED"}}}]}
    m.get_paginator.return_value = _P([f])
    m.batch_get_finding_details.return_value = {"findingDetails": []}
    s = make_scanner(["VULN"])
    s._clients["inspector2:us-east-1"] = m
    with patch("builtins.print"):
        s._check_vuln()
    assert any(r.check_id == "VULN-04" and r.status == "FAIL" for r in s.results)


# IAM-07 — an unavailable credential report surfaces a WARN, never silent absence
def test_iam_07_unavailable_report_warns():
    s = _iam_scanner()
    s._cred_report = []          # empty AND not ok -> report could not be evaluated
    s._cred_report_ok = False
    with patch("aws_live_scanner.ClientError", MockClientError, create=True):
        s._check_iam()
    assert any(r.check_id == "IAM-07" and r.status == "WARN" for r in s.results)


# IAM-08 — a freshly set, never-used password on an old user is NOT a 45d-unused finding
@patch("aws_live_scanner.ClientError", MockClientError, create=True)
def test_iam_08_recent_unused_password_not_flagged():
    s = _iam_scanner()
    s._cred_report = [_ROOT_IDLE,
        {"user": "dave", "password_enabled": "true", "password_last_used": "N/A",
         "password_last_changed": _ago(5), "user_creation_time": _ago(400),
         "access_key_1_active": "false", "access_key_2_active": "false"}]
    s._check_iam()
    assert not any(r.check_id == "IAM-08" and "dave" in r.resource for r in s.results)


# KMS-03 — a multi-Region key in PendingReplicaDeletion is flagged
def test_kms_03_pending_replica_deletion():
    s = make_scanner(["KMS"])
    kms = MagicMock()
    kms.get_paginator.return_value = MockPaginator("Keys", [{"KeyId": "k-rep"}])
    kms.describe_key.return_value = {"KeyMetadata": {
        "KeyManager": "CUSTOMER", "KeyState": "PendingReplicaDeletion"}}
    kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
    s._clients["kms:us-east-1"] = kms
    s._check_kms()
    assert any(r.check_id == "KMS-03" and r.status == "FAIL" and r.resource == "k-rep"
               for r in s.results)


# AMI-01 — an org/OU-shared (non-public) AMI is treated as a cross-account share
def test_ami_01_org_share_flagged():
    s = _ami_scanner([{"ImageId": "ami-org", "Name": "shared", "Public": False}],
                     attrs={"ami-org": [{"OrganizationArn":
                                         "arn:aws:organizations::1:organization/o-abc"}]})
    s._check_ami()
    w = [r for r in s.results if r.check_id == "AMI-01" and r.status == "WARN"]
    assert len(w) == 1 and "ami-org" in w[0].resource
    assert not any(r.check_id == "AMI-01" and r.status == "PASS" for r in s.results)


# VPC-04 pagination — a rule-bearing default SG on page 2 is still flagged
def test_vpc_04_default_sg_second_page():
    s = make_scanner(["VPC"])
    ec2 = MagicMock()
    pag = MagicMock()
    pag.paginate.return_value = [
        {"SecurityGroups": [{"GroupId": "sg-a", "GroupName": "app", "VpcId": "v",
                             "IpPermissions": [], "IpPermissionsEgress": []}]},
        {"SecurityGroups": [{"GroupId": "sg-def", "GroupName": "default", "VpcId": "v",
                             "IpPermissions": [{"IpProtocol": "-1"}], "IpPermissionsEgress": []}]}]
    ec2.get_paginator.return_value = pag
    ec2.describe_vpcs.return_value = {"Vpcs": []}
    ec2.describe_flow_logs.return_value = {"FlowLogs": []}
    s._clients["ec2:us-east-1"] = ec2
    s._check_vpc()
    assert any(r.check_id == "VPC-04" and r.status == "WARN" and "sg-def" in r.resource
               for r in s.results)


# ELB-07 pagination — a monitor-mode ALB on page 2 is still flagged
def test_elb_07_lb_second_page():
    s = make_scanner(["ELB"])
    elb = MagicMock()
    pag = MagicMock()
    pag.paginate.return_value = [
        {"LoadBalancers": [{"LoadBalancerArn": "arn:1", "LoadBalancerName": "p1",
                            "Type": "application"}]},
        {"LoadBalancers": [{"LoadBalancerArn": "arn:2", "LoadBalancerName": "mon-lb",
                            "Type": "application"}]}]
    elb.get_paginator.return_value = pag
    elb.describe_load_balancer_attributes.side_effect = lambda LoadBalancerArn: {
        "Attributes": [{"Key": "routing.http.desync_mitigation_mode",
                        "Value": "monitor" if LoadBalancerArn == "arn:2" else "defensive"}]}
    elb.describe_listeners.return_value = {"Listeners": []}
    s._clients["elbv2:us-east-1"] = elb
    s._check_elb()
    assert any(r.check_id == "ELB-07" and r.status == "WARN" and r.resource == "mon-lb"
               for r in s.results)
