#!/usr/bin/env python3
"""Unit tests for AWS Live Security Scanner v2.1.0.

Uses unittest.mock to simulate boto3 API responses.
No AWS credentials required.

Run:  python -m pytest tests/ -v
      python -m unittest tests.test_live_scanner -v
"""

import sys
import os
import json
import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime, timezone, timedelta
from dataclasses import asdict

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_live_scanner import (
    AWSLiveScanner, Result, VERSION,
    compute_risk_score, score_to_grade,
    COMPLIANCE_MAP, REMEDIATION_MAP, CHECK_SEVERITY,
    SECTIONS, SECTION_LABELS,
    evaluate_privesc, IAM_PRIVESC_RULES,
    evaluate_privesc_scoped, resource_scope, IAM_PRIVESC_ASSUMEROLE,
    fails_threshold, diff_findings,
)

# Mock ClientError for tests (boto3 may not be installed)
class MockClientError(Exception):
    def __init__(self, code="TestError", message="test"):
        self.response = {"Error": {"Code": code, "Message": message}}
        super().__init__(message)


# ─── Helpers ─────────────────────────────────────────────────────────────────
def make_scanner(sections=None) -> AWSLiveScanner:
    """Create scanner with mocked boto3 — no real AWS calls.
    Overrides _client to return from _clients dict directly, bypassing boto3."""
    with patch("aws_live_scanner.HAS_BOTO3", True):
        scanner = AWSLiveScanner(region="us-east-1", verbose=False,
                                  sections=sections or ["IAM"])
        scanner.account = "123456789012"

    # Override _client to pull from pre-populated _clients dict
    original_client = scanner._client
    def mock_client(service, region=None):
        key = f"{service}:{region or scanner.region}"
        if key in scanner._clients:
            return scanner._clients[key]
        # Return a generic mock for unconfigured services
        m = MagicMock()
        scanner._clients[key] = m
        return m
    scanner._client = mock_client

    return scanner


class MockPaginator:
    """Mock boto3 paginator that yields one page."""
    def __init__(self, key, items):
        self._key = key
        self._items = items

    def paginate(self, **kwargs):
        return [{self._key: self._items}]


class _GAADPaginator:
    """Mock GetAccountAuthorizationDetails paginator — yields one page holding
    UserDetailList / GroupDetailList / RoleDetailList / Policies."""
    def __init__(self, page):
        self._page = page

    def paginate(self, **kwargs):
        return [self._page]


def _gaad_iam(users=None, roles=None, groups=None, policies=None):
    """Return a MagicMock IAM client whose only configured paginator is
    get_account_authorization_details (the single call _get_iam_principals now uses)."""
    page = {
        "UserDetailList":  users or [],
        "GroupDetailList": groups or [],
        "RoleDetailList":  roles or [],
        "Policies":        policies or [],
    }
    iam = MagicMock()
    iam.get_paginator.side_effect = lambda name: _GAADPaginator(page)
    return iam


# ─── Test: Core data structures ──────────────────────────────────────────────
class TestDataStructures(unittest.TestCase):

    def test_version(self):
        self.assertEqual(VERSION, "2.16.0")

    def test_sections_count(self):
        self.assertEqual(len(SECTIONS), 43)

    def test_all_sections_have_labels(self):
        for s in SECTIONS:
            self.assertIn(s, SECTION_LABELS)

    def test_result_dataclass_fields(self):
        r = Result("FAIL", "IAM-01", "IAM", "root", "test",
                    severity="CRITICAL",
                    compliance={"CIS": "1.5"},
                    remediation_cmd="aws iam ...")
        self.assertEqual(r.severity, "CRITICAL")
        self.assertEqual(r.compliance, {"CIS": "1.5"})
        self.assertEqual(r.remediation_cmd, "aws iam ...")

    def test_result_defaults(self):
        r = Result("PASS", "X-01", "X", "res", "msg")
        self.assertEqual(r.severity, "")
        self.assertEqual(r.compliance, {})
        self.assertEqual(r.remediation_cmd, "")


# ─── Test: Risk scoring ─────────────────────────────────────────────────────
class TestRiskScoring(unittest.TestCase):

    def test_perfect_score(self):
        results = [Result("PASS", "X-01", "X", "", "ok")]
        self.assertEqual(compute_risk_score(results), 100.0)

    def test_fail_reduces_score(self):
        results = [
            Result("FAIL", "X-01", "X", "", "bad", severity="HIGH"),
        ]
        self.assertEqual(compute_risk_score(results), 95.0)

    def test_critical_heavy_penalty(self):
        results = [
            Result("FAIL", "X-01", "X", "", "bad", severity="CRITICAL"),
        ]
        self.assertEqual(compute_risk_score(results), 85.0)

    def test_score_clamped_at_zero(self):
        results = [
            Result("FAIL", f"X-{i}", "X", "", "bad", severity="CRITICAL")
            for i in range(10)
        ]
        self.assertEqual(compute_risk_score(results), 0.0)

    def test_pass_results_no_penalty(self):
        results = [
            Result("PASS", "X-01", "X", "", "ok", severity="CRITICAL"),
        ]
        self.assertEqual(compute_risk_score(results), 100.0)

    def test_grade_a(self):
        self.assertEqual(score_to_grade(95), "A")
        self.assertEqual(score_to_grade(90), "A")

    def test_grade_b(self):
        self.assertEqual(score_to_grade(85), "B")

    def test_grade_f(self):
        self.assertEqual(score_to_grade(50), "F")
        self.assertEqual(score_to_grade(0), "F")


# ─── Test: Compliance and remediation maps ───────────────────────────────────
class TestMaps(unittest.TestCase):

    def test_compliance_map_has_iam(self):
        self.assertIn("IAM-01", COMPLIANCE_MAP)
        self.assertIn("CIS", COMPLIANCE_MAP["IAM-01"])
        self.assertIn("PCI-DSS", COMPLIANCE_MAP["IAM-01"])

    def test_remediation_map_has_entries(self):
        self.assertGreater(len(REMEDIATION_MAP), 20)
        for check_id, cmd in REMEDIATION_MAP.items():
            # Remediation should contain an AWS CLI command somewhere
            self.assertIn("aws ", cmd.lower(),
                          f"{check_id} remediation missing AWS CLI: {cmd[:60]}")

    def test_severity_map_covers_new_sections(self):
        new_checks = ["LMB-01", "EKS-01", "ECS-01", "SEC-01", "WAF-01",
                       "ELC-01", "OSR-01", "DDB-01", "SFN-01",
                       "APIGW-01", "ELB-01", "EBS-01", "RS-01", "EFS-01", "ACM-01",
                       "SM-01", "COG-01", "AGW2-01",
                       "IAMPE-01", "IAMPE-03", "IAMPE-10", "IAMPE-19", "IAMPE-20",
                       # Phase 5 managed-service vuln axis
                       "RDS-12", "AUR-01", "AUR-02", "AUR-03", "AUR-04", "AUR-05",
                       "ELC-05", "ELC-06", "OSR-06", "OSR-07",
                       "RS-06", "RS-07", "RSS-01", "RSS-02", "RSS-03", "RSS-04",
                       # Phase 6 per-service depth
                       "SSM-01", "SSM-02", "LT-01", "ASG-01", "AMI-02", "AMI-03",
                       "S3-09", "S3-10", "BCK-02", "BCK-03", "DDB-05",
                       "ECS-06", "ECS-07", "ECS-08", "EKS-06", "CNT-06", "LMB-06",
                       "CLB-01", "CLB-02", "VPC-05", "VPC-06", "WAF-05", "CFN-06",
                       "SM-05", "SM-06", "SM-07"]
        for c in new_checks:
            self.assertIn(c, CHECK_SEVERITY, f"{c} missing from CHECK_SEVERITY")


# ─── Test: _add method auto-populates fields ────────────────────────────────
class TestAddMethod(unittest.TestCase):

    def test_fail_populates_severity_and_compliance(self):
        scanner = make_scanner()
        scanner._add("FAIL", "IAM-01", "IAM", "root", "Root MFA missing")
        r = scanner.results[-1]
        self.assertEqual(r.severity, "CRITICAL")
        self.assertIn("CIS", r.compliance)
        self.assertTrue(r.remediation_cmd)

    def test_pass_no_severity(self):
        scanner = make_scanner()
        scanner._add("PASS", "IAM-01", "IAM", "root", "Root MFA ok")
        r = scanner.results[-1]
        self.assertEqual(r.severity, "")
        self.assertEqual(r.compliance, {})
        self.assertEqual(r.remediation_cmd, "")

    def test_warn_gets_low_severity(self):
        scanner = make_scanner()
        scanner._add("WARN", "EC2-05", "EC2", "i-123", "Public IP")
        r = scanner.results[-1]
        self.assertEqual(r.severity, "LOW")


# ─── Test: IAM checks ───────────────────────────────────────────────────────
class TestIAMChecks(unittest.TestCase):

    @patch("aws_live_scanner.ClientError", MockClientError, create=True)
    def test_root_mfa_disabled(self):
        scanner = make_scanner(["IAM"])
        iam = MagicMock()
        iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}
        }
        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {"MinimumPasswordLength": 14,
                               "RequireSymbols": True, "RequireNumbers": True,
                               "RequireUppercaseCharacters": True,
                               "MaxPasswordAge": 90, "PreventPasswordReuse": True,
                               "PasswordReusePrevention": 24}
        }
        scanner._clients["iam:us-east-1"] = iam
        scanner._cred_report = []
        scanner._all_regions = ["us-east-1"]

        aa = MagicMock()
        aa.list_analyzers.return_value = {"analyzers": []}
        scanner._clients["accessanalyzer:us-east-1"] = aa

        scanner._check_iam()

        fails = [r for r in scanner.results if r.status == "FAIL"]
        check_ids = [r.check_id for r in fails]
        self.assertIn("IAM-01", check_ids)
        self.assertIn("IAM-02", check_ids)

    @patch("aws_live_scanner.ClientError", MockClientError, create=True)
    def test_root_mfa_enabled(self):
        scanner = make_scanner(["IAM"])
        iam = MagicMock()
        iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        }
        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {"MinimumPasswordLength": 14,
                               "RequireSymbols": True, "RequireNumbers": True,
                               "RequireUppercaseCharacters": True,
                               "MaxPasswordAge": 90, "PreventPasswordReuse": True,
                               "PasswordReusePrevention": 24}
        }
        scanner._clients["iam:us-east-1"] = iam
        scanner._cred_report = []
        scanner._all_regions = ["us-east-1"]

        aa = MagicMock()
        aa.list_analyzers.return_value = {"analyzers": [{"arn": "x"}]}
        scanner._clients["accessanalyzer:us-east-1"] = aa

        scanner._check_iam()

        passes = [r for r in scanner.results
                  if r.status == "PASS" and r.check_id == "IAM-01"]
        self.assertTrue(passes)


# ─── Test: S3 checks ────────────────────────────────────────────────────────
class TestS3Checks(unittest.TestCase):

    def test_bpa_enabled(self):
        scanner = make_scanner(["S3"])
        s3 = MagicMock()
        s3c = MagicMock()
        s3c.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True
            }
        }
        s3.list_buckets.return_value = {"Buckets": []}
        scanner._clients = {"s3:us-east-1": s3, "s3control:us-east-1": s3c}
        scanner.account = "123456789012"

        scanner._check_s3()

        passes = [r for r in scanner.results
                  if r.status == "PASS" and r.check_id == "S3-01"]
        self.assertTrue(passes)


# ─── Test: Lambda checks ────────────────────────────────────────────────────
class TestLambdaChecks(unittest.TestCase):

    @patch("aws_live_scanner.ClientError", MockClientError, create=True)
    def test_deprecated_runtime_detected(self):
        scanner = make_scanner(["LAMBDA"])
        lmb = MagicMock()
        lmb.get_paginator.return_value = MockPaginator("Functions", [
            {"FunctionName": "old-fn", "Runtime": "python3.7",
             "Environment": {"Variables": {}}},
        ])
        lmb.get_policy.side_effect = MockClientError("ResourceNotFoundException")
        lmb.get_function_concurrency.return_value = {}
        scanner._clients["lambda:us-east-1"] = lmb

        scanner._check_lambda()

        fails = [r for r in scanner.results if r.status == "FAIL"]
        check_ids = [r.check_id for r in fails]
        self.assertIn("LMB-04", check_ids)

    @patch("aws_live_scanner.ClientError", MockClientError, create=True)
    def test_secret_in_env_var(self):
        scanner = make_scanner(["LAMBDA"])
        lmb = MagicMock()
        lmb.get_paginator.return_value = MockPaginator("Functions", [
            {"FunctionName": "leaky-fn", "Runtime": "python3.12",
             "Environment": {"Variables": {"DB_PASSWORD": "hunter2"}}},
        ])
        lmb.get_policy.side_effect = MockClientError("ResourceNotFoundException")
        lmb.get_function_concurrency.return_value = {}
        scanner._clients["lambda:us-east-1"] = lmb

        scanner._check_lambda()

        fails = [r for r in scanner.results
                 if r.status == "FAIL" and r.check_id == "LMB-03"]
        self.assertTrue(fails)
        self.assertIn("DB_PASSWORD", fails[0].message)


# ─── Test: DynamoDB checks ──────────────────────────────────────────────────
class TestDynamoDBChecks(unittest.TestCase):

    def test_pitr_disabled(self):
        scanner = make_scanner(["DYNAMODB"])
        ddb = MagicMock()
        ddb.get_paginator.return_value = MockPaginator("TableNames", ["my-table"])
        ddb.describe_table.return_value = {"Table": {
            "TableName": "my-table",
            "SSEDescription": {"SSEType": "KMS"},
            "DeletionProtectionEnabled": True,
            "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
        }}
        ddb.describe_continuous_backups.return_value = {
            "ContinuousBackupsDescription": {
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "DISABLED"
                }
            }
        }
        scanner._clients = {"dynamodb:us-east-1": ddb}

        scanner._check_dynamodb()

        fails = [r for r in scanner.results
                 if r.status == "FAIL" and r.check_id == "DDB-02"]
        self.assertTrue(fails)


# ─── Test: EKS checks ───────────────────────────────────────────────────────
class TestEKSChecks(unittest.TestCase):

    def test_public_endpoint(self):
        scanner = make_scanner(["EKS"])
        eks = MagicMock()
        eks.list_clusters.return_value = {"clusters": ["test-cluster"]}
        eks.describe_cluster.return_value = {"cluster": {
            "name": "test-cluster",
            "resourcesVpcConfig": {
                "endpointPublicAccess": True,
                "publicAccessCidrs": ["0.0.0.0/0"],
                "securityGroupIds": ["sg-123"],
            },
            "logging": {"clusterLogging": [
                {"types": ["api", "audit", "authenticator",
                           "controllerManager", "scheduler"],
                 "enabled": True}
            ]},
            "encryptionConfig": [{"resources": ["secrets"]}],
            "version": "1.29", "platformVersion": "eks.8",
        }}
        scanner._clients = {"eks:us-east-1": eks}

        scanner._check_eks()

        fails = [r for r in scanner.results
                 if r.status == "FAIL" and r.check_id == "EKS-01"]
        self.assertTrue(fails)


# ─── Test: ElastiCache checks ───────────────────────────────────────────────
class TestElastiCacheChecks(unittest.TestCase):

    def test_no_encryption(self):
        scanner = make_scanner(["ELASTICACHE"])
        ec = MagicMock()
        ec.describe_replication_groups.return_value = {
            "ReplicationGroups": [{
                "ReplicationGroupId": "my-redis",
                "AtRestEncryptionEnabled": False,
                "TransitEncryptionEnabled": False,
                "AuthTokenEnabled": False,
                "AutomaticFailover": "disabled",
            }]
        }
        scanner._clients = {"elasticache:us-east-1": ec}

        scanner._check_elasticache()

        fails = [r for r in scanner.results if r.status == "FAIL"]
        check_ids = [r.check_id for r in fails]
        self.assertIn("ELC-01", check_ids)
        self.assertIn("ELC-02", check_ids)
        self.assertIn("ELC-03", check_ids)


# ─── Test: JSON report ──────────────────────────────────────────────────────
class TestJSONReport(unittest.TestCase):

    def test_json_includes_new_fields(self):
        import tempfile
        scanner = make_scanner()
        scanner._add("FAIL", "IAM-01", "IAM", "root", "Root MFA missing")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name

        try:
            scanner.save_json(path)
            with open(path, "r") as f:
                data = json.load(f)
            self.assertIn("posture_score", data)
            self.assertIn("posture_grade", data)
            r = data["results"][0]
            self.assertEqual(r["severity"], "CRITICAL")
            self.assertIn("CIS", r["compliance"])
            self.assertTrue(r["remediation_cmd"])
        finally:
            os.unlink(path)


# ─── Test: API Gateway checks ────────────────────────────────────────────────
class TestAPIGatewayChecks(unittest.TestCase):

    def test_no_logging_no_waf(self):
        scanner = make_scanner(["APIGATEWAY"])
        apigw = MagicMock()
        apigw.get_rest_apis.return_value = {
            "items": [{"id": "abc123", "name": "my-api"}]
        }
        apigw.get_stages.return_value = {"item": [{
            "stageName": "prod",
            "methodSettings": {"*/*": {"loggingLevel": "OFF",
                                       "cacheDataEncrypted": False}},
            "cacheClusterEnabled": False,
            "tracingEnabled": False,
        }]}
        scanner._clients = {"apigateway:us-east-1": apigw}

        scanner._check_apigateway()

        fails = [r.check_id for r in scanner.results if r.status == "FAIL"]
        self.assertIn("APIGW-01", fails)
        self.assertIn("APIGW-02", fails)

    def test_logging_and_waf_pass(self):
        scanner = make_scanner(["APIGATEWAY"])
        apigw = MagicMock()
        apigw.get_rest_apis.return_value = {
            "items": [{"id": "abc123", "name": "secure-api"}]
        }
        apigw.get_stages.return_value = {"item": [{
            "stageName": "prod",
            "accessLogSettings": {"destinationArn": "arn:aws:logs:::lg"},
            "webAclArn": "arn:aws:wafv2:::acl",
            "methodSettings": {"*/*": {"loggingLevel": "INFO"}},
            "cacheClusterEnabled": True,
            "tracingEnabled": True,
        }]}
        scanner._clients = {"apigateway:us-east-1": apigw}

        scanner._check_apigateway()

        passes = [r.check_id for r in scanner.results if r.status == "PASS"]
        self.assertIn("APIGW-01", passes)
        self.assertIn("APIGW-02", passes)
        # cache enabled but cacheDataEncrypted absent -> FAIL APIGW-03
        fails = [r.check_id for r in scanner.results if r.status == "FAIL"]
        self.assertIn("APIGW-03", fails)


# ─── Test: ELB checks ────────────────────────────────────────────────────────
class TestELBChecks(unittest.TestCase):

    def test_no_logging_weak_tls_http_no_redirect(self):
        scanner = make_scanner(["ELB"])
        elb = MagicMock()
        elb.get_paginator.return_value = MockPaginator("LoadBalancers", [{
            "LoadBalancerArn": "arn:lb", "LoadBalancerName": "web-alb",
            "Type": "application",
        }])
        elb.describe_load_balancer_attributes.return_value = {"Attributes": [
            {"Key": "access_logs.s3.enabled", "Value": "false"},
            {"Key": "deletion_protection.enabled", "Value": "false"},
            {"Key": "routing.http.drop_invalid_header_fields.enabled", "Value": "false"},
        ]}
        elb.describe_listeners.return_value = {"Listeners": [
            {"Protocol": "HTTP", "Port": 80, "DefaultActions": [{"Type": "forward"}]},
            {"Protocol": "HTTPS", "Port": 443,
             "SslPolicy": "ELBSecurityPolicy-2016-08", "DefaultActions": []},
        ]}
        scanner._clients = {"elbv2:us-east-1": elb}

        scanner._check_elb()

        fails = [r.check_id for r in scanner.results if r.status == "FAIL"]
        self.assertIn("ELB-01", fails)   # no access logging
        self.assertIn("ELB-02", fails)   # HTTP without redirect
        self.assertIn("ELB-03", fails)   # weak TLS policy
        self.assertIn("ELB-05", fails)   # drop invalid headers off


# ─── Test: EBS checks ────────────────────────────────────────────────────────
class TestEBSChecks(unittest.TestCase):

    def test_unencrypted_and_public(self):
        scanner = make_scanner(["EBS"])
        ec2 = MagicMock()
        ec2.get_ebs_encryption_by_default.return_value = {
            "EbsEncryptionByDefault": False}

        def paginator_for(name):
            if name == "describe_volumes":
                return MockPaginator("Volumes", [
                    {"VolumeId": "vol-1", "Encrypted": False}])
            if name == "describe_snapshots":
                # both describe_snapshots calls share this; first lists owned,
                # second lists public — return based on call kwargs handled below
                return _SnapPaginator()
            return MockPaginator("X", [])

        class _SnapPaginator:
            def paginate(self, **kwargs):
                if kwargs.get("RestorableByUserIds") == ["all"]:
                    return [{"Snapshots": [{"SnapshotId": "snap-pub"}]}]
                return [{"Snapshots": [
                    {"SnapshotId": "snap-1", "Encrypted": False}]}]

        ec2.get_paginator.side_effect = paginator_for
        scanner._clients = {"ec2:us-east-1": ec2}

        scanner._check_ebs()

        fails = [r.check_id for r in scanner.results if r.status == "FAIL"]
        self.assertIn("EBS-01", fails)   # encryption by default off
        self.assertIn("EBS-02", fails)   # unencrypted volume
        self.assertIn("EBS-03", fails)   # unencrypted snapshot
        self.assertIn("EBS-04", fails)   # public snapshot


# ─── Test: Redshift checks ───────────────────────────────────────────────────
class TestRedshiftChecks(unittest.TestCase):

    def test_unencrypted_public_cluster(self):
        scanner = make_scanner(["REDSHIFT"])
        rs = MagicMock()
        rs.describe_clusters.return_value = {"Clusters": [{
            "ClusterIdentifier": "analytics",
            "Encrypted": False,
            "PubliclyAccessible": True,
            "EnhancedVpcRouting": False,
            "MasterUsername": "awsuser",
        }]}
        rs.describe_logging_status.return_value = {"LoggingEnabled": False}
        scanner._clients = {"redshift:us-east-1": rs}

        scanner._check_redshift()

        fails = [r.check_id for r in scanner.results if r.status == "FAIL"]
        warns = [r.check_id for r in scanner.results if r.status == "WARN"]
        self.assertIn("RS-01", fails)
        self.assertIn("RS-02", fails)
        self.assertIn("RS-03", fails)
        self.assertIn("RS-04", fails)
        self.assertIn("RS-05", warns)


# ─── Test: EFS checks ────────────────────────────────────────────────────────
class TestEFSChecks(unittest.TestCase):

    def test_unencrypted_no_policy(self):
        scanner = make_scanner(["EFS"])
        efs = MagicMock()
        efs.describe_file_systems.return_value = {"FileSystems": [{
            "FileSystemId": "fs-123", "Name": "shared", "Encrypted": False,
        }]}
        efs.describe_file_system_policy.side_effect = Exception("no policy")
        efs.describe_backup_policy.return_value = {
            "BackupPolicy": {"Status": "DISABLED"}}
        scanner._clients = {"efs:us-east-1": efs}

        scanner._check_efs()

        fails = [r.check_id for r in scanner.results if r.status == "FAIL"]
        self.assertIn("EFS-01", fails)   # unencrypted
        self.assertIn("EFS-02", fails)   # no TLS policy


# ─── Test: ACM checks ────────────────────────────────────────────────────────
class TestACMChecks(unittest.TestCase):

    def test_expired_and_unused(self):
        scanner = make_scanner(["ACM"])
        acm = MagicMock()
        acm.get_paginator.return_value = MockPaginator("CertificateSummaryList", [
            {"CertificateArn": "arn:cert1", "DomainName": "old.example.com"},
        ])
        acm.describe_certificate.return_value = {"Certificate": {
            "DomainName": "old.example.com",
            "NotAfter": datetime.now(timezone.utc) - timedelta(days=5),
            "KeyAlgorithm": "RSA_1024",
            "InUseBy": [],
        }}
        scanner._clients = {"acm:us-east-1": acm}

        scanner._check_acm()

        fails = [r.check_id for r in scanner.results if r.status == "FAIL"]
        warns = [r.check_id for r in scanner.results if r.status == "WARN"]
        self.assertIn("ACM-01", fails)   # expired
        self.assertIn("ACM-02", fails)   # weak key algorithm
        self.assertIn("ACM-03", warns)   # unused


# ─── Test: SageMaker checks ──────────────────────────────────────────────────
class TestSageMakerChecks(unittest.TestCase):

    def test_insecure_notebook(self):
        scanner = make_scanner(["SAGEMAKER"])
        sm = MagicMock()
        sm.list_notebook_instances.return_value = {
            "NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        sm.describe_notebook_instance.return_value = {
            "DirectInternetAccess": "Enabled",
            "RootAccess": "Enabled",
            # no KmsKeyId, no SubnetId
        }
        scanner._clients = {"sagemaker:us-east-1": sm}

        scanner._check_sagemaker()

        fails = [r.check_id for r in scanner.results if r.status == "FAIL"]
        self.assertIn("SM-01", fails)   # direct internet
        self.assertIn("SM-02", fails)   # root access
        self.assertIn("SM-03", fails)   # no KMS
        self.assertIn("SM-04", fails)   # not in VPC

    def test_hardened_notebook(self):
        scanner = make_scanner(["SAGEMAKER"])
        sm = MagicMock()
        sm.list_notebook_instances.return_value = {
            "NotebookInstances": [{"NotebookInstanceName": "nb-secure"}]}
        sm.describe_notebook_instance.return_value = {
            "DirectInternetAccess": "Disabled",
            "RootAccess": "Disabled",
            "KmsKeyId": "arn:aws:kms:::key/abc",
            "SubnetId": "subnet-123",
        }
        scanner._clients = {"sagemaker:us-east-1": sm}

        scanner._check_sagemaker()

        self.assertEqual([r for r in scanner.results if r.status == "FAIL"], [])


# ─── Test: Cognito checks ────────────────────────────────────────────────────
class TestCognitoChecks(unittest.TestCase):

    def test_weak_pool(self):
        scanner = make_scanner(["COGNITO"])
        cog = MagicMock()
        cog.list_user_pools.return_value = {
            "UserPools": [{"Id": "pool-1", "Name": "users"}]}
        cog.describe_user_pool.return_value = {"UserPool": {
            "MfaConfiguration": "OFF",
            "Policies": {"PasswordPolicy": {
                "MinimumLength": 6, "RequireUppercase": False,
                "RequireLowercase": True, "RequireNumbers": False,
                "RequireSymbols": False}},
            "UserPoolAddOns": {"AdvancedSecurityMode": "OFF"},
            "DeletionProtection": "INACTIVE",
        }}
        scanner._clients = {"cognito-idp:us-east-1": cog}

        scanner._check_cognito()

        fails = [r.check_id for r in scanner.results if r.status == "FAIL"]
        warns = [r.check_id for r in scanner.results if r.status == "WARN"]
        self.assertIn("COG-01", fails)   # MFA off
        self.assertIn("COG-02", fails)   # weak password policy
        self.assertIn("COG-03", fails)   # advanced security off
        self.assertIn("COG-04", warns)   # deletion protection off

    def test_optional_mfa_warns(self):
        scanner = make_scanner(["COGNITO"])
        cog = MagicMock()
        cog.list_user_pools.return_value = {
            "UserPools": [{"Id": "pool-2", "Name": "opt"}]}
        cog.describe_user_pool.return_value = {"UserPool": {
            "MfaConfiguration": "OPTIONAL",
            "Policies": {"PasswordPolicy": {
                "MinimumLength": 12, "RequireUppercase": True,
                "RequireLowercase": True, "RequireNumbers": True,
                "RequireSymbols": True}},
            "UserPoolAddOns": {"AdvancedSecurityMode": "ENFORCED"},
            "DeletionProtection": "ACTIVE",
        }}
        scanner._clients = {"cognito-idp:us-east-1": cog}

        scanner._check_cognito()

        warns = [r.check_id for r in scanner.results if r.status == "WARN"]
        self.assertIn("COG-01", warns)


# ─── Test: API Gateway v2 (HTTP APIs) checks ─────────────────────────────────
class TestAPIGatewayV2Checks(unittest.TestCase):

    def test_no_logging_open_route(self):
        scanner = make_scanner(["APIGATEWAYV2"])
        api2 = MagicMock()
        api2.get_apis.return_value = {
            "Items": [{"ApiId": "h1", "Name": "http-api", "ProtocolType": "HTTP"}]}
        api2.get_stages.return_value = {"Items": [{
            "StageName": "$default",
            "DefaultRouteSettings": {},
        }]}
        api2.get_routes.return_value = {"Items": [
            {"RouteKey": "GET /public", "AuthorizationType": "NONE"},
            {"RouteKey": "GET /private", "AuthorizationType": "JWT"},
        ]}
        scanner._clients = {"apigatewayv2:us-east-1": api2}

        scanner._check_apigatewayv2()

        fails = [r.check_id for r in scanner.results if r.status == "FAIL"]
        warns = [r.check_id for r in scanner.results if r.status == "WARN"]
        self.assertIn("AGW2-01", fails)   # no access logging
        self.assertIn("AGW2-02", fails)   # open route
        self.assertIn("AGW2-03", warns)   # no throttling

    def test_secure_api(self):
        scanner = make_scanner(["APIGATEWAYV2"])
        api2 = MagicMock()
        api2.get_apis.return_value = {
            "Items": [{"ApiId": "h2", "Name": "secure-http"}]}
        api2.get_stages.return_value = {"Items": [{
            "StageName": "prod",
            "AccessLogSettings": {"DestinationArn": "arn:aws:logs:::lg"},
            "DefaultRouteSettings": {"ThrottlingBurstLimit": 100,
                                     "ThrottlingRateLimit": 50},
        }]}
        api2.get_routes.return_value = {"Items": [
            {"RouteKey": "GET /data", "AuthorizationType": "AWS_IAM"},
        ]}
        scanner._clients = {"apigatewayv2:us-east-1": api2}

        scanner._check_apigatewayv2()

        passes = [r.check_id for r in scanner.results if r.status == "PASS"]
        self.assertIn("AGW2-01", passes)
        self.assertIn("AGW2-02", passes)
        self.assertIn("AGW2-03", passes)


# ─── Test: IAM privilege-escalation engine (pure evaluator) ──────────────────
class TestIAMPrivescEngine(unittest.TestCase):

    def _ids(self, allow, deny=None):
        return [r["id"] for r in evaluate_privesc(set(allow), set(deny or []))]

    def test_full_admin_short_circuits(self):
        # Literal "*" -> only IAMPE-19, not every rule
        self.assertEqual(self._ids(["*"]), ["IAMPE-19"])

    def test_create_policy_version(self):
        self.assertIn("IAMPE-01", self._ids(["iam:createpolicyversion"]))

    def test_iam_wildcard_surfaces_iam_paths(self):
        ids = self._ids(["iam:*"])
        for cid in ("IAMPE-01", "IAMPE-03", "IAMPE-04", "IAMPE-08"):
            self.assertIn(cid, ids)
        self.assertNotIn("IAMPE-19", ids)   # iam:* is not full admin

    def test_attach_policy_wildcard_match(self):
        # "iam:Attach*" should cover iam:AttachUserPolicy
        self.assertIn("IAMPE-03", self._ids(["iam:attach*"]))

    def test_passrole_requires_second_action(self):
        self.assertEqual(self._ids(["iam:passrole"]), [])
        self.assertIn("IAMPE-10",
                      self._ids(["iam:passrole", "ec2:runinstances"]))

    def test_lambda_requires_create_and_invoke(self):
        # create without invoke -> no path
        self.assertEqual(
            self._ids(["iam:passrole", "lambda:createfunction"]), [])
        # create + invoke -> IAMPE-11
        self.assertIn("IAMPE-11", self._ids(
            ["iam:passrole", "lambda:createfunction", "lambda:invokefunction"]))

    def test_explicit_deny_overrides_allow(self):
        self.assertEqual(
            self._ids(["iam:attachuserpolicy"], ["iam:attachuserpolicy"]), [])
        # deny by wildcard also blocks
        self.assertEqual(self._ids(["iam:attachuserpolicy"], ["iam:*"]), [])

    def test_readonly_principal_no_paths(self):
        self.assertEqual(
            self._ids(["s3:get*", "ec2:describe*", "cloudwatch:list*"]), [])

    def test_all_rules_have_severity(self):
        ids = ([r["id"] for r in IAM_PRIVESC_RULES]
               + ["IAMPE-19", IAM_PRIVESC_ASSUMEROLE["id"]])
        for cid in ids:
            self.assertIn(cid, CHECK_SEVERITY, f"{cid} missing severity")


# ─── Test: resource-aware privesc scoping ────────────────────────────────────
class TestPrivescResourceScoping(unittest.TestCase):

    def _scoped(self, doc):
        stmts = AWSLiveScanner._policy_to_statements(doc)
        return {f["id"]: f.get("scope") for f in evaluate_privesc_scoped(stmts)}

    def test_passrole_scope_label(self):
        scoped = self._scoped({"Statement": [{"Effect": "Allow",
            "Action": ["iam:PassRole", "ec2:RunInstances"],
            "Resource": ["arn:aws:iam::123:role/app"]}]})
        self.assertEqual(scoped.get("IAMPE-10"), "resource-scoped")

        broad = self._scoped({"Statement": [{"Effect": "Allow",
            "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}]})
        self.assertEqual(broad.get("IAMPE-10"), "account-wide")

    def test_assumerole_only_when_unrestricted(self):
        # scoped AssumeRole -> NOT flagged (the false positive resource-awareness removes)
        scoped = self._scoped({"Statement": [{"Effect": "Allow",
            "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::123:role/ci"}]})
        self.assertNotIn("IAMPE-20", scoped)
        # AssumeRole on * -> IAMPE-20
        broad = self._scoped({"Statement": [{"Effect": "Allow",
            "Action": "sts:AssumeRole", "Resource": "*"}]})
        self.assertIn("IAMPE-20", broad)

    def test_action_star_on_single_resource_is_not_admin(self):
        # Action * scoped to one S3 bucket: not full admin, and IAM actions don't
        # apply to an S3 resource -> no privesc findings at all.
        scoped = self._scoped({"Statement": [{"Effect": "Allow",
            "Action": "*", "Resource": "arn:aws:s3:::mybucket/*"}]})
        self.assertEqual(scoped, {})

    def test_true_full_admin(self):
        scoped = self._scoped({"Statement": [{"Effect": "Allow",
            "Action": "*", "Resource": "*"}]})
        self.assertEqual(list(scoped.keys()), ["IAMPE-19"])

    def test_resource_scope_service_filtering(self):
        stmts = AWSLiveScanner._policy_to_statements({"Statement": [{"Effect": "Allow",
            "Action": "iam:PassRole", "Resource": "arn:aws:iam::123:role/x"}]})
        label, arns = resource_scope(stmts, "iam:passrole")
        self.assertEqual(label, "resource-scoped")
        self.assertEqual(arns, ["arn:aws:iam::123:role/x"])
        # A non-iam resource is not relevant to an iam action
        stmts2 = AWSLiveScanner._policy_to_statements({"Statement": [{"Effect": "Allow",
            "Action": "iam:PassRole", "Resource": "arn:aws:s3:::bucket"}]})
        self.assertEqual(resource_scope(stmts2, "iam:passrole"), ("none", None))

    def test_missing_resource_treated_as_broad(self):
        scoped = self._scoped({"Statement": [{"Effect": "Allow",
            "Action": "iam:AttachUserPolicy"}]})
        self.assertEqual(scoped.get("IAMPE-03"), "account-wide")


# ─── Test: policy document parsing ───────────────────────────────────────────
class TestPolicyParsing(unittest.TestCase):

    def test_dict_document(self):
        doc = {"Statement": [
            {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"],
             "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
        ]}
        allow, deny = AWSLiveScanner._policy_to_action_sets(doc)
        self.assertIn("iam:passrole", allow)
        self.assertIn("ec2:runinstances", allow)
        self.assertIn("s3:deletebucket", deny)

    def test_url_encoded_string_document(self):
        import urllib.parse
        raw = json.dumps({"Statement": {
            "Effect": "Allow", "Action": "iam:*", "Resource": "*"}})
        encoded = urllib.parse.quote(raw)
        allow, deny = AWSLiveScanner._policy_to_action_sets(encoded)
        self.assertIn("iam:*", allow)

    def test_notaction_allow_over_approximates(self):
        doc = {"Statement": [
            {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}]}
        allow, _ = AWSLiveScanner._policy_to_action_sets(doc)
        self.assertIn("*", allow)


# ─── Test: IAM privesc section (mocked IAM client) ───────────────────────────
class TestIAMPrivescSection(unittest.TestCase):

    def _iam_with_user(self, policy_doc):
        """Build a mock IAM client exposing GetAccountAuthorizationDetails: one
        user 'alice' with a single inline policy."""
        return _gaad_iam(users=[{
            "UserName": "alice",
            "Arn": "arn:aws:iam::123456789012:user/alice",
            "UserPolicyList": [{"PolicyName": "inline", "PolicyDocument": policy_doc}],
            "AttachedManagedPolicies": [],
            "GroupList": [],
        }])

    def test_attach_policy_path_detected(self):
        scanner = make_scanner(["IAMPRIVESC"])
        iam = self._iam_with_user({"Statement": [
            {"Effect": "Allow", "Action": "iam:AttachUserPolicy",
             "Resource": "*"}]})
        scanner._clients = {"iam:us-east-1": iam}

        scanner._check_iam_privesc()

        fails = [r for r in scanner.results
                 if r.status == "FAIL" and r.check_id == "IAMPE-03"]
        self.assertTrue(fails)
        self.assertEqual(fails[0].severity, "CRITICAL")
        self.assertIn("alice", fails[0].resource)

    def test_full_admin_user_reports_only_19(self):
        scanner = make_scanner(["IAMPRIVESC"])
        iam = self._iam_with_user({"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        scanner._clients = {"iam:us-east-1": iam}

        scanner._check_iam_privesc()

        fail_ids = [r.check_id for r in scanner.results if r.status == "FAIL"]
        self.assertEqual(fail_ids, ["IAMPE-19"])

    def test_readonly_user_passes(self):
        scanner = make_scanner(["IAMPRIVESC"])
        iam = self._iam_with_user({"Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "ec2:DescribeInstances"],
             "Resource": "*"}]})
        scanner._clients = {"iam:us-east-1": iam}

        scanner._check_iam_privesc()

        fails = [r for r in scanner.results if r.status == "FAIL"]
        passes = [r for r in scanner.results
                  if r.status == "PASS" and r.check_id == "IAMPE-00"]
        self.assertEqual(fails, [])
        self.assertTrue(passes)


# ─── Test: workflow integration (SARIF / ASFF / fail-on / diff) ──────────────
class TestFailOnThreshold(unittest.TestCase):

    def _results(self, *sevs):
        return [Result("FAIL", f"X-{i}", "X", "r", "m", severity=s)
                for i, s in enumerate(sevs)]

    def test_fail_on_triggers_at_or_above(self):
        results = self._results("MEDIUM", "LOW")
        self.assertTrue(fails_threshold(results, "MEDIUM"))
        self.assertTrue(fails_threshold(results, "LOW"))
        self.assertFalse(fails_threshold(results, "HIGH"))
        self.assertFalse(fails_threshold(results, "CRITICAL"))

    def test_fail_on_ignores_warn_and_pass(self):
        results = [
            Result("WARN", "X-1", "X", "r", "m", severity="LOW"),
            Result("PASS", "X-2", "X", "r", "m", severity="CRITICAL"),
        ]
        self.assertFalse(fails_threshold(results, "LOW"))

    def test_critical_fail_trips_high_threshold(self):
        self.assertTrue(fails_threshold(self._results("CRITICAL"), "HIGH"))


class TestDiffFindings(unittest.TestCase):

    def test_new_and_resolved(self):
        current = [
            Result("FAIL", "IAM-01", "IAM", "root", "still bad", severity="CRITICAL"),
            Result("FAIL", "S3-03", "S3", "bucket-x", "newly bad", severity="HIGH"),
            Result("PASS", "S3-01", "S3", "bucket-y", "ok"),
        ]
        baseline = [
            {"status": "FAIL", "check_id": "IAM-01", "resource": "root", "message": "x"},
            {"status": "FAIL", "check_id": "VPC-01", "resource": "sg-1", "message": "fixed now"},
        ]
        d = diff_findings(current, baseline)
        new_keys = {(r.check_id, r.resource) for r in d["new"]}
        resolved_keys = {(x["check_id"], x["resource"]) for x in d["resolved"]}
        self.assertEqual(new_keys, {("S3-03", "bucket-x")})
        self.assertEqual(resolved_keys, {("VPC-01", "sg-1")})

    def test_pass_results_are_not_findings(self):
        current = [Result("PASS", "X-1", "X", "r", "ok")]
        d = diff_findings(current, [])
        self.assertEqual(d["new"], [])


class TestSarifOutput(unittest.TestCase):

    def _scanner_with_findings(self):
        scanner = make_scanner()
        scanner.account = "123456789012"
        scanner.results = [
            Result("FAIL", "IAMPE-19", "IAMPRIVESC", "user:bob",
                   "Full administrative access", severity="CRITICAL",
                   compliance={"CIS": "1.16"}, remediation_cmd="aws iam ..."),
            Result("WARN", "ACM-03", "ACM", "old.example.com",
                   "Certificate not associated", severity="LOW"),
            Result("PASS", "S3-01", "S3", "bucket", "BPA enabled"),
        ]
        return scanner

    def test_sarif_structure(self):
        import tempfile
        scanner = self._scanner_with_findings()
        path = tempfile.mktemp(suffix=".sarif")
        try:
            scanner.save_sarif(path)
            with open(path) as f:
                doc = json.load(f)
            self.assertEqual(doc["version"], "2.1.0")
            run = doc["runs"][0]
            # only FAIL + WARN become findings (PASS excluded)
            self.assertEqual(len(run["results"]), 2)
            self.assertEqual(len(run["tool"]["driver"]["rules"]), 2)
            # CRITICAL maps to error level
            crit = [r for r in run["results"] if r["ruleId"] == "IAMPE-19"][0]
            self.assertEqual(crit["level"], "error")
            self.assertIn("partialFingerprints", crit)
        finally:
            os.unlink(path)


class TestAsffOutput(unittest.TestCase):

    def test_asff_fields(self):
        import tempfile
        scanner = make_scanner()
        scanner.account = "123456789012"
        scanner.results = [
            Result("FAIL", "IAM-01", "IAM", "root", "Root MFA missing",
                   severity="CRITICAL", compliance={"CIS": "1.5", "NIST": "IA-2(1)"},
                   remediation_cmd="aws iam enable-mfa-device ..."),
            Result("PASS", "S3-01", "S3", "bucket", "ok"),
        ]
        path = tempfile.mktemp(suffix=".json")
        try:
            scanner.save_asff(path)
            with open(path) as f:
                findings = json.load(f)
            self.assertEqual(len(findings), 1)   # PASS excluded
            f0 = findings[0]
            self.assertEqual(f0["SchemaVersion"], "2018-10-08")
            self.assertEqual(f0["AwsAccountId"], "123456789012")
            self.assertEqual(f0["Severity"]["Label"], "CRITICAL")
            self.assertEqual(f0["Compliance"]["Status"], "FAILED")
            self.assertIn("CIS 1.5", f0["Compliance"]["RelatedRequirements"])
            self.assertTrue(f0["Remediation"]["Recommendation"]["Text"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
