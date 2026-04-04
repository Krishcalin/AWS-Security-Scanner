#!/usr/bin/env python3
"""Unit tests for AWS Live Security Scanner v2.0.0.

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


# ─── Test: Core data structures ──────────────────────────────────────────────
class TestDataStructures(unittest.TestCase):

    def test_version(self):
        self.assertEqual(VERSION, "2.0.0")

    def test_sections_count(self):
        self.assertEqual(len(SECTIONS), 25)

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
                       "ELC-01", "OSR-01", "DDB-01", "SFN-01"]
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
        ddb.list_tables.return_value = {"TableNames": ["my-table"]}
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


if __name__ == "__main__":
    unittest.main()
