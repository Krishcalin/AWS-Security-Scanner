"""Second tranche: checks with a real FAIL path that no test had ever driven.

CHOSEN BY MEASUREMENT, not by browsing. `docs/CHECK_FIRING.md` lists checks that run
but have never been driven to a FAIL; 65 of those are declared above LOW, so they have
never rendered the severity the catalogue advertises nor carried their written
remediation. Splitting that 65 by whether a FAIL site exists OUTSIDE an exception
handler gives three populations:

  * 20 have a real FAIL path and simply no test — this file drives 5 of them,
    chosen for severity rather than for count: the two CRITICALs and the three IAM
    checks. The remaining 15 (CloudFront, OpenSearch and seven singletons) are a
    later tranche;
  * 5 can only FAIL from an exception handler (SNS-01, SQS-03, R53-02, DDB-01,
    BDR-05), so their declared severity describes an API failure rather than the
    condition they are named for. That is a product decision, recorded not changed;
  * 40 emit through a variable, which no static pass can classify — the limitation
    that produced four different wrong answers earlier in this project's history.

THE TWO CRITICALS ARE THE POINT. `RDS-02` (a publicly accessible database) and
`RDS-06` (a publicly shared snapshot) are the two highest-severity checks in the
catalogue that no test had ever proven capable of failing. Both have ordinary,
unambiguous failure conditions.
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_live_scanner import make_scanner, MockClientError, MockPaginator


@pytest.fixture(autouse=True)
def _client_error():
    """`ClientError` is imported inside `try: import boto3`, so in a boto3-less run
    it does not exist and every `except ClientError` raises NameError before the
    handler runs. The suite patches it with a stand-in; applied here for the module
    because the IAM section catches it."""
    from unittest.mock import patch
    with patch("engine.aws_live_scanner.ClientError", MockClientError,
               create=True):
        yield


def statuses(scanner, check_id):
    return {r.status for r in scanner.results if r.check_id == check_id}


def assert_failed_on(scanner, check_id, resource=None, message_startswith=None):
    """Assert a FAIL for `check_id` RAISED BY THE NAMED CONDITION.

    `RDS-06` and `IAM-05` each have a second FAIL site inside a broad exception
    handler, so a bare "did it FAIL?" assertion is satisfied by a fixture that
    merely throws — the check would look driven while its real condition stayed
    dead. Every assertion here therefore pins the row to the condition: for RDS-06
    the resource is the snapshot id (the handler emits `rds-snapshots`), for IAM-05
    the message is the policy-issue list (the handler emits `NoSuchEntity` or the
    exception text).
    """
    rows = [r for r in scanner.results
            if r.check_id == check_id and r.status == "FAIL"]
    assert rows, "%s never reached FAIL; emitted %s" % (
        check_id, sorted(statuses(scanner, check_id)) or ["nothing"])
    if resource is not None:
        rows = [r for r in rows if r.resource == resource]
        assert rows, "%s failed, but not on resource %r — got %r" % (
            check_id, resource,
            [r.resource for r in scanner.results
             if r.check_id == check_id and r.status == "FAIL"])
    if message_startswith is not None:
        assert [r for r in rows if r.message.startswith(message_startswith)], (
            "%s failed, but not with the expected condition (%r) — got %r"
            % (check_id, message_startswith, [r.message for r in rows]))


# ── RDS: the two CRITICALs ──────────────────────────────────────────────────

@pytest.fixture()
def rds_scanner():
    s = make_scanner(["RDS"])
    rds = MagicMock()
    rds.get_paginator.side_effect = lambda op: {
        "describe_db_instances": MockPaginator("DBInstances", [{
            "DBInstanceIdentifier": "prod-db",
            "Engine": "postgres",
            "PubliclyAccessible": True,       # RDS-02
            "StorageEncrypted": False,
            "BackupRetentionPeriod": 0,
            "MultiAZ": False,
            "DeletionProtection": False,
            "AutoMinorVersionUpgrade": False,
        }]),
        "describe_db_snapshots": MockPaginator("DBSnapshots", [{
            "DBSnapshotIdentifier": "prod-db-snap",
            "Encrypted": False,
        }]),
    }[op]
    rds.describe_db_snapshots.return_value = {"DBSnapshots": [
        {"DBSnapshotIdentifier": "prod-db-snap", "Encrypted": False}]}
    rds.describe_db_snapshot_attributes.return_value = {
        "DBSnapshotAttributesResult": {"DBSnapshotAttributes": [
            {"AttributeName": "restore", "AttributeValues": ["all"]}]}}   # RDS-06
    rds.describe_db_clusters.return_value = {"DBClusters": []}
    s._clients["rds:us-east-1"] = rds
    return s


def test_a_public_database_and_a_public_snapshot_both_fail(rds_scanner):
    """The two highest-severity checks in the catalogue that no test had proven.
    RDS-02 is a database reachable from the internet; RDS-06 is a snapshot shared
    with `all`, which is how a database leaks without the database being touched."""
    rds_scanner._check_rds()
    assert_failed_on(rds_scanner, "RDS-02", resource="prod-db",
                     message_startswith="DB PUBLICLY ACCESSIBLE")
    assert_failed_on(rds_scanner, "RDS-06", resource="prod-db-snap",
                     message_startswith="RDS snapshot PUBLICLY ACCESSIBLE")


# ── IAM: driven off the credential report, not a client ─────────────────────

@pytest.fixture()
def iam_scanner():
    s = make_scanner(["IAM"])
    # `_get_credential_report` parses the IAM credential report CSV into rows; the
    # checks read those rows, so the report is the fixture, not a boto3 call.
    s._get_credential_report = lambda: [
        {"user": "console-user", "password_enabled": "true",
         "mfa_active": "false",                      # IAM-04
         "access_key_1_active": "true",
         "access_key_1_last_rotated": "2019-01-01T00:00:00+00:00",  # IAM-06
         "access_key_2_active": "false",
         "access_key_2_last_rotated": "N/A",
         "password_last_used": "2019-02-01T00:00:00+00:00",
         "password_last_changed": "2019-01-01T00:00:00+00:00"},
    ]
    iam = MagicMock()
    # A weak password policy drives IAM-05. Left as a bare MagicMock the section
    # raises TypeError comparing a mock to an int, which is a broken fixture rather
    # than a finding.
    iam.get_account_password_policy.return_value = {"PasswordPolicy": {
        "MinimumPasswordLength": 6,
        "RequireSymbols": False,
        "RequireNumbers": False,
        "RequireUppercaseCharacters": False,
        "RequireLowercaseCharacters": False,
        "MaxPasswordAge": 0,
        "PasswordReusePrevention": 0,
    }}
    s._clients["iam:us-east-1"] = iam
    return s


def test_console_user_key_age_and_password_policy_all_fail(iam_scanner):
    """IAM-04 is a password-enabled user with no MFA, IAM-06 an active access key
    older than 90 days, IAM-05 a password policy below the CIS floor. All three are
    the ordinary shape of the finding, and none had ever been driven."""
    iam_scanner._check_iam_credentials() if hasattr(
        iam_scanner, "_check_iam_credentials") else iam_scanner._check_iam()
    assert_failed_on(iam_scanner, "IAM-04", resource="console-user",
                     message_startswith="Console user WITHOUT MFA")
    assert_failed_on(iam_scanner, "IAM-05", resource="password-policy",
                     message_startswith="Password policy issues:")
    assert_failed_on(iam_scanner, "IAM-06", resource="console-user/access_key_1",
                     message_startswith="console-user access_key_1 is ")
