"""Phase 6 Batch B4 — storage exposure/immutability: BCK-02 Vault Lock, BCK-03 vault
access policy, DDB-05 table resource policy. Offline: MagicMock backup + dynamodb."""
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner, MockPaginator


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


# ── Backup BCK-02/03 ──────────────────────────────────────────────────────────
def _backup_scanner(vaults, policies=None, policy_errors=None):
    s = make_scanner(sections=["BACKUP"])
    s.account = "111111111111"
    bk = MagicMock()
    bk.list_backup_vaults.return_value = {"BackupVaultList": vaults}   # BCK-01 (unpaginated)
    bk.list_backup_plans.return_value = {"BackupPlansList": []}
    bk.get_paginator.side_effect = lambda n: MockPaginator("BackupVaultList", vaults)

    def _pol(BackupVaultName):
        if policy_errors and BackupVaultName in policy_errors:
            raise policy_errors[BackupVaultName]
        p = (policies or {}).get(BackupVaultName)
        if p is None:
            raise Exception("ResourceNotFoundException: no policy")
        return {"Policy": json.dumps(p)}
    bk.get_backup_vault_access_policy.side_effect = _pol
    s._clients["backup:us-east-1"] = bk
    return s


def test_bck02_no_lock_fails():
    s = _backup_scanner([{"BackupVaultName": "v1", "Locked": False}])
    s._check_backup()
    assert "FAIL" in _status(s, "BCK-02")


def test_bck02_governance_mode_warns():
    s = _backup_scanner([{"BackupVaultName": "v2", "Locked": True}])  # no LockDate
    s._check_backup()
    assert "WARN" in _status(s, "BCK-02")


def test_bck02_compliance_active_passes():
    past = datetime.now(timezone.utc) - timedelta(days=10)
    s = _backup_scanner([{"BackupVaultName": "v3", "Locked": True, "LockDate": past}])
    s._check_backup()
    assert "PASS" in _status(s, "BCK-02")


def test_bck02_grace_period_warns():
    future = datetime.now(timezone.utc) + timedelta(days=2)
    s = _backup_scanner([{"BackupVaultName": "v4", "Locked": True, "LockDate": future}])
    s._check_backup()
    assert "WARN" in _status(s, "BCK-02")


def test_bck02_enumerate_error_warns_not_pass():
    s = _backup_scanner([{"BackupVaultName": "v1", "Locked": True}])
    s._clients["backup:us-east-1"].get_paginator.side_effect = RuntimeError("AccessDenied")
    s._check_backup()
    assert "WARN" in _status(s, "BCK-02")


def test_bck03_public_vault_policy_fails():
    pol = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "backup:*",
                          "Resource": "*"}]}
    s = _backup_scanner([{"BackupVaultName": "v1", "Locked": True, "LockDate":
                          datetime.now(timezone.utc) - timedelta(days=5)}],
                        policies={"v1": pol})
    s._check_backup()
    assert "FAIL" in _status(s, "BCK-03")


def test_bck03_cross_account_is_warn_not_fail():
    # cross-account backup copy is a legitimate DR pattern -> WARN
    pol = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                          "Action": "backup:CopyIntoBackupVault", "Resource": "*"}]}
    s = _backup_scanner([{"BackupVaultName": "v1", "Locked": True, "LockDate":
                          datetime.now(timezone.utc) - timedelta(days=5)}],
                        policies={"v1": pol})
    s._check_backup()
    assert "WARN" in _status(s, "BCK-03") and "FAIL" not in _status(s, "BCK-03")


def test_bck03_no_policy_silent():
    s = _backup_scanner([{"BackupVaultName": "v1", "Locked": True, "LockDate":
                          datetime.now(timezone.utc) - timedelta(days=5)}])  # ResourceNotFound
    s._check_backup()
    assert not [r for r in s.results if r.check_id == "BCK-03"]


# ── DynamoDB DDB-05 ───────────────────────────────────────────────────────────
def _ddb_scanner(policy=None, policy_error=None, trusted=None):
    s = make_scanner(sections=["DYNAMODB"])
    s.account = "111111111111"
    if trusted:
        s.trusted_accounts = set(trusted)
    ddb = MagicMock()
    ddb.get_paginator.side_effect = lambda n: MockPaginator("TableNames", ["t1"])
    ddb.describe_table.return_value = {"Table": {
        "TableArn": "arn:aws:dynamodb:us-east-1:111111111111:table/t1",
        "SSEDescription": {"SSEType": "KMS"}, "DeletionProtectionEnabled": True}}
    ddb.describe_continuous_backups.return_value = {
        "ContinuousBackupsDescription": {"PointInTimeRecoveryDescription":
                                         {"PointInTimeRecoveryStatus": "ENABLED"}}}
    if policy_error:
        ddb.get_resource_policy.side_effect = policy_error
    elif policy is None:
        ddb.get_resource_policy.side_effect = Exception("PolicyNotFoundException")
    else:
        ddb.get_resource_policy.return_value = {"Policy": json.dumps(policy)}
    s._clients["dynamodb:us-east-1"] = ddb
    return s


def test_ddb05_public_policy_fails():
    pol = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "dynamodb:GetItem",
                          "Resource": "*"}]}
    s = _ddb_scanner(policy=pol)
    s._check_dynamodb()
    assert "FAIL" in _status(s, "DDB-05")


def test_ddb05_cross_account_fails():
    pol = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                          "Action": "dynamodb:GetItem", "Resource": "*"}]}
    s = _ddb_scanner(policy=pol)
    s._check_dynamodb()
    assert "FAIL" in _status(s, "DDB-05")


def test_ddb05_no_policy_silent():
    s = _ddb_scanner(policy=None)
    s._check_dynamodb()
    assert not [r for r in s.results if r.check_id == "DDB-05"]


def test_ddb05_access_denied_warns():
    s = _ddb_scanner(policy_error=Exception("AccessDeniedException"))
    s._check_dynamodb()
    assert "WARN" in _status(s, "DDB-05")


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("BCK-02", "BCK-03", "DDB-05"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()
