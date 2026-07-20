"""Phase 6 Batch B7 — supply-chain image/code signing: CNT-06 ECR registry signing config,
LMB-06 Lambda code-signing enforcement. Offline: MagicMock ecr + lambda."""
import json
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner, MockPaginator


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


# ── CNT-06 ECR registry signing ───────────────────────────────────────────────
def _ecr_scanner(signing_rules=None, signing_error=None, no_op=False):
    s = make_scanner(sections=["ECR"])
    ecr = MagicMock()
    ecr.describe_repositories.return_value = {"repositories": [
        {"repositoryName": "app", "imageScanningConfiguration": {"scanOnPush": True},
         "encryptionConfiguration": {"encryptionType": "KMS"}, "imageTagMutability": "IMMUTABLE"}]}
    ecr.get_repository_policy.side_effect = Exception("RepositoryPolicyNotFoundException")
    ecr.get_lifecycle_policy.side_effect = Exception("LifecyclePolicyNotFoundException")
    ecr.describe_image_scan_findings.side_effect = Exception("no scan")
    if no_op:
        del ecr.get_signing_configuration       # simulate older SDK w/o the op
    elif signing_error:
        ecr.get_signing_configuration.side_effect = signing_error
    else:
        ecr.get_signing_configuration.return_value = {
            "signingConfiguration": {"rules": signing_rules if signing_rules is not None else []}}
    s._clients["ecr:us-east-1"] = ecr
    return s


def test_cnt06_no_signing_config_fails():
    s = _ecr_scanner(signing_rules=[])
    s._check_ecr()
    assert "FAIL" in _status(s, "CNT-06")


def test_cnt06_signing_configured_passes():
    s = _ecr_scanner(signing_rules=[{"signingProfileArn": "arn:aws:signer:...:profile/p"}])
    s._check_ecr()
    assert "PASS" in _status(s, "CNT-06")


def test_cnt06_older_sdk_skipped_silently():
    s = _ecr_scanner(no_op=True)
    s._check_ecr()
    assert not [r for r in s.results if r.check_id == "CNT-06"]   # no finding, no crash


def test_cnt06_access_denied_warns_not_pass():
    s = _ecr_scanner(signing_error=Exception("AccessDeniedException"))
    s._check_ecr()
    assert "WARN" in _status(s, "CNT-06") and "PASS" not in _status(s, "CNT-06")


def test_cnt06_does_not_break_cnt01():
    s = _ecr_scanner(signing_error=Exception("UnknownOperationException"))
    s._check_ecr()
    assert any(r.check_id == "CNT-01" for r in s.results)   # ECR repo loop still ran


# ── LMB-06 Lambda code signing ────────────────────────────────────────────────
def _lambda_scanner(funcs, csc_by_fn=None, mode_by_arn=None, csc_error=None):
    s = make_scanner(sections=["LAMBDA"])
    lmb = MagicMock()
    lmb.get_paginator.side_effect = lambda n: MockPaginator("Functions", funcs)
    lmb.get_policy.return_value = {"Policy": json.dumps({"Statement": []})}  # no public grant
    lmb.get_function_concurrency.return_value = {"ReservedConcurrentExecutions": 5}

    def _csc(FunctionName):
        if csc_error and FunctionName in csc_error:
            raise Exception("AccessDeniedException")
        return {"CodeSigningConfigArn": (csc_by_fn or {}).get(FunctionName)}
    lmb.get_function_code_signing_config.side_effect = _csc

    def _gcsc(CodeSigningConfigArn):
        return {"CodeSigningConfig": {"CodeSigningPolicies":
                {"UntrustedArtifactOnDeployment": (mode_by_arn or {}).get(CodeSigningConfigArn, "Warn")}}}
    lmb.get_code_signing_config.side_effect = _gcsc
    s._clients["lambda:us-east-1"] = lmb
    return s


def test_lmb06_warn_mode_fails():
    s = _lambda_scanner([{"FunctionName": "f1"}],
                        csc_by_fn={"f1": "arn:csc:1"}, mode_by_arn={"arn:csc:1": "Warn"})
    s._check_lambda()
    assert "FAIL" in _status(s, "LMB-06")


def test_lmb06_enforce_mode_passes():
    s = _lambda_scanner([{"FunctionName": "f1"}],
                        csc_by_fn={"f1": "arn:csc:1"}, mode_by_arn={"arn:csc:1": "Enforce"})
    s._check_lambda()
    assert "PASS" in _status(s, "LMB-06")


def test_lmb06_unsigned_is_info_aggregate_not_per_fn():
    s = _lambda_scanner([{"FunctionName": "f1"}, {"FunctionName": "f2"}])  # no CSC
    s._check_lambda()
    lmb06 = [r for r in s.results if r.check_id == "LMB-06"]
    assert len(lmb06) == 1 and lmb06[0].status == "INFO"


def test_lmb06_denied_read_warns_not_false_clear():
    s = _lambda_scanner([{"FunctionName": "f1"}], csc_error={"f1"})
    s._check_lambda()
    assert "WARN" in _status(s, "LMB-06")


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("CNT-06", "LMB-06"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()
