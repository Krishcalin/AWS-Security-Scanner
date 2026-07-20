"""Phase 6 Batch B11 — SageMaker Studio domains (SM-05 public egress, SM-06 home-EFS CMK)
+ inference endpoint-config storage CMK (SM-07). All run independently of notebook instances
(the early-return was refactored). Offline: MagicMock sagemaker."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner


def _sm_scanner(domains=None, domain_detail=None, ep_configs=None, ep_detail=None,
                domains_error=False, ep_error=False, notebooks=None):
    s = make_scanner(sections=["SAGEMAKER"])
    sm = MagicMock()
    sm.list_notebook_instances.return_value = {"NotebookInstances": notebooks or []}
    if domains_error:
        sm.list_domains.side_effect = RuntimeError("AccessDenied")
    else:
        sm.list_domains.return_value = {"Domains": domains or []}
    sm.describe_domain.side_effect = lambda DomainId: (domain_detail or {}).get(DomainId, {})
    if ep_error:
        sm.list_endpoint_configs.side_effect = RuntimeError("AccessDenied")
    else:
        sm.list_endpoint_configs.return_value = {"EndpointConfigs": ep_configs or []}
    sm.describe_endpoint_config.side_effect = \
        lambda EndpointConfigName: (ep_detail or {}).get(EndpointConfigName, {})
    s._clients["sagemaker:us-east-1"] = sm
    return s


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


# ── SM-05 Studio domain egress ────────────────────────────────────────────────
def test_sm05_public_internet_domain_fails():
    s = _sm_scanner(domains=[{"DomainId": "d-1"}],
                    domain_detail={"d-1": {"DomainName": "studio",
                                   "AppNetworkAccessType": "PublicInternetOnly"}})
    s._check_sagemaker()
    assert "FAIL" in _status(s, "SM-05")


def test_sm05_vpc_only_passes():
    s = _sm_scanner(domains=[{"DomainId": "d-1"}],
                    domain_detail={"d-1": {"DomainName": "studio",
                                   "AppNetworkAccessType": "VpcOnly", "KmsKeyId": "k"}})
    s._check_sagemaker()
    assert "PASS" in _status(s, "SM-05")


def test_sm05_missing_field_defaults_to_public_fail():
    s = _sm_scanner(domains=[{"DomainId": "d-1"}],
                    domain_detail={"d-1": {"DomainName": "studio", "KmsKeyId": "k"}})  # no AppNetworkAccessType
    s._check_sagemaker()
    assert "FAIL" in _status(s, "SM-05")


def test_sm05_runs_with_zero_notebooks():
    # the refactor: domains evaluated even with no notebook instances
    s = _sm_scanner(notebooks=[], domains=[{"DomainId": "d-1"}],
                    domain_detail={"d-1": {"DomainName": "studio",
                                   "AppNetworkAccessType": "PublicInternetOnly"}})
    s._check_sagemaker()
    assert "FAIL" in _status(s, "SM-05")


def test_sm05_list_denied_warns_no_phantom_clean():
    s = _sm_scanner(domains_error=True)
    s._check_sagemaker()
    assert "WARN" in _status(s, "SM-05") and "INFO" not in _status(s, "SM-05")


def test_sm05_no_domains_info():
    s = _sm_scanner(domains=[])
    s._check_sagemaker()
    assert "INFO" in _status(s, "SM-05")


# ── SM-06 home-EFS CMK ────────────────────────────────────────────────────────
def test_sm06_no_cmk_fails():
    s = _sm_scanner(domains=[{"DomainId": "d-1"}],
                    domain_detail={"d-1": {"DomainName": "studio",
                                   "AppNetworkAccessType": "VpcOnly"}})  # no KmsKeyId
    s._check_sagemaker()
    assert "FAIL" in _status(s, "SM-06")


def test_sm06_legacy_kms_field_passes():
    s = _sm_scanner(domains=[{"DomainId": "d-1"}],
                    domain_detail={"d-1": {"DomainName": "studio", "AppNetworkAccessType": "VpcOnly",
                                   "HomeEfsFileSystemKmsKeyId": "arn:kms:..."}})
    s._check_sagemaker()
    assert "PASS" in _status(s, "SM-06")


# ── SM-07 endpoint-config CMK ─────────────────────────────────────────────────
def test_sm07_no_cmk_fails():
    s = _sm_scanner(ep_configs=[{"EndpointConfigName": "ec1"}],
                    ep_detail={"ec1": {"EndpointConfigName": "ec1"}})  # no KmsKeyId
    s._check_sagemaker()
    assert "FAIL" in _status(s, "SM-07")


def test_sm07_cmk_passes():
    s = _sm_scanner(ep_configs=[{"EndpointConfigName": "ec1"}],
                    ep_detail={"ec1": {"EndpointConfigName": "ec1", "KmsKeyId": "arn:kms:..."}})
    s._check_sagemaker()
    assert "PASS" in _status(s, "SM-07")


def test_sm07_list_denied_warns():
    s = _sm_scanner(ep_error=True)
    s._check_sagemaker()
    assert "WARN" in _status(s, "SM-07")


def test_sm07_no_configs_info():
    s = _sm_scanner(ep_configs=[])
    s._check_sagemaker()
    assert "INFO" in _status(s, "SM-07")


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("SM-05", "SM-06", "SM-07"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()
