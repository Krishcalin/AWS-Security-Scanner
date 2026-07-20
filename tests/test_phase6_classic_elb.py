"""Phase 6 Batch B8 — Classic Load Balancer (elb v1): CLB-01 plaintext-only internet-facing
CLB, CLB-02 weak SSL negotiation policy. Offline: MagicMock elb (v1)."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner, MockPaginator


def _clb_scanner(clbs, policies_by_lb=None, policy_error=None):
    s = make_scanner(sections=["ELB"])
    elb = MagicMock()
    elb.get_paginator.side_effect = lambda n: MockPaginator("LoadBalancerDescriptions", clbs)

    def _pols(LoadBalancerName):
        if policy_error and LoadBalancerName in policy_error:
            raise RuntimeError("AccessDenied")
        return {"PolicyDescriptions": (policies_by_lb or {}).get(LoadBalancerName, [])}
    elb.describe_load_balancer_policies.side_effect = _pols
    s._clients["elb:us-east-1"] = elb
    return s


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def _listener(proto, port=443):
    return {"Listener": {"Protocol": proto, "LoadBalancerPort": port}}


def _weak_policy():
    return [{"PolicyName": "p", "PolicyTypeName": "SSLNegotiationPolicyType",
             "PolicyAttributeDescriptions": [
                 {"AttributeName": "Protocol-TLSv1", "AttributeValue": "true"}]}]


def _strong_policy():
    return [{"PolicyName": "p", "PolicyTypeName": "SSLNegotiationPolicyType",
             "PolicyAttributeDescriptions": [
                 {"AttributeName": "Protocol-TLSv1.2", "AttributeValue": "true"},
                 {"AttributeName": "Protocol-TLSv1", "AttributeValue": "false"}]}]


# ── CLB-01 plaintext ──────────────────────────────────────────────────────────
def test_clb01_internet_facing_plaintext_fails():
    s = _clb_scanner([{"LoadBalancerName": "web", "Scheme": "internet-facing",
                       "ListenerDescriptions": [_listener("HTTP", 80)]}])
    s._check_classic_elb()
    assert "FAIL" in _status(s, "CLB-01")


def test_clb01_internal_plaintext_is_info():
    s = _clb_scanner([{"LoadBalancerName": "int", "Scheme": "internal",
                       "ListenerDescriptions": [_listener("TCP", 80)]}])
    s._check_classic_elb()
    assert "INFO" in _status(s, "CLB-01") and "FAIL" not in _status(s, "CLB-01")


def test_clb01_https_present_passes():
    s = _clb_scanner([{"LoadBalancerName": "sec", "Scheme": "internet-facing",
                       "ListenerDescriptions": [_listener("HTTP", 80), _listener("HTTPS", 443)]}],
                     policies_by_lb={"sec": _strong_policy()})
    s._check_classic_elb()
    assert "PASS" in _status(s, "CLB-01")


def test_clb01_no_clbs_info():
    s = _clb_scanner([])
    s._check_classic_elb()
    assert _status(s, "CLB-01") == {"INFO"}


def test_clb01_error_warns():
    s = _clb_scanner([])
    s._clients["elb:us-east-1"].get_paginator.side_effect = RuntimeError("AccessDenied")
    s._check_classic_elb()
    assert "WARN" in _status(s, "CLB-01")


# ── CLB-02 weak SSL policy ────────────────────────────────────────────────────
def test_clb02_weak_policy_fails():
    s = _clb_scanner([{"LoadBalancerName": "sec", "Scheme": "internet-facing",
                       "ListenerDescriptions": [_listener("HTTPS", 443)]}],
                     policies_by_lb={"sec": _weak_policy()})
    s._check_classic_elb()
    assert "FAIL" in _status(s, "CLB-02")


def test_clb02_strong_policy_passes():
    s = _clb_scanner([{"LoadBalancerName": "sec", "Scheme": "internet-facing",
                       "ListenerDescriptions": [_listener("HTTPS", 443)]}],
                     policies_by_lb={"sec": _strong_policy()})
    s._check_classic_elb()
    assert "PASS" in _status(s, "CLB-02")


def test_clb02_policy_read_error_warns_not_pass():
    s = _clb_scanner([{"LoadBalancerName": "sec", "Scheme": "internet-facing",
                       "ListenerDescriptions": [_listener("HTTPS", 443)]}],
                     policy_error={"sec"})
    s._check_classic_elb()
    assert "WARN" in _status(s, "CLB-02") and "PASS" not in _status(s, "CLB-02")


def test_clb02_skipped_for_plaintext_only():
    # a plaintext-only CLB has no HTTPS listener -> CLB-02 not evaluated (no needless call)
    s = _clb_scanner([{"LoadBalancerName": "web", "Scheme": "internet-facing",
                       "ListenerDescriptions": [_listener("HTTP", 80)]}])
    s._check_classic_elb()
    assert not _status(s, "CLB-02")


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("CLB-01", "CLB-02"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()
