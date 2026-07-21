"""Phase 7 fix-verify regression tests — one per confirmed adversarial-verify defect.
F1 (no-ENI gates identity fusion), F2 (phantom PASS on denied L7), F4 (DynamoDB 300-cap
signal), F5 (classifier separators/synonyms), F6 (reachable_service accumulate across
regions), F9 (CloudFront unresolved-origin message). Offline: MagicMock (no boto3, no AWS)."""
import os
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner
from aws_graph import SecurityGraph
import aws_deepplane as D

ACCT = "123456789012"


def _iso(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def _empty_ec2(enis=None):
    ec2 = MagicMock()
    page = {"NetworkInterfaces": enis or []}
    ec2.get_paginator.return_value.paginate.return_value = [page]
    return ec2


def _exposure_scanner():
    s = make_scanner(sections=["EXPOSURE"])
    s.account = ACCT
    g = SecurityGraph()
    g.add_node(s._admin_cap_id(), "AdminCapability")
    s.graph = g
    s._iam_principals = []
    return s, g


# ── F1 [HIGH]: identity fusion must fire even when the region has zero ENIs ────
def test_f1_identity_fusion_fires_with_zero_enis():
    s, g = _exposure_scanner()
    admin = s._admin_cap_id()
    user_arn = f"arn:aws:iam::{ACCT}:user/admin1"
    g.add_node(user_arn, "IAMUser", name="admin1")
    g.add_edge(user_arn, admin, "CAN_PRIVESC_TO", conditioned=False)
    s._cred_report = [{"user": "admin1", "arn": user_arn, "access_key_1_active": "true",
                       "access_key_1_last_rotated": _iso(200),
                       "access_key_1_last_used_date": "N/A", "access_key_2_active": "false"}]
    s._cred_report_ok = True
    s._clients["ec2:us-east-1"] = _empty_ec2()          # zero ENIs
    with patch("builtins.print"):
        s._check_exposure()
    assert "FAIL" in _status(s, "IDENTITY-01")           # not silently skipped
    assert g.node("internet") is not None                # CORRELATE prerequisite present


# ── F2 [MEDIUM]: denied L7 describe downgrades the aggregate PASS to WARN ──────
def test_f2_denied_l7_downgrades_pass_to_warn():
    s, g = _exposure_scanner()
    s._cred_report = []
    s._cred_report_ok = False                            # no identity finding
    # one private (non-public) ENI so enis is non-empty but nothing is directly exposed
    s._clients["ec2:us-east-1"] = _empty_ec2(
        [{"NetworkInterfaceId": "eni-1", "InterfaceType": "interface",
          "PrivateIpAddresses": [], "Groups": []}])
    denied = MagicMock()
    denied.get_paginator.side_effect = RuntimeError("AccessDenied")
    for svc in ("elbv2", "elb", "cloudfront", "apigateway", "apigatewayv2"):
        s._clients[f"{svc}:us-east-1"] = denied
    with patch("builtins.print"):
        s._check_exposure()
    assert "WARN" in _status(s, "EXPOSURE-02")            # UNDETERMINED, not a phantom PASS
    assert "PASS" not in _status(s, "EXPOSURE-02")


def test_f2_clean_l7_still_passes():
    # positive control: L7 enumerates cleanly (empty) + nothing exposed -> honest PASS
    s, g = _exposure_scanner()
    s._cred_report = []
    s._cred_report_ok = False
    s._clients["ec2:us-east-1"] = _empty_ec2(
        [{"NetworkInterfaceId": "eni-1", "InterfaceType": "interface",
          "PrivateIpAddresses": [], "Groups": []}])
    def _empty_pager(key):
        c = MagicMock()
        c.get_paginator.return_value.paginate.return_value = [{key: []}]
        return c
    s._clients["elbv2:us-east-1"] = _empty_pager("LoadBalancers")
    s._clients["elb:us-east-1"] = _empty_pager("LoadBalancerDescriptions")
    s._clients["cloudfront:us-east-1"] = _empty_pager("DistributionList")
    s._clients["apigateway:us-east-1"] = _empty_pager("items")
    s._clients["apigatewayv2:us-east-1"] = _empty_pager("Items")
    with patch("builtins.print"):
        s._check_exposure()
    assert "PASS" in _status(s, "EXPOSURE-02")
    assert "WARN" not in _status(s, "EXPOSURE-02")


# ── F4 [MEDIUM]: DynamoDB >300 tables emits a visible truncation signal ────────
def test_f4_dynamodb_truncation_emits_info():
    s = make_scanner(sections=["DATA"])
    s.account = ACCT
    g = SecurityGraph()
    ddb = MagicMock()
    names = [f"t{i}" for i in range(350)]
    ddb.get_paginator.return_value.paginate.return_value = [{"TableNames": names}]
    ddb.list_tags_of_resource.return_value = {"Tags": []}     # none crown
    s._clients["dynamodb:us-east-1"] = ddb
    s._dspm_dynamodb(g, [])
    trunc = [r for r in s.results if r.check_id == "DSPM-01" and r.status == "INFO"
             and "300 of 350" in r.message]
    assert trunc, "silent 300-table truncation must emit an operator signal"


# ── F5 [MEDIUM]: classifier folds separators + recognizes compliance synonyms ─
def test_f5_separator_folding():
    for k in ("Data-Classification", "data_classification", "Data Classification"):
        assert D.is_crown_jewel_by_tags([{"Key": k, "Value": "Confidential"}]), k


def test_f5_synonym_keys_and_values():
    assert D.is_crown_jewel_by_tags([{"Key": "Confidentiality", "Value": "Restricted"}])
    assert D.is_crown_jewel_by_tags([{"Key": "Compliance", "Value": "HIPAA"}])
    assert D.is_crown_jewel_by_tags([{"Key": "Compliance", "Value": "GDPR"}])


def test_f5_still_rejects_exact_value_trap():
    assert D.is_crown_jewel_by_tags([{"Key": "Classification", "Value": "high-availability"}]) is None
    assert D.is_crown_jewel_by_tags([{"Key": "Environment", "Value": "prod"}]) is None


# ── F6 [MEDIUM]: _reachable_workloads accumulates (|=), survives a later region ─
def test_f6_reachable_workloads_accumulates():
    s, g = _exposure_scanner()
    s._cred_report = []
    s._cred_report_ok = False
    prior = f"arn:aws:ec2:us-west-2:{ACCT}:instance/i-prior"
    s._reachable_workloads = {prior}                     # a previously-swept region's exposed host
    s._clients["ec2:us-east-1"] = _empty_ec2()           # this region exposes nothing
    with patch("builtins.print"):
        s._check_exposure()
    # with the buggy `=` overwrite this would be wiped to set(); `|=` keeps it
    assert prior in s._reachable_workloads


# ── F9 [LOW]: CloudFront unresolved custom origin uses the softened wording ────
def test_f9_cloudfront_unresolved_message_softened():
    s, g = _exposure_scanner()
    cf = MagicMock()
    dist = {"Id": "E1", "DomainName": "d.cloudfront.net", "Enabled": True,
            "Aliases": {"Items": []},
            "Origins": {"Items": [{"DomainName": "some-lb.elb.amazonaws.com",
                                   "CustomOriginConfig": {"OriginProtocolPolicy": "https-only"}}]}}
    cf.get_paginator.return_value.paginate.return_value = [{"DistributionList": {"Items": [dist]}}]
    s._clients["cloudfront:us-east-1"] = cf
    s._l7_cloudfront(g, "internet", {})                  # empty lb_dns -> unresolved
    msgs = [r.message for r in s.results if r.check_id == "EXPOSURE-03" and r.status == "INFO"]
    assert any("not matched to an enumerated" in m for m in msgs)
    assert not any("no mapped in-account load balancer" in m for m in msgs)   # false-absence gone


# ── F10 [completeness]: LB-fronted PRIVATE instance reaches the ATTACK-02 flagship ─
def test_f10_lb_fronted_instance_reaches_attack02_flagship():
    s = make_scanner(sections=["DATA"])
    s.account = ACCT
    s._iam_principals = []
    g = SecurityGraph()
    inst = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-lb"
    lb = "lb/arn:aws:elasticloadbalancing:us-east-1:x:loadbalancer/app/a/1"
    prof = f"arn:aws:iam::{ACCT}:instance-profile/p"
    role = f"arn:aws:iam::{ACCT}:role/r"
    bucket = "arn:aws:s3:::crown"
    g.add_node("internet", "InternetSource")
    g.add_node(lb, "LoadBalancer", name="app")
    g.add_node(inst, "EC2Instance", instance_id="i-lb")
    g.add_node(prof, "InstanceProfile")
    g.add_node(role, "IAMRole", name="r")
    g.add_node(bucket, "S3Bucket", name="crown", crown_jewel=True)
    g.add_node("CVE-X", "Vulnerability", kev=True)
    g.add_edge("internet", lb, "EXPOSED_TO", basis="l7-elbv2")
    g.add_edge(lb, inst, "TARGETS", basis="l7-elbv2", target_type="instance")  # LB-fronted
    g.add_edge(inst, prof, "HAS_INSTANCE_PROFILE")
    g.add_edge(prof, role, "HAS_ROLE")
    g.add_edge(inst, "CVE-X", "HAS_VULN", cve="CVE-X", kev=True, exploit_available="YES")
    g.add_edge(role, bucket, "CAN_READ_DATA", conditioned=False)
    s.graph = g
    with patch("builtins.print"):
        s._correlate_flagship(g)
    # Without TARGETS in the flagship reachability set, the LB-fronted host is invisible.
    assert "FAIL" in _status(s, "ATTACK-02")

