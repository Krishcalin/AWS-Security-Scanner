"""Phase 6 Batch B10 — WAF-05 managed rule group presence + CFN-06 CloudFront origin-side
weak TLS. Both reuse already-fetched responses (0 extra API). Offline: MagicMock."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


# ── WAF-05 ────────────────────────────────────────────────────────────────────
def _waf_scanner(rules, web_acl_error=False):
    s = make_scanner(sections=["WAF"])
    waf = MagicMock()
    waf.list_web_acls.return_value = {"WebACLs": [{"Name": "acl", "Id": "id1", "ARN": "arn:acl"}]}
    waf.get_logging_configuration.return_value = {"LoggingConfiguration": {}}
    if web_acl_error:
        waf.get_web_acl.side_effect = RuntimeError("AccessDenied")
    else:
        waf.get_web_acl.return_value = {"WebACL": {"Rules": rules, "DefaultAction": {"Block": {}}}}
    # _check_waf uses regional + cloudfront scopes; give both the same client
    s._clients["wafv2:us-east-1"] = waf
    return s


def test_waf05_no_managed_group_fails():
    rules = [{"Name": "custom", "Statement": {"RateBasedStatement": {}}}]
    s = _waf_scanner(rules)
    s._check_waf()
    assert "FAIL" in _status(s, "WAF-05")


def test_waf05_managed_group_passes():
    rules = [{"Name": "aws", "Statement": {"ManagedRuleGroupStatement":
              {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}}}]
    s = _waf_scanner(rules)
    s._check_waf()
    assert "PASS" in _status(s, "WAF-05")


def test_waf05_empty_rules_no_double_report():
    # WAF-03 owns the no-rules FAIL; WAF-05 stays silent
    s = _waf_scanner([])
    s._check_waf()
    assert not _status(s, "WAF-05")


def test_waf03_read_error_now_warns_not_silent():
    # the bare except:pass was tightened to WARN
    s = _waf_scanner([], web_acl_error=True)
    s._check_waf()
    assert "WARN" in _status(s, "WAF-03")


# ── CFN-06 ────────────────────────────────────────────────────────────────────
def _cfn_scanner(origins):
    s = make_scanner(sections=["CLOUDFRONT"])
    cf = MagicMock()
    cf.list_distributions.return_value = {"DistributionList": {"Items": [{
        "Id": "d1", "DomainName": "d1.cloudfront.net", "Status": "Deployed",
        "DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only"},
        "ViewerCertificate": {"MinimumProtocolVersion": "TLSv1.2_2021"},
        "WebACLId": "acl", "Origins": {"Items": origins}}]}}
    cf.get_distribution_config.return_value = {"DistributionConfig": {"Logging": {"Enabled": True}}}
    s._clients["cloudfront:us-east-1"] = cf
    return s


def _custom_origin(oid, ssl_protos, opp="https-only"):
    return {"Id": oid, "CustomOriginConfig": {"OriginProtocolPolicy": opp,
            "OriginSslProtocols": {"Items": ssl_protos}}}


def test_cfn06_weak_origin_tls_warns():
    s = _cfn_scanner([_custom_origin("o1", ["TLSv1", "TLSv1.2"])])
    s._check_cloudfront()
    assert "WARN" in _status(s, "CFN-06")


def test_cfn06_strong_origin_tls_passes():
    s = _cfn_scanner([_custom_origin("o1", ["TLSv1.2"])])
    s._check_cloudfront()
    assert "PASS" in _status(s, "CFN-06")


def test_cfn06_http_only_origin_skipped():
    # http-only is CFN-05's plaintext FAIL; CFN-06 must not double-report
    s = _cfn_scanner([_custom_origin("o1", ["TLSv1"], opp="http-only")])
    s._check_cloudfront()
    assert not _status(s, "CFN-06")


def test_cfn06_s3_origin_skipped():
    # S3 origin has no CustomOriginConfig -> CFN-06 skips
    s = _cfn_scanner([{"Id": "s3o", "S3OriginConfig": {"OriginAccessIdentity": ""},
                       "OriginAccessControlId": "oac-1"}])
    s._check_cloudfront()
    assert not _status(s, "CFN-06")


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("WAF-05", "CFN-06"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()
