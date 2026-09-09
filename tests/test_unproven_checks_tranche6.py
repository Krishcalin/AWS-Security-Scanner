"""Tranche 6 — HIGH checks that emit, but had never been driven to a failure.

THE DISTINCTION THIS FILE IS ABOUT. `docs/CHECK_FIRING.md` separates "never observed"
(tranche 5's subject) from "runs, but never fails", and the second is easy to mistake for
harmless. It is not, because of one asymmetry in `_add`: severity, compliance and
remediation are read from the catalogue **only for a FAIL**. A WARN is forced to
`severity="LOW"` and carries no remediation. So a check declared HIGH that has only ever
been seen PASSing or WARNing has never once rendered what the catalogue promises for it —
the number in the report and the entry in the catalogue have never been compared.

Thirteen checks were in that state at HIGH. Eleven are driven here. The other two are
NOT a coverage gap and no fixture would honestly close them:

  * `BDR-05` and `DDB-01` have exactly one literal FAIL site each, and it is inside an
    `except` handler — `_add("FAIL", ..., str(e))`. Their declared HIGH is reachable only
    by making the AWS call throw. Driving that would "prove" the error handler, not the
    check, and would put a tick beside a claim that is still false. They are part of a
    wider defect (a read failure reported as a security finding, and the real condition
    reported at LOW) which is fixed separately rather than papered over here.

Every case asserts severity, remediation and compliance — not just the status — and every
check has a negative case, because a check that fires unconditionally is worse than no
check.
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_graph                                        # noqa: E402
from test_live_scanner import make_scanner                          # noqa: E402
from test_unproven_checks_tranche5 import _ids, _renders            # noqa: E402

OWN = "123456789012"
REGION = "us-east-1"


def _scanner(section, service, client, region=REGION):
    s = make_scanner(sections=[section])
    s.account = OWN
    s._clients[f"{service}:{region}"] = client
    return s


# ══════════════════════════════════════════════════════════════════════════════
# BDR-01 (HIGH) — Bedrock model-invocation logging
# ══════════════════════════════════════════════════════════════════════════════
def _bedrock(logging_config):
    b = MagicMock()
    b.get_model_invocation_logging_configuration.return_value = {
        "loggingConfig": logging_config}
    b.list_guardrails.return_value = {"guardrails": [
        {"name": "g", "id": "gr-1", "status": "READY"}]}
    return _scanner("BEDROCK", "bedrock", b)


def test_bdr01_no_invocation_logging_fails():
    """Without it there is no record of what was asked of a model or what came back —
    the audit trail every other control in the section assumes."""
    s = _bedrock({})
    s._check_bedrock()
    _renders(s, "BDR-01", "HIGH", contains="NOT configured")


def test_bdr01_logging_configured_with_no_destination_also_fails():
    """A config block with neither CloudWatch nor S3 set is logging that goes nowhere,
    which reads as enabled in the console and delivers nothing."""
    s = _bedrock({"textDataDeliveryEnabled": True})
    s._check_bedrock()
    _renders(s, "BDR-01", "HIGH", contains="no destination")


def test_bdr01_logging_to_cloudwatch_passes():
    s = _bedrock({"cloudWatchConfig": {"logGroupName": "/aws/bedrock"},
                  "textDataDeliveryEnabled": True})
    s._check_bedrock()
    assert not _ids(s, "BDR-01", "FAIL") and _ids(s, "BDR-01", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# CFN-01 / CFN-02 / CFN-03 (HIGH) — CloudFront. NB: CFN-* is CLOUDFRONT here;
# CloudFormation is STACK-*, which is a trap the section registry warns about.
# ══════════════════════════════════════════════════════════════════════════════
def _cloudfront(dist):
    cf = MagicMock()
    cf.list_distributions.return_value = {"DistributionList": {"Items": [dist]}}
    cf.get_distribution_config.return_value = {"DistributionConfig": {}}
    return _scanner("CLOUDFRONT", "cloudfront", cf, region="us-east-1")


def _dist(**kw):
    base = {"Id": "E123", "DomainName": "d1.cloudfront.net", "Status": "Deployed",
            "DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only"},
            "CacheBehaviors": {"Items": []},
            "ViewerCertificate": {"MinimumProtocolVersion": "TLSv1.2_2021",
                                  "CertificateSource": "acm"},
            "WebACLId": "arn:aws:wafv2:::webacl/x",
            "Logging": {"Enabled": True, "Bucket": "logs"}}
    base.update(kw)
    return base


def test_cfn01_allow_all_viewer_policy_fails():
    s = _cloudfront(_dist(DefaultCacheBehavior={"ViewerProtocolPolicy": "allow-all"}))
    s._check_cloudfront()
    _renders(s, "CFN-01", "HIGH", contains="HTTP allowed")


def test_cfn01_a_single_insecure_cache_behaviour_is_enough():
    """The default behaviour can be https-only while a path pattern is not, and the path
    is the one nobody looks at."""
    s = _cloudfront(_dist(CacheBehaviors={"Items": [
        {"PathPattern": "/legacy/*", "ViewerProtocolPolicy": "allow-all"}]}))
    s._check_cloudfront()
    _renders(s, "CFN-01", "HIGH", contains="/legacy/*")


def test_cfn01_https_only_passes():
    s = _cloudfront(_dist())
    s._check_cloudfront()
    assert not _ids(s, "CFN-01", "FAIL") and _ids(s, "CFN-01", "PASS")


def test_cfn02_insecure_minimum_tls_version_fails():
    s = _cloudfront(_dist(ViewerCertificate={"MinimumProtocolVersion": "TLSv1",
                                             "CertificateSource": "cloudfront"}))
    s._check_cloudfront()
    _renders(s, "CFN-02", "HIGH", contains="TLSv1")


def test_cfn02_modern_tls_policy_passes():
    s = _cloudfront(_dist())
    s._check_cloudfront()
    assert not _ids(s, "CFN-02", "FAIL") and _ids(s, "CFN-02", "PASS")


def test_cfn03_distribution_with_no_web_acl_fails():
    s = _cloudfront(_dist(WebACLId=""))
    s._check_cloudfront()
    _renders(s, "CFN-03", "HIGH", contains="No WAF Web ACL")


def test_cfn03_attached_web_acl_passes():
    s = _cloudfront(_dist())
    s._check_cloudfront()
    assert not _ids(s, "CFN-03", "FAIL") and _ids(s, "CFN-03", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# OSR-02 / OSR-04 / OSR-05 (HIGH) — OpenSearch domain posture
# ══════════════════════════════════════════════════════════════════════════════
def _opensearch(**cfg):
    base = {"DomainName": "logs",
            "DomainEndpointOptions": {"EnforceHTTPS": True,
                                      "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"},
            "EncryptionAtRestOptions": {"Enabled": True},
            "NodeToNodeEncryptionOptions": {"Enabled": True},
            "VPCOptions": {"SubnetIds": ["subnet-1"]},
            "AdvancedSecurityOptions": {"Enabled": True},
            "LogPublishingOptions": {}, "AccessPolicies": "{}"}
    base.update(cfg)
    osr = MagicMock()
    osr.list_domain_names.return_value = {"DomainNames": [{"DomainName": "logs"}]}
    osr.describe_domain.return_value = {"DomainStatus": base}
    return _scanner("OPENSEARCH", "opensearch", osr)


def test_osr02_encryption_at_rest_off_fails():
    s = _opensearch(EncryptionAtRestOptions={"Enabled": False})
    s._check_opensearch()
    _renders(s, "OSR-02", "HIGH", contains="Encryption at rest=OFF")


def test_osr04_domain_outside_a_vpc_fails():
    """A domain with no VPCOptions has a public endpoint, so its only protection is its
    access policy — and OSR-05 covers what happens when that is not fine-grained."""
    s = _opensearch(VPCOptions={})
    s._check_opensearch()
    _renders(s, "OSR-04", "HIGH", contains="Public endpoint")


def test_osr05_fine_grained_access_control_off_fails():
    s = _opensearch(AdvancedSecurityOptions={"Enabled": False})
    s._check_opensearch()
    _renders(s, "OSR-05", "HIGH", contains="Fine-grained access control=OFF")


def test_a_hardened_opensearch_domain_is_silent_on_all_three():
    s = _opensearch()
    s._check_opensearch()
    for cid in ("OSR-02", "OSR-04", "OSR-05"):
        assert not _ids(s, cid, "FAIL"), cid
        assert _ids(s, cid, "PASS"), cid


# ══════════════════════════════════════════════════════════════════════════════
# R53-03 (HIGH) — domain transfer lock
# ══════════════════════════════════════════════════════════════════════════════
def _route53_domains(detail):
    r53 = MagicMock()
    r53.list_hosted_zones.return_value = {"HostedZones": []}
    r53d = MagicMock()
    r53d.list_domains.return_value = {"Domains": [{"DomainName": "example.com"}]}
    r53d.get_domain_detail.return_value = detail
    s = _scanner("ROUTE53", "route53", r53, region="us-east-1")
    s._clients["route53domains:us-east-1"] = r53d
    return s


def test_r5303_domain_without_a_transfer_lock_fails():
    """Without the lock a domain can be transferred away on a compromised registrar
    account, which takes every name that resolves through it."""
    s = _route53_domains({"StatusList": [], "AutoRenew": True,
                          "ExpirationDate": "2027-01-01"})
    s._check_route53()
    _renders(s, "R53-03", "HIGH", contains="Transfer lock=OFF")


def test_r5303_locked_domain_passes():
    s = _route53_domains({"StatusList": ["clientTransferProhibited", "TRANSFER_LOCK"],
                          "AutoRenew": True, "ExpirationDate": "2027-01-01"})
    s._check_route53()
    assert not _ids(s, "R53-03", "FAIL") and _ids(s, "R53-03", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# LF-02 (HIGH) — a Lake Formation grant that switches Lake Formation off
# ══════════════════════════════════════════════════════════════════════════════
def _lakeformation(permissions):
    lf = MagicMock()
    lf.get_data_lake_settings.return_value = {"DataLakeSettings": {
        "CreateDatabaseDefaultPermissions": [], "CreateTableDefaultPermissions": []}}
    lf.list_permissions.return_value = {"PrincipalResourcePermissions": permissions}
    return _scanner("LAKEFORMATION", "lakeformation", lf)


def test_lf02_grant_to_iam_allowed_principals_fails():
    """For any resource carrying it, Lake Formation permissions are not consulted at all
    and IAM alone decides who reads the data — the control is present and inert."""
    s = _lakeformation([{
        "Principal": {"DataLakePrincipalIdentifier": "IAM_ALLOWED_PRINCIPALS"},
        "Resource": {"Table": {"Name": "customers", "DatabaseName": "prod"}},
        "Permissions": ["ALL"]}])
    s._check_lakeformation()
    _renders(s, "LF-02", "HIGH", contains="IAM_ALLOWED_PRINCIPALS")


def test_lf02_named_principal_grants_pass():
    s = _lakeformation([{
        "Principal": {"DataLakePrincipalIdentifier": f"arn:aws:iam::{OWN}:role/analyst"},
        "Resource": {"Table": {"Name": "customers", "DatabaseName": "prod"}},
        "Permissions": ["SELECT"]}])
    s._check_lakeformation()
    assert not _ids(s, "LF-02", "FAIL") and _ids(s, "LF-02", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# LSAIL-01 (HIGH) — a Lightsail instance open to the internet.
# It left "never observed" in tranche 5 because the new fixtures build instances;
# it only ever reached PASS, which is the whole point of this tranche.
# ══════════════════════════════════════════════════════════════════════════════
def _lightsail_ports(port_states):
    ls = MagicMock()
    ls.get_instances.return_value = {"instances": [{"name": "web-1",
                                                    "ipv6Addresses": []}]}
    ls.get_instance_port_states.return_value = {"portStates": port_states}
    ls.get_relational_databases.return_value = {"relationalDatabases": []}
    ls.get_buckets.return_value = {"buckets": []}
    return _scanner("LIGHTSAIL", "lightsail", ls)


def test_lsail01_world_open_port_fails():
    s = _lightsail_ports([{"fromPort": 22, "toPort": 22, "protocol": "tcp",
                           "cidrs": ["0.0.0.0/0"], "ipv6Cidrs": []}])
    s._check_lightsail()
    _renders(s, "LSAIL-01", "HIGH", contains="tcp/22")


def test_lsail01_ipv6_only_exposure_is_still_a_failure():
    """The IPv6 rule list is a separate column on the same port entry, and closing the
    IPv4 side is the mistake LSAIL-03 exists to warn about."""
    s = _lightsail_ports([{"fromPort": 3389, "toPort": 3389, "protocol": "tcp",
                           "cidrs": ["10.0.0.0/8"], "ipv6Cidrs": ["::/0"]}])
    s._check_lightsail()
    _renders(s, "LSAIL-01", "HIGH", contains="tcp/3389")


def test_lsail01_restricted_ports_pass():
    s = _lightsail_ports([{"fromPort": 22, "toPort": 22, "protocol": "tcp",
                           "cidrs": ["10.0.0.0/8"], "ipv6Cidrs": []}])
    s._check_lightsail()
    assert not _ids(s, "LSAIL-01", "FAIL") and _ids(s, "LSAIL-01", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# THREAT-01 (HIGH) — an active GuardDuty finding
# ══════════════════════════════════════════════════════════════════════════════
def _guardduty(findings):
    gd = MagicMock()
    gd.list_detectors.return_value = {"DetectorIds": ["det-1"]}
    gd.get_detector.return_value = {"Status": "ENABLED"}
    gd.get_paginator.return_value.paginate.return_value = [
        {"FindingIds": [f["Id"] for f in findings]}]
    gd.get_findings.return_value = {"Findings": findings}
    s = _scanner("THREAT", "guardduty", gd)
    s.graph = aws_graph.SecurityGraph()
    return s


def _finding(**kw):
    base = {"Id": "f-1", "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
            "Severity": 8.0, "Title": "SSH brute force",
            "Service": {"Archived": False},
            "Resource": {"ResourceType": "Instance",
                         "InstanceDetails": {"InstanceId": "i-1"}}}
    base.update(kw)
    return base


def test_threat01_active_guardduty_finding_fails():
    s = _guardduty([_finding()])
    s._check_threat()
    _renders(s, "THREAT-01", "HIGH", contains="UnauthorizedAccess:EC2/SSHBruteForce")


def test_threat01_sample_findings_are_excluded():
    """[SAMPLE] findings are generated by GuardDuty's own test button. Counting them
    would poison every prioritisation that reads severity."""
    s = _guardduty([_finding(Id="f-2", Title="[SAMPLE] SSH brute force")])
    s._check_threat()
    assert not _ids(s, "THREAT-01", "FAIL")
    assert _ids(s, "THREAT-01", "PASS")


def test_threat01_no_findings_passes():
    s = _guardduty([])
    s._check_threat()
    assert not _ids(s, "THREAT-01", "FAIL") and _ids(s, "THREAT-01", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# The accounting this tranche is answerable to
# ══════════════════════════════════════════════════════════════════════════════
#: The two of the thirteen that a fixture cannot honestly close, and why. Kept as data
#: so the next reader does not have to re-derive it from an AST pass.
ONLY_FAIL_IS_AN_ERROR_HANDLER = {
    "BDR-05": "its only literal FAIL is `_add(\"FAIL\", ..., str(e))` in an except "
              "handler; the over-broad-Bedrock-permission finding it exists for is a "
              "WARN, so its declared HIGH renders only when the IAM read throws",
    "DDB-01": "same shape — the AWS-owned-key finding is a WARN, and the FAIL is the "
              "list_tables error path",
}


def test_this_tranche_accounts_for_all_thirteen():
    import re as _re
    src = open(os.path.abspath(__file__), encoding="utf-8").read()
    driven = set(_re.findall(r'_renders\(s,\s*"([A-Z0-9-]+)"', src))
    claimed = {"BDR-01", "CFN-01", "CFN-02", "CFN-03", "LF-02", "LSAIL-01",
               "OSR-02", "OSR-04", "OSR-05", "R53-03", "THREAT-01"}
    assert claimed - driven == set(), f"claimed but not driven: {sorted(claimed - driven)}"
    assert len(claimed) + len(ONLY_FAIL_IS_AN_ERROR_HANDLER) == 13, (
        "thirteen HIGH checks ran without ever failing; %d driven + %d explained does "
        "not account for them" % (len(claimed), len(ONLY_FAIL_IS_AN_ERROR_HANDLER)))
