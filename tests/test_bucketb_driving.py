"""Driving tests for the bucket-B checks that gained a FAIL path and had no test.

WHY A SEPARATE FILE. 17 of the 22 checks changed by the bucket-B pass were already
driven by a test that built the bad configuration and asserted WARN; flipping those
expectations proved the new behaviour where it lived. These four had no such test:
the condition was reachable, nothing exercised it, and the change would otherwise
have shipped as an unproven claim -- which is the exact failure docs/CHECK_FIRING.md
was built to make visible, and it would have been perverse to introduce a new one
while closing others.

WHAT EACH ASSERTS. Not just the status. `_add` reads severity, compliance and
remediation from the catalogue only for a FAIL, so the point of the change is that
those three now render -- and that is what gets asserted, alongside the negative case
that keeps the check from becoming an unconditional finding.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_graph                                       # noqa: E402
from engine import aws_live_scanner as A                           # noqa: E402
from test_live_scanner import make_scanner                         # noqa: E402

OWN = "123456789012"
CLUSTER = "prod"
CLUSTER_ARN = f"arn:aws:eks:us-east-1:{OWN}:cluster/{CLUSTER}"


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _renders_catalogue(r, expected_severity):
    """A FAIL must carry what the catalogue holds for it -- that is the whole point."""
    assert r.severity == expected_severity, (
        f"{r.check_id} rendered {r.severity!r}, catalogue says {expected_severity!r}")
    assert r.remediation_cmd, f"{r.check_id} FAIL carries no remediation command"
    assert r.compliance, f"{r.check_id} FAIL carries no compliance mapping"


# ── SEC-02: rotation interval past the 90-day maximum ───────────────────────────
def _secret(days):
    return {"ARN": "arn:secret:x", "Name": "db-password", "RotationEnabled": True,
            "RotationRules": {"AutomaticallyAfterDays": days},
            "KmsKeyId": "arn:aws:kms:::key/cmk"}


def _secrets_scanner(secrets):
    s = make_scanner(sections=["SECRETS"])
    s.account = OWN
    sm = MagicMock()
    sm.get_paginator.return_value.paginate.return_value = [{"SecretList": secrets}]
    sm.get_resource_policy.return_value = {}
    s._clients["secretsmanager:us-east-1"] = sm
    return s


def test_sec02_rotation_past_ninety_days_fails():
    """SEC-01 FAILs when rotation is off. An interval of a year is the same risk
    arriving more slowly, and was reported at LOW with no remediation."""
    s = _secrets_scanner([_secret(365)])
    s._check_secrets()
    f = _ids(s, "SEC-02", "FAIL")
    assert f, "SEC-02 did not fire for a 365-day rotation interval"
    assert "365d" in f[0].message and "90-day" in f[0].message
    _renders_catalogue(f[0], "HIGH")


def test_sec02_within_ninety_days_passes():
    s = _secrets_scanner([_secret(30)])
    s._check_secrets()
    assert _ids(s, "SEC-02", "PASS") and not _ids(s, "SEC-02", "FAIL")


# ── WAF-04: default action ALLOW ────────────────────────────────────────────────
def _waf_scanner(default_action):
    s = make_scanner(sections=["WAF"])
    waf = MagicMock()
    waf.list_web_acls.return_value = {
        "WebACLs": [{"Name": "acl", "Id": "id1", "ARN": "arn:acl"}]}
    waf.get_logging_configuration.return_value = {"LoggingConfiguration": {}}
    waf.get_web_acl.return_value = {"WebACL": {
        "Rules": [{"Name": "aws", "Statement": {"ManagedRuleGroupStatement": {
            "VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}}}],
        "DefaultAction": default_action}}
    s._clients["wafv2:us-east-1"] = waf
    return s


def test_waf04_default_allow_fails():
    """A Web ACL that defaults to ALLOW only blocks what it explicitly names, which
    is the inverse of how a WAF is meant to be reasoned about."""
    s = _waf_scanner({"Allow": {}})
    s._check_waf()
    f = _ids(s, "WAF-04", "FAIL")
    assert f, "WAF-04 did not fire for a default-ALLOW Web ACL"
    assert "matching no rule is permitted" in f[0].message
    _renders_catalogue(f[0], "MEDIUM")


def test_waf04_default_block_is_silent():
    s = _waf_scanner({"Block": {}})
    s._check_waf()
    assert not _ids(s, "WAF-04")


# ── KIEM-02: namespace-admin / edit on an AWS principal ─────────────────────────
NS_ADMIN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy"


def _pager(key, items):
    p = MagicMock()
    p.paginate.return_value = [{key: items}]
    return p


def _eks(entries=None, assoc=None):
    eks = MagicMock()
    pagers = {"list_access_entries": _pager("accessEntries", entries or []),
              "list_associated_access_policies": _pager("associatedAccessPolicies", assoc or []),
              "list_pod_identity_associations": _pager("associations", [])}
    eks.get_paginator.side_effect = lambda op: pagers.get(op, _pager("x", []))
    eks.describe_access_entry.side_effect = lambda clusterName, principalArn: {
        "accessEntry": {"principalArn": principalArn, "type": "STANDARD"}}
    return eks


def _eks_scanner():
    s = make_scanner(["EKS"])
    s.account = OWN
    s.graph = aws_graph.SecurityGraph()
    return s


def test_kiem02_namespace_admin_fails():
    """KIEM-01 FAILs for cluster-admin. Namespace-admin is the same class of standing
    in-cluster privilege, one scope down, and can usually be escalated out of it."""
    parn = f"arn:aws:iam::{OWN}:role/team-deploy"
    s = _eks_scanner()
    s._check_eks_kiem(
        _eks(entries=[parn], assoc=[{"policyArn": NS_ADMIN,
                                     "accessScope": {"type": "namespace",
                                                     "namespaces": ["prod"]}}]),
        CLUSTER, {"arn": CLUSTER_ARN, "accessConfig": {"authenticationMode": "API"}})
    f = _ids(s, "KIEM-02", "FAIL")
    assert f, "KIEM-02 did not fire for a namespace-admin access entry"
    _renders_catalogue(f[0], "MEDIUM")


def test_kiem02_view_only_is_silent():
    view = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
    parn = f"arn:aws:iam::{OWN}:role/readonly"
    s = _eks_scanner()
    s._check_eks_kiem(
        _eks(entries=[parn], assoc=[{"policyArn": view, "accessScope": {"type": "cluster"}}]),
        CLUSTER, {"arn": CLUSTER_ARN, "accessConfig": {"authenticationMode": "API"}})
    assert not _ids(s, "KIEM-02", "FAIL")


# ── KSPM-04: the default ServiceAccount auto-mounts its API token ───────────────
def _ns(name):
    return {"metadata": {"name": name, "labels": {}}}


def _sa(name, namespace, automount=None):
    sa = {"metadata": {"name": name, "namespace": namespace}}
    if automount is not None:
        sa["automountServiceAccountToken"] = automount
    return sa


def _reachable_cluster():
    return {"arn": CLUSTER_ARN, "endpoint": "https://x",
            "certificateAuthority": {"data": "Zm9v"},
            "resourcesVpcConfig": {"endpointPublicAccess": True,
                                   "endpointPrivateAccess": True}}


def _run_kspm(s, *, namespaces=None, serviceaccounts=None):
    """Route the read-only K8s GETs this check makes to fixtures."""
    routes = {
        "/api/v1/namespaces": {"items": namespaces or []},
        "/api/v1/serviceaccounts": {"items": serviceaccounts or []},
    }

    def _get(ctx, path):
        for key, val in routes.items():
            if path.startswith(key):
                return val
        return {"items": []}

    s._k8s_get = _get
    s._check_kspm(CLUSTER, _reachable_cluster(), CLUSTER_ARN,
                  f"arn:aws:iam::{OWN}:role/kspm")


def test_kspm04_default_serviceaccount_automount_fails():
    """Every pod in the namespace that names no ServiceAccount gets this token
    mounted, so a single container escape reaches the API server as an identity."""
    s = _eks_scanner()
    _run_kspm(s, namespaces=[_ns("prod")],
              serviceaccounts=[_sa("default", "prod")])
    f = _ids(s, "KSPM-04", "FAIL")
    assert f, "KSPM-04 did not fire for a default ServiceAccount that auto-mounts"
    _renders_catalogue(f[0], "MEDIUM")


def test_kspm04_automount_disabled_is_silent():
    s = _eks_scanner()
    _run_kspm(s, namespaces=[_ns("prod")],
              serviceaccounts=[_sa("default", "prod", automount=False)])
    assert not _ids(s, "KSPM-04", "FAIL")


def test_kspm04_ignores_system_namespaces():
    """Telling an operator that kube-system's default SA automounts is noise: it is
    how the control plane works and is not theirs to change."""
    s = _eks_scanner()
    _run_kspm(s, namespaces=[_ns("kube-system")],
              serviceaccounts=[_sa("default", "kube-system")])
    assert not _ids(s, "KSPM-04", "FAIL")
