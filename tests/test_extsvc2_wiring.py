"""Batch 2 — classifiers and the six scanner sections.

Batch 2 is the first consumer of `aws_checkdef`. The clearest evidence the refactor
works is what is NOT in this file: there is no test asserting each check has a detail
page, a compliance mapping and a remediation, because a `CheckDef` cannot be constructed
without them. Batch 1 needed a hand-written detail page per check and a lockstep test to
catch the ones that were forgotten.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_checkdef as C
from engine import aws_extsvc2 as E
from engine import aws_live_scanner as A

SECTIONS = {
    "_check_networkfirewall": ("NFW-01", "NFW-02", "NFW-03"),
    "_check_lightsail": ("LSAIL-01", "LSAIL-02"),
    "_check_privateca": ("PCA-01",),
    "_check_quicksight": ("QS-01",),
    "_check_identitycenter": ("SSO-01",),
    "_check_glue": ("GLUE-01", "GLUE-02"),
}


class _Deny:
    def __getattr__(self, name):
        def _raise(*a, **kw):
            raise Exception("AccessDeniedException")
        return _raise


def _scanner(client=None):
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["GLUE"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: client if client is not None else MagicMock()
    s._is_access_denied = lambda e: "AccessDenied" in str(e)
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


# ── invariants for all six sections ─────────────────────────────────────────
@pytest.mark.parametrize("method,checks", sorted(SECTIONS.items()))
def test_a_denied_read_is_a_coverage_note_never_a_pass_or_a_finding(method, checks):
    s = _scanner(_Deny())
    getattr(s, method)()
    for cid in checks:
        assert not _ids(s, cid, "PASS"), cid
        assert not _ids(s, cid, "FAIL"), cid
    assert any(c in s._coverage.not_evaluated for c in checks), method


@pytest.mark.parametrize("method", sorted(SECTIONS))
def test_every_section_terminates_against_a_bare_magicmock(method):
    s = _scanner()
    done = threading.Event()

    def _go():
        try:
            getattr(s, method)()
        except Exception:
            pass
        finally:
            done.set()

    threading.Thread(target=_go, daemon=True).start()
    assert done.wait(timeout=20), f"{method} did not terminate"


# ── Network Firewall ────────────────────────────────────────────────────────
def test_a_firewall_with_no_log_destination_is_reported():
    r = E.nfw_logging("fw", {"LogDestinationConfigs": []})
    assert r["logging"] is False and "recording none of it" in r["statement"]


def test_a_firewall_with_a_log_destination_is_quiet():
    r = E.nfw_logging("fw", {"LogDestinationConfigs": [{"LogType": "FLOW"}]})
    assert r["logging"] is True and r["statement"] == ""


def test_a_stateless_default_of_pass_fails_open():
    r = E.nfw_policy_default("fw", {"StatelessDefaultActions": ["aws:pass"]})
    assert r["fails_open"] is True and "fails open" in r["statement"]


def test_forward_to_stateful_engine_is_not_fail_open():
    r = E.nfw_policy_default("fw", {"StatelessDefaultActions": ["aws:forward_to_sfe"]})
    assert r["fails_open"] is False and r["statement"] == ""


def test_absent_default_actions_are_unknown_not_fail_open():
    r = E.nfw_policy_default("fw", {})
    assert r["known"] is False and r["fails_open"] is False


def test_disabled_firewall_protections_are_reported():
    r = E.nfw_protection({"FirewallName": "fw", "DeleteProtection": False,
                          "SubnetChangeProtection": True,
                          "FirewallPolicyChangeProtection": True})
    assert r["unprotected"] == ("DeleteProtection",)


def test_absent_protection_flags_are_unknown_not_disabled():
    r = E.nfw_protection({"FirewallName": "fw"})
    assert r["known"] is False and r["unprotected"] == ()


# ── Lightsail ───────────────────────────────────────────────────────────────
def test_a_world_open_lightsail_port_is_reported():
    r = E.lightsail_ports("i1", [{"fromPort": 22, "toPort": 22, "protocol": "tcp",
                                  "cidrs": ["0.0.0.0/0"]}])
    assert r["world_open"] is True and "tcp/22" in r["open_ports"]


def test_a_scoped_lightsail_port_is_quiet():
    r = E.lightsail_ports("i1", [{"fromPort": 22, "toPort": 22, "protocol": "tcp",
                                  "cidrs": ["10.0.0.0/8"], "accessType": "Private"}])
    assert r["world_open"] is False


def test_an_ipv6_world_open_port_is_reported():
    r = E.lightsail_ports("i1", [{"fromPort": 80, "toPort": 80, "protocol": "tcp",
                                  "ipv6Cidrs": ["::/0"]}])
    assert r["world_open"] is True


def test_a_public_lightsail_database_is_reported():
    r = E.lightsail_database({"name": "db", "publiclyAccessible": True})
    assert r["public"] is True and "database password" in r["statement"]


def test_an_absent_lightsail_public_flag_is_unknown():
    r = E.lightsail_database({"name": "db"})
    assert r["public_known"] is False and r["statement"] == ""


# ── Private CA ──────────────────────────────────────────────────────────────
def test_a_wildcard_ca_policy_is_reported_as_a_trust_root_problem():
    doc = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*"}]}
    r = E.pca_policy_exposure("arn:ca", json.dumps(doc))
    assert r["public"] is True and "TRUST ROOT" in r["statement"]


def test_a_scoped_ca_policy_is_quiet():
    doc = {"Statement": [{"Effect": "Allow",
                          "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                          "Action": "acm-pca:IssueCertificate"}]}
    r = E.pca_policy_exposure("arn:ca", json.dumps(doc))
    assert r["public"] is False


def test_no_ca_policy_is_not_a_finding():
    r = E.pca_policy_exposure("arn:ca", None)
    assert r["has_policy"] is False and r["public"] is False


# ── QuickSight ──────────────────────────────────────────────────────────────
def test_account_public_sharing_enabled_is_reported():
    r = E.quicksight_account({"PublicSharingEnabled": True, "Edition": "ENTERPRISE"})
    assert r["public_sharing"] is True
    assert "bypasses the datastore" in r["statement"]


def test_account_public_sharing_disabled_is_quiet():
    r = E.quicksight_account({"PublicSharingEnabled": False})
    assert r["public_sharing"] is False and r["statement"] == ""


def test_an_absent_public_sharing_flag_is_unknown():
    assert E.quicksight_account({})["known"] is False


def test_a_dashboard_granted_to_the_public_principal_is_reported():
    r = E.quicksight_dashboard("d1", [{"Principal": "arn:aws:quicksight:::user/public"}])
    assert r["public"] is True


def test_a_normally_shared_dashboard_is_quiet():
    r = E.quicksight_dashboard("d1", [{"Principal": "arn:aws:quicksight:::user/alice"}])
    assert r["public"] is False


# ── IAM Identity Center ─────────────────────────────────────────────────────
def test_a_wildcard_permission_set_is_reported():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*",
                                     "Resource": "*"}]})
    r = E.sso_permission_set("AdminAccess", doc)
    assert r["admin"] is True and "every account" in r["statement"]


def test_a_scoped_permission_set_is_quiet():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                                     "Resource": "arn:aws:s3:::b/*"}]})
    assert E.sso_permission_set("ReadOnly", doc)["admin"] is False


def test_a_permission_set_with_no_inline_policy_is_not_flagged():
    r = E.sso_permission_set("Managed", None)
    assert r["parsed"] is False and r["admin"] is False


# ── Glue ────────────────────────────────────────────────────────────────────
def test_cleartext_connection_passwords_are_reported():
    r = E.glue_catalog_encryption(
        {"ConnectionPasswordEncryption": {"ReturnConnectionPasswordEncrypted": False}})
    assert r["passwords_encrypted"] is False
    assert "CLEARTEXT" in r["password_statement"]


def test_encrypted_connection_passwords_are_quiet():
    r = E.glue_catalog_encryption(
        {"ConnectionPasswordEncryption": {"ReturnConnectionPasswordEncrypted": True}})
    assert r["passwords_encrypted"] is True and r["password_statement"] == ""


def test_a_disabled_catalog_encryption_mode_is_reported():
    r = E.glue_catalog_encryption({"EncryptionAtRest": {"CatalogEncryptionMode":
                                                        "DISABLED"}})
    assert r["encrypted"] is False and "not encrypted at rest" in r["statement"]


def test_sse_kms_catalog_encryption_is_quiet():
    r = E.glue_catalog_encryption({"EncryptionAtRest": {"CatalogEncryptionMode":
                                                        "SSE-KMS"}})
    assert r["encrypted"] is True and r["statement"] == ""


def test_absent_glue_settings_are_unknown_not_disabled():
    r = E.glue_catalog_encryption({})
    assert r["mode_known"] is False and r["password_known"] is False


def test_a_public_glue_dev_endpoint_is_reported():
    r = E.glue_dev_endpoint({"EndpointName": "dev", "PublicAddress": "1.2.3.4"})
    assert r["public"] is True and "interactive shell" in r["statement"]


def test_a_private_glue_dev_endpoint_is_quiet():
    r = E.glue_dev_endpoint({"EndpointName": "dev"})
    assert r["public"] is False and r["statement"] == ""


# ── section behaviour ───────────────────────────────────────────────────────
def _glue_client(pw=True, mode="SSE-KMS", public_ep=False):
    c = MagicMock()
    c.get_data_catalog_encryption_settings.return_value = {
        "DataCatalogEncryptionSettings": {
            "ConnectionPasswordEncryption": {"ReturnConnectionPasswordEncrypted": pw},
            "EncryptionAtRest": {"CatalogEncryptionMode": mode}}}
    c.get_dev_endpoints.return_value = {
        "DevEndpoints": [{"EndpointName": "dev",
                          **({"PublicAddress": "1.2.3.4"} if public_ep else {})}]}
    return c


def test_the_glue_section_reports_cleartext_passwords():
    s = _scanner(_glue_client(pw=False))
    s._check_glue()
    assert _ids(s, "GLUE-01", "FAIL")


def test_the_glue_section_passes_a_healthy_catalog():
    s = _scanner(_glue_client(pw=True))
    s._check_glue()
    assert _ids(s, "GLUE-01", "PASS") and _ids(s, "GLUE-02", "PASS")


def test_the_glue_section_reports_a_public_dev_endpoint():
    s = _scanner(_glue_client(public_ep=True))
    s._check_glue()
    assert _ids(s, "GLUE-02", "FAIL")


def test_the_quicksight_section_reports_account_public_sharing():
    c = MagicMock()
    c.describe_account_settings.return_value = {
        "AccountSettings": {"PublicSharingEnabled": True}}
    s = _scanner(c)
    s._check_quicksight()
    assert _ids(s, "QS-01", "FAIL")


# ── registry wiring ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("section", ["NETWORKFIREWALL", "LIGHTSAIL", "PRIVATECA",
                                     "QUICKSIGHT", "IDENTITYCENTER", "GLUE"])
def test_each_section_is_registered_and_labelled(section):
    assert section in A.SECTIONS and section in A.SECTION_LABELS


@pytest.mark.parametrize("cid", sorted(c for cs in SECTIONS.values() for c in cs))
def test_every_batch2_check_came_from_one_declaration(cid):
    """The refactor, stated as a test: one CheckDef, five projections. Nothing here
    was hand-written into a map literal."""
    from engine import aws_finding_detail as D
    from engine import aws_perm_ledger as L
    assert cid in C.REGISTRY
    d = C.REGISTRY[cid]
    assert A.CHECK_SEVERITY[cid] == d.severity
    assert A.COMPLIANCE_MAP[cid] == dict(d.compliance)
    assert A.REMEDIATION_MAP[cid] == d.remediation
    assert D.FINDING_DETAIL[cid]["risk"] == d.risk
    assert cid in L.REQUIREMENTS


def test_the_identity_center_iam_prefix_is_sso_not_the_client_name():
    """The boto3 client is `sso-admin`; the IAM prefix is `sso`. Same trap as
    bedrock-agentcore -- a policy written with the client name grants nothing and
    looks correct in review."""
    actions = [p.action for p in C.REGISTRY["SSO-01"].permissions]
    assert actions and all(a.startswith("sso:") for a in actions)
    assert not any(a.startswith("sso-admin:") for a in actions)
