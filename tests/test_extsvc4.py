"""Batch 4 — classifiers and the five scanner sections.

MediaStore was in the requested set and is absent on purpose: AWS ended support for it on
2025-11-13. A check against a discontinued service can never fire, and a check that
cannot fire reads as coverage — which is worse than not having one. A test below pins
that as a decision rather than an oversight.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_checkdef as C
import aws_extsvc4 as E
import aws_live_scanner as A

SECTIONS = {
    "_check_lakeformation": ("LF-01", "LF-02"),
    "_check_workspacesweb": ("WSW-01", "WSW-02"),
    "_check_storagegateway": ("SGW-01", "SGW-02"),
    "_check_paymentcrypto": ("PAY-01",),
    "_check_managedblockchain": ("MBC-01",),
}


class _Deny:
    def __getattr__(self, name):
        def _raise(*a, **kw):
            raise Exception("AccessDeniedException")
        return _raise


def _scanner(client=None):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False,
                             sections=["LAKEFORMATION"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: client if client is not None else MagicMock()
    s._is_access_denied = lambda e: "AccessDenied" in str(e)
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def princ(name):
    return {"Principal": {"DataLakePrincipalIdentifier": name}}


# ── the omission, recorded ──────────────────────────────────────────────────
def test_mediastore_is_absent_on_purpose_not_by_oversight():
    """Support ended 2025-11-13. A check that cannot fire reads as coverage."""
    assert E.MEDIASTORE_EOL == "2025-11-13"
    assert not any(k.startswith("MSTORE") for k in C.REGISTRY)
    assert "MEDIASTORE" not in A.SECTIONS


# ── invariants across the five sections ─────────────────────────────────────
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


# ── Lake Formation ──────────────────────────────────────────────────────────
def test_iam_allowed_principals_in_the_database_default_is_reported():
    """The sentinel does not weaken Lake Formation, it switches it off for the
    resource: LF grants are not evaluated and plain IAM governs."""
    r = E.lf_default_permissions(
        {"CreateDatabaseDefaultPermissions": [princ("IAM_ALLOWED_PRINCIPALS")]})
    assert r["bypassed"] is True and "databases" in r["where"]
    assert "does NOT evaluate its own grants" in r["statement"]


def test_iam_allowed_principals_in_the_table_default_is_reported():
    r = E.lf_default_permissions(
        {"CreateTableDefaultPermissions": [princ("IAM_ALLOWED_PRINCIPALS")]})
    assert r["where"] == ("tables",)


def test_cleared_defaults_are_quiet():
    r = E.lf_default_permissions({"CreateDatabaseDefaultPermissions": [],
                                  "CreateTableDefaultPermissions": []})
    assert r["bypassed"] is False and r["statement"] == ""


def test_a_named_principal_in_the_defaults_is_not_the_bypass():
    r = E.lf_default_permissions(
        {"CreateDatabaseDefaultPermissions": [princ("arn:aws:iam::1:role/data")]})
    assert r["bypassed"] is False


def test_an_existing_grant_to_the_bypass_principal_is_reported():
    """Clearing the default does nothing about resources that already exist -- the
    part most often missed."""
    rows = [{**princ("IAM_ALLOWED_PRINCIPALS"),
             "Resource": {"Table": {"Name": "orders"}}}]
    r = E.lf_grants(rows)
    assert r["bypassed"] is True and "orders" in r["resources"]


def test_grants_to_real_principals_are_quiet():
    rows = [{**princ("arn:aws:iam::1:role/analyst"),
             "Resource": {"Table": {"Name": "orders"}}}]
    assert E.lf_grants(rows)["bypassed"] is False


def test_the_admin_list_is_surfaced():
    r = E.lf_default_permissions({"DataLakeAdmins": [princ("arn:aws:iam::1:role/admin")]})
    assert r["admins"] == ("arn:aws:iam::1:role/admin",)


# ── WorkSpaces Web ──────────────────────────────────────────────────────────
def test_a_portal_without_ip_access_settings_is_reported():
    r = E.wsw_portal({"portalArn": "arn:p", "displayName": "corp"})
    assert r["ip_restricted"] is False
    assert "opened from any network" in r["statement"]


def test_a_portal_with_ip_access_settings_is_quiet():
    r = E.wsw_portal({"portalArn": "arn:p", "ipAccessSettingsArn": "arn:ip"})
    assert r["ip_restricted"] is True and r["statement"] == ""


def test_a_portal_with_neither_logger_is_reported():
    r = E.wsw_portal({"portalArn": "arn:p"})
    assert "no record of who used" in r["logging_statement"]


def test_either_logger_satisfies_the_logging_check():
    a = E.wsw_portal({"portalArn": "arn:p", "userAccessLoggingSettingsArn": "arn:l"})
    b = E.wsw_portal({"portalArn": "arn:p", "sessionLoggerArn": "arn:s"})
    assert a["logging_statement"] == "" and b["logging_statement"] == ""


# ── Storage Gateway ─────────────────────────────────────────────────────────
def test_a_world_open_nfs_client_list_is_reported():
    r = E.sgw_nfs_share({"FileShareId": "share-1", "ClientList": ["0.0.0.0/0"]})
    assert r["world_open"] is True and "window onto the S3 bucket" in r["statement"]


def test_a_scoped_nfs_client_list_is_quiet():
    r = E.sgw_nfs_share({"FileShareId": "share-1", "ClientList": ["10.0.0.0/8"]})
    assert r["world_open"] is False and r["statement"] == ""


def test_an_empty_client_list_is_not_world_open():
    assert E.sgw_nfs_share({"FileShareId": "s", "ClientList": []})["world_open"] is False


def test_a_share_without_a_cmk_is_reported():
    r = E.sgw_share_encryption({"FileShareId": "s", "KMSEncrypted": False})
    assert r["cmk"] is False and "customer-managed key" in r["statement"]


def test_an_absent_kms_flag_is_unknown_not_unencrypted():
    r = E.sgw_share_encryption({"FileShareId": "s"})
    assert r["known"] is False and r["statement"] == ""


# ── Payment Cryptography ────────────────────────────────────────────────────
def test_an_exportable_payment_key_is_reported():
    r = E.paycrypt_key({"KeyArn": "arn:key/1", "Exportable": True})
    assert r["exportable"] is True and "out of the HSM" in r["statement"]


def test_a_non_exportable_payment_key_is_quiet():
    r = E.paycrypt_key({"KeyArn": "arn:key/1", "Exportable": False})
    assert r["exportable"] is False and r["statement"] == ""


def test_an_absent_exportable_flag_is_unknown():
    assert E.paycrypt_key({"KeyArn": "arn:key/1"})["known"] is False


def test_a_wildcard_payment_key_policy_is_reported():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*",
                                     "Action": "*"}]})
    r = E.paycrypt_policy("arn:key/1", doc)
    assert r["public"] is True and "card data" in r["statement"]


# ── Managed Blockchain ──────────────────────────────────────────────────────
def _member(ca_logs=None):
    m = {"Id": "m-1", "Name": "acme"}
    if ca_logs is not None:
        m["LogPublishingConfiguration"] = {
            "Fabric": {"CaLogs": {"Cloudwatch": {"Enabled": ca_logs}}}}
    return m


def test_a_member_without_ca_logging_is_reported():
    r = E.mbc_member(_member(ca_logs=False))
    assert r["ca_logging"] is False and "admits identities" in r["statement"]


def test_a_member_with_ca_logging_is_quiet():
    r = E.mbc_member(_member(ca_logs=True))
    assert r["ca_logging"] is True and r["statement"] == ""


def test_an_absent_log_configuration_is_unknown_not_disabled():
    r = E.mbc_member(_member())
    assert r["ca_logging_known"] is False and r["statement"] == ""


# ── section behaviour ───────────────────────────────────────────────────────
def test_the_lakeformation_section_reports_the_bypass():
    c = MagicMock()
    c.get_data_lake_settings.return_value = {"DataLakeSettings": {
        "CreateDatabaseDefaultPermissions": [princ("IAM_ALLOWED_PRINCIPALS")]}}
    c.list_permissions.return_value = {"PrincipalResourcePermissions": []}
    s = _scanner(c)
    s._check_lakeformation()
    assert _ids(s, "LF-01", "FAIL") and _ids(s, "LF-02", "PASS")


def test_the_workspacesweb_section_reports_an_unrestricted_portal():
    c = MagicMock()
    c.list_portals.return_value = {"portals": [{"portalArn": "arn:p"}]}
    c.get_portal.return_value = {"portal": {"portalArn": "arn:p",
                                            "displayName": "corp"}}
    s = _scanner(c)
    s._check_workspacesweb()
    assert _ids(s, "WSW-01", "FAIL") and _ids(s, "WSW-02", "FAIL")


def test_the_paymentcrypto_section_reports_an_exportable_key():
    c = MagicMock()
    c.list_keys.return_value = {"Keys": [{"KeyArn": "arn:aws:pc:::key/abc"}]}
    c.get_key.return_value = {"Key": {"KeyArn": "arn:aws:pc:::key/abc",
                                      "Exportable": True}}
    s = _scanner(c)
    s._check_paymentcrypto()
    assert _ids(s, "PAY-01", "FAIL")


# ── robustness and registry wiring ──────────────────────────────────────────
@pytest.mark.parametrize("fn", [E.lf_default_permissions, E.wsw_portal,
                                E.sgw_nfs_share, E.sgw_share_encryption,
                                E.paycrypt_key, E.mbc_member])
@pytest.mark.parametrize("bad", [None, {}, "x", 7])
def test_no_classifier_raises_on_malformed_input(fn, bad):
    fn(bad if isinstance(bad, dict) else None)


def test_sequence_helpers_survive_malformed_input():
    E.lf_grants(None)
    E.lf_grants(["not-a-dict", None])
    E.paycrypt_policy("", "not json")


@pytest.mark.parametrize("section", ["LAKEFORMATION", "WORKSPACESWEB",
                                     "STORAGEGATEWAY", "PAYMENTCRYPTO",
                                     "MANAGEDBLOCKCHAIN"])
def test_each_section_is_registered_and_labelled(section):
    assert section in A.SECTIONS and section in A.SECTION_LABELS


@pytest.mark.parametrize("cid", sorted(c for cs in SECTIONS.values() for c in cs))
def test_every_batch4_check_came_from_one_declaration(cid):
    import aws_finding_detail as D
    import aws_perm_ledger as L
    d = C.REGISTRY[cid]
    assert A.CHECK_SEVERITY[cid] == d.severity
    assert A.REMEDIATION_MAP[cid] == d.remediation
    assert D.FINDING_DETAIL[cid]["risk"] == d.risk
    assert cid in L.REQUIREMENTS


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(E), re.M)
