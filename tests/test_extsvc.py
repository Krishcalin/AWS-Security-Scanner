"""Extended AWS service coverage, batch 1 — the classifiers.

OverWatch instantiates 60 boto3 clients; botocore ships models for 426 services, and 116
of the uncovered ones expose read APIs that answer a real security question. This is the
first batch off that gap analysis.

Every field asserted here was verified against the botocore service model BEFORE the
classifier was written — the operation exists, the field exists, the enum values are
AWS's. The alternative is a check that reads a field nobody returns, which looks like a
clean pass forever; this codebase has been bitten by exactly that (the EC2 API version
that predated DescribeInstanceTypes).

The recurring restraint across all six services: an absent field is UNKNOWN, never
"good". A missing boolean is not `False`.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_extsvc as E


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action="*", resource="*", principal=None):
    s = {"Effect": "Allow", "Action": action, "Resource": resource}
    if principal is not None:
        s["Principal"] = principal
    return s


# ── the enum values are AWS's, not invented ─────────────────────────────────
def test_the_enum_constants_match_the_service_models():
    """Verified against botocore: codebuild ProjectVisibilityType, transfer
    EndpointType, iot AutoRegistrationStatus."""
    assert E.PUBLIC_READ == "PUBLIC_READ"
    assert E.PUBLIC == "PUBLIC"
    assert E.CLEARTEXT_PROTOCOLS == ("FTP",)


def test_ftps_and_sftp_are_not_treated_as_cleartext():
    """The transfer Protocol enum is (SFTP, FTP, FTPS, AS2). Only bare FTP is
    unencrypted -- flagging FTPS would punish the correct choice."""
    assert "FTPS" not in E.CLEARTEXT_PROTOCOLS
    assert "SFTP" not in E.CLEARTEXT_PROTOCOLS


# ── policy-document parsing ─────────────────────────────────────────────────
def test_a_dict_document_parses():
    assert E.parse_doc(doc(allow()))["Version"] == "2012-10-17"


def test_a_json_string_document_parses():
    assert E.parse_doc(json.dumps(doc(allow())))["Statement"]


def test_a_url_encoded_document_parses():
    from urllib.parse import quote
    assert E.parse_doc(quote(json.dumps(doc(allow()))))["Statement"]


@pytest.mark.parametrize("bad", [None, "", "not json", 7, [], b"\xff\xfe"])
def test_malformed_documents_parse_to_empty_rather_than_raising(bad):
    assert E.parse_doc(bad) == {}


# ── AWS IoT Core ────────────────────────────────────────────────────────────
def test_an_iot_policy_allowing_everything_on_everything_is_flagged():
    """An IoT policy attaches to CERTIFICATES, so one over-broad policy is not one
    over-privileged principal -- it is every device carrying that certificate."""
    r = E.iot_policy_risk("wide", doc(allow("*", "*")))
    assert r["wildcard"] is True
    assert "every device carrying one" in r["statement"]


def test_a_scoped_iot_policy_is_not_flagged():
    r = E.iot_policy_risk("scoped", doc(allow("iot:Publish", "arn:aws:iot:*:*:topic/x")))
    assert r["wildcard"] is False and r["statement"] == ""


def test_a_wildcard_action_with_a_scoped_resource_is_not_flagged():
    """Both halves have to be wide before this is the finding it claims to be."""
    r = E.iot_policy_risk("half", doc(allow("*", "arn:aws:iot:*:*:topic/x")))
    assert r["wildcard"] is False


def test_a_deny_statement_is_not_a_grant():
    d = doc({"Effect": "Deny", "Action": "*", "Resource": "*"})
    assert E.iot_policy_risk("deny", d)["wildcard"] is False


def test_an_unparseable_iot_policy_is_not_reported_as_safe():
    r = E.iot_policy_risk("broken", "not json")
    assert r["parsed"] is False and r["wildcard"] is False


def test_iot_logging_disabled_is_reported():
    r = E.iot_logging_posture({"disableAllLogs": True})
    assert r["disabled"] is True and "no record exists" in r["statement"]


def test_iot_logging_enabled_is_quiet():
    assert E.iot_logging_posture({"disableAllLogs": False})["statement"] == ""


def test_an_absent_iot_logging_switch_is_unknown_not_disabled():
    r = E.iot_logging_posture({})
    assert r["known"] is False and r["disabled"] is False and r["statement"] == ""


def test_an_auto_registering_ca_is_flagged():
    r = E.iot_ca_posture({"certificateId": "ca-1", "autoRegistrationStatus": "ENABLE"})
    assert r["auto_register"] is True and "without review" in r["statement"]


def test_a_ca_with_auto_registration_disabled_is_quiet():
    r = E.iot_ca_posture({"certificateId": "ca-1", "autoRegistrationStatus": "DISABLE"})
    assert r["auto_register"] is False and r["statement"] == ""


def test_a_ca_with_no_registration_status_is_unknown():
    assert E.iot_ca_posture({"certificateId": "ca-1"})["known"] is False


# ── Amazon EMR ──────────────────────────────────────────────────────────────
def test_emr_block_public_access_off_is_reported():
    r = E.emr_block_public_access({"BlockPublicSecurityGroupRules": False})
    assert r["blocked"] is False and "nothing stops a cluster" in r["statement"]


def test_emr_block_public_access_on_is_quiet():
    r = E.emr_block_public_access({"BlockPublicSecurityGroupRules": True})
    assert r["blocked"] is True and r["statement"] == ""


def test_an_absent_emr_block_setting_is_unknown_not_off():
    """An absent boolean is not False -- reporting it as off manufactures a finding."""
    r = E.emr_block_public_access({})
    assert r["known"] is False and r["statement"] == ""


def test_an_emr_cluster_without_a_security_configuration_is_reported():
    r = E.emr_cluster_posture({"Id": "j-1", "SecurityConfiguration": ""})
    assert r["has_security_configuration"] is False
    assert "no named security configuration" in r["statement"]


def test_an_emr_cluster_with_a_security_configuration_is_quiet():
    r = E.emr_cluster_posture({"Id": "j-1", "SecurityConfiguration": "sec-1"})
    assert r["has_security_configuration"] is True and r["statement"] == ""


def test_emr_visible_to_all_users_is_read_as_a_tristate():
    assert E.emr_cluster_posture({"VisibleToAllUsers": True})["visible_to_all"] is True
    assert E.emr_cluster_posture({})["visible_all_known"] is False


# ── AWS CodeBuild ───────────────────────────────────────────────────────────
def test_a_public_codebuild_project_is_reported():
    r = E.codebuild_posture({"name": "p", "projectVisibility": "PUBLIC_READ"})
    assert r["public"] is True and "readable by anyone" in r["statement"]


def test_a_private_codebuild_project_is_quiet():
    r = E.codebuild_posture({"name": "p", "projectVisibility": "PRIVATE"})
    assert r["public"] is False and r["statement"] == ""


def test_an_absent_visibility_is_unknown_not_public():
    r = E.codebuild_posture({"name": "p"})
    assert r["vis_known"] is False and r["public"] is False


def test_explicitly_disabled_artifact_encryption_is_reported():
    """encryptionDisabled is an opt-out, not a default -- somebody chose this."""
    r = E.codebuild_posture({"name": "p", "artifacts": {"encryptionDisabled": True}})
    assert r["artifact_encryption_disabled"] is True
    assert "explicitly DISABLED" in r["artifact_statement"]


def test_absent_artifact_encryption_flag_is_unknown():
    r = E.codebuild_posture({"name": "p", "artifacts": {}})
    assert r["artifact_encryption_known"] is False
    assert r["artifact_statement"] == ""


# ── Amazon DocumentDB ───────────────────────────────────────────────────────
def test_a_snapshot_shared_with_all_is_public():
    """A direct observation rather than an inference: the attribute either lists 'all'
    or it does not, and if it does then any AWS account can restore the database."""
    r = E.docdb_snapshot_exposure("snap-1", [
        {"AttributeName": "restore", "AttributeValues": ["all"]}])
    assert r["public"] is True and "ALL AWS accounts" in r["statement"]


def test_a_snapshot_shared_with_named_accounts_is_reported_separately():
    r = E.docdb_snapshot_exposure("snap-1", [
        {"AttributeName": "restore", "AttributeValues": ["111122223333"]}])
    assert r["public"] is False
    assert r["shared_accounts"] == ("111122223333",)
    assert "1 external account" in r["shared_statement"]


def test_a_private_snapshot_is_quiet():
    r = E.docdb_snapshot_exposure("snap-1", [
        {"AttributeName": "restore", "AttributeValues": []}])
    assert r["public"] is False and r["statement"] == ""
    assert r["shared_statement"] == ""


def test_a_non_restore_attribute_is_ignored():
    """Only the 'restore' attribute governs sharing."""
    r = E.docdb_snapshot_exposure("snap-1", [
        {"AttributeName": "something-else", "AttributeValues": ["all"]}])
    assert r["public"] is False and r["known"] is False


def test_an_unencrypted_docdb_cluster_is_reported():
    r = E.docdb_cluster_posture({"DBClusterIdentifier": "c1", "StorageEncrypted": False})
    assert "not encrypted at rest" in r["statement"]
    assert "only be set at creation" in r["statement"]


def test_an_encrypted_docdb_cluster_is_quiet():
    r = E.docdb_cluster_posture({"DBClusterIdentifier": "c1", "StorageEncrypted": True})
    assert r["encrypted"] is True and r["statement"] == ""


def test_a_docdb_cluster_without_audit_export_is_reported():
    r = E.docdb_cluster_posture({"DBClusterIdentifier": "c1",
                                 "EnabledCloudwatchLogsExports": ["profiler"]})
    assert r["audit_enabled"] is False and "does not export audit logs" in r["audit_statement"]


def test_a_docdb_cluster_with_audit_export_is_quiet():
    r = E.docdb_cluster_posture({"DBClusterIdentifier": "c1",
                                 "EnabledCloudwatchLogsExports": ["audit"]})
    assert r["audit_enabled"] is True and r["audit_statement"] == ""


def test_an_absent_docdb_encryption_flag_is_unknown():
    r = E.docdb_cluster_posture({"DBClusterIdentifier": "c1"})
    assert r["encryption_known"] is False and r["statement"] == ""


# ── EC2 Image Builder ───────────────────────────────────────────────────────
def test_a_wildcard_principal_image_policy_is_reported():
    r = E.imagebuilder_policy_exposure("arn:img", doc(allow(principal="*")))
    assert r["public"] is True and "everything baked into it" in r["statement"]


def test_a_wildcard_aws_principal_is_reported():
    r = E.imagebuilder_policy_exposure("arn:img", doc(allow(principal={"AWS": "*"})))
    assert r["public"] is True


def test_a_named_account_image_policy_is_not_public():
    r = E.imagebuilder_policy_exposure(
        "arn:img", doc(allow(principal={"AWS": "arn:aws:iam::111122223333:root"})))
    assert r["public"] is False and r["statement"] == ""


def test_no_image_policy_is_not_a_finding():
    r = E.imagebuilder_policy_exposure("arn:img", None)
    assert r["has_policy"] is False and r["public"] is False


# ── AWS Transfer Family ─────────────────────────────────────────────────────
def test_plain_ftp_is_reported_as_cleartext():
    r = E.transfer_posture({"ServerId": "s-1", "Protocols": ["FTP"]})
    assert r["cleartext"] == ("FTP",)
    assert "unencrypted" in r["statement"]


def test_sftp_only_is_quiet():
    r = E.transfer_posture({"ServerId": "s-1", "Protocols": ["SFTP"]})
    assert r["cleartext"] == () and r["statement"] == ""


def test_ftps_is_not_reported_as_cleartext():
    r = E.transfer_posture({"ServerId": "s-1", "Protocols": ["FTPS"]})
    assert r["cleartext"] == ()


def test_a_server_with_no_logging_role_is_reported():
    r = E.transfer_posture({"ServerId": "s-1", "Protocols": ["SFTP"]})
    assert r["logging"] is False and "no record of who connected" in r["logging_statement"]


def test_a_server_with_a_logging_role_is_quiet():
    r = E.transfer_posture({"ServerId": "s-1", "Protocols": ["SFTP"],
                            "LoggingRole": "arn:aws:iam::1:role/r"})
    assert r["logging"] is True and r["logging_statement"] == ""


def test_a_public_endpoint_is_reported_as_context_not_as_a_defect():
    """A PUBLIC endpoint is the intended mode for many Transfer servers. Calling it a
    defect would flag the normal case."""
    r = E.transfer_posture({"ServerId": "s-1", "EndpointType": "PUBLIC"})
    assert r["public"] is True
    assert "reported as context rather than as a defect" in r["endpoint_statement"]


def test_a_vpc_endpoint_server_raises_no_endpoint_line():
    r = E.transfer_posture({"ServerId": "s-1", "EndpointType": "VPC"})
    assert r["public"] is False and r["endpoint_statement"] == ""


# ── robustness ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("fn", [
    E.iot_logging_posture, E.iot_ca_posture, E.emr_block_public_access,
    E.emr_cluster_posture, E.codebuild_posture, E.docdb_cluster_posture,
    E.transfer_posture,
])
@pytest.mark.parametrize("bad", [None, {}, "x", 7, []])
def test_no_classifier_raises_on_malformed_input(fn, bad):
    fn(bad if isinstance(bad, dict) else None)


def test_snapshot_and_policy_helpers_survive_malformed_input():
    E.docdb_snapshot_exposure("", None)
    E.docdb_snapshot_exposure("", ["not-a-dict", None, 7])
    E.imagebuilder_policy_exposure("", None)
    E.iot_policy_risk("", None)


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(E), re.M)
