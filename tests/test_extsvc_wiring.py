"""Batch 1 — the six new scanner sections.

Each is TOP-LEVEL rather than nested inside an existing section. That is a direct
response to the data-perimeter check, which was hooked inside `_check_iam` and, when it
spun on a MagicMock continuation token, took every IAM-section test with it. A
self-contained section can only break itself.

Two invariants are asserted for all six: a denied read produces a COVERAGE NOTE rather
than a pass or a finding, and every pagination loop terminates against a bare MagicMock
(whose `.get()` returns a truthy mock).
"""
from __future__ import annotations

import io
import json
import os
import sys
import threading
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_live_scanner as A

SECTIONS = {
    "_check_iot": ("IOT-01", "IOT-02", "IOT-03"),
    "_check_emr": ("EMR-01", "EMR-02"),
    "_check_codebuild": ("CB-01", "CB-02"),
    "_check_docdb": ("DOCDB-01", "DOCDB-02", "DOCDB-03"),
    "_check_imagebuilder": ("IMGB-01",),
    "_check_transfer": ("XFER-01", "XFER-02", "XFER-03"),
}


def _scanner(client=None):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["IOT"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: client if client is not None else MagicMock()
    s._is_access_denied = lambda e: "AccessDenied" in str(e)
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _denied():
    c = MagicMock()
    for m in dir(c):
        pass
    c.side_effect = None
    return c


class _Deny:
    """A client whose every operation raises AccessDenied."""

    def __getattr__(self, name):
        def _raise(*a, **kw):
            raise Exception("AccessDeniedException")
        return _raise


# ── the invariants that hold for every new section ──────────────────────────
@pytest.mark.parametrize("method,checks", sorted(SECTIONS.items()))
def test_a_denied_read_never_becomes_a_pass_or_a_finding(method, checks):
    s = _scanner(_Deny())
    getattr(s, method)()
    for cid in checks:
        assert not _ids(s, cid, "PASS"), f"{cid} passed on a denied read"
        assert not _ids(s, cid, "FAIL"), f"{cid} failed on a denied read"


@pytest.mark.parametrize("method,checks", sorted(SECTIONS.items()))
def test_a_denied_read_is_recorded_as_a_coverage_note(method, checks):
    s = _scanner(_Deny())
    getattr(s, method)()
    assert any(c in s._coverage.not_evaluated for c in checks), \
        f"{method}: denial left no coverage note"


@pytest.mark.parametrize("method", sorted(SECTIONS))
def test_every_section_terminates_against_a_bare_magicmock(method):
    """A MagicMock's .get() returns a truthy mock, so an unguarded `while token`
    never exits -- the defect that cost a suite run in the data-perimeter section."""
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


# ── IoT ─────────────────────────────────────────────────────────────────────
def _iot(policy_doc=None, disable_logs=False, ca_auto="DISABLE"):
    c = MagicMock()
    c.list_policies.return_value = {"policies": [{"policyName": "p1"}]}
    c.get_policy.return_value = {"policyDocument": json.dumps(
        policy_doc or {"Statement": [{"Effect": "Allow", "Action": "iot:Publish",
                                      "Resource": "arn:aws:iot:::topic/x"}]})}
    c.get_v2_logging_options.return_value = {"disableAllLogs": disable_logs}
    c.list_ca_certificates.return_value = {"certificates": [{"certificateId": "ca-1"}]}
    c.describe_ca_certificate.return_value = {
        "certificateDescription": {"certificateId": "ca-1",
                                   "autoRegistrationStatus": ca_auto}}
    return c


def test_a_wildcard_iot_policy_fails():
    s = _scanner(_iot({"Statement": [{"Effect": "Allow", "Action": "*",
                                      "Resource": "*"}]}))
    s._check_iot()
    assert _ids(s, "IOT-01", "FAIL")


def test_a_scoped_iot_policy_passes():
    s = _scanner(_iot())
    s._check_iot()
    assert _ids(s, "IOT-01", "PASS") and not _ids(s, "IOT-01", "FAIL")


def test_iot_logging_disabled_fails():
    s = _scanner(_iot(disable_logs=True))
    s._check_iot()
    assert _ids(s, "IOT-02", "FAIL")


def test_iot_logging_enabled_passes():
    s = _scanner(_iot(disable_logs=False))
    s._check_iot()
    assert _ids(s, "IOT-02", "PASS")


def test_an_auto_registering_ca_fails():
    s = _scanner(_iot(ca_auto="ENABLE"))
    s._check_iot()
    assert _ids(s, "IOT-03", "FAIL")


# ── EMR ─────────────────────────────────────────────────────────────────────
def _emr(blocked=True, sec_config="sec-1"):
    c = MagicMock()
    c.get_block_public_access_configuration.return_value = {
        "BlockPublicAccessConfiguration": {"BlockPublicSecurityGroupRules": blocked}}
    c.list_clusters.return_value = {"Clusters": [{"Id": "j-1"}]}
    c.describe_cluster.return_value = {
        "Cluster": {"Id": "j-1", "SecurityConfiguration": sec_config}}
    return c


def test_emr_block_public_access_off_fails():
    s = _scanner(_emr(blocked=False))
    s._check_emr()
    assert _ids(s, "EMR-01", "FAIL")


def test_emr_block_public_access_on_passes():
    s = _scanner(_emr(blocked=True))
    s._check_emr()
    assert _ids(s, "EMR-01", "PASS")


def test_an_emr_cluster_without_security_config_fails():
    s = _scanner(_emr(sec_config=""))
    s._check_emr()
    assert _ids(s, "EMR-02", "FAIL")


# ── CodeBuild ───────────────────────────────────────────────────────────────
def _cb(visibility="PRIVATE", enc_disabled=False):
    c = MagicMock()
    c.list_projects.return_value = {"projects": ["p1"]}
    c.batch_get_projects.return_value = {"projects": [
        {"name": "p1", "projectVisibility": visibility,
         "artifacts": {"encryptionDisabled": enc_disabled}}]}
    return c


def test_a_public_codebuild_project_fails():
    s = _scanner(_cb("PUBLIC_READ"))
    s._check_codebuild()
    assert _ids(s, "CB-01", "FAIL")


def test_a_private_codebuild_project_passes():
    s = _scanner(_cb("PRIVATE"))
    s._check_codebuild()
    assert _ids(s, "CB-01", "PASS")


def test_disabled_artifact_encryption_fails():
    s = _scanner(_cb(enc_disabled=True))
    s._check_codebuild()
    assert _ids(s, "CB-02", "FAIL")


# ── DocumentDB ──────────────────────────────────────────────────────────────
def _docdb(share=None, encrypted=True, logs=("audit",)):
    c = MagicMock()
    c.describe_db_cluster_snapshots.return_value = {
        "DBClusterSnapshots": [{"DBClusterSnapshotIdentifier": "snap-1"}]}
    c.describe_db_cluster_snapshot_attributes.return_value = {
        "DBClusterSnapshotAttributesResult": {"DBClusterSnapshotAttributes": [
            {"AttributeName": "restore", "AttributeValues": list(share or [])}]}}
    c.describe_db_clusters.return_value = {"DBClusters": [
        {"DBClusterIdentifier": "c1", "StorageEncrypted": encrypted,
         "EnabledCloudwatchLogsExports": list(logs)}]}
    return c


def test_a_public_docdb_snapshot_fails():
    s = _scanner(_docdb(share=["all"]))
    s._check_docdb()
    f = _ids(s, "DOCDB-01", "FAIL")
    assert f and "ALL AWS accounts" in f[0].message


def test_a_snapshot_shared_with_a_named_account_warns_rather_than_fails():
    s = _scanner(_docdb(share=["111122223333"]))
    s._check_docdb()
    assert _ids(s, "DOCDB-01", "WARN") and not _ids(s, "DOCDB-01", "FAIL")


def test_a_private_docdb_snapshot_passes():
    s = _scanner(_docdb(share=[]))
    s._check_docdb()
    assert _ids(s, "DOCDB-01", "PASS")


def test_an_unencrypted_docdb_cluster_fails():
    s = _scanner(_docdb(encrypted=False))
    s._check_docdb()
    assert _ids(s, "DOCDB-02", "FAIL")


def test_a_docdb_cluster_without_audit_export_fails():
    s = _scanner(_docdb(logs=("profiler",)))
    s._check_docdb()
    assert _ids(s, "DOCDB-03", "FAIL")


# ── Image Builder ───────────────────────────────────────────────────────────
def _ib(principal=None):
    c = MagicMock()
    c.list_images.return_value = {"imageVersionList": [{"arn": "arn:img:1"}]}
    stmt = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    if principal is not None:
        stmt["Principal"] = principal
    c.get_image_policy.return_value = {"policy": json.dumps({"Statement": [stmt]})}
    return c


def test_a_wildcard_principal_image_policy_fails():
    s = _scanner(_ib(principal="*"))
    s._check_imagebuilder()
    assert _ids(s, "IMGB-01", "FAIL")


def test_a_scoped_image_policy_passes():
    s = _scanner(_ib(principal={"AWS": "arn:aws:iam::111122223333:root"}))
    s._check_imagebuilder()
    assert _ids(s, "IMGB-01", "PASS")


# ── Transfer Family ─────────────────────────────────────────────────────────
def _xfer(protocols=("SFTP",), logging_role="arn:role", endpoint="VPC"):
    c = MagicMock()
    c.list_servers.return_value = {"Servers": [{"ServerId": "s-1"}]}
    c.describe_server.return_value = {"Server": {
        "ServerId": "s-1", "Protocols": list(protocols),
        "LoggingRole": logging_role, "EndpointType": endpoint}}
    return c


def test_plain_ftp_fails():
    s = _scanner(_xfer(protocols=("FTP",)))
    s._check_transfer()
    assert _ids(s, "XFER-01", "FAIL")


def test_sftp_only_passes():
    s = _scanner(_xfer(protocols=("SFTP",)))
    s._check_transfer()
    assert _ids(s, "XFER-01", "PASS")


def test_ftps_is_not_reported_as_cleartext():
    s = _scanner(_xfer(protocols=("FTPS",)))
    s._check_transfer()
    assert _ids(s, "XFER-01", "PASS")


def test_a_server_without_a_logging_role_fails():
    s = _scanner(_xfer(logging_role=""))
    s._check_transfer()
    assert _ids(s, "XFER-02", "FAIL")


def test_a_public_endpoint_is_informational_not_a_failure():
    s = _scanner(_xfer(endpoint="PUBLIC"))
    s._check_transfer()
    assert _ids(s, "XFER-03", "INFO") and not _ids(s, "XFER-03", "FAIL")


def test_a_vpc_endpoint_emits_no_endpoint_line():
    s = _scanner(_xfer(endpoint="VPC"))
    s._check_transfer()
    assert not _ids(s, "XFER-03")


# ── registry wiring ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("section", ["IOT", "EMR", "CODEBUILD", "DOCDB",
                                     "IMAGEBUILDER", "TRANSFER"])
def test_each_section_is_registered_labelled_and_dispatched(section):
    assert section in A.SECTIONS
    assert section in A.SECTION_LABELS
    method = f"_check_{section.lower()}"
    assert hasattr(A.AWSLiveScanner, method), method
    # the dispatch table is an inline dict literal, so assert on the source
    src = io.open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "aws_live_scanner.py"), encoding="utf-8").read()
    assert f'"{section}":' in src and f"self.{method}," in src


@pytest.mark.parametrize("cid", sorted(c for cs in SECTIONS.values() for c in cs))
def test_every_new_check_is_fully_mapped(cid):
    """The lockstep rule: a check that scores but cannot be explained or fixed is
    worse than no check at all."""
    import aws_finding_detail as D
    assert cid in A.CHECK_SEVERITY
    assert cid in A.COMPLIANCE_MAP
    assert cid in A.REMEDIATION_MAP
    assert cid in D.FINDING_DETAIL
    assert "aws " in A.REMEDIATION_MAP[cid]
