"""Batch 3 — classifiers and the six scanner sections.

First batch written on `aws_checkdef` from the start rather than retrofitted. Both the
check-map lockstep and the Terraform/CFN parity test passed on the first run, which is
the thing batches 1 and 2 each needed a separate corrective pass for.
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
from engine import aws_extsvc3 as E
from engine import aws_live_scanner as A

SECTIONS = {
    "_check_s3tables": ("S3T-01", "S3T-02"),
    "_check_vpclattice": ("LATT-01", "LATT-02"),
    "_check_codeartifact": ("CART-01",),
    "_check_directoryservice": ("DIRSVC-01", "DIRSVC-02"),
    "_check_prometheus": ("AMP-01",),
    "_check_xray": ("XRAY-01",),
}


class _Deny:
    def __getattr__(self, name):
        def _raise(*a, **kw):
            raise Exception("AccessDeniedException")
        return _raise


def _scanner(client=None):
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["XRAY"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: client if client is not None else MagicMock()
    s._is_access_denied = lambda e: "AccessDenied" in str(e)
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def pol(principal="*"):
    return json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": principal, "Action": "*", "Resource": "*"}]})


# ── invariants across all six sections ──────────────────────────────────────
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


# ── S3 Tables ───────────────────────────────────────────────────────────────
def test_a_wildcard_table_bucket_policy_is_reported():
    r = E.table_bucket_policy("arn:tb", pol("*"))
    assert r["public"] is True and "separate from the S3 bucket policies" in r["statement"]


def test_a_scoped_table_bucket_policy_is_quiet():
    r = E.table_bucket_policy("arn:tb", pol({"AWS": "arn:aws:iam::111122223333:root"}))
    assert r["public"] is False


def test_no_table_bucket_policy_is_not_a_finding():
    assert E.table_bucket_policy("arn:tb", None)["public"] is False


def test_sse_s3_table_encryption_is_reported():
    r = E.table_bucket_encryption("arn:tb", {"sseAlgorithm": "AES256"})
    assert r["kms"] is False and "no second, key-level control" in r["statement"]


def test_kms_table_encryption_is_quiet():
    r = E.table_bucket_encryption("arn:tb", {"sseAlgorithm": "aws:kms",
                                             "kmsKeyArn": "arn:key"})
    assert r["kms"] is True and r["statement"] == ""


def test_absent_table_encryption_is_unknown_not_unencrypted():
    r = E.table_bucket_encryption("arn:tb", {})
    assert r["known"] is False and r["statement"] == ""


# ── VPC Lattice ─────────────────────────────────────────────────────────────
def test_auth_type_none_is_reported():
    r = E.lattice_auth({"id": "svc-1", "name": "orders", "authType": "NONE"})
    assert r["unauthenticated"] is True
    assert "no caller identity involved at all" in r["statement"]


def test_auth_type_aws_iam_is_quiet():
    r = E.lattice_auth({"id": "svc-1", "authType": "AWS_IAM"})
    assert r["unauthenticated"] is False and r["statement"] == ""


def test_an_absent_auth_type_is_unknown_not_none():
    r = E.lattice_auth({"id": "svc-1"})
    assert r["known"] is False and r["unauthenticated"] is False


def test_a_wildcard_auth_policy_on_an_iam_service_is_reported():
    """Authentication and authorization are separate questions. This configuration
    answers the first properly and leaves the second open."""
    r = E.lattice_auth_policy("orders", pol("*"))
    assert r["permissive"] is True and "admits everyone" in r["statement"]


def test_a_scoped_auth_policy_is_quiet():
    r = E.lattice_auth_policy("orders", pol({"AWS": "arn:aws:iam::1:role/app"}))
    assert r["permissive"] is False


# ── CodeArtifact ────────────────────────────────────────────────────────────
def test_a_wildcard_codeartifact_policy_is_reported():
    r = E.codeartifact_policy("domain", "d1", pol("*"))
    assert r["public"] is True and "dependency-confusion" in r["statement"]


def test_the_kind_is_named_in_the_finding():
    assert "repository r1" in E.codeartifact_policy("repository", "r1", pol("*"))["statement"]


def test_a_scoped_codeartifact_policy_is_quiet():
    r = E.codeartifact_policy("domain", "d1", pol({"AWS": "arn:aws:iam::1:root"}))
    assert r["public"] is False


# ── Directory Service ───────────────────────────────────────────────────────
def test_ldaps_disabled_is_reported():
    r = E.directory_ldaps("d-1", [{"LDAPSStatus": "Disabled"}])
    assert r["disabled"] is True and "cleartext" in r["statement"]


def test_ldaps_enabled_is_quiet():
    r = E.directory_ldaps("d-1", [{"LDAPSStatus": "Enabled"}])
    assert r["disabled"] is False and r["statement"] == ""


def test_ldaps_enablefailed_is_reported_because_it_looks_configured():
    """EnableFailed protects nothing while appearing set."""
    r = E.directory_ldaps("d-1", [{"LDAPSStatus": "EnableFailed"}])
    assert r["failed"] is True and "easy to miss" in r["statement"]


def test_no_ldaps_settings_is_unknown_not_disabled():
    r = E.directory_ldaps("d-1", [])
    assert r["known"] is False and r["statement"] == ""


def test_a_directory_shared_externally_is_reported():
    r = E.directory_sharing("d-1", [{"SharedAccountId": "999988887777"}],
                            ["123456789012"])
    assert r["shared"] is True and "AUTHENTICATION boundary" in r["statement"]


def test_a_share_to_the_owning_account_is_not_external():
    r = E.directory_sharing("d-1", [{"SharedAccountId": "123456789012"}],
                            ["123456789012"])
    assert r["shared"] is False


# ── Managed Prometheus ──────────────────────────────────────────────────────
def test_a_workspace_without_a_cmk_is_reported():
    r = E.amp_workspace({"workspaceId": "ws-1"})
    assert r["cmk"] is False and "map of the estate" in r["statement"]


def test_a_workspace_with_a_cmk_is_quiet():
    r = E.amp_workspace({"workspaceId": "ws-1", "kmsKeyArn": "arn:key"})
    assert r["cmk"] is True and r["statement"] == ""


# ── X-Ray ───────────────────────────────────────────────────────────────────
def test_encryption_type_none_is_reported():
    r = E.xray_encryption({"Type": "NONE", "Status": "ACTIVE"})
    assert r["cmk"] is False and "readable record" in r["statement"]


def test_encryption_type_kms_is_quiet():
    r = E.xray_encryption({"Type": "KMS", "KeyId": "arn:key", "Status": "ACTIVE"})
    assert r["cmk"] is True and r["statement"] == ""


def test_an_absent_xray_type_is_unknown():
    assert E.xray_encryption({})["known"] is False


# ── section behaviour ───────────────────────────────────────────────────────
def test_the_xray_section_reports_default_encryption():
    c = MagicMock()
    c.get_encryption_config.return_value = {"EncryptionConfig": {"Type": "NONE"}}
    s = _scanner(c)
    s._check_xray()
    assert _ids(s, "XRAY-01", "FAIL")


def test_the_xray_section_passes_a_cmk():
    c = MagicMock()
    c.get_encryption_config.return_value = {
        "EncryptionConfig": {"Type": "KMS", "KeyId": "arn:key"}}
    s = _scanner(c)
    s._check_xray()
    assert _ids(s, "XRAY-01", "PASS")


def test_the_lattice_section_reports_an_unauthenticated_service():
    c = MagicMock()
    c.list_services.return_value = {"items": [{"id": "svc-1"}]}
    c.get_service.return_value = {"id": "svc-1", "name": "orders", "authType": "NONE"}
    s = _scanner(c)
    s._check_vpclattice()
    assert _ids(s, "LATT-01", "FAIL")


def test_the_directory_section_reports_disabled_ldaps():
    c = MagicMock()
    c.describe_directories.return_value = {
        "DirectoryDescriptions": [{"DirectoryId": "d-1"}]}
    c.describe_ldaps_settings.return_value = {
        "LDAPSSettingsInfo": [{"LDAPSStatus": "Disabled"}]}
    c.describe_shared_directories.return_value = {"SharedDirectories": []}
    s = _scanner(c)
    s._check_directoryservice()
    assert _ids(s, "DIRSVC-01", "FAIL")
    assert _ids(s, "DIRSVC-02", "PASS")


# ── robustness and registry wiring ──────────────────────────────────────────
@pytest.mark.parametrize("fn", [E.lattice_auth, E.amp_workspace, E.xray_encryption])
@pytest.mark.parametrize("bad", [None, {}, "x", 7])
def test_no_classifier_raises_on_malformed_input(fn, bad):
    fn(bad if isinstance(bad, dict) else None)


def test_policy_helpers_survive_malformed_input():
    E.table_bucket_policy("", None)
    E.table_bucket_encryption("", None)
    E.codeartifact_policy("", "", "not json")
    E.directory_ldaps("", None)
    E.directory_sharing("", None, None)
    E.lattice_auth_policy("", None)


@pytest.mark.parametrize("section", ["S3TABLES", "VPCLATTICE", "CODEARTIFACT",
                                     "DIRECTORYSERVICE", "PROMETHEUS", "XRAY"])
def test_each_section_is_registered_and_labelled(section):
    assert section in A.SECTIONS and section in A.SECTION_LABELS


@pytest.mark.parametrize("cid", sorted(c for cs in SECTIONS.values() for c in cs))
def test_every_batch3_check_came_from_one_declaration(cid):
    from engine import aws_finding_detail as D
    from engine import aws_perm_ledger as L
    d = C.REGISTRY[cid]
    assert A.CHECK_SEVERITY[cid] == d.severity
    assert A.COMPLIANCE_MAP[cid] == dict(d.compliance)
    assert A.REMEDIATION_MAP[cid] == d.remediation
    assert D.FINDING_DETAIL[cid]["risk"] == d.risk
    assert cid in L.REQUIREMENTS


def test_the_prometheus_iam_prefix_is_aps_not_the_client_name():
    """The boto3 client is `amp`; the IAM prefix is `aps`. Third instance of this trap
    in the codebase after bedrock-agentcore and sso/sso-admin."""
    actions = [p.action for p in C.REGISTRY["AMP-01"].permissions]
    assert actions and all(a.startswith("aps:") for a in actions)
    assert not any(a.startswith("amp:") for a in actions)


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(E), re.M)
