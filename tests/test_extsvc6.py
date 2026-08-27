"""Batch 6 — classifiers, the six scanner sections, and the ranking tool's own fix.

Recomputing the gap turned up three services ranked above everything built here that
could not be built at all: MediaStore (support ended 2025-11-13) and AWS WAF Classic's
two clients (2025-09-30). And `es` scoring 16 was a false positive in the ranking tool
itself — it and `opensearch` are the same service at different API versions, both signing
as `es`, and `opensearch` was already covered. The tool now deduplicates by signing name
and excludes discontinued services; both are asserted below.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from engine import aws_checkdef as C
from engine import aws_extsvc6 as E
from engine import aws_live_scanner as A

SECTIONS = {
    "_check_verifiedpermissions": ("VP-01", "VP-02"),
    "_check_cloudhsm": ("HSM-01", "HSM-02"),
    "_check_cloudwan": ("NWM-01",),
    "_check_managedgrafana": ("GRF-01",),
    "_check_auroradsql": ("DSQL-01",),
    "_check_fleetwise": ("FW-01", "FW-02"),
}


class _Deny:
    def __getattr__(self, name):
        def _raise(*a, **kw):
            raise Exception("AccessDeniedException")
        return _raise


def _scanner(client=None):
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["CLOUDHSM"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: client if client is not None else MagicMock()
    s._is_access_denied = lambda e: "AccessDenied" in str(e)
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def pol(principal="*"):
    return json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": principal, "Action": "*"}]})


# ── the omissions, recorded with dates ──────────────────────────────────────
def test_discontinued_services_are_declined_with_a_date():
    """Three of the four highest-ranked gaps were services no account can still have."""
    assert E.DISCONTINUED["mediastore"] == "2025-11-13"
    assert E.DISCONTINUED["waf"] == "2025-09-30"
    assert E.DISCONTINUED["waf-regional"] == "2025-09-30"


def test_no_check_was_built_for_a_discontinued_service():
    blob = " ".join(A.SECTIONS)
    assert "MEDIASTORE" not in blob and "WAFCLASSIC" not in blob


# ── the ranking tool's own correction ───────────────────────────────────────
def test_the_gap_tool_deduplicates_by_signing_name():
    """`es` and `opensearch` are one service; keying on client directories ranked an
    already-covered service at 16."""
    import coverage_gap as G
    rows = G.analyse()
    signs = [r["signing_name"] for r in rows]
    assert len(signs) == len(set(signs)), "the ranking still double-counts a service"


def test_opensearch_is_recognised_as_covered_under_its_signing_name():
    import coverage_gap as G
    rows = {r["signing_name"]: r for r in G.analyse()}
    assert rows["es"]["covered"] is True, "opensearch/es still reads as a gap"


def test_the_gap_tool_excludes_discontinued_services_from_the_ranking():
    import coverage_gap as G
    rows = G.analyse()
    dead = [r for r in rows if r["service"] in G.DISCONTINUED]
    assert dead and all(r["discontinued"] for r in dead)


def test_covered_resolution_goes_through_signing_names_not_client_strings():
    """cloudhsmv2 is the client; cloudhsm is the IAM prefix and the signing name."""
    import coverage_gap as G
    covered = G.covered_signing_names()
    assert "cloudhsm" in covered, "cloudhsmv2 did not resolve to its signing name"


# ── invariants across the six sections ──────────────────────────────────────
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


# ── Verified Permissions ────────────────────────────────────────────────────
def test_validation_off_is_reported():
    r = E.vp_policy_store({"policyStoreId": "ps-1",
                           "validationSettings": {"mode": "OFF"}})
    assert r["validation_off"] is True
    assert "never matches" in r["statement"]


def test_strict_validation_is_quiet():
    r = E.vp_policy_store({"policyStoreId": "ps-1",
                           "validationSettings": {"mode": "STRICT"}})
    assert r["validation_off"] is False and r["statement"] == ""


def test_deletion_protection_disabled_is_reported():
    r = E.vp_policy_store({"policyStoreId": "ps-1", "deletionProtection": "DISABLED"})
    assert r["unprotected"] is True and "one call" in r["protection_statement"]


def test_absent_validation_settings_are_unknown_not_off():
    r = E.vp_policy_store({"policyStoreId": "ps-1"})
    assert r["mode_known"] is False and r["validation_off"] is False


# ── CloudHSM ────────────────────────────────────────────────────────────────
def test_a_cluster_without_a_retention_policy_is_reported():
    r = E.hsm_cluster({"ClusterId": "c-1"})
    assert r["retention_known"] is False
    assert "ONE artefact that leaves an HSM" in r["statement"]


def test_a_cluster_with_a_retention_policy_is_quiet():
    r = E.hsm_cluster({"ClusterId": "c-1",
                       "BackupRetentionPolicy": {"Type": "DAYS", "Value": "90"}})
    assert r["retention_known"] is True and r["statement"] == ""


def test_a_wildcard_hsm_policy_is_reported():
    r = E.hsm_policy("c-1", pol("*"))
    assert r["public"] is True and "restored into another cluster" in r["statement"]


def test_a_scoped_hsm_policy_is_quiet():
    r = E.hsm_policy("c-1", pol({"AWS": "arn:aws:iam::111122223333:root"}))
    assert r["public"] is False


# ── Cloud WAN ───────────────────────────────────────────────────────────────
def test_a_wildcard_global_network_policy_is_reported():
    r = E.nwm_policy("gn-1", pol("*"))
    assert r["public"] is True and "segmentation of the whole global network" in r["statement"]


def test_no_global_network_policy_is_not_a_finding():
    assert E.nwm_policy("gn-1", None)["has_policy"] is False


# ── Managed Grafana ─────────────────────────────────────────────────────────
def test_organization_access_type_is_reported():
    r = E.grafana_workspace({"id": "g-1", "name": "obs",
                             "accountAccessType": "ORGANIZATION"})
    assert r["organization_wide"] is True and "reaches into other accounts" in r["statement"]


def test_current_account_access_is_quiet():
    r = E.grafana_workspace({"id": "g-1", "accountAccessType": "CURRENT_ACCOUNT"})
    assert r["organization_wide"] is False and r["statement"] == ""


def test_an_absent_access_type_is_unknown():
    assert E.grafana_workspace({"id": "g-1"})["access_known"] is False


# ── Aurora DSQL ─────────────────────────────────────────────────────────────
def test_deletion_protection_disabled_on_dsql_is_reported():
    r = E.dsql_cluster({"identifier": "cl-1", "deletionProtectionEnabled": False})
    assert r["protected"] is False and "one API call into a deliberate act" in r["statement"]


def test_deletion_protection_enabled_on_dsql_is_quiet():
    r = E.dsql_cluster({"identifier": "cl-1", "deletionProtectionEnabled": True})
    assert r["protected"] is True and r["statement"] == ""


def test_an_absent_dsql_protection_flag_is_unknown():
    assert E.dsql_cluster({"identifier": "cl-1"})["protection_known"] is False


# ── IoT FleetWise ───────────────────────────────────────────────────────────
def test_fleetwise_default_encryption_is_reported():
    r = E.fleetwise_encryption({"encryptionType": "FLEETWISE_DEFAULT_ENCRYPTION"})
    assert r["cmk"] is False and "re-identifiable" in r["statement"]


def test_fleetwise_kms_encryption_is_quiet():
    r = E.fleetwise_encryption({"encryptionType": "KMS_BASED_ENCRYPTION",
                                "kmsKeyId": "arn:key"})
    assert r["cmk"] is True and r["statement"] == ""


def test_fleetwise_logging_off_is_reported():
    r = E.fleetwise_logging({"cloudWatchLogDelivery": {"logType": "OFF"}})
    assert r["off"] is True


def test_fleetwise_logging_on_is_quiet():
    r = E.fleetwise_logging({"cloudWatchLogDelivery": {"logType": "ERROR"}})
    assert r["off"] is False and r["statement"] == ""


# ── section behaviour ───────────────────────────────────────────────────────
def test_the_verified_permissions_section_reports_both_gaps():
    c = MagicMock()
    c.list_policy_stores.return_value = {"policyStores": [{"policyStoreId": "ps-1"}]}
    c.get_policy_store.return_value = {"policyStoreId": "ps-1",
                                       "validationSettings": {"mode": "OFF"},
                                       "deletionProtection": "DISABLED"}
    s = _scanner(c)
    s._check_verifiedpermissions()
    assert _ids(s, "VP-01", "FAIL") and _ids(s, "VP-02", "FAIL")


def test_the_fleetwise_section_reports_default_encryption():
    c = MagicMock()
    c.get_encryption_configuration.return_value = {
        "encryptionType": "FLEETWISE_DEFAULT_ENCRYPTION"}
    c.get_logging_options.return_value = {"cloudWatchLogDelivery": {"logType": "ERROR"}}
    s = _scanner(c)
    s._check_fleetwise()
    assert _ids(s, "FW-01", "FAIL") and _ids(s, "FW-02", "PASS")


# ── robustness and wiring ───────────────────────────────────────────────────
@pytest.mark.parametrize("fn", [E.vp_policy_store, E.hsm_cluster, E.grafana_workspace,
                                E.dsql_cluster, E.fleetwise_encryption,
                                E.fleetwise_logging])
@pytest.mark.parametrize("bad", [None, {}, "x", 7])
def test_no_classifier_raises_on_malformed_input(fn, bad):
    fn(bad if isinstance(bad, dict) else None)


def test_policy_helpers_survive_malformed_input():
    E.hsm_policy("", "not json")
    E.nwm_policy("", None)


def test_cloudhsm_iam_prefix_is_cloudhsm_not_the_v2_client_name():
    """The sixth client-name trap: client `cloudhsmv2`, IAM prefix `cloudhsm`."""
    actions = [p.action for c in ("HSM-01", "HSM-02")
               for p in C.REGISTRY[c].permissions]
    assert actions and all(a.startswith("cloudhsm:") for a in actions)
    assert not any(a.startswith("cloudhsmv2:") for a in actions)


@pytest.mark.parametrize("section", ["VERIFIEDPERMISSIONS", "CLOUDHSM", "CLOUDWAN",
                                     "MANAGEDGRAFANA", "AURORADSQL", "FLEETWISE"])
def test_each_section_is_registered_and_labelled(section):
    assert section in A.SECTIONS and section in A.SECTION_LABELS


@pytest.mark.parametrize("cid", sorted(c for cs in SECTIONS.values() for c in cs))
def test_every_batch6_check_came_from_one_declaration(cid):
    from engine import aws_finding_detail as D
    from engine import aws_perm_ledger as L
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
