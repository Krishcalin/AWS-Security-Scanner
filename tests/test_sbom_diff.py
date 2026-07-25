"""Phase-4 Slice-4 · B5 — SBOM diff (pure) + the service resolver (auto-pair, isolation)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_sbom_diff as sd
import aws_state
import cnapp_connectors as cc
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"


# ── pure diff ─────────────────────────────────────────────────────────────────
def test_diff_added_removed_version_and_license_change():
    a = [{"purl_identity": "pkg:npm/a", "name": "a", "version": "1.0", "license_spdx": "MIT"},
         {"purl_identity": "pkg:npm/b", "name": "b", "version": "2.0", "license_spdx": "MIT"},
         {"purl_identity": "pkg:npm/c", "name": "c", "version": "3.0", "license_spdx": "MIT"}]
    b = [{"purl_identity": "pkg:npm/a", "name": "a", "version": "1.1", "license_spdx": "MIT"},        # bump
         {"purl_identity": "pkg:npm/b", "name": "b", "version": "2.0", "license_spdx": "GPL-3.0-only"},  # license
         {"purl_identity": "pkg:npm/d", "name": "d", "version": "4.0", "license_spdx": "MIT"}]        # +d, -c
    d = sd.diff_snapshots(a, [], b, [])
    assert [x.name for x in d.added] == ["d"]
    assert [x.name for x in d.removed] == ["c"]
    ch = {x.name: x for x in d.changed}
    assert ch["a"].change == "version_changed" and ch["a"].from_version == "1.0" and ch["a"].to_version == "1.1"
    assert ch["b"].change == "license_changed" and ch["b"].to_license == "GPL-3.0-only"


def test_version_bump_is_a_change_not_add_plus_remove():
    a = [{"purl_identity": "pkg:npm/x", "name": "x", "version": "1.0"}]
    b = [{"purl_identity": "pkg:npm/x", "name": "x", "version": "2.0"}]
    d = sd.diff_snapshots(a, [], b, [])
    assert d.added == [] and d.removed == [] and len(d.changed) == 1


def test_cve_delta_is_set_diff():
    d = sd.diff_snapshots([], [{"cve": "CVE-1"}, {"cve": "CVE-2"}],
                          [], [{"cve": "CVE-2"}, {"cve": "CVE-3"}])
    assert d.cve_delta == {"new": ["CVE-3"], "fixed": ["CVE-1"]}


def test_purl_less_fallback_identity_diffs():
    a = [{"purl_identity": "openssl@apk", "name": "openssl", "version": "1.0"}]
    b = [{"purl_identity": "openssl@apk", "name": "openssl", "version": "3.0"}]
    d = sd.diff_snapshots(a, [], b, [])
    assert len(d.changed) == 1 and d.changed[0].purl_identity == "openssl@apk"


# ── service resolver ──────────────────────────────────────────────────────────
def _svc_with_two_snaps():
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be)
    svc = PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state,
        vuln_bundle={"records": [], "epss": {}, "kev": set(), "exploits": set()}, clock=lambda: 1)
    state.record_sbom_snapshot({"snapshot_id": "A", "account": ACCT, "node_id": "repo:v1",
                                "subject_key": "repo", "source_format": "cyclonedx",
                                "component_count": 2, "ingested_epoch": 1000})
    state.insert_sbom_components("A", [{"purl_identity": "pkg:npm/x", "name": "x", "version": "1.0"},
                                       {"purl_identity": "pkg:npm/y", "name": "y", "version": "1.0"}])
    state.insert_snapshot_cves("A", [{"cve": "CVE-1"}])
    state.record_sbom_snapshot({"snapshot_id": "B", "account": ACCT, "node_id": "repo:v2",
                                "subject_key": "repo", "source_format": "cyclonedx",
                                "component_count": 2, "ingested_epoch": 2000})
    state.insert_sbom_components("B", [{"purl_identity": "pkg:npm/x", "name": "x", "version": "2.0"},
                                       {"purl_identity": "pkg:npm/z", "name": "z", "version": "1.0"}])
    state.insert_snapshot_cves("B", [{"cve": "CVE-2"}])
    return svc


def test_service_diff_auto_pairs_latest_two_of_subject():
    d = _svc_with_two_snaps().sbom_diff(ACCT)          # newest is B, previous is A
    assert d["from_snapshot"] == "A" and d["to_snapshot"] == "B"
    assert [c["name"] for c in d["added"]] == ["z"]
    assert [c["name"] for c in d["removed"]] == ["y"]
    assert d["cve_delta"] == {"new": ["CVE-2"], "fixed": ["CVE-1"]}


def test_service_diff_explicit_ids():
    d = _svc_with_two_snaps().sbom_diff(ACCT, from_id="A", to_id="B")
    assert d["from_snapshot"] == "A" and d["to_snapshot"] == "B"


def test_service_diff_cross_account_isolated():
    svc = _svc_with_two_snaps()
    svc.state.record_sbom_snapshot({"snapshot_id": "OTHER", "account": "999988887777",
                                    "node_id": "x", "subject_key": "repo", "source_format": "cyclonedx",
                                    "component_count": 0, "ingested_epoch": 3000})
    assert svc.sbom_diff(ACCT, from_id="A", to_id="OTHER") is None      # another account → no diff


def test_service_diff_needs_two_snapshots():
    reg = AccountRegistry.open(":memory:")
    svc = PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "s", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=aws_state.StateStore(reg._be),
        vuln_bundle={"records": [], "epss": {}, "kev": set(), "exploits": set()}, clock=lambda: 1)
    assert svc.sbom_diff(ACCT) is None
