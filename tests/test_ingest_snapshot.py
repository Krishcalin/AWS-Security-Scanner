"""Phase-4 Slice-4 · B4 — an inventory-lane ingest persists a durable SBOM snapshot
(header + full component set + immutable CVE set) + read-time license verdicts. The
findings lane persists NO snapshot. Dict fakes, no boto."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import cnapp_connectors as cc
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"
INST = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
BUNDLE = {"records": [], "epss": {}, "kev": set(), "exploits": set()}


def _svc():
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be)
    results = InMemoryResultStore()
    g = SecurityGraph()
    g.add_node(INST, "EC2Instance", instance_id="i-1")
    results.put(ACCT, {"account": ACCT, "graph_full": g.to_dict(),
                       "attack_paths": [], "finding_catalog": [], "results": []})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state, vuln_bundle=BUNDLE,
        clock=lambda: 5000)


def _cdx_inventory():
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"component": {"purl": "pkg:oci/app"}, "tools": {"components": [{"name": "trivy"}]}},
            "components": [
                {"bom-ref": "c1", "name": "log4j-core", "version": "2.14.1",
                 "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                 "licenses": [{"license": {"id": "Apache-2.0"}}]},
                {"bom-ref": "c2", "name": "agpl-lib", "version": "1.0", "purl": "pkg:npm/agpl-lib@1.0",
                 "licenses": [{"license": {"id": "AGPL-3.0-only"}}]},
                {"bom-ref": "c3", "name": "gpl-lib", "version": "2.0", "purl": "pkg:npm/gpl-lib@2.0",
                 "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
                {"bom-ref": "c4", "name": "mystery", "version": "0.1", "purl": "pkg:npm/mystery@0.1"},
            ]}


def _sarif():
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Trivy", "rules": [{"id": "CVE-2021-1"}]}},
        "results": [{"ruleId": "CVE-2021-1", "level": "error",
                     "message": {"text": "Package: x\nInstalled Version: 1\nFixed Version: 2"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": INST}}}]}]}]}


def test_inventory_ingest_writes_snapshot_and_components():
    svc = _svc()
    res = svc.ingest_document(ACCT, doc=_cdx_inventory(), target_resource=INST)
    assert res["lane"] == "inventory"
    snaps = svc.state.list_sbom_snapshots(ACCT)
    # snapshot id is account-scoped (account:doc_id) so two tenants can't collide on content hash
    assert len(snaps) == 1 and snaps[0]["snapshot_id"] == f"{ACCT}:{res['doc_id']}"
    assert snaps[0]["component_count"] == 4
    by = {c["name"]: c for c in svc.state.get_snapshot_components(snaps[0]["snapshot_id"])}
    assert by["agpl-lib"]["license_category"] == "network_copyleft"
    assert by["log4j-core"]["license_spdx"] == "Apache-2.0"
    assert by["mystery"]["license_category"] == "unknown"       # no license → unknown


def test_findings_lane_writes_no_snapshot():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_sarif(), target_resource=INST)   # SARIF = findings lane
    assert svc.state.list_sbom_snapshots(ACCT) == []


def test_license_findings_deny_and_review():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_cdx_inventory(), target_resource=INST)
    lf = {f["name"]: f for f in svc.list_license_findings(ACCT)}
    assert lf["agpl-lib"]["check_id"] == "LIC-DENY" and lf["agpl-lib"]["severity"] == "HIGH"
    assert lf["gpl-lib"]["check_id"] == "LIC-REVIEW" and lf["gpl-lib"]["severity"] == "MEDIUM"
    assert lf["mystery"]["check_id"] == "LIC-REVIEW"            # unknown → review
    assert "log4j-core" not in lf                               # Apache-2.0 → allow


def test_snapshot_idempotent_reingest():
    svc = _svc()
    a = svc.ingest_document(ACCT, doc=_cdx_inventory(), target_resource=INST)
    b = svc.ingest_document(ACCT, doc=_cdx_inventory(), target_resource=INST)
    assert a["doc_id"] == b["doc_id"]                           # doc_content_id idempotent
    assert len(svc.state.list_sbom_snapshots(ACCT)) == 1        # one snapshot, not two


def test_component_count_matches_stored_rows_on_duplicate_identity():
    # regression (#2): two versions of one package share a version-stripped identity; the
    # stored row count + component_count must agree (deduped), not silently diverge.
    svc = _svc()
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {},
           "components": [{"bom-ref": "a", "name": "foo", "version": "1.0.0", "purl": "pkg:npm/foo@1.0.0"},
                          {"bom-ref": "b", "name": "foo", "version": "2.0.0", "purl": "pkg:npm/foo@2.0.0"}]}
    res = svc.ingest_document(ACCT, doc=doc, target_resource=INST)
    snap = svc.state.list_sbom_snapshots(ACCT)[0]
    stored = svc.state.get_snapshot_components(snap["snapshot_id"])
    assert snap["component_count"] == len(stored)              # header matches retrievable rows
    assert res["doc_id"]


def test_license_policy_override_computed_on_read():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_cdx_inventory(), target_resource=INST)
    # override the policy → AGPL now allowed; verdict recomputed on read, no re-ingest
    svc._license_policy = {"deny": [], "review": ["strong_copyleft"], "allow": ["permissive"], "ids": {}}
    names = {f["name"] for f in svc.list_license_findings(ACCT)}
    assert "agpl-lib" not in names and "gpl-lib" in names
