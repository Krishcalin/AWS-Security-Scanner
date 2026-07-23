"""B6 — PlatformService ingest orchestration (dict fakes, no boto).

Upload → own against the account's graph_full → enrich from the injected bundle →
persist → reachability re-run → ranked inventory. Verifies the end-to-end thesis:
an ingested KEV on an internet-exposed, path-to-crown host ranks CRITICAL, an
isolated one ranks noise; refresh + org roll-up; cross-account 400."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import cnapp_connectors as cc
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"
INST = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
ROLE = f"arn:aws:iam::{ACCT}:role/r-1"
PROF = f"arn:aws:iam::{ACCT}:instance-profile/p-1"
BUCKET = "arn:aws:s3:::crown-data"

BUNDLE = {
    "records": [{"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"],
                 "database_specific": {"severity": "CRITICAL"},
                 "severity": [{"score": 10.0}]}],
    "epss": {"CVE-2021-44228": 0.975}, "kev": {"CVE-2021-44228"},
    "exploits": {"CVE-2021-44228"},
}


def _graph_with_path():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("eni-1", "NetworkInterface")
    g.add_node(INST, "EC2Instance", instance_id="i-1")
    g.add_edge("internet", "eni-1", "EXPOSED_TO", ports="tcp/443")
    g.add_edge("eni-1", INST, "ATTACHED_TO")
    g.add_node(PROF, "InstanceProfile")
    g.add_edge(INST, PROF, "HAS_INSTANCE_PROFILE")
    g.add_node(ROLE, "IAMRole", name="r-1")
    g.add_edge(PROF, ROLE, "HAS_ROLE")
    g.add_node(BUCKET, "S3Bucket", crown_jewel=True)
    g.add_edge(ROLE, BUCKET, "CAN_READ_DATA", conditioned=False)
    return g


def _svc(with_graph=True, bundle=BUNDLE):
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be)
    results = InMemoryResultStore()
    if with_graph:
        results.put(ACCT, {"account": ACCT, "graph_full": _graph_with_path().to_dict(),
                           "attack_paths": [], "finding_catalog": [], "results": []})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    svc = PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, val: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state, vuln_bundle=bundle,
        clock=lambda: 5000)
    return svc


def _trivy_sarif(cve="CVE-2021-44228"):
    return {
        "version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "Trivy", "rules": [{
                "id": cve, "properties": {"security-severity": "10.0"}}]}},
            "results": [{"ruleId": cve, "level": "error",
                         "message": {"text": "Package: log4j-core\nInstalled Version: 2.14.1\n"
                                             "Fixed Version: 2.17.1"},
                         "locations": [{"physicalLocation": {"artifactLocation": {
                             "uri": f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"}}}]}],
        }],
    }


# ── the thesis end to end ────────────────────────────────────────────────────
def test_ingest_kev_ranks_critical_when_reachable():
    svc = _svc()
    res = svc.ingest_document(ACCT, doc=_trivy_sarif(), target_resource=INST)
    assert res["mapping_status"] == "resolved" and res["finding_count"] == 1
    assert res["resolved_node"] == INST
    # newly-reachable KEV surfaced for the digest signal
    assert any(x["cve"] == "CVE-2021-44228" for x in res["newly_reachable_kev"])
    row = svc.list_vulns(ACCT)[0]
    assert row["cve"] == "CVE-2021-44228" and row["priority_band"] == "CRITICAL"
    assert row["on_attack_path"] is True and row["priority_score"] >= 90
    assert row["sources"] == ["ingest:trivy"] and row["kev"] is True


def test_isolated_kev_ranks_noise():
    svc = _svc()
    iso = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-orphan"
    svc.ingest_document(ACCT, doc=_trivy_sarif(), target_resource=iso)
    row = svc.list_vulns(ACCT, node=iso)[0]
    assert row["on_attack_path"] is False
    assert row["priority_band"] in ("MEDIUM", "LOW")


def test_enrichment_is_single_source_from_bundle():
    """Doc says nothing about KEV; the bundle does — and only the bundle decides."""
    svc = _svc()
    svc.ingest_document(ACCT, doc=_trivy_sarif(), target_resource=INST)
    row = svc.list_vulns(ACCT)[0]
    assert row["kev"] is True and row["epss"] == 0.975 and row["exploit_available"] == "YES"


def test_second_tool_unions_sources_one_row():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_trivy_sarif(), target_resource=INST)
    # a CycloneDX report from grype for the same CVE+node
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "metadata": {"tools": {"components": [{"name": "grype"}]}},
           "components": [{"bom-ref": "c1", "name": "log4j-core", "version": "2.14.1",
                           "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
           "vulnerabilities": [{"id": "CVE-2021-44228",
                                "ratings": [{"severity": "critical"}],
                                "affects": [{"ref": "c1"}]}]}
    svc.ingest_document(ACCT, doc=cdx, target_resource=INST)
    rows = svc.list_vulns(ACCT)
    assert len(rows) == 1
    assert set(rows[0]["sources"]) == {"ingest:trivy", "ingest:grype"}


def test_vex_not_affected_suppressed_no_path():
    svc = _svc()
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {},
           "components": [{"bom-ref": "c1", "name": "log4j-core", "version": "2.14.1",
                           "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
           "vulnerabilities": [{"id": "CVE-2021-44228",
                                "ratings": [{"severity": "critical"}],
                                "analysis": {"state": "not_affected"},
                                "affects": [{"ref": "c1"}]}]}
    svc.ingest_document(ACCT, doc=cdx, target_resource=INST)
    row = svc.list_vulns(ACCT)[0]
    assert row["suppressed"] is True and row["on_attack_path"] is False
    assert svc.list_vulns(ACCT, include_suppressed=False) == []


def test_cross_account_target_rejected():
    svc = _svc()
    with pytest.raises(ValueError):
        svc.ingest_document(ACCT, doc=_trivy_sarif(),
                            target_resource="arn:aws:ec2:us-east-1:999999999999:instance/i-x")


def test_reupload_identical_doc_idempotent():
    svc = _svc()
    a = svc.ingest_document(ACCT, doc=_trivy_sarif(), target_resource=INST)
    b = svc.ingest_document(ACCT, doc=_trivy_sarif(), target_resource=INST)
    assert a["doc_id"] == b["doc_id"]
    assert len(svc.list_ingest_docs(ACCT)) == 1
    assert len(svc.list_vulns(ACCT)) == 1


def test_refresh_recomputes_against_new_graph():
    svc = _svc(with_graph=False)                    # no scan yet → not reachable
    svc.ingest_document(ACCT, doc=_trivy_sarif(), target_resource=INST)
    assert svc.list_vulns(ACCT)[0]["on_attack_path"] is False
    # a native scan now lands a graph with the full path
    svc.results.put(ACCT, {"account": ACCT, "graph_full": _graph_with_path().to_dict(),
                           "attack_paths": [], "finding_catalog": [], "results": []})
    diff = svc.refresh_vuln_reachability(ACCT)
    assert any(x["cve"] == "CVE-2021-44228" for x in diff["became_reachable"])
    assert svc.list_vulns(ACCT)[0]["on_attack_path"] is True


def test_org_vulns_tags_account():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_trivy_sarif(), target_resource=INST)
    rows = svc.org_vulns()
    assert rows and rows[0]["account"] == ACCT


def test_unparseable_doc_raises_valueerror():
    svc = _svc()
    with pytest.raises(ValueError):
        svc.ingest_document(ACCT, doc={"nope": 1})


def test_get_vuln_detail_across_nodes():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_trivy_sarif(), target_resource=INST)
    detail = svc.get_vuln(ACCT, "CVE-2021-44228")
    assert len(detail) == 1 and detail[0]["node_id"] == INST
