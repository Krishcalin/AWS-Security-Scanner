"""B7 — connector/digest wiring for the ingest plane.

(1) build_drift_digest.extra_newly_on_path merges a newly-REACHABLE KEV into
    newly_on_path + forces material_change (pure).
(2) _enriched_findings appends two CHECK-LEVEL aggregates (VULN-ING-KEV / VULN-ING)
    that a VULN-* + on_attack_path rule fires on.
(3) the worker refreshes ingest reachability and feeds became_reachable to the digest.
Pure/offline."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import cnapp_connectors as cc
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService, _ingest_digest_items

ACCT = "111122223333"
INST = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
ROLE = f"arn:aws:iam::{ACCT}:role/r-1"
PROF = f"arn:aws:iam::{ACCT}:instance-profile/p-1"
BUCKET = "arn:aws:s3:::crown-data"
BUNDLE = {"records": [{"id": "CVE-2021-44228", "database_specific": {"severity": "CRITICAL"},
                       "severity": [{"score": 10.0}]}],
          "epss": {"CVE-2021-44228": 0.975}, "kev": {"CVE-2021-44228"},
          "exploits": {"CVE-2021-44228"}}


# ── (1) pure digest merge ────────────────────────────────────────────────────
def test_build_drift_digest_extra_newly_on_path_merges_and_material():
    extra = [{"check_id": "VULN-ING-KEV:CVE-2021-44228", "severity": "CRITICAL",
              "on_attack_path": True}]
    d = cc.build_drift_digest(
        account=ACCT, scan_id="s1", scan_epoch=1000,
        drift={"new": [], "resolved": [], "reopened": [], "mutated": []},
        trend=[], mttr={}, catalog_by_check={}, onpath=set(),
        extra_newly_on_path=extra, window_id="w1")
    assert d["material_change"] is True                    # forced by the extra signal
    cids = [x["check_id"] for x in d["newly_on_path"]]
    assert "VULN-ING-KEV:CVE-2021-44228" in cids
    # strict subset invariant still holds
    onpath = {x["check_id"] for x in d["newly_on_path"]}
    exposed = {x["check_id"] for x in d["newly_exposed"]}
    assert onpath <= exposed


def test_build_drift_digest_no_extra_is_unchanged():
    d = cc.build_drift_digest(
        account=ACCT, scan_id="s1", scan_epoch=1000,
        drift={"new": [], "resolved": [], "reopened": [], "mutated": []},
        trend=[], mttr={}, catalog_by_check={}, onpath=set(), window_id="w1")
    assert d["material_change"] is False and d["newly_on_path"] == []


def test_ingest_digest_items_shaping():
    items = _ingest_digest_items([
        {"node_id": INST, "cve": "CVE-2021-44228", "kev": True},
        {"node_id": INST, "cve": "CVE-2023-1", "kev": False, "severity": "HIGH"}])
    assert items[0]["check_id"] == "VULN-ING-KEV:CVE-2021-44228"
    assert items[0]["severity"] == "CRITICAL" and items[0]["on_attack_path"] is True
    assert items[1]["check_id"] == "VULN-ING:CVE-2023-1" and items[1]["severity"] == "HIGH"


# ── (2) synthetic aggregates + rule match ────────────────────────────────────
def _graph():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("eni-1", "NetworkInterface")
    g.add_node(INST, "EC2Instance", instance_id="i-1")
    g.add_edge("internet", "eni-1", "EXPOSED_TO")
    g.add_edge("eni-1", INST, "ATTACHED_TO")
    g.add_node(PROF, "InstanceProfile"); g.add_edge(INST, PROF, "HAS_INSTANCE_PROFILE")
    g.add_node(ROLE, "IAMRole"); g.add_edge(PROF, ROLE, "HAS_ROLE")
    g.add_node(BUCKET, "S3Bucket", crown_jewel=True)
    g.add_edge(ROLE, BUCKET, "CAN_READ_DATA", conditioned=False)
    return g


def _svc():
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be)
    results = InMemoryResultStore()
    results.put(ACCT, {"account": ACCT, "graph_full": _graph().to_dict(),
                       "attack_paths": [], "finding_catalog": [], "results": []})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state, vuln_bundle=BUNDLE,
        clock=lambda: 5000)


def _sarif():
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Trivy", "rules": [{
            "id": "CVE-2021-44228", "properties": {"security-severity": "10.0"}}]}},
        "results": [{"ruleId": "CVE-2021-44228", "level": "error",
                     "message": {"text": "Package: log4j-core\nInstalled Version: 2.14.1"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": INST}}}]}]}]}


def test_reachable_survivor_becomes_vuln_ing_kev_aggregate():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_sarif(), target_resource=INST)
    findings, coverage = svc._enriched_findings(ACCT)
    agg = [f for f in findings if f.check_id == "VULN-ING-KEV"]
    assert len(agg) == 1
    f = agg[0]
    assert f.severity == "CRITICAL" and f.on_attack_path is True
    assert f.count == 1 and any("CVE-2021-44228@" in a for a in f.affected)
    assert (ACCT, "VULN-ING-KEV") in coverage             # coverage includes the synthetic id


def test_vuln_ing_aggregate_fires_a_vuln_glob_onpath_rule():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_sarif(), target_resource=INST)
    store = svc.connectors
    cid = svc.create_connector(type="slack", name="S", config={}, secret="https://hooks.slack.com/x")["connector_id"]
    svc.set_connector_enabled(cid, True)
    svc.create_rule(cid, {"check_globs": ["VULN-*"], "on_attack_path": True,
                          "min_severity": "HIGH"})
    fired = svc.preview_rules(ACCT)
    assert any(row.get("check_id") == "VULN-ING-KEV" for row in fired)


def test_suppressed_survivor_not_in_aggregate():
    svc = _svc()
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {},
           "components": [{"bom-ref": "c1", "name": "log4j-core", "version": "2.14.1",
                           "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
           "vulnerabilities": [{"id": "CVE-2021-44228", "ratings": [{"severity": "critical"}],
                                "analysis": {"state": "not_affected"}, "affects": [{"ref": "c1"}]}]}
    svc.ingest_document(ACCT, doc=cdx, target_resource=INST)
    findings, _ = svc._enriched_findings(ACCT)
    assert not any(f.check_id.startswith("VULN-ING") for f in findings)


def test_refresh_returns_became_reachable_for_digest():
    svc = _svc()
    # first ingest with NO graph → not reachable
    svc.results.put(ACCT, {"account": ACCT, "graph_full": SecurityGraph().to_dict(),
                           "attack_paths": [], "finding_catalog": [], "results": []})
    svc.ingest_document(ACCT, doc=_sarif(), target_resource=INST)
    svc.results.put(ACCT, {"account": ACCT, "graph_full": _graph().to_dict(),
                           "attack_paths": [], "finding_catalog": [], "results": []})
    diff = svc.refresh_vuln_reachability(ACCT)
    items = _ingest_digest_items(diff["became_reachable"])
    assert any(x["check_id"] == "VULN-ING-KEV:CVE-2021-44228" for x in items)
