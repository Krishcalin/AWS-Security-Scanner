"""Policy-as-code service + API: the read-time POLICY-xx WARN overlay in get_finding_catalog +
org_findings, the list_policies org roll-up (WARN/PASS + pack + match_count), display-only posture
safety, fail-safe on a malformed policy, and GET /policies. Pure/offline."""
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
CROWN = "arn:aws:s3:::crown"

CATALOG = [{"check_id": "S3-01", "section": "S3", "severity": "HIGH", "status": "FAIL",
            "compliance": {"PCI-DSS": "3.4"}}]

POL_PCI = {"id": "pci-34", "name": "PCI-DSS 3.4 must pass", "severity": "HIGH", "pack": "pci",
           "compliance": {"PCI-DSS": "3.4"},
           "match": {"finding": {"compliance_framework": "PCI-DSS", "compliance_control": "3.4", "status": "FAIL"}}}
POL_CROWN = {"id": "no-pub-crown", "name": "No public crown data", "severity": "CRITICAL", "pack": "data",
             "match": {"op": "all",
                       "graph": {"kind": "S3Bucket", "where": {"op": "and", "of": [
                           {"pred": "crown_jewel"}, {"pred": "reachable_from", "target": "internet"}]}},
                       "finding": {"status": "FAIL"}}}
POL_NONE = {"id": "never", "name": "Impossible", "match": {"finding": {"check_id_glob": "ZZZ-*"}}}
POL_BAD = {"id": "bad", "match": {"finding": {"bogus": 1}}}   # malformed -> inert


def _graph():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node(CROWN, "S3Bucket", name="crown", crown_jewel=True, public=True)
    g.add_edge("internet", CROWN, "EXPOSED_TO")
    return g


def _svc(policies, *, graph=None, catalog=None, posture=None):
    reg = AccountRegistry.open(":memory:")
    results = InMemoryResultStore()
    payload = {"account": ACCT, "results": [], "attack_paths": [], "finding_catalog": catalog or []}
    if graph is not None:
        payload["graph_full"] = graph.to_dict()
    if posture is not None:
        payload["posture_score"] = posture
    results.put(ACCT, payload)
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=aws_state.StateStore(reg._be),
        policies=policies, clock=lambda: 5000)


def test_catalog_overlays_firing_policies():
    svc = _svc([POL_PCI, POL_CROWN], graph=_graph(), catalog=CATALOG)
    e = {f["check_id"]: f for f in svc.get_finding_catalog(ACCT)}
    assert e["POLICY-pci-34"]["status"] == "WARN" and e["POLICY-pci-34"]["affected"] == ["finding:S3-01"]
    assert e["POLICY-no-pub-crown"]["severity"] == "CRITICAL"
    assert e["POLICY-no-pub-crown"]["affected"] == [CROWN, "finding:S3-01"]


def test_non_firing_policy_emits_nothing():
    svc = _svc([POL_NONE], graph=_graph(), catalog=CATALOG)
    assert not any(f["check_id"].startswith("POLICY-") for f in svc.get_finding_catalog(ACCT))


def test_malformed_policy_is_inert():
    svc = _svc([POL_BAD, POL_PCI], graph=_graph(), catalog=CATALOG)
    ids = {f["check_id"] for f in svc.get_finding_catalog(ACCT)}   # must not raise
    assert "POLICY-bad" not in ids and "POLICY-pci-34" in ids


def test_no_policies_is_a_noop():
    svc = _svc([], graph=_graph(), catalog=CATALOG)
    assert not any(f["check_id"].startswith("POLICY-") for f in svc.get_finding_catalog(ACCT))


def test_no_scan_means_no_policy_findings():
    assert _svc([POL_PCI], graph=None).get_finding_catalog(ACCT) == []


def test_policy_is_display_only_never_touches_posture():
    svc = _svc([POL_PCI], graph=_graph(), catalog=CATALOG, posture=80)
    summ = svc.get_account_summary(ACCT)
    assert summ["posture_score"] == 80                       # read-time overlay, not sc.results
    # severity_counts derives from the STORED catalog (one HIGH: S3-01). The HIGH policy overlay is
    # NOT added — else HIGH would be 2. Proves the overlay never enters the posture histogram.
    assert summ["severity_counts"]["HIGH"] == 1
    assert any(f["check_id"] == "POLICY-pci-34" for f in svc.get_finding_catalog(ACCT))


def test_finding_only_policy_needs_no_graph():
    # a compliance-as-code policy fires with no graph_full at all
    svc = _svc([POL_PCI], graph=None, catalog=None)
    svc.results.put(ACCT, {"account": ACCT, "results": [], "attack_paths": [], "finding_catalog": CATALOG})
    assert any(f["check_id"] == "POLICY-pci-34" for f in svc.get_finding_catalog(ACCT))


def test_org_findings_overlay_and_rollup():
    svc = _svc([POL_PCI, POL_CROWN, POL_NONE], graph=_graph(), catalog=CATALOG)
    org = {f["check_id"] for f in svc.org_findings()}
    assert "POLICY-pci-34" in org
    roll = {p["id"]: p for p in svc.list_policies()}
    assert roll["pci-34"]["status"] == "WARN" and roll["pci-34"]["match_count"] == 1 and roll["pci-34"]["pack"] == "pci"
    assert roll["no-pub-crown"]["status"] == "WARN" and roll["no-pub-crown"]["match_count"] == 2
    assert roll["never"]["status"] == "PASS" and roll["never"]["match_count"] == 0


def test_list_policies_empty_when_none():
    assert _svc([], graph=_graph()).list_policies() == []


def test_non_dict_match_policy_is_inert_not_a_crash():
    # an operator typo (`match: finding` -> a string) must NOT crash the Findings screen / rollup —
    # the needs_graph pre-pass is defensive and the per-policy parse rejects it inertly.
    svc = _svc([{"id": "typo", "match": "finding"}, POL_PCI], graph=_graph(), catalog=CATALOG)
    ids = {f["check_id"] for f in svc.get_finding_catalog(ACCT)}      # must not raise
    assert "POLICY-typo" not in ids and "POLICY-pci-34" in ids
    roll = {p["id"]: p for p in svc.list_policies()}                  # must not raise
    assert roll["typo"]["status"] == "PASS" and roll["pci-34"]["status"] == "WARN"


# ── API ──────────────────────────────────────────────────────────────────────────
try:
    import cnapp_api
    _HAVE_FASTAPI = cnapp_api._HAVE_FASTAPI
except Exception:
    _HAVE_FASTAPI = False

api = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi not installed")


def _client(svc):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc, current_role=lambda: "viewer"))


@api
def test_route_policies_rollup():
    c = _client(_svc([POL_PCI, POL_NONE], graph=_graph(), catalog=CATALOG))
    r = c.get("/policies")
    assert r.status_code == 200
    body = {p["id"]: p for p in r.json()}
    assert body["pci-34"]["status"] == "WARN" and body["never"]["status"] == "PASS"


@api
def test_route_policies_empty_when_unconfigured():
    r = _client(_svc([], graph=_graph())).get("/policies")
    assert r.status_code == 200 and r.json() == []
