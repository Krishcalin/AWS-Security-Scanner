"""Phase-4 Slice-5 · B8 — the registry views (list_registry_images / list_registry_repos)
derive deployed-vs-registry-only, scan_source, subject_key, and per-repo aggregates from the
persisted scan graph + results. Read-only; dict fakes, no boto/fastapi.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import cnapp_connectors as cc
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"
RURI = f"{ACCT}.dkr.ecr.us-east-1.amazonaws.com/app"
A = f"{RURI}@sha256:deployed"      # deployed (inbound RUNS_IMAGE)
B = f"{RURI}@sha256:regonly"       # registry-only


def _svc(graph, results_list):
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be)
    results = InMemoryResultStore()
    results.put(ACCT, {"account": ACCT, "graph_full": graph.to_dict(),
                       "results": results_list, "attack_paths": [], "finding_catalog": []})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state,
        vuln_bundle={"records": [], "epss": {}, "kev": set(), "exploits": set()},
        clock=lambda: 5000)


def _graph():
    g = SecurityGraph()
    g.add_node("wl", "ECSTaskDefinition")
    g.add_node(A, "ECRImage", repository="app", digest="sha256:deployed", image_uri=RURI)
    g.add_node(B, "ECRImage", repository="app", digest="sha256:regonly", image_uri=RURI)
    g.add_edge("wl", A, "RUNS_IMAGE")                        # A is deployed
    g.add_node("CVE-1", "Vulnerability", severity="HIGH")
    g.add_node("CVE-2", "Vulnerability", severity="CRITICAL")
    g.add_edge(A, "CVE-1", "HAS_VULN", severity="HIGH", scan_source="ecr-native-scan")
    g.add_edge(B, "CVE-2", "HAS_VULN", severity="CRITICAL", scan_source="ecr-sidescan")
    return g


_RESULTS = [{"check_id": "CNT-01", "status": "FAIL", "severity": "HIGH",
             "resource": "app", "message": "scan-on-push OFF"}]


def test_list_registry_images_deployed_vs_registry_only():
    svc = _svc(_graph(), _RESULTS)
    imgs = {im["digest"]: im for im in svc.list_registry_images(ACCT)}
    assert imgs["sha256:deployed"]["deployed"] is True
    assert imgs["sha256:regonly"]["deployed"] is False       # no inbound RUNS_IMAGE
    assert imgs["sha256:deployed"]["scan_sources"] == ["ecr-native-scan"]
    assert imgs["sha256:regonly"]["scan_sources"] == ["ecr-sidescan"]
    assert imgs["sha256:regonly"]["critical"] == 1 and imgs["sha256:deployed"]["high"] == 1
    # subject_key strips @digest so both images deep-link to the same repo subject
    assert imgs["sha256:deployed"]["subject_key"] == RURI == imgs["sha256:regonly"]["subject_key"]


def test_list_registry_images_repo_filter():
    svc = _svc(_graph(), _RESULTS)
    assert len(svc.list_registry_images(ACCT, repo="app")) == 2
    assert svc.list_registry_images(ACCT, repo="nope") == []


def test_list_registry_repos_aggregates_and_posture():
    svc = _svc(_graph(), _RESULTS)
    repos = svc.list_registry_repos(ACCT)
    assert len(repos) == 1
    r = repos[0]
    assert r["repository"] == "app" and r["images"] == 2 and r["deployed"] == 1
    assert r["critical"] == 1 and r["high"] == 1 and r["vuln_count"] == 2
    assert any(f["check_id"] == "CNT-01" for f in r["findings"])   # posture attached


def test_registry_views_empty_when_no_graph():
    svc = _svc(SecurityGraph(), [])
    assert svc.list_registry_images(ACCT) == []
    assert svc.list_registry_repos(ACCT) == []


def test_repos_excludes_cnt02_surfaces_posture_only_and_drops_registry_wide():
    results = [
        {"check_id": "CNT-02", "status": "FAIL", "severity": "HIGH", "resource": "app:v1", "message": "cve"},
        {"check_id": "CNT-01", "status": "FAIL", "severity": "HIGH", "resource": "lonely-repo", "message": "scan off"},
        {"check_id": "CNT-06", "status": "FAIL", "severity": "HIGH", "resource": "registry", "message": "no signing"},
    ]
    svc = _svc(SecurityGraph(), results)             # NO image nodes
    repos = {r["repository"]: r for r in svc.list_registry_repos(ACCT)}
    assert "lonely-repo" in repos                     # posture-only repo still surfaces
    assert any(f["check_id"] == "CNT-01" for f in repos["lonely-repo"]["findings"])
    assert "app" not in repos                         # CNT-02 is per-CVE, not posture
    assert "registry" not in repos                    # registry-wide CNT-06 is not a fake repo


def test_list_registry_images_skips_digestless_placeholder():
    g = SecurityGraph()
    g.add_node(A, "ECRImage", repository="app", digest="sha256:deployed", image_uri=RURI)
    g.add_node(f"{RURI}:latest", "ECRImage", repository="app", digest="", image_uri=RURI)  # tag placeholder
    svc = _svc(g, [])
    digs = [im["digest"] for im in svc.list_registry_images(ACCT)]
    assert digs == ["sha256:deployed"]               # digest-less placeholder dropped
