"""Coverage-close Batch 1 · Projects (LBI/MBI/HBI business-impact grouping). Read-only,
config-driven, DISPLAY-ONLY roll-up over the EXISTING finding catalog (glob+account match);
the tier never touches the posture/attack-path score (aws_correlate frozen). No DB table.
Offline; the API half skips if fastapi is absent."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import cnapp_connectors as cc
import cnapp_server
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

A = "111111111111"
B = "222222222222"
RDS = "arn:aws:rds:us-east-1:111111111111:db:prod-payments-db"

PROJECTS = [
    {"id": "payments", "name": "Payments", "tier": "HBI",
     "match": {"accounts": [A], "resource_globs": ["*prod-payments*", "arn:aws:rds:*"]}},
    {"id": "sandbox", "name": "Sandbox", "tier": "LBI", "match": {"accounts": [B]}},
    {"id": "empty", "name": "Misconfigured", "tier": "MBI", "match": {}},  # matches NOTHING
]

A_FINDS = [
    {"check_id": "ATTACK-02", "severity": "CRITICAL", "section": "DATA", "affected": [RDS]},
    {"check_id": "IAM-07", "severity": "HIGH", "section": "IAM", "affected": ["some-role"]},  # acct A, no glob hit
]
B_FINDS = [{"check_id": "S3-01", "severity": "MEDIUM", "section": "S3", "affected": ["bucket-x"]}]


def _svc(projects=PROJECTS):
    reg = AccountRegistry.open(":memory:")
    results = InMemoryResultStore()
    for acct, finds in ((A, A_FINDS), (B, B_FINDS)):
        reg.upsert_account(acct, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
        reg.set_onboarding_status(acct, "active", 1000)
        results.put(acct, {"account": acct, "finding_catalog": finds, "attack_paths": [], "results": []})
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=aws_state.StateStore(reg._be),
        projects=projects, clock=lambda: 5000)


# ── service roll-up ───────────────────────────────────────────────────────────
def test_list_projects_rolls_up_by_glob_and_account():
    by_id = {p["id"]: p for p in _svc().list_projects()}
    # payments: account A AND a glob hit -> only the RDS/prod-payments finding (NOT IAM-07)
    assert by_id["payments"]["finding_count"] == 1
    assert by_id["payments"]["severity_counts"]["CRITICAL"] == 1
    assert by_id["payments"]["tier"] == "HBI"
    # sandbox: account B, no globs -> account-only match -> all of B's findings
    assert by_id["sandbox"]["finding_count"] == 1
    # empty match -> matches nothing (never everything)
    assert by_id["empty"]["finding_count"] == 0


def test_project_summary_returns_matched_findings():
    s = _svc().project_summary("payments")
    assert s and s["finding_count"] == 1
    assert [f["check_id"] for f in s["findings"]] == ["ATTACK-02"]


def test_project_summary_unknown_is_none():
    assert _svc().project_summary("nope") is None


def test_no_projects_configured_is_empty():
    assert _svc(projects=[]).list_projects() == []


def test_account_only_project_does_not_match_other_accounts():
    # sandbox (account B) must NOT pick up account A's findings
    s = _svc().project_summary("sandbox")
    assert all(f["account"] == B for f in s["findings"])


# ── config loader (cnapp_server._load_projects) ───────────────────────────────
def test_load_projects_from_env_json(monkeypatch):
    monkeypatch.setenv("CNAPP_PROJECTS", '[{"id":"p1","name":"P1","tier":"HBI","match":{"accounts":["1"]}}]')
    got = cnapp_server._load_projects()
    assert len(got) == 1 and got[0]["id"] == "p1"


def test_load_projects_fail_safe_on_garbage(monkeypatch):
    monkeypatch.setenv("CNAPP_PROJECTS", "not json {[")
    assert cnapp_server._load_projects() == []          # never crashes the server


def test_load_projects_absent_is_empty(monkeypatch):
    monkeypatch.delenv("CNAPP_PROJECTS", raising=False)
    assert cnapp_server._load_projects() == []


def test_load_projects_drops_entries_without_id(monkeypatch):
    monkeypatch.setenv("CNAPP_PROJECTS", '[{"name":"noid"},{"id":"ok"}]')
    assert [p["id"] for p in cnapp_server._load_projects()] == ["ok"]


# ── API routes ────────────────────────────────────────────────────────────────
_HAVE_FASTAPI = None
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
def test_route_projects_list_and_detail():
    c = _client(_svc())
    ids = {p["id"] for p in c.get("/projects").json()}
    assert ids == {"payments", "sandbox", "empty"}
    body = c.get("/projects/payments").json()
    assert body["tier"] == "HBI" and body["finding_count"] == 1


@api
def test_route_unknown_project_404():
    assert _client(_svc()).get("/projects/nope").status_code == 404
