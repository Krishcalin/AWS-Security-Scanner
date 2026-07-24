"""Cross-contract tests: the FastAPI hub (cnapp_api) must return exactly the shapes
the built React console (frontend/) consumes. Neither the TS build nor the existing
single-side route tests guard this seam, so these lock it: each live endpoint's
response must be a structural SUPERSET of the frontend's golden sample fixture
(frontend/public/sample/*.json) — the shape every screen was built against.

Also the regression home for two live-wiring drifts found by the contract-audit:
  * /accounts/{id}/validate — each check must expose `ok` (the OnboardWizard reads
    check.ok; the backend previously only sent `status`, painting every row failed).
  * /accounts — rows must carry posture_score/posture_grade (the CloudAccounts
    posture column; the registry stores only lifecycle metadata).

Skips if fastapi/httpx are absent (deploy-time deps)."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_api

pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI,
                                reason="fastapi not installed (deploy-time dep)")

from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "123456789012"          # matches the sample fixture account ids
_SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "frontend", "public", "sample")


def _fixture(name):
    with open(os.path.join(_SAMPLE, name), encoding="utf-8") as f:
        return json.load(f)


class FakeSession:
    def __init__(self, acct):
        self.acct = acct

    def client(self, service, **k):
        acct = self.acct

        class C:
            def get_caller_identity(self):
                return {"Account": acct}
        return C()


class _CF:
    def get_caller_identity(self):
        return {"Account": ACCT}

    def describe_regions(self):
        return {"Regions": []}


# a realistic serialize_scanner-shaped payload (the shape the read endpoints project)
_PAYLOAD = {
    "account": ACCT, "region": "us-east-1", "posture_score": 82, "posture_grade": "B",
    "summary": {"PASS": 10, "FAIL": 3, "WARN": 1, "INFO": 2},
    "compliance_scorecard": {"CIS": {"controls_total": 5, "controls_passed": 3,
                                     "controls_failed": 2, "failed_controls": ["1.1"]}},
    "graph": {"nodes": 4, "edges": 3, "node_kinds": {}, "edge_kinds": {}},
    "graph_full": {"directed": True, "multigraph": False,
                   "nodes": [{"id": "internet", "kind": "InternetSource"}], "edges": []},
    "attack_paths": [{"score": 90, "severity": "CRITICAL", "nodes": ["internet", "i-1"],
                      "title": "internet -> ec2 -> admin"}],
    "choke_points": [{"node": "i-1", "cut": 2}],
    "finding_catalog": [{"check_id": "S3-01", "section": "S3", "severity": "HIGH",
                         "status": "FAIL", "compliance": {"CIS": "1.1"}, "distinct": 1,
                         "affected": ["b"], "count": 1, "risk": "public bucket risk text",
                         "impact": "data exposure impact text", "steps": ["a", "b", "c"],
                         "remediation_cmd": "aws s3api put-public-access-block ..."}],
    "results": [{"status": "FAIL", "check_id": "S3-01", "section": "S3", "resource": "b",
                 "message": "public | b", "severity": "HIGH", "compliance": {},
                 "remediation_cmd": ""}],
}


def _svc():
    reg = AccountRegistry.open(":memory:")
    clk = {"t": 0}
    return PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="arn:aws:iam::5:role/Hub",
        cfn_template_url="https://h/x.yaml", secret_writer=lambda a, v: "ssm://x",
        secret_reader=lambda r: "ext", session_factory=lambda aid: FakeSession(aid),
        assume_role_fn=lambda *a, **k: {},
        client_factory=lambda creds, svc, reg_: _CF(),
        clock=lambda: clk.__setitem__("t", clk["t"] + 1) or clk["t"])


def _seeded(role="admin"):
    """A TestClient over a service with ACCT onboarded+active and a scan payload put."""
    from fastapi.testclient import TestClient
    svc = _svc()
    svc.init_onboarding(ACCT, region="us-east-1", method="single")
    svc.validate_account(ACCT)                    # -> active + healthy checks
    svc.results.put(ACCT, dict(_PAYLOAD))
    return TestClient(cnapp_api.create_app(svc, current_role=lambda: role)), svc


def _superset(live, fixture_keys, where):
    missing = [k for k in fixture_keys if k not in live]
    assert not missing, f"{where}: live response missing frontend keys {missing}"


# ── regression 1: validate checks expose `ok` (OnboardWizard reads check.ok) ──
def test_validate_checks_expose_ok_bool():
    c, _ = _seeded()
    r = c.post(f"/accounts/{ACCT}/validate?org_mode=false", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["checks"]                 # healthy overall
    for chk in body["checks"]:
        assert "ok" in chk and isinstance(chk["ok"], bool), f"check missing ok: {chk}"
        assert chk["ok"] == (chk["status"] == "ok")              # ok mirrors status
        assert "status" in chk                                   # kept for other consumers


# ── regression 2: /accounts rows carry posture (CloudAccounts posture column) ──
def test_list_accounts_carries_posture():
    c, svc = _seeded()
    # a second, un-scanned account: posture is None (not absent) until its first scan
    svc.init_onboarding("234567890123", region="us-east-1", method="single")
    rows = {a["account_id"]: a for a in c.get("/accounts").json()}
    assert rows[ACCT]["posture_score"] == 82 and rows[ACCT]["posture_grade"] == "B"
    assert rows["234567890123"]["posture_score"] is None
    assert rows["234567890123"]["posture_grade"] is None


# ── golden-fixture superset locks (the console was built against these shapes) ──
def test_accounts_response_superset_of_fixture():
    c, _ = _seeded()
    row = next(a for a in c.get("/accounts").json() if a["account_id"] == ACCT)
    _superset(row, _fixture("accounts.json")[0].keys(), "GET /accounts row")


def test_account_summary_superset_of_fixture():
    c, _ = _seeded()
    r = c.get(f"/accounts/{ACCT}/summary")
    assert r.status_code == 200
    body = r.json()
    _superset(body, _fixture(f"account_{ACCT}_summary.json").keys(), "GET /summary")
    assert body["severity_counts"]["HIGH"] == 1                 # computed, not passed through


def test_findings_response_superset_of_fixture():
    c, _ = _seeded()
    rows = c.get(f"/accounts/{ACCT}/findings").json()
    assert rows, "seeded finding_catalog should surface"
    fx = _fixture(f"account_{ACCT}_findings.json")
    _superset(rows[0], fx[0].keys(), "GET /findings item")


def test_org_overview_superset_of_fixture():
    c, _ = _seeded()
    body = c.get("/org/overview").json()
    _superset(body, _fixture("org_overview.json").keys(), "GET /org/overview")
    if body.get("accounts"):
        _superset(body["accounts"][0], _fixture("org_overview.json")["accounts"][0].keys(),
                  "org_overview.accounts[0]")


# ── the read endpoints the console hits are all wired + return the right container ──
def test_read_endpoints_wired_and_typed():
    c, _ = _seeded()
    assert isinstance(c.get(f"/accounts/{ACCT}/paths").json(), list)
    assert isinstance(c.get(f"/accounts/{ACCT}/graph").json(), dict)
    assert isinstance(c.get(f"/accounts/{ACCT}/issues").json(), list)
    assert isinstance(c.get("/org/findings").json(), list)
    assert isinstance(c.get(f"/accounts/{ACCT}/findings").json(), list)
