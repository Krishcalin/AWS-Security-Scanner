"""Offline tests for cnapp_api — the FastAPI surface. Verifies RBAC (viewer<admin),
route wiring to PlatformService, and status codes. Skips if fastapi/httpx are not
installed (deploy-time deps); the backend logic is fully covered via PlatformService."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_api

pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI,
                                reason="fastapi not installed (deploy-time dep)")

from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "210987654321"


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
    """Stub AWS client for both sts + ec2 canary."""
    def get_caller_identity(self):
        return {"Account": ACCT}
    def describe_regions(self):
        return {"Regions": []}


def _svc():
    reg = AccountRegistry.open(":memory:")
    clk = {"t": 0}
    return PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="arn:aws:iam::5:role/Hub",
        cfn_template_url="https://h/x.yaml", secret_writer=lambda a, v: "ssm://x",
        secret_reader=lambda r: "ext", session_factory=lambda aid: FakeSession(aid),
        assume_role_fn=lambda *a: {},
        client_factory=lambda creds, svc, reg_: _CF(),
        clock=lambda: clk.__setitem__("t", clk["t"] + 1) or clk["t"])


def _client(role="admin"):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    app = cnapp_api.create_app(_svc(), current_role=lambda: role)
    return TestClient(app)


def test_onboard_then_get_account():
    c = _client("admin")
    r = c.post("/accounts", json={"account_id": ACCT, "region": "us-east-1", "method": "single"})
    assert r.status_code == 201
    assert r.json()["cfn_launch_url"].startswith("https://console.aws.amazon.com")
    g = c.get(f"/accounts/{ACCT}")
    assert g.status_code == 200 and g.json()["onboarding_status"] == "pending"
    assert "external_id_ref" not in g.json()          # masked


def test_rbac_viewer_cannot_onboard():
    c = _client("viewer")
    r = c.post("/accounts", json={"account_id": ACCT})
    assert r.status_code == 403


def test_rbac_viewer_can_read():
    c = _client("viewer")
    assert c.get("/accounts").status_code == 200
    assert c.get("/org/overview").status_code == 200


def test_scan_trigger_and_status_flow():
    c = _client("admin")
    c.post("/accounts", json={"account_id": ACCT})
    c.post(f"/accounts/{ACCT}/validate")              # -> active
    r = c.post("/scans", json={"account_ids": [ACCT]})
    assert r.status_code == 202
    jids = r.json()["job_ids"]
    assert len(jids) == 1
    assert c.get(f"/scans/{jids[0]}").json()["account_id"] == ACCT


def test_missing_account_404():
    c = _client("admin")
    assert c.post("/accounts/999999999999/validate").status_code == 404
    assert c.get("/scans/nope").status_code == 404


# ── regression: unset auth hook FAILS CLOSED (denies), never grants admin ─────
def test_default_auth_hook_denies_everything():
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    app = cnapp_api.create_app(_svc())                       # NO current_role -> deny-all
    c = TestClient(app)
    assert c.get("/accounts").status_code == 403             # even a viewer read is denied
    assert c.post("/accounts", json={"account_id": ACCT}).status_code == 403


# ── regression: malformed account id -> 422, not 500 ─────────────────────────
def test_malformed_account_id_returns_422():
    c = _client("admin")
    assert c.post("/accounts", json={"account_id": "abc"}).status_code == 422
    assert c.post("/accounts", json={"account_id": "12345"}).status_code == 422
