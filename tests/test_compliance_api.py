"""API-route tests for the compliance-breadth routes (viewer reads; reference data +
derived scorecards). Skips if fastapi is not installed."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_live_scanner as als
import cnapp_api

pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI,
                                reason="fastapi not installed (deploy-time dep)")

from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "123456789012"


def _R(status, cid):
    return types.SimpleNamespace(status=status, check_id=cid, section="S3", resource="b",
                                 message="m", severity="HIGH", compliance=als.COMPLIANCE_MAP.get(cid, {}))


def _client(role="viewer"):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    results = InMemoryResultStore()
    results.put(ACCT, {"compliance_scorecard": als.compliance_scorecard(
        [_R("FAIL", "S3-01"), _R("PASS", "S3-03")])})
    svc = PlatformService(registry=AccountRegistry.open(":memory:"), results=results,
                          hub_role_arn="a", cfn_template_url="b",
                          secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
                          clock=lambda: 1)
    return TestClient(cnapp_api.create_app(svc, current_role=lambda: role))


def test_frameworks_route_viewer():
    r = _client("viewer").get("/compliance/frameworks")
    assert r.status_code == 200
    body = r.json()
    assert body["spine"] == "NIST-800-53-Rev5" and len(body["frameworks"]) >= 35


def test_crosswalk_route_filter():
    r = _client("viewer").get("/compliance/crosswalk?framework=PCI-DSS-4")
    assert r.status_code == 200 and r.json()
    assert all(e["framework"] == "PCI-DSS-4" for e in r.json())


def test_account_compliance_route_and_min_confidence():
    c = _client("viewer")
    r = c.get(f"/accounts/{ACCT}/compliance")
    assert r.status_code == 200
    assert set(r.json()["native"]) == {"CIS", "PCI-DSS", "HIPAA", "SOC2", "NIST"}
    assert len(r.json()["derived"]) >= 30
    hi = c.get(f"/accounts/{ACCT}/compliance?min_confidence=high")
    assert hi.json()["derived"]["PCI-DSS-4"]["controls_total"] <= r.json()["derived"]["PCI-DSS-4"]["controls_total"]


def test_account_compliance_404_when_no_scan():
    assert _client("viewer").get("/accounts/999999999999/compliance").status_code == 404
