"""Slice 2 · Batch 2 — copilot wired into PlatformService + the FastAPI route.
Skips the HTTP half if fastapi is absent; the service half always runs."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_api
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "123456789012"
PAYLOAD = {
    "finding_catalog": [{
        "check_id": "S3-01", "section": "S3", "severity": "HIGH", "status": "FAIL",
        "compliance": {"CIS": "2.1.4"}, "distinct": 1, "affected": ["prod-bucket"], "count": 1,
        "risk": "The bucket allows public read access.", "impact": "Data exposure.",
        "steps": ["Enable account Block Public Access", "Re-scan"],
        "remediation_cmd": "aws s3api put-public-access-block ..."}],
    "attack_paths": [], "choke_points": [],
}


def _svc(copilot_llm=None):
    return PlatformService(
        registry=AccountRegistry.open(":memory:"), results=InMemoryResultStore(),
        hub_role_arn="arn:aws:iam::5:role/Hub", cfn_template_url="https://h/x.yaml",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "ext",
        copilot_llm=copilot_llm, clock=lambda: 1)


def test_service_copilot_grounded_answer():
    s = _svc()
    s.results.put(ACCT, PAYLOAD)
    a = s.copilot_answer(ACCT, "how do I fix S3-01?")
    assert a and a["citations"] == ["S3-01"] and "Block Public Access" in a["answer"]


def test_service_copilot_no_scan_returns_none():
    assert _svc().copilot_answer("999999999999", "anything?") is None


def test_service_copilot_abstains_off_topic():
    s = _svc()
    s.results.put(ACCT, PAYLOAD)
    assert s.copilot_answer(ACCT, "what is the capital of France?")["abstained"] is True


def test_service_copilot_llm_seam():
    s = _svc(copilot_llm=lambda system, q, ctx: "LLM-GROUNDED")
    s.results.put(ACCT, PAYLOAD)
    a = s.copilot_answer(ACCT, "public bucket?")
    assert a["mode"] == "llm" and a["answer"] == "LLM-GROUNDED"


def test_org_copilot_empty_is_abstain_not_crash():
    assert _svc().org_copilot_answer("top risks?")["abstained"] is True


# ── HTTP surface ─────────────────────────────────────────────────────────────
pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI, reason="fastapi not installed")


def _client(role="viewer", copilot_llm=None):
    from fastapi.testclient import TestClient
    s = _svc(copilot_llm=copilot_llm)
    s.results.put(ACCT, PAYLOAD)
    return TestClient(cnapp_api.create_app(s, current_role=lambda: role))


def test_api_copilot_route():
    r = _client().post(f"/accounts/{ACCT}/copilot", json={"question": "top risks?"})
    assert r.status_code == 200 and r.json()["citations"] == ["S3-01"]


def test_api_copilot_no_scan_404():
    r = _client().post("/accounts/999999999999/copilot", json={"question": "x"})
    assert r.status_code == 404


def test_api_copilot_empty_question_422():
    r = _client().post(f"/accounts/{ACCT}/copilot", json={"question": ""})
    assert r.status_code == 422                                # Field(min_length=1)


def test_api_org_copilot_route():
    r = _client().post("/org/copilot", json={"question": "top risks?"})
    assert r.status_code == 200 and "abstained" in r.json()
