"""Phase 0 · step 1 — the AI-pillar defects that were wrong in shipped code.

Each test here pins a defect that produced a CONFIDENT WRONG ANSWER rather than an
error: a posture grade of 0 on a healthy account, a clean AI report for an account
whose entire AI footprint was never looked at, and a permission denial rendered as
"this service isn't in that region". Those are the expensive kind, because nothing
in the output invites a second look.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_graph
from engine import aws_live_scanner
from engine.aws_live_scanner import AWSLiveScanner, compute_risk_score

ROLE = "arn:aws:iam::123456789012:role/AIExecutionRole"


def _scanner(sections=None) -> AWSLiveScanner:
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False,
                           sections=sections or ["DATA"])
        s.account = "123456789012"

    def mock_client(service, region=None):
        key = f"{service}:{region or s.region}"
        if key not in s._clients:
            s._clients[key] = MagicMock()
        return s._clients[key]

    s._client = mock_client
    return s


def _with_one_ai_resource(s: AWSLiveScanner) -> AWSLiveScanner:
    """One Bedrock agent whose execution role can PassRole on anything → AISPM-01."""
    s._aispm_resources = [{
        "kind": "BedrockAgent", "name": "support-bot",
        "arn": "arn:aws:bedrock:us-east-1:123456789012:agent/ABC123",
        "role_arn": ROLE, "network_checkable": False, "network": {},
        "data_bearing": False,
    }]
    s._get_iam_principals = lambda: [{
        "arn": ROLE, "name": "AIExecutionRole",
        "statements": [{"effect": "Allow", "actions": {"iam:passrole"},
                        "resources": {"*"}, "not_resources": set(),
                        "condition": None}],
    }]
    return s


# ── THE regression. If this ever fails again, a healthy account grades F. ─────
def test_posture_score_is_identical_at_one_region_and_seventeen():
    """`DATA` is not a GLOBAL_SECTION, so with --all-regions it runs once per
    region over a stash that BEDROCK_AGENTS/SAGEMAKER already filled for EVERY
    region. Re-emitting the whole set per region charged compute_risk_score again
    each time — 17 regions x CRITICAL(15) = -255, clamped to a flat 0 for the
    WHOLE account, not merely the AI section."""
    one = _with_one_ai_resource(_scanner())
    one._collect_aispm(aws_graph.SecurityGraph())
    score_one_region = compute_risk_score(one.results)

    many = _with_one_ai_resource(_scanner())
    g = aws_graph.SecurityGraph()
    for _ in range(17):
        many._collect_aispm(g)
    score_seventeen = compute_risk_score(many.results)

    assert score_seventeen == score_one_region
    assert score_one_region < 100.0, "fixture must actually produce a FAIL to be a guard"
    assert score_one_region > 0.0, "a single AI finding must not floor the account"


def test_each_ai_resource_is_reported_exactly_once():
    s = _with_one_ai_resource(_scanner())
    g = aws_graph.SecurityGraph()
    for _ in range(17):
        s._collect_aispm(g)
    per_check = {}
    for r in s.results:
        per_check.setdefault(r.check_id, []).append(r)
    for check_id, rows in per_check.items():
        assert len(rows) == 1, f"{check_id} emitted {len(rows)}x for one resource"


def test_the_latch_does_not_suppress_a_first_real_collection():
    """A guard that over-fires would be a worse bug than the one it replaces."""
    s = _with_one_ai_resource(_scanner())
    s._collect_aispm(aws_graph.SecurityGraph())
    assert s.results, "the first collection must still emit"


# ── the RAG-only account that was scanned as if it had no AI at all ──────────
def _bedrock_agent_client(*, agents, kbs):
    ba = MagicMock()
    ba.list_agents.return_value = {"agentSummaries": agents}
    ba.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": kbs}
    ba.get_knowledge_base.return_value = {
        "knowledgeBase": {"serverSideEncryptionConfiguration": {}}}
    ba.list_data_sources.return_value = {"dataSourceSummaries": []}
    return ba


def test_knowledge_bases_are_audited_when_the_account_has_no_agents():
    """AGT-03 sat inside `for a in agents:` AND behind `if not agents: return`, so
    an account doing pure RAG — knowledge bases, no agents — produced a clean AI
    report having never enumerated its knowledge bases."""
    s = _scanner(sections=["BEDROCK_AGENTS"])
    s._clients["bedrock-agent:us-east-1"] = _bedrock_agent_client(
        agents=[], kbs=[{"knowledgeBaseId": "KB1", "name": "customer-docs",
                         "status": "ACTIVE"}])
    s._check_bedrock_agents()

    agt3 = [r for r in s.results if r.check_id == "AGT-03"]
    assert agt3, "a knowledge base existed and was never audited"
    assert any("customer-docs" in r.resource or "customer-docs" in r.message
               for r in agt3)


def test_knowledge_bases_are_not_re_reported_once_per_agent():
    """Knowledge bases are account-level, not agent-level."""
    s = _scanner(sections=["BEDROCK_AGENTS"])
    ba = _bedrock_agent_client(
        agents=[{"agentId": f"A{i}", "agentName": f"agent-{i}"} for i in range(4)],
        kbs=[{"knowledgeBaseId": "KB1", "name": "shared-kb", "status": "ACTIVE"}])
    ba.get_agent.side_effect = Exception("agent detail not needed for this test")
    s._clients["bedrock-agent:us-east-1"] = ba
    s._check_bedrock_agents()

    kb_rows = [r for r in s.results
               if r.check_id == "AGT-03" and "shared-kb" in (r.resource + r.message)]
    assert len(kb_rows) == 1, f"one KB, four agents -> {len(kb_rows)} findings"


# ── a refusal is not an absence ──────────────────────────────────────────────
class _Denied(Exception):
    def __init__(self):
        super().__init__("An error occurred (AccessDeniedException) when calling "
                         "the GetModelInvocationLoggingConfiguration operation")
        self.response = {"Error": {"Code": "AccessDeniedException"}}


def test_access_denied_is_not_reported_as_the_region_lacking_bedrock():
    """The old handler rendered every exception as 'Bedrock may not be available in
    this region', so a permission denial read as an empty account."""
    s = _scanner(sections=["BEDROCK"])
    bedrock = MagicMock()
    bedrock.get_model_invocation_logging_configuration.side_effect = _Denied()
    s._clients["bedrock:us-east-1"] = bedrock
    s._check_bedrock()

    bdr1 = [r for r in s.results if r.check_id == "BDR-01"]
    assert bdr1
    assert not any("may not be available in this region" in r.message for r in bdr1)
    assert any("NOT evaluated" in r.message and "bedrock:" in r.message for r in bdr1)


def test_an_unevaluated_check_carries_no_severity_penalty():
    """A check we were refused must not silently cost the customer posture score."""
    s = _scanner(sections=["BEDROCK"])
    bedrock = MagicMock()
    bedrock.get_model_invocation_logging_configuration.side_effect = _Denied()
    s._clients["bedrock:us-east-1"] = bedrock
    s._check_bedrock()
    assert compute_risk_score(s.results) == 100.0


def test_a_genuine_region_error_still_reads_as_a_region_error():
    """The split must not swallow the real case it was originally written for."""
    s = _scanner(sections=["BEDROCK"])
    bedrock = MagicMock()
    bedrock.get_model_invocation_logging_configuration.side_effect = \
        Exception("Could not connect to the endpoint URL")
    s._clients["bedrock:us-east-1"] = bedrock
    s._check_bedrock()
    assert any("may not be available in this region" in r.message
               for r in s.results if r.check_id == "BDR-01")
