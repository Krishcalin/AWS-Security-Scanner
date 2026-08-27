"""Phase 1 · slice 1.4 — guardrail coverage over the AI estate.

The case this exists for is the one a per-agent check cannot express. AGT-05 asks "does
this agent have a guardrail" one agent at a time; on an account with NO guardrails
anywhere it produces a list of individual failures and no statement about the estate,
and on an account with none AND no comparison it produces nothing an executive can read.
AGT-06 says "0 of 6 agents are governed", which has an answer precisely when strength
grading has nothing to grade.

Ranking reuses aws_correlate reachability unchanged, so an ungoverned agent that is
internet-reachable and can reach crown data outranks an isolated one — the same ordering
the EDR coverage screen uses, so the two read alike.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_aispm
from engine import aws_graph
from engine.aws_live_scanner import AWSLiveScanner

AGENT_A = "arn:aws:bedrock:us-east-1:123456789012:agent/EXPOSEDCROWN"
AGENT_B = "arn:aws:bedrock:us-east-1:123456789012:agent/EXPOSEDONLY"
AGENT_C = "arn:aws:bedrock:us-east-1:123456789012:agent/ISOLATED"
AGENT_D = "arn:aws:bedrock:us-east-1:123456789012:agent/GOVERNED"
ROLE = "arn:aws:iam::123456789012:role/AgentRole"
CROWN = "arn:aws:s3:::prod-pii"


def agent(arn, name, *, guardrail=""):
    return {"kind": "BedrockAgent", "name": name, "arn": arn, "role_arn": ROLE,
            "network_checkable": False, "network": {}, "data_bearing": False,
            "guardrail_id": guardrail}


def _graph(*, expose=(), crown_reaching=()):
    g = aws_graph.SecurityGraph()
    g.add_node("internet", "InternetSource", cidr="0.0.0.0/0")
    g.add_node(CROWN, "S3Bucket", crown_jewel=True, DataStore=True, name="prod-pii")
    g.add_node(ROLE, "IAMRole", name="AgentRole")
    for arn in (AGENT_A, AGENT_B, AGENT_C, AGENT_D):
        g.add_node(arn, "BedrockAgent", name=arn.rsplit("/", 1)[-1], ai_resource=True)
    for arn in expose:
        g.add_edge("internet", arn, "EXPOSED_TO", basis="test-fixture")
    for arn in crown_reaching:
        g.add_edge(arn, ROLE, "HAS_ROLE")
    if crown_reaching:
        g.add_edge(ROLE, CROWN, "CAN_READ_DATA")
    return g


# ── the ranking ─────────────────────────────────────────────────────────────
def test_gaps_rank_by_exposure_not_by_name():
    g = _graph(expose=(AGENT_A, AGENT_B), crown_reaching=(AGENT_A,))
    cov = aws_aispm.guardrail_coverage(g, [
        agent(AGENT_C, "isolated"), agent(AGENT_B, "exposed-only"),
        agent(AGENT_A, "exposed-crown")])
    order = [x["label"] for x in cov["gaps"]]
    assert order[0] == "exposed-crown", f"headline gap should be the worst: {order}"
    assert order.index("exposed-only") < order.index("isolated")
    assert cov["gaps"][0]["exposure_rank"] == 3


def test_an_agent_with_a_guardrail_is_not_a_gap():
    g = _graph(expose=(AGENT_D,))
    cov = aws_aispm.guardrail_coverage(g, [agent(AGENT_D, "governed",
                                                 guardrail="gr-abc123")])
    assert cov["gaps"] == []
    assert cov["overall"] == {"governed": 1, "total": 1, "pct": 100.0}


def test_a_blank_guardrail_id_is_not_a_guardrail():
    """A field present but empty is the shape AWS returns for 'none attached'."""
    cov = aws_aispm.guardrail_coverage(_graph(), [agent(AGENT_A, "a", guardrail="   ")])
    assert cov["overall"]["governed"] == 0


# ── the case the slice exists for ───────────────────────────────────────────
def test_an_estate_with_no_guardrails_at_all_still_produces_a_number():
    """The whole point. Strength grading has nothing to grade here; coverage still
    answers the question."""
    cov = aws_aispm.guardrail_coverage(_graph(), [
        agent(AGENT_A, "a"), agent(AGENT_B, "b"), agent(AGENT_C, "c")])
    assert cov["overall"] == {"governed": 0, "total": 3, "pct": 0.0}
    assert len(cov["gaps"]) == 3


def test_an_estate_with_no_agents_reports_no_percentage_rather_than_zero():
    """0% governed and 'no agents exist' are different facts. Reporting the second as
    the first invents a failure."""
    cov = aws_aispm.guardrail_coverage(_graph(), [])
    assert cov["overall"]["total"] == 0
    assert cov["overall"]["pct"] is None


def test_non_agent_ai_resources_are_not_counted_against_coverage():
    """A guardrail governs model invocation. A notebook is a workstation — counting it
    would depress the percentage with resources the control does not apply to, which is
    how a coverage metric stops being believed."""
    cov = aws_aispm.guardrail_coverage(_graph(), [
        agent(AGENT_A, "a"),
        {"kind": "SageMakerNotebook", "name": "nb", "arn": "arn:aws:sagemaker:::nb",
         "network_checkable": True, "network": {}, "data_bearing": False},
    ])
    assert cov["overall"]["total"] == 1


def test_it_works_without_a_graph():
    """Coverage is a property of the inventory; the graph only supplies ranking."""
    cov = aws_aispm.guardrail_coverage(None, [agent(AGENT_A, "a")])
    assert cov["overall"]["total"] == 1
    assert cov["gaps"][0]["exposure_rank"] == 0


# ── the scanner surface ─────────────────────────────────────────────────────
def _scanner(resources):
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["DATA"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: MagicMock()
    s._aispm_resources = list(resources)
    return s


def test_the_finding_states_the_fraction_and_names_the_worst_gap():
    s = _scanner([agent(AGENT_A, "exposed-crown"), agent(AGENT_D, "governed",
                                                         guardrail="gr-1")])
    s._emit_guardrail_coverage(_graph(expose=(AGENT_A,), crown_reaching=(AGENT_A,)))
    fails = [r for r in s.results if r.check_id == "AGT-06" and r.status == "FAIL"]
    assert fails
    msg = fails[0].message
    assert "1 of 2" in msg and "50.0%" in msg
    assert "exposed-crown" in msg
    assert "crown data" in msg


def test_full_coverage_reports_a_pass():
    s = _scanner([agent(AGENT_D, "governed", guardrail="gr-1")])
    s._emit_guardrail_coverage(_graph())
    assert any(r.check_id == "AGT-06" and r.status == "PASS" for r in s.results)


def test_an_account_with_no_agents_says_nothing():
    """Silence is right here: there is no estate to govern, and a 0% finding would be
    a failure invented out of an absence."""
    s = _scanner([])
    s._emit_guardrail_coverage(_graph())
    assert not [r for r in s.results if r.check_id == "AGT-06"]


def test_the_check_is_fully_mapped():
    from engine import aws_finding_detail as D
    from engine.aws_live_scanner import CHECK_SEVERITY, COMPLIANCE_MAP, REMEDIATION_MAP
    assert "AGT-06" in CHECK_SEVERITY
    assert "AGT-06" in COMPLIANCE_MAP
    assert "AGT-06" in REMEDIATION_MAP
    assert "AGT-06" in D.FINDING_DETAIL
