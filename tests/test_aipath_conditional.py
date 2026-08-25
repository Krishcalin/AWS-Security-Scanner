"""AIPATH-01 — the finding must not assert an ingress the graph refuses to draw.

Slice 0.3 settled the substance: every input to ``ai_network_exposed`` is an EGRESS or
isolation signal, so ``_emit_ai_topology`` emits no inbound ``internet -[EXPOSED_TO]->``
edge, and the module docstring cites the SageMaker reference verbatim for why. That
refusal was correct and it held.

What it did not reach was AIPATH-01's own prose, which went on opening "FUSED AI ATTACK
PATH: network-exposed ..." while the detail page told the reader about "an attacker who
reaches the model host". The graph and the sentence describing it disagreed for two
slices, and only the graph was tested — which is the gap these tests close. A finding is
a claim; if the claim is stronger than the evidence structure behind it, the fact that
the structure is honest does not save it, because the customer reads the sentence.

So the invariant under test is agreement, not wording: whenever AIPATH-01 fires, the
graph must contain no inbound edge to the node it names, AND the message must not tell
the reader otherwise. Either half alone is what allowed the drift.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_epistemics
import aws_graph
import aws_live_scanner as A
from aws_live_scanner import AWSLiveScanner

ROLE = "arn:aws:iam::123456789012:role/AIExecutionRole"
NB = "arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/nb"
PASSROLE = [{"effect": "Allow", "actions": {"iam:passrole"}, "resources": {"*"},
             "not_resources": set(), "condition": None}]

# Language that asserts someone can reach the resource from outside. None of it is
# supportable from an egress signal. "internet" alone is deliberately NOT on this list:
# AISPM-03 says "direct internet egress bypasses VPC egress controls", which is exactly
# right, and a blanket ban would push a correct sentence into a euphemism.
INGRESS_CLAIMS = (
    "network-exposed", "internet-facing", "publicly reachable", "publicly accessible",
    "reachable from the internet", "exposed to the internet", "reaches the model host",
    "attack path", "fused path", "end-to-end breach path",
)


def _run(*, exposed=True):
    """One SageMaker notebook with direct-internet EGRESS whose role can PassRole.

    A Bedrock agent is ``network_checkable=False`` and can never satisfy the gate, so a
    fixture built on one would assert nothing about AIPATH-01 at all."""
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["DATA"])
        s.account = "123456789012"
    s._client = lambda service, region=None: MagicMock()
    s._get_scp_context = lambda: None
    s._aispm_resources = [{
        "kind": "SageMakerNotebook", "name": "research-nb", "arn": NB, "role_arn": ROLE,
        "network_checkable": True, "data_bearing": False,
        "network": {"direct_internet": True, "in_vpc": False} if exposed
        else {"direct_internet": False, "in_vpc": True},
    }]
    s._get_iam_principals = lambda: [
        {"arn": ROLE, "name": "AIExecutionRole", "statements": PASSROLE}]
    g = aws_graph.SecurityGraph()
    s._collect_aispm(g)
    return s.results, g


def _finding():
    results, g = _run()
    hits = [r for r in results if r.check_id == "AIPATH-01" and r.status == "FAIL"]
    assert hits, "fixture no longer raises AIPATH-01 — every assertion below is vacuous"
    return hits[0], g


# ── the control ─────────────────────────────────────────────────────────────
def test_the_pair_still_fires():
    """Guard against the whole file passing because nothing is emitted any more."""
    msg, _ = _finding()
    assert "research-nb" in msg.message


def test_the_isolated_case_does_not_fire():
    results, _ = _run(exposed=False)
    assert not [r for r in results if r.check_id == "AIPATH-01"]


# ── the invariant: the sentence agrees with the graph ───────────────────────
def test_the_graph_has_no_inbound_edge_to_the_node_the_finding_names():
    """The structural half. If a later change starts drawing this edge, AIPATH-01 stops
    being conditional and this test should be deleted along with the premise — not
    quietly updated to match."""
    _, g = _finding()
    edges = list(g.edges())
    # Positive control, in the same test on purpose: an absence assertion over a graph
    # that turned out to be empty, or queried by a key that does not exist, passes for
    # the wrong reason and looks identical while doing so.
    assert [e for e in edges if e.get("dst") == ROLE], (
        f"the HAS_ROLE edge is missing, so 'no inbound edge' proves nothing: {edges}")
    inbound = [e for e in edges if e.get("dst") == NB]
    assert not inbound, f"an inbound edge to the AI node appeared: {inbound}"


@pytest.mark.parametrize("claim", INGRESS_CLAIMS)
def test_the_message_asserts_no_ingress(claim):
    """The prose half — the one that was actually wrong."""
    msg, _ = _finding()
    assert claim not in msg.message.lower(), (
        f"AIPATH-01 claims {claim!r}, which no signal it reads can support")


@pytest.mark.parametrize("claim", INGRESS_CLAIMS)
def test_the_detail_page_asserts_no_ingress(claim):
    """The detail page is longer than the finding and was where the overclaim was most
    explicit, so it needs the same guard rather than inheriting trust from the message."""
    import aws_finding_detail as D
    entry = D.FINDING_DETAIL["AIPATH-01"]
    text = " ".join([entry["risk"], entry["impact"], *entry["steps"]]).lower()
    # The detail is allowed — and expected — to NAME the thing it disclaims.
    disclaimed = ("does not claim", "no observed route", "never asserted",
                  "should not be read that way")
    if claim in text:
        assert any(d in text for d in disclaimed), (
            f"detail uses {claim!r} without disclaiming it")


def test_the_message_states_the_premise_rather_than_hiding_it():
    """A conditional finding that does not say what it is conditional on reads exactly
    like an unconditional one."""
    msg, _ = _finding()
    low = msg.message.lower()
    assert "if the resource is compromised" in low
    assert "egress" in low, "the true network fact should be named, not omitted"


# ── classification and severity ─────────────────────────────────────────────
def test_it_is_classified_conditional():
    assert aws_epistemics.classify("AIPATH-01") == aws_epistemics.CONDITIONAL
    assert "capability, not occurrence" in aws_epistemics.describe("AIPATH-01").lower()


def test_it_is_not_critical():
    """CRITICAL in this product means every link was observed (ATTACK-01/02) or the
    primitive needs no assumption (IAMPE-01/03/04). A finding resting on an unverifiable
    premise does not qualify, however serious its consequences would be if it held."""
    assert A.CHECK_SEVERITY["AIPATH-01"] == "HIGH"
    assert A.CHECK_SEVERITY["ATTACK-01"] == "CRITICAL", "the comparison point moved"


def test_it_is_not_ranked_below_its_own_legs():
    """An ordering, not an equality. Equal is what it is today, but pinning equality
    would mean that raising AISPM-01 later silently *requires* raising AIPATH-01 with
    it — which is not the reasoning. The rule is only that a finding reporting a pair
    must never rank below either half of the pair, or it becomes noise beneath its own
    inputs."""
    rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    pair = rank[A.CHECK_SEVERITY["AIPATH-01"]]
    for leg in ("AISPM-01", "AISPM-02"):
        assert pair >= rank[A.CHECK_SEVERITY[leg]], (
            f"AIPATH-01 ranks below its own leg {leg}")


def test_the_remediation_does_not_promise_a_path_will_disappear():
    """The old text told operators to re-scan and watch an internet -> AI -> role -> crown
    path vanish. It never appeared, so that instruction could only ever read as a tool
    that had not done what it said."""
    rem = A.REMEDIATION_MAP["AIPATH-01"].lower()
    assert "fused ai attack path" not in rem
    assert "aws sagemaker" in rem, "the concrete containment command was lost"
