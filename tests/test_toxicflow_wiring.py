"""Phase 3 · slice 3.1 — the scanner surface for toxic flow.

Two integration properties carry the slice, and both are about restraint.

The check id is chosen by the ENTRY GATE, not by severity: a proven untrusted-content
path is TFLOW-01 and an assumed one is TFLOW-02, and they sit in different epistemic
classes. That split is the whole reason the flagship can be stated strongly where it is
observable and honestly where it is not.

And the graph gains a node, never an inbound edge. Fabricating `internet -> agent` is
what `_emit_ai_topology` refuses one layer down, and doing it here would be the same
error at the size of the product's headline feature.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_epistemics as E
from engine import aws_graph
from engine import aws_live_scanner as A
from engine import aws_toxicflow as T
from engine.aws_live_scanner import AWSLiveScanner

ROLE = "arn:aws:iam::123456789012:role/AgentRole"
CROWN = "arn:aws:s3:::prod-pii"
PASSROLE = [{"effect": "Allow", "actions": {"iam:passrole"}, "resources": {"*"},
             "not_resources": set(), "condition": None}]


def _scanner():
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["DATA"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: MagicMock()
    return s


def _graph(*, crown=True):
    g = aws_graph.SecurityGraph()
    g.add_node(ROLE, "IAMRole", name="AgentRole")
    if crown:
        g.add_node(CROWN, "S3Bucket", crown_jewel=True, DataStore=True, name="prod-pii")
        g.add_edge(ROLE, CROWN, "CAN_READ_DATA")
    return g


def _agent(**over):
    a = {"kind": "BedrockAgent", "name": "support-bot", "role_arn": ROLE,
         "arn": "arn:aws:bedrock:us-east-1:123456789012:agent/A1",
         "network_checkable": False, "network": {}, "data_bearing": False}
    a.update(over)
    return a


def _principals():
    return {ROLE.lower(): {"arn": ROLE, "name": "AgentRole", "statements": PASSROLE}}


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _surface(kind):
    if kind == "proven":
        return T.injection_surface([{"dataSourceId": "d", "name": "public-docs",
                                     "dataSourceConfiguration": {"type": "WEB"}}])
    return T.injection_surface([{"dataSourceId": "d", "name": "corpus",
                                 "dataSourceConfiguration": {"type": "S3"}}])


# ── the entry gate picks the check ──────────────────────────────────────────
def test_a_proven_entry_raises_the_critical_check():
    s = _scanner()
    s._aispm_resources = [_agent(injection_surface=_surface("proven"))]
    s._emit_toxic_flow(_graph(), _principals())
    f = _ids(s, "TFLOW-01", "FAIL")
    assert f and "public-docs" in f[0].message
    assert f[0].severity == "CRITICAL"
    assert not _ids(s, "TFLOW-02")


def test_an_assumed_entry_raises_the_conditional_check_and_leads_with_if():
    s = _scanner()
    s._aispm_resources = [_agent(injection_surface=_surface("assumed"))]
    s._emit_toxic_flow(_graph(), _principals())
    f = _ids(s, "TFLOW-02", "FAIL")
    assert f and f[0].message.startswith("IF an injection reaches")
    assert not _ids(s, "TFLOW-01")


def test_the_two_checks_sit_in_different_epistemic_classes():
    """The split is the point: one entry is observed, the other is a premise."""
    assert E.classify("TFLOW-01") == E.INFERRED
    assert E.classify("TFLOW-02") == E.CONDITIONAL
    assert "capability, not occurrence" in E.describe("TFLOW-02").lower()


def test_an_agent_with_no_surface_recorded_is_treated_as_assumed():
    """Absent is not proven. An agent whose knowledge-base association could not be read
    must not inherit the strong finding."""
    s = _scanner()
    s._aispm_resources = [_agent()]
    s._emit_toxic_flow(_graph(), _principals())
    assert _ids(s, "TFLOW-02") and not _ids(s, "TFLOW-01")


# ── restraint ───────────────────────────────────────────────────────────────
def test_an_agent_that_reaches_nothing_produces_no_flow():
    """An injection arriving somewhere harmless is not a finding, however proven the
    entry. A flagship that fired on every agent would be noise with a good name."""
    s = _scanner()
    s._aispm_resources = [_agent(role_arn=None,
                                 injection_surface=_surface("proven"))]
    s._emit_toxic_flow(_graph(crown=False), {})
    assert not [r for r in s.results if r.check_id.startswith("TFLOW-")]


def test_a_boundary_conditioned_escalation_is_not_a_terminal():
    """The same rule AISPM-01 applies, and the mechanism is worth being precise about:
    CONDITIONED comes from a permission BOUNDARY or SCP that permits the escalation only
    under a Condition — a condition on the identity statement itself still grades KEEP.
    An earlier draft of this test put the condition in the wrong place and passed for the
    wrong reason, which is the same class of error the whole programme keeps catching."""
    s = _scanner()
    boundary = [{"effect": "Allow", "actions": {"iam:passrole"}, "resources": {"*"},
                 "not_resources": set(),
                 "condition": {"StringEquals": {"aws:PrincipalTag/team": "ml"}}}]
    s._aispm_resources = [_agent(injection_surface=_surface("proven"))]
    s._emit_toxic_flow(_graph(crown=False),
                       {ROLE.lower(): {"arn": ROLE, "statements": PASSROLE,
                                       "boundary": boundary}})
    assert not [r for r in s.results if r.check_id.startswith("TFLOW-")], (
        "an escalation that only exists under a Condition is not something somebody "
        "reaches by talking to a model")


def test_the_graph_gains_a_node_but_no_inbound_edge():
    """Fabricating internet -> agent is exactly what _emit_ai_topology refuses one layer
    down. Doing it here would be the same error at the size of the flagship."""
    s = _scanner()
    g = _graph()
    s._aispm_resources = [_agent(injection_surface=_surface("proven"))]
    s._emit_toxic_flow(g, _principals())
    kinds = {n["kind"] for n in g.nodes()}
    assert "ToxicFlow" in kinds
    agent_arn = s._aispm_resources[0]["arn"]
    assert not [e for e in g.edges() if e.get("dst") in (agent_arn, "toxicflow:support-bot")]


def test_attenuation_is_wired_from_the_real_inputs():
    """A blocking guardrail and full confirmation must actually lower the score, or the
    controls are decoration in the computation as well as in the account."""
    def score(**extra):
        s = _scanner()
        s._aispm_resources = [_agent(injection_surface=_surface("proven"), **extra)]
        s._emit_toxic_flow(_graph(), _principals())
        msg = _ids(s, "TFLOW-01", "FAIL")[0].message
        return int(msg.split("flow score ")[1].split("]")[0])

    bare = score()
    guarded = score(guardrail_blocks=True)
    gated = score(guardrail_blocks=True, confirmation_gated=2, confirmation_total=2)
    assert gated < guarded < bare
    assert gated > 0, "controls reduce a flow; they never erase it"


def test_the_message_names_what_stands_in_the_way():
    s = _scanner()
    s._aispm_resources = [_agent(injection_surface=_surface("proven"),
                                 guardrail_blocks=True)]
    s._emit_toxic_flow(_graph(), _principals())
    assert "Between the two:" in _ids(s, "TFLOW-01", "FAIL")[0].message


def test_agentcore_runtimes_get_flows_too():
    s = _scanner()
    s._aispm_resources = [_agent(kind="AgentCoreRuntime", name="rt")]
    s._emit_toxic_flow(_graph(), _principals())
    assert [r for r in s.results if r.check_id.startswith("TFLOW-")]


# ── the bucket-write gate ───────────────────────────────────────────────────
def test_only_write_grants_make_a_bucket_an_entry():
    """A publicly READABLE knowledge-base bucket is a data-exposure problem (S3-09), not
    an injection path. Conflating the two would put the flagship finding on every public
    bucket in the account."""
    import json
    s = _scanner()
    c = MagicMock()
    s._client = lambda svc, region=None: c
    for policy, expected in (
            ([{"Effect": "Allow", "Principal": {"AWS": "*"},
               "Action": "s3:PutObject", "Resource": "arn:aws:s3:::b/*"}], "public"),
            ([{"Effect": "Allow", "Principal": {"AWS": "*"},
               "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}], None)):
        c.get_bucket_policy.return_value = {"Policy": json.dumps({"Statement": policy})}
        assert s._bucket_write_scope("arn:aws:s3:::kb") == expected


def test_an_unreadable_bucket_policy_is_not_an_open_one():
    s = _scanner()
    c = MagicMock()
    c.get_bucket_policy.side_effect = Exception("AccessDenied")
    s._client = lambda svc, region=None: c
    assert s._bucket_write_scope("arn:aws:s3:::kb") is None


def test_the_bucket_classifier_is_the_shared_one():
    """A second reading of a bucket policy is a second thing to get wrong, and the two
    would drift. S3-09/S3-10 and this must agree by construction."""
    import inspect
    src = inspect.getsource(AWSLiveScanner._bucket_write_scope)
    assert "classify_resource_policy_stmt" in src


# ── it costs nothing new ────────────────────────────────────────────────────
def test_the_slice_added_no_new_iam_action():
    """Every input was already read. ListAgentKnowledgeBases is the one call that is new
    to the scanner, and SecurityAudit already grants it."""
    from engine import aws_perm_ledger as L
    need = {r.action for c in ("TFLOW-01", "TFLOW-02") for r in L.REQUIREMENTS[c]}
    assert need == {"bedrock:GetDataSource", "bedrock:GetAgent"}
    granted = [{"effect": "Allow", "actions": {"bedrock:listagentknowledgebases"},
                "resources": {"*"}, "not_resources": set(), "condition": None}]
    assert L.granted(granted, "bedrock:ListAgentKnowledgeBases"), (
        "SecurityAudit grants this; if that stops being true the slice's cost changes")


def test_the_checks_are_fully_mapped():
    from engine import aws_finding_detail as D
    for cid in ("TFLOW-01", "TFLOW-02"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP
        assert cid in A.REMEDIATION_MAP and cid in D.FINDING_DETAIL
        assert "aws " in A.REMEDIATION_MAP[cid].lower()


def test_the_conditional_detail_says_it_is_capability_not_occurrence():
    from engine import aws_finding_detail as D
    risk = D.FINDING_DETAIL["TFLOW-02"]["risk"]
    assert "CONDITIONAL" in risk
    assert "capability, not occurrence" in risk


def test_the_emitter_never_raises_on_malformed_stash():
    s = _scanner()
    s._aispm_resources = [{}, {"kind": "BedrockAgent"},
                          _agent(injection_surface="nonsense")]
    s._emit_toxic_flow(_graph(), _principals())      # must not raise
