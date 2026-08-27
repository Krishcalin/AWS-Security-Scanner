"""Phase 3 · slice 3.4 — the scanner surface for memory-poisoning exposure.

Three integration properties carry the slice.

**Two surfaces, one question.** The retention window is `memoryConfiguration.storageDays`
on a Bedrock agent and `eventExpiryDuration` on an AgentCore memory. Both answer "how
long does an instruction that reached memory keep being read back", so both emit AMEM-01.

**A window that could not be read is not a short one.** An agent with memory enabled and
no retention value gets AMEM-00 (INFO) rather than a PASS. The band exists so that
absence never renders as safety.

**The denial is scoped.** This is the first check in the permission ledger that spans two
surfaces, and only the AgentCore one needs `bedrock-agentcore:GetMemory`. Recording an
unqualified "AMEM-01 was not evaluated" would contradict the AMEM-01 findings the same
scan emitted for every Bedrock agent — a phantom GAP, the mirror of the phantom pass.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_perm_ledger as L
from engine.aws_live_scanner import AWSLiveScanner


def _scanner():
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["DATA"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: MagicMock()
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _detail(days=None, enabled=True):
    if not enabled:
        return {"agentId": "A1"}
    cfg = {"enabledMemoryTypes": ["SESSION_SUMMARY"]}
    if days is not None:
        cfg["storageDays"] = days
    return {"agentId": "A1", "memoryConfiguration": cfg}


def _memory(days=30, cmk=True):
    m = {"id": "mem-1", "name": "support-memory", "status": "ACTIVE",
         "eventExpiryDuration": days,
         "strategies": [{"type": "SEMANTIC", "namespaces": ["/actor/{id}"]}]}
    if cmk:
        m["encryptionKeyArn"] = "arn:aws:kms:us-east-1:123456789012:key/k1"
    return m


def _agentcore(detail=None, denied=False):
    ac = MagicMock()
    if denied:
        err = Exception("AccessDeniedException")
        err.response = {"Error": {"Code": "AccessDeniedException"}}
        ac.get_memory.side_effect = err
    else:
        ac.get_memory.return_value = {"memory": detail}
    return ac


# ── the Bedrock-agent surface ───────────────────────────────────────────────
def test_no_memory_emits_nothing():
    """An agent that cannot carry an instruction between sessions is the outcome the
    check hopes for. Emitting a PASS for it would put a row in the report for every
    agent in the account and bury the ones that matter."""
    s = _scanner()
    s._emit_agent_memory("support-bot", _detail(enabled=False))
    assert not _ids(s, "AMEM-01") and not _ids(s, "AMEM-00")


@pytest.mark.parametrize("days,status", [(7, "PASS"), (29, "PASS"),
                                         (30, "FAIL"), (365, "FAIL")])
def test_the_band_picks_the_status(days, status):
    s = _scanner()
    s._emit_agent_memory("support-bot", _detail(days=days))
    assert len(_ids(s, "AMEM-01", status)) == 1


def test_an_unreadable_window_is_info_not_a_pass():
    """storageDays is optional and the reference states no default. A PASS here would
    be the phantom pass in its purest form: silence read as a short window."""
    s = _scanner()
    s._emit_agent_memory("support-bot", _detail(days=None))
    assert not _ids(s, "AMEM-01")
    info = _ids(s, "AMEM-00")
    assert len(info) == 1 and info[0].status == "INFO"
    assert "could not be established rather than being short" in info[0].message


def test_the_finding_names_the_agent_and_the_window():
    s = _scanner()
    s._emit_agent_memory("support-bot", _detail(days=180))
    msg = _ids(s, "AMEM-01", "FAIL")[0].message
    assert "support-bot" in msg and "180 day(s)" in msg


def test_the_finding_says_contents_were_not_read():
    """Without this the reader assumes memory was inspected and found clean."""
    s = _scanner()
    s._emit_agent_memory("support-bot", _detail(days=180))
    assert "does NOT read memory contents" in _ids(s, "AMEM-01", "FAIL")[0].message


# ── the AgentCore surface ───────────────────────────────────────────────────
def test_the_agentcore_window_raises_the_same_check():
    """Same question, different field name. A reader should not have to know which
    service the agent runs on to find the answer."""
    s = _scanner()
    s._audit_agentcore_memory(_agentcore(_memory(days=120)), [{"id": "mem-1"}])
    fails = _ids(s, "AMEM-01", "FAIL")
    assert len(fails) == 1 and "support-memory" in fails[0].message


def test_a_short_agentcore_window_passes():
    s = _scanner()
    s._audit_agentcore_memory(_agentcore(_memory(days=7)), [{"id": "mem-1"}])
    assert len(_ids(s, "AMEM-01", "PASS")) == 1


def test_an_aws_managed_key_raises_the_custody_check():
    s = _scanner()
    s._audit_agentcore_memory(_agentcore(_memory(cmk=False)), [{"id": "mem-1"}])
    fails = _ids(s, "AMEM-02", "FAIL")
    assert len(fails) == 1
    assert "no key you can disable" in fails[0].message


def test_a_customer_managed_key_raises_nothing():
    s = _scanner()
    s._audit_agentcore_memory(_agentcore(_memory(cmk=True)), [{"id": "mem-1"}])
    assert not _ids(s, "AMEM-02")


def test_an_estate_with_no_memories_is_silent():
    s = _scanner()
    s._audit_agentcore_memory(_agentcore(_memory()), [])
    assert not _ids(s, "AMEM-01") and not _ids(s, "AMEM-02")


def test_an_older_client_without_get_memory_does_not_raise():
    """botocore ships AgentCore operations on its own schedule. A client that predates
    GetMemory must cost the check, not the scan."""
    ac = MagicMock(spec=[])
    s = _scanner()
    s._audit_agentcore_memory(ac, [{"id": "mem-1"}])
    assert not _ids(s, "AMEM-01")


# ── the scoped denial ───────────────────────────────────────────────────────
def test_a_denied_agentcore_read_scopes_the_amem01_gap():
    """The load-bearing one. AMEM-01 also runs off GetAgent, so the honest statement
    is that the AgentCore half was refused — not that the check never ran."""
    s = _scanner()
    s._audit_agentcore_memory(_agentcore(denied=True), [{"id": "mem-1"}])
    reason = s._coverage.not_evaluated["AMEM-01"]
    assert "AgentCore memories" in reason
    assert "bedrock-agentcore:GetMemory" in reason
    # AMEM-02 has no second surface, so its denial is unqualified and true.
    assert s._coverage.not_evaluated["AMEM-02"] == (
        "AccessDenied — missing bedrock-agentcore:GetMemory")


def test_the_ledger_does_not_claim_amem01_is_unevaluable():
    """The preflight announces blocked checks before the scan runs. Naming GetMemory as
    AMEM-01's requirement would have printed "AMEM-01 will NOT be evaluated" into a
    report that then carries an AMEM-01 row for every Bedrock agent."""
    granted = [{"effect": "Allow", "actions": {"bedrock:getagent"}, "resources": {"*"},
                "not_resources": set(), "condition": None}]
    led = L.evaluate(granted)
    assert "AMEM-01" in led.evaluable
    assert "AMEM-02" in led.blocked
    assert L.REQUIREMENTS["AMEM-01"][0].action == "bedrock:GetAgent"


def test_declining_get_memory_names_amem02_and_stops_there():
    """The ledger's contract is that declining an action names exactly what it costs.
    Over-naming is as much a defect as under-naming: an operator told they lose the
    whole memory picture may grant an action they did not need to."""
    granted = [{"effect": "Allow", "actions": {"bedrock:getagent"}, "resources": {"*"},
                "not_resources": set(), "condition": None}]
    led = L.evaluate(granted)
    assert "AMEM-02" in led.forfeit(["bedrock-agentcore:GetMemory"])
    assert "AMEM-01" not in led.forfeit(["bedrock-agentcore:GetMemory"])


def test_a_scoped_note_still_marks_coverage_incomplete():
    """Scoping the reason narrows the claim; it does not soften it. A partial answer is
    still not a complete one, and the console must not draw it as a clean scan."""
    m = L.CoverageManifest()
    m.note_denied("AMEM-01", "bedrock-agentcore:GetMemory", scope="AgentCore memories")
    assert not m.complete
    assert "bedrock-agentcore:GetMemory" in m.missing_actions
