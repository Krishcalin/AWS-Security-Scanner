"""Phase 3 · slice 3.4 — memory-poisoning exposure, the configuration half.

Agent memory is what lets a prompt injection outlive the conversation that carried it: an
instruction written in one session is read back in the next. Everything else in Phase 3
asks what an injection reaches now; this asks how long it keeps reaching.

The roadmap's framing — *config half only* — is the constraint under test. Answering "is
there a poisoned memory in here" means reading stored conversation, which is the
escalation D2 declined. What configuration alone establishes is the exposure WINDOW and
the key CUSTODY, and the tests below are largely about the module staying on that side of
the line: absent retention is unknown rather than zero, no memory is not a finding, and
the finding says out loud that contents were not examined.

That last one matters. A reader who sees a memory finding with no mention of contents will
assume the contents were checked and were clean, which is a phantom pass produced by
omission rather than by assertion.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_agentmemory as M


def agent(days=None, types=("SESSION_SUMMARY",)):
    cfg = {"enabledMemoryTypes": list(types)}
    if days is not None:
        cfg["storageDays"] = days
    return {"agentId": "A1", "memoryConfiguration": cfg}


def memory(days=30, cmk=True, strategies=(("SEMANTIC", 2),)):
    m = {"id": "mem-1", "name": "support-memory", "status": "ACTIVE",
         "eventExpiryDuration": days,
         "strategies": [{"type": t, "namespaces": ["/x"] * n} for t, n in strategies]}
    if cmk:
        m["encryptionKeyArn"] = "arn:aws:kms:us-east-1:123456789012:key/k1"
    return m


# ── no memory is the good outcome ───────────────────────────────────────────
def test_an_agent_without_memory_is_not_a_finding():
    """An agent that cannot carry an instruction between sessions is the outcome this
    check hopes for, not a gap in it."""
    p = M.bedrock_agent_memory({"agentId": "A1"})
    assert p["enabled"] is False
    assert M.exposure_window(p)["band"] == "none"
    assert M.summarize(p, M.exposure_window(p)) == ""


def test_zero_retention_is_none_not_short():
    p = M.bedrock_agent_memory(agent(days=0))
    assert M.exposure_window(p)["band"] == "none"


# ── absent is unknown, not zero ─────────────────────────────────────────────
def test_absent_retention_is_unknown_rather_than_assumed():
    """storageDays is optional and the reference states no default. Assuming one would
    either invent an exposure window or erase a real one — the same distinction that kept
    requireMMDSV2 unknown in 2.2 and made requireConfirmation a fact in 2.4."""
    p = M.bedrock_agent_memory(agent(days=None))
    assert p["enabled"] is True and p["known_days"] is False
    w = M.exposure_window(p)
    assert w["band"] == "unknown"
    assert "could not be established rather than being short" in w["why"]


# ── the window ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("days,band", [(1, "short"), (29, "short"), (30, "extended"),
                                       (89, "extended"), (90, "long"), (365, "long")])
def test_the_retention_bands(days, band):
    assert M.exposure_window(M.bedrock_agent_memory(agent(days=days)))["band"] == band


def test_the_window_is_stated_in_days_not_as_a_verdict():
    """There is no correct retention period — a support assistant that remembers a
    customer for a year may be exactly right. The finding states the number so the
    operator can say whether they chose it."""
    w = M.exposure_window(M.bedrock_agent_memory(agent(days=180)))
    assert "180 day(s)" in w["why"]
    assert "read back into the model's context" in w["why"]


def test_both_surfaces_cap_at_a_year():
    assert M.MAX_RETENTION_DAYS == 365


# ── AgentCore memory ────────────────────────────────────────────────────────
def test_agentcore_memory_reads_expiry_and_custody():
    p = M.agentcore_memory(memory(days=120, cmk=False))
    assert p["enabled"] is True and p["days"] == 120 and p["cmk"] is False
    assert M.exposure_window(p)["band"] == "long"


def test_a_customer_managed_key_is_noted_as_present():
    p = M.agentcore_memory(memory(cmk=True))
    assert p["cmk"] is True
    assert "AWS-managed key" not in M.summarize(p, M.exposure_window(p))


def test_an_aws_managed_key_is_called_out_as_custody():
    """Same question the token vault raised in 2.5: no key to disable means no lever."""
    p = M.agentcore_memory(memory(cmk=False))
    s = M.summarize(p, M.exposure_window(p))
    assert "AWS-managed key" in s and "disable" in s


def test_strategy_types_are_reported():
    p = M.agentcore_memory(memory(strategies=(("SEMANTIC", 1), ("USER_PREFERENCE", 1))))
    assert p["types"] == ["SEMANTIC", "USER_PREFERENCE"]


def test_namespaces_are_counted_not_interpreted():
    """A namespace template decides whether memory is per-actor or shared, but the
    template variables are operator-defined and their semantics are not in the API
    reference. The count is a fact; a reading of it would be a guess."""
    p = M.agentcore_memory(memory(strategies=(("SEMANTIC", 3),)))
    assert p["namespaces"] == 3
    for key in p:
        assert "shared" not in key and "scoped" not in key


# ── the line this slice does not cross ──────────────────────────────────────
def test_the_finding_says_contents_were_not_read():
    """Without this, a reader assumes the contents were checked and found clean — a
    phantom pass produced by omission rather than assertion."""
    p = M.bedrock_agent_memory(agent(days=90))
    s = M.summarize(p, M.exposure_window(p))
    assert "does NOT read memory contents" in s
    assert "not a question this scan asks" in s


def test_the_module_reads_no_memory_content():
    """D2 in force. The config half is the whole of this slice, and a field named for
    stored conversation appearing here would be the reversal of a decision taken
    deliberately."""
    import inspect
    src = inspect.getsource(M).lower()
    for banned in ('"content"', "'content'", '"messages"', "'messages'",
                   '"summary"', "'summary'", '"events"', "'events'"):
        assert banned not in src, f"{banned} suggests reading stored conversation"


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    bad = re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests|urllib)\b",
                     inspect.getsource(M), re.M)
    assert not bad


@pytest.mark.parametrize("bad", [None, {}, "nope", {"memoryConfiguration": "x"},
                                 {"memoryConfiguration": {"storageDays": "90"}}])
def test_nothing_raises_on_malformed_input(bad):
    p = M.bedrock_agent_memory(bad)
    M.exposure_window(p)
    M.summarize(p, M.exposure_window(p))
    M.agentcore_memory(bad if isinstance(bad, dict) else None)


def test_a_string_retention_is_not_treated_as_a_number():
    """A JSON quirk must not become an exposure window."""
    p = M.bedrock_agent_memory({"memoryConfiguration": {"storageDays": "90"}})
    assert p["known_days"] is False
