"""Phase 2 · slice 2.4 — excessive agency and the human-in-the-loop gate.

Fixtures follow the Bedrock Agent API reference: `parentActionSignature` with its five
valid values, `actionGroupState`, and `functionSchema.functions[].requireConfirmation`
(`ENABLED | DISABLED`, not required).

Two properties carry the slice.

An absent `requireConfirmation` counts as UNGATED, and that is a documented default
rather than an assumption: "By default, user confirmation is DISABLED if this field is
not specified." The contrast with `requireMMDSV2` in slice 2.2 is deliberate — there the
reference states no default, so absent stays unknown and raises nothing. Same shape of
field, opposite treatment, because the documentation differs.

And nothing here infers consequence from a function's NAME. Flagging `delete_account`
while passing `get_weather` is a guess about semantics wearing the clothes of a
configuration reading, and the first false positive on a read-only `purge_cache` is what
teaches an operator to skip the category.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_agency as A


def fn(name, confirm=None):
    f = {"name": name, "description": f"does {name}"}
    if confirm is not None:
        f["requireConfirmation"] = confirm
    return f


def group(name="tools", *, signature=None, state="ENABLED", functions=None,
          api_schema=None):
    g = {"actionGroupId": "AG12345678", "actionGroupName": name,
         "actionGroupState": state}
    if signature:
        g["parentActionSignature"] = signature
    if functions is not None:
        g["functionSchema"] = {"functions": functions}
    if api_schema is not None:
        g["apiSchema"] = api_schema
    return g


# ── the vocabulary ──────────────────────────────────────────────────────────
def test_the_signature_enum_matches_the_reference():
    assert set(A.PARENT_SIGNATURES) == {
        "AMAZON.UserInput", "AMAZON.CodeInterpreter", "ANTHROPIC.Computer",
        "ANTHROPIC.Bash", "ANTHROPIC.TextEditor"}


def test_user_input_is_not_treated_as_high_agency():
    """It lets the agent ask the user a question, which is the opposite of excessive
    agency — it is the agent deferring rather than acting."""
    assert "AMAZON.UserInput" not in A.HIGH_AGENCY
    caps = A.group_capabilities(group(signature="AMAZON.UserInput"))
    assert caps["high_agency"] is False


@pytest.mark.parametrize("sig,sev", [("ANTHROPIC.Bash", "CRITICAL"),
                                     ("ANTHROPIC.Computer", "CRITICAL"),
                                     ("AMAZON.CodeInterpreter", "HIGH"),
                                     ("ANTHROPIC.TextEditor", "HIGH")])
def test_high_agency_capabilities_and_their_severities(sig, sev):
    caps = A.group_capabilities(group(signature=sig))
    assert caps["high_agency"] is True
    assert caps["severity"] == sev
    assert caps["grants"] and caps["why"], "a severity without a reason is a number"


def test_a_disabled_action_group_grants_nothing():
    """actionGroupState DISABLED means the agent cannot invoke it. Reporting a
    capability that is already switched off is a finding about nothing."""
    caps = A.group_capabilities(group(signature="ANTHROPIC.Bash", state="DISABLED"))
    assert caps["high_agency"] is False
    assert caps["enabled"] is False


def test_an_unrecognised_signature_is_flagged_as_unknown_not_bucketed():
    caps = A.group_capabilities(group(signature="ANTHROPIC.Quantum"))
    assert caps["known_signature"] is False
    assert caps["high_agency"] is False, "an unknown capability is not assumed dangerous"


# ── confirmation coverage ───────────────────────────────────────────────────
def test_an_absent_requireconfirmation_counts_as_ungated():
    """AWS: "By default, user confirmation is DISABLED if this field is not specified."
    A documented default, so absent is a fact and not an unknown."""
    cov = A.confirmation_coverage([group(functions=[fn("a"), fn("b")])])
    assert cov["total"] == 2 and cov["gated"] == 0
    assert cov["pct"] == 0.0


def test_explicit_enabled_counts_as_gated():
    cov = A.confirmation_coverage([group(functions=[fn("a", "ENABLED"),
                                                    fn("b", "DISABLED")])])
    assert cov["gated"] == 1 and cov["total"] == 2 and cov["pct"] == 50.0
    assert cov["ungated"] == ["tools/b"]


def test_ungated_functions_are_named_with_their_group():
    cov = A.confirmation_coverage([group("billing", functions=[fn("refund")])])
    assert cov["ungated"] == ["billing/refund"]


def test_functions_in_a_disabled_group_are_not_counted():
    cov = A.confirmation_coverage([group(state="DISABLED", functions=[fn("a")])])
    assert cov["total"] == 0


def test_an_agent_with_no_functions_reports_no_percentage_rather_than_zero():
    """0% gated and "there is nothing to gate" are different facts, and reporting the
    second as the first invents a failure on an agent that has no action surface."""
    cov = A.confirmation_coverage([group(functions=[])])
    assert cov["total"] == 0 and cov["pct"] is None


def test_an_openapi_group_is_recorded_as_unassessed_not_as_ungated():
    """x-requireConfirmation lives inside the OpenAPI payload, which may be an S3
    reference we do not read. Counting it as ungated invents a gap; counting it as
    gated hides one. Naming the blind spot is the only honest third option."""
    cov = A.confirmation_coverage([group("api", api_schema={"s3": {"s3BucketName": "b"}})])
    assert cov["total"] == 0
    assert cov["openapi_groups_not_assessed"] == ["api"]


# ── the two together ────────────────────────────────────────────────────────
def test_a_high_agency_capability_with_no_gate_escalates():
    """The shape LLM06 is actually about: the capability is what makes the missing gate
    matter, and the missing gate is what makes the capability reachable by an
    instruction rather than by a person."""
    a = A.assess_agent([group(signature="AMAZON.CodeInterpreter"),
                        group("tools", functions=[fn("run")])])
    assert a["ungated_high_agency"] is True
    assert a["worst_severity"] == "CRITICAL", (
        "CodeInterpreter is HIGH alone; ungated it compounds")


def test_a_gated_high_agency_capability_does_not_escalate():
    a = A.assess_agent([group(signature="AMAZON.CodeInterpreter"),
                        group("tools", functions=[fn("run", "ENABLED")])])
    assert a["ungated_high_agency"] is False
    assert a["worst_severity"] == "HIGH"


def test_bash_stays_critical_whether_gated_or_not():
    """A confirmation prompt in front of shell execution is better than nothing and is
    not a mitigation for holding it — the escalation rule must not be able to LOWER a
    severity."""
    a = A.assess_agent([group(signature="ANTHROPIC.Bash",
                              functions=[fn("run", "ENABLED")])])
    assert a["worst_severity"] == "CRITICAL"


def test_an_agent_with_no_capabilities_and_gated_functions_is_clean():
    a = A.assess_agent([group(functions=[fn("a", "ENABLED")])])
    assert a["capabilities"] == []
    assert a["worst_severity"] == ""
    assert a["ungated_high_agency"] is False


def test_an_agent_with_no_action_surface_at_all():
    a = A.assess_agent([])
    assert a["has_any_surface"] is False


def test_a_capability_with_no_functions_still_counts_as_surface():
    """The built-in signatures carry their own behaviour and are not described by a
    function schema, so an empty coverage count must not read as 'no agency'."""
    a = A.assess_agent([group(signature="ANTHROPIC.Bash")])
    assert a["has_any_surface"] is True
    assert a["signatures"] == ["ANTHROPIC.Bash"]


# ── what it deliberately does not do ────────────────────────────────────────
def test_no_consequence_is_inferred_from_a_function_name():
    """delete_account and get_weather must be treated identically. Guessing semantics
    from a name fails on any non-English convention and produces the false positive that
    teaches operators to skip the category."""
    scary = A.confirmation_coverage([group(functions=[fn("delete_all_accounts")])])
    tame = A.confirmation_coverage([group(functions=[fn("get_weather")])])
    assert scary["gated"] == tame["gated"] == 0
    assert scary["total"] == tame["total"] == 1
    import inspect
    src = inspect.getsource(A).lower()
    for word in ("delete", "drop", "payment", "transfer", "destroy"):
        assert f'"{word}' not in src, (
            f"a name-based heuristic on {word!r} crept in")


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    bad = re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests|urllib)\b",
                     inspect.getsource(A), re.M)
    assert not bad, f"pure classifier imports I/O: {bad}"


@pytest.mark.parametrize("bad", [None, [], [{}], ["nope"], [{"functionSchema": None}],
                                 [{"functionSchema": {"functions": "x"}}]])
def test_nothing_raises_on_malformed_input(bad):
    A.confirmation_coverage(bad)
    A.assess_agent(bad)
    A.group_capabilities(bad[0] if bad else None)
