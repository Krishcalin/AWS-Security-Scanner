"""Phase 3 · slice 3.3 — MCP server provenance, the classifier.

An AgentCore Gateway *is* an MCP server, and what it publishes to an agent is decided by
its targets. Three of the four target kinds describe an API inside the account; the
fourth, `mcpServer`, federates an endpoint somewhere else. This module's job is to tell
those apart and say what a URL can — and cannot — establish about who runs a tool
provider.

The tests below are mostly about the second half. Provenance invites over-claiming: a
hostname does not tell you who operates a service or whether they are trustworthy, and a
scanner that implies otherwise is worse than one that says less. What a URL establishes
is the transport and whether the host sits under a domain AWS runs. Everything past that
is a question for the person reading the finding.

The blind-spot note carries the slice. Under the pinned service model AWS records a
federated server's endpoint and never its tools, so a rug pull leaves no trace in the
account — and a reader who sees a federated server reported without that sentence will
assume the tools were checked.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_mcp as M


def target(kind="mcpServer", endpoint="https://tools.vendor.example/mcp", **over):
    inner = {"endpoint": endpoint} if kind == "mcpServer" else {"s3": {"uri": "s3://b/k"}}
    t = {"targetId": "t1", "name": "vendor-tools",
         "targetConfiguration": {"mcp": {kind: inner}}}
    t.update(over)
    return t


def gateway(instructions=None, versions=("2025-03-26",)):
    mcp = {"supportedVersions": list(versions), "searchType": "SEMANTIC"}
    if instructions is not None:
        mcp["instructions"] = instructions
    return {"name": "tools", "protocolConfiguration": {"mcp": mcp}}


# ── which of the four kinds ─────────────────────────────────────────────────
@pytest.mark.parametrize("kind", M.TARGET_KINDS)
def test_every_documented_kind_is_recognized(kind):
    assert M.target_kind(target(kind)) == kind


def test_only_the_mcp_server_kind_is_federated():
    """The other three describe an API inside the account: the tool definitions are the
    operator's own, versioned with their infrastructure and diffable in review."""
    assert M.assess_target(target("mcpServer"))["federated"] is True
    for kind in ("openApiSchema", "smithyModel", "lambda"):
        assert M.assess_target(target(kind))["federated"] is False


def test_a_kind_added_after_the_pin_reads_as_not_understood():
    """A target variant this SDK does not know must never fall through to a default.
    'Understood and fine' and 'not understood' are different claims, and only one of
    them is true here."""
    t = {"targetId": "t9", "targetConfiguration": {"mcp": {"quantumThing": {}}}}
    assert M.target_kind(t) == "unknown:quantumThing"
    assert M.assess_target(t)["federated"] is False


def test_a_summary_row_has_no_readable_kind():
    """ListGatewayTargets returns TargetSummary, which carries no targetConfiguration.
    That must read as unreadable rather than as a target of no interesting kind — the
    distinction is the whole reason this slice needs GetGatewayTarget."""
    a = M.assess_target({"targetId": "t1", "name": "x", "status": "READY"})
    assert a["readable"] is False and a["federated"] is False
    assert "could not be read" in M.describe(a)


# ── provenance, and its limits ──────────────────────────────────────────────
def test_an_aws_hosted_endpoint_is_told_apart_from_an_arbitrary_one():
    """Not because AWS-hosted is safe, but because the remediation differs: one is a
    vendor question, the other is an AWS-resource question."""
    aws = M.endpoint_provenance("https://x.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp")
    other = M.endpoint_provenance("https://tools.vendor.example/mcp")
    assert aws["provenance"] == M.PROV_AWS
    assert other["provenance"] == M.PROV_THIRD_PARTY


def test_plaintext_is_the_finding():
    p = M.endpoint_provenance("http://tools.vendor.example/mcp")
    assert p["plaintext"] is True and p["scheme"] == "http"
    assert "rewrite what a tool claims to do" in M.describe(M.assess_target(
        target(endpoint="http://tools.vendor.example/mcp")))


def test_https_is_not_plaintext():
    assert M.endpoint_provenance("https://tools.vendor.example/mcp")["plaintext"] is False


def test_an_unparseable_endpoint_is_unknown_rather_than_either_verdict():
    """Guessing which way a malformed endpoint resolves would either invent a finding or
    erase one."""
    for bad in ("", "   ", "not a url", "ftp://x/y"):
        p = M.endpoint_provenance(bad)
        assert p["provenance"] == M.PROV_UNKNOWN, bad
        assert p["plaintext"] is False, bad


def test_a_scheme_less_endpoint_is_not_called_plaintext():
    """host:port with no scheme is unknown transport, not proven-insecure transport."""
    p = M.endpoint_provenance("tools.vendor.example:8080")
    assert p["plaintext"] is False


def test_provenance_claims_nothing_about_trust():
    """A hostname does not tell you who operates a service. A field named for trust or
    for a vendor identity would be a guess dressed as provenance."""
    p = M.endpoint_provenance("https://tools.vendor.example/mcp")
    for key in p:
        assert key not in ("trusted", "vendor", "reputation", "approved", "known")


def test_the_host_is_lowercased_for_comparison():
    assert M.endpoint_provenance("HTTPS://Tools.Vendor.Example/x")["host"] == \
        "tools.vendor.example"


# ── the gateway instructions channel ────────────────────────────────────────
def test_the_instructions_string_is_read_from_the_protocol_config():
    assert M.gateway_instructions(gateway("Use these tools for billing.")) == \
        "Use these tools for billing."


def test_an_absent_instructions_field_is_empty_rather_than_missing():
    assert M.gateway_instructions(gateway()) == ""
    assert M.gateway_instructions(None) == ""
    assert M.gateway_instructions({"protocolConfiguration": "nope"}) == ""


def test_the_module_authors_no_injection_phrasings():
    """3.2 refuses to author them, and refusing once is worth nothing if the next
    module does it. This module hands the string to aws_toolpoison unchanged."""
    import inspect
    src = inspect.getsource(M).lower()
    for phrase in ("ignore previous", "ignore all", "disregard", "you are now",
                   "system prompt", "jailbreak"):
        assert phrase not in src, phrase


# ── the blind spot ──────────────────────────────────────────────────────────
def test_the_blind_spot_is_declared_for_a_federated_target():
    """The intent is unchanged: a federated target whose tool list is not recorded must
    SAY so rather than read as audited. The exact sentence is no longer pinned, because
    the one this used to assert -- "never the tools it serves" -- became false when the
    SDK pin moved to botocore 1.43.51 and McpServerTargetConfiguration gained
    mcpToolSchema and listingMode."""
    note = M.blind_spot_note(M.assess_target(target()))
    assert "no tool schema is recorded" in note
    assert "no trace in this account" in note


def test_no_blind_spot_is_declared_when_the_schema_IS_recorded():
    """The correction. listingMode DEFAULT caches the tool schema at the control plane,
    so it is readable and diffable -- declaring a blind spot there would be the same
    error in the opposite direction."""
    t = {"targetConfiguration": {"mcp": {"mcpServer": {
        "endpoint": "https://example.com/mcp", "listingMode": "DEFAULT",
        "mcpToolSchema": {"inlinePayload": []}}}}}
    assert M.blind_spot_note(M.assess_target(t)) == ""


def test_no_blind_spot_is_claimed_for_an_in_account_target():
    """An openApiSchema target has its definitions in the account. Declaring a blind
    spot there would be alarm without content."""
    for kind in ("openApiSchema", "smithyModel", "lambda"):
        assert M.blind_spot_note(M.assess_target(target(kind))) == ""


# ── the fingerprint ─────────────────────────────────────────────────────────
def test_the_fingerprint_is_stable_across_dict_ordering():
    """It anchors change detection across scans, so it must depend on the configuration
    and never on how the SDK happened to serialize it."""
    a = M.surface_fingerprint(gateway("x"), [target(), target("lambda", tid="t2")])
    b = M.surface_fingerprint(gateway("x"), [target("lambda", tid="t2"), target()])
    assert a == b


def test_a_repointed_target_changes_the_fingerprint():
    a = M.surface_fingerprint(gateway("x"), [target(endpoint="https://a.example/mcp")])
    b = M.surface_fingerprint(gateway("x"), [target(endpoint="https://b.example/mcp")])
    assert a != b


def test_changed_instructions_change_the_fingerprint():
    assert M.surface_fingerprint(gateway("x"), []) != \
        M.surface_fingerprint(gateway("y"), [])


def test_the_fingerprint_cannot_see_a_server_serving_different_tools():
    """The limit that makes MCP-04 necessary, asserted so nobody later reads the
    fingerprint as covering more than it does: identical configuration produces an
    identical digest no matter what the far end is actually serving."""
    assert M.surface_fingerprint(gateway("x"), [target()]) == \
        M.surface_fingerprint(gateway("x"), [target()])


# ── robustness ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, {}, "nope", 7, {"targetConfiguration": "x"},
                                 {"targetConfiguration": {"mcp": "x"}},
                                 {"targetConfiguration": {"mcp": {"mcpServer": "x"}}}])
def test_nothing_raises_on_malformed_input(bad):
    a = M.assess_target(bad)
    M.describe(a)
    M.blind_spot_note(a)
    M.mcp_endpoint(bad)
    M.surface_fingerprint(bad, [bad])


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests|urllib\.request)\b",
                          inspect.getsource(M), re.M)
