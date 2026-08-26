"""The MCP follow-on the SDK pin unlocked — and a claim it made that had become false.

`MCP-04` existed because a federated MCP server's tool list could not be read, so its
absence had to be *stated* rather than passed over. Under botocore 1.40.51 that was
true. The pin now sits at 1.43.51, where `McpServerTargetConfiguration` carries
`mcpToolSchema` and `listingMode` — so the check was emitting, verbatim:

    "the tool list is not a thing any API here returns, which means no scan of any
     depth can diff it"

which is no longer true where `listingMode` is `DEFAULT`. A live check asserting
something false is the phantom this codebase exists to prevent, so the claim is now
conditioned on what is actually readable, and the distinction it draws is a useful one:
`DEFAULT` caches the schema (diffable, no blind spot), `DYNAMIC` does not (blind spot,
and unlike a platform limit it is a *configuration choice* that can be changed).

`MCP-06` is the other half: the Registry and its approval lifecycle, which also did not
exist under the old pin.
"""
from __future__ import annotations

import os
import sys
import threading
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_checkdef as C
import aws_live_scanner as A
import aws_mcp as M


def target(**kw):
    return {"targetConfiguration": {"mcp": {"mcpServer": {"endpoint": "https://x", **kw}}}}


def _scanner(client=None):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["AGENTCORE"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: client if client is not None else MagicMock()
    s._is_access_denied = lambda e: "AccessDenied" in str(e)
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


# ── the enum values are AWS's ───────────────────────────────────────────────
def test_the_listing_mode_values_are_the_ones_the_model_declares():
    assert M.LISTING_DEFAULT == "DEFAULT" and M.LISTING_DYNAMIC == "DYNAMIC"


def test_only_approved_counts_as_approved():
    assert M.RECORD_APPROVED == "APPROVED"
    assert "REJECTED" in M.RECORD_REVIEWABLE and "DRAFT" in M.RECORD_REVIEWABLE


# ── the claim that had become false ─────────────────────────────────────────
def test_a_default_listing_mode_with_a_schema_has_NO_blind_spot():
    """The correction. DEFAULT caches the tool schema at the control plane, so it IS
    recorded and CAN be diffed -- the old note asserted the opposite."""
    a = M.assess_target(target(listingMode="DEFAULT",
                               mcpToolSchema={"inlinePayload": []}))
    assert a["federated"] is True
    assert M.blind_spot_note(a) == ""


def test_a_dynamic_listing_mode_does_have_a_blind_spot():
    a = M.assess_target(target(listingMode="DYNAMIC"))
    note = M.blind_spot_note(a)
    assert "retrieved at listing time" in note


def test_the_dynamic_note_says_it_is_a_choice_rather_than_a_platform_limit():
    """The material difference: DYNAMIC can be changed to DEFAULT. The old note said
    nothing could be done, which was true then and is not now."""
    a = M.assess_target(target(listingMode="DYNAMIC"))
    assert "configuration choice" in M.blind_spot_note(a)


def test_a_target_with_no_listing_mode_still_declares_the_blind_spot():
    """Targets predating the field must not silently become 'fine'."""
    a = M.assess_target(target())
    assert "no tool schema is recorded" in M.blind_spot_note(a)


def test_no_surviving_note_claims_no_api_returns_the_tool_list():
    """The specific sentence that was false. It must not survive anywhere."""
    for kw in ({}, {"listingMode": "DYNAMIC"},
               {"listingMode": "DEFAULT", "mcpToolSchema": {"inlinePayload": []}}):
        note = M.blind_spot_note(M.assess_target(target(**kw)))
        assert "not a thing any API here returns" not in note
        assert "no scan of any depth can diff it" not in note


def test_a_non_federated_target_still_declares_nothing():
    assert M.blind_spot_note({"federated": False}) == ""


def test_the_remediation_no_longer_says_nothing_can_be_done():
    """MCP-04's remediation used to open 'No action closes this one'. For DYNAMIC that
    is now wrong: switching to DEFAULT caches the schema."""
    rem = A.REMEDIATION_MAP["MCP-04"]
    assert not rem.startswith("No action closes this one")
    assert "DYNAMIC" in rem and "DEFAULT" in rem


# ── listing_mode itself ─────────────────────────────────────────────────────
@pytest.mark.parametrize("mode,expect", [("DEFAULT", False), ("DYNAMIC", True)])
def test_listing_mode_reads_the_field(mode, expect):
    r = M.listing_mode(target(listingMode=mode))
    assert r["known"] is True and r["dynamic"] is expect


def test_an_unrecognised_listing_mode_is_not_known():
    """A value added after this pin must read as not understood, never as fine."""
    r = M.listing_mode(target(listingMode="SOMETHING_NEW"))
    assert r["known"] is False and r["dynamic"] is False


@pytest.mark.parametrize("bad", [None, {}, "x", 7, {"targetConfiguration": "nope"}])
def test_listing_mode_survives_malformed_input(bad):
    M.listing_mode(bad if isinstance(bad, dict) else None)


# ── MCP-06: the registry ────────────────────────────────────────────────────
@pytest.mark.parametrize("status", ["DRAFT", "PENDING_APPROVAL", "REJECTED",
                                    "DEPRECATED"])
def test_a_record_short_of_approval_is_reported(status):
    r = M.registry_record({"name": "tool-a", "status": status})
    assert r["approved"] is False and status in r["statement"]


def test_an_approved_record_is_quiet():
    r = M.registry_record({"name": "tool-a", "status": "APPROVED"})
    assert r["approved"] is True and r["statement"] == ""


def test_an_absent_status_is_unknown_not_unapproved():
    r = M.registry_record({"name": "tool-a"})
    assert r["known"] is False and r["approved"] is False and r["statement"] == ""


def test_the_finding_does_not_claim_the_component_is_in_use():
    """The registry records approval state, not consumption. Claiming an unapproved
    record is live would be an inference the data does not support."""
    import aws_finding_detail as D
    risk = D.FINDING_DETAIL["MCP-06"]["risk"].lower()
    assert "not establish" in risk and "consumption" in risk


@pytest.mark.parametrize("bad", [None, {}, "x", 7])
def test_registry_record_survives_malformed_input(bad):
    M.registry_record(bad if isinstance(bad, dict) else None)


# ── the emitter ─────────────────────────────────────────────────────────────
def _registry_client(status="APPROVED"):
    c = MagicMock()
    c.list_registries.return_value = {"registrySummaries": [{"registryId": "reg-1"}]}
    c.list_registry_records.return_value = {
        "registryRecordSummaries": [{"name": "tool-a", "recordId": "r-1",
                                     "status": status}]}
    return c


def test_the_emitter_reports_an_unapproved_record():
    s = _scanner()
    s._emit_mcp_registry(_registry_client("PENDING_APPROVAL"))
    assert _ids(s, "MCP-06", "FAIL")


def test_the_emitter_passes_an_approved_record():
    s = _scanner()
    s._emit_mcp_registry(_registry_client("APPROVED"))
    assert _ids(s, "MCP-06", "PASS")


def test_a_denied_registry_read_is_a_coverage_note():
    class _Deny:
        def __getattr__(self, name):
            def _raise(*a, **kw):
                raise Exception("AccessDeniedException")
            return _raise

    s = _scanner()
    s._emit_mcp_registry(_Deny())
    assert "MCP-06" in s._coverage.not_evaluated
    assert not _ids(s, "MCP-06")


def test_the_emitter_terminates_against_a_bare_magicmock():
    s = _scanner()
    done = threading.Event()

    def _go():
        try:
            s._emit_mcp_registry(MagicMock())
        except Exception:
            pass
        finally:
            done.set()

    threading.Thread(target=_go, daemon=True).start()
    assert done.wait(timeout=20), "_emit_mcp_registry did not terminate"


# ── wiring ──────────────────────────────────────────────────────────────────
def test_mcp06_came_from_one_declaration():
    import aws_finding_detail as D
    import aws_perm_ledger as L
    d = C.REGISTRY["MCP-06"]
    assert A.CHECK_SEVERITY["MCP-06"] == d.severity
    assert A.REMEDIATION_MAP["MCP-06"] == d.remediation
    assert D.FINDING_DETAIL["MCP-06"]["risk"] == d.risk
    assert "MCP-06" in L.REQUIREMENTS


def test_the_registry_permissions_use_the_agentcore_iam_prefix():
    """bedrock-agentcore, not the bedrock-agentcore-control endpoint name -- the
    original instance of the client-name trap in this codebase."""
    actions = [p.action for p in C.REGISTRY["MCP-06"].permissions]
    assert actions and all(a.startswith("bedrock-agentcore:") for a in actions)
    assert not any("agentcore-control" in a for a in actions)
