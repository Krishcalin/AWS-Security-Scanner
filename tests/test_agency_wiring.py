"""Phase 2 · slice 2.4 — the scanner surface for excessive agency.

The property worth testing beyond "it emits": this slice costs nothing new. It rides on
`get_agent_action_group`, which AGT-04 already calls and slice 1.2 already granted. The
ledger records all three checks against that one action so declining it names everything
it forfeits, and a test pins that no new permission appeared.

The other one: severity is split across three check ids on purpose. CHECK_SEVERITY is per
check id, so a single id would have to price ANTHROPIC.Bash — a shell — the same as
ANTHROPIC.TextEditor. One of those would then be wrong, and the wrong one would be the
shell.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_agency as G
import aws_live_scanner as A
from aws_live_scanner import AWSLiveScanner


def fn(name, confirm=None):
    f = {"name": name}
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


def _scanner():
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False,
                           sections=["BEDROCK_AGENTS"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: MagicMock()
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


# ── the checks ──────────────────────────────────────────────────────────────
def test_a_shell_capability_is_critical():
    s = _scanner()
    s._emit_agency("support-bot", [group(signature="ANTHROPIC.Bash")])
    f = _ids(s, "AGY-01", "FAIL")
    assert f and "ANTHROPIC.Bash" in f[0].message
    assert "shell command execution" in f[0].message
    assert f[0].severity == "CRITICAL"


def test_desktop_control_is_critical_too():
    s = _scanner()
    s._emit_agency("bot", [group(signature="ANTHROPIC.Computer")])
    assert _ids(s, "AGY-01", "FAIL")


def test_code_execution_and_file_access_are_high_not_critical():
    for sig in ("AMAZON.CodeInterpreter", "ANTHROPIC.TextEditor"):
        s = _scanner()
        s._emit_agency("bot", [group(signature=sig)])
        f = _ids(s, "AGY-02", "FAIL")
        assert f, sig
        assert f[0].severity == "HIGH", sig
        assert not _ids(s, "AGY-01"), f"{sig} must not price as a shell"


def test_user_input_raises_nothing():
    """It lets the agent ask a question back. Flagging it would put a finding on the one
    capability that represents the agent deferring rather than acting."""
    s = _scanner()
    s._emit_agency("bot", [group(signature="AMAZON.UserInput")])
    assert not _ids(s, "AGY-01") and not _ids(s, "AGY-02")


def test_a_disabled_action_group_raises_nothing():
    s = _scanner()
    s._emit_agency("bot", [group(signature="ANTHROPIC.Bash", state="DISABLED")])
    assert not _ids(s, "AGY-01")


# ── the confirmation gate ───────────────────────────────────────────────────
def test_no_confirmation_anywhere_is_a_fail_that_cites_the_default():
    """The message has to say the field defaults to DISABLED, or an operator reading it
    concludes somebody deliberately turned a safeguard off — and goes looking for who."""
    s = _scanner()
    s._emit_agency("bot", [group(functions=[fn("a"), fn("b")])])
    f = _ids(s, "AGY-03", "FAIL")
    assert f
    assert "prompt-injection safeguard" in f[0].message
    assert "DISABLED unless set" in f[0].message


def test_partial_coverage_warns_and_names_the_ungated():
    s = _scanner()
    s._emit_agency("bot", [group("billing", functions=[fn("read", "ENABLED"),
                                                       fn("refund")])])
    w = _ids(s, "AGY-03", "WARN")
    assert w and "1 of 2" in w[0].message and "billing/refund" in w[0].message


def test_full_coverage_passes():
    s = _scanner()
    s._emit_agency("bot", [group(functions=[fn("a", "ENABLED")])])
    assert _ids(s, "AGY-03", "PASS")


def test_an_agent_with_no_action_surface_says_nothing():
    s = _scanner()
    s._emit_agency("bot", [])
    assert not [r for r in s.results if r.check_id.startswith("AGY-")]


def test_a_capability_with_no_functions_still_reports_the_capability():
    """The built-in signatures carry their own behaviour and have no function schema.
    An empty coverage count must not silence the capability finding."""
    s = _scanner()
    s._emit_agency("bot", [group(signature="ANTHROPIC.Bash", functions=[])])
    assert _ids(s, "AGY-01", "FAIL")
    assert not _ids(s, "AGY-03"), "nothing to gate is not a gating failure"


def test_the_fusion_is_called_out_in_the_message():
    s = _scanner()
    s._emit_agency("bot", [group(signature="ANTHROPIC.Bash"),
                           group("tools", functions=[fn("run")])])
    f = _ids(s, "AGY-03", "FAIL")
    assert f and "ANTHROPIC.Bash" in f[0].message, (
        "an ungated agent that also holds a shell should say so in the same breath")


def test_an_openapi_group_is_named_as_unassessed():
    s = _scanner()
    s._emit_agency("bot", [group("api", api_schema={"s3": {"s3BucketName": "b"}})])
    notes = _ids(s, "AGY-00")
    assert notes and "no phantom pass" in notes[0].message
    assert not _ids(s, "AGY-03"), "an unread schema is not an ungated one"


def test_the_informational_id_stays_out_of_the_score():
    assert "AGY-00" not in A.CHECK_SEVERITY


# ── it costs nothing new ────────────────────────────────────────────────────
def test_the_slice_added_no_new_iam_action():
    """It rides on get_agent_action_group, which AGT-04 already calls and slice 1.2
    already granted. If that stops being true the justification for the slice changes,
    and this is where it surfaces."""
    import aws_perm_ledger as L
    agy = {r.action for c in ("AGY-01", "AGY-02", "AGY-03")
           for r in L.REQUIREMENTS[c]}
    assert agy == {"bedrock:GetAgentActionGroup"}
    others = {r.action for c, reqs in L.REQUIREMENTS.items()
              for r in reqs if not c.startswith("AGY-")}
    assert agy <= others, "AGY introduced an action no other check needed"


def test_declining_that_one_action_now_names_the_agency_checks_too():
    """The ledger's contract: decline an action and it tells you everything you lose."""
    import aws_perm_ledger as L
    led = L.evaluate([{"effect": "Allow", "actions": {"iam:get*"}, "resources": {"*"},
                       "not_resources": set(), "condition": None}])
    lost = set(led.forfeit(["bedrock:GetAgentActionGroup"]))
    assert {"AGY-01", "AGY-02", "AGY-03", "AGT-04"} <= lost


def test_the_assessment_runs_off_detail_the_loop_already_fetched():
    import inspect
    src = inspect.getsource(A)
    assert "agency_groups.append(grp_detail)" in src, (
        "the assessment must reuse the detail AGT-04 fetches, not fetch its own")
    assert "self._emit_agency(aname, agency_groups)" in src


# ── mapping ─────────────────────────────────────────────────────────────────
def test_the_checks_are_fully_mapped():
    import aws_finding_detail as D
    for cid in ("AGY-01", "AGY-02", "AGY-03"):
        assert cid in A.CHECK_SEVERITY, cid
        assert cid in A.COMPLIANCE_MAP, cid
        assert cid in A.REMEDIATION_MAP, cid
        assert cid in D.FINDING_DETAIL, cid
        assert "aws " in A.REMEDIATION_MAP[cid].lower(), cid


def test_capability_checks_map_to_least_functionality():
    """CM-7 is literally the control this measures: an agent holding a shell it does not
    need is the definition of excessive functionality."""
    assert A.COMPLIANCE_MAP["AGY-01"]["NIST"] == "CM-7"
    assert A.COMPLIANCE_MAP["AGY-02"]["NIST"] == "CM-7"
