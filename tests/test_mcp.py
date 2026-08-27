"""Phase 1 · slice 1.5 — the local read-only MCP server, and decision D6.

D6 ruled that the client boundary is ENFORCED rather than advertised. The roadmap's
proposal was a warning inside the tool descriptions; those are read by the model, not by
the engineer editing a config file, so they are a disclaimer. What is tested here is the
part that actually holds:

  * the server REFUSES TO START without an explicit acknowledgement, so sending an
    estate's security posture to a hosted model is a decision somebody made rather than
    a default nobody noticed;
  * identifiers are REDACTED BY DEFAULT, so the analysis travels and the ARNs do not;
  * every call is AUDITED, because we cannot audit what the client did with a response
    but we can say exactly what left here.

Protocol shapes are taken from the MCP specification (2025-06-18) rather than from
memory: newline-delimited JSON-RPC with no embedded newlines, an initialize handshake
that echoes a supported protocolVersion, unknown TOOLS as protocol errors and failures
INSIDE a known tool as results carrying isError.
"""
from __future__ import annotations

import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hub import cnapp_mcp as M

from _layout import module_path

ACCOUNT = "123456789012"
BUCKET_ARN = f"arn:aws:s3:::prod-customer-pii"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/AdminRole"

REPORT = {
    "timestamp": "2026-08-25T09:00:00Z",
    "posture_score": 61,
    "posture_grade": "C",
    "summary": {"CRITICAL": 1, "HIGH": 3, "total": 4},
    "coverage": {"complete": False,
                 "not_evaluated": {"AIGRD-01": "AccessDenied - missing "
                                               "bedrock:GetGuardrail"},
                 "unscanned_regions": ["eu-west-3"]},
    "permission_ledger": {"missing_actions": ["bedrock:GetGuardrail"],
                          "blocked": {"AIGRD-01": ["bedrock:GetGuardrail"]}},
    "finding_catalog": {"AIGRD-03": {"risk": "A guardrail is available but not "
                                             "mandatory.", "steps": ["..."]}},
    "attack_paths": [{"nodes": ["internet", BUCKET_ARN], "severity": "CRITICAL"}],
    "choke_points": [],
    "results": [
        {"status": "FAIL", "check_id": "S3-01", "section": "S3", "resource": BUCKET_ARN,
         "message": f"Bucket {BUCKET_ARN} in account {ACCOUNT} is public "
                    f"(203.0.113.7)", "severity": "CRITICAL"},
        {"status": "FAIL", "check_id": "IAM-01", "section": "IAM", "resource": ROLE_ARN,
         "message": f"Role {ROLE_ARN} has AdministratorAccess", "severity": "HIGH"},
        {"status": "PASS", "check_id": "S3-02", "section": "S3", "resource": BUCKET_ARN,
         "message": "Encrypted", "severity": ""},
    ],
}


@pytest.fixture
def report(tmp_path):
    p = tmp_path / "scan.json"
    p.write_text(json.dumps(REPORT), encoding="utf-8")
    return M.Report(str(p))


def server(report, *, identifiers=False, audit=None):
    return M.Server(report, M.Redactor(enabled=not identifiers),
                    M.Audit(audit, identifiers))


def call(srv, tool, **args):
    out = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": tool, "arguments": args}})
    return out


def payload(out):
    return json.loads(out["result"]["content"][0]["text"])


# ── D6: the gate ────────────────────────────────────────────────────────────
def test_the_server_refuses_to_start_without_acknowledgement():
    """The whole of D6 in one assertion. Without this the boundary is a sentence in a
    tool description that the engineer wiring up the config never reads."""
    assert M.gate({}) == (False, False)
    assert M.gate({M.ACK_ENV: "0"})[0] is False
    assert M.gate({M.ACK_ENV: "true"})[0] is False, (
        "only an explicit 1 counts - 'true' is somebody guessing at the interface")
    assert M.gate({M.ACK_ENV: "1"})[0] is True


def test_identifiers_need_their_own_second_flag():
    assert M.gate({M.ACK_ENV: "1"}) == (True, False)
    assert M.gate({M.ACK_ENV: "1", M.IDENTIFIERS_ENV: "1"}) == (True, True)


def test_main_exits_nonzero_and_writes_the_refusal_to_stderr(monkeypatch, capsys):
    """stderr, not stdout: the spec says the server MUST NOT write anything to stdout
    that is not a valid MCP message, and a refusal banner on stdout would corrupt the
    stream of any client that launched it."""
    monkeypatch.delenv(M.ACK_ENV, raising=False)
    rc = M.main([])
    cap = capsys.readouterr()
    assert rc != 0
    assert cap.out == "", "nothing may reach stdout"
    assert M.ACK_ENV in cap.err
    assert "OUTSIDE the OverWatch boundary" in cap.err


def test_the_refusal_explains_the_local_model_path():
    """A gate that only says no pushes people to route around it."""
    assert "local model" in M.REFUSAL.lower()
    assert "docs/MCP.md" in M.REFUSAL
    assert M.IDENTIFIERS_ENV in M.REFUSAL


# ── D6: redaction by default ────────────────────────────────────────────────
def test_identifiers_are_redacted_by_default(report):
    out = payload(call(server(report), "overwatch_findings"))
    blob = json.dumps(out)
    assert ACCOUNT not in blob, "an account id reached the client"
    assert "prod-customer-pii" not in blob, "a bucket name reached the client"
    assert "203.0.113.7" not in blob, "an IP reached the client"
    assert "AdminRole" not in blob


def test_the_analysis_survives_redaction(report):
    """Redaction has to leave something useful behind, or operators will simply turn it
    off - which would make it worse than not having it."""
    out = payload(call(server(report), "overwatch_findings"))
    blob = json.dumps(out)
    assert "is public" in blob
    assert "AdministratorAccess" in blob
    assert "S3-01" in blob and "CRITICAL" in blob


def test_pseudonyms_are_stable_within_a_session(report):
    """An analyst must be able to say "that same bucket again" across two answers."""
    srv = server(report)
    a = json.dumps(payload(call(srv, "overwatch_findings")))
    b = json.dumps(payload(call(srv, "overwatch_attack_paths")))
    import re
    tok = re.findall(r"\bs3-[0-9a-f]{6}\b", a)
    assert tok, f"no pseudonym minted: {a[:200]}"
    assert tok[0] in b, "the same resource got two different pseudonyms"


def test_pseudonyms_do_not_link_two_sessions(report):
    """Process-scoped salt. The transcripts end up somewhere we do not control, so two
    of them should not be joinable on our pseudonyms."""
    import re
    one = re.findall(r"\bs3-[0-9a-f]{6}\b",
                     json.dumps(payload(call(server(report), "overwatch_findings"))))
    two = re.findall(r"\bs3-[0-9a-f]{6}\b",
                     json.dumps(payload(call(server(report), "overwatch_findings"))))
    assert one and two, "no pseudonyms minted in one of the sessions"
    assert one != two, "two sessions minted the same pseudonym; the salt is not per-process"


def test_full_identifiers_when_explicitly_enabled(report):
    out = payload(call(server(report, identifiers=True), "overwatch_findings"))
    blob = json.dumps(out)
    assert ACCOUNT in blob and "prod-customer-pii" in blob


def test_redaction_covers_dict_keys_too():
    """Report payloads are keyed by ARN in places. Cleaning values and leaving keys is
    the kind of partial control that reads as protection and is not."""
    r = M.Redactor(enabled=True)
    out = r.walk({BUCKET_ARN: {"nested": ACCOUNT}})
    blob = json.dumps(out)
    assert "prod-customer-pii" not in blob and ACCOUNT not in blob


def test_reference_material_is_not_redacted(report):
    """OverWatch's own remediation text carries example ARNs. Redacting them would
    mangle the commands an operator is meant to copy, and there is no customer data in
    it to protect."""
    out = payload(call(server(report), "overwatch_check_reference",
                       check_id="AIGRD-03"))
    assert "not mandatory" in json.dumps(out)


# ── D6: the audit trail ─────────────────────────────────────────────────────
def test_every_tool_call_is_audited(report, tmp_path):
    log = tmp_path / "audit" / "mcp.jsonl"
    srv = server(report, audit=str(log))
    call(srv, "overwatch_findings", severity="CRITICAL")
    call(srv, "overwatch_coverage")
    rows = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
    assert [r["tool"] for r in rows] == ["overwatch_findings", "overwatch_coverage"]
    assert rows[0]["arguments"] == {"severity": "CRITICAL"}
    assert rows[0]["identifiers_served"] is False
    assert rows[0]["sha256"] and rows[0]["bytes"] > 0


def test_the_audit_records_whether_identifiers_were_served(report, tmp_path):
    log = tmp_path / "mcp.jsonl"
    call(server(report, identifiers=True, audit=str(log)), "overwatch_findings")
    row = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert row["identifiers_served"] is True


def test_the_audit_does_not_store_a_second_copy_of_the_findings(report, tmp_path):
    """A digest and counts, not the content. Duplicating the customer's findings on
    disk to prove we served them would be its own small data problem."""
    log = tmp_path / "mcp.jsonl"
    call(server(report, identifiers=True, audit=str(log)), "overwatch_findings")
    text = log.read_text(encoding="utf-8")
    assert "AdministratorAccess" not in text
    assert "prod-customer-pii" not in text


def test_an_unwritable_audit_path_does_not_break_serving(report, tmp_path):
    bad = tmp_path / "file.txt"
    bad.write_text("x", encoding="utf-8")
    srv = server(report, audit=str(bad / "nested" / "mcp.jsonl"))
    assert payload(call(srv, "overwatch_coverage"))["complete"] is False


# ── the protocol ────────────────────────────────────────────────────────────
def test_initialize_echoes_a_supported_version(report):
    out = server(report).handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                 "params": {"protocolVersion": "2025-03-26"}})
    assert out["result"]["protocolVersion"] == "2025-03-26"


def test_an_unsupported_version_is_answered_with_ours_not_an_error(report):
    """The spec: respond with another version we support and let the client decide,
    rather than refusing the handshake."""
    out = server(report).handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                 "params": {"protocolVersion": "1.0.0"}})
    assert "error" not in out
    assert out["result"]["protocolVersion"] == M.PROTOCOL_VERSION


def test_initialize_instructions_state_the_boundary_and_the_redaction(report):
    out = server(report).handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                 "params": {}})
    ins = out["result"]["instructions"]
    assert "leaves the OverWatch boundary" in ins
    assert "REDACTED" in ins
    assert "overwatch_coverage" in ins, (
        "the model should be told to check coverage before calling anything clean")


def test_instructions_say_so_when_identifiers_are_served(report):
    out = server(report, identifiers=True).handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert "FULL" in out["result"]["instructions"]


def test_notifications_get_no_response(report):
    assert server(report).handle({"jsonrpc": "2.0",
                                  "method": "notifications/initialized"}) is None


def test_an_unknown_tool_is_a_protocol_error(report):
    out = call(server(report), "overwatch_delete_everything")
    assert out["error"]["code"] == -32602


def test_a_failure_inside_a_known_tool_is_a_result_with_iserror(report):
    """So the model can read the reason and react, rather than the client seeing a
    transport failure."""
    out = call(server(report), "overwatch_check_reference", check_id="NOPE-99")
    assert "error" not in out
    assert out["result"]["isError"] is True


def test_an_unknown_method_is_a_method_not_found(report):
    out = server(report).handle({"jsonrpc": "2.0", "id": 9, "method": "resources/read"})
    assert out["error"]["code"] == -32601


def test_every_tool_advertised_has_a_handler(report):
    assert {t["name"] for t in M.TOOLS} == set(M.HANDLERS)


def test_every_tool_description_carries_the_egress_warning():
    """Belt and braces on the gate. The check_reference tool is exempt: it serves no
    customer data, and a warning there would be noise that trains readers to skip it."""
    for t in M.TOOLS:
        if t["name"] == "overwatch_check_reference":
            continue
        assert "leave the OverWatch boundary" in t["description"], t["name"]


def test_the_stdio_loop_writes_one_line_per_message(report):
    """The spec: messages are delimited by newlines and MUST NOT contain embedded
    newlines. Pretty-printing a response would break every client."""
    inp = io.StringIO(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {}}) + "\n" +
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n" +
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n")
    out = io.StringIO()
    server(report).serve(stdin=inp, stdout=out)
    lines = [x for x in out.getvalue().split("\n") if x]
    assert len(lines) == 2, "the notification must not produce a response"
    for line in lines:
        json.loads(line)                      # each line is a complete message


def test_malformed_input_does_not_kill_the_session(report):
    inp = io.StringIO("not json\n" +
                      json.dumps({"jsonrpc": "2.0", "id": 2,
                                  "method": "tools/list"}) + "\n")
    out = io.StringIO()
    server(report).serve(stdin=inp, stdout=out)
    lines = [json.loads(x) for x in out.getvalue().split("\n") if x]
    assert lines[0]["error"]["code"] == -32700
    assert "tools" in lines[1]["result"], "the session continued after a parse error"


# ── read-only, and honest about coverage ────────────────────────────────────
def test_a_missing_report_is_an_iserror_not_a_crash(tmp_path):
    srv = server(M.Report(str(tmp_path / "nope.json")))
    out = call(srv, "overwatch_findings")
    assert out["result"]["isError"] is True
    assert "Run a scan first" in json.dumps(out)


def test_coverage_tells_the_model_what_was_not_evaluated(report):
    out = payload(call(server(report), "overwatch_coverage"))
    assert out["complete"] is False
    assert "AIGRD-01" in out["not_evaluated"]
    assert "not evidence" in out["note"]


def test_findings_filter_and_cap(report):
    assert payload(call(server(report), "overwatch_findings",
                        severity="CRITICAL"))["count"] == 1
    assert payload(call(server(report), "overwatch_findings",
                        status="PASS"))["count"] == 1
    assert payload(call(server(report), "overwatch_findings",
                        limit=1))["returned"] == 1


def test_prompts_are_offered_and_fill_their_arguments(report):
    srv = server(report)
    assert srv.handle({"jsonrpc": "2.0", "id": 1,
                       "method": "prompts/list"})["result"]["prompts"]
    out = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "prompts/get",
                      "params": {"name": "explain_a_check",
                                 "arguments": {"check_id": "AIGRD-03"}}})
    assert "AIGRD-03" in out["result"]["messages"][0]["content"]["text"]


def test_an_unfilled_prompt_placeholder_does_not_leak_braces(report):
    out = server(report).handle({"jsonrpc": "2.0", "id": 2, "method": "prompts/get",
                                 "params": {"name": "audit_readiness"}})
    assert "{framework}" not in out["result"]["messages"][0]["content"]["text"]


# ── the documentation is part of the interface ──────────────────────────────
def _docs():
    import pathlib
    return (pathlib.Path(__file__).resolve().parent.parent
            / "docs" / "MCP.md").read_text(encoding="utf-8")


def test_the_docs_name_the_real_environment_variables():
    """These are what an operator exports. If a rename lands and the doc keeps the old
    name, the product is simply unusable and nothing else in the suite notices."""
    doc = _docs()
    for const in (M.ACK_ENV, M.IDENTIFIERS_ENV, M.REPORT_ENV, M.AUDIT_ENV):
        assert const in doc, f"docs/MCP.md never mentions {const}"
    assert M.DEFAULT_AUDIT.replace(os.sep, "/") in doc


def test_the_documented_scanner_flags_exist():
    """Written after documenting `--profile full --json-out`, neither of which exists.
    The real flag is `--json FILE`. A quickstart whose first command fails is worse than
    no quickstart, and this is a recurring way for prose to drift from the CLI."""
    import ast
    import pathlib
    import re
    # Read the flags out of the SOURCE rather than importing and introspecting. The
    # scanner builds its parser inline inside main(), and the first draft of this test
    # skipped itself when it could not find a build_arg_parser() to call -- a guard that
    # skips is decoration, which is how the wrong flags got documented in the first place.
    src = pathlib.Path(
        module_path("aws_live_scanner.py")).read_text(encoding="utf-8")
    known = set()
    for node in ast.walk(ast.parse(src)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"):
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str) \
                        and a.value.startswith("-"):
                    known.add(a.value)
    assert "--json" in known, "flag extraction failed; the guard would pass vacuously"
    # Matches both the historical `aws_live_scanner.py --flag` and the
    # current `python -m engine.aws_live_scanner --flag`. The invocation
    # changed when the flat root became engine/ + hub/ + store/; the FLAGS
    # did not, and the flags are what this guard is about. The `assert used`
    # below is what caught the doc rewrite -- without it this would have
    # quietly checked nothing and still passed.
    used = set(re.findall(
        r"aws_live_scanner(?:\.py)?[^\n`]*?(--[a-z][a-z0-9-]*)", _docs()))
    assert used, "no scanner command found in docs/MCP.md to check"
    missing = used - known
    assert not missing, f"docs/MCP.md uses flags the scanner does not define: {missing}"
