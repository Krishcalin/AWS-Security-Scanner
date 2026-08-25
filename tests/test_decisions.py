"""The product decisions in docs/DECISIONS.md, enforced.

A decision recorded only in prose gets contradicted by code nobody checked against it.
These tests are the difference between "we decided not to do that" and "we haven't done
that yet" — which is exactly the distinction a sovereign buyer's security review is
probing when it asks.

Only the decisions with a testable consequence appear here:

  D2  no prompt or completion CONTENT enters the product  (Section F does the work;
      this asserts the guard the decision cites still exists)
  D4  no active adversarial probing of a customer's models, agents or guardrails
  D7  no dependency on the sibling Guardrail product

D1 and D6 are enforced by their own slices' suites (test_perm_ledger.py, test_mcp.py),
and D3 by test_cbom.py. D3 was first recorded here as deferred and then overruled — build
it — so what remains in this file for it is the BOUND rather than the deferral: that the
reversal covers cryptography only, that the CBOM emits no findings, and that it added no
API call or permission, which is the basis the slice was approved on.
"""
from __future__ import annotations

import ast
import glob
import os
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DECISIONS = ROOT / "docs" / "DECISIONS.md"
_EXCLUDE = {".git", "node_modules", "frontend", "venv", ".venv", "__pycache__",
            "build", "dist", "htmlcov"}


def _app_modules():
    out = []
    for f in glob.glob(str(ROOT / "**" / "*.py"), recursive=True):
        rel = os.path.relpath(f, ROOT)
        if rel.split(os.sep)[0] in _EXCLUDE:
            continue
        out.append(f)
    return sorted(out)


def _src(path):
    return open(path, encoding="utf-8").read()


# ── the record itself ───────────────────────────────────────────────────────
def test_every_open_decision_has_a_recorded_answer():
    """The roadmap names six. A decision missing from the record is one that will be
    re-litigated in a meeting, or worse, answered accidentally by a commit."""
    doc = _src(DECISIONS)
    for d in ("D1", "D2", "D3", "D4", "D6", "D7"):
        assert re.search(rf"^## {d} ", doc, re.M), f"{d} has no entry in DECISIONS.md"
    assert "There is no D5" in doc, (
        "the roadmap skips D5; say so, or the next reader hunts for it")


def test_each_decision_states_an_answer_not_a_discussion():
    doc = _src(DECISIONS)
    for d in ("D1", "D2", "D3", "D4", "D6", "D7"):
        head = re.search(rf"^## {d} .*$", doc, re.M).group(0)
        assert "—" in head and head.rstrip().split("—")[-1].strip(), (
            f"{d}'s heading carries no verdict: {head}")


# ── D2: no prompt or completion content ─────────────────────────────────────
def test_d2_the_guard_it_cites_still_exists():
    """DECISIONS.md points at Section F. If Section F is deleted or renamed, the
    decision record becomes a claim with nothing behind it — which is worse than no
    record, because it reads as assurance."""
    tel = _src(ROOT / "tests" / "test_zero_telemetry.py")
    assert "F1. the ingest plane never reads model conversation content" in tel
    assert "def test_no_ingest_module_reads_model_conversation_content" in tel
    assert "def test_f1_rejects_the_poisoned_fixture" in tel, (
        "the tripwire must be proven to fire, or it is decoration")


# ── D4: never cross read-only into active probing ───────────────────────────
#: Method calls that would mean OverWatch invoked a model, agent or guardrail rather
#: than reading its configuration. Names, not substrings: `aws_aiguard` holds
#: "bedrock:invokemodel" as a STRING because it analyses policy text, and `aws_airules`
#: matches "InvokeModel" as a CloudTrail EVENT NAME. Neither is a call, and a grep
#: cannot tell the difference — an AST walk can.
_PROBING_CALLS = {
    "invoke_model", "invoke_model_with_response_stream",
    "invoke_agent", "invoke_inline_agent", "invoke_flow",
    "converse", "converse_stream",
    "apply_guardrail", "retrieve_and_generate",
    "invoke_endpoint", "invoke_endpoint_async",
    "invoke_agent_runtime",
}


def test_d4_no_module_invokes_a_model_agent_or_guardrail():
    """The written answer to "do you red-team?" is no, and this is what makes it a fact
    rather than a position. Adversarial probing spends the customer's inference budget
    and produces, in their own CloudTrail, the exact signature AITHR-01 exists to alarm
    on — we would be generating the events our own detection hunts."""
    offenders = []
    for f in _app_modules():
        if os.path.basename(f).startswith("test_"):
            continue
        try:
            tree = ast.parse(_src(f), f)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in _PROBING_CALLS:
                offenders.append(f"{os.path.relpath(f, ROOT)}:{node.lineno} "
                                 f"-> .{node.func.attr}()")
    assert not offenders, (
        "OverWatch invokes a model/agent/guardrail, crossing the read-only-of-CONFIG "
        f"charter and contradicting D4: {offenders}")


def test_d4_the_ast_check_would_actually_catch_a_call():
    """The control for the test above. An AST walk that matched nothing would pass on an
    empty codebase just as happily as on a clean one."""
    tree = ast.parse("client.invoke_model(modelId='x', body=b'')")
    hits = [n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr in _PROBING_CALLS]
    assert hits, "the detector does not detect"


def test_d4_string_constants_are_not_mistaken_for_calls():
    """aws_aiguard names these actions to reason about POLICY TEXT, and aws_airules
    matches them as CloudTrail event names. A substring check would flag both and force
    someone to weaken the guard to get a green suite."""
    tree = ast.parse('ACTIONS = ("bedrock:invokemodel", "bedrock:converse")\n'
                     'if ev == "InvokeModel": pass')
    hits = [n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr in _PROBING_CALLS]
    assert not hits


def test_d4_every_permission_we_request_is_read_shaped():
    """The other half of the same promise. A ledger entry for a mutating action would be
    the first step across the line, and it would arrive in a policy document rather than
    in code."""
    import aws_perm_ledger as L
    verbs = ("Get", "List", "Describe", "BatchGet", "Simulate", "Lookup", "Search")
    bad = sorted({r.action for reqs in L.REQUIREMENTS.values() for r in reqs
                  if ":" in r.action
                  and not r.action.split(":", 1)[1].startswith(verbs)})
    assert not bad, f"the permission ledger requests non-read actions: {bad}"


def test_d4_is_recorded_as_scope_not_merely_as_an_answer():
    """"We answered no" and "that is out of scope" are different artifacts. The first is
    a position; the second lets a buyer plan, and is the honest form when the truthful
    version is that we will never build it."""
    doc = _src(DECISIONS)
    assert "## Declared non-goals" in doc
    assert "Out of scope" in doc.split("| **D4**")[1].split("|")[2]


def test_d4_covers_the_agentic_form_and_not_only_endpoint_probing():
    """The first draft of this record named endpoint probing alone, which answers the
    easier half. Agentic red teaming — driving the customer's OWN tool-executing agent —
    causes real WRITES by construction: the agent under test does not know the
    instruction is a drill, and neither does whatever it writes to. The roadmap calls it
    the highest-consequence item on its skip list, and an entry that omits it would let
    somebody build it while believing D4 permitted it."""
    body = _src(DECISIONS).split("## Declared non-goals")[1].split("### Also out of")[0]
    assert "Agentic red teaming" in body
    assert "writes" in body.lower()
    assert "not behind a flag" in body.lower(), (
        "a flag would make it a supported capability with a support burden and an "
        "incident path; the record has to close that door explicitly")


def test_d4_states_what_we_offer_instead():
    """A non-goal that only says no reads as a gap. The alternative is the reason this
    is a stronger answer than the capability would have been."""
    # Whitespace-collapsed: the doc is hard-wrapped, so "pen-test ingest" legitimately
    # spans a line break. A test that fails on where a paragraph wrapped is testing the
    # formatter, not the content, and the temptation on seeing it red is to reflow the
    # prose to satisfy it.
    body = re.sub(r"\s+", " ", _src(DECISIONS).split("## Declared non-goals")[1]).lower()
    for alt in ("toxic flow", "exploitability", "pen-test ingest"):
        assert alt in body, f"the scope statement never names {alt}"


def test_the_non_goals_do_not_silently_rule_on_the_rest_of_the_skip_list():
    """The roadmap recommends declining several further items. Promoting a
    recommendation to a ruling nobody made is how a scope document stops being worth
    reading, so those are referenced and explicitly NOT recorded as decided."""
    body = _src(DECISIONS).split("## Declared non-goals")[1]
    assert "not** recorded as decisions here" in body or            "not recorded as decisions here" in body
    assert "AI_CNAPP_ROADMAP.md" in body


# ── D7: no dependency on the sibling Guardrail ──────────────────────────────
_SIBLING_MARKERS = ("ai_runtime_guardrail", "ai-runtime-guardrail",
                    "prompt_firewall", "prompt-firewall")


def test_d7_nothing_depends_on_the_sibling_product():
    """Measured, not assumed: 11 commits, no Dockerfile, no console entry point, no
    release workflow. A promising prototype is not something another product's roadmap
    can be made contingent on."""
    offenders = []
    for f in _app_modules():
        if os.path.relpath(f, ROOT).startswith("tests" + os.sep):
            continue
        low = _src(f).lower()
        for m in _SIBLING_MARKERS:
            if m in low:
                offenders.append(f"{os.path.relpath(f, ROOT)} -> {m}")
    assert not offenders, (
        f"OverWatch references the sibling Guardrail product: {offenders}. D7 says it "
        f"may only ever be an OPTIONAL detection source behind the connector plane, "
        f"never a prerequisite.")


def test_d7_the_ai_detection_story_stands_alone():
    """The reason D7 costs nothing: the detections it might have depended on derive from
    CloudTrail, which every account already has."""
    import ast as _ast
    src = _src(ROOT / "aws_airules.py")
    imported = set()
    for node in _ast.walk(_ast.parse(src)):
        if isinstance(node, _ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, _ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    external = {m for m in imported if m.startswith("aws_")} - {"aws_cdr",
                                                                "aws_deepplane"}
    assert not external, (
        f"the LLMjacking rule pack grew a dependency beyond CloudTrail-derived "
        f"sources: {external}")


# ── D3 is deliberately unenforced, and says why ─────────────────────────────
def test_d3_is_recorded_as_built_and_bounded():
    """D3 was first recorded as deferred and then overruled: build it. What the record
    must still carry is the BOUND — reversing the xBOM skip for cryptography is not
    reversing it for AIBOM/HBOM/QBOM, and an entry that omits that reopens the whole
    question every time someone reads it."""
    doc = _src(DECISIONS)
    body = doc.split("## D3")[1].split("## D4")[0]
    assert "BUILT" in body
    assert "AIBOM" in body and "stay skipped" in body
    assert "inventory, not a verdict" in body, (
        "the record must say the CBOM emits no findings, or someone will add one")


def test_d3_added_no_api_call_and_no_permission():
    """The decision was approved on the basis that the material is already read. If a
    future edit adds a dedicated fetch or an IAM action for the CBOM, the justification
    for the slice no longer holds and this is where that surfaces."""
    import aws_perm_ledger as L
    acts = {r.action for reqs in L.REQUIREMENTS.values() for r in reqs}
    assert not any("cbom" in a.lower() for a in acts)
    src = _src(ROOT / "aws_cbom.py")
    assert "boto3" not in src.replace("no boto3", "")
