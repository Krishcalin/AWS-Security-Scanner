"""D11-D13, enforced rather than merely recorded.

WHY A SEPARATE FILE
-------------------
`test_decisions.py` guards D1-D7. These three arrived with the Phase II SRS
(OW2-SRS-001) and each was answered in a way that only means something if
something checks it:

  D11  auto-fix: governance BUILT, execution WITHHELD
  D12  the egress allowlist does not grow for SIEM forwarding
  D13  inbound connectors are vendor-neutral

A decision recorded without a guard is a decision that gets reversed by a commit
whose author never read the record. That is the failure mode the whole DECISIONS
log exists to prevent, so an entry that says "Enforced by" had better be true.

WHAT WAS ALREADY COVERED, AND WHAT WAS NOT
-------------------------------------------
D4 already asserts the permission LEDGER is read-shaped, and the CFN test already
asserts the scanner role carries SecurityAudit + ViewOnlyAccess and NOT
ReadOnlyAccess. Between them they cover what OverWatch *asks for*.

Neither covered what the code *calls*, and nothing at all pinned the egress
allowlist itself: `EGRESS_ALLOWLIST` was a plain set in a test file, so a fourth
entry could be added and every test would still pass. That is the gap these fill.
"""
from __future__ import annotations

import ast
import io
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DECISIONS = os.path.join(ROOT, "docs", "DECISIONS.md")


def _src(path: str) -> str:
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


#: Below this, assume the walk is broken rather than that the codebase shrank.
#: Currently ~108 modules match; the floor only has to be high enough that an
#: EMPTY or nearly-empty root cannot slip past. Lower it deliberately, in a
#: commit that says why, if the module count ever genuinely falls.
_MIN_MODULES = 50


def _modules():
    """Every root aws_/cnapp_ module, as (name, source).

    Returns a LIST, not a generator, and refuses to be empty. Its callers collect
    offenders and assert the offender list is empty -- so a walk that yields
    nothing asserts empty against empty and PASSES, reporting a control that
    never ran. That is the failure this whole codebase exists to refuse, and it
    would be reached by something as ordinary as moving these modules into a
    subdirectory: os.listdir does not recurse.
    """
    found = [(name, _src(os.path.join(ROOT, name)))
             for name in sorted(os.listdir(ROOT))
             if name.endswith(".py") and (name.startswith("aws_")
                                          or name.startswith("cnapp_"))]
    assert len(found) >= _MIN_MODULES, (
        "only %d aws_/cnapp_ modules found in %s -- the walk is broken, so every "
        "check built on it would pass without inspecting anything. If the modules "
        "moved, point ROOT at their new home; os.listdir does not recurse."
        % (len(found), ROOT))
    return found


# ── the record itself ───────────────────────────────────────────────────────

@pytest.mark.parametrize("d", ["D11", "D12", "D13"])
def test_each_new_decision_has_an_entry_with_a_verdict(d):
    doc = _src(DECISIONS)
    m = re.search(rf"^## {d} .*$", doc, re.M)
    assert m, f"{d} has no entry in DECISIONS.md"
    head = m.group(0)
    assert "—" in head and head.rstrip().split("—")[-1].strip(), (
        f"{d}'s heading carries no verdict: {head}")


@pytest.mark.parametrize("d", ["D11", "D12", "D13"])
def test_each_new_decision_appears_in_the_status_table(d):
    table = _src(DECISIONS).split("## Status at a glance")[1].split("\n\n")[1]
    assert f"**{d}**" in table, f"{d} is written up but missing from the table"


# ── D11 · governance built, execution withheld ──────────────────────────────

#: boto3 verbs that change something in an AWS account.
MUTATING = (
    "create_", "delete_", "put_", "update_", "modify_", "attach_", "detach_",
    "terminate_", "stop_", "start_", "reboot_", "revoke_", "authorize_",
    "disable_", "enable_", "tag_", "untag_", "remove_", "associate_",
    "disassociate_", "restore_", "replace_", "reset_", "set_",
)

#: THE MUTATION SURFACE, frozen with a reason each.
#:
#: The first draft of this test asserted OverWatch calls no mutating AWS API at
#: all. That is FALSE, and writing D11 that way would have recorded a guarantee
#: the product does not make. The real rule is narrower and sharper:
#:
#:     OverWatch mutates only resources IT CREATED. It never mutates a customer's.
#:
#: Auto-fix would be the first time it touches a customer resource, which is
#: exactly the line D11 withholds. Shrink-only: a new entry is a decision.
MUTATION_SURFACE = {
    "aws_sidescan_ebs.py":
        "the agentless side-scan creates its OWN snapshot and volume, tagged "
        "cnapp:sidescan=<scan_id>, and tears them down. Cleanup is provenance-"
        "guarded by is_owned() so a customer's snapshot is never deleted.",
    "aws_graph_neptune_loader.py":
        "writes graph load-files to the OPERATOR's own S3 bucket and starts a "
        "Neptune loader job in the operator's own cluster. Nothing in a scanned "
        "account is touched.",
    "aws_flowlog.py":
        "logs:StartQuery / StopQuery run a CloudWatch Logs Insights READ. The "
        "verb is mutating-shaped; the operation returns data and changes nothing.",
}

#: Hub-local modules: their create_/delete_ calls are database and HTTP-session
#: operations against OverWatch's own store, not AWS. Scanning them for AWS
#: mutations is a category error, which is what the first draft made.
_HUB_LOCAL_PREFIX = "cnapp_"

#: Attribute calls that look mutating but are local data-structure operations.
LOCAL_OK = {
    "create_app_from_env", "create_app_with_local_auth", "create_engine",
    "create_task", "create_default_context", "create_connection",
    "set_defaults", "set_debuglevel", "setdefault", "update_from_dict",
    "put_nowait", "start_new_thread", "remove_option", "set_option",
    "remove_header",
}


def _mutating_calls(src: str):
    out = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            name = node.func.attr
            if name in LOCAL_OK:
                continue
            if any(name.startswith(v) for v in MUTATING):
                out.append((name, node.lineno))
    return out


def test_d11_the_mutation_surface_has_not_grown():
    """The half D4's ledger test cannot see.

    D4 asserts the permission LEDGER requests only read actions -- what we ask
    for. This asserts what the code CALLS, against a frozen registry. A new module
    reaching a mutating AWS API is D11 being reversed by a commit whose author
    never read the record.
    """
    offenders = {}
    for name, src in _modules():
        if name.startswith(_HUB_LOCAL_PREFIX) or name in MUTATION_SURFACE:
            continue
        hits = _mutating_calls(src)
        if hits:
            offenders[name] = sorted({h[0] for h in hits})
    assert not offenders, (
        "modules outside the frozen mutation surface call a mutating API: "
        + "; ".join(f"{f}: {v}" for f, v in offenders.items())
        + ". D11 answered 'governance built, execution withheld'. If this is a "
        "local operation add it to LOCAL_OK; if it mutates a CUSTOMER resource, "
        "D11 has been reversed.")


def test_d11_the_registry_has_not_gone_stale():
    live = {n for n, src in _modules()
            if not n.startswith(_HUB_LOCAL_PREFIX) and _mutating_calls(src)}
    stale = sorted(set(MUTATION_SURFACE) - live)
    assert not stale, f"MUTATION_SURFACE entries that no longer mutate: {stale}"


def test_d11_every_mutation_is_justified_in_writing():
    for mod, why in MUTATION_SURFACE.items():
        assert len(why) > 60, f"{mod} is in the mutation surface without a real reason"


def test_d11_the_side_scan_still_refuses_to_delete_what_it_did_not_create():
    """The guard that makes the narrow rule true. Without is_owned(), 'we only
    delete our own' is a comment rather than a control."""
    src = _src(os.path.join(ROOT, "aws_sidescan_ebs.py"))
    assert "def is_owned" in src, "the provenance guard is gone"
    assert "cnapp:sidescan" in src, "scanner-created resources are no longer tagged"


def test_d11_the_remediation_engine_still_only_generates():
    """aws_remediate produces Terraform/CFN/CLI text. The moment it executes any of
    it, 'OverWatch cannot alter your estate' stops being true."""
    src = _src(os.path.join(ROOT, "aws_remediate.py"))
    assert "import boto3" not in src, "the remediation engine must not reach AWS"
    assert "subprocess" not in src, "the remediation engine must not shell out"


def test_d11_no_deploy_artifact_grants_a_remediation_role():
    """'Execution withheld' means the EXECUTING ROLE IS ABSENT from what we ship.
    Governance without the role is the whole of the decision; a role that exists
    'but is disabled' is a different decision nobody made."""
    import json
    import yaml  # noqa: F401  (pyyaml is a declared dependency)
    for fname in ("cnapp-scanner-role.yaml", "cnapp-hub-role.yaml"):
        path = os.path.join(ROOT, "deploy", fname)
        if not os.path.exists(path):
            continue
        raw = _src(path)
        assert "Remediation" not in raw and "remediate" not in raw.lower(), (
            f"{fname} mentions remediation -- D11 withheld the executing role")


def test_d11_records_that_governance_is_built_and_execution_is_not():
    body = _src(DECISIONS).split("## D11")[1].split("\n## ")[0]
    assert "withheld" in body.lower() or "absent" in body.lower(), (
        "D11's entry must say the executing role is not shipped")


# ── D12 · the egress allowlist does not grow ────────────────────────────────

def test_d12_the_egress_allowlist_is_exactly_three_files():
    """THE guard D12 turns on, and it did not exist.

    `EGRESS_ALLOWLIST` was a plain set inside test_zero_telemetry: it constrained
    WHERE egress may live, and nothing constrained the set itself. A fourth entry
    could be added in the same commit as the code it excuses, and every test would
    still pass.

    OW2-CC-030 (SIEM forwarding) does not need a fourth entry: cnapp_connectors.py
    is already allowlisted and already ships a signed, SSRF-guarded webhook
    transport, a Splunk HEC renderer and a message-template override. CEF/syslog is
    a RENDERER inside that file, which is the same conclusion the registry work
    reached -- 'the allowlist does NOT grow: all registry egress stays in this one
    file.'
    """
    import tests.test_zero_telemetry as zt
    assert zt.EGRESS_ALLOWLIST == {
        "aws_kube.py", "cnapp_connectors.py", "aws_layer_fetch.py"}, (
        "the egress allowlist changed. Growing it is decision D12, not a refactor: "
        "record the reason in docs/DECISIONS.md before widening it here.")


def test_d12_the_connector_plane_can_already_carry_a_new_siem_renderer():
    """The evidence that D12 needs no widening: a renderer registry and a template
    override already exist inside the allowlisted file."""
    src = _src(os.path.join(ROOT, "cnapp_connectors.py"))
    assert "RENDERERS" in src, "no renderer registry to extend"
    assert "splunk" in src, "no existing SIEM renderer to model CEF on"


def test_d12_is_recorded_as_needing_no_widening():
    body = _src(DECISIONS).split("## D12")[1].split("\n## ")[0]
    assert "cnapp_connectors" in body, (
        "D12's entry must name the file the renderer belongs in, or the next reader "
        "will add a fourth allowlist entry")


# ── D13 · inbound connectors are vendor-neutral ─────────────────────────────

#: The ingests that already made this call, and are the precedent D13 generalises.
VENDOR_NEUTRAL_INGESTS = ("aws_ingest_aidr.py", "aws_ingest_credexp.py")


@pytest.mark.parametrize("mod", VENDOR_NEUTRAL_INGESTS)
def test_d13_the_precedent_ingests_hardcode_no_vendor_endpoint(mod):
    """Both shipped without a verifiable upstream contract by keeping field names in
    an alias map rather than in the logic. A hardcoded vendor host would mean the
    module had bound itself to one supplier after all."""
    path = os.path.join(ROOT, mod)
    if not os.path.exists(path):
        pytest.skip(f"{mod} not present")
    src = _src(path)
    hosts = re.findall(r"https?://[a-zA-Z0-9.-]+", src)
    real = [h for h in hosts if "example" not in h and "localhost" not in h]
    assert not real, f"{mod} hardcodes a vendor endpoint: {real}"


@pytest.mark.parametrize("mod", VENDOR_NEUTRAL_INGESTS)
def test_d13_the_precedent_ingests_make_no_network_call(mod):
    path = os.path.join(ROOT, mod)
    if not os.path.exists(path):
        pytest.skip(f"{mod} not present")
    src = _src(path)
    for primitive in ("urllib.request", "http.client", "import socket", "requests."):
        assert primitive not in src, (
            f"{mod} performs its own egress; D13 keeps ingest offline and leaves "
            "the fetching to the operator or the connector plane")


def test_d13_names_the_precedent_rather_than_asserting_a_principle():
    body = _src(DECISIONS).split("## D13")[1].split("\n## ")[0]
    assert "aws_ingest_credexp" in body or "aws_ingest_aidr" in body, (
        "D13's entry should name the modules that already work this way -- a "
        "principle with a precedent is followed; one without is re-argued")
