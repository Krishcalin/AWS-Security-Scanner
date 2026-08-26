"""The declared IAM surface: is it current, and is it real?

Two guards over the same thing — the set of permissions OverWatch asks a customer to
grant — each closing a failure this codebase actually hit.

**Is it current?** The pinned missing-action and blocked-check lists are now generated
into `perm_ledger_baseline.py`. Generation alone would be worthless if nobody
regenerated, so the baseline is compared against a live evaluation: add a check and this
fails until somebody runs `--update`, which lands the change in the diff where a reviewer
sees it. That is the `test_suite_ratchet` bargain, and it is deliberately not a
self-deriving assertion — computing the expectation at test time would make it
tautological and delete the thing it protects.

**Is it real?** Three times now a boto3 *client name* has been mistaken for an IAM
*prefix*: `bedrock-agentcore-control` vs `bedrock-agentcore`, `sso-admin` vs `sso`, and
`amp` vs `aps`. Each would have produced a policy that grants nothing while reading
correctly in review, and each was caught by hand. botocore already knows the answer —
`metadata.signingName`, falling back to `endpointPrefix` — so the fourth one gets caught
by a test instead.
"""
from __future__ import annotations

import glob
import gzip
import io
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aws_checkdef as C
import aws_perm_ledger as L
import perm_ledger_baseline as B

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── is the baseline current? ────────────────────────────────────────────────
def test_the_committed_baseline_matches_a_live_evaluation():
    """Add a check that needs a new grant and this fails until `--update` is run.

    The friction is the point: the permission surface is what a customer approves, so it
    must not widen without somebody deciding it should."""
    live = B.compute()
    assert live == B.BASELINE, (
        "the permission-ledger baseline is stale. Run "
        "`python tests/perm_ledger_baseline.py --update` and review the diff — a widened "
        "permission surface is a decision, not a side effect.")


@pytest.mark.parametrize("fixture", sorted(B.BASELINE))
def test_every_baselined_fixture_carries_all_three_facts(fixture):
    d = B.BASELINE[fixture]
    assert d["missing_actions"] and isinstance(d["missing_actions"], list)
    assert isinstance(d["blocked_checks"], list)
    assert isinstance(d["annotated_policy_rows"], int)


@pytest.mark.parametrize("fixture", sorted(B.BASELINE))
def test_the_baseline_lists_are_sorted(fixture):
    """Sorted so a diff shows what changed rather than where it moved."""
    d = B.BASELINE[fixture]
    assert d["missing_actions"] == sorted(d["missing_actions"])
    assert d["blocked_checks"] == sorted(d["blocked_checks"])


def test_regenerating_the_baseline_is_idempotent():
    """The suite ratchet's own `--update` once corrupted its file with an off-by-two
    slice, so this one is checked rather than assumed."""
    path = os.path.join(ROOT, "tests", "perm_ledger_baseline.py")
    before = io.open(path, encoding="utf-8").read()
    try:
        subprocess.run([sys.executable, path, "--update"], cwd=ROOT,
                       capture_output=True, check=True)
        once = io.open(path, encoding="utf-8").read()
        subprocess.run([sys.executable, path, "--update"], cwd=ROOT,
                       capture_output=True, check=True)
        twice = io.open(path, encoding="utf-8").read()
        assert once == twice, "--update is not idempotent"
        assert once == before, "the committed baseline is not what --update produces"
    finally:
        io.open(path, "w", encoding="utf-8", newline="").write(before)


def test_the_two_suites_no_longer_hand_type_the_lists():
    """The whole point of the exercise. Three regex attempts at maintaining these
    literals produced three different corruptions; the lists are data now."""
    for name in ("test_perm_ledger.py", "test_perm_ledger_wiring.py"):
        src = io.open(os.path.join(ROOT, "tests", name), encoding="utf-8").read()
        assert "perm_ledger_baseline import BASELINE" in src, name
        assert '"aoss:BatchGetCollection"' not in src, (
            f"{name} still hand-types the pinned action list")


def test_no_test_name_states_a_count_that_can_go_stale():
    """`..._is_missing_exactly_thirtytwo_actions` was renamed to thirtyfour, then
    fiftyone, then eightytwo. A name that states a number is a durable lie waiting to
    happen, so the number lives in the baseline instead."""
    import re
    for name in ("test_perm_ledger.py", "test_perm_ledger_wiring.py"):
        src = io.open(os.path.join(ROOT, "tests", name), encoding="utf-8").read()
        bad = re.findall(r"def (test_\w*(?:exactly|precisely)_\w*)\(", src)
        assert not bad, f"{name}: test name states a count: {bad}"


# ── is the surface real? ────────────────────────────────────────────────────
def _botocore_iam_prefixes() -> dict:
    """Every IAM prefix botocore knows about -> the client dirs that use it.

    `signingName` WINS where present, and `endpointPrefix` is only a fallback for the
    services that omit it (EMR's client dir is `emr`, its IAM prefix is
    `elasticmapreduce`, and only endpointPrefix says so).

    Taking both would defeat the guard: `amp` and `bedrock-agentcore-control` are their
    own endpointPrefix, so admitting endpointPrefix unconditionally would accept exactly
    the wrong spellings this test exists to reject."""
    import botocore
    base = os.path.join(os.path.dirname(botocore.__file__), "data")
    out: dict = {}
    for svc in sorted(os.listdir(base)):
        d = os.path.join(base, svc)
        if not os.path.isdir(d):
            continue
        try:
            versions = sorted(v for v in os.listdir(d)
                              if os.path.isdir(os.path.join(d, v)))
            f = glob.glob(os.path.join(d, versions[-1], "service-2.json*"))[0]
            op = gzip.open if f.endswith(".gz") else open
            with op(f, "rt", encoding="utf-8") as fh:
                meta = json.load(fh)["metadata"]
        except Exception:
            continue
        prefix = meta.get("signingName") or meta.get("endpointPrefix")
        if prefix:
            out.setdefault(prefix, set()).add(svc)
    return out


PREFIXES = _botocore_iam_prefixes()


def _declared_actions() -> set:
    acts = {r.action for reqs in L.REQUIREMENTS.values() for r in reqs}
    acts |= {p.action for d in C.REGISTRY.values() for p in d.permissions}
    return acts


def test_botocore_yields_a_usable_prefix_table():
    assert len(PREFIXES) > 300
    # the three traps this test exists for
    assert "aps" in PREFIXES and "sso" in PREFIXES
    assert "bedrock-agentcore" in PREFIXES
    assert "elasticmapreduce" in PREFIXES


@pytest.mark.parametrize("action", sorted(_declared_actions()))
def test_every_declared_action_uses_a_real_iam_prefix(action):
    """A client name in place of an IAM prefix grants nothing and looks correct."""
    prefix = action.split(":", 1)[0]
    assert prefix in PREFIXES, (
        f"{action}: '{prefix}' is not an IAM prefix botocore knows. If it is a boto3 "
        f"CLIENT name, the IAM prefix is that service's signingName — a policy written "
        f"with the client name grants nothing while reading correctly in review.")


@pytest.mark.parametrize("client,iam", [
    ("amp", "aps"),
    ("sso-admin", "sso"),
    ("bedrock-agentcore-control", "bedrock-agentcore"),
    ("emr", "elasticmapreduce"),
])
def test_the_known_client_name_traps_resolve_the_way_we_declared_them(client, iam):
    """Pinned so the table keeps answering the questions it was built for."""
    assert iam in PREFIXES
    assert client in PREFIXES.get(iam, set()), (
        f"botocore no longer maps client {client!r} to IAM prefix {iam!r}")


@pytest.mark.parametrize("wrong", ["sso-admin", "amp", "bedrock-agentcore-control"])
def test_the_client_names_themselves_are_not_valid_iam_prefixes(wrong):
    """The negative half: if these ever became valid prefixes the test above would stop
    catching anything, because the wrong spelling would pass."""
    assert wrong not in PREFIXES, (
        f"{wrong} resolves as an IAM prefix, so the guard above would accept the wrong "
        f"spelling. signingName must win over endpointPrefix in the prefix table.")


def test_no_declared_action_names_a_write_verb():
    """The charter, re-asserted over the LEDGER as well as the registry -- aws_checkdef
    enforces it for new declarations, but the legacy REQUIREMENTS literals predate it."""
    reads = ("Describe", "Get", "List", "BatchGet", "Lookup", "Select", "Search",
             "Simulate")
    bad = sorted(a for a in _declared_actions()
                 if not a.split(":", 1)[1].startswith(reads))
    assert not bad, f"non-read actions declared: {bad}"
