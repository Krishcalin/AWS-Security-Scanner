"""No silent caps: a truncated list must say that it is truncated.

THE DEFECT THIS CLOSES
-----------------------
`cnapp_service` rendered eleven lists under an integer cap. Some carried a sibling
`count` that made the true total recoverable; none DECLARED the truncation, and one
pair carried no total at all:

    "attack_paths": p.get("attack_paths", [])[:10],
    "choke_points": p.get("choke_points", [])[:10],
    # What this scan did NOT establish, travelling with the number it did.
    # A grade rendered without it is a grade whose denominator is unknown.
    "coverage": p.get("coverage"),

The principle was written down three lines below a cap that broke it. Ten attack
paths could be ten of ten or ten of four hundred, and the payload could not tell
the difference.

WHY THE RATCHET IS THE POINT
-----------------------------
Converting the eleven sites is a one-off. The durable half is
`test_no_new_silent_cap_has_been_added`, which walks the AST and asserts that the
ONLY integer-bounded slices left are the three registered below, each with a
reason. A twelfth cap added next year fails this test until its author either
routes it through `capped()` or writes down why it is not a truncation.

That is the same shrink-only shape the check-map lockstep and the suite ratchet
already use, and it is what stops "no silent caps" from being a comment.
"""
from __future__ import annotations

import ast
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hub import cnapp_service as S  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: (function, cap) -> why this integer-bounded slice is NOT an undeclared
#: truncation. Shrink-only: add an entry only with a reason that survives review.
EXEMPT = {
    ("meter_scan_completed", 7):
        "iso[:7] slices a timestamp to YYYY-MM for the metering period. A string "
        "slice, not a list cap -- nothing is dropped.",
    ("preview_control_query", 100):
        "the field is literally named `sample`, and the response already carries "
        "total, truncated, accounts_scanned and accounts_total. Declared.",
    ("preview_control_query", 20):
        "a per-account bound on a preview; per_account[].count carries each "
        "account's true total alongside it. Declared.",
}

CAPPED_FILES = ("cnapp_service.py", "cnapp_api.py")


def _slices(path):
    src = io.open(os.path.join(ROOT, path), encoding="utf-8").read()
    tree = ast.parse(src)
    owner = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for n in ast.walk(fn):
                if hasattr(n, "lineno"):
                    owner.setdefault(n.lineno, fn.name)
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Slice):
            up = n.slice.upper
            if isinstance(up, ast.Constant) and isinstance(up.value, int):
                out.append((owner.get(n.lineno, "<module>"), up.value, n.lineno))
    return out


# ── the ratchet ─────────────────────────────────────────────────────────────

def test_no_new_silent_cap_has_been_added():
    found = set()
    for path in CAPPED_FILES:
        for fn, cap, line in _slices(path):
            found.add((fn, cap))
    unregistered = sorted(found - set(EXEMPT))
    assert not unregistered, (
        "%d integer-bounded slice(s) are neither routed through capped() nor "
        "registered as exempt: %s. Either use cnapp_service.capped(items, N, "
        "'field') so the response declares the cap, or add an EXEMPT entry "
        "saying why nothing is being dropped."
        % (len(unregistered), unregistered))


def test_the_exempt_registry_has_not_grown_stale():
    """An exemption for a slice that no longer exists is a rule nobody is
    following. Shrink-only cuts both ways."""
    found = {(fn, cap) for path in CAPPED_FILES for fn, cap, _ in _slices(path)}
    stale = sorted(set(EXEMPT) - found)
    assert not stale, "EXEMPT entries with no matching slice: %s" % (stale,)


def test_every_exemption_states_a_reason():
    for key, reason in EXEMPT.items():
        assert len(reason) > 40, "%s is exempt without a real reason" % (key,)


# ── the helper ──────────────────────────────────────────────────────────────

def test_capped_declares_the_total_and_the_truncation():
    assert S.capped([1, 2, 3, 4, 5], 3, "x") == {
        "x": [1, 2, 3], "x_total": 5, "x_truncated": True}


def test_an_uncapped_list_says_it_was_not_truncated():
    assert S.capped([1, 2], 5, "x") == {
        "x": [1, 2], "x_total": 2, "x_truncated": False}


def test_exactly_at_the_limit_is_not_truncated():
    out = S.capped([1, 2, 3], 3, "x")
    assert out["x_truncated"] is False and out["x_total"] == 3


def test_none_and_empty_are_not_truncated():
    for empty in (None, [], ()):
        out = S.capped(empty, 5, "x")
        assert out == {"x": [], "x_total": 0, "x_truncated": False}


def test_the_total_is_the_pre_cap_length_not_the_rendered_length():
    # The whole point: _total must survive the slice.
    out = S.capped(range(900), 500, "affected")
    assert len(out["affected"]) == 500
    assert out["affected_total"] == 900
    assert out["affected_truncated"] is True


def test_capped_consumes_a_generator_without_losing_the_total():
    out = S.capped((i for i in range(7)), 3, "x")
    assert out["x"] == [0, 1, 2] and out["x_total"] == 7


def test_capped_does_not_alias_the_caller_list():
    src = [1, 2, 3]
    out = S.capped(src, 10, "x")
    out["x"].append(4)
    assert src == [1, 2, 3], "a rendered list must not be the caller's list"


# ── the shapes that were undeclared before ──────────────────────────────────

@pytest.mark.parametrize("prefix", ["attack_paths", "choke_points",
                                    "top_attack_paths", "top_choke_points",
                                    "affected", "incidents", "notes"])
def test_each_converted_field_emits_its_declaration(prefix):
    out = S.capped(range(50), 10, prefix)
    assert set(out) == {prefix, prefix + "_total", prefix + "_truncated"}
    assert out[prefix + "_total"] == 50
    assert out[prefix + "_truncated"] is True


def test_the_account_payload_declares_its_path_caps():
    """The site the module docstring quotes: the cap that sat three lines above
    a comment about denominators."""
    src = io.open(os.path.join(ROOT, "cnapp_service.py"), encoding="utf-8").read()
    assert 'capped(p.get("attack_paths"), 10, "attack_paths")' in src
    assert 'capped(p.get("choke_points"), 10, "choke_points")' in src
    assert '"attack_paths": p.get("attack_paths", [])[:10]' not in src
