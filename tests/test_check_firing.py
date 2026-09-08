"""The catalogue promises 458 checks. This is how many the suite proves.

WHY A RECORDING AND NOT A GREP. "Which checks can produce a finding" reads like a
source question and is not one. A check id reaches `_add` as a literal, a bare
variable (`fid`), a subscript (`f["id"]`) or a conditional, and every one of the
scanner's 90 sections uses at least one non-literal form. Four successive static
passes gave four different answers — 76, 48, 42, then 0 — and only the last was
honest, because nothing is provable that way. So `tests/conftest.py` records
`AWSLiveScanner._add` (the single point where every finding in the product is
constructed) across a real suite run, and `scripts/check_firing.py` turns that into
`docs/CHECK_FIRING.md`.

THE THREE STATES, and the distinction that carries the value:

  * PROVEN FAILING — a test drives the check to an actual FAIL. It works.
  * RUNS, NEVER FAILS — it emits, but nothing has made it report a problem. Not
    automatically a defect: a check may legitimately only ever warn. But `_add` reads
    severity, compliance and remediation from the maps ONLY for a FAIL — a WARN is
    forced to LOW and carries no remediation — so a check registered CRITICAL that
    only ever WARNs has never rendered what the catalogue advertises for it.
  * NEVER OBSERVED — no test makes it emit anything at all. This is where a genuinely
    dead check hides: THREAT-02 is registered in all four maps, carries a full
    remediation write-up, is counted in the published total, and is emitted by no code
    path anywhere. Nothing in the build said so until this file existed.

WHAT THIS FILE DOES NOT CLAIM. "Never observed in the suite" is not "cannot fire". It
is a TEST-COVERAGE fact, and most of the 103 are checks nobody has written a driving
test for rather than checks that are broken. The value is that the number is now
visible and can only go down, and that a genuinely unreachable check can no longer
hide among them.
"""
from __future__ import annotations

import io
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "CHECK_FIRING.md")

#: The ratchet. Lower these when coverage improves and the doc is regenerated; never
#: raise them. A new check arrives unproven, so adding one without a driving test
#: pushes `never_observed` past the ceiling and fails the build — which is the point.
MAX_NEVER_OBSERVED = 103
MAX_RUNS_BUT_NEVER_FAILS = 82


def doc_text() -> str:
    if not os.path.exists(DOC):
        pytest.fail(
            "docs/CHECK_FIRING.md is missing. Regenerate it:\n"
            "  OVERWATCH_RECORD_CHECKS=fired.json python -m pytest tests/ -q\n"
            "  python scripts/check_firing.py --from fired.json")
    return io.open(DOC, encoding="utf-8").read()


def headline(text: str):
    m = re.search(r"\*\*(\d+) registered checks\.\*\* (\d+) are proven to FAIL in the "
                  r"suite; (\d+) run but have never been driven to a failure; (\d+) "
                  r"were never observed", text)
    assert m, "the doc's headline sentence has changed shape; update this test"
    return tuple(int(g) for g in m.groups())


def test_the_doc_exists_and_is_generated():
    """Hand-editing it would turn a measurement into an assertion."""
    text = doc_text()
    assert "GENERATED FILE - DO NOT EDIT BY HAND" in text
    assert "scripts/check_firing.py" in text


def test_the_headline_adds_up():
    """Three states, no fourth, and they partition the catalogue. A doc whose numbers
    do not sum is a doc nobody can quote."""
    registered, failing, soft, unseen = headline(doc_text())
    assert failing + soft + unseen == registered


def test_the_doc_describes_the_current_catalogue():
    """A check added without regenerating leaves the doc describing a smaller product,
    and every number below becomes a statement about the past."""
    from engine.aws_live_scanner import CHECK_SEVERITY
    registered, _f, _s, _u = headline(doc_text())
    assert registered == len(CHECK_SEVERITY), (
        "docs/CHECK_FIRING.md covers %d checks, the catalogue now has %d. "
        "Regenerate it." % (registered, len(CHECK_SEVERITY)))


def test_unproven_checks_can_only_decrease():
    """THE RATCHET. A new check arrives unproven, so shipping one with no driving test
    pushes this past the ceiling. Lower the ceiling when coverage improves; never
    raise it to make a build pass."""
    _r, _f, _s, unseen = headline(doc_text())
    assert unseen <= MAX_NEVER_OBSERVED, (
        "%d checks are never observed, ceiling is %d. Write a test that drives the "
        "new check to a finding rather than raising this." % (unseen,
                                                              MAX_NEVER_OBSERVED))


def test_never_failing_checks_can_only_decrease():
    """Same ratchet on the softer category: a check that runs but has never been
    driven to a FAIL has never rendered its declared severity or its remediation."""
    _r, _f, soft, _u = headline(doc_text())
    assert soft <= MAX_RUNS_BUT_NEVER_FAILS, (
        "%d checks run but never fail, ceiling is %d." % (soft,
                                                          MAX_RUNS_BUT_NEVER_FAILS))


def test_the_ceilings_are_not_stale():
    """The half that keeps the ratchet honest. A ceiling left far above the real
    number stops being a ratchet and becomes decoration, so it must be tightened when
    the gap opens up."""
    _r, _f, soft, unseen = headline(doc_text())
    assert MAX_NEVER_OBSERVED - unseen <= 5, (
        "the never-observed ceiling (%d) is well above the actual (%d); lower it"
        % (MAX_NEVER_OBSERVED, unseen))
    assert MAX_RUNS_BUT_NEVER_FAILS - soft <= 5, (
        "the never-fails ceiling (%d) is well above the actual (%d); lower it"
        % (MAX_RUNS_BUT_NEVER_FAILS, soft))


def test_threat_02_is_still_listed_as_never_observed():
    """The known dead check, pinned so it cannot be quietly forgotten. Either a test
    drives it, or the check is retired from the catalogue — both are progress, and
    both change this line deliberately."""
    text = doc_text()
    unseen = text.split("## Never observed")[1].split("## Runs, but never fails")[0]
    assert "`THREAT-02`" in unseen, (
        "THREAT-02 is no longer never-observed. If it now fires, delete this test; if "
        "it was retired from the catalogue, delete it here too.")


def test_no_unregistered_check_reaches_a_failure():
    """`_add` looks up severity AND remediation by check id, so a FAIL whose id the
    catalogue does not know renders at the default MEDIUM with no remediation — a
    finding that silently misstates its own severity.

    Today's 28 unregistered ids are all INFO/WARN/PASS section markers, which is
    benign. The generator computes that from the recording and states it, so this can
    assert the fact rather than the shape: an earlier version of this test only
    checked the section was non-empty, which is not what its name says."""
    text = doc_text()
    if "## Emitted but not registered" not in text:
        return
    section = text.split("## Emitted but not registered")[1]
    m = re.search(r"\*\*Reaching FAIL: (.+?)\*\*", section)
    assert m, "the generator no longer states which unregistered ids reach FAIL"
    assert m.group(1).startswith("none"), (
        "unregistered check id(s) reach FAIL and render at the default severity with "
        "no remediation: %s. Register them, or stop them failing." % m.group(1))
