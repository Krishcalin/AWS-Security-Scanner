"""Every section the scanner can dispatch is a section a scan actually runs.

THE DEFECT. `SECTIONS` is the DEFAULT run list — `__init__` does
``_req = [s.upper() for s in sections] if sections else list(SECTIONS)`` — and four
sections had a check method, a dispatch-table entry and a `SECTION_LABELS` entry
while being absent from it. A default scan ran none of them:

  * `VECTORSTORE`, `SHADOW_AI`, `AI_LOGGING` — 14 checks (VEC-*, SHAI-*, AILOG-*),
    reachable only by passing a section name that appears nowhere in CLAUDE.md or
    README, so no user could have known to ask.
  * `SIDESCAN` — worse, because it has a flag. `--side-scan` set `self.side_scan`,
    `_check_side_scan` read it, and nothing ever called `_check_side_scan`. The
    agentless EBS side-scan, a headline CWPP capability, could not run.

WHY THE EXISTING TESTS DID NOT CATCH IT, which is the more useful lesson. Each of
those sections HAS a wiring test, and each constructs the scanner as
``AWSLiveScanner(sections=["SHADOW_AI"])`` — naming the section explicitly. That
proves the section works WHEN ASKED FOR and never that anything asks for it.
`test_agentcore_wiring.py` uses the stronger form (`assert "AGENTCORE" in
A.SECTIONS`); the weaker style is what let four sections go unrun.

So this file asserts the property for ALL sections at once rather than one more
name at a time, and `OFF_DEFAULT` below is the ratchet: a section may sit off the
default list only with a written reason, and an entry that rejoins the list fails
too, so it cannot rot into fiction.
"""
from __future__ import annotations

import io
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_live_scanner as A
from engine.aws_live_scanner import AWSLiveScanner

SRC = io.open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "engine", "aws_live_scanner.py"),
              encoding="utf-8", errors="replace").read()

#: Sections deliberately NOT on the default run list, each with the reason. Empty
#: today: every dispatched section runs, and the three flag-guarded ones
#: (SIDESCAN, plus the ECR/Lambda paths inside their own sections) cost nothing on a
#: default scan because their first statement returns unless the flag is set.
#:
#: DO NOT add an entry here to make a build pass. A section that is expensive or
#: destructive belongs on the list with a guard inside it, the way SIDESCAN now is —
#: that is what makes "off by default" a property of the SCAN rather than a property
#: of a list somebody forgot to update.
OFF_DEFAULT: dict = {}


def dispatched() -> set:
    """Section names the run-table maps to a check method."""
    return set(re.findall(r'"([A-Z0-9_]+)":\s*self\._check_', SRC))


# ── the ratchet ─────────────────────────────────────────────────────────────

def test_every_dispatched_section_is_on_the_default_run_list():
    """The whole defect in one assertion. A section wired into the dispatch table
    and left out of SECTIONS is invisible: it has a label, it has checks, it has
    tests, and no scan runs it."""
    missing = sorted(dispatched() - set(A.SECTIONS) - set(OFF_DEFAULT))
    assert not missing, (
        "%s dispatchable but absent from SECTIONS, so a default scan never runs "
        "them. Add them to SECTIONS (guard inside the method if they are "
        "expensive), or declare them in OFF_DEFAULT with a reason." % (missing,))


def test_no_off_default_entry_is_actually_on_the_list():
    """The half that keeps OFF_DEFAULT honest: a waiver nobody prunes stops
    describing the code and starts describing its history."""
    stale = sorted(s for s in OFF_DEFAULT if s in A.SECTIONS)
    assert not stale, "%s is on the default list and should leave OFF_DEFAULT" % (stale,)


def test_every_section_can_actually_be_dispatched():
    """The other direction: a name on the run list with no method behind it is a
    section that silently does nothing."""
    orphans = sorted(set(A.SECTIONS) - dispatched())
    assert not orphans, "%s on the run list but mapped to no check method" % (orphans,)


def test_labels_and_sections_agree():
    """A section with no label renders as a bare constant on screen; a label with no
    section describes something that never runs."""
    assert not [s for s in A.SECTIONS if s not in A.SECTION_LABELS]
    assert not [s for s in A.SECTION_LABELS if s not in A.SECTIONS]


# ── the four that were stranded ─────────────────────────────────────────────

@pytest.mark.parametrize("section", ["VECTORSTORE", "SHADOW_AI", "AI_LOGGING"])
def test_the_ai_posture_sections_run_by_default(section):
    """14 checks that a default scan could not produce. These are AI-SPM, which the
    product markets as a differentiator."""
    assert section in A.SECTIONS


def test_side_scan_is_reachable_at_all():
    """`--side-scan` set a flag that `_check_side_scan` read, and nothing called
    `_check_side_scan`. The flag was inert."""
    from unittest.mock import patch
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        sc = AWSLiveScanner(region="us-east-1", verbose=False)
    assert "SIDESCAN" in sc.sections, (
        "a default scan does not plan SIDESCAN, so --side-scan cannot take effect")


def test_dispatching_side_scan_costs_nothing_when_the_flag_is_off():
    """Why putting it on the default list is safe: the guard is the FIRST thing the
    method does, so an unasked-for side-scan makes no AWS call. Without this, adding
    the section to the run list would have turned every default scan into an EBS
    snapshot sweep."""
    from unittest.mock import patch
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        sc = AWSLiveScanner(region="us-east-1", verbose=False)
    assert sc.side_scan is False
    before = len(sc.results)
    sc._check_side_scan()                      # no client, no snapshot, no error
    assert len(sc.results) == before


# ── ordering, which the run list also encodes ───────────────────────────────

def test_correlate_runs_last():
    """SECTIONS is a canonical order, not a set: `__init__` sorts any --sections
    request back into it because correlation must see every edge the other sections
    built."""
    assert A.SECTIONS[-1] == "CORRELATE"


def test_the_vuln_producing_sections_precede_correlation():
    """SIDESCAN and WINVULN emit HAS_VULN edges that attack-path correlation ranks.
    Placed after CORRELATE they would produce findings that no path ever reflects."""
    idx = {s: i for i, s in enumerate(A.SECTIONS)}
    assert idx["SIDESCAN"] < idx["CORRELATE"]
    assert idx["WINVULN"] < idx["CORRELATE"]


def test_graph_building_order_is_preserved():
    """The dependency the run list has always encoded, asserted here because this
    file now edits that list."""
    idx = {s: i for i, s in enumerate(A.SECTIONS)}
    assert idx["IAMPRIVESC"] < idx["EXPOSURE"]
    assert idx["IAMPRIVESC"] < idx["COGNITO_IDENTITY"]


# ── regional vs global ──────────────────────────────────────────────────────

def test_shadow_ai_runs_once_rather_than_per_region():
    """`_check_undeclared_ai_creators` sweeps `_ai_scan_regions()` itself, so a
    per-region pass under --all-regions would repeat the whole CloudTrail sweep once
    per region. Same reason AI_THREAT is global."""
    assert "SHADOW_AI" in AWSLiveScanner.GLOBAL_SECTIONS


@pytest.mark.parametrize("section", ["VECTORSTORE", "AI_LOGGING"])
def test_the_regional_ai_sections_are_not_global(section):
    """The negative control. These hold no internal region sweep, so marking them
    global would silently scan only the one region and report the rest as clean."""
    assert section not in AWSLiveScanner.GLOBAL_SECTIONS
