"""Every number the docs publish, checked against the code that produces it.

WHY THIS EXISTS. The README badge said 296 severity-mapped checks across 44 sections
and the catalogue held 458 across 90 — the product understated itself by 162 checks on
its own front page, and the section list in CLAUDE.md enumerated fewer than half the
sections that run. Nothing tested any of it, so the figures drifted quietly across
four releases and every doc repeated the same stale number in a slightly different
sentence.

A published figure is a claim. This file makes the claims derive from the code, so a
check added tomorrow either updates the docs or fails the build.

WHAT IT DELIBERATELY DOES NOT DO. It does not scan for every integer in the
documentation. `docs/banner.svg` contains `x1="296"` and README contains the AWS
account id `111122223333` — both matched a naive search for the old figures, and a
test that flagged them would be one somebody disables. Each assertion below names the
sentence it is checking.
"""
from __future__ import annotations

import io
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from engine.aws_live_scanner import (CHECK_SEVERITY, COMPLIANCE_MAP,  # noqa: E402
                                     REMEDIATION_MAP, SECTIONS)
from engine.aws_finding_detail import FINDING_DETAIL  # noqa: E402

CHECKS = len(CHECK_SEVERITY)
SECS = len(SECTIONS)


def read(name: str) -> str:
    return io.open(os.path.join(ROOT, name), encoding="utf-8").read()


@pytest.fixture(scope="module")
def claude():
    return read("CLAUDE.md")


@pytest.fixture(scope="module")
def readme():
    return read("README.md")


# ── the headline claim, wherever it is repeated ─────────────────────────────

@pytest.mark.parametrize("doc", ["CLAUDE.md", "README.md"])
def test_every_severity_mapped_claim_matches_the_catalogue(doc):
    """The phrase appears seven times across the two documents in five different
    sentences. Each one is a claim, and they must all be the same claim."""
    found = re.findall(r"(\d+)\s+severity-mapped", read(doc))
    assert found, "%s no longer states the check count anywhere" % doc
    wrong = sorted({n for n in found if int(n) != CHECKS})
    assert not wrong, (
        "%s publishes %s severity-mapped checks; the catalogue holds %d"
        % (doc, wrong, CHECKS))


@pytest.mark.parametrize("doc", ["CLAUDE.md", "README.md"])
def test_every_section_count_matches_the_run_list(doc):
    """`SECTIONS` is the default run list, so it is the number a reader is being told
    about. It went 86 -> 90 when four dispatchable sections were found never to run."""
    # The lookbehind matters: without it this matches "Phase-8 section above" and the
    # tail of a hyphenated identifier, and a test that flags those is one somebody
    # disables rather than trusts.
    found = re.findall(r"(?<![\w-])(\d+)\s+(?:audit\s+)?sections?\b", read(doc))
    assert found, "%s no longer states the section count" % doc
    wrong = sorted({n for n in found if int(n) != SECS})
    assert not wrong, (
        "%s publishes %s sections; SECTIONS holds %d" % (doc, wrong, SECS))


# ── the badge, which is the first thing anyone sees ─────────────────────────

def test_the_readme_badge_matches(readme):
    """It is rendered at the top of the repo's front page, and it was the most
    visible wrong number in the project."""
    m = re.search(r"badge/checks-(\d+)%20severity--mapped", readme)
    assert m, "the checks badge is gone from the README"
    assert int(m.group(1)) == CHECKS
    alt = re.search(r'alt="(\d+) severity-mapped checks"', readme)
    assert alt and int(alt.group(1)) == CHECKS, (
        "the badge image and its alt text disagree")


def test_the_contents_link_still_resolves(readme):
    """A heading carrying a figure means its anchor carries the figure too, so
    correcting one and not the other leaves a table-of-contents entry pointing at
    nothing. GitHub derives the anchor from the heading text."""
    heading = re.search(r"^### (Security Checks Coverage \(.+?\))$", readme, re.M)
    assert heading, "the coverage heading has moved"
    slug = re.sub(r"[^a-z0-9 -]", "", heading.group(1).lower()).replace(" ", "-")
    assert "(#%s)" % slug in readme, (
        "the table-of-contents anchor does not match the heading %r (expected #%s)"
        % (heading.group(1), slug))


# ── the enumerated list, which is easy to leave half-updated ────────────────

def test_the_section_list_names_every_section(claude):
    """It enumerated 44 of them. A partial list is worse than a count, because a
    reader checks whether their service is on it."""
    m = re.search(r"- \*\*(\d+) sections\*\*: (.+)", claude)
    assert m, "CLAUDE.md no longer enumerates the sections"
    assert int(m.group(1)) == SECS
    listed = [s.strip() for s in m.group(2).split(",")]
    assert listed == list(SECTIONS), (
        "the enumerated list has drifted from SECTIONS: missing %s, extra %s"
        % (sorted(set(SECTIONS) - set(listed)), sorted(set(listed) - set(SECTIONS))))


# ── the lockstep maps ───────────────────────────────────────────────────────

def test_the_map_sizes_are_published_correctly(claude):
    m = re.search(r"`CHECK_SEVERITY` \((\d+) entries\), `COMPLIANCE_MAP` \((\d+)\), "
                  r"`REMEDIATION_MAP` \((\d+)\)", claude)
    assert m, "the lockstep-maps sentence has changed shape"
    assert [int(g) for g in m.groups()] == [len(CHECK_SEVERITY), len(COMPLIANCE_MAP),
                                            len(REMEDIATION_MAP)]


def test_the_maps_really_are_in_lockstep():
    """The sentence above claims a check lands in all of them. That is enforced by
    test_check_maps_lockstep; asserted here too because the published figure is only
    meaningful if one number describes all four."""
    assert len(CHECK_SEVERITY) == len(COMPLIANCE_MAP) == len(REMEDIATION_MAP)
    assert len(FINDING_DETAIL) == len(CHECK_SEVERITY)


def test_actionable_is_not_claimed_to_mean_fail_able(claude):
    """CLAUDE.md used to say the REMEDIATION_MAP keys "are the actionable (FAIL-able)
    checks". docs/CHECK_FIRING.md measured that: the suite drives 273 of 458 to a FAIL.
    A doc that equates carrying a remediation with being provably able to fail is
    making a claim the product's own measurement contradicts."""
    assert "actionable (FAIL-able) checks" not in claude
    assert "CHECK_FIRING" in claude, (
        "the lockstep paragraph no longer points at the measurement that qualifies it")
