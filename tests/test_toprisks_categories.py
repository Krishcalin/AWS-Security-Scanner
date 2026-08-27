"""Every check family the product ships must land on the Top Risks dashboard.

WHY THIS IS A PYTHON TEST OVER A TYPESCRIPT FILE
------------------------------------------------
The category map lives in `frontend/src/lib/toprisks.ts`, but the thing it has to
stay in step with -- `CHECK_SEVERITY` -- lives here. A TypeScript test cannot see
the 452-check universe, and a JSON fixture of it would need its own currency test.
So this reads the source, the same way `test_seed_demo_data` reads
`frontend/src/api/types.ts` to check the payload shape it emits.

WHAT GOES WRONG WITHOUT IT
--------------------------
The first cut of the dashboard categorised 95 of 120 check families. The other 25 --
EC2, EBS, LMB, SQS, R53, CloudFront and the rest -- appeared on no card at all, which
is 27% of a real catalog silently missing from the screen a reader opens first. An
absent finding does not look absent; it looks like an estate with less wrong with it.

Adding a check family is now the moment you decide where it belongs, rather than
something discovered later by someone wondering why their finding is not on screen.
"""
from __future__ import annotations

import io
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.aws_live_scanner import CHECK_SEVERITY  # noqa: E402

TOPRISKS = os.path.join(ROOT, "frontend", "src", "lib", "toprisks.ts")


def _source() -> str:
    return io.open(TOPRISKS, encoding="utf-8").read()


def _categories() -> dict:
    """slug -> [prefix, ...], parsed out of the RISK_CATEGORIES literal."""
    src = _source()
    start = src.index("export const RISK_CATEGORIES")
    end = src.index("export const SEV_RANK")
    body = src[start:end]
    out = {}
    for block in body.split("slug: ")[1:]:
        slug = re.match(r"'([^']+)'", block).group(1)
        m = re.search(r"prefixes: \[(.*?)\]", block, re.S)
        assert m, f"category {slug} has no prefixes array"
        out[slug] = re.findall(r"'([^']+)'", m.group(1))
    return out


#: Families that are REAL but absent from CHECK_SEVERITY, because they are emitted as
#: display-only catalog cards rather than scored checks. `CIEM-00/01/02` come from
#: aws_unused and the IAMPRIVESC section: effective-permission analysis, surfaced to a
#: reader but deliberately not carrying a posture-score weight of its own.
#:
#: This list is short on purpose. Anything added here is a family the coverage ratchet
#: below stops policing, so it needs the same evidence CIEM- has -- an actual emission
#: site -- not merely a wish to make a test pass.
DISPLAY_ONLY = {"CIEM"}


def _families() -> set:
    return {c.split("-")[0] for c in CHECK_SEVERITY} | DISPLAY_ONLY


def test_the_source_file_is_where_this_test_thinks_it_is():
    """A moved or renamed file must fail loudly, not silently pass an empty parse."""
    assert os.path.exists(TOPRISKS), (
        f"{TOPRISKS} not found — if the category map moved, update this test rather "
        f"than deleting it, or check-family coverage stops being enforced.")
    assert _categories(), "parsed no categories out of toprisks.ts"


def test_every_check_family_lands_in_a_category():
    """THE RATCHET. A new check family with nowhere to go fails here."""
    covered = {p.rstrip("-") for ps in _categories().values() for p in ps}
    orphans = sorted(_families() - covered)
    assert not orphans, (
        f"{len(orphans)} check famil{'y' if len(orphans) == 1 else 'ies'} appear on no "
        f"Top Risks card: {orphans}. Add each to a category in "
        f"frontend/src/lib/toprisks.ts — a finding that renders on no card is "
        f"indistinguishable from a finding that does not exist.")


def test_no_category_names_a_family_that_does_not_exist():
    """The other direction: a prefix matching nothing is a card that can never fill,
    and an empty card reads as 'no risk in this domain'."""
    families = _families()
    dead = sorted({p for ps in _categories().values() for p in ps
                   if p.rstrip("-") not in families})
    assert not dead, (
        f"categories name check families the product does not ship: {dead}. Either "
        f"the family was removed, or the prefix is misspelled.")


def test_every_prefix_carries_its_dash():
    """`SEC-` must never match `SECRET-01` by accident, and `SEG-` is a different
    category from `SEC-` entirely."""
    bad = sorted({p for ps in _categories().values() for p in ps if not p.endswith("-")})
    assert not bad, f"prefixes missing their trailing dash: {bad}"


def test_category_slugs_are_unique():
    cats = _categories()
    src = _source()
    assert len(cats) == src.count("slug: '"), "duplicate slug in RISK_CATEGORIES"


@pytest.mark.parametrize("slug", sorted(_categories()))
def test_no_category_is_empty(slug):
    assert _categories()[slug], f"category {slug} lists no prefixes"


def test_a_family_claimed_twice_is_deliberate():
    """Two categories may share a prefix (a storage gateway open to the internet is
    both a data and an exposure concern), but it should be visible when it happens
    rather than accidental — so this pins the current set."""
    seen, dup = set(), set()
    for ps in _categories().values():
        for p in ps:
            if p in seen:
                dup.add(p)
            seen.add(p)
    assert dup == set(), (
        f"prefixes claimed by more than one category: {sorted(dup)}. That is allowed, "
        f"but update this test to record the decision so it is not accidental.")
