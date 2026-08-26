"""Ownership attribution, and its refusal to shrink the denominator.

WHY THE COVERAGE TESTS ARE THE ONES THAT MATTER
------------------------------------------------
A scorecard is a filter over findings, and a filter deletes what it does not match.
The dangerous failure here is not a wrong owner — a wrong owner complains. It is the
600 untagged findings that never reach any scorecard, so the portfolio pack sums to a
cleaner estate than the one that exists, and nobody complains because nobody sees them.

So most of the tests below assert on `AttributionCoverage` rather than on the buckets:
that unattributed findings survive into a real bucket, that ambiguity is reported as
ambiguity instead of being awarded to whichever application was declared first, and
that a selector matching nothing is reported rather than rendering a clean scorecard.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_epistemics  # noqa: E402
import aws_ownership as O  # noqa: E402


def app(app_id, **kw):
    kw.setdefault("name", app_id.title())
    kw.setdefault("owner", "team-" + app_id)
    return O.Application(app_id=app_id, **kw)


def finding(resource, account="111111111111", severity="HIGH", key=None):
    return {"resource": resource, "account": account, "severity": severity,
            "finding_key": key or resource}


# ── the registry refuses to be constructed in a state that lies ──────────────

def test_key_only_tag_selector_is_rejected():
    # A selector with no value claims every resource bearing the key, which is how
    # one application silently swallows the estate.
    with pytest.raises(ValueError, match="claims every resource"):
        app("payments", tag_selectors=(("Application", ""),))


def test_unknown_criticality_is_rejected():
    with pytest.raises(ValueError, match="criticality"):
        app("payments", criticality="very-important")


def test_app_id_is_required():
    with pytest.raises(ValueError):
        O.Application(app_id="", name="x")


# ── precedence ───────────────────────────────────────────────────────────────

def test_explicit_pin_beats_tag_and_account():
    a = app("pinned", resource_arns=("arn:aws:s3:::bucket",))
    b = app("tagged", tag_selectors=(("App", "b"),))
    c = app("acct", accounts=("111111111111",))
    att = O.attribute("arn:aws:s3:::bucket", {"App": "b"}, "111111111111", [a, b, c])
    assert att.app_id == "pinned"
    assert att.rule == O.RULE_RESOURCE


def test_tag_beats_account():
    b = app("tagged", tag_selectors=(("App", "b"),))
    c = app("acct", accounts=("111111111111",))
    att = O.attribute("arn:x", {"App": "b"}, "111111111111", [b, c])
    assert att.app_id == "tagged"
    assert att.rule == O.RULE_TAG


def test_account_tier_is_the_fallback():
    c = app("acct", accounts=("111111111111",))
    att = O.attribute("arn:x", {"Unrelated": "v"}, "111111111111", [c])
    assert att.app_id == "acct"
    assert att.rule == O.RULE_ACCOUNT


def test_no_match_records_why():
    att = O.attribute("arn:x", {}, "999999999999", [app("a", accounts=("111",))])
    assert att.app_id is None
    assert att.rule == O.NONE
    assert "999999999999" in att.basis


# ── the refusal to guess ─────────────────────────────────────────────────────

def test_two_applications_claiming_one_resource_is_ambiguous_not_first_wins():
    a = app("alpha", tag_selectors=(("App", "shared"),))
    b = app("bravo", tag_selectors=(("App", "shared"),))
    att = O.attribute("arn:x", {"App": "shared"}, "111111111111", [a, b])
    assert att.app_id is None
    assert att.rule == O.AMBIGUOUS
    assert att.candidates == ("alpha", "bravo")


def test_ambiguity_is_order_independent():
    a = app("alpha", tag_selectors=(("App", "shared"),))
    b = app("bravo", tag_selectors=(("App", "shared"),))
    one = O.attribute("arn:x", {"App": "shared"}, "1", [a, b])
    two = O.attribute("arn:x", {"App": "shared"}, "1", [b, a])
    assert one == two, "ownership must not depend on registry declaration order"


def test_ambiguous_tier_does_not_fall_through_to_a_decisive_broader_tier():
    # Two applications contest the tag. A third owns the account outright. Falling
    # through would resolve a contradiction by widening the question and would
    # confidently bill the wrong team.
    a = app("alpha", tag_selectors=(("App", "shared"),))
    b = app("bravo", tag_selectors=(("App", "shared"),))
    c = app("charlie", accounts=("111111111111",))
    att = O.attribute("arn:x", {"App": "shared"}, "111111111111", [a, b, c])
    assert att.rule == O.AMBIGUOUS
    assert att.app_id is None


# ── coverage: the denominator survives ───────────────────────────────────────

def test_unattributed_findings_land_in_a_real_bucket():
    apps = [app("alpha", tag_selectors=(("App", "alpha"),))]
    tags = {"arn:a": {"App": "alpha"}}
    fs = [finding("arn:a"), finding("arn:b"), finding("arn:c")]
    buckets, cov = O.attribute_findings(fs, apps, lambda r: tags.get(r))
    assert len(buckets["alpha"]) == 1
    assert len(buckets[O.UNATTRIBUTED]) == 2, "untagged findings must not vanish"
    assert cov.total == 3 and cov.attributed == 1 and cov.unattributed == 2


def test_coverage_pct_and_headline_state_the_shortfall():
    apps = [app("alpha", tag_selectors=(("App", "alpha"),))]
    tags = {"arn:a": {"App": "alpha"}}
    fs = [finding("arn:a")] + [finding("arn:%d" % i) for i in range(3)]
    _, cov = O.attribute_findings(fs, apps, lambda r: tags.get(r))
    assert cov.pct == 25.0
    assert not cov.complete
    head = cov.headline()
    assert "25.0%" in head and "3 unowned" in head
    assert "exclude" in head, "the headline must say the totals are a subset"


def test_complete_coverage_says_so_plainly():
    apps = [app("alpha", accounts=("111111111111",))]
    _, cov = O.attribute_findings([finding("arn:a"), finding("arn:b")], apps)
    assert cov.complete
    assert cov.headline() == "All 2 findings attributed to an application."


def test_ambiguous_findings_are_counted_apart_from_unowned():
    a = app("alpha", tag_selectors=(("App", "s"),))
    b = app("bravo", tag_selectors=(("App", "s"),))
    tags = {"arn:a": {"App": "s"}}
    fs = [finding("arn:a"), finding("arn:b")]
    _, cov = O.attribute_findings(fs, [a, b], lambda r: tags.get(r))
    assert cov.ambiguous == 1
    assert cov.unattributed == 1
    assert cov.attributed == 0


def test_gap_accounts_point_at_where_the_tagging_is_missing():
    apps = [app("alpha", tag_selectors=(("App", "alpha"),))]
    fs = ([finding("arn:%d" % i, account="222222222222") for i in range(3)]
          + [finding("arn:x", account="333333333333")])
    _, cov = O.attribute_findings(fs, apps)
    assert cov.gap_accounts[0] == ("222222222222", 3)


def test_no_tag_lookup_means_the_tag_rule_never_fires():
    apps = [app("alpha", tag_selectors=(("App", "alpha"),))]
    _, cov = O.attribute_findings([finding("arn:a")], apps)
    assert cov.by_rule[O.RULE_TAG] == 0
    assert cov.unattributed == 1


def test_empty_scope_does_not_claim_completeness():
    _, cov = O.attribute_findings([], [app("alpha")])
    assert cov.total == 0
    assert not cov.complete, "zero findings is not the same as full coverage"
    assert cov.pct == 0.0


def test_every_attribution_records_the_rule_that_fired():
    apps = [app("alpha", accounts=("111111111111",))]
    buckets, _ = O.attribute_findings([finding("arn:a")], apps)
    _, att = buckets["alpha"][0]
    assert att.rule == O.RULE_ACCOUNT
    assert "111111111111" in att.basis


def test_findings_may_be_objects_not_only_mappings():
    class F:
        resource = "arn:a"
        account = "111111111111"
    apps = [app("alpha", accounts=("111111111111",))]
    buckets, cov = O.attribute_findings([F()], apps)
    assert cov.attributed == 1 and "alpha" in buckets


# ── registry health ──────────────────────────────────────────────────────────

def test_selector_matching_nothing_is_reported():
    apps = [app("ghost", criticality="high", tag_selectors=(("App", "ghost"),))]
    buckets, _ = O.attribute_findings([finding("arn:a")], apps)
    kinds = {i.kind for i in O.attribution_health(apps, buckets)}
    assert "matched-nothing" in kinds


def test_ownerless_application_cannot_receive_a_scorecard():
    a = O.Application(app_id="orphan", name="Orphan", owner="", accounts=("1",),
                      criticality="high")
    kinds = {i.kind for i in O.attribution_health([a])}
    assert "no-owner" in kinds


def test_application_with_no_selectors_would_always_score_clean():
    a = O.Application(app_id="empty", name="Empty", owner="t", criticality="high")
    issues = {i.kind: i for i in O.attribution_health([a])}
    assert "no-selectors" in issues
    assert "always score as clean" in issues["no-selectors"].detail


def test_unclassified_criticality_is_flagged_not_treated_as_standard():
    kinds = {i.kind for i in O.attribution_health([app("a", accounts=("1",))])}
    assert "unclassified" in kinds


def test_health_is_deterministic_in_application_order():
    a, b = app("zulu", accounts=("1",)), app("alpha", accounts=("1",))
    assert O.attribution_health([a, b]) == O.attribution_health([b, a])


# ── owner resolution ─────────────────────────────────────────────────────────

def test_owner_of_unattributed_is_empty_not_a_placeholder():
    apps = [app("alpha", accounts=("1",))]
    assert O.owner_of(O.UNATTRIBUTED, apps) == ""
    assert O.owner_of(None, apps) == ""


def test_owner_of_known_application():
    apps = [app("alpha", accounts=("1",))]
    assert O.owner_of("alpha", apps) == "team-alpha"


# ── provenance ───────────────────────────────────────────────────────────────

def test_attribution_is_configured_never_observed():
    assert O.PROVENANCE == aws_epistemics.CONFIGURED
    _, cov = O.attribute_findings([finding("arn:a")], [])
    assert cov.provenance == aws_epistemics.CONFIGURED
    assert "not who is in fact maintaining" in cov.note
