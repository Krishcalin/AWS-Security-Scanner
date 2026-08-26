"""KRA metrics, and the fact that losing a permission scores better than fixing one.

THE ASYMMETRY THESE TESTS EXIST TO PIN
---------------------------------------
Every KRA in FR-8 is a ratio or count whose denominator comes from enumeration, and
enumeration is exactly what fails when a permission is missing. So the failure has a
direction: lose iam:ListUsers and MFA coverage reports 100%; lose a region and
"internet-exposed critical workloads" reports 0. Both are the stated target. The
reward for losing visibility is a better number, and that number reaches the BBSC.

The fix is that a verdict is asserted only when the WHOLE range supports it, which
makes the asymmetry explicit:

    NOT_MET survives incomplete data.  MET does not.

Having already found three exposed workloads, the target of zero is missed whatever
else was unreadable. Having found none, nothing has been established. The two zeroes
are different claims, and `test_zero_found_with_a_blind_region_is_not_a_pass` is the
one that stops them being rendered the same.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_kra as K  # noqa: E402


# ═══ the headline defect, in both directions ═════════════════════════════════

def test_zero_found_with_a_blind_region_is_not_a_pass():
    # "Zero internet-exposed critical workloads" is the OW2-KM-001(b) target. A
    # region that could not be scanned produces the same zero as a clean estate.
    clean = K.count(K.EXPOSED_CRITICAL, observed=0)
    blind = K.count(K.EXPOSED_CRITICAL, observed=0, not_evaluated=4,
                    reasons=[("eu-west-1", "region unreachable")])
    assert clean.verdict == K.MET
    assert blind.verdict == K.NOT_ESTABLISHED
    assert blind.value == 0.0, "the observation is still reported"
    assert blind.worst == 4.0, "but four unchecked subjects could each be exposed"


def test_full_mfa_coverage_over_an_incomplete_user_list_is_not_a_pass():
    # Losing iam:ListUsers removes the non-compliant users from the denominator.
    real = K.ratio(K.MFA_COVERAGE, compliant=40, counted=40)
    partial = K.ratio(K.MFA_COVERAGE, compliant=40, counted=40, not_evaluated=10,
                      reasons=[("account 2222", "AccessDenied — iam:ListUsers")])
    assert real.verdict == K.MET
    assert partial.value == 100.0
    assert partial.verdict == K.NOT_ESTABLISHED
    assert partial.worst == 80.0


def test_losing_visibility_must_not_improve_the_verdict():
    # The property, stated directly: removing evidence can never turn NOT_MET into
    # MET. It may only turn it into NOT_ESTABLISHED.
    seen = K.ratio(K.MFA_COVERAGE, compliant=8, counted=10)
    assert seen.verdict == K.NOT_MET
    blinded = K.ratio(K.MFA_COVERAGE, compliant=8, counted=8, not_evaluated=2)
    assert blinded.verdict != K.MET
    assert blinded.verdict == K.NOT_ESTABLISHED


# ═══ NOT_MET survives incompleteness; MET does not ═══════════════════════════

def test_not_met_is_still_assertable_with_missing_data():
    # Three exposed workloads already found: the zero target is missed regardless
    # of what else could not be read.
    m = K.count(K.EXPOSED_CRITICAL, observed=3, not_evaluated=9,
                reasons=[("ap-south-1", "region unreachable")])
    assert m.verdict == K.NOT_MET
    assert not m.population.complete


def test_a_single_non_compliant_member_settles_a_hundred_percent_target():
    m = K.ratio(K.MFA_COVERAGE, compliant=99, counted=100, not_evaluated=50)
    assert m.best < 100.0
    assert m.verdict == K.NOT_MET, (
        "one user without MFA misses a 100% target however many were unreadable")


def test_a_sub_hundred_target_is_not_settled_by_a_near_miss():
    # With a 95% target, unevaluated members could carry the number over the line,
    # so NOT_MET is not assertable. This is why the best end is computed at all.
    d = K.MetricDef(id="X", label="x", definition="d", source="s", cadence="c",
                    target=95.0, direction=K.HIGHER_IS_BETTER)
    m = K.ratio(d, compliant=93, counted=95, not_evaluated=20)
    assert m.value == pytest.approx(97.9, abs=0.1)
    assert m.best >= 95.0 > m.worst, "the unevaluated members straddle the target"
    assert m.verdict == K.NOT_ESTABLISHED


def test_met_requires_the_worst_end_to_still_meet_the_target():
    d = K.MetricDef(id="X", label="x", definition="d", source="s", cadence="c",
                    target=80.0, direction=K.HIGHER_IS_BETTER)
    # 95 compliant of 100 counted, 2 unreadable: worst is 95/102 = 93.1%, still >= 80.
    m = K.ratio(d, compliant=95, counted=100, not_evaluated=2)
    assert m.verdict == K.MET, "incomplete data can still support a verdict"
    assert not m.population.complete


# ═══ the denominator can itself be unknown ═══════════════════════════════════

def test_discovery_coverage_without_organizations_is_not_a_hundred_percent():
    # The most confident wrong answer in the set: reporting the share of accounts
    # we happened to hear about as if it were coverage.
    m = K.ratio(K.DISCOVERY_COVERAGE, compliant=12, counted=12,
                denominator_known=False,
                reasons=[("organization", "AccessDenied — organizations:ListAccounts")])
    assert m.verdict == K.NOT_ESTABLISHED
    assert m.value is None, "no percentage is reported at all"
    assert "nobody established" in m.reason


def test_an_unknown_denominator_is_distinct_from_an_incomplete_population():
    unknown = K.ratio(K.DISCOVERY_COVERAGE, 12, 12, denominator_known=False)
    incomplete = K.ratio(K.DISCOVERY_COVERAGE, 12, 12, not_evaluated=3)
    assert unknown.value is None and incomplete.value is not None
    assert unknown.population.coverage == 0.0
    assert not unknown.population.denominator_known
    assert incomplete.population.denominator_known


def test_an_unbounded_count_is_not_established():
    m = K.count(K.EXPOSED_CRITICAL, observed=0, denominator_known=False)
    assert m.verdict == K.NOT_ESTABLISHED
    assert m.value is None
    assert "not bounded" in m.reason


def test_an_empty_population_establishes_nothing():
    m = K.ratio(K.MFA_COVERAGE, compliant=0, counted=0)
    assert m.verdict == K.NOT_ESTABLISHED
    assert "nothing to measure" in m.reason


# ═══ complete data behaves exactly as before ═════════════════════════════════

def test_a_complete_population_reports_a_plain_verdict():
    m = K.ratio(K.MFA_COVERAGE, compliant=100, counted=100)
    assert m.verdict == K.MET
    assert m.population.complete
    assert m.best == m.worst == 100.0
    assert "NOT ESTABLISHED" not in m.headline()


def test_a_complete_miss_reports_a_plain_failure():
    m = K.count(K.EXPOSED_CRITICAL, observed=2)
    assert m.verdict == K.NOT_MET
    assert m.headline().endswith("not met")


def test_value_is_the_observed_figure_not_a_bound():
    m = K.ratio(K.MFA_COVERAGE, compliant=9, counted=10, not_evaluated=5)
    assert m.value == 90.0, "what was measured is still reported"
    assert m.worst == 60.0, "all five unreadable users could lack MFA"
    assert m.best == pytest.approx(93.3, abs=0.1), (
        "the best case is 14/15, not 100% — the one user already known to lack MFA "
        "survives every scenario, so a bound must never discard observed evidence")


# ═══ invariants ══════════════════════════════════════════════════════════════

def test_the_range_always_contains_the_target_decision():
    m = K.ratio(K.MFA_COVERAGE, compliant=5, counted=10, not_evaluated=10)
    assert m.worst <= m.value <= m.best


def test_compliant_cannot_exceed_counted():
    with pytest.raises(ValueError, match="cannot exceed"):
        K.ratio(K.MFA_COVERAGE, compliant=11, counted=10)


def test_target_met_is_false_for_not_established_but_so_is_failure():
    m = K.count(K.EXPOSED_CRITICAL, observed=0, not_evaluated=1)
    assert not m.target_met
    assert m.verdict != K.NOT_MET, (
        "NOT_ESTABLISHED must not be readable as a failure of the estate")


def test_lower_is_better_metrics_use_a_ceiling():
    assert K.EXPOSED_CRITICAL.direction == K.LOWER_IS_BETTER
    assert K.EXPOSED_CRITICAL.meets(0.0) and not K.EXPOSED_CRITICAL.meets(1.0)


def test_metric_computation_is_pure_and_reproducible():
    a = K.ratio(K.MFA_COVERAGE, 8, 10, 3)
    b = K.ratio(K.MFA_COVERAGE, 8, 10, 3)
    assert a == b


# ═══ the declaration carries its own documentation (OW2-KM-001/002) ══════════

def test_a_metric_without_a_source_or_cadence_is_rejected():
    with pytest.raises(ValueError, match="definition, a source and a cadence"):
        K.MetricDef(id="X", label="x", definition="d", source="", cadence="c",
                    target=1, direction=K.HIGHER_IS_BETTER)


def test_unknown_direction_is_rejected():
    with pytest.raises(ValueError, match="direction must be"):
        K.MetricDef(id="X", label="x", definition="d", source="s", cadence="c",
                    target=1, direction="sideways")


def test_all_five_km_001_kras_are_declared():
    assert len(K.KRAS) == 5
    refs = " ".join(m.srs_ref for m in K.KRAS)
    for letter in "abcde":
        assert "OW2-KM-001(%s)" % letter in refs


def test_every_kra_carries_definition_source_and_cadence():
    # OW2-KM-001 requires all three visible beside the number.
    for m in K.KRAS:
        assert m.definition and m.source and m.cadence


def test_the_metric_dictionary_is_derived_not_maintained():
    d = K.metric_dictionary()
    assert len(d["metrics"]) == len(K.KRAS)
    assert {m["id"] for m in d["metrics"]} == {m.id for m in K.KRAS}
    assert set(d["verdicts"]) == set(K.VERDICTS)
    assert "OW2-KM-007" in d["rule"]


def test_the_dictionary_explains_not_established_as_absence_of_evidence():
    text = K.metric_dictionary()["verdicts"][K.NOT_ESTABLISHED]
    assert "not a failure of the estate" in text
    assert "restore the missing read" in text


# ═══ the scorecard rollup ════════════════════════════════════════════════════

def board():
    return K.Scorecard((
        K.ratio(K.CRITICAL_CLOSURE, 10, 10),
        K.count(K.EXPOSED_CRITICAL, 0, not_evaluated=3,
                reasons=[("eu-west-1", "region unreachable")]),
        K.ratio(K.MFA_COVERAGE, 8, 10),
        K.ratio(K.DISCOVERY_COVERAGE, 5, 5, denominator_known=False),
    ))


def test_unestablished_metrics_are_counted_in_their_own_column():
    s = board()
    assert len(s.unestablished) == 2
    assert len(s.established) == 2


def test_the_summary_never_folds_unknowns_into_met():
    s = board().summary()
    assert "1 of 4 KRA targets met" in s
    assert "1 not met" in s
    assert "2 not established" in s


def test_the_summary_says_unknowns_are_neither_passes_nor_failures():
    assert "neither passes nor failures" in board().summary()


def test_a_fully_established_board_reads_plainly():
    s = K.Scorecard((K.ratio(K.MFA_COVERAGE, 10, 10),
                     K.count(K.EXPOSED_CRITICAL, 0))).summary()
    assert s == "2 of 2 KRA targets met."


def test_scorecard_lookup_by_id():
    assert board().by_id("KRA-C").definition is K.MFA_COVERAGE
    assert board().by_id("nope") is None


def test_scorecard_export_carries_the_dictionary_with_the_numbers():
    d = board().to_dict()
    assert d["not_established"] == 2
    assert len(d["metrics"]) == 4
    assert "dictionary" in d, "OW2-KM-002: the numbers travel with their definitions"
    assert d["metrics"][1]["population"]["reasons"][0]["subject"] == "eu-west-1"


def test_every_exported_metric_states_its_population():
    for m in board().to_dict()["metrics"]:
        assert m["population"]["described"]


def test_headline_of_an_unestablished_metric_shows_the_range():
    m = K.count(K.EXPOSED_CRITICAL, observed=0, not_evaluated=4,
                reasons=[("eu-west-1", "region unreachable")])
    h = m.headline()
    assert "NOT ESTABLISHED" in h
    assert "0–4" in h
    assert "Restore the missing read" in h
