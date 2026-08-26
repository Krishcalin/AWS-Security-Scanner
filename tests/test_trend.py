"""Forecasts that refuse to exist before their evidence does.

THE DEFECT (review finding D6)
-------------------------------
AD-04 requires six months of clean trend data before forecasts are production-grade.
FR-4 is scheduled into II-C, months 6-12 -- which begins exactly when that data
starts accumulating. So every forecast inside Phase II carries the OW2-PA-006 label
"indicative - insufficient history": an honest label, on a feature nobody should act
on, attached to the deliverable most likely to be shown to a board.

WHY REFUSING BEATS LABELLING
-----------------------------
A label is a string beside a number, and the number is what gets copied into the
slide. This is the same argument that withheld the posture letter grade and that
made a KRA report NOT_ESTABLISHED rather than a flattering percentage: the caveat
travels separately from the value, and only the value survives the journey.

SIX MONTHS ELAPSED IS NOT SIX MONTHS OF DATA
---------------------------------------------
AD-04 says CLEAN trend data. A period in which the scan reached half the estate
contributes an artefact of what was not seen. `test_a_low_coverage_period_does_not_
count_toward_sufficiency` is the D3 rule reaching forward into FR-4, and it is why
these two defects share a fix.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_trend as T  # noqa: E402

DAY = T.DAY
T0 = 1_700_000_000
MONTH = 30 * DAY


def period(i, value, coverage=1.0, reason=""):
    return T.Period(T0 + i * MONTH, T0 + (i + 1) * MONTH, value, coverage, reason)


def series(values, min_periods=T.AD_04_PERIODS, **kw):
    return T.Series("open critical findings",
                    tuple(period(i, v) for i, v in enumerate(values)),
                    min_periods=min_periods, unit="findings", **kw)


# ═══ refusing, not labelling ═════════════════════════════════════════════════

def test_two_points_produce_no_projection_at_all():
    p = T.project(series([10, 12]))
    assert p.sufficiency == T.INSUFFICIENT
    assert p.value is None and p.low is None and p.high is None
    assert not p.produced


def test_the_refusal_explains_itself_and_still_reports_what_was_measured():
    p = T.project(series([10, 12]))
    assert "extrapolation is withheld because it would be a claim" in p.reason
    assert p.observed == (10.0, 12.0), (
        "what was measured is a fact and is still reported; only the forecast is "
        "withheld")


def test_the_headline_of_a_refusal_carries_no_number():
    h = T.project(series([10, 12])).headline()
    assert "no projection" in h
    assert "projected to reach" not in h


def test_three_points_are_the_minimum_that_fits_anything():
    assert T.MIN_FITTABLE == 3
    assert T.project(series([10, 12, 14])).produced


# ═══ the three tiers ═════════════════════════════════════════════════════════

def test_short_history_is_indicative_and_carries_the_pa_006_label():
    p = T.project(series([10, 12, 14, 16]))          # 4 of 6
    assert p.sufficiency == T.INDICATIVE
    assert p.label == T.INDICATIVE_LABEL
    assert p.produced
    assert "magnitude is not settled" in p.reason


def test_ad_04_window_reached_is_production_grade():
    p = T.project(series([10, 12, 14, 16, 18, 20]))  # 6 of 6
    assert p.sufficiency == T.PRODUCTION
    assert p.label == ""


def test_only_a_production_forecast_may_feed_a_kra():
    # OW2-PA-007: accuracy must be demonstrated before KRAs reference forecasts.
    assert not T.project(series([10, 12, 14, 16])).kra_eligible
    assert T.project(series([10, 12, 14, 16, 18, 20])).kra_eligible


def test_a_refusal_is_never_kra_eligible():
    assert not T.project(series([10, 12])).kra_eligible


def test_an_indicative_headline_says_it_cannot_feed_a_kra():
    h = T.project(series([10, 12, 14, 16])).headline()
    assert T.INDICATIVE_LABEL.upper() in h
    assert "not eligible as a KRA input" in h


# ═══ elapsed time is not collected data ══════════════════════════════════════

def test_a_low_coverage_period_does_not_count_toward_sufficiency():
    # Six months elapsed, but two months measured half the estate.
    ps = (period(0, 10), period(1, 12), period(2, 14, coverage=0.5),
          period(3, 16, coverage=0.4), period(4, 18), period(5, 20))
    s = T.Series("m", ps, min_periods=6)
    assert len(s.periods) == 6
    assert len(s.usable) == 4
    assert s.sufficiency == T.INDICATIVE, (
        "a forecast built on six months of holes must not report itself as "
        "production-grade")


def test_the_excluded_period_says_why_it_was_excluded():
    s = T.Series("m", (period(0, 10), period(1, 12, coverage=0.5)), min_periods=6)
    _, reason = s.gaps[0]
    assert "below the 90% floor" in reason
    assert "what was reachable, not the estate" in reason


def test_a_missing_period_must_carry_a_reason():
    with pytest.raises(ValueError, match="unexplained gap"):
        T.Period(T0, T0 + MONTH, None)


def test_a_missing_period_is_excluded_with_its_stated_reason():
    s = T.Series("m", (period(0, 10), period(1, 12),
                       T.Period(T0 + 2 * MONTH, T0 + 3 * MONTH, None,
                                reason="no scan ran during the change freeze")),
                 min_periods=6)
    assert len(s.usable) == 2
    assert "change freeze" in s.gaps[0][1]


def test_the_series_description_distinguishes_elapsed_from_collected():
    s = T.Series("m", (period(0, 10), period(1, 12, coverage=0.2)), min_periods=6)
    d = s.describe()
    assert "1 of 2 periods usable" in d
    assert "elapsed time is not the same as collected data" in d


def test_coverage_floor_is_configurable():
    ps = (period(0, 10), period(1, 12, coverage=0.8), period(2, 14))
    assert len(T.Series("m", ps, min_coverage=0.9).usable) == 2
    assert len(T.Series("m", ps, min_coverage=0.7).usable) == 3


# ═══ the projection itself ═══════════════════════════════════════════════════

def test_a_rising_series_projects_upward():
    p = T.project(series([10, 12, 14, 16, 18, 20]), horizon_days=30)
    assert p.value > 20


def test_a_falling_series_projects_downward():
    p = T.project(series([20, 18, 16, 14, 12, 10]), horizon_days=30)
    assert p.value < 10


def test_a_flat_series_projects_flat_and_says_so():
    p = T.project(series([10, 10, 10, 10, 10, 10]))
    assert p.value == pytest.approx(10.0, abs=0.01)
    assert any("flat" in d for d in p.drivers)


def test_the_band_contains_the_point_estimate():
    p = T.project(series([10, 13, 12, 17, 16, 21]))
    assert p.low <= p.value <= p.high


def test_the_band_widens_with_the_horizon():
    s = series([10, 13, 12, 17, 16, 21])
    near = T.project(s, horizon_days=30)
    far = T.project(s, horizon_days=180)
    assert (far.high - far.low) > (near.high - near.low), (
        "extrapolating six periods out is not as reliable as one, and a constant "
        "band would imply it is")


def test_a_negative_horizon_is_rejected():
    with pytest.raises(ValueError, match="must be positive"):
        T.project(series([10, 12, 14]), horizon_days=0)


# ═══ explainability is mandatory (OW2-PA-003) ════════════════════════════════

def test_a_produced_projection_always_carries_drivers():
    for values in ([10, 12, 14], [10, 12, 14, 16, 18, 20], [5, 5, 5, 5, 5, 5]):
        p = T.project(series(values))
        assert p.drivers, "OW2-PA-003 forbids a black-box number"


def test_drivers_are_plain_language_with_a_direction_and_a_rate():
    d = T.project(series([10, 12, 14, 16, 18, 20])).drivers
    assert any("rising" in x and "per period" in x for x in d)


def test_acceleration_is_reported_when_present():
    d = T.project(series([10, 11, 12, 20, 30, 45])).drivers
    assert any("accelerated" in x for x in d)


def test_excluded_periods_are_named_as_a_driver():
    ps = (period(0, 10), period(1, 12), period(2, 14),
          period(3, 16, coverage=0.3), period(4, 18), period(5, 20))
    d = T.project(T.Series("m", ps, min_periods=6)).drivers
    assert any("excluded as unusable" in x for x in d)


def test_the_method_is_stated_rather_than_taken_on_trust():
    m = T.project(series([10, 12, 14, 16, 18, 20])).method
    assert "least squares" in m
    assert "6 usable periods" in m


def test_projection_is_pure_and_reproducible():
    s = series([10, 13, 12, 17, 16, 21])
    assert T.project(s, 30) == T.project(s, 30)


def test_to_dict_carries_the_eligibility_flag():
    d = T.project(series([10, 12, 14, 16])).to_dict()
    assert d["kra_eligible"] is False
    assert d["label"] == T.INDICATIVE_LABEL
    assert d["drivers"]


# ═══ accuracy tracking (OW2-PA-007) ══════════════════════════════════════════

def pred(target_days, predicted, low=None, high=None):
    return T.Prediction("m", T0, T0 + target_days * DAY, predicted, low, high)


def test_accuracy_refuses_on_too_few_resolved_forecasts():
    a = T.accuracy([(pred(30, 10, 8, 12), 11.0)], now_epoch=T0 + 60 * DAY)
    assert not a.sufficient
    assert a.band_hit_rate is None
    assert "before an accuracy figure means anything" in a.reason


def test_an_unresolved_prediction_is_never_scored_as_a_miss():
    # Counting a pending forecast as wrong is as dishonest as counting it as right.
    a = T.accuracy([(pred(30, 10, 8, 12), 11.0),
                    (pred(30, 10, 8, 12), 11.0),
                    (pred(30, 10, 8, 12), 11.0),
                    (pred(365, 99, 90, 110), None)], now_epoch=T0 + 60 * DAY)
    assert a.scored == 3
    assert a.unresolved == 1
    assert a.sufficient


def test_a_prediction_whose_date_has_not_arrived_is_unresolved():
    a = T.accuracy([(pred(365, 10, 8, 12), 11.0)], now_epoch=T0 + 30 * DAY)
    assert a.scored == 0 and a.unresolved == 1


def test_band_hit_rate_counts_only_predictions_inside_their_band():
    ps = [(pred(30, 10, 8, 12), 11.0),
          (pred(30, 10, 8, 12), 20.0),
          (pred(30, 10, 8, 12), 9.0),
          (pred(30, 10, 8, 12), 9.5)]
    a = T.accuracy(ps, now_epoch=T0 + 60 * DAY)
    assert a.scored == 4 and a.within_band == 3
    assert a.band_hit_rate == 75.0


def test_mean_absolute_error_is_reported():
    ps = [(pred(30, 10, 8, 12), 12.0),
          (pred(30, 10, 8, 12), 8.0),
          (pred(30, 10, 8, 12), 10.0)]
    a = T.accuracy(ps, now_epoch=T0 + 60 * DAY)
    assert a.mean_abs_error == pytest.approx(1.33, abs=0.01)


def test_the_accuracy_headline_reports_the_unresolved_count():
    ps = [(pred(30, 10, 8, 12), 11.0)] * 3 + [(pred(365, 1, 0, 2), None)]
    h = T.accuracy(ps, now_epoch=T0 + 60 * DAY).headline()
    assert "1 still unresolved" in h


def test_an_unsufficient_accuracy_headline_says_not_established():
    h = T.accuracy([], now_epoch=T0).headline()
    assert "not established" in h
