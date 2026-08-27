#!/usr/bin/env python3
"""
aws_trend.py — time-series collection, data sufficiency, and forecasts that
refuse to exist before their evidence does.

Implements the half of FR-4 that can be built today (OW2-PA-001 time-series
materialisation, OW2-PA-006 the data-sufficiency indicator, OW2-PA-007 in-product
accuracy tracking) and fixes review defect D6.

PURE: stdlib only, no boto3, no I/O, no ``now()``.

────────────────────────────────────────────────────────────────────────────────
THE DEFECT (review finding D6)
────────────────────────────────────────────────────────────────────────────────
AD-04 requires "≥6 months of clean trend data post FR-1/FR-2 go-live before
forecast outputs are treated as production-grade." FR-4 is scheduled into II-C,
months 6–12 — **which begins exactly when that data starts accumulating.**

So every forecast produced inside Phase II carries the OW2-PA-006 label
"indicative — insufficient history": an honest label, on a feature nobody should
act on, attached to the deliverable most likely to be shown to a board.

The sequencing fix is to split FR-4 (see ``docs/FORECAST_SEQUENCING.md``). This
module is the enforcement: collection ships now, and the forecast **cannot** be
emitted early, because the code refuses rather than labels.

────────────────────────────────────────────────────────────────────────────────
WHY REFUSING BEATS LABELLING
────────────────────────────────────────────────────────────────────────────────
OW2-PA-006 says thin outputs "shall be labelled". A label is a string beside a
number, and the number is what gets copied into the slide. This is the same
argument that withheld the posture letter grade and that made a KRA report
NOT_ESTABLISHED instead of a flattering percentage: **the caveat travels
separately from the value, and only the value survives the journey.**

So below :data:`MIN_FITTABLE` usable periods there is no projected value at all —
``Projection.value is None``. What *is* still reported is the observed series,
because what was measured is a fact and only the extrapolation is a claim.

────────────────────────────────────────────────────────────────────────────────
SIX MONTHS ELAPSED IS NOT SIX MONTHS OF DATA
────────────────────────────────────────────────────────────────────────────────
AD-04 says *clean* trend data, and the distinction is load-bearing. A period in
which the scan could not reach half the estate contributes a data point that is an
artefact of what was not seen, not a measurement of the estate. Counting it toward
sufficiency means a forecast built on six months of holes reports itself as
production-grade.

:class:`Series` therefore counts **usable periods**, not elapsed calendar time. A
period is usable when it carries a value and its scan coverage met
:attr:`Series.min_coverage` — which is the D3 rule reaching forward into FR-4, and
the reason these two defects share a fix.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

DAY = 86_400

# ── sufficiency tiers ────────────────────────────────────────────────────────
INSUFFICIENT = "insufficient"
"""Too few usable periods to fit anything. No projected value is produced."""

INDICATIVE = "indicative"
"""Fittable, but short of AD-04's window. Projected with a band and the
OW2-PA-006 label. Never a KRA input."""

PRODUCTION = "production"
"""Meets AD-04. Only this tier may be referenced by a KRA (OW2-PA-007)."""

TIERS = (INSUFFICIENT, INDICATIVE, PRODUCTION)

MIN_FITTABLE = 3
"""Fewer than three usable points cannot distinguish a trend from a pair of
readings, so no line is fitted at all."""

AD_04_PERIODS = 6
"""AD-04's six months, expressed in monthly periods."""

INSUFFICIENT_NOTE = (
    "Not enough usable history to project. The observed series is reported "
    "because what was measured is a fact; the extrapolation is withheld because "
    "it would be a claim.")

INDICATIVE_LABEL = "indicative — insufficient history"
"""OW2-PA-006, verbatim."""


@dataclass(frozen=True)
class Period:
    """One observation window in a series."""

    start_epoch: int
    end_epoch: int
    value: Optional[float] = None
    coverage: float = 1.0
    reason: str = ""

    def __post_init__(self) -> None:
        if self.end_epoch <= self.start_epoch:
            raise ValueError("period end must be after its start")
        if not (0.0 <= self.coverage <= 1.0):
            raise ValueError("coverage must be in [0, 1]")
        if self.value is None and not self.reason:
            raise ValueError(
                "a period with no value must say why; an unexplained gap is "
                "indistinguishable from a period that genuinely measured nothing")

    def usable(self, min_coverage: float) -> bool:
        return self.value is not None and self.coverage >= min_coverage

    def unusable_reason(self, min_coverage: float) -> str:
        if self.value is None:
            return self.reason
        if self.coverage < min_coverage:
            return ("scan coverage was %.0f%%, below the %.0f%% floor — this point "
                    "measures what was reachable, not the estate"
                    % (100.0 * self.coverage, 100.0 * min_coverage))
        return ""


@dataclass(frozen=True)
class Series:
    """A metric over time, and an honest count of how much of it is usable."""

    metric: str
    periods: Tuple[Period, ...]
    min_periods: int = AD_04_PERIODS
    min_coverage: float = 0.9
    unit: str = ""

    def __post_init__(self) -> None:
        if self.min_periods < 1:
            raise ValueError("min_periods must be positive")
        object.__setattr__(self, "periods",
                           tuple(sorted(self.periods, key=lambda p: p.start_epoch)))

    @property
    def usable(self) -> Tuple[Period, ...]:
        return tuple(p for p in self.periods if p.usable(self.min_coverage))

    @property
    def gaps(self) -> Tuple[Tuple[int, str], ...]:
        """``(period_start, reason)`` for every period that does not count."""
        return tuple((p.start_epoch, p.unusable_reason(self.min_coverage))
                     for p in self.periods if not p.usable(self.min_coverage))

    @property
    def sufficiency(self) -> str:
        n = len(self.usable)
        if n < MIN_FITTABLE:
            return INSUFFICIENT
        return INDICATIVE if n < self.min_periods else PRODUCTION

    @property
    def production_grade(self) -> bool:
        return self.sufficiency == PRODUCTION

    def describe(self) -> str:
        n, total = len(self.usable), len(self.periods)
        line = ("%d of %d periods usable against a %d-period requirement"
                % (n, total, self.min_periods))
        if self.gaps:
            line += ("; %d period(s) excluded — elapsed time is not the same as "
                     "collected data" % len(self.gaps))
        return line


def _fit(points: Sequence[Tuple[float, float]]) -> Tuple[float, float]:
    """Ordinary least squares. Returns ``(slope, intercept)``.

    OW2-PA-004 requires transparent statistical methods for v1; this is the whole
    of the model, and it is stated in :attr:`Projection.method` so nobody has to
    take the number on trust.
    """
    n = len(points)
    mx = sum(x for x, _ in points) / n
    my = sum(y for _, y in points) / n
    denom = sum((x - mx) ** 2 for x, _ in points)
    if denom == 0:
        return 0.0, my
    slope = sum((x - mx) * (y - my) for x, y in points) / denom
    return slope, my - slope * mx


@dataclass(frozen=True)
class Projection:
    """A forward estimate, or an explicit refusal to make one."""

    metric: str
    horizon_days: int
    value: Optional[float]
    low: Optional[float]
    high: Optional[float]
    sufficiency: str
    drivers: Tuple[str, ...] = ()
    method: str = ""
    label: str = ""
    reason: str = ""
    observed: Tuple[float, ...] = ()
    usable_periods: int = 0

    @property
    def produced(self) -> bool:
        return self.value is not None

    @property
    def kra_eligible(self) -> bool:
        """OW2-PA-007: only a production-grade forecast may be referenced by a KRA.
        Checked as a property so a scorecard cannot wire one in by accident."""
        return self.produced and self.sufficiency == PRODUCTION

    def headline(self) -> str:
        if not self.produced:
            return "%s: no projection — %s" % (self.metric, self.reason)
        band = ""
        if self.low is not None and self.high is not None:
            band = " (range %.1f to %.1f)" % (self.low, self.high)
        line = ("%s projected to reach %.1f in %d days%s. Drivers: %s."
                % (self.metric, self.value, self.horizon_days, band,
                   "; ".join(self.drivers)))
        if self.label:
            line += " %s — not eligible as a KRA input." % self.label.upper()
        return line

    def to_dict(self) -> dict:
        return {
            "metric": self.metric, "horizon_days": self.horizon_days,
            "value": self.value, "low": self.low, "high": self.high,
            "sufficiency": self.sufficiency, "label": self.label or None,
            "kra_eligible": self.kra_eligible, "drivers": list(self.drivers),
            "method": self.method, "reason": self.reason,
            "usable_periods": self.usable_periods,
            "headline": self.headline(),
        }


def project(series: Series, horizon_days: int = 30) -> Projection:
    """Extrapolate a series, or refuse.

    OW2-PA-003 forbids black-box scores without drivers, so :attr:`drivers` is
    never empty on a produced projection.
    """
    if horizon_days <= 0:
        raise ValueError("horizon_days must be positive")
    usable = series.usable
    tier = series.sufficiency
    observed = tuple(float(p.value) for p in usable)

    if tier == INSUFFICIENT:
        return Projection(
            series.metric, horizon_days, None, None, None, INSUFFICIENT,
            reason=("%s %s." % (INSUFFICIENT_NOTE, series.describe())),
            observed=observed, usable_periods=len(usable))

    points = [(float(p.end_epoch) / DAY, float(p.value)) for p in usable]
    slope, intercept = _fit(points)
    last_x = points[-1][0]
    x = last_x + horizon_days
    value = slope * x + intercept

    residuals = [abs(y - (slope * px + intercept)) for px, y in points]
    spread = max(residuals) if residuals else 0.0
    # The band widens with the horizon: extrapolating four periods out is not as
    # reliable as extrapolating one, and a constant band would imply it is.
    period_days = max(1.0, (points[-1][0] - points[0][0]) / max(1, len(points) - 1))
    widen = 1.0 + (horizon_days / period_days) / max(1, len(points))
    half = spread * widen

    drivers = _drivers(series, slope, period_days, observed)
    label = INDICATIVE_LABEL if tier == INDICATIVE else ""
    reason = ""
    if tier == INDICATIVE:
        reason = ("%d usable periods against the %d AD-04 requires; direction is "
                  "meaningful, magnitude is not settled"
                  % (len(usable), series.min_periods))

    return Projection(
        series.metric, horizon_days, round(value, 2),
        round(value - half, 2), round(value + half, 2), tier,
        drivers=drivers,
        method=("ordinary least squares over %d usable periods, band from maximum "
                "residual widened by horizon" % len(usable)),
        label=label, reason=reason, observed=observed, usable_periods=len(usable))


def _drivers(series: Series, slope: float, period_days: float,
             observed: Sequence[float]) -> Tuple[str, ...]:
    """Plain-language drivers (OW2-PA-003). Never empty."""
    out: List[str] = []
    per_period = slope * period_days
    if abs(per_period) < 1e-9:
        out.append("the measure has been flat across the usable periods")
    else:
        out.append("%s by about %.1f%s per period"
                   % ("rising" if per_period > 0 else "falling",
                      abs(per_period), (" " + series.unit) if series.unit else ""))
    if len(observed) >= 4:
        recent = observed[-2] - observed[-3]
        earlier = observed[1] - observed[0]
        if abs(recent) > abs(earlier) * 1.5:
            out.append("the rate of change has accelerated in recent periods")
        elif abs(recent) * 1.5 < abs(earlier):
            out.append("the rate of change has slowed in recent periods")
    if series.gaps:
        out.append("%d period(s) were excluded as unusable, so the fit rests on "
                   "fewer observations than the calendar suggests" % len(series.gaps))
    return tuple(out)


# ══════════════════════════════════════════════════════════════════════════════
# Accuracy tracking (OW2-PA-007)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Prediction:
    """A projection recorded at the time it was made, for later scoring."""

    metric: str
    made_at_epoch: int
    target_epoch: int
    predicted: float
    low: Optional[float] = None
    high: Optional[float] = None
    sufficiency: str = INDICATIVE

    def resolved_at(self, now_epoch: int) -> bool:
        return int(now_epoch) >= int(self.target_epoch)


@dataclass(frozen=True)
class Accuracy:
    """Predicted vs actual, with its own sufficiency question.

    OW2-PA-007 exists "to build executive confidence before KRAs reference
    forecasts". An accuracy figure over two resolved predictions builds false
    confidence, so this refuses on the same principle the forecast does.
    """

    scored: int
    within_band: int
    mean_abs_error: Optional[float]
    unresolved: int
    sufficient: bool
    reason: str = ""

    @property
    def band_hit_rate(self) -> Optional[float]:
        if not self.sufficient or not self.scored:
            return None
        return round(100.0 * self.within_band / self.scored, 1)

    def headline(self) -> str:
        if not self.sufficient:
            return "Forecast accuracy: not established — %s" % self.reason
        return ("Forecast accuracy: %.1f%% of predictions landed inside their stated "
                "band across %d resolved forecasts (mean absolute error %.2f). %d "
                "still unresolved."
                % (self.band_hit_rate, self.scored, self.mean_abs_error,
                   self.unresolved))


def accuracy(pairs: Sequence[Tuple[Prediction, Optional[float]]],
             now_epoch: int, min_scored: int = MIN_FITTABLE) -> Accuracy:
    """Score resolved predictions against what actually happened.

    ``pairs`` is ``(prediction, actual_or_None)``. A prediction whose target date
    has not arrived is unresolved and is never scored as a miss — counting a
    pending forecast as wrong is as dishonest as counting it as right.
    """
    scored = 0
    hits = 0
    errors: List[float] = []
    unresolved = 0
    for pred, actual in pairs:
        if actual is None or not pred.resolved_at(now_epoch):
            unresolved += 1
            continue
        scored += 1
        errors.append(abs(actual - pred.predicted))
        if pred.low is not None and pred.high is not None:
            if pred.low <= actual <= pred.high:
                hits += 1
    if scored < min_scored:
        return Accuracy(scored, hits, None, unresolved, False,
                        reason=("only %d forecast(s) have resolved; at least %d are "
                                "needed before an accuracy figure means anything"
                                % (scored, min_scored)))
    return Accuracy(scored, hits, round(sum(errors) / scored, 2), unresolved, True)
