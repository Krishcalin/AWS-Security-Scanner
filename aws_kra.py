#!/usr/bin/env python3
"""
aws_kra.py — KRA metrics that cannot report success they did not establish.

Implements OW2-KM-001 (the five KRA metrics, each with definition, data source and
cadence visible in-product), OW2-KM-002 (the exportable metric dictionary), and the
requirement the SRS is missing — proposed here as **OW2-KM-007**, see
``docs/KRA_METRICS.md``.

PURE: stdlib only, no boto3, no I/O, no ``now()``.

────────────────────────────────────────────────────────────────────────────────
THE DEFECT (review finding D3)
────────────────────────────────────────────────────────────────────────────────
Every KRA in FR-8 is a ratio or a count whose denominator comes from enumeration,
and **enumeration is exactly what fails when a permission is missing or a region is
unreachable**. So the failure mode is not noise, it is bias with a direction:

* Lose ``iam:ListUsers`` → the users without MFA cannot be counted → **MFA coverage
  reports 100%**, which is the target.
* Lose a region → its internet-exposed workloads cannot be seen → **exposed critical
  workloads reports 0**, which is the target.
* Lose ``organizations:ListAccounts`` → the denominator of asset-discovery coverage
  is unknown → **coverage reports 100% of the accounts we happened to know about.**

In every case the *reward for losing visibility is a better number*, and the number
is the one that reaches the BBSC. Nothing in OW2-SRS-001 forbids this. OW2-DT-008
measures discovery coverage and OW2-PA-006 flags thin forecast history, but no
requirement says a metric must state the population it was computed over, and none
says a refused read may not be reported as a pass.

────────────────────────────────────────────────────────────────────────────────
THE FIX: A VERDICT IS ONLY ASSERTED WHEN THE WHOLE INTERVAL SUPPORTS IT
────────────────────────────────────────────────────────────────────────────────
A metric computed over a partial population does not have a value, it has a
**range**. Both ends are computed:

    best   the value if everything unmeasured turned out compliant
    worst  the value if everything unmeasured turned out adverse

and the verdict follows from where that whole interval sits relative to the target:

    MET              the WORST end still meets the target  → true regardless
    NOT_MET          the BEST end still misses it          → true regardless
    NOT_ESTABLISHED  the interval straddles the target     → unmeasured data decides

This is what makes the asymmetry explicit, and the asymmetry is the whole point:
**NOT_MET survives incomplete data; MET does not.** Having already found three
exposed critical workloads, the target of zero is missed no matter what else was
unreadable. Having found none, nothing has been established at all. A product that
treats those two zeroes the same is the product this module exists not to be.

``NOT_ESTABLISHED`` is deliberately not a failure. It does not mean the estate is
bad; it means nobody knows, and it is reported in its own column so that fixing the
*permission* — not the estate — is the visible next action.

────────────────────────────────────────────────────────────────────────────────
THE DENOMINATOR CAN ITSELF BE UNKNOWN
────────────────────────────────────────────────────────────────────────────────
KRA (d), asset-discovery coverage, is measured against AWS Organizations
enumeration. If that call is refused there is no denominator, so the metric has no
range either — not even an infinite one. :data:`DENOMINATOR_UNKNOWN` is a distinct
state from an incomplete population, because a coverage metric quietly reporting
100% of the accounts it happened to hear about is the most confident wrong answer
in the whole set.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ── direction ────────────────────────────────────────────────────────────────
HIGHER_IS_BETTER = "higher-is-better"
LOWER_IS_BETTER = "lower-is-better"
DIRECTIONS = (HIGHER_IS_BETTER, LOWER_IS_BETTER)

# ── verdicts ─────────────────────────────────────────────────────────────────
MET = "MET"
NOT_MET = "NOT_MET"
NOT_ESTABLISHED = "NOT_ESTABLISHED"
VERDICTS = (MET, NOT_MET, NOT_ESTABLISHED)

DENOMINATOR_UNKNOWN = "denominator-unknown"
"""The authoritative population could not be enumerated at all. Distinct from an
incomplete population: there is no range to report, because there is no total."""

UNIT_PCT = "percent"
UNIT_COUNT = "count"


@dataclass(frozen=True)
class MetricDef:
    """One KRA, declared once.

    OW2-KM-001 requires the definition, data source and refresh cadence to be
    visible in-product; OW2-KM-002 requires an exportable, signed-off metric
    dictionary. Both are derived from this declaration rather than maintained
    separately, so the dictionary cannot drift from the metric it describes.
    """

    id: str
    label: str
    definition: str
    source: str
    cadence: str
    target: float
    direction: str
    unit: str = UNIT_PCT
    srs_ref: str = ""

    def __post_init__(self) -> None:
        if self.direction not in DIRECTIONS:
            raise ValueError("direction must be one of %s" % ", ".join(DIRECTIONS))
        if not self.definition or not self.source or not self.cadence:
            raise ValueError(
                "metric %r needs a definition, a source and a cadence: OW2-KM-001 "
                "requires all three visible beside the number, and a metric that "
                "cannot say where it came from cannot be audited" % (self.id,))

    def meets(self, value: float) -> bool:
        if self.direction == HIGHER_IS_BETTER:
            return value >= self.target
        return value <= self.target


@dataclass(frozen=True)
class Population:
    """The denominator, made part of the metric rather than a footnote."""

    counted: int
    not_evaluated: int = 0
    reasons: Tuple[Tuple[str, str], ...] = ()
    denominator_known: bool = True

    @property
    def total(self) -> int:
        return self.counted + self.not_evaluated

    @property
    def complete(self) -> bool:
        return self.denominator_known and self.not_evaluated == 0

    @property
    def coverage(self) -> float:
        if not self.denominator_known:
            return 0.0
        return 1.0 if not self.total else self.counted / self.total

    def describe(self) -> str:
        if not self.denominator_known:
            return ("the authoritative population could not be enumerated, so this "
                    "metric has no denominator")
        if self.complete:
            return "computed over all %d members of the population" % self.total
        return ("computed over %d of %d members (%.0f%% of the population); %d could "
                "not be evaluated"
                % (self.counted, self.total, 100.0 * self.coverage, self.not_evaluated))


@dataclass(frozen=True)
class Metric:
    """A computed KRA, its range, and a verdict only where one is warranted."""

    definition: MetricDef
    value: Optional[float]
    best: Optional[float]
    worst: Optional[float]
    population: Population
    verdict: str
    reason: str = ""

    @property
    def established(self) -> bool:
        return self.verdict != NOT_ESTABLISHED

    @property
    def target_met(self) -> bool:
        """Never True unless the whole interval supports it. A caller that treats a
        falsy result as failure is wrong, which is why :attr:`verdict` is the field
        reports should render."""
        return self.verdict == MET

    def headline(self) -> str:
        d = self.definition
        if self.value is None:
            return "%s: not established — %s" % (d.label, self.reason)
        shown = ("%.1f%%" % self.value if d.unit == UNIT_PCT else "%g" % self.value)
        line = "%s: %s (target %s%s)" % (
            d.label, shown,
            "%.0f%%" % d.target if d.unit == UNIT_PCT else "%g" % d.target,
            "" if d.direction == HIGHER_IS_BETTER else " or fewer")
        if self.verdict == NOT_ESTABLISHED:
            rng = ("%.1f%%–%.1f%%" % (self.worst, self.best) if d.unit == UNIT_PCT
                   else "%g–%g" % (self.best, self.worst))
            line += " — NOT ESTABLISHED: the true value lies in %s. %s" % (
                rng, self.reason)
        elif self.verdict == NOT_MET:
            line += " — not met"
        else:
            line += " — met"
        return line

    def to_dict(self) -> dict:
        return {
            "id": self.definition.id,
            "label": self.definition.label,
            "definition": self.definition.definition,
            "source": self.definition.source,
            "cadence": self.definition.cadence,
            "target": self.definition.target,
            "direction": self.definition.direction,
            "unit": self.definition.unit,
            "srs_ref": self.definition.srs_ref,
            "value": self.value,
            "range_best": self.best,
            "range_worst": self.worst,
            "verdict": self.verdict,
            "reason": self.reason,
            "population": {
                "counted": self.population.counted,
                "not_evaluated": self.population.not_evaluated,
                "coverage_pct": round(100.0 * self.population.coverage, 1),
                "complete": self.population.complete,
                "denominator_known": self.population.denominator_known,
                "described": self.population.describe(),
                "reasons": [{"subject": s, "reason": r}
                            for s, r in self.population.reasons],
            },
            "headline": self.headline(),
        }


def _verdict(d: MetricDef, best: float, worst: float,
             pop: Population) -> Tuple[str, str]:
    """MET only when the worst end still meets the target; NOT_MET only when the
    best end still misses it. Anything else is undecided by the data."""
    if d.meets(worst):
        return MET, ""
    if not d.meets(best):
        return NOT_MET, ""
    return NOT_ESTABLISHED, (
        "%s, and the unevaluated remainder is enough to decide the target either "
        "way. Restore the missing read rather than reading this as a pass."
        % pop.describe())


def ratio(
    d: MetricDef,
    compliant: int,
    counted: int,
    not_evaluated: int = 0,
    reasons: Sequence[Tuple[str, str]] = (),
    denominator_known: bool = True,
) -> Metric:
    """A percentage metric over an enumerable population (MFA coverage, closure
    rate, discovery coverage).

    ``counted`` is how many members were actually evaluated; ``not_evaluated`` how
    many are known to exist but could not be read. Both ends of the range put the
    unevaluated members in the denominator — which is the step the naive
    calculation skips, and skipping it is what produces the flattering 100%.
    """
    if compliant > counted:
        raise ValueError("compliant (%d) cannot exceed counted (%d)"
                         % (compliant, counted))
    pop = Population(counted, not_evaluated, tuple(reasons), denominator_known)

    if not denominator_known:
        return Metric(d, None, None, None, pop, NOT_ESTABLISHED,
                      "the authoritative population could not be enumerated, so a "
                      "percentage of it cannot be computed — reporting the share of "
                      "the members that happened to be visible would be a claim "
                      "about a population nobody established")
    total = pop.total
    if total == 0:
        return Metric(d, None, None, None, pop, NOT_ESTABLISHED,
                      "the population is empty, so there is nothing to measure")

    observed = 100.0 * compliant / counted if counted else 0.0
    best = 100.0 * (compliant + not_evaluated) / total
    worst = 100.0 * compliant / total
    verdict, reason = _verdict(d, best, worst, pop)
    return Metric(d, round(observed, 1), round(best, 1), round(worst, 1),
                  pop, verdict, reason)


def count(
    d: MetricDef,
    observed: int,
    not_evaluated: int = 0,
    reasons: Sequence[Tuple[str, str]] = (),
    denominator_known: bool = True,
) -> Metric:
    """A count-of-adverse-things metric with a target ceiling (exposed critical
    workloads, target zero).

    ``not_evaluated`` is how many candidate subjects could not be checked. Each one
    could be adverse, so the worst end of the range is ``observed + not_evaluated``.
    Reporting ``observed`` alone as the answer is how "zero exposed workloads"
    becomes a statement about a region nobody could reach.
    """
    pop = Population(observed, not_evaluated, tuple(reasons), denominator_known)
    if not denominator_known:
        return Metric(d, None, None, None, pop, NOT_ESTABLISHED,
                      "the set of candidate subjects could not be enumerated, so a "
                      "count of the adverse ones is not bounded")
    best = float(observed)
    worst = float(observed + not_evaluated)
    verdict, reason = _verdict(d, best, worst, pop)
    return Metric(d, float(observed), best, worst, pop, verdict, reason)


# ══════════════════════════════════════════════════════════════════════════════
# The five KRAs of OW2-KM-001, declared once.
# ══════════════════════════════════════════════════════════════════════════════

CRITICAL_CLOSURE = MetricDef(
    id="KRA-A", label="Critical findings closed within SLA",
    definition=("Share of CRITICAL findings whose verified remediation occurred "
                "within 15 days of first detection. Verified means a later scan "
                "that provably executed the same check no longer observed it, not "
                "a ticket closure. Findings still open are counted in the "
                "denominator, because a rate over closed findings alone reaches "
                "100% the moment nothing closes."),
    source="findings table (first_seen_epoch, resolved_epoch) via aws_sla",
    cadence="recomputed every scan; reported monthly",
    target=100.0, direction=HIGHER_IS_BETTER, unit=UNIT_PCT,
    srs_ref="OW2-KM-001(a)")

EXPOSED_CRITICAL = MetricDef(
    id="KRA-B", label="Internet-exposed critical workloads",
    definition=("Count of workloads tagged crown-jewel or high criticality that are "
                "internet-reachable on an unconditioned path. Reachability requires "
                "all four exposure gates, not merely a security group allowing "
                "0.0.0.0/0."),
    source="security graph exposure oracle (aws_exposure) + criticality tags",
    cadence="recomputed every scan; reported monthly",
    target=0.0, direction=LOWER_IS_BETTER, unit=UNIT_COUNT,
    srs_ref="OW2-KM-001(b)")

MFA_COVERAGE = MetricDef(
    id="KRA-C", label="MFA coverage",
    definition=("Share of console-capable identities with MFA enabled. Identities "
                "that could not be enumerated are counted in the denominator, not "
                "dropped from it."),
    source="iam:ListUsers + iam:ListMFADevices across all organisation accounts",
    cadence="recomputed every scan; reported monthly",
    target=100.0, direction=HIGHER_IS_BETTER, unit=UNIT_PCT,
    srs_ref="OW2-KM-001(c)")

DISCOVERY_COVERAGE = MetricDef(
    id="KRA-D", label="Cloud asset discovery coverage",
    definition=("Share of accounts in the AWS Organization that were successfully "
                "enumerated. The denominator is Organizations enumeration; if that "
                "call is refused the metric is not established, because the share "
                "of the accounts we happened to hear about is not a coverage "
                "figure."),
    source="organizations:ListAccounts vs accounts actually scanned",
    cadence="recomputed every scan; reported monthly",
    target=100.0, direction=HIGHER_IS_BETTER, unit=UNIT_PCT,
    srs_ref="OW2-KM-001(d), OW2-DT-008")

ATTACK_PATH_REDUCTION = MetricDef(
    id="KRA-E", label="Attack-path reduction",
    definition=("Month-on-month reduction in the count of paths from an internet "
                "node to a crown-jewel asset. Computed only when both months were "
                "measured over comparable scope; a scope change is not a reduction."),
    source="aws_correlate ranked attack paths, month-over-month",
    cadence="monthly",
    target=0.0, direction=HIGHER_IS_BETTER, unit=UNIT_PCT,
    srs_ref="OW2-KM-001(e), OW2-DT-004")

KRAS: Tuple[MetricDef, ...] = (CRITICAL_CLOSURE, EXPOSED_CRITICAL, MFA_COVERAGE,
                               DISCOVERY_COVERAGE, ATTACK_PATH_REDUCTION)


def metric_dictionary(metrics: Sequence[MetricDef] = KRAS) -> dict:
    """The signed-off metric dictionary OW2-KM-002 requires.

    Derived from the declarations rather than maintained beside them, so the
    dictionary and the metric cannot disagree about what a number means.
    """
    return {
        "metrics": [
            {"id": m.id, "label": m.label, "definition": m.definition,
             "source": m.source, "cadence": m.cadence, "target": m.target,
             "direction": m.direction, "unit": m.unit, "srs_ref": m.srs_ref}
            for m in metrics
        ],
        "verdicts": {
            MET: "The target is met, and would still be met if every unevaluated "
                 "member turned out adverse.",
            NOT_MET: "The target is missed, and would still be missed if every "
                     "unevaluated member turned out compliant.",
            NOT_ESTABLISHED: "The unevaluated remainder is large enough to decide "
                             "the target either way. This is not a failure of the "
                             "estate; it is an absence of evidence, and the "
                             "remedy is to restore the missing read.",
        },
        "rule": (
            "Proposed OW2-KM-007: every metric states the population it was "
            "computed over and enumerates what could not be evaluated, with the "
            "reason. A check whose read was refused is never reported as passing."),
    }


@dataclass(frozen=True)
class Scorecard:
    """A set of KRAs reported together, with the honest summary line."""

    metrics: Tuple[Metric, ...]

    def by_id(self, mid: str) -> Optional[Metric]:
        for m in self.metrics:
            if m.definition.id == mid:
                return m
        return None

    @property
    def established(self) -> Tuple[Metric, ...]:
        return tuple(m for m in self.metrics if m.established)

    @property
    def unestablished(self) -> Tuple[Metric, ...]:
        return tuple(m for m in self.metrics if not m.established)

    def summary(self) -> str:
        """The line that goes above a KRA table.

        Counts NOT_ESTABLISHED separately rather than folding it into either
        column — folding it into 'met' is the defect; folding it into 'not met'
        would blame the estate for a permissions problem.
        """
        met = sum(1 for m in self.metrics if m.verdict == MET)
        missed = sum(1 for m in self.metrics if m.verdict == NOT_MET)
        unknown = len(self.unestablished)
        parts = ["%d of %d KRA targets met" % (met, len(self.metrics))]
        if missed:
            parts.append("%d not met" % missed)
        if unknown:
            parts.append(
                "%d not established — the data needed to decide them was not "
                "readable, so they are neither passes nor failures" % unknown)
        return "; ".join(parts) + "."

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "established": len(self.established),
            "not_established": len(self.unestablished),
            "metrics": [m.to_dict() for m in self.metrics],
            "dictionary": metric_dictionary(tuple(m.definition for m in self.metrics)),
        }
