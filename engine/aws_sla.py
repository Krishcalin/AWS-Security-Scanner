#!/usr/bin/env python3
"""
aws_sla.py — remediation SLA clocks, MTTR, and pre-breach warning.

Implements OW2-AR-031 (per-severity SLA timers, paused only by an approved
exception), OW2-AR-032 (escalation thresholds), OW2-CC-014 (MTTR with its
definition attached), OW2-PA-005 (SLA-breach risk surfaced *before* the breach)
and the closure half of OW2-KM-001(a).

PURE: stdlib only, no boto3, no I/O, and **no ``now()``** — the caller supplies
the clock. That is not stylistic. An SLA state that reads the wall clock is not
reproducible, so the same finding renders differently in a report generated twice,
and no auditor can ever recompute a published KRA. Every function here is a pure
function of (finding, policy, waiver windows, now).

────────────────────────────────────────────────────────────────────────────────
WHY THIS CAN BE BUILT HONESTLY ON WHAT ALREADY EXISTS
────────────────────────────────────────────────────────────────────────────────
OW2-AR-030 requires that a finding reach *Remediated* only on rescan verification,
never on ticket closure. ``aws_state`` already does this and does it more strictly
than the SRS asks: the resolve transition is **coverage-gated** — a finding closes
only when a scan that demonstrably executed that check on that account/region
failed to re-observe it. A partial scan cannot mass-resolve checks it never ran.

So ``resolved_epoch`` is a verified-remediation timestamp, not a workflow event,
and an MTTR computed from it is measuring the thing it claims to measure. This
module would be dishonest built on any weaker signal, and that is worth stating
because MTTR is the number most often quietly computed from ticket closure.

────────────────────────────────────────────────────────────────────────────────
THE DENOMINATOR
────────────────────────────────────────────────────────────────────────────────
An MTTR over closed findings is a survivor statistic. The findings that take
longest are disproportionately still open, so they are absent from the mean, and
MTTR *improves* as remediation stalls. :class:`MttrReport` therefore carries
``excluded_open`` and the oldest still-open age per band, and
:meth:`MttrReport.caveat` renders them. A caller that prints the mean without the
excluded count is publishing a number that moves the wrong way under stress.

Findings whose severity has no policy entry are ``NO_POLICY`` — never assigned a
default. Inventing a 90-day clock for an unrecognised band would create a
compliant-looking timer for something nobody agreed to.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

DAY = 86_400

# Appendix A of OW2-SRS-001. Configurable per OW2-AR-031; these are the defaults.
DEFAULT_SLA_DAYS: Dict[str, int] = {
    "CRITICAL": 15,
    "HIGH": 30,
    "MEDIUM": 60,
    "LOW": 90,
}

# ── states ───────────────────────────────────────────────────────────────────
WITHIN = "within"
APPROACHING = "approaching"      # past the escalation threshold, not yet breached
BREACHED = "breached"
PAUSED = "paused"                # under a live approved exception
CLOSED_IN_SLA = "closed-in-sla"
CLOSED_LATE = "closed-late"
NO_POLICY = "no-policy"

OPEN_STATES = (WITHIN, APPROACHING, BREACHED, PAUSED)
STATES = OPEN_STATES + (CLOSED_IN_SLA, CLOSED_LATE, NO_POLICY)

MTTR_DEFINITION = (
    "Mean elapsed time from a finding's first detection to its verified "
    "remediation, where verified means a later scan that provably executed the "
    "same check no longer observed it. Time spent under an approved, unexpired "
    "exception is subtracted. Findings still open are excluded from the mean and "
    "counted separately, because the slowest remediations are the ones most likely "
    "to still be open."
)


@dataclass(frozen=True)
class SlaPolicy:
    """Per-severity remediation windows and the escalation threshold."""

    days: Mapping[str, int] = None
    escalate_at: float = 0.75

    def __post_init__(self) -> None:
        object.__setattr__(self, "days", dict(self.days or DEFAULT_SLA_DAYS))
        if not (0.0 < self.escalate_at <= 1.0):
            raise ValueError("escalate_at must be in (0, 1]")
        for sev, d in self.days.items():
            if int(d) <= 0:
                raise ValueError("SLA for %s must be positive, got %r" % (sev, d))

    def window(self, severity: str) -> Optional[int]:
        d = self.days.get((severity or "").upper())
        return None if d is None else int(d) * DAY


def merge_windows(
    windows: Iterable[Tuple[int, Optional[int]]],
    clip_start: int,
    clip_end: int,
) -> Tuple[Tuple[int, int], ...]:
    """Clip exception windows to ``[clip_start, clip_end]`` and merge overlaps.

    Merging is what prevents two overlapping approved exceptions from pausing the
    clock twice — which would let an owner buy unlimited time by stacking
    exceptions, and would show up as an impossibly good MTTR rather than as an
    obvious abuse. An open-ended window (``end is None``) runs to ``clip_end``.
    """
    spans: List[Tuple[int, int]] = []
    for start, end in windows:
        s = max(int(start), int(clip_start))
        e = int(clip_end if end is None else min(int(end), clip_end))
        if e > s:
            spans.append((s, e))
    if not spans:
        return ()
    spans.sort()
    merged = [spans[0]]
    for s, e in spans[1:]:
        ls, le = merged[-1]
        if s <= le:
            merged[-1] = (ls, max(le, e))
        else:
            merged.append((s, e))
    return tuple(merged)


def paused_seconds(
    windows: Iterable[Tuple[int, Optional[int]]],
    clip_start: int,
    clip_end: int,
) -> int:
    return sum(e - s for s, e in merge_windows(windows, clip_start, clip_end))


@dataclass(frozen=True)
class SlaState:
    """One finding's clock. Every field is derivable from the inputs, so two runs
    over the same scan produce identical output."""

    finding_key: str
    severity: str
    state: str
    first_seen_epoch: int
    window_seconds: Optional[int]
    elapsed_seconds: int          # net of paused time
    raw_elapsed_seconds: int      # wall-clock since first detection, pauses ignored
    paused_seconds: int
    remaining_seconds: Optional[int]
    due_epoch: Optional[int]      # shifted forward by paused time
    closed_epoch: Optional[int]
    reason: str = ""

    @property
    def pct_elapsed(self) -> Optional[float]:
        if not self.window_seconds:
            return None
        return round(100.0 * self.elapsed_seconds / self.window_seconds, 1)

    @property
    def is_open(self) -> bool:
        return self.state in OPEN_STATES

    @property
    def breached(self) -> bool:
        return self.state in (BREACHED, CLOSED_LATE)

    @property
    def exception_assisted(self) -> bool:
        """Closed inside SLA ONLY because an exception paused the clock.

        This is review defect D4 made countable. The finding took longer than the
        window in wall-clock time; an approval is the sole reason it is not a
        breach. Legitimate or not, it must not be indistinguishable from a
        remediation that actually met the deadline."""
        return (self.state == CLOSED_IN_SLA and self.window_seconds is not None
                and self.raw_elapsed_seconds > self.window_seconds)

    @property
    def breach_deferred(self) -> bool:
        """Open, already past its window in wall-clock time, and paused.

        A breach being held off the books. OW2-KM-004 keeps these visible to audit
        in a register, but a register is not a metric and only metrics reach the
        BBSC."""
        return (self.state == PAUSED and self.window_seconds is not None
                and self.raw_elapsed_seconds > self.window_seconds)


def evaluate(
    finding,
    now_epoch: int,
    policy: Optional[SlaPolicy] = None,
    exception_windows: Sequence[Tuple[int, Optional[int]]] = (),
) -> SlaState:
    """Compute the SLA state of one finding.

    ``finding`` is duck-typed on ``finding_key``, ``severity``, ``first_seen_epoch``
    and ``resolved_epoch`` (mappings work too), matching the ``findings`` table.
    """
    policy = policy or SlaPolicy()
    key = _get(finding, "finding_key", "")
    sev = (_get(finding, "severity", "") or "").upper()
    first = int(_get(finding, "first_seen_epoch", 0) or 0)
    closed = _get(finding, "resolved_epoch", None)
    closed = int(closed) if closed else None
    status = (_get(finding, "status", "") or "").lower()
    if status == "resolved" and closed is None:
        # Resolved without a timestamp: the clock cannot be computed, and guessing
        # "now" would invent a remediation date that flatters the metric.
        return SlaState(key, sev, NO_POLICY, first, None, 0, 0, 0, None, None, None,
                        reason="finding is resolved but carries no resolved_epoch; "
                               "elapsed time is unknown and was not inferred")

    window = policy.window(sev)
    if window is None:
        return SlaState(key, sev, NO_POLICY, first, None, 0, 0, 0, None, None, closed,
                        reason="no SLA policy for severity %r; no default was "
                               "assumed" % (sev or "<empty>"))

    end = closed if closed is not None else int(now_epoch)
    paused = paused_seconds(exception_windows, first, end)
    raw_elapsed = max(0, end - first)
    elapsed = max(0, end - first - paused)
    due = first + window + paused
    remaining = due - end

    if closed is not None:
        state = CLOSED_IN_SLA if elapsed <= window else CLOSED_LATE
        return SlaState(key, sev, state, first, window, elapsed, raw_elapsed,
                        paused, remaining, due, closed)

    # Open. A live exception freezes the clock; it does not clear the breach that
    # already happened, so the breach check comes first (OW2-KM-004: an exception
    # never hides a finding).
    if elapsed > window:
        state, reason = BREACHED, "SLA window exceeded"
    elif _under_live_exception(exception_windows, end):
        state, reason = PAUSED, "clock paused by an approved, unexpired exception"
    elif elapsed >= window * policy.escalate_at:
        state = APPROACHING
        reason = ("past %d%% of the SLA window — escalation threshold reached"
                  % round(policy.escalate_at * 100))
    else:
        state, reason = WITHIN, ""
    return SlaState(key, sev, state, first, window, elapsed, raw_elapsed, paused,
                    remaining, due, None, reason)


def _under_live_exception(windows: Sequence[Tuple[int, Optional[int]]],
                          at: int) -> bool:
    for start, end in windows:
        if int(start) <= at and (end is None or at < int(end)):
            return True
    return False


def _get(obj, name: str, default=None):
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


@dataclass(frozen=True)
class BandMttr:
    severity: str
    mean_seconds: Optional[float]
    median_seconds: Optional[float]
    closed_count: int
    open_count: int
    breached_count: int
    oldest_open_seconds: Optional[int]

    @property
    def mean_days(self) -> Optional[float]:
        return None if self.mean_seconds is None else round(self.mean_seconds / DAY, 1)

    @property
    def median_days(self) -> Optional[float]:
        return None if self.median_seconds is None else round(self.median_seconds / DAY, 1)

    @property
    def oldest_open_days(self) -> Optional[float]:
        return (None if self.oldest_open_seconds is None
                else round(self.oldest_open_seconds / DAY, 1))


@dataclass(frozen=True)
class MttrReport:
    """MTTR by severity, carrying its own definition and its own caveat.

    OW2-CC-014 requires the definition to be displayed alongside the metric. It is
    a field here rather than a UI string so the number and its definition cannot
    drift apart across the API, the PDF and the dashboard.
    """

    bands: Tuple[BandMttr, ...]
    definition: str = MTTR_DEFINITION
    excluded_no_policy: int = 0

    def band(self, severity: str) -> Optional[BandMttr]:
        for b in self.bands:
            if b.severity == (severity or "").upper():
                return b
        return None

    @property
    def total_open(self) -> int:
        return sum(b.open_count for b in self.bands)

    @property
    def total_closed(self) -> int:
        return sum(b.closed_count for b in self.bands)

    def caveat(self) -> str:
        """The sentence that must accompany the mean. Never empty when it matters."""
        if not self.total_closed:
            return ("No findings have reached verified remediation in this scope, so "
                    "no MTTR can be computed.")
        bits = ["Computed over %d verified remediations." % self.total_closed]
        if self.total_open:
            worst = max((b.oldest_open_seconds or 0) for b in self.bands)
            bits.append(
                "%d findings are still open and are excluded from the mean; the "
                "oldest has been open %.0f days. MTTR falls when remediation stalls, "
                "because the slowest items stay in the excluded set."
                % (self.total_open, worst / DAY))
        if self.excluded_no_policy:
            bits.append("%d findings have no SLA policy for their severity and are "
                        "excluded entirely." % self.excluded_no_policy)
        return " ".join(bits)


def mttr(states: Iterable[SlaState],
         severities: Sequence[str] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")) -> MttrReport:
    """Aggregate SLA states into MTTR bands."""
    closed: Dict[str, List[int]] = {s: [] for s in severities}
    open_n: Dict[str, int] = {s: 0 for s in severities}
    breach: Dict[str, int] = {s: 0 for s in severities}
    oldest: Dict[str, Optional[int]] = {s: None for s in severities}
    no_policy = 0

    for st in states:
        if st.state == NO_POLICY:
            no_policy += 1
            continue
        sev = st.severity
        if sev not in closed:
            no_policy += 1
            continue
        if st.is_open:
            open_n[sev] += 1
            prev = oldest[sev]
            oldest[sev] = st.elapsed_seconds if prev is None else max(prev, st.elapsed_seconds)
            if st.state == BREACHED:
                breach[sev] += 1
        else:
            closed[sev].append(st.elapsed_seconds)
            if st.state == CLOSED_LATE:
                breach[sev] += 1

    bands = []
    for sev in severities:
        vals = sorted(closed[sev])
        mean = (sum(vals) / len(vals)) if vals else None
        med = _median(vals) if vals else None
        bands.append(BandMttr(sev, mean, med, len(vals), open_n[sev], breach[sev],
                              oldest[sev]))
    return MttrReport(tuple(bands), excluded_no_policy=no_policy)


def _median(sorted_vals: Sequence[int]) -> float:
    n = len(sorted_vals)
    mid = n // 2
    if n % 2:
        return float(sorted_vals[mid])
    return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0


def at_risk(states: Iterable[SlaState]) -> Tuple[SlaState, ...]:
    """Findings heading for a breach that has not happened yet (OW2-PA-005).

    Deliberately arithmetic, not predictive. A finding is at risk when its clock
    has passed the escalation threshold and it is still open. This is the useful
    half of breach prediction and needs none of the six months of history AD-04
    requires — an owner warned at 75% elapsed can still act, which is the point of
    the requirement. Trend-based forecasting belongs in FR-4 and should not
    pretend to be this.
    """
    risky = [s for s in states if s.state == APPROACHING]
    risky.sort(key=lambda s: (s.remaining_seconds if s.remaining_seconds is not None
                              else 0))
    return tuple(risky)


def breached(states: Iterable[SlaState]) -> Tuple[SlaState, ...]:
    out = [s for s in states if s.state == BREACHED]
    out.sort(key=lambda s: -(s.elapsed_seconds - (s.window_seconds or 0)))
    return tuple(out)


@dataclass(frozen=True)
class ClosureRate:
    """OW2-KM-001(a), reported so it cannot be quoted without its adjustment.

    Review defect D4: the SLA clock pauses under an approved exception
    (OW2-AR-031), so a CRITICAL finding remediated on day 200 against a 15-day
    window counts as closed-within-SLA when an exception covered the gap.
    Measured: one approval moves this metric from 0% to 100%.

    OW2-KM-004 keeps excepted findings in a register visible to audit, which is
    right and is not sufficient -- a register is not a metric, and only the metric
    reaches the BBSC under OW2-KM-002.

    The fix is not to forbid pausing; exceptions exist for real reasons and
    OW2-AR-031 requires them. It is that BOTH NUMBERS TRAVEL TOGETHER: `pct`
    honours exceptions, `unadjusted_pct` ignores them, and the gap between them is
    exactly how much of the headline is exception-derived. If they agree,
    exceptions are doing no work. :meth:`headline` renders both, so there is no
    code path that emits the flattering figure alone.
    """

    severity: str
    in_sla: int
    considered: int
    exception_assisted: int
    deferred_breaches: int

    @property
    def pct(self) -> float:
        """As measured, with exception pauses honoured."""
        return 0.0 if not self.considered else round(
            100.0 * self.in_sla / self.considered, 1)

    @property
    def unadjusted_pct(self) -> float:
        """What the rate would be if no exception had paused any clock."""
        if not self.considered:
            return 0.0
        return round(100.0 * (self.in_sla - self.exception_assisted)
                     / self.considered, 1)

    @property
    def exception_derived_points(self) -> float:
        """Percentage points of the headline attributable to approvals.

        Computed from the raw counts, not by subtracting two already-rounded
        percentages -- that route reports 33.4 where the answer is 33.3."""
        if not self.considered:
            return 0.0
        return round(100.0 * self.exception_assisted / self.considered, 1)

    def headline(self) -> str:
        if not self.considered:
            return ("No %s findings with an SLA policy in scope, so no closure rate "
                    "can be computed." % self.severity)
        line = ("%s findings closed within SLA: %.1f%% (%d of %d)"
                % (self.severity.title(), self.pct, self.in_sla, self.considered))
        if self.exception_assisted:
            line += (" -- but %.1f points of that come from %d closure%s that met "
                     "the deadline only because an approved exception paused the "
                     "clock. Unadjusted, the rate is %.1f%%."
                     % (self.exception_derived_points, self.exception_assisted,
                        "" if self.exception_assisted == 1 else "s",
                        self.unadjusted_pct))
        if self.deferred_breaches:
            line += (" A further %d open finding%s already past the window %s held "
                     "off the books by a live exception."
                     % (self.deferred_breaches,
                        "" if self.deferred_breaches == 1 else "s",
                        "is" if self.deferred_breaches == 1 else "are"))
        return line

    def to_dict(self) -> dict:
        return {"severity": self.severity, "pct": self.pct,
                "unadjusted_pct": self.unadjusted_pct,
                "exception_derived_points": self.exception_derived_points,
                "in_sla": self.in_sla, "considered": self.considered,
                "exception_assisted": self.exception_assisted,
                "deferred_breaches": self.deferred_breaches,
                "headline": self.headline()}


def closure_rate(states: Iterable[SlaState],
                 severity: str = "CRITICAL") -> ClosureRate:
    """OW2-KM-001(a): share of findings in a band closed inside the SLA window.

    ``considered`` counts every finding in the band that has a policy -- open ones
    included -- because a rate computed only over closed findings reaches 100% the
    moment nothing closes.
    """
    sev = (severity or "").upper()
    considered = in_sla = assisted = deferred = 0
    for s in states:
        if s.severity != sev or s.state == NO_POLICY:
            continue
        considered += 1
        if s.state == CLOSED_IN_SLA:
            in_sla += 1
            if s.exception_assisted:
                assisted += 1
        elif s.breach_deferred:
            deferred += 1
    return ClosureRate(sev, in_sla, considered, assisted, deferred)


@dataclass(frozen=True)
class ExceptionLoad:
    """How much SLA time the exception workflow is buying, and for whom.

    OW2-KM-003 requires a mandatory expiry and automatic re-opening on it. That
    stops an exception being FORMALLY permanent; it does not stop one being
    serially renewed, which is a permanent exception with better paperwork. The
    renewal chain is the pattern worth surfacing, and it is visible in the windows
    already stored -- a finding with six approvals had six separate decisions that
    each looked reasonable in isolation.
    """

    findings: int
    under_exception: int
    days_granted: int
    longest_chain: int
    perpetual: Tuple[str, ...] = ()
    perpetual_multiple: float = 2.0

    @property
    def rate(self) -> float:
        return 0.0 if not self.findings else round(
            100.0 * self.under_exception / self.findings, 1)

    def headline(self) -> str:
        if not self.findings:
            return "No findings in scope."
        bits = ["%d of %d findings are under an approved exception (%.1f%%), "
                "totalling %d exception-days granted."
                % (self.under_exception, self.findings, self.rate,
                   self.days_granted)]
        if self.longest_chain > 1:
            bits.append("The longest renewal chain is %d approvals on one finding."
                        % self.longest_chain)
        if self.perpetual:
            bits.append(
                "%d finding%s accumulated more than %.0fx %s SLA window in "
                "exception time, which is a permanent exception granted "
                "incrementally: %s."
                % (len(self.perpetual), "" if len(self.perpetual) == 1 else "s",
                   self.perpetual_multiple,
                   "its" if len(self.perpetual) == 1 else "their",
                   ", ".join(self.perpetual[:5])))
        return " ".join(bits)


def exception_load(
    states: Iterable[SlaState],
    windows_by_key: Optional[Mapping[str, Sequence[Tuple[int, Optional[int]]]]] = None,
    perpetual_multiple: float = 2.0,
) -> ExceptionLoad:
    """Aggregate the exception workflow's effect across a set of findings.

    ``windows_by_key`` maps finding_key to its raw (UNMERGED) exception windows;
    the count of windows is the renewal chain, so they must not be pre-merged.
    """
    windows_by_key = windows_by_key or {}
    total = under = granted = 0
    longest = 0
    perpetual: List[str] = []
    for s in states:
        if s.state == NO_POLICY:
            continue
        total += 1
        if s.paused_seconds > 0:
            under += 1
            granted += s.paused_seconds // DAY
        longest = max(longest, len(windows_by_key.get(s.finding_key, ())))
        if (s.window_seconds
                and s.paused_seconds > perpetual_multiple * s.window_seconds):
            perpetual.append(s.finding_key)
    return ExceptionLoad(total, under, int(granted), longest,
                         tuple(sorted(perpetual)), perpetual_multiple)
