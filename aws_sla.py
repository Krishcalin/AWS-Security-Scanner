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
        return SlaState(key, sev, NO_POLICY, first, None, 0, 0, None, None, None,
                        reason="finding is resolved but carries no resolved_epoch; "
                               "elapsed time is unknown and was not inferred")

    window = policy.window(sev)
    if window is None:
        return SlaState(key, sev, NO_POLICY, first, None, 0, 0, None, None, closed,
                        reason="no SLA policy for severity %r; no default was "
                               "assumed" % (sev or "<empty>"))

    end = closed if closed is not None else int(now_epoch)
    paused = paused_seconds(exception_windows, first, end)
    elapsed = max(0, end - first - paused)
    due = first + window + paused
    remaining = due - end

    if closed is not None:
        state = CLOSED_IN_SLA if elapsed <= window else CLOSED_LATE
        return SlaState(key, sev, state, first, window, elapsed, paused,
                        remaining, due, closed)

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
    return SlaState(key, sev, state, first, window, elapsed, paused, remaining,
                    due, None, reason)


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


def closure_rate(states: Iterable[SlaState], severity: str = "CRITICAL") -> Tuple[float, int, int]:
    """OW2-KM-001(a): share of findings in a band closed inside the SLA window.

    Returns ``(pct, closed_in_sla, considered)``. ``considered`` counts every
    finding in the band that has a policy — open ones included — because a rate
    computed only over closed findings reaches 100% the moment nothing closes.
    """
    sev = (severity or "").upper()
    considered = in_sla = 0
    for s in states:
        if s.severity != sev or s.state == NO_POLICY:
            continue
        considered += 1
        if s.state == CLOSED_IN_SLA:
            in_sla += 1
    pct = 0.0 if not considered else round(100.0 * in_sla / considered, 1)
    return pct, in_sla, considered
