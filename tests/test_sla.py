"""SLA clocks, MTTR, and the survivor bias that makes MTTR lie.

WHY THE DENOMINATOR TESTS ARE THE ONES THAT MATTER
---------------------------------------------------
MTTR over closed findings is a survivor statistic: the slowest remediations are the
ones most likely to still be open, so they are absent from the mean. A team that stops
remediating entirely watches its MTTR improve. That is not a rounding problem, it is
the metric pointing the wrong way under exactly the conditions it exists to detect.

So the tests below pin three things the next well-meaning refactor is most likely to
break: that open findings are counted and reported rather than quietly excluded, that
overlapping exceptions cannot pause the clock twice, and that a severity with no policy
is NO_POLICY rather than silently given the 90-day default.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_sla as S  # noqa: E402

DAY = S.DAY
T0 = 1_700_000_000


def f(key="k", severity="HIGH", first=T0, resolved=None, status="open"):
    return {"finding_key": key, "severity": severity, "first_seen_epoch": first,
            "resolved_epoch": resolved, "status": status}


# ── policy construction ──────────────────────────────────────────────────────

def test_default_policy_matches_appendix_a():
    p = S.SlaPolicy()
    assert p.days["CRITICAL"] == 15 and p.days["HIGH"] == 30
    assert p.days["MEDIUM"] == 60 and p.days["LOW"] == 90


def test_zero_or_negative_window_is_rejected():
    with pytest.raises(ValueError, match="must be positive"):
        S.SlaPolicy(days={"HIGH": 0})


def test_escalation_threshold_must_be_a_fraction():
    with pytest.raises(ValueError):
        S.SlaPolicy(escalate_at=1.5)
    with pytest.raises(ValueError):
        S.SlaPolicy(escalate_at=0.0)


# ── the refusal to invent a policy ───────────────────────────────────────────

def test_unknown_severity_gets_no_default_window():
    st = S.evaluate(f(severity="NOTICE"), T0 + 400 * DAY)
    assert st.state == S.NO_POLICY
    assert st.window_seconds is None
    assert "no default was assumed" in st.reason


def test_resolved_without_a_timestamp_is_not_backfilled_with_now():
    st = S.evaluate(f(status="resolved", resolved=None), T0 + 5 * DAY)
    assert st.state == S.NO_POLICY
    assert "was not inferred" in st.reason


# ── open-clock states ────────────────────────────────────────────────────────

def test_within_window():
    st = S.evaluate(f(), T0 + 5 * DAY)
    assert st.state == S.WITHIN
    assert st.pct_elapsed == pytest.approx(16.7, abs=0.1)
    assert st.remaining_seconds == 25 * DAY


def test_approaching_at_the_escalation_threshold():
    st = S.evaluate(f(), T0 + 23 * DAY)          # 76.7% of 30 days
    assert st.state == S.APPROACHING
    assert "escalation threshold" in st.reason


def test_exactly_at_threshold_escalates():
    st = S.evaluate(f(), T0 + int(22.5 * DAY))   # exactly 75%
    assert st.state == S.APPROACHING


def test_breached_after_the_window():
    st = S.evaluate(f(), T0 + 31 * DAY)
    assert st.state == S.BREACHED
    assert st.breached
    assert st.remaining_seconds < 0


def test_boundary_is_not_a_breach():
    assert S.evaluate(f(), T0 + 30 * DAY).state == S.APPROACHING


# ── exceptions pause, they do not hide ───────────────────────────────────────

def test_live_exception_pauses_the_clock():
    st = S.evaluate(f(), T0 + 10 * DAY, exception_windows=[(T0 + 2 * DAY, None)])
    assert st.state == S.PAUSED
    assert st.paused_seconds == 8 * DAY
    assert st.elapsed_seconds == 2 * DAY


def test_pause_shifts_the_due_date_rather_than_extending_the_window():
    st = S.evaluate(f(), T0 + 10 * DAY, exception_windows=[(T0, T0 + 4 * DAY)])
    assert st.window_seconds == 30 * DAY
    assert st.due_epoch == T0 + 34 * DAY


def test_an_expired_exception_stops_pausing():
    st = S.evaluate(f(), T0 + 10 * DAY, exception_windows=[(T0, T0 + 3 * DAY)])
    assert st.state == S.WITHIN
    assert st.paused_seconds == 3 * DAY


def test_an_exception_never_clears_a_breach_that_already_happened():
    # OW2-KM-004: an exception must not hide a finding. Approving one after the
    # window blew is a decision to accept the risk, not a way to unbreach it.
    st = S.evaluate(f(), T0 + 40 * DAY,
                    exception_windows=[(T0 + 39 * DAY, None)])
    assert st.state == S.BREACHED


def test_overlapping_exceptions_cannot_pause_the_clock_twice():
    # Stacking exceptions would otherwise buy unlimited time and show up as an
    # impossibly good MTTR rather than as an obvious abuse.
    windows = [(T0, T0 + 10 * DAY), (T0 + 5 * DAY, T0 + 12 * DAY)]
    assert S.paused_seconds(windows, T0, T0 + 20 * DAY) == 12 * DAY


def test_disjoint_exceptions_both_count():
    windows = [(T0, T0 + 2 * DAY), (T0 + 5 * DAY, T0 + 6 * DAY)]
    assert S.paused_seconds(windows, T0, T0 + 20 * DAY) == 3 * DAY


def test_exception_windows_are_clipped_to_the_finding_lifetime():
    windows = [(T0 - 100 * DAY, T0 + 2 * DAY)]
    assert S.paused_seconds(windows, T0, T0 + 20 * DAY) == 2 * DAY


def test_zero_length_and_inverted_windows_are_ignored():
    assert S.paused_seconds([(T0 + 5 * DAY, T0 + 5 * DAY)], T0, T0 + 9 * DAY) == 0
    assert S.paused_seconds([(T0 + 9 * DAY, T0 + 2 * DAY)], T0, T0 + 20 * DAY) == 0


# ── closure ──────────────────────────────────────────────────────────────────

def test_closed_inside_the_window():
    st = S.evaluate(f(resolved=T0 + 10 * DAY, status="resolved"), T0 + 99 * DAY)
    assert st.state == S.CLOSED_IN_SLA
    assert st.elapsed_seconds == 10 * DAY
    assert not st.is_open


def test_closed_late():
    st = S.evaluate(f(resolved=T0 + 45 * DAY, status="resolved"), T0 + 99 * DAY)
    assert st.state == S.CLOSED_LATE
    assert st.breached


def test_paused_time_can_pull_a_late_closure_back_inside_sla():
    st = S.evaluate(f(resolved=T0 + 45 * DAY, status="resolved"), T0 + 99 * DAY,
                    exception_windows=[(T0 + 5 * DAY, T0 + 25 * DAY)])
    assert st.state == S.CLOSED_IN_SLA
    assert st.elapsed_seconds == 25 * DAY


def test_evaluate_is_a_pure_function_of_its_inputs():
    a = S.evaluate(f(), T0 + 7 * DAY)
    b = S.evaluate(f(), T0 + 7 * DAY)
    assert a == b, "SLA state must be reproducible so a published KRA can be recomputed"


# ── MTTR and the excluded set ────────────────────────────────────────────────

def states(*specs):
    return [S.evaluate(f(key="k%d" % i, severity=sev, resolved=res,
                         status="resolved" if res else "open"), now)
            for i, (sev, res, now) in enumerate(specs)]


def test_mttr_mean_and_median_by_band():
    r = S.mttr(states(("HIGH", T0 + 10 * DAY, T0 + 99 * DAY),
                      ("HIGH", T0 + 20 * DAY, T0 + 99 * DAY),
                      ("HIGH", T0 + 30 * DAY, T0 + 99 * DAY)))
    b = r.band("HIGH")
    assert b.mean_days == 20.0
    assert b.median_days == 20.0
    assert b.closed_count == 3


def test_open_findings_are_excluded_from_the_mean_but_counted():
    r = S.mttr(states(("HIGH", T0 + 10 * DAY, T0 + 99 * DAY),
                      ("HIGH", None, T0 + 200 * DAY)))
    b = r.band("HIGH")
    assert b.mean_days == 10.0
    assert b.open_count == 1
    assert b.oldest_open_days == 200.0


def test_the_caveat_names_the_survivor_bias():
    r = S.mttr(states(("HIGH", T0 + 10 * DAY, T0 + 99 * DAY),
                      ("HIGH", None, T0 + 300 * DAY)))
    c = r.caveat()
    assert "1 findings are still open" in c
    assert "300 days" in c
    assert "MTTR falls when remediation stalls" in c


def test_no_closures_yields_no_mttr_rather_than_zero():
    r = S.mttr(states(("HIGH", None, T0 + 5 * DAY)))
    assert r.band("HIGH").mean_days is None
    assert "no MTTR can be computed" in r.caveat()


def test_findings_without_a_policy_are_excluded_and_declared():
    r = S.mttr(states(("NOTICE", T0 + 5 * DAY, T0 + 99 * DAY),
                      ("HIGH", T0 + 5 * DAY, T0 + 99 * DAY)))
    assert r.excluded_no_policy == 1
    assert "no SLA policy" in r.caveat()


def test_mttr_definition_travels_with_the_number():
    r = S.mttr(states(("HIGH", T0 + 5 * DAY, T0 + 99 * DAY)))
    assert "verified remediation" in r.definition
    assert "approved, unexpired exception" in r.definition


def test_all_four_bands_are_always_present_even_when_empty():
    r = S.mttr([])
    assert [b.severity for b in r.bands] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert all(b.mean_days is None for b in r.bands)


# ── pre-breach warning and closure rate ──────────────────────────────────────

def test_at_risk_surfaces_only_open_findings_before_they_breach():
    sts = states(("HIGH", None, T0 + 23 * DAY),   # approaching
                 ("HIGH", None, T0 + 40 * DAY),   # already breached
                 ("HIGH", None, T0 + 2 * DAY))    # comfortable
    risky = S.at_risk(sts)
    assert len(risky) == 1
    assert risky[0].state == S.APPROACHING


def test_at_risk_orders_by_urgency():
    sts = states(("HIGH", None, T0 + 23 * DAY), ("HIGH", None, T0 + 29 * DAY))
    risky = S.at_risk(sts)
    assert risky[0].remaining_seconds < risky[1].remaining_seconds


def test_breached_orders_by_how_far_past_due():
    sts = states(("HIGH", None, T0 + 31 * DAY), ("HIGH", None, T0 + 90 * DAY))
    assert S.breached(sts)[0].elapsed_seconds == 90 * DAY


def test_closure_rate_denominator_includes_open_findings():
    # Counting only closed findings reaches 100% the moment nothing closes.
    sts = states(("CRITICAL", T0 + 5 * DAY, T0 + 99 * DAY),
                 ("CRITICAL", None, T0 + 99 * DAY),
                 ("CRITICAL", None, T0 + 99 * DAY))
    r = S.closure_rate(sts, "CRITICAL")
    assert (r.in_sla, r.considered) == (1, 3)
    assert r.pct == 33.3


def test_closure_rate_ignores_other_bands_and_unpolicied_findings():
    sts = states(("CRITICAL", T0 + 5 * DAY, T0 + 99 * DAY),
                 ("HIGH", T0 + 5 * DAY, T0 + 99 * DAY),
                 ("NOTICE", T0 + 5 * DAY, T0 + 99 * DAY))
    assert S.closure_rate(sts, "CRITICAL").considered == 1


def test_late_closure_does_not_count_toward_the_kra():
    sts = states(("CRITICAL", T0 + 40 * DAY, T0 + 99 * DAY))
    r = S.closure_rate(sts, "CRITICAL")
    assert (r.pct, r.in_sla, r.considered) == (0.0, 0, 1)
