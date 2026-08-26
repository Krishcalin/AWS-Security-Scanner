"""The exception workflow, and the headline KRA it can carry on its own.

THE DEFECT
-----------
OW2-AR-031 pauses the SLA clock under an approved exception. OW2-KM-003 routes
CRITICAL exceptions to the CISO. So a CRITICAL finding remediated on day 200
against a 15-day window counts as closed-within-SLA when an exception covered the
gap: `test_one_approval_moves_the_headline_from_zero_to_one_hundred` measures
exactly that, and it is the whole of review defect D4 in one assertion.

OW2-KM-004 keeps excepted findings in a register visible to audit. That is right,
and it is not sufficient -- a register is not a metric, and the BBSC hand-off under
OW2-KM-002 carries metrics.

WHAT IS AND IS NOT FIXED
-------------------------
Pausing is NOT forbidden. Exceptions exist for real reasons and OW2-AR-031 requires
them; a tool that refused to honour an approved exception would simply be wrong.
What changes is that the adjustment travels inside the number's own rendering, so
there is no code path that emits the flattering figure alone -- and the two places
where an approval changes what a number SAYS rather than what the estate IS become
KRAs with a target of zero.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_kra as K  # noqa: E402
import aws_sla as S  # noqa: E402

DAY = S.DAY
T0 = 1_700_000_000


def f(resolved=None, key="k", sev="CRITICAL"):
    return {"finding_key": key, "severity": sev, "first_seen_epoch": T0,
            "resolved_epoch": resolved,
            "status": "resolved" if resolved else "open"}


# ═══ the defect, measured ════════════════════════════════════════════════════

def test_one_approval_moves_the_headline_from_zero_to_one_hundred():
    # A CRITICAL finding fixed on day 200 against a 15-day SLA.
    late = S.evaluate(f(T0 + 200 * DAY), T0 + 300 * DAY)
    excepted = S.evaluate(f(T0 + 200 * DAY), T0 + 300 * DAY,
                          exception_windows=[(T0 + 5 * DAY, T0 + 195 * DAY)])
    assert S.closure_rate([late]).pct == 0.0
    assert S.closure_rate([excepted]).pct == 100.0


def test_the_unadjusted_rate_strips_the_approval_back_out():
    excepted = S.evaluate(f(T0 + 200 * DAY), T0 + 300 * DAY,
                          exception_windows=[(T0 + 5 * DAY, T0 + 195 * DAY)])
    r = S.closure_rate([excepted])
    assert r.pct == 100.0
    assert r.unadjusted_pct == 0.0
    assert r.exception_derived_points == 100.0


def test_the_headline_cannot_be_rendered_without_the_adjustment():
    r = S.closure_rate([S.evaluate(f(T0 + 200 * DAY), T0 + 300 * DAY,
                                   exception_windows=[(T0 + 5 * DAY, T0 + 195 * DAY)])])
    h = r.headline()
    assert "100.0%" in h
    assert "only because an approved exception paused the clock" in h
    assert "Unadjusted, the rate is 0.0%" in h


def test_exception_derived_points_come_from_counts_not_rounded_percentages():
    # Subtracting two rounded percentages reports 33.4 where the answer is 33.3.
    states = [
        S.evaluate(f(T0 + 200 * DAY, "a"), T0 + 300 * DAY,
                   exception_windows=[(T0 + 5 * DAY, T0 + 195 * DAY)]),
        S.evaluate(f(T0 + 3 * DAY, "b"), T0 + 300 * DAY),
        S.evaluate(f(None, "c"), T0 + 300 * DAY),
    ]
    assert S.closure_rate(states).exception_derived_points == 33.3


# ═══ the two predicates ══════════════════════════════════════════════════════

def test_exception_assisted_marks_a_closure_that_only_the_approval_saved():
    st = S.evaluate(f(T0 + 200 * DAY), T0 + 300 * DAY,
                    exception_windows=[(T0 + 5 * DAY, T0 + 195 * DAY)])
    assert st.state == S.CLOSED_IN_SLA
    assert st.raw_elapsed_seconds == 200 * DAY
    assert st.elapsed_seconds == 10 * DAY
    assert st.exception_assisted


def test_a_genuinely_fast_closure_is_not_exception_assisted():
    st = S.evaluate(f(T0 + 3 * DAY), T0 + 300 * DAY,
                    exception_windows=[(T0 + 1 * DAY, T0 + 2 * DAY)])
    assert st.state == S.CLOSED_IN_SLA
    assert not st.exception_assisted, (
        "an exception that was not load-bearing must not be counted against anyone")


def test_deferred_breach_is_an_open_finding_past_its_window_and_paused():
    st = S.evaluate(f(None), T0 + 90 * DAY, exception_windows=[(T0 + 2 * DAY, None)])
    assert st.state == S.PAUSED
    assert st.raw_elapsed_seconds > st.window_seconds
    assert st.breach_deferred


def test_a_paused_finding_still_inside_its_window_is_not_a_deferred_breach():
    st = S.evaluate(f(None), T0 + 5 * DAY, exception_windows=[(T0 + 1 * DAY, None)])
    assert st.state == S.PAUSED
    assert not st.breach_deferred


def test_an_already_breached_finding_is_not_double_counted_as_deferred():
    # evaluate() reports BREACHED ahead of PAUSED, so the breach is on the books.
    st = S.evaluate(f(None), T0 + 40 * DAY, exception_windows=[(T0 + 39 * DAY, None)])
    assert st.state == S.BREACHED
    assert not st.breach_deferred


def test_the_raw_clock_ignores_pauses_entirely():
    st = S.evaluate(f(None), T0 + 50 * DAY, exception_windows=[(T0, T0 + 45 * DAY)])
    assert st.raw_elapsed_seconds == 50 * DAY
    assert st.paused_seconds == 45 * DAY
    assert st.elapsed_seconds == 5 * DAY


# ═══ exception load and renewal chains ═══════════════════════════════════════

def states():
    return [S.evaluate(f(T0 + 200 * DAY, "k1"), T0 + 300 * DAY,
                       exception_windows=[(T0 + 5 * DAY, T0 + 195 * DAY)]),
            S.evaluate(f(T0 + 3 * DAY, "k2"), T0 + 300 * DAY),
            S.evaluate(f(None, "k3"), T0 + 300 * DAY,
                       exception_windows=[(T0 + 2 * DAY, None)])]


def test_exception_load_counts_findings_and_days_granted():
    load = S.exception_load(states())
    assert load.findings == 3
    assert load.under_exception == 2
    assert load.rate == 66.7
    assert load.days_granted == 190 + 298


def test_serial_renewal_is_the_pattern_worth_surfacing():
    # KM-003's mandatory expiry stops an exception being formally permanent. It
    # does not stop six consecutive approvals, which is the same thing with better
    # paperwork.
    load = S.exception_load(states(), {"k1": [(1, 2), (3, 4), (5, 6), (7, 8)]})
    assert load.longest_chain == 4
    assert "longest renewal chain is 4 approvals" in load.headline()


def test_renewal_windows_must_not_be_pre_merged():
    # Merging back-to-back windows would collapse the chain to 1 and hide it.
    merged = S.exception_load(states(), {"k1": [(1, 8)]})
    assert merged.longest_chain == 1


def test_cumulative_exception_beyond_a_multiple_of_the_window_is_flagged():
    load = S.exception_load(states())
    assert "k1" in load.perpetual
    assert "permanent exception granted incrementally" in load.headline()


def test_a_short_exception_is_not_flagged_as_perpetual():
    st = [S.evaluate(f(None, "x"), T0 + 10 * DAY,
                     exception_windows=[(T0 + 1 * DAY, T0 + 3 * DAY)])]
    assert S.exception_load(st).perpetual == ()


def test_perpetual_multiple_is_configurable():
    assert S.exception_load(states(), perpetual_multiple=100.0).perpetual == ()


def test_findings_without_a_policy_are_excluded_from_the_load():
    st = states() + [S.evaluate(f(None, "n", sev="NOTICE"), T0 + 9 * DAY)]
    assert S.exception_load(st).findings == 3


def test_load_headline_is_singular_for_one_perpetual_finding():
    st = [states()[0]]
    h = S.exception_load(st).headline()
    assert "1 finding accumulated" in h
    assert "than 2x its SLA window" in h


# ═══ the KRAs (proposed OW2-KM-001 (f) and (g)) ══════════════════════════════

def test_both_new_kras_target_zero_and_neither_target_is_arbitrary():
    for m in K.EXCEPTION_KRAS:
        assert m.target == 0.0
        assert m.direction == K.LOWER_IS_BETTER
        assert m.unit == K.UNIT_COUNT


def test_the_new_kras_are_declared_as_proposed_additions_not_as_existing():
    assert len(K.KRAS) == 5, "OW2-KM-001 declares five; these are proposals"
    assert len(K.ALL_KRAS) == 7
    for m in K.EXCEPTION_KRAS:
        assert "proposed" in m.srs_ref and "D4" in m.srs_ref


def test_closure_kras_returns_the_triple_never_the_headline_alone():
    r = S.closure_rate(states())
    ms = K.closure_kras(r)
    assert [m.definition.id for m in ms] == ["KRA-A", "KRA-F", "KRA-G"]


def test_the_counter_metrics_fail_when_approvals_are_carrying_the_number():
    ms = K.closure_kras(S.closure_rate(states()))
    assert ms[1].verdict == K.NOT_MET, "one exception-assisted closure"
    assert ms[2].verdict == K.NOT_MET, "one deferred breach"


def test_a_clean_estate_passes_all_three():
    st = [S.evaluate(f(T0 + 3 * DAY, "a"), T0 + 90 * DAY)]
    ms = K.closure_kras(S.closure_rate(st))
    assert all(m.verdict == K.MET for m in ms)


def test_shipping_the_closure_rate_without_its_companions_is_detectable():
    ms = K.closure_kras(S.closure_rate(states()))
    assert K.unpaired(ms) == ()
    assert K.unpaired(ms[:1]) == ("KRA-F", "KRA-G"), (
        "a scorecard assembled without the counter-metrics must be a build error, "
        "not a quieter report")


def test_unpaired_is_silent_when_the_headline_is_absent_entirely():
    assert K.unpaired([K.count(K.EXPOSED_CRITICAL, 0)]) == ()


def test_the_pairing_rule_names_the_headline_kra():
    assert K.PAIRED_WITH[K.CRITICAL_CLOSURE.id] == ("KRA-F", "KRA-G")


def test_the_new_kras_appear_in_the_metric_dictionary():
    d = K.metric_dictionary(K.ALL_KRAS)
    ids = {m["id"] for m in d["metrics"]}
    assert {"KRA-F", "KRA-G"} <= ids
    for m in d["metrics"]:
        assert m["definition"] and m["source"] and m["cadence"]
