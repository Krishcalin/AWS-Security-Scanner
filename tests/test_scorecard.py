"""Per-application scorecards, and the four ways one lies.

WHY THE HONESTY TESTS OUTNUMBER THE ARITHMETIC ONES
----------------------------------------------------
A scorecard is the most dangerous artefact this product produces. Every other
output is read by someone who can go and check; a scorecard is read by an
application owner who cannot, and a portfolio pack by a CISO who will not. It is
also a FILTER, and a filter deletes what it does not match while looking complete.

Four rules from elsewhere in the codebase converge here, and each has a test that
would fail if a well-meaning refactor "simplified" it:

  1. the pack states its coverage, and unowned findings get a visible row
  2. the closure rate never renders without the approvals that produced it (D4)
  3. rank is withheld without an asset count, rather than computed on raw counts
  4. no prior month means no trend, never "0% change"

Each of those, done the easy way, produces a scorecard that is more flattering and
less true.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_kra  # noqa: E402
import aws_ownership as O  # noqa: E402
import aws_riskscore as R  # noqa: E402
import aws_scorecard as SC  # noqa: E402
import aws_sla as S  # noqa: E402

DAY = S.DAY
T0 = 1_700_000_000
NOW = T0 + 90 * DAY


def app(app_id, **kw):
    kw.setdefault("name", app_id.title())
    kw.setdefault("owner", "team-" + app_id)
    kw.setdefault("criticality", "high")
    return O.Application(app_id=app_id, **kw)


def f(key, sev="HIGH", account="111111111111", resolved=None, first=T0):
    return {"finding_key": key, "severity": sev, "account": account,
            "resource": "arn:" + key, "first_seen_epoch": first,
            "resolved_epoch": resolved,
            "status": "resolved" if resolved else "open"}


def factors(v=0.3):
    return [R.FactorValue(k, v, "test") for k in R.FACTOR_KEYS]


PAY = app("pay", accounts=("111111111111",), portfolio="digital")
ANA = app("ana", accounts=("222222222222",), portfolio="digital")


# ── 1. the pack states its coverage, and unowned findings are visible ───────

def test_unowned_findings_get_a_row_rather_than_vanishing():
    findings = [f("a"), f("b"), f("orphan", account="999999999999")]
    pack = SC.build(findings, [PAY], now_epoch=NOW)
    un = pack.unattributed
    assert un is not None, "unowned findings must not be filtered out of the pack"
    assert un.findings_total == 1
    assert un.owner == "", "the unowned row has no owner -- that IS the finding"
    assert un.grade is None


def test_the_pack_headline_states_the_shortfall():
    findings = [f("a")] + [f("orphan%d" % i, account="999999999999") for i in range(3)]
    pack = SC.build(findings, [PAY], now_epoch=NOW)
    h = pack.headline()
    assert "25.0%" in h
    assert "exclude" in h
    assert "no owner to send a scorecard to" in h


def test_a_complete_pack_says_so_without_a_scare():
    pack = SC.build([f("a"), f("b")], [PAY], now_epoch=NOW)
    assert pack.unattributed is None
    assert "All 2 findings attributed" in pack.headline()


def test_applications_excludes_the_unowned_row():
    pack = SC.build([f("a"), f("orphan", account="999999999999")], [PAY],
                    now_epoch=NOW)
    assert len(pack.applications) == 1
    assert len(pack.scorecards) == 2


def test_the_unowned_row_sorts_last_and_cannot_head_the_table():
    findings = [f("a", "HIGH")] + [f("o%d" % i, "CRITICAL", account="9" * 12)
                                   for i in range(5)]
    pack = SC.build(findings, [PAY], now_epoch=NOW)
    assert pack.scorecards[-1].is_unattributed, (
        "unowned has the most criticals here; it still must not head a graded table")


# ── 2. the closure rate never renders alone (defect D4) ────────────────────

def test_the_sla_line_carries_the_approvals_that_produced_it():
    # One CRITICAL closed on day 200 against a 15-day SLA, saved by an exception.
    findings = [f("c1", "CRITICAL", resolved=T0 + 200 * DAY)]
    pack = SC.build(findings, [PAY], now_epoch=T0 + 300 * DAY,
                    exception_windows={"c1": [(T0 + 5 * DAY, T0 + 195 * DAY)]})
    line = pack.by_id("pay").sla_line()
    assert "100.0%" in line
    assert "only because an approved exception paused the clock" in line
    assert "Unadjusted, the rate is 0.0%" in line


def test_an_honest_closure_reports_no_exception_assistance():
    findings = [f("c1", "CRITICAL", resolved=T0 + 3 * DAY)]
    pack = SC.build(findings, [PAY], now_epoch=T0 + 300 * DAY)
    line = pack.by_id("pay").sla_line()
    assert "100.0%" in line
    assert "exception" not in line


def test_no_critical_findings_says_so_rather_than_reporting_zero_percent():
    pack = SC.build([f("h1", "HIGH")], [PAY], now_epoch=NOW)
    assert "No CRITICAL findings" in pack.by_id("pay").sla_line()


# ── 3. rank is withheld without a denominator (OW2-SC-004) ─────────────────

def test_rank_is_withheld_when_the_asset_count_is_unknown():
    pack = SC.build([f("a")], [PAY], now_epoch=NOW)
    card = pack.by_id("pay")
    assert card.rank is None
    assert card.per_100_assets is None
    assert "by size, not by security" in card.rank_withheld


def test_rank_is_computed_when_assets_are_known_and_normalised_per_100():
    findings = [f("a", "CRITICAL"), f("b", "CRITICAL"),
                f("c", "CRITICAL", account="222222222222")]
    pack = SC.build(findings, [PAY, ANA], now_epoch=NOW,
                    assets_by_app={"pay": 1000, "ana": 10})
    pay, ana = pack.by_id("pay"), pack.by_id("ana")
    # pay: 2 criticals over 1000 assets. ana: 1 critical over 10.
    assert pay.per_100_assets < ana.per_100_assets
    assert pay.rank == 1 and ana.rank == 2, (
        "the larger estate must not be penalised for being larger")
    assert pay.peers == ana.peers == 2


def test_a_partially_rankable_portfolio_reports_who_was_actually_compared():
    """'3rd of 4' must never silently mean '3rd of the 4 we could measure'."""
    findings = [f("a"), f("c", account="222222222222")]
    pack = SC.build(findings, [PAY, ANA], now_epoch=NOW,
                    assets_by_app={"pay": 100})            # ana unknown
    pay, ana = pack.by_id("pay"), pack.by_id("ana")
    assert pay.rank == 1 and pay.peers == 1, "only one application was rankable"
    assert ana.rank is None and ana.peers == 1
    assert ana.rank_withheld


def test_ranking_is_per_portfolio_not_global():
    other = app("ops", accounts=("333333333333",), portfolio="platform")
    findings = [f("a"), f("c", account="222222222222"),
                f("d", account="333333333333")]
    pack = SC.build(findings, [PAY, ANA, other], now_epoch=NOW,
                    assets_by_app={"pay": 100, "ana": 100, "ops": 100})
    assert pack.by_id("ops").rank == 1, "a lone application leads its own portfolio"
    assert pack.by_id("ops").peers == 1


# ── 4. absent history is not a flat trend ──────────────────────────────────

def test_no_prior_month_means_no_trend_not_zero_change():
    pack = SC.build([f("a")], [PAY], now_epoch=NOW, factors_by_app={"pay": factors()})
    card = pack.by_id("pay")
    assert card.trend is None
    assert any("first scorecard" in c for c in card.caveats())


def test_a_prior_month_produces_a_direction():
    pack = SC.build([f("a")], [PAY], now_epoch=NOW,
                    factors_by_app={"pay": factors(0.3)},
                    previous_posture={"pay": 50.0})
    t = pack.by_id("pay").trend
    assert t is not None
    assert t.direction in ("improved", "worsened", "unchanged")
    assert "month-on-month" in t.render()


def test_an_unchanged_month_is_reported_as_unchanged():
    pack = SC.build([f("a")], [PAY], now_epoch=NOW,
                    factors_by_app={"pay": factors(0.3)})
    posture = pack.by_id("pay").posture
    again = SC.build([f("a")], [PAY], now_epoch=NOW,
                     factors_by_app={"pay": factors(0.3)},
                     previous_posture={"pay": float(posture)})
    assert again.by_id("pay").trend.render() == "unchanged month-on-month"


# ── the grade comes from the published model, or is withheld ───────────────

def test_the_grade_comes_from_the_risk_model_not_from_finding_counts():
    pack = SC.build([f("a")], [PAY], now_epoch=NOW,
                    factors_by_app={"pay": factors(0.0)})
    card = pack.by_id("pay")
    assert card.posture == 100 and card.grade == "A"


def test_no_factors_means_no_grade_and_says_why():
    pack = SC.build([f("a")], [PAY], now_epoch=NOW)
    card = pack.by_id("pay")
    assert card.grade is None
    assert "published model" in card.grade_withheld
    assert card.grade_withheld in card.caveats()


def test_a_refused_composite_withholds_the_grade_rather_than_guessing():
    thin = [R.FactorValue(R.FINDINGS, 1.0, "only one factor")]
    pack = SC.build([f("a")], [PAY], now_epoch=NOW, factors_by_app={"pay": thin})
    card = pack.by_id("pay")
    assert card.grade is None and card.posture is None
    assert "not a composite" in card.grade_withheld


# ── exceptions are segregated, never hidden (OW2-SC-008) ───────────────────

def test_excepted_findings_are_counted_apart_from_the_open_totals():
    findings = [f("a", "CRITICAL"), f("b", "CRITICAL")]
    pack = SC.build(findings, [PAY], now_epoch=NOW, excepted_keys={"b"})
    card = pack.by_id("pay")
    assert card.open_critical == 1, "the excepted one is not in the open count"
    assert card.excepted == 1
    assert card.findings_total == 2, "and it is not dropped either"


def test_the_excepted_count_is_explained_in_the_caveats():
    pack = SC.build([f("a"), f("b")], [PAY], now_epoch=NOW, excepted_keys={"b"})
    assert any("counted separately" in c for c in pack.by_id("pay").caveats())


def test_an_exception_cannot_improve_the_open_counts_invisibly():
    plain = SC.build([f("a", "CRITICAL")], [PAY], now_epoch=NOW).by_id("pay")
    with_exc = SC.build([f("a", "CRITICAL")], [PAY], now_epoch=NOW,
                        excepted_keys={"a"}).by_id("pay")
    assert plain.open_critical == 1 and with_exc.open_critical == 0
    assert with_exc.excepted == 1, "the drop must be accounted for, not silent"


# ── declared truncation on the finding list ────────────────────────────────

def test_the_finding_list_declares_its_own_cap():
    findings = [f("k%02d" % i, "HIGH") for i in range(25)]
    card = SC.build(findings, [PAY], now_epoch=NOW).by_id("pay")
    assert len(card.top_findings) == SC.TOP_FINDINGS
    assert card.top_findings_total == 25
    assert card.top_findings_truncated
    assert any("Showing 10 of 25" in c for c in card.caveats())


def test_a_short_list_is_not_reported_as_truncated():
    card = SC.build([f("a")], [PAY], now_epoch=NOW).by_id("pay")
    assert not card.top_findings_truncated
    assert not any("Showing" in c for c in card.caveats())


def test_critical_findings_lead_the_list():
    findings = [f("z", "HIGH"), f("a", "CRITICAL")]
    card = SC.build(findings, [PAY], now_epoch=NOW).by_id("pay")
    assert card.top_findings[0] == "a"


# ── KRA metrics ride along, with their own honesty ─────────────────────────

def test_exposure_with_an_unreadable_region_is_not_established():
    pack = SC.build([f("a")], [PAY], now_epoch=NOW,
                    exposure_by_app={"pay": (0, 3)})
    m = pack.by_id("pay").exposure
    assert m.verdict == aws_kra.NOT_ESTABLISHED
    assert m.value == 0.0


def test_full_mfa_over_a_partial_user_list_is_not_established():
    pack = SC.build([f("a")], [PAY], now_epoch=NOW,
                    mfa_by_app={"pay": (40, 40, 10)})
    m = pack.by_id("pay").mfa
    assert m.value == 100.0
    assert m.verdict == aws_kra.NOT_ESTABLISHED


def test_absent_kra_inputs_produce_no_metric_rather_than_a_zero():
    card = SC.build([f("a")], [PAY], now_epoch=NOW).by_id("pay")
    assert card.exposure is None and card.mfa is None
    assert card.to_dict()["kras"] == []


# ── reproducibility and export ─────────────────────────────────────────────

def test_a_pack_is_a_pure_function_of_its_inputs():
    args = dict(now_epoch=NOW, factors_by_app={"pay": factors()},
                assets_by_app={"pay": 100})
    a = SC.build([f("a")], [PAY], **args)
    b = SC.build([f("a")], [PAY], **args)
    assert a.to_dict() == b.to_dict(), (
        "an owner disputing a grade must be able to have it recomputed")


def test_the_export_carries_coverage_beside_the_scorecards():
    d = SC.build([f("a"), f("o", account="9" * 12)], [PAY], now_epoch=NOW).to_dict()
    assert d["coverage"]["pct"] == 50.0
    assert d["coverage"]["complete"] is False
    assert d["headline"]
    assert len(d["scorecards"]) == 2


def test_every_scorecard_exports_its_caveats():
    d = SC.build([f("a")], [PAY], now_epoch=NOW).to_dict()
    assert d["scorecards"][0]["caveats"], (
        "no grade, no rank and no trend here -- all three must be stated")


def test_an_empty_estate_does_not_claim_completeness():
    pack = SC.build([], [PAY], now_epoch=NOW)
    assert pack.coverage.total == 0
    assert not pack.coverage.complete
    assert pack.applications == ()
