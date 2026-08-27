"""The composite Cloud Risk Score, and the three ways Appendix B was wrong.

WHY THE NORMALISATION TEST IS THE ONE THAT MATTERS
---------------------------------------------------
Appendix B of OW2-SRS-001 tabulates weights summing to 95 and bands the result
against a 0-100 scale. The obvious fix is to renumber the table; the durable fix is
to make the engine normalise, so the defect cannot return when an administrator
retunes a weight under OW2-CC-004 or somebody adds a sixth factor.

`test_appendix_b_verbatim_weights_produce_a_defined_score` is therefore the
regression that matters: it feeds the document's own broken 95-sum straight in and
asserts a well-defined 0-100 result. If a later refactor reintroduces an assumption
that weights are already percentages, that test fails and this docstring explains why.

The other two defects get their own sections: a maximally bad estate must not earn
an A (direction), and compensating controls must not reduce exposure.

`test_the_credit_never_touches_the_exposure_component` is the D2 regression, and it
exists because the first version of this module got it wrong and passed its own
tests. That version applied the credit as a multiplier over the WHOLE composite,
gated on live exposure -- which still let tooling shave the exposure contribution on
every estate whose gate did not happen to trip. The gate is a useful second guard;
it was never the fix. Restricting the credit to CREDITABLE_FACTORS is.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_riskscore as R  # noqa: E402


def fv(key, value, basis="test"):
    return R.FactorValue(key, value, basis)


def all_at(v):
    return [fv(k, v) for k in R.FACTOR_KEYS]


# ═══ DEFECT 1 — the weights do not sum ═══════════════════════════════════════

def test_appendix_b_weights_still_sum_to_95_as_drafted():
    # Pinned so the correction is anchored to the real document, not to a
    # remembered version of it.
    assert sum(R.APPENDIX_B_WEIGHTS.values()) == 95.0


def test_appendix_b_verbatim_weights_produce_a_defined_score():
    m = R.RiskModel(weights=R.APPENDIX_B_WEIGHTS)
    s = R.score(all_at(1.0), m)
    assert s.risk == 100, "a maximally bad estate must reach the top of the scale"
    assert s.posture == 0


def test_normalised_weights_sum_to_one():
    norm = R.RiskModel(weights=R.APPENDIX_B_WEIGHTS).normalized()
    assert sum(norm.values()) == pytest.approx(1.0)
    assert norm[R.FINDINGS] == pytest.approx(30.0 / 95.0)


def test_weights_are_relative_so_any_scale_gives_the_same_score():
    a = R.score(all_at(0.4), R.RiskModel(weights={"findings": 30, "exploitability": 20,
                                                  "exposure": 20, "criticality": 15,
                                                  "hygiene": 10}))
    b = R.score(all_at(0.4), R.RiskModel(weights={"findings": 6, "exploitability": 4,
                                                  "exposure": 4, "criticality": 3,
                                                  "hygiene": 2}))
    assert a.risk == b.risk == 40


def test_a_hand_corrected_hundred_sum_scores_identically_to_the_95_sum():
    # The point of normalising: ratifying a tidier table (Appendix D item 2) must
    # not move anybody's published score.
    ninety_five = R.score(all_at(0.5), R.RiskModel(weights=R.APPENDIX_B_WEIGHTS))
    hundred = R.score(all_at(0.5), R.RiskModel(
        weights={"findings": 31.58, "exploitability": 21.05, "exposure": 21.05,
                 "criticality": 15.79, "hygiene": 10.53}))
    assert ninety_five.risk == hundred.risk


def test_methodology_publishes_the_normalisation_rather_than_hiding_it():
    doc = R.RiskModel().methodology()
    assert doc["declared_weight_total"] == 95.0
    assert "sums to 95" in doc["normalisation"]
    pcts = {f["key"]: f["weight_normalised_pct"] for f in doc["factors"]}
    assert sum(pcts.values()) == pytest.approx(100.0, abs=0.05)


def test_negative_weight_is_rejected_with_the_reason():
    with pytest.raises(ValueError, match="compensating control"):
        R.RiskModel(weights={"findings": 30, "exposure": -10})


def test_unknown_factor_in_the_weight_set_is_rejected():
    with pytest.raises(ValueError, match="unknown risk factor"):
        R.RiskModel(weights={"findings": 30, "vibes": 10})


def test_all_zero_weights_are_rejected():
    with pytest.raises(ValueError, match="sum to zero"):
        R.RiskModel(weights={"findings": 0, "exposure": 0})


# ═══ DEFECT 2 — the score ran the wrong way against its banding ══════════════

def test_a_maximally_bad_estate_does_not_earn_an_a():
    # Appendix B as drafted scores this 95 and bands it A.
    s = R.score(all_at(1.0))
    assert s.risk == 100
    assert s.grade == "E"


def test_a_clean_estate_earns_an_a():
    s = R.score(all_at(0.0))
    assert s.risk == 0 and s.posture == 100 and s.grade == "A"


def test_posture_is_the_complement_of_risk():
    s = R.score(all_at(0.37))
    assert s.posture == 100 - s.risk


def test_appendix_b_band_thresholds_are_preserved_exactly():
    m = R.RiskModel()
    assert [g for g, _ in m.bands] == ["A", "B", "C", "D", "E"]
    assert m.band(90.0) == "A" and m.band(89.9) == "B"
    assert m.band(80.0) == "B" and m.band(70.0) == "C"
    assert m.band(60.0) == "D" and m.band(59.9) == "E"


def test_bands_apply_to_posture_not_risk():
    s = R.score(all_at(0.05))          # low risk
    assert s.risk == 5 and s.posture == 95 and s.grade == "A"


def test_methodology_states_the_direction_explicitly():
    d = R.RiskModel().methodology()["direction"]
    assert "higher is worse" in d and "higher is better" in d
    assert "POSTURE" in d


# ═══ DEFECT 3 — compensating controls were the wrong instrument ══════════════

CLEAR = R.ExposureGate(False)          # exposure was evaluated and is not live


def test_the_credit_never_touches_the_exposure_component():
    # THE D2 REGRESSION. A multiplier over the whole composite would reduce the
    # exposure contribution, which is precisely the behaviour D2 objects to. An
    # earlier version of this module did exactly that and passed its own tests.
    factors = [fv(R.FINDINGS, 0.3), fv(R.EXPLOITABILITY, 0.2), fv(R.EXPOSURE, 0.8),
               fv(R.CRITICALITY, 0.3), fv(R.HYGIENE, 0.2)]
    base = R.score(factors, exposure_gate=CLEAR)
    cred = R.score(factors, control_credit=0.15, exposure_gate=CLEAR)

    exposure_points = [c for c in base.contributions if c.key == R.EXPOSURE][0].points
    # Everything the credit removed must be attributable to creditable factors only.
    assert cred.credit_points == pytest.approx(base.raw_risk - _exact(cred), abs=0.01)
    assert cred.credit_points < exposure_points * 0.15, (
        "credit removed more than a whole-composite multiplier would have taken from "
        "exposure alone, so exposure is still being credited")


def _exact(s):
    creditable = set(s.credited_factors)
    return sum(c.points * (1 - s.control_credit) if c.key in creditable else c.points
               for c in s.contributions)


def test_only_findings_is_creditable():
    assert R.CREDITABLE_FACTORS == (R.FINDINGS,)
    assert R.EXPOSURE not in R.CREDITABLE_FACTORS
    assert R.EXPLOITABILITY not in R.CREDITABLE_FACTORS
    assert R.CRITICALITY not in R.CREDITABLE_FACTORS


def test_a_model_cannot_declare_exposure_creditable():
    with pytest.raises(ValueError, match="exposure cannot be creditable"):
        R.RiskModel(creditable=(R.FINDINGS, R.EXPOSURE))


def test_unknown_creditable_factor_is_rejected():
    with pytest.raises(ValueError, match="unknown creditable factor"):
        R.RiskModel(creditable=("vibes",))


def test_control_credit_is_capped_at_fifteen_percent_of_the_creditable_share():
    base = R.score(all_at(0.8), exposure_gate=CLEAR)
    credited = R.score(all_at(0.8), control_credit=0.15, exposure_gate=CLEAR)
    findings_points = [c for c in base.contributions if c.key == R.FINDINGS][0].points
    assert credited.control_credit == 0.15
    assert credited.credit_points == pytest.approx(findings_points * 0.15, abs=0.01)


def test_the_effective_ceiling_is_published_not_left_to_subtraction():
    # Appendix B intended 15 points. Against its weights the honest ceiling is ~4.7,
    # because only the findings factor is creditable. Publishing it is the point.
    m = R.RiskModel()
    assert m.max_effective_credit() == pytest.approx(0.15 * 30.0 / 95.0, abs=1e-6)
    doc = m.methodology()["compensating_controls"]
    assert doc["max_credit_pct"] == 15.0
    assert doc["max_effective_credit_points"] == pytest.approx(4.74, abs=0.01)
    assert "Exposure" in doc["not_creditable"]


def test_credit_above_the_ceiling_is_clamped_not_honoured():
    s = R.score(all_at(0.8), control_credit=0.9, exposure_gate=CLEAR)
    assert s.control_credit == R.MAX_CONTROL_CREDIT


def test_tooling_cannot_buy_down_a_live_exposure():
    gate = R.ExposureGate(True, "an internet-reachable host carries a KEV-listed CVE")
    ungated = R.score(all_at(0.8), control_credit=0.15, exposure_gate=CLEAR)
    gated = R.score(all_at(0.8), control_credit=0.15, exposure_gate=gate)
    assert gated.risk > ungated.risk
    assert gated.control_credit == 0.0
    assert gated.credit_gated


# ── the second guard: a missing verdict is not a clearance ───────────────────

def test_no_gate_verdict_withholds_the_credit_rather_than_granting_it():
    # Defaulting an unevaluated gate to "not tripped" would hand out credit on the
    # strength of nobody having looked.
    s = R.score(all_at(0.8), control_credit=0.15)
    assert s.credit_gated
    assert s.control_credit == 0.0
    assert "not a cleared one" in s.gate_reason


def test_no_gate_verdict_is_harmless_when_no_credit_is_claimed():
    s = R.score(all_at(0.8))
    assert not s.credit_gated and s.control_credit == 0.0


def test_an_evaluated_clear_gate_does_grant_the_credit():
    s = R.score(all_at(0.8), control_credit=0.15, exposure_gate=CLEAR)
    assert not s.credit_gated
    assert s.control_credit == 0.15


def test_the_caveat_names_what_is_not_creditable():
    s = R.score(all_at(0.5), control_credit=0.15, exposure_gate=CLEAR)
    c = s.caveat()
    assert "not creditable" in c
    assert "how reachable the asset is" in c


def test_credit_points_are_measured_not_inferred_from_the_ceiling():
    s = R.score(all_at(0.2), control_credit=0.15, exposure_gate=CLEAR)
    findings = [c for c in s.contributions if c.key == R.FINDINGS][0]
    assert s.credit_points == pytest.approx(findings.points * 0.15, abs=0.01)
    assert s.credit_points < 100 * R.RiskModel().max_effective_credit()


def test_a_tripped_gate_must_be_explainable():
    with pytest.raises(ValueError, match="carry a reason"):
        R.ExposureGate(tripped=True)


def test_gated_credit_is_surfaced_in_the_caveat():
    gate = R.ExposureGate(True, "two exposed crown-jewel workloads")
    s = R.score(all_at(0.5), control_credit=0.15, exposure_gate=gate)
    assert "withheld" in s.caveat() and "crown-jewel" in s.caveat()


def test_credit_can_never_drive_risk_below_zero():
    s = R.score(all_at(0.0), control_credit=0.15, exposure_gate=CLEAR)
    assert s.risk == 0


def test_compensating_controls_are_not_in_the_weight_set():
    assert "controls" not in R.FACTOR_KEYS
    assert len(R.FACTOR_KEYS) == 5


# ═══ an unmeasured factor is not a factor worth zero ═════════════════════════

def test_unavailable_factor_is_excluded_not_scored_zero():
    factors = [fv(k, 1.0) for k in R.FACTOR_KEYS if k != R.EXPLOITABILITY]
    factors.append(R.FactorValue(R.EXPLOITABILITY, None, reason="no EPSS/KEV feed"))
    s = R.score(factors)
    assert s.risk == 100, "excluding a factor must not lower risk for the rest"
    assert s.excluded == ((R.EXPLOITABILITY, "no EPSS/KEV feed"),)


def test_scoring_zero_for_a_missing_factor_would_have_understated_risk():
    # The contrast this module exists to prevent.
    honest = R.score([fv(k, 1.0) for k in R.FACTOR_KEYS if k != R.EXPLOITABILITY]
                     + [R.FactorValue(R.EXPLOITABILITY, None, reason="no feed")])
    as_zero = R.score([fv(k, 1.0) for k in R.FACTOR_KEYS if k != R.EXPLOITABILITY]
                      + [fv(R.EXPLOITABILITY, 0.0)])
    assert honest.risk == 100 and as_zero.risk == 79
    assert honest.risk > as_zero.risk


def test_a_factor_simply_not_supplied_is_treated_as_missing_data():
    s = R.score([fv(k, 1.0) for k in R.FACTOR_KEYS if k != R.HYGIENE])
    assert s.excluded == ((R.HYGIENE, "not supplied to the scoring call"),)
    assert s.risk == 100


def test_excluded_weight_is_redistributed_across_the_survivors():
    s = R.score([fv(k, 1.0) for k in R.FACTOR_KEYS if k != R.HYGIENE])
    assert sum(c.weight_used for c in s.contributions) == pytest.approx(1.0)
    assert s.weight_coverage == pytest.approx(85.0 / 95.0)


def test_a_value_with_no_reason_is_rejected():
    with pytest.raises(ValueError, match="must say why"):
        R.FactorValue(R.EXPOSURE, None)


def test_values_must_be_normalised_before_scoring():
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        R.FactorValue(R.EXPOSURE, 42.0)


def test_duplicate_factor_is_rejected():
    with pytest.raises(ValueError, match="twice"):
        R.score([fv(R.EXPOSURE, 0.1), fv(R.EXPOSURE, 0.2)])


# ── refusal ──────────────────────────────────────────────────────────────────

def test_too_little_data_refuses_rather_than_publishing():
    s = R.score([fv(R.FINDINGS, 1.0)])          # 30/95 = 31.6% coverage
    assert s.refused
    assert s.risk is None and s.grade is None
    assert "not a composite" in s.refusal_reason


def test_refusal_threshold_is_configurable():
    m = R.RiskModel(min_weight_coverage=0.3)
    s = R.score([fv(R.FINDINGS, 1.0)], m)
    assert not s.refused


def test_no_factors_at_all_refuses():
    assert R.score([]).refused


def test_a_refused_score_still_names_what_was_missing():
    s = R.score([fv(R.FINDINGS, 1.0)])
    assert len(s.excluded) == 4
    assert "31%" in s.refusal_reason or "32%" in s.refusal_reason


def test_caveat_is_never_silently_empty_when_something_was_excluded():
    s = R.score([fv(k, 0.5) for k in R.FACTOR_KEYS if k != R.HYGIENE])
    c = s.caveat()
    assert "89% of the model" in c
    assert "rather than counted as zero risk" in c


def test_complete_score_has_no_caveat():
    assert R.score(all_at(0.5)).caveat() == ""
    assert R.score(all_at(0.5)).complete


# ── model versioning (OW2-CC-004) ────────────────────────────────────────────

def test_model_version_is_stable_for_the_same_model():
    assert R.RiskModel().version == R.RiskModel().version


def test_retuning_any_weight_changes_the_version():
    a = R.RiskModel().version
    b = R.RiskModel(weights=dict(R.APPENDIX_B_WEIGHTS, exposure=25.0)).version
    assert a != b, "a score must carry proof of which model produced it"


def test_changing_the_credit_ceiling_changes_the_version():
    assert R.RiskModel().version != R.RiskModel(max_control_credit=0.10).version


def test_changing_the_bands_changes_the_version():
    bands = (("A", 95.0), ("B", 80.0), ("C", 70.0), ("D", 60.0), ("E", 0.0))
    assert R.RiskModel().version != R.RiskModel(bands=bands).version


def test_rescaling_weights_does_not_change_the_score_but_does_change_the_version():
    # Honest: the model text differs, so recalculation is flagged, even though the
    # arithmetic is identical. Flagging a no-op recalculation is the safe direction.
    half = R.RiskModel(weights={k: v / 2 for k, v in R.APPENDIX_B_WEIGHTS.items()})
    assert R.score(all_at(0.6)).risk == R.score(all_at(0.6), half).risk
    assert R.RiskModel().version != half.version


def test_every_score_carries_its_model_version():
    s = R.score(all_at(0.5))
    assert s.model_version == R.RiskModel().version
    assert s.to_dict()["model_version"] == s.model_version


# ── scopes, drivers, explainability ──────────────────────────────────────────

def test_all_four_scopes_from_cc_001_are_supported():
    assert R.SCOPES == ("estate", "account", "business-unit", "application")
    for sc in R.SCOPES:
        assert R.score(all_at(0.2), scope=sc, scope_id="x").scope == sc


def test_unknown_scope_is_rejected():
    with pytest.raises(ValueError, match="scope must be"):
        R.score(all_at(0.2), scope="galaxy")


def test_drivers_rank_by_contribution_not_by_declared_weight():
    s = R.score([fv(R.FINDINGS, 0.1), fv(R.EXPLOITABILITY, 0.1),
                 fv(R.EXPOSURE, 1.0), fv(R.CRITICALITY, 0.1), fv(R.HYGIENE, 0.1)])
    assert R.drivers(s, 1)[0].key == R.EXPOSURE


def test_contributions_sum_to_the_raw_risk():
    s = R.score(all_at(0.63))
    assert sum(c.points for c in s.contributions) == pytest.approx(s.raw_risk)


def test_explain_names_the_drivers():
    s = R.score([fv(R.FINDINGS, 0.9), fv(R.EXPLOITABILITY, 0.1),
                 fv(R.EXPOSURE, 0.1), fv(R.CRITICALITY, 0.1), fv(R.HYGIENE, 0.1)])
    text = R.explain(s)
    assert "grade" in text.lower() or "posture" in text.lower()
    assert "severity-weighted open findings" in text


def test_explain_of_a_refused_score_says_so_rather_than_inventing_a_number():
    text = R.explain(R.score([fv(R.FINDINGS, 1.0)]))
    assert "Refused" in text
    assert "100" not in text.split("Weight coverage")[0]


# ── reproducibility ──────────────────────────────────────────────────────────

def test_scoring_is_a_pure_function_of_its_inputs():
    a = R.score(all_at(0.44), control_credit=0.1, scope="account", scope_id="1",
                exposure_gate=CLEAR)
    b = R.score(all_at(0.44), control_credit=0.1, scope="account", scope_id="1",
                exposure_gate=CLEAR)
    assert a == b, "a published score must be recomputable by anyone with the inputs"


def test_to_dict_round_trips_the_whole_decomposition():
    d = R.score(all_at(0.5), control_credit=0.1, exposure_gate=CLEAR).to_dict()
    assert d["posture"] == 100 - d["risk"]
    assert len(d["contributions"]) == 5
    assert d["control_credit_pct"] == 10.0
    assert d["credited_factors"] == ["findings"]
    assert d["credit_points_removed"] > 0
