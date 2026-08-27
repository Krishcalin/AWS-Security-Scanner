"""Live risk factors, and the four places "unmeasured" is tempting to call zero.

WHAT THIS TURNS ON
------------------
aws_riskscore implemented the corrected Appendix B model and nothing produced its
inputs, so every scorecard grade was withheld. This builds the five factors, and
the ExposureGate verdict that had no producer -- which is why D2's rule ("no
quantity of tooling buys down a live exposure") has been enforced-by-withholding
rather than enforced-by-deciding since it shipped.

THE TESTS THAT MATTER
---------------------
Not the arithmetic. The four refusals, each of which has a plausible-looking wrong
answer that makes an estate score better:

  no vulnerability data     -> excluded, NOT exploitability 0.0
  no security graph         -> excluded, NOT exposure 0.0
  criticality unclassified  -> excluded, NOT the bottom of the scale
  one posture observation   -> excluded, NOT a flat trend

Each wrong answer rewards an organisation for not measuring something.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_factors as F  # noqa: E402
import aws_riskscore as R  # noqa: E402


def path(**kw):
    base = {"conditioned": False, "kev": False, "direct_public_crown": False,
            "terminal_kind": "data", "exposure": 0.5}
    base.update(kw)
    return base


def vuln(kev=0, epss=None):
    return {"kev": kev, "epss": epss}


def f(sev):
    return {"severity": sev}


# ── the four refusals ───────────────────────────────────────────────────────

def test_no_vulnerability_data_is_excluded_not_scored_zero():
    fv = F.exploitability_factor(None)
    assert fv.value is None
    assert "not the same as nothing being exploitable" in fv.reason


def test_an_estate_that_never_scanned_does_not_beat_one_that_did():
    """The whole point. Scoring 0.0 for absent data would reward not looking."""
    never_scanned = F.exploitability_factor(None)
    scanned_clean = F.exploitability_factor([])
    assert never_scanned.value is None
    assert scanned_clean.value == 0.0, "a real scan finding nothing IS a zero"


def test_no_graph_is_excluded_not_exposure_zero():
    fv = F.exposure_factor(None)
    assert fv.value is None
    assert "not an unexposed estate" in fv.reason


def test_a_built_graph_with_no_paths_is_a_real_zero():
    fv = F.exposure_factor([])
    assert fv.value == 0.0
    assert "graph built" in fv.basis, "a measured factor carries a basis, not a reason"


def test_unclassified_criticality_is_excluded_not_bottom_of_scale():
    fv = F.criticality_factor("unclassified")
    assert fv.value is None
    assert "declining to classify anything" in fv.reason


@pytest.mark.parametrize("tier,expected", [("crown-jewel", 1.0), ("high", 0.66),
                                           ("standard", 0.33)])
def test_declared_criticality_tiers_map_to_published_values(tier, expected):
    assert F.criticality_factor(tier).value == expected


def test_a_single_posture_observation_is_not_a_flat_trend():
    fv = F.hygiene_factor([{"posture_score": 80.0}])
    assert fv.value is None
    assert "first scan is not a flat trend" in fv.reason


def test_no_trend_at_all_is_excluded():
    assert F.hygiene_factor(None).value is None
    assert F.hygiene_factor([]).value is None


# ── the arithmetic, once it is measurable ──────────────────────────────────

def test_findings_load_is_severity_weighted_and_saturates():
    assert F.findings_factor([]).value == 0.0
    one_crit = F.findings_factor([f("CRITICAL")]).value
    three_high = F.findings_factor([f("HIGH")] * 3).value
    assert one_crit > three_high, "one CRITICAL must outweigh three HIGHs"
    assert F.findings_factor([f("CRITICAL")] * 50).value == 1.0, "saturates"


def test_an_empty_finding_list_is_a_measurement_not_an_absence():
    fv = F.findings_factor([])
    assert fv.value == 0.0
    assert "no open findings" in fv.basis, "a measured factor carries a basis, not a reason"


def test_exploitability_counts_kev_regardless_of_epss():
    fv = F.exploitability_factor([vuln(kev=1, epss=0.01), vuln(epss=0.01)])
    assert fv.value == 0.5, "KEV counts even at a trivial EPSS"


def test_exploitability_counts_high_epss_without_kev():
    fv = F.exploitability_factor([vuln(epss=0.9), vuln(epss=0.1)])
    assert fv.value == 0.5


def test_a_vuln_with_no_epss_and_no_kev_is_not_counted_hot():
    assert F.exploitability_factor([vuln(), vuln()]).value == 0.0


def test_exposure_uses_the_worst_unconditioned_path():
    fv = F.exposure_factor([path(exposure=0.2), path(exposure=0.9)])
    assert fv.value == 0.9


def test_conditioned_paths_are_excluded_from_exposure():
    """A conditioned path is true only if an assumption holds, and a headline
    score is the wrong place to spend an assumption."""
    fv = F.exposure_factor([path(exposure=0.9, conditioned=True),
                            path(exposure=0.2)])
    assert fv.value == 0.2


def test_only_conditioned_paths_means_no_unconditioned_exposure():
    fv = F.exposure_factor([path(exposure=0.9, conditioned=True)])
    assert fv.value == 0.0


def test_hygiene_scores_high_when_posture_falls():
    worsening = F.hygiene_factor([{"posture_score": 90.0}, {"posture_score": 70.0}])
    improving = F.hygiene_factor([{"posture_score": 70.0}, {"posture_score": 90.0}])
    assert worsening.value == 1.0, "a 20-point slide saturates"
    assert improving.value == 0.0, "improvement is not negative risk"


# ── the exposure gate, which had no producer until now ─────────────────────

def test_the_gate_trips_on_an_unconditioned_kev_path_to_data():
    g = F.exposure_gate([path(kev=True, terminal_kind="data")])
    assert g.tripped
    assert "KEV-listed" in g.reason
    assert "not whether it is reachable" in g.reason


def test_the_gate_trips_on_a_direct_public_crown_edge():
    g = F.exposure_gate([path(direct_public_crown=True, terminal_kind="admin")])
    assert g.tripped and "public-to-crown" in g.reason


def test_a_conditioned_path_does_not_trip_the_gate():
    assert not F.exposure_gate([path(kev=True, conditioned=True)]).tripped


def test_a_path_to_neither_admin_nor_data_does_not_trip_the_gate():
    assert not F.exposure_gate([path(kev=True, terminal_kind="compute")]).tripped


def test_an_ordinary_path_does_not_trip_the_gate():
    assert not F.exposure_gate([path()]).tripped


def test_no_paths_means_an_untripped_gate():
    assert not F.exposure_gate([]).tripped
    assert not F.exposure_gate(None).tripped


def test_the_gate_actually_withholds_credit_end_to_end():
    """The behaviour D2 asked for, now reachable rather than theoretical."""
    factors, gate = F.build([f("HIGH")], criticality="high",
                            paths=[path(kev=True, terminal_kind="data")],
                            vulns=[vuln(kev=1)], trend=[{"posture_score": 90.0},
                                                        {"posture_score": 85.0}])
    scored = R.score(factors, control_credit=0.15, exposure_gate=gate)
    assert scored.credit_gated
    assert scored.control_credit == 0.0
    assert "withheld" in scored.caveat()


def test_a_clean_gate_lets_the_credit_through():
    factors, gate = F.build([f("HIGH")], criticality="high", paths=[path()],
                            vulns=[vuln()], trend=[{"posture_score": 90.0},
                                                   {"posture_score": 89.0}])
    scored = R.score(factors, control_credit=0.15, exposure_gate=gate)
    assert not scored.credit_gated
    assert scored.control_credit == 0.15


# ── assembly, and what a grade needs ───────────────────────────────────────

def test_a_fully_measured_scope_produces_a_grade():
    factors, gate = F.build([f("HIGH")], criticality="high", paths=[path()],
                            vulns=[vuln()], trend=[{"posture_score": 90.0},
                                                   {"posture_score": 89.0}])
    scored = R.score(factors, exposure_gate=gate)
    assert not scored.refused
    assert scored.grade is not None
    assert scored.complete, "nothing excluded when everything was measured"


def test_a_thin_scope_still_grades_if_enough_weight_survives():
    # Findings + criticality alone is 45 of 95 declared weight -- below the floor.
    factors, gate = F.build([f("HIGH")], criticality="high")
    scored = R.score(factors, exposure_gate=gate)
    assert scored.refused, "under half the model is not a composite"


def test_the_excluded_factors_are_named_on_the_score():
    factors, _ = F.build([f("HIGH")], criticality="high")
    scored = R.score(factors)
    excluded = {k for k, _ in scored.excluded}
    assert excluded == {R.EXPLOITABILITY, R.EXPOSURE, R.HYGIENE}


def test_build_returns_all_five_factors_in_model_order():
    factors, _ = F.build([f("HIGH")])
    assert [fv.key for fv in factors] == list(R.FACTOR_KEYS)


# ── the saturation points are published ────────────────────────────────────

def test_every_saturation_constant_is_exported_for_the_methodology():
    s = F.saturation_points()
    assert s["findings_saturation"] == F.FINDINGS_SATURATION
    assert s["epss_exploitable_at"] == F.EPSS_EXPLOITABLE
    assert s["hygiene_saturation_points"] == F.HYGIENE_SATURATION
    assert s["severity_points"]["CRITICAL"] > s["severity_points"]["HIGH"]


def test_the_export_says_these_are_judgements():
    assert "judgements, not derived truths" in F.saturation_points()["note"]


def test_unclassified_is_absent_from_the_criticality_map_by_design():
    assert "unclassified" not in F.CRITICALITY_VALUE
