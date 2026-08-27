"""Phase 5 · slice 5.1 — CISA ZTMM v2 scoring, with its work shown.

The roadmap's framing is that *the differentiator is the evidence, not the label*, and
almost every test here defends a refusal to produce a label the evidence does not support.

**The structure was verified, not inferred.** Five pillars times seven functions gives 35
and is wrong: Applications and Data each carry a fifth pillar-specific function, so the
model has **37**. A scorer built on the obvious inference would under-count two pillars'
denominators and report better coverage than it has — the failure slice 4.5 shipped and
had to correct.

**No overall score, ever.** An estate Advanced on four pillars and unscoreable on Devices
does not have a maturity level; it has four maturity levels and a blind spot.

**A pillar takes its weakest function, not its average.** Zero trust is a chain, and
averaging is how a scorer flatters an estate into a number nobody can act on.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_ztmm as Z


class R:
    def __init__(self, check_id, status):
        self.check_id, self.status = check_id, status


def mapping(**stages):
    """{(pillar, function): {stage: [checks]}} for one function."""
    return {("Identity", "Authentication"): dict(stages)}


# ── the structure ───────────────────────────────────────────────────────────
def test_the_model_has_thirty_seven_functions_not_thirty_five():
    """The load-bearing verification. Five-times-seven is the obvious inference and it
    is wrong; Applications and Data each carry a fifth pillar-specific function."""
    assert Z.TOTAL_FUNCTIONS == 37
    assert len(Z.PILLARS) == 5


def test_function_counts_are_not_uniform():
    counts = {p: len(Z.FUNCTIONS[p]) for p in Z.PILLARS}
    assert counts == {"Identity": 7, "Devices": 7, "Networks": 7,
                      "Applications and Workloads": 8, "Data": 8}


def test_every_pillar_carries_the_three_cross_cutting_functions():
    """They are functions WITHIN each pillar, not a sixth pillar."""
    for p in Z.PILLARS:
        for cc in Z.CROSS_CUTTING:
            assert cc in Z.FUNCTIONS[p], (p, cc)


def test_the_source_is_named_and_dated():
    """CISA revises the model. An undated snapshot silently becomes a wrong claim."""
    assert "v2.0" in Z.SOURCE and Z.SOURCE_DATE.count("-") == 2


# ── unscored is not a stage ─────────────────────────────────────────────────
def test_a_function_nothing_maps_to_is_unscored_not_traditional():
    """Calling our own blind spot 'Traditional' turns a limit of the scanner into a
    finding about the customer."""
    r = Z.score_function("Identity", "Authentication", {}, [])
    assert r["stage"] == Z.UNSCORED
    assert "NOT assessed" in r["why"]


def test_unscored_is_not_on_the_stage_scale():
    assert Z.UNSCORED not in Z.STAGES
    assert Z.stage_rank(Z.UNSCORED) == -1


def test_an_agentless_blind_spot_explains_itself():
    """'Devices is unscoreable' is too coarse — the reason differs per function."""
    r = Z.score_function("Devices", "Device threat detection", {}, [])
    assert r["stage"] == Z.UNSCORED
    assert "endpoint agent" in r["blind_spot"]


def test_the_blind_list_is_per_function_not_per_pillar():
    """2.2 and 2.3 have real AWS-side signal; 2.1 and 2.4 do not."""
    blind = {f for (p, f) in Z.AGENTLESS_BLIND if p == "Devices"}
    assert "Resource access" not in blind
    assert "Asset and supply-chain risk management" not in blind
    assert "Device threat detection" in blind


# ── scoring a function ──────────────────────────────────────────────────────
def test_a_stage_is_reached_only_when_every_mapped_check_passes():
    """A maturity claim built from a majority of passing checks is a claim about the
    average, not about the estate."""
    m = mapping(Initial=["A", "B"])
    ok = Z.score_function("Identity", "Authentication", m,
                          [R("A", "PASS"), R("B", "PASS")])
    assert ok["stage"] == Z.INITIAL
    part = Z.score_function("Identity", "Authentication", m,
                            [R("A", "PASS"), R("B", "FAIL")])
    assert part["stage"] == Z.TRADITIONAL
    assert part["failing"] == ["B"]


def test_stages_are_cumulative_and_a_gap_stops_the_climb():
    m = mapping(Initial=["A"], Advanced=["B"], Optimal=["C"])
    r = Z.score_function("Identity", "Authentication", m,
                         [R("A", "PASS"), R("B", "FAIL"), R("C", "PASS")])
    assert r["stage"] == Z.INITIAL      # Optimal passing does not skip the Advanced gap


def test_the_top_stage_is_reachable():
    m = mapping(Initial=["A"], Advanced=["B"], Optimal=["C"])
    r = Z.score_function("Identity", "Authentication", m,
                         [R("A", "PASS"), R("B", "PASS"), R("C", "PASS")])
    assert r["stage"] == Z.OPTIMAL


def test_one_failing_resource_outweighs_passing_ones_of_the_same_check():
    m = mapping(Initial=["A"])
    r = Z.score_function("Identity", "Authentication", m,
                         [R("A", "PASS"), R("A", "FAIL")])
    assert r["stage"] == Z.TRADITIONAL


def test_a_blocked_check_is_absence_of_evidence_not_a_traditional_score():
    m = mapping(Initial=["A"])
    r = Z.score_function("Identity", "Authentication", m, [],
                         not_evaluated={"A": "AccessDenied"})
    assert "absence of evidence, not a Traditional posture" in r["why"]


def test_the_evidence_is_returned_alongside_the_stage():
    """The differentiator is the evidence, not the label."""
    m = mapping(Initial=["A", "B"])
    r = Z.score_function("Identity", "Authentication", m, [R("A", "PASS")])
    assert r["evidence"]["Initial"]["checks"] == ["A", "B"]
    assert r["evidence"]["Initial"]["ran"] == ["A"]


# ── scoring a pillar ────────────────────────────────────────────────────────
def test_a_pillar_takes_its_weakest_function_not_its_average():
    """Optimal authentication with Traditional access management is not Advanced."""
    m = {("Identity", "Authentication"): {"Initial": ["A"], "Advanced": ["B"],
                                          "Optimal": ["C"]},
         ("Identity", "Access management"): {"Initial": ["D"]}}
    p = Z.score_pillar("Identity", m, [R("A", "PASS"), R("B", "PASS"),
                                       R("C", "PASS"), R("D", "FAIL")])
    assert p["stage"] == Z.TRADITIONAL
    assert "WEAKEST" in p["statement"]


def test_unscored_functions_are_excluded_from_the_pillar_stage():
    """They cannot drag a score down — and must not silently prop one up either."""
    m = {("Identity", "Authentication"): {"Initial": ["A"]}}
    p = Z.score_pillar("Identity", m, [R("A", "PASS")])
    assert p["stage"] == Z.INITIAL
    assert p["functions_scored"] == 1
    assert p["functions_unscored"] == 6
    assert "excluded from the stage rather than counted as Traditional" in p["statement"]


def test_a_pillar_with_nothing_scored_says_so_plainly():
    p = Z.score_pillar("Devices", {}, [])
    assert p["stage"] == Z.UNSCORED
    assert "NOT SCORED" in p["statement"]
    assert "not a finding about the estate" in p["statement"]


# ── the estate ──────────────────────────────────────────────────────────────
def test_there_is_no_overall_maturity_score():
    """The number every competing product prints, and the one that hides which pillar
    is unscoreable."""
    e = Z.score_estate({}, [])
    assert e["overall_stage"] is None
    assert "no overall maturity score" in e["statement"].lower()


def test_the_estate_reports_the_true_denominator():
    e = Z.score_estate({("Identity", "Authentication"): {"Initial": ["A"]}},
                       [R("A", "PASS")])
    assert e["functions_total"] == 37
    assert e["functions_scored"] == 1
    assert e["functions_unscored"] == 36
    assert "of 37" in e["statement"]


def test_every_pillar_appears_even_when_unscoreable():
    e = Z.score_estate({}, [])
    assert set(e["pillars"]) == set(Z.PILLARS)


# ── robustness ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, {}, "nope", 7])
def test_nothing_raises_on_malformed_input(bad):
    Z.score_function("Identity", "Authentication",
                     bad if isinstance(bad, dict) else None, None)
    Z.score_pillar("Identity", bad if isinstance(bad, dict) else None, None)
    Z.score_estate(bad if isinstance(bad, dict) else None, None)


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(Z), re.M)


# ── the mapping ─────────────────────────────────────────────────────────────
def test_the_mapping_names_only_real_checks():
    """The guard that matters most. A table authored from a reading of the model is
    exactly where invented identifiers appear -- and an id that does not exist maps to
    nothing, scores nothing, and reads as an honest UNSCORED rather than as the bug it
    is. Same class as the pickle table naming builtins.open in slice 4.6."""
    from engine import aws_live_scanner as A
    ids = {c for stages in Z.ZTMM_MAPPING.values()
           for lst in stages.values() for c in lst}
    missing = sorted(i for i in ids if i not in A.CHECK_SEVERITY)
    assert not missing, f"mapping names checks that do not exist: {missing}"


def test_the_mapping_uses_only_real_stages():
    for key, stages in Z.ZTMM_MAPPING.items():
        for stage in stages:
            assert stage in Z.STAGES, (key, stage)


def test_the_mapping_names_only_real_functions():
    for (pillar, function) in Z.ZTMM_MAPPING:
        assert pillar in Z.PILLARS, pillar
        assert function in Z.FUNCTIONS[pillar], (pillar, function)


def test_no_function_is_both_mapped_and_declared_blind():
    """Claiming a function is unscoreable while scoring it would be incoherent."""
    overlap = set(Z.ZTMM_MAPPING) & set(Z.AGENTLESS_BLIND)
    assert not overlap, overlap


def test_the_shipped_mapping_leaves_most_functions_honestly_unscored():
    """22 of 37 today. The point is that the other 15 report as UNSCORED with a reason
    rather than being quietly scored Traditional to fill the table."""
    e = Z.score_estate(Z.ZTMM_MAPPING, [])
    assert e["functions_total"] == 37
    assert 0 < len(Z.ZTMM_MAPPING) < 37
    assert e["overall_stage"] is None


def test_devices_is_mostly_unscoreable_and_says_which_parts():
    """Two functions have real AWS-side signal; five do not, each with its own reason."""
    p = Z.score_pillar("Devices", Z.ZTMM_MAPPING, [])
    blind = [r for r in p["rows"] if r["blind_spot"]]
    assert len(blind) == 5
    assert all(r["stage"] == Z.UNSCORED for r in blind)
