"""The shipping posture score, and the fact that losing a permission improved it.

THE DEFECT THIS FILE PINS
--------------------------
`aws_live_scanner.compute_risk_score` is 100 - the severity penalty for every FAIL
it SAW. A check that returned AccessDenied produces no result, so it produces no
penalty, so the score goes UP. On the four-check fixture below, losing
iam:ListUsers moves an account from 75/C to 85/B. The scan got worse and the grade
improved.

That number is written to `scans.posture_score`, drives the console grade, and
accumulates into the 24-month history OW2-CC-006 requires -- so the defect is baked
into the trend line, not just the tile.

WHY THE ARITHMETIC IS UNCHANGED
--------------------------------
Silently re-weighting a shipped score rewrites every dashboard and every stored
trend. `aws_epistemics` already records that as a change needing its own regression
baseline. So `qualify()` leaves the number EXACTLY as it was -- and the first test
below is the one that guarantees it, because the tempting "fix" is to subtract the
unassessed penalty from the score and quietly move everybody's history.

What changes is the LETTER GRADE, and only when coverage is too low. The grade is
the artefact that gets copied into a scorecard, a board pack and an auditor's file,
all of which strip the caveat travelling beside it.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_live_scanner as als  # noqa: E402
from engine import aws_riskscore as R  # noqa: E402

R_ = als.Result

SEV = {"IAM-02": "CRITICAL", "IAM-03": "HIGH", "S3-09": "MEDIUM"}
W = als.SEVERITY_WEIGHTS


def full():
    return [R_("FAIL", "IAM-01", "IAM", "r", "m", "CRITICAL"),
            R_("FAIL", "IAM-02", "IAM", "r", "m", "HIGH"),
            R_("FAIL", "IAM-03", "IAM", "r", "m", "HIGH"),
            R_("PASS", "S3-01", "S3", "r", "m")]


def denied():
    return [R_("FAIL", "IAM-01", "IAM", "r", "m", "CRITICAL"),
            R_("PASS", "S3-01", "S3", "r", "m")]


DENIALS = {"IAM-02": "AccessDenied — missing iam:ListUsers",
           "IAM-03": "AccessDenied — missing iam:ListUsers"}


# ── the defect itself, pinned so it cannot be argued away ────────────────────

def test_losing_a_permission_raises_the_raw_posture_score():
    # This is NOT desired behaviour. It is the behaviour, pinned, so that the
    # qualification layer below has something to be measured against.
    assert als.compute_risk_score(full()) == 75.0
    assert als.compute_risk_score(denied()) == 85.0
    assert als.score_to_grade(75.0) == "C" and als.score_to_grade(85.0) == "B"


# ── the score must not move ──────────────────────────────────────────────────

def test_qualifying_never_changes_the_score():
    # The tempting fix is to subtract the unassessed penalty. That silently
    # rewrites scans.posture_score and 24 months of trend for every account.
    for results, missing in ((full(), {}), (denied(), DENIALS)):
        raw = als.compute_risk_score(results)
        assert als.qualified_posture(results, missing).score == raw


def test_a_complete_scan_is_byte_identical_to_before():
    q = als.qualified_posture(full(), {})
    assert q.score == 75.0
    assert q.grade == "C"
    assert q.complete
    assert q.caveat() == "", "a complete scan must gain no noise"
    assert not q.provisional and not q.withheld


# ── the grade is what gets withheld ──────────────────────────────────────────

def test_the_grade_is_withheld_when_coverage_collapses():
    q = als.qualified_posture(denied(), DENIALS)          # 50% coverage
    assert q.score == 85.0, "the score survives so trend lines do not break"
    assert q.grade is None, "the letter travels without its caveat, so it is withheld"
    assert q.withheld


def test_a_small_gap_leaves_a_provisional_grade_rather_than_none():
    results = full() + [R_("PASS", "S3-%02d" % i, "S3", "r", "m") for i in range(20)]
    q = als.qualified_posture(results, {"KMS-07": "AccessDenied — missing kms:GetKeyPolicy"})
    assert q.coverage > R.POSTURE_COVERAGE_FLOOR
    assert q.grade is not None
    assert q.provisional and not q.withheld
    assert "provisional" in q.caveat().lower()


def test_the_floor_is_strict_by_design():
    assert R.POSTURE_COVERAGE_FLOOR == 0.9


# ── the unassessed band ──────────────────────────────────────────────────────

def test_unassessed_penalty_uses_the_declared_severity_not_the_result_severity():
    # The fixture calls IAM-02 HIGH; CHECK_SEVERITY declares it CRITICAL. The
    # declared map is the source of truth, because a refused check produced no
    # result to read a severity from in the first place.
    q = als.qualified_posture(denied(), DENIALS)
    assert als.CHECK_SEVERITY["IAM-02"] == "CRITICAL"
    assert q.unassessed_penalty == W["CRITICAL"]


def test_worst_case_score_is_the_other_end_of_the_interval():
    q = als.qualified_posture(denied(), DENIALS)
    assert q.worst_case_score == q.score - q.unassessed_penalty
    assert q.worst_case_score <= q.score


def test_worst_case_never_goes_below_zero():
    q = R.qualify(3.0, ["A-01"], {"B-01": "denied"},
                  check_severity={"B-01": "CRITICAL"}, severity_weights=W)
    assert q.worst_case_score == 0.0


def test_the_reported_score_is_a_ceiling_not_a_floor():
    # 85 with 15 unassessed means the truth lies in [70, 85]. The reported number
    # is the best case. An earlier draft of the caveat called it a floor.
    q = als.qualified_posture(denied(), DENIALS)
    c = q.caveat()
    assert "ceiling" in c
    assert "floor" not in c


# ── the phantom zero, one level down ─────────────────────────────────────────

def test_a_refused_check_with_no_declared_severity_is_not_costless():
    # IAM-03 is not in CHECK_SEVERITY. Silently weighting it 0 would repeat the
    # exact mistake this module exists to fix, one level down.
    assert "IAM-03" not in als.CHECK_SEVERITY
    q = als.qualified_posture(denied(), DENIALS)
    assert q.unknown_severity == 1
    assert "lower bound on the damage" in q.caveat()


def test_the_penalty_is_declared_a_lower_bound_when_severities_are_unknown():
    q = als.qualified_posture(denied(), DENIALS)
    assert q.to_dict()["unassessed_penalty_is_lower_bound"] is True
    assert "at worst" in q.caveat()


def test_a_fully_declared_gap_is_not_a_lower_bound():
    q = R.qualify(85.0, ["A-01"], {"B-01": "denied"},
                  check_severity={"B-01": "HIGH"}, severity_weights=W)
    assert q.unknown_severity == 0
    assert q.to_dict()["unassessed_penalty_is_lower_bound"] is False
    assert "lower bound" not in q.caveat()


# ── mechanics ────────────────────────────────────────────────────────────────

def test_a_check_that_ran_is_not_counted_as_denied():
    # A check can be denied in one region and evaluated in another; observing it
    # anywhere means it is not wholly unevaluated.
    q = als.qualified_posture(full(), {"IAM-02": "AccessDenied in eu-west-1"})
    assert q.not_evaluated == 0
    assert q.complete


def test_coverage_is_evaluated_over_evaluated_plus_denied():
    q = als.qualified_posture(denied(), DENIALS)
    assert q.evaluated == 2 and q.not_evaluated == 2
    assert q.coverage == 0.5


def test_no_denials_means_full_coverage():
    assert als.qualified_posture(full(), {}).coverage == 1.0


def test_empty_scan_does_not_divide_by_zero():
    q = R.qualify(100.0, [], {})
    assert q.coverage == 1.0 and q.complete


def test_largest_gaps_are_ranked_by_penalty():
    q = R.qualify(90.0, ["A-01"],
                  {"LOW-01": "denied", "CRIT-01": "denied", "MED-01": "denied"},
                  check_severity={"LOW-01": "LOW", "CRIT-01": "CRITICAL",
                                  "MED-01": "MEDIUM"},
                  severity_weights=W)
    assert q.top_unassessed[0][0] == "CRIT-01"


def test_the_caveat_names_the_missing_permission():
    q = als.qualified_posture(denied(), DENIALS)
    assert "iam:ListUsers" in q.caveat()


def test_to_dict_carries_every_field_a_report_needs():
    d = als.qualified_posture(denied(), DENIALS).to_dict()
    assert d["posture_score"] == 85.0
    assert d["posture_grade"] is None
    assert d["posture_grade_withheld"] is True
    assert d["coverage_pct"] == 50.0
    assert d["checks_not_evaluated"] == 2
    assert d["worst_case_score"] == 70.0
    assert d["caveat"]


def test_qualify_is_pure_and_reproducible():
    a = als.qualified_posture(denied(), DENIALS)
    b = als.qualified_posture(denied(), DENIALS)
    assert a == b


# ── the wiring ───────────────────────────────────────────────────────────────

def test_the_scanner_exposes_its_own_coverage_manifest():
    from engine import aws_perm_ledger

    class FakeScan:
        results = denied()
        _coverage = aws_perm_ledger.CoverageManifest()

    sc = FakeScan()
    sc._coverage.note_denied("IAM-02", "iam:ListUsers")
    q = als.qualified_posture(sc.results, dict(sc._coverage.not_evaluated))
    assert q.not_evaluated == 1
    assert "iam:ListUsers" in q.caveat()


def test_serialize_scanner_carries_posture_coverage():
    from engine import aws_perm_ledger
    from hub import cnapp_service

    class FakeScan:
        account, region = "111111111111", "us-east-1"
        results = denied()
        graph = None
        attack_paths: list = []
        choke_points: list = []
        _perm_ledger = None

        def __init__(self):
            self._coverage = aws_perm_ledger.CoverageManifest()

        def _build_finding_catalog(self):
            return []

    sc = FakeScan()
    sc._coverage.note_denied("IAM-02", "iam:ListUsers")
    sc._coverage.note_denied("IAM-03", "iam:ListUsers")
    d = cnapp_service.serialize_scanner(sc)
    assert d["posture_score"] == 85.0, "the stored score must not move"
    assert d["posture_grade"] is None, "the grade is withheld at 50% coverage"
    assert d["posture_coverage"]["coverage_pct"] == 50.0
    assert d["posture_coverage"]["worst_case_score"] == 70.0
