"""Phase 4 · slice 4.5 — the AI compliance evidence pack.

An auditor does not want failures. They want to know, control by control, whether it was
assessed, by what, and what the answer rests on — and above all **what was not assessed**.

Nearly every test here defends one property: **a control with no mapped check must never
read as satisfied.** That is the phantom pass at framework scale and the standard way a
compliance report lies — a framework has 72 controls, a product maps 17, and the summary
shows green because the other 55 produced no failures. Producing no failures and being
satisfied are different facts.

Two consequences run through the module and are pinned here. There is **no status meaning
"compliant"** — the strongest available is `ASSESSED_PASS`, *these checks ran and passed*.
And coverage is reported as **counts, never a percentage**, because "68% compliant" is
exactly the sentence this module exists to make impossible to write.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_evidence as EV


class R:
    """Minimal stand-in for aws_live_scanner.Result."""
    def __init__(self, check_id, status, resource="r", severity="HIGH"):
        self.check_id, self.status = check_id, status
        self.resource, self.severity = resource, severity


XW = {
    "AC-3": {"NIST-AI-RMF-1.0": {"targets": ["GOVERN 1.4"], "confidence": "low",
                                 "note": "OverWatch's reading of the two texts."}},
    "SC-28": {"NIST-AI-RMF-1.0": {"targets": ["MAP 5.1"], "confidence": "medium",
                                  "note": "encryption at rest."}},
    "AU-2": {"NIST-AI-RMF-1.0": {"targets": ["GOVERN 1.4"], "confidence": "high",
                                 "note": "audit."}},
}
CM = {"VEC-02": {"NIST": "AC-3"}, "AILOG-02": {"NIST": "SC-28"},
      "AILOG-04": {"NIST": "AU-2"}, "IAM-01": {"NIST": "AC-3"}}


# ── the mapping ─────────────────────────────────────────────────────────────
def test_a_framework_control_collects_every_spine_control_that_reaches_it():
    rows = EV.framework_controls(XW, "NIST-AI-RMF-1.0")
    assert rows["GOVERN 1.4"]["spine"] == ["AC-3", "AU-2"]


def test_confidence_is_the_lowest_of_the_contributing_mappings():
    """An evidence row is only as trustworthy as the weakest link that produced it.
    Taking the highest would let one confident mapping launder several speculative
    ones."""
    rows = EV.framework_controls(XW, "NIST-AI-RMF-1.0")
    assert rows["GOVERN 1.4"]["confidence"] == "low"      # AC-3 low beats AU-2 high


def test_the_mapping_provenance_is_carried_not_dropped():
    """The crosswalk is candid that no official NIST 800-53 -> AI RMF crosswalk exists
    and these are OverWatch's reading. Dropping that caveat would launder an opinion
    into a finding."""
    rows = EV.framework_controls(XW, "NIST-AI-RMF-1.0")
    assert any("OverWatch's reading" in n for n in rows["GOVERN 1.4"]["notes"])


def test_a_framework_with_no_mappings_yields_nothing():
    assert EV.framework_controls(XW, "MITRE-ATLAS") == {}


# ── the statuses ────────────────────────────────────────────────────────────
def _row(control="GOVERN 1.4", spine=("AC-3",), conf="low"):
    return {"control": control, "spine": list(spine), "confidence": conf, "notes": []}


def test_a_control_with_no_mapped_check_is_not_assessed():
    """The load-bearing test of the whole slice."""
    e = EV.control_evidence(_row(spine=["ZZ-99"]), CM, [])
    assert e["status"] == EV.NOT_ASSESSED
    assert "not the same as being satisfied" in e["why"]


def test_a_not_assessed_control_never_reads_as_passing():
    e = EV.control_evidence(_row(spine=["ZZ-99"]), CM, [R("VEC-02", "PASS")])
    assert e["status"] != EV.ASSESSED_PASS


def test_mapped_checks_that_all_passed_are_assessed_pass():
    e = EV.control_evidence(_row(), CM, [R("VEC-02", "PASS"), R("IAM-01", "PASS")])
    assert e["status"] == EV.ASSESSED_PASS


def test_assessed_pass_does_not_claim_the_control_is_satisfied():
    """The strongest thing a scanner may say. Whether it satisfies the control is the
    auditor's judgement, and a tool that pre-empts it is selling an opinion."""
    e = EV.control_evidence(_row(), CM, [R("VEC-02", "PASS"), R("IAM-01", "PASS")])
    assert "not a determination that the control is satisfied" in e["why"]


def test_one_failing_check_makes_the_control_fail():
    e = EV.control_evidence(_row(), CM, [R("VEC-02", "PASS"), R("IAM-01", "FAIL")])
    assert e["status"] == EV.ASSESSED_FAIL
    assert e["failing"][0]["check"] == "IAM-01"


def test_one_failing_resource_outweighs_passing_ones_of_the_same_check():
    """A control with one failing resource has not passed."""
    e = EV.control_evidence(_row(), CM, [R("VEC-02", "PASS", "a"),
                                         R("VEC-02", "FAIL", "b"),
                                         R("IAM-01", "PASS")])
    assert e["status"] == EV.ASSESSED_FAIL


def test_a_mapped_but_unevaluable_control_is_not_evaluated():
    """An absence of evidence, not an absence of findings."""
    e = EV.control_evidence(_row(), CM, [], not_evaluated={"VEC-02": "AccessDenied",
                                                           "IAM-01": "AccessDenied"})
    assert e["status"] == EV.NOT_EVALUATED
    assert "absence of evidence" in e["why"]


def test_a_partly_evaluated_control_is_partial_not_pass():
    """The result is incomplete, not clean — the distinction a green tick destroys."""
    e = EV.control_evidence(_row(), CM, [R("VEC-02", "PASS")],
                            not_evaluated={"IAM-01": "AccessDenied"})
    assert e["status"] == EV.PARTIAL
    assert "incomplete, not clean" in e["why"]


def test_blocked_checks_are_named():
    e = EV.control_evidence(_row(), CM, [R("VEC-02", "PASS")],
                            not_evaluated={"IAM-01": "AccessDenied"})
    assert e["checks_blocked"] == ["IAM-01"]


# ── epistemics ──────────────────────────────────────────────────────────────
def test_the_epistemic_class_of_the_evidence_is_carried():
    """A control evidenced only by CONFIGURED checks has not been shown to WORK, and an
    auditor reading 'passed' without that qualifier is told more than was established."""
    e = EV.control_evidence(_row(), CM, [R("VEC-02", "PASS"), R("IAM-01", "PASS")])
    assert e["epistemics"] and all(isinstance(c, str) for c in e["epistemics"])


def test_a_control_with_nothing_run_carries_no_epistemic_claim():
    e = EV.control_evidence(_row(spine=["ZZ-99"]), CM, [])
    assert e["epistemics"] == []


# ── the pack ────────────────────────────────────────────────────────────────
def test_the_pack_covers_every_ai_framework():
    pack = EV.build_pack(XW, CM, [R("VEC-02", "PASS")])
    assert set(pack["frameworks"]) == set(EV.AI_FRAMEWORKS)


def test_the_pack_carries_scan_coverage_apart_from_mapping_coverage():
    """Two different gaps. A reader who conflates 'no check maps here' with 'the scan
    could not look' will over-trust the pack."""
    pack = EV.build_pack(XW, CM, [], coverage={
        "complete": False, "unscanned_regions": ["eu-west-1"],
        "not_evaluated": {"VEC-02": "AccessDenied"},
        "missing_actions": ["aoss:ListCollections"]})
    sc = pack["scan_coverage"]
    assert sc["complete"] is False
    assert sc["unscanned_regions"] == ["eu-west-1"]
    assert sc["missing_actions"] == ["aoss:ListCollections"]


def test_scan_coverage_feeds_the_control_rows():
    pack = EV.build_pack(XW, CM, [], coverage={
        "not_evaluated": {"VEC-02": "AccessDenied", "IAM-01": "AccessDenied"}})
    rmf = pack["frameworks"]["NIST-AI-RMF-1.0"]["controls"]
    gov = next(c for c in rmf if c["control"] == "GOVERN 1.4")
    assert gov["status"] == EV.NOT_EVALUATED


# ── the summary ─────────────────────────────────────────────────────────────
def test_the_summary_is_counts_not_a_percentage():
    """'68% compliant' is the sentence this module exists to make impossible."""
    pack = EV.build_pack(XW, CM, [R("VEC-02", "PASS")])
    s = pack["frameworks"]["NIST-AI-RMF-1.0"]["summary"]
    assert "%" not in s["statement"]
    assert s["controls_total"] >= 1
    assert "controls_reached" in s and "controls_not_assessed" in s


def test_the_summary_states_what_was_not_looked_at():
    # With no catalog size the pack must say the fraction is UNKNOWN rather than
    # computing one from its own reach -- the bug the denominator tests below pin.
    pack = EV.build_pack(XW, CM, [R("VEC-02", "PASS")])
    st = pack["frameworks"]["NIST-AI-RMF-1.0"]["summary"]["statement"]
    assert "UNKNOWN" in st
    # And with one, it names what was never looked at.
    pack2 = EV.build_pack(XW, CM, [R("VEC-02", "PASS")],
                          framework_meta=[{"id": "NIST-AI-RMF-1.0",
                                           "catalog_size": 72}])
    assert "were NOT looked at" in         pack2["frameworks"]["NIST-AI-RMF-1.0"]["summary"]["statement"]


# ── the words this module refuses ───────────────────────────────────────────
def test_no_status_means_compliant():
    """A scanner establishes that checks ran and what they found. Whether that satisfies
    a control is the auditor's call."""
    for s in EV.STATUSES:
        assert "COMPLIANT" not in s.upper()


def test_the_module_never_says_compliant_or_certified():
    import inspect
    src = inspect.getsource(EV).lower()
    for banned in ("is compliant", "fully compliant", "certified", "attestation of"):
        assert banned not in src, banned


# ── robustness ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, {}, "nope", 7])
def test_nothing_raises_on_malformed_input(bad):
    EV.framework_controls(bad if isinstance(bad, dict) else None, "NIST-AI-RMF-1.0")
    EV.control_evidence(bad if isinstance(bad, dict) else None, CM, [])
    EV.build_pack(bad if isinstance(bad, dict) else None, CM, [])
    EV.coverage_summary(None)


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(EV), re.M)


def test_it_works_against_the_shipped_crosswalk():
    """Not a fixture: the real file, so a change to the crosswalk that breaks the pack
    fails here rather than in a customer's audit."""
    from engine import compliance_crosswalk
    from engine import aws_live_scanner as A
    # (crosswalk, frameworks, digest) -- the crosswalk comes FIRST. The signature is
    # Tuple[Dict, Dict, str], which is ambiguous, and the first authoring of this line
    # had it backwards; the test failed against the real file rather than passing
    # against an assumption, which is why it reads the shipped crosswalk at all.
    xw, _frameworks, _digest = compliance_crosswalk.get_crosswalk()
    pack = EV.build_pack(xw, A.COMPLIANCE_MAP, [])
    rmf = pack["frameworks"]["NIST-AI-RMF-1.0"]
    assert rmf["summary"]["controls_total"] > 0
    assert all(c["status"] in EV.STATUSES for c in rmf["controls"])


# ── the denominator ─────────────────────────────────────────────────────────
def test_the_denominator_is_the_framework_not_our_reach():
    """The bug this module shipped with, and the exact failure it was written to
    prevent, reproduced in its own summary.

    A framework control only enters `rows` if the crosswalk already maps it, so the
    mapped set is always N-of-N by construction. Against the real crosswalk that read
    "12 of 12 reached" for NIST AI RMF — a framework with 72 controls. A reader would
    have taken it as complete coverage of a framework the scan reaches one sixth of."""
    rows = [{"control": "GOVERN 1.4", "status": EV.ASSESSED_PASS}]
    s = EV.coverage_summary(rows, catalog_size=72)
    assert s["controls_in_framework"] == 72
    assert s["controls_mapped"] == 1
    assert s["controls_unmapped"] == 71
    assert "1 of 72" in s["statement"]
    assert "were NOT looked at" in s["statement"]


def test_an_absent_catalog_size_says_unknown_rather_than_implying_full_coverage():
    """Silence here is what produced the bug. If the framework's size is not supplied,
    the fraction is stated as unknown rather than computed from our own reach."""
    s = EV.coverage_summary([{"control": "X", "status": EV.ASSESSED_PASS}])
    assert s["controls_in_framework"] is None
    assert "UNKNOWN" in s["statement"]
    assert " of 1 " not in s["statement"]


def test_the_real_pack_reports_the_true_fraction():
    """Against the shipped crosswalk and framework catalog, not a fixture."""
    from engine import compliance_crosswalk
    from engine import aws_live_scanner as A
    xw, frameworks, _digest = compliance_crosswalk.get_crosswalk()
    meta = list(frameworks.values()) if isinstance(frameworks, dict) else frameworks
    pack = EV.build_pack(xw, A.COMPLIANCE_MAP, [], framework_meta=meta)
    rmf = pack["frameworks"]["NIST-AI-RMF-1.0"]["summary"]
    assert rmf["controls_in_framework"] == 72
    assert rmf["controls_mapped"] < rmf["controls_in_framework"]
    assert rmf["controls_unmapped"] > 0
