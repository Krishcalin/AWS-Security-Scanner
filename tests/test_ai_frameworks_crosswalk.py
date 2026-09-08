"""Phase 2 · slice 2.7 — NIST AI RMF, ISO/IEC 42001 and MITRE ATLAS in the crosswalk.

These tests are about honesty of granularity, which is the thing most easily lost in a
compliance mapping and the thing an auditor is most likely to catch.

Three different source situations produced three different mapping depths:

* **AI RMF** is public, so edges name exact subcategories.
* **ISO 42001** is paywalled. Its nine Annex A objectives (A.2-A.10) are publicly
  documented; the 38 individual control numbers are not. Edges therefore stop at the
  objective. Writing "A.6.2.4" would look more precise and be less true, and the person
  holding the actual standard is exactly the one who would notice.
* **ATLAS** is a threat knowledge base rather than a control catalog, so an edge means
  the control MITIGATES the technique. Only technique IDs published by a citable primary
  source are used.

And no edge claims high confidence, because no official NIST 800-53 -> AI RMF crosswalk
backs them. They are OverWatch's reading, and the notes say so rather than borrowing an
authority that does not exist.
"""
from __future__ import annotations

import io
import json
import os
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DOC = json.loads(io.open(ROOT / "compliance" / "crosswalk.json",
                         encoding="utf-8").read())
FRAMEWORKS = {f["id"]: f for f in DOC["frameworks"]}
CROSSWALK = DOC["crosswalk"]

AI_RMF = "NIST-AI-RMF-1.0"
ISO42001 = "ISO-42001-2023"
ATLAS = "MITRE-ATLAS"

#: The only ATLAS techniques with a citable primary source: AWS publishes these three in
#: the GuardDuty AI Protection finding-type documentation.
CITED_TECHNIQUES = {"AML.T0040", "AML.T0034", "AML.T0051"}


def _edges(framework):
    return {c: e[framework] for c, e in CROSSWALK.items() if framework in e}


# ── the frameworks exist and describe themselves honestly ───────────────────
def test_the_three_ai_frameworks_are_registered():
    for fw in (AI_RMF, ISO42001, ATLAS):
        assert fw in FRAMEWORKS, fw
        assert FRAMEWORKS[fw]["native"] is False, "the spine stays NIST 800-53"


def test_atlas_declares_that_it_is_not_a_control_catalog():
    """The relation is different in kind from every other framework here, and a reader
    who assumes otherwise will read 'this control maps to prompt injection' as a claim
    of equivalence."""
    d = FRAMEWORKS[ATLAS]["description"]
    assert "NOT a control catalog" in d
    assert "MITIGATES" in d


def test_iso42001_declares_its_objective_level_granularity():
    d = FRAMEWORKS[ISO42001]["description"]
    assert "OBJECTIVE level" in d
    assert "paywall" in d.lower()


# ── granularity matches what each source can support ────────────────────────
def test_ai_rmf_targets_are_real_subcategory_identifiers():
    """Function + category.subcategory, e.g. GOVERN 1.6 or MEASURE 2.7."""
    pat = re.compile(r"^(GOVERN|MAP|MEASURE|MANAGE) \d+\.\d+$")
    for control, edge in _edges(AI_RMF).items():
        for t in edge["targets"]:
            assert pat.match(t), f"{control} -> {t!r} is not an AI RMF subcategory id"


def test_iso42001_targets_stop_at_the_objective():
    """A.6 is verifiable from public sources; A.6.2.4 is not. Precision we cannot support
    is worse than the coarser mapping, because it invites a reader to check it."""
    pat = re.compile(r"^A\.(?:[2-9]|10)$")
    for control, edge in _edges(ISO42001).items():
        for t in edge["targets"]:
            assert pat.match(t), (
                f"{control} -> {t!r}: ISO 42001 edges must name an Annex A objective "
                f"(A.2-A.10), not an individual control number we cannot verify")


def test_atlas_targets_are_only_techniques_with_a_citable_source():
    """AWS publishes exactly three ATLAS technique IDs in its GuardDuty AI Protection
    documentation. Everything else in the ATLAS catalog would be recalled rather than
    cited, and a compliance artifact is the wrong place to find out the difference."""
    for control, edge in _edges(ATLAS).items():
        for t in edge["targets"]:
            assert t in CITED_TECHNIQUES, (
                f"{control} -> {t!r} is not one of the AWS-published techniques "
                f"{sorted(CITED_TECHNIQUES)}")


# ── no borrowed authority ───────────────────────────────────────────────────
def test_no_ai_framework_edge_claims_high_confidence():
    """There is no official NIST 800-53 -> AI RMF crosswalk. Claiming high confidence
    would assert an authority that does not exist behind a mapping somebody may rely on."""
    for fw in (AI_RMF, ISO42001, ATLAS):
        for control, edge in _edges(fw).items():
            assert edge["confidence"] in ("low", "medium"), (
                f"{control} -> {fw} claims {edge['confidence']} confidence")


def test_every_edge_states_its_basis():
    for fw in (AI_RMF, ISO42001, ATLAS):
        for control, edge in _edges(fw).items():
            note = edge["note"]
            assert len(note) > 40, f"{control} -> {fw} has no real note"
            if fw == AI_RMF:
                assert "No official" in note, (
                    f"{control} must say no official crosswalk backs it")
            if fw == ISO42001:
                assert "not publicly verifiable" in note or "OBJECTIVE" in note
            if fw == ATLAS:
                assert "MITIGATES" in note


def test_edges_only_target_controls_in_the_frozen_universe():
    universe = set(DOC["nist_universe"])
    for fw in (AI_RMF, ISO42001, ATLAS):
        for control in _edges(fw):
            assert control in universe, f"{control} is outside the frozen 38"


# ── the mappings that carry the AI story ────────────────────────────────────
def test_the_inventory_control_maps_to_the_inventory_subcategory():
    """CM-8 -> GOVERN 1.6 is the strongest edge in the set: GOVERN 1.6 asks for
    mechanisms to inventory AI systems, and CM-8 is the inventory control."""
    assert "GOVERN 1.6" in CROSSWALK["CM-8"][AI_RMF]["targets"]


def test_cost_harvesting_maps_to_denial_of_service_protection():
    """AML.T0034 is inflating inference spend rather than taking data, which is a
    resource-exhaustion problem and not a confidentiality one."""
    assert "AML.T0034" in CROSSWALK["SC-5"][ATLAS]["targets"]


def test_inference_api_access_maps_to_access_enforcement():
    assert "AML.T0040" in CROSSWALK["AC-3"][ATLAS]["targets"]


def test_the_security_evaluation_subcategory_carries_the_vuln_controls():
    for c in ("RA-5", "CA-8", "SC-7"):
        assert "MEASURE 2.7" in CROSSWALK[c][AI_RMF]["targets"], c


# ── the file still loads through the production path ────────────────────────
def test_the_shipped_file_still_validates():
    """The loader rejects unknown frameworks, unknown NIST controls, blank targets and
    bad confidence values. Adding three frameworks by hand is exactly when that matters."""
    from engine import compliance_crosswalk as cx
    edges, frameworks, digest = cx.load_crosswalk()
    assert edges and frameworks and digest, (
        "the shipped file no longer loads through the production path")
    assert {AI_RMF, ISO42001, ATLAS} <= set(frameworks)
    # The loader is where a hand-edited file gets caught: it rejects edges targeting a
    # native framework, unknown NIST controls, blank targets, missing confidence and
    # duplicate framework ids. Reaching this line at all means none of those fired.
    assert len(frameworks) == 44
