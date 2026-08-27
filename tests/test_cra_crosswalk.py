"""Lane R1 — the EU Cyber Resilience Act framework in the compliance crosswalk.

These pin two things that are easy to get wrong and expensive to get wrong.

First, the ANNEX I STRUCTURE: Part I is 13 requirements lettered (a)-(m), Part II is 8
numbered (1)-(8). A target id outside that set is a fabricated citation, and a
fabricated citation in a compliance artefact is worse than no artefact.

Second, the SCOPE HONESTY: CRA obligations attach to the PRODUCT a manufacturer places
on the EU market, while OverWatch assesses the ESTATE it runs on. The framework
description has to say so, because the fine ceiling is EUR 15 million or 2.5% of
worldwide turnover and nobody should read a percentage here as conformity.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import compliance_crosswalk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Annex I as published: Part I (a)-(m), Part II (1)-(8).
PART_I = tuple(f"I({c})" for c in "abcdefghijklm")
PART_II = tuple(f"II({i})" for i in range(1, 9))
ANNEX_I = frozenset(PART_I + PART_II)


@pytest.fixture(scope="module")
def loaded():
    crosswalk, frameworks, _digest = compliance_crosswalk.get_crosswalk()
    return crosswalk, frameworks


def _cra_edges(crosswalk):
    return {n: e["EU-CRA"] for n, e in crosswalk.items() if "EU-CRA" in e}


# ── the framework itself ────────────────────────────────────────────────────
def test_the_cra_framework_is_registered(loaded):
    _crosswalk, frameworks = loaded
    assert "EU-CRA" in frameworks
    cra = frameworks["EU-CRA"]
    assert cra["native"] is False, "CRA is derived from the NIST spine, not native"
    assert "2024/2847" in cra["name"]
    assert cra["catalog_size"] == len(ANNEX_I) == 21


def test_the_description_states_both_dates_and_does_not_conflate_them():
    """The Article 14 reporting clock (Sep 2026) and the Annex I SBOM requirement
    (Dec 2027) are different duties. Presenting SBOM tooling as an answer to the
    2026 date is the specific error this framework exists to avoid repeating."""
    _crosswalk, frameworks = compliance_crosswalk.get_crosswalk()[0], \
        compliance_crosswalk.get_crosswalk()[1]
    desc = frameworks["EU-CRA"]["description"]
    assert "11 September 2026" in desc
    assert "11 December 2027" in desc
    assert "Single Reporting Platform" in desc


def test_the_description_carries_the_product_versus_estate_caveat():
    """CRA binds the product placed on the market; we assess the estate it runs on.
    Without this stated, a percentage on a console reads as conformity."""
    _crosswalk, frameworks = compliance_crosswalk.get_crosswalk()[0], \
        compliance_crosswalk.get_crosswalk()[1]
    desc = frameworks["EU-CRA"]["description"].lower()
    assert "supporting evidence" in desc
    assert "never conformity itself" in desc


def test_the_framework_cites_primary_sources(loaded):
    _crosswalk, frameworks = loaded
    srcs = " ".join(frameworks["EU-CRA"]["sources"])
    assert "eur-lex.europa.eu" in srcs
    assert "digital-strategy.ec.europa.eu" in srcs


# ── every citation is real ──────────────────────────────────────────────────
def test_every_target_is_a_real_annex_i_requirement(loaded):
    """The guard against a fabricated citation. Annex I has exactly 21 numbered
    requirements; anything else is invented."""
    crosswalk, _frameworks = loaded
    bad = {}
    for nist, edge in _cra_edges(crosswalk).items():
        stray = [t for t in edge["targets"] if t not in ANNEX_I]
        if stray:
            bad[nist] = stray
    assert not bad, f"targets outside Annex I (a)-(m) / (1)-(8): {bad}"


def test_target_ids_use_the_published_citation_form(loaded):
    crosswalk, _frameworks = loaded
    pat = re.compile(r"^(I\([a-m]\)|II\([1-8]\))$")
    for nist, edge in _cra_edges(crosswalk).items():
        for t in edge["targets"]:
            assert pat.match(t), f"{nist} -> {t!r} is not a published Annex I citation"


def test_the_sbom_requirement_maps_to_the_component_inventory_control(loaded):
    """II(1) is the machine-readable SBOM obligation and the one piece of the CRA
    OverWatch genuinely already builds. CM-8 is the control that carries it."""
    crosswalk, _frameworks = loaded
    edges = _cra_edges(crosswalk)
    assert "CM-8" in edges, "the component-inventory control has no CRA edge"
    assert "II(1)" in edges["CM-8"]["targets"]
    assert edges["CM-8"]["confidence"] == "high"


# ── shape and honesty of the edge set ───────────────────────────────────────
def test_edges_only_reference_the_frozen_nist_universe(loaded):
    """An edge outside the 38 breaks the accuracy validator that gates this file."""
    crosswalk, _frameworks = loaded
    universe = set(crosswalk)
    assert set(_cra_edges(crosswalk)) <= universe


def test_every_edge_has_a_confidence_tier_and_an_explanatory_note(loaded):
    crosswalk, _frameworks = loaded
    for nist, edge in _cra_edges(crosswalk).items():
        assert edge["confidence"] in ("high", "medium", "low"), nist
        assert len(edge.get("note", "")) > 40, f"{nist} has no real justification"


def test_coverage_is_partial_and_that_is_recorded_not_hidden():
    """We reach 11 of 21 Annex I requirements. The other ten are properties of a
    development and support process, not of infrastructure -- claiming them would be
    the failure this whole document is written against."""
    crosswalk, _frameworks = compliance_crosswalk.get_crosswalk()[0], \
        compliance_crosswalk.get_crosswalk()[1]
    reached = {t for e in _cra_edges(crosswalk).values() for t in e["targets"]}
    assert len(reached) == 11, f"coverage changed: {sorted(reached)}"
    unreachable = ANNEX_I - reached
    # the reporting duty is not an Annex I requirement at all, and the rest are
    # process properties an agentless estate scan cannot observe
    assert unreachable == {"I(c)", "I(g)", "I(i)", "I(k)", "I(m)",
                           "II(4)", "II(5)", "II(6)", "II(7)", "II(8)"}


# ── the document that explains it ───────────────────────────────────────────
def test_the_cra_note_exists_and_separates_the_two_obligations():
    path = os.path.join(ROOT, "docs", "CRA.md")
    assert os.path.isfile(path), "docs/CRA.md is the artefact this lane delivers"
    text = open(path, encoding="utf-8").read()
    assert "11 September 2026" in text and "11 December 2027" in text
    assert "24 hours" in text and "72 hours" in text and "14 days" in text
    assert "Single Reporting Platform" in text
    # the sentence that stops the conflation being repeated in a deck
    assert "does nothing for the Article 14 reporting clock" in text
    # and the one that stops a score being read as conformity
    assert "never conformity itself" in text
