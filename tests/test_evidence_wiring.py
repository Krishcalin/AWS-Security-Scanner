"""Phase 4 · slice 4.5 — the evidence pack as an artefact on disk.

The pack ships alongside the other evidence files rather than behind a flag: an auditor
asking about NIST AI RMF wants it in the pack they already received, and a report that
must be requested separately is one nobody knows to request.

What is defended here is the property that makes it worth shipping — the artefact states
what OverWatch does **not** reach. The crosswalk maps 12 of the AI RMF's 72 controls, and
the file says so in those words.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_evidence as EV
import aws_live_scanner as A


def _scanner(results=()):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["DATA"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: MagicMock()
    s.results = list(results)
    return s


def _pack(results=(), coverage=None):
    s = _scanner(results)
    if coverage:
        for cid, why in (coverage or {}).items():
            s._coverage.not_evaluated[cid] = why
    with tempfile.TemporaryDirectory() as d:
        s.save_ai_evidence_pack(d)
        path = os.path.join(d, "ai_compliance_evidence.json")
        assert os.path.exists(path), "pack was not written"
        with open(path, encoding="utf-8") as f:
            return json.load(f)


def test_the_pack_is_written_with_every_ai_framework():
    p = _pack()
    assert set(p["frameworks"]) == set(EV.AI_FRAMEWORKS)


def test_the_pack_states_the_true_fraction_of_each_framework():
    """The load-bearing property. 'mapped 12 of 72' rather than '12 of 12' -- a reader
    who sees only the mapped set will take it for the framework."""
    rmf = _pack()["frameworks"]["NIST-AI-RMF-1.0"]["summary"]
    assert rmf["controls_in_framework"] == 72
    assert rmf["controls_mapped"] < 72
    assert rmf["controls_unmapped"] > 0
    assert "were NOT looked at" in rmf["statement"]


def test_the_pack_never_reports_a_percentage():
    """'68% compliant' is the sentence the whole slice exists to make impossible."""
    p = _pack()
    for v in p["frameworks"].values():
        assert "%" not in v["summary"]["statement"]


def test_the_pack_carries_the_crosswalk_digest():
    """So a reader can tell which version of an opinionated mapping produced it."""
    p = _pack()
    assert p["crosswalk_digest"].startswith("cw-")


def test_scan_coverage_is_carried_separately_from_mapping_coverage():
    p = _pack(coverage={"VEC-02": "AccessDenied — missing aoss:GetAccessPolicy"})
    assert "VEC-02" in p["scan_coverage"]["not_evaluated"]


def test_a_blocked_check_never_leaves_its_control_reading_as_passed():
    """The whole point of feeding the coverage manifest in."""
    ids = [c for c, m in A.COMPLIANCE_MAP.items() if (m or {}).get("NIST") == "AC-3"]
    p = _pack(coverage={c: "AccessDenied" for c in ids})
    rows = [r for v in p["frameworks"].values() for r in v["controls"]
            if "AC-3" in r["spine"]]
    assert rows, "no control maps through AC-3"
    assert all(r["status"] != EV.ASSESSED_PASS for r in rows)


def test_the_pack_survives_a_scan_with_no_results():
    p = _pack([])
    for v in p["frameworks"].values():
        assert all(r["status"] in EV.STATUSES for r in v["controls"])


def test_a_missing_crosswalk_costs_the_pack_and_nothing_else():
    s = _scanner()
    with patch("compliance_crosswalk.get_crosswalk", return_value=({}, {}, "")):
        with tempfile.TemporaryDirectory() as d:
            s.save_ai_evidence_pack(d)      # must not raise
            assert os.listdir(d) == []
