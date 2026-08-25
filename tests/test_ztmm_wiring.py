"""Phase 5 · slice 5.1 — the ZTMM scorecard as an artefact on disk.

The roadmap's framing is that *the differentiator is the evidence, not the label*, so the
file has to carry the evidence and refuse the label the evidence does not support.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_live_scanner as A
import aws_ztmm as Z


class R:
    def __init__(self, check_id, status):
        self.check_id, self.status = check_id, status


def _card(results=(), not_evaluated=None):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["DATA"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: MagicMock()
    s.results = list(results)
    for cid, why in (not_evaluated or {}).items():
        s._coverage.not_evaluated[cid] = why
    with tempfile.TemporaryDirectory() as d:
        s.save_ztmm_scorecard(d)
        path = os.path.join(d, "ztmm_scorecard.json")
        assert os.path.exists(path), "scorecard was not written"
        with open(path, encoding="utf-8") as f:
            return json.load(f)


def test_the_scorecard_is_written_with_every_pillar():
    c = _card()
    assert set(c["pillars"]) == set(Z.PILLARS)


def test_the_scorecard_carries_no_overall_maturity_number():
    """The figure every competing product prints, and the one that hides which pillar
    is unscoreable."""
    c = _card()
    assert c["overall_stage"] is None


def test_the_true_denominator_is_reported():
    c = _card()
    assert c["functions_total"] == 37
    assert c["functions_scored"] < 37


def test_a_stage_is_accompanied_by_the_checks_that_evidenced_it():
    c = _card([R("IAM-01", "PASS"), R("IAM-02", "PASS")])
    auth = next(r for r in c["pillars"]["Identity"]["rows"]
                if r["function"] == "Authentication")
    assert auth["stage"] == Z.INITIAL
    assert set(auth["evidence"]["Initial"]["ran"]) == {"IAM-01", "IAM-02"}


def test_a_failing_check_holds_the_function_at_traditional():
    c = _card([R("IAM-01", "PASS"), R("IAM-02", "FAIL")])
    auth = next(r for r in c["pillars"]["Identity"]["rows"]
                if r["function"] == "Authentication")
    assert auth["stage"] == Z.TRADITIONAL
    assert auth["failing"] == ["IAM-02"]


def test_devices_reports_its_blind_spots_rather_than_a_score():
    c = _card()
    blind = [r for r in c["pillars"]["Devices"]["rows"] if r["blind_spot"]]
    assert len(blind) == 5
    assert all(r["stage"] == Z.UNSCORED for r in blind)


def test_a_blocked_check_never_leaves_a_function_looking_traditional_by_default():
    c = _card([], not_evaluated={"IAM-01": "AccessDenied", "IAM-02": "AccessDenied"})
    auth = next(r for r in c["pillars"]["Identity"]["rows"]
                if r["function"] == "Authentication")
    assert "absence of evidence" in auth["why"]


def test_the_source_and_date_are_recorded_in_the_artefact():
    """CISA revises the model; a scorecard that cannot say which version it scored
    against is not evidence."""
    c = _card()
    assert "v2.0" in c["source"] and c["source_date"]
