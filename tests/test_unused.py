"""Unit tests for aws_unused — CIEM unused-access / right-sizing signal.

Pure classification/scoring (dormancy factor, right-sizing finding, non-mutating
down-rank overlay) plus the collection path against mock IAM / Access Analyzer
clients (graceful degradation: analyzer-absent => SLAD, never 'all used').
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_unused as un

DAY = 86400
NOW = 1_000 * DAY


# ── pure: classify_dormancy ──────────────────────────────────────────────────
def test_dormant_when_last_used_old():
    assert un.classify_dormancy(NOW - 100 * DAY, NOW, None, window_days=90) is True


def test_active_when_recently_used():
    assert un.classify_dormancy(NOW - 10 * DAY, NOW, None, window_days=90) is False


def test_never_used_old_principal_is_dormant():
    assert un.classify_dormancy(None, NOW, NOW - 200 * DAY, window_days=90) is True


def test_never_used_young_principal_unknown():
    assert un.classify_dormancy(None, NOW, NOW - 10 * DAY, window_days=90) is None


# ── pure: dormancy_factor ────────────────────────────────────────────────────
def test_factor_unknown_is_one():
    sig = un.UnusedSignal(arn="a", dormant=None)
    assert un.dormancy_factor(sig, NOW) == 1.0


def test_factor_dormant():
    sig = un.UnusedSignal(arn="a", dormant=True)
    assert un.dormancy_factor(sig, NOW) == 0.6


def test_factor_stale():
    sig = un.UnusedSignal(arn="a", dormant=False, last_used_epoch=NOW - 50 * DAY)
    assert un.dormancy_factor(sig, NOW) == 0.8


def test_factor_active():
    sig = un.UnusedSignal(arn="a", dormant=False, last_used_epoch=NOW - 5 * DAY)
    assert un.dormancy_factor(sig, NOW) == 1.0


def test_factor_never_below_floor():
    sig = un.UnusedSignal(arn="a", dormant=True)
    assert un.dormancy_factor(sig, NOW) >= un.FACTOR_FLOOR


# ── pure: right_sizing_finding ───────────────────────────────────────────────
def test_right_sizing_for_dormant():
    sig = un.UnusedSignal(arn="arn:aws:iam::1:role/x", dormant=True, source="SLAD",
                          last_used_iso="2025-01-01T00:00:00+00:00")
    f = un.right_sizing_finding(sig)
    assert f["severity"] == "LOW" and f["check_id"] == "CIEM-01"
    assert "arn:aws:iam::1:role/x" in f["resource"]


def test_right_sizing_none_for_active_no_unused():
    sig = un.UnusedSignal(arn="a", dormant=False)
    assert un.right_sizing_finding(sig) is None


def test_right_sizing_for_unused_services_even_if_active():
    sig = un.UnusedSignal(arn="a", dormant=False, source="AA",
                          unused_services=["s3", "ec2", "dynamodb"])
    f = un.right_sizing_finding(sig)
    assert f is not None and "unused services" in f["message"]


# ── pure: downrank_overlay (non-mutating) ────────────────────────────────────
class FakePath:
    def __init__(self, nodes, score):
        self.nodes = tuple(nodes)
        self.score = score


def test_downrank_overlay_applies_to_dormant_node():
    paths = [FakePath(["internet", "eni-1", "arn:role/dormant", "admin"], 90),
             FakePath(["internet", "eni-2", "arn:role/active", "admin"], 85)]
    overlay = un.downrank_overlay(paths, {"arn:role/dormant": 0.6})
    assert len(overlay) == 1
    assert overlay[0]["index"] == 0
    assert overlay[0]["adjusted_score"] == 54     # 90 * 0.6
    assert overlay[0]["original_score"] == 90


def test_downrank_overlay_uses_min_factor():
    paths = [FakePath(["a", "b", "c"], 100)]
    overlay = un.downrank_overlay(paths, {"a": 0.8, "c": 0.6})
    assert overlay[0]["factor"] == 0.6           # most dormant hop dominates
    assert overlay[0]["adjusted_score"] == 60


def test_downrank_overlay_empty_when_no_dormant():
    paths = [FakePath(["a", "b"], 90)]
    assert un.downrank_overlay(paths, {"z": 0.6}) == []


# ── collection: mock clients + graceful degradation ──────────────────────────
class FakeIAM:
    def __init__(self, services, status="COMPLETED"):
        self._services = services
        self._status = status

    def generate_service_last_accessed_details(self, **kw):
        return {"JobId": "job-1"}

    def get_service_last_accessed_details(self, **kw):
        return {"JobStatus": self._status, "ServicesLastAccessed": self._services,
                "IsTruncated": False}


class FakeAnalyzerNone:
    def list_analyzers(self, **kw):
        return {"analyzers": []}


def test_slad_fallback_when_no_analyzer():
    # analyzer absent -> SLAD path; all services unused -> dormant
    iam = FakeIAM([{"ServiceNamespace": "s3", "LastAuthenticated": None},
                   {"ServiceNamespace": "ec2", "LastAuthenticated": None}])
    sig = un.unused_signal_for("arn:aws:iam::1:role/x", iam, FakeAnalyzerNone(),
                               NOW, create_epoch=NOW - 300 * DAY,
                               sleep=lambda s: None)
    assert sig.source == "SLAD"
    assert sig.dormant is True                    # never used + old principal
    assert set(sig.unused_services) == {"s3", "ec2"}


def test_slad_active_principal():
    iam = FakeIAM([{"ServiceNamespace": "s3",
                    "LastAuthenticated": NOW - 3 * DAY}])
    sig = un.unused_signal_for("arn:aws:iam::1:role/x", iam, FakeAnalyzerNone(),
                               NOW, sleep=lambda s: None)
    assert sig.dormant is False
    assert sig.last_used_epoch == NOW - 3 * DAY


def test_analyzer_absent_is_not_all_used():
    # the key anti-FN: no analyzer must NOT be read as fully-used
    assert un.find_unused_access_analyzer(FakeAnalyzerNone()) is None


def test_slad_job_failure_yields_unknown():
    iam = FakeIAM([], status="FAILED")
    sig = un.unused_signal_for("arn:aws:iam::1:role/x", iam, FakeAnalyzerNone(),
                               NOW, sleep=lambda s: None)
    assert sig.dormant is None                    # unknown -> no down-rank
    assert sig.error is not None


class FakeIAMStuck:
    """SLAD job that never leaves IN_PROGRESS."""
    def generate_service_last_accessed_details(self, **kw):
        return {"JobId": "job-stuck"}

    def get_service_last_accessed_details(self, **kw):
        return {"JobStatus": "IN_PROGRESS", "ServicesLastAccessed": [], "IsTruncated": False}


def test_slad_stuck_in_progress_is_unknown_not_dormant():
    # regression (adversarial rank 7): a job that never completes within max_wait
    # must be UNKNOWN (dormant=None), not misclassified dormant=True from zero data.
    sig = un.unused_signal_for("arn:aws:iam::1:role/x", FakeIAMStuck(), FakeAnalyzerNone(),
                               NOW, create_epoch=NOW - 300 * DAY,
                               sleep=lambda s: None)
    assert sig.dormant is None
    assert sig.error is not None
    assert un.dormancy_factor(sig, NOW) == 1.0          # no down-rank on unknown
    assert un.right_sizing_finding(sig) is None          # no spurious CIEM finding


class FakeAnalyzerWithFinding:
    def list_analyzers(self, **kw):
        if kw.get("type") == "ACCOUNT_UNUSED_ACCESS":
            return {"analyzers": [{"arn": "aa-arn", "type": "ACCOUNT_UNUSED_ACCESS"}]}
        return {"analyzers": []}

    def list_findings_v2(self, **kw):
        return {"findings": [{"findingType": "UnusedIAMRole", "id": "f1"}]}

    def get_finding_v2(self, **kw):
        return {"findingDetails": [{"unusedIamRoleDetails":
                {"lastAccessed": NOW - 200 * DAY}}]}

    def get_paginator(self, name):
        raise Exception("no paginator")


def test_analyzer_path_marks_dormant_role():
    iam = FakeIAM([])
    sig = un.unused_signal_for("arn:aws:iam::1:role/x", iam,
                               FakeAnalyzerWithFinding(), NOW, sleep=lambda s: None)
    assert sig.source == "AA"
    assert sig.dormant is True
