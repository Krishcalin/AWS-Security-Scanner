"""The live console must actually print findings, and IAM-01/02 must not invent one.

TWO DEFECTS, ONE PROPERTY: a thing that looked present and was not.

1. THE PRINTER WAS DEAD CODE. The per-finding console line had come to rest after the
   `return` in `_remediation_for`, where it was unreachable and referred to `status`,
   `resource`, `severity`, `check_id` and `message` — none of which that method has.
   `STATUS_ICON[` appeared exactly once in a 20,000-line file, inside that block. The
   effect was silent and total: a scan printed section headers and `_log` lines and not
   one finding, FAIL and WARN included, and `--verbose` was a documented flag that did
   nothing. Nothing failed, because nothing asserted that a scan prints its results.

2. IAM-01 REPORTED A FAILED READ AS A CRITICAL FINDING. A denied or throttled
   `iam:GetAccountSummary` emitted `_add("FAIL", "IAM-01", ..., f"...: {e}")`, which
   `_add` decorates with IAM-01's compliance keys and remediation — root MFA declared
   absent when nothing had been observed. IAM-02, answered by the same call, was
   dropped in silence.

   Two ratchets existed and neither fired. The structural one asks whether a check's
   ONLY FAIL is in an except handler; IAM-01 has a real FAIL at the root-MFA branch, so
   it passed. The exception-text one matched a single AST shape, `str(e)`; IAM-01 used
   an f-string, which is an ast.JoinedStr. Both holes are closed in
   tests/test_read_failure_is_not_a_finding.py; this module pins the behaviour.
"""
from __future__ import annotations

import io
import os
import sys
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import engine.aws_live_scanner as A                                  # noqa: E402
from engine.aws_live_scanner import REMEDIATION_MAP                   # noqa: E402
from test_live_scanner import make_scanner                            # noqa: E402


def _emit(verbose):
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", sections=["IAM"], verbose=verbose)
    buf = io.StringIO()
    with redirect_stdout(buf):
        s._add("FAIL", "IAM-01", "IAM", "root", "Root MFA is NOT enabled")
        s._add("WARN", "IAM-02", "IAM", "root", "Could not evaluate")
        s._add("PASS", "IAM-04", "IAM", "alice", "MFA present")
    return buf.getvalue()


# ── 1. the printer ──────────────────────────────────────────────────────────
def test_a_failing_finding_reaches_the_console_without_verbose():
    """The whole point of watching a scan run."""
    out = _emit(False)
    assert "IAM-01" in out and "Root MFA is NOT enabled" in out


def test_a_warning_also_prints_without_verbose():
    assert "IAM-02" in _emit(False)


def test_a_passing_finding_prints_only_with_verbose():
    assert "IAM-04" not in _emit(False)
    assert "IAM-04" in _emit(True)


def test_the_printed_line_carries_the_catalogue_severity_and_the_resource():
    out = _emit(False)
    assert "[CRITICAL]" in out, "severity comes from CHECK_SEVERITY via _add"
    assert "| root" in out, "the resource is what tells the operator which one"


def test_remediation_for_still_resolves_by_check_id_and_prints_nothing():
    """The printer was stranded INSIDE this method. Moving it out must not have
    changed what it returns: WARN resolves from the catalogue, PASS gets nothing."""
    class _R:
        status, check_id = "WARN", "IAM-02"

    class _P:
        status, check_id = "PASS", "IAM-02"

    s = make_scanner(sections=["IAM"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        warn = s._remediation_for(_R())
        passing = s._remediation_for(_P())
    assert warn == REMEDIATION_MAP["IAM-02"]
    assert passing == ""
    assert buf.getvalue() == "", "_remediation_for is a resolver, not a printer"


def test_the_printer_lives_in_add_where_its_names_are_bound():
    """A structural guard. The block referenced five names `_remediation_for` does not
    have; if it drifts back there it is dead again and nothing else would notice."""
    import ast
    import inspect
    src = inspect.getsource(A.AWSLiveScanner._remediation_for)
    assert "STATUS_ICON" not in src, (
        "the console printer is back inside _remediation_for, where it is unreachable")
    add_src = inspect.getsource(A.AWSLiveScanner._add)
    assert "STATUS_ICON" in add_src, "the printer must live in _add"
    # and it must be reachable — no return before it
    tree = ast.parse(inspect.getsource(A.AWSLiveScanner._add).lstrip())
    fn = tree.body[0]
    printed_at = [n.lineno for n in ast.walk(fn)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                  and n.func.id == "print"]
    returned_at = [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Return)]
    assert printed_at, "no print in _add"
    assert not returned_at or min(returned_at) > max(printed_at), (
        "_add returns before it prints — the finding never reaches the console")


# ── 2. IAM-01/02 on a failed read ───────────────────────────────────────────
def _iam_scanner(summary_raises):
    iam = MagicMock()
    if summary_raises is not None:
        iam.get_account_summary.side_effect = summary_raises
    else:
        iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}}
    s = make_scanner(sections=["IAM"])
    s.account = "123456789012"
    s._clients["iam:us-east-1"] = iam
    return s


class _Denied(Exception):
    def __init__(self):
        super().__init__("AccessDenied")
        self.response = {"Error": {"Code": "AccessDenied"}}


def _results(s, cid):
    return [r for r in s.results if r.check_id == cid]


def test_a_denied_account_summary_never_produces_a_critical_fail():
    """THE DEFECT. IAM-01 is CRITICAL; a missing grant must not render as one."""
    s = _iam_scanner(_Denied())
    with redirect_stdout(io.StringIO()):
        try:
            s._check_iam()
        except Exception:
            pass
    fails = [r for r in _results(s, "IAM-01") if r.status == "FAIL"]
    assert not fails, (
        "a denied iam:GetAccountSummary produced a FAIL for IAM-01 — the catalogue "
        "would decorate it CRITICAL with root-MFA remediation for a setting nobody read")


def test_both_checks_answered_by_that_one_call_are_reported():
    """IAM-02 used to vanish entirely when the call failed — a phantom pass."""
    s = _iam_scanner(_Denied())
    with redirect_stdout(io.StringIO()):
        try:
            s._check_iam()
        except Exception:
            pass
    for cid in ("IAM-01", "IAM-02"):
        warns = [r for r in _results(s, cid) if r.status == "WARN"]
        assert warns, f"{cid} is silent when its only source call failed"
        assert "NOT EVALUATED" in warns[0].message


def test_the_denial_names_the_grant_that_would_answer_it():
    s = _iam_scanner(_Denied())
    with redirect_stdout(io.StringIO()):
        try:
            s._check_iam()
        except Exception:
            pass
    warns = [r for r in _results(s, "IAM-01") if r.status == "WARN"]
    assert warns and "iam:GetAccountSummary" in warns[0].message


def test_the_real_condition_still_fails_when_the_read_succeeds():
    """The fix must not cost the check its actual finding."""
    s = _iam_scanner(None)
    with redirect_stdout(io.StringIO()):
        try:
            s._check_iam()
        except Exception:
            pass
    fails = [r for r in _results(s, "IAM-01") if r.status == "FAIL"]
    assert fails, "root MFA disabled must still FAIL"
    assert fails[0].severity == "CRITICAL"
    assert fails[0].remediation_cmd, "a real FAIL carries the catalogue remediation"
