"""The credential-report poll: shipped timings, and why they are constants.

`tests/conftest.py` zeroes these for the suite. That is only safe if the SHIPPED values
stay what they are, so they are pinned here — otherwise a test-only speedup could
quietly become the production behaviour, and the scan would stop waiting for an
asynchronous report that genuinely takes time on a fresh account.

The second guard is the one that actually caused trouble: against a mocked client the
state never reaches "COMPLETE", so the method burned its whole retry budget — about 23
seconds per test, 3m50s in `test_exposure.py` alone. It made the suite look hung at the
same 29% mark on three consecutive runs.
"""
from __future__ import annotations

import io
import os
import re
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_live_scanner as A

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _scanner(client):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["IAM"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: client
    return s


# ── the shipped values ──────────────────────────────────────────────────────
def test_the_shipped_poll_values_are_what_ships():
    """Pinned because conftest zeroes them. A scan that stops waiting would read an
    asynchronous report before it is ready, on exactly the fresh accounts where the
    report takes longest."""
    src = io.open(os.path.join(ROOT, "aws_live_scanner.py"), encoding="utf-8").read()
    assert re.search(r"^CRED_REPORT_ATTEMPTS = 10\b", src, re.M)
    assert re.search(r"^CRED_REPORT_POLL_SECONDS = 2\b", src, re.M)
    assert re.search(r"^CRED_REPORT_RETRY_SECONDS = 5\b", src, re.M)


def test_the_shipped_budget_stays_bounded():
    """~18s of polling plus a 5s retry. Bounded on purpose: a never-COMPLETE state must
    not be able to stall a whole scan."""
    src = io.open(os.path.join(ROOT, "aws_live_scanner.py"), encoding="utf-8").read()
    attempts = int(re.search(r"^CRED_REPORT_ATTEMPTS = (\d+)\b", src, re.M).group(1))
    poll = int(re.search(r"^CRED_REPORT_POLL_SECONDS = (\d+)\b", src, re.M).group(1))
    retry = int(re.search(r"^CRED_REPORT_RETRY_SECONDS = (\d+)\b", src, re.M).group(1))
    assert (attempts - 1) * poll + retry <= 30


def test_conftest_actually_zeroed_them_for_this_run():
    assert A.CRED_REPORT_POLL_SECONDS == 0
    assert A.CRED_REPORT_RETRY_SECONDS == 0


# ── the behaviour that made the suite look hung ─────────────────────────────
def test_a_non_string_state_stops_the_poll_immediately():
    """A MagicMock State can never equal "COMPLETE", so there is nothing to wait for.
    Without this short-circuit the method burns the entire retry budget on every mocked
    client that reaches it."""
    c = MagicMock()
    with patch("aws_live_scanner.CRED_REPORT_ATTEMPTS", 10), \
         patch("aws_live_scanner.CRED_REPORT_POLL_SECONDS", 2), \
         patch("aws_live_scanner.CRED_REPORT_RETRY_SECONDS", 0):
        s = _scanner(c)
        start = time.monotonic()
        s._get_credential_report()
        elapsed = time.monotonic() - start
    assert elapsed < 2, f"burned {elapsed:.1f}s on a non-string State"
    assert c.generate_credential_report.call_count == 1


def test_an_absent_state_still_polls_because_empty_string_is_a_string():
    """The guard must not break the real case: State absent -> "" -> keep polling, which
    is correct for a report that is genuinely still generating."""
    c = MagicMock()
    c.generate_credential_report.return_value = {}
    with patch("aws_live_scanner.CRED_REPORT_ATTEMPTS", 4), \
         patch("aws_live_scanner.CRED_REPORT_POLL_SECONDS", 0), \
         patch("aws_live_scanner.CRED_REPORT_RETRY_SECONDS", 0):
        _scanner(c)._get_credential_report()
    assert c.generate_credential_report.call_count == 4


def test_a_complete_state_stops_polling_at_once():
    c = MagicMock()
    c.generate_credential_report.return_value = {"State": "COMPLETE"}
    c.get_credential_report.return_value = {"Content": b"dXNlcgpyb290Cg=="}
    with patch("aws_live_scanner.CRED_REPORT_ATTEMPTS", 10), \
         patch("aws_live_scanner.CRED_REPORT_POLL_SECONDS", 0):
        s = _scanner(c)
        s._get_credential_report()
    assert c.generate_credential_report.call_count == 1


def test_an_unavailable_report_is_recorded_as_unevaluated_not_as_empty():
    """The pre-existing contract, re-asserted because this change touches the path:
    None/[] must let credential checks tell an empty account from an unreadable report
    rather than issuing a false all-clear."""
    c = MagicMock()
    c.generate_credential_report.side_effect = Exception("AccessDenied")
    with patch("aws_live_scanner.CRED_REPORT_RETRY_SECONDS", 0):
        s = _scanner(c)
        s._get_credential_report()
    assert s._cred_report_ok is False


def test_a_successful_report_is_marked_ok():
    c = MagicMock()
    c.generate_credential_report.return_value = {"State": "COMPLETE"}
    c.get_credential_report.return_value = {"Content": b"dXNlcixhcm4Kcm9vdCxhcm46YXdzCg=="}
    with patch("aws_live_scanner.CRED_REPORT_POLL_SECONDS", 0):
        s = _scanner(c)
        rows = s._get_credential_report()
    assert s._cred_report_ok is True and rows


def test_the_report_is_cached_and_not_regenerated():
    c = MagicMock()
    c.generate_credential_report.return_value = {"State": "COMPLETE"}
    c.get_credential_report.return_value = {"Content": b"dXNlcixhcm4Kcm9vdCxhcm46YXdzCg=="}
    with patch("aws_live_scanner.CRED_REPORT_POLL_SECONDS", 0):
        s = _scanner(c)
        s._get_credential_report()
        s._get_credential_report()
    assert c.generate_credential_report.call_count == 1


# ── the sleeps are the only ones in the scanner ─────────────────────────────
def test_the_scanner_has_no_unparameterised_sleeps_left():
    """Any new fixed sleep would reintroduce the same tax. Both remaining calls take a
    module constant the suite can zero."""
    src = io.open(os.path.join(ROOT, "aws_live_scanner.py"), encoding="utf-8").read()
    sleeps = re.findall(r"time\.sleep\(([^)]*)\)", src)
    assert sleeps, "expected the credential-report sleeps to still exist"
    for arg in sleeps:
        assert arg.startswith("CRED_REPORT_"), f"unparameterised sleep: time.sleep({arg})"
