"""Shared pytest configuration.

THE CREDENTIAL-REPORT SLEEPS
-----------------------------
``_get_credential_report`` polls an asynchronous AWS API. Against a mocked client the
state never reaches ``COMPLETE``, so every test that reaches the method burns the entire
retry budget: nine two-second polls plus a five-second retry, about 23 seconds each.

That was not a small tax. ``tests/test_exposure.py`` alone took **3m50s**, most of a
roughly six-minute suite, and it is the reason the suite once appeared to hang -- a
stall at the same 29% mark on three consecutive runs, which was misdiagnosed as a
product bug and cost two killed runs before anyone profiled it.

Zeroing the timings here rather than in the module keeps the shipped behaviour honest:
production still polls at the real interval, and ``test_credential_report_timing.py``
pins those defaults so this fixture can never quietly become what ships.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True, scope="session")
def _no_credential_report_sleeps():
    """Collapse the credential-report poll for the whole session.

    Session-scoped and autouse: the cost is paid by any test that constructs a scanner
    and reaches an IAM path, which is far more of them than the handful that mention
    credential reports by name."""
    from engine import aws_live_scanner as A

    saved = (A.CRED_REPORT_ATTEMPTS, A.CRED_REPORT_POLL_SECONDS,
             A.CRED_REPORT_RETRY_SECONDS)
    A.CRED_REPORT_ATTEMPTS = 1          # one attempt, so the loop cannot sleep at all
    A.CRED_REPORT_POLL_SECONDS = 0
    A.CRED_REPORT_RETRY_SECONDS = 0
    yield
    (A.CRED_REPORT_ATTEMPTS, A.CRED_REPORT_POLL_SECONDS,
     A.CRED_REPORT_RETRY_SECONDS) = saved
