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

import io
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


# ── the check-firing recorder ───────────────────────────────────────────────
#
# WHY THIS IS NOT A STATIC ANALYSIS. "Which checks can actually produce a finding"
# looks answerable by reading the source, and is not: a check id reaches `_add` as a
# literal, a bare variable (`fid`), a subscript (`f["id"]`) or a conditional, and
# every one of the scanner's 90 sections uses at least one non-literal form. Three
# successive greps produced three different confident wrong answers before that was
# clear. The only truthful source is what the suite actually emits.
#
# `AWSLiveScanner._add` is the single emission point — every finding in the product
# is constructed there (the one other `Result(...)` is the multi-region aggregator
# copying rows that already exist) — so one patch captures everything.
#
# OFF UNLESS ASKED FOR. Set OVERWATCH_RECORD_CHECKS=<path> and the run writes what it
# saw; unset, this costs one env lookup at startup and nothing else. `tools/
# build_check_firing.py` is what sets it.

def pytest_configure(config):
    dest = os.environ.get("OVERWATCH_RECORD_CHECKS")
    if not dest:
        return
    from engine.aws_live_scanner import AWSLiveScanner

    seen = set()
    original = AWSLiveScanner._add

    def recording_add(self, status, check_id, section, resource, message):
        seen.add((check_id, status))
        return original(self, status, check_id, section, resource, message)

    AWSLiveScanner._add = recording_add
    config._overwatch_seen = seen
    config._overwatch_add = original


def pytest_sessionfinish(session, exitstatus):
    dest = os.environ.get("OVERWATCH_RECORD_CHECKS")
    seen = getattr(session.config, "_overwatch_seen", None)
    if not dest or seen is None:
        return
    import json

    # Restore, so a plugin that outlives the session does not keep the wrapper.
    from engine.aws_live_scanner import AWSLiveScanner
    AWSLiveScanner._add = session.config._overwatch_add

    with io.open(dest, "w", encoding="utf-8") as fh:
        json.dump(sorted([cid, st] for cid, st in seen), fh, indent=1)
