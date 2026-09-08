"""Offline tests for cnapp_worker.run_scan_job — the async scan executor. Covers
the happy path, the engine sys.exit(2) trap (must NOT kill the worker), and the
pre-validation guard that denies a wrong-account/revoked role before scanning."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.aws_graph import SecurityGraph
from hub.cnapp_registry import AccountRegistry
from hub.cnapp_service import InMemoryResultStore, PlatformService
from hub.cnapp_worker import drain_once, run_scan_job

ACCT = "210987654321"
HUB = "arn:aws:iam::555000111222:role/CnappHubRole"


class FakeSession:
    def __init__(self, acct, reports=None):
        self.acct = acct
        self._reports = reports if reports is not None else acct
    def client(self, service, **k):
        rep = self._reports
        class C:
            def get_caller_identity(self):
                return {"Account": rep}
        return C()


def _result(status, cid, sev):
    return types.SimpleNamespace(status=status, check_id=cid, section="S3", resource="b",
                                 message="m | b", severity=sev, compliance={}, remediation_cmd="")


def _runner(session, spec):
    g = SecurityGraph(); g.add_node("internet", "InternetSource")
    return types.SimpleNamespace(account=session.acct, region="us-east-1", graph=g,
                                 attack_paths=[], choke_points=[],
                                 results=[_result("FAIL", "S3-01", "HIGH"),
                                          _result("FAIL", "S3-03", "MEDIUM"),
                                          _result("PASS", "S3-02", "")],
                                 # the real AWSLiveScanner always has this; serialize_scanner
                                 # projects it into the payload's finding_catalog.
                                 _build_finding_catalog=lambda: [])


def _svc(**over):
    reg = AccountRegistry.open(":memory:")
    clk = {"t": 0}
    def clock():
        clk["t"] += 100
        return clk["t"]
    kw = dict(registry=reg, results=InMemoryResultStore(), hub_role_arn=HUB,
              cfn_template_url="https://h/x.yaml", secret_writer=lambda a, v: "ssm://x",
              secret_reader=lambda r: "ext", session_factory=lambda aid: FakeSession(aid),
              assume_role_fn=lambda *a: {}, client_factory=None, scan_runner=_runner,
              clock=clock)
    kw.update(over)
    return PlatformService(**kw), reg


def _active(reg, aid):
    reg.upsert_account(aid, now_epoch=1)
    reg.set_onboarding_status(aid, "active", 1)


def test_happy_path_done_and_persists():
    svc, reg = _svc()
    _active(reg, ACCT)
    jid = svc.trigger_scan([ACCT])[0]
    term = run_scan_job(svc, reg.get_scan_job(jid))
    assert term["status"] == "done" and term["findings_count"] == 2      # two FAILs
    assert reg.get_account(ACCT)["last_scan_at"] is not None
    assert svc.results.get_latest(ACCT)["account"] == ACCT


def test_systemexit_trap_does_not_kill_worker():
    def exiting(session, spec):
        raise SystemExit(2)
    svc, reg = _svc(scan_runner=exiting)
    _active(reg, ACCT)
    jid = svc.trigger_scan([ACCT])[0]
    term = run_scan_job(svc, reg.get_scan_job(jid))     # must return, not exit
    assert term["status"] == "error" and "engine exit 2" in term["error"]


def test_prevalidate_wrong_account_denies_before_scan():
    ran = {"scanned": False}
    def runner(session, spec):
        ran["scanned"] = True
        return _runner(session, spec)
    svc, reg = _svc(session_factory=lambda aid: FakeSession(aid, reports="000000000000"),
                    scan_runner=runner)
    _active(reg, ACCT)
    jid = svc.trigger_scan([ACCT])[0]
    term = run_scan_job(svc, reg.get_scan_job(jid))
    assert term["status"] == "error"
    assert ran["scanned"] is False                       # engine never invoked
    assert reg.get_account(ACCT)["onboarding_status"] == "denied"


def _client_error(code):
    """A botocore-shaped ClientError. The worker reads the code out of
    `response["Error"]["Code"]`, so a RuntimeError whose MESSAGE happens to contain
    "AccessDenied" is not a refusal — which is exactly what this test used to
    assert, and is why a network blip could deny an account."""
    e = RuntimeError("%s: not authorized to perform sts:AssumeRole" % code)
    e.response = {"Error": {"Code": code, "Message": "denied"}}
    return e


def test_assume_role_refusal_denies():
    def refused(aid):
        raise _client_error("AccessDenied")
    svc, reg = _svc(session_factory=refused)
    _active(reg, ACCT)
    jid = svc.trigger_scan([ACCT])[0]
    term = run_scan_job(svc, reg.get_scan_job(jid))
    assert term["status"] == "error" and "assume role" in term["error"]
    assert reg.get_account(ACCT)["onboarding_status"] == "denied"


def test_a_transient_assume_role_failure_does_not_deny():
    """THE DEFECT THIS REPLACES. Every exception out of session_factory used to set
    the account to 'denied', and a denied account leaves trigger_scan's ACTIVE set
    permanently — so one throttle or DNS blip silently stopped scanning an estate
    until somebody re-onboarded it."""
    def throttled(aid):
        raise _client_error("ThrottlingException")
    svc, reg = _svc(session_factory=throttled)
    _active(reg, ACCT)
    jid = svc.trigger_scan([ACCT])[0]
    term = run_scan_job(svc, reg.get_scan_job(jid))
    assert term["status"] == "error"
    assert reg.get_account(ACCT)["onboarding_status"] == "active"
    assert svc.trigger_scan([ACCT]), "the account can no longer be scheduled"


def test_drain_once_runs_all_queued():
    svc, reg = _svc()
    for aid in ("111111111111", "222222222222"):
        _active(reg, aid)
    svc.trigger_scan(all=True)
    done = drain_once(svc)
    assert len(done) == 2 and all(j["status"] == "done" for j in done)


# ── regression: pre-validate fails CLOSED on empty observed account ───────────
def test_prevalidate_empty_observed_fails_closed():
    ran = {"scanned": False}
    def runner(session, spec):
        ran["scanned"] = True
        return _runner(session, spec)
    svc, reg = _svc(session_factory=lambda aid: FakeSession(aid, reports=""),  # STS returns no acct
                    scan_runner=runner)
    _active(reg, ACCT)
    jid = svc.trigger_scan([ACCT])[0]
    term = run_scan_job(svc, reg.get_scan_job(jid))
    assert term["status"] == "error" and ran["scanned"] is False
    assert reg.get_account(ACCT)["onboarding_status"] == "denied"


# ── regression: account disabled after enqueue is skipped (TOCTOU) ───────────
def test_disabled_after_enqueue_is_skipped_not_scanned():
    ran = {"scanned": False}
    def runner(session, spec):
        ran["scanned"] = True
        return _runner(session, spec)
    svc, reg = _svc(scan_runner=runner)
    _active(reg, ACCT)
    jid = svc.trigger_scan([ACCT])[0]
    reg.set_onboarding_status(ACCT, "disabled", 5)          # disabled between enqueue + run
    term = run_scan_job(svc, reg.get_scan_job(jid))
    assert term["status"] == "error" and "no longer active" in term["error"]
    assert ran["scanned"] is False
    assert reg.get_account(ACCT)["onboarding_status"] == "disabled"   # NOT flipped to denied


# ── regression: KeyboardInterrupt is NOT swallowed into a failed job ─────────
def test_keyboardinterrupt_propagates():
    def interrupt(session, spec):
        raise KeyboardInterrupt
    svc, reg = _svc(scan_runner=interrupt)
    _active(reg, ACCT)
    jid = svc.trigger_scan([ACCT])[0]
    with pytest.raises(KeyboardInterrupt):
        run_scan_job(svc, reg.get_scan_job(jid))
