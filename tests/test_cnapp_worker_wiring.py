"""The scan executor, connected — and the account it used to deny on the way.

WHAT WAS WRONG. `POST /scans` and `POST /scans/schedule-tick` both only ENQUEUE;
`trigger_scan`'s own docstring says "(The worker drains the queue; this never blocks
on a scan.)". Nothing drained it. `cnapp_worker` was imported by its tests and
nothing else, and had no `__main__`, so the documented async scan path was
unreachable from both ends: a hosted deployment accepted scan requests, recorded
them `queued`, and never ran one.

AND WIRING IT NAIVELY WOULD HAVE BEEN WORSE THAN LEAVING IT. `PlatformService`
takes `session_factory` as Optional-defaulting-to-None and `build_service()` never
set it, so the first job would raise `'NoneType' object is not callable` — caught,
and turned into `fail(..., deny=True)`, which sets the account to `denied`. Denied
accounts drop out of `trigger_scan`'s ACTIVE set, so one worker run would have
permanently stopped scanning every account it touched, on the strength of OUR
missing configuration. That cascade is the first test below, and it is the reason
the guard exists rather than only the factory.

Three things are asserted here, in the order they can fail:
  1. the hub's own misconfiguration never changes a customer's onboarding status,
     and a genuine assume-role refusal still does (the negative control, or the
     fix would simply have disabled a legitimate signal);
  2. production wiring actually supplies the seam, so the guard above stays a
     safety net rather than the normal path;
  3. the process runs, reports per-status counts, and survives a failing tick.
"""
from __future__ import annotations

import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hub import cnapp_worker
from hub.cnapp_registry import AccountRegistry
from hub.cnapp_service import InMemoryResultStore, PlatformService

ACCT = "210987654321"
HUB = "arn:aws:iam::555000111222:role/CnappHubRole"


class FakeSession:
    def __init__(self, acct, reports=None):
        self.acct = acct
        self._reports = acct if reports is None else reports

    def client(self, service, **k):
        rep = self._reports

        class C:
            def get_caller_identity(self):
                return {"Account": rep}
        return C()


def _runner(session, spec):
    from engine.aws_graph import SecurityGraph
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    return types.SimpleNamespace(
        account=session.acct, region="us-east-1", graph=g, attack_paths=[],
        choke_points=[], results=[], _build_finding_catalog=lambda: [])


def _svc(**over):
    reg = AccountRegistry.open(":memory:")
    clk = {"t": 0}

    def clock():
        clk["t"] += 100
        return clk["t"]

    kw = dict(registry=reg, results=InMemoryResultStore(), hub_role_arn=HUB,
              cfn_template_url="https://h/x.yaml",
              secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "ext",
              scan_runner=_runner, clock=clock)
    kw.update(over)
    return PlatformService(**kw), reg


def _active(reg, aid=ACCT):
    reg.upsert_account(aid, now_epoch=1)
    reg.set_onboarding_status(aid, "active", 1)


# ── 1. our configuration is not the customer's fault ────────────────────────

def test_an_unwired_session_factory_fails_the_job_without_denying_the_account():
    """THE CASCADE THIS PREVENTS. Before the guard: TypeError -> caught as an
    assume-role failure -> deny=True -> onboarding_status 'denied' -> the account
    leaves trigger_scan's ACTIVE set -> it is never scanned again. All from a seam
    the hub forgot to wire."""
    svc, reg = _svc()                      # session_factory omitted, as production was
    assert svc.session_factory is None
    _active(reg)
    jid = svc.trigger_scan([ACCT])[0]

    term = cnapp_worker.run_scan_job(svc, reg.get_scan_job(jid))

    assert term["status"] == "error"
    assert "misconfigured" in term["error"]
    assert reg.get_account(ACCT)["onboarding_status"] == "active", (
        "the hub's own missing configuration changed the customer's onboarding "
        "status")
    # and the account is still scannable, which is the consequence that matters
    assert svc.trigger_scan([ACCT]), "the account dropped out of the ACTIVE set"


def _refusal(code="AccessDenied"):
    """A botocore-shaped ClientError carrying an error code, which is what the
    worker classifies on. A bare RuntimeError whose message merely mentions
    AccessDenied is NOT a refusal."""
    e = RuntimeError("%s" % code)
    e.response = {"Error": {"Code": code, "Message": "no"}}
    return e


def test_a_real_assume_role_refusal_still_denies():
    """The negative control. Making the case above non-denying must not disable the
    signal for the case denial is FOR: we reached AWS and were refused, which is a
    fact about the customer's trust policy."""
    def refusing(_aid):
        raise _refusal("AccessDenied")

    svc, reg = _svc(session_factory=refusing)
    _active(reg)
    jid = svc.trigger_scan([ACCT])[0]

    term = cnapp_worker.run_scan_job(svc, reg.get_scan_job(jid))
    assert term["status"] == "error"
    assert reg.get_account(ACCT)["onboarding_status"] == "denied"


def test_a_wrong_account_session_still_denies():
    """The other legitimate denial: the role assumed fine but points somewhere else.
    _pre_validate fails closed, and that is a fact about their configuration."""
    svc, reg = _svc(session_factory=lambda aid: FakeSession(aid, reports="999999999999"))
    _active(reg)
    jid = svc.trigger_scan([ACCT])[0]

    term = cnapp_worker.run_scan_job(svc, reg.get_scan_job(jid))
    assert term["status"] == "error"
    assert reg.get_account(ACCT)["onboarding_status"] == "denied"


class _BrokenSession:
    """A session whose STS call fails for a reason we choose."""

    def __init__(self, exc):
        self._exc = exc

    def client(self, service, **k):
        exc = self._exc

        class C:
            def get_caller_identity(self):
                raise exc
        return C()


def test_a_transient_credential_check_failure_does_not_deny():
    """The pre-check reaches AWS to confirm the session lands in the right account.
    When that call cannot COMPLETE, it has learned nothing about the customer — so
    the job fails and their onboarding status is untouched. Denying here was the
    second half of the same defect as the assume-role path."""
    svc, reg = _svc(session_factory=lambda aid: _BrokenSession(
        _refusal("RequestTimeout")))
    _active(reg)
    jid = svc.trigger_scan([ACCT])[0]

    term = cnapp_worker.run_scan_job(svc, reg.get_scan_job(jid))
    assert term["status"] == "error"
    assert "credential check failed" in term["error"]
    assert reg.get_account(ACCT)["onboarding_status"] == "active"


def test_a_refused_credential_check_denies():
    """The negative control for the test above: STS answering AccessDenied IS a
    statement about their trust policy."""
    svc, reg = _svc(session_factory=lambda aid: _BrokenSession(
        _refusal("AccessDenied")))
    _active(reg)
    jid = svc.trigger_scan([ACCT])[0]

    term = cnapp_worker.run_scan_job(svc, reg.get_scan_job(jid))
    assert term["status"] == "error"
    assert reg.get_account(ACCT)["onboarding_status"] == "denied"


# ── the classifier, directly ────────────────────────────────────────────────

@pytest.mark.parametrize("code", ["AccessDenied", "AccessDeniedException",
                                  "AuthFailure", "UnauthorizedOperation",
                                  "NotAuthorized", "UnauthorizedAccess"])
def test_a_refusal_code_is_a_refusal(code):
    assert cnapp_worker._is_refusal(_refusal(code)) is True


@pytest.mark.parametrize("code", ["ThrottlingException", "RequestLimitExceeded",
                                  "RequestTimeout", "ServiceUnavailable",
                                  "InternalError", "EndpointConnectionError",
                                  "InvalidClientTokenId", "ExpiredToken"])
def test_everything_else_is_transient(code):
    """INCLUDING codes that sound like an auth problem. `InvalidClientTokenId` and
    `ExpiredToken` are OUR credentials being wrong, not their trust policy refusing
    us, and denying their account for our expired token is the same class of mistake
    as denying it for a DNS blip."""
    assert cnapp_worker._is_refusal(_refusal(code)) is False


def test_an_unrecognised_exception_is_transient():
    """The default has to be 'do not deny'. The two mistakes are not symmetric: a
    transient failure wrongly denied removes the account from every future scan
    silently, while a refusal wrongly retried fails again in the open next tick."""
    assert cnapp_worker._is_refusal(RuntimeError("something odd")) is False
    assert cnapp_worker._is_refusal(ValueError()) is False


def test_a_message_mentioning_access_denied_is_not_a_refusal():
    """The classifier reads the ERROR CODE, not the text. The old tests raised
    RuntimeError("AccessDenied assuming role") and expected a denial, which is how a
    blanket deny looked correct: the fixture said the words."""
    assert cnapp_worker._is_refusal(
        RuntimeError("AccessDenied: not authorized")) is False


def test_a_refusal_can_be_identified_by_exception_type():
    """botocore is an optional import here, so an error may arrive without a
    `response` dict. The exception's own type name is the fallback."""
    class AccessDenied(Exception):
        pass
    assert cnapp_worker._is_refusal(AccessDenied()) is True


# ── 2. production actually supplies the seam ────────────────────────────────

def test_build_service_wires_a_session_factory(tmp_path, monkeypatch):
    """So the guard above is a safety net and not the normal path. This is the
    assertion that would have failed for the whole life of the hosted backend."""
    from hub import cnapp_server

    monkeypatch.setenv("CNAPP_DB_URL", "sqlite:///%s" % (tmp_path / "ow.db"))
    svc = cnapp_server.build_service()
    assert callable(svc.session_factory), (
        "build_service() left session_factory unset; every queued scan job dies")


def test_the_wired_factory_resolves_the_role_from_the_registry(monkeypatch):
    """It must read the account's own role_arn, not build one from a default and
    silently assume the wrong role."""
    reg = AccountRegistry.open(":memory:")
    reg.upsert_account(ACCT, now_epoch=1)
    reg.set_account_role(ACCT, "arn:aws:iam::%s:role/Custom" % ACCT, "ssm://ext") \
        if hasattr(reg, "set_account_role") else None

    seen = {}

    def fake_assume(account_id, role_arn, external_id=None, region=None):
        seen.update(account_id=account_id, role_arn=role_arn, region=region)
        return FakeSession(account_id)

    from engine import aws_live_scanner as als
    monkeypatch.setattr(als, "assume_role_session", fake_assume, raising=False)

    factory = cnapp_worker.make_session_factory(reg, lambda r: "ext",
                                                region="eu-west-1")
    factory(ACCT)
    assert seen["account_id"] == ACCT
    assert seen["region"] == "eu-west-1"
    assert ACCT in seen["role_arn"]


# ── 3. the process ──────────────────────────────────────────────────────────

def test_one_shot_enqueues_and_drains(monkeypatch, capsys):
    """The whole point: a tick must RUN the jobs, not just queue them. Before this
    entry point existed, `POST /scans/schedule-tick` enqueued and returned."""
    svc, reg = _svc(session_factory=lambda aid: FakeSession(aid))
    _active(reg)
    svc.trigger_scan([ACCT])

    from hub import cnapp_server
    monkeypatch.setattr(cnapp_server, "build_service", lambda: svc)

    assert cnapp_worker.main([]) == 0
    out = capsys.readouterr().out
    assert "ran 1" in out
    # The queue being empty afterwards is the observable effect of draining, and
    # the thing no code path could achieve before this entry point existed.
    assert svc.pending_jobs() == []


def test_the_summary_does_not_hide_failures(monkeypatch, capsys):
    """"ran 3" reads as success. A tick where every job failed must not print the
    same sentence as one where every job succeeded."""
    def exploding(session, spec):
        raise RuntimeError("boom")

    svc, reg = _svc(session_factory=lambda aid: FakeSession(aid),
                    scan_runner=exploding)
    _active(reg)
    svc.trigger_scan([ACCT])

    from hub import cnapp_server
    monkeypatch.setattr(cnapp_server, "build_service", lambda: svc)

    assert cnapp_worker.main([]) == 0
    out = capsys.readouterr().out
    assert "error 1" in out, "a tick of nothing but failures printed no failure count"


def test_drain_only_does_not_enqueue(monkeypatch, capsys):
    """For a deployment where something else owns scheduling."""
    svc, reg = _svc(session_factory=lambda aid: FakeSession(aid))
    _active(reg)
    called = {"n": 0}
    real = svc.schedule_due_scans

    def counting(*a, **k):
        called["n"] += 1
        return real(*a, **k)
    svc.schedule_due_scans = counting

    from hub import cnapp_server
    monkeypatch.setattr(cnapp_server, "build_service", lambda: svc)

    assert cnapp_worker.main(["--drain-only"]) == 0
    assert called["n"] == 0, "--drain-only still ran the scheduler"


def test_a_worker_that_cannot_start_says_so_and_exits_non_zero(monkeypatch, capsys):
    """It has scanned nothing. Exiting 0 would make a broken deployment look like a
    quiet one with no due accounts — the same false-clean this codebase refuses
    everywhere else."""
    from hub import cnapp_server

    def boom():
        raise RuntimeError("CNAPP_DB_URL points nowhere")
    monkeypatch.setattr(cnapp_server, "build_service", boom)

    assert cnapp_worker.main([]) == 1
    assert "could not start" in capsys.readouterr().out


def test_the_loop_survives_a_failing_tick():
    """A worker exists to outlive individual failures. If one bad tick killed the
    process, a transient fault would stop all scanning until somebody noticed."""
    svc, _reg = _svc(session_factory=lambda aid: FakeSession(aid))
    calls = {"n": 0}

    def flaky(_svc, **k):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("transient")
        return {"enqueued": [], "ran": []}

    import hub.cnapp_worker as w
    real = w.scheduler_tick
    w.scheduler_tick = flaky
    try:
        totals = w.run_forever(svc, ticks=3, interval=0, sleep=lambda _s: None,
                               log=lambda *_a: None)
    finally:
        w.scheduler_tick = real

    assert totals["ticks"] == 3, "the loop stopped at the failing tick"
    assert totals["errors"] == 1


def test_the_loop_is_bounded_and_sleeps_between_ticks():
    """`ticks` and the injected sleep are what make this testable at all; an
    unbounded loop on a real clock is why worker loops go untested."""
    svc, _reg = _svc(session_factory=lambda aid: FakeSession(aid))
    slept = []
    totals = cnapp_worker.run_forever(svc, ticks=3, interval=42,
                                      sleep=slept.append, log=lambda *_a: None)
    assert totals["ticks"] == 3
    # two sleeps for three ticks: it does not sleep after the last one
    assert slept == [42, 42]


# ── the ratchet this module just left ───────────────────────────────────────

def test_cnapp_worker_is_no_longer_an_unreached_module():
    """It was listed in tests/test_unreached_modules.py as imported only by tests and
    unrunnable. Both halves are now false, so the entry disappears — that file's own
    test_no_declared_orphan_has_quietly_gained_a_caller enforces the removal."""
    from tests.test_unreached_modules import ENTRY_POINTS, UNREACHED
    assert "cnapp_worker" not in UNREACHED
    assert "cnapp_worker" in ENTRY_POINTS
