#!/usr/bin/env python3
"""
cnapp_worker.py — async scan-job execution for the hosted CNAPP (Phase 8).

Drains queued scan jobs off the request path. For each job it: assumes the spoke
role, PRE-VALIDATES the credentials with sts:GetCallerIdentity, runs the unchanged
engine, and persists the serialized result — while trapping two failure modes that
would otherwise kill a long-lived worker:

  1. The engine calls ``sys.exit(2)`` on a credential/connect failure
     (aws_live_scanner.py run()); we catch ``SystemExit`` and convert it to a
     FAILED job instead of terminating the worker process.
  2. A pre-validation failure (revoked role, wrong account) is turned into a FAILED
     job + a 'denied' onboarding status, so the engine is never even invoked.

One AWSLiveScanner per job — the engine is stateful (mutates self.region, caches
clients on the session) and NOT safe to share across concurrent jobs.

Pure/offline-testable: the worker takes a PlatformService whose collaborators are
injected; a test drives it with a fake scan_runner + session_factory.
"""

from __future__ import annotations

from typing import Optional

import cnapp_onboarding
from cnapp_service import ScanSpec, serialize_scanner


def _pre_validate(session, account_id: str) -> Optional[str]:
    """Confirm the assumed session actually points at ``account_id`` before running
    a full scan. Returns None on success, else a short failure reason. Fails CLOSED:
    an empty/unknown observed account is a failure, never a pass."""
    try:
        sts = session.client("sts")
        observed = str((sts.get_caller_identity() or {}).get("Account", "") or "")
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:                           # noqa: BLE001
        return f"credential check failed: {type(e).__name__}: {e}"
    if observed != account_id:
        return f"assumed session is account {observed or '<unknown>'}, expected {account_id}"
    return None


def run_scan_job(svc, job: dict, *, spec: ScanSpec = None) -> dict:
    """Execute one scan job end-to-end and persist its outcome. Returns the terminal
    job record. Never raises for an expected AWS/engine failure — those become a
    FAILED job. ``job`` is a scan_jobs row dict ({job_id, account_id, ...})."""
    spec = spec or ScanSpec()
    account_id = job["account_id"]
    job_id = job["job_id"]
    now = svc.clock()
    svc.registry.record_scan_job(account_id, job_id, "running", now_epoch=now,
                                 started_at=now)

    def fail(reason: str, *, deny: bool = False) -> dict:
        end = svc.clock()
        svc.registry.record_scan_job(account_id, job_id, "error", now_epoch=end,
                                     finished_at=end, error=reason[:500])
        if deny:
            svc.registry.set_onboarding_status(account_id, "denied", end)
        return svc.registry.get_scan_job(job_id)

    # 0. re-check the account is still active (it may have been disabled/denied
    #    between enqueue and execution). A non-deny abort — a transient disable
    #    must not itself flip the account to 'denied'.
    acct = svc.registry.get_account(account_id)
    if not acct or acct.get("onboarding_status") != "active":
        status = acct.get("onboarding_status") if acct else "missing"
        return fail(f"account no longer active (status={status}) — skipping scan")

    # 1. build the assumed-role session
    try:
        session = svc.session_factory(account_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:                            # noqa: BLE001
        return fail(f"could not assume role: {type(e).__name__}: {e}", deny=True)

    # 2. pre-validate creds before the (expensive) scan
    reason = _pre_validate(session, account_id)
    if reason:
        return fail(reason, deny=True)

    # 3. run the engine, trapping its sys.exit(2) (but never KeyboardInterrupt)
    try:
        sc = svc.scan_runner(session, spec)
    except SystemExit as e:
        return fail(f"engine exit {getattr(e, 'code', '?')} (credential/connect failure)")
    except KeyboardInterrupt:
        raise
    except Exception as e:                            # noqa: BLE001
        return fail(f"scan error: {type(e).__name__}: {e}")

    # 4. persist results + stamp the account's last_scan_at (terminal 'done')
    try:
        payload = serialize_scanner(sc)
        svc.results.put(account_id, payload)
        findings = payload.get("summary", {}).get("FAIL", 0)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:                            # noqa: BLE001
        return fail(f"result persistence error: {type(e).__name__}: {e}")

    # 5. best-effort: fire enabled connectors over the fresh results. A dead/slow
    #    receiver or any notify error must NEVER fail a completed scan job, so this
    #    is wrapped + swallowed. A no-op when no connector store / rules are wired.
    if getattr(svc, "connectors", None) is not None:
        try:
            svc.notify_account(account_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:                             # noqa: BLE001
            pass

    end = svc.clock()
    svc.registry.record_scan_job(account_id, job_id, "done", now_epoch=end,
                                 finished_at=end, findings_count=findings)
    return svc.registry.get_scan_job(job_id)


def drain_once(svc, *, spec: ScanSpec = None, limit: int = 100) -> list:
    """Run every currently-queued job once (single-threaded). A real deployment
    would run this on a loop / worker pool; kept simple + synchronous so it is
    deterministic to test."""
    done = []
    for job in svc.pending_jobs()[:limit]:
        done.append(run_scan_job(svc, job, spec=spec))
    return done


def make_session_factory(registry, secret_reader, *, role_name: str = "CnappScannerRole",
                         region: str = "us-east-1"):
    """Production session factory: (account_id) -> boto3.Session assumed into the
    spoke role, resolving the ExternalId from the secret store at call time.
    Imported by the API wiring, not by tests."""
    import aws_live_scanner as als

    def factory(account_id: str):
        acct = registry.get_account(account_id) or {}
        role_arn = acct.get("role_arn") or f"arn:aws:iam::{account_id}:role/{role_name}"
        external_id = cnapp_onboarding.resolve_external_id(
            acct.get("external_id_ref"), secret_reader=secret_reader, region=region)
        return als.assume_role_session(account_id, role_arn, external_id=external_id,
                                       region=region)
    return factory
