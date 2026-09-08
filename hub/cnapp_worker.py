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

from hub import cnapp_onboarding
from hub.cnapp_service import ScanSpec, serialize_scanner


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

    # 0b. OUR CONFIGURATION IS NOT THE CUSTOMER'S FAULT. `session_factory` is
    #     Optional and defaults to None, and hub/cnapp_server.py build_service()
    #     did not set it — so the call below raised TypeError, the handler treated
    #     it as an assume-role failure, and `deny=True` set the account to 'denied'.
    #     'denied' means "we asked AWS and were refused", and it also drops the
    #     account out of `trigger_scan`'s ACTIVE set: one misconfigured worker run
    #     permanently stopped scanning every account it touched. A hub that cannot
    #     build a session has learned nothing about the customer's trust policy, so
    #     the job fails and the onboarding status is left exactly as it was.
    if not callable(getattr(svc, "session_factory", None)):
        return fail("hub misconfigured: no session_factory is wired, so no role "
                    "can be assumed; the account's onboarding status is unchanged")

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

    # 4. persist results + stamp the account's last_scan_at (terminal 'done').
    #    Capture the PREVIOUS payload first (for the digest's compliance delta) before
    #    results.put overwrites it.
    try:
        prev_payload = svc.results.get_latest(account_id) if getattr(svc, "state", None) else None
        payload = serialize_scanner(sc)
        svc.results.put(account_id, payload)
        findings = payload.get("summary", {}).get("FAIL", 0)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:                            # noqa: BLE001
        return fail(f"result persistence error: {type(e).__name__}: {e}")

    # 4.5 best-effort: fold this scan into the lifecycle store (drift / trend / MTTR).
    #     After the expensive AWS work; wrapped so a state error never fails a 'done' job.
    drift = None
    became_reachable: list = []
    scan_epoch = svc.clock()
    if getattr(svc, "state", None) is not None:
        try:
            drift = svc.record_lifecycle(account_id, payload, scan_id=job_id, scan_epoch=scan_epoch)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:                             # noqa: BLE001
            drift = None
        # 4.6 re-rank ingested CVEs against the FRESH graph_full; capture the
        #     newly-reachable delta for the drift digest. Best-effort / fail-open.
        try:
            became_reachable = svc.refresh_vuln_reachability(account_id).get("became_reachable", [])
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:                             # noqa: BLE001
            became_reachable = []

    # 4.7 best-effort: persist any registry-pulled image SBOMs (Slice-5 Tier B) as durable
    #     snapshots so diff / license / VEX apply. Read-only (works off the pulled SBOM +
    #     stored graph); a persistence error must NEVER fail a 'done' job.
    if getattr(svc, "state", None) is not None and getattr(sc, "registry_sboms", None):
        for _sbom in sc.registry_sboms:
            try:
                svc.ingest_document(account_id, doc=_sbom["doc"],
                                    source_tool="ecr-sidescan", target_resource=_sbom["node_id"])
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:                             # noqa: BLE001
                pass

    # 5. best-effort: fire enabled connectors — the per-finding queue AND (if we have a
    #    drift dict) one drift-digest per scan. A dead/slow receiver or any notify error
    #    must NEVER fail a completed job, so each is wrapped + swallowed.
    if getattr(svc, "connectors", None) is not None:
        try:
            svc.notify_account(account_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:                             # noqa: BLE001
            pass
        if drift is not None:
            try:
                svc.notify_digest(account_id, drift, scan_id=job_id, scan_epoch=scan_epoch,
                                  prev_payload=prev_payload, became_reachable=became_reachable)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:                         # noqa: BLE001
                pass

    end = svc.clock()
    svc.registry.record_scan_job(account_id, job_id, "done", now_epoch=end,
                                 finished_at=end, findings_count=findings)
    # 6. best-effort: meter the completed scan (billable account.active gauge). Wrapped +
    #    swallowed like the connector block — metering must NEVER fail a completed job.
    if getattr(svc, "metering", None) is not None:
        try:
            resources = len((payload.get("graph_full") or {}).get("nodes", []))
            svc.meter_scan_completed(account_id, job_id, findings=findings, resources=resources)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:                             # noqa: BLE001
            pass
    return svc.registry.get_scan_job(job_id)


def drain_once(svc, *, spec: ScanSpec = None, limit: int = 100) -> list:
    """Run every currently-queued job once (single-threaded). A real deployment
    would run this on a loop / worker pool; kept simple + synchronous so it is
    deterministic to test."""
    done = []
    for job in svc.pending_jobs()[:limit]:
        done.append(run_scan_job(svc, job, spec=spec))
    return done


def scheduler_tick(svc, *, spec: ScanSpec = None, limit: int = 100) -> dict:
    """One continuous-scanning tick: enqueue every account whose cadence is due, then
    drain the queue. Driven by an external cron (k8s CronJob / systemd timer) or
    ``POST /scans/schedule-tick``. Deterministic under the injected clock, so a test
    drives it directly."""
    enqueued = svc.schedule_due_scans()
    ran = drain_once(svc, spec=spec, limit=limit)
    return {"enqueued": enqueued, "ran": ran}


def make_session_factory(registry, secret_reader, *, role_name: str = "CnappScannerRole",
                         region: str = "us-east-1"):
    """Production session factory: (account_id) -> boto3.Session assumed into the
    spoke role, resolving the ExternalId from the secret store at call time.
    Imported by the API wiring, not by tests."""
    from engine import aws_live_scanner as als

    def factory(account_id: str):
        acct = registry.get_account(account_id) or {}
        role_arn = acct.get("role_arn") or f"arn:aws:iam::{account_id}:role/{role_name}"
        external_id = cnapp_onboarding.resolve_external_id(
            acct.get("external_id_ref"), secret_reader=secret_reader, region=region)
        return als.assume_role_session(account_id, role_arn, external_id=external_id,
                                       region=region)
    return factory


# ── the process ─────────────────────────────────────────────────────────────
def run_forever(svc, *, spec: ScanSpec = None, interval: int = 300,
                limit: int = 100, ticks: Optional[int] = None,
                sleep=None, log=print) -> dict:
    """Tick, sleep, repeat. ``ticks`` bounds the loop so a test can drive it, and
    ``sleep`` is injected for the same reason — an unbounded loop with a real
    ``time.sleep`` is not testable, and an untested worker loop is how this module
    came to have no caller at all.

    A tick that raises does NOT kill the worker: the whole point of this process is
    to outlive individual failures, and ``run_scan_job`` already converts expected
    AWS/engine failures into FAILED jobs. Anything that escapes it is unexpected, so
    it is reported and the loop continues to the next tick.
    """
    import time

    sleep = sleep or time.sleep
    totals = {"ticks": 0, "enqueued": 0, "ran": 0, "errors": 0}
    n = 0
    while ticks is None or n < ticks:
        n += 1
        try:
            out = scheduler_tick(svc, spec=spec, limit=limit)
            totals["enqueued"] += len(out["enqueued"])
            totals["ran"] += len(out["ran"])
            log("tick %d: enqueued %d, ran %d"
                % (n, len(out["enqueued"]), len(out["ran"])))
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:                        # noqa: BLE001
            totals["errors"] += 1
            log("tick %d FAILED: %s: %s" % (n, type(e).__name__, e))
        totals["ticks"] = n
        if ticks is None or n < ticks:
            sleep(interval)
    return totals


def main(argv=None) -> int:
    """``python -m hub.cnapp_worker`` — drain the hosted scan queue.

    WHY THIS EXISTS. ``POST /scans`` and ``POST /scans/schedule-tick`` both only
    ENQUEUE: ``trigger_scan``'s docstring says outright "(The worker drains the
    queue; this never blocks on a scan.)". Nothing drained it. A hosted deployment
    accepted scan requests, recorded them ``queued``, and never ran one — and with
    no ``__main__`` this module could not be started either, so the documented async
    scan path was unreachable from both ends.

    The service comes from ``cnapp_server.build_service()``, the same construction
    the API uses, so the worker and the API cannot disagree about the database, the
    secret store, or which role is assumed.
    """
    import argparse

    from hub import cnapp_server

    p = argparse.ArgumentParser(
        prog="python -m hub.cnapp_worker",
        description="Drain the hosted OverWatch scan-job queue.")
    p.add_argument("--interval", type=int, default=0, metavar="SECONDS",
                   help="Run continuously, sleeping this long between ticks. "
                        "Default 0 = one tick and exit, for a cron/CronJob.")
    p.add_argument("--limit", type=int, default=100,
                   help="Maximum jobs to run per tick (default 100).")
    p.add_argument("--drain-only", action="store_true",
                   help="Drain jobs already queued without enqueueing accounts whose "
                        "cadence is due. Use when something else owns scheduling.")
    args = p.parse_args(argv)

    try:
        svc = cnapp_server.build_service()
    except Exception as e:                            # noqa: BLE001
        # A worker that cannot build its service has scanned nothing. Say so and
        # exit non-zero rather than looking like a clean run with no due accounts.
        print("worker could not start: %s: %s" % (type(e).__name__, e))
        return 1

    if args.interval > 0:
        totals = run_forever(svc, interval=args.interval, limit=args.limit)
        print("stopped after %(ticks)d tick(s): enqueued %(enqueued)d, "
              "ran %(ran)d, %(errors)d failed tick(s)" % totals)
        return 0

    if args.drain_only:
        ran = drain_once(svc, limit=args.limit)
        enqueued = []
    else:
        out = scheduler_tick(svc, limit=args.limit)
        enqueued, ran = out["enqueued"], out["ran"]

    # Per-status counts, because "ran 12" hides twelve failures.
    by_status = {}
    for job in ran:
        by_status[job.get("status", "?")] = by_status.get(job.get("status", "?"), 0) + 1
    print("enqueued %d, ran %d%s" % (
        len(enqueued), len(ran),
        (" (" + ", ".join("%s %d" % kv for kv in sorted(by_status.items())) + ")")
        if by_status else ""))
    return 0


if __name__ == "__main__":                            # pragma: no cover
    raise SystemExit(main())
