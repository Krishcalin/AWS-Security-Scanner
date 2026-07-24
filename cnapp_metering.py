#!/usr/bin/env python3
"""cnapp_metering.py — usage metering for the MSSP play (Phase-4 Slice-1).

A ``MeteringStore`` over the shared ``cnapp_backend.Backend``, writing an append-only,
exactly-once ``usage_events`` ledger (dedup via ``UNIQUE(workspace_id, metric,
event_key)``). The BILLABLE dimension is *accounts under management*: an
``account.active`` event per (account, billing-period) — emitted whenever an account is
scanned in a period, and re-derivable by :func:`reconcile`. ``account.onboarded`` and
``scan.completed`` are recorded for observability.

Design guarantees:
  * **Fail-open.** ``record`` never raises — a metering write can never break a scan /
    onboard / ingest. Under-billing self-heals via the idempotent ``reconcile``.
  * **Idempotent.** ``ON CONFLICT DO NOTHING`` on the dedup key means re-emitting the
    same event (a re-run scan, a re-drained job) never double-counts.
  * **Dual-dialect + pure.** Placeholders are ``?`` and routed through ``Backend.execute``
    (which converts ``?→%s`` on Postgres). ``period`` is a stored ``'YYYY-MM'`` string so
    rollups ``GROUP BY period`` are pure ANSI on both engines.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

from aws_state import make_scan_ts

DEFAULT_WORKSPACE = "ws-default"

_INSERT = (
    "INSERT INTO usage_events(workspace_id,account_id,metric,event_key,quantity,"
    "period,event_epoch,event_iso,meta_json) VALUES(?,?,?,?,?,?,?,?,?) "
    "ON CONFLICT (workspace_id,metric,event_key) DO NOTHING")


class MeteringStore:
    def __init__(self, backend):
        self._be = backend

    def record(self, workspace_id: str, metric: str, *, event_key: str, now_epoch: int,
               account_id: Optional[str] = None, quantity: int = 1,
               meta: Optional[dict] = None) -> None:
        """Append a usage event (exactly-once by (workspace_id, metric, event_key)).
        FAIL-OPEN: any error is swallowed so a metering write never breaks its caller."""
        try:
            ts = make_scan_ts(int(now_epoch))
            self._be.execute(_INSERT, [workspace_id, account_id, metric, event_key,
                                       int(quantity), ts.iso[:7], ts.epoch, ts.iso,
                                       json.dumps(meta or {})])
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            pass

    def usage_summary(self, workspace_id: str, *, period: Optional[str] = None) -> List[Dict]:
        sql = ["SELECT metric, COUNT(*) event_count, SUM(quantity) quantity "
               "FROM usage_events WHERE workspace_id=?"]
        params: List = [workspace_id]
        if period:
            sql.append("AND period=?"); params.append(period)
        sql.append("GROUP BY metric ORDER BY metric")
        return [dict(r) for r in self._be.query_all(" ".join(sql), params)]

    def usage_history(self, workspace_id: str, *, from_period: Optional[str] = None,
                      to_period: Optional[str] = None) -> List[Dict]:
        sql = ["SELECT period, metric, COUNT(*) event_count, SUM(quantity) quantity "
               "FROM usage_events WHERE workspace_id=?"]
        params: List = [workspace_id]
        if from_period:
            sql.append("AND period>=?"); params.append(from_period)
        if to_period:
            sql.append("AND period<=?"); params.append(to_period)
        sql.append("GROUP BY period, metric ORDER BY period, metric")
        return [dict(r) for r in self._be.query_all(" ".join(sql), params)]

    def usage_rollup_all(self, *, period: Optional[str] = None) -> List[Dict]:
        """Cross-workspace rollup — the superadmin (MSSP operator) billing view."""
        sql = ["SELECT workspace_id, metric, COUNT(*) event_count, SUM(quantity) quantity "
               "FROM usage_events"]
        params: List = []
        if period:
            sql.append("WHERE period=?"); params.append(period)
        sql.append("GROUP BY workspace_id, metric ORDER BY workspace_id, metric")
        return [dict(r) for r in self._be.query_all(" ".join(sql), params)]


def reconcile(store: MeteringStore, registry, workspaces, *, now_epoch: int) -> Dict[str, int]:
    """Re-derive the billable metering events from durable source tables — so a
    fail-open dropped write self-heals. Idempotent (``ON CONFLICT DO NOTHING``): a
    second run adds nothing. Emits ``account.onboarded`` (lifetime, per account) and
    ``account.active`` (current billing period, per active account under management)."""
    period = make_scan_ts(int(now_epoch)).iso[:7]
    onboarded = active = 0
    for a in registry.list_accounts():
        aid = a["account_id"]
        ws = (workspaces.workspace_of_account(aid) if workspaces else None) or DEFAULT_WORKSPACE
        store.record(ws, "account.onboarded", event_key=aid, now_epoch=now_epoch, account_id=aid)
        onboarded += 1
        if a.get("onboarding_status") == "active":
            store.record(ws, "account.active", event_key=f"{aid}:{period}",
                         now_epoch=now_epoch, account_id=aid)
            active += 1
    return {"reconciled_period": period, "onboarded": onboarded, "active": active}
