#!/usr/bin/env python3
"""cnapp_marketplace_metering.py — OPTIONAL AWS Marketplace usage emitter.

Bills the Slice-1 metering signal — *accounts under management* — to AWS Marketplace via
the hourly ``marketplacemetering:MeterUsage`` API (the container/AMI self-hosted metering
call). OPT-IN and off by default: a deployment wires it only for a *metered* Marketplace
listing. An **air-gapped** install uses a contract / private-offer SKU and never wires this
at all (see ``deploy/marketplace/README.md``).

The ONLY egress is the AWS Marketplace API (an AWS endpoint, reachable via a
``marketplacemetering`` VPC endpoint) — no telemetry. The boto3 client is injected, so this
module is pure + offline-testable.
"""
from __future__ import annotations

from typing import Optional

from aws_state import make_scan_ts


def accounts_under_management(metering, *, period: Optional[str] = None) -> int:
    """The billable quantity for a period = the count of distinct ``account.active`` events
    across all workspaces (the MSSP operator's aggregate). Reads the Slice-1 ledger only —
    no AWS call. ``metering`` is a ``cnapp_metering.MeteringStore``."""
    rows = metering.usage_rollup_all(period=period)
    return sum(int(r.get("event_count") or 0)
               for r in rows if r.get("metric") == "account.active")


def meter_hourly(metering, *, product_code: str, now_epoch: int, mp_client,
                 dimension: str = "accounts_under_mgmt",
                 period: Optional[str] = None) -> dict:
    """Emit ONE hourly ``MeterUsage`` record for the current period's accounts under
    management. ``mp_client`` is a boto3 ``marketplacemetering`` client (injected so this is
    testable offline). Idempotent by design: AWS Marketplace hour-buckets ``MeterUsage`` and
    rejects a duplicate submission in the same hour (``DuplicateRequestException``), so a
    re-run within the hour is a safe no-op — the caller schedules it hourly."""
    ts = make_scan_ts(int(now_epoch))
    qty = accounts_under_management(metering, period=period or ts.iso[:7])
    try:
        resp = mp_client.meter_usage(
            ProductCode=product_code,
            Timestamp=ts.epoch,
            UsageDimension=dimension,
            UsageQuantity=qty)
    except Exception as e:  # noqa: BLE001
        # AWS Marketplace hour-buckets MeterUsage and rejects a duplicate submission in the
        # same hour with DuplicateRequestException — that IS the intended idempotent no-op, so
        # swallow it (identified by name to stay decoupled from botocore's exception hierarchy).
        if type(e).__name__ == "DuplicateRequestException" or "DuplicateRequest" in str(e):
            return {"quantity": qty, "dimension": dimension, "period": period or ts.iso[:7],
                    "metering_record_id": None, "duplicate": True}
        raise
    return {"quantity": qty, "dimension": dimension, "period": period or ts.iso[:7],
            "metering_record_id": resp.get("MeteringRecordId"), "duplicate": False}
