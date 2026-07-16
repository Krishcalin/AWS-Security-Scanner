#!/usr/bin/env python3
"""
aws_graph_neptune_loader.py — push the exported security graph into a live Amazon
Neptune cluster (CNAPP Phase 7). Reuses aws_graph_neptune's PURE exporters
(to_gremlin_csv / to_opencypher_upsert) unchanged; adds pure request-builders +
mock-tested orchestration runners. SigV4 is delegated to the boto3 neptunedata
client (never hand-rolled).

Pure/testable (no boto3): s3_key_layout, build_loader_request, is_loader_terminal,
opencypher_requests. Live runners (run_gremlin_bulk_load / run_opencypher_upsert)
take injected s3 / neptunedata clients + sleep, so they are fully mock-tested; the
only genuinely-live seam is the real AWS calls. Fail-open: boto3 absent / any
ClientError → the caller keeps today's behavior (write local CSV/cypher files).
"""

from __future__ import annotations

import json
from typing import Callable, Dict, List

import aws_graph_neptune as gn

# Neptune bulk-loader terminal statuses (poll until one of these).
LOADER_TERMINAL = frozenset({
    "LOAD_COMPLETED", "LOAD_FAILED", "LOAD_CANCELLED_BY_USER",
    "LOAD_CANCELLED_DUE_TO_ERRORS", "LOAD_UNEXPECTED_ERROR", "LOAD_S3_READ_ERROR",
    "LOAD_S3_ACCESS_DENIED_ERROR", "LOAD_DATA_DEADLOCK", "LOAD_FAILED_BECAUSE_DEPENDENCY_NOT_SATISFIED",
    "LOAD_FAILED_INVALID_REQUEST",
})


def is_loader_terminal(status: str) -> bool:
    return status in LOADER_TERMINAL


def s3_key_layout(bundle, prefix: str, scan_id: str) -> Dict[str, str]:
    """Deterministic S3 key per bundle file: {prefix}/{scan_id}/<file>. Returns
    {local_filename -> s3_key}."""
    base = "/".join(p for p in (prefix.strip("/"), scan_id) if p)
    out: Dict[str, str] = {}
    for label in sorted(bundle.vertex_files):
        fn = f"vertices_{label}.csv"
        out[fn] = f"{base}/{fn}"
    for label in sorted(bundle.edge_files):
        fn = f"edges_{label}.csv"
        out[fn] = f"{base}/{fn}"
    return out


def build_loader_request(source_uri: str, iam_role_arn: str, region: str, *,
                         mode: str = "AUTO", update_single_cardinality: bool = True,
                         fail_on_error: bool = True, parallelism: str = "MEDIUM",
                         queue_request: bool = True) -> dict:
    """The start_loader_job payload for a Gremlin CSV bulk load. The S3 bucket MUST
    be in the same region as the cluster or Neptune returns LOAD_S3_READ_ERROR."""
    return {
        "source": source_uri, "format": "csv", "s3BucketRegion": region,
        "iamRoleArn": iam_role_arn, "mode": mode,
        "failOnError": "TRUE" if fail_on_error else "FALSE",
        "parallelism": parallelism,
        "updateSingleCardinalityProperties": "TRUE" if update_single_cardinality else "FALSE",
        "queueRequest": "TRUE" if queue_request else "FALSE",
    }


def opencypher_requests(graph, batch: int = 200) -> List[dict]:
    """Reuse the pure openCypher upsert batches, shaped for
    neptunedata.execute_open_cypher_query (parameters JSON-encoded, deterministic)."""
    out: List[dict] = []
    for query, params in gn.to_opencypher_upsert(graph, batch=batch):
        out.append({"openCypherQuery": query,
                    "parameters": json.dumps(params, sort_keys=True)})
    return out


def run_gremlin_bulk_load(graph, *, s3, neptunedata, bucket: str, prefix: str,
                          scan_id: str, iam_role_arn: str, region: str,
                          poll_seconds: float = 5, sleep: Callable = None,
                          max_polls: int = 240) -> dict:
    """Upload the Gremlin CSV bundle to S3, start a bulk-load job, and poll to a
    terminal status. Injected s3 / neptunedata / sleep → fully mock-testable."""
    import time
    sleep = sleep or time.sleep
    bundle = gn.to_gremlin_csv(graph)
    layout = s3_key_layout(bundle, prefix, scan_id)
    # key the content map by the SAME filename convention as s3_key_layout
    files: Dict[str, str] = {}
    for label, text in bundle.vertex_files.items():
        files[f"vertices_{label}.csv"] = text
    for label, text in bundle.edge_files.items():
        files[f"edges_{label}.csv"] = text
    for fn, key in layout.items():
        s3.put_object(Bucket=bucket, Key=key, Body=files[fn].encode("utf-8"))
    source_uri = f"s3://{bucket}/{'/'.join(p for p in (prefix.strip('/'), scan_id) if p)}/"
    req = build_loader_request(source_uri, iam_role_arn, region)
    started = neptunedata.start_loader_job(**req)
    load_id = (started.get("payload") or {}).get("loadId") or started.get("loadId")
    status = "LOAD_IN_PROGRESS"
    detail = {}
    for _ in range(max_polls):
        resp = neptunedata.get_loader_job_status(loadId=load_id)
        payload = resp.get("payload") or resp
        status = (((payload.get("overallStatus") or {}).get("status"))
                  or payload.get("status") or status)
        detail = payload
        if is_loader_terminal(status):
            break
        sleep(poll_seconds)
    return {"loadId": load_id, "status": status, "files": len(layout), "detail": detail}


def run_opencypher_upsert(graph, *, neptunedata, batch: int = 200) -> dict:
    """Idempotent openCypher upsert over the HTTPS endpoint (SigV4 via the boto3
    neptunedata client). Returns a per-batch execution summary."""
    reqs = opencypher_requests(graph, batch=batch)
    ok = 0
    for r in reqs:
        neptunedata.execute_open_cypher_query(
            openCypherQuery=r["openCypherQuery"], parameters=r["parameters"])
        ok += 1
    return {"batches": len(reqs), "executed": ok}
