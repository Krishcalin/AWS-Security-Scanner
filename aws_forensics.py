#!/usr/bin/env python3
"""aws_forensics.py — cloud-forensics timeline: reconstruct who-did-what-when around
a resource from read-only CloudTrail management events and correlate it with the
attack-path graph, finding catalog, and live CDR detections.

Boto3-free and pure: ``build_timeline`` takes already-fetched CloudTrail event dicts
(the ONLY socket touch is the injected seam in cnapp_service, whose default impl is
``default_trail_lookup`` below) and returns an ordered, correlated timeline. It is
INFO/analysis only — the single id ``FORENSIC-00`` is a fail-open marker (the seam
returned no data → name the ``cloudtrail:LookupEvents`` prerequisite, never a
phantom "clean" timeline) and stays OUT of every scanner metadata map, so it needs
no severity / compliance / remediation / finding_detail row.

Per-event anomaly flags reuse ``aws_cdr.detect_cloudtrail_signals`` (root usage,
security-tooling tamper, credential creation, denied sensitive action), so the
forensics view and the CDR detection plane agree on what "suspicious" means.
"""
from __future__ import annotations

from typing import Dict, List, Optional


FORENSIC_UNAVAILABLE = (
    "cloudtrail:LookupEvents returned no data — enable/grant cloudtrail:LookupEvents "
    "(management events) to reconstruct the timeline (FORENSIC-00)")


def _tail(arn: str) -> str:
    s = str(arn or "")
    return s.split("/")[-1].split(":")[-1]


def _affects(entry: dict, resource_arn: str) -> bool:
    """Does a finding_catalog entry concern this resource? Loose match on the ARN
    or its tail against the entry's ``affected`` labels (which are resource names /
    ``cve@node-tail`` strings, not node ids)."""
    if not resource_arn:
        return False
    tail = _tail(resource_arn)
    for a in entry.get("affected", []):
        sa = str(a)
        if resource_arn == sa or (tail and tail in sa):
            return True
    return False


def _timeline_row(ev: dict) -> dict:
    """One CloudTrail event → a flat, display-ready timeline row with anomaly flags."""
    import aws_cdr                                           # near use; pure, no boto3
    ui = ev.get("userIdentity") or {}
    return {
        "event_id": ev.get("eventID") or ev.get("EventId"),
        "time": ev.get("eventTime") or ev.get("EventTime"),
        "event_name": ev.get("eventName"),
        "event_source": ev.get("eventSource"),
        "actor": ui.get("userName") or ui.get("arn") or ui.get("type"),
        "actor_arn": ui.get("arn"),
        "actor_type": ui.get("type"),
        "source_ip": ev.get("sourceIPAddress"),
        "region": ev.get("awsRegion"),
        "read_only": ev.get("readOnly"),
        "error_code": ev.get("errorCode"),
        "anomaly_signals": aws_cdr.detect_cloudtrail_signals(ev),
    }


def build_timeline(events: Optional[List[dict]], *, resource_arn: Optional[str] = None,
                   graph_dict: Optional[dict] = None, catalog: Optional[List[dict]] = None,
                   detections: Optional[List[dict]] = None) -> dict:
    """Build the correlated, time-ordered timeline for ``resource_arn``.

    ``events`` is the list of CloudTrail event dicts from the injected seam, or
    ``None`` when the seam could not read (denied/absent) → a FORENSIC-00
    unavailable result (fail-open, never a phantom clean timeline). Correlation is
    resource-level: whether the resource is on the attack-path graph, which
    findings concern it, and which live CDR detections name it — plus per-event
    actor / source-IP / anomaly flags."""
    if events is None:
        return {"status": "unavailable", "finding_id": "FORENSIC-00",
                "reason": FORENSIC_UNAVAILABLE, "resource": resource_arn,
                "count": 0, "timeline": []}

    rows = [_timeline_row(ev) for ev in events]
    # stable time order; events without a timestamp sort first (unknown-time)
    rows.sort(key=lambda r: (r.get("time") is None, r.get("time") or ""))

    on_graph = False
    if graph_dict and resource_arn:
        from aws_graph import SecurityGraph                  # near use; pure, no boto3
        on_graph = SecurityGraph.from_dict(graph_dict).node(resource_arn) is not None

    related_findings = sorted({e.get("check_id") for e in (catalog or [])
                               if _affects(e, resource_arn) and e.get("check_id")})
    related_detections = [{"id": d.get("id") or d.get("detection_id"),
                           "source": d.get("source"), "band": d.get("band"),
                           "incident": bool(d.get("incident"))}
                          for d in (detections or [])
                          if d.get("node_id") and d.get("node_id") == resource_arn]
    anomaly_events = [r for r in rows if r.get("anomaly_signals")]

    return {"status": "ok", "finding_id": None, "resource": resource_arn,
            "on_graph": on_graph, "count": len(rows), "timeline": rows,
            "related_findings": related_findings, "related_detections": related_detections,
            "actors": sorted({r["actor_arn"] for r in rows if r.get("actor_arn")}),
            "anomaly_count": len(anomaly_events),
            "anomaly_events": anomaly_events}


def default_trail_lookup(cloudtrail_client, resource_arn: str, start=None, end=None,
                         limit: int = 200) -> Optional[List[dict]]:
    """Default seam implementation — the ONLY socket touch. Given an already-created
    (assume-role'd) boto3 CloudTrail client, run a read-only ``lookup_events`` query
    for the resource and return parsed ``CloudTrailEvent`` dicts, or ``None`` on any
    error (→ FORENSIC-00 fail-open). Management-events only; never a data/secret read.
    A deployment wires this behind the service's ``trail_reader`` seam using its
    injected ``client_factory``; the pure builder never imports boto3."""
    import json
    try:
        attrs = [{"AttributeKey": "ResourceName", "AttributeValue": resource_arn}]
        kwargs = {"LookupAttributes": attrs, "MaxResults": min(int(limit), 50)}
        if start is not None:
            kwargs["StartTime"] = start
        if end is not None:
            kwargs["EndTime"] = end
        out: List[dict] = []
        paginator = cloudtrail_client.get_paginator("lookup_events")
        for page in paginator.paginate(**kwargs):
            for ev in page.get("Events", []):
                raw = ev.get("CloudTrailEvent")
                try:
                    out.append(json.loads(raw) if isinstance(raw, str) else (raw or {}))
                except Exception:
                    out.append({"eventName": ev.get("EventName"),
                                "eventTime": str(ev.get("EventTime")),
                                "eventID": ev.get("EventId")})
                if len(out) >= int(limit):
                    return out
        return out
    except Exception:
        return None
