"""Slice 3 · Batch 5 — aws_forensics.build_timeline pure builder + FORENSIC-00 fail-open."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_forensics as F
from aws_graph import SecurityGraph

ACCT = "111122223333"
INST = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"


def _ev(name="RunInstances", actor=f"arn:aws:iam::{ACCT}:user/bob", t="2026-01-02T03:04:05Z",
        etype="IAMUser", ip="1.2.3.4", eid="e1", err=None):
    e = {"eventID": eid, "eventTime": t, "eventName": name, "eventSource": "ec2.amazonaws.com",
         "userIdentity": {"type": etype, "arn": actor, "userName": actor.split("/")[-1]},
         "sourceIPAddress": ip, "awsRegion": "us-east-1", "readOnly": False}
    if err:
        e["errorCode"] = err
    return e


def test_unavailable_when_none():
    r = F.build_timeline(None, resource_arn=INST)
    assert r["status"] == "unavailable" and r["finding_id"] == "FORENSIC-00" and r["timeline"] == []


def test_ordered_and_flat_rows():
    evs = [_ev(eid="late", t="2026-02-01T00:00:00Z"), _ev(eid="early", t="2026-01-01T00:00:00Z")]
    r = F.build_timeline(evs, resource_arn=INST)
    assert r["status"] == "ok" and r["count"] == 2
    assert [row["event_id"] for row in r["timeline"]] == ["early", "late"]


def test_anomaly_flagged():
    root = _ev(name="StopLogging", etype="Root", actor=f"arn:aws:iam::{ACCT}:root")
    r = F.build_timeline([root], resource_arn=INST)
    assert r["anomaly_count"] == 1
    sigs = r["timeline"][0]["anomaly_signals"]
    assert "root-usage" in sigs and "security-tooling-tamper" in sigs


def test_correlates_graph_findings_detections():
    g = SecurityGraph()
    g.add_node(INST, "EC2Instance", instance_id="i-1")
    catalog = [{"check_id": "VPC-01", "affected": ["i-1"]}]
    dets = [{"id": "gd-1", "node_id": INST, "source": "guardduty", "band": "High", "incident": True}]
    r = F.build_timeline([_ev()], resource_arn=INST, graph_dict=g.to_dict(),
                         catalog=catalog, detections=dets)
    assert r["on_graph"] is True
    assert "VPC-01" in r["related_findings"]
    assert r["related_detections"] and r["related_detections"][0]["id"] == "gd-1"


def test_not_on_graph_when_absent():
    g = SecurityGraph()
    r = F.build_timeline([_ev()], resource_arn=INST, graph_dict=g.to_dict())
    assert r["on_graph"] is False and r["related_findings"] == []


def test_actor_extracted():
    r = F.build_timeline([_ev()], resource_arn=INST)
    assert r["actors"] == [f"arn:aws:iam::{ACCT}:user/bob"]
