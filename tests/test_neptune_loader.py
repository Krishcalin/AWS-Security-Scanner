"""Unit tests for aws_graph_neptune_loader — pure request-builders + mock-tested
bulk-load / openCypher runners (no boto3; injected s3/neptunedata/sleep)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_graph_neptune as gn
import aws_graph_neptune_loader as L
from aws_graph import SecurityGraph


def _graph():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("arn:i-1", "EC2Instance", instance_id="i-1")
    g.add_node("cve", "Vulnerability", kev=True, epss=0.9)
    g.add_edge("internet", "arn:i-1", "EXPOSED_TO")
    g.add_edge("arn:i-1", "cve", "HAS_VULN", cve="cve", kev=True)
    return g


# ── pure builders ────────────────────────────────────────────────────────────
def test_s3_key_layout_deterministic():
    bundle = gn.to_gremlin_csv(_graph())
    layout = L.s3_key_layout(bundle, "cnapp/graph", "scan-1")
    assert L.s3_key_layout(bundle, "cnapp/graph", "scan-1") == layout
    assert all(k.startswith("cnapp/graph/scan-1/") for k in layout.values())
    assert any(v.endswith("vertices_EC2Instance.csv") for v in layout.values())


def test_build_loader_request():
    req = L.build_loader_request("s3://b/p/", "arn:aws:iam::1:role/neptune", "us-east-1")
    assert req["format"] == "csv" and req["s3BucketRegion"] == "us-east-1"
    assert req["iamRoleArn"].endswith("role/neptune")
    assert req["updateSingleCardinalityProperties"] == "TRUE"   # idempotent reload
    assert req["source"] == "s3://b/p/"


def test_is_loader_terminal():
    assert L.is_loader_terminal("LOAD_COMPLETED")
    assert L.is_loader_terminal("LOAD_S3_READ_ERROR")
    assert not L.is_loader_terminal("LOAD_IN_PROGRESS")


# ── regression (adversarial rank 6): fail-closed terminal detection ──────────
def test_is_loader_terminal_fail_closed():
    # only the 3 in-progress states are non-terminal; any other (incl. future/
    # unusual failure codes) is terminal so the poll loop never hangs to timeout
    assert L.is_loader_terminal("LOAD_DATA_FAILED_DUE_TO_FEED_MODIFIED_OR_DELETED")
    assert L.is_loader_terminal("LOAD_COMMITTED_W_WRITE_CONFLICTS")
    assert not L.is_loader_terminal("LOAD_NOT_STARTED")
    assert not L.is_loader_terminal("LOAD_IN_QUEUE")


def test_bulk_load_breaks_fast_on_unusual_terminal():
    polls = {"n": 0}

    class ND:
        def start_loader_job(self, **kw):
            return {"payload": {"loadId": "l1"}}

        def get_loader_job_status(self, loadId):
            polls["n"] += 1
            return {"payload": {"overallStatus": {"status": "LOAD_COMMITTED_W_WRITE_CONFLICTS"}}}
    out = L.run_gremlin_bulk_load(_graph(), s3=FakeS3(), neptunedata=ND(), bucket="b",
                                  prefix="p", scan_id="s", iam_role_arn="r",
                                  region="us-east-1", sleep=lambda _s: None, max_polls=50)
    assert out["status"] == "LOAD_COMMITTED_W_WRITE_CONFLICTS"
    assert polls["n"] == 1                     # broke after the first poll, not 50


def test_opencypher_requests_json_params():
    reqs = L.opencypher_requests(_graph())
    assert reqs and all("openCypherQuery" in r and "parameters" in r for r in reqs)
    import json
    json.loads(reqs[0]["parameters"])          # parameters is JSON text


# ── mock-tested live runners ─────────────────────────────────────────────────
class FakeS3:
    def __init__(self):
        self.puts = []

    def put_object(self, Bucket, Key, Body):
        self.puts.append((Bucket, Key, len(Body)))


class FakeNeptunedata:
    def __init__(self, statuses):
        self._statuses = list(statuses)
        self.started = None
        self.cypher = []

    def start_loader_job(self, **kw):
        self.started = kw
        return {"payload": {"loadId": "load-123"}}

    def get_loader_job_status(self, loadId):
        s = self._statuses.pop(0) if self._statuses else "LOAD_COMPLETED"
        return {"payload": {"overallStatus": {"status": s}}}

    def execute_open_cypher_query(self, openCypherQuery, parameters):
        self.cypher.append((openCypherQuery, parameters))
        return {}


def test_run_gremlin_bulk_load():
    s3, nd = FakeS3(), FakeNeptunedata(["LOAD_IN_PROGRESS", "LOAD_COMPLETED"])
    out = L.run_gremlin_bulk_load(_graph(), s3=s3, neptunedata=nd, bucket="mybucket",
                                  prefix="cnapp", scan_id="s1",
                                  iam_role_arn="arn:role/n", region="us-east-1",
                                  sleep=lambda _s: None)
    assert out["status"] == "LOAD_COMPLETED" and out["loadId"] == "load-123"
    assert out["files"] == len(s3.puts) and s3.puts               # CSVs uploaded
    assert nd.started["format"] == "csv"


def test_run_gremlin_bulk_load_surfaces_error_status():
    s3, nd = FakeS3(), FakeNeptunedata(["LOAD_S3_READ_ERROR"])
    out = L.run_gremlin_bulk_load(_graph(), s3=s3, neptunedata=nd, bucket="b",
                                  prefix="p", scan_id="s1", iam_role_arn="r",
                                  region="us-east-1", sleep=lambda _s: None)
    assert out["status"] == "LOAD_S3_READ_ERROR"                  # terminal, not hung


def test_run_opencypher_upsert():
    nd = FakeNeptunedata([])
    out = L.run_opencypher_upsert(_graph(), neptunedata=nd)
    assert out["batches"] == out["executed"] == len(nd.cypher)
    assert out["batches"] >= 1
