"""Blast-radius B2 — cnapp_service.get_blast_radius + the GET /accounts/{id}/graph/
blast-radius route. Read-only reverse+forward reachability over the persisted graph_full,
over the frozen aws_correlate.E_PATH edge universe (annotations like HAS_VULN are NOT
traversed). Offline; the API half skips if fastapi is absent."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import cnapp_connectors as cc
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"
EC2 = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
ROLE = f"arn:aws:iam::{ACCT}:role/AppRole"
ADMIN = f"cap:admin:{ACCT}"
BUCKET = "arn:aws:s3:::crown-bucket"


def _graph():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node(EC2, "EC2Instance", name="i-1")
    g.add_node(ROLE, "IAMRole", name="AppRole")
    g.add_node(ADMIN, "AdminCapability", name="admin")
    g.add_node(BUCKET, "S3Bucket", name="crown-bucket", crown_jewel=True)
    g.add_node("island", "S3Bucket")                       # unconnected, not crown
    g.add_edge("internet", EC2, "EXPOSED_TO")              # internet reaches the host
    g.add_edge(EC2, ROLE, "HAS_ROLE")
    g.add_edge(ROLE, ADMIN, "CAN_PRIVESC_TO")              # ...which can privesc to admin
    g.add_edge(EC2, BUCKET, "CAN_READ_DATA")               # ...and read crown-jewel data
    g.add_node("CVE-1", "Vulnerability", severity="CRITICAL")
    g.add_edge(EC2, "CVE-1", "HAS_VULN")                   # annotation — must NOT be traversed
    return g


def _svc(graph=None):
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be)
    results = InMemoryResultStore()
    if graph is not None:
        results.put(ACCT, {"account": ACCT, "graph_full": graph.to_dict(),
                           "results": [], "attack_paths": [], "finding_catalog": []})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state, clock=lambda: 5000)


# ── service layer ─────────────────────────────────────────────────────────────
def test_reaches_crown_and_admin_forward():
    r = _svc(_graph()).get_blast_radius(ACCT, EC2)
    assert r["exists"] is True and r["kind"] == "EC2Instance"
    terminals = {row["id"]: row["terminal"] for row in r["reaches"]}
    assert terminals == {BUCKET: "data", ADMIN: "admin"}     # crown + admin, nothing else
    assert r["counts"]["crowns"] == 1 and r["counts"]["admins"] == 1
    # crown ("data") is ranked first
    assert r["reaches"][0]["terminal"] == "data"


def test_reached_by_and_internet_flag_reverse():
    r = _svc(_graph()).get_blast_radius(ACCT, EC2)
    reached = {row["id"] for row in r["reached_by"]}
    assert reached == {"internet"}                            # only the internet reaches the host
    assert r["internet_reachable"] is True
    assert r["counts"]["sources"] == 1


def test_has_vuln_annotation_not_traversed():
    # CVE-1 hangs off the host via HAS_VULN (not in E_PATH) — it must never be a reach.
    r = _svc(_graph()).get_blast_radius(ACCT, EC2)
    assert all(row["id"] != "CVE-1" for row in r["reaches"])


def test_deep_node_no_internet_and_no_reaches():
    # the crown bucket is a leaf: reaches nothing, and internet does not *directly* need flagging
    r = _svc(_graph()).get_blast_radius(ACCT, BUCKET)
    assert r["reaches"] == [] and r["counts"]["crowns"] == 0
    assert r["internet_reachable"] is True                    # internet->ec2->...->bucket reverse-reaches it
    reached = {row["id"] for row in r["reached_by"]}
    assert "internet" in reached and EC2 in reached


def test_unknown_node_exists_false():
    r = _svc(_graph()).get_blast_radius(ACCT, "arn:aws:ec2:us-east-1:111122223333:instance/nope")
    assert r["exists"] is False and r["reaches"] == [] and r["reached_by"] == []
    assert r["internet_reachable"] is False


def test_no_scan_returns_none():
    assert _svc(graph=None).get_blast_radius(ACCT, EC2) is None


def test_max_hops_clamped():
    # service clamps to [1,12]; hops=1 from the host reaches only its 1-hop terminals
    r = _svc(_graph()).get_blast_radius(ACCT, EC2, max_hops=1)
    assert r["max_hops"] == 1
    terminals = {row["id"] for row in r["reaches"]}
    assert BUCKET in terminals and ADMIN not in terminals     # admin is 2 hops away


# ── API route ─────────────────────────────────────────────────────────────────
_HAVE_FASTAPI = None
try:
    import cnapp_api
    _HAVE_FASTAPI = cnapp_api._HAVE_FASTAPI
except Exception:
    _HAVE_FASTAPI = False

api = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi not installed (deploy-time dep)")


def _client(svc, role="viewer"):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc, current_role=lambda: role))


@api
def test_route_returns_blast_radius():
    body = _client(_svc(_graph())).get(
        f"/accounts/{ACCT}/graph/blast-radius?node={EC2}").json()
    assert body["exists"] is True
    assert {r["terminal"] for r in body["reaches"]} == {"data", "admin"}
    assert body["internet_reachable"] is True


@api
def test_route_requires_node_param():
    r = _client(_svc(_graph())).get(f"/accounts/{ACCT}/graph/blast-radius")
    assert r.status_code == 422                               # node is required (min_length=1)


@api
def test_route_rejects_out_of_range_hops():
    r = _client(_svc(_graph())).get(
        f"/accounts/{ACCT}/graph/blast-radius?node={EC2}&max_hops=99")
    assert r.status_code == 422                               # le=12


@api
def test_route_404_when_no_scan():
    r = _client(_svc(graph=None)).get(f"/accounts/{ACCT}/graph/blast-radius?node={EC2}")
    assert r.status_code == 404


@api
def test_route_unknown_node_is_200_exists_false():
    r = _client(_svc(_graph())).get(f"/accounts/{ACCT}/graph/blast-radius?node=ghost")
    assert r.status_code == 200 and r.json()["exists"] is False
