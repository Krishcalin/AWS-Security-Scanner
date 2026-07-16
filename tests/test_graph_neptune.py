"""Unit tests for aws_graph_neptune — pure Neptune export (Gremlin CSV +
openCypher MERGE) and the round-trip loader. Type fidelity (bool-not-int),
escaping, list scalarization, determinism, and round-trip identity."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_graph_neptune as gn
from aws_graph import SecurityGraph


def _sample_graph():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource", cidr="0.0.0.0/0")
    g.add_node("arn:i-1", "EC2Instance", instance_id="i-1")
    g.add_node("CVE-2024-0001", "Vulnerability", severity="CRITICAL", epss=0.94,
               kev=True, exploit_available="YES", fix_available="YES")
    g.add_node("cap:admin", "AdminCapability", account="111")
    g.add_edge("internet", "arn:i-1", "EXPOSED_TO", port=22)
    g.add_edge("arn:i-1", "CVE-2024-0001", "HAS_VULN", cve="CVE-2024-0001",
               severity="CRITICAL", epss=0.94, kev=True, exploit_available="YES",
               fix_available="YES", scan_source="side-scan")
    g.add_edge("arn:i-1", "cap:admin", "CAN_PRIVESC_TO", conditioned=False,
               rules=["IAMPE-01", "IAMPE-10"])
    return g


# ── type inference (the #1 exporter bug) ─────────────────────────────────────
def test_neptune_type_bool_before_int():
    assert gn.neptune_type(True) == "Bool"
    assert gn.neptune_type(False) == "Bool"
    assert gn.neptune_type(5) == "Int"
    assert gn.neptune_type(2**40) == "Long"
    assert gn.neptune_type(0.5) == "Double"
    assert gn.neptune_type("YES") == "String"


def test_fmt_scalar_bool():
    assert gn.fmt_scalar(True) == "true" and gn.fmt_scalar(False) == "false"
    assert gn.fmt_scalar(0.5) == "0.5"


def test_csv_field_escaping():
    assert gn.csv_field("plain") == "plain"
    assert gn.csv_field("a,b") == '"a,b"'
    assert gn.csv_field('quote"here') == '"quote""here"'


def test_edge_id_deterministic():
    a = gn.edge_id("s", "K", "d")
    assert a == gn.edge_id("s", "K", "d") and a.startswith("e:")
    assert a != gn.edge_id("s", "K", "d2")


# ── Gremlin CSV ──────────────────────────────────────────────────────────────
def test_gremlin_csv_vertex_headers_and_types():
    b = gn.to_gremlin_csv(_sample_graph())
    vuln = b.vertex_files["Vulnerability"]
    header = vuln.splitlines()[0]
    # kev must be Bool (not Int), epss Double, severity String
    assert "kev:Bool" in header
    assert "epss:Double" in header
    assert "severity:String" in header
    assert header.startswith("~id,~label,")


def test_gremlin_csv_edge_header_and_row():
    b = gn.to_gremlin_csv(_sample_graph())
    hv = b.edge_files["HAS_VULN"]
    header, row = hv.splitlines()[0], hv.splitlines()[1]
    assert header.startswith("~id,~from,~to,~label,")
    assert "kev:Bool" in header
    assert "arn:i-1" in row and "CVE-2024-0001" in row and "true" in row


def test_gremlin_csv_rules_scalarized():
    b = gn.to_gremlin_csv(_sample_graph())
    priv = b.edge_files["CAN_PRIVESC_TO"]
    header = priv.splitlines()[0]
    assert "rules:String" in header          # list -> String, never an array on an edge
    assert "IAMPE-01;IAMPE-10" in priv


def test_gremlin_csv_deterministic():
    g = _sample_graph()
    assert gn.to_gremlin_csv(g).vertex_files == gn.to_gremlin_csv(g).vertex_files


def test_gremlin_csv_manifest():
    b = gn.to_gremlin_csv(_sample_graph())
    assert b.manifest["node_count"] == 4 and b.manifest["edge_count"] == 3
    assert "Vulnerability" in b.manifest["node_labels"]


# ── openCypher ───────────────────────────────────────────────────────────────
def test_opencypher_node_and_edge_queries():
    plan = gn.to_opencypher_upsert(_sample_graph())
    qs = [q for q, _ in plan]
    assert any("MERGE (n {`~id`: row.id}) SET n:`Vulnerability`" in q for q in qs)
    assert any("MERGE (s)-[r:`HAS_VULN`]->(d)" in q for q in qs)
    # params carry native types
    node_batch = next(p for q, p in plan if "Vulnerability" in q)
    props = node_batch["rows"][0]["props"]
    assert props["kev"] is True and isinstance(props["epss"], float)


def test_opencypher_rules_scalarized():
    plan = gn.to_opencypher_upsert(_sample_graph())
    edge_batch = next(p for q, p in plan if "CAN_PRIVESC_TO" in q)
    assert edge_batch["rows"][0]["props"]["rules"] == "IAMPE-01;IAMPE-10"


def test_opencypher_batching():
    g = SecurityGraph()
    for i in range(450):
        g.add_node(f"n{i:03d}", "Thing", v=i)
    plan = gn.to_opencypher_upsert(g, batch=200)
    thing_batches = [p for q, p in plan if "Thing" in q]
    assert len(thing_batches) == 3            # 450 -> 200+200+50
    assert sum(len(p["rows"]) for p in thing_batches) == 450


# ── round-trip fidelity ──────────────────────────────────────────────────────
def test_load_graph_round_trip():
    g = _sample_graph()
    d = g.to_dict()
    assert gn.load_graph(d).to_dict() == d


def test_round_trip_preserves_bool_and_float():
    g = _sample_graph()
    g2 = gn.load_graph(g.to_dict())
    v = g2.node("CVE-2024-0001")["props"]
    assert v["kev"] is True and v["epss"] == 0.94
