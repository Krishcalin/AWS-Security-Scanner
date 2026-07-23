"""B1 — SecurityGraph.from_dict: exact inverse of to_dict.

The hosted plane rebuilds a graph from stored ``graph_full`` before emitting
ingested HAS_VULN edges and re-running reachability, so from_dict must be
loss-safe (reserved keys, nested props, bool/float fidelity) and MERGE-idempotent.
Pure/offline — no boto, no service."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_graph import SecurityGraph
import aws_graph_neptune as gn


def _rich_graph():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource", cidr="0.0.0.0/0")
    g.add_node("arn:i-1", "EC2Instance", instance_id="i-1", crown_jewel=False)
    g.add_node("arn:bucket", "S3Bucket", crown_jewel=True, tags={"env": "prod"})
    g.add_node("CVE-2021-44228", "Vulnerability", severity="CRITICAL",
               epss=0.975, kev=True, exploit_available="YES")
    g.add_node("cap:admin", "AdminCapability", account="111122223333")
    g.add_edge("internet", "arn:i-1", "EXPOSED_TO", port=443)
    g.add_edge("arn:i-1", "CVE-2021-44228", "HAS_VULN", cve="CVE-2021-44228",
               severity="CRITICAL", epss=0.975, kev=True,
               exploit_available="YES", scan_source="side-scan")
    g.add_edge("arn:i-1", "cap:admin", "CAN_PRIVESC_TO", conditioned=False,
               rules=["IAMPE-01", "IAMPE-10"])
    g.add_edge("arn:i-1", "arn:bucket", "CAN_READ_DATA")
    return g


def test_round_trip_byte_stable():
    g = _rich_graph()
    d = g.to_dict()
    assert SecurityGraph.from_dict(d).to_dict() == d


def test_round_trip_thrice_idempotent():
    """to_dict∘from_dict∘to_dict∘from_dict is a fixed point."""
    d0 = _rich_graph().to_dict()
    d1 = SecurityGraph.from_dict(d0).to_dict()
    d2 = SecurityGraph.from_dict(d1).to_dict()
    assert d0 == d1 == d2


def test_preserves_bool_float_and_nested():
    g2 = SecurityGraph.from_dict(_rich_graph().to_dict())
    vp = g2.node("CVE-2021-44228")["props"]
    assert vp["kev"] is True and isinstance(vp["epss"], float) and vp["epss"] == 0.975
    bp = g2.node("arn:bucket")["props"]
    assert bp["crown_jewel"] is True and bp["tags"] == {"env": "prod"}


def test_reserved_keys_not_leaked_into_props():
    """id/kind (nodes) and source/target/kind (edges) must NOT survive as props."""
    g2 = SecurityGraph.from_dict(_rich_graph().to_dict())
    for n in g2.nodes():
        assert "id" not in n["props"] and "kind" not in n["props"]
    for e in g2.edges():
        for reserved in ("source", "target", "src", "dst"):
            assert reserved not in e["props"]


def test_edge_endpoints_and_kind_rebuilt():
    g2 = SecurityGraph.from_dict(_rich_graph().to_dict())
    hv = g2.out_edges("arn:i-1", ["HAS_VULN"])
    assert len(hv) == 1
    e = hv[0]
    assert e["src"] == "arn:i-1" and e["dst"] == "CVE-2021-44228"
    assert e["kind"] == "HAS_VULN" and e["props"]["scan_source"] == "side-scan"


def test_reload_merges_not_duplicates():
    """Loading the same dict into an existing graph MERGEs (no dup nodes/edges)."""
    d = _rich_graph().to_dict()
    g = SecurityGraph.from_dict(d)
    # re-apply on top of itself
    for n in d["nodes"]:
        props = {k: v for k, v in n.items() if k not in ("id", "kind")}
        g.add_node(n["id"], n["kind"], **props)
    for e in d["edges"]:
        props = {k: v for k, v in e.items() if k not in ("source", "target", "kind")}
        g.add_edge(e["source"], e["target"], e["kind"], **props)
    assert g.to_dict() == d


def test_reachable_survives_round_trip():
    g2 = SecurityGraph.from_dict(_rich_graph().to_dict())
    reach = g2.reachable("internet", None, max_hops=4)
    assert "arn:i-1" in reach and "arn:bucket" in reach


def test_tolerates_missing_and_empty():
    assert SecurityGraph.from_dict({}).to_dict() == {
        "directed": True, "multigraph": False, "nodes": [], "edges": []}
    # a node row with no id is skipped (add_node returns None on falsy id)
    g = SecurityGraph.from_dict({"nodes": [{"kind": "Ghost"}], "edges": []})
    assert len(g) == 0


def test_load_graph_delegates_to_from_dict():
    d = _rich_graph().to_dict()
    assert gn.load_graph(d).to_dict() == SecurityGraph.from_dict(d).to_dict()
