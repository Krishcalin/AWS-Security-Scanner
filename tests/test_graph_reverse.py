"""Blast-radius B1 — SecurityGraph.reverse_reachable: the reverse (predecessor) walk
that powers "what can reach node X". The mirror of reachable(); it must NOT mutate the
stored structure (no persistent _in index), so the to_dict/from_dict round-trip stays
byte-stable. Pure/offline — no boto, no service."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_graph import SecurityGraph


def _chain():
    # internet -> ec2 -> role -> admin ; ec2 -> bucket(crown). A branch: bastion -> ec2.
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("ec2", "EC2Instance")
    g.add_node("bastion", "EC2Instance")
    g.add_node("role", "IAMRole")
    g.add_node("admin", "AdminCapability")
    g.add_node("bucket", "S3Bucket", crown_jewel=True)
    g.add_node("island", "S3Bucket")                  # unconnected
    g.add_edge("internet", "ec2", "EXPOSED_TO")
    g.add_edge("bastion", "ec2", "CAN_ASSUME")
    g.add_edge("ec2", "role", "HAS_ROLE")
    g.add_edge("role", "admin", "CAN_PRIVESC_TO")
    g.add_edge("ec2", "bucket", "CAN_READ_DATA")
    return g


def test_reverse_finds_all_predecessors():
    g = _chain()
    rev = g.reverse_reachable("admin", None, max_hops=8)
    assert set(rev) == {"role", "ec2", "internet", "bastion"}   # everything that reaches admin
    assert "island" not in rev and "bucket" not in rev          # not predecessors of admin


def test_reverse_path_is_source_to_start_inclusive():
    g = _chain()
    rev = g.reverse_reachable("admin", None, max_hops=8)
    # path is ordered SOURCE .. start, with start (admin) at the tail
    assert rev["internet"] == ["internet", "ec2", "role", "admin"]
    assert rev["role"] == ["role", "admin"]


def test_reverse_excludes_start_as_a_key():
    g = _chain()
    assert "admin" not in g.reverse_reachable("admin", None, max_hops=8)


def test_reverse_honors_edge_kinds():
    g = _chain()
    # over CAN_PRIVESC_TO only, admin's sole predecessor is role (the ec2->role hop is HAS_ROLE)
    rev = g.reverse_reachable("admin", {"CAN_PRIVESC_TO"}, max_hops=8)
    assert set(rev) == {"role"}


def test_reverse_respects_max_hops():
    g = _chain()
    one = g.reverse_reachable("admin", None, max_hops=1)
    assert set(one) == {"role"}                                  # only the immediate predecessor


def test_reverse_edge_filter_skips_conditioned():
    g = SecurityGraph()
    g.add_node("a", "X"); g.add_node("b", "X"); g.add_node("c", "X")
    g.add_edge("a", "b", "CAN_ASSUME", conditioned=True)
    g.add_edge("b", "c", "CAN_ASSUME", conditioned=False)
    uncond = lambda e: not e["props"].get("conditioned")
    rev = g.reverse_reachable("c", {"CAN_ASSUME"}, max_hops=8, edge_filter=uncond)
    assert set(rev) == {"b"}                                     # a->b is conditioned, skipped


def test_reverse_cycle_safe():
    g = SecurityGraph()
    g.add_node("a", "X"); g.add_node("b", "X")
    g.add_edge("a", "b", "CAN_ASSUME")
    g.add_edge("b", "a", "CAN_ASSUME")                           # cycle
    rev = g.reverse_reachable("a", None, max_hops=8)
    assert set(rev) == {"b"}                                     # terminates, no infinite loop


def test_reverse_does_not_mutate_serialization():
    # THE invariant: building reverse adjacency on-demand must leave to_dict byte-identical.
    g = _chain()
    before = g.to_dict()
    g.reverse_reachable("admin", None, max_hops=8)
    assert g.to_dict() == before
    assert SecurityGraph.from_dict(before).to_dict() == before


def test_reverse_and_forward_are_mirror():
    g = _chain()
    # if X is reverse-reachable from Y, then Y is forward-reachable from X (same edge set)
    fwd = g.reachable("internet", None, max_hops=8)
    rev = g.reverse_reachable("admin", None, max_hops=8)
    assert "admin" in fwd and "internet" in rev


def test_reverse_unknown_node_is_empty():
    assert _chain().reverse_reachable("no-such-node", None) == {}
