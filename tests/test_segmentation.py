"""Phase 5 · slice 5.4 — segmentation derived from attack paths.

OverWatch already ranks choke points. The trouble with a choke point is that you usually
cannot delete it — it is a production role or an instance that serves traffic. This slice
asks the adjacent question that converts into action: which network boundary would you
cut, and what actually dies if you cut it?

Three properties are defended here.

**Only network edges are cuttable.** No firewall rule severs an IAM trust policy. A path
made only of identity edges is a permissions problem wearing a path's clothes.

**Verify the cut; do not assert it.** Counting the paths an edge appears in over-claims
whenever a parallel route exists. A path is severed only when nothing else reaches the
same (entry, terminal) pair.

**The identity-only paths stay in the denominator.** "Cutting X severs 8 of 10" while the
other two are permanently untouchable by segmentation is true and misleading.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_correlate
from engine import aws_segmentation as S


class Path:
    """Minimal stand-in for aws_correlate.AttackPath (the module reads by attribute)."""

    def __init__(self, entry, terminal, edges, score=50):
        self.entry, self.terminal, self.edges, self.score = entry, terminal, edges, score


def net(src, dst):
    return (src, dst, "EXPOSED_TO")


def ident(src, dst):
    return (src, dst, "CAN_ASSUME")


# ── what is cuttable ────────────────────────────────────────────────────────
def test_the_network_kinds_are_the_two_that_are_actually_network():
    assert S.NETWORK_EDGE_KINDS == {"EXPOSED_TO", "TARGETS"}


def test_every_network_kind_is_a_real_traversable_edge():
    """A cut on an edge the path engine never traverses would sever nothing."""
    assert S.NETWORK_EDGE_KINDS <= aws_correlate.E_PATH


def test_network_and_identity_kinds_are_disjoint_and_cover_the_path_edges():
    assert not (S.NETWORK_EDGE_KINDS & S.IDENTITY_EDGE_KINDS)
    assert S.NETWORK_EDGE_KINDS | S.IDENTITY_EDGE_KINDS == set(aws_correlate.E_PATH)


def test_an_identity_only_path_is_not_segmentable():
    """No firewall rule severs an IAM trust policy."""
    p = Path("role:a", "s3:bucket", [ident("role:a", "role:b"),
                                     ("role:b", "s3:bucket", "CAN_READ_DATA")])
    assert S.is_segmentable(p) is False
    assert S.network_hops(p) == []


def test_a_path_with_a_network_hop_is_segmentable():
    p = Path("internet", "s3:b", [net("internet", "eni-1"),
                                  ("eni-1", "s3:b", "CAN_READ_DATA")])
    assert S.is_segmentable(p) is True


def test_hops_come_back_in_traversal_order():
    p = Path("internet", "x", [net("internet", "eni-1"), ident("eni-1", "role:a"),
                               ("role:a", "x", "TARGETS")])
    assert [h[2] for h in S.network_hops(p)] == ["EXPOSED_TO", "TARGETS"]


# ── verifying the cut ───────────────────────────────────────────────────────
def test_a_cut_with_no_alternative_route_severs_the_path():
    p = Path("internet", "s3:b", [net("internet", "eni-1"),
                                  ("eni-1", "s3:b", "CAN_READ_DATA")])
    ev = S.evaluate_cut(net("internet", "eni-1"), [p])
    assert ev["severed"] == 1 and ev["over_claim"] == 0


def test_a_parallel_route_means_the_path_is_NOT_severed():
    """The load-bearing test. The naive count says 1 severed; the same terminal is still
    reachable through the other ENI, so nothing was severed at all."""
    a = Path("internet", "s3:b", [net("internet", "eni-1"),
                                  ("eni-1", "s3:b", "CAN_READ_DATA")])
    b = Path("internet", "s3:b", [net("internet", "eni-2"),
                                  ("eni-2", "s3:b", "CAN_READ_DATA")])
    ev = S.evaluate_cut(net("internet", "eni-1"), [a, b])
    assert ev["claimed"] == 1
    assert ev["severed"] == 0
    assert ev["still_reachable"] == 1


def test_the_over_claim_is_reported_rather_than_hidden():
    a = Path("internet", "s3:b", [net("internet", "eni-1")])
    b = Path("internet", "s3:b", [net("internet", "eni-2")])
    ev = S.evaluate_cut(net("internet", "eni-1"), [a, b])
    assert ev["over_claim"] == 1


def test_a_different_terminal_is_not_a_parallel_route():
    """Reaching a DIFFERENT crown jewel is not an alternative route to this one."""
    a = Path("internet", "s3:a", [net("internet", "eni-1")])
    b = Path("internet", "s3:b", [net("internet", "eni-2")])
    assert S.evaluate_cut(net("internet", "eni-1"), [a, b])["severed"] == 1


def test_severing_is_weighted_by_path_score():
    a = Path("internet", "s3:a", [net("internet", "eni-1")], score=90)
    ev = S.evaluate_cut(net("internet", "eni-1"), [a])
    assert ev["weighted"] == 90.0


# ── ranking ─────────────────────────────────────────────────────────────────
def _estate():
    return [
        Path("internet", "s3:crown", [net("internet", "eni-1"),
                                      ("eni-1", "s3:crown", "CAN_READ_DATA")], score=90),
        Path("internet", "rds:db", [net("internet", "eni-1"),
                                    ("eni-1", "rds:db", "CAN_READ_DATA")], score=70),
        Path("internet", "s3:minor", [net("internet", "eni-2"),
                                      ("eni-2", "s3:minor", "CAN_READ_DATA")], score=20),
        Path("role:a", "s3:crown", [ident("role:a", "role:b"),
                                    ("role:b", "s3:crown", "CAN_READ_DATA")], score=60),
    ]


def test_the_highest_value_cut_ranks_first():
    recs = S.recommend(_estate())
    assert recs[0]["dst"] == "eni-1"
    assert recs[0]["severed"] == 2


def test_a_cut_that_severs_nothing_is_not_offered_as_advice():
    a = Path("internet", "s3:b", [net("internet", "eni-1")])
    b = Path("internet", "s3:b", [net("internet", "eni-2")])
    assert S.recommend([a, b]) == []


def test_the_recommendation_names_the_security_groups_when_known():
    nodes = {"eni-1": {"sg_ids": ["sg-abc", "sg-def"], "subnet_id": "subnet-1",
                       "vpc_id": "vpc-9"}}
    recs = S.recommend(_estate(), nodes=nodes)
    assert "sg-abc" in recs[0]["statement"] and "subnet-1" in recs[0]["statement"]


def test_nothing_is_invented_when_the_node_facts_are_missing():
    """A cut is named only as concretely as the evidence allows."""
    recs = S.recommend(_estate(), nodes={})
    assert recs[0]["sg_ids"] == () and "security group" not in recs[0]["statement"]


def test_the_ports_come_from_the_edge_when_present():
    props = {net("internet", "eni-1"): {"ports": "tcp/22", "family": "ipv4"}}
    recs = S.recommend(_estate(), edge_props=props)
    assert "tcp/22" in recs[0]["statement"]


def test_top_bounds_the_list():
    assert len(S.recommend(_estate(), top=1)) == 1


# ── the summary, and the number the naive version drops ─────────────────────
def test_identity_only_paths_are_counted_not_dropped():
    """"Cutting X severs 8 of 10" while the other two are permanently untouchable by
    segmentation is true and misleading."""
    s = S.summarize(_estate(), S.recommend(_estate()))
    assert s["paths"] == 4 and s["segmentable"] == 3 and s["identity_only"] == 1


def test_the_summary_says_identity_paths_need_a_permissions_change():
    s = S.summarize(_estate(), S.recommend(_estate()))
    assert "permissions change, not" in s["statement"]


def test_an_all_identity_estate_offers_no_segmentation_advice():
    paths = [Path("role:a", "s3:b", [ident("role:a", "role:b")])]
    recs = S.recommend(paths)
    s = S.summarize(paths, recs)
    assert recs == [] and s["segmentable"] == 0 and s["identity_only"] == 1


def test_no_paths_says_so_rather_than_recommending():
    assert S.summarize([], [])["statement"] == "no attack paths to segment"


# ── the honesty invariants ──────────────────────────────────────────────────
def _all_strings():
    recs = S.recommend(_estate(), nodes={"eni-1": {"sg_ids": ["sg-a"]}})
    out = [r["statement"] for r in recs]
    out.append(S.summarize(_estate(), recs)["statement"])
    out.append(S.SCOPE_NOTE)
    return " ".join(out).lower()


@pytest.mark.parametrize("verb", ["will block", "will prevent", "will stop",
                                  "guarantees", "eliminates"])
def test_no_output_predicts_what_a_cut_will_do(verb):
    """A recommendation is a recommendation. Nothing here applies a change."""
    assert verb not in _all_strings()


def test_the_output_says_it_is_scoped_to_this_graph():
    assert "in this graph" in _all_strings()


def test_the_scope_note_says_it_is_not_an_applied_change():
    assert "not an applied change" in S.SCOPE_NOTE


# ── robustness ──────────────────────────────────────────────────────────────
def test_paths_can_be_plain_dicts():
    p = {"entry": "internet", "terminal": "s3:b",
         "edges": [["internet", "eni-1", "EXPOSED_TO"]], "score": 30}
    assert S.evaluate_cut(net("internet", "eni-1"), [p])["severed"] == 1


@pytest.mark.parametrize("bad", [None, [], [None], "x", 7])
def test_nothing_raises_on_malformed_input(bad):
    seq = bad if isinstance(bad, list) else None
    S.cut_candidates(seq)
    S.evaluate_cut(("a", "b", "EXPOSED_TO"), seq)
    S.recommend(seq)
    S.summarize(seq, None)
    S.describe_cut(None)
    S.network_hops(bad if isinstance(bad, dict) else None)


def test_malformed_edges_are_skipped_rather_than_crashing():
    p = Path("internet", "x", [("only-two",), None, net("internet", "eni-1")])
    assert len(S.network_hops(p)) == 1


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(S), re.M)
