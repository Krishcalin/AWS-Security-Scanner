"""Phase 5 · slice 5.4 — the scanner surface for segmentation recommendations.

Also home to a general guard discovered here the hard way. This slice was first written
as `SEG-01`, which is an EXISTING check (world-open sensitive port on a security group).
Python dict literals accept duplicate keys silently and the last one wins, so the new
remediation string quietly replaced the real check's remediation and nothing failed. The
`test_no_NEW_check_map_duplicate_key_appears` ratchet below parses the maps as source
and would have caught it on the first run.
"""
from __future__ import annotations

import ast
import io
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_correlate
from engine import aws_graph
from engine import aws_live_scanner as A
from engine import aws_segmentation as S

from _layout import module_path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Path:
    def __init__(self, entry, terminal, edges, score=50, nodes=(), severity="HIGH"):
        self.entry, self.terminal, self.edges, self.score = entry, terminal, edges, score
        self.nodes, self.severity = nodes, severity


def _scanner():
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["CORRELATE"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: MagicMock()
    return s


def _graph():
    g = aws_graph.SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("eni-1", "NetworkInterface", subnet_id="subnet-a", vpc_id="vpc-9",
               sg_ids=["sg-abc"])
    g.add_node("s3:crown", "S3Bucket")
    g.add_edge("internet", "eni-1", "EXPOSED_TO", ports="tcp/22", family="ipv4")
    g.add_edge("eni-1", "s3:crown", "CAN_READ_DATA")
    return g


def _paths():
    net = ("internet", "eni-1", "EXPOSED_TO")
    read = ("eni-1", "s3:crown", "CAN_READ_DATA")
    return [
        Path("internet", "s3:crown", [net, read], score=90),
        Path("internet", "rds:db", [net, ("eni-1", "rds:db", "CAN_READ_DATA")], score=70),
        Path("role:a", "s3:crown", [("role:a", "role:b", "CAN_ASSUME"),
                                    ("role:b", "s3:crown", "CAN_READ_DATA")], score=60),
    ]


def _run(paths=None, graph=None):
    s = _scanner()
    s._recommend_segmentation(paths if paths is not None else _paths(),
                              graph if graph is not None else _graph())
    return s


def _ids(s, cid):
    return [r for r in s.results if r.check_id == cid]


# ── the emitted findings ────────────────────────────────────────────────────
def test_a_recommendation_is_emitted_for_the_best_cut():
    s = _run()
    assert _ids(s, "SEGREC-01")


def test_the_recommendation_names_the_security_group_from_the_graph():
    """sg_ids was added to the ENI node for this slice: advice that cannot name the
    security group to change is advice an operator cannot act on."""
    s = _run()
    assert "sg-abc" in _ids(s, "SEGREC-01")[0].message


def test_the_recommendation_names_the_ports_from_the_edge():
    s = _run()
    assert "tcp/22" in _ids(s, "SEGREC-01")[0].message


def test_the_summary_is_emitted_once():
    s = _run()
    assert len(_ids(s, "SEGREC-00")) == 1


def test_the_summary_counts_the_identity_only_path_separately():
    """The number a naive version drops. One of the three paths reaches the crown jewel
    without crossing a network hop, so no segmentation change touches it."""
    msg = _ids(_run(), "SEGREC-00")[0].message
    assert "2 of 3" in msg and "identity relationships" in msg


def test_recommendations_are_informational_not_failures():
    """The underlying exposure is already reported by EXPOSURE-01/02 and the paths by
    PATHS-01; emitting advice as a failure would double-count and inflate the total."""
    s = _run()
    assert all(r.status == "INFO" for r in s.results if r.check_id.startswith("SEGREC"))


def test_no_paths_emits_nothing():
    assert not [r for r in _run(paths=[]).results if r.check_id.startswith("SEGREC")]


def test_an_all_identity_estate_emits_no_recommendation():
    paths = [Path("role:a", "s3:b", [("role:a", "role:b", "CAN_ASSUME")])]
    s = _run(paths=paths)
    assert not _ids(s, "SEGREC-01")
    assert _ids(s, "SEGREC-00")        # the summary still says why


def test_a_missing_graph_node_degrades_rather_than_crashing():
    """Never invent a security group that was not in the graph."""
    g = aws_graph.SecurityGraph()
    g.add_node("internet", "InternetSource")
    s = _run(graph=g)
    assert "sg-" not in _ids(s, "SEGREC-01")[0].message


def test_no_emitted_line_predicts_what_a_cut_will_do():
    blob = " ".join(r.message for r in _run().results).lower()
    for verb in ("will block", "will prevent", "will stop"):
        assert verb not in blob


def test_the_emitted_line_scopes_itself_to_this_graph():
    assert "in this graph" in _ids(_run(), "SEGREC-01")[0].message


# ── the check-id collision that started this ────────────────────────────────
def test_segrec_does_not_collide_with_the_existing_seg_checks():
    """SEG-01 is a real, different check: a world-open sensitive port on a security
    group. It must keep its own severity, mapping and remediation."""
    assert A.CHECK_SEVERITY["SEG-01"] == "MEDIUM"
    assert A.CHECK_SEVERITY["SEGREC-01"] == "INFO"
    assert A.REMEDIATION_MAP["SEG-01"].startswith("Restrict the security group")
    assert A.COMPLIANCE_MAP["SEG-01"]["CIS"] == "5.2"


def _dup_map(filename, targets):
    """{map name: [check ids declared more than once in that one dict literal]}."""
    src = io.open(module_path(filename), encoding="utf-8").read()
    out = {}
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Dict):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if (targets and not any(n in targets for n in names)) or not names:
            continue
        seen, dups = set(), set()
        for k in node.value.keys:
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                if k.value in seen:
                    dups.add(k.value)
                seen.add(k.value)
        if dups:
            out.setdefault(names[0], set()).update(dups)
    return {k: sorted(v) for k, v in out.items()}


#: Frozen baseline for the duplicate-key ratchet below. Every entry here is a
#: check id declared twice inside ONE dict literal. Most are redundant repeats
#: with an identical value; SM-02/SM-04 are a DELIBERATE, CHANGELOG-documented
#: severity override that uses last-wins shadowing on purpose. The point of the
#: ratchet is not to clean these up -- it is that a NEW one can never appear
#: silently, which is exactly how this slice briefly replaced the real SEG-01.
_KNOWN_DUPLICATE_CHECK_IDS = {
    "aws_finding_detail.py": {
    },
    "aws_live_scanner.py": {
        "CHECK_SEVERITY": ['ACM-03', 'AGW2-03', 'APIGW-04', 'BCK-01', 'CNT-01', 'COG-04', 'DDB-03', 'DDB-04', 'ECS-04', 'ECS-05', 'EKS-04', 'EKS-05', 'ELB-04', 'ELC-04', 'GLC-01', 'GLC-02', 'GLC-03', 'LMB-05', 'OSR-03', 'R53-01', 'R53-02', 'R53-03', 'R53-04', 'R53-05', 'RS-05', 'SEC-03', 'SEC-04', 'SFN-01', 'SFN-02', 'SFN-03', 'SM-02', 'SM-04', 'SNS-01', 'SNS-02', 'SNS-03', 'SNS-04', 'SQS-01', 'SQS-02', 'SQS-03', 'SQS-04', 'WAF-03', 'WAF-04'],
        "REMEDIATION_MAP": ['DDB-04'],
    },
}


@pytest.mark.parametrize("filename,targets", [
    ("aws_live_scanner.py", ("CHECK_SEVERITY", "COMPLIANCE_MAP", "REMEDIATION_MAP")),
    ("aws_finding_detail.py", None),
])
def test_no_NEW_check_map_duplicate_key_appears(filename, targets):
    """The general guard, as a ratchet. Python dict literals accept duplicate keys
    silently and the LAST one wins, so re-using a check id in one of these maps
    overwrites the original with no error anywhere -- which is exactly how this slice
    briefly replaced the real SEG-01's remediation with its own, and nothing failed.

    The pre-existing duplicates are frozen above rather than cleaned up: 40 of them are
    harmless repeats of an identical value, and SM-02/SM-04 is a deliberate documented
    severity override. Reverting someone else's intentional decision is not this slice's
    business -- catching the NEXT accidental collision is."""
    found = _dup_map(filename, targets)
    baseline = _KNOWN_DUPLICATE_CHECK_IDS.get(filename, {})
    new = {}
    for mapname, ids in found.items():
        extra = sorted(set(ids) - set(baseline.get(mapname, ())))
        if extra:
            new[mapname] = extra
    assert not new, (
        f"NEW duplicate check id(s) in {filename}: {new}. A check id declared twice in "
        f"one dict literal silently overwrites the earlier entry -- pick a free id.")


# ── the edge classification is not allowed to drift ─────────────────────────
def test_the_cuttable_edges_still_partition_the_traversable_ones():
    """If a new traversable edge kind is added to E_PATH and not classified here, it is
    silently neither cuttable nor identity-only, and the summary's denominator quietly
    stops adding up."""
    assert S.NETWORK_EDGE_KINDS | S.IDENTITY_EDGE_KINDS == set(aws_correlate.E_PATH)
