"""aws_policy — the pure policy-as-code engine. Covers parse() rejection (the config boundary),
the finding-catalog predicate (compliance-as-code: framework+control, check_id glob, severity
gte/lte, status, section), the graph clause (reuses aws_wql), the cross-domain any|all combine,
the POLICY-xx WARN finding shape (always display-only), and that a non-firing policy yields None.
Pure/offline."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_policy
from aws_graph import SecurityGraph

CATALOG = [
    {"check_id": "S3-01", "section": "S3", "severity": "HIGH", "status": "FAIL",
     "compliance": {"PCI-DSS": "3.4", "CIS": "2.1"}},
    {"check_id": "IAM-05", "section": "IAM", "severity": "MEDIUM", "status": "PASS",
     "compliance": {"PCI-DSS": "7.1"}},
    {"check_id": "S3-02", "section": "S3", "severity": "LOW", "status": "FAIL", "compliance": {}},
]


def _graph():
    g = SecurityGraph()
    g.add_node("b", "S3Bucket", name="crown", crown_jewel=True, public=True)
    return g


def _ids(matched):
    return [n["id"] for n in matched["nodes"]] + [f["check_id"] for f in matched["findings"]]


# ── parse rejection (config boundary) ─────────────────────────────────────────
@pytest.mark.parametrize("bad", [
    {"id": "x"},                                              # no match
    {"id": "x", "match": {}},                                # empty match (no clause)
    {"match": {"finding": {"status": "FAIL"}}},              # no id
    {"id": "x", "match": {"op": "xor", "finding": {"status": "FAIL"}}},  # bad op
    {"id": "x", "match": {"finding": {"bogus": 1}}},         # unknown finding field
    {"id": "x", "match": {"finding": {}}},                   # empty finding pred
    {"id": "x", "match": {"finding": {"severity": "SPICY"}}},  # bad severity
    {"id": "x", "match": {"finding": {"severity": "HIGH", "severity_op": "regex"}}},  # bad op
    {"id": "x", "match": {"finding": {"compliance_control": "3.4"}}},   # control without framework
    {"id": "x", "match": {"graph": {"select": "edge"}}},     # bad WQL query
    {"id": "x", "match": {"unknown_key": 1}},                # unknown match key
])
def test_parse_rejects(bad):
    with pytest.raises(aws_policy.PolicyError):
        aws_policy.parse(bad)


def test_parse_accepts_valid():
    assert aws_policy.parse({"id": "p", "match": {"finding": {"status": "FAIL"}}})


# ── finding predicate (compliance-as-code) ────────────────────────────────────
def test_compliance_framework_and_control():
    p = {"id": "pci34", "match": {"finding": {"compliance_framework": "PCI-DSS",
                                              "compliance_control": "3.4", "status": "FAIL"}}}
    m = aws_policy.evaluate(aws_policy.parse(p), None, CATALOG)
    assert _ids(m) == ["S3-01"]


def test_compliance_framework_case_insensitive():
    p = {"id": "pci", "match": {"finding": {"compliance_framework": "pci-dss", "status": "FAIL"}}}
    m = aws_policy.evaluate(aws_policy.parse(p), None, CATALOG)
    assert _ids(m) == ["S3-01"]                              # IAM-05 is PASS, S3-02 has no PCI


def test_check_id_glob_and_severity_gte():
    p = {"id": "s3hi", "match": {"finding": {"check_id_glob": "S3-*", "severity": "MEDIUM", "severity_op": "gte"}}}
    m = aws_policy.evaluate(aws_policy.parse(p), None, CATALOG)
    assert _ids(m) == ["S3-01"]                              # S3-02 is LOW (< MEDIUM)


def test_status_and_section():
    p = {"id": "s3fail", "match": {"finding": {"section": "S3", "status": "FAIL"}}}
    m = aws_policy.evaluate(aws_policy.parse(p), None, CATALOG)
    assert sorted(_ids(m)) == ["S3-01", "S3-02"]


# ── graph clause + cross-domain ───────────────────────────────────────────────
def test_graph_clause_reuses_wql():
    p = {"id": "pubcrown", "match": {"graph": {"kind": "S3Bucket", "where": {"op": "and", "of": [
        {"pred": "crown_jewel"}, {"pred": "has_prop", "field": "public", "value": True}]}}}}
    m = aws_policy.evaluate(aws_policy.parse(p), _graph(), CATALOG)
    assert _ids(m) == ["b"]


def test_cross_domain_all_needs_both():
    p = {"id": "combo", "match": {"op": "all",
                                  "graph": {"kind": "S3Bucket", "where": {"pred": "crown_jewel"}},
                                  "finding": {"compliance_framework": "PCI-DSS", "status": "FAIL"}}}
    assert sorted(_ids(aws_policy.evaluate(aws_policy.parse(p), _graph(), CATALOG))) == ["S3-01", "b"]
    # 'all' with no failing PCI finding -> does not fire
    clean = [dict(f, status="PASS") for f in CATALOG]
    assert aws_policy.evaluate(aws_policy.parse(p), _graph(), clean) is None


def test_cross_domain_any_fires_on_either():
    p = {"id": "either", "match": {"op": "any",
                                   "graph": {"kind": "DynamoDBTable"},   # no match
                                   "finding": {"status": "FAIL"}}}       # matches
    m = aws_policy.evaluate(aws_policy.parse(p), _graph(), CATALOG)
    assert sorted(_ids(m)) == ["S3-01", "S3-02"]


def test_non_firing_returns_none():
    p = {"id": "none", "match": {"finding": {"check_id_glob": "NOPE-*"}}}
    assert aws_policy.evaluate(aws_policy.parse(p), None, CATALOG) is None


def test_finding_only_policy_needs_no_graph():
    p = {"id": "f", "match": {"finding": {"status": "FAIL"}}}
    assert not aws_policy.needs_graph(p)
    assert aws_policy.evaluate(aws_policy.parse(p), None, CATALOG) is not None   # graph=None ok


# ── POLICY-xx finding shape ────────────────────────────────────────────────────
def test_policy_finding_is_warn_display_only():
    p = {"id": "pci34", "name": "PCI 3.4", "severity": "CRITICAL",
         "compliance": {"PCI-DSS": "3.4"}, "match": {"finding": {"compliance_framework": "PCI-DSS", "status": "FAIL"}}}
    m = aws_policy.evaluate(aws_policy.parse(p), None, CATALOG)
    f = aws_policy.policy_finding(p, "111122223333", m)
    assert f["check_id"] == "POLICY-pci34" and f["status"] == "WARN" and f["severity"] == "CRITICAL"
    assert f["section"] == "Policy" and f["affected"] == ["finding:S3-01"]
    assert f["compliance"] == {"PCI-DSS": "3.4"} and f["account"] == "111122223333"


def test_policy_meta():
    p = {"id": "p1", "name": "P One", "pack": "cis-pack", "match": {"finding": {"status": "FAIL"}}}
    meta = aws_policy.policy_meta(p)
    assert meta["id"] == "p1" and meta["pack"] == "cis-pack" and meta["section"] == "Policy"


# ── adversarial-verify regressions (Batch 5) ────────────────────────────────────
@pytest.mark.parametrize("bad_match", ["finding", ["finding"], 5, True, None])
def test_needs_graph_is_defensive_on_non_dict_match(bad_match):
    # a malformed policy must not crash the needs_graph pre-pass (it reaches parse() and is inert)
    assert aws_policy.needs_graph({"id": "x", "match": bad_match}) is False


def test_empty_check_id_glob_matches_all():
    # an empty check_id_glob means "*" (aws_state._glob), matching every finding
    p = {"id": "eg", "match": {"finding": {"check_id_glob": ""}}}
    m = aws_policy.evaluate(aws_policy.parse(p), None, CATALOG)
    assert sorted(_ids(m)) == ["IAM-05", "S3-01", "S3-02"]
