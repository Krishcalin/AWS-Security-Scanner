#!/usr/bin/env python3
"""gen_wql_parity.py — emit the SHARED cross-language WQL parity fixture.

WQL is compiled by BOTH aws_wql.py (the live hub) and frontend/src/lib/wql.ts (SAMPLE mode).
For SAMPLE==LIVE to hold, the two engines must return byte-identical rows. This script makes
the Python engine the ORACLE: it builds one canonical graph, runs a comprehensive query battery
through aws_wql.evaluate, and writes {graph, cases:[{name, query, expected}]} to
frontend/src/lib/__fixtures__/wql_parity.json. wql.test.ts replays every case through the TS
engine and asserts equality; tests/test_wql_parity.py asserts this committed file is still
current (so aws_wql.py can't drift from the fixture). Regenerate with:  python scripts/gen_wql_parity.py

`expected` is wrapped {count, nodes} — the shape cnapp_service.run_wql returns and wql.ts
evaluate() mirrors — where `nodes` is exactly aws_wql.evaluate's row list.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_controls
import aws_dspm
import aws_policy
import aws_wql
from aws_graph import SecurityGraph

PARITY_ACCOUNT = "111122223333"

FIXTURE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "frontend", "src", "lib", "__fixtures__", "wql_parity.json")

# ── the canonical graph — deliberately exercises every predicate, both reach
# directions, code-point sort ties, char-class globs, and the E_PATH/annotation split ──
LB = "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/app-lb/00"
WEB = "arn:aws:ec2:us-east-1:1:instance/i-web"
ISO = "arn:aws:ec2:us-east-1:1:instance/i-iso"
ZEUS = "arn:aws:iam::1:role/Zeus"          # no name prop → label falls back to _seg (Zeus)
APOLLO = "arn:aws:iam::1:role/apollo"      # code-point: 'Z'(0x5A) < 'a'(0x61) → Zeus sorts first
ADMINROLE = "arn:aws:iam::1:role/AdminRole"
ADMIN = "cap:admin:1"
CROWN_PUB = "arn:aws:s3:::crown-public"
CROWN_PRIV = "arn:aws:s3:::crown-private"
ISLAND = "arn:aws:s3:::island"
PRODDB = "arn:aws:rds:us-east-1:1:db/prod-db"
KEV_CVE = "CVE-2021-44228"
LOW_CVE = "CVE-2019-0001"


def build_graph() -> SecurityGraph:
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node(LB, "LoadBalancer", name="app-lb", public=True, region="us-east-1")
    g.add_node(WEB, "EC2Instance", name="web-01", region="us-east-1", external=True)
    g.add_node(ISO, "EC2Instance", name="iso-01", region="us-west-2")
    g.add_node(ZEUS, "IAMRole")
    g.add_node(APOLLO, "IAMRole")
    g.add_node(ADMINROLE, "IAMRole", name="AdminRole")
    g.add_node(ADMIN, "AdminCapability")
    g.add_node(CROWN_PUB, "S3Bucket", name="crown-public", crown_jewel=True, public=True,
               encrypted=False, sensitivity="high", DataStore=True, region="us-east-1")
    g.add_node(CROWN_PRIV, "S3Bucket", name="crown-private", crown_jewel=True, public=False,
               encrypted=True, sensitivity="medium", DataStore=True, region="us-east-1")
    g.add_node(ISLAND, "S3Bucket", name="island", crown_jewel=False, public=False, encrypted=True)
    g.add_node(PRODDB, "RDSInstance", name="prod-db", crown_jewel=True, encrypted=True,
               DataStore=True, region="us-east-1")
    g.add_node(KEV_CVE, "Vulnerability", severity="CRITICAL", kev=True, epss=0.97,
               exploit_available="YES", cve=KEV_CVE)
    g.add_node(LOW_CVE, "Vulnerability", severity="LOW", kev=False, epss=0.02, cve=LOW_CVE)
    # E_PATH (traversable attack edges)
    g.add_edge("internet", LB, "EXPOSED_TO")
    g.add_edge(LB, WEB, "TARGETS")
    g.add_edge(WEB, ZEUS, "HAS_ROLE")
    g.add_edge(ZEUS, ADMIN, "CAN_PRIVESC_TO")
    g.add_edge(ADMINROLE, ADMIN, "CAN_PRIVESC_TO")   # AdminRole reaches admin but is NOT exposed
    g.add_edge(WEB, CROWN_PUB, "CAN_READ_DATA")
    g.add_edge(WEB, PRODDB, "CAN_READ_DATA")
    g.add_edge(APOLLO, CROWN_PRIV, "CAN_READ_DATA")  # apollo reaches a crown, unexposed, non-admin
    g.add_edge(ISO, ISLAND, "CAN_READ_DATA")         # island is not a crown
    # annotations (NOT E_PATH — must never fabricate a hop, but DO satisfy has_edge)
    g.add_edge(WEB, KEV_CVE, "HAS_VULN", kev=True, cve=KEV_CVE, epss=0.97)
    g.add_edge(ISO, LOW_CVE, "HAS_VULN", kev=False, cve=LOW_CVE, epss=0.02)
    return g


# ── the query battery: every predicate, op, boolean shape, and known trap ──────
CASES = [
    ("all_nodes", {}),
    ("kind_eq_role", {"kind": "IAMRole"}),
    ("kind_in_two", {"kind_in": ["S3Bucket", "RDSInstance"]}),
    # the `kind` LEAF predicate (distinct code path from the top-level kind/kind_in fields)
    ("where_kind_leaf_eq", {"where": {"op": "and", "of": [
        {"pred": "kind", "op": "eq", "value": "S3Bucket"}, {"pred": "crown_jewel"}]}}),
    ("where_kind_leaf_in", {"where": {"pred": "kind", "op": "in", "value": ["IAMRole", "AdminCapability"]}}),
    # code-point sort: Zeus (0x5A) must precede apollo (0x61), grouped after AdminRole by id
    ("determinism_codepoint_roles", {"kind": "IAMRole"}),
    ("limit_two", {"limit": 2}),
    # has_prop — truthy vs explicit value
    ("has_prop_crown_truthy", {"kind": "S3Bucket", "where": {"pred": "has_prop", "field": "crown_jewel"}}),
    ("has_prop_public_true", {"where": {"pred": "has_prop", "field": "public", "value": True}}),
    ("has_prop_encrypted_false_is_falsy", {"kind": "S3Bucket", "where": {"pred": "has_prop", "field": "encrypted"}}),
    # prop comparators
    ("prop_eq_region", {"where": {"pred": "prop", "field": "region", "op": "eq", "value": "us-west-2"}}),
    ("prop_neq_region", {"kind_in": ["EC2Instance"], "where": {"pred": "prop", "field": "region", "op": "neq", "value": "us-east-1"}}),
    ("prop_in_severity", {"kind": "Vulnerability", "where": {"pred": "prop", "field": "severity", "op": "in", "value": ["CRITICAL", "HIGH"]}}),
    ("prop_gt_epss", {"kind": "Vulnerability", "where": {"pred": "prop", "field": "epss", "op": "gt", "value": 0.5}}),
    ("prop_gte_epss_boundary", {"kind": "Vulnerability", "where": {"pred": "prop", "field": "epss", "op": "gte", "value": 0.97}}),
    ("prop_lt_epss", {"kind": "Vulnerability", "where": {"pred": "prop", "field": "epss", "op": "lt", "value": 0.5}}),
    ("prop_lte_epss_boundary", {"kind": "Vulnerability", "where": {"pred": "prop", "field": "epss", "op": "lte", "value": 0.02}}),
    ("prop_exists_kev_absent_on_ec2", {"kind": "EC2Instance", "where": {"pred": "prop", "field": "kev", "op": "exists"}}),
    ("prop_neq_absent_is_true", {"kind": "EC2Instance", "where": {"pred": "prop", "field": "kev", "op": "neq", "value": True}}),
    ("prop_contains_substring_name", {"where": {"pred": "prop", "field": "name", "op": "contains", "value": "crown"}}),
    ("prop_contains_substring_cve", {"kind": "Vulnerability", "where": {"pred": "prop", "field": "cve", "op": "contains", "value": "44228"}}),
    # prop_glob — plain, char-range, and negated char-class (the fnmatch.translate traps)
    ("prop_glob_star", {"kind": "S3Bucket", "where": {"pred": "prop_glob", "field": "name", "value": "crown-*"}}),
    ("prop_glob_charrange", {"kind": "S3Bucket", "where": {"pred": "prop_glob", "field": "name", "value": "crown-[a-z]rivate"}}),
    ("prop_glob_neg_class", {"kind": "S3Bucket", "where": {"pred": "prop_glob", "field": "name", "value": "[!i]*"}}),
    # leading '^' is a LITERAL class member in fnmatch (only '!' negates) — the SAMPLE glob must
    # NOT treat it as JS-regex negation. [^c]* => names starting with '^' or 'c' => the two crowns.
    ("prop_glob_caret_is_literal", {"kind": "S3Bucket", "where": {"pred": "prop_glob", "field": "name", "value": "[^c]*"}}),
    # has_edge — E_PATH edge + annotation edge, both directions
    ("has_edge_out_hasvuln", {"kind": "EC2Instance", "where": {"pred": "has_edge", "kind": "HAS_VULN", "dir": "out"}}),
    ("has_edge_in_hasvuln", {"kind": "Vulnerability", "where": {"pred": "has_edge", "kind": "HAS_VULN", "dir": "in"}}),
    ("has_edge_out_canreaddata", {"where": {"pred": "has_edge", "kind": "CAN_READ_DATA", "dir": "out"}}),
    # reachability
    ("reachable_from_internet", {"where": {"pred": "reachable_from", "target": "internet"}}),
    ("reaches_admin_all", {"where": {"pred": "reaches", "target": "admin"}}),
    ("reaches_crown_all", {"where": {"pred": "reaches", "target": "crown"}}),
    ("crown_jewel_all", {"where": {"pred": "crown_jewel"}}),
    # boolean composition
    ("flagship_exposed_crown_s3", {"kind": "S3Bucket", "where": {"op": "and", "of": [
        {"pred": "crown_jewel"}, {"pred": "reachable_from", "target": "internet"}]}}),
    ("or_admin_or_crown_roles", {"kind": "IAMRole", "where": {"op": "or", "of": [
        {"pred": "reaches", "target": "admin"}, {"pred": "reaches", "target": "crown"}]}}),
    ("not_crown_s3", {"kind": "S3Bucket", "where": {"op": "not", "of": [{"pred": "crown_jewel"}]}}),
    ("nested_crown_and_not_public", {"kind_in": ["S3Bucket", "RDSInstance"], "where": {"op": "and", "of": [
        {"pred": "crown_jewel"},
        {"op": "not", "of": [{"pred": "has_prop", "field": "public", "value": True}]}]}}),
    # hop cap: at max_hops=1 the crown S3 is 1 hop off internet? No — internet->lb is hop1; so
    # reachable_from internet at max_hops=1 is just the LB. Guards the bound is honored.
    ("reachable_from_internet_hop1", {"max_hops": 1, "where": {"pred": "reachable_from", "target": "internet"}}),
]


# ── saved-query-as-Control cases: the synthetic-finding shape must also match cross-language.
# Each control is evaluated over the SAME canonical graph; `expected` is the WARN finding dict
# aws_controls.control_finding produces (or None when the query matches nothing → the control
# "passes" and emits no finding). Guards the severity default + the exact risk string too.
CONTROLS = [
    {"id": "public-crown-data", "name": "Publicly exposed crown data", "severity": "CRITICAL",
     "description": "Crown-jewel S3 buckets reachable from the internet.",
     "query": {"kind": "S3Bucket", "where": {"op": "and", "of": [
         {"pred": "crown_jewel"}, {"pred": "reachable_from", "target": "internet"}]}}},
    {"id": "roles-to-admin", "name": "Roles that can reach admin", "severity": "HIGH",
     "query": {"kind": "IAMRole", "where": {"pred": "reaches", "target": "admin"}}},
    {"id": "bad-severity-defaults-medium", "name": "Weird severity → MEDIUM", "severity": "BOGUS",
     "query": {"kind": "RDSInstance", "where": {"pred": "crown_jewel"}}},
    {"id": "matches-nothing", "name": "Unencrypted DynamoDB (none here)",
     "query": {"kind": "DynamoDBTable"}},
]


# DSPM classify parity — aws_dspm.classify is the oracle for the TS mirror (dspm.ts). Covers the
# heterogeneous sensitivity signal: tag values -> data_type, Macie int score -> tier-only, secret,
# stray bool, unclassified, ai-data, and the secret+tag combination.
DSPM_CASES = [
    {"sensitivity": "pci"}, {"sensitivity": "hipaa"}, {"sensitivity": "pii"},
    {"sensitivity": "confidential"}, {"sensitivity": 82}, {"sensitivity": 60},
    {"secret": True}, {"sensitivity": "flagged"}, {}, {"sensitivity": True},
    {"sensitivity": "ai-data"}, {"secret": True, "sensitivity": "pci"},
]


# Policy-as-code parity — aws_policy.evaluate + policy_finding are the oracle for policy.ts. Each
# policy is evaluated over the SAME canonical graph + a fixed finding catalog; `expected` is the
# POLICY-xx finding dict (or None when the policy does not fire). Covers compliance-as-code
# (framework+control), check_id glob + severity, the graph clause, cross-domain any|all, and
# the severity default.
POLICY_CATALOG = [
    {"check_id": "S3-01", "section": "S3", "severity": "HIGH", "status": "FAIL",
     "compliance": {"PCI-DSS": "3.4", "CIS": "2.1"}},
    {"check_id": "IAM-05", "section": "IAM", "severity": "MEDIUM", "status": "PASS",
     "compliance": {"PCI-DSS": "7.1"}},
    {"check_id": "S3-02", "section": "S3", "severity": "LOW", "status": "FAIL", "compliance": {}},
]
POLICIES = [
    {"id": "pci-34-fail", "name": "PCI-DSS 3.4 must pass", "severity": "HIGH", "pack": "pci",
     "compliance": {"PCI-DSS": "3.4"},
     "match": {"finding": {"compliance_framework": "PCI-DSS", "compliance_control": "3.4", "status": "FAIL"}}},
    {"id": "s3-high-fail", "match": {"finding": {"check_id_glob": "S3-*", "severity": "MEDIUM",
                                                 "severity_op": "gte", "status": "FAIL"}}},
    {"id": "exposed-crown-graph", "name": "Exposed crown", "severity": "CRITICAL",
     "match": {"graph": {"kind": "S3Bucket", "where": {"op": "and", "of": [
         {"pred": "crown_jewel"}, {"pred": "reachable_from", "target": "internet"}]}}}},
    {"id": "combo-all", "match": {"op": "all",
                                  "graph": {"kind": "S3Bucket", "where": {"pred": "crown_jewel"}},
                                  "finding": {"compliance_framework": "PCI-DSS", "status": "FAIL"}}},
    {"id": "weird-sev", "severity": "SPICY", "match": {"finding": {"status": "FAIL"}}},   # -> MEDIUM
    {"id": "never-fires", "match": {"finding": {"check_id_glob": "ZZZ-*"}}},
    {"id": "empty-glob-all", "match": {"finding": {"check_id_glob": ""}}},   # ''->'*' matches every finding
]


def build_fixture() -> dict:
    g = build_graph()
    cases = []
    for name, query in CASES:
        rows = aws_wql.evaluate(query, g)
        cases.append({"name": name, "query": query, "expected": {"count": len(rows), "nodes": rows}})
    controls = []
    for ctrl in CONTROLS:
        rows = aws_wql.evaluate(ctrl["query"], g)
        expected = aws_controls.control_finding(ctrl, PARITY_ACCOUNT, rows) if rows else None
        controls.append({"control": ctrl, "account": PARITY_ACCOUNT, "expected": expected})
    dspm = [{"props": p, "expected": aws_dspm.classify(p)} for p in DSPM_CASES]
    policies = []
    for pol in POLICIES:
        matched = aws_policy.evaluate(aws_policy.parse(pol), g, POLICY_CATALOG)
        expected = aws_policy.policy_finding(pol, PARITY_ACCOUNT, matched) if matched else None
        policies.append({"policy": pol, "account": PARITY_ACCOUNT, "expected": expected})
    return {
        "_comment": "GENERATED by scripts/gen_wql_parity.py — do not edit by hand. The Python "
                    "engines (aws_wql.evaluate + aws_controls.control_finding + aws_dspm.classify + "
                    "aws_policy) are the oracle; wql.ts + controls.ts + dspm.ts + policy.ts must match.",
        "graph": g.to_dict(),
        "cases": cases,
        "controls": controls,
        "dspm": dspm,
        "policy_catalog": POLICY_CATALOG,
        "policies": policies,
    }


def main() -> None:
    fx = build_fixture()
    os.makedirs(os.path.dirname(FIXTURE_PATH), exist_ok=True)
    with open(FIXTURE_PATH, "w", encoding="utf-8") as f:
        json.dump(fx, f, indent=2, sort_keys=False)
        f.write("\n")
    print(f"wrote {FIXTURE_PATH} · {len(fx['cases'])} cases · "
          f"{len(fx['graph']['nodes'])} nodes / {len(fx['graph']['edges'])} edges")


if __name__ == "__main__":
    main()
