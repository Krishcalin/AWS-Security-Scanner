"""WQL (aws_wql) — the typed JSON query compiler over the security graph. Covers parser
rejection (the security boundary), every predicate, boolean/NOT nesting, the flagship queries,
hop-cap boundedness, deterministic (kind,id) order, and that 'reaches admin' == per-node
forward reachability to an AdminCapability (the blast-radius parity contract). Pure/offline."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_correlate
import aws_wql
from aws_graph import SecurityGraph

EC2 = "arn:aws:ec2:us-east-1:1:instance/i-1"
ROLE = "arn:aws:iam::1:role/AppRole"
ADMIN = "cap:admin:1"
BUCKET = "arn:aws:s3:::crown-bucket"
CVE = "CVE-2021-44228"


def _graph():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node(EC2, "EC2Instance", name="i-1")
    g.add_node(ROLE, "IAMRole", name="AppRole")
    g.add_node(ADMIN, "AdminCapability")
    g.add_node(BUCKET, "S3Bucket", name="crown", crown_jewel=True, public=True)
    g.add_node("island", "S3Bucket", crown_jewel=False)          # unconnected, not crown
    g.add_node(CVE, "Vulnerability", severity="CRITICAL", kev=True, epss=0.97)
    g.add_edge("internet", EC2, "EXPOSED_TO")
    g.add_edge(EC2, ROLE, "HAS_ROLE")
    g.add_edge(ROLE, ADMIN, "CAN_PRIVESC_TO")
    g.add_edge(EC2, BUCKET, "CAN_READ_DATA")
    g.add_edge(EC2, CVE, "HAS_VULN", cve=CVE, kev=True)          # annotation (not in E_PATH)
    return g


def _ids(rows):
    return [r["id"] for r in rows]


# ── parser rejection (the security boundary) ──────────────────────────────────
@pytest.mark.parametrize("bad", [
    {"select": "edge"},                                         # only 'node' in v1
    {"nonsense": 1},                                            # unknown top key
    {"kind": 5},                                                # kind not a string
    {"where": {"pred": "nope"}},                               # unknown predicate
    {"where": {"pred": "prop", "field": "arbitrary", "op": "eq", "value": 1}},  # non-whitelisted prop
    {"where": {"pred": "prop", "field": "severity", "op": "regex", "value": "x"}},  # unknown op
    {"where": {"op": "not", "of": [{"pred": "crown_jewel"}, {"pred": "crown_jewel"}]}},  # not needs 1
    {"where": {"op": "and", "of": []}},                        # empty boolean
    {"limit": 0}, {"limit": -3}, {"max_hops": 0},
    {"where": {"pred": "reaches", "target": "moon"}},          # bad reaches target
    {"where": {"pred": "reachable_from", "target": "vpc"}},    # only internet in v1
    # explicit null is NOT the same as an absent key: dict.get keeps None, which fails every
    # strict check (SAMPLE wql.ts must reject these identically — see the mirror's `own()`).
    {"select": None}, {"limit": None}, {"max_hops": None},
    {"where": {"pred": "kind", "op": None, "value": "S3Bucket"}},
    {"where": {"pred": "has_edge", "kind": "HAS_ROLE", "dir": None}},
])
def test_parse_rejects_malformed(bad):
    with pytest.raises(aws_wql.WQLError):
        aws_wql.parse(bad)


def test_parse_rejects_overdeep_nesting():
    # a boolean tree deeper than WQL_MAX_DEPTH must raise WQLError (a clean 400), never a
    # RecursionError (a 500). Build depth = MAX_DEPTH + 5 nested 'not's.
    pred = {"pred": "crown_jewel"}
    for _ in range(aws_wql.WQL_MAX_DEPTH + 5):
        pred = {"op": "not", "of": [pred]}
    with pytest.raises(aws_wql.WQLError):
        aws_wql.parse({"where": pred})


def test_parse_rejects_too_many_predicates():
    # a wide boolean 'of' beyond WQL_MAX_PREDS must raise WQLError — bounds evaluate() work so a
    # single query can't do O(nodes * huge) predicate evaluations (CPU-amplification guard).
    wide = {"op": "or", "of": [{"pred": "crown_jewel"} for _ in range(aws_wql.WQL_MAX_PREDS + 5)]}
    with pytest.raises(aws_wql.WQLError):
        aws_wql.parse({"where": wide})


def test_parse_clamps_limit_and_hops():
    q = aws_wql.parse({"limit": 99999, "max_hops": 999})
    assert q["limit"] == aws_wql.WQL_MAX_LIMIT and q["max_hops"] == aws_wql.WQL_MAX_HOPS


# ── predicates ────────────────────────────────────────────────────────────────
def test_kind_and_kind_in():
    g = _graph()
    assert _ids(aws_wql.evaluate({"kind": "IAMRole"}, g)) == [ROLE]
    got = set(_ids(aws_wql.evaluate({"kind_in": ["IAMRole", "EC2Instance"]}, g)))
    assert got == {ROLE, EC2}


def test_has_prop_truthy_and_value():
    g = _graph()
    crowns = _ids(aws_wql.evaluate({"kind": "S3Bucket", "where": {"pred": "has_prop", "field": "crown_jewel", "value": True}}, g))
    assert crowns == [BUCKET]                                   # island has crown_jewel=False


def test_prop_comparators():
    g = _graph()
    # epss > 0.5 on the vuln node
    hi = aws_wql.evaluate({"kind": "Vulnerability", "where": {"pred": "prop", "field": "epss", "op": "gt", "value": 0.5}}, g)
    assert _ids(hi) == [CVE]
    lo = aws_wql.evaluate({"kind": "Vulnerability", "where": {"pred": "prop", "field": "epss", "op": "lt", "value": 0.5}}, g)
    assert lo == []
    # exists on an absent prop
    none = aws_wql.evaluate({"kind": "EC2Instance", "where": {"pred": "prop", "field": "kev", "op": "exists"}}, g)
    assert none == []                                          # EC2 has no kev prop


def test_prop_glob():
    g = _graph()
    r = aws_wql.evaluate({"kind": "IAMRole", "where": {"pred": "prop_glob", "field": "name", "value": "App*"}}, g)
    assert _ids(r) == [ROLE]


def test_has_edge_out_and_in():
    g = _graph()
    # EC2 has an outbound HAS_VULN annotation edge
    assert _ids(aws_wql.evaluate({"kind": "EC2Instance", "where": {"pred": "has_edge", "kind": "HAS_VULN", "dir": "out"}}, g)) == [EC2]
    # the CVE node has an INBOUND HAS_VULN edge
    assert _ids(aws_wql.evaluate({"kind": "Vulnerability", "where": {"pred": "has_edge", "kind": "HAS_VULN", "dir": "in"}}, g)) == [CVE]


def test_boolean_and_or_not():
    g = _graph()
    # exposed AND crown S3 → the flagship exposed-crown query
    q = {"kind": "S3Bucket", "where": {"op": "and", "of": [
        {"pred": "crown_jewel"}, {"pred": "reachable_from", "target": "internet"}]}}
    assert _ids(aws_wql.evaluate(q, g)) == [BUCKET]
    # NOT crown → the island bucket
    q2 = {"kind": "S3Bucket", "where": {"op": "not", "of": [{"pred": "crown_jewel"}]}}
    assert _ids(aws_wql.evaluate(q2, g)) == ["island"]


# ── flagship queries ──────────────────────────────────────────────────────────
def test_flagship_roles_reach_admin():
    g = _graph()
    q = {"kind": "IAMRole", "where": {"pred": "reaches", "target": "admin"}}
    assert _ids(aws_wql.evaluate(q, g)) == [ROLE]


def test_flagship_workloads_without_endpoint_security_matches_all_when_unenriched():
    # THE honest gap: runtime_monitored is not a graph prop today, so NOT-has-prop matches
    # every workload. This test DOCUMENTS that (guarding against shipping it as a Control).
    g = _graph()
    q = {"kind_in": ["EC2Instance"], "where": {"op": "not", "of": [{"pred": "has_prop", "field": "runtime_monitored"}]}}
    assert _ids(aws_wql.evaluate(q, g)) == [EC2]                # matches ALL (unenriched → misleading)


# ── determinism + boundedness ─────────────────────────────────────────────────
def test_deterministic_kind_id_order():
    g = _graph()
    rows = aws_wql.evaluate({"kind_in": ["S3Bucket", "IAMRole", "EC2Instance"]}, g)
    kinds = [r["kind"] for r in rows]
    assert kinds == sorted(kinds)                              # grouped by kind, code-point sorted


def test_limit_truncates():
    g = _graph()
    assert len(aws_wql.evaluate({"limit": 1}, g)) == 1


# ── the blast-radius parity contract ──────────────────────────────────────────
def test_reaches_admin_equals_forward_reachability():
    # WQL 'reaches admin' (a reverse-BFS-from-admin precompute) must equal, per node, whether
    # that node forward-reaches an AdminCapability — the same relation get_blast_radius.reaches
    # surfaces. Prove the two agree over EVERY node.
    g = _graph()
    admins = {n["id"] for n in g.nodes("AdminCapability")}
    wql_set = {r["id"] for r in aws_wql.evaluate({"where": {"pred": "reaches", "target": "admin"}}, g)}
    forward_set = {n["id"] for n in g.nodes()
                   if admins & set(g.reachable(n["id"], aws_correlate.E_PATH, max_hops=12))}
    assert wql_set == forward_set
    assert EC2 in wql_set and ROLE in wql_set                  # internet→ec2→role→admin chain


# ── service run_wql + POST /graph/query route ─────────────────────────────────
import aws_state
import cnapp_connectors as cc
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"


def _svc(graph=None):
    reg = AccountRegistry.open(":memory:")
    results = InMemoryResultStore()
    if graph is not None:
        results.put(ACCT, {"account": ACCT, "graph_full": graph.to_dict(),
                           "results": [], "attack_paths": [], "finding_catalog": []})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=aws_state.StateStore(reg._be), clock=lambda: 5000)


def test_service_run_wql_returns_nodes():
    r = _svc(_graph()).run_wql(ACCT, {"kind": "S3Bucket", "where": {"pred": "crown_jewel"}})
    assert r["count"] == 1 and _ids(r["nodes"]) == [BUCKET]


def test_service_run_wql_none_when_no_scan():
    assert _svc(graph=None).run_wql(ACCT, {"kind": "S3Bucket"}) is None


def test_service_run_wql_bad_query_raises_valueerror():
    with pytest.raises(ValueError):
        _svc(_graph()).run_wql(ACCT, {"where": {"pred": "nope"}})


def test_service_run_wql_overdeep_query_is_valueerror_not_recursionerror():
    # the route maps ValueError -> 400; an over-deep predicate must surface as ValueError
    # (WQLError subclasses it), NOT a RecursionError that would escape as a 500.
    pred = {"pred": "crown_jewel"}
    for _ in range(aws_wql.WQL_MAX_DEPTH + 5):
        pred = {"op": "not", "of": [pred]}
    with pytest.raises(ValueError):
        _svc(_graph()).run_wql(ACCT, {"where": pred})


# API
try:
    import cnapp_api
    _HAVE_FASTAPI = cnapp_api._HAVE_FASTAPI
except Exception:
    _HAVE_FASTAPI = False

api = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi not installed")


def _client(svc):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return cnapp_api, TestClient(cnapp_api.create_app(svc, current_role=lambda: "viewer"))


@api
def test_route_query_returns_matches():
    _, c = _client(_svc(_graph()))
    body = c.post(f"/accounts/{ACCT}/graph/query",
                  json={"query": {"kind": "IAMRole", "where": {"pred": "reaches", "target": "admin"}}})
    assert body.status_code == 200 and _ids(body.json()["nodes"]) == [ROLE]


@api
def test_route_query_malformed_is_400():
    _, c = _client(_svc(_graph()))
    r = c.post(f"/accounts/{ACCT}/graph/query", json={"query": {"where": {"pred": "nope"}}})
    assert r.status_code == 400


@api
def test_route_query_404_when_no_scan():
    _, c = _client(_svc(graph=None))
    r = c.post(f"/accounts/{ACCT}/graph/query", json={"query": {"kind": "S3Bucket"}})
    assert r.status_code == 404
