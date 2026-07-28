"""Controls (saved-WQL-query-as-Control) — the read-only, display-only overlay of a matching
saved query into the finding catalog as a synthetic WARN entry, plus the org roll-up + GET
/controls route. Verifies: the overlay appears in get_finding_catalog + org_findings; a control
that matches nothing emits nothing; a bad/unsafe saved query is inert (never crashes findings);
the overlay is WARN-only (posture, which counts FAIL, is untouched); list_controls rolls up
match counts + accounts and marks WARN/PASS. Pure/offline."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_controls
import aws_state
import cnapp_connectors as cc
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"
EC2 = "arn:aws:ec2:us-east-1:1:instance/i-1"
ROLE = "arn:aws:iam::1:role/AppRole"
ADMIN = "cap:admin:1"
BUCKET = "arn:aws:s3:::crown-bucket"

CTRL_EXPOSED = {"id": "exposed-crown", "name": "Exposed crown S3", "severity": "CRITICAL",
                "query": {"kind": "S3Bucket", "where": {"op": "and", "of": [
                    {"pred": "crown_jewel"}, {"pred": "reachable_from", "target": "internet"}]}}}
CTRL_ADMIN = {"id": "roles-admin", "name": "Roles to admin", "severity": "HIGH",
              "query": {"kind": "IAMRole", "where": {"pred": "reaches", "target": "admin"}}}
CTRL_NONE = {"id": "no-match", "name": "No DynamoDB", "query": {"kind": "DynamoDBTable"}}
CTRL_BAD = {"id": "bad", "name": "Malformed saved query",
            "query": {"where": {"pred": "nope"}}}       # unsafe/unknown predicate → inert


def _graph():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node(EC2, "EC2Instance", name="i-1")
    g.add_node(ROLE, "IAMRole", name="AppRole")
    g.add_node(ADMIN, "AdminCapability")
    g.add_node(BUCKET, "S3Bucket", name="crown", crown_jewel=True, public=True)
    g.add_edge("internet", EC2, "EXPOSED_TO")
    g.add_edge(EC2, ROLE, "HAS_ROLE")
    g.add_edge(ROLE, ADMIN, "CAN_PRIVESC_TO")
    g.add_edge(EC2, BUCKET, "CAN_READ_DATA")
    return g


def _svc(controls, *, graph=None, base_findings=None, posture=None):
    reg = AccountRegistry.open(":memory:")
    results = InMemoryResultStore()
    payload = {"account": ACCT, "results": [], "attack_paths": [], "finding_catalog": base_findings or []}
    if graph is not None:
        payload["graph_full"] = graph.to_dict()
    if posture is not None:
        payload["posture_score"] = posture
    results.put(ACCT, payload)
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=aws_state.StateStore(reg._be),
        controls=controls, clock=lambda: 5000)


# ── the synthetic finding shape (aws_controls.control_finding) ─────────────────
def test_control_finding_shape():
    rows = [{"id": BUCKET, "kind": "S3Bucket", "label": "crown", "props": {}}]
    f = aws_controls.control_finding(CTRL_EXPOSED, ACCT, rows)
    assert f["check_id"] == "CONTROL-exposed-crown"
    assert f["status"] == "WARN" and f["severity"] == "CRITICAL"
    assert f["section"] == "Custom Controls"
    assert f["affected"] == [BUCKET] and f["count"] == 1 and f["distinct"] == 1
    assert f["account"] == ACCT


def test_control_severity_defaults_to_medium():
    assert aws_controls.control_severity({"severity": "nonsense"}) == "MEDIUM"
    assert aws_controls.control_severity({}) == "MEDIUM"
    assert aws_controls.control_severity({"severity": "LOW"}) == "LOW"


# ── overlay into the account catalog ───────────────────────────────────────────
def test_catalog_overlays_matching_control():
    svc = _svc([CTRL_EXPOSED, CTRL_ADMIN], graph=_graph())
    cat = svc.get_finding_catalog(ACCT)
    ids = {f["check_id"] for f in cat}
    assert "CONTROL-exposed-crown" in ids and "CONTROL-roles-admin" in ids
    exposed = next(f for f in cat if f["check_id"] == "CONTROL-exposed-crown")
    assert exposed["affected"] == [BUCKET] and exposed["status"] == "WARN"


def test_control_that_matches_nothing_emits_no_finding():
    svc = _svc([CTRL_NONE], graph=_graph())
    assert svc.get_finding_catalog(ACCT) == []      # no DynamoDB → control passes → no entry


def test_bad_saved_query_is_inert_not_an_error():
    svc = _svc([CTRL_BAD, CTRL_EXPOSED], graph=_graph())
    cat = svc.get_finding_catalog(ACCT)              # must NOT raise
    ids = {f["check_id"] for f in cat}
    assert "CONTROL-bad" not in ids                  # malformed control silently skipped
    assert "CONTROL-exposed-crown" in ids            # the good one still overlays


def test_no_controls_configured_is_a_noop():
    svc = _svc([], graph=_graph(), base_findings=[{"check_id": "IAM-01", "severity": "HIGH"}])
    assert [f["check_id"] for f in svc.get_finding_catalog(ACCT)] == ["IAM-01"]


def test_no_scan_means_no_control_findings():
    svc = _svc([CTRL_EXPOSED], graph=None)
    assert svc.get_finding_catalog(ACCT) == []


def test_control_findings_are_display_only_never_touch_posture():
    # get_account_summary reads the STORED finding_catalog (not get_finding_catalog), so control
    # findings must not appear in the severity histogram nor perturb the baked posture score.
    svc = _svc([CTRL_EXPOSED], graph=_graph(), posture=88)
    summ = svc.get_account_summary(ACCT)
    assert summ["posture_score"] == 88
    assert sum(summ["severity_counts"].values()) == 0     # stored catalog was empty
    # yet the display catalog DOES carry the control finding
    assert any(f["check_id"] == "CONTROL-exposed-crown" for f in svc.get_finding_catalog(ACCT))


# ── org roll-up + list_controls ────────────────────────────────────────────────
def test_org_findings_overlays_controls_tagged_by_account():
    svc = _svc([CTRL_EXPOSED], graph=_graph())
    org = svc.org_findings()
    ctrl = [f for f in org if f["check_id"] == "CONTROL-exposed-crown"]
    assert len(ctrl) == 1 and ctrl[0]["account"] == ACCT


def test_org_findings_include_controls_false_excludes_overlay():
    # the Projects roll-up path passes include_controls=False so display-only controls never
    # inflate business-impact cards (and it matches the SAMPLE Projects path, which reads raw findings).
    svc = _svc([CTRL_EXPOSED], graph=_graph())
    assert not any(f["check_id"] == "CONTROL-exposed-crown"
                   for f in svc.org_findings(include_controls=False))


def test_projects_rollup_excludes_control_overlay():
    # a control WARN matching this account must NOT be counted into a project's finding_count
    # (else LIVE Projects diverges from SAMPLE, which reads raw findings without controls).
    reg = AccountRegistry.open(":memory:")
    results = InMemoryResultStore()
    results.put(ACCT, {"account": ACCT, "results": [], "attack_paths": [],
                       "finding_catalog": [{"check_id": "S3-01", "severity": "HIGH",
                                            "affected": [BUCKET], "account": ACCT}],
                       "graph_full": _graph().to_dict()})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    proj = [{"id": "p1", "name": "All of acct", "tier": "HBI", "match": {"accounts": [ACCT]}}]
    svc = PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=aws_state.StateStore(reg._be),
        projects=proj, controls=[CTRL_EXPOSED], clock=lambda: 5000)
    roll = svc.list_projects()[0]
    assert roll["finding_count"] == 1                    # only the real S3-01, NOT the control
    detail = svc.project_summary("p1")
    assert [f["check_id"] for f in detail["findings"]] == ["S3-01"]


def test_list_controls_rollup_warn_and_pass():
    svc = _svc([CTRL_EXPOSED, CTRL_ADMIN, CTRL_NONE], graph=_graph())
    rows = {c["id"]: c for c in svc.list_controls()}
    assert rows["exposed-crown"]["status"] == "WARN"
    assert rows["exposed-crown"]["match_count"] == 1
    assert rows["exposed-crown"]["accounts_matched"] == [ACCT]
    assert rows["roles-admin"]["match_count"] == 1 and rows["roles-admin"]["status"] == "WARN"
    assert rows["no-match"]["status"] == "PASS" and rows["no-match"]["match_count"] == 0
    assert rows["no-match"]["accounts_matched"] == []


def test_list_controls_empty_when_none_configured():
    assert _svc([], graph=_graph()).list_controls() == []


# ── GET /controls route ────────────────────────────────────────────────────────
try:
    import cnapp_api
    _HAVE_FASTAPI = cnapp_api._HAVE_FASTAPI
except Exception:
    _HAVE_FASTAPI = False

api = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi not installed")


def _client(svc):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc, current_role=lambda: "viewer"))


@api
def test_route_controls_returns_rollup():
    c = _client(_svc([CTRL_EXPOSED, CTRL_NONE], graph=_graph()))
    r = c.get("/controls")
    assert r.status_code == 200
    body = {x["id"]: x for x in r.json()}
    assert body["exposed-crown"]["status"] == "WARN"
    assert body["no-match"]["status"] == "PASS"


@api
def test_route_controls_empty_list_when_unconfigured():
    c = _client(_svc([], graph=_graph()))
    r = c.get("/controls")
    assert r.status_code == 200 and r.json() == []
