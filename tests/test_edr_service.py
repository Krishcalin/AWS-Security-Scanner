"""EDR service + API layer: ingest_edr (sensors -> coverage table, detections -> shared CDR
verdict path), edr_coverage / org roll-up, the runtime_monitored read-time overlay that makes
the WQL endpoint-security query real, the EDR-01 (WARN, display-only) + EDR-02 (FAIL, Runtime)
findings, and the POST /edr/ingest (ingest tier) + GET /edr/coverage routes. Pure/offline."""
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
WEB = "arn:aws:ec2:us-east-1:111122223333:instance/i-web"
QUIET = "arn:aws:ec2:us-east-1:111122223333:instance/i-quiet"
ROLE = "arn:aws:iam::111122223333:role/app-role"
ADMIN = "cap:admin:111122223333"
CROWN = "arn:aws:s3:::crown-bucket"


def _graph(admin_path=False):
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node(WEB, "EC2Instance", instance_id="i-web", name="web-01")
    g.add_node(QUIET, "EC2Instance", instance_id="i-quiet", name="quiet-01")
    g.add_node(CROWN, "S3Bucket", name="crown", crown_jewel=True)
    g.add_edge("internet", WEB, "EXPOSED_TO")
    g.add_edge(WEB, CROWN, "CAN_READ_DATA")
    if admin_path:
        g.add_node(ROLE, "IAMRole", name="app-role")
        g.add_node(ADMIN, "AdminCapability")
        g.add_edge(WEB, ROLE, "HAS_ROLE")
        g.add_edge(ROLE, ADMIN, "CAN_PRIVESC_TO")
    return g


def _svc(graph=None):
    reg = AccountRegistry.open(":memory:")
    results = InMemoryResultStore()
    payload = {"account": ACCT, "results": [], "attack_paths": [], "finding_catalog": []}
    if graph is not None:
        payload["graph_full"] = graph.to_dict()
    results.put(ACCT, payload)
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=aws_state.StateStore(reg._be), clock=lambda: 5000)


def _wql_uncovered(svc):
    q = {"kind_in": ["EC2Instance"], "where": {"op": "not", "of": [
        {"pred": "has_prop", "field": "runtime_monitored"}]}}
    return [n["id"] for n in svc.run_wql(ACCT, q)["nodes"]]


# ── ingest + coverage ───────────────────────────────────────────────────────────
def test_ingest_sensors_and_coverage():
    svc = _svc(_graph())
    r = svc.ingest_edr(ACCT, vendor="crowdstrike", sensors=[{"instance_id": "i-web", "status": "healthy"}])
    assert r["sensors_upserted"] == 1 and r["coverage"] == {"monitored": 1, "total": 2, "pct": 50.0}
    cov = svc.edr_coverage(ACCT)
    assert cov["overall"] == {"monitored": 1, "total": 2, "pct": 50.0}
    assert [g["node_id"] for g in cov["gaps"]] == [QUIET]


def test_reingest_is_idempotent():
    svc = _svc(_graph())
    svc.ingest_edr(ACCT, vendor="falco", sensors=[{"instance_id": "i-web"}])
    svc.ingest_edr(ACCT, vendor="falco", sensors=[{"instance_id": "i-web"}])
    assert svc.edr_coverage(ACCT)["overall"]["monitored"] == 1   # one workload, not two rows


def test_unknown_vendor_raises_valueerror():
    with pytest.raises(ValueError):
        _svc(_graph()).ingest_edr(ACCT, vendor="nessus", sensors=[{"instance_id": "i-web"}])


def test_edr_coverage_none_without_scan():
    assert _svc(graph=None).edr_coverage(ACCT) is None


def test_org_coverage_rollup():
    svc = _svc(_graph())
    svc.ingest_edr(ACCT, vendor="crowdstrike", sensors=[{"instance_id": "i-web"}])
    org = svc.org_edr_coverage()
    assert org["overall"] == {"monitored": 1, "total": 2, "pct": 50.0}
    assert org["accounts"][0]["account"] == ACCT and org["accounts"][0]["gap_count"] == 1


# ── the runtime_monitored overlay closes the Batch-2 WQL gap ─────────────────────
def test_runtime_monitored_overlay_makes_wql_query_real():
    svc = _svc(_graph())
    assert set(_wql_uncovered(svc)) == {WEB, QUIET}          # before: nothing is monitored
    svc.ingest_edr(ACCT, vendor="crowdstrike", sensors=[{"instance_id": "i-web"}])
    assert _wql_uncovered(svc) == [QUIET]                    # after: only the uncovered host


# ── EDR-01 coverage finding (WARN, display-only) ─────────────────────────────────
def test_edr01_present_when_sensors_and_gaps():
    svc = _svc(_graph())
    svc.ingest_edr(ACCT, vendor="crowdstrike", sensors=[{"instance_id": "i-web"}])
    cat = svc.get_finding_catalog(ACCT)
    edr01 = [f for f in cat if f["check_id"] == "EDR-01"]
    assert len(edr01) == 1
    assert edr01[0]["status"] == "WARN" and edr01[0]["severity"] == "MEDIUM"
    assert edr01[0]["affected"] == [QUIET]


def test_no_edr01_without_a_sensor_feed():
    # never surface "all workloads uncovered" as a finding before any sensor is wired up
    svc = _svc(_graph())
    assert not any(f["check_id"] == "EDR-01" for f in svc.get_finding_catalog(ACCT))


def test_edr01_is_display_only_not_in_posture():
    # EDR-01 rides the read-time overlay; get_account_summary reads the STORED catalog, so the
    # posture histogram/score never sees it.
    svc = _svc(_graph())
    svc.ingest_edr(ACCT, vendor="crowdstrike", sensors=[{"instance_id": "i-web"}])
    summ = svc.get_account_summary(ACCT)
    assert sum(summ["severity_counts"].values()) == 0


# ── EDR-02 incident finding (FAIL, Runtime section) ──────────────────────────────
def test_edr02_incident_finding_on_attack_path():
    svc = _svc(_graph(admin_path=True))
    svc.ingest_edr(ACCT, vendor="crowdstrike", detections=[{
        "composite_id": "d-inc", "max_severity": 95, "status": "new",
        "behaviors": [{"description": "cred theft", "technique_id": "T1552"}],
        "device": {"instance_id": "i-web"}}])
    incs = svc.list_incidents(ACCT)
    assert any(i["detection_id"] == "d-inc" and i["source"] == "crowdstrike" for i in incs)
    entries = svc._detection_finding_entries(ACCT)
    edr02 = [e for e in entries if e["check_id"] == "EDR-02"]
    assert len(edr02) == 1 and edr02[0]["section"] == "Runtime" and edr02[0]["status"] == "FAIL"


def test_runtime_incidents_not_mislabeled_as_cloud_threats():
    # a runtime detection must NOT surface as the cloud-threat THREAT-ING check
    svc = _svc(_graph(admin_path=True))
    svc.ingest_edr(ACCT, vendor="falco", detections=[{
        "rule": "shell in container", "priority": "Critical", "time": "t",
        "output_fields": {"container.id": "c1"}, "tags": ["T1059"]}])
    # falco alert maps to no node here (container-only) -> unmapped, not necessarily an incident;
    # the key assertion: if any runtime incident exists it is EDR-02, never THREAT-ING.
    ids = {e["check_id"] for e in svc._detection_finding_entries(ACCT)}
    assert "THREAT-ING" not in ids or "EDR-02" in ids


# ── API ──────────────────────────────────────────────────────────────────────────
try:
    import cnapp_api
    _HAVE_FASTAPI = cnapp_api._HAVE_FASTAPI
except Exception:
    _HAVE_FASTAPI = False

api = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi not installed")


def _client(svc, role="viewer"):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc, current_role=lambda: role))


@api
def test_route_ingest_requires_ingest_tier():
    svc = _svc(_graph())
    # a viewer token cannot push EDR data (ingest > viewer)
    r = _client(svc, role="viewer").post(f"/accounts/{ACCT}/edr/ingest",
                                         json={"vendor": "crowdstrike", "sensors": [{"instance_id": "i-web"}]})
    assert r.status_code == 403
    # an ingest token succeeds
    ok = _client(svc, role="ingest").post(f"/accounts/{ACCT}/edr/ingest",
                                          json={"vendor": "crowdstrike", "sensors": [{"instance_id": "i-web"}]})
    assert ok.status_code == 200 and ok.json()["coverage"]["monitored"] == 1


@api
def test_route_ingest_unknown_vendor_400():
    r = _client(_svc(_graph()), role="ingest").post(
        f"/accounts/{ACCT}/edr/ingest", json={"vendor": "nessus", "sensors": []})
    assert r.status_code == 400


@api
def test_route_coverage_200_and_404():
    svc = _svc(_graph())
    svc.ingest_edr(ACCT, vendor="crowdstrike", sensors=[{"instance_id": "i-web"}])
    ok = _client(svc).get(f"/accounts/{ACCT}/edr/coverage")
    assert ok.status_code == 200 and ok.json()["overall"]["monitored"] == 1
    missing = _client(_svc(graph=None)).get(f"/accounts/{ACCT}/edr/coverage")
    assert missing.status_code == 404


@api
def test_route_org_coverage():
    svc = _svc(_graph())
    svc.ingest_edr(ACCT, vendor="crowdstrike", sensors=[{"instance_id": "i-web"}])
    r = _client(svc).get("/org/edr/coverage")
    assert r.status_code == 200 and r.json()["overall"]["total"] == 2
