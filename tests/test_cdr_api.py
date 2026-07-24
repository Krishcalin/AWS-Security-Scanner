"""Slice 3 · Batch 4 — CDR API routes on cnapp_api + service.ingest_detection
end-to-end: RBAC (admin ingest / viewer read), escalation to incidents, error
mapping (400 unknown source / cross-account ARN), synthetic-catalog reach. Skips
if fastapi is absent."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_api
import cnapp_connectors as cc

pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI,
                                reason="fastapi not installed (deploy-time dep)")

import aws_state
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"
INST = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
ROLE = f"arn:aws:iam::{ACCT}:role/r-1"
PROF = f"arn:aws:iam::{ACCT}:instance-profile/p-1"
BUCKET = "arn:aws:s3:::crown-data"
ADMIN = f"capability:admin:{ACCT}"


def _graph():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("eni-1", "NetworkInterface")
    g.add_node(INST, "EC2Instance", instance_id="i-1")
    g.add_edge("internet", "eni-1", "EXPOSED_TO")
    g.add_edge("eni-1", INST, "ATTACHED_TO")
    g.add_node(PROF, "InstanceProfile"); g.add_edge(INST, PROF, "HAS_INSTANCE_PROFILE")
    g.add_node(ROLE, "IAMRole"); g.add_edge(PROF, ROLE, "HAS_ROLE")
    g.add_node(BUCKET, "S3Bucket", crown_jewel=True)
    g.add_edge(ROLE, BUCKET, "CAN_READ_DATA", conditioned=False)
    g.add_node(ADMIN, "AdminCapability")
    g.add_edge(ROLE, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
    return g


def _svc(with_state=True):
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be) if with_state else None
    results = InMemoryResultStore()
    results.put(ACCT, {"account": ACCT, "graph_full": _graph().to_dict(),
                       "attack_paths": [], "finding_catalog": [], "results": []})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state, clock=lambda: 5000)


def _client(role="admin", svc=None):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc or _svc(), current_role=lambda: role))


def _gd_instance(fid="gd-1"):
    return {"Id": fid, "Type": "Backdoor:EC2/C&CActivity", "Title": "c2", "Severity": 8.0,
            "Service": {"Archived": False},
            "Resource": {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": "i-1"}}}


def _asff_bucket(fid="sh-1"):
    return {"Id": fid, "ProductArn": "arn:aws:securityhub:x", "Title": "public bucket",
            "Types": ["Effects/Data Exposure"], "Severity": {"Label": "CRITICAL"},
            "RecordState": "ACTIVE", "Workflow": {"Status": "NEW"},
            "Resources": [{"Id": BUCKET, "Type": "AwsS3Bucket"}]}


# ── RBAC ─────────────────────────────────────────────────────────────────────
def test_viewer_cannot_ingest_detections():
    r = _client("viewer").post(f"/accounts/{ACCT}/detections",
                               json={"events": _gd_instance(), "source": "guardduty"})
    assert r.status_code == 403


def test_admin_can_ingest_and_incident_surfaces():
    c = _client("admin")
    r = c.post(f"/accounts/{ACCT}/detections",
               json={"events": [_gd_instance()], "source": "guardduty"})
    assert r.status_code == 200
    body = r.json()
    assert body["normalized"] == 1 and body["incident_count"] == 1
    inc = c.get(f"/accounts/{ACCT}/incidents").json()
    assert len(inc) == 1 and inc[0]["node_id"] == INST and inc[0]["incident"] is True


def test_asff_crown_detection_is_incident():
    c = _client("admin")
    c.post(f"/accounts/{ACCT}/detections", json={"events": _asff_bucket(), "source": "securityhub"})
    inc = c.get(f"/accounts/{ACCT}/incidents").json()
    assert any(i["node_id"] == BUCKET and i["hits_crown"] for i in inc)


def test_unknown_source_400():
    r = _client("admin").post(f"/accounts/{ACCT}/detections",
                              json={"events": {}, "source": "nessus"})
    assert r.status_code == 400


def test_cross_account_arn_400():
    ev = {"Id": "x", "ProductArn": "p", "Title": "t", "Types": ["T"],
          "Severity": {"Label": "HIGH"}, "RecordState": "ACTIVE", "Workflow": {"Status": "NEW"},
          "Resources": [{"Id": "arn:aws:ec2:us-east-1:999999999999:instance/i-x"}]}
    r = _client("admin").post(f"/accounts/{ACCT}/detections",
                              json={"events": ev, "source": "securityhub"})
    assert r.status_code == 400


def test_list_detections_and_source_filter():
    c = _client("admin")
    c.post(f"/accounts/{ACCT}/detections", json={"events": _gd_instance(), "source": "guardduty"})
    c.post(f"/accounts/{ACCT}/detections", json={"events": _asff_bucket(), "source": "securityhub"})
    assert len(c.get(f"/accounts/{ACCT}/detections").json()) == 2
    gd = c.get(f"/accounts/{ACCT}/detections?source=guardduty").json()
    assert len(gd) == 1 and gd[0]["source"] == "guardduty"


def test_no_state_fail_open_list():
    c = _client("viewer", svc=_svc(with_state=False))
    assert c.get(f"/accounts/{ACCT}/detections").json() == []
    assert c.get(f"/accounts/{ACCT}/incidents").json() == []


def test_detection_reaches_findings_catalog():
    svc = _svc()
    svc.ingest_detection(ACCT, events=_asff_bucket(), source="securityhub")
    findings, _ = svc._enriched_findings(ACCT)
    assert any(f.check_id in ("THREAT-ING", "THREAT-ING-KEV") for f in findings)


def test_refresh_reevaluates():
    svc = _svc()
    svc.ingest_detection(ACCT, events=_gd_instance(), source="guardduty")
    out = svc.refresh_detection_escalation(ACCT)
    assert out["reevaluated"] == 1


def test_refresh_remaps_unmapped_detection():
    # adversarial-verify regression: a GuardDuty detection streamed BEFORE its resource is in the
    # graph is stored unmapped; once a later scan graphs the resource on an attack path, refresh
    # (which now restores node_key) must re-map + escalate it — not leave it permanently unmapped.
    svc = _svc()
    inst2 = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-2"
    gd2 = {"Id": "gd-2", "Type": "Backdoor:EC2/C&CActivity", "Title": "c2", "Severity": 8.0,
           "Service": {"Archived": False},
           "Resource": {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": "i-2"}}}
    svc.ingest_detection(ACCT, events=gd2, source="guardduty")
    r0 = [r for r in svc.list_detections(ACCT) if r["detection_id"] == "gd-2"][0]
    assert r0["mapping_status"] == "unmapped" and r0["incident"] is False
    # a later native scan lands a graph where i-2 sits on internet -> ... -> role -> admin
    g2 = _graph()
    g2.add_node(inst2, "EC2Instance", instance_id="i-2")
    g2.add_node("eni-2", "NetworkInterface")
    g2.add_edge("internet", "eni-2", "EXPOSED_TO")
    g2.add_edge("eni-2", inst2, "ATTACHED_TO")
    g2.add_edge(inst2, PROF, "HAS_INSTANCE_PROFILE")
    svc.results.put(ACCT, {"account": ACCT, "graph_full": g2.to_dict(), "attack_paths": [],
                           "finding_catalog": [], "results": []})
    out = svc.refresh_detection_escalation(ACCT)
    assert out["reevaluated"] >= 1
    r1 = [r for r in svc.list_detections(ACCT) if r["detection_id"] == "gd-2"][0]
    assert r1["mapping_status"] == "resolved" and r1["node_id"] == inst2 and r1["incident"] is True
