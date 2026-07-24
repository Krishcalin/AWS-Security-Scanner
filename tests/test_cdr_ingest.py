"""Slice 3 · Batch 3 — aws_cdr pure normalizers + node resolution + reachability
verdicts. No boto3; hand-built graph mirroring tests/test_ingest_service._graph_with_path."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_cdr as C
from aws_graph import SecurityGraph

ACCT = "111122223333"
INST = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
ROLE = f"arn:aws:iam::{ACCT}:role/r-1"
PROF = f"arn:aws:iam::{ACCT}:instance-profile/p-1"
BUCKET = "arn:aws:s3:::crown-data"
ADMIN = f"capability:admin:{ACCT}"


def _graph_with_path():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("eni-1", "NetworkInterface")
    g.add_node(INST, "EC2Instance", instance_id="i-1")
    g.add_edge("internet", "eni-1", "EXPOSED_TO", ports="tcp/443")
    g.add_edge("eni-1", INST, "ATTACHED_TO")
    g.add_node(PROF, "InstanceProfile")
    g.add_edge(INST, PROF, "HAS_INSTANCE_PROFILE")
    g.add_node(ROLE, "IAMRole", name="r-1")
    g.add_edge(PROF, ROLE, "HAS_ROLE")
    g.add_node(BUCKET, "S3Bucket", crown_jewel=True)
    g.add_edge(ROLE, BUCKET, "CAN_READ_DATA", conditioned=False)
    return g


def _graph_with_admin_path():
    # admin terminals need no vuln (ATTACK-01), so this yields a clean on-path fixture
    g = _graph_with_path()
    g.add_node(ADMIN, "AdminCapability")
    g.add_edge(ROLE, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
    return g


# ── normalize_guardduty ──────────────────────────────────────────────────────
def _gd_instance(fid="gd-1", archived=False, sample=False, sev=8.0):
    return {"Id": fid, "Type": "Backdoor:EC2/C&CActivity",
            "Title": "[SAMPLE] x" if sample else "Backdoor on instance",
            "Severity": sev, "Service": {"Archived": archived},
            "Resource": {"ResourceType": "Instance",
                         "InstanceDetails": {"InstanceId": "i-1"}}}


def test_normalize_guardduty_instance():
    d = C.normalize_guardduty(_gd_instance())
    assert d and d.node_kind == "EC2Instance" and d.node_key == "i-1" and d.band == "High"


def test_normalize_guardduty_skips_archived_and_sample():
    assert C.normalize_guardduty(_gd_instance(archived=True)) is None
    assert C.normalize_guardduty(_gd_instance(sample=True)) is None


def test_normalize_guardduty_accesskey_carries_key():
    f = {"Id": "gd-2", "Type": "UnauthorizedAccess:IAMUser/x", "Title": "creds",
         "Severity": 7.0, "Service": {"Archived": False},
         "Resource": {"ResourceType": "AccessKey",
                      "AccessKeyDetails": {"UserName": "alice", "AccessKeyId": "AKIA1"}}}
    d = C.normalize_guardduty(f)
    assert d.node_kind == "IAMPrincipal" and d.node_key == "alice"
    assert d.evidence["access_key_id"] == "AKIA1"


# ── normalize_asff ───────────────────────────────────────────────────────────
def _asff(state="ACTIVE", wf="NEW", label="HIGH", sample=False):
    return {"Id": "sh-1", "ProductArn": "arn:aws:securityhub:x",
            "Title": "[SAMPLE]" if sample else "S3 public",
            "Types": ["Effects/Data Exposure"], "Severity": {"Label": label},
            "RecordState": state, "Workflow": {"Status": wf},
            "Resources": [{"Id": BUCKET, "Type": "AwsS3Bucket"}]}


def test_normalize_asff_high():
    d = C.normalize_asff(_asff())
    assert d and d.resource_arn == BUCKET and d.band == "High" and d.source == "securityhub"


def test_normalize_asff_skips_archived_suppressed_resolved_sample():
    assert C.normalize_asff(_asff(state="ARCHIVED")) is None
    assert C.normalize_asff(_asff(wf="SUPPRESSED")) is None
    assert C.normalize_asff(_asff(wf="RESOLVED")) is None
    assert C.normalize_asff(_asff(sample=True)) is None


def test_normalize_asff_normalized_score_band():
    f = _asff()
    f["Severity"] = {"Normalized": 95}
    assert C.normalize_asff(f).band == "Critical"


# ── cloudtrail anomaly ───────────────────────────────────────────────────────
def test_detect_signals_root_and_tamper():
    ev = {"userIdentity": {"type": "Root", "arn": f"arn:aws:iam::{ACCT}:root"},
          "eventName": "StopLogging"}
    sigs = C.detect_cloudtrail_signals(ev)
    assert "root-usage" in sigs and "security-tooling-tamper" in sigs


def test_normalize_cloudtrail_none_when_no_signal():
    ev = {"userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCT}:user/bob"},
          "eventName": "DescribeInstances"}
    assert C.normalize_cloudtrail_anomaly(ev) is None


def test_normalize_cloudtrail_maps_to_principal():
    ev = {"userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCT}:user/bob"},
          "eventName": "CreateAccessKey", "eventID": "ct-1"}
    d = C.normalize_cloudtrail_anomaly(ev)
    assert d.source == "cloudtrail" and d.node_kind == "IAMPrincipal"
    assert d.resource_arn == f"arn:aws:iam::{ACCT}:user/bob"


# ── resolve_detection_node ───────────────────────────────────────────────────
def test_resolve_by_arn_exact_node():
    det = C.NormalizedDetection(id="d", source="s", type="t", title="", severity=5,
                                band="Medium", resource_arn=BUCKET)
    nid, kind, status = C.resolve_detection_node(_graph_with_path(), det, ACCT)
    assert nid == BUCKET and status == "resolved"


def test_resolve_guardduty_instance_by_id():
    det = C.normalize_guardduty(_gd_instance())
    nid, kind, status = C.resolve_detection_node(_graph_with_path(), det, ACCT)
    assert nid == INST and status == "resolved"


def test_resolve_cross_account_raises():
    det = C.NormalizedDetection(id="d", source="s", type="t", title="", severity=5,
                                band="Medium",
                                resource_arn="arn:aws:ec2:us-east-1:999999999999:instance/i-x")
    with pytest.raises(ValueError):
        C.resolve_detection_node(_graph_with_path(), det, ACCT)


def test_resolve_unmapped_synthetic():
    det = C.NormalizedDetection(id="d9", source="s", type="t", title="", severity=5,
                                band="Medium", node_kind="EC2Instance", node_key="i-ghost")
    nid, kind, status = C.resolve_detection_node(_graph_with_path(), det, ACCT)
    assert nid == "cdr:unmapped:d9" and status == "unmapped"


def test_resolve_iam_username_skips_non_principal_nodes():
    # adversarial-verify regression: a GuardDuty AccessKey detection whose UserName equals a
    # NON-principal IAM node's tail (instance-profile/policy/group) must NOT bind to it — else
    # a credential detection escalates on a node the credential never touched (phantom incident)
    g = SecurityGraph()
    g.add_node(f"arn:aws:iam::{ACCT}:instance-profile/appsvc", "InstanceProfile")
    g.add_node(f"arn:aws:iam::{ACCT}:policy/appsvc", "IAMPolicy")
    det = C.NormalizedDetection(id="gd-key", source="guardduty", type="t", title="",
                                severity=7.0, band="High",
                                node_kind="IAMPrincipal", node_key="appsvc")
    nid, kind, status = C.resolve_detection_node(g, det, ACCT)
    assert nid == "cdr:unmapped:gd-key" and status == "unmapped"


def test_resolve_iam_username_binds_real_principal():
    g = SecurityGraph()
    user = f"arn:aws:iam::{ACCT}:user/appsvc"
    g.add_node(user, "IAMUser", name="appsvc")
    det = C.NormalizedDetection(id="gd-k2", source="guardduty", type="t", title="",
                                severity=7.0, band="High",
                                node_kind="IAMPrincipal", node_key="appsvc")
    nid, kind, status = C.resolve_detection_node(g, det, ACCT)
    assert nid == user and status == "resolved"


# ── compute_detection_verdicts ───────────────────────────────────────────────
def test_detection_on_attack_path_is_incident():
    g = _graph_with_admin_path()
    det = C.normalize_guardduty(_gd_instance())
    verdicts, incidents, _ = C.compute_detection_verdicts(g.to_dict(), [det], ACCT)
    v = verdicts[det.id]
    assert v["on_attack_path"] and v["incident"]
    assert incidents and incidents[0]["id"] == det.id


def test_detection_on_crown_bucket_is_incident():
    det = C.NormalizedDetection(id="shX", source="securityhub", type="t", title="pub",
                                severity=7.5, band="High", resource_arn=BUCKET)
    verdicts, incidents, _ = C.compute_detection_verdicts(_graph_with_path().to_dict(),
                                                          [det], ACCT)
    v = verdicts[det.id]
    assert v["hits_crown_node"] and v["incident"]


def test_isolated_detection_not_incident():
    iso = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-orphan"
    det = C.NormalizedDetection(id="d0", source="guardduty", type="t", title="", severity=5,
                                band="Medium", resource_arn=iso)
    verdicts, incidents, _ = C.compute_detection_verdicts(_graph_with_admin_path().to_dict(),
                                                          [det], ACCT)
    v = verdicts[det.id]
    assert not v["on_attack_path"] and not v["hits_crown_node"] and not v["incident"]
    assert v["priority_band"] in ("MEDIUM", "LOW")


def test_honest_collapse_no_internet():
    d = _graph_with_path().to_dict()
    d["nodes"] = [n for n in d["nodes"] if n["id"] != "internet"]
    d["edges"] = [e for e in d["edges"] if e["source"] != "internet"]
    det = C.NormalizedDetection(id="d1", source="guardduty", type="t", title="", severity=8,
                                band="High", resource_arn=INST)
    v = C.compute_detection_verdicts(d, [det], ACCT)[0][det.id]
    assert v["on_attack_path"] is False and v["reachable_from_internet"] is False


def test_crown_detection_still_incident_without_internet():
    # a detection directly on a crown store is an incident even with no scan/internet node
    d = _graph_with_path().to_dict()
    d["nodes"] = [n for n in d["nodes"] if n["id"] != "internet"]
    det = C.NormalizedDetection(id="d2", source="securityhub", type="t", title="", severity=9,
                                band="Critical", resource_arn=BUCKET)
    v = C.compute_detection_verdicts(d, [det], ACCT)[0][det.id]
    assert v["hits_crown_node"] and v["incident"]


def test_dedup_same_detection_id():
    det = C.NormalizedDetection(id="dup", source="guardduty", type="t", title="", severity=8,
                                band="High", resource_arn=INST)
    verdicts, _, _ = C.compute_detection_verdicts(_graph_with_path().to_dict(), [det, det], ACCT)
    assert len(verdicts) == 1
