"""Coverage-close Batch 1 · Phase A — cost/hygiene findings (EBS-05 orphaned volumes,
EC2-09 unassociated EIPs, ELB-08 LB with no healthy backends, RDS-13 idle DB). All emit
WARN (=> severity LOW, ZERO posture-score impact — the score counts FAIL only), tagged
NIST CM-8 (already in the frozen 38-control universe). Read-only, fail-open, offline mocks."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_live_scanner import COMPLIANCE_MAP
from test_live_scanner import make_scanner, MockPaginator


def _client(paginators=None, **direct):
    """A boto3-client mock: get_paginator returns a configured page (empty for unknowns), and
    each keyword sets a direct-call return value. Lets a big _check_* method run to our check."""
    m = MagicMock()
    pag = paginators or {}
    m.get_paginator.side_effect = lambda name: pag.get(name, MockPaginator("_empty", []))
    for k, v in direct.items():
        getattr(m, k).return_value = v
    return m


def _finds(scanner, check_id):
    return [r for r in scanner.results if r.check_id == check_id]


# ── EBS-05 — orphaned (available/unattached) volumes ──────────────────────────
def test_ebs05_flags_only_available_volumes():
    s = make_scanner(sections=["EBS"])
    s._clients["ec2:us-east-1"] = _client(
        paginators={
            "describe_volumes": MockPaginator("Volumes", [
                {"VolumeId": "vol-orphan", "Encrypted": True, "State": "available"},
                {"VolumeId": "vol-inuse", "Encrypted": True, "State": "in-use"}]),
            "describe_snapshots": MockPaginator("Snapshots", [])},
        get_ebs_encryption_by_default={"EbsEncryptionByDefault": True})
    s._check_ebs()
    w = _finds(s, "EBS-05")
    assert len(w) == 1 and w[0].status == "WARN" and w[0].resource == "vol-orphan"
    assert w[0].severity == "LOW" and w[0].compliance == {"NIST": "CM-8"}


def test_ebs05_silent_when_all_attached():
    s = make_scanner(sections=["EBS"])
    s._clients["ec2:us-east-1"] = _client(
        paginators={"describe_volumes": MockPaginator("Volumes", [
            {"VolumeId": "vol-1", "Encrypted": True, "State": "in-use"}]),
            "describe_snapshots": MockPaginator("Snapshots", [])},
        get_ebs_encryption_by_default={"EbsEncryptionByDefault": True})
    s._check_ebs()
    assert _finds(s, "EBS-05") == []


# ── EC2-09 — unassociated Elastic IPs ─────────────────────────────────────────
def test_ec209_flags_unassociated_eip_only():
    s = make_scanner(sections=["EC2"])
    s._clients["ec2:us-east-1"] = _client(
        describe_addresses={"Addresses": [
            {"PublicIp": "1.2.3.4", "AllocationId": "eipalloc-orphan"},
            {"PublicIp": "5.6.7.8", "AllocationId": "eipalloc-used", "AssociationId": "eipassoc-9"}]},
        get_ebs_encryption_by_default={"EbsEncryptionByDefault": True})
    s._check_ec2()
    w = _finds(s, "EC2-09")
    assert len(w) == 1 and w[0].resource == "1.2.3.4" and w[0].compliance == {"NIST": "CM-8"}


# ── ELB-08 — load balancer with no healthy backends ───────────────────────────
def _elb_scanner(target_health_state):
    s = make_scanner(sections=["ELB"])
    s._clients["elbv2:us-east-1"] = _client(
        paginators={"describe_load_balancers": MockPaginator("LoadBalancers", [
            {"LoadBalancerArn": "arn:aws:elb:us-east-1:1:lb/app/x", "LoadBalancerName": "lb-x",
             "Type": "application", "Scheme": "internet-facing"}])},
        describe_load_balancer_attributes={"Attributes": []},
        describe_target_groups={"TargetGroups": [{"TargetGroupArn": "arn:tg-1"}]},
        describe_target_health={"TargetHealthDescriptions": [{"TargetHealth": {"State": target_health_state}}]},
        describe_listeners={"Listeners": []})
    s._check_elb()
    return s


def test_elb08_flags_lb_with_no_healthy_targets():
    w = _finds(_elb_scanner("unhealthy"), "ELB-08")
    assert len(w) == 1 and w[0].status == "WARN" and w[0].resource == "lb-x"


def test_elb08_silent_when_a_target_is_healthy():
    assert _finds(_elb_scanner("healthy"), "ELB-08") == []


# ── RDS-13 — idle database (zero connections) ─────────────────────────────────
def test_rds13_flags_idle_db_only():
    s = make_scanner(sections=["RDS"])
    s._clients["rds:us-east-1"] = _client(
        paginators={"describe_db_instances": MockPaginator("DBInstances", [
            {"DBInstanceIdentifier": "idle-db", "Engine": "mysql"},
            {"DBInstanceIdentifier": "busy-db", "Engine": "mysql"}])})
    cw = MagicMock()
    cw.get_metric_statistics.side_effect = lambda **kw: (
        {"Datapoints": [{"Maximum": 0.0}, {"Maximum": 0.0}]}
        if kw["Dimensions"][0]["Value"] == "idle-db"
        else {"Datapoints": [{"Maximum": 7.0}]})
    s._clients["cloudwatch:us-east-1"] = cw
    s._check_rds()
    w = _finds(s, "RDS-13")
    assert {r.resource for r in w} == {"idle-db"}
    assert w[0].compliance == {"NIST": "CM-8"}


def test_rds13_skips_db_with_no_datapoints():
    # no metric data (new/never-observed DB) must NOT be reported idle — avoid a false positive
    s = make_scanner(sections=["RDS"])
    s._clients["rds:us-east-1"] = _client(
        paginators={"describe_db_instances": MockPaginator("DBInstances", [
            {"DBInstanceIdentifier": "unknown-db", "Engine": "mysql"}])})
    cw = MagicMock()
    cw.get_metric_statistics.return_value = {"Datapoints": []}
    s._clients["cloudwatch:us-east-1"] = cw
    s._check_rds()
    assert _finds(s, "RDS-13") == []


# ── fail-open: a denied/throttled read must NOT emit a cost finding (no false CM-8 FAIL) ──
def test_ec209_fails_open_on_denied_describe_addresses():
    s = make_scanner(sections=["EC2"])
    ec2 = _client(get_ebs_encryption_by_default={"EbsEncryptionByDefault": True})
    ec2.describe_addresses.side_effect = Exception("AccessDenied: ec2:DescribeAddresses")
    s._clients["ec2:us-east-1"] = ec2
    s._check_ec2()
    assert _finds(s, "EC2-09") == []                 # fail-open: no finding, no CM-8 flip


def test_elb08_fails_open_on_denied_target_health():
    s = make_scanner(sections=["ELB"])
    elb = _client(
        paginators={"describe_load_balancers": MockPaginator("LoadBalancers", [
            {"LoadBalancerArn": "arn:x", "LoadBalancerName": "lb", "Type": "application", "Scheme": "internet-facing"}])},
        describe_load_balancer_attributes={"Attributes": []}, describe_listeners={"Listeners": []})
    elb.describe_target_groups.side_effect = Exception("Throttling")
    s._clients["elbv2:us-east-1"] = elb
    s._check_elb()
    assert _finds(s, "ELB-08") == []


def test_rds13_fails_open_on_denied_metric_read():
    s = make_scanner(sections=["RDS"])
    s._clients["rds:us-east-1"] = _client(
        paginators={"describe_db_instances": MockPaginator("DBInstances", [
            {"DBInstanceIdentifier": "db", "Engine": "mysql"}])})
    cw = MagicMock()
    cw.get_metric_statistics.side_effect = Exception("AccessDenied: cloudwatch:GetMetricStatistics")
    s._clients["cloudwatch:us-east-1"] = cw
    s._check_rds()
    assert _finds(s, "RDS-13") == []


# ── invariant guard: the 4 additions stay inside the frozen 38-control universe ──
def test_cost_findings_stay_in_frozen_nist_universe():
    universe = {m["NIST"] for m in COMPLIANCE_MAP.values() if m.get("NIST")}
    assert len(universe) == 38, f"NIST universe drifted to {len(universe)}"
    assert "CM-8" in universe
    for cid in ("EBS-05", "EC2-09", "ELB-08", "RDS-13"):
        assert COMPLIANCE_MAP[cid] == {"NIST": "CM-8"}
