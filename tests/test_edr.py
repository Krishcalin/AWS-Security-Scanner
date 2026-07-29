"""aws_edr — runtime-sensor (EDR/CWPP) ingest + coverage. Covers the four vendor normalizers
(CrowdStrike / Falco / GuardDuty-Runtime / OCSF), the [SAMPLE]/closed/band filters, the
sensor->workload-node join (reusing aws_cdr, incl. the cross-account guard + unmapped lane),
runtime_monitored stamping, the coverage math + attack-path-ranked gaps, and that a runtime
detection folds through the UNCHANGED aws_cdr/aws_correlate reachability into an incident.
Pure/offline; aws_correlate stays byte-frozen."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_cdr
import aws_edr
from aws_graph import SecurityGraph

WEB = "arn:aws:ec2:us-east-1:111122223333:instance/i-web"
QUIET = "arn:aws:ec2:us-east-1:111122223333:instance/i-quiet"
POD = "pod:default/api"
ADMIN = "cap:admin:111122223333"
CROWN = "arn:aws:s3:::crown-bucket"
ACCT = "111122223333"


def _graph():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node(WEB, "EC2Instance", instance_id="i-web", name="web-01")
    g.add_node(QUIET, "EC2Instance", instance_id="i-quiet", name="quiet-01")
    g.add_node(POD, "KubePod", name="api", namespace="default")
    g.add_node(ADMIN, "AdminCapability")
    g.add_node(CROWN, "S3Bucket", name="crown", crown_jewel=True)
    g.add_edge("internet", WEB, "EXPOSED_TO")
    g.add_edge(WEB, CROWN, "CAN_READ_DATA")
    return g


# ── normalizers ────────────────────────────────────────────────────────────────
def test_crowdstrike_maps_instance_and_mitre():
    d = aws_edr.normalize_crowdstrike({
        "composite_id": "cs1", "max_severity": 85, "status": "new",
        "behaviors": [{"description": "susp powershell", "tactic": "Execution", "technique_id": "T1059"}],
        "device": {"instance_id": "i-web", "hostname": "web-01", "device_id": "dev1"}})
    assert d.source == "crowdstrike" and d.band == "High"
    assert d.node_kind == "EC2Instance" and d.node_key == "i-web"
    assert d.evidence["technique"] == "T1059" and d.evidence["tactic"] == "Execution"


def test_falco_synthesizes_id_and_resolves_pod():
    d = aws_edr.normalize_falco({
        "rule": "Terminal shell in container", "priority": "Warning", "time": "2026-02-01T00:00:00Z",
        "output": "shell in api pod", "tags": ["T1059", "shell", "container"],
        "output_fields": {"k8s.pod.name": "api", "k8s.ns.name": "default", "container.id": "c1"}})
    assert d.source == "falco" and d.id.startswith("rt:") and d.band == "Medium"
    assert d.node_kind == "KubePod" and d.node_key == "default/api"   # namespaced to disambiguate
    assert d.evidence["technique"] == "T1059"


def test_guardduty_runtime_prefers_host_instance():
    d = aws_edr.normalize_guardduty_runtime({
        "Id": "gd1", "Type": "Execution:Runtime/ReverseShell", "Severity": 8.0, "Title": "Reverse shell",
        "Resource": {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": "i-web"}}})
    assert d.source == "guardduty-runtime" and d.band == "High"
    assert d.node_kind == "EC2Instance" and d.node_key == "i-web" and d.evidence["tactic"] == "Execution"


def test_ocsf_passthrough_severity_and_attack():
    d = aws_edr.normalize_ocsf({
        "severity_id": 5, "time": "t",
        "finding_info": {"uid": "o1", "title": "malware exec",
                         "attacks": [{"tactic": {"name": "Execution"}, "technique": {"uid": "T1204"}}]},
        "device": {"instance_uid": "i-web", "hostname": "web-01"}})
    assert d.source == "ocsf" and d.band == "Critical"
    assert d.node_kind == "EC2Instance" and d.node_key == "i-web"
    assert d.evidence["technique"] == "T1204"


def test_ocsf_resolves_explicit_arn():
    d = aws_edr.normalize_ocsf({
        "severity_id": 4, "finding_info": {"uid": "o2", "title": "x"},
        "resources": [{"uid": WEB}]})
    assert d.resource_arn == WEB


@pytest.mark.parametrize("ev", [
    {"rule": "x", "priority": "Notice", "output_fields": {}},          # below band floor
    {"rule": "x", "priority": "Debug", "output_fields": {}},
])
def test_falco_below_band_floor_dropped(ev):
    assert aws_edr.normalize_falco(ev) is None


def test_sample_and_closed_filtered():
    assert aws_edr.normalize_crowdstrike({"name": "[SAMPLE] test", "max_severity": 90, "device": {}}) is None
    assert aws_edr.normalize_crowdstrike({"status": "closed", "max_severity": 90,
                                          "behaviors": [{"description": "x"}], "device": {}}) is None
    assert aws_edr.normalize_ocsf({"severity_id": 6, "status": "Resolved",
                                   "finding_info": {"uid": "z", "title": "t"}}) is None


# ── dispatch ────────────────────────────────────────────────────────────────────
def test_normalize_dispatch_and_failsoft():
    got = aws_edr.normalize("guardduty-runtime", [
        {"Id": "a", "Type": "Execution:Runtime/X", "Severity": 8.0, "Resource": {"ResourceType": "Instance",
                                                                                 "InstanceDetails": {"InstanceId": "i-web"}}},
        {"garbage": True},          # fails soft -> dropped, no crash
    ])
    assert [d.id for d in got] == ["a"]


def test_normalize_unknown_source_raises():
    with pytest.raises(ValueError):
        aws_edr.normalize("sentinelone-native", [{}])


# ── sensor join + runtime_monitored ─────────────────────────────────────────────
def test_resolve_sensor_by_instance_and_pod():
    g = _graph()
    assert aws_edr.resolve_sensor_node(g, aws_edr.SensorRecord(vendor="cs", instance_id="i-web"), ACCT) == WEB
    assert aws_edr.resolve_sensor_node(g, aws_edr.SensorRecord(vendor="falco", pod_name="api"), ACCT) == POD


def test_resolve_sensor_unmapped_is_none():
    g = _graph()
    assert aws_edr.resolve_sensor_node(g, aws_edr.SensorRecord(vendor="cs", instance_id="i-ghost"), ACCT) is None


def test_cross_account_sensor_ignored_not_crashed():
    g = _graph()
    other = aws_edr.SensorRecord(vendor="cs", resource_arn="arn:aws:ec2:us-east-1:999999999999:instance/i-x")
    ids = aws_edr.monitored_node_ids(g, [other], ACCT)     # cross-account ARN -> ValueError swallowed
    assert ids == set()


def test_apply_runtime_monitored_stamps_and_is_idempotent():
    g = _graph()
    sensors = [aws_edr.SensorRecord(vendor="cs", instance_id="i-web")]
    n1 = aws_edr.apply_runtime_monitored(g, sensors, ACCT)
    n2 = aws_edr.apply_runtime_monitored(g, sensors, ACCT)
    assert n1 == 1 and n2 == 1
    assert (g.node(WEB)["props"] or {}).get("runtime_monitored") is True
    assert "runtime_monitored" not in (g.node(QUIET)["props"] or {})    # unmonitored untouched


# ── coverage + gaps ─────────────────────────────────────────────────────────────
def test_coverage_math_and_gap_ranking():
    g = _graph()
    sensors = [aws_edr.SensorRecord(vendor="cs", instance_id="i-web"),
               aws_edr.SensorRecord(vendor="falco", pod_name="api")]
    cov = aws_edr.compute_coverage(g, sensors, ACCT)
    assert cov["overall"] == {"monitored": 2, "total": 3, "pct": 66.7}
    assert cov["per_kind"]["EC2Instance"] == {"monitored": 1, "total": 2, "pct": 50.0}
    assert cov["per_kind"]["KubePod"] == {"monitored": 1, "total": 1, "pct": 100.0}
    # only the unmonitored quiet EC2 is a gap; it is isolated -> rank 0
    assert [g_["node_id"] for g_ in cov["gaps"]] == [QUIET]
    assert cov["gaps"][0]["exposure_rank"] == 0


def test_gap_ranking_exposed_crown_bound_first():
    # an UNMONITORED workload that is internet-reachable AND on a path to crown is the headline gap
    g = _graph()
    g.add_node("arn:aws:ec2:us-east-1:111122223333:instance/i-exposed", "EC2Instance", instance_id="i-exposed")
    g.add_edge("internet", "arn:aws:ec2:us-east-1:111122223333:instance/i-exposed", "EXPOSED_TO")
    g.add_edge("arn:aws:ec2:us-east-1:111122223333:instance/i-exposed", CROWN, "CAN_READ_DATA")
    cov = aws_edr.compute_coverage(g, [], ACCT)            # no sensors -> everything is a gap
    top = cov["gaps"][0]
    assert top["node_id"].endswith("i-exposed")
    assert top["reachable_from_internet"] and top["reaches_crown"] and top["exposure_rank"] == 3


def test_coverage_without_internet_node_is_honest():
    g = SecurityGraph()
    g.add_node(WEB, "EC2Instance", instance_id="i-web")
    cov = aws_edr.compute_coverage(g, [], ACCT)
    assert cov["overall"]["total"] == 1 and cov["overall"]["monitored"] == 0
    assert cov["gaps"][0]["exposure_rank"] == 0            # no reachability -> no fabricated exposure


# ── the reuse contract: a runtime detection escalates via aws_cdr UNCHANGED ─────
def test_runtime_detection_folds_into_incident_via_cdr():
    g = _graph()
    # give the exposed host a privilege-escalation route to admin (admin terminals need no vuln),
    # so it sits on a real internet->admin attack path — the case where a runtime alert escalates.
    role = "arn:aws:iam::111122223333:role/app-role"
    g.add_node(role, "IAMRole", name="app-role")
    g.add_edge(WEB, role, "HAS_ROLE")
    g.add_edge(role, ADMIN, "CAN_PRIVESC_TO")
    dets = aws_edr.normalize("crowdstrike", [{
        "composite_id": "cs-inc", "max_severity": 95, "status": "new",
        "behaviors": [{"description": "cred theft", "tactic": "CredentialAccess", "technique_id": "T1552"}],
        "device": {"instance_id": "i-web"}}])
    verdicts, incidents, _ = aws_cdr.compute_detection_verdicts(g.to_dict(), dets, ACCT)
    v = verdicts["cs-inc"]
    assert v["node_id"] == WEB and v["source"] == "crowdstrike"
    # i-web is internet-exposed and can escalate to admin -> the runtime alert is an incident
    assert v["on_attack_path"] and v["incident"]
    assert any(i["id"] == "cs-inc" for i in incidents)


def test_correlate_is_untouched_by_edr_import():
    import aws_correlate
    assert "THREAT_ON" not in aws_correlate.E_PATH        # runtime alerts never become a hop
    assert "RUNTIME_ALERT" not in aws_correlate.E_PATH


# ── adversarial-verify regressions (Batch 3) ────────────────────────────────────
def test_offline_sensor_is_not_coverage():
    # an offline/degraded agent must NOT count as coverage (else the metric is inflated and a
    # real blind spot is hidden). Absent status is still healthy.
    g = _graph()
    assert aws_edr.monitored_node_ids(g, [aws_edr.SensorRecord(vendor="cs", instance_id="i-web", status="offline")], ACCT) == set()
    assert aws_edr.monitored_node_ids(g, [aws_edr.SensorRecord(vendor="cs", instance_id="i-web", status="degraded")], ACCT) == set()
    assert aws_edr.monitored_node_ids(g, [aws_edr.SensorRecord(vendor="cs", instance_id="i-web", status="healthy")], ACCT) == {WEB}
    assert aws_edr.monitored_node_ids(g, [aws_edr.SensorRecord(vendor="cs", instance_id="i-web")], ACCT) == {WEB}


def test_ocsf_closed_by_status_id_is_dropped():
    # a Resolved/Suppressed OCSF finding carrying only the integer status_id must be filtered
    for sid in (3, 4):
        assert aws_edr.normalize_ocsf({"severity_id": 5, "status_id": sid,
                                       "finding_info": {"uid": "o", "title": "reverse shell"},
                                       "device": {"instance_uid": "i-web"}}) is None
    # an active finding (status_id 1 = New) still passes
    assert aws_edr.normalize_ocsf({"severity_id": 5, "status_id": 1,
                                   "finding_info": {"uid": "o2", "title": "x"},
                                   "device": {"instance_uid": "i-web"}}) is not None


def test_crowdstrike_ignored_is_dropped():
    assert aws_edr.normalize_crowdstrike({"status": "ignored", "max_severity": 95,
                                          "behaviors": [{"description": "cred dumping"}],
                                          "device": {"instance_id": "i-web"}}) is None


def test_kubepod_namespace_disambiguates_same_name():
    # two StatefulSet pods named 'web-0' in different namespaces must not mis-bind
    g = SecurityGraph()
    prod = "k8s:pod:cl:prod:web-0"
    staging = "k8s:pod:cl:staging:web-0"
    g.add_node(prod, "KubePod", name="web-0", namespace="prod")
    g.add_node(staging, "KubePod", name="web-0", namespace="staging")
    d = aws_edr.normalize_falco({"rule": "shell", "priority": "Critical", "time": "t",
                                 "output_fields": {"k8s.pod.name": "web-0", "k8s.ns.name": "staging"}})
    node_id, _, status = aws_cdr.resolve_detection_node(g, d, ACCT)
    assert node_id == staging and status == "resolved"    # bound to staging, not prod
    # a sensor for the prod pod binds to prod
    assert aws_edr.resolve_sensor_node(g, aws_edr.SensorRecord(vendor="falco", pod_name="web-0", pod_namespace="prod"), ACCT) == prod
