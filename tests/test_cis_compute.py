"""Driving tests for the 43 CIS AWS Compute Services Benchmark checks.

WHY THIS FILE HAS TO EXIST. `docs/CHECK_FIRING.md` exists because this codebase has
repeatedly shipped checks that were registered in all five projections, counted in the
published total, and could not fire. Adding forty-three checks in one commit is the
single most likely way to do that again, so every one of them is driven here to an actual
FAIL through `AWSLiveScanner`, not through its evaluator.

WHAT `_renders` ASSERTS, AND WHY IT IS NOT JUST THE STATUS. `_add` reads severity,
compliance and remediation from the catalogue for a FAIL and for no other status: a WARN
is forced to LOW and carries no remediation. So "the check fired" and "the finding
renders what the catalogue promises for it" are different claims, and only the second one
is worth anything to an operator reading the report. Every case below asserts the second.

THE NEGATIVE CASES ARE NOT DECORATION. A check that fires unconditionally is worse than
no check, because it trains people to filter the id out. Each control here has at least
one case proving the compliant configuration is silent.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import date, datetime, timedelta, timezone
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_cis_compute as C                              # noqa: E402
# MockClientError, not botocore's: `ClientError` is bound in aws_live_scanner only when
# boto3 imported, and the scanner reads the error code off the exception for exactly that
# reason (see AWSLiveScanner._error_code). A fixture raising the real type would test a
# path production does not take.
from test_live_scanner import MockClientError, make_scanner          # noqa: E402

OWN = "123456789012"
OTHER = "999988887777"
NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
TODAY = date(2026, 9, 1)


# ── shared helpers ───────────────────────────────────────────────────────────
def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _renders(s, cid, expected_severity, contains=None):
    """The finding fired AND carries what the catalogue holds for it."""
    hits = _ids(s, cid, "FAIL")
    assert hits, f"{cid} did not FAIL"
    r = hits[0]
    assert r.severity == expected_severity, (
        f"{cid} rendered {r.severity!r}, catalogue says {expected_severity!r}")
    assert r.remediation_cmd, f"{cid} FAIL carries no remediation command"
    assert r.compliance, f"{cid} FAIL carries no compliance mapping"
    assert "CIS-COMPUTE" in r.compliance, (
        f"{cid} is a Compute-benchmark control and carries no CIS-COMPUTE citation")
    if contains:
        assert contains in r.message, f"{cid} message lacks {contains!r}: {r.message}"
    return r


class _Pager:
    """A boto3 paginator yielding exactly one page."""

    def __init__(self, key, items):
        self._key, self._items = key, items

    def paginate(self, **kw):
        return [{self._key: self._items}]


def _pagers(**by_method):
    """get_paginator side-effect: method name -> (key, items)."""
    def _get(method):
        if method not in by_method:
            raise RuntimeError(f"no paginator configured for {method}")
        key, items = by_method[method]
        return _Pager(key, items)
    return _get


# ══════════════════════════════════════════════════════════════════════════════
# AMI-04 / AMI-05 — CIS-Compute 2.1.1, 2.1.3
# ══════════════════════════════════════════════════════════════════════════════
def _ami_scanner(images, instances=(), described=None, pattern=None):
    s = make_scanner(sections=["AMI"])
    s.account = OWN
    s.ami_name_pattern = pattern
    ec2 = MagicMock()
    ec2.describe_images.side_effect = lambda **kw: (
        {"Images": list(described)} if "ImageIds" in kw else {"Images": list(images)})
    ec2.describe_image_attribute.return_value = {"LaunchPermissions": []}
    ec2.get_paginator.side_effect = _pagers(
        describe_instances=("Reservations", [{"Instances": list(instances)}]))
    s._clients["ec2:us-east-1"] = ec2
    return s


def test_ami04_name_outside_the_convention_fails():
    s = _ami_scanner([{"ImageId": "ami-1", "Name": "scratch-build",
                       "BlockDeviceMappings": [{"Ebs": {"Encrypted": True}}]}],
                     pattern=r"^golden-[a-z]+-\d{8}$")
    s._check_ami()
    _renders(s, "AMI-04", "LOW", contains="does not match")


def test_ami04_is_not_evaluated_without_a_configured_convention():
    """The default. Guessing a convention would fail correct estates, so the check says
    so rather than passing or failing."""
    s = _ami_scanner([{"ImageId": "ami-1", "Name": "anything",
                       "BlockDeviceMappings": [{"Ebs": {"Encrypted": True}}]}])
    s._check_ami()
    assert not _ids(s, "AMI-04", "FAIL")
    info = _ids(s, "AMI-04", "INFO")
    assert info and "NOT EVALUATED" in info[0].message


def test_ami04_conforming_name_passes():
    s = _ami_scanner([{"ImageId": "ami-1", "Name": "golden-base-20260101",
                       "BlockDeviceMappings": [{"Ebs": {"Encrypted": True}}]}],
                     pattern=r"^golden-[a-z]+-\d{8}$")
    s._check_ami()
    assert not _ids(s, "AMI-04", "FAIL")
    assert _ids(s, "AMI-04", "PASS")


def test_ami05_third_party_image_fails():
    inst = {"InstanceId": "i-1", "ImageId": "ami-x", "State": {"Name": "running"}}
    s = _ami_scanner([], instances=[inst],
                     described=[{"ImageId": "ami-x", "OwnerId": OTHER, "Public": True}])
    s._check_ami()
    _renders(s, "AMI-05", "MEDIUM", contains=OTHER)


def test_ami05_amazon_owned_and_self_owned_are_silent():
    insts = [{"InstanceId": "i-1", "ImageId": "ami-a", "State": {"Name": "running"}},
             {"InstanceId": "i-2", "ImageId": "ami-b", "State": {"Name": "running"}}]
    s = _ami_scanner([], instances=insts, described=[
        {"ImageId": "ami-a", "OwnerId": "137112412989", "ImageOwnerAlias": "amazon"},
        {"ImageId": "ami-b", "OwnerId": OWN}])
    s._check_ami()
    assert not _ids(s, "AMI-05", "FAIL")
    assert _ids(s, "AMI-05", "PASS")


def test_ami05_unresolvable_image_is_not_reported_as_untrusted():
    """A deregistered or invisible AMI is unknown provenance, not bad provenance."""
    r = C.ami_provenance({"InstanceId": "i-1", "ImageId": "ami-gone"}, None, OWN)
    assert r["untrusted"] is False and r["known"] is False


# ══════════════════════════════════════════════════════════════════════════════
# EC2-10 / EC2-11 — CIS-Compute 2.3, 2.4  (Organizations tag policy)
# ══════════════════════════════════════════════════════════════════════════════
def _org_scanner(policies, contents=None):
    s = make_scanner(sections=["EC2"])
    s.account = OWN
    org = MagicMock()
    org.get_paginator.side_effect = _pagers(list_policies=("Policies", list(policies)))
    org.describe_policy.side_effect = lambda PolicyId: {
        "Policy": {"Content": json.dumps((contents or {}).get(PolicyId, {}))}}
    s._clients["organizations:us-east-1"] = org
    return s


def test_ec210_no_tag_policy_fails():
    s = _org_scanner([])
    s._check_ec2_tag_policy()
    _renders(s, "EC2-10", "LOW", contains="no tag policy")


def test_ec211_tag_policy_that_ignores_ec2_fails():
    pol = {"tags": {"Environment": {"enforced_for": {"@@assign": ["s3:bucket"]}}}}
    s = _org_scanner([{"Id": "p-1"}], {"p-1": pol})
    s._check_ec2_tag_policy()
    assert _ids(s, "EC2-10", "PASS")
    _renders(s, "EC2-11", "LOW", contains="none of them enforces")


def test_ec211_tag_policy_covering_ec2_passes():
    pol = {"tags": {"Owner": {"enforced_for": {"@@assign": ["ec2:instance",
                                                            "ec2:volume"]}}}}
    s = _org_scanner([{"Id": "p-1"}], {"p-1": pol})
    s._check_ec2_tag_policy()
    assert not _ids(s, "EC2-11", "FAIL")
    assert _ids(s, "EC2-11", "PASS")


def test_ec210_absent_organization_is_not_evaluated_rather_than_failed():
    """A standalone account cannot have an organisational tag policy, and a member
    account is normally refused ListPolicies. Neither is an actionable finding."""
    s = make_scanner(sections=["EC2"])
    org = MagicMock()
    org.get_paginator.side_effect = RuntimeError("AWSOrganizationsNotInUseException")
    org.list_policies.side_effect = RuntimeError("AWSOrganizationsNotInUseException")
    s._clients["organizations:us-east-1"] = org
    s._check_ec2_tag_policy()
    assert not _ids(s, "EC2-10", "FAIL")
    assert _ids(s, "EC2-10", "INFO")


# ══════════════════════════════════════════════════════════════════════════════
# EC2-12..EC2-17, ASG-02 — CIS-Compute 2.5, 2.6, 2.7, 2.10, 2.11, 2.12, 2.14
# ══════════════════════════════════════════════════════════════════════════════
DEFAULT_SG = "sg-default"


def _hygiene_scanner(instances, *, enis=(), asgs=(), default_sgs=(DEFAULT_SG,)):
    s = make_scanner(sections=["EC2"])
    s.account = OWN
    s._today = TODAY
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _pagers(
        describe_security_groups=("SecurityGroups",
                                  [{"GroupId": g, "GroupName": "default"}
                                   for g in default_sgs]),
        describe_instances=("Reservations", [{"Instances": list(instances)}]),
        describe_network_interfaces=("NetworkInterfaces", list(enis)))
    s._clients["ec2:us-east-1"] = ec2
    asg_client = MagicMock()
    asg_client.get_paginator.side_effect = _pagers(
        describe_auto_scaling_groups=("AutoScalingGroups", list(asgs)))
    s._clients["autoscaling:us-east-1"] = asg_client
    return s


def _running(iid="i-1", **kw):
    base = {"InstanceId": iid, "State": {"Name": "running"},
            "LaunchTime": NOW - timedelta(days=5),
            "Monitoring": {"State": "enabled"},
            "SecurityGroups": [{"GroupId": "sg-app"}],
            "BlockDeviceMappings": []}
    base.update(kw)
    return base


def test_ec212_instance_running_past_180_days_fails():
    s = _hygiene_scanner([_running(LaunchTime=NOW - timedelta(days=400))])
    s._check_ec2_hygiene()
    _renders(s, "EC2-12", "LOW", contains="400 days")


def test_ec213_basic_monitoring_fails():
    s = _hygiene_scanner([_running(Monitoring={"State": "disabled"})])
    s._check_ec2_hygiene()
    _renders(s, "EC2-13", "LOW", contains="detailed monitoring")


def test_ec214_default_security_group_membership_fails():
    s = _hygiene_scanner([_running(SecurityGroups=[{"GroupId": DEFAULT_SG}])])
    s._check_ec2_hygiene()
    _renders(s, "EC2-14", "MEDIUM", contains=DEFAULT_SG)


def test_ec215_detached_eni_fails():
    s = _hygiene_scanner([_running()], enis=[
        {"NetworkInterfaceId": "eni-1", "Status": "available",
         "PrivateIpAddress": "10.0.0.9", "SubnetId": "subnet-1"}])
    s._check_ec2_hygiene()
    _renders(s, "EC2-15", "LOW", contains="eni-1")


def test_ec216_long_stopped_instance_fails_and_uses_the_stop_time():
    """The benchmark's audit reads LaunchTime, which for a stopped instance is when it
    last STARTED. StateTransitionReason carries the actual stop time, so it wins."""
    inst = _running("i-old", State={"Name": "stopped"},
                    LaunchTime=NOW - timedelta(days=800),
                    StateTransitionReason="User initiated (2026-01-02 10:00:00 GMT)")
    s = _hygiene_scanner([inst])
    s._check_ec2_hygiene()
    r = _renders(s, "EC2-16", "LOW", contains="by stop time")
    # 2026-01-02 10:00 UTC to 2026-09-01 00:00 UTC is 241 whole days -- the stop time is
    # used, not the 800-day LaunchTime, which is the whole point of the case.
    assert "241 days" in r.message, r.message


def test_ec216_falls_back_to_launch_time_when_the_reason_is_unparseable():
    inst = _running("i-old", State={"Name": "stopped"},
                    LaunchTime=NOW - timedelta(days=300),
                    StateTransitionReason="User initiated")
    s = _hygiene_scanner([inst])
    s._check_ec2_hygiene()
    assert "by last start" in _ids(s, "EC2-16", "FAIL")[0].message


def test_ec216_recently_stopped_instance_is_silent():
    inst = _running("i-new", State={"Name": "stopped"},
                    StateTransitionReason="User initiated (2026-08-25 10:00:00 GMT)")
    s = _hygiene_scanner([inst])
    s._check_ec2_hygiene()
    assert not _ids(s, "EC2-16", "FAIL")


def test_ec217_volume_surviving_termination_fails():
    s = _hygiene_scanner([_running(BlockDeviceMappings=[
        {"DeviceName": "/dev/sdb",
         "Ebs": {"VolumeId": "vol-9", "DeleteOnTermination": False}}])])
    s._check_ec2_hygiene()
    _renders(s, "EC2-17", "LOW", contains="vol-9")


def test_asg02_tags_that_do_not_propagate_fail():
    s = _hygiene_scanner([_running()], asgs=[
        {"AutoScalingGroupName": "web",
         "Tags": [{"Key": "Environment", "PropagateAtLaunch": False}]}])
    s._check_ec2_hygiene()
    _renders(s, "ASG-02", "LOW", contains="PropagateAtLaunch=false")


def test_asg02_untagged_group_fails_for_the_other_reason():
    s = _hygiene_scanner([_running()], asgs=[{"AutoScalingGroupName": "web", "Tags": []}])
    s._check_ec2_hygiene()
    _renders(s, "ASG-02", "LOW", contains="carries no tags at all")


def test_a_clean_estate_emits_no_hygiene_failures():
    """One healthy instance, one attached ENI, one propagating ASG: silence on all six,
    and the PASS lines that say so."""
    s = _hygiene_scanner(
        [_running()],
        enis=[{"NetworkInterfaceId": "eni-1", "Status": "in-use"}],
        asgs=[{"AutoScalingGroupName": "web",
               "Tags": [{"Key": "Owner", "PropagateAtLaunch": True}]}])
    s._check_ec2_hygiene()
    for cid in ("EC2-12", "EC2-13", "EC2-14", "EC2-15", "EC2-16", "EC2-17", "ASG-02"):
        assert not _ids(s, cid, "FAIL"), cid
    for cid in ("EC2-12", "EC2-13", "EC2-14", "EC2-15", "EC2-17", "ASG-02"):
        assert _ids(s, cid, "PASS"), f"{cid} emitted no PASS on a clean estate"


def test_a_denied_instance_read_produces_silence_not_a_false_clean():
    s = _hygiene_scanner([])
    s._clients["ec2:us-east-1"].get_paginator.side_effect = RuntimeError("AccessDenied")
    s._check_ec2_hygiene()
    assert not [r for r in s.results if r.status in ("PASS", "FAIL")]


# ══════════════════════════════════════════════════════════════════════════════
# ECS-09..ECS-17, FARGATE-03 — CIS-Compute 3.8-3.16 and 11.1
# ══════════════════════════════════════════════════════════════════════════════
CARN = f"arn:aws:ecs:us-east-1:{OWN}:cluster/prod"


def _cluster(**kw):
    base = {"clusterName": "prod", "clusterArn": CARN,
            "settings": [{"name": "containerInsights", "value": "enhanced"}],
            "configuration": {
                "executeCommandConfiguration": {"logging": "OVERRIDE"},
                "managedStorageConfiguration": {
                    "fargateEphemeralStorageKmsKeyId": "arn:aws:kms:::key/cmk"}},
            "tags": [{"key": "Owner", "value": "platform"}]}
    base.update(kw)
    return base


def _service(**kw):
    base = {"serviceName": "web", "serviceArn": f"{CARN}/web",
            "launchType": "FARGATE", "platformVersion": "LATEST",
            "platformFamily": "Linux", "enableExecuteCommand": False,
            "tags": [{"key": "Owner", "value": "platform"}]}
    base.update(kw)
    return base


def _taskdef(**kw):
    base = {"family": "app", "networkMode": "awsvpc",
            "containerDefinitions": [{
                "name": "app",
                "image": f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/app@sha256:" + "a" * 64,
                "user": "1000", "logConfiguration": {"logDriver": "awslogs"},
                "readonlyRootFilesystem": True}]}
    base.update(kw)
    return base


def _ecs_scanner(*, clusters=None, services=(), taskdefs=(), task_sets=(),
                 td_tags=(("Owner", "platform"),)):
    s = make_scanner(sections=["ECS"])
    s.account = OWN
    ecs = MagicMock()
    ecs.list_clusters.return_value = {"clusterArns": [CARN]}
    ecs.describe_clusters.return_value = {
        "clusters": list(clusters if clusters is not None else [_cluster()])}
    ecs.list_task_definitions.return_value = {
        "taskDefinitionArns": [f"td-{i}" for i in range(len(taskdefs))]}
    tds = list(taskdefs)
    ecs.describe_task_definition.side_effect = lambda taskDefinition, **kw: {
        "taskDefinition": tds[int(str(taskDefinition).split("-")[-1])],
        "tags": [{"key": k, "value": v} for k, v in td_tags]}
    ecs.describe_services.return_value = {"services": list(services)}
    ecs.describe_task_sets.return_value = {"taskSets": list(task_sets)}
    ecs.get_paginator.side_effect = _pagers(
        list_services=("serviceArns", [f"{CARN}/{sv['serviceName']}" for sv in services]))
    s._clients["ecs:us-east-1"] = ecs
    return s, ecs


def test_ecs09_pinned_fargate_platform_version_fails():
    s, ecs = _ecs_scanner(services=[_service(platformVersion="1.3.0")])
    s._check_ecs_cis(ecs, [CARN])
    _renders(s, "ECS-09", "MEDIUM", contains="1.3.0")


def test_ecs09_latest_and_a_supported_pin_are_silent():
    s, ecs = _ecs_scanner(services=[_service(), _service(serviceName="api",
                                                         platformVersion="1.4.0")])
    s._check_ecs_cis(ecs, [CARN])
    assert not _ids(s, "ECS-09", "FAIL")


def test_ecs09_ignores_an_ec2_launch_type_service():
    """Platform version is a Fargate concept. An EC2-launch-type service has none, and
    reporting one would be a finding with no remediation."""
    s, ecs = _ecs_scanner(services=[_service(launchType="EC2", platformVersion="1.0.0",
                                             capacityProviderStrategy=[])])
    s._check_ecs_cis(ecs, [CARN])
    assert not _ids(s, "ECS-09", "FAIL")


def test_ecs10_container_insights_disabled_fails():
    s, ecs = _ecs_scanner(clusters=[_cluster(settings=[])])
    s._check_ecs_cis(ecs, [CARN])
    _renders(s, "ECS-10", "LOW", contains="Container Insights")


def test_ecs10_enhanced_counts_as_enabled():
    s, ecs = _ecs_scanner()
    s._check_ecs_cis(ecs, [CARN])
    assert not _ids(s, "ECS-10", "FAIL") and _ids(s, "ECS-10", "PASS")


def test_ecs11_untagged_service_fails():
    s, ecs = _ecs_scanner(services=[_service(tags=[])])
    s._check_ecs_cis(ecs, [CARN])
    _renders(s, "ECS-11", "LOW", contains="carries no tags")


def test_ecs12_untagged_cluster_fails():
    s, ecs = _ecs_scanner(clusters=[_cluster(tags=[])])
    s._check_ecs_cis(ecs, [CARN])
    _renders(s, "ECS-12", "LOW", contains="carries no tags")


def test_ecs13_untagged_task_definition_fails():
    s, _ = _ecs_scanner(taskdefs=[_taskdef()], td_tags=())
    s._check_ecs()
    _renders(s, "ECS-13", "LOW", contains="task definition app")


def test_ecs14_image_from_outside_the_estate_fails():
    td = _taskdef(containerDefinitions=[
        {"name": "app", "image": "docker.io/library/nginx:latest", "user": "1000",
         "logConfiguration": {"logDriver": "awslogs"}, "readonlyRootFilesystem": True}])
    s, _ = _ecs_scanner(taskdefs=[td])
    s._check_ecs()
    _renders(s, "ECS-14", "MEDIUM", contains="nginx")


def test_ecs14_digest_pinned_ecr_image_in_this_account_is_silent():
    s, _ = _ecs_scanner(taskdefs=[_taskdef()])
    s._check_ecs()
    assert not _ids(s, "ECS-14", "FAIL")


def test_ecs14_ecr_repository_in_a_trusted_account_is_silent():
    td = _taskdef(containerDefinitions=[
        {"name": "app",
         "image": f"{OTHER}.dkr.ecr.us-east-1.amazonaws.com/shared:v1",
         "user": "1000", "logConfiguration": {"logDriver": "awslogs"},
         "readonlyRootFilesystem": True}])
    s, _ = _ecs_scanner(taskdefs=[td])
    s.trusted_accounts = {OTHER}
    s._check_ecs()
    assert not _ids(s, "ECS-14", "FAIL")


def test_ecs15_task_set_with_a_public_ip_fails():
    s, ecs = _ecs_scanner(
        services=[_service()],
        task_sets=[{"id": "ts-1", "networkConfiguration": {
            "awsvpcConfiguration": {"assignPublicIp": "ENABLED"}}}])
    s._check_ecs_cis(ecs, [CARN])
    _renders(s, "ECS-15", "HIGH", contains="ts-1")


def test_ecs15_disabled_task_set_is_silent():
    s, ecs = _ecs_scanner(
        services=[_service()],
        task_sets=[{"id": "ts-1", "networkConfiguration": {
            "awsvpcConfiguration": {"assignPublicIp": "DISABLED"}}}])
    s._check_ecs_cis(ecs, [CARN])
    assert not _ids(s, "ECS-15", "FAIL")


def test_ecs16_bridge_network_mode_fails():
    s, _ = _ecs_scanner(taskdefs=[_taskdef(networkMode="bridge")])
    s._check_ecs()
    _renders(s, "ECS-16", "LOW", contains="networkMode=bridge")


def test_ecs16_leaves_host_mode_to_ecs06():
    """ECS-06 owns `host` and calls it an escape primitive. Reporting it twice under two
    ids would double-count one problem."""
    s, _ = _ecs_scanner(taskdefs=[_taskdef(networkMode="host")])
    s._check_ecs()
    assert not _ids(s, "ECS-16", "FAIL")
    assert _ids(s, "ECS-06", "FAIL")


def test_ecs17_exec_enabled_without_session_logging_fails():
    s, ecs = _ecs_scanner(
        clusters=[_cluster(configuration={"executeCommandConfiguration":
                                          {"logging": "DEFAULT"}})],
        services=[_service(enableExecuteCommand=True)])
    s._check_ecs_cis(ecs, [CARN])
    _renders(s, "ECS-17", "HIGH", contains="ECS Exec enabled")


def test_ecs17_is_silent_where_nobody_can_open_a_session():
    """A cluster with no Exec-enabled service has nothing to log. Failing it would be a
    finding on a cluster with no exposure, which is how a check gets filtered out."""
    s, ecs = _ecs_scanner(
        clusters=[_cluster(configuration={"executeCommandConfiguration":
                                          {"logging": "NONE"}})],
        services=[_service(enableExecuteCommand=False)])
    s._check_ecs_cis(ecs, [CARN])
    assert not _ids(s, "ECS-17")


def test_fargate03_aws_owned_ephemeral_key_fails():
    s, ecs = _ecs_scanner(clusters=[_cluster(configuration={})])
    s._check_ecs_cis(ecs, [CARN])
    _renders(s, "FARGATE-03", "LOW", contains="AWS-owned key")


def test_fargate03_customer_managed_key_passes():
    s, ecs = _ecs_scanner()
    s._check_ecs_cis(ecs, [CARN])
    assert not _ids(s, "FARGATE-03", "FAIL") and _ids(s, "FARGATE-03", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# LMB-10..LMB-17 — CIS-Compute 12.2, 12.5, 12.7, 12.9, 12.10, 12.12-12.14
# ══════════════════════════════════════════════════════════════════════════════
INSIGHTS = ("arn:aws:lambda:us-east-1:580247275435:layer:"
            "LambdaInsightsExtension:53")
ROLE = f"arn:aws:iam::{OWN}:role/fn-exec"


def _fn(name="fn", **kw):
    base = {"FunctionName": name, "Role": f"{ROLE}-{name}",
            "Layers": [{"Arn": INSIGHTS}], "Runtime": "python3.12",
            "Environment": {"Variables": {}}, "KMSKeyArn": ""}
    base.update(kw)
    return base


def _lambda_scanner(funcs, *, policies=None, recursion=None, role_exists=True,
                    role_statements=(), layers=(), layer_policies=None):
    s = make_scanner(sections=["LAMBDA"])
    s.account = OWN
    lmb = MagicMock()
    lmb.get_policy.side_effect = lambda FunctionName: (
        {"Policy": json.dumps({"Statement": (policies or {}).get(FunctionName, [])})}
        if (policies or {}).get(FunctionName) is not None
        else (_ for _ in ()).throw(
            MockClientError("ResourceNotFoundException")))
    lmb.get_function_recursion_config.side_effect = lambda FunctionName: {
        "RecursiveLoop": (recursion or {}).get(FunctionName, "Terminate")}
    lmb.get_layer_version_policy.side_effect = lambda LayerName, VersionNumber: (
        {"Policy": json.dumps({"Statement": (layer_policies or {})[LayerName]})}
        if LayerName in (layer_policies or {})
        else (_ for _ in ()).throw(
            MockClientError("ResourceNotFoundException")))
    lmb.get_paginator.side_effect = _pagers(list_layers=("Layers", list(layers)))
    s._clients["lambda:us-east-1"] = lmb

    iam = MagicMock()
    if role_exists:
        iam.get_role.return_value = {"Role": {}}
    else:
        iam.get_role.side_effect = MockClientError("NoSuchEntity")
    iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Statement": list(role_statements)}}}
    iam.get_paginator.side_effect = _pagers(
        list_attached_role_policies=("AttachedPolicies",
                                     [{"PolicyArn": "arn:aws:iam::aws:policy/X"}]
                                     if role_statements else []),
        list_role_policies=("PolicyNames", []))
    s._clients["iam:us-east-1"] = iam
    return s, lmb


def test_lmb10_missing_insights_layer_fails():
    s, lmb = _lambda_scanner([_fn(Layers=[])])
    s._check_lambda_cis(lmb, [_fn(Layers=[])])
    _renders(s, "LMB-10", "LOW", contains="Lambda Insights")


def test_lmb10_present_insights_layer_passes():
    funcs = [_fn()]
    s, lmb = _lambda_scanner(funcs)
    s._check_lambda_cis(lmb, funcs)
    assert not _ids(s, "LMB-10", "FAIL") and _ids(s, "LMB-10", "PASS")


def test_lmb11_shared_execution_role_fails():
    funcs = [_fn("a", Role=ROLE), _fn("b", Role=ROLE)]
    s, lmb = _lambda_scanner(funcs)
    s._check_lambda_cis(lmb, funcs)
    _renders(s, "LMB-11", "MEDIUM", contains="shared by 2 functions")


def test_lmb11_one_role_each_passes():
    funcs = [_fn("a"), _fn("b")]
    s, lmb = _lambda_scanner(funcs)
    s._check_lambda_cis(lmb, funcs)
    assert not _ids(s, "LMB-11", "FAIL") and _ids(s, "LMB-11", "PASS")


def test_lmb12_deleted_execution_role_fails():
    funcs = [_fn()]
    s, lmb = _lambda_scanner(funcs, role_exists=False)
    s._check_lambda_cis(lmb, funcs)
    _renders(s, "LMB-12", "MEDIUM", contains="does not exist")


def test_lmb12_an_unreadable_role_is_not_reported_as_missing():
    """A denied iam:GetRole and a deleted role look identical from the function's side.
    Only one of them is a finding."""
    assert C.lambda_role_missing({"FunctionName": "f", "Role": ROLE}, None)["missing"] \
        is False


def test_lmb13_admin_execution_role_fails():
    funcs = [_fn()]
    s, lmb = _lambda_scanner(funcs, role_statements=[
        {"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"}])
    s._check_lambda_cis(lmb, funcs)
    _renders(s, "LMB-13", "HIGH", contains="Action '*' on Resource '*'")


def test_lmb13_scoped_role_is_silent():
    funcs = [_fn()]
    s, lmb = _lambda_scanner(funcs, role_statements=[
        {"Sid": "Read", "Effect": "Allow", "Action": ["s3:GetObject"],
         "Resource": ["arn:aws:s3:::b/*"]}])
    s._check_lambda_cis(lmb, funcs)
    assert not _ids(s, "LMB-13", "FAIL")


def test_lmb14_unknown_cross_account_invoke_grant_fails():
    funcs = [_fn()]
    s, lmb = _lambda_scanner(funcs, policies={"fn": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OTHER}:root"},
         "Action": "lambda:InvokeFunction"}]})
    s._check_lambda_cis(lmb, funcs)
    _renders(s, "LMB-14", "HIGH", contains=OTHER)


def test_lmb14_trusted_account_and_wildcard_are_left_alone():
    """A wildcard principal is LMB-01's finding; reporting it here as well would count
    one exposure twice under two severities."""
    funcs = [_fn()]
    s, lmb = _lambda_scanner(funcs, policies={"fn": [
        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "lambda:InvokeFunction"},
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OTHER}:root"},
         "Action": "lambda:InvokeFunction"}]})
    s.trusted_accounts = {OTHER}
    s._check_lambda_cis(lmb, funcs)
    assert not _ids(s, "LMB-14", "FAIL")


def test_lmb15_environment_on_the_default_key_fails():
    funcs = [_fn(Environment={"Variables": {"STAGE": "prod"}}, KMSKeyArn="")]
    s, lmb = _lambda_scanner(funcs)
    s._check_lambda_cis(lmb, funcs)
    _renders(s, "LMB-15", "MEDIUM", contains="AWS-managed Lambda key")


def test_lmb15_no_environment_variables_is_not_a_finding():
    funcs = [_fn(Environment={"Variables": {}}, KMSKeyArn="")]
    s, lmb = _lambda_scanner(funcs)
    s._check_lambda_cis(lmb, funcs)
    assert not _ids(s, "LMB-15", "FAIL")


def test_lmb16_publicly_shared_layer_fails():
    funcs = [_fn()]
    s, lmb = _lambda_scanner(
        funcs, layers=[{"LayerName": "shared", "LatestMatchingVersion": {"Version": 3}}],
        layer_policies={"shared": [{"Effect": "Allow", "Principal": "*",
                                    "Action": "lambda:GetLayerVersion"}]})
    s._check_lambda_cis(lmb, funcs)
    _renders(s, "LMB-16", "HIGH", contains="shared")


def test_lmb16_layer_with_no_policy_passes():
    funcs = [_fn()]
    s, lmb = _lambda_scanner(
        funcs, layers=[{"LayerName": "priv", "LatestMatchingVersion": {"Version": 1}}])
    s._check_lambda_cis(lmb, funcs)
    assert not _ids(s, "LMB-16", "FAIL") and _ids(s, "LMB-16", "PASS")


def test_lmb17_recursion_detection_switched_off_fails():
    funcs = [_fn()]
    s, lmb = _lambda_scanner(funcs, recursion={"fn": "Allow"})
    s._check_lambda_cis(lmb, funcs)
    _renders(s, "LMB-17", "MEDIUM", contains="Allow")


def test_lmb17_default_terminate_is_silent():
    funcs = [_fn()]
    s, lmb = _lambda_scanner(funcs)
    s._check_lambda_cis(lmb, funcs)
    assert not _ids(s, "LMB-17", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# LSAIL-03..LSAIL-07 — CIS-Compute 5.6-5.10
# ══════════════════════════════════════════════════════════════════════════════
def _bucket(**kw):
    base = {"name": "assets",
            "accessRules": {"getObject": "private", "allowPublicOverrides": False},
            "accessLogConfig": {"enabled": True},
            "accessKeys": [],
            "resourcesReceivingAccess": [{"name": "web-1", "resourceType": "Instance"}]}
    base.update(kw)
    return base


def _lightsail_scanner(*, instances=(), buckets=()):
    s = make_scanner(sections=["LIGHTSAIL"])
    s.account = OWN
    ls = MagicMock()
    ls.get_instances.return_value = {"instances": list(instances)}
    ls.get_instance_port_states.return_value = {"portStates": []}
    ls.get_relational_databases.return_value = {"relationalDatabases": []}
    ls.get_buckets.return_value = {"buckets": list(buckets)}
    s._clients["lightsail:us-east-1"] = ls
    return s


def test_lsail03_ipv6_enabled_instance_fails():
    s = _lightsail_scanner(instances=[{"name": "web-1",
                                       "ipv6Addresses": ["2600:1f18::1"]}])
    s._check_lightsail()
    _renders(s, "LSAIL-03", "LOW", contains="IPv6 networking enabled")


def test_lsail03_ipv4_only_instance_is_silent():
    s = _lightsail_scanner(instances=[{"name": "web-1", "ipv6Addresses": []}])
    s._check_lightsail()
    assert not _ids(s, "LSAIL-03", "FAIL")


def test_lsail04_bucket_access_keys_fail():
    s = _lightsail_scanner(buckets=[_bucket(accessKeys=[{"accessKeyId": "AKIA..."}])])
    s._check_lightsail()
    _renders(s, "LSAIL-04", "MEDIUM", contains="bucket access key")


def test_lsail05_bucket_with_nothing_attached_fails():
    s = _lightsail_scanner(buckets=[_bucket(resourcesReceivingAccess=[])])
    s._check_lightsail()
    _renders(s, "LSAIL-05", "LOW", contains="no attached Lightsail resource")


def test_lsail06_public_bucket_fails_and_names_both_settings():
    s = _lightsail_scanner(buckets=[_bucket(accessRules={"getObject": "public",
                                                         "allowPublicOverrides": True})])
    s._check_lightsail()
    r = _renders(s, "LSAIL-06", "HIGH", contains="getObject=public")
    assert "allowPublicOverrides=true" in r.message


def test_lsail06_public_overrides_alone_still_fails():
    """A private bucket that permits per-object overrides can be made public one object
    at a time without the bucket-level setting ever changing."""
    s = _lightsail_scanner(buckets=[_bucket(accessRules={"getObject": "private",
                                                         "allowPublicOverrides": True})])
    s._check_lightsail()
    _renders(s, "LSAIL-06", "HIGH", contains="allowPublicOverrides=true")


def test_lsail07_bucket_without_access_logging_fails():
    s = _lightsail_scanner(buckets=[_bucket(accessLogConfig={"enabled": False})])
    s._check_lightsail()
    _renders(s, "LSAIL-07", "MEDIUM", contains="access logging disabled")


def test_a_correctly_configured_lightsail_bucket_is_silent():
    s = _lightsail_scanner(buckets=[_bucket()])
    s._check_lightsail()
    for cid in ("LSAIL-04", "LSAIL-05", "LSAIL-06", "LSAIL-07"):
        assert not _ids(s, cid, "FAIL"), cid
    assert _ids(s, "LSAIL-06", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# APRUN-01 — CIS-Compute 6.1
# ══════════════════════════════════════════════════════════════════════════════
def _apprunner_scanner(services):
    s = make_scanner(sections=["APPRUNNER"])
    s.account = OWN
    ar = MagicMock()
    ar.list_services.return_value = {
        "ServiceSummaryList": [{"ServiceArn": f"arn:svc/{sv['ServiceName']}"}
                               for sv in services]}
    by_arn = {f"arn:svc/{sv['ServiceName']}": sv for sv in services}
    ar.describe_service.side_effect = lambda ServiceArn: {"Service": by_arn[ServiceArn]}
    s._clients["apprunner:us-east-1"] = ar
    return s


def test_aprun01_default_egress_fails():
    s = _apprunner_scanner([{"ServiceName": "api", "NetworkConfiguration": {
        "EgressConfiguration": {"EgressType": "DEFAULT"}}}])
    s._check_apprunner()
    _renders(s, "APRUN-01", "MEDIUM", contains="EgressType=DEFAULT")


def test_aprun01_vpc_connector_passes():
    s = _apprunner_scanner([{"ServiceName": "api", "NetworkConfiguration": {
        "EgressConfiguration": {"EgressType": "VPC",
                                "VpcConnectorArn": "arn:conn"}}}])
    s._check_apprunner()
    assert not _ids(s, "APRUN-01", "FAIL") and _ids(s, "APRUN-01", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# BATCH-01 / BATCH-02 — CIS-Compute 8.1, 8.2
# ══════════════════════════════════════════════════════════════════════════════
def _batch_trust(condition=None):
    st = {"Effect": "Allow", "Principal": {"Service": "batch.amazonaws.com"},
          "Action": "sts:AssumeRole"}
    if condition:
        st["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [st]}


def _batch_scanner(job_defs, roles=()):
    s = make_scanner(sections=["BATCH"])
    s.account = OWN
    batch = MagicMock()
    batch.describe_job_definitions.return_value = {"jobDefinitions": list(job_defs)}
    s._clients["batch:us-east-1"] = batch
    iam = MagicMock()
    iam.get_paginator.side_effect = _pagers(list_roles=("Roles", list(roles)))
    s._clients["iam:us-east-1"] = iam
    return s


def test_batch01_job_definition_without_a_log_driver_fails():
    s = _batch_scanner([{"jobDefinitionName": "etl",
                         "containerProperties": {"image": "x"}}])
    s._check_batch()
    _renders(s, "BATCH-01", "MEDIUM", contains="no logConfiguration")


def test_batch01_configured_log_driver_passes():
    s = _batch_scanner([{"jobDefinitionName": "etl", "containerProperties": {
        "image": "x", "logConfiguration": {"logDriver": "awslogs"}}}])
    s._check_batch()
    assert not _ids(s, "BATCH-01", "FAIL") and _ids(s, "BATCH-01", "PASS")


def test_batch02_service_role_without_a_source_condition_fails():
    s = _batch_scanner([], roles=[{"RoleName": "BatchServiceRole",
                                   "AssumeRolePolicyDocument": _batch_trust()}])
    s._check_batch()
    _renders(s, "BATCH-02", "MEDIUM", contains="no aws:SourceArn")


def test_batch02_wildcard_source_arn_still_fails():
    """A SourceArn ending in /* names a resource TYPE, which re-admits the whole
    population the condition was supposed to narrow."""
    cond = {"ArnLike": {"aws:SourceArn":
                        [f"arn:aws:batch:us-east-1:{OWN}:compute-environment/*"]}}
    s = _batch_scanner([], roles=[{"RoleName": "BatchServiceRole",
                                   "AssumeRolePolicyDocument": _batch_trust(cond)}])
    s._check_batch()
    _renders(s, "BATCH-02", "MEDIUM", contains="ends in a wildcard")


def test_batch02_scoped_source_arn_passes():
    cond = {"ArnLike": {"aws:SourceArn":
                        [f"arn:aws:batch:us-east-1:{OWN}:compute-environment/testCE"]}}
    s = _batch_scanner([], roles=[{"RoleName": "BatchServiceRole",
                                   "AssumeRolePolicyDocument": _batch_trust(cond)}])
    s._check_batch()
    assert not _ids(s, "BATCH-02", "FAIL") and _ids(s, "BATCH-02", "PASS")


def test_batch02_ignores_roles_batch_cannot_assume():
    lambda_trust = {"Statement": [{"Effect": "Allow",
                                   "Principal": {"Service": "lambda.amazonaws.com"},
                                   "Action": "sts:AssumeRole"}]}
    s = _batch_scanner([], roles=[{"RoleName": "fn-exec",
                                   "AssumeRolePolicyDocument": lambda_trust}])
    s._check_batch()
    assert not _ids(s, "BATCH-02", "FAIL")
    assert _ids(s, "BATCH-02", "INFO")


# ══════════════════════════════════════════════════════════════════════════════
# EB-01..EB-04 — CIS-Compute 10.1-10.4
# ══════════════════════════════════════════════════════════════════════════════
def _opt(ns, name, value):
    return {"Namespace": ns, "OptionName": name, "Value": value}


HEALTHY_EB = [
    _opt("aws:elasticbeanstalk:managedactions", "ManagedActionsEnabled", "true"),
    _opt("aws:elasticbeanstalk:cloudwatch:logs", "StreamLogs", "true"),
    _opt("aws:elbv2:loadbalancer", "AccessLogsS3Enabled", "true"),
    _opt("aws:elbv2:listener:443", "Protocol", "HTTPS"),
]


def _beanstalk_scanner(settings):
    s = make_scanner(sections=["BEANSTALK"])
    s.account = OWN
    eb = MagicMock()
    eb.describe_environments.return_value = {
        "Environments": [{"EnvironmentName": "prod-env", "ApplicationName": "app"}]}
    eb.describe_configuration_settings.return_value = {
        "ConfigurationSettings": [{"OptionSettings": list(settings)}]}
    s._clients["elasticbeanstalk:us-east-1"] = eb
    return s


def _without(namespace, option):
    return [o for o in HEALTHY_EB
            if not (o["Namespace"] == namespace and o["OptionName"] == option)]


def test_eb01_managed_updates_disabled_fails():
    s = _beanstalk_scanner(_without("aws:elasticbeanstalk:managedactions",
                                    "ManagedActionsEnabled"))
    s._check_beanstalk()
    _renders(s, "EB-01", "MEDIUM", contains="managed platform updates disabled")


def test_eb02_log_streaming_off_fails():
    s = _beanstalk_scanner(_without("aws:elasticbeanstalk:cloudwatch:logs", "StreamLogs"))
    s._check_beanstalk()
    _renders(s, "EB-02", "MEDIUM", contains="does not stream instance logs")


def test_eb03_access_logs_off_fails():
    s = _beanstalk_scanner(_without("aws:elbv2:loadbalancer", "AccessLogsS3Enabled"))
    s._check_beanstalk()
    _renders(s, "EB-03", "MEDIUM", contains="access logs disabled")


def test_eb04_http_only_listener_fails():
    settings = _without("aws:elbv2:listener:443", "Protocol") + [
        _opt("aws:elbv2:listener:80", "Protocol", "HTTP")]
    s = _beanstalk_scanner(settings)
    s._check_beanstalk()
    _renders(s, "EB-04", "HIGH", contains="no HTTPS listener")


def test_eb04_worker_tier_with_no_listener_at_all_is_silent():
    """An absent listener is not a plaintext one. A worker-tier environment has no load
    balancer, and failing it would be a finding with no possible remediation."""
    s = _beanstalk_scanner(_without("aws:elbv2:listener:443", "Protocol"))
    s._check_beanstalk()
    assert not _ids(s, "EB-04", "FAIL")


def test_a_healthy_beanstalk_environment_is_silent():
    s = _beanstalk_scanner(HEALTHY_EB)
    s._check_beanstalk()
    for cid in ("EB-01", "EB-02", "EB-03", "EB-04"):
        assert not _ids(s, cid, "FAIL"), cid
    assert _ids(s, "EB-01", "PASS") and _ids(s, "EB-04", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# IMGB-02 / IMGB-03 — CIS-Compute 17.1, 17.2
# ══════════════════════════════════════════════════════════════════════════════
def _imagebuilder_scanner(dists=(), recipes=()):
    s = make_scanner(sections=["IMAGEBUILDER"])
    s.account = OWN
    ib = MagicMock()
    ib.list_distribution_configurations.return_value = {
        "distributionConfigurationSummaryList": [{"arn": d["arn"]} for d in dists]}
    by_arn = {d["arn"]: d for d in dists}
    ib.get_distribution_configuration.side_effect = (
        lambda distributionConfigurationArn: {
            "distributionConfiguration": by_arn[distributionConfigurationArn]})
    ib.list_image_recipes.return_value = {
        "imageRecipeSummaryList": [{"arn": r["arn"]} for r in recipes]}
    by_recipe = {r["arn"]: r for r in recipes}
    ib.get_image_recipe.side_effect = lambda imageRecipeArn: {
        "imageRecipe": by_recipe[imageRecipeArn]}
    ib.list_images.return_value = {"imageVersionList": []}
    s._clients["imagebuilder:us-east-1"] = ib
    return s


def test_imgb02_public_distribution_configuration_fails():
    s = _imagebuilder_scanner(dists=[{
        "arn": "arn:dist/pub", "name": "pub",
        "distributions": [{"region": "us-east-1", "amiDistributionConfiguration": {
            "launchPermission": {"userGroups": ["all"]}}}]}])
    s._check_imagebuilder()
    _renders(s, "IMGB-02", "HIGH", contains="us-east-1")


def test_imgb02_account_scoped_distribution_passes():
    s = _imagebuilder_scanner(dists=[{
        "arn": "arn:dist/priv", "name": "priv",
        "distributions": [{"region": "us-east-1", "amiDistributionConfiguration": {
            "launchPermission": {"userIds": [OTHER]}}}]}])
    s._check_imagebuilder()
    assert not _ids(s, "IMGB-02", "FAIL") and _ids(s, "IMGB-02", "PASS")


def _b64(text):
    import base64
    return base64.b64encode(text.encode()).decode()


def test_imgb03_user_data_override_without_cleanup_fails():
    s = _imagebuilder_scanner(recipes=[{
        "arn": "arn:recipe/x", "name": "x",
        "additionalInstanceConfiguration": {
            "userDataOverride": _b64("#!/bin/bash\necho hello\n")}}])
    s._check_imagebuilder()
    _renders(s, "IMGB-03", "MEDIUM", contains="perform_cleanup")


def test_imgb03_override_that_reenables_cleanup_is_silent():
    script = ("#!/bin/bash\nmkdir -p /var/lib/amazon/toe\n"
              "touch /var/lib/amazon/toe/perform_cleanup\n")
    s = _imagebuilder_scanner(recipes=[{
        "arn": "arn:recipe/x", "name": "x",
        "additionalInstanceConfiguration": {"userDataOverride": _b64(script)}}])
    s._check_imagebuilder()
    assert not _ids(s, "IMGB-03", "FAIL")


def test_imgb03_recipe_with_no_override_is_silent():
    """No override means the built-in cleanup runs. Only replacing the boot script can
    bypass it, so a recipe without one is not a candidate for this finding at all."""
    s = _imagebuilder_scanner(recipes=[{"arn": "arn:recipe/y", "name": "y"}])
    s._check_imagebuilder()
    assert not _ids(s, "IMGB-03", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# The claim the whole file exists to support
# ══════════════════════════════════════════════════════════════════════════════
def test_every_declared_compute_check_is_driven_to_a_failure_somewhere_here():
    """THE RATCHET, ASSERTED LOCALLY. docs/CHECK_FIRING.md measures this across the whole
    suite and can only be regenerated after the fact. This says it here, in the file that
    owns these checks, so adding a forty-fourth without a driving test fails immediately
    rather than at the next regeneration."""
    import re as _re
    src = open(os.path.abspath(__file__), encoding="utf-8").read()
    driven = set(_re.findall(r'_renders\(s,\s*"([A-Z0-9-]+)"', src))
    declared = {c.id for c in C.CHECKS}
    missing = sorted(declared - driven)
    assert not missing, (
        "declared with no test driving them to a FAIL: %s. A check that cannot be shown "
        "to fire is the defect docs/CHECK_FIRING.md exists to make visible." % missing)


def test_the_out_of_scope_list_states_a_reason_for_each_entry():
    """Five recommendations are not implemented. An exclusion without a reason is
    indistinguishable from an omission."""
    assert set(C.NOT_DETERMINABLE) == {"5.1", "5.2", "5.11", "5.12", "16.1"}
    for num, why in C.NOT_DETERMINABLE.items():
        assert len(why) > 60, f"{num}: reason is too short to be one"
