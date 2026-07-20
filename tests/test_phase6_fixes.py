"""Regressions for the Phase 6 adversarial-verify findings:
1 (major) SSM-02 ignored describe_instance_patch_states NextToken -> critical patches on page 2+
  hidden as 'never scanned' INFO (missed-vuln FN).
2 (major) S3-10/DDB-05/BCK-03 false-positive: CloudFront OAI pseudo-account 'cloudfront' flagged
  as cross-account (shared classifier now requires a real 12-digit account id).
3 (major) VPC-05 conflated IPv4/IPv6 NACL chains -> an IPv6 deny masked an IPv4 allow-all (false PASS).
4 (minor) ECS-07 '/var/lib/docker' lacked a trailing-slash boundary -> siblings false-flagged CRITICAL.
5 (minor) CNT-06 unreachable when the account has zero ECR repositories."""
import json
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_live_scanner as A
from aws_live_scanner import classify_resource_policy_stmt
from test_live_scanner import make_scanner, MockPaginator


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


# ── Fix 1: SSM-02 pages through NextToken ─────────────────────────────────────
def test_ssm02_follows_nexttoken_finds_page2_critical():
    s = make_scanner(sections=["EC2"])
    ids = [f"i-{n:02d}" for n in range(1, 12)]     # 11 managed instances
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = lambda n: MockPaginator(
        "Reservations", [{"Instances": [{"InstanceId": i} for i in ids]}])
    ssm = MagicMock()
    ssm.get_paginator.side_effect = lambda n: MockPaginator(
        "InstanceInformationList",
        [{"InstanceId": i, "ResourceType": "EC2Instance", "PingStatus": "Online"} for i in ids])

    pages = {
        None: {"InstancePatchStates": [{"InstanceId": i, "CriticalNonCompliantCount": 0,
                                        "SecurityNonCompliantCount": 0} for i in ids[:10]],
               "NextToken": "PAGE2"},
        "PAGE2": {"InstancePatchStates": [{"InstanceId": "i-11", "CriticalNonCompliantCount": 5,
                                           "SecurityNonCompliantCount": 0}]},
    }
    ssm.describe_instance_patch_states.side_effect = \
        lambda InstanceIds, NextToken=None: pages[NextToken]
    s._clients["ec2:us-east-1"] = ec2
    s._clients["ssm:us-east-1"] = ssm
    s._check_ssm()
    # i-11's critical non-compliance (page 2) must now surface as a FAIL, not an INFO
    assert "FAIL" in _status(s, "SSM-02")
    assert ssm.describe_instance_patch_states.call_count == 2


# ── Fix 2: CloudFront OAI is not cross-account ────────────────────────────────
def test_classifier_ignores_cloudfront_oai():
    stmt = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
            "Principal": {"AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E2Q"}}
    assert classify_resource_policy_stmt(stmt, "111111111111") is None


def test_s3_10_no_false_positive_on_oai():
    s = make_scanner(sections=["S3"])
    s.account = "111111111111"
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "assets"}]}
    full = {"BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": full}
    s3.get_bucket_encryption.side_effect = Exception("none")
    s3.get_bucket_logging.return_value = {}
    s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
    s3.get_bucket_policy.return_value = {"Policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::assets/*",
         "Principal": {"AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E2Q"}}]})}
    s3c = MagicMock()
    s3c.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": full}
    s._clients["s3:us-east-1"] = s3
    s._clients["s3control:us-east-1"] = s3c
    s._check_s3()
    assert "FAIL" not in _status(s, "S3-10")


def test_classifier_still_flags_real_external_account():
    stmt = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
            "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}
    res = classify_resource_policy_stmt(stmt, "111111111111")
    assert res and res["kind"] == "cross_account" and res["external_accounts"] == ["999999999999"]


# ── Fix 3: VPC-05 evaluates IPv4/IPv6 chains independently ────────────────────
def _vpc_nacl_scanner(entries):
    s = make_scanner(sections=["VPC"])
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {"SecurityGroups": []}
    ec2.describe_vpcs.return_value = {"Vpcs": []}
    ec2.describe_flow_logs.return_value = {"FlowLogs": []}
    pag = {"describe_network_acls": ("NetworkAcls",
            [{"NetworkAclId": "acl-1", "IsDefault": False, "Entries": entries}]),
           "describe_vpc_peering_connections": ("VpcPeeringConnections", [])}
    ec2.get_paginator.side_effect = lambda n: MockPaginator(*pag[n])
    s._clients["ec2:us-east-1"] = ec2
    return s


def test_vpc05_ipv6_deny_does_not_mask_ipv4_allow():
    # IPv6 deny-all at rule 90, IPv4 allow-all at rule 100 -> IPv4 admin ports ARE open
    s = _vpc_nacl_scanner([
        {"RuleNumber": 90, "RuleAction": "deny", "Protocol": "-1", "Ipv6CidrBlock": "::/0",
         "Egress": False},
        {"RuleNumber": 100, "RuleAction": "allow", "Protocol": "-1", "CidrBlock": "0.0.0.0/0",
         "Egress": False}])
    s._check_vpc()
    assert "FAIL" in _status(s, "VPC-05")


def test_vpc05_same_family_deny_still_protects():
    # IPv4 deny-all before IPv4 allow-all -> protected
    s = _vpc_nacl_scanner([
        {"RuleNumber": 90, "RuleAction": "deny", "Protocol": "-1", "CidrBlock": "0.0.0.0/0",
         "Egress": False},
        {"RuleNumber": 100, "RuleAction": "allow", "Protocol": "-1", "CidrBlock": "0.0.0.0/0",
         "Egress": False}])
    s._check_vpc()
    assert "FAIL" not in _status(s, "VPC-05")


# ── Fix 4: ECS-07 trailing-slash boundary ─────────────────────────────────────
def _ecs_vol_scanner(source_path):
    s = make_scanner(sections=["ECS"])
    ecs = MagicMock()
    ecs.list_clusters.return_value = {"clusterArns": ["c"]}
    ecs.list_task_definitions.return_value = {"taskDefinitionArns": ["td:1"]}
    ecs.describe_task_definition.return_value = {"taskDefinition": {
        "family": "app", "containerDefinitions": [{"name": "c1"}],
        "volumes": [{"name": "v", "host": {"sourcePath": source_path}}]}}
    s._clients["ecs:us-east-1"] = ecs
    s.graph = None
    return s


def test_ecs07_docker_sibling_not_critical():
    s = _ecs_vol_scanner("/var/lib/docker-plugins")   # sibling dir, not /var/lib/docker
    s._check_ecs()
    assert "FAIL" not in _status(s, "ECS-07") and "WARN" in _status(s, "ECS-07")


def test_ecs07_real_docker_dir_still_critical():
    s = _ecs_vol_scanner("/var/lib/docker/volumes")
    s._check_ecs()
    assert "FAIL" in _status(s, "ECS-07")


def test_ecs07_exact_docker_dir_still_critical():
    s = _ecs_vol_scanner("/var/lib/docker")
    s._check_ecs()
    assert "FAIL" in _status(s, "ECS-07")


# ── Fix 5: CNT-06 runs with zero ECR repositories ─────────────────────────────
def test_cnt06_runs_with_zero_repos():
    s = make_scanner(sections=["ECR"])
    ecr = MagicMock()
    ecr.describe_repositories.return_value = {"repositories": []}
    ecr.get_signing_configuration.return_value = {"signingConfiguration": {"rules": []}}
    s._clients["ecr:us-east-1"] = ecr
    s._check_ecr()
    assert "FAIL" in _status(s, "CNT-06")   # registry-signing evaluated despite 0 repos
