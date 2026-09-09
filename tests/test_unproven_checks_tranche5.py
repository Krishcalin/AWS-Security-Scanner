"""Tranche 5 — the never-observed checks the catalogue shouts loudest about.

WHICH CHECKS AND WHY THESE. `docs/CHECK_FIRING.md` records 61 checks that no test makes
emit anything at all. Twenty-six of them are declared CRITICAL or HIGH, which is the worst
combination the doc can report: the catalogue promises an operator that this finding is
urgent, and nothing anywhere has ever seen it produced. This file drives those.

THE TRIAGE THAT PICKED THEM. An AST pass over every `_add` call showed 22 of the 26 have a
literal FAIL path already in the code — they were simply never driven, because the nearest
existing fixture sets the SAFE value. `ECS-02` (root user) is observed and `ECS-01`
(privileged) is not, from the same loop over the same task definition, because no fixture
in the suite has ever set `privileged: true`. That is the shape of most of this tranche:
not broken checks, untested ones. The remaining four are recorded at the bottom of this
docstring rather than silently dropped:

  * `WAF-01` has NO FAIL PATH at all — its only posture WARN is "no Web ACLs in this
    scope", and a blanket FAIL would flag every account with nothing to protect. It needs
    a logic change, not a fixture, and is deliberately still deferred.
  * `CWPP-01`, `SEG-02` and `VULN-03` reach `_add` through a non-literal id (a variable or
    a subscript), so the static pass cannot locate their FAIL path and neither can a
    reader. They are left for a pass that starts by making the id legible.

WHAT EACH TEST ASSERTS. Not just the status. `_add` reads severity, compliance and
remediation from the catalogue for a FAIL and for nothing else, so a check that has only
ever WARNed has never rendered what the catalogue advertises. `_renders` asserts all
three, which is the claim that matters to whoever reads the report.
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_graph                                        # noqa: E402
from test_live_scanner import make_scanner                          # noqa: E402

OWN = "123456789012"
OTHER = "999988887777"
REGION = "us-east-1"

#: A resource policy granting everything to everyone. Half these services differ only in
#: which API hands it back, so the document itself is worth writing once.
WIDE_OPEN = {
    "Version": "2012-10-17",
    "Statement": [{"Sid": "Everyone", "Effect": "Allow", "Principal": {"AWS": "*"},
                   "Action": "*", "Resource": "*"}],
}


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _renders(s, cid, expected_severity, contains=None):
    """It fired, and it carries what the catalogue holds for it."""
    hits = _ids(s, cid, "FAIL")
    assert hits, f"{cid} did not FAIL — findings seen: " + ", ".join(
        sorted({f'{r.check_id}:{r.status}' for r in s.results})) or "(none)"
    r = hits[0]
    assert r.severity == expected_severity, (
        f"{cid} rendered {r.severity!r}, catalogue says {expected_severity!r}")
    assert r.remediation_cmd, f"{cid} FAIL carries no remediation command"
    assert r.compliance, f"{cid} FAIL carries no compliance mapping"
    if contains:
        assert contains in r.message, f"{cid} message lacks {contains!r}: {r.message}"
    return r


def _scanner(section, service, client):
    s = make_scanner(sections=[section])
    s.account = OWN
    s._clients[f"{service}:{REGION}"] = client
    return s


# ══════════════════════════════════════════════════════════════════════════════
# ECS-01 (CRITICAL) and ECS-04 (HIGH) — the same loop, never driven to either
# ══════════════════════════════════════════════════════════════════════════════
CLUSTER_ARN = f"arn:aws:ecs:{REGION}:{OWN}:cluster/prod"


def _ecs(task_def):
    ecs = MagicMock()
    ecs.list_clusters.return_value = {"clusterArns": [CLUSTER_ARN]}
    ecs.describe_clusters.return_value = {"clusters": []}
    ecs.list_task_definitions.return_value = {"taskDefinitionArns": ["td-0"]}
    ecs.describe_task_definition.return_value = {
        "taskDefinition": task_def, "tags": [{"key": "Owner", "value": "team"}]}
    return _scanner("ECS", "ecs", ecs)


def _container(**kw):
    base = {"name": "app", "image": f"{OWN}.dkr.ecr.{REGION}.amazonaws.com/app@sha256:"
                                    + "a" * 64,
            "user": "1000", "logConfiguration": {"logDriver": "awslogs"},
            "readonlyRootFilesystem": True, "environment": []}
    base.update(kw)
    return base


def test_ecs01_privileged_container_fails():
    """The CRITICAL nothing had ever seen. A privileged container disables the whole
    container isolation model — it is root on the host with all capabilities."""
    s = _ecs({"family": "app", "networkMode": "awsvpc",
              "containerDefinitions": [_container(privileged=True)]})
    s._check_ecs()
    _renders(s, "ECS-01", "CRITICAL", contains="privileged mode")


def test_ecs01_unprivileged_container_is_silent():
    s = _ecs({"family": "app", "networkMode": "awsvpc",
              "containerDefinitions": [_container()]})
    s._check_ecs()
    assert not _ids(s, "ECS-01", "FAIL")


def test_ecs04_plaintext_secret_in_a_container_env_var_fails():
    s = _ecs({"family": "app", "networkMode": "awsvpc",
              "containerDefinitions": [_container(
                  environment=[{"name": "DB_PASSWORD", "value": "hunter2"}])]})
    s._check_ecs()
    _renders(s, "ECS-04", "HIGH", contains="DB_PASSWORD")


def test_ecs04_ordinary_env_vars_are_silent():
    s = _ecs({"family": "app", "networkMode": "awsvpc",
              "containerDefinitions": [_container(
                  environment=[{"name": "LOG_LEVEL", "value": "info"}])]})
    s._check_ecs()
    assert not _ids(s, "ECS-04", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# LMB-01 (HIGH) — a Lambda anyone on the internet can invoke
# ══════════════════════════════════════════════════════════════════════════════
def _lambda(policy_statements):
    lmb = MagicMock()
    lmb.get_paginator.return_value.paginate.return_value = [
        {"Functions": [{"FunctionName": "fn", "Role": f"arn:aws:iam::{OWN}:role/fn",
                        "Runtime": "python3.12", "Layers": [],
                        "Environment": {"Variables": {}}, "KMSKeyArn": ""}]}]
    lmb.get_policy.return_value = {
        "Policy": json.dumps({"Statement": policy_statements})}
    lmb.get_function_url_config.side_effect = RuntimeError("no url")
    return _scanner("LAMBDA", "lambda", lmb)


def test_lmb01_wildcard_invoke_principal_fails():
    s = _lambda([{"Effect": "Allow", "Principal": {"AWS": "*"},
                  "Action": "lambda:InvokeFunction"}])
    s._check_lambda()
    _renders(s, "LMB-01", "HIGH", contains="public invoke access")


def test_lmb01_a_conditioned_wildcard_is_not_the_same_finding():
    """A wildcard principal narrowed by a condition is not open to the internet, and the
    check has always said so — nothing had ever exercised the distinction."""
    s = _lambda([{"Effect": "Allow", "Principal": {"AWS": "*"},
                  "Action": "lambda:InvokeFunction",
                  "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}}])
    s._check_lambda()
    assert not _ids(s, "LMB-01", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# SEC-01 (HIGH) — rotation off entirely. SEC-02 covers "rotates too slowly"; the
# fixture that drove it always set RotationEnabled=True, so this stayed unseen.
# ══════════════════════════════════════════════════════════════════════════════
def _secrets(secret):
    sm = MagicMock()
    sm.get_paginator.return_value.paginate.return_value = [{"SecretList": [secret]}]
    sm.get_resource_policy.return_value = {}
    return _scanner("SECRETS", "secretsmanager", sm)


def test_sec01_rotation_disabled_fails():
    s = _secrets({"ARN": "arn:secret:x", "Name": "db-password",
                  "RotationEnabled": False, "KmsKeyId": "arn:aws:kms:::key/cmk"})
    s._check_secrets()
    _renders(s, "SEC-01", "HIGH", contains="rotation NOT enabled")


def test_sec01_rotation_enabled_is_silent():
    s = _secrets({"ARN": "arn:secret:x", "Name": "db-password",
                  "RotationEnabled": True,
                  "RotationRules": {"AutomaticallyAfterDays": 30},
                  "KmsKeyId": "arn:aws:kms:::key/cmk"})
    s._check_secrets()
    assert not _ids(s, "SEC-01", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# LSAIL-02 (HIGH) — a Lightsail managed database on a public endpoint
# ══════════════════════════════════════════════════════════════════════════════
def _lightsail(databases):
    ls = MagicMock()
    ls.get_instances.return_value = {"instances": []}
    ls.get_relational_databases.return_value = {"relationalDatabases": databases}
    ls.get_buckets.return_value = {"buckets": []}
    return _scanner("LIGHTSAIL", "lightsail", ls)


def test_lsail02_public_database_fails():
    s = _lightsail([{"name": "prod-db", "publiclyAccessible": True}])
    s._check_lightsail()
    _renders(s, "LSAIL-02", "HIGH", contains="publicly accessible")


def test_lsail02_private_database_passes():
    s = _lightsail([{"name": "prod-db", "publiclyAccessible": False}])
    s._check_lightsail()
    assert not _ids(s, "LSAIL-02", "FAIL") and _ids(s, "LSAIL-02", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# The wildcard-principal family. Eight services, one document, eight APIs that
# hand it back differently — which is exactly why each needs its own driving test.
# ══════════════════════════════════════════════════════════════════════════════
def test_cart01_public_codeartifact_domain_fails():
    c = MagicMock()
    c.list_domains.return_value = {"domains": [{"name": "internal"}]}
    c.get_domain_permissions_policy.return_value = {
        "policy": {"document": json.dumps(WIDE_OPEN)}}
    c.list_repositories_in_domain.return_value = {"repositories": []}
    s = _scanner("CODEARTIFACT", "codeartifact", c)
    s._check_codeartifact()
    _renders(s, "CART-01", "HIGH", contains="wildcard")


def test_cart01_scoped_domain_passes():
    c = MagicMock()
    c.list_domains.return_value = {"domains": [{"name": "internal"}]}
    c.get_domain_permissions_policy.return_value = {"policy": {"document": json.dumps(
        {"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OWN}:root"},
                        "Action": "codeartifact:ReadFromRepository"}]})}}
    c.list_repositories_in_domain.return_value = {"repositories": []}
    s = _scanner("CODEARTIFACT", "codeartifact", c)
    s._check_codeartifact()
    assert not _ids(s, "CART-01", "FAIL") and _ids(s, "CART-01", "PASS")


def test_ecrpub01_wildcard_write_on_a_public_repository_fails():
    """Readability is never the finding on a PUBLIC registry — write is."""
    ep = MagicMock()
    ep.describe_repositories.return_value = {
        "repositories": [{"repositoryName": "tools"}]}
    ep.get_repository_policy.return_value = {"policyText": json.dumps(
        {"Statement": [{"Effect": "Allow", "Principal": "*",
                        "Action": "ecr-public:PutImage"}]})}
    s = _scanner("ECRPUBLIC", "ecr-public", ep)
    s._check_ecrpublic()
    _renders(s, "ECRPUB-01", "HIGH", contains="WRITE")


def test_ecrpub01_wildcard_read_only_is_silent():
    ep = MagicMock()
    ep.describe_repositories.return_value = {
        "repositories": [{"repositoryName": "tools"}]}
    ep.get_repository_policy.return_value = {"policyText": json.dumps(
        {"Statement": [{"Effect": "Allow", "Principal": "*",
                        "Action": "ecr-public:BatchGetImage"}]})}
    s = _scanner("ECRPUBLIC", "ecr-public", ep)
    s._check_ecrpublic()
    assert not _ids(s, "ECRPUB-01", "FAIL")


def test_hsm02_shared_cloudhsm_resource_policy_fails():
    ch = MagicMock()
    ch.describe_clusters.return_value = {"Clusters": [
        {"ClusterId": "cluster-abc", "ClusterArn": "arn:aws:cloudhsm:::cluster/abc",
         "BackupRetentionPolicy": {"Type": "DAYS", "Value": "90"}}]}
    ch.get_resource_policy.return_value = {"Policy": json.dumps(WIDE_OPEN)}
    s = _scanner("CLOUDHSM", "cloudhsmv2", ch)
    s._check_cloudhsm()
    _renders(s, "HSM-02", "HIGH", contains="wildcard principal")


def test_nfw02_stateless_default_of_aws_pass_fails():
    """A firewall that forwards what matches no rule fails OPEN."""
    nfw = MagicMock()
    nfw.list_firewalls.return_value = {
        "Firewalls": [{"FirewallName": "edge",
                       "FirewallArn": "arn:aws:network-firewall:::firewall/edge"}]}
    nfw.describe_logging_configuration.return_value = {
        "LoggingConfiguration": {"LogDestinationConfigs": [{"LogType": "FLOW"}]}}
    nfw.describe_firewall.return_value = {
        "Firewall": {"FirewallPolicyArn": "arn:pol", "DeleteProtection": True,
                     "FirewallPolicyChangeProtection": True,
                     "SubnetChangeProtection": True}}
    nfw.describe_firewall_policy.return_value = {
        "FirewallPolicy": {"StatelessDefaultActions": ["aws:pass"],
                           "StatelessFragmentDefaultActions": ["aws:pass"]}}
    s = _scanner("NETWORKFIREWALL", "network-firewall", nfw)
    s._check_networkfirewall()
    _renders(s, "NFW-02", "HIGH", contains="aws:pass")


def test_nfw02_default_drop_passes():
    nfw = MagicMock()
    nfw.list_firewalls.return_value = {"Firewalls": [{"FirewallName": "edge"}]}
    nfw.describe_logging_configuration.return_value = {
        "LoggingConfiguration": {"LogDestinationConfigs": [{"LogType": "FLOW"}]}}
    nfw.describe_firewall.return_value = {"Firewall": {"FirewallPolicyArn": "arn:pol"}}
    nfw.describe_firewall_policy.return_value = {
        "FirewallPolicy": {"StatelessDefaultActions": ["aws:drop"]}}
    s = _scanner("NETWORKFIREWALL", "network-firewall", nfw)
    s._check_networkfirewall()
    assert not _ids(s, "NFW-02", "FAIL") and _ids(s, "NFW-02", "PASS")


def test_pca01_shared_private_ca_fails():
    """A private CA is a trust root: sharing issuance is not sharing a resource."""
    pca = MagicMock()
    pca.list_certificate_authorities.return_value = {
        "CertificateAuthorities": [{"Arn": "arn:aws:acm-pca:::ca/abc"}]}
    pca.get_policy.return_value = {"Policy": json.dumps(WIDE_OPEN)}
    s = _scanner("PRIVATECA", "acm-pca", pca)
    s._check_privateca()
    _renders(s, "PCA-01", "HIGH", contains="TRUST ROOT")


def test_s3t01_public_table_bucket_policy_fails():
    c = MagicMock()
    c.list_table_buckets.return_value = {
        "tableBuckets": [{"arn": "arn:aws:s3tables:::bucket/analytics"}]}
    c.get_table_bucket_policy.return_value = {
        "resourcePolicy": json.dumps(WIDE_OPEN)}
    c.get_table_bucket_encryption.return_value = {
        "encryptionConfiguration": {"sseAlgorithm": "aws:kms",
                                    "kmsKeyArn": "arn:key"}}
    s = _scanner("S3TABLES", "s3tables", c)
    s._check_s3tables()
    _renders(s, "S3T-01", "HIGH", contains="wildcard principal")


def test_sgw01_world_open_nfs_share_fails():
    sgw = MagicMock()
    sgw.list_file_shares.return_value = {"FileShareInfoList": [
        {"FileShareARN": "arn:aws:storagegateway:::share/sh-1",
         "FileShareType": "NFS"}]}
    sgw.describe_nfs_file_shares.return_value = {"NFSFileShareInfoList": [
        {"FileShareARN": "arn:aws:storagegateway:::share/sh-1",
         "FileShareId": "sh-1", "ClientList": ["0.0.0.0/0"],
         "KMSEncrypted": True, "KMSKey": "arn:key"}]}
    sgw.describe_smb_file_shares.return_value = {"SMBFileShareInfoList": []}
    s = _scanner("STORAGEGATEWAY", "storagegateway", sgw)
    s._check_storagegateway()
    _renders(s, "SGW-01", "HIGH", contains="0.0.0.0/0")


def test_sgw01_restricted_client_list_passes():
    sgw = MagicMock()
    sgw.list_file_shares.return_value = {"FileShareInfoList": [
        {"FileShareARN": "arn:share/sh-1", "FileShareType": "NFS"}]}
    sgw.describe_nfs_file_shares.return_value = {"NFSFileShareInfoList": [
        {"FileShareARN": "arn:share/sh-1", "FileShareId": "sh-1",
         "ClientList": ["10.0.0.0/8"], "KMSEncrypted": True, "KMSKey": "arn:key"}]}
    sgw.describe_smb_file_shares.return_value = {"SMBFileShareInfoList": []}
    s = _scanner("STORAGEGATEWAY", "storagegateway", sgw)
    s._check_storagegateway()
    assert not _ids(s, "SGW-01", "FAIL") and _ids(s, "SGW-01", "PASS")


def test_sso01_permission_set_granting_star_on_star_fails():
    """A permission set is invisible to a per-account IAM audit: the role it provisions
    looks ordinary in each account it lands in."""
    sso = MagicMock()
    sso.list_instances.return_value = {"Instances": [{"InstanceArn": "arn:sso:::inst/1"}]}
    sso.list_permission_sets.return_value = {"PermissionSets": ["arn:ps/1"]}
    sso.describe_permission_set.return_value = {"PermissionSet": {"Name": "AdminAccess"}}
    sso.get_inline_policy_for_permission_set.return_value = {
        "InlinePolicy": json.dumps(
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})}
    s = _scanner("IDENTITYCENTER", "sso-admin", sso)
    s._check_identitycenter()
    _renders(s, "SSO-01", "HIGH", contains="AdminAccess")


def test_sso01_scoped_permission_set_passes():
    sso = MagicMock()
    sso.list_instances.return_value = {"Instances": [{"InstanceArn": "arn:sso:::inst/1"}]}
    sso.list_permission_sets.return_value = {"PermissionSets": ["arn:ps/1"]}
    sso.describe_permission_set.return_value = {"PermissionSet": {"Name": "ReadOnly"}}
    sso.get_inline_policy_for_permission_set.return_value = {
        "InlinePolicy": json.dumps({"Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]})}
    s = _scanner("IDENTITYCENTER", "sso-admin", sso)
    s._check_identitycenter()
    assert not _ids(s, "SSO-01", "FAIL") and _ids(s, "SSO-01", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# EC2-06 (HIGH) — an unencrypted EBS volume. EBS-02 covers the same fact from the
# EBS section; EC2-06 is the EC2 section's own view of it and had never been driven.
# ══════════════════════════════════════════════════════════════════════════════
def test_ec206_unencrypted_volume_fails():
    ec2 = MagicMock()
    ec2.describe_volumes.return_value = {"Volumes": [
        {"VolumeId": "vol-plain", "Encrypted": False, "State": "in-use"},
        {"VolumeId": "vol-enc", "Encrypted": True, "State": "in-use"}]}
    ec2.describe_instances.return_value = {"Reservations": []}
    ec2.get_paginator.return_value.paginate.return_value = [{"Reservations": []}]
    ec2.describe_addresses.return_value = {"Addresses": []}
    s = _scanner("EC2", "ec2", ec2)
    s._check_ec2()
    _renders(s, "EC2-06", "HIGH", contains="vol-plain")
    assert _ids(s, "EC2-06", "PASS"), "the encrypted volume should still be counted"


def test_ec206_all_volumes_encrypted_is_silent():
    ec2 = MagicMock()
    ec2.describe_volumes.return_value = {"Volumes": [
        {"VolumeId": "vol-enc", "Encrypted": True, "State": "in-use"}]}
    ec2.describe_instances.return_value = {"Reservations": []}
    ec2.get_paginator.return_value.paginate.return_value = [{"Reservations": []}]
    ec2.describe_addresses.return_value = {"Addresses": []}
    s = _scanner("EC2", "ec2", ec2)
    s._check_ec2()
    assert not _ids(s, "EC2-06", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# BDR-02 (HIGH) — an account using Bedrock with no Guardrails at all
# ══════════════════════════════════════════════════════════════════════════════
def _bedrock(guardrails):
    b = MagicMock()
    b.get_model_invocation_logging_configuration.return_value = {
        "loggingConfig": {"cloudWatchConfig": {"logGroupName": "/aws/bedrock"}}}
    b.list_guardrails.return_value = {"guardrails": guardrails}
    b.list_custom_models.return_value = {"modelSummaries": []}
    b.list_model_customization_jobs.return_value = {"modelCustomizationJobSummaries": []}
    return _scanner("BEDROCK", "bedrock", b)


def test_bdr02_no_guardrails_fails():
    """An account invoking foundation models with no Guardrail has nothing between a
    user's prompt and the model, in either direction."""
    s = _bedrock([])
    s._check_bedrock()
    _renders(s, "BDR-02", "HIGH", contains="No Bedrock Guardrails")


def test_bdr02_a_configured_guardrail_passes():
    s = _bedrock([{"name": "pii-filter", "id": "gr-1", "status": "READY"}])
    s._check_bedrock()
    assert not _ids(s, "BDR-02", "FAIL") and _ids(s, "BDR-02", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# AGT-02 / AGT-04 / AGT-05 (HIGH) — Bedrock agent posture
# ══════════════════════════════════════════════════════════════════════════════
def _agents(agent_detail, *, action_group=None, lambda_policy=None):
    ba = MagicMock()
    ba.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}
    ba.list_agents.return_value = {"agentSummaries": [{"agentId": "AG1",
                                                       "agentName": "helper"}]}
    ba.get_agent.return_value = {"agent": agent_detail}
    ba.list_agent_action_groups.return_value = {
        "actionGroupSummaries": [{"actionGroupName": "tools", "actionGroupId": "grp1"}]
        if action_group else []}
    ba.get_agent_action_group.return_value = {"agentActionGroup": action_group or {}}

    lmb = MagicMock()
    if lambda_policy is None:
        lmb.get_policy.side_effect = RuntimeError("ResourceNotFoundException")
    else:
        lmb.get_policy.return_value = {"Policy": json.dumps(lambda_policy)}

    s = make_scanner(sections=["BEDROCK_AGENTS"])
    s.account = OWN
    s._clients[f"bedrock-agent:{REGION}"] = ba
    s._clients[f"lambda:{REGION}"] = lmb
    s._clients[f"iam:{REGION}"] = MagicMock(**{
        "list_role_policies.return_value": {"PolicyNames": []},
        "list_attached_role_policies.return_value": {"AttachedPolicies": []}})
    return s


def _agent(**kw):
    base = {"agentName": "helper", "agentArn": f"arn:aws:bedrock:::agent/AG1",
            "agentStatus": "PREPARED", "customerEncryptionKeyArn": "arn:key",
            "agentResourceRoleArn": f"arn:aws:iam::{OWN}:role/agent-exec",
            "guardrailConfiguration": {"guardrailIdentifier": "gr-1"},
            "idleSessionTTLInSeconds": 600, "instruction": "be helpful"}
    base.update(kw)
    return base


def test_agt02_agent_with_no_execution_role_fails():
    s = _agents(_agent(agentResourceRoleArn=""))
    s._check_bedrock_agents()
    _renders(s, "AGT-02", "HIGH", contains="No execution role")


def test_agt05_agent_with_no_guardrail_fails():
    """The agent-level counterpart of BDR-02: the account may have Guardrails and this
    agent still be running without one attached."""
    s = _agents(_agent(guardrailConfiguration={}))
    s._check_bedrock_agents()
    _renders(s, "AGT-05", "HIGH", contains="No Guardrail on agent")


def test_agt05_guardrail_attached_passes():
    s = _agents(_agent())
    s._check_bedrock_agents()
    assert not _ids(s, "AGT-05", "FAIL") and _ids(s, "AGT-05", "PASS")


def test_agt04_action_group_lambda_with_a_wildcard_invoker_fails():
    """The action-group Lambda is the agent's hands. A wildcard invoke principal means
    anyone can call the tool directly, without going through the agent at all."""
    s = _agents(_agent(),
                action_group={"actionGroupName": "tools",
                              "actionGroupExecutor": {
                                  "lambda": f"arn:aws:lambda:{REGION}:{OWN}:function:tool"},
                              "description": "does things"},
                lambda_policy={"Statement": [
                    {"Effect": "Allow", "Principal": "*",
                     "Action": "lambda:InvokeFunction"}]})
    s._check_bedrock_agents()
    _renders(s, "AGT-04", "HIGH", contains="wildcard")


def test_agt04_scoped_action_group_lambda_passes():
    s = _agents(_agent(),
                action_group={"actionGroupName": "tools",
                              "actionGroupExecutor": {
                                  "lambda": f"arn:aws:lambda:{REGION}:{OWN}:function:tool"},
                              "description": "does things"},
                lambda_policy={"Statement": [
                    {"Effect": "Allow",
                     "Principal": {"Service": "bedrock.amazonaws.com"},
                     "Action": "lambda:InvokeFunction"}]})
    s._check_bedrock_agents()
    assert not _ids(s, "AGT-04", "FAIL") and _ids(s, "AGT-04", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# KSPM-02 (HIGH) — a wildcard RBAC role bound to a subject
# ══════════════════════════════════════════════════════════════════════════════
K_CLUSTER = "prod"
K_ARN = f"arn:aws:eks:{REGION}:{OWN}:cluster/{K_CLUSTER}"


def _reachable_cluster():
    return {"arn": K_ARN, "endpoint": "https://x",
            "certificateAuthority": {"data": "Zm9v"},
            "resourcesVpcConfig": {"endpointPublicAccess": True,
                                   "endpointPrivateAccess": True}}


def _run_kspm(s, routes):
    def _get(ctx, path):
        for key, val in routes.items():
            if path.startswith(key):
                return val
        return {"items": []}
    s._k8s_get = _get
    s._check_kspm(K_CLUSTER, _reachable_cluster(), K_ARN,
                  f"arn:aws:iam::{OWN}:role/kspm")


def _kspm_scanner():
    s = make_scanner(["EKS"])
    s.account = OWN
    s.graph = aws_graph.SecurityGraph()
    return s


WILDCARD_ROLE = {"metadata": {"name": "everything-reader"},
                 "rules": [{"apiGroups": ["*"], "resources": ["*"],
                            "verbs": ["get", "list", "watch"]}]}
WILDCARD_BINDING = {"metadata": {"name": "reader-binding"},
                    "roleRef": {"kind": "ClusterRole", "name": "everything-reader"},
                    "subjects": [{"kind": "ServiceAccount", "name": "reporting",
                                  "namespace": "prod"}]}


def test_kspm02_wildcard_rbac_role_fails():
    s = _kspm_scanner()
    _run_kspm(s, {
        "/api/v1/namespaces": {"items": [{"metadata": {"name": "prod", "labels": {}}}]},
        "/apis/rbac.authorization.k8s.io/v1/clusterroles": {"items": [WILDCARD_ROLE]},
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": {
            "items": [WILDCARD_BINDING]},
    })
    _renders(s, "KSPM-02", "HIGH", contains="wildcard")


def test_kspm02_a_scoped_role_is_silent():
    scoped = {"metadata": {"name": "pod-reader"},
              "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]}
    binding = {"metadata": {"name": "b"},
               "roleRef": {"kind": "ClusterRole", "name": "pod-reader"},
               "subjects": [{"kind": "ServiceAccount", "name": "app",
                             "namespace": "prod"}]}
    s = _kspm_scanner()
    _run_kspm(s, {
        "/api/v1/namespaces": {"items": [{"metadata": {"name": "prod", "labels": {}}}]},
        "/apis/rbac.authorization.k8s.io/v1/clusterroles": {"items": [scoped]},
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": {"items": [binding]},
    })
    assert not _ids(s, "KSPM-02", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# DATA-02 (HIGH) — a Macie crown-jewel bucket that is also public
# ══════════════════════════════════════════════════════════════════════════════
def _macie(buckets):
    mac = MagicMock()
    mac.get_macie_session.return_value = {"status": "ENABLED"}
    mac.get_paginator.return_value.paginate.return_value = [{"buckets": buckets}]
    s = _scanner("DATA", "macie2", mac)
    s.graph = aws_graph.SecurityGraph()
    return s


def _crown(**kw):
    """A Macie bucket entry that `is_crown_jewel` accepts. The score traps matter: -1,
    1, the neutral 50 default, and a zero classifiable count all mean UNKNOWN, so the
    fixture has to clear them or the check is silent for the wrong reason."""
    base = {"bucketName": "customer-exports", "classifiableObjectCount": 4200,
            "sensitivityScore": 85,
            "publicAccess": {"effectivePermission": "PUBLIC"},
            "sharedAccess": "NOT_SHARED",
            "serverSideEncryption": {"type": "aws:kms"}}
    base.update(kw)
    return base


def test_data02_public_crown_jewel_bucket_fails():
    s = _macie([_crown()])
    s._collect_macie(s.graph)
    _renders(s, "DATA-02", "HIGH", contains="PUBLIC")


def test_data02_externally_shared_crown_jewel_also_fails():
    s = _macie([_crown(publicAccess={"effectivePermission": "NOT_PUBLIC"},
                       sharedAccess="EXTERNAL")])
    s._collect_macie(s.graph)
    _renders(s, "DATA-02", "HIGH", contains="externally shared")


def test_data02_private_crown_jewel_is_silent():
    s = _macie([_crown(publicAccess={"effectivePermission": "NOT_PUBLIC"})])
    s._collect_macie(s.graph)
    assert not _ids(s, "DATA-02", "FAIL")
    assert _ids(s, "DATA-01", "FAIL"), "it is still a crown jewel"


# ══════════════════════════════════════════════════════════════════════════════
# EXTACCESS-01 (HIGH) — Access Analyzer's authoritative public-bucket verdict
# ══════════════════════════════════════════════════════════════════════════════
def _access_analyzer(finding_detail):
    aa = MagicMock()
    aa.list_analyzers.return_value = {"analyzers": [
        {"arn": "arn:aws:access-analyzer:::analyzer/a1", "status": "ACTIVE",
         "type": "ACCOUNT"}]}
    aa.get_paginator.return_value.paginate.return_value = [{"findings": [
        {"id": "f1", "resourceType": "AWS::S3::Bucket",
         "resource": "arn:aws:s3:::exports"}]}]
    aa.get_finding_v2.return_value = finding_detail
    s = _scanner("DATA", "accessanalyzer", aa)
    s.graph = aws_graph.SecurityGraph()
    return s


def test_extaccess01_public_bucket_confirmed_by_access_analyzer_fails():
    """Authoritative, unlike a policy read: Access Analyzer proves reachability rather
    than inferring it."""
    s = _access_analyzer({"externalAccessDetails": {
        "isPublic": True, "principal": {"AWS": "*"}, "action": ["s3:GetObject"]}})
    s._collect_access_analyzer(s.graph)
    _renders(s, "EXTACCESS-01", "HIGH", contains="PUBLICLY accessible")


def test_extaccess01_named_external_principal_is_extaccess02_instead():
    """A named cross-account principal is a different finding, and reporting it as
    'public' would overstate what Access Analyzer actually said."""
    s = _access_analyzer({"externalAccessDetails": {
        "isPublic": False, "principal": {"AWS": f"arn:aws:iam::{OTHER}:root"},
        "action": ["s3:GetObject"]}})
    s._collect_access_analyzer(s.graph)
    assert not _ids(s, "EXTACCESS-01", "FAIL")
    assert _ids(s, "EXTACCESS-02", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# FARGATE-02 (HIGH) — a Fargate task whose own ENI is internet-reachable
# ══════════════════════════════════════════════════════════════════════════════
TASK_NODE = f"arn:aws:ecs:{REGION}:{OWN}:task/prod/abc123"


def test_fargate02_task_with_a_public_eni_fails():
    """Route 2 in _check_exposure: an awsvpc task ENI carries no InstanceId, so the task
    is wired directly. The ALB-fronted route is already tested; this direct-exposure one
    is the branch that emits FARGATE-02 and nothing had reached it."""
    from test_exposure import IGW_V4, NACLS, _eni, _mock_ec2, _sg, perm, rt

    s = make_scanner(sections=["EXPOSURE"])
    s.account = OWN
    s.graph = aws_graph.SecurityGraph()
    s._get_iam_principals = lambda: []
    s._iam_principals = []
    s._fargate_payloads = [{
        "node_id": TASK_NODE, "node_props": {"cluster": "prod"},
        "task_role_arn": "", "image_nodes": [], "eni_ids": ["eni-f1"],
        "private_ips": ["10.0.1.50"], "subnet_id": "subnet-1", "cluster": "prod"}]
    enis = [_eni("eni-f1", None, "sg-open")]
    sgs = [_sg("sg-open", [perm("tcp", 443, 443)])]
    s._client = lambda service, region=None: _mock_ec2(enis, [rt(IGW_V4)], NACLS,
                                                       sgs, [])
    s._check_exposure()
    _renders(s, "FARGATE-02", "HIGH", contains="PUBLIC task IP")
    assert TASK_NODE in s._exposed_fargate


def test_fargate02_private_task_eni_is_silent():
    from test_exposure import NACLS, _eni, _mock_ec2, _sg, perm, rt

    s = make_scanner(sections=["EXPOSURE"])
    s.account = OWN
    s.graph = aws_graph.SecurityGraph()
    s._get_iam_principals = lambda: []
    s._iam_principals = []
    s._fargate_payloads = [{
        "node_id": TASK_NODE, "node_props": {"cluster": "prod"},
        "task_role_arn": "", "image_nodes": [], "eni_ids": ["eni-f1"],
        "private_ips": ["10.0.1.50"], "subnet_id": "subnet-1", "cluster": "prod"}]
    enis = [_eni("eni-f1", None, "sg-open", public=False)]
    sgs = [_sg("sg-open", [perm("tcp", 443, 443)])]
    s._client = lambda service, region=None: _mock_ec2(enis, [rt("local")], NACLS,
                                                       sgs, [])
    s._check_exposure()
    assert not _ids(s, "FARGATE-02", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# The ratchet this file is accountable to
# ══════════════════════════════════════════════════════════════════════════════
#: The 26 never-observed CRITICAL/HIGH checks, and what happened to each. Four are
#: NOT driven here and the reason is recorded rather than left to be rediscovered.
DEFERRED = {
    "WAF-01": "no FAIL path exists — its only posture WARN is 'no Web ACLs in this "
              "scope', and a blanket FAIL would flag every account with nothing to "
              "protect. Needs a logic change, not a fixture.",
    "CWPP-01": "reaches _add through a non-literal check id, so neither the static "
               "pass nor a reader can locate its FAIL path.",
    "SEG-02": "same — non-literal id.",
    "VULN-03": "same — non-literal id.",
}


def test_this_file_drives_every_high_severity_check_it_claims_to():
    """A file named for a tranche has to be checkable against that tranche. The list is
    read from the source rather than restated, so a test deleted here fails here."""
    import re as _re
    src = open(os.path.abspath(__file__), encoding="utf-8").read()
    driven = set(_re.findall(r'_renders\(s,\s*"([A-Z0-9-]+)"', src))
    claimed = {
        "ECS-01", "ECS-04", "LMB-01", "SEC-01", "LSAIL-02", "CART-01", "ECRPUB-01",
        "HSM-02", "NFW-02", "PCA-01", "S3T-01", "SGW-01", "SSO-01", "EC2-06",
        "BDR-02", "AGT-02", "AGT-04", "AGT-05", "KSPM-02", "DATA-02",
        "EXTACCESS-01", "FARGATE-02",
    }
    assert claimed - driven == set(), f"claimed but not driven: {sorted(claimed - driven)}"
    assert len(claimed) + len(DEFERRED) == 26, (
        "the tranche was 26 checks; %d driven + %d deferred does not account for it"
        % (len(claimed), len(DEFERRED)))
