"""Tranche 8 — the never-observed MEDIUM and LOW checks.

Tranches 5 to 7 worked down from CRITICAL, so what is left is what severity-first
ordering leaves for last. Eleven of these belong to single-check service sections
added by the service-coverage batches: the section was wired, registered and
counted, and no test ever supplied it a client. A section nothing calls is
indistinguishable from a section that does not work.

WHAT THE DOC'S BUCKETS DO NOT TELL YOU, and this tranche had to establish:

  * `SM-16`, `SM-18` and `SM-20` are NOT missing a fixture in the way the others
    are. They are the `enc_ctl` half of `_check_sagemaker_monitoring`, which is
    skipped entirely when `encryption_applicable` is false — and it is false on a
    single instance, because inter-container traffic does not exist there. Their
    `iso_ctl` siblings (`SM-15`, `SM-17`, `SM-19`) all fire, which is what makes
    the gap look arbitrary until you see the instance count.

  * Those ids never appear as literals anywhere: `_check_sagemaker_monitoring`
    resolves them through `aws_sagemaker.SECURITY_HUB_PARITY[ctl][0]`. A static
    search for the emit site returns nothing and concludes "unreachable", which is
    wrong, and is the same trap `docs/CHECK_FIRING.md` exists to avoid.

  * `SM-12` really is unreachable, for a reason no bucket records:
    `aws_sagemaker.notebook_platform()` is defined, exported in `__all__` and unit
    tested, and NOTHING CALLS IT. That is built-and-unreached at function
    granularity, which `tests/test_unreached_modules.py` cannot see because it asks
    whether a MODULE has a production caller, and `aws_sagemaker` plainly does.
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_live_scanner import make_scanner                            # noqa: E402
from test_unproven_checks_tranche5 import _ids, _renders              # noqa: E402

OWN = "123456789012"
REGION = "us-east-1"

#: A resource policy that grants the world. Every "is this shared publicly" check
#: in this tranche reduces to finding a wide principal, so they share one document
#: rather than four subtly different ones.
WIDE_OPEN = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": "*",
                   "Action": "*", "Resource": "*"}],
})
SCOPED = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"AWS": f"arn:aws:iam::{OWN}:root"},
                   "Action": "*", "Resource": "*"}],
})


def _scanner(section, service, client):
    s = make_scanner(sections=[section])
    s.account = OWN
    s._clients[f"{service}:{REGION}"] = client
    return s


# ═════════════════════════════════════════════════════════════════════════════
# AMP-01 (MEDIUM) — Prometheus metrics on an AWS-owned key
# ═════════════════════════════════════════════════════════════════════════════
def _amp(workspace):
    c = MagicMock()
    c.list_workspaces.return_value = {"workspaces": [{"workspaceId": "ws-1"}]}
    c.describe_workspace.return_value = {"workspace": workspace}
    return _scanner("PROMETHEUS", "amp", c)


def test_amp01_workspace_without_a_cmk_fails():
    """Metrics carry hostnames, topology and traffic shape — a map of the estate —
    so who holds the key is a real question and not a formality."""
    s = _amp({"workspaceId": "ws-1", "alias": "prod"})
    s._check_prometheus()
    _renders(s, "AMP-01", "MEDIUM", contains="ws-1")


def test_amp01_passes_with_a_customer_managed_key():
    s = _amp({"workspaceId": "ws-1",
              "kmsKeyArn": f"arn:aws:kms:{REGION}:{OWN}:key/abc"})
    s._check_prometheus()
    assert not _ids(s, "AMP-01", "FAIL")
    assert _ids(s, "AMP-01", "PASS")


# ═════════════════════════════════════════════════════════════════════════════
# CGP-01 (MEDIUM) — a profiling group readable by anyone
# ═════════════════════════════════════════════════════════════════════════════
def _cgp(policy):
    c = MagicMock()
    c.list_profiling_groups.return_value = {"profilingGroupNames": ["billing"]}
    c.get_policy.return_value = {"policy": policy}
    return _scanner("CODEGURUPROFILER", "codeguruprofiler", c)


def test_cgp01_world_readable_profiling_group_fails():
    """A profile is a map of the application's internals — method names, call
    frequencies, where the time goes."""
    s = _cgp(WIDE_OPEN)
    s._check_codeguruprofiler()
    _renders(s, "CGP-01", "MEDIUM", contains="billing")


def test_cgp01_passes_on_an_account_scoped_policy():
    s = _cgp(SCOPED)
    s._check_codeguruprofiler()
    assert not _ids(s, "CGP-01", "FAIL")


# ═════════════════════════════════════════════════════════════════════════════
# DSQL-01 (MEDIUM) — deletion protection off on a distributed SQL cluster
# ═════════════════════════════════════════════════════════════════════════════
def _dsql(cluster):
    c = MagicMock()
    c.list_clusters.return_value = {"clusters": [{"identifier": "cl-1"}]}
    c.get_cluster.return_value = cluster
    return _scanner("AURORADSQL", "dsql", c)


def test_dsql01_cluster_without_deletion_protection_fails():
    s = _dsql({"identifier": "cl-1", "deletionProtectionEnabled": False})
    s._check_auroradsql()
    _renders(s, "DSQL-01", "MEDIUM", contains="cl-1")


def test_dsql01_absent_flag_is_not_a_finding():
    """`protection_known` gates on the value being a real bool. An absent field is
    an unknown, and reporting an unknown as a failure is how a scanner earns a
    reputation for noise."""
    s = _dsql({"identifier": "cl-1"})
    s._check_auroradsql()
    assert not _ids(s, "DSQL-01", "FAIL")
    assert not _ids(s, "DSQL-01", "PASS")


# ═════════════════════════════════════════════════════════════════════════════
# FMS-01 (MEDIUM) — a Firewall Manager policy that reports without enforcing
# ═════════════════════════════════════════════════════════════════════════════
def _fms(policy):
    c = MagicMock()
    c.list_policies.return_value = {"PolicyList": [{"PolicyId": "p-1",
                                                    "PolicyName": "edge"}]}
    c.get_policy.return_value = {"Policy": policy}
    c.get_notification_channel.return_value = {"SnsTopicArn": "arn:aws:sns:x"}
    return _scanner("FIREWALLMANAGER", "fms", c)


def test_fms01_policy_that_does_not_remediate_fails():
    """A control that reports without enforcing looks like coverage on a dashboard
    and changes nothing in the account."""
    s = _fms({"PolicyId": "p-1", "PolicyName": "edge", "RemediationEnabled": False})
    s._check_firewallmanager()
    _renders(s, "FMS-01", "MEDIUM", contains="edge")


def test_fms01_passes_when_remediation_is_on():
    s = _fms({"PolicyId": "p-1", "PolicyName": "edge", "RemediationEnabled": True})
    s._check_firewallmanager()
    assert not _ids(s, "FMS-01", "FAIL")
    assert _ids(s, "FMS-01", "PASS")


# ═════════════════════════════════════════════════════════════════════════════
# GRF-01 (MEDIUM) — a Grafana workspace that reaches across the organization
# ═════════════════════════════════════════════════════════════════════════════
def _grafana(workspace):
    c = MagicMock()
    c.list_workspaces.return_value = {"workspaces": [{"id": "g-1"}]}
    c.describe_workspace.return_value = {"workspace": workspace}
    return _scanner("MANAGEDGRAFANA", "grafana", c)


def test_grf01_organization_wide_workspace_fails():
    """Anyone who can sign in to the workspace inherits its reach into every
    account in the organization."""
    s = _grafana({"id": "g-1", "name": "obs",
                  "accountAccessType": "ORGANIZATION"})
    s._check_managedgrafana()
    _renders(s, "GRF-01", "MEDIUM", contains="obs")


def test_grf01_passes_on_a_current_account_workspace():
    s = _grafana({"id": "g-1", "name": "obs",
                  "accountAccessType": "CURRENT_ACCOUNT"})
    s._check_managedgrafana()
    assert not _ids(s, "GRF-01", "FAIL")
    assert _ids(s, "GRF-01", "PASS")


# ═════════════════════════════════════════════════════════════════════════════
# IMI-01 (MEDIUM) — IoT managed integrations on the default key
# ═════════════════════════════════════════════════════════════════════════════
def _imi(encryption_type):
    c = MagicMock()
    c.get_default_encryption_configuration.return_value = (
        {"encryptionType": encryption_type} if encryption_type else {})
    return _scanner("IOTMANAGEDINT", "iot-managed-integrations", c)


def test_imi01_default_encryption_fails():
    """This store holds connection material for third-party device clouds."""
    s = _imi("MANAGED_INTEGRATIONS_DEFAULT_ENCRYPTION")
    s._check_iotmanagedint()
    _renders(s, "IMI-01", "MEDIUM")


def test_imi01_passes_on_a_customer_key():
    s = _imi("CUSTOMER_KEY_ENCRYPTION")
    s._check_iotmanagedint()
    assert not _ids(s, "IMI-01", "FAIL")


def test_imi01_says_nothing_when_the_type_is_absent():
    s = _imi(None)
    s._check_iotmanagedint()
    assert not _ids(s, "IMI-01")


# ═════════════════════════════════════════════════════════════════════════════
# LATT-02 (MEDIUM) — a VPC Lattice auth policy open to any principal
# ═════════════════════════════════════════════════════════════════════════════
def _lattice(policy, auth_type="AWS_IAM"):
    c = MagicMock()
    c.list_services.return_value = {"items": [{"id": "svc-1", "name": "orders"}]}
    c.get_service.return_value = {"id": "svc-1", "name": "orders",
                                  "authType": auth_type}
    c.get_auth_policy.return_value = {"policy": policy}
    return _scanner("VPCLATTICE", "vpc-lattice", c)


def test_latt02_permissive_auth_policy_fails():
    """LATT-01 asks whether authentication is required at all; LATT-02 asks whether
    the policy behind it narrows anything. A service can require AWS_IAM and still
    admit every principal in the world."""
    s = _lattice(WIDE_OPEN)
    s._check_vpclattice()
    _renders(s, "LATT-02", "MEDIUM", contains="orders")


def test_latt02_passes_on_a_scoped_auth_policy():
    s = _lattice(SCOPED)
    s._check_vpclattice()
    assert not _ids(s, "LATT-02", "FAIL")
    assert _ids(s, "LATT-02", "PASS")


# ═════════════════════════════════════════════════════════════════════════════
# MBC-01 (MEDIUM) — blockchain CA logging off
# ═════════════════════════════════════════════════════════════════════════════
def _mbc(member):
    c = MagicMock()
    c.list_networks.return_value = {"Networks": [{"Id": "n-1"}]}
    c.list_members.return_value = {"Members": [{"Id": "m-1", "Name": "org"}]}
    c.get_member.return_value = {"Member": member}
    return _scanner("MANAGEDBLOCKCHAIN", "managedblockchain", c)


def test_mbc01_certificate_authority_without_logging_fails():
    """The CA is what admits identities to an immutable ledger. Without its log
    there is no record of who was admitted, and the ledger's immutability makes
    that worse rather than better."""
    s = _mbc({"Id": "m-1", "Name": "org",
              "LogPublishingConfiguration": {
                  "Fabric": {"CaLogs": {"Cloudwatch": {"Enabled": False}}}}})
    s._check_managedblockchain()
    _renders(s, "MBC-01", "MEDIUM")


def test_mbc01_passes_when_ca_logging_is_on():
    s = _mbc({"Id": "m-1", "Name": "org",
              "LogPublishingConfiguration": {
                  "Fabric": {"CaLogs": {"Cloudwatch": {"Enabled": True}}}}})
    s._check_managedblockchain()
    assert not _ids(s, "MBC-01", "FAIL")


# ═════════════════════════════════════════════════════════════════════════════
# MPV-01 (MEDIUM) — a MediaPackage channel anyone may ingest to
# ═════════════════════════════════════════════════════════════════════════════
def _mpv(policy):
    c = MagicMock()
    c.list_channel_groups.return_value = {"Items": [{"ChannelGroupName": "live"}]}
    c.list_channels.return_value = {"Items": [{"ChannelName": "main"}]}
    c.get_channel_policy.return_value = {"Policy": policy}
    return _scanner("MEDIAPACKAGE", "mediapackagev2", c)


def test_mpv01_wildcard_ingest_policy_fails():
    """A channel policy governs who may INGEST — a wildcard is an open door to
    whatever the audience is about to watch."""
    s = _mpv(WIDE_OPEN)
    s._check_mediapackage()
    _renders(s, "MPV-01", "MEDIUM", contains="main")


def test_mpv01_passes_on_a_scoped_channel_policy():
    s = _mpv(SCOPED)
    s._check_mediapackage()
    assert not _ids(s, "MPV-01", "FAIL")
    assert _ids(s, "MPV-01", "PASS")


# ═════════════════════════════════════════════════════════════════════════════
# NWM-01 (MEDIUM) — a Cloud WAN global network with a public resource policy
# ═════════════════════════════════════════════════════════════════════════════
def _nwm(policy):
    c = MagicMock()
    c.describe_global_networks.return_value = {
        "GlobalNetworks": [{"GlobalNetworkId": "gn-1",
                            "GlobalNetworkArn": f"arn:aws:networkmanager::{OWN}:gn/1"}]}
    c.get_resource_policy.return_value = {"PolicyDocument": policy}
    return _scanner("CLOUDWAN", "networkmanager", c)


def test_nwm01_wildcard_resource_policy_fails():
    """The core network policy is the segmentation map: who may attach, and what
    reaches what once attached."""
    s = _nwm(WIDE_OPEN)
    s._check_cloudwan()
    _renders(s, "NWM-01", "MEDIUM", contains="gn-1")


def test_nwm01_passes_on_a_scoped_resource_policy():
    s = _nwm(SCOPED)
    s._check_cloudwan()
    assert not _ids(s, "NWM-01", "FAIL")


# ═════════════════════════════════════════════════════════════════════════════
# SGW-02 (MEDIUM) — a Storage Gateway share not on a customer-managed key
# ═════════════════════════════════════════════════════════════════════════════
ARN_NFS = f"arn:aws:storagegateway:{REGION}:{OWN}:share/share-nfs"
ARN_SMB = f"arn:aws:storagegateway:{REGION}:{OWN}:share/share-smb"


def _sgw(*, nfs=None, smb=None):
    c = MagicMock()
    infos = []
    if nfs is not None:
        infos.append({"FileShareType": "NFS", "FileShareARN": ARN_NFS})
    if smb is not None:
        infos.append({"FileShareType": "SMB", "FileShareARN": ARN_SMB})
    c.list_file_shares.return_value = {"FileShareInfoList": infos}
    c.describe_nfs_file_shares.return_value = {"NFSFileShareInfoList":
                                               [nfs] if nfs else []}
    c.describe_smb_file_shares.return_value = {"SMBFileShareInfoList":
                                               [smb] if smb else []}
    return _scanner("STORAGEGATEWAY", "storagegateway", c)


def test_sgw02_smb_share_without_a_cmk_fails():
    """A file share is a window onto an S3 bucket, and the key decides who can look
    through it from the storage side."""
    s = _sgw(smb={"FileShareARN": ARN_SMB, "KMSEncrypted": False})
    s._check_storagegateway()
    _renders(s, "SGW-02", "MEDIUM", contains="share-smb")


def test_sgw02_also_fires_on_the_nfs_path():
    """Two loops, two describe calls, one control. The NFS arm reports SGW-02 as a
    second finding beside SGW-01, so a regression in either loop is visible."""
    s = _sgw(nfs={"FileShareARN": ARN_NFS, "KMSEncrypted": False,
                  "ClientList": ["10.0.0.0/8"]})
    s._check_storagegateway()
    assert _ids(s, "SGW-02", "FAIL"), "the NFS loop did not report SGW-02"


def test_sgw02_passes_on_a_customer_managed_key():
    s = _sgw(smb={"FileShareARN": ARN_SMB, "KMSEncrypted": True})
    s._check_storagegateway()
    assert not _ids(s, "SGW-02", "FAIL")
    assert _ids(s, "SGW-02", "PASS")


def test_sgw02_absent_flag_is_not_a_finding():
    s = _sgw(smb={"FileShareARN": ARN_SMB})
    s._check_storagegateway()
    assert not _ids(s, "SGW-02")


# ═════════════════════════════════════════════════════════════════════════════
# SFN-01 (MEDIUM), SFN-02 and SFN-03 (LOW) — a whole section nothing ran
#
# STEPFUNCTIONS had no test of any kind, which is why all three ids sat in the
# never-observed bucket together rather than one of them looking odd. Only SFN-01
# has a FAIL path: SFN-02 and SFN-03 are PASS-or-WARN by construction, and that
# is the right shape for them — "X-Ray is off" and "encrypted with the AWS-managed
# key" are hardening preferences, not defects, which is exactly why both were
# brought down to LOW. Being never-observed and having no FAIL path are different
# problems; these tests fix the first and deliberately leave the second alone.
# ═════════════════════════════════════════════════════════════════════════════
SFN_ARN = f"arn:aws:states:{REGION}:{OWN}:stateMachine:orders"


def _sfn(detail, machines=None):
    c = MagicMock()
    c.list_state_machines.return_value = {
        "stateMachines": [{"name": "orders", "stateMachineArn": SFN_ARN}]
        if machines is None else machines}
    c.describe_state_machine.return_value = detail
    return _scanner("STEPFUNCTIONS", "stepfunctions", c)


def test_sfn01_state_machine_with_logging_off_fails():
    """A state machine is an orchestrator: it is the thing that called the other
    things. With logging off there is no record of what it ran or with what."""
    s = _sfn({"loggingConfiguration": {"level": "OFF"}})
    s._check_stepfunctions()
    _renders(s, "SFN-01", "MEDIUM", contains="orders")


def test_sfn01_absent_logging_configuration_is_treated_as_off():
    """`level` defaults to "OFF" when the block is missing, which is what the API
    means by an unconfigured machine — so an absent block is a real finding here
    rather than an unknown."""
    s = _sfn({})
    s._check_stepfunctions()
    assert _ids(s, "SFN-01", "FAIL")


def test_sfn01_passes_when_logging_is_on():
    s = _sfn({"loggingConfiguration": {"level": "ALL"}})
    s._check_stepfunctions()
    assert not _ids(s, "SFN-01", "FAIL")
    assert _ids(s, "SFN-01", "PASS")


def test_sfn01_reports_an_empty_account_as_info_not_a_pass():
    """No state machines is not a clean result, and an INFO says so without
    claiming the account passed a check it never ran."""
    s = _sfn({}, machines=[])
    s._check_stepfunctions()
    assert _ids(s, "SFN-01", "INFO")
    assert not _ids(s, "SFN-01", "PASS")


def test_sfn02_tracing_off_warns_and_on_passes():
    """Both arms, because a check observed in only one state is half observed."""
    off = _sfn({"loggingConfiguration": {"level": "ALL"}})
    off._check_stepfunctions()
    assert _ids(off, "SFN-02", "WARN")

    on = _sfn({"loggingConfiguration": {"level": "ALL"},
               "tracingConfiguration": {"enabled": True}})
    on._check_stepfunctions()
    assert _ids(on, "SFN-02", "PASS")


def test_sfn03_aws_managed_key_warns_and_a_cmk_passes():
    aws_key = _sfn({"loggingConfiguration": {"level": "ALL"}})
    aws_key._check_stepfunctions()
    assert _ids(aws_key, "SFN-03", "WARN")

    cmk = _sfn({"loggingConfiguration": {"level": "ALL"},
                "encryptionConfiguration": {
                    "kmsKeyId": f"arn:aws:kms:{REGION}:{OWN}:key/abc"}})
    cmk._check_stepfunctions()
    assert _ids(cmk, "SFN-03", "PASS")


def test_sfn02_and_sfn03_have_no_fail_path_and_that_is_deliberate():
    """Pinned like WAF-01 in tranche 7. Both render LOW and describe a preference
    rather than a defect. If either gains a FAIL path this fails, and whoever added
    it has to decide that deliberately instead of inheriting it from a fixture."""
    import ast
    src = open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "engine", "aws_live_scanner.py"), encoding="utf-8").read()
    fails = {
        n.args[1].value for n in ast.walk(ast.parse(src))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "_add" and len(n.args) >= 2
        and isinstance(n.args[0], ast.Constant) and n.args[0].value == "FAIL"
        and isinstance(n.args[1], ast.Constant)
        and n.args[1].value in ("SFN-02", "SFN-03")}
    assert not fails, (
        f"{sorted(fails)} gained a FAIL path. That may well be right, but it "
        f"changes the severity these ids can render, so update the catalogue and "
        f"delete this pin deliberately.")


# ═════════════════════════════════════════════════════════════════════════════
# SM-16, SM-18, SM-20 (MEDIUM) — the encryption half of three monitoring kinds
#
# `_check_sagemaker_monitoring` asks two questions of five resource kinds. The
# isolation half fired for all five; the encryption half fired for only two,
# which looks arbitrary until you see why: it is skipped entirely unless
# `encryption_applicable`, and that is `instance_count >= 2`. There is no
# inter-container traffic on one instance, so the control genuinely cannot be
# failed there — the fixtures simply never configured a second instance for
# these three kinds.
#
# None of these ids appears as a literal anywhere in the scanner: they are
# resolved through `SECURITY_HUB_PARITY[ctl][0]`, which is why a grep for the
# emit site finds nothing and wrongly concludes the check is dead code.
# ═════════════════════════════════════════════════════════════════════════════
_MONITORING_LISTS = {
    "list_data_quality_job_definitions": "JobDefinitionSummaries",
    "list_model_explainability_job_definitions": "JobDefinitionSummaries",
    "list_model_bias_job_definitions": "JobDefinitionSummaries",
    "list_model_quality_job_definitions": "JobDefinitionSummaries",
    "list_monitoring_schedules": "MonitoringScheduleSummaries",
}


def _job_detail(*, instances, encrypted=False, isolated=False):
    return {
        "NetworkConfig": {"EnableNetworkIsolation": isolated,
                          "EnableInterContainerTrafficEncryption": encrypted},
        "JobResources": {"ClusterConfig": {"InstanceCount": instances}},
    }


def _sagemaker_monitoring(list_op, describe_op, detail):
    """A SageMaker client that offers exactly one monitoring kind.

    Every other list operation returns an empty page rather than a bare MagicMock,
    because `_sm_page` reads `resp.get(key)` and a MagicMock is truthy — one
    unconfigured operation quietly turns into a page of mocks."""
    sm = MagicMock()
    for op, key in _MONITORING_LISTS.items():
        getattr(sm, op).return_value = {key: []}
    getattr(sm, list_op).return_value = {
        "JobDefinitionSummaries": [{"MonitoringJobDefinitionName": "job-1"}]}
    getattr(sm, describe_op).return_value = detail
    s = make_scanner(sections=["SAGEMAKER"])
    s.account = OWN
    return s, sm


_ENC_KINDS = [
    ("SM-16", "list_model_explainability_job_definitions",
     "describe_model_explainability_job_definition"),
    ("SM-18", "list_model_bias_job_definitions",
     "describe_model_bias_job_definition"),
    ("SM-20", "list_model_quality_job_definitions",
     "describe_model_quality_job_definition"),
]


def test_sm16_18_20_fail_on_multi_instance_jobs_without_encryption():
    """Two instances is the threshold at which the traffic exists at all."""
    for cid, list_op, desc_op in _ENC_KINDS:
        s, sm = _sagemaker_monitoring(list_op, desc_op,
                                      _job_detail(instances=2, encrypted=False))
        s._check_sagemaker_monitoring(sm)
        _renders(s, cid, "MEDIUM", contains="job-1")


def test_sm16_18_20_are_silent_on_a_single_instance():
    """The reason they were never observed, pinned. A single-instance job has no
    inter-container traffic, so failing it would be a finding about a risk the
    configuration cannot have."""
    for cid, list_op, desc_op in _ENC_KINDS:
        s, sm = _sagemaker_monitoring(list_op, desc_op,
                                      _job_detail(instances=1, encrypted=False))
        s._check_sagemaker_monitoring(sm)
        assert not _ids(s, cid), (
            f"{cid} reported on a single-instance job, where the control does "
            f"not apply")


def test_sm16_18_20_pass_when_multi_instance_traffic_is_encrypted():
    for cid, list_op, desc_op in _ENC_KINDS:
        s, sm = _sagemaker_monitoring(list_op, desc_op,
                                      _job_detail(instances=2, encrypted=True))
        s._check_sagemaker_monitoring(sm)
        assert not _ids(s, cid, "FAIL")
        assert _ids(s, cid, "PASS")


def test_the_isolation_half_is_unconditional():
    """SM-15/17/19 report on one instance where SM-16/18/20 do not — the asymmetry
    is the design, not an oversight, so it is asserted rather than assumed."""
    s, sm = _sagemaker_monitoring(
        "list_model_bias_job_definitions",
        "describe_model_bias_job_definition",
        _job_detail(instances=1, isolated=False))
    s._check_sagemaker_monitoring(sm)
    assert _ids(s, "SM-17", "FAIL"), "isolation must report on a single instance"
    assert not _ids(s, "SM-18")


# ═════════════════════════════════════════════════════════════════════════════
# SM-24 (MEDIUM) — feature group online store without a customer key
# ═════════════════════════════════════════════════════════════════════════════
def _feature_group(detail):
    sm = MagicMock()
    sm.list_feature_groups.return_value = {
        "FeatureGroupSummaries": [{"FeatureGroupName": "customers"}]}
    sm.describe_feature_group.return_value = detail
    s = make_scanner(sections=["SAGEMAKER"])
    s.account = OWN
    return s, sm


def test_sm24_standard_online_store_without_a_key_fails():
    s, sm = _feature_group({"OnlineStoreConfig": {"StorageType": "Standard"}})
    s._check_sagemaker_feature_groups(sm)
    _renders(s, "SM-24", "MEDIUM", contains="customers")


def test_sm24_does_not_apply_to_an_in_memory_online_store():
    """The control names STANDARD storage. InMemory is a different product, and a
    finding scoped to the other one is not actionable."""
    s, sm = _feature_group({"OnlineStoreConfig": {"StorageType": "InMemory"}})
    s._check_sagemaker_feature_groups(sm)
    assert not _ids(s, "SM-24")


def test_sm24_passes_with_a_security_config_key():
    s, sm = _feature_group({"OnlineStoreConfig": {
        "StorageType": "Standard",
        "SecurityConfig": {"KmsKeyId": f"arn:aws:kms:{REGION}:{OWN}:key/abc"}}})
    s._check_sagemaker_feature_groups(sm)
    assert not _ids(s, "SM-24", "FAIL")
    assert _ids(s, "SM-24", "PASS")


# ═════════════════════════════════════════════════════════════════════════════
# SM-26 (MEDIUM) — captured inference payloads with no key
# ═════════════════════════════════════════════════════════════════════════════
def _inference_experiment(detail):
    sm = MagicMock()
    sm.list_inference_experiments.return_value = {
        "InferenceExperiments": [{"Name": "shadow-1"}]}
    sm.describe_inference_experiment.return_value = detail
    s = make_scanner(sections=["SAGEMAKER"])
    s.account = OWN
    return s, sm


def test_sm26_captured_data_without_a_key_fails():
    """Captured payloads are the real inference traffic — the requests customers
    actually sent and what the model actually answered."""
    s, sm = _inference_experiment({"DataStorageConfig": {"Destination": "s3://b/x"}})
    s._check_sagemaker_inference_experiments(sm)
    _renders(s, "SM-26", "MEDIUM", contains="shadow-1")


def test_sm26_is_silent_when_capture_is_off():
    """With no capture there is no payload, so the control does not apply and
    nothing is claimed in either direction."""
    s, sm = _inference_experiment({})
    s._check_sagemaker_inference_experiments(sm)
    assert not _ids(s, "SM-26")
    assert _ids(s, "SM-25", "FAIL"), "SM-25 is unconditional and should still fire"


def test_sm26_passes_with_a_key_on_the_capture_destination():
    s, sm = _inference_experiment({"DataStorageConfig": {
        "Destination": "s3://b/x",
        "KmsKey": f"arn:aws:kms:{REGION}:{OWN}:key/abc"}})
    s._check_sagemaker_inference_experiments(sm)
    assert not _ids(s, "SM-26", "FAIL")
    assert _ids(s, "SM-26", "PASS")


# ═════════════════════════════════════════════════════════════════════════════
# SM-27 (LOW) — an untagged app image config
# ═════════════════════════════════════════════════════════════════════════════
def _app_image_config(tags):
    sm = MagicMock()
    sm.list_app_image_configs.return_value = {"AppImageConfigs": [{
        "AppImageConfigName": "jupyter",
        "AppImageConfigArn": f"arn:aws:sagemaker:{REGION}:{OWN}:app-image-config/j"}]}
    sm.list_images.return_value = {"Images": []}
    sm.list_tags.return_value = {"Tags": tags}
    s = make_scanner(sections=["SAGEMAKER"])
    s.account = OWN
    return s, sm


def test_sm27_untagged_app_image_config_fails():
    """Inventory hygiene rather than posture, which is why it is LOW — but an
    untagged resource cannot be attributed to an owner."""
    s, sm = _app_image_config([])
    s._check_sagemaker_tagging(sm)
    _renders(s, "SM-27", "LOW", contains="jupyter")


def test_sm27_ignores_aws_system_tags():
    """`aws:` tags are applied by AWS, so a resource carrying only those is still
    untagged as far as ownership goes."""
    s, sm = _app_image_config([{"Key": "aws:cloudformation:stack-name",
                                "Value": "s"}])
    s._check_sagemaker_tagging(sm)
    assert _ids(s, "SM-27", "FAIL")


def test_sm27_passes_with_any_non_system_tag():
    s, sm = _app_image_config([{"Key": "Owner", "Value": "ml-team"}])
    s._check_sagemaker_tagging(sm)
    assert not _ids(s, "SM-27", "FAIL")
    assert _ids(s, "SM-27", "PASS")


# ═════════════════════════════════════════════════════════════════════════════
# VPC-03 (MEDIUM) — a VPC with no flow logs
#
# Three arms, and only the middle one had ever run. A default VPC WARNs and a
# non-default VPC FAILs, which is the distinction that makes the check usable:
# almost every account carries an unused default VPC, and failing it teaches
# people to ignore the id.
# ═════════════════════════════════════════════════════════════════════════════
def _vpc(vpcs, flow_log_ids=()):
    ec2 = MagicMock()
    ec2.describe_vpcs.return_value = {"Vpcs": vpcs}
    ec2.describe_flow_logs.return_value = {
        "FlowLogs": [{"ResourceId": r} for r in flow_log_ids]}
    ec2.describe_security_groups.return_value = {"SecurityGroups": []}
    ec2.describe_network_acls.return_value = {"NetworkAcls": []}
    return _scanner("VPC", "ec2", ec2), ec2


def test_vpc03_non_default_vpc_without_flow_logs_fails():
    s, _ = _vpc([{"VpcId": "vpc-1", "IsDefault": False}])
    s._check_vpc()
    _renders(s, "VPC-03", "MEDIUM", contains="vpc-1")


def test_vpc03_default_vpc_only_warns():
    """A default VPC nobody uses is not the same finding as a production VPC with
    no traffic record, and collapsing the two would make the id noise."""
    s, _ = _vpc([{"VpcId": "vpc-def", "IsDefault": True}])
    s._check_vpc()
    assert not _ids(s, "VPC-03", "FAIL")
    assert _ids(s, "VPC-03", "WARN")


def test_vpc03_passes_when_flow_logs_exist():
    s, _ = _vpc([{"VpcId": "vpc-1", "IsDefault": False}], flow_log_ids=["vpc-1"])
    s._check_vpc()
    assert not _ids(s, "VPC-03", "FAIL")
    assert _ids(s, "VPC-03", "PASS")


# ═════════════════════════════════════════════════════════════════════════════
# DATA-03 (MEDIUM) — an unencrypted crown-jewel bucket
#
# Macie's score semantics are full of traps (-1 error, 1 empty, 50 the neutral
# default), so `is_crown_jewel` refuses to call anything a crown jewel without a
# real score ABOVE the default on a bucket with classifiable objects. That is why
# a naive fixture produces no DATA-xx findings at all.
# ═════════════════════════════════════════════════════════════════════════════
def _macie(bucket, status="ENABLED"):
    from test_live_scanner import MockPaginator
    mac = MagicMock()
    mac.get_macie_session.return_value = {"status": status}
    mac.get_paginator.return_value = MockPaginator("buckets", [bucket])
    s = _scanner("DATA", "macie2", mac)
    from engine import aws_graph
    return s, aws_graph.SecurityGraph()


def _sensitive_bucket(**over):
    b = {"bucketName": "customer-exports", "classifiableObjectCount": 42,
         "sensitivityScore": 80}
    b.update(over)
    return b


def test_data03_unencrypted_crown_jewel_bucket_fails():
    s, g = _macie(_sensitive_bucket(serverSideEncryption={"type": "NONE"}))
    s._collect_macie(g)
    _renders(s, "DATA-03", "MEDIUM", contains="customer-exports")


def test_data03_is_silent_on_an_encrypted_crown_jewel():
    s, g = _macie(_sensitive_bucket(serverSideEncryption={"type": "AES256"}))
    s._collect_macie(g)
    assert not _ids(s, "DATA-03")
    assert _ids(s, "DATA-01", "FAIL"), "it is still a crown jewel"


def test_data03_is_silent_at_the_neutral_macie_score():
    """50 is the default Macie assigns before it has analysed anything. Treating it
    as sensitive would make every unanalysed bucket a finding."""
    s, g = _macie(_sensitive_bucket(sensitivityScore=50,
                                    serverSideEncryption={"type": "NONE"}))
    s._collect_macie(g)
    assert not _ids(s, "DATA-03")


# ═════════════════════════════════════════════════════════════════════════════
# SEC-04 (LOW) — a secret nobody has read in over 90 days
# ═════════════════════════════════════════════════════════════════════════════
def _secrets(secret):
    from test_live_scanner import MockPaginator
    sm = MagicMock()
    sm.get_paginator.return_value = MockPaginator("SecretList", [secret])
    sm.get_resource_policy.return_value = {}
    return _scanner("SECRETS", "secretsmanager", sm), sm


def _aged_secret(days_since_access):
    from datetime import datetime, timedelta, timezone
    return {"Name": "legacy/db", "RotationEnabled": True,
            "RotationRules": {"AutomaticallyAfterDays": 30},
            "KmsKeyId": f"arn:aws:kms:{REGION}:{OWN}:key/abc",
            "LastAccessedDate": datetime.now(timezone.utc)
            - timedelta(days=days_since_access)}


def test_sec04_stale_secret_warns():
    """An unused secret is still a live credential; it is LOW because unused is not
    itself a breach, and a WARN because 'nobody read it' is not a misconfiguration."""
    s, sm = _secrets(_aged_secret(200))
    s._check_secrets()
    hits = _ids(s, "SEC-04", "WARN")
    assert hits, "SEC-04 did not warn on a 200-day-stale secret"
    assert "legacy/db" in hits[0].message


def test_sec04_is_silent_inside_the_90_day_window():
    s, sm = _secrets(_aged_secret(10))
    s._check_secrets()
    assert not _ids(s, "SEC-04")


def test_sec04_is_silent_when_the_secret_was_never_accessed():
    """No LastAccessedDate is an unknown, not a stale secret."""
    s, sm = _secrets({"Name": "fresh", "RotationEnabled": True,
                      "RotationRules": {"AutomaticallyAfterDays": 30},
                      "KmsKeyId": "arn:aws:kms:x"})
    s._check_secrets()
    assert not _ids(s, "SEC-04")


# ═════════════════════════════════════════════════════════════════════════════
# SEG-06 (LOW) — internet-exposed on a sensitive port AND free to egress
# ═════════════════════════════════════════════════════════════════════════════
def _sg_pair(*, ingress_port, egress_all, attached=True):
    from engine import aws_exposure
    sg = {"GroupId": "sg-1", "GroupName": "app", "VpcId": "vpc-1",
          "IpPermissions": [{"IpProtocol": "tcp", "FromPort": ingress_port,
                             "ToPort": ingress_port,
                             "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                             "Ipv6Ranges": []}],
          "IpPermissionsEgress": ([{"IpProtocol": "-1",
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                    "Ipv6Ranges": []}] if egress_all else [])}
    enis = ([{"NetworkInterfaceId": "eni-1", "SubnetId": "subnet-1",
              "VpcId": "vpc-1", "Groups": [{"GroupId": "sg-1"}],
              "Status": "in-use"}] if attached else [])
    return aws_exposure.microseg_findings([sg], enis)


def test_seg06_world_open_admin_port_with_open_egress_warns():
    """The pairing is the finding: inbound gets an attacker in, unrestricted egress
    is how the data leaves."""
    found = _sg_pair(ingress_port=22, egress_all=True)
    seg06 = [f for f in found if f["id"] == "SEG-06"]
    assert seg06, "no SEG-06 for a world-open SSH group with all-egress"
    assert seg06[0]["status"] == "WARN"
    assert "exfiltrate" in seg06[0]["message"]


def test_seg06_needs_both_halves():
    """Open egress alone is the AWS default on every security group ever created,
    so flagging it by itself would fire on the whole estate."""
    assert not [f for f in _sg_pair(ingress_port=22, egress_all=False)
                if f["id"] == "SEG-06"]
    assert not [f for f in _sg_pair(ingress_port=8080, egress_all=True)
                if f["id"] == "SEG-06"], "8080 is not a sensitive port"


def test_seg06_is_silent_on_an_unattached_group():
    assert not [f for f in _sg_pair(ingress_port=22, egress_all=True,
                                    attached=False)
                if f["id"] == "SEG-06"]


def test_seg06_renders_through_the_scanner():
    """`microseg_findings` returns dicts and never touches `_add`, so exercising the
    producer alone leaves the id unobserved in `docs/CHECK_FIRING.md` — the check
    would still read as dead. Tranche 7 hit exactly this with SEG-02."""
    from engine import aws_graph
    s = make_scanner(sections=["EXPOSURE"])
    s.account = OWN
    s.graph = aws_graph.SecurityGraph()
    for f in _sg_pair(ingress_port=22, egress_all=True):
        s._add(f["status"], f["id"], "EXPOSURE", f["resource"], f["message"])
    hits = _ids(s, "SEG-06", "WARN")
    assert hits, "SEG-06 never reached _add"
    assert hits[0].severity == "LOW", (
        "a WARN is forced to LOW by _add regardless of the catalogue, which is "
        "why SEG-06 is declared LOW rather than advertising a severity it cannot "
        "render")


# ═════════════════════════════════════════════════════════════════════════════
# MART-03 (LOW) — a model artifact in somebody else's bucket
#
# WARN and LOW deliberately: the only ownership signal is whether the bucket NAME
# carries a different 12-digit account id. `_looks_like_account_scoped` exists to
# SUPPRESS the finding on obviously-own buckets, not to assert foreignness, so a
# FAIL here would be an assertion from a naming convention.
# ═════════════════════════════════════════════════════════════════════════════
def _artifact_scanner():
    s = make_scanner(sections=["SAGEMAKER"])
    s.account = OWN
    s._bucket_write_scope = lambda arn: "ACCOUNT"     # readable, not external
    return s


def test_mart03_bucket_named_for_another_account_warns():
    s = _artifact_scanner()
    s._assess_model_artifact("fraud-v2", {
        "uri": "s3://ml-artifacts-999988887777/model.tar.gz",
        "channel": "primary", "pinned": True})
    hits = _ids(s, "MART-03", "WARN")
    assert hits, "MART-03 did not warn on a foreign-looking artifact bucket"
    assert "fraud-v2" in hits[0].message


def test_mart03_is_silent_on_a_bucket_carrying_our_own_account_id():
    s = _artifact_scanner()
    s._assess_model_artifact("fraud-v2", {
        "uri": f"s3://ml-artifacts-{OWN}/model.tar.gz",
        "channel": "primary", "pinned": True})
    assert not _ids(s, "MART-03")


def test_mart03_is_silent_on_a_bucket_with_no_account_id_in_the_name():
    """The suppression helper only recognises a 12-digit component. A plainly-named
    bucket carries no ownership signal at all, so nothing is claimed."""
    s = _artifact_scanner()
    s._assess_model_artifact("fraud-v2", {
        "uri": "s3://company-models/model.tar.gz",
        "channel": "primary", "pinned": True})
    assert not _ids(s, "MART-03")


# ═════════════════════════════════════════════════════════════════════════════
# THE "RUNS BUT NEVER FAILS" MEDIUMS
#
# `_add` reads severity, compliance and remediation from the catalogue ONLY for a
# FAIL. A WARN is forced to LOW and carries no remediation. So a check declared
# MEDIUM that the suite has only ever driven to PASS or WARN has never once
# rendered what the catalogue advertises for it, and nothing would notice if the
# FAIL branch were broken.
#
# Eight of the twelve have a real FAIL path that no fixture had reached. Two more
# (SM-22, SM-25) are computed-id SageMaker controls. ACM-05 and SHAI-03 have no
# FAIL path at all and are handled separately at the bottom of this file.
# ═════════════════════════════════════════════════════════════════════════════
def test_ddb04_table_without_deletion_protection_fails():
    from test_live_scanner import MockPaginator
    ddb = MagicMock()
    ddb.get_paginator.return_value = MockPaginator("TableNames", ["orders"])
    ddb.describe_table.return_value = {"Table": {
        "TableName": "orders",
        "TableArn": f"arn:aws:dynamodb:{REGION}:{OWN}:table/orders",
        "DeletionProtectionEnabled": False,
        "SSEDescription": {"Status": "ENABLED", "SSEType": "KMS"},
        "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"}}}
    ddb.describe_continuous_backups.return_value = {
        "ContinuousBackupsDescription": {
            "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": "ENABLED"}}}
    ddb.get_resource_policy.side_effect = Exception("PolicyNotFound")
    s = _scanner("DYNAMODB", "dynamodb", ddb)
    s._check_dynamodb()
    _renders(s, "DDB-04", "MEDIUM", contains="orders")


def test_enc03_customer_key_without_rotation_fails():
    """Only CUSTOMER-managed, Enabled keys are asked the question: AWS-managed keys
    rotate on AWS's schedule and a disabled key rotates nothing."""
    kms = MagicMock()
    kms.get_paginator.return_value.paginate.return_value = [
        {"Keys": [{"KeyId": "key-1"}]}]
    kms.describe_key.return_value = {"KeyMetadata": {
        "KeyId": "key-1", "KeyManager": "CUSTOMER", "KeyState": "Enabled",
        "Description": "prod-data"}}
    kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}
    kms.get_key_policy.return_value = {"Policy": SCOPED}
    s = _scanner("KMS", "kms", kms)
    s._check_kms()
    _renders(s, "ENC-03", "MEDIUM", contains="prod-data")


def test_fw02_fleetwise_with_logging_off_fails():
    """Vehicle telemetry is personal data, and FleetWise logging off means no record
    of what was collected or where it went."""
    fw = MagicMock()
    fw.get_encryption_configuration.return_value = {
        "encryptionType": "KMS_BASED_ENCRYPTION",
        "kmsKeyId": f"arn:aws:kms:{REGION}:{OWN}:key/abc"}
    fw.get_logging_options.return_value = {"cloudWatchLogDelivery": {
        "logType": "OFF"}}
    s = _scanner("FLEETWISE", "iotfleetwise", fw)
    s._check_fleetwise()
    _renders(s, "FW-02", "MEDIUM")


def test_hsm01_cluster_with_no_backup_retention_policy_fails():
    """Backups are the one artefact that leaves an HSM, so how long they are kept
    is the only durability question the control plane can answer."""
    ch = MagicMock()
    ch.describe_clusters.return_value = {"Clusters": [
        {"ClusterId": "cluster-1",
         "ClusterArn": f"arn:aws:cloudhsm:{REGION}:{OWN}:cluster/cluster-1"}]}
    ch.describe_backups.return_value = {"Backups": []}
    s = _scanner("CLOUDHSM", "cloudhsmv2", ch)
    s._check_cloudhsm()
    _renders(s, "HSM-01", "MEDIUM", contains="cluster-1")


def _nfw(*, logging_dests, delete_protection):
    nfw = MagicMock()
    nfw.list_firewalls.return_value = {"Firewalls": [{"FirewallName": "edge"}]}
    nfw.describe_logging_configuration.return_value = {
        "LoggingConfiguration": {"LogDestinationConfigs": logging_dests}}
    nfw.describe_firewall.return_value = {"Firewall": {
        "FirewallName": "edge",
        "DeleteProtection": delete_protection,
        "SubnetChangeProtection": True,
        "FirewallPolicyChangeProtection": True}}
    return _scanner("NETWORKFIREWALL", "network-firewall", nfw)


def test_nfw01_firewall_with_no_log_destination_fails():
    """It is inspecting traffic and recording none of it — the one artefact an
    investigation would want does not exist."""
    s = _nfw(logging_dests=[], delete_protection=True)
    s._check_networkfirewall()
    _renders(s, "NFW-01", "MEDIUM", contains="edge")


def test_nfw03_firewall_without_delete_protection_fails():
    """The difference between a firewall and a suggestion, once somebody has
    console access."""
    s = _nfw(logging_dests=[{"LogType": "FLOW"}], delete_protection=False)
    s._check_networkfirewall()
    _renders(s, "NFW-03", "MEDIUM", contains="edge")


def test_nfw03_is_silent_when_no_protection_flag_is_a_bool():
    """`known` gates on at least one flag being a real bool, so an SDK that returns
    none of them is an unknown rather than an unprotected firewall."""
    nfw = MagicMock()
    nfw.list_firewalls.return_value = {"Firewalls": [{"FirewallName": "edge"}]}
    nfw.describe_logging_configuration.return_value = {
        "LoggingConfiguration": {"LogDestinationConfigs": [{"LogType": "FLOW"}]}}
    nfw.describe_firewall.return_value = {"Firewall": {"FirewallName": "edge"}}
    s = _scanner("NETWORKFIREWALL", "network-firewall", nfw)
    s._check_networkfirewall()
    assert not _ids(s, "NFW-03", "FAIL")


def test_osr03_domain_without_node_to_node_encryption_fails():
    osr = MagicMock()
    osr.list_domain_names.return_value = {"DomainNames": [{"DomainName": "logs"}]}
    osr.describe_domain.return_value = {"DomainStatus": {
        "DomainName": "logs",
        "EncryptionAtRestOptions": {"Enabled": True},
        "NodeToNodeEncryptionOptions": {"Enabled": False},
        "VPCOptions": {"SubnetIds": ["subnet-1"]},
        "DomainEndpointOptions": {"EnforceHTTPS": True},
        "AdvancedSecurityOptions": {"Enabled": True},
        "LogPublishingOptions": {}}}
    s = _scanner("OPENSEARCH", "opensearch", osr)
    s._check_opensearch()
    _renders(s, "OSR-03", "MEDIUM", contains="logs")


def test_s3t02_table_bucket_on_s3_managed_encryption_fails():
    """An S3 Tables bucket carries its OWN encryption setting, which no existing S3
    check inspects — AES256 is real encryption, but on a key you cannot revoke."""
    arn = f"arn:aws:s3tables:{REGION}:{OWN}:bucket/analytics"
    c = MagicMock()
    c.list_table_buckets.return_value = {"tableBuckets": [{"arn": arn}]}
    c.get_table_bucket_policy.return_value = {"resourcePolicy": SCOPED}
    c.get_table_bucket_encryption.return_value = {
        "encryptionConfiguration": {"sseAlgorithm": "AES256"}}
    s = _scanner("S3TABLES", "s3tables", c)
    s._check_s3tables()
    _renders(s, "S3T-02", "MEDIUM", contains="analytics")


def test_sm22_monitoring_schedule_encryption_fails_on_multiple_instances():
    """The fifth monitoring kind, and the last of the pair-halves. A schedule nests
    its NetworkConfig one level deeper than a job definition, under
    MonitoringScheduleConfig.MonitoringJobDefinition — which is exactly the shape
    `_network_config` exists to absorb."""
    sm = MagicMock()
    for op, key in _MONITORING_LISTS.items():
        getattr(sm, op).return_value = {key: []}
    sm.list_monitoring_schedules.return_value = {
        "MonitoringScheduleSummaries": [{"MonitoringScheduleName": "drift"}]}
    sm.describe_monitoring_schedule.return_value = {
        "MonitoringScheduleConfig": {"MonitoringJobDefinition": {
            "NetworkConfig": {"EnableNetworkIsolation": True,
                              "EnableInterContainerTrafficEncryption": False},
            "MonitoringResources": {"ClusterConfig": {"InstanceCount": 3}}}}}
    s = make_scanner(sections=["SAGEMAKER"])
    s.account = OWN
    s._check_sagemaker_monitoring(sm)
    _renders(s, "SM-22", "MEDIUM", contains="drift")


# ═════════════════════════════════════════════════════════════════════════════
# ACM-05 and SHAI-03 — declared MEDIUM, can only WARN, and that is correct
#
# Tranche 7's bucket-B pass named these two beside WAF-01 and left all three
# alone, on the grounds that each needed "a logic change rather than a status
# flip". That is right about the status flip and it left the other half undone:
# a check that can only WARN renders LOW no matter what the catalogue says, so
# declaring them MEDIUM advertised a severity neither could ever reach.
#
# Neither describes a defect:
#   * ACM-05 reports an IMPORTED certificate, or one INELIGIBLE for managed
#     renewal. Importing a certificate is a deliberate, common and legitimate
#     choice; the finding is "this one will not renew itself", which is an
#     operational reminder.
#   * SHAI-03's own message ends "Not applicable if the VPC does not use
#     Bedrock" — it cannot determine applicability, and says so. That is the
#     honest could-not-determine shape, the same one that put WINVULN-03 at LOW.
#
# So both are declared LOW to match what they render. A FAIL remains possible
# later for a NARROWER question (ACM-05: ineligible AND expiring soon; SHAI-03:
# a VPC observed making Bedrock calls with no endpoint) — that is a new check,
# not a severity argument.
# ═════════════════════════════════════════════════════════════════════════════
def test_acm05_imported_certificate_warns_and_renders_low():
    from datetime import datetime, timedelta, timezone
    acm = MagicMock()
    acm.get_paginator.return_value.paginate.return_value = [
        {"CertificateSummaryList": [
            {"CertificateArn": f"arn:aws:acm:{REGION}:{OWN}:certificate/c1",
             "DomainName": "api.example.com"}]}]
    acm.describe_certificate.return_value = {"Certificate": {
        "DomainName": "api.example.com", "Status": "ISSUED",
        "Type": "IMPORTED", "InUseBy": ["arn:aws:elb:x"],
        "KeyAlgorithm": "RSA_2048",
        "NotAfter": datetime.now(timezone.utc) + timedelta(days=365)}}
    s = _scanner("ACM", "acm", acm)
    s._check_acm()
    hits = _ids(s, "ACM-05", "WARN")
    assert hits, "ACM-05 never fired on an imported certificate"
    assert hits[0].severity == "LOW", (
        "a WARN is forced to LOW by _add; declaring ACM-05 MEDIUM advertised a "
        "severity it cannot render")


def test_acm05_and_shai03_are_declared_low_to_match_what_they_render():
    """Pinned. If either gains a FAIL path the catalogue can be raised again — but
    then this test fails first, so the change is deliberate."""
    from engine import aws_live_scanner as A
    for cid in ("ACM-05", "SHAI-03"):
        assert A.CHECK_SEVERITY[cid] == "LOW", (
            f"{cid} is declared {A.CHECK_SEVERITY[cid]} but has no FAIL path, so "
            f"that severity is unreachable")


# ═════════════════════════════════════════════════════════════════════════════
# SM-12 (MEDIUM) — the notebook platform check that had no caller
#
# `aws_sagemaker.notebook_platform` was written, exported in `__all__` and unit
# tested in test_sagemaker_depth.py, and no production code called it. The id sat
# in all four metadata maps and in SECURITY_HUB_PARITY, was counted in the
# published total, and could not fire. `test_unreached_modules.py` could not see
# it because it asks whether a MODULE has a production caller, and aws_sagemaker
# plainly does — this is the same liability one level down.
# ═════════════════════════════════════════════════════════════════════════════
def _notebook(detail):
    sm = MagicMock()
    sm.list_notebook_instances.return_value = {
        "NotebookInstances": [{"NotebookInstanceName": "research"}]}
    sm.describe_notebook_instance.return_value = detail
    for op, key in _MONITORING_LISTS.items():
        getattr(sm, op).return_value = {key: []}
    for op, key in (("list_feature_groups", "FeatureGroupSummaries"),
                    ("list_inference_experiments", "InferenceExperiments"),
                    ("list_app_image_configs", "AppImageConfigs"),
                    ("list_images", "Images"), ("list_models", "Models"),
                    ("list_domains", "Domains"),
                    ("list_endpoint_configs", "EndpointConfigs"),
                    ("list_endpoints", "Endpoints")):
        getattr(sm, op).return_value = {key: []}
    return _scanner("SAGEMAKER", "sagemaker", sm)


def _base_notebook(**over):
    d = {"NotebookInstanceName": "research", "DirectInternetAccess": "Disabled",
         "RootAccess": "Disabled",
         "KmsKeyId": f"arn:aws:kms:{REGION}:{OWN}:key/abc",
         "SubnetId": "subnet-1",
         "NotebookInstanceArn":
             f"arn:aws:sagemaker:{REGION}:{OWN}:notebook-instance/research"}
    d.update(over)
    return d


def test_sm12_notebook_on_an_unsupported_platform_fails():
    s = _notebook(_base_notebook(PlatformIdentifier="notebook-al2-v2"))
    s._check_sagemaker()
    _renders(s, "SM-12", "MEDIUM", contains="notebook-al2-v2")


def test_sm12_passes_on_a_supported_platform():
    from engine import aws_sagemaker as SM
    s = _notebook(_base_notebook(
        PlatformIdentifier=SM.SUPPORTED_NOTEBOOK_PLATFORMS[0]))
    s._check_sagemaker()
    assert not _ids(s, "SM-12", "FAIL")
    assert _ids(s, "SM-12", "PASS")


def test_sm12_says_nothing_when_the_platform_field_is_absent():
    """The field is optional on older instances. Failing one for a missing field
    would assert an end-of-support date nobody published — which is precisely what
    `notebook_platform` refuses to do."""
    s = _notebook(_base_notebook())
    s._check_sagemaker()
    assert not _ids(s, "SM-12")


def test_notebook_platform_now_has_a_production_caller():
    """The defect, pinned. A pure helper with tests and no caller passes CI and
    reads as delivered work."""
    import ast
    src = open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "engine", "aws_live_scanner.py"), encoding="utf-8").read()
    calls = [n for n in ast.walk(ast.parse(src))
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "notebook_platform"]
    assert calls, "aws_sagemaker.notebook_platform has no caller again"


# ═════════════════════════════════════════════════════════════════════════════
# THREAT-02 — retired, not driven
# ═════════════════════════════════════════════════════════════════════════════
def test_threat_02_is_gone_from_every_metadata_map():
    """It was registered in all four maps with a full remediation write-up and
    emitted by no code path anywhere. The control-plane-anomaly semantics it
    reserved are implemented by aws_cdr.normalize_cloudtrail_anomaly and emitted
    as THREAT-ING, so retiring the id loses no capability — it removes a claim of
    coverage that did not exist."""
    from engine import aws_finding_detail
    from engine import aws_live_scanner as A
    assert "THREAT-02" not in A.CHECK_SEVERITY
    assert "THREAT-02" not in A.COMPLIANCE_MAP
    assert "THREAT-02" not in A.REMEDIATION_MAP
    assert "THREAT-02" not in aws_finding_detail.FINDING_DETAIL
    assert "THREAT-01" in A.CHECK_SEVERITY, "the sibling must survive"


# ═════════════════════════════════════════════════════════════════════════════
# WAF-06 (HIGH) — an internet-facing ALB with nothing in front of it
# ═════════════════════════════════════════════════════════════════════════════
ALB_ARN = (f"arn:aws:elasticloadbalancing:{REGION}:{OWN}:"
           f"loadbalancer/app/public-web/abc")
ACL_ARN = f"arn:aws:wafv2:{REGION}:{OWN}:regional/webacl/edge/1"


def _waf_entry_points(*, balancers, protected_arns=(), acls=None,
                      resources_raises=False):
    waf = MagicMock()
    waf.list_web_acls.return_value = {
        "WebACLs": [{"ARN": ACL_ARN, "Name": "edge", "Id": "1"}]
        if acls is None else acls}
    if resources_raises:
        waf.list_resources_for_web_acl.side_effect = Exception("AccessDenied")
    else:
        waf.list_resources_for_web_acl.return_value = {
            "ResourceArns": list(protected_arns)}
    elb = MagicMock()
    elb.describe_load_balancers.return_value = {"LoadBalancers": balancers}
    s = _scanner("WAF", "wafv2", waf)
    s._clients[f"elbv2:{REGION}"] = elb
    return s


def _alb(**over):
    lb = {"LoadBalancerArn": ALB_ARN, "LoadBalancerName": "public-web",
          "Type": "application", "Scheme": "internet-facing"}
    lb.update(over)
    return lb


def test_waf06_internet_facing_alb_with_no_web_acl_fails():
    s = _waf_entry_points(balancers=[_alb()])
    s._check_waf_unprotected_entry_points()
    _renders(s, "WAF-06", "HIGH", contains="public-web")


def test_waf06_passes_when_the_alb_is_associated():
    s = _waf_entry_points(balancers=[_alb()], protected_arns=[ALB_ARN])
    s._check_waf_unprotected_entry_points()
    assert not _ids(s, "WAF-06", "FAIL")
    assert _ids(s, "WAF-06", "PASS")


def test_waf06_ignores_internal_load_balancers():
    """A WAF protects the internet edge. An internal ALB is a different question."""
    s = _waf_entry_points(balancers=[_alb(Scheme="internal")])
    s._check_waf_unprotected_entry_points()
    assert not _ids(s, "WAF-06")


def test_waf06_ignores_network_load_balancers():
    """An NLB operates below the layer a WAF inspects and cannot carry a Web ACL,
    so a finding on one would be unactionable."""
    s = _waf_entry_points(balancers=[_alb(Type="network")])
    s._check_waf_unprotected_entry_points()
    assert not _ids(s, "WAF-06")


def test_waf06_fails_open_when_the_association_list_is_denied():
    """A refused association read looks exactly like an empty one, and an empty one
    turns every load balancer in the estate into a finding. Nothing is claimed."""
    s = _waf_entry_points(balancers=[_alb()], resources_raises=True)
    s._check_waf_unprotected_entry_points()
    assert not _ids(s, "WAF-06")


def test_waf06_reports_an_unprotected_alb_even_with_no_web_acls_at_all():
    """The case WAF-01 could not express. No Web ACLs plus an internet-facing ALB
    is not 'nothing to protect' — it is an unprotected entry point."""
    s = _waf_entry_points(balancers=[_alb()], acls=[])
    s._check_waf_unprotected_entry_points()
    _renders(s, "WAF-06", "HIGH", contains="public-web")


def test_waf01_keeps_its_meaning_and_renders_low():
    """The whole reason WAF-06 is a new id: anyone filtering or waiving on WAF-01
    still gets the same subject, at the severity it can actually render."""
    from engine import aws_live_scanner as A
    assert A.CHECK_SEVERITY["WAF-01"] == "LOW"
    waf = MagicMock()
    waf.list_web_acls.return_value = {"WebACLs": []}
    s = _scanner("WAF", "wafv2", waf)
    s._clients[f"elbv2:{REGION}"] = MagicMock(**{
        "describe_load_balancers.return_value": {"LoadBalancers": []}})
    s._check_waf()
    hits = _ids(s, "WAF-01", "WARN")
    assert hits, "WAF-01 no longer reports an empty scope"
    assert hits[0].severity == "LOW"
