"""Phase 4 · slice 4.1 — SageMaker depth to Security Hub parity, the classifier.

OverWatch shipped four of the twenty-five published SageMaker controls. This module
answers the other twenty-one, and most of these tests are about the readings that could
have gone the other way.

**Absent means disabled here, and only here.** Everywhere else in this codebase an
absent field is *unknown* — that ruling kept `requireMMDSV2` unknown in 2.2 and
`storageDays` unknown in 3.4. `EnableNetworkIsolation` is the documented exception:
SageMaker.14 fails a schedule with the flag "set to false **or not configured**". The
difference is sourced, not stylistic, and a test pins it so nobody later "fixes" it into
consistency with the wrong rule.

**Applicability is not severity.** Four controls are conditional — inter-container
encryption on a single instance, online-store encryption on InMemory storage, captured-
data encryption with no capture, instance count on a serverless variant. In every case
the configuration cannot express the failure, so reporting one would be a finding the
operator cannot act on.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_sagemaker as SM


def job_def(isolation=None, encryption=None, instances=1):
    net = {}
    if isolation is not None:
        net["EnableNetworkIsolation"] = isolation
    if encryption is not None:
        net["EnableInterContainerTrafficEncryption"] = encryption
    return {"JobDefinitionName": "dq-1", "NetworkConfig": net,
            "JobResources": {"ClusterConfig": {"InstanceCount": instances}}}


def schedule(isolation=None, encryption=None, instances=1):
    net = {}
    if isolation is not None:
        net["EnableNetworkIsolation"] = isolation
    if encryption is not None:
        net["EnableInterContainerTrafficEncryption"] = encryption
    return {"MonitoringScheduleName": "sched-1",
            "MonitoringScheduleConfig": {"MonitoringJobDefinition": {
                "NetworkConfig": net,
                "MonitoringResources": {"ClusterConfig": {"InstanceCount": instances}}}}}


# ── the shared NetworkConfig reading ────────────────────────────────────────
def test_the_five_kinds_are_tabled_once():
    """Twelve of the twenty-one controls ask the same two questions of five resource
    types. Writing that logic five times is how the two halves drift apart."""
    assert len(SM.MONITORING_KINDS) == 5
    controls = {k[6] for k in SM.MONITORING_KINDS} | {k[7] for k in SM.MONITORING_KINDS}
    assert controls == {"SageMaker.9", "SageMaker.10", "SageMaker.11", "SageMaker.12",
                        "SageMaker.13", "SageMaker.14", "SageMaker.15", "SageMaker.20",
                        "SageMaker.22", "SageMaker.25"}


def test_a_schedule_nests_its_network_config_one_level_deeper():
    """A job definition carries NetworkConfig at the top; a schedule buries it under
    MonitoringScheduleConfig.MonitoringJobDefinition. Handling that at five call sites
    is how one of them ends up reading nothing."""
    p = SM.monitoring_posture(schedule(isolation=True, encryption=True, instances=3))
    assert p["isolated"] is True and p["encrypted"] is True


def test_a_schedule_uses_monitoring_resources_not_job_resources():
    """The resources key differs by kind. Reading only JobResources returns 0 for every
    schedule, and a conditional check that never fires reads exactly like one that
    always passes."""
    assert SM.monitoring_posture(schedule(instances=4))["instance_count"] == 4
    assert SM.monitoring_posture(job_def(instances=4))["instance_count"] == 4


def test_an_absent_flag_is_disabled_here_and_that_is_deliberate():
    """The documented exception to this codebase's absent-means-unknown rule.
    SageMaker.14 fails a schedule whose flag is 'set to false OR NOT CONFIGURED'."""
    p = SM.monitoring_posture(job_def(isolation=None, encryption=None))
    assert p["isolated"] is False and p["encrypted"] is False


def test_an_explicit_false_reads_the_same_as_absent():
    assert SM.monitoring_posture(job_def(isolation=False))["isolated"] is False


def test_a_non_boolean_flag_is_not_treated_as_enabled():
    """A JSON quirk must not become a PASS."""
    d = job_def()
    d["NetworkConfig"]["EnableNetworkIsolation"] = "true"
    assert SM.monitoring_posture(d)["isolated"] is False


# ── conditional applicability ───────────────────────────────────────────────
def test_encryption_is_inapplicable_on_a_single_instance():
    """SageMaker.15 says so explicitly: it fails only at an instance count of 2 or
    greater. There is no inter-container traffic on one container to encrypt, so
    failing it would report a risk the configuration cannot have."""
    p = SM.monitoring_posture(job_def(instances=1))
    assert p["encryption_applicable"] is False


def test_encryption_is_applicable_from_two_instances_up():
    assert SM.monitoring_posture(job_def(instances=2))["encryption_applicable"] is True


def test_the_description_omits_an_inapplicable_encryption_failure():
    line = SM.describe_monitoring("data quality job definition", "dq-1",
                                  SM.monitoring_posture(job_def(instances=1)))
    assert "outbound network calls" in line
    assert "unencrypted" not in line


def test_a_fully_configured_resource_describes_as_nothing():
    p = SM.monitoring_posture(job_def(isolation=True, encryption=True, instances=3))
    assert SM.describe_monitoring("data quality job definition", "dq-1", p) == ""


# ── models: isolation and registry provenance ───────────────────────────────
def model(isolation=False, primary_mode="Vpc", pipeline_modes=()):
    d = {"ModelName": "m1", "EnableNetworkIsolation": isolation}
    if primary_mode is not None:
        d["PrimaryContainer"] = {"Image": "img",
                                 "ImageConfig": {"RepositoryAccessMode": primary_mode}}
    if pipeline_modes:
        d["Containers"] = [{"ContainerHostname": f"c{i}",
                            "ImageConfig": {"RepositoryAccessMode": m}}
                           for i, m in enumerate(pipeline_modes)]
    return d


def test_a_platform_registry_primary_container_fails_the_registry_control():
    p = SM.model_posture(model(primary_mode="Platform"))
    assert p["primary_private_registry"] is False


def test_a_vpc_registry_primary_container_passes():
    assert SM.model_posture(model(primary_mode="Vpc"))["primary_private_registry"] is True


def test_a_container_with_no_image_config_fails():
    """The control fails a container whose image configuration is absent, not just one
    set to Platform."""
    d = {"ModelName": "m1", "PrimaryContainer": {"Image": "img"}}
    assert SM.model_posture(d)["primary_private_registry"] is False


def test_the_primary_and_pipeline_controls_are_counted_apart():
    """SageMaker.16 is the primary container, .19 the pipeline. Separate controls with
    separate remediations, so collapsing them into 'some container is public' would
    lose which one to fix."""
    p = SM.model_posture(model(primary_mode="Vpc",
                               pipeline_modes=("Platform", "Vpc")))
    assert p["primary_private_registry"] is True
    assert p["public_pipeline_containers"] == ["c0"]


def test_a_pipeline_only_model_treats_its_first_container_as_primary():
    """A model has either a PrimaryContainer or a Containers pipeline. With only the
    pipeline, its first entry is what .16 is about."""
    p = SM.model_posture({"ModelName": "m1", "Containers": [
        {"ContainerHostname": "c0", "ImageConfig": {"RepositoryAccessMode": "Vpc"}},
        {"ContainerHostname": "c1", "ImageConfig": {"RepositoryAccessMode": "Platform"}}]})
    assert p["primary_private_registry"] is True
    assert p["public_pipeline_containers"] == ["c1"]


def test_model_isolation_is_read():
    assert SM.model_posture(model(isolation=True))["isolated"] is True
    assert SM.model_posture(model(isolation=False))["isolated"] is False


def test_the_model_description_names_every_failure():
    line = SM.describe_model("m1", SM.model_posture(
        model(isolation=False, primary_mode="Platform", pipeline_modes=("Platform",))))
    assert "network isolation is off" in line
    assert "public platform registry" in line
    assert "1 pipeline container" in line


# ── feature groups ──────────────────────────────────────────────────────────
def test_an_unencrypted_offline_store_is_reported():
    p = SM.feature_group_encryption({"OfflineStoreConfig": {"S3StorageConfig": {
        "S3Uri": "s3://b/k"}}})
    assert p["has_offline"] is True and p["offline_kms"] is False


def test_an_encrypted_offline_store_passes():
    p = SM.feature_group_encryption({"OfflineStoreConfig": {"S3StorageConfig": {
        "S3Uri": "s3://b/k", "KmsKeyId": "arn:aws:kms:::key/k"}}})
    assert p["offline_kms"] is True


def test_online_encryption_is_inapplicable_to_in_memory_storage():
    """SageMaker.18 names STANDARD storage. An InMemory online store is a different
    product, and failing it for a control scoped to the other is unactionable."""
    p = SM.feature_group_encryption({"OnlineStoreConfig": {"StorageType": "InMemory"}})
    assert p["online_applicable"] is False


def test_online_encryption_applies_when_the_storage_type_is_unstated():
    """Standard is the default, so silence means the control applies."""
    p = SM.feature_group_encryption({"OnlineStoreConfig": {"EnableOnlineStore": True}})
    assert p["online_applicable"] is True and p["online_kms"] is False


def test_an_encrypted_online_store_passes():
    p = SM.feature_group_encryption({"OnlineStoreConfig": {
        "SecurityConfig": {"KmsKeyId": "arn:aws:kms:::key/k"}}})
    assert p["online_kms"] is True


# ── inference experiments ───────────────────────────────────────────────────
def test_instance_storage_encryption_is_read():
    assert SM.inference_experiment_encryption({"KmsKey": "k"})["instance_kms"] is True
    assert SM.inference_experiment_encryption({})["instance_kms"] is False


def test_captured_data_encryption_is_inapplicable_without_capture():
    """With no capture there is no captured payload, and .24 is about the payload."""
    p = SM.inference_experiment_encryption({"KmsKey": "k"})
    assert p["capture_enabled"] is False


def test_captured_data_encryption_is_reported_when_capture_is_on():
    p = SM.inference_experiment_encryption({"DataStorageConfig": {"Destination": "s3://b"}})
    assert p["capture_enabled"] is True and p["data_kms"] is False


# ── endpoint redundancy ─────────────────────────────────────────────────────
def test_a_single_instance_variant_is_reported():
    p = SM.endpoint_variant_redundancy({"ProductionVariants": [
        {"VariantName": "v1", "InitialInstanceCount": 1}]})
    assert p["single_instance"] == ["v1"]


def test_a_redundant_variant_passes():
    p = SM.endpoint_variant_redundancy({"ProductionVariants": [
        {"VariantName": "v1", "InitialInstanceCount": 2}]})
    assert p["single_instance"] == []


def test_a_serverless_variant_is_out_of_scope():
    """The control note scopes it to instance-based configuration. A serverless variant
    has no instance count to raise, so failing it names a fix that does not exist."""
    p = SM.endpoint_variant_redundancy({"ProductionVariants": [
        {"VariantName": "v1", "ServerlessConfig": {"MemorySizeInMB": 2048}}]})
    assert p["applicable"] == 0 and p["single_instance"] == []


# ── notebook platform ───────────────────────────────────────────────────────
def test_a_supported_platform_passes():
    p = SM.notebook_platform({"PlatformIdentifier": "notebook-al2023-v1"})
    assert p["known"] is True and p["supported"] is True


def test_an_unsupported_platform_is_reported():
    p = SM.notebook_platform({"PlatformIdentifier": "notebook-al2-v2"})
    assert p["known"] is True and p["supported"] is False


def test_an_absent_platform_is_unknown_rather_than_unsupported():
    """The field is optional on older instances. Calling one unsupported on a missing
    field asserts an end-of-support date nobody published."""
    p = SM.notebook_platform({})
    assert p["known"] is False


def test_the_supported_platform_list_is_dated():
    """A hardcoded list with no date silently becomes a wrong answer about patch
    currency as platforms age out."""
    assert SM.SUPPORTED_NOTEBOOK_PLATFORMS
    assert SM.PLATFORM_SOURCE_DATE.count("-") == 2


# ── tagging ─────────────────────────────────────────────────────────────────
def test_with_no_required_keys_any_tag_satisfies_the_control():
    """AWS's documented default: with requiredKeyTags unset the control checks only
    that some non-system tag key exists."""
    assert SM.missing_tag_keys([{"Key": "owner", "Value": "team"}]) == []
    assert SM.missing_tag_keys([]) == ["<any non-system tag>"]


def test_aws_system_tags_do_not_count():
    """The control ignores tags with the aws: prefix, which are applied automatically."""
    assert SM.missing_tag_keys([{"Key": "aws:cloudformation:stack-name", "Value": "s"}]) \
        == ["<any non-system tag>"]


def test_required_keys_are_named_when_missing():
    missing = SM.missing_tag_keys([{"Key": "owner", "Value": "t"}],
                                  required=["owner", "costcenter", "env"])
    assert missing == ["costcenter", "env"]


def test_tag_keys_are_compared_case_sensitively():
    """The reference says tag keys are case sensitive."""
    assert SM.missing_tag_keys([{"Key": "Owner"}], required=["owner"]) == ["owner"]


# ── robustness ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, {}, "nope", 7, [], {"NetworkConfig": "x"},
                                 {"ProductionVariants": "x"},
                                 {"OnlineStoreConfig": "x"},
                                 {"PrimaryContainer": "x"}])
def test_nothing_raises_on_malformed_input(bad):
    SM.monitoring_posture(bad)
    SM.model_posture(bad)
    SM.feature_group_encryption(bad)
    SM.inference_experiment_encryption(bad)
    SM.endpoint_variant_redundancy(bad)
    SM.notebook_platform(bad)
    SM.missing_tag_keys(bad if isinstance(bad, list) else None)


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(SM), re.M)
