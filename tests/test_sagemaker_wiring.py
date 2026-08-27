"""Phase 4 · slice 4.1 — the scanner surface for SageMaker parity, and the ledger fix.

Three things land here.

**Parity is a checkable claim, not an assertion.** `SECURITY_HUB_PARITY` maps all 25
published controls to the OverWatch check that answers each, with AWS's own severity. A
test fails the build if a control is listed without a check behind it, and another fails
if our severity disagrees with the standard we claim to match — a scanner that quietly
re-rates a control is disagreeing with the standard where nobody can see it.

**Applicability is honoured at the scanner, not just the classifier.** Four controls are
conditional, and in each case the finding is *not emitted at all* rather than emitted and
dismissed: no encryption finding on a single instance, no pipeline finding on a
single-container model, no captured-data finding with capture off, no redundancy finding
on a serverless-only endpoint config.

**The permission ledger was lying about SageMaker.** Its three entries were rotated by
one — `SM-04` (notebook VPC) held the Studio *domain* actions, `SM-06` (Studio home-EFS
key) held the *endpoint-config* actions, and `SM-07` (endpoint-config key) held the
*notebook* actions. Declining `ListNotebookInstances` was reported as costing SM-07
alone when it actually costs all five notebook checks. "Declining an action names exactly
what it costs" is this module's entire contract.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_live_scanner as A
from engine import aws_perm_ledger as L
from engine import aws_sagemaker as SM
from engine.aws_live_scanner import AWSLiveScanner


def _scanner(client):
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["SAGEMAKER"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: client
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _sm(**pages):
    """A SageMaker client whose list_* return the pages given and nothing else."""
    c = MagicMock()
    for op in ("list_models", "list_feature_groups", "list_inference_experiments",
               "list_endpoint_configs", "list_app_image_configs", "list_images",
               "list_data_quality_job_definitions",
               "list_model_explainability_job_definitions",
               "list_model_bias_job_definitions",
               "list_model_quality_job_definitions", "list_monitoring_schedules"):
        getattr(c, op).return_value = {}
    for op, payload in pages.items():
        getattr(c, op).return_value = payload
    return c


# ── the parity claim ────────────────────────────────────────────────────────
def test_every_published_control_is_answered():
    """The load-bearing claim of the slice. If AWS publishes a 26th control and it is
    added to the table without a check, this fails rather than the coverage silently
    reading as complete."""
    assert len(SM.SECURITY_HUB_PARITY) == 25
    for control, (cid, _sev, _what) in SM.SECURITY_HUB_PARITY.items():
        assert cid in A.CHECK_SEVERITY, f"{control} maps to {cid}, which has no severity"


def test_our_severity_matches_the_standard_we_claim_parity_with():
    """Under-rating a control while claiming parity with the standard that rates it is
    a disagreement nobody discovers until an audit."""
    wrong = {c: (sev, A.CHECK_SEVERITY[cid])
             for c, (cid, sev, _) in SM.SECURITY_HUB_PARITY.items()
             if A.CHECK_SEVERITY[cid] != sev}
    assert not wrong, f"severity disagrees with Security Hub: {wrong}"


def test_no_control_shares_a_check_with_another():
    ids = [cid for cid, _, _ in SM.SECURITY_HUB_PARITY.values()]
    assert len(set(ids)) == len(ids)


def test_our_own_checks_are_named_as_extras_not_gaps():
    """'We go beyond the standard here' and 'we have an unmapped check' are opposite
    facts that look identical in a coverage count."""
    mapped = {cid for cid, _, _ in SM.SECURITY_HUB_PARITY.values()}
    ours = set(SM.OVERWATCH_ORIGINAL)
    assert not (mapped & ours)
    all_sm = {c for c in A.CHECK_SEVERITY if c.startswith("SM-")}
    assert all_sm == mapped | ours, f"unaccounted SM checks: {all_sm - mapped - ours}"


def test_the_parity_snapshot_is_dated():
    """AWS adds controls. An undated snapshot silently becomes a false parity claim."""
    assert SM.PARITY_SOURCE.startswith("https://docs.aws.amazon.com/")
    assert SM.PARITY_SOURCE_DATE.count("-") == 2


# ── models ──────────────────────────────────────────────────────────────────
def _model_client(**over):
    d = {"ModelName": "m1", "EnableNetworkIsolation": False,
         "PrimaryContainer": {"Image": "i",
                              "ImageConfig": {"RepositoryAccessMode": "Platform"}}}
    d.update(over)
    c = _sm(list_models={"Models": [{"ModelName": "m1"}]})
    c.describe_model.return_value = d
    return c


def test_an_unisolated_model_fails():
    s = _scanner(_model_client())
    s._check_sagemaker_models(s._client("sagemaker"))
    assert len(_ids(s, "SM-09", "FAIL")) == 1


def test_a_platform_registry_model_fails_the_primary_control():
    s = _scanner(_model_client())
    s._check_sagemaker_models(s._client("sagemaker"))
    f = _ids(s, "SM-10", "FAIL")
    assert f and "public platform registry" in f[0].message


def test_a_single_container_model_raises_no_pipeline_finding():
    """SM-11 is about a multi-container pipeline. A single-container model has no
    pipeline, and reporting one describes a shape the configuration does not have."""
    s = _scanner(_model_client())
    s._check_sagemaker_models(s._client("sagemaker"))
    assert not _ids(s, "SM-11")


def test_a_pipeline_with_a_public_container_fails_sm11():
    c = _model_client(Containers=[
        {"ContainerHostname": "c1", "ImageConfig": {"RepositoryAccessMode": "Platform"}}])
    s = _scanner(c)
    s._check_sagemaker_models(s._client("sagemaker"))
    f = _ids(s, "SM-11", "FAIL")
    assert f and "c1" in f[0].message


def test_a_fully_configured_model_passes_all_three():
    c = _model_client(EnableNetworkIsolation=True,
                      PrimaryContainer={"Image": "i",
                                        "ImageConfig": {"RepositoryAccessMode": "Vpc"}})
    s = _scanner(c)
    s._check_sagemaker_models(s._client("sagemaker"))
    assert _ids(s, "SM-09", "PASS") and _ids(s, "SM-10", "PASS")
    assert not _ids(s, "SM-09", "FAIL") and not _ids(s, "SM-10", "FAIL")


# ── the five monitoring kinds ───────────────────────────────────────────────
def _job_client(op, key, name_field, detail):
    c = _sm(**{op: {key: [{name_field: "j1"}]}})
    return c


@pytest.mark.parametrize("kind", SM.MONITORING_KINDS, ids=lambda k: k[0])
def test_each_monitoring_kind_reports_isolation(kind):
    """All five, driven off the same table the scanner walks — so a kind added to the
    table without a scanner path fails here rather than silently never running."""
    label, list_op, list_key, name_field, desc_op, desc_kwarg, iso_ctl, _e, _c = kind
    iso_id = SM.SECURITY_HUB_PARITY[iso_ctl][0]
    c = _job_client(list_op, list_key, name_field, None)
    getattr(c, desc_op).return_value = {
        "NetworkConfig": {"EnableNetworkIsolation": False},
        "JobResources": {"ClusterConfig": {"InstanceCount": 1}}}
    s = _scanner(c)
    s._check_sagemaker_monitoring(s._client("sagemaker"))
    f = _ids(s, iso_id, "FAIL")
    assert len(f) == 1, f"{label} did not report {iso_id}"
    assert "has network isolation disabled" in f[0].message


def test_encryption_is_not_reported_on_a_single_instance():
    """Not emitted at all, rather than emitted and dismissed. A FAIL here would name a
    risk the configuration cannot have; a PASS would be one it did not earn."""
    c = _job_client("list_data_quality_job_definitions", "JobDefinitionSummaries",
                    "MonitoringJobDefinitionName", None)
    c.describe_data_quality_job_definition.return_value = {
        "NetworkConfig": {"EnableNetworkIsolation": True},
        "JobResources": {"ClusterConfig": {"InstanceCount": 1}}}
    s = _scanner(c)
    s._check_sagemaker_monitoring(s._client("sagemaker"))
    assert not _ids(s, "SM-14")


def test_encryption_is_reported_from_two_instances_up():
    c = _job_client("list_data_quality_job_definitions", "JobDefinitionSummaries",
                    "MonitoringJobDefinitionName", None)
    c.describe_data_quality_job_definition.return_value = {
        "NetworkConfig": {"EnableNetworkIsolation": True},
        "JobResources": {"ClusterConfig": {"InstanceCount": 3}}}
    s = _scanner(c)
    s._check_sagemaker_monitoring(s._client("sagemaker"))
    f = _ids(s, "SM-14", "FAIL")
    assert f and "3 instances" in f[0].message


def test_a_schedule_reads_its_nested_network_config():
    """The nesting that returns 0 instances and an un-isolated verdict if read wrong."""
    c = _sm(list_monitoring_schedules={
        "MonitoringScheduleSummaries": [{"MonitoringScheduleName": "s1"}]})
    c.describe_monitoring_schedule.return_value = {
        "MonitoringScheduleConfig": {"MonitoringJobDefinition": {
            "NetworkConfig": {"EnableNetworkIsolation": True,
                              "EnableInterContainerTrafficEncryption": True},
            "MonitoringResources": {"ClusterConfig": {"InstanceCount": 2}}}}}
    s = _scanner(c)
    s._check_sagemaker_monitoring(s._client("sagemaker"))
    assert _ids(s, "SM-21", "PASS") and _ids(s, "SM-22", "PASS")


# ── feature groups, experiments, endpoints, tagging ─────────────────────────
def test_an_unencrypted_offline_store_fails():
    c = _sm(list_feature_groups={"FeatureGroupSummaries": [{"FeatureGroupName": "fg"}]})
    c.describe_feature_group.return_value = {
        "OfflineStoreConfig": {"S3StorageConfig": {"S3Uri": "s3://b"}}}
    s = _scanner(c)
    s._check_sagemaker_feature_groups(s._client("sagemaker"))
    f = _ids(s, "SM-23", "FAIL")
    assert f and "historical record" in f[0].message


def test_an_in_memory_online_store_is_not_reported():
    c = _sm(list_feature_groups={"FeatureGroupSummaries": [{"FeatureGroupName": "fg"}]})
    c.describe_feature_group.return_value = {
        "OnlineStoreConfig": {"StorageType": "InMemory"}}
    s = _scanner(c)
    s._check_sagemaker_feature_groups(s._client("sagemaker"))
    assert not _ids(s, "SM-24")


def test_captured_data_is_not_reported_when_capture_is_off():
    c = _sm(list_inference_experiments={"InferenceExperiments": [{"Name": "e1"}]})
    c.describe_inference_experiment.return_value = {"KmsKey": "k"}
    s = _scanner(c)
    s._check_sagemaker_inference_experiments(s._client("sagemaker"))
    assert _ids(s, "SM-25", "PASS")
    assert not _ids(s, "SM-26")


def test_a_single_instance_variant_fails_redundancy():
    c = _sm(list_endpoint_configs={"EndpointConfigs": [{"EndpointConfigName": "ec"}]})
    c.describe_endpoint_config.return_value = {
        "ProductionVariants": [{"VariantName": "v1", "InitialInstanceCount": 1}]}
    s = _scanner(c)
    s._check_sagemaker_endpoint_redundancy(s._client("sagemaker"))
    f = _ids(s, "SM-08", "FAIL")
    assert f and "v1" in f[0].message


def test_a_serverless_only_config_is_not_reported():
    """No instance count exists to raise, so a finding would name a fix that does not
    exist for this configuration."""
    c = _sm(list_endpoint_configs={"EndpointConfigs": [{"EndpointConfigName": "ec"}]})
    c.describe_endpoint_config.return_value = {
        "ProductionVariants": [{"VariantName": "v1",
                                "ServerlessConfig": {"MemorySizeInMB": 2048}}]}
    s = _scanner(c)
    s._check_sagemaker_endpoint_redundancy(s._client("sagemaker"))
    assert not _ids(s, "SM-08")


def test_an_untagged_image_fails():
    c = _sm(list_images={"Images": [{"ImageName": "im", "ImageArn": "arn:aws:sm:::image/im"}]})
    c.list_tags.return_value = {"Tags": []}
    s = _scanner(c)
    s._check_sagemaker_tagging(s._client("sagemaker"))
    assert _ids(s, "SM-28", "FAIL")


def test_an_aws_system_tag_does_not_satisfy_the_control():
    c = _sm(list_images={"Images": [{"ImageName": "im", "ImageArn": "arn:aws:sm:::image/im"}]})
    c.list_tags.return_value = {"Tags": [{"Key": "aws:cloudformation:stack-id"}]}
    s = _scanner(c)
    s._check_sagemaker_tagging(s._client("sagemaker"))
    assert _ids(s, "SM-28", "FAIL")


# ── refused reads never become clean bills of health ────────────────────────
def test_a_denied_list_is_a_coverage_note_not_an_empty_pass():
    """An empty list reads as 'nothing to check'. Issuing that on the strength of a
    refused call is the phantom pass, and _paginate_all is avoided here for exactly
    this reason."""
    c = _sm()
    err = Exception("AccessDeniedException")
    c.list_models.side_effect = err
    s = _scanner(c)
    with patch.object(s, "_is_access_denied", return_value=True):
        s._check_sagemaker_models(s._client("sagemaker"))
    assert "SM-09" in s._coverage.not_evaluated
    assert not _ids(s, "SM-09", "PASS")
    assert any("no phantom pass" in r.message for r in _ids(s, "SM-00"))


def test_an_sdk_without_the_operation_costs_the_check_not_the_scan():
    c = MagicMock(spec=["describe_model"])
    s = _scanner(c)
    s._check_sagemaker_models(c)        # must not raise
    assert not _ids(s, "SM-09")


def test_the_denial_names_the_iam_action_not_the_python_method():
    assert A._op_to_api("list_feature_groups") == "ListFeatureGroups"
    assert A._op_to_api("list_model_bias_job_definitions") == "ListModelBiasJobDefinitions"


# ── the ledger correction ───────────────────────────────────────────────────
def test_notebook_actions_now_name_the_notebook_checks():
    """Before the fix this returned ('SM-07',) — the endpoint-config key check, which
    reads no notebook at all."""
    cost = L.evaluate([]).forfeit(["sagemaker:ListNotebookInstances"])
    assert set(cost) == {"SM-01", "SM-02", "SM-03", "SM-04", "SM-12"}


def test_domain_actions_now_name_the_domain_checks():
    cost = L.evaluate([]).forfeit(["sagemaker:ListDomains"])
    assert set(cost) == {"SM-05", "SM-06"}


def test_endpoint_config_actions_now_name_the_endpoint_checks():
    cost = L.evaluate([]).forfeit(["sagemaker:DescribeEndpointConfig"])
    assert set(cost) == {"SM-07", "SM-08"}


def test_every_sagemaker_check_is_in_the_ledger():
    """A check with no ledger entry cannot be sold, and cannot tell an operator what
    declining its permission costs."""
    sm_checks = {c for c in A.CHECK_SEVERITY if c.startswith("SM-")}
    assert sm_checks <= set(L.REQUIREMENTS), sm_checks - set(L.REQUIREMENTS)


def test_every_ledger_action_is_one_the_scanner_actually_calls():
    """The defect this replaces was an entry naming a call its check never makes."""
    import inspect
    # BOTH modules: the scanner makes the call, but the five monitoring operations are
    # named in aws_sagemaker.MONITORING_KINDS and reached through getattr, so grepping
    # only the scanner would report them as uncalled. Found by this test failing on its
    # first run, which is the outcome it exists for.
    src = inspect.getsource(A) + inspect.getsource(SM)
    for cid, reqs in L.REQUIREMENTS.items():
        if not cid.startswith("SM-"):
            continue
        for r in reqs:
            method = r.action.split(":", 1)[1]
            snake = "".join(("_" + ch.lower()) if ch.isupper() else ch
                            for ch in method).lstrip("_")
            assert snake in src, f"{cid} names {r.action} but {snake}( is never called"
