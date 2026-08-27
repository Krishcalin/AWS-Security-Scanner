"""Phase 2 · slice 2.2 — AgentCore inventory and agent identity.

Fixtures are shaped from the AgentCore Control API reference (GetAgentRuntime response,
NetworkConfiguration) and from the paginator file in the botocore version this project
PINS. Both mattered:

* the published reference documents resources that do not exist in botocore 1.40.51, so
  code written from it alone would fail against the SDK we ship;
* the List result keys are not uniform (``items`` for gateways, ``browserSummaries`` for
  browsers, ``memories`` for memory), and guessing one wrong produces a silently empty
  inventory — which reads exactly like a clean account.

The load-bearing behaviours are the MMDSv2 posture, because it is the credential-theft
path an injected agent can actually walk, and the refusal to describe a network mode as
inbound exposure, because that is the mistake AIPATH-01 shipped for two slices.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_agentcore as A

ROLE = "arn:aws:iam::123456789012:role/AgentRuntimeRole"
WID = "arn:aws:bedrock-agentcore:us-east-1:123456789012:workload-identity/wi-1"


def runtime(**over):
    r = {
        "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
                           "runtime/support_bot-a1b2c3d4e5",
        "agentRuntimeId": "support_bot-a1b2c3d4e5",
        "agentRuntimeName": "support_bot",
        "status": "READY",
        "roleArn": ROLE,
        "workloadIdentityDetails": {"workloadIdentityArn": WID},
        "networkConfiguration": {"networkMode": "VPC", "networkModeConfig": {
            "subnets": ["subnet-1"], "securityGroups": ["sg-1"],
            "requireServiceS3Endpoint": True}},
        "metadataConfiguration": {"requireMMDSV2": True},
        "environmentVariables": {"LOG_LEVEL": "info"},
    }
    r.update(over)
    return r


# ── the pinned-SDK surface ──────────────────────────────────────────────────
def test_the_list_operations_match_the_pinned_service_model():
    """These result keys are transcribed from botocore 1.40.51's paginators-1.json.
    They are not derivable from the operation name, and a wrong one yields an empty
    inventory that looks like an account with no agents."""
    by_op = {op: key for op, key, _ in A.LIST_OPERATIONS}
    assert by_op["list_gateways"] == "items"
    assert by_op["list_agent_runtimes"] == "agentRuntimes"
    assert by_op["list_browsers"] == "browserSummaries"
    assert by_op["list_code_interpreters"] == "codeInterpreterSummaries"
    assert by_op["list_memories"] == "memories"
    assert by_op["list_workload_identities"] == "workloadIdentities"
    assert by_op["list_oauth2_credential_providers"] == "credentialProviders"


def test_no_operation_absent_from_the_pinned_sdk_is_referenced():
    """The published reference is ahead of the SDK we ship. Harnesses, PaymentConnectors,
    PolicyEngines and Registries are documented and do not exist in botocore 1.40.51."""
    ops = {op for op, _, _ in A.LIST_OPERATIONS}
    for later in ("list_harnesses", "list_payment_connectors", "list_policy_engines",
                  "list_registries", "list_datasets", "list_evaluators"):
        assert later not in ops, f"{later} is not in the pinned service model"


def test_the_iam_prefix_is_not_the_endpoint_name():
    """bedrock-agentcore-control is the endpoint; bedrock-agentcore is the authorization
    namespace. A policy written with the endpoint name grants nothing and denies nothing,
    and would look correct in review."""
    assert A.IAM_PREFIX == "bedrock-agentcore"


# ── identity: the part a cloud-native inventory misses ──────────────────────
def test_both_identities_are_recorded():
    ident = A.runtime_identity(runtime())
    assert ident["role_arn"] == ROLE
    assert ident["workload_identity_arn"] == WID
    assert ident["has_aws_identity"] and ident["has_workload_identity"]


def test_a_runtime_without_a_workload_identity_is_reported_as_such():
    r = runtime(); r.pop("workloadIdentityDetails")
    ident = A.runtime_identity(r)
    assert ident["has_workload_identity"] is False
    assert ident["has_aws_identity"] is True


# ── MMDSv2: the credential-theft path ───────────────────────────────────────
def test_mmdsv2_required_is_the_good_state():
    assert A.metadata_posture(runtime())["required"] is True


def test_mmdsv2_not_required_is_detected():
    p = A.metadata_posture(runtime(metadataConfiguration={"requireMMDSV2": False}))
    assert p["required"] is False and p["known"] is True


def test_an_absent_metadata_config_is_unknown_not_false():
    """Absent and "explicitly not required" are different facts, and the reference does
    not state a default. Treating unknown as failure invents a finding on every runtime
    whose API response simply omits the block."""
    r = runtime(); r.pop("metadataConfiguration")
    p = A.metadata_posture(r)
    assert p["required"] is None
    assert p["known"] is False


def test_a_non_boolean_metadata_value_is_unknown():
    p = A.metadata_posture(runtime(metadataConfiguration={"requireMMDSV2": "yes"}))
    assert p["required"] is None and p["known"] is False


# ── network: described as what it is ────────────────────────────────────────
def test_vpc_attached_runtime():
    n = A.network_posture(runtime())
    assert n["mode"] == "VPC" and n["vpc_attached"] is True
    assert n["egress_unmediated"] is False
    assert n["s3_endpoint_required"] is True


def test_public_mode_is_reported_as_unmediated_egress():
    n = A.network_posture(runtime(networkConfiguration={"networkMode": "PUBLIC"}))
    assert n["mode"] == "PUBLIC"
    assert n["vpc_attached"] is False
    assert n["egress_unmediated"] is True


def test_the_posture_exposes_no_ingress_field():
    """The AIPATH-01 lesson, applied before the mistake rather than after it. The
    reference gives networkMode as PUBLIC | VPC and says nothing about inbound
    reachability; who may invoke a runtime is authorizerConfiguration's question."""
    n = A.network_posture(runtime(networkConfiguration={"networkMode": "PUBLIC"}))
    for banned in ("exposed", "public", "internet_facing", "reachable", "ingress"):
        assert banned not in n, (
            f"network_posture exposes {banned!r}, inviting an ingress claim no signal "
            f"here supports")


def test_an_unrecognised_mode_is_echoed_not_bucketed():
    n = A.network_posture(runtime(networkConfiguration={"networkMode": "HYBRID"}))
    assert n["mode"] == "HYBRID" and n["known_mode"] is False


def test_vpc_mode_with_no_subnets_still_counts_as_unmediated():
    """Derived from observable subnets rather than the mode string, so a half-configured
    runtime is not reported as isolated on the strength of a label."""
    n = A.network_posture(runtime(networkConfiguration={
        "networkMode": "VPC", "networkModeConfig": {"subnets": []}}))
    assert n["vpc_attached"] is False and n["egress_unmediated"] is True


# ── authorizer: presence only, on purpose ───────────────────────────────────
def test_authorizer_presence_is_recorded():
    assert A.authorizer_posture(runtime())["configured"] is False
    got = A.authorizer_posture(runtime(
        authorizerConfiguration={"customJWTAuthorizer": {"discoveryUrl": "https://x"}}))
    assert got["configured"] is True
    assert got["kinds"] == ["customJWTAuthorizer"]


# ── environment variables: names, never values ──────────────────────────────
def test_secret_shaped_env_keys_are_found():
    keys = env = A.env_secret_keys(runtime(environmentVariables={
        "LOG_LEVEL": "info", "STRIPE_API_KEY": "sk_live_abc123",
        "DB_PASSWORD": "hunter2"}))
    assert "STRIPE_API_KEY" in keys and "DB_PASSWORD" in keys
    assert "LOG_LEVEL" not in keys


def test_env_values_never_leave_the_classifier():
    keys = A.env_secret_keys(runtime(environmentVariables={
        "STRIPE_API_KEY": "sk_live_SUPERSECRET"}))
    assert all("SUPERSECRET" not in k for k in keys), (
        "a secret value escaped into the finding surface")


def test_an_empty_secret_shaped_var_is_not_a_finding():
    """A name that looks secret with no value is a placeholder, not a leaked credential."""
    assert A.env_secret_keys(runtime(environmentVariables={"API_KEY": ""})) == []


# ── estate ──────────────────────────────────────────────────────────────────
def test_inventory_counts_and_credential_rollup():
    inv = A.inventory_counts({
        "AgentCoreRuntime": [1, 2, 3],
        "AgentCoreGateway": [1],
        "AgentCoreOauth2Provider": [1, 2],
        "AgentCoreApiKeyProvider": [1],
    })
    assert inv["counts"]["AgentCoreRuntime"] == 3
    assert inv["total"] == 7
    assert inv["credential_providers"] == 3, (
        "credentials to systems outside AWS deserve their own number")
    assert "AgentCoreMemory" not in inv["kinds_present"]


def test_an_empty_estate_summarises_as_such():
    assert A.summarize({}) == "no AgentCore resources"
    assert A.inventory_counts(None)["total"] == 0


def test_the_summary_leads_with_the_most_numerous():
    s = A.summarize({"AgentCoreRuntime": [1, 2, 3], "AgentCoreGateway": [1]})
    assert s.startswith("3 Runtime")


# ── robustness ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, {}, {"networkConfiguration": None},
                                 {"metadataConfiguration": []},
                                 {"environmentVariables": "nope"},
                                 {"workloadIdentityDetails": None}])
def test_no_classifier_raises_on_malformed_input(bad):
    A.runtime_identity(bad)
    A.metadata_posture(bad)
    A.network_posture(bad)
    A.authorizer_posture(bad)
    A.env_secret_keys(bad)


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    src = inspect.getsource(A)
    bad = re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests|urllib)\b",
                     src, re.M)
    assert not bad, f"pure classifier module imports I/O: {bad}"
