"""Phase 2 · slice 2.2 — the AGENTCORE section.

The design decision under test is the one that shaped the whole slice: AgentCore runtimes
are STASHED into ``_aispm_resources`` rather than given a parallel blast-radius pipeline.
That is why there is no AgentCore equivalent of AISPM-01/02/03 here — feeding the stash
means the existing implementation covers them, and there is one answer to "what can this
agent's role do" rather than two that drift apart.

So the checks that exist are only the ones genuinely specific to AgentCore: the microVM
metadata service, secret-shaped environment variables, the external credential surface
and the code-execution tool surface.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_agentcore as G
from engine import aws_aispm
from engine import aws_live_scanner as A
from engine.aws_live_scanner import AWSLiveScanner

ROLE = "arn:aws:iam::123456789012:role/AgentRuntimeRole"
RT_ARN = ("arn:aws:bedrock-agentcore:us-east-1:123456789012:"
          "runtime/support_bot-a1b2c3d4e5")


def runtime_detail(**over):
    d = {
        "agentRuntimeArn": RT_ARN, "agentRuntimeId": "support_bot-a1b2c3d4e5",
        "agentRuntimeName": "support_bot", "status": "READY", "roleArn": ROLE,
        "workloadIdentityDetails": {"workloadIdentityArn": "arn:aws:bedrock-agentcore:"
                                                           "us-east-1:123456789012:"
                                                           "workload-identity/wi-1"},
        "networkConfiguration": {"networkMode": "VPC", "networkModeConfig": {
            "subnets": ["subnet-1"], "securityGroups": ["sg-1"]}},
        "metadataConfiguration": {"requireMMDSV2": True},
        "environmentVariables": {"LOG_LEVEL": "info"},
    }
    d.update(over)
    return d


def _ac(*, estate=None, detail=None, list_denied=False, get_denied=False):
    """A bedrock-agentcore-control client. Each list_* returns its OWN result key, which
    is the part that is not guessable and not uniform across resources."""
    c = MagicMock()
    estate = estate or {}
    for op, key, kind in G.LIST_OPERATIONS:
        if list_denied:
            getattr(c, op).side_effect = Exception("AccessDeniedException")
        else:
            getattr(c, op).return_value = {key: estate.get(kind, [])}
    if get_denied:
        c.get_agent_runtime.side_effect = Exception("AccessDeniedException")
    else:
        c.get_agent_runtime.return_value = detail or runtime_detail()
    return c


def _scanner(ac):
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["AGENTCORE"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: (ac if svc == "bedrock-agentcore-control"
                                          else MagicMock())
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


RT_SUMMARY = {"agentRuntimeId": "support_bot-a1b2c3d4e5",
              "agentRuntimeName": "support_bot", "agentRuntimeArn": RT_ARN}


# ── registration ────────────────────────────────────────────────────────────
def test_the_section_is_registered_and_regional():
    assert "AGENTCORE" in A.SECTIONS
    assert "AGENTCORE" not in AWSLiveScanner.GLOBAL_SECTIONS, (
        "AgentCore resources are regional; a global section would inventory one region "
        "and report the rest as empty")


def test_it_runs_before_data_so_the_stash_is_complete():
    """_collect_aispm consumes _aispm_resources in DATA. A runtime stashed after that
    point is silently dropped from every blast-radius check."""
    idx = {s: i for i, s in enumerate(A.SECTIONS)}
    assert idx["AGENTCORE"] < idx["DATA"]


def test_the_bedrock_agents_label_no_longer_claims_agentcore():
    """It read "AWS BEDROCK AGENT CORE" while auditing the older bedrock-agent API. With
    a real AgentCore section present, two sections would claim the same name."""
    assert A.SECTION_LABELS["BEDROCK_AGENTS"] == "AWS BEDROCK AGENTS"
    assert "AGENTCORE" in A.SECTION_LABELS["AGENTCORE"]


def test_the_checks_are_fully_mapped():
    from engine import aws_finding_detail as D
    for cid in ("AGC-01", "AGC-02", "AGC-03", "AGC-04"):
        assert cid in A.CHECK_SEVERITY, cid
        assert cid in A.COMPLIANCE_MAP, cid
        assert cid in A.REMEDIATION_MAP, cid
        assert cid in D.FINDING_DETAIL, cid
        assert "aws " in A.REMEDIATION_MAP[cid].lower(), cid


def test_the_informational_id_stays_out_of_the_score():
    assert "AGC-00" not in A.CHECK_SEVERITY, (
        "AGC-00 carries inventory and not-evaluated notes; scoring it would make an "
        "estate look worse for being visible")


# ── inventory ───────────────────────────────────────────────────────────────
def test_the_estate_is_reported():
    s = _scanner(_ac(estate={"AgentCoreRuntime": [RT_SUMMARY],
                             "AgentCoreGateway": [{"gatewayId": "g1"}]}))
    s._check_agentcore()
    info = _ids(s, "AGC-00", "INFO")
    assert info
    assert "1 Runtime" in info[0].message and "1 Gateway" in info[0].message


def test_an_empty_region_says_so_once():
    s = _scanner(_ac(estate={}))
    s._check_agentcore()
    assert _ids(s, "AGC-00", "INFO")
    assert not [r for r in s.results if r.status == "FAIL"]


def test_a_missing_client_is_recorded_not_treated_as_empty():
    """An SDK without the service and an account without agents are different facts."""
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["AGENTCORE"])
        s.account = "123456789012"

    def boom(svc, region=None):
        raise Exception("Unknown service: 'bedrock-agentcore-control'")
    s._client = boom
    s._check_agentcore()
    notes = _ids(s, "AGC-00")
    assert notes and "no phantom pass" in notes[0].message


def test_refused_lists_are_recorded_as_partial_not_clean():
    s = _scanner(_ac(list_denied=True))
    s._check_agentcore()
    assert "AGC-00" in s._coverage.not_evaluated
    assert not s._coverage.complete
    notes = _ids(s, "AGC-00")
    assert notes and "not evidence of absence" in notes[0].message
    assert not [r for r in s.results if r.status == "PASS"]


# ── AGC-01: the metadata service ────────────────────────────────────────────
def test_mmdsv2_not_required_is_a_fail():
    s = _scanner(_ac(estate={"AgentCoreRuntime": [RT_SUMMARY]},
                     detail=runtime_detail(
                         metadataConfiguration={"requireMMDSV2": False})))
    s._check_agentcore()
    f = _ids(s, "AGC-01", "FAIL")
    assert f and "metadata service" in f[0].message
    assert "prompt injection" in f[0].message


def test_mmdsv2_required_passes():
    s = _scanner(_ac(estate={"AgentCoreRuntime": [RT_SUMMARY]}))
    s._check_agentcore()
    assert _ids(s, "AGC-01", "PASS")


def test_an_absent_metadata_block_is_neither_pass_nor_fail():
    d = runtime_detail(); d.pop("metadataConfiguration")
    s = _scanner(_ac(estate={"AgentCoreRuntime": [RT_SUMMARY]}, detail=d))
    s._check_agentcore()
    assert not _ids(s, "AGC-01")
    assert any("not assumed" in r.message for r in _ids(s, "AGC-00"))


# ── AGC-02: environment variables ───────────────────────────────────────────
def test_secret_shaped_env_vars_are_reported_by_name_only():
    s = _scanner(_ac(estate={"AgentCoreRuntime": [RT_SUMMARY]},
                     detail=runtime_detail(environmentVariables={
                         "STRIPE_API_KEY": "sk_live_LEAKED", "LOG_LEVEL": "info"})))
    s._check_agentcore()
    f = _ids(s, "AGC-02", "FAIL")
    assert f and "STRIPE_API_KEY" in f[0].message
    assert "sk_live_LEAKED" not in f[0].message, "a secret VALUE reached a finding"


def test_a_clean_environment_raises_nothing():
    s = _scanner(_ac(estate={"AgentCoreRuntime": [RT_SUMMARY]}))
    s._check_agentcore()
    assert not _ids(s, "AGC-02")


# ── AGC-03 / AGC-04: surface disclosures ────────────────────────────────────
def test_external_credential_providers_are_disclosed():
    s = _scanner(_ac(estate={"AgentCoreOauth2Provider": [{"name": "github"}],
                             "AgentCoreApiKeyProvider": [{"name": "stripe"}]}))
    s._check_agentcore()
    w = _ids(s, "AGC-03", "WARN")
    assert w and "OUTSIDE AWS" in w[0].message
    assert "2 AgentCore credential provider" in w[0].message


def test_the_tool_surface_is_disclosed():
    s = _scanner(_ac(estate={"AgentCoreCodeInterpreter": [{"id": "ci1"}],
                             "AgentCoreBrowser": [{"id": "b1"}, {"id": "b2"}]}))
    s._check_agentcore()
    w = _ids(s, "AGC-04", "WARN")
    assert w and "1 code interpreter" in w[0].message and "2 browser" in w[0].message


def test_gateways_and_memories_alone_do_not_raise_the_tool_surface():
    """AGC-04 is about executing code and fetching URLs. A gateway publishes tools and a
    memory stores state; neither is the capability the finding names."""
    s = _scanner(_ac(estate={"AgentCoreGateway": [{"id": "g"}],
                             "AgentCoreMemory": [{"id": "m"}]}))
    s._check_agentcore()
    assert not _ids(s, "AGC-04")


# ── the stash: everything else comes free ───────────────────────────────────
def test_runtimes_are_stashed_for_the_aispm_pipeline():
    s = _scanner(_ac(estate={"AgentCoreRuntime": [RT_SUMMARY]}))
    s._check_agentcore()
    assert len(s._aispm_resources) == 1
    res = s._aispm_resources[0]
    assert res["kind"] == "AgentCoreRuntime"
    assert res["role_arn"] == ROLE
    assert res["arn"] == RT_ARN


def test_the_stashed_network_shape_is_the_one_aispm_reads():
    """The stash exists so AISPM-03 describes AgentCore egress in the same already-honest
    words it uses for SageMaker. If the shape does not match what ai_network_exposed
    reads, the runtime is silently treated as isolated."""
    s = _scanner(_ac(estate={"AgentCoreRuntime": [RT_SUMMARY]},
                     detail=runtime_detail(
                         networkConfiguration={"networkMode": "PUBLIC"})))
    s._check_agentcore()
    res = s._aispm_resources[0]
    assert res["network_checkable"] is True
    assert aws_aispm.ai_network_exposed(res) is True, (
        "a PUBLIC AgentCore runtime must read as egress-unmediated to AISPM-03")


def test_a_vpc_attached_runtime_reads_as_isolated():
    s = _scanner(_ac(estate={"AgentCoreRuntime": [RT_SUMMARY]}))
    s._check_agentcore()
    assert aws_aispm.ai_network_exposed(s._aispm_resources[0]) is False


def test_a_refused_getagentruntime_records_both_checks_it_cost():
    """One read gates AGC-01 and AGC-02. Recording only one leaves the other looking
    clean -- the phantom pass the coverage manifest exists to prevent."""
    s = _scanner(_ac(estate={"AgentCoreRuntime": [RT_SUMMARY]}, get_denied=True))
    s._check_agentcore()
    assert {"AGC-01", "AGC-02"} <= set(s._coverage.not_evaluated)
    assert not _ids(s, "AGC-01", "PASS")
    assert s._aispm_resources == [], "an unreadable runtime must not be stashed half-built"


def test_the_section_never_raises_on_malformed_responses():
    c = MagicMock()
    for op, key, _ in G.LIST_OPERATIONS:
        getattr(c, op).return_value = {key: None}
    c.get_agent_runtime.return_value = {}
    s = _scanner(c)
    s._check_agentcore()          # must not raise


# ── the grants ──────────────────────────────────────────────────────────────
def test_the_new_permissions_are_in_both_onboarding_paths():
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    for rel in ("deploy/cnapp-scanner-role.yaml",
                "deploy/terraform/scanner-role/main.tf"):
        text = (root / rel).read_text(encoding="utf-8")
        for act in ("ListAgentRuntimes", "GetAgentRuntime",
                    "ListOauth2CredentialProviders", "ListCodeInterpreters"):
            assert f"bedrock-agentcore:{act}" in text, f"{rel} missing {act}"


def test_the_policy_uses_the_iam_prefix_not_the_endpoint_name():
    """bedrock-agentcore-control is the endpoint. A policy written with it grants
    nothing, denies nothing, and looks entirely correct in review."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    for rel in ("deploy/cnapp-scanner-role.yaml",
                "deploy/terraform/scanner-role/main.tf"):
        text = (root / rel).read_text(encoding="utf-8")
        assert "bedrock-agentcore-control:" not in text, (
            f"{rel} grants against the endpoint name, which authorizes nothing")
