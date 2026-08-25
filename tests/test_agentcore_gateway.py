"""Phase 2 · slice 2.3 — gateway authorization posture.

The whole slice turns on one thing being wrong: a boolean `authorizerType == "NONE"`
check. AWS documents BOTH permissive inbound modes as deliberate architectures.
`AUTHENTICATE_ONLY` exists precisely so a caller's token is verified and then forwarded
for the target to validate; `NONE` exists so an existing authentication system can keep
owning the decision. Firing a critical finding on either would report a supported design
as a breach, which is how a scanner stops being believed.

What actually decides it is whose identity reaches the target, and the developer guide
states the consequence of getting it wrong verbatim: "The gateway execution role is
shared across all targets configured with GATEWAY_IAM_ROLE. Its permissions are the upper
bound for what any authorized caller can exercise through the gateway." With inbound
NONE, "any caller" includes unauthenticated ones.

The other property under test is that an unreadable target list is not read as an absent
one — reporting OPEN on the strength of a refused API call is the phantom-finding mirror
of a phantom pass.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_agentcore as G
import aws_live_scanner as A
from aws_live_scanner import AWSLiveScanner

GW_ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/tools-a1b2c3d4e5"
ROLE = "arn:aws:iam::123456789012:role/GatewayRole"


def gw(authorizer="CUSTOM_JWT", **over):
    d = {"gatewayId": "tools-a1b2c3d4e5", "gatewayArn": GW_ARN, "name": "tools",
         "authorizerType": authorizer, "protocolType": "MCP", "status": "READY",
         "gatewayUrl": "https://tools-a1b2c3d4e5.gateway.bedrock-agentcore."
                       "us-east-1.amazonaws.com/mcp",
         "roleArn": ROLE}
    d.update(over)
    return d


def target(cred_type):
    return {"targetId": "t1", "name": "lambda-tools",
            "credentialProviderConfigurations": [
                {"credentialProviderType": cred_type}]}


# ── the grading ─────────────────────────────────────────────────────────────
def test_a_gateway_that_authorizes_is_enforced():
    for t in ("CUSTOM_JWT", "AWS_IAM"):
        v = G.gateway_authorization(gw(t), [target("GATEWAY_IAM_ROLE")])
        assert v["verdict"] == G.GW_ENFORCED, t


def test_authenticate_only_carrying_the_caller_identity_is_a_supported_design():
    """The test this slice exists for. A boolean check on authorizerType reports this
    as a failure, and it is what AWS recommends for AgentCore Runtime targets."""
    v = G.gateway_authorization(gw("AUTHENTICATE_ONLY"),
                                [target("CALLER_IAM_CREDENTIALS")])
    assert v["verdict"] == G.GW_DELEGATED
    assert v["unauthenticated"] is False


def test_token_passthrough_is_also_delegation():
    v = G.gateway_authorization(gw("AUTHENTICATE_ONLY"), [target("JWT_PASSTHROUGH")])
    assert v["verdict"] == G.GW_DELEGATED


def test_permissive_inbound_with_the_gateways_own_credentials_is_the_finding():
    v = G.gateway_authorization(gw("NONE"), [target("GATEWAY_IAM_ROLE")])
    assert v["verdict"] == G.GW_OPEN
    assert v["unauthenticated"] is True
    assert "gateway's own credentials" in v["reason"]


def test_authenticate_only_with_gateway_credentials_is_open_but_not_unauthenticated():
    """Both are OPEN, and the difference still matters: one admits anyone at all, the
    other admits anyone who can sign a request. The message says which."""
    v = G.gateway_authorization(gw("AUTHENTICATE_ONLY"), [target("GATEWAY_IAM_ROLE")])
    assert v["verdict"] == G.GW_OPEN
    assert v["unauthenticated"] is False


def test_a_policy_engine_compensates():
    """The control AWS itself points at for this case."""
    v = G.gateway_authorization(
        gw("NONE", policyEngineConfiguration={"arn": "arn:aws:...:policy-engine/p1"}),
        [target("GATEWAY_IAM_ROLE")])
    assert v["verdict"] == G.GW_COMPENSATED
    assert "policy engine" in v["reason"]


def test_an_interceptor_compensates():
    v = G.gateway_authorization(
        gw("NONE", interceptorConfigurations=[{"interceptor": {"lambda": {"arn": "a"}}}]),
        [target("GATEWAY_IAM_ROLE")])
    assert v["verdict"] == G.GW_COMPENSATED
    assert "interceptor" in v["reason"]


def test_mixed_outbound_types_do_not_get_the_benefit_of_the_doubt():
    """One target carrying the caller's identity does not make the gateway safe when
    another hands out the gateway role."""
    v = G.gateway_authorization(gw("NONE"), [target("CALLER_IAM_CREDENTIALS"),
                                             target("GATEWAY_IAM_ROLE")])
    assert v["verdict"] == G.GW_OPEN


def test_unreadable_targets_are_unknown_not_open():
    """A refused ListGatewayTargets must not manufacture a CRITICAL. That is the
    phantom-finding mirror of a phantom pass, and it is how a scanner earns the
    reputation the whole product is built against."""
    v = G.gateway_authorization(gw("NONE"), None)
    assert v["verdict"] == G.GW_UNKNOWN
    assert "unknown, not benign" in v["reason"]


def test_a_gateway_with_no_targets_is_not_unknown():
    """Empty and unreadable are different facts."""
    v = G.gateway_authorization(gw("NONE"), [])
    assert v["verdict"] == G.GW_OPEN


def test_debug_exception_level():
    assert G.gateway_debug_errors(gw("CUSTOM_JWT", exceptionLevel="DEBUG")) is True
    assert G.gateway_debug_errors(gw("CUSTOM_JWT")) is False


@pytest.mark.parametrize("bad", [None, {}, {"authorizerType": None}])
def test_grading_never_raises_on_malformed_input(bad):
    assert G.gateway_authorization(bad, None)["verdict"] in G.GW_VERDICTS
    G.gateway_debug_errors(bad)


# ── the scanner surface ─────────────────────────────────────────────────────
def _scanner(ac):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["AGENTCORE"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: (ac if svc == "bedrock-agentcore-control"
                                          else MagicMock())
    return s


def _ac(gateway, targets=None, *, get_denied=False, targets_denied=False):
    c = MagicMock()
    if get_denied:
        c.get_gateway.side_effect = Exception("AccessDeniedException")
    else:
        c.get_gateway.return_value = gateway
    if targets_denied:
        c.list_gateway_targets.side_effect = Exception("AccessDeniedException")
    else:
        c.list_gateway_targets.return_value = {"items": targets or []}
    return c


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


SUMMARY = [{"gatewayId": "tools-a1b2c3d4e5", "name": "tools", "gatewayArn": GW_ARN}]


def test_the_open_gateway_fails():
    s = _scanner(_ac(gw("NONE"), [target("GATEWAY_IAM_ROLE")]))
    s._audit_agentcore_gateways(s._client("bedrock-agentcore-control"), SUMMARY)
    f = _ids(s, "AGC-05", "FAIL")
    assert f and "unauthenticated callers" in f[0].message
    assert "upper bound" in f[0].message


def test_the_delegated_gateway_passes():
    s = _scanner(_ac(gw("AUTHENTICATE_ONLY"), [target("CALLER_IAM_CREDENTIALS")]))
    s._audit_agentcore_gateways(s._client("bedrock-agentcore-control"), SUMMARY)
    assert _ids(s, "AGC-05", "PASS")


def test_the_compensated_gateway_warns_rather_than_fails():
    s = _scanner(_ac(gw("NONE", policyEngineConfiguration={"arn": "a"}),
                     [target("GATEWAY_IAM_ROLE")]))
    s._audit_agentcore_gateways(s._client("bedrock-agentcore-control"), SUMMARY)
    assert _ids(s, "AGC-05", "WARN")
    assert not _ids(s, "AGC-05", "FAIL")


def test_unreadable_targets_produce_a_coverage_note_not_a_finding():
    s = _scanner(_ac(gw("NONE"), targets_denied=True))
    s._audit_agentcore_gateways(s._client("bedrock-agentcore-control"), SUMMARY)
    assert not _ids(s, "AGC-05", "FAIL")
    assert "AGC-05" in s._coverage.not_evaluated
    assert any("no phantom pass" in r.message for r in _ids(s, "AGC-00"))


def test_a_refused_getgateway_records_both_checks():
    s = _scanner(_ac(gw("NONE"), get_denied=True))
    s._audit_agentcore_gateways(s._client("bedrock-agentcore-control"), SUMMARY)
    assert {"AGC-05", "AGC-06"} <= set(s._coverage.not_evaluated)
    assert not _ids(s, "AGC-05", "PASS")


def test_debug_errors_are_reported():
    s = _scanner(_ac(gw("CUSTOM_JWT", exceptionLevel="DEBUG"),
                     [target("GATEWAY_IAM_ROLE")]))
    s._audit_agentcore_gateways(s._client("bedrock-agentcore-control"), SUMMARY)
    f = _ids(s, "AGC-06", "FAIL")
    assert f and "DEBUG" in f[0].message


def test_the_gateway_role_is_stashed_for_blast_radius():
    """It is the role every GATEWAY_IAM_ROLE target runs as, which is exactly what
    AGC-05 says bounds a caller's reach — so AISPM-01/02 must see it."""
    s = _scanner(_ac(gw("NONE"), [target("GATEWAY_IAM_ROLE")]))
    s._audit_agentcore_gateways(s._client("bedrock-agentcore-control"), SUMMARY)
    assert len(s._aispm_resources) == 1
    res = s._aispm_resources[0]
    assert res["kind"] == "AgentCoreGateway" and res["role_arn"] == ROLE
    assert res["network_checkable"] is False, (
        "a gateway has no VPC surface; marking it checkable would invent an AISPM-03 "
        "verdict from an empty network dict")


def test_an_sdk_without_get_gateway_does_not_raise():
    c = MagicMock(spec=["list_gateway_targets"])
    s = _scanner(c)
    s._audit_agentcore_gateways(c, SUMMARY)     # must not raise
    assert not _ids(s, "AGC-05")


# ── mapping ─────────────────────────────────────────────────────────────────
def test_the_checks_are_fully_mapped():
    import aws_finding_detail as D
    for cid in ("AGC-05", "AGC-06"):
        assert cid in A.CHECK_SEVERITY, cid
        assert cid in A.COMPLIANCE_MAP, cid
        assert cid in A.REMEDIATION_MAP, cid
        assert cid in D.FINDING_DETAIL, cid


def test_the_detail_explains_that_permissive_inbound_can_be_correct():
    """If the write-up does not say why AUTHENTICATE_ONLY exists, an operator reading a
    CRITICAL will 'fix' a working delegated design by bolting on a second authorizer."""
    import aws_finding_detail as D
    risk = D.FINDING_DETAIL["AGC-05"]["risk"].lower()
    assert "on purpose" in risk or "deliberate" in risk
    assert "caller" in risk and "authenticate_only" in risk


def test_the_new_permissions_are_in_both_onboarding_paths():
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    for rel in ("deploy/cnapp-scanner-role.yaml",
                "deploy/terraform/scanner-role/main.tf"):
        text = (root / rel).read_text(encoding="utf-8")
        for act in ("GetGateway", "ListGatewayTargets"):
            assert f"bedrock-agentcore:{act}" in text, f"{rel} missing {act}"


# ── slice 2.5: agent credential exposure ────────────────────────────────────
def _cred_ac(vault=None, wi_detail=None, *, vault_denied=False):
    c = MagicMock()
    if vault_denied:
        c.get_token_vault.side_effect = Exception("AccessDeniedException")
    else:
        c.get_token_vault.return_value = vault or {}
    c.get_workload_identity.return_value = wi_detail or {}
    return c


CREDS = {"AgentCoreOauth2Provider": [{"name": "github"}],
         "AgentCoreWorkloadIdentity": [{"name": "agent-wi"}]}


def test_a_service_managed_token_vault_fails():
    """Not an encryption failure — a custody one. The vault holds credentials to systems
    outside AWS, and a service-managed key removes every lever over them at once."""
    ac = _cred_ac({"tokenVaultId": "default",
                   "kmsConfiguration": {"keyType": "ServiceManagedKey"}})
    s = _scanner(ac)
    s._audit_agentcore_credentials(ac, CREDS)
    f = _ids(s, "AGC-07", "FAIL")
    assert f and "revoke access by disabling a key" in f[0].message
    assert "1 credential(s)" in f[0].message


def test_a_customer_managed_token_vault_passes():
    ac = _cred_ac({"tokenVaultId": "default",
                   "kmsConfiguration": {"keyType": "CustomerManagedKey",
                                        "kmsKeyArn": "arn:aws:kms:::key/k"}})
    s = _scanner(ac)
    s._audit_agentcore_credentials(ac, CREDS)
    assert _ids(s, "AGC-07", "PASS")


def test_an_empty_kms_configuration_is_unknown_not_service_managed():
    """An uninterpretable response and a service-managed key are different facts."""
    ac = _cred_ac({"tokenVaultId": "default"})
    s = _scanner(ac)
    s._audit_agentcore_credentials(ac, CREDS)
    assert not _ids(s, "AGC-07")
    assert any("not assumed" in r.message for r in _ids(s, "AGC-00"))


def test_a_refused_token_vault_read_is_recorded():
    ac = _cred_ac(vault_denied=True)
    s = _scanner(ac)
    s._audit_agentcore_credentials(ac, CREDS)
    assert "AGC-07" in s._coverage.not_evaluated
    assert not _ids(s, "AGC-07", "PASS")


def test_an_estate_with_no_credentials_asks_no_custody_question():
    ac = _cred_ac({"kmsConfiguration": {"keyType": "ServiceManagedKey"}})
    s = _scanner(ac)
    s._audit_agentcore_credentials(ac, {})
    assert not _ids(s, "AGC-07")


def test_a_plaintext_oauth_return_url_fails():
    ac = _cred_ac({"kmsConfiguration": {"keyType": "CustomerManagedKey"}},
                  {"name": "agent-wi",
                   "allowedResourceOauth2ReturnUrls": ["https://ok.example/cb",
                                                       "http://bad.example/cb"]})
    s = _scanner(ac)
    s._audit_agentcore_credentials(ac, CREDS)
    f = _ids(s, "AGC-08", "FAIL")
    assert f and "http://bad.example/cb" in f[0].message
    assert "https://ok.example/cb" not in f[0].message


def test_https_and_custom_scheme_return_urls_pass():
    ac = _cred_ac({"kmsConfiguration": {"keyType": "CustomerManagedKey"}},
                  {"name": "agent-wi",
                   "allowedResourceOauth2ReturnUrls": ["https://ok.example/cb",
                                                       "myapp://callback"]})
    s = _scanner(ac)
    s._audit_agentcore_credentials(ac, CREDS)
    assert not _ids(s, "AGC-08")


def test_a_wildcard_is_not_flagged():
    """Whether AgentCore matches these by prefix, pattern or equality is undocumented.
    A finding whose severity depends on undocumented matching semantics is a guess about
    somebody else's implementation, so only the SCHEME is judged."""
    assert G.unsafe_return_urls(
        {"allowedResourceOauth2ReturnUrls": ["https://*.example.com/cb"]}) == []


def test_an_sdk_without_the_new_operations_does_not_raise():
    c = MagicMock(spec=[])
    s = _scanner(c)
    s._audit_agentcore_credentials(c, CREDS)      # must not raise


def test_the_credential_checks_are_fully_mapped():
    import aws_finding_detail as D
    for cid in ("AGC-07", "AGC-08"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP
        assert cid in A.REMEDIATION_MAP and cid in D.FINDING_DETAIL
