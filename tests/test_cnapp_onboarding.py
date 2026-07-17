"""Offline tests for cnapp_onboarding — ExternalId minting, secret-ref indirection
(the value is NEVER stored, only a resolvable ref), CFN launch-URL/CLI building,
and resolve_external_id's scheme handling."""
import os
import sys
from urllib.parse import parse_qs, urlparse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_onboarding as OB

ACCT = "112233445566"
HUB = "arn:aws:iam::555000111222:role/CnappHubRole"
TMPL = "https://cnapp-hub.s3.amazonaws.com/cnapp-scanner-role.yaml"


def test_init_stores_only_ref_never_value():
    store = {}
    def writer(acct, value):
        ref = f"secretsmanager://cnapp/externalid/{acct}"
        store[ref] = value
        return ref
    init = OB.init_onboarding(ACCT, "us-east-1", id_gen=lambda: "A" * 40,
                              secret_writer=writer, hub_role_arn=HUB, cfn_template_url=TMPL)
    assert init.external_id_ref == f"secretsmanager://cnapp/externalid/{ACCT}"
    assert init.role_name == "CnappScannerRole"
    # the ref must not be the value, and the value must have been written to the store
    assert "A" * 40 not in init.external_id_ref
    assert store[init.external_id_ref] == "A" * 40


def test_launch_url_has_prefilled_params():
    init = OB.init_onboarding(ACCT, "eu-west-1", id_gen=lambda: "E" * 32,
                              secret_writer=lambda a, v: "ssm://cnapp/ext/" + a,
                              hub_role_arn=HUB, cfn_template_url=TMPL)
    q = parse_qs(urlparse(init.cfn_launch_url).fragment.split("?", 1)[1])
    assert q["param_HubRoleArn"] == [HUB]
    assert q["param_ExternalId"] == ["E" * 32]
    assert q["stackName"] == ["CnappScannerRole"]
    assert "eu-west-1" in init.cfn_launch_url
    assert "CAPABILITY_NAMED_IAM" in init.cli


def test_server_generated_id_rejects_empty():
    with pytest.raises(ValueError):
        OB.init_onboarding(ACCT, id_gen=lambda: "", secret_writer=lambda a, v: "ssm://x",
                           hub_role_arn=HUB, cfn_template_url=TMPL)


def test_bad_account_id_rejected():
    with pytest.raises(ValueError):
        OB.init_onboarding("12345", secret_writer=lambda a, v: "ssm://x",
                           hub_role_arn=HUB, cfn_template_url=TMPL)


def test_writer_must_return_resolvable_ref():
    with pytest.raises(ValueError):
        OB.init_onboarding(ACCT, id_gen=lambda: "X" * 20,
                           secret_writer=lambda a, v: "X" * 20,   # a raw value, not a ref
                           hub_role_arn=HUB, cfn_template_url=TMPL)


def test_resolve_round_trip_and_scheme_rules():
    store = {"secretsmanager://cnapp/ext/1": "sekret1", "ssm://cnapp/ext/2": "sekret2"}
    reader = lambda ref: store[ref]
    assert OB.resolve_external_id("secretsmanager://cnapp/ext/1", secret_reader=reader) == "sekret1"
    assert OB.resolve_external_id("ssm://cnapp/ext/2", secret_reader=reader) == "sekret2"
    assert OB.resolve_external_id(None, secret_reader=reader) is None
    with pytest.raises(ValueError):
        OB.resolve_external_id("hmac:deadbeef", secret_reader=reader)      # audit-only
    with pytest.raises(ValueError):
        OB.resolve_external_id("plaintext-value", secret_reader=reader)    # unknown scheme


def test_default_id_gen_is_high_entropy():
    a, b = OB.default_id_gen(), OB.default_id_gen()
    assert a != b and len(a) == 40 and all(c in "0123456789abcdef" for c in a)


def test_unknown_scheme_error_never_echoes_the_raw_secret():
    """A schemeless literal (a raw ExternalId mis-stored) must NOT appear in the
    ValueError text — that message can reach persisted job errors / logs."""
    raw = "a1b2c3d4" * 5                              # looks like a real 40-hex ExternalId
    with pytest.raises(ValueError) as ei:
        OB.resolve_external_id(raw, secret_reader=lambda r: "x")
    assert raw not in str(ei.value)
    assert "<no-scheme>" in str(ei.value)
