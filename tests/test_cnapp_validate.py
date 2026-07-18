"""Offline tests for cnapp_validate.validate_connection — the pure onboarding
validation decision engine. Fakes the injected assume-role fn + client factory;
covers the happy path, the failure taxonomy, the account-mismatch hard stop, and
the cadence state machine. Zero boto3."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cnapp_validate import (ConnectionHealth, cadence, validate_connection,
                            _error_code, DEFAULT_CANARY)

ACCT = "210987654321"
ROLE = f"arn:aws:iam::{ACCT}:role/CnappScannerRole"


class _Boto(Exception):
    """A botocore-shaped error (has .response['Error']['Code'])."""
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def _assume_ok(role, xid, sess, region):
    return {"AccessKeyId": "AK", "SecretAccessKey": "s", "SessionToken": "t"}


def _client_factory(account=ACCT, *, canary_error=None, org_accounts=None, org_error=None):
    class STS:
        def get_caller_identity(self):
            return {"Account": account}

    class EC2:
        def describe_regions(self):
            if canary_error:
                raise canary_error
            return {"Regions": [{"RegionName": "us-east-1"}]}

    class ORG:
        def get_paginator(self, name):
            class P:
                def paginate(self_):
                    if org_error:
                        raise org_error
                    return [{"Accounts": [{"Id": a, "Status": "ACTIVE"}
                                          for a in (org_accounts or [])]}]
            return P()

    def factory(creds, service, region):
        return {"sts": STS(), "ec2": EC2(), "organizations": ORG()}[service]
    return factory


def test_happy_path_healthy():
    res = validate_connection(expected_account_id=ACCT, role=ROLE, now_epoch=1000,
                              assume_role_fn=_assume_ok, client_factory=_client_factory(),
                              external_id="x")
    assert res.health == ConnectionHealth.HEALTHY and res.ok
    assert [c.status for c in res.checks] == ["ok", "ok", "ok"]
    assert res.next_revalidation_epoch == 1000 + cadence(ConnectionHealth.HEALTHY)


def test_org_mode_counts_accounts():
    res = validate_connection(expected_account_id=ACCT, role=ROLE, now_epoch=1,
                              assume_role_fn=_assume_ok,
                              client_factory=_client_factory(org_accounts=[ACCT, "998877665544"]),
                              external_id="x", org_mode=True)
    assert res.health == ConnectionHealth.HEALTHY
    assert res.org_account_count == 2
    assert res.checks[-1].name == "org_list_accounts"


def test_assume_access_denied_is_unauthorized_naming_both_causes():
    def deny(*a):
        raise _Boto("AccessDenied")
    res = validate_connection(expected_account_id=ACCT, role=ROLE, now_epoch=1,
                              assume_role_fn=deny, client_factory=_client_factory(),
                              external_id="x")
    assert res.health == ConnectionHealth.UNAUTHORIZED and not res.ok
    rem = res.checks[0].remediation or ""
    assert "ExternalId" in rem and ("trust" in rem.lower() or "hub" in rem.lower())
    # downstream steps skipped
    assert [c.status for c in res.checks[1:]] == ["skip", "skip"]


def test_account_mismatch_hard_stop():
    res = validate_connection(expected_account_id=ACCT, role=ROLE, now_epoch=1,
                              assume_role_fn=_assume_ok,
                              client_factory=_client_factory(account="999999999999"),
                              external_id="x")
    assert res.health == ConnectionHealth.UNAUTHORIZED
    assert res.observed_account_id == "999999999999"
    # canary + (no org) skipped after the mismatch
    assert res.checks[1].error_code == "AccountMismatch"
    assert res.checks[2].status == "skip"


def test_throttling_is_validating_fast_retry():
    def throttled(*a):
        raise _Boto("Throttling")
    res = validate_connection(expected_account_id=ACCT, role=ROLE, now_epoch=500,
                              assume_role_fn=throttled, client_factory=_client_factory(),
                              external_id="x")
    assert res.health == ConnectionHealth.VALIDATING
    assert res.next_revalidation_epoch == 500 + cadence(ConnectionHealth.VALIDATING) == 560


def test_no_such_entity_is_validating_pending_deploy():
    def missing(*a):
        raise _Boto("NoSuchEntity")
    res = validate_connection(expected_account_id=ACCT, role=ROLE, now_epoch=1,
                              assume_role_fn=missing, client_factory=_client_factory(),
                              external_id="x")
    assert res.health == ConnectionHealth.VALIDATING     # role not deployed yet -> retry


def test_canary_denied_is_degraded():
    """Role assumable + right account, but SecurityAudit missing -> DEGRADED."""
    res = validate_connection(expected_account_id=ACCT, role=ROLE, now_epoch=1,
                              assume_role_fn=_assume_ok,
                              client_factory=_client_factory(canary_error=_Boto("AccessDenied")),
                              external_id="x")
    assert res.health == ConnectionHealth.DEGRADED
    canary = next(c for c in res.checks if c.name == "security_audit_canary")
    assert canary.status == "fail" and "SecurityAudit" in (canary.remediation or "")


def test_org_denied_is_degraded_single_account_still_works():
    res = validate_connection(expected_account_id=ACCT, role=ROLE, now_epoch=1,
                              assume_role_fn=_assume_ok,
                              client_factory=_client_factory(org_error=_Boto("AccessDenied")),
                              external_id="x", org_mode=True)
    assert res.health == ConnectionHealth.DEGRADED


def test_cadence_table_and_backoff_cap():
    assert cadence(ConnectionHealth.HEALTHY) == 6 * 3600
    assert cadence(ConnectionHealth.DEGRADED) == 3600
    assert cadence(ConnectionHealth.VALIDATING) == 60
    # UNAUTHORIZED backs off monotonically and never exceeds the 24h cap; the
    # exponent saturates at 6 (900 * 2**6 = 57600), so it plateaus there.
    seq = [cadence(ConnectionHealth.UNAUTHORIZED, n) for n in range(0, 10)]
    assert seq[0] == 15 * 60
    assert all(seq[i] <= seq[i + 1] for i in range(len(seq) - 1))
    assert max(seq) <= 24 * 3600
    assert seq[6] == seq[9]                         # saturated (exponent capped at 6)


def test_error_code_extraction_without_botocore():
    assert _error_code(_Boto("Throttling")) == "Throttling"
    assert _error_code(ValueError("x")) == "ValueError"     # falls back to class name


def test_result_serializes():
    res = validate_connection(expected_account_id=ACCT, role=ROLE, now_epoch=1,
                              assume_role_fn=_assume_ok, client_factory=_client_factory(),
                              external_id="x")
    d = res.to_dict()
    assert d["health"] == "healthy" and d["ok"] is True
    assert all("name" in c and "status" in c for c in d["checks"])


# ── regression: empty observed account must NOT reach HEALTHY (fail closed) ────
def test_empty_observed_account_is_unauthorized_not_healthy():
    """GetCallerIdentity returning no Account must fail the identity assertion
    rather than fabricate a 'confirmed' HEALTHY verdict (adversarial finding)."""
    class NoAcctFactory:
        def __call__(self, creds, service, region):
            class STS:
                def get_caller_identity(self):
                    return {}            # no Account key
            class EC2:
                def describe_regions(self):
                    return {"Regions": []}
            return {"sts": STS(), "ec2": EC2()}[service]
    res = validate_connection(expected_account_id=ACCT, role=ROLE, now_epoch=1,
                              assume_role_fn=_assume_ok, client_factory=NoAcctFactory(),
                              external_id="x")
    assert res.health == ConnectionHealth.UNAUTHORIZED and not res.ok
    ci = next(c for c in res.checks if c.name == "caller_identity")
    assert ci.status == "fail" and ci.error_code == "NoCallerAccount"
    # the canary step is skipped, never fabricates a 'Confirmed account' ok
    assert not any(c.status == "ok" and "Confirmed" in c.detail for c in res.checks)
