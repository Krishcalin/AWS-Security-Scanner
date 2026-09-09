"""The NHI section — five checks that were registered, tested, and callerless.

WHAT THIS FILE IS FOR. `engine/aws_nhi.py` shipped complete: machine-vs-human
classification, NHI-01..05, a permission ledger, full remediation write-ups, and 25
assertions in `tests/test_nhi.py`. Nothing called it. It was IMPORTED by three
production modules and referenced by none of them, so `test_unreached_modules.py`
saw a reached module — that ratchet asks about imports, and an unused import is
indistinguishable from a wired one from there. The five checks sat in all four
metadata maps, counted in the published total, and could not fire.

So this file is deliberately not another unit test of `nhi_findings`. Tranche 4 made
the point that this repo now builds on: the IAM privesc matcher was thoroughly
unit-tested as a pure function, yet no IAMPE finding had ever been constructed,
because those tests never reach `_add`. Tested logic and a proven finding are
different claims. Every test here drives the SCANNER and asserts on `s.results`.

THE ONE PLACE THE WIRING HAD TO DO MORE THAN CALL. NHI-01 is gated on a `machine`
verdict, and a console password is CONFIGURED human evidence — so `classify_principal`
returns `ambiguous` for precisely the identity NHI-01 describes, and the check cannot
fire on the module's own classification. `test_nhi.py` records that plainly: it fires
NHI-01 only by passing a verdict by hand, "the way a caller with better evidence
would". `_nhi_classification` is that caller, and it invents nothing — it re-asks the
same classifier with the password set aside and accepts `machine` only if the
identity earns it on structural grounds alone.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_nhi                                    # noqa: E402
from engine import aws_live_scanner as A                      # noqa: E402
from engine.aws_live_scanner import AWSLiveScanner            # noqa: E402

ACCOUNT = "123456789012"
OUTSIDER = "999988887777"


def svc_trust(service="ec2.amazonaws.com"):
    return {"Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": service},
                           "Action": "sts:AssumeRole"}]}


def cross_trust(account, *, external_id=False):
    stmt = {"Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "sts:AssumeRole"}
    if external_id:
        stmt["Condition"] = {"StringEquals": {"sts:ExternalId": "shared-secret"}}
    return {"Version": "2012-10-17", "Statement": [stmt]}


def oidc_trust(*, sub=False):
    stmt = {"Effect": "Allow",
            "Principal": {"Federated":
                          f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"},
            "Action": "sts:AssumeRoleWithWebIdentity"}
    cond = {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}
    if sub:
        cond["StringLike"] = {"token.actions.githubusercontent.com:sub": "repo:acme/app:*"}
    stmt["Condition"] = cond
    return {"Version": "2012-10-17", "Statement": [stmt]}


def role(name, trust, *, instance_profile=False, tags=None):
    return {"RoleName": name, "Arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
            "Path": "/", "AssumeRolePolicyDocument": trust,
            "AttachedManagedPolicies": [], "RolePolicyList": [],
            "InstanceProfileList": ([{"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/{name}"}]
                                    if instance_profile else []),
            "Tags": [{"Key": k, "Value": v} for k, v in (tags or {}).items()]}


def user(name, *, tags=None):
    return {"UserName": name, "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
            "Path": "/", "AttachedManagedPolicies": [], "UserPolicyList": [],
            "GroupList": [], "Tags": [{"Key": k, "Value": v}
                                      for k, v in (tags or {}).items()]}


def cred_row(name, *, password=False, key_rotated=None):
    """One credential-report row. `key_rotated` is an ISO timestamp or None."""
    return {"user": name, "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
            "password_enabled": "true" if password else "false",
            "access_key_1_active": "true" if key_rotated else "false",
            "access_key_1_last_rotated": key_rotated or "N/A",
            "access_key_2_active": "false", "access_key_2_last_rotated": "N/A"}


def scanner(*, users=(), roles=(), cred=(), trusted=()):
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["NHI"])
    s.account = ACCOUNT
    s.trusted_accounts = set(trusted)

    iam = MagicMock()
    iam.get_paginator.return_value.paginate.return_value = [
        {"UserDetailList": list(users), "RoleDetailList": list(roles),
         "GroupDetailList": [], "Policies": []}]
    s._client = lambda svc, region=None: iam if svc == "iam" else MagicMock()
    # Pre-populate rather than mock the base64/CSV round trip: _get_credential_report
    # returns a non-None cache untouched, which is the documented way in.
    s._cred_report = list(cred)
    s._cred_report_ok = bool(cred)
    return s


def run(s):
    s._check_nhi()
    return s.results


def fired(results, check_id, status="FAIL"):
    return [r for r in results if r.check_id == check_id and r.status == status]


# ── registration ────────────────────────────────────────────────────────────────
def test_the_section_is_registered_everywhere_a_section_must_be():
    """SECTIONS is the DEFAULT run list. A section in the dispatch table but not here
    is one a normal scan never runs — the defect four AI sections had."""
    assert "NHI" in A.SECTIONS
    assert "NHI" in A.SECTION_LABELS
    assert "NHI" in AWSLiveScanner.GLOBAL_SECTIONS, (
        "IAM is global; a regional NHI would emit every finding once per region")
    idx = {sec: i for i, sec in enumerate(A.SECTIONS)}
    assert idx["NHI"] < idx["CORRELATE"]


def test_the_module_has_a_production_caller():
    """The actual regression. `aws_nhi` was imported by three modules and called by
    none, which is why an import-based orphan check could not see it."""
    s = scanner(roles=[role("svc", svc_trust())])
    with patch.object(aws_nhi, "nhi_findings", wraps=aws_nhi.nhi_findings) as spy:
        run(s)
    assert spy.called, "the NHI section must actually call aws_nhi.nhi_findings"


def test_the_section_is_dispatchable_by_name():
    s = scanner(roles=[role("svc", svc_trust())])
    assert s.sections == ["NHI"]


# ── the five checks, driven to FAIL through _add ────────────────────────────────
def test_NHI_01_a_service_account_holding_a_console_password():
    """The case the check exists for: an IAM user with access keys AND a console
    password. On the classifier's raw verdict this is `ambiguous` and reports nothing,
    which is why the wiring resolves it."""
    s = scanner(users=[user("svc-backup")],
                cred=[cred_row("svc-backup", password=True,
                               key_rotated="2026-08-01T00:00:00+00:00")])
    r = fired(run(s), "NHI-01")
    assert r, "NHI-01 did not fire for a service account with a console password"
    assert r[0].severity == "HIGH", "the catalogue's HIGH must actually render"
    assert r[0].remediation_cmd, "a FAIL must carry the remediation the catalogue holds"


def test_NHI_01_stays_silent_when_the_human_evidence_is_not_just_the_password():
    """The resolution must not become a rubber stamp. A user with a password and no
    keys has no structural machine evidence, so nothing is forced."""
    s = scanner(users=[user("alice")], cred=[cred_row("alice", password=True)])
    assert not fired(run(s), "NHI-01")


def test_NHI_02_an_unrotated_machine_credential():
    s = scanner(users=[user("svc-etl")],
                cred=[cred_row("svc-etl", key_rotated="2020-01-01T00:00:00+00:00")])
    r = fired(run(s), "NHI-02")
    assert r, "NHI-02 did not fire for a key well past the 90-day threshold"
    assert r[0].severity == "MEDIUM"


def test_NHI_02_is_silent_on_a_fresh_credential():
    s = scanner(users=[user("svc-etl")],
                cred=[cred_row("svc-etl", key_rotated="2026-09-01T00:00:00+00:00")])
    assert not fired(run(s), "NHI-02")


def test_NHI_03_an_unowned_machine_identity():
    s = scanner(roles=[role("svc-worker", svc_trust())])
    r = fired(run(s), "NHI-03")
    assert r, "NHI-03 did not fire for a machine identity with no owner tag"
    assert r[0].severity == "LOW"


def test_NHI_03_is_silent_when_an_owner_tag_exists():
    s = scanner(roles=[role("svc-worker", svc_trust(), tags={"owner": "platform"})])
    assert not fired(run(s), "NHI-03")


def test_NHI_04_third_party_trust_without_an_external_id():
    """Needs the RAW trust document. The normalized form keeps only a boolean for
    conditions, so an ExternalId guard is unknowable from it."""
    s = scanner(roles=[role("vendor-access", cross_trust(OUTSIDER))])
    r = fired(run(s), "NHI-04")
    assert r, "NHI-04 did not fire for an unguarded third-party trust"
    assert r[0].severity == "HIGH"
    assert OUTSIDER in r[0].message


def test_NHI_04_is_silent_when_an_external_id_guards_the_trust():
    s = scanner(roles=[role("vendor-access", cross_trust(OUTSIDER, external_id=True))])
    assert not fired(run(s), "NHI-04")


def test_NHI_04_is_silent_for_an_account_the_operator_calls_its_own():
    """`trusted_accounts` is the allowlist the cross-account grant checks already
    honour; NHI must not make the operator declare ownership twice."""
    s = scanner(roles=[role("sibling", cross_trust(OUTSIDER))], trusted=[OUTSIDER])
    assert not fired(run(s), "NHI-04")


def test_NHI_05_federated_trust_without_a_subject_condition():
    s = scanner(roles=[role("gha-deploy", oidc_trust(sub=False))])
    r = fired(run(s), "NHI-05")
    assert r, "NHI-05 did not fire for an OIDC trust with no :sub condition"
    assert r[0].severity == "HIGH"


def test_NHI_05_is_silent_when_a_subject_condition_pins_the_workload():
    s = scanner(roles=[role("gha-deploy", oidc_trust(sub=True))])
    assert not fired(run(s), "NHI-05")


# ── the honest-answer paths ─────────────────────────────────────────────────────
def test_a_normalized_trust_policy_reports_itself_unevaluated_not_clean():
    """If only the normalized trust reaches the module, NHI-04/05 must say the
    condition was unreadable. Silence would render as 'no such risk here'."""
    s = scanner(roles=[role("vendor", cross_trust(OUTSIDER))])
    for p in s._get_iam_principals():
        p.pop("trust_raw", None)                     # simulate the normalized-only path
    s._check_nhi()
    info = [r for r in s.results if r.check_id == "NHI-04" and r.status == "INFO"]
    assert info, "an unreadable condition must be reported, not dropped"
    assert not fired(s.results, "NHI-04")


def test_no_credential_report_means_no_invented_findings():
    """NHI-01/02 read the credential report. Without one their inputs are None, and
    None is 'we did not find out' — never a clean bill."""
    s = scanner(users=[user("svc-etl")], cred=[])
    res = run(s)
    assert not fired(res, "NHI-01") and not fired(res, "NHI-02")


def test_an_empty_account_says_so_rather_than_passing():
    s = scanner()
    assert [r for r in run(s) if r.check_id == "NHI-00" and r.status == "INFO"]


def test_a_principal_that_blows_up_does_not_take_out_the_section():
    s = scanner(roles=[role("a", svc_trust()), role("b", svc_trust())])
    calls = {"n": 0}
    real = aws_nhi.nhi_findings

    def flaky(prin, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return real(prin, **kw)

    with patch.object(aws_nhi, "nhi_findings", flaky):
        res = run(s)
    assert calls["n"] == 2, "the second principal must still be assessed"
    assert [r for r in res if r.status == "WARN"]


def test_findings_name_the_classification_that_produced_them():
    """A finding derived from a WEAK verdict must be readable as such."""
    s = scanner(roles=[role("svc-worker", svc_trust())])
    r = fired(run(s), "NHI-03")
    assert r and "classified machine" in r[0].message


# ── the input the wiring had to start carrying ──────────────────────────────────
def test_get_iam_principals_carries_the_raw_trust_document_and_tags():
    """Both arrive on the same GetAccountAuthorizationDetails page that was already
    being fetched, so NHI costs no call and no grant."""
    s = scanner(roles=[role("r", cross_trust(OUTSIDER), tags={"owner": "platform"})],
                users=[user("u", tags={"team": "data"})])
    by_name = {p["name"]: p for p in s._get_iam_principals()}
    assert by_name["r"]["trust_raw"] == cross_trust(OUTSIDER)
    assert by_name["r"]["tags"] == {"owner": "platform"}
    assert by_name["u"]["tags"] == {"team": "data"}
