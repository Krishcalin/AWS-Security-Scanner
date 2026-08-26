"""Non-human identity classification, and its refusal to guess.

WHY THE REFUSALS ARE THE TESTS THAT MATTER
-------------------------------------------
AWS records no flag saying whether a principal is a machine. Every NHI product on the
market infers it, and the inference is where the damage happens in both directions:

* guess MACHINE about a person -> the tool recommends revoking a colleague's access;
* guess HUMAN about a service -> the identity the pillar exists to surface is hidden.

So the design rule is that naming conventions, on their own, never decide anything. A
role called `deploy-prod` gets classified `ambiguous`, and the summary counts it as
unclassified rather than quietly absorbing it into one column. Most of the tests below
exist to hold that line, because it is the line a later "improvement" is most likely to
cross in the name of better coverage.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_epistemics  # noqa: E402
import aws_nhi  # noqa: E402


def trust(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def svc(service="ec2.amazonaws.com"):
    return {"Effect": "Allow", "Principal": {"Service": service},
            "Action": "sts:AssumeRole"}


def federated(issuer, condition=None):
    s = {"Effect": "Allow", "Principal": {"Federated": issuer},
         "Action": "sts:AssumeRoleWithWebIdentity"}
    if condition:
        s["Condition"] = condition
    return s


def cross(account="999999999999", external_id=False):
    s = {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
         "Action": "sts:AssumeRole"}
    if external_id:
        s["Condition"] = {"StringEquals": {"sts:ExternalId": "abc123"}}
    return s


# ── CONFIGURED: read off an API, not interpreted ────────────────────────────
def test_a_service_principal_trust_is_machine_by_construction():
    """The strongest signal available. A person cannot assume ec2.amazonaws.com."""
    c = aws_nhi.classify_principal(
        {"kind": "IAMRole", "name": "whatever", "trust_policy": trust(svc())})
    assert c["verdict"] == aws_nhi.MACHINE
    assert c["confidence"] == aws_epistemics.CONFIGURED


def test_a_console_login_is_human_by_construction():
    c = aws_nhi.classify_principal(
        {"kind": "IAMUser", "name": "sarah", "has_login_profile": True})
    assert c["verdict"] == aws_nhi.HUMAN
    assert c["confidence"] == aws_epistemics.CONFIGURED


def test_every_verdict_carries_the_evidence_that_produced_it():
    c = aws_nhi.classify_principal(
        {"kind": "IAMRole", "name": "x", "trust_policy": trust(svc("lambda.amazonaws.com"))})
    assert c["signals"]
    assert any("lambda.amazonaws.com" in s["evidence"] for s in c["signals"])
    assert c["reason"]


# ── INFERRED: structural, still an interpretation ───────────────────────────
@pytest.mark.parametrize("issuer", [
    "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com",
    "arn:aws:iam::1:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/ABC",
    "arn:aws:iam::1:oidc-provider/gitlab.com",
])
def test_a_workload_identity_issuer_infers_machine(issuer):
    c = aws_nhi.classify_principal(
        {"kind": "IAMRole", "name": "r", "trust_policy": trust(federated(issuer))})
    assert c["verdict"] == aws_nhi.MACHINE
    assert c["confidence"] == aws_epistemics.INFERRED


def test_a_saml_trust_infers_human_federation():
    c = aws_nhi.classify_principal(
        {"kind": "IAMRole", "name": "r",
         "trust_policy": trust(federated("arn:aws:iam::1:saml-provider/Okta"))})
    assert c["verdict"] == aws_nhi.HUMAN


def test_an_instance_profile_infers_machine():
    c = aws_nhi.classify_principal(
        {"kind": "IAMRole", "name": "r", "has_instance_profile": True})
    assert c["verdict"] == aws_nhi.MACHINE


# ── THE LINE: naming alone never decides ────────────────────────────────────
@pytest.mark.parametrize("name", ["svc-payments", "ci-deploy", "lambda-exec",
                                  "terraform-runner", "github-actions-role"])
def test_a_machine_shaped_NAME_alone_is_not_enough(name):
    """THE rule. These all look like services and several of them are. Acting on a
    naming convention is how a tool tells somebody to delete a person's access."""
    c = aws_nhi.classify_principal({"kind": "IAMRole", "name": name})
    assert c["verdict"] == aws_nhi.AMBIGUOUS
    assert c["confidence"] == aws_nhi.WEAK


@pytest.mark.parametrize("name", ["admin-alice", "dev-bob", "breakglass"])
def test_a_human_shaped_NAME_alone_is_not_enough_either(name):
    c = aws_nhi.classify_principal({"kind": "IAMRole", "name": name})
    assert c["verdict"] == aws_nhi.AMBIGUOUS


def test_the_weak_name_signal_is_still_REPORTED_even_though_it_does_not_decide():
    """Suppressing it would hide why the identity looked interesting at all."""
    c = aws_nhi.classify_principal({"kind": "IAMRole", "name": "svc-billing"})
    assert any(s["confidence"] == aws_nhi.WEAK for s in c["signals"])


def test_a_name_cannot_OVERTURN_structural_evidence():
    """A role called `admin-something` that a service assumes is still a machine."""
    c = aws_nhi.classify_principal(
        {"kind": "IAMRole", "name": "admin-backup", "trust_policy": trust(svc())})
    assert c["verdict"] == aws_nhi.MACHINE


def test_the_unclassified_case_says_why():
    c = aws_nhi.classify_principal({"kind": "IAMRole", "name": "deploy-prod"})
    assert "not enough to classify" in c["reason"]


# ── conflicting evidence is a finding, not a tie to break ───────────────────
def test_both_machine_and_human_evidence_is_reported_as_ambiguous():
    c = aws_nhi.classify_principal(
        {"kind": "IAMUser", "name": "svc-etl", "has_login_profile": True,
         "has_instance_profile": True})
    assert c["verdict"] == aws_nhi.AMBIGUOUS
    assert "worth investigating" in c["reason"]


def test_a_keyed_user_with_no_console_login_infers_machine():
    """The classic long-lived service account. Inferred, and labelled as such."""
    c = aws_nhi.classify_principal(
        {"kind": "IAMUser", "name": "etl", "has_login_profile": False,
         "access_key_count": 2})
    assert c["verdict"] == aws_nhi.MACHINE
    assert c["confidence"] == aws_epistemics.INFERRED


# ── the NHI-specific findings ───────────────────────────────────────────────
def machine(**kw):
    return {"kind": "IAMRole", "name": "svc", "trust_policy": trust(svc()), **kw}


def ids(findings):
    return sorted(f["check_id"] for f in findings)


def test_a_machine_with_a_console_login_is_NHI_01():
    f = aws_nhi.nhi_findings({"kind": "IAMUser", "name": "svc-etl",
                              "trust_policy": trust(svc()), "has_login_profile": True})
    # classification is ambiguous here (both signals), so NHI-01 must NOT fire --
    # it is scoped to identities we actually established are machines.
    assert "NHI-01" not in ids(f)


def test_NHI_01_fires_for_an_established_machine_with_a_login():
    p = machine(has_login_profile=True)
    # Force the machine verdict the way a caller with better evidence would.
    cls = {"verdict": aws_nhi.MACHINE, "confidence": aws_epistemics.CONFIGURED}
    f = aws_nhi.nhi_findings(p, classification=cls)
    assert "NHI-01" in ids(f)


def test_a_stale_machine_credential_is_NHI_02():
    f = aws_nhi.nhi_findings(machine(oldest_key_age_days=400))
    assert "NHI-02" in ids(f)
    assert next(x for x in f if x["check_id"] == "NHI-02")["key_age_days"] == 400


def test_a_fresh_credential_is_not_reported():
    assert "NHI-02" not in ids(aws_nhi.nhi_findings(machine(oldest_key_age_days=10)))


def test_an_unowned_machine_identity_is_NHI_03():
    assert "NHI-03" in ids(aws_nhi.nhi_findings(machine()))


@pytest.mark.parametrize("tag", ["Owner", "team", "CONTACT", "maintainer"])
def test_any_recognised_ownership_tag_clears_NHI_03(tag):
    assert "NHI-03" not in ids(aws_nhi.nhi_findings(machine(tags={tag: "platform"})))


def test_a_third_party_trust_without_an_external_id_is_NHI_04():
    f = aws_nhi.nhi_findings(
        machine(trust_policy=trust(svc(), cross("999999999999"))),
        known_accounts=["111111111111"])
    assert "NHI-04" in ids(f)
    assert next(x for x in f if x["check_id"] == "NHI-04")["external_account"] == "999999999999"


def test_an_external_id_clears_NHI_04():
    f = aws_nhi.nhi_findings(
        machine(trust_policy=trust(svc(), cross("999999999999", external_id=True))),
        known_accounts=["111111111111"])
    assert "NHI-04" not in ids(f)


def test_a_trust_from_a_KNOWN_account_is_not_third_party():
    f = aws_nhi.nhi_findings(
        machine(trust_policy=trust(svc(), cross("111111111111"))),
        known_accounts=["111111111111"])
    assert "NHI-04" not in ids(f)


def test_without_a_known_account_list_NO_third_party_claim_is_made():
    """THE honest branch. With nothing to compare against, every internal trust would
    look external. Silence beats reporting an estate's own accounts as vendors."""
    f = aws_nhi.nhi_findings(machine(trust_policy=trust(svc(), cross("999999999999"))))
    assert "NHI-04" not in ids(f)


def test_a_federated_trust_without_a_sub_condition_is_NHI_05():
    gh = "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"
    f = aws_nhi.nhi_findings(machine(trust_policy=trust(federated(gh))))
    assert "NHI-05" in ids(f)


def test_an_aud_condition_alone_does_not_clear_NHI_05():
    """Every workflow on the issuer shares the audience; only :sub pins which one."""
    gh = "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"
    f = aws_nhi.nhi_findings(machine(trust_policy=trust(
        federated(gh, {"StringEquals": {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}))))
    assert "NHI-05" in ids(f)


def test_a_sub_condition_clears_NHI_05():
    gh = "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"
    f = aws_nhi.nhi_findings(machine(trust_policy=trust(
        federated(gh, {"StringEquals": {
            "token.actions.githubusercontent.com:sub": "repo:acme/api:ref:refs/heads/main"}}))))
    assert "NHI-05" not in ids(f)


def test_every_finding_carries_the_confidence_it_rests_on():
    """A finding derived from a service-principal trust reads differently from one
    derived from a naming convention, and the reader must be able to tell."""
    for f in aws_nhi.nhi_findings(machine(oldest_key_age_days=400)):
        assert f["classification"] == aws_nhi.MACHINE
        assert f["classification_confidence"] in (
            aws_epistemics.CONFIGURED, aws_epistemics.INFERRED, aws_nhi.WEAK)


def test_findings_are_scoped_to_machines():
    """A person's 400-day-old password is a different finding, owned by IAM-*."""
    human = {"kind": "IAMUser", "name": "sarah", "has_login_profile": True,
             "oldest_key_age_days": 400}
    assert "NHI-02" not in ids(aws_nhi.nhi_findings(human))


# ── the summary must not hide its own coverage gap ──────────────────────────
def test_the_summary_counts_the_unclassified_prominently():
    s = aws_nhi.summarize([
        {"kind": "IAMRole", "name": "a", "trust_policy": trust(svc())},
        {"kind": "IAMUser", "name": "b", "has_login_profile": True},
        {"kind": "IAMRole", "name": "deploy-prod"},
    ])
    assert (s["machine"], s["human"], s["unclassified"]) == (1, 1, 1)
    assert "may well be a machine" in s["coverage_note"]


def test_a_fully_classified_estate_carries_no_coverage_note():
    s = aws_nhi.summarize([{"kind": "IAMRole", "name": "a", "trust_policy": trust(svc())}])
    assert s["unclassified"] == 0 and s["coverage_note"] == ""


def test_the_summary_reports_the_confidence_mix():
    s = aws_nhi.summarize([
        {"kind": "IAMRole", "name": "a", "trust_policy": trust(svc())},
        {"kind": "IAMRole", "name": "b", "has_instance_profile": True},
    ])
    assert s["by_confidence"][aws_epistemics.CONFIGURED] == 1
    assert s["by_confidence"][aws_epistemics.INFERRED] == 1


# ── malformed input ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, {}, {"trust_policy": "not-a-policy"},
                                 {"trust_policy": {"Statement": "nope"}},
                                 {"trust_policy": {"Statement": [{"Principal": "*"}]}}])
def test_malformed_input_does_not_raise(bad):
    c = aws_nhi.classify_principal(bad)
    assert c["verdict"] in (aws_nhi.MACHINE, aws_nhi.HUMAN, aws_nhi.AMBIGUOUS)
    aws_nhi.nhi_findings(bad)


def test_a_single_statement_object_is_handled_like_a_list():
    """IAM accepts Statement as an object; a parser that only handles lists reads the
    policy as empty and silently classifies the identity as unknown."""
    c = aws_nhi.classify_principal(
        {"kind": "IAMRole", "name": "r", "trust_policy": {"Statement": svc()}})
    assert c["verdict"] == aws_nhi.MACHINE


def test_a_principal_list_is_handled_like_a_string():
    c = aws_nhi.classify_principal({"kind": "IAMRole", "name": "r", "trust_policy": trust(
        {"Effect": "Allow", "Principal": {"Service": ["ec2.amazonaws.com",
                                                      "lambda.amazonaws.com"]}})})
    assert c["verdict"] == aws_nhi.MACHINE


def test_summarize_of_nothing_is_empty_not_an_error():
    assert aws_nhi.summarize(None)["total"] == 0


# ── the shape the product actually produces ─────────────────────────────────
# aws_live_scanner.parse_trust_policy normalizes a trust document for graph edges and
# keeps only `has_condition: bool`. A classifier that read only raw IAM documents would
# be inapplicable to the estate data this product collects -- and, worse, NHI-04/05 would
# never fire against it, which reads as "no such risk" rather than "not looked at".
def normalized(**kw):
    base = {"effect": "Allow", "aws": [], "service": [], "federated": [],
            "wildcard": False, "actions": {"sts:AssumeRole"}, "has_condition": False}
    base.update(kw)
    return [base]


def test_the_normalized_scanner_shape_classifies():
    c = aws_nhi.classify_principal(
        {"kind": "IAMRole", "name": "r",
         "trust_policy": normalized(service=["ec2.amazonaws.com"])})
    assert c["verdict"] == aws_nhi.MACHINE
    assert c["confidence"] == aws_epistemics.CONFIGURED


def test_the_normalized_shape_detects_a_workload_issuer():
    c = aws_nhi.classify_principal(
        {"kind": "IAMRole", "name": "r", "trust_policy": normalized(
            federated=["arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"])})
    assert c["verdict"] == aws_nhi.MACHINE


def test_NHI_05_reports_itself_UNEVALUATED_on_the_normalized_shape():
    """THE honest branch. The :sub condition is a condition, and this shape records only
    that some condition exists. Silence here would be indistinguishable from a pass."""
    f = aws_nhi.nhi_findings({"kind": "IAMRole", "name": "r", "trust_policy": normalized(
        service=["ec2.amazonaws.com"],
        federated=["arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"])})
    row = next(x for x in f if x["check_id"] == "NHI-05")
    assert row["status"] == "NOT_EVALUATED"
    assert "raw AssumeRolePolicyDocument" in row["detail"]


def test_NHI_04_reports_itself_UNEVALUATED_on_the_normalized_shape():
    f = aws_nhi.nhi_findings(
        {"kind": "IAMRole", "name": "r",
         "trust_policy": normalized(service=["ec2.amazonaws.com"],
                                    aws=["arn:aws:iam::999999999999:root"])},
        known_accounts=["111111111111"])
    row = next(x for x in f if x["check_id"] == "NHI-04")
    assert row["status"] == "NOT_EVALUATED"


def test_an_unevaluated_check_is_never_reported_as_a_risk():
    """It must not carry a real severity, or it would rank alongside actual findings."""
    f = aws_nhi.nhi_findings({"kind": "IAMRole", "name": "r", "trust_policy": normalized(
        service=["ec2.amazonaws.com"],
        federated=["arn:aws:iam::1:oidc-provider/gitlab.com"])})
    for row in f:
        if row.get("status") == "NOT_EVALUATED":
            assert row["severity"] == "INFO"


def test_the_raw_shape_still_evaluates_conditions_normally():
    """The normalized path must not have weakened the raw path."""
    gh = "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"
    f = aws_nhi.nhi_findings(machine(trust_policy=trust(federated(gh))))
    row = next(x for x in f if x["check_id"] == "NHI-05")
    assert row.get("status") != "NOT_EVALUATED"
    assert row["severity"] == "HIGH"
