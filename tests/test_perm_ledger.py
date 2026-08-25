"""Phase 1 · slice 1.1 — the permission ledger.

The load-bearing test feeds the ledger the actions our SHIPPED role actually grants
(SecurityAudit v92 + ViewOnlyAccess, as attached by deploy/cnapp-scanner-role.yaml) and
asserts it finds exactly the three actions the AI pillar is missing.

That number is the point. Both the roadmap and an earlier analysis asserted the pillar
was broadly AccessDenied-degraded, having looked at ViewOnlyAccess alone and reasoned
from memory. Reading the attached policies showed three missing actions, all narrow, all
Get-shaped. A ledger computed from the policy documents does not make that mistake, and
this test is what stops the codebase making it a third time.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_perm_ledger as L

# The bedrock/sagemaker/lambda actions SecurityAudit v92 really grants, transcribed
# from the published policy document. Deliberately verbatim rather than wildcarded:
# the whole point is that `bedrock:Get*` is NOT what AWS grants, and a wildcard here
# would hide the very gap the ledger exists to find.
SECURITY_AUDIT_BEDROCK = {
    "bedrock:getagent", "bedrock:getagentalias", "bedrock:getagentknowledgebase",
    "bedrock:getcustommodel", "bedrock:getfoundationmodel", "bedrock:getimportedmodel",
    "bedrock:getinferenceprofile", "bedrock:getingestionjob",
    "bedrock:getknowledgebasedocuments", "bedrock:getmodelcopyjob",
    "bedrock:getmodelcustomizationjob", "bedrock:getmodelimportjob",
    "bedrock:getmodelinvocationloggingconfiguration", "bedrock:getpromptrouter",
    "bedrock:getprovisionedmodelthroughput",
    "bedrock:listagentactiongroups", "bedrock:listagentaliases",
    "bedrock:listagentknowledgebases", "bedrock:listagents", "bedrock:listagentversions",
    "bedrock:listcustommodels", "bedrock:listdatasources", "bedrock:listevaluationjobs",
    "bedrock:listfoundationmodels", "bedrock:listguardrails",
    "bedrock:listimportedmodels", "bedrock:listinferenceprofiles",
    "bedrock:listingestionjobs", "bedrock:listknowledgebases",
    "bedrock:listprovisionedmodelthroughputs", "bedrock:listtagsforresource",
}
SHIPPED_ROLE = [{
    "effect": "Allow",
    "actions": SECURITY_AUDIT_BEDROCK | {
        "sagemaker:describe*", "sagemaker:list*",     # SecurityAudit grants both
        "lambda:getpolicy", "ec2:describe*", "iam:get*", "iam:list*",
    },
    "resources": {"*"}, "not_resources": set(), "condition": None,
}]

# What ViewOnlyAccess alone grants for Bedrock — two actions. This is the policy the
# earlier analysis looked at, and looking at it alone is why the gap was overstated.
VIEW_ONLY_ALONE = [{
    "effect": "Allow",
    "actions": {"bedrock:listcustommodels", "bedrock:listtagsforresource"},
    "resources": {"*"}, "not_resources": set(), "condition": None,
}]

# Slice 2.1 added the fourth: SecurityAudit grants bedrock:ListGuardrails but not
# bedrock:GetGuardrail -- the same List-without-Get shape as the other three, and the
# reason guardrail STRENGTH cannot be read from the managed policies alone.
EXPECTED_GAP = ("bedrock:GetAgentActionGroup", "bedrock:GetDataSource",
                "bedrock:GetGuardrail", "bedrock:GetKnowledgeBase")


# ── the load-bearing assertion ──────────────────────────────────────────────
def test_the_shipped_role_is_missing_exactly_four_actions():
    """Computed from the policy documents, not recalled. If this number moves, either
    AWS changed SecurityAudit or we added a call — both worth a human looking."""
    led = L.evaluate(SHIPPED_ROLE)
    assert led.missing_actions == EXPECTED_GAP, (
        f"expected exactly {EXPECTED_GAP}, got {led.missing_actions}")


def test_the_blocked_checks_are_the_knowledge_base_and_guardrail_grading_ones():
    """All three guardrail-grading checks block on the SAME single action, which is
    what makes GetGuardrail cheap to justify: one Get buys three checks. AIGRD-03 is
    absent on purpose -- enforcement is read from statements already collected."""
    led = L.evaluate(SHIPPED_ROLE)
    assert set(led.blocked) == {"AGT-03", "AGT-04",
                                "AIGRD-01", "AIGRD-02", "AIGRD-04"}
    assert led.blocked["AGT-03"] == ("bedrock:GetDataSource",
                                     "bedrock:GetKnowledgeBase")
    assert led.blocked["AGT-04"] == ("bedrock:GetAgentActionGroup",)
    for cid in ("AIGRD-01", "AIGRD-02", "AIGRD-04"):
        assert led.blocked[cid] == ("bedrock:GetGuardrail",), cid
    assert "AIGRD-03" not in led.blocked


def test_getagentknowledgebase_is_not_getknowledgebase():
    """The specific confusion that made the gap invisible. SecurityAudit grants
    GetAgentKnowledgeBase — a different API that reads a KB *association on an agent*.
    Our scanner calls GetKnowledgeBase, which it does not grant."""
    assert L.granted(SHIPPED_ROLE, "bedrock:GetAgentKnowledgeBase")
    assert not L.granted(SHIPPED_ROLE, "bedrock:GetKnowledgeBase")


def test_viewonlyaccess_alone_overstates_the_gap():
    """Reading one of the two attached policies is how the pillar came to be described
    as broadly degraded. It is not — but it IS if you only look here."""
    narrow = L.evaluate(VIEW_ONLY_ALONE)
    assert len(narrow.missing_actions) > len(L.evaluate(SHIPPED_ROLE).missing_actions)
    assert "bedrock:ListGuardrails" in narrow.missing_actions
    assert "bedrock:ListGuardrails" not in L.evaluate(SHIPPED_ROLE).missing_actions


# ── the forfeit accounting ──────────────────────────────────────────────────
def test_declining_an_action_names_what_it_costs():
    """The number that turns an IAM review into a decision instead of a leap."""
    led = L.evaluate(SHIPPED_ROLE)
    assert led.forfeit(["bedrock:GetKnowledgeBase"]) == ("AGT-03",)
    assert led.forfeit(["bedrock:GetAgentActionGroup"]) == ("AGT-04",)
    assert led.forfeit(["bedrock:GetGuardrail"]) == (
        "AIGRD-01", "AIGRD-02", "AIGRD-04")
    assert set(led.forfeit(EXPECTED_GAP)) == {"AGT-03", "AGT-04",
                                              "AIGRD-01", "AIGRD-02", "AIGRD-04"}


def test_declining_an_action_a_working_check_depends_on_is_also_counted():
    """Forfeit is not only about currently-blocked checks: declining something already
    granted costs the checks that rely on it."""
    led = L.evaluate(SHIPPED_ROLE)
    assert "BDR-01" in led.forfeit(["bedrock:GetModelInvocationLoggingConfiguration"])
    assert "AGT-05" in led.forfeit(["bedrock:GetAgent"])


def test_declining_nothing_forfeits_nothing():
    assert L.evaluate(SHIPPED_ROLE).forfeit([]) == ()


# ── the emitted policy ──────────────────────────────────────────────────────
def test_the_additive_policy_asks_for_the_minimum_and_nothing_else():
    pol = L.evaluate(SHIPPED_ROLE).additive_policy()
    assert pol["Version"] == "2012-10-17"
    assert pol["Statement"][0]["Action"] == list(EXPECTED_GAP)
    assert pol["Statement"][0]["Effect"] == "Allow"


def test_the_additive_policy_contains_only_read_actions():
    """The charter promise that must survive: read-only-of-CONFIG. A Put/Create/Delete
    here would break it, and s3:GetObject or logs:StartQuery would cross the config/data
    line that belongs to the separate opt-in blocks."""
    pol = L.evaluate(SHIPPED_ROLE).additive_policy()
    for action in pol["Statement"][0]["Action"]:
        verb = action.split(":", 1)[1]
        assert verb.startswith(("Get", "List", "Describe")), f"{action} is not a read"
        assert action.lower() not in ("s3:getobject", "logs:startquery")


def test_a_fully_granted_role_asks_for_nothing():
    """An admin role must produce an EMPTY policy, not a redundant one."""
    admin = [{"effect": "Allow", "actions": {"*"}, "resources": {"*"},
              "not_resources": set(), "condition": None}]
    led = L.evaluate(admin)
    assert led.missing_actions == ()
    assert led.additive_policy()["Statement"] == []
    assert not led.blocked


def test_every_requested_action_carries_a_justification():
    """An action without a reason is exactly the policy line a reviewer rejects."""
    for row in L.evaluate(SHIPPED_ROLE).annotated_policy():
        assert row["why"], f"{row['action']} has no justification"
        assert row["enables"], f"{row['action']} enables no check"
        assert len(row["why"]) > 30, f"{row['action']}'s reason is not a reason"


# ── IAM semantics ───────────────────────────────────────────────────────────
def test_wildcards_grant_and_explicit_deny_wins():
    wild = [{"effect": "Allow", "actions": {"bedrock:*"}, "resources": {"*"},
             "not_resources": set(), "condition": None}]
    assert L.granted(wild, "bedrock:GetKnowledgeBase")

    denied = wild + [{"effect": "Deny", "actions": {"bedrock:getknowledgebase"},
                      "resources": {"*"}, "not_resources": set(), "condition": None}]
    assert not L.granted(denied, "bedrock:GetKnowledgeBase")
    assert "bedrock:GetKnowledgeBase" in L.evaluate(denied).missing_actions


def test_checks_that_need_no_permission_are_recorded_as_free():
    """AISPM-* reason over already-cached principals and graph edges. Saying so is
    better than staying silent: it tells a reviewer these cost them nothing."""
    led = L.evaluate(SHIPPED_ROLE)
    assert set(led.free) == {"AISPM-01", "AISPM-02", "AISPM-03", "AIPATH-01",
                             "AIGRD-03"}
    for cid in led.free:
        assert cid in led.evaluable


# ── the coverage manifest ───────────────────────────────────────────────────
def test_a_denied_check_is_not_evaluated_rather_than_passed():
    """The distinction the whole module exists for."""
    m = L.CoverageManifest()
    m.note_denied("AGT-03", "bedrock:GetKnowledgeBase")
    assert "AGT-03" in m.not_evaluated
    assert "AccessDenied" in m.not_evaluated["AGT-03"]
    assert "bedrock:GetKnowledgeBase" in m.missing_actions
    assert not m.complete


def test_a_manifest_with_nothing_withheld_is_complete():
    m = L.CoverageManifest(scanned_regions=["us-east-1"], enumerated=["BedrockAgent"])
    assert m.complete


def test_an_unscanned_region_makes_a_scan_incomplete():
    """A clean report over one region is not a clean report over the account."""
    m = L.CoverageManifest(scanned_regions=["us-east-1"],
                           unscanned_regions=["us-west-2"])
    assert not m.complete


def test_the_manifest_round_trips():
    m = L.CoverageManifest(scanned_regions=["us-east-1"],
                           unscanned_regions=["eu-west-1"],
                           enumerated=["BedrockAgent", "SageMakerNotebook"])
    m.note_denied("AGT-04", "bedrock:GetAgentActionGroup")
    again = L.CoverageManifest.from_dict(m.to_dict())
    assert again.to_dict() == m.to_dict()
    assert again.complete is False


# ── the table itself ────────────────────────────────────────────────────────
def test_every_requirement_names_a_real_check():
    from aws_live_scanner import CHECK_SEVERITY
    unknown = sorted(c for c in L.REQUIREMENTS if c not in CHECK_SEVERITY)
    assert not unknown, f"requirement table names checks that do not exist: {unknown}"


def test_every_requirement_action_is_a_read():
    for check_id, reqs in L.REQUIREMENTS.items():
        for r in reqs:
            verb = r.action.split(":", 1)[1]
            assert verb.startswith(("Get", "List", "Describe")), (
                f"{check_id} requires {r.action}, which is not a read action")
