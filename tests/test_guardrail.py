"""What a blocking CI/CD gate does when it cannot evaluate.

THE DEFECT (review finding D5)
-------------------------------
OW2-GR-003 defaults production to `block` after bake-in. OW2-IF-001 protects
SCANNING from connector failure and says nothing about the pipeline gate. So when
the policy engine is unreachable the specification supports both fail-closed (every
production deploy halts, including the one fixing the outage) and fail-open (the
control is silently disabled estate-wide while pipelines show green).

THE INVARIANT THESE TESTS EXIST TO HOLD
----------------------------------------
An evaluation that did not happen is never an allow.
`test_a_clean_pass_is_only_ever_reachable_from_a_complete_evaluation` states it as a
property over every combination rather than as a worked example, because the way
this breaks in practice is a new code path added later that looks locally
reasonable — a `try/except: return ALLOW`, or a caller that reads its own timeout as
a pass. That single line is the cheapest way to disable the entire control, and it
would leave every pipeline green.
"""
from __future__ import annotations

import itertools
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_guardrail as G  # noqa: E402

NOW = 1_700_000_000
PROD, DEV = "prod", "dev"

ENCRYPT = G.Policy("GR-01", "Encryption at rest",
                   modes={PROD: G.BLOCK, DEV: G.WARN})
PUBLIC_DB = G.Policy("GR-02", "No public database",
                     modes={PROD: G.BLOCK, DEV: G.BLOCK})
TAGS = G.Policy("GR-05", "Mandatory tags",
                modes={PROD: G.WARN, DEV: G.AUDIT})
REGION = G.Policy("GR-04", "Approved regions only",
                  modes={PROD: G.AUDIT, DEV: G.AUDIT})

ALL = [ENCRYPT, PUBLIC_DB, TAGS]


def ok(*pids, violations=(), ms=1000):
    return G.Evaluation(G.EVALUATED, violations=violations,
                        evaluated_policy_ids=pids or tuple(p.id for p in ALL),
                        elapsed_ms=ms)


def down(detail="policy engine unreachable", ms=500, outcome=G.UNAVAILABLE, **kw):
    return G.Evaluation(outcome, detail=detail, elapsed_ms=ms, **kw)


def glass(actor="sre@example.com", expires=NOW + 3600):
    return G.BreakGlass(actor, "Restoring the policy engine; this deploy contains "
                               "the fix for the outage that stopped it.", expires)


# ═══ the invariant ═══════════════════════════════════════════════════════════

def test_a_clean_pass_is_only_ever_reachable_from_a_complete_evaluation():
    # Every combination of outcome, environment and override. A clean pass -- allow,
    # not degraded, not an override -- must imply the gate actually evaluated.
    for outcome, env, bg in itertools.product(
            G.OUTCOMES, (PROD, DEV), (None, glass())):
        ev = (ok() if outcome == G.EVALUATED
              else G.Evaluation(outcome, detail="engine down",
                                evaluated_policy_ids=(), elapsed_ms=10))
        v = G.decide(ev, ALL, env, now_epoch=NOW, break_glass=bg)
        if v.action == G.ALLOW and not v.degraded and not v.is_override:
            assert v.outcome == G.EVALUATED, (
                "a clean pass escaped from outcome=%r in %s" % (outcome, env))
            assert v.verified


def test_verified_is_false_for_every_incomplete_outcome():
    for outcome in G.INCOMPLETE:
        ev = G.Evaluation(outcome, detail="engine down", elapsed_ms=10)
        assert not G.decide(ev, ALL, DEV, now_epoch=NOW).verified


# ═══ fail-closed, and what it costs ══════════════════════════════════════════

def test_an_unavailable_gate_blocks_in_production():
    v = G.decide(down(), ALL, PROD, now_epoch=NOW)
    assert v.action == G.BLOCK_ACTION
    assert v.exit_code == G.EXIT_BLOCKED
    assert "Fail-closed" in v.reason


def test_the_block_names_the_policies_that_did_not_run():
    v = G.decide(down(), ALL, PROD, now_epoch=NOW)
    assert set(v.unevaluated) == {"GR-01", "GR-02", "GR-05"}
    for pid in ("GR-01", "GR-02", "GR-05"):
        assert pid in v.reason, (
            "an engineer whose deploy was stopped must be told what was not checked")


def test_the_block_explains_why_the_gate_failed():
    v = G.decide(down("TLS handshake to opa.internal timed out"), ALL, PROD,
                 now_epoch=NOW)
    assert "TLS handshake" in v.reason


def test_an_incomplete_outcome_must_carry_a_detail():
    with pytest.raises(ValueError, match="cannot explain why"):
        G.Evaluation(G.UNAVAILABLE, elapsed_ms=5)


# ═══ an unavailable gate does what its strictest mode would have done ════════

def test_an_unavailable_gate_does_not_block_where_nothing_blocks():
    # Only audit-mode policies apply, so an unreachable engine must not invent
    # enforcement that was never configured.
    v = G.decide(down(), [REGION], PROD, now_epoch=NOW)
    assert v.action == G.ALLOW
    assert v.degraded


def test_an_unavailable_gate_warns_where_warn_was_configured():
    v = G.decide(down(), [TAGS], PROD, now_epoch=NOW)
    assert v.action == G.WARN_ACTION
    assert v.degraded


def test_a_degraded_allow_is_never_rendered_as_a_pass():
    v = G.decide(down(), [REGION], PROD, now_epoch=NOW)
    assert v.exit_code == G.EXIT_UNVERIFIED
    assert not v.verified
    assert "This is not a pass" in v.headline()
    assert "no policy was checked" in v.headline().lower()


def test_losing_the_service_cannot_downgrade_enforcement():
    # dev has GR-02 at block; the gate being down must still block there.
    assert G.decide(down(), ALL, DEV, now_epoch=NOW).action == G.BLOCK_ACTION


# ═══ break-glass ═════════════════════════════════════════════════════════════

def test_break_glass_lets_the_outage_fix_ship():
    v = G.decide(down(), ALL, PROD, now_epoch=NOW, break_glass=glass())
    assert v.action == G.ALLOW
    assert v.is_override
    assert v.exit_code == G.EXIT_UNVERIFIED


def test_an_override_is_never_a_pass():
    v = G.decide(down(), ALL, PROD, now_epoch=NOW, break_glass=glass())
    assert not v.verified
    assert "ALLOWED UNDER OVERRIDE" in v.headline()
    assert "did not clear this change" in v.headline()


def test_an_expired_override_blocks_rather_than_degrading_to_a_warning():
    v = G.decide(down(), ALL, PROD, now_epoch=NOW,
                 break_glass=glass(expires=NOW - 1))
    assert v.action == G.BLOCK_ACTION
    assert v.override_rejected == "expired"
    assert not v.is_override


def test_an_override_requires_an_actor():
    with pytest.raises(ValueError, match="unattributed"):
        G.BreakGlass("  ", "a" * 40, NOW + 60)


def test_an_override_requires_a_real_justification():
    with pytest.raises(ValueError, match="looks complete and says nothing"):
        G.BreakGlass("me", "temp", NOW + 60)


def test_an_override_requires_an_expiry():
    with pytest.raises(ValueError, match="permanent policy change"):
        G.BreakGlass("me", "a" * 40, 0)


def test_an_override_on_a_healthy_gate_does_not_launder_a_real_violation():
    # The engine ran and found a blocking breach. Break-glass is for an
    # unavailable gate, not for overruling a verdict it actually produced.
    ev = ok(violations=(G.Violation("GR-02", "db-1", "publicly accessible"),))
    v = G.decide(ev, ALL, PROD, now_epoch=NOW, break_glass=glass())
    assert v.action == G.BLOCK_ACTION
    assert not v.is_override


# ═══ partial evaluation ══════════════════════════════════════════════════════

def test_silence_about_a_policy_is_not_a_pass_for_it():
    # The caller claims EVALUATED but names only two of three policies.
    v = G.decide(ok("GR-01", "GR-02"), ALL, PROD, now_epoch=NOW)
    assert v.outcome == G.PARTIAL
    assert v.unevaluated == ("GR-05",)


def test_a_partial_evaluation_that_already_found_a_breach_still_blocks():
    ev = G.Evaluation(G.PARTIAL, detail="engine crashed mid-run",
                      violations=(G.Violation("GR-02", "db-1", "public"),),
                      evaluated_policy_ids=("GR-02",), elapsed_ms=900)
    v = G.decide(ev, ALL, PROD, now_epoch=NOW)
    assert v.action == G.BLOCK_ACTION
    assert "still a breach" in v.reason


def test_a_breach_found_before_failure_blocks_even_with_break_glass_absent():
    ev = G.Evaluation(G.PARTIAL, detail="engine crashed",
                      violations=(G.Violation("GR-02", "db-1", "public"),),
                      evaluated_policy_ids=("GR-02",), elapsed_ms=10)
    assert G.decide(ev, ALL, DEV, now_epoch=NOW).action == G.BLOCK_ACTION


# ═══ normal operation is unchanged ═══════════════════════════════════════════

def test_a_clean_evaluation_passes_with_exit_zero():
    v = G.decide(ok(), ALL, PROD, now_epoch=NOW)
    assert v.action == G.ALLOW and v.verified
    assert v.exit_code == G.EXIT_OK
    assert v.headline().startswith("PASSED")


def test_a_blocking_violation_blocks():
    ev = ok(violations=(G.Violation("GR-01", "vol-1", "unencrypted"),))
    v = G.decide(ev, ALL, PROD, now_epoch=NOW)
    assert v.action == G.BLOCK_ACTION


def test_the_same_violation_only_warns_where_the_mode_says_warn():
    ev = ok(violations=(G.Violation("GR-01", "vol-1", "unencrypted"),))
    v = G.decide(ev, ALL, DEV, now_epoch=NOW)
    assert v.action == G.WARN_ACTION
    assert v.exit_code == G.EXIT_OK
    assert v.verified, "a warn is a completed evaluation, not a degraded one"


def test_the_strictest_mode_among_violated_policies_wins():
    ev = ok(violations=(G.Violation("GR-05", "r", "no tags"),
                        G.Violation("GR-01", "v", "unencrypted")))
    assert G.decide(ev, ALL, PROD, now_epoch=NOW).action == G.BLOCK_ACTION


def test_policy_rejects_an_unknown_mode():
    with pytest.raises(ValueError, match="unknown mode"):
        G.Policy("X", "x", modes={PROD: "maybe"})


# ═══ the latency budget (OW2-GR-004) ═════════════════════════════════════════

def test_a_pipeline_timeout_is_not_a_pass():
    # The single easiest way to disable the whole control is a CI config that
    # reads its own timeout as success.
    v = G.decide(down("pipeline stopped waiting after 120s", outcome=G.TIMEOUT,
                      ms=120_001), ALL, PROD, now_epoch=NOW)
    assert v.action == G.BLOCK_ACTION
    assert v.outcome == G.TIMEOUT


def test_a_late_but_complete_evaluation_is_honoured_on_its_merits():
    # Ignoring a real BLOCK because it was slow would be worse than being late.
    ev = ok(violations=(G.Violation("GR-01", "v", "unencrypted"),), ms=200_000)
    v = G.decide(ev, ALL, PROD, now_epoch=NOW)
    assert v.action == G.BLOCK_ACTION
    assert v.budget_exceeded


def test_a_late_clean_evaluation_passes_but_records_the_breach():
    v = G.decide(ok(ms=200_000), ALL, PROD, now_epoch=NOW)
    assert v.action == G.ALLOW and v.verified
    assert v.budget_exceeded, "OW2-GR-004 must stay measurable, not aspirational"


def test_within_budget_records_no_breach():
    assert not G.decide(ok(ms=1000), ALL, PROD, now_epoch=NOW).budget_exceeded


# ═══ the record (OW2-GR-005) ═════════════════════════════════════════════════

def test_every_verdict_produces_an_audit_record():
    for v in (G.decide(ok(), ALL, PROD, now_epoch=NOW),
              G.decide(down(), ALL, PROD, now_epoch=NOW),
              G.decide(down(), ALL, PROD, now_epoch=NOW, break_glass=glass())):
        r = v.audit_record()
        assert r["action"] in G.ACTIONS
        assert r["outcome"] in G.OUTCOMES
        assert isinstance(r["verified"], bool)
        assert r["headline"]


def test_the_override_record_carries_actor_and_justification():
    r = G.decide(down(), ALL, PROD, now_epoch=NOW,
                 break_glass=glass()).audit_record()
    assert r["override"]["actor"] == "sre@example.com"
    assert "outage" in r["override"]["justification"]
    assert r["override"]["expires_epoch"] == NOW + 3600


def test_a_pass_record_carries_no_override():
    assert G.decide(ok(), ALL, PROD, now_epoch=NOW).audit_record()["override"] is None


def test_a_rejected_override_is_recorded_as_rejected():
    r = G.decide(down(), ALL, PROD, now_epoch=NOW,
                 break_glass=glass(expires=NOW - 1)).audit_record()
    assert r["override_rejected"] == "expired"
    assert r["override"] is None


# ═══ the weekly report, and the bridge to GR-006 ═════════════════════════════

def week():
    return [G.decide(ok(), ALL, PROD, now_epoch=NOW),
            G.decide(ok(), ALL, PROD, now_epoch=NOW),
            G.decide(down(), ALL, PROD, now_epoch=NOW),
            G.decide(down(), ALL, PROD, now_epoch=NOW, break_glass=glass()),
            G.decide(down(), [REGION], PROD, now_epoch=NOW)]


def test_unverified_allows_finds_everything_that_shipped_unchecked():
    us = G.unverified_allows(week())
    assert len(us) == 2, "one override and one degraded allow"
    assert all(v.action != G.BLOCK_ACTION for v in us)
    assert all(not v.verified for v in us)


def test_a_block_is_not_an_unverified_allow():
    assert G.unverified_allows([G.decide(down(), ALL, PROD, now_epoch=NOW)]) == ()


def test_the_weekly_report_counts_each_category_apart():
    r = G.override_report(week())
    assert r["total"] == 5
    assert r["verified_pass"] == 2
    assert r["blocked"] == 1
    assert r["overrides"] == 1
    assert r["degraded_allows"] == 1


def test_the_report_attributes_overrides_to_actors():
    assert G.override_report(week())["overrides_by_actor"] == {"sre@example.com": 1}


def test_the_report_says_what_an_unverified_allow_means():
    s = G.override_report(week())["summary"]
    assert "2 of 5 changes shipped without the gate clearing them" in s
    assert "no policy was checked against" in s


def test_a_clean_week_says_so_plainly():
    s = G.override_report([G.decide(ok(), ALL, PROD, now_epoch=NOW)])["summary"]
    assert "nothing shipped without the gate clearing it" in s


def test_an_empty_week_does_not_claim_success():
    assert "No pipeline evaluations" in G.override_report([])["summary"]


def test_budget_breaches_are_counted_for_gr_004_compliance():
    vs = [G.decide(ok(ms=200_000), ALL, PROD, now_epoch=NOW),
          G.decide(ok(ms=1000), ALL, PROD, now_epoch=NOW)]
    assert G.override_report(vs)["budget_breaches"] == 1


# ═══ reproducibility ═════════════════════════════════════════════════════════

def test_a_verdict_is_a_pure_function_of_its_inputs():
    a = G.decide(down(), ALL, PROD, now_epoch=NOW, break_glass=glass())
    b = G.decide(down(), ALL, PROD, now_epoch=NOW, break_glass=glass())
    assert a == b, "an auditor must be able to recompute a verdict from its record"
