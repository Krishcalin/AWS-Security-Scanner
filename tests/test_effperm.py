"""Unit tests for aws_effperm — the pure IAM effective-permissions solver.

Truth table for pivot_effective + eval_scope/eval_scp_level, the AWS SCP
scenarios (deny-by-default across the org tree, deny-wins), and the permission-
boundary ceiling (Shirley/Nikhil style) cases. Fail-open when boundary/SCP are
absent is asserted first — it is the load-bearing invariant.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_effperm as ep


def stmt(effect, actions=None, not_actions=None, resources=None, condition=None):
    return {
        "effect": effect,
        "actions": set(a.lower() for a in (actions or [])),
        "not_actions": set(a.lower() for a in (not_actions or [])),
        "resources": set(r.lower() for r in (resources or ["*"])),
        "not_resources": set(),
        "condition": condition,
    }


ALLOW_PASSROLE = [stmt("Allow", ["iam:PassRole", "sts:AssumeRole"])]


# ── eval_scope truth table ───────────────────────────────────────────────────
def test_eval_scope_unconditional_allow():
    assert ep.eval_scope("iam:passrole", ALLOW_PASSROLE) == ep.ALLOWED


def test_eval_scope_implicit_deny_when_no_match():
    assert ep.eval_scope("s3:getobject", ALLOW_PASSROLE) == ep.IMPLICIT_DENY


def test_eval_scope_explicit_deny_wins_over_allow():
    s = ALLOW_PASSROLE + [stmt("Deny", ["iam:PassRole"])]
    assert ep.eval_scope("iam:passrole", s) == ep.EXPLICIT_DENY


def test_eval_scope_conditioned_allow_only():
    s = [stmt("Allow", ["iam:PassRole"], condition={"StringEquals": {"x": "y"}})]
    assert ep.eval_scope("iam:passrole", s) == ep.ALLOWED_COND


def test_eval_scope_conditioned_deny_only():
    s = [stmt("Deny", ["iam:PassRole"], condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}})]
    assert ep.eval_scope("iam:passrole", s) == ep.EXPLICIT_DENY_COND


def test_eval_scope_unconditional_allow_beats_conditioned_deny():
    s = [stmt("Allow", ["iam:PassRole"]),
         stmt("Deny", ["iam:PassRole"], condition={"Bool": {"x": "false"}})]
    # unconditional allow present, only conditioned deny -> ALLOWED (deny is gated)
    assert ep.eval_scope("iam:passrole", s) == ep.ALLOWED


def test_eval_scope_wildcard_and_case_insensitive():
    s = [stmt("Allow", ["IAM:*"])]
    assert ep.eval_scope("iam:passrole", s) == ep.ALLOWED
    assert ep.eval_scope("s3:getobject", s) == ep.IMPLICIT_DENY


# ── NotAction inverse matching (Deny + NotAction guardrail) ──────────────────
def test_deny_notaction_denies_everything_except_listed():
    # Deny NotAction:[s3:*]  => denies all actions EXCEPT s3:*
    s = [stmt("Deny", not_actions=["s3:*"])]
    assert ep.eval_scope("iam:passrole", s) == ep.EXPLICIT_DENY   # not in s3:* -> denied
    assert ep.eval_scope("s3:getobject", s) == ep.IMPLICIT_DENY   # in s3:* -> not matched


def test_allow_notaction_allows_everything_except_listed():
    s = [stmt("Allow", not_actions=["iam:*"])]
    assert ep.eval_scope("sts:assumerole", s) == ep.ALLOWED
    assert ep.eval_scope("iam:passrole", s) == ep.IMPLICIT_DENY


# ── pivot_effective: fail-open invariant ─────────────────────────────────────
def test_failopen_no_boundary_no_scp_never_drops():
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, None, None) == ep.KEEP


def test_failopen_even_when_identity_does_not_grant():
    # identity doesn't grant the action, but with no ceiling data we still don't DROP
    assert ep.pivot_effective("s3:getobject", ALLOW_PASSROLE, None, None) == ep.KEEP


def test_identity_explicit_deny_drops_regardless():
    s = ALLOW_PASSROLE + [stmt("Deny", ["iam:PassRole"])]
    assert ep.pivot_effective("iam:passrole", s, None, None) == ep.DROP


# ── permission boundary as a ceiling (intersection) ──────────────────────────
def test_boundary_implicit_deny_drops():
    boundary = [stmt("Allow", ["s3:*"])]   # boundary doesn't mention iam:PassRole
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, boundary, None) == ep.DROP


def test_boundary_explicit_deny_drops():
    boundary = [stmt("Allow", ["*"]), stmt("Deny", ["iam:PassRole"])]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, boundary, None) == ep.DROP


def test_boundary_allows_keeps():
    boundary = [stmt("Allow", ["iam:*", "sts:*"])]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, boundary, None) == ep.KEEP


def test_boundary_conditioned_allow_downgrades():
    boundary = [stmt("Allow", ["iam:PassRole"], condition={"StringEquals": {"x": "y"}})]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, boundary, None) == ep.CONDITIONED


# ── SCP: deny-by-default across the org tree, AND across levels ──────────────
def _full_access_scp():
    return [stmt("Allow", ["*"])]   # AwsManaged FullAWSAccess


def test_scp_all_levels_allow_keeps():
    scp_levels = [[_full_access_scp()], [_full_access_scp()], [_full_access_scp()]]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, None, scp_levels) == ep.KEEP


def test_scp_missing_allow_at_one_level_drops():
    # root allows *, but the account-level SCP only allows s3 -> iam:PassRole carved out
    scp_levels = [[_full_access_scp()], [[stmt("Allow", ["s3:*"])]]]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, None, scp_levels) == ep.DROP


def test_scp_explicit_deny_at_any_level_drops():
    scp_levels = [[_full_access_scp()],
                  [[stmt("Allow", ["*"]), stmt("Deny", ["iam:PassRole"])]]]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, None, scp_levels) == ep.DROP


def test_scp_within_level_or_of_allows():
    # one SCP allows s3, another allows iam -> union within the level allows both
    level = [[stmt("Allow", ["s3:*"])], [stmt("Allow", ["iam:*"])]]
    scp_levels = [level]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, None, scp_levels) == ep.KEEP


def test_scp_within_level_deny_still_wins():
    level = [[stmt("Allow", ["*"])], [stmt("Deny", ["iam:PassRole"])]]
    assert ep.eval_scp_level("iam:passrole", level) == ep.EXPLICIT_DENY


def test_scp_conditioned_allow_downgrades():
    scp_levels = [[[stmt("Allow", ["iam:PassRole"],
                         condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}})]]]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, None, scp_levels) == ep.CONDITIONED


# ── combined boundary ∩ SCP; deny-wins across the whole chain ────────────────
def test_boundary_and_scp_both_must_allow():
    boundary = [stmt("Allow", ["iam:*"])]
    scp_levels = [[_full_access_scp()]]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, boundary, scp_levels) == ep.KEEP
    # tighten SCP -> drop even though boundary allows
    scp_tight = [[[stmt("Allow", ["s3:*"])]]]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, boundary, scp_tight) == ep.DROP


def test_conditioned_propagates_from_either_ceiling():
    boundary = [stmt("Allow", ["iam:*"])]
    scp_cond = [[[stmt("Allow", ["iam:PassRole"], condition={"Bool": {"x": "true"}})]]]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, boundary, scp_cond) == ep.CONDITIONED


# ── drop_reason evidence ─────────────────────────────────────────────────────
def test_drop_reason_boundary():
    boundary = [stmt("Allow", ["s3:*"])]
    assert ep.drop_reason("iam:passrole", ALLOW_PASSROLE, boundary, None) == "boundary_implicit_deny"


def test_drop_reason_scp_no_allow():
    scp_levels = [[[stmt("Allow", ["s3:*"])]]]
    assert ep.drop_reason("iam:passrole", ALLOW_PASSROLE, None, scp_levels) == "scp_no_allow"


def test_drop_reason_none_when_kept():
    assert ep.drop_reason("iam:passrole", ALLOW_PASSROLE, None, None) is None


# ── regression (adversarial rank 6): a boundary that only CONDITIONALLY denies
# the action and never Allows it grants nothing -> the ceiling implicitly denies
# -> DROP (was wrongly scored CONDITIONED / edge kept). ────────────────────────
def test_boundary_conditioned_deny_no_allow_drops():
    boundary = [stmt("Deny", ["iam:PassRole"], condition={"Bool": {"x": "true"}})]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, boundary, None) == ep.DROP
    assert ep.drop_reason("iam:passrole", ALLOW_PASSROLE, boundary, None) == "boundary_implicit_deny"


def test_boundary_real_conditioned_allow_still_conditioned():
    # a genuine conditioned ALLOW must remain CONDITIONED (not regressed to DROP)
    boundary = [stmt("Allow", ["iam:PassRole"], condition={"Bool": {"x": "true"}})]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, boundary, None) == ep.CONDITIONED


def test_boundary_conditioned_allow_beats_conditioned_deny():
    # ALLOWED_COND wins over EXPLICIT_DENY_COND inside eval_scope -> CONDITIONED kept
    boundary = [stmt("Allow", ["iam:PassRole"], condition={"a": {"x": "1"}}),
                stmt("Deny", ["iam:PassRole"], condition={"b": {"y": "2"}})]
    assert ep.pivot_effective("iam:passrole", ALLOW_PASSROLE, boundary, None) == ep.CONDITIONED


# ── full-admin wildcard pivot ────────────────────────────────────────────────
def test_wildcard_pivot_capped_by_boundary():
    ident = [stmt("Allow", ["*"])]
    boundary = [stmt("Allow", ["s3:*"])]   # boundary caps admin down to s3
    # '*' is not covered by s3:* -> boundary implicit-deny -> DROP
    assert ep.pivot_effective("*", ident, boundary, None) == ep.DROP


def test_wildcard_pivot_kept_when_boundary_admin():
    ident = [stmt("Allow", ["*"])]
    boundary = [stmt("Allow", ["*"])]
    assert ep.pivot_effective("*", ident, boundary, None) == ep.KEEP
