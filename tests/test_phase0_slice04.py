"""Phase 0 · slice 0.4 — AISPM-01 respects the ceiling, and every finding says how
much we actually know.

Part A pins the correctness fix: `role_privesc_capable` reads identity statements
alone, so it ignores permission boundaries and SCPs. Enterprises boundary AI
execution roles precisely because those roles are new, which means the raw signal
over-reported on exactly the accounts most likely to be evaluating the product —
and contradicted the CIEM verdict OverWatch already computed for the same role.

Part B pins the epistemic class: a GuardDuty detection and a capability analysis are
not the same kind of claim, and a product that averages them will eventually assert
an incident when it computed a possibility.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_effperm
from engine import aws_epistemics
from engine import aws_graph
from engine import aws_live_scanner
from engine.aws_live_scanner import AWSLiveScanner

from _layout import module_files

ROLE = "arn:aws:iam::123456789012:role/AIExecutionRole"

# an identity policy that hands the AI role a classic escalation primitive
PASSROLE_ALLOW = [{"effect": "Allow", "actions": {"iam:passrole"}, "resources": {"*"},
                   "not_resources": set(), "condition": None}]


def _scanner() -> AWSLiveScanner:
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["DATA"])
        s.account = "123456789012"
    s._client = lambda service, region=None: MagicMock()
    s._get_scp_context = lambda: None
    return s


def _run(boundary, *, exposed=False):
    """One AI resource whose execution role can PassRole, under `boundary`.

    `exposed=True` gives a SageMaker notebook with direct internet egress, which is
    what makes AIPATH-01 reachable at all -- a Bedrock agent is network_checkable=False
    and has no egress leg, so testing the pair with one would assert nothing."""
    s = _scanner()
    res = {"kind": "BedrockAgent", "name": "support-bot",
           "arn": "arn:aws:bedrock:us-east-1:123456789012:agent/A1",
           "role_arn": ROLE, "network_checkable": False, "network": {},
           "data_bearing": False}
    if exposed:
        res = {"kind": "SageMakerNotebook", "name": "research-nb",
               "arn": "arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/nb",
               "role_arn": ROLE, "network_checkable": True,
               "network": {"direct_internet": True, "in_vpc": False},
               "data_bearing": False}
    s._aispm_resources = [res]
    prin = {"arn": ROLE, "name": "AIExecutionRole", "statements": PASSROLE_ALLOW}
    if boundary is not None:
        prin["boundary"] = boundary
    s._get_iam_principals = lambda: [prin]
    s._collect_aispm(aws_graph.SecurityGraph())
    return s.results


def _ids(results, status=None):
    return [r.check_id for r in results if status is None or r.status == status]


# ── Part A · the over-reporting fix ──────────────────────────────────────────
def test_without_a_boundary_the_conservative_verdict_is_unchanged():
    """Fail-open is the whole safety property: an account whose ceiling we cannot
    read must keep the old behaviour exactly."""
    assert "AISPM-01" in _ids(_run(None), "FAIL")


def test_a_boundary_that_denies_the_escalation_clears_the_finding():
    """THE FIX. The boundary is a ceiling: a role whose boundary never allows
    iam:PassRole cannot pass a role, whatever its identity policy says."""
    boundary = [{"effect": "Allow", "actions": {"s3:getobject"}, "resources": {"*"},
                 "not_resources": set(), "condition": None}]
    results = _run(boundary)
    assert "AISPM-01" not in _ids(results, "FAIL"), (
        "a boundary that provably neutralises every escalation route must clear "
        "AISPM-01 — this is the over-report that contradicted our own CIEM")


def test_an_explicit_deny_in_the_boundary_also_clears_it():
    boundary = [
        {"effect": "Allow", "actions": {"*"}, "resources": {"*"},
         "not_resources": set(), "condition": None},
        {"effect": "Deny", "actions": {"iam:passrole"}, "resources": {"*"},
         "not_resources": set(), "condition": None},
    ]
    assert "AISPM-01" not in _ids(_run(boundary), "FAIL")


def test_a_conditioned_boundary_downgrades_to_warn_rather_than_clearing():
    """Neither a clean pass nor a critical: escalation is possible *if* the Condition
    is met, and the operator is the one who knows whether it is."""
    boundary = [{"effect": "Allow", "actions": {"iam:passrole"}, "resources": {"*"},
                 "not_resources": set(),
                 "condition": {"StringEquals": {"aws:PrincipalTag/team": "ml"}}}]
    results = _run(boundary)
    assert "AISPM-01" not in _ids(results, "FAIL")
    warns = [r for r in results if r.check_id == "AISPM-01" and r.status == "WARN"]
    assert warns, "a Condition-gated escalation must still be surfaced"
    assert "Condition" in warns[0].message


def test_open_egress_plus_unconditioned_escalation_does_raise_the_pair():
    """The control for the test below. Without this, 'AIPATH-01 not raised' could be
    passing because the fixture can never raise it, which asserts nothing at all."""
    assert "AIPATH-01" in _ids(_run(None, exposed=True), "FAIL")


def test_a_conditioned_escalation_does_not_raise_the_conditional_pair():
    """AIPATH-01 asserts a role with real reach. A capability that exists
    only under a Condition is not that — and the test above proves this fixture WOULD
    have raised it, so the absence here is the fix and not the fixture."""
    boundary = [{"effect": "Allow", "actions": {"iam:passrole"}, "resources": {"*"},
                 "not_resources": set(),
                 "condition": {"StringEquals": {"aws:PrincipalTag/team": "ml"}}}]
    assert "AIPATH-01" not in _ids(_run(boundary, exposed=True), "FAIL")


def test_admin_star_on_star_is_not_cleared_by_capping_one_route():
    """A boundary that denies only iam:PassRole has not neutralised administrative
    access — every other escalation route must be tested before the capability is
    called gone. This is the dangerous over-prune, and it is why the classifier
    expands '*' rather than testing one synthetic action."""
    s = _scanner()
    admin = [{"effect": "Allow", "actions": {"*"}, "resources": {"*"},
              "not_resources": set(), "condition": None}]
    boundary = [
        {"effect": "Allow", "actions": {"*"}, "resources": {"*"},
         "not_resources": set(), "condition": None},
        {"effect": "Deny", "actions": {"iam:passrole"}, "resources": {"*"},
         "not_resources": set(), "condition": None},
    ]
    verdict, reason = aws_live_scanner.aws_aispm.role_privesc_effective(
        admin, boundary, None)
    assert verdict == aws_effperm.KEEP, (
        f"capping one route must not clear administrative access (got {verdict})")
    assert reason


def test_the_raw_signal_is_preserved_for_callers_without_a_ceiling():
    """role_privesc_capable is still the honest answer when no ceiling is known, and
    its wording must not drift — other checks quote it."""
    from engine import aws_aispm
    assert aws_aispm.role_privesc_capable(PASSROLE_ALLOW) == \
        "grants iam:passrole on an unscoped (*) resource"
    admin = [{"effect": "Allow", "actions": {"*"}, "resources": {"*"},
              "not_resources": set(), "condition": None}]
    assert aws_aispm.role_privesc_capable(admin) == \
        "grants * on * (full administrative access)"
    assert aws_aispm.role_privesc_capable([]) is None


def test_a_scoped_passrole_is_still_not_flagged():
    """The pre-existing conservative stance: a PassRole scoped to one role ARN is
    not an escalation primitive and never was."""
    from engine import aws_aispm
    scoped = [{"effect": "Allow", "actions": {"iam:passrole"},
               "resources": {"arn:aws:iam::123456789012:role/AppRole"},
               "not_resources": set(), "condition": None}]
    assert aws_aispm.role_privesc_capable(scoped) is None


def test_an_unreadable_org_fails_open_rather_than_clearing_findings():
    """_get_scp_context raising must never be the reason a finding disappears."""
    s = _scanner()
    s._get_scp_context = MagicMock(side_effect=Exception("organizations: AccessDenied"))
    s._aispm_resources = [{
        "kind": "BedrockAgent", "name": "bot", "arn": "arn:aws:bedrock:::agent/A",
        "role_arn": ROLE, "network_checkable": False, "network": {},
        "data_bearing": False}]
    s._get_iam_principals = lambda: [
        {"arn": ROLE, "name": "R", "statements": PASSROLE_ALLOW}]
    s._collect_aispm(aws_graph.SecurityGraph())
    assert "AISPM-01" in _ids(s.results, "FAIL")


# ── Part B · the epistemic class ─────────────────────────────────────────────
def test_every_class_is_one_of_the_four():
    for cid in ("S3-01", "CDR-01", "AISPM-01", "IAMPE-03", "NOPE-99"):
        assert aws_epistemics.classify(cid) in aws_epistemics.CLASSES


def test_ingested_runtime_evidence_is_observed_not_inferred():
    """The whole point: what a sensor reported and what we reasoned to are different
    kinds of claim, and fusing them without saying so is how certainty gets laundered."""
    assert aws_epistemics.classify("EDR-01") == aws_epistemics.OBSERVED
    assert aws_epistemics.classify("FORENSIC-00") == aws_epistemics.OBSERVED


def test_capability_verdicts_are_inferred():
    # AIPATH-01 was here and has been moved to the CONDITIONAL assertion below. Its
    # legs are inferred; the fusion rests on "assume a compromise lands", which is a
    # premise rather than a derivation.
    for cid in ("AISPM-01", "AISPM-02", "IAMPE-03", "CIEM-01"):
        assert aws_epistemics.classify(cid) == aws_epistemics.INFERRED, cid


def test_a_plain_config_read_defaults_to_configured():
    for cid in ("S3-01", "BDR-01", "AGT-03", "EC2-07"):
        assert aws_epistemics.classify(cid) == aws_epistemics.CONFIGURED, cid


def test_confidence_is_ordered_observation_over_assumption():
    c = aws_epistemics.confidence
    assert c("EDR-01") >= c("AISPM-01") > aws_epistemics.CONFIDENCE[
        aws_epistemics.CONDITIONAL]


def test_the_conditional_class_is_enforceable_before_its_first_member():
    """Phase 3's toxic flow lands in this class. Defining it now is what stops the
    first such finding shipping mislabelled as an observation."""
    assert aws_epistemics.CONDITIONAL in aws_epistemics.CLASSES
    assert aws_epistemics.CONDITIONAL in aws_epistemics.CONFIDENCE
    assert "capability, not occurrence" in aws_epistemics.describe("AISPM-01").lower() \
        or aws_epistemics.classify("AISPM-01") != aws_epistemics.CONDITIONAL


def _shipped_check_ids():
    """Every check id OverWatch actually emits.

    NOT `CHECK_SEVERITY` — that dict holds only the ids the live scanner scores, and
    real ids live outside it too (CIEM- in aws_unused.py, FORENSIC- in
    aws_forensics.py, EDR- in cnapp_service.py). A drift guard anchored on the
    smaller set fires on correct entries, which is how a guard gets deleted."""
    import re
    ids = set()
    # module_files() walks all three layers. The previous glob was
    # glob(ROOT, "*.py"), which does not recurse -- after the engine/hub/store
    # split it matched nothing, `ids` came back empty, and every explicitly
    # named check id read as dead.
    for f in module_files():
        src = open(f, encoding="utf-8", errors="replace").read()
        ids.update(re.findall(r'"([A-Z][A-Z0-9]*-\d{2,})"', src))
    assert ids, "no check ids found at all -- the sweep is broken, not the codebase"
    return ids


def test_every_explicitly_named_check_id_actually_exists():
    """Drift guard: a renamed check must not leave a dead entry silently
    reclassifying nothing."""
    known = _shipped_check_ids()
    unknown = {c for c in aws_epistemics.explicit_ids() if c not in known}
    assert not unknown, (
        f"epistemics names check ids that no longer exist: {sorted(unknown)}")


def test_every_named_prefix_matches_at_least_one_real_check():
    """This is the assertion that caught a prefix invented from memory rather than
    read from the code. Keep it."""
    known = _shipped_check_ids()
    dead = [p for p in aws_epistemics.explicit_prefixes()
            if not any(k.startswith(p) for k in known)]
    assert not dead, f"epistemics names prefixes that match no check: {dead}"


def test_describe_returns_a_sentence_for_every_class():
    for cid in ("CDR-01", "S3-01", "AISPM-01"):
        text = aws_epistemics.describe(cid)
        assert text and text[0].isupper() and text.rstrip().endswith(".")
