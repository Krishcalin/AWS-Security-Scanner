"""Phase 0 · slice 0.6 — ONE lockstep for every check, with a ratchet.

Before this, coverage of the three metadata maps was guarded per phase:
`test_phase7_maps_lockstep` named four check ids, `test_phase8_maps_lockstep` named
four more, and anything nobody wrote a phase test for was simply unguarded. That is
how `BDR-01..05` and `AGT-01..05` came to sit in CHECK_SEVERITY — penalising the
posture score — while mapping to no framework, rendering an empty console detail
panel, carrying no remediation command, and reducing the copilot's corpus entry for
a Bedrock finding to the literal string 'BDR-02 BEDROCK HIGH FAIL bedrock'.

The fix is not another list of ids to remember. It is coverage BY DEFAULT plus one
visible backlog that can only shrink:

  * every check must appear in all three maps,
  * except the ids frozen below, which are today's known gaps,
  * and a NEW gap can never be added, because a missing check that is not already in
    the frozen set fails the build.

These lists are GENERATED from the runtime dicts, not typed and not read out of the
source text — IAMPE-* compliance mappings are populated at import time from the
privesc technique table and never appear as literal keys, so a source-text baseline
disagrees with reality by 19 entries. To shrink a backlog, fill the maps for a check
and delete its id; `test_no_backlog_entry_is_already_fixed` names the ids that have
become redundant, so the lists cannot quietly rot into fiction.

NB: the per-phase tests in test_live_scanner.py are now strictly subsumed by these.
They are left in place because they also document which checks belong to which phase,
and deleting passing tests is a separate decision from adding this one.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_finding_detail
from aws_live_scanner import CHECK_SEVERITY, COMPLIANCE_MAP, REMEDIATION_MAP

DETAIL_MAP = aws_finding_detail.FINDING_DETAIL

# Frameworks a compliance mapping may key on. A stray key here silently drops a
# control from the crosswalk, which derives 34 further frameworks from the NIST spine.
ALLOWED_FRAMEWORKS = {"CIS", "PCI-DSS", "HIPAA", "SOC2", "NIST"}

# ── the frozen backlog — now EMPTY, and it can only stay that way ───────────
# Depth pass 2 filled the last of it. These stay as (empty) frozensets rather than
# being deleted with the tests that read them, because the ratchet below is what
# keeps them empty: a check added without its metadata now fails immediately with
# nothing to grandfather it. Do not repopulate these to make a build pass.
BACKLOG_COMPLIANCE: frozenset = frozenset()

BACKLOG_REMEDIATION: frozenset = frozenset()

BACKLOG_DETAIL: frozenset = frozenset()


def _missing(target):
    return {c for c in CHECK_SEVERITY if c not in target}


# ── the ratchet: coverage by default, no NEW gaps ───────────────────────────
@pytest.mark.parametrize("label,target,backlog", [
    ("COMPLIANCE_MAP", COMPLIANCE_MAP, BACKLOG_COMPLIANCE),
    ("REMEDIATION_MAP", REMEDIATION_MAP, BACKLOG_REMEDIATION),
    ("FINDING_DETAIL", DETAIL_MAP, BACKLOG_DETAIL),
])
def test_no_new_check_may_join_the_backlog(label, target, backlog):
    """THE RATCHET. A check absent from a map is only tolerated if it was already
    absent when this baseline was frozen. Add a check and forget its metadata and
    this fails — which is the whole point, because the failure mode it replaces was
    silent: a finding that scores, renders blank, and offers no fix."""
    new = sorted(_missing(target) - backlog)
    assert not new, (
        f"{len(new)} check(s) missing from {label} and not in the frozen backlog: "
        f"{new}. Add a compliance mapping, a remediation command and a detail entry "
        f"— a check that scores but cannot be explained or fixed is worse than no "
        f"check at all.")


@pytest.mark.parametrize("label,target,backlog", [
    ("COMPLIANCE_MAP", COMPLIANCE_MAP, BACKLOG_COMPLIANCE),
    ("REMEDIATION_MAP", REMEDIATION_MAP, BACKLOG_REMEDIATION),
    ("FINDING_DETAIL", DETAIL_MAP, BACKLOG_DETAIL),
])
def test_no_backlog_entry_is_already_fixed(label, target, backlog):
    """Keeps the backlog honest. An id that has since been filled must be deleted
    from the frozen list, or the list drifts into fiction and stops meaning anything."""
    fixed = sorted(backlog - _missing(target))
    assert not fixed, (
        f"{len(fixed)} id(s) in the {label} backlog are now covered and should be "
        f"deleted from the frozen list: {fixed}")


def test_the_backlog_is_empty_and_stays_that_way():
    """The ratchet's terminal state. Depth pass 2 filled the last grandfathered gap,
    so there is nothing left to tolerate: every check in CHECK_SEVERITY now has a
    compliance mapping, a remediation command and a detail page.

    This test exists because the easy way to make the ratchet above pass is to add the
    failing id back to a backlog, which converts a hard failure into a silent one. That
    is the exact regression the backlog was introduced to end, so re-populating these
    sets is a deliberate act that has to fail here first."""
    populated = {name: sorted(b) for name, b in
                 (("BACKLOG_COMPLIANCE", BACKLOG_COMPLIANCE),
                  ("BACKLOG_REMEDIATION", BACKLOG_REMEDIATION),
                  ("BACKLOG_DETAIL", BACKLOG_DETAIL)) if b}
    assert not populated, (
        f"the frozen backlog was re-populated: {populated}. It is shrink-only and it "
        f"reached zero -- a check missing its metadata must be given the metadata, not "
        f"grandfathered back in.")


@pytest.mark.parametrize("backlog", [BACKLOG_COMPLIANCE, BACKLOG_REMEDIATION,
                                     BACKLOG_DETAIL])
def test_no_backlog_entry_names_a_check_that_no_longer_exists(backlog):
    dead = sorted(c for c in backlog if c not in CHECK_SEVERITY)
    assert not dead, f"backlog names checks that no longer exist: {dead}"


# ── shape of what IS mapped ─────────────────────────────────────────────────
def test_compliance_keys_are_confined_to_the_allowed_frameworks():
    bad = {c: sorted(set(v) - ALLOWED_FRAMEWORKS)
           for c, v in COMPLIANCE_MAP.items() if set(v) - ALLOWED_FRAMEWORKS}
    assert not bad, f"compliance mappings use unknown framework keys: {bad}"


# Command prefixes that count as runnable. `aws` covers almost everything; `kubectl`
# is here because the KSPM/KIEM checks fix Kubernetes objects that no AWS API can
# touch -- automountServiceAccountToken has no aws-CLI form, and inventing one would
# be worse than the prose this test exists to reject.
RUNNABLE_PREFIXES = ("aws ", "kubectl ")


def test_every_remediation_carries_a_runnable_command():
    """Prose is not remediation. The console offers this as a copyable one-liner."""
    prose = sorted(c for c, v in REMEDIATION_MAP.items()
                   if not any(p in (v or "").lower() for p in RUNNABLE_PREFIXES))
    assert not prose, f"remediation entries with no CLI command: {prose}"


def test_every_detail_entry_has_risk_impact_and_steps():
    incomplete = sorted(
        c for c, v in DETAIL_MAP.items()
        if not (v.get("risk") and v.get("impact") and v.get("steps")))
    assert not incomplete, f"detail entries missing risk/impact/steps: {incomplete}"


def test_detail_steps_are_a_non_empty_list_of_strings():
    bad = sorted(c for c, v in DETAIL_MAP.items()
                 if not isinstance(v.get("steps"), list) or not v["steps"]
                 or not all(isinstance(x, str) and x.strip() for x in v["steps"]))
    assert not bad, f"detail entries with malformed steps: {bad}"


# ── the specific regression this slice was written for ──────────────────────
AI_CHECKS = tuple(f"{p}-0{i}" for p in ("BDR", "AGT") for i in range(1, 6))


def test_the_ai_pillar_is_fully_mapped():
    """BDR-01..05 and AGT-01..05 were the ten orphans. They must never return to any
    backlog, and no future AI check may join one."""
    for cid in AI_CHECKS:
        assert cid in CHECK_SEVERITY, f"{cid} vanished from CHECK_SEVERITY"
        assert cid in COMPLIANCE_MAP, f"{cid} has no compliance mapping"
        assert cid in REMEDIATION_MAP, f"{cid} has no remediation command"
        assert cid in DETAIL_MAP, f"{cid} has no console detail entry"
        assert cid not in BACKLOG_COMPLIANCE and cid not in BACKLOG_REMEDIATION \
            and cid not in BACKLOG_DETAIL, f"{cid} must not be back in a backlog"


def test_ai_compliance_mappings_stay_inside_the_frozen_nist_universe():
    """The crosswalk derives 34 frameworks from a frozen 38-control NIST spine, and
    its CI validator asserts the file's universe equals the set used here. A NIST
    control outside the 38 (SI-10 is the tempting one for a guardrail) breaks that."""
    import json
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "compliance", "crosswalk.json")
    universe = set(json.load(open(path, encoding="utf-8"))["nist_universe"])
    for cid in AI_CHECKS:
        nist = COMPLIANCE_MAP[cid].get("NIST")
        assert nist in universe, (
            f"{cid} maps to NIST {nist}, which is outside the frozen 38-control "
            f"universe — this breaks the crosswalk accuracy validator")
