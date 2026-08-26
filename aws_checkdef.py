#!/usr/bin/env python3
"""aws_checkdef.py — declare a check ONCE, derive every map from it.

A new check currently costs edits in five places: ``CHECK_SEVERITY``,
``COMPLIANCE_MAP`` and ``REMEDIATION_MAP`` in ``aws_live_scanner``, ``FINDING_DETAIL``
in ``aws_finding_detail``, and ``REQUIREMENTS`` in ``aws_perm_ledger``. At the 385-check
mark that was tolerable. With 110 uncovered services still to go it is the dominant cost
of adding coverage, and — worse — it is five chances to get one check half-declared.

The existing ``test_check_maps_lockstep`` catches a half-declared check, and it is a good
test. But it catches it *afterwards*. A ``CheckDef`` cannot be constructed at all unless
every projection is present and well-formed, which moves the same invariant from
test-time to definition-time: the failure mode stops being "someone forgot the detail
page" and becomes "this does not import".

WHAT THIS DOES NOT DO
----------------------
It does **not** migrate the 399 existing checks. Rewriting nearly four hundred hand-
authored entries to prove a point would be a large, risky diff with no behavioural
benefit, and the literals are perfectly readable where they are. This is a *second*,
additive path that new checks use; the old literals keep working untouched.

THE COLLISION GUARD IS THE POINT
---------------------------------
Merging by ``dict.update`` bypasses the duplicate-key ratchet, which parses dict
*literals* as source and therefore cannot see a registry merge. So ``merge_*`` refuses to
overwrite an id that already exists in the target map. That is the SEG-01 defect —
a new check silently replacing a real one's remediation, with nothing failing anywhere —
caught structurally rather than by a test that happened to be written.

Pure. No boto3, no network, no I/O, and no import of the modules it feeds.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Mapping, Sequence, Tuple

__all__ = [
    "CheckDef", "Perm", "REGISTRY", "register", "reset",
    "severities", "compliance", "remediation", "detail", "permissions",
    "merge_maps", "merge_detail", "merge_requirements",
    "SEVERITIES", "FRAMEWORKS", "READ_VERBS",
]

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: Every check carries all four, because the evidence pack's denominator counts
#: controls rather than findings — a missing framework silently shrinks it.
FRAMEWORKS = ("PCI-DSS", "HIPAA", "SOC2", "NIST")

#: The charter is read-only-of-CONFIG. A declaration naming any other verb is a
#: charter violation, so it is rejected here rather than reviewed later.
READ_VERBS = ("Describe", "Get", "List", "BatchGet", "Lookup", "Select", "Search")


@dataclass(frozen=True)
class Perm:
    """One IAM action a check needs, and why. The justification is not decoration:
    declining a grant has to name what it costs, and a reason nobody can read is a
    permission nobody can refuse on the merits."""
    action: str
    why: str

    def __post_init__(self):
        if ":" not in self.action:
            raise ValueError(f"{self.action}: not a service-qualified IAM action")
        verb = self.action.split(":", 1)[1]
        if not verb.startswith(READ_VERBS):
            raise ValueError(
                f"{self.action}: not a read verb. OverWatch is read-only-of-CONFIG; "
                f"a declaration naming a write action is a charter violation")
        if len(self.why) < 31:
            raise ValueError(
                f"{self.action}: justification is {len(self.why)} chars. Say what the "
                f"read buys and what declining it costs — the ledger is read by someone "
                f"deciding whether to grant it")


@dataclass(frozen=True)
class CheckDef:
    """One check, declared once.

    Construction validates every projection, so a half-declared check cannot exist.
    The alternative — five separate literals and a test that notices later — is how
    a check ends up scoring without anything that explains or fixes it."""
    id: str
    section: str
    severity: str
    compliance: Mapping[str, str]
    remediation: str
    risk: str
    impact: str
    steps: Tuple[str, ...]
    permissions: Tuple[Perm, ...] = ()

    def __post_init__(self):
        if not self.id or "-" not in self.id:
            raise ValueError(f"{self.id!r}: a check id looks like PREFIX-NN")
        if self.severity not in SEVERITIES:
            raise ValueError(f"{self.id}: severity {self.severity!r} not in {SEVERITIES}")
        missing = [f for f in FRAMEWORKS if not self.compliance.get(f)]
        if missing:
            raise ValueError(
                f"{self.id}: compliance missing {missing}. All four are required — the "
                f"evidence pack counts controls, so a gap silently shrinks a denominator")
        if "aws " not in self.remediation:
            raise ValueError(
                f"{self.id}: remediation carries no runnable aws CLI command. Advice an "
                f"operator cannot execute is not remediation")
        if len(self.risk) < 200:
            raise ValueError(
                f"{self.id}: risk is {len(self.risk)} chars. The detail page is what a "
                f"reviewer reads to decide whether the finding is real; a sentence is "
                f"not enough to make that call")
        if not self.impact:
            raise ValueError(f"{self.id}: impact is empty")
        if len(self.steps) < 2:
            raise ValueError(
                f"{self.id}: give at least two remediation steps — a single step is "
                f"almost always missing the verification that follows it")

    # ── projections ─────────────────────────────────────────────────────────
    def as_detail(self) -> dict:
        return {"risk": self.risk, "impact": self.impact, "steps": list(self.steps)}


#: id -> CheckDef. Ordered by declaration, which keeps generated maps readable.
REGISTRY: Dict[str, CheckDef] = {}


def register(*defs: CheckDef) -> Tuple[CheckDef, ...]:
    """Add checks to the registry, rejecting a duplicate id outright.

    A duplicate id is the SEG-01 defect: Python dict literals accept one silently and
    the last wins, so a new check can replace a real one's remediation with nothing
    failing anywhere. Here it is a hard error at import."""
    for d in defs:
        if not isinstance(d, CheckDef):
            raise TypeError(f"register() takes CheckDef, got {type(d).__name__}")
        if d.id in REGISTRY:
            raise ValueError(
                f"{d.id}: already registered. Pick a free id — a duplicate silently "
                f"overwrites the earlier check everywhere it is merged")
        REGISTRY[d.id] = d
    return defs


def reset() -> Dict[str, CheckDef]:
    """Clear the registry and RETURN what was in it, so a caller can put it back.

    Tests only, and handle the return value. The registry is module-global and modules
    register at import — which happens once per session — so clearing it without
    restoring wipes every real registration for the rest of the run. That is not
    hypothetical: an autouse fixture did exactly this and took eleven batch-2 tests with
    it, all of which passed in isolation."""
    saved = dict(REGISTRY)
    REGISTRY.clear()
    return saved


# ── projections over the whole registry ─────────────────────────────────────
def severities() -> Dict[str, str]:
    return {k: v.severity for k, v in REGISTRY.items()}


def compliance() -> Dict[str, Dict[str, str]]:
    return {k: dict(v.compliance) for k, v in REGISTRY.items()}


def remediation() -> Dict[str, str]:
    return {k: v.remediation for k, v in REGISTRY.items()}


def detail() -> Dict[str, dict]:
    return {k: v.as_detail() for k, v in REGISTRY.items()}


def permissions() -> Dict[str, Tuple[Perm, ...]]:
    return {k: v.permissions for k, v in REGISTRY.items() if v.permissions}


# ── merges, each refusing to shadow an existing entry ────────────────────────
def _merge(target: dict, source: Mapping, what: str) -> None:
    clash = sorted(set(target) & set(source))
    if clash:
        raise ValueError(
            f"registered check id(s) {clash} already exist in {what}. A registry merge "
            f"bypasses the duplicate-key ratchet, which only sees dict literals — so "
            f"the collision is refused here instead")
    target.update(source)


def merge_maps(check_severity: dict, compliance_map: dict,
               remediation_map: dict) -> None:
    """Project the registry into aws_live_scanner's three maps."""
    _merge(check_severity, severities(), "CHECK_SEVERITY")
    _merge(compliance_map, compliance(), "COMPLIANCE_MAP")
    _merge(remediation_map, remediation(), "REMEDIATION_MAP")


def merge_detail(finding_detail: dict) -> None:
    _merge(finding_detail, detail(), "FINDING_DETAIL")


def merge_requirements(requirements: dict, factory) -> None:
    """Project into aws_perm_ledger's REQUIREMENTS.

    ``factory(action, why)`` builds that module's Requirement, so this module stays
    free of any import of the modules it feeds."""
    built = {k: tuple(factory(p.action, p.why) for p in perms)
             for k, perms in permissions().items()}
    _merge(requirements, built, "REQUIREMENTS")
