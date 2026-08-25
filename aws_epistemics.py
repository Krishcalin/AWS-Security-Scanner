#!/usr/bin/env python3
"""aws_epistemics.py — how much OverWatch actually KNOWS about a finding.

The scoring engine is already open about *how it weights* a finding: every path
score prints its own factor decomposition. It is silent about a different question,
and the AI era makes that silence expensive — **how was this known?**

Four checks can carry identical severity and rest on completely different evidence:

* a GuardDuty detection means a third party *watched something happen*;
* a KMS-encryption check means *an API returned a value*;
* an escalation-capability verdict means *we reasoned over policy documents*;
* a toxic-flow path means *we assumed a prompt injection lands, and traced it*.

Averaging those into one number is how a product ends up asserting an incident when
it computed a possibility. Naming the class is what lets ingested runtime evidence
sit on the same graph as static configuration without either one borrowing the
other's certainty — and it is the direct antidote to shipping a false sense of
safety, because a reader can see which findings are claims about the world and which
are claims about a configuration.

Pure, boto3-free, no I/O. The classification is a property of the CHECK, not of any
particular result, so it is a static table.

DELIBERATELY NOT WIRED INTO SCORING. :data:`CONFIDENCE` exists and is tested, but
``compute_risk_score`` is untouched: changing severity weights is a scoring change
that needs its own regression baseline and its own conversation with anyone whose
dashboards move. This module makes the fact available; a later slice may spend it.
"""
from __future__ import annotations

from typing import Dict, Optional

# ── the four classes ─────────────────────────────────────────────────────────
OBSERVED = "observed"
"""Someone watched it happen. Ingested runtime evidence — a GuardDuty finding, an
EDR detection, a CloudTrail event. OverWatch did not derive this; it received it."""

CONFIGURED = "configured"
"""An API returned this value. The check asserts something about a configuration we
read directly, and the only way it is wrong is if the API lied or we misread it."""

INFERRED = "inferred"
"""We reasoned to it. Policy evaluation, graph reachability, capability analysis —
correct given complete inputs, and our inputs are never guaranteed complete."""

CONDITIONAL = "conditional-on-assumption"
"""True only if a stated assumption holds. A toxic flow assumes the injection lands;
it proves CAPABILITY, never OCCURRENCE. A finding in this class must never be
rendered in language that implies something happened."""

CLASSES = (OBSERVED, CONFIGURED, INFERRED, CONDITIONAL)

# Relative confidence, for a future scoring slice. Ordered, not calibrated: the only
# claim made here is that an observation outranks an inference, and an inference
# outranks something that is true only under an assumption.
CONFIDENCE: Dict[str, float] = {
    OBSERVED: 1.0,
    CONFIGURED: 1.0,
    INFERRED: 0.85,
    CONDITIONAL: 0.6,
}

# ── the table ────────────────────────────────────────────────────────────────
# Only DEPARTURES from the default are listed. The default is CONFIGURED because the
# overwhelming majority of checks read a value from a describe/list call and assert
# something about it; enumerating those would be a 250-row table nobody maintains.
#
# A check earns an entry here when its truth does not come from a single API read.

_OBSERVED_PREFIXES = (
    "EDR-",      # ingested runtime sensor detections (CrowdStrike / Falco / OCSF)
    "FORENSIC-", # timeline reconstructed from CloudTrail — a record of what happened
)

# NB: cloud detections from GuardDuty / Security Hub / CloudTrail do NOT appear here,
# because they do not carry check ids at all — they arrive as NormalizedDetection
# objects with a `source` and `type` (see aws_cdr.py). They are OBSERVED by
# construction: nothing derives them, they are received. The classification therefore
# belongs at their own boundary, not in this id table, and inventing a "CDR-" prefix
# to hold them here would have been a table entry describing nothing.

_INFERRED_IDS = frozenset({
    # AI-SPM: capability verdicts reasoned over policy + graph, not read from an API.
    "AISPM-01",   # escalation capability, ceiling-aware but still a judgement
    "AISPM-02",   # crown-data reach, via CAN_READ_DATA edges we derived
})

_INFERRED_PREFIXES = (
    "IAMPE-",     # IAM privilege-escalation paths — policy reasoning
    "CIEM-",      # effective-permission analysis
    "ATTACK-",    # attack-path correlation
    "KIEM-",      # cross-plane K8s->AWS entitlement reasoning
)

_CONDITIONAL_IDS = frozenset({
    "AIPATH-01",  # "assume a compromise lands" — a premise, not a derivation
})
"""Findings that hold only if a stated assumption does.

AIPATH-01 is the first member, and it arrived by correction rather than by design.
It sat in _INFERRED_IDS, which was half right: both of its legs ARE inferred — an
escalation verdict reasoned over policy, a crown-data reach read off CAN_READ_DATA
edges. What is not inferred is the thing that JOINS them. Nothing OverWatch reads
says the resource can be reached; the fusion assumes a compromise lands and traces
what follows. That is a premise, and a premise makes the finding conditional however
sound the reasoning downstream of it is.

This constant existed before its first member on the theory that the class must be
enforceable before the first finding needs it, or that finding ships mislabelled.
The theory was right and the timing was not: AIPATH-01 already existed, already
rested on a premise, and shipped mislabelled anyway — because the class was written
for Phase 3's toxic flow and nobody re-read the checks already on the books against
it. Adding a category does not reclassify what came before it."""


def classify(check_id: str) -> str:
    """The epistemic class of a check id. Unknown ids resolve to CONFIGURED, which is
    both the common case and the safe default: it claims we read a value, which is the
    weakest of the three positive claims and the easiest to falsify."""
    cid = (check_id or "").upper()
    if cid in _CONDITIONAL_IDS:
        return CONDITIONAL
    if cid in _INFERRED_IDS:
        return INFERRED
    if cid.startswith(_OBSERVED_PREFIXES):
        return OBSERVED
    if cid.startswith(_INFERRED_PREFIXES):
        return INFERRED
    return CONFIGURED


def confidence(check_id: str) -> float:
    """Relative confidence in a check's class. See the note on CONFIDENCE."""
    return CONFIDENCE[classify(check_id)]


def describe(check_id: str) -> str:
    """One line a console can render next to a finding, explaining how it is known."""
    return {
        OBSERVED: "Observed — a runtime source reported this happening.",
        CONFIGURED: "Configured — read directly from the resource's configuration.",
        INFERRED: "Inferred — derived by analysing policy and graph reachability.",
        CONDITIONAL: ("Conditional — true if the stated assumption holds. "
                      "Demonstrates capability, not occurrence."),
    }[classify(check_id)]


def explicit_ids() -> frozenset:
    """Every check id named explicitly in this module — the drift-guard surface."""
    return _INFERRED_IDS | _CONDITIONAL_IDS


def explicit_prefixes() -> tuple:
    return _OBSERVED_PREFIXES + _INFERRED_PREFIXES
