#!/usr/bin/env python3
"""aws_ztmm.py — Phase 5 · slice 5.1: CISA ZTMM v2 scoring, with its work shown.

"Zero Trust CNAPP" is not a build and no analyst market exists by that name. What is real
is scoring an AWS estate against **CISA Zero Trust Maturity Model v2.0** *from
configuration alone*, and showing the evidence behind every pillar score.

THE STRUCTURE, VERIFIED RATHER THAN ASSUMED
--------------------------------------------
Five pillars, four maturity stages, and three cross-cutting capabilities that appear as
**functions within every pillar**. The function counts are **not uniform**, and that
matters more than it sounds:

===========================  =========
pillar                       functions
===========================  =========
Identity                             7
Devices                              7
Networks                             7
Applications and Workloads           8
Data                                 8
**total**                       **37**
===========================  =========

The obvious inference — five pillars times seven — gives 35 and is wrong. Applications
and Data each carry a fifth pillar-specific function. A scorer built on the assumption
would under-count two pillars' denominators and report better coverage than it has, which
is exactly the failure slice `4.5` shipped and had to correct: reporting *"12 of 12"* for
a 72-control framework because it used its own reach as the denominator.

THE DEVICES PROBLEM, STATED RATHER THAN AVERAGED AWAY
------------------------------------------------------
The Devices pillar is endpoint management — device inventory, compliance monitoring,
device threat detection, resource access from a *device*. An agentless AWS configuration
scanner can say almost nothing about it, and OverWatch's charter forbids the agent that
could. That is not a gap to be closed later; it is a structural limit of this vantage
point.

So this module will **never** average a Devices score into an overall number, and there
is deliberately **no overall ZTMM score at all**. An estate that is Advanced on four
pillars and unscoreable on one does not have a maturity level — it has four maturity
levels and a blind spot, and the single number that hides which is the number every
competing product prints.

WHAT A SCORE MEANS HERE
------------------------
A function scores at the **highest stage every one of its mapped checks supports**, and
`UNSCORED` when nothing maps to it. A function with one failing check has not reached the
stage that check evidences — the same rule `4.5` applies at control level. And the stage
is reported alongside the checks that produced it, because the roadmap's own framing is
that *the differentiator is the evidence, not the label*.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

from typing import Dict, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "STAGES", "TRADITIONAL", "INITIAL", "ADVANCED", "OPTIMAL", "UNSCORED",
    "PILLARS", "FUNCTIONS", "CROSS_CUTTING", "TOTAL_FUNCTIONS",
    "SOURCE", "SOURCE_DATE",
    "score_function", "score_pillar", "score_estate", "describe_pillar",
    "ZTMM_MAPPING",
    "AGENTLESS_BLIND", "stage_rank",
]

SOURCE = "CISA Zero Trust Maturity Model v2.0 (April 2023)"
SOURCE_DATE = "2026-08-25"

#: The four stages, weakest first. TRADITIONAL is the baseline the model describes as
#: the starting point rather than an achievement.
TRADITIONAL = "Traditional"
INITIAL = "Initial"
ADVANCED = "Advanced"
OPTIMAL = "Optimal"
#: Not a stage. A function nothing maps to was NOT ASSESSED, and calling that
#: "Traditional" would turn our own blind spot into a finding about the customer.
UNSCORED = "Unscored"

STAGES: Tuple[str, ...] = (TRADITIONAL, INITIAL, ADVANCED, OPTIMAL)
_RANK = {TRADITIONAL: 0, INITIAL: 1, ADVANCED: 2, OPTIMAL: 3}

PILLARS: Tuple[str, ...] = (
    "Identity", "Devices", "Networks", "Applications and Workloads", "Data",
)

#: The three capabilities that appear as a function inside EVERY pillar.
CROSS_CUTTING: Tuple[str, ...] = (
    "Visibility and analytics", "Automation and orchestration", "Governance",
)

#: Every function, verbatim, per pillar. Read off the model rather than inferred: the
#: last two pillars have five pillar-specific functions where the first three have four.
FUNCTIONS: Dict[str, Tuple[str, ...]] = {
    "Identity": (
        "Authentication", "Identity stores", "Risk assessments", "Access management",
    ) + CROSS_CUTTING,
    "Devices": (
        "Policy enforcement and compliance monitoring",
        "Asset and supply-chain risk management",
        "Resource access", "Device threat detection",
    ) + CROSS_CUTTING,
    "Networks": (
        "Network segmentation", "Network traffic management", "Traffic encryption",
        "Network resilience",
    ) + CROSS_CUTTING,
    "Applications and Workloads": (
        "Application access", "Application threat protections", "Accessible applications",
        "Secure application development and deployment workflow",
        "Application security testing",
    ) + CROSS_CUTTING,
    "Data": (
        "Data inventory management", "Data categorization", "Data availability",
        "Data access", "Data encryption",
    ) + CROSS_CUTTING,
}

TOTAL_FUNCTIONS = sum(len(f) for f in FUNCTIONS.values())

#: Functions an agentless configuration scan cannot evidence from AWS APIs, and why.
#: Named individually rather than by pillar, because "Devices is unscoreable" is too
#: coarse: 2.2 and 2.3 have real AWS-side signal (asset inventory, resource access via
#: IAM) while 2.1 and 2.4 need something running ON the endpoint.
AGENTLESS_BLIND: Dict[Tuple[str, str], str] = {
    ("Devices", "Policy enforcement and compliance monitoring"):
        "requires an endpoint management plane (MDM/Intune-equivalent); no AWS "
        "configuration API reports whether a laptop is compliant",
    ("Devices", "Device threat detection"):
        "requires an endpoint agent, which this product's charter excludes",
    ("Devices", "Visibility and analytics"):
        "endpoint telemetry, not cloud configuration",
    ("Devices", "Automation and orchestration"):
        "device lifecycle automation happens in an MDM, not in AWS",
    ("Devices", "Governance"):
        "device procurement and lifecycle policy is an organizational artefact "
        "outside any cloud API",
    ("Data", "Data categorization"):
        "labelling and classification of file CONTENT; OverWatch classifies data "
        "STORES from configuration and never reads objects (see D8)",
}


def stage_rank(stage: Optional[str]) -> int:
    """Order for comparison. UNSCORED is deliberately NOT ranked below Traditional —
    it is not on the scale at all, and callers must handle it explicitly."""
    return _RANK.get(stage or "", -1)


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


def score_function(pillar: str, function: str,
                   mapping: Optional[Mapping],
                   results: Optional[Sequence],
                   not_evaluated: Optional[Mapping] = None) -> dict:
    """One function's stage, and the evidence for it.

    ``mapping`` is ``{(pillar, function): {stage: [check_id, ...]}}`` — the checks whose
    PASSING evidences that stage.

    A function reaches a stage only when **every** check mapped to that stage passed. One
    failing check means the stage is not evidenced: a maturity claim built from a
    majority of passing checks is a claim about the average, not about the estate."""
    key = (pillar, function)
    per_stage = _d(_d(mapping).get(key))
    blind = AGENTLESS_BLIND.get(key)

    if not per_stage:
        return {
            "pillar": pillar, "function": function, "stage": UNSCORED,
            "why": (f"no OverWatch check maps to this function — it was NOT assessed"
                    + (f"; {blind}" if blind else "")),
            "blind_spot": blind or "",
            "evidence": {}, "failing": [], "blocked": [],
        }

    by_check: Dict[str, str] = {}
    for res in (results or []):
        cid = getattr(res, "check_id", None)
        status = getattr(res, "status", "")
        if status not in ("PASS", "FAIL", "WARN"):
            continue
        prev = by_check.get(cid)
        by_check[cid] = "FAIL" if "FAIL" in (status, prev) else status

    ne = _d(not_evaluated)
    evidence: Dict[str, dict] = {}
    failing: List[str] = []
    blocked: List[str] = []
    reached = None

    for stage in STAGES:
        checks = [c for c in (per_stage.get(stage) or [])]
        if not checks:
            continue
        ran = [c for c in checks if c in by_check]
        bad = [c for c in checks if by_check.get(c) == "FAIL"]
        miss = [c for c in checks if c in ne]
        evidence[stage] = {"checks": sorted(checks), "ran": sorted(ran),
                           "failing": sorted(bad), "blocked": sorted(miss)}
        failing.extend(bad)
        blocked.extend(miss)
        # The stage is evidenced only if every mapped check ran AND none failed.
        if ran and not bad and len(ran) == len(checks):
            reached = stage
        else:
            break               # stages are cumulative; a gap stops the climb

    return {
        "pillar": pillar, "function": function,
        "stage": reached if reached else (UNSCORED if not by_check else TRADITIONAL),
        "why": _why(reached, failing, blocked),
        "blind_spot": blind or "",
        "evidence": evidence,
        "failing": sorted(set(failing)), "blocked": sorted(set(blocked)),
    }


def _why(reached, failing, blocked) -> str:
    if reached is None and blocked:
        return ("no stage could be evidenced: the checks that would establish one could "
                "not be evaluated in this scan — an absence of evidence, not a "
                "Traditional posture")
    if reached is None:
        return ("no stage evidenced; the checks mapped to Initial did not all pass, "
                "which is the model's Traditional baseline rather than a finding")
    if failing:
        return (f"reached {reached}; the next stage is not evidenced because "
                f"{len(set(failing))} mapped check(s) failed")
    return f"reached {reached}: every check mapped to that stage ran and passed"


def score_pillar(pillar: str, mapping: Optional[Mapping],
                 results: Optional[Sequence],
                 not_evaluated: Optional[Mapping] = None) -> dict:
    """A pillar's functions, and the honest summary across them.

    The pillar stage is the **weakest** scored function, not the average. Zero trust is a
    chain: an estate with Optimal authentication and Traditional access management is not
    Advanced, and averaging is how a scorer flatters an estate into a number nobody can
    act on. Unscored functions are excluded from the minimum and counted separately —
    they cannot drag a score down, and they must not silently prop one up either."""
    rows = [score_function(pillar, fn, mapping, results, not_evaluated)
            for fn in FUNCTIONS.get(pillar, ())]
    scored = [r for r in rows if r["stage"] != UNSCORED]
    unscored = [r for r in rows if r["stage"] == UNSCORED]
    weakest = None
    if scored:
        weakest = min(scored, key=lambda r: stage_rank(r["stage"]))["stage"]
    return {
        "pillar": pillar,
        "stage": weakest or UNSCORED,
        "functions_total": len(rows),
        "functions_scored": len(scored),
        "functions_unscored": len(unscored),
        "unscored_names": [r["function"] for r in unscored],
        "rows": rows,
        "statement": describe_pillar(pillar, weakest, len(scored), len(rows), unscored),
    }


def describe_pillar(pillar, stage, scored, total, unscored) -> str:
    if not scored:
        names = ", ".join(r["function"] for r in (unscored or []))
        return (f"{pillar}: NOT SCORED. None of its {total} function(s) is evidenced by "
                f"an OverWatch check ({names}). This is a limit of what an agentless "
                f"configuration scan can see, not a finding about the estate")
    tail = ""
    if unscored:
        tail = (f"; {len(unscored)} function(s) could not be assessed at all and are "
                f"excluded from the stage rather than counted as Traditional")
    return (f"{pillar}: {stage}, taken from the WEAKEST of {scored} scored function(s) "
            f"of {total} — zero trust is a chain, so the minimum is the honest summary "
            f"and an average would flatter it{tail}")


def score_estate(mapping: Optional[Mapping], results: Optional[Sequence],
                 not_evaluated: Optional[Mapping] = None) -> dict:
    """Every pillar. Deliberately WITHOUT an overall score.

    There is no single ZTMM number here and there will not be one. An estate that is
    Advanced on four pillars and unscoreable on Devices does not have a maturity level —
    it has four maturity levels and a blind spot, and the number that hides which is the
    number every competing product prints."""
    pillars = {p: score_pillar(p, mapping, results, not_evaluated) for p in PILLARS}
    scored = sum(p["functions_scored"] for p in pillars.values())
    return {
        "source": SOURCE,
        "source_date": SOURCE_DATE,
        "pillars": pillars,
        "functions_total": TOTAL_FUNCTIONS,
        "functions_scored": scored,
        "functions_unscored": TOTAL_FUNCTIONS - scored,
        "overall_stage": None,
        "statement": (
            f"{scored} of {TOTAL_FUNCTIONS} ZTMM function(s) are evidenced by at least "
            f"one OverWatch check. There is deliberately NO overall maturity score: an "
            f"estate strong on four pillars and unscoreable on a fifth does not have a "
            f"single maturity level, and a number that hides which pillar is which is "
            f"worse than no number."),
    }


# ─── the mapping ─────────────────────────────────────────────────────────────
#: ``{(pillar, function): {stage: [check_id, ...]}}`` — the checks whose PASSING
#: evidences that stage for that function.
#:
#: Scoped deliberately. Authoring a mapping for all 37 functions from a reading of the
#: model would reproduce the error this codebase keeps catching: a table that looks
#: right and names things that do not exist. Every id below is a check OverWatch
#: actually ships, and ``test_the_mapping_names_only_real_checks`` fails the build if
#: one stops existing. Functions absent from this table score UNSCORED and say so.
#:
#: On the STAGE assignments: they follow the model's own descriptions rather than a
#: severity ranking. CISA's Initial for Authentication is "MFA, which may include
#: passwords"; Advanced is "phishing-resistant MFA". So root MFA lands at Initial and
#: nothing OverWatch reads from configuration can evidence Advanced there — a scanner
#: cannot see whether the second factor is phishing-resistant. Where that is true the
#: stage is simply absent, which caps the function honestly rather than inventing
#: evidence for it.
ZTMM_MAPPING: Dict[Tuple[str, str], Dict[str, List[str]]] = {
    # ── Identity ─────────────────────────────────────────────────────────────
    ("Identity", "Authentication"): {
        INITIAL: ["IAM-01", "IAM-02"],
    },
    ("Identity", "Identity stores"): {
        INITIAL: ["IAM-05"],
    },
    ("Identity", "Risk assessments"): {
        INITIAL: ["AITHR-01"],
        ADVANCED: ["AITHR-02"],
    },
    ("Identity", "Access management"): {
        INITIAL: ["IAM-04", "IAM-06"],
        ADVANCED: ["IAMPE-01", "EXTACCESS-01"],
    },
    ("Identity", "Visibility and analytics"): {
        INITIAL: ["LOG-01"],
        ADVANCED: ["LOG-08", "LOG-10"],
    },
    ("Identity", "Governance"): {
        INITIAL: ["IAM-07"],
    },

    # ── Networks ─────────────────────────────────────────────────────────────
    ("Networks", "Network segmentation"): {
        INITIAL: ["SEG-01"],
        ADVANCED: ["SEG-02", "VPC-01"],
    },
    ("Networks", "Network traffic management"): {
        INITIAL: ["SEG-05"],
    },
    ("Networks", "Traffic encryption"): {
        INITIAL: ["ELB-01"],
        ADVANCED: ["ACM-01", "ACM-02"],
    },
    ("Networks", "Visibility and analytics"): {
        INITIAL: ["VPC-03"],
    },

    # ── Applications and Workloads ───────────────────────────────────────────
    ("Applications and Workloads", "Application access"): {
        INITIAL: ["APIGW-01"],
    },
    ("Applications and Workloads", "Application threat protections"): {
        INITIAL: ["WAF-01"],
        ADVANCED: ["WAF-02"],
    },
    ("Applications and Workloads", "Accessible applications"): {
        INITIAL: ["EXPOSURE-01"],
    },
    ("Applications and Workloads", "Application security testing"): {
        INITIAL: ["CWPP-01"],
    },
    ("Applications and Workloads", "Visibility and analytics"): {
        INITIAL: ["LOG-03"],
    },

    # ── Data ─────────────────────────────────────────────────────────────────
    ("Data", "Data inventory management"): {
        INITIAL: ["DSPM-01"],
    },
    ("Data", "Data availability"): {
        INITIAL: ["BCK-01"],
    },
    ("Data", "Data access"): {
        INITIAL: ["S3-01", "S3-09"],
        ADVANCED: ["S3-10", "EXTACCESS-02"],
    },
    ("Data", "Data encryption"): {
        INITIAL: ["S3-03", "EBS-01"],
        ADVANCED: ["KMS-02", "RDS-01"],
    },
    ("Data", "Visibility and analytics"): {
        INITIAL: ["LOG-04"],
    },

    # ── Devices ──────────────────────────────────────────────────────────────
    # Two functions have genuine AWS-side signal. The other five are in
    # AGENTLESS_BLIND and score UNSCORED with a reason.
    ("Devices", "Asset and supply-chain risk management"): {
        INITIAL: ["CWPP-02"],
    },
    ("Devices", "Resource access"): {
        INITIAL: ["EC2-04"],
    },
}
