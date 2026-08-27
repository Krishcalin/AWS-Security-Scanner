#!/usr/bin/env python3
"""aws_evidence.py — Phase 4 · slice 4.5: the AI compliance evidence pack.

An auditor does not want a list of failures. They want to know, control by control:
*was this assessed, how, by what, and what does the answer rest on* — and, above all,
**what was not assessed**. Findings are what a scanner produces; evidence is what
survives a question.

WHY THIS IS THE SLICE OVERWATCH CAN ACTUALLY WIN
------------------------------------------------
Every compliance product maps controls to checks and paints the result green. Almost none
can tell you which controls their scan never reached, because they do not know. OverWatch
does, from three artefacts it already maintains and which exist for exactly this reason:

* the **permission ledger** — which checks the role could not evaluate, and which action
  would fix that;
* the **coverage manifest** — which regions were never looked at, which resource types
  could not be enumerated, and which checks returned AccessDenied;
* **`aws_epistemics`** — whether a claim is `OBSERVED`, `CONFIGURED`, `INFERRED` or
  `CONDITIONAL`, so "the guardrail is configured" is not silently upgraded to "the
  guardrail works".

THE FAILURE THIS MODULE EXISTS TO PREVENT
------------------------------------------
A control with **no mapped check** must never read as satisfied. That is the phantom pass
at framework scale, and it is the standard way a compliance report lies: a framework has
72 controls, a product maps 17 of them, and the summary shows green because the other 55
produced no failures. Producing no failures and being satisfied are different facts.

So this module has **no status meaning "compliant"**. The strongest thing it will say is
``ASSESSED_PASS`` — *these checks ran and passed* — and every row carries the mapping's
own confidence and provenance alongside it. The crosswalk is candid that the AI-framework
mappings are OverWatch's reading of two texts rather than an official crosswalk, because
none exists; an evidence pack that dropped that caveat would be laundering an opinion into
a finding.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from engine import aws_epistemics

__all__ = [
    "AI_FRAMEWORKS", "ASSESSED_PASS", "ASSESSED_FAIL", "PARTIAL",
    "NOT_EVALUATED", "NOT_ASSESSED", "STATUSES",
    "framework_controls", "control_evidence", "build_pack", "coverage_summary",
    "describe_status",
]

#: The three frameworks slice 2.7 put on the crosswalk spine.
AI_FRAMEWORKS: Tuple[str, ...] = (
    "NIST-AI-RMF-1.0", "ISO-42001-2023", "MITRE-ATLAS",
)

#: Deliberately NOT "COMPLIANT". A scanner establishes that checks ran and what they
#: found; whether that satisfies a control is the auditor's judgement, and a tool that
#: pre-empts it is selling an opinion as a fact.
ASSESSED_PASS = "ASSESSED_PASS"      # mapped checks ran, none failed
ASSESSED_FAIL = "ASSESSED_FAIL"      # mapped checks ran, at least one failed
PARTIAL = "PARTIAL"                  # some mapped checks ran, others could not
NOT_EVALUATED = "NOT_EVALUATED"      # mapped, but nothing could be evaluated
NOT_ASSESSED = "NOT_ASSESSED"        # no OverWatch check maps here at all
STATUSES: Tuple[str, ...] = (ASSESSED_FAIL, PARTIAL, NOT_EVALUATED,
                             NOT_ASSESSED, ASSESSED_PASS)

_HUMAN = {
    ASSESSED_PASS: ("checks mapped to this control ran and none failed — this is "
                    "evidence the checks passed, not a determination that the control "
                    "is satisfied"),
    ASSESSED_FAIL: "checks mapped to this control ran and at least one failed",
    PARTIAL: ("some mapped checks ran and others could not be evaluated — the result "
              "is incomplete, not clean"),
    NOT_EVALUATED: ("this control is mapped, but no mapped check could be evaluated in "
                    "this scan — an absence of evidence, not an absence of findings"),
    NOT_ASSESSED: ("no OverWatch check maps to this control — it was NOT looked at, "
                   "and producing no failures is not the same as being satisfied"),
}


def describe_status(status: str) -> str:
    return _HUMAN.get(status, "")


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


def framework_controls(crosswalk: Optional[Mapping], framework: str) -> Dict[str, dict]:
    """Every control of one framework the crosswalk reaches, and how.

    Returns ``{framework_control: {"spine": [nist...], "confidence": str,
    "notes": [str]}}``. A framework control reached through more than one spine control
    keeps the LOWEST confidence of them: an evidence row is only as trustworthy as the
    weakest link that produced it, and taking the highest would let one confident mapping
    launder several speculative ones."""
    out: Dict[str, dict] = {}
    order = {"high": 3, "medium": 2, "low": 1}
    for nist, per_fw in (crosswalk or {}).items():
        entry = _d(_d(per_fw).get(framework))
        conf = entry.get("confidence") or "low"
        note = entry.get("note") or ""
        for target in (entry.get("targets") or []):
            if not isinstance(target, str):
                continue
            row = out.setdefault(target, {"control": target, "spine": [],
                                          "confidence": conf, "notes": []})
            row["spine"].append(nist)
            if order.get(conf, 1) < order.get(row["confidence"], 1):
                row["confidence"] = conf
            if note and note not in row["notes"]:
                row["notes"].append(note)
    for row in out.values():
        row["spine"] = sorted(set(row["spine"]))
    return out


def control_evidence(row: Optional[dict],
                     compliance_map: Optional[Mapping],
                     results: Optional[Sequence],
                     not_evaluated: Optional[Mapping] = None) -> dict:
    """One evidence row: what bears on this control, what it found, what it rests on."""
    r = _d(row)
    spine = list(r.get("spine") or [])
    checks = sorted(cid for cid, m in (compliance_map or {}).items()
                    if _d(m).get("NIST") in spine)

    blocked = sorted(c for c in checks if c in (not_evaluated or {}))
    seen: Dict[str, str] = {}
    failing: List[dict] = []
    for res in (results or []):
        cid = getattr(res, "check_id", None)
        if cid not in checks:
            continue
        status = getattr(res, "status", "")
        if status in ("PASS", "FAIL", "WARN"):
            prev = seen.get(cid)
            # FAIL dominates: a control with one failing resource has not passed.
            seen[cid] = "FAIL" if "FAIL" in (status, prev) else status
        if status == "FAIL":
            failing.append({"check": cid,
                            "resource": getattr(res, "resource", ""),
                            "severity": getattr(res, "severity", "")})

    ran = sorted(seen)
    if not checks:
        status = NOT_ASSESSED
    elif not ran:
        status = NOT_EVALUATED
    elif any(v == "FAIL" for v in seen.values()):
        status = ASSESSED_FAIL
    elif blocked or len(ran) < len(checks):
        status = PARTIAL
    else:
        status = ASSESSED_PASS

    # The epistemic class of the strongest claim behind this row. A control evidenced
    # only by CONFIGURED checks has not been shown to WORK, and an auditor reading
    # "passed" without that qualifier is being told more than the scan established.
    classes = sorted({aws_epistemics.classify(c) for c in ran}) if ran else []

    return {
        "control": r.get("control", ""),
        "status": status,
        "why": describe_status(status),
        "spine": spine,
        "checks": checks,
        "checks_run": ran,
        "checks_blocked": blocked,
        "failing": failing,
        "confidence": r.get("confidence") or "low",
        "mapping_notes": list(r.get("notes") or []),
        "epistemics": classes,
    }


def build_pack(crosswalk: Optional[Mapping],
               compliance_map: Optional[Mapping],
               results: Optional[Sequence],
               *, coverage: Optional[Mapping] = None,
               frameworks: Optional[Sequence[str]] = None,
               framework_meta: Optional[Sequence[Mapping]] = None) -> dict:
    """The whole pack: every AI framework, every control it reaches, and the gaps."""
    cov = _d(coverage)
    not_eval = _d(cov.get("not_evaluated"))
    out: Dict[str, dict] = {}
    sizes = {f.get("id"): f.get("catalog_size")
             for f in (framework_meta or []) if isinstance(f, dict)}
    for fw in (frameworks or AI_FRAMEWORKS):
        rows = framework_controls(crosswalk, fw)
        evid = [control_evidence(r, compliance_map, results, not_eval)
                for _, r in sorted(rows.items())]
        out[fw] = {"framework": fw, "controls": evid,
                   "summary": coverage_summary(evid, catalog_size=sizes.get(fw))}
    return {
        "frameworks": out,
        # Carried verbatim so the pack states what the SCAN could not see, not only
        # what the mapping could not reach. Two different gaps, and a reader who
        # conflates them will over-trust the pack.
        "scan_coverage": {
            "complete": cov.get("complete"),
            "unscanned_regions": list(cov.get("unscanned_regions") or []),
            "not_evaluated": dict(not_eval),
            "missing_actions": list(cov.get("missing_actions") or []),
        },
    }


def coverage_summary(rows: Optional[Sequence[dict]],
                     catalog_size: Optional[int] = None) -> dict:
    """How much of a framework this scan actually reached.

    ``catalog_size`` is the framework's FULL control count, and leaving it out is how
    this function first lied. A framework control only enters ``rows`` if the crosswalk
    already maps it, so the mapped set is 12-of-12 by construction — while NIST AI RMF
    has 72 controls. Reporting "12 of 12" is the phantom pass at framework scale: the
    exact failure this module was written to prevent, reproduced in its own summary.
    With the catalog size the denominator is the framework, not our reach.

    Counts rather than a percentage throughout. A percentage invites being read as a
    score, and "68% compliant" is precisely the sentence this module exists to make
    impossible to write."""
    rows = list(rows or [])
    by = {s: sum(1 for r in rows if r.get("status") == s) for s in STATUSES}
    mapped = len(rows) - by[NOT_ASSESSED]
    total = catalog_size if isinstance(catalog_size, int) and catalog_size > 0 else None
    unmapped = (total - mapped) if total is not None else None

    if total is None:
        head = (f"{mapped} control(s) in this framework have at least one OverWatch "
                f"check mapped to them. The framework's full control count was not "
                f"supplied, so what fraction of it that represents is UNKNOWN")
    else:
        head = (f"{mapped} of {total} control(s) in this framework have at least one "
                f"OverWatch check mapped to them; the remaining {unmapped} are not "
                f"reached by the crosswalk at all and were NOT looked at")
    return {
        "controls_in_framework": total,
        "controls_mapped": mapped,
        "controls_unmapped": unmapped,
        "controls_total": len(rows),
        "controls_reached": mapped,
        "controls_not_assessed": by[NOT_ASSESSED],
        "by_status": by,
        "statement": (
            f"{head}. Of those mapped, {by[ASSESSED_FAIL]} had a failing check, "
            f"{by[PARTIAL]} were incompletely evaluated and {by[NOT_EVALUATED]} could "
            f"not be evaluated at all."),
    }
