#!/usr/bin/env python3
"""
aws_factors.py — live inputs for the composite Cloud Risk Score.

:mod:`aws_riskscore` implements the corrected Appendix B model and has been
correct and uncalled: nothing produced the five :class:`~aws_riskscore.FactorValue`
inputs it consumes, so every grade in a scorecard was withheld. This module
produces them from data the scanner already collects, and produces the
:class:`~aws_riskscore.ExposureGate` verdict that had no producer either.

PURE: stdlib only, no boto3, no I/O, no ``now()``. Consumes already-materialised
findings, attack paths, ingested vulnerabilities and posture history.

────────────────────────────────────────────────────────────────────────────────
EVERY SATURATION POINT IS PUBLISHED, BECAUSE THAT IS WHERE THE JUDGEMENT HIDES
────────────────────────────────────────────────────────────────────────────────
A factor normalised to [0, 1] has to decide what counts as "1.0", and that
decision moves every score built on it while looking like arithmetic. The
constants below are the whole of it, they are named, and
:func:`saturation_points` hands them to the methodology export so they sit beside
the weights rather than inside the code.

They are also **stated as judgements**, not derived truths. Nobody can prove that
100 severity-weighted points is where an estate's finding load stops getting
worse in a way the score should notice; what can be done is to say so where a
reader will see it.

────────────────────────────────────────────────────────────────────────────────
UNMEASURED IS NOT ZERO — THE SAME RULE, ONE LAYER DOWN
────────────────────────────────────────────────────────────────────────────────
Each builder returns a ``FactorValue`` with ``value=None`` and a reason when its
input is absent, and :mod:`aws_riskscore` then excludes it and redistributes its
weight rather than scoring it 0.0. Two cases are worth naming because the wrong
answer is tempting:

* **No ingested vulnerabilities** does not mean nothing is exploitable. It means
  nobody has told us. Scoring exploitability 0.0 would reward an estate for never
  running a vulnerability scanner.
* **``criticality == "unclassified"``** is NOT the bottom of the scale. An asset
  nobody has assessed is not a low-value asset, and mapping it to 0.0 would let
  an organisation improve its portfolio score by declining to classify anything.
  It returns None.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Mapping, Optional, Sequence, Tuple

from engine import aws_riskscore

# ── published saturation points (judgements, not derived truths) ─────────────

SEVERITY_POINTS: Mapping[str, float] = {
    "CRITICAL": 10.0, "HIGH": 3.0, "MEDIUM": 1.0, "LOW": 0.25, "INFO": 0.0,
}
"""Severity weights for the finding-load factor. Deliberately steep: one CRITICAL
outweighs three HIGHs, because a score that lets volume drown severity is the
complaint every CNAPP buyer already has about their current tool."""

FINDINGS_SATURATION = 100.0
"""Severity-weighted points at which the finding-load factor reaches 1.0. An
estate at 400 points and one at 4,000 are both simply bad; the score stops
distinguishing them and the finding list does that job instead."""

EPSS_EXPLOITABLE = 0.5
"""EPSS at or above which a vulnerability counts as exploitable for this factor.
KEV membership counts regardless of EPSS -- a CVE known to be exploited in the
wild is not a probability question."""

HYGIENE_SATURATION = 20.0
"""Posture points of 90-day movement at which the trend factor saturates. A
20-point slide in a quarter is already the whole story."""

CRITICALITY_VALUE: Mapping[str, float] = {
    "crown-jewel": 1.0,
    "high": 0.66,
    "standard": 0.33,
}
"""``unclassified`` is deliberately ABSENT: it maps to no value at all, not to
the bottom of the scale. See the module docstring."""

MIN_TREND_SCANS = 2
"""Fewer than two posture observations cannot show a direction."""


def saturation_points() -> dict:
    """The constants above, for the published methodology (OW2-CC-003).

    Weights without saturation points are half a methodology: they say how much
    each factor counts and not what makes one of them "full".
    """
    return {
        "severity_points": dict(SEVERITY_POINTS),
        "findings_saturation": FINDINGS_SATURATION,
        "epss_exploitable_at": EPSS_EXPLOITABLE,
        "hygiene_saturation_points": HYGIENE_SATURATION,
        "criticality_values": dict(CRITICALITY_VALUE),
        "note": ("These are judgements, not derived truths. They decide what "
                 "counts as a factor being 'full', which moves every score built "
                 "on them while looking like arithmetic."),
    }


def _sev(f) -> str:
    v = f.get("severity") if isinstance(f, Mapping) else getattr(f, "severity", "")
    return (v or "").upper()


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


# ── the five factors ────────────────────────────────────────────────────────

def findings_factor(findings: Sequence) -> aws_riskscore.FactorValue:
    """Severity-weighted open finding load, saturating."""
    if not findings:
        # An empty finding list IS a measurement: nothing open is nothing open.
        return aws_riskscore.FactorValue(
            aws_riskscore.FINDINGS, 0.0, "no open findings in scope")
    points = sum(SEVERITY_POINTS.get(_sev(f), 0.0) for f in findings)
    return aws_riskscore.FactorValue(
        aws_riskscore.FINDINGS, _clamp(points / FINDINGS_SATURATION),
        "%.1f severity-weighted points over a %.0f-point saturation"
        % (points, FINDINGS_SATURATION))


def exploitability_factor(vulns: Optional[Sequence]) -> aws_riskscore.FactorValue:
    """Share of known vulnerabilities that are KEV-listed or high-EPSS."""
    if vulns is None:
        return aws_riskscore.FactorValue(
            aws_riskscore.EXPLOITABILITY, None, reason=(
                "no vulnerability data has been ingested for this scope. That is "
                "not the same as nothing being exploitable, so this factor is "
                "excluded rather than scored zero"))
    if not vulns:
        return aws_riskscore.FactorValue(
            aws_riskscore.EXPLOITABILITY, 0.0,
            "vulnerability data present and no open vulnerabilities in scope")
    hot = 0
    for v in vulns:
        kev = bool(v.get("kev") if isinstance(v, Mapping) else getattr(v, "kev", 0))
        epss = (v.get("epss") if isinstance(v, Mapping) else getattr(v, "epss", None))
        if kev or (epss is not None and float(epss) >= EPSS_EXPLOITABLE):
            hot += 1
    return aws_riskscore.FactorValue(
        aws_riskscore.EXPLOITABILITY, _clamp(hot / len(vulns)),
        "%d of %d vulnerabilities are KEV-listed or EPSS >= %.2f"
        % (hot, len(vulns), EPSS_EXPLOITABLE))


def exposure_factor(paths: Optional[Sequence]) -> aws_riskscore.FactorValue:
    """Worst unconditioned path exposure in scope.

    Uses the per-path ``exposure`` the correlation engine already computes rather
    than re-deriving reachability -- the four-gate oracle is the authority on that
    and a second opinion here would be a second, worse one.

    CONDITIONED paths are excluded: they are true only if an assumption holds, and
    a headline score is the wrong place to spend an assumption.
    """
    if paths is None:
        return aws_riskscore.FactorValue(
            aws_riskscore.EXPOSURE, None, reason=(
                "no security graph for this scope, so reachability was never "
                "computed. An unbuilt graph is not an unexposed estate"))
    live = [p for p in paths if not _attr(p, "conditioned", False)]
    if not live:
        return aws_riskscore.FactorValue(
            aws_riskscore.EXPOSURE, 0.0,
            "graph built; no unconditioned attack path in scope")
    worst = max(float(_attr(p, "exposure", 0.0) or 0.0) for p in live)
    return aws_riskscore.FactorValue(
        aws_riskscore.EXPOSURE, _clamp(worst),
        "worst unconditioned path exposure across %d path(s)" % len(live))


def criticality_factor(criticality: Optional[str]) -> aws_riskscore.FactorValue:
    """The application's own crown-jewel tier (AD-03)."""
    tier = (criticality or "").strip().lower()
    if tier not in CRITICALITY_VALUE:
        return aws_riskscore.FactorValue(
            aws_riskscore.CRITICALITY, None, reason=(
                "criticality is %r. An asset nobody has assessed is not a "
                "low-value asset, so this is excluded rather than scored at the "
                "bottom of the scale -- otherwise an estate improves its score by "
                "declining to classify anything" % (criticality or "unset")))
    return aws_riskscore.FactorValue(
        aws_riskscore.CRITICALITY, CRITICALITY_VALUE[tier],
        "declared criticality tier %r" % tier)


def hygiene_factor(trend: Optional[Sequence]) -> aws_riskscore.FactorValue:
    """90-day direction of the posture score. Worsening scores high."""
    if not trend or len(trend) < MIN_TREND_SCANS:
        return aws_riskscore.FactorValue(
            aws_riskscore.HYGIENE, None, reason=(
                "fewer than %d posture observations, so no direction exists. A "
                "first scan is not a flat trend" % MIN_TREND_SCANS))
    first = float(_attr(trend[0], "posture_score", 0.0) or 0.0)
    last = float(_attr(trend[-1], "posture_score", 0.0) or 0.0)
    drop = first - last                      # posture falling => hygiene worsening
    return aws_riskscore.FactorValue(
        aws_riskscore.HYGIENE, _clamp(drop / HYGIENE_SATURATION),
        "posture moved %+.1f across %d observations" % (last - first, len(trend)))


def _attr(obj, name, default=None):
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


# ── the exposure gate, which had no producer ────────────────────────────────

def exposure_gate(paths: Optional[Sequence]) -> aws_riskscore.ExposureGate:
    """Whether compensating-control credit must be withheld.

    Review defect D2 established that no quantity of tooling may buy down a live
    exposure, and :mod:`aws_riskscore` has refused to grant credit without a
    verdict ever since -- because nothing produced one. This is that producer.

    The gate trips on a path that is **unconditioned** and reaches an admin or
    data terminal while carrying a KEV-listed vulnerability or a direct
    public-to-crown edge. Each of those facts is already on the path object; none
    is re-derived here.

    A missing graph returns an UNTRIPPED gate rather than None, and the caller is
    responsible for not requesting credit it cannot justify -- which
    :func:`aws_riskscore.score` enforces by withholding credit when no verdict is
    supplied at all.
    """
    if not paths:
        return aws_riskscore.ExposureGate(False)
    for p in paths:
        if _attr(p, "conditioned", False):
            continue
        kev = bool(_attr(p, "kev", False))
        direct = bool(_attr(p, "direct_public_crown", False))
        if not (kev or direct):
            continue
        terminal = str(_attr(p, "terminal_kind", "") or "")
        if terminal in ("admin", "data"):
            why = "a KEV-listed vulnerability" if kev else "a direct public-to-crown edge"
            return aws_riskscore.ExposureGate(
                True,
                "an unconditioned attack path reaches %s data with %s; a "
                "compensating control changes how fast that is caught, not "
                "whether it is reachable" % (terminal, why))
    return aws_riskscore.ExposureGate(False)


# ── assembly ────────────────────────────────────────────────────────────────

def build(
    findings: Sequence,
    *,
    criticality: Optional[str] = None,
    paths: Optional[Sequence] = None,
    vulns: Optional[Sequence] = None,
    trend: Optional[Sequence] = None,
) -> Tuple[List[aws_riskscore.FactorValue], aws_riskscore.ExposureGate]:
    """All five factors plus the gate, for one scope.

    Returns ``(factors, gate)``. Every argument that is None yields a factor that
    is excluded with a reason rather than a value that flatters.
    """
    return ([
        findings_factor(findings),
        exploitability_factor(vulns),
        exposure_factor(paths),
        criticality_factor(criticality),
        hygiene_factor(trend),
    ], exposure_gate(paths))
