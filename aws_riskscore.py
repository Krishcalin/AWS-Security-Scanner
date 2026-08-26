#!/usr/bin/env python3
"""
aws_riskscore.py — the composite Cloud Risk Score (FR-1, OW2-CC-001…006).

Implements Appendix B of OW2-SRS-001 with three defects in that appendix
corrected. PURE: stdlib only, no boto3, no I/O, no ``now()``. Every score is a
function of (model, factor values, control credit, exposure gate), so a published
number can be recomputed by anyone holding the same inputs — which is what
OW2-CC-004 means when it says historical scores shall not be silently recomputed.

────────────────────────────────────────────────────────────────────────────────
DEFECT 1 — THE WEIGHTS DO NOT SUM
────────────────────────────────────────────────────────────────────────────────
Appendix B tabulates 30 + 20 + 20 + 15 + 10 = **95%**, with compensating controls
as a separate −15% credit. A model whose positive weights top out at 95 cannot be
read against a 0–100 scale without a normalisation step the document never states.

The fix here is deliberately not "renumber the table to 100". Any hand-authored
weight set drifts the moment somebody adds a sixth factor or an administrator
retunes one under OW2-CC-004, and the same defect returns silently. So
:meth:`RiskModel.normalized` accepts weights in **arbitrary units** and normalises
them itself. 30/20/20/15/10 works, 6/4/4/3/2 works, and both produce the identical
score. Weights become a statement of relative importance, which is the only thing
anyone actually means by them, and the appendix's arithmetic can no longer be
wrong because nobody is doing arithmetic.

The normalised set is reported in :meth:`RiskModel.methodology`, so the
normalisation is published rather than hidden (OW2-CC-003).

────────────────────────────────────────────────────────────────────────────────
DEFECT 2 — THE SCORE RUNS THE WRONG WAY AGAINST ITS OWN BANDING
────────────────────────────────────────────────────────────────────────────────
Appendix B is titled "Cloud Risk Score Model" and every factor in it is one where
MORE MEANS WORSE — severity-weighted findings, exploitability, exposure, asset
criticality. It then bands the result "A ≥ 90 · B 80–89 · … · E < 60". As written,
an estate with maximum severity, maximum exploitability and maximum exposure
scores 95 and is awarded an **A**.

The document is carrying two different quantities under one name: FR-1 says
"Cloud Risk Score" and OW2-SC-002 says "security posture score and letter grade".
They are not the same number and they point in opposite directions.

Both are produced here and the relationship is stated:

    risk    = weighted composite, 0–100, HIGHER IS WORSE
    posture = 100 − risk,          0–100, HIGHER IS BETTER
    grade   = band(posture)

The banding thresholds from Appendix B are preserved exactly and applied to the
posture, which is also the convention ``aws_live_scanner.compute_risk_score``
already uses — so FR-1 and FR-2 stop disagreeing, and neither has to move.

────────────────────────────────────────────────────────────────────────────────
DEFECT 3 — COMPENSATING CONTROLS ARE THE WRONG INSTRUMENT
────────────────────────────────────────────────────────────────────────────────
OW2-CC-002(e) lists compensating controls as a sixth weighted factor with a −15%
credit. An EDR sensor does not make an internet-reachable unpatched host less
reachable or less unpatched; it makes the consequence more likely to be noticed.
Credited as a weight, an estate improves its published risk score by buying
tooling without changing a single exposure — and OW2-KM-001(b), which targets
*zero* internet-exposed critical workloads, then disagrees with the composite
about the same estate.

So the credit is a **bounded multiplier applied only to the factors a control can
legitimately modulate**, and it is additionally gated:

    risk   = Σ contributions, creditable ones × (1 − credit)
    credit ≤ MAX_CONTROL_CREDIT
    credit = 0 when the exposure gate is tripped, OR when no gate verdict exists

:data:`CREDITABLE_FACTORS` is ``(findings,)`` alone. Detection and containment
genuinely reduce the risk carried by a population of open issues — they are found
sooner and contained faster. They do not touch the other four:

* **exposure** — definitionally. This is the whole of the objection above.
* **exploitability** — a KEV entry is a property of the vulnerability, not of the
  response to it.
* **criticality** — a property of the asset.
* **hygiene trend** — a measurement of the process, not a credit against it.

**This deliberately does not preserve Appendix B's 15-point magnitude, and that is
the point.** Against the Appendix B weights the maximum effective credit is
0.15 × 31.58% ≈ **4.7 points**, not 15. The 15 was attached to the wrong
instrument; keeping its size while fixing the instrument would have been having it
both ways. :meth:`RiskModel.methodology` publishes the effective ceiling, so nobody
has to discover it by subtraction.

TWO GUARDS, NOT ONE. Restricting the credit to creditable factors is the
principled fix. The exposure gate is a second, stricter one: on a live
unconditioned exposure even the findings credit is withheld, because there the
control sits downstream of a compromise that has already succeeded. And **a
missing gate verdict withholds the credit rather than granting it** — "nobody
evaluated exposure" must never read as "exposure is fine", which is the same
phantom pass this module refuses everywhere else. A caller that wants credit
supplies a verdict.

────────────────────────────────────────────────────────────────────────────────
A FACTOR WITH NO DATA IS NOT A FACTOR WORTH ZERO
────────────────────────────────────────────────────────────────────────────────
If EPSS and KEV data are unavailable, exploitability is not 0.0 — it is unknown,
and scoring it 0.0 lowers the risk of an estate nobody measured. That is the
phantom pass wearing a percentage sign, and it is the single most likely way for
this engine to publish a reassuring number about an estate it could not read.

Unavailable factors are therefore EXCLUDED and their weight redistributed across
the factors that do have data, with the exclusion reported on the result. When too
much weight is missing (:attr:`RiskModel.min_weight_coverage`, default half), the
score is REFUSED rather than published — a composite resting on a quarter of its
model is not a composite.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ── the five risk factors (Appendix B, compensating controls removed to the
#    multiplier where it belongs) ───────────────────────────────────────────────
FINDINGS = "findings"
EXPLOITABILITY = "exploitability"
EXPOSURE = "exposure"
CRITICALITY = "criticality"
HYGIENE = "hygiene"

FACTOR_KEYS = (FINDINGS, EXPLOITABILITY, EXPOSURE, CRITICALITY, HYGIENE)

FACTOR_LABELS: Dict[str, str] = {
    FINDINGS: "Severity-weighted open findings",
    EXPLOITABILITY: "Exploitability",
    EXPOSURE: "Exposure",
    CRITICALITY: "Asset criticality",
    HYGIENE: "Hygiene trend",
}

FACTOR_INPUTS: Dict[str, str] = {
    FINDINGS: "Counts by severity, normalised per 100 assets",
    EXPLOITABILITY: "CVSS, EPSS and KEV presence on open vulnerabilities",
    EXPOSURE: "Internet-reachable resources and exposure paths from the twin",
    CRITICALITY: "Crown-jewel and criticality tags on affected assets",
    HYGIENE: "90-day direction of finding volume and SLA compliance",
}

# Appendix B, verbatim. Units are arbitrary and normalised at use; these are
# retained in the document's own numbers so the table and the code can be read
# against each other, and so the steering committee ratifies what it drafted
# (Appendix D item 2).
APPENDIX_B_WEIGHTS: Dict[str, float] = {
    FINDINGS: 30.0,
    EXPLOITABILITY: 20.0,
    EXPOSURE: 20.0,
    CRITICALITY: 15.0,
    HYGIENE: 10.0,
}

# Appendix B banding, applied to POSTURE (see defect 2). Ordered best first.
APPENDIX_B_BANDS: Tuple[Tuple[str, float], ...] = (
    ("A", 90.0), ("B", 80.0), ("C", 70.0), ("D", 60.0), ("E", 0.0),
)

MAX_CONTROL_CREDIT = 0.15
"""The −15% Appendix B intended, as a multiplier ceiling rather than a weight.

Note this is a ceiling on the *creditable* portion, not on the composite. See
:data:`CREDITABLE_FACTORS` and :meth:`RiskModel.max_effective_credit`."""

CREDITABLE_FACTORS: Tuple[str, ...] = (FINDINGS,)
"""The only factors a compensating control may reduce.

Detection and containment genuinely lower the risk carried by a population of open
issues. They do not make an asset less reachable (exposure), a CVE less exploited
in the wild (exploitability), a database less valuable (criticality), or a
remediation trend less bad (hygiene). Crediting any of those is how an estate
improves its published score by buying tooling."""

NO_GATE_VERDICT = (
    "no exposure verdict was supplied, so credit was withheld rather than assumed "
    "safe — an unevaluated exposure is not a cleared one")

SCOPES = ("estate", "account", "business-unit", "application")
"""OW2-CC-001. The engine is scope-agnostic; the label travels with the result."""

REFUSED_INSUFFICIENT = (
    "Refused: too little of the model had data. A composite resting on a minority "
    "of its factors is not a composite, and publishing one would report a risk "
    "level for an estate that was largely not measured.")


@dataclass(frozen=True)
class ExposureGate:
    """Whether compensating-control credit is withheld, and why.

    Computed by the caller from the graph — this module does not re-derive
    exposure, it consumes the verdict. ``tripped`` should be set when the scope
    contains at least one internet-reachable asset carrying a KEV-listed or
    CRITICAL finding on an unconditioned path.
    """

    tripped: bool = False
    reason: str = ""

    def __post_init__(self) -> None:
        if self.tripped and not self.reason:
            raise ValueError(
                "a tripped exposure gate must carry a reason; the withheld credit "
                "has to be explainable to whoever asks why their score did not move")


@dataclass(frozen=True)
class RiskModel:
    """A versioned, publishable scoring model (OW2-CC-003, OW2-CC-004)."""

    weights: Mapping[str, float] = None
    max_control_credit: float = MAX_CONTROL_CREDIT
    bands: Tuple[Tuple[str, float], ...] = APPENDIX_B_BANDS
    min_weight_coverage: float = 0.5
    creditable: Tuple[str, ...] = CREDITABLE_FACTORS
    label: str = "Appendix B v1 (corrected)"

    def __post_init__(self) -> None:
        w = dict(self.weights if self.weights is not None else APPENDIX_B_WEIGHTS)
        unknown = sorted(set(w) - set(FACTOR_KEYS))
        if unknown:
            raise ValueError("unknown risk factor(s): %s" % ", ".join(unknown))
        for k, v in w.items():
            if float(v) < 0:
                raise ValueError(
                    "weight for %s is negative (%r); a risk factor that reduces risk "
                    "is a compensating control and belongs in the credit multiplier, "
                    "not in the weight set" % (k, v))
        if sum(float(v) for v in w.values()) <= 0:
            raise ValueError("weights sum to zero; the model would score nothing")
        object.__setattr__(self, "weights", w)
        if not (0.0 <= self.max_control_credit < 1.0):
            raise ValueError("max_control_credit must be in [0, 1)")
        if not (0.0 < self.min_weight_coverage <= 1.0):
            raise ValueError("min_weight_coverage must be in (0, 1]")
        if not self.bands:
            raise ValueError("at least one band is required")
        cred = tuple(self.creditable or ())
        bad = sorted(set(cred) - set(FACTOR_KEYS))
        if bad:
            raise ValueError("unknown creditable factor(s): %s" % ", ".join(bad))
        if EXPOSURE in cred:
            raise ValueError(
                "exposure cannot be creditable: a compensating control does not make "
                "an asset less reachable, and crediting it lets an estate improve its "
                "published score by buying tooling (OW2-CC-002(e), review defect D2)")
        object.__setattr__(self, "creditable", cred)

    # ── normalisation: the fix for defect 1 ──────────────────────────────────
    def normalized(self, over: Optional[Iterable[str]] = None) -> Dict[str, float]:
        """Weights as fractions summing to 1.0.

        ``over`` restricts normalisation to the factors that actually had data,
        which is how an excluded factor's weight is redistributed rather than
        silently scoring zero.
        """
        keys = [k for k in FACTOR_KEYS if k in self.weights]
        if over is not None:
            allow = set(over)
            keys = [k for k in keys if k in allow]
        total = sum(float(self.weights[k]) for k in keys)
        if total <= 0:
            return {}
        return {k: float(self.weights[k]) / total for k in keys}

    def max_effective_credit(self) -> float:
        """The largest share of the composite the credit can actually remove.

        Published rather than left to be discovered by subtraction: against the
        Appendix B weights this is 0.15 × 31.58% ≈ 4.7 points, not 15.
        """
        norm = self.normalized()
        return self.max_control_credit * sum(norm.get(k, 0.0) for k in self.creditable)

    @property
    def version(self) -> str:
        """Short digest of everything that decides a score.

        OW2-CC-004 requires that a recalculation be flagged with the model version
        used. Deriving the version from the model's own content rather than from a
        hand-maintained integer means an administrator cannot retune a weight and
        leave the version behind — every score carries proof of which model
        produced it.
        """
        canonical = json.dumps({
            "weights": {k: float(self.weights[k]) for k in sorted(self.weights)},
            "max_control_credit": round(float(self.max_control_credit), 6),
            "creditable": sorted(self.creditable),
            "bands": [[g, float(t)] for g, t in self.bands],
            "min_weight_coverage": round(float(self.min_weight_coverage), 6),
        }, sort_keys=True, separators=(",", ":"))
        return "m" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]

    def band(self, posture: float) -> str:
        for grade, floor in self.bands:
            if posture >= floor:
                return grade
        return self.bands[-1][0]

    def methodology(self) -> dict:
        """The published methodology document OW2-CC-003 requires.

        Exported as data rather than prose so the UI, the PDF and the API render
        the same model and cannot drift apart.
        """
        norm = self.normalized()
        return {
            "label": self.label,
            "model_version": self.version,
            "direction": ("risk: 0-100, higher is worse. posture = 100 - risk, "
                          "higher is better. The letter grade bands the POSTURE."),
            "factors": [
                {
                    "key": k,
                    "label": FACTOR_LABELS[k],
                    "inputs": FACTOR_INPUTS[k],
                    "weight_declared": float(self.weights[k]),
                    "weight_normalised_pct": round(100.0 * norm.get(k, 0.0), 2),
                }
                for k in FACTOR_KEYS if k in self.weights
            ],
            "declared_weight_total": round(sum(float(v) for v in self.weights.values()), 4),
            "normalisation": (
                "Declared weights are relative, not percentages: they are normalised "
                "to sum to 1.0 before use. Appendix B as drafted sums to 95, which is "
                "why this is done by the engine rather than by hand."),
            "compensating_controls": {
                "instrument": ("bounded multiplier applied ONLY to the creditable "
                               "factors, never to the composite"),
                "creditable_factors": [FACTOR_LABELS[k] for k in self.creditable],
                "not_creditable": [FACTOR_LABELS[k] for k in FACTOR_KEYS
                                   if k not in self.creditable],
                "max_credit_pct": round(100.0 * self.max_control_credit, 2),
                "max_effective_credit_points": round(
                    100.0 * self.max_effective_credit(), 2),
                "rationale": (
                    "Detection and containment reduce the risk carried by a "
                    "population of open findings. They do not make an asset less "
                    "reachable, a CVE less exploited in the wild, a database less "
                    "valuable, or a remediation trend less bad. Appendix B's 15 "
                    "points were attached to the wrong instrument; the effective "
                    "ceiling above is what a control can actually remove."),
                "gate": ("Credit is withheld entirely when the exposure gate is "
                         "tripped, and also when no gate verdict was supplied — an "
                         "unevaluated exposure is not a cleared one."),
            },
            "bands": [{"grade": g, "min_posture": t} for g, t in self.bands],
            "unavailable_factors": (
                "A factor with no data is excluded and its weight redistributed "
                "across the factors that have data; it is never scored 0.0, which "
                "would lower the risk of an estate that was not measured. Below "
                "%.0f%% weight coverage the score is refused."
                % (100.0 * self.min_weight_coverage)),
        }


@dataclass(frozen=True)
class FactorValue:
    """One factor's normalised value in [0, 1], or None when it could not be
    evaluated. ``basis`` records how the value was derived (OW2-DR-002 lineage);
    ``reason`` is required when the value is None."""

    key: str
    value: Optional[float]
    basis: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if self.key not in FACTOR_KEYS:
            raise ValueError("unknown risk factor %r" % (self.key,))
        if self.value is None:
            if not self.reason:
                raise ValueError(
                    "factor %r has no value and no reason; an unmeasured factor must "
                    "say why, or it is indistinguishable from a measured zero"
                    % (self.key,))
        else:
            v = float(self.value)
            if not (0.0 <= v <= 1.0):
                raise ValueError(
                    "factor %r is %r; values must be normalised to [0, 1] before "
                    "scoring so the weight set is the only thing deciding influence"
                    % (self.key, self.value))
            object.__setattr__(self, "value", v)

    @property
    def available(self) -> bool:
        return self.value is not None


@dataclass(frozen=True)
class Contribution:
    key: str
    label: str
    value: float
    weight_used: float          # normalised over available factors
    points: float               # weight_used * value * 100, pre-credit

    @property
    def pct_of_risk(self) -> float:
        return round(self.points, 2)


@dataclass(frozen=True)
class RiskScore:
    """A scored scope, carrying enough to be recomputed and argued with."""

    scope: str
    scope_id: str
    model_version: str
    risk: Optional[int]
    posture: Optional[int]
    grade: Optional[str]
    contributions: Tuple[Contribution, ...] = ()
    raw_risk: float = 0.0
    control_credit: float = 0.0
    credit_gated: bool = False
    gate_reason: str = ""
    excluded: Tuple[Tuple[str, str], ...] = ()
    credited_factors: Tuple[str, ...] = ()
    weight_coverage: float = 1.0
    refused: bool = False
    refusal_reason: str = ""

    @property
    def complete(self) -> bool:
        return not self.refused and not self.excluded

    def caveat(self) -> str:
        """The sentence that must travel with the number. Never silently empty
        when something was excluded."""
        if self.refused:
            return self.refusal_reason
        bits: List[str] = []
        if self.excluded:
            names = ", ".join(FACTOR_LABELS[k].lower() for k, _ in self.excluded)
            bits.append(
                "Scored on %.0f%% of the model: %s could not be evaluated, and %s "
                "weight was redistributed across the remaining factors rather than "
                "counted as zero risk."
                % (100.0 * self.weight_coverage, names,
                   "its" if len(self.excluded) == 1 else "their"))
        if self.credit_gated:
            bits.append("Compensating-control credit withheld — %s." % self.gate_reason)
        elif self.control_credit and self.credited_factors:
            names = ", ".join(FACTOR_LABELS[k].lower() for k in self.credited_factors)
            bits.append(
                "Compensating controls reduced %s by %.1f%%, removing %.1f points. "
                "Exposure, exploitability and asset criticality are not creditable — "
                "a control changes how fast a compromise is caught, not how "
                "reachable the asset is."
                % (names, 100.0 * self.control_credit, self.credit_points))
        return " ".join(bits)

    @property
    def credit_points(self) -> float:
        """Points the credit actually removed. Never inferred from the ceiling."""
        creditable = set(self.credited_factors)
        return round(sum(c.points for c in self.contributions
                         if c.key in creditable) * self.control_credit, 2)

    def to_dict(self) -> dict:
        return {
            "scope": self.scope, "scope_id": self.scope_id,
            "model_version": self.model_version,
            "risk": self.risk, "posture": self.posture, "grade": self.grade,
            "raw_risk": round(self.raw_risk, 2),
            "control_credit_pct": round(100.0 * self.control_credit, 2),
            "credit_points_removed": self.credit_points,
            "credited_factors": list(self.credited_factors),
            "credit_gated": self.credit_gated, "gate_reason": self.gate_reason,
            "weight_coverage_pct": round(100.0 * self.weight_coverage, 2),
            "excluded": [{"factor": k, "reason": r} for k, r in self.excluded],
            "contributions": [
                {"factor": c.key, "label": c.label, "value": round(c.value, 4),
                 "weight_used_pct": round(100.0 * c.weight_used, 2),
                 "points": round(c.points, 2)}
                for c in self.contributions
            ],
            "refused": self.refused,
            "caveat": self.caveat(),
        }


def score(
    factors: Sequence[FactorValue],
    model: Optional[RiskModel] = None,
    *,
    scope: str = "estate",
    scope_id: str = "",
    control_credit: float = 0.0,
    exposure_gate: Optional[ExposureGate] = None,
) -> RiskScore:
    """Compute the composite Cloud Risk Score for one scope.

    ``control_credit`` is a fraction in [0, 1] describing compensating-control
    coverage; it is clamped to the model ceiling and zeroed by a tripped gate.
    """
    model = model or RiskModel()
    if scope not in SCOPES:
        raise ValueError("scope must be one of %s" % ", ".join(SCOPES))

    seen: Dict[str, FactorValue] = {}
    for f in factors:
        if f.key in seen:
            raise ValueError("factor %r supplied twice" % (f.key,))
        seen[f.key] = f

    # A factor the model weights but the caller never mentioned is missing data,
    # not an implicit zero — the same rule as an explicitly unavailable one.
    excluded: List[Tuple[str, str]] = []
    available: List[str] = []
    for k in FACTOR_KEYS:
        if k not in model.weights:
            continue
        fv = seen.get(k)
        if fv is None:
            excluded.append((k, "not supplied to the scoring call"))
        elif not fv.available:
            excluded.append((k, fv.reason))
        else:
            available.append(k)

    full = model.normalized()
    coverage = sum(full.get(k, 0.0) for k in available)

    if not available or coverage < model.min_weight_coverage:
        return RiskScore(
            scope=scope, scope_id=scope_id, model_version=model.version,
            risk=None, posture=None, grade=None,
            excluded=tuple(excluded), weight_coverage=round(coverage, 6),
            refused=True,
            refusal_reason="%s Weight coverage was %.0f%%, below the %.0f%% floor."
                           % (REFUSED_INSUFFICIENT, 100.0 * coverage,
                              100.0 * model.min_weight_coverage))

    used = model.normalized(over=available)
    contributions = tuple(
        Contribution(k, FACTOR_LABELS[k], float(seen[k].value), used[k],
                     used[k] * float(seen[k].value) * 100.0)
        for k in FACTOR_KEYS if k in used
    )
    raw = sum(c.points for c in contributions)

    # Credit resolution. Two independent guards, and BOTH default to withholding:
    # a missing gate verdict is not a clearance, and a non-creditable factor is
    # never reduced no matter what the gate says.
    credit = max(0.0, min(float(control_credit), model.max_control_credit))
    gated = False
    gate_reason = ""
    if exposure_gate is None:
        if credit > 0.0:
            gated, gate_reason, credit = True, NO_GATE_VERDICT, 0.0
    elif exposure_gate.tripped:
        gated, gate_reason, credit = True, exposure_gate.reason, 0.0

    # The principled half of the D2 fix: the multiplier touches only the factors a
    # control can legitimately modulate. Exposure is never among them, so no volume
    # of tooling moves the exposure share of the score.
    creditable = set(model.creditable)
    risk_f = sum(c.points * (1.0 - credit) if c.key in creditable else c.points
                 for c in contributions)
    risk_f = max(0.0, min(100.0, risk_f))
    risk = int(round(risk_f))
    posture = 100 - risk

    return RiskScore(
        scope=scope, scope_id=scope_id, model_version=model.version,
        risk=risk, posture=posture, grade=model.band(float(posture)),
        contributions=contributions, raw_risk=raw,
        control_credit=credit, credit_gated=gated,
        gate_reason=gate_reason, excluded=tuple(excluded),
        credited_factors=tuple(k for k in model.creditable if k in used),
        weight_coverage=round(coverage, 6))


def drivers(result: RiskScore, top: int = 3) -> Tuple[Contribution, ...]:
    """The factors carrying the score, largest first.

    OW2-PA-003 forbids black-box numbers without drivers. The same rule is worth
    applying to the score itself and not only to the forecast: a composite nobody
    can decompose is a number an owner cannot act on.
    """
    return tuple(sorted(result.contributions, key=lambda c: -c.points)[:max(0, top)])


def explain(result: RiskScore) -> str:
    """One paragraph an executive tile can render on hover (OW2-UI-002)."""
    if result.refused:
        return result.caveat()
    top = drivers(result, 2)
    lead = ("Risk %d of 100 (posture %d, grade %s) under model %s."
            % (result.risk, result.posture, result.grade, result.model_version))
    if top:
        lead += " Driven mainly by %s." % " and ".join(
            "%s at %.0f of %.0f available points"
            % (c.label.lower(), c.points, c.weight_used * 100.0) for c in top)
    tail = result.caveat()
    return (lead + " " + tail).strip()
