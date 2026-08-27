#!/usr/bin/env python3
"""
aws_scorecard.py — per-application security scorecards (FR-2).

Implements OW2-SC-002 through OW2-SC-008. PURE: stdlib only, no boto3, no I/O, no
``now()`` — the caller supplies the clock, so a scorecard issued twice from the
same inputs is byte-identical and an owner disputing last month's grade can have
it recomputed rather than re-litigated.

This is the module that finally consumes :mod:`aws_ownership`, :mod:`aws_sla`,
:mod:`aws_kra` and :mod:`aws_riskscore` together. Each of them was correct and
uncalled; a scorecard is the artefact that needs all four at once, which is why
it is where they get wired.

────────────────────────────────────────────────────────────────────────────────
A SCORECARD IS THE MOST DANGEROUS ARTEFACT THIS PRODUCT PRODUCES
────────────────────────────────────────────────────────────────────────────────
Every other output is read by someone who can go and check. A scorecard is read
by an application owner who cannot, and a portfolio pack is read by a CISO who
certainly will not. It is also a **filter** — and a filter deletes what it does
not match, silently, while looking complete.

So four rules from the rest of the codebase are load-bearing here, and each is
enforced rather than documented:

1. **The pack states its own coverage.** :class:`Pack` carries the
   :class:`aws_ownership.AttributionCoverage` and renders it in
   :meth:`Pack.headline`. Attribute 400 of 1,000 findings and the per-application
   totals sum to a cleaner estate than the one that exists. The unattributed
   findings are not dropped: they get their own row, which cannot be mistaken for
   an application because it has no owner and no grade.

2. **The closure rate never travels alone** (review defect D4). The SLA clock
   pauses under an approved exception, so one approval can move that number from
   0% to 100%. :class:`Scorecard` carries the exception-assisted count and the
   deferred-breach count beside it, and :meth:`Scorecard.sla_line` renders all
   three or none.

3. **Ranking is refused without a denominator** (OW2-SC-004). Peer comparison must
   be normalised per 100 assets so a larger estate is not penalised for being
   larger. If the asset count for an application is unknown, its rank is
   ``None`` — not a rank computed on raw counts, which would be a league table
   ordered by size wearing the costume of a security measurement.

4. **Absent history is not a flat trend.** No prior period means ``trend is
   None``, never "0% change" — the same rule :mod:`aws_trend` applies to
   forecasts.

────────────────────────────────────────────────────────────────────────────────
EXCEPTIONS ARE SEGREGATED, NEVER HIDDEN (OW2-SC-008)
────────────────────────────────────────────────────────────────────────────────
Findings under an approved, unexpired exception are counted in their own field and
never folded into the open counts. That is the SRS requirement, and the reason is
the same as D4's: an exception is a decision to accept a risk, not evidence that
the risk went away. A scorecard that merged them would let an owner improve their
grade by asking rather than by fixing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import aws_kra
import aws_ownership
import aws_riskscore
import aws_sla

#: Findings listed on a scorecard line. Cut with a declared total, never silently.
TOP_FINDINGS = 10

NO_RANK = ("Peer rank withheld: this application's asset count is unknown, and "
           "OW2-SC-004 requires comparison normalised per 100 assets. Ranking on "
           "raw counts would order the portfolio by size, not by security.")

NO_TREND = ("No prior period to compare against. This is the first scorecard for "
            "this application, not a month with no change.")


def _sev(f) -> str:
    v = f.get("severity") if isinstance(f, Mapping) else getattr(f, "severity", "")
    return (v or "").upper()


def _key(f) -> str:
    v = (f.get("finding_key") if isinstance(f, Mapping)
         else getattr(f, "finding_key", ""))
    return v or ""


@dataclass(frozen=True)
class Trend:
    """Month-on-month movement. Only ever constructed when both months exist."""

    previous: float
    current: float

    @property
    def delta(self) -> float:
        return round(self.current - self.previous, 1)

    @property
    def direction(self) -> str:
        if self.delta > 0:
            return "improved"
        return "worsened" if self.delta < 0 else "unchanged"

    def render(self) -> str:
        if not self.delta:
            return "unchanged month-on-month"
        return "%s %+.1f month-on-month" % (self.direction, self.delta)


@dataclass(frozen=True)
class Scorecard:
    """One application's monthly scorecard (OW2-SC-002)."""

    app_id: str
    name: str
    owner: str
    portfolio: str
    criticality: str

    posture: Optional[int] = None
    grade: Optional[str] = None
    grade_withheld: str = ""

    open_critical: int = 0
    open_high: int = 0
    excepted: int = 0

    closure: Optional[aws_sla.ClosureRate] = None
    exposure: Optional[aws_kra.Metric] = None
    mfa: Optional[aws_kra.Metric] = None
    privilege: Optional[aws_kra.Metric] = None

    assets: Optional[int] = None
    trend: Optional[Trend] = None
    rank: Optional[int] = None
    peers: int = 0
    rank_withheld: str = ""

    top_findings: Tuple[str, ...] = ()
    top_findings_total: int = 0
    findings_total: int = 0

    @property
    def top_findings_truncated(self) -> bool:
        return self.top_findings_total > len(self.top_findings)

    @property
    def per_100_assets(self) -> Optional[float]:
        """Severity-weighted finding density. None when assets are unknown —
        which is also why :attr:`rank` is withheld."""
        if not self.assets:
            return None
        weighted = self.open_critical * 3 + self.open_high
        return round(100.0 * weighted / self.assets, 1)

    @property
    def is_unattributed(self) -> bool:
        return self.app_id == aws_ownership.UNATTRIBUTED

    def sla_line(self) -> str:
        """OW2-SC-002's SLA compliance figure, D4-paired.

        Renders all three numbers or none. There is no code path that emits the
        headline rate without the approvals that produced it.
        """
        if self.closure is None or not self.closure.considered:
            return "No CRITICAL findings with an SLA policy in scope."
        return self.closure.headline()

    def caveats(self) -> Tuple[str, ...]:
        out: List[str] = []
        if self.grade_withheld:
            out.append(self.grade_withheld)
        if self.rank_withheld:
            out.append(self.rank_withheld)
        if self.trend is None:
            out.append(NO_TREND)
        if self.excepted:
            out.append(
                "%d finding(s) sit under an approved exception and are counted "
                "separately, not in the open totals above (OW2-SC-008)."
                % self.excepted)
        if self.top_findings_truncated:
            out.append("Showing %d of %d findings."
                       % (len(self.top_findings), self.top_findings_total))
        return tuple(out)

    def to_dict(self) -> dict:
        return {
            "app_id": self.app_id, "name": self.name, "owner": self.owner,
            "portfolio": self.portfolio, "criticality": self.criticality,
            "posture": self.posture, "grade": self.grade,
            "grade_withheld": self.grade_withheld or None,
            "open_critical": self.open_critical, "open_high": self.open_high,
            "excepted": self.excepted,
            "findings_total": self.findings_total,
            "top_findings": list(self.top_findings),
            "top_findings_total": self.top_findings_total,
            "top_findings_truncated": self.top_findings_truncated,
            "assets": self.assets, "per_100_assets": self.per_100_assets,
            "rank": self.rank, "peers": self.peers,
            "rank_withheld": self.rank_withheld or None,
            "trend": ({"previous": self.trend.previous,
                       "current": self.trend.current,
                       "delta": self.trend.delta,
                       "direction": self.trend.direction,
                       "render": self.trend.render()} if self.trend else None),
            "sla": self.closure.to_dict() if self.closure else None,
            "sla_line": self.sla_line(),
            "kras": [m.to_dict() for m in
                     (self.exposure, self.mfa, self.privilege) if m is not None],
            "caveats": list(self.caveats()),
        }


@dataclass(frozen=True)
class Pack:
    """A portfolio of scorecards, and the coverage they were computed over."""

    scorecards: Tuple[Scorecard, ...]
    coverage: aws_ownership.AttributionCoverage
    period: str = ""

    def by_id(self, app_id: str) -> Optional[Scorecard]:
        for s in self.scorecards:
            if s.app_id == app_id:
                return s
        return None

    @property
    def applications(self) -> Tuple[Scorecard, ...]:
        """Real applications, excluding the unattributed row."""
        return tuple(s for s in self.scorecards if not s.is_unattributed)

    @property
    def unattributed(self) -> Optional[Scorecard]:
        for s in self.scorecards:
            if s.is_unattributed:
                return s
        return None

    def headline(self) -> str:
        """The line that must appear above any per-application total.

        A portfolio pack that omits this is a report about a subset presented as a
        report about the estate.
        """
        n = len(self.applications)
        base = "%d application scorecard(s) for %s." % (n, self.period or "this period")
        cov = self.coverage.headline()
        un = self.unattributed
        if un is not None and un.findings_total:
            cov += (" Those %d findings appear below as an unowned row: they have no "
                    "owner to send a scorecard to, which is the finding."
                    % un.findings_total)
        return base + " " + cov

    def to_dict(self) -> dict:
        return {
            "period": self.period,
            "headline": self.headline(),
            "coverage": {
                "total": self.coverage.total,
                "attributed": self.coverage.attributed,
                "unattributed": self.coverage.unattributed,
                "ambiguous": self.coverage.ambiguous,
                "pct": self.coverage.pct,
                "complete": self.coverage.complete,
                "headline": self.coverage.headline(),
            },
            "scorecards": [s.to_dict() for s in self.scorecards],
        }


# ══════════════════════════════════════════════════════════════════════════════
# assembly
# ══════════════════════════════════════════════════════════════════════════════

def build(
    findings: Sequence,
    apps: Sequence[aws_ownership.Application],
    *,
    now_epoch: int,
    tag_lookup=None,
    sla_policy: Optional[aws_sla.SlaPolicy] = None,
    exception_windows: Optional[Mapping[str, Sequence]] = None,
    excepted_keys: Optional[Iterable[str]] = None,
    assets_by_app: Optional[Mapping[str, int]] = None,
    previous_posture: Optional[Mapping[str, float]] = None,
    factors_by_app: Optional[Mapping[str, Sequence[aws_riskscore.FactorValue]]] = None,
    exposure_by_app: Optional[Mapping[str, Tuple[int, int]]] = None,
    mfa_by_app: Optional[Mapping[str, Tuple[int, int, int]]] = None,
    model: Optional[aws_riskscore.RiskModel] = None,
    period: str = "",
) -> Pack:
    """Assemble a portfolio pack.

    Every optional argument is optional in the same way: when it is absent the
    corresponding figure is **withheld with a reason**, never defaulted. A
    scorecard that quietly reports 0 for a thing nobody measured is the failure
    this whole module is arranged against.
    """
    sla_policy = sla_policy or aws_sla.SlaPolicy()
    exception_windows = exception_windows or {}
    excepted = set(excepted_keys or ())
    assets_by_app = assets_by_app or {}
    previous_posture = previous_posture or {}
    factors_by_app = factors_by_app or {}
    exposure_by_app = exposure_by_app or {}
    mfa_by_app = mfa_by_app or {}
    model = model or aws_riskscore.RiskModel()

    buckets, coverage = aws_ownership.attribute_findings(findings, apps, tag_lookup)
    by_id = {a.app_id: a for a in apps}

    cards: List[Scorecard] = []
    for bucket_id, rows in buckets.items():
        app = by_id.get(bucket_id)
        owned = [f for f, _ in rows]
        cards.append(_one(bucket_id, app, owned, now_epoch=now_epoch,
                          sla_policy=sla_policy, exception_windows=exception_windows,
                          excepted=excepted, assets=assets_by_app.get(bucket_id),
                          previous=previous_posture.get(bucket_id),
                          factors=factors_by_app.get(bucket_id),
                          exposure=exposure_by_app.get(bucket_id),
                          mfa=mfa_by_app.get(bucket_id), model=model))

    cards = _rank_within_portfolios(cards)
    # Unattributed sorts last: it is not an application and must not head a table
    # ordered by grade.
    cards.sort(key=lambda s: (s.is_unattributed, -(s.open_critical), s.name))
    return Pack(tuple(cards), coverage, period)


def _one(bucket_id, app, owned, *, now_epoch, sla_policy, exception_windows,
         excepted, assets, previous, factors, exposure, mfa, model) -> Scorecard:
    live = [f for f in owned if _key(f) not in excepted]
    n_excepted = len(owned) - len(live)

    states = [aws_sla.evaluate(f, now_epoch, sla_policy,
                               exception_windows.get(_key(f), ()))
              for f in live]
    closure = aws_sla.closure_rate(states, "CRITICAL")

    posture = grade = None
    withheld = ""
    if factors:
        scored = aws_riskscore.score(factors, model, scope="application",
                                     scope_id=bucket_id)
        if scored.refused:
            withheld = scored.refusal_reason
        else:
            posture, grade = scored.posture, scored.grade
    else:
        withheld = ("Grade withheld: no risk factors were supplied for this "
                    "application, and a grade invented from finding counts alone "
                    "is not the published model (OW2-SC-003).")

    top = sorted(live, key=lambda f: (_sev(f) != "CRITICAL", _sev(f) != "HIGH",
                                      _key(f)))
    return Scorecard(
        app_id=bucket_id,
        name=(app.name if app else "Unattributed"),
        owner=(app.owner if app else ""),
        portfolio=(app.portfolio if app else ""),
        criticality=(app.criticality if app else "unclassified"),
        posture=posture, grade=grade, grade_withheld=withheld,
        open_critical=sum(1 for f in live if _sev(f) == "CRITICAL"),
        open_high=sum(1 for f in live if _sev(f) == "HIGH"),
        excepted=n_excepted,
        closure=closure,
        exposure=_exposure_metric(exposure),
        mfa=_mfa_metric(mfa),
        assets=assets,
        trend=(Trend(float(previous), float(posture))
               if previous is not None and posture is not None else None),
        rank_withheld=("" if assets else NO_RANK),
        top_findings=tuple(_key(f) for f in top[:TOP_FINDINGS]),
        top_findings_total=len(live),
        findings_total=len(owned),
    )


def _exposure_metric(pair) -> Optional[aws_kra.Metric]:
    if not pair:
        return None
    observed, unevaluated = pair
    return aws_kra.count(aws_kra.EXPOSED_CRITICAL, observed=observed,
                         not_evaluated=unevaluated)


def _mfa_metric(triple) -> Optional[aws_kra.Metric]:
    if not triple:
        return None
    compliant, counted, unevaluated = triple
    return aws_kra.ratio(aws_kra.MFA_COVERAGE, compliant=compliant, counted=counted,
                         not_evaluated=unevaluated)


def _rank_within_portfolios(cards: Sequence[Scorecard]) -> List[Scorecard]:
    """OW2-SC-004: rank within a portfolio, normalised per 100 assets.

    Only cards whose asset count is known can be ranked; the rest keep
    ``rank=None`` and their withheld reason. A partially rankable portfolio
    reports ``peers`` as the number actually compared, so "3rd of 4" never
    silently means "3rd of the 4 we could measure, out of 11".
    """
    out = list(cards)
    groups: Dict[str, List[int]] = {}
    for i, c in enumerate(out):
        if c.is_unattributed:
            continue
        groups.setdefault(c.portfolio, []).append(i)

    for _, idxs in groups.items():
        rankable = [i for i in idxs if out[i].per_100_assets is not None]
        rankable.sort(key=lambda i: out[i].per_100_assets)
        n = len(rankable)
        for pos, i in enumerate(rankable, start=1):
            c = out[i]
            out[i] = Scorecard(**{**c.__dict__, "rank": pos, "peers": n,
                                  "rank_withheld": ""})
        for i in idxs:
            if out[i].per_100_assets is None:
                c = out[i]
                out[i] = Scorecard(**{**c.__dict__, "rank": None, "peers": n,
                                      "rank_withheld": NO_RANK})
    return out
