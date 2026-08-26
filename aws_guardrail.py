#!/usr/bin/env python3
"""
aws_guardrail.py — what a blocking CI/CD gate does when it cannot evaluate.

Implements the decision layer for FR-5 (OW2-GR-003 enforcement modes, OW2-GR-004
the latency budget, OW2-GR-005 the central record and override justification) and
fixes review defect D5.

PURE: stdlib only, no boto3, no I/O, no ``now()`` — the caller supplies the clock,
so a verdict is reproducible and an auditor can recompute one from its record.

────────────────────────────────────────────────────────────────────────────────
THE DEFECT (review finding D5)
────────────────────────────────────────────────────────────────────────────────
OW2-GR-003 defaults production to **block** after a bake-in period. OW2-IF-001
protects *scanning* from connector failure — "connector failure shall never block
scanning" — and says nothing at all about the pipeline gate. So when the policy
evaluation service is unreachable, the specification supports both of:

* **fail closed** — every production deploy halts, including the deploy that fixes
  the outage that caused it. The gate becomes the incident.
* **fail open** — the control is silently disabled across the entire estate while
  every pipeline shows a green check. Nobody finds out until an audit.

Neither is acceptable *undeclared*, and a guardrail whose failure mode is
undeclared is discovered during an incident, by the people least able to reason
about it at the time.

────────────────────────────────────────────────────────────────────────────────
THE RULE
────────────────────────────────────────────────────────────────────────────────
**An evaluation that did not happen is never an allow.** Every path that permits a
deploy without a completed evaluation is either

* a *degraded allow*, because the strictest applicable mode was audit — recorded,
  exit code 2, never rendered as a pass; or
* an *override*, which is attributed, justified, time-boxed and separately
  reported under OW2-GR-005.

There is no third path, and :func:`decide` has no argument that produces a clean
pass from an incomplete evaluation. The invariant is tested directly:
``action == ALLOW and not degraded and not is_override`` implies the outcome was
``EVALUATED``.

**An unavailable gate does what its strictest configured mode would have done.**
Blocking everything is the brutal reading of fail-closed and it is not what the
enforcement modes say: a policy in audit mode never blocks, so an unreachable
service must not start blocking on its behalf. Deriving the failure action from
the configured mode means losing the service cannot silently *downgrade*
enforcement, and cannot silently *escalate* it either.

**Break-glass exists because fail-closed without it is unusable.** The deploy that
fixes the outage has to be able to ship. So the override is a real, supported path
— and it is expensive on purpose: an actor, a justification, an expiry, and a line
in the weekly report to ISD.

────────────────────────────────────────────────────────────────────────────────
ON THE LATENCY BUDGET (OW2-GR-004)
────────────────────────────────────────────────────────────────────────────────
The review's first phrasing was that exceeding the 120-second budget should make
the result "explicitly an override, never a pass". That is right for the case that
matters and wrong as a general rule, so it is implemented more precisely:

* The pipeline **gave up waiting** and has no result → ``TIMEOUT``, treated exactly
  like ``UNAVAILABLE``. This is the case that matters: a pipeline must never read
  its own timeout as a pass, which is the single easiest way to disable the whole
  control with a one-line change to a CI config.
* A complete evaluation **arrived late** → it is honoured on its merits, because
  ignoring a real BLOCK because it was slow would be worse. The budget breach is
  recorded via :attr:`Verdict.budget_exceeded` so OW2-GR-004 stays measurable
  rather than aspirational.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ── enforcement modes (OW2-GR-003) ───────────────────────────────────────────
BLOCK = "block"
WARN = "warn"
AUDIT = "audit"
MODES = (BLOCK, WARN, AUDIT)
_MODE_RANK = {BLOCK: 3, WARN: 2, AUDIT: 1}

# ── what happened to the evaluation ──────────────────────────────────────────
EVALUATED = "evaluated"
UNAVAILABLE = "unavailable"
TIMEOUT = "timeout"
PARTIAL = "partial"
OUTCOMES = (EVALUATED, UNAVAILABLE, TIMEOUT, PARTIAL)

#: Outcomes in which the gate did NOT establish that the change is compliant.
INCOMPLETE = (UNAVAILABLE, TIMEOUT, PARTIAL)

# ── what the pipeline does ───────────────────────────────────────────────────
ALLOW = "allow"
WARN_ACTION = "warn"
BLOCK_ACTION = "block"
ACTIONS = (ALLOW, WARN_ACTION, BLOCK_ACTION)

# ── exit codes, mirroring scripts/overwatch_evidence.py ──────────────────────
#: 0 proceed, the gate evaluated and nothing blocking was found (warnings allowed)
EXIT_OK = 0
#: 1 do not proceed
EXIT_BLOCKED = 1
#: 2 proceeding WITHOUT a completed evaluation — override, or degraded audit mode.
#: Distinct from 0 so a pipeline that wants strictness can fail on it, and so the
#: weekly OW2-GR-005 report can count them without parsing prose.
EXIT_UNVERIFIED = 2

DEFAULT_BUDGET_MS = 120_000
"""OW2-GR-004: pipeline verdicts shall return within 120 seconds."""

MIN_JUSTIFICATION = 20
"""Characters. "temp" and "fix" are not justifications, and a field that accepts
them produces an audit trail that is worse than none because it looks complete."""


@dataclass(frozen=True)
class Policy:
    """One guardrail policy and its per-environment enforcement mode."""

    id: str
    title: str
    modes: Mapping[str, str] = field(default_factory=dict)
    default_mode: str = AUDIT
    severity: str = "HIGH"

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("policy id is required")
        bad = {e: m for e, m in dict(self.modes).items() if m not in MODES}
        if bad:
            raise ValueError("policy %s has unknown mode(s) %r; expected one of %s"
                             % (self.id, bad, ", ".join(MODES)))
        if self.default_mode not in MODES:
            raise ValueError("default_mode must be one of %s" % ", ".join(MODES))
        object.__setattr__(self, "modes", dict(self.modes))

    def mode(self, env: str) -> str:
        return self.modes.get(env, self.default_mode)


@dataclass(frozen=True)
class Violation:
    policy_id: str
    resource: str
    detail: str = ""


@dataclass(frozen=True)
class Evaluation:
    """The raw result of asking the policy engine, including not getting one."""

    outcome: str
    violations: Tuple[Violation, ...] = ()
    evaluated_policy_ids: Tuple[str, ...] = ()
    errors: Mapping[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0
    detail: str = ""

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError("outcome must be one of %s" % ", ".join(OUTCOMES))
        if self.outcome in INCOMPLETE and not self.detail:
            raise ValueError(
                "outcome %r must carry a detail saying what went wrong; a gate that "
                "cannot explain why it did not evaluate cannot be acted on by the "
                "engineer whose deploy it just stopped" % (self.outcome,))
        object.__setattr__(self, "errors", dict(self.errors))


@dataclass(frozen=True)
class BreakGlass:
    """An attributed, justified, time-boxed override (OW2-GR-005).

    Expensive on purpose. Fail-closed without a usable override is unusable — the
    deploy that fixes the outage has to ship — but an override that is cheap stops
    being an exception and becomes the path of least resistance.
    """

    actor: str
    justification: str
    expires_epoch: int
    ticket: str = ""

    def __post_init__(self) -> None:
        if not (self.actor or "").strip():
            raise ValueError("break-glass requires an actor; an unattributed "
                             "override cannot be reviewed by anyone")
        just = (self.justification or "").strip()
        if len(just) < MIN_JUSTIFICATION:
            raise ValueError(
                "break-glass justification must be at least %d characters; a field "
                "that accepts 'temp' yields an audit trail that looks complete and "
                "says nothing" % MIN_JUSTIFICATION)
        if not self.expires_epoch:
            raise ValueError(
                "break-glass requires an expiry; an override without one is a "
                "permanent policy change made during an incident")

    def valid_at(self, now_epoch: int) -> bool:
        return int(now_epoch) < int(self.expires_epoch)


@dataclass(frozen=True)
class Verdict:
    """What the pipeline does, and everything the record needs to say why."""

    action: str
    outcome: str
    reason: str
    env: str
    violations: Tuple[Violation, ...] = ()
    unevaluated: Tuple[str, ...] = ()
    is_override: bool = False
    override: Optional[BreakGlass] = None
    degraded: bool = False
    budget_exceeded: bool = False
    elapsed_ms: int = 0
    override_rejected: str = ""

    @property
    def exit_code(self) -> int:
        if self.action == BLOCK_ACTION:
            return EXIT_BLOCKED
        if self.is_override or self.degraded:
            return EXIT_UNVERIFIED
        return EXIT_OK

    @property
    def verified(self) -> bool:
        """True only when the gate actually established compliance. The property a
        dashboard should colour on, rather than on ``action == ALLOW``."""
        return self.outcome == EVALUATED and not self.is_override

    def headline(self) -> str:
        if self.action == BLOCK_ACTION:
            return "BLOCKED — %s" % self.reason
        if self.is_override:
            return ("ALLOWED UNDER OVERRIDE — the gate did not clear this change. %s"
                    % self.reason)
        if self.degraded:
            return ("ALLOWED WITHOUT EVALUATION — %s. This is not a pass; no policy "
                    "was checked against this change." % self.reason)
        if self.action == WARN_ACTION:
            return "ALLOWED WITH WARNINGS — %s" % self.reason
        return "PASSED — %s" % self.reason

    def audit_record(self) -> dict:
        """The central record OW2-GR-005 requires for every evaluation."""
        return {
            "action": self.action,
            "outcome": self.outcome,
            "environment": self.env,
            "verified": self.verified,
            "exit_code": self.exit_code,
            "reason": self.reason,
            "violations": [{"policy": v.policy_id, "resource": v.resource,
                            "detail": v.detail} for v in self.violations],
            "unevaluated_policies": list(self.unevaluated),
            "degraded": self.degraded,
            "budget_exceeded": self.budget_exceeded,
            "elapsed_ms": self.elapsed_ms,
            "override": ({"actor": self.override.actor,
                          "justification": self.override.justification,
                          "expires_epoch": self.override.expires_epoch,
                          "ticket": self.override.ticket}
                         if self.is_override and self.override else None),
            "override_rejected": self.override_rejected or None,
            "headline": self.headline(),
        }


def _strictest(policies: Iterable[Policy], env: str) -> str:
    rank = 0
    mode = AUDIT
    for p in policies:
        m = p.mode(env)
        if _MODE_RANK[m] > rank:
            rank, mode = _MODE_RANK[m], m
    return mode


def _action_for(mode: str) -> str:
    return {BLOCK: BLOCK_ACTION, WARN: WARN_ACTION, AUDIT: ALLOW}[mode]


def decide(
    evaluation: Evaluation,
    policies: Sequence[Policy],
    env: str,
    *,
    now_epoch: int = 0,
    break_glass: Optional[BreakGlass] = None,
    budget_ms: int = DEFAULT_BUDGET_MS,
) -> Verdict:
    """Turn an evaluation — including a failed one — into a pipeline verdict.

    ``policies`` is the full declared set for this change, so the policies that did
    NOT report can be named. A gate that cannot say which policies it failed to run
    cannot tell an engineer what risk they are accepting.
    """
    declared = {p.id: p for p in policies}
    ran = set(evaluation.evaluated_policy_ids)
    unevaluated = tuple(sorted(set(declared) - ran))
    budget_exceeded = bool(budget_ms) and evaluation.elapsed_ms > budget_ms

    outcome = evaluation.outcome
    # A completed evaluation that names fewer policies than were declared is
    # PARTIAL whatever the caller claimed — silence about a policy is not a pass
    # for it, and this is the case a caller is most likely to get wrong.
    if outcome == EVALUATED and unevaluated:
        outcome = PARTIAL

    if outcome == EVALUATED:
        return _decide_evaluated(evaluation, declared, env, budget_exceeded)
    return _decide_incomplete(evaluation, declared, unevaluated, env, outcome,
                              now_epoch, break_glass, budget_exceeded)


def _decide_evaluated(ev: Evaluation, declared: Mapping[str, Policy], env: str,
                      budget_exceeded: bool) -> Verdict:
    if not ev.violations:
        return Verdict(ALLOW, EVALUATED,
                       "all %d policies evaluated, no violations"
                       % len(ev.evaluated_policy_ids),
                       env, budget_exceeded=budget_exceeded,
                       elapsed_ms=ev.elapsed_ms)

    violated = [declared[v.policy_id] for v in ev.violations if v.policy_id in declared]
    mode = _strictest(violated, env)
    action = _action_for(mode)
    reason = ("%d violation(s); strictest applicable mode in %s is %s"
              % (len(ev.violations), env, mode))
    return Verdict(action, EVALUATED, reason, env, violations=ev.violations,
                   budget_exceeded=budget_exceeded, elapsed_ms=ev.elapsed_ms)


def _decide_incomplete(ev: Evaluation, declared: Mapping[str, Policy],
                       unevaluated: Tuple[str, ...], env: str, outcome: str,
                       now_epoch: int, break_glass: Optional[BreakGlass],
                       budget_exceeded: bool) -> Verdict:
    missing = [declared[pid] for pid in unevaluated if pid in declared]
    mode = _strictest(missing, env) if missing else AUDIT
    would_be = _action_for(mode)

    # Violations found before the failure still count. A partial evaluation that
    # already found a blocking violation blocks on its own merits.
    hard = [v for v in ev.violations
            if v.policy_id in declared and declared[v.policy_id].mode(env) == BLOCK]
    if hard:
        return Verdict(BLOCK_ACTION, outcome,
                       "%d blocking violation(s) found before the gate failed (%s); "
                       "an incomplete evaluation that already found a breach is "
                       "still a breach" % (len(hard), ev.detail),
                       env, violations=ev.violations, unevaluated=unevaluated,
                       budget_exceeded=budget_exceeded, elapsed_ms=ev.elapsed_ms)

    base = ("%s — %d policy/policies did not evaluate (%s); strictest configured "
            "mode among them in %s is %s"
            % (ev.detail, len(unevaluated), ", ".join(unevaluated) or "none",
               env, mode))

    if would_be != BLOCK_ACTION:
        # WARN or AUDIT. Allowed, but never a pass: nothing was checked.
        return Verdict(would_be, outcome, base, env, violations=ev.violations,
                       unevaluated=unevaluated, degraded=True,
                       budget_exceeded=budget_exceeded, elapsed_ms=ev.elapsed_ms)

    if break_glass is None:
        return Verdict(BLOCK_ACTION, outcome,
                       base + ". Fail-closed: supply an attributed, justified, "
                              "time-boxed override to proceed",
                       env, violations=ev.violations, unevaluated=unevaluated,
                       budget_exceeded=budget_exceeded, elapsed_ms=ev.elapsed_ms)

    if not break_glass.valid_at(now_epoch):
        # An expired override must not quietly degrade to a warning.
        return Verdict(BLOCK_ACTION, outcome,
                       base + ". Break-glass rejected: the override expired",
                       env, violations=ev.violations, unevaluated=unevaluated,
                       budget_exceeded=budget_exceeded, elapsed_ms=ev.elapsed_ms,
                       override_rejected="expired")

    return Verdict(ALLOW, outcome,
                   base + ". Override by %s: %s"
                          % (break_glass.actor, break_glass.justification),
                   env, violations=ev.violations, unevaluated=unevaluated,
                   is_override=True, override=break_glass,
                   budget_exceeded=budget_exceeded, elapsed_ms=ev.elapsed_ms)


def unverified_allows(verdicts: Iterable[Verdict]) -> Tuple[Verdict, ...]:
    """Every deploy that proceeded without the gate clearing it.

    This is the OW2-GR-005 weekly report to ISD, and it is also the input to
    OW2-GR-006: a change that shipped unverified is exactly where to look for a
    resource that violates a guardrail but exists in the estate.
    """
    return tuple(v for v in verdicts if v.action != BLOCK_ACTION and not v.verified)


def override_report(verdicts: Iterable[Verdict]) -> dict:
    """Weekly override summary (OW2-GR-005)."""
    vs = list(verdicts)
    unverified = unverified_allows(vs)
    overrides = [v for v in unverified if v.is_override]
    degraded = [v for v in unverified if v.degraded and not v.is_override]
    rejected = [v for v in vs if v.override_rejected]
    by_actor: Dict[str, int] = {}
    for v in overrides:
        if v.override:
            by_actor[v.override.actor] = by_actor.get(v.override.actor, 0) + 1
    return {
        "total": len(vs),
        "blocked": sum(1 for v in vs if v.action == BLOCK_ACTION),
        "verified_pass": sum(1 for v in vs if v.verified and v.action != BLOCK_ACTION),
        "overrides": len(overrides),
        "degraded_allows": len(degraded),
        "rejected_overrides": len(rejected),
        "budget_breaches": sum(1 for v in vs if v.budget_exceeded),
        "overrides_by_actor": dict(sorted(by_actor.items())),
        "summary": _report_summary(len(vs), len(overrides), len(degraded)),
    }


def _report_summary(total: int, overrides: int, degraded: int) -> str:
    if not total:
        return "No pipeline evaluations in the reporting window."
    unverified = overrides + degraded
    if not unverified:
        return ("All %d pipeline evaluations completed; nothing shipped without the "
                "gate clearing it." % total)
    return ("%d of %d changes shipped without the gate clearing them — %d under an "
            "attributed override, %d because the gate was unavailable and the "
            "strictest applicable mode did not block. Each is a change no policy "
            "was checked against."
            % (unverified, total, overrides, degraded))
