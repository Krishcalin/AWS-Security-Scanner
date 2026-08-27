#!/usr/bin/env python3
"""
aws_ownership.py — attribute findings to an Application and an accountable owner.

The SRS (OW2-SRS-001) marks this as AD-02, an *assumption*. It is not an
assumption; it is the load-bearing dependency under half the document. Scorecards
(FR-2) are per-application. Benchmarking (FR-6) compares business units. The
dashboard filters by application (OW2-CC-012). Every KRA in FR-8 is reported by
owner. None of that exists until a finding can name who is accountable for it, and
nothing in Phase I does that — findings carry an account and a resource ARN, and
an account is not an owner.

PURE: stdlib only, no boto3, no I/O, no ``now()``. Consumes already-materialized
findings and a tag lookup; returns dataclasses. Offline-testable end to end.

────────────────────────────────────────────────────────────────────────────────
THE FAILURE MODE THIS MODULE EXISTS TO PREVENT
────────────────────────────────────────────────────────────────────────────────
A scorecard is a filter, and every filter silently deletes what it does not match.
Attribute 400 of 1,000 findings to applications, render a scorecard per
application, and the portfolio pack adds up to a materially cleaner estate than
the one that exists — not because anything was hidden, but because 600 findings
had no tag and fell out of the denominator on the way to the slide.

That is a phantom pass by omission, and it is worse here than in a check, because
an executive reads a scorecard as complete by default. So:

* :func:`attribute` NEVER guesses. A resource matching two applications is
  ``AMBIGUOUS`` — it is not awarded to the first match, because "first" is an
  artefact of dict ordering and would make ownership depend on load order.
* :func:`attribute_findings` returns :class:`AttributionCoverage` alongside the
  buckets, and the coverage is not optional. A caller that renders scorecards
  without rendering the unattributed count is rendering a subset as a total.
* Unattributed findings are returned under :data:`UNATTRIBUTED`, a real bucket
  with a real owner slot that is empty. They are never dropped.

The rule that fired is recorded on every attribution (``Attribution.rule`` /
``.basis``), which is the source lineage OW2-DR-002 requires: an owner who
disputes a finding on their scorecard can be told exactly why it landed there.

────────────────────────────────────────────────────────────────────────────────
PRECEDENCE
────────────────────────────────────────────────────────────────────────────────
Ordered most-specific first. The first tier that yields exactly one application
wins; a tier that yields more than one stops the search as AMBIGUOUS rather than
falling through to a vaguer tier that happens to be decisive.

  1. ``explicit-resource``  operator pinned this exact ARN to this application
  2. ``tag``                a tag selector on the resource matched
  3. ``account``            the application owns the whole account

Falling through to a broader tier after an ambiguous narrow one would resolve a
contradiction by widening the question, which is how a tool ends up confidently
telling the wrong team to fix something.

EPISTEMICS: attribution is :data:`aws_epistemics.CONFIGURED` — a tag value an API
returned, or a mapping the operator declared. It is never OBSERVED: nothing here
watched anyone take responsibility for anything. A stale tag produces a confident
wrong owner, which is why :func:`attribution_health` exists to surface selectors
that match nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from engine import aws_epistemics

# ── vocabulary ───────────────────────────────────────────────────────────────
UNATTRIBUTED = "__unattributed__"
"""Bucket id for findings no application claimed. A real bucket, deliberately: it
appears in the portfolio pack next to the applications, so the gap is visible to
the same person who reads the scores."""

AMBIGUOUS = "ambiguous"
NONE = "none"
RULE_RESOURCE = "explicit-resource"
RULE_TAG = "tag"
RULE_ACCOUNT = "account"

RULES = (RULE_RESOURCE, RULE_TAG, RULE_ACCOUNT, AMBIGUOUS, NONE)

# Criticality tiers (AD-03). "unclassified" is the default and is NOT a synonym
# for "standard" — an untagged asset is one nobody has assessed, and a scorecard
# that silently treats it as low-criticality understates the estate.
CROWN_JEWEL = "crown-jewel"
CRITICALITY = (CROWN_JEWEL, "high", "standard", "unclassified")

PROVENANCE = aws_epistemics.CONFIGURED

_ATTRIBUTION_NOTE = (
    "Attribution is derived from operator-declared mappings and resource tags. It "
    "reflects what configuration says, not who is in fact maintaining the resource; "
    "a stale tag yields a confident wrong owner."
)


@dataclass(frozen=True)
class Application:
    """An application entity (OW2-SC-001).

    ``owner`` is the accountable party — a team alias or a person. Empty is
    permitted and is itself a finding-worthy state: an application with no owner
    cannot receive a scorecard, so :func:`attribution_health` reports it.
    """

    app_id: str
    name: str
    owner: str = ""
    portfolio: str = ""
    criticality: str = "unclassified"
    accounts: Tuple[str, ...] = ()
    tag_selectors: Tuple[Tuple[str, str], ...] = ()
    resource_arns: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.app_id:
            raise ValueError("app_id is required")
        if self.criticality not in CRITICALITY:
            raise ValueError(
                "criticality must be one of %s, got %r"
                % (", ".join(CRITICALITY), self.criticality))
        for key, val in self.tag_selectors:
            if not key:
                raise ValueError("tag selector key must be non-empty")
            if val == "":
                # A key-only selector would claim every resource carrying the key
                # regardless of value, which is how one application swallows the
                # estate. Require the value; use one selector per value.
                raise ValueError(
                    "tag selector %r needs an explicit value; a key-only selector "
                    "claims every resource bearing that key" % (key,))


@dataclass(frozen=True)
class Attribution:
    """Why a resource landed where it did. ``app_id`` is None unless exactly one
    application claimed it."""

    app_id: Optional[str]
    rule: str
    basis: str
    candidates: Tuple[str, ...] = ()

    @property
    def attributed(self) -> bool:
        return self.app_id is not None


@dataclass(frozen=True)
class AttributionCoverage:
    """The denominator, made explicit.

    ``pct`` is the share of findings that reached a named application. A scorecard
    pack rendered at 40% coverage is a report about 40% of the estate, and saying
    so is the whole point of this dataclass.
    """

    total: int
    attributed: int
    unattributed: int
    ambiguous: int
    by_rule: Mapping[str, int]
    gap_accounts: Tuple[Tuple[str, int], ...]
    provenance: str = PROVENANCE
    note: str = _ATTRIBUTION_NOTE

    @property
    def pct(self) -> float:
        return 0.0 if not self.total else round(100.0 * self.attributed / self.total, 1)

    @property
    def complete(self) -> bool:
        return self.total > 0 and self.unattributed == 0 and self.ambiguous == 0

    def headline(self) -> str:
        """One line a report can print next to any per-application total."""
        if self.total == 0:
            return "No findings in scope."
        if self.complete:
            return "All %d findings attributed to an application." % self.total
        parts = ["%d of %d findings attributed (%.1f%%)"
                 % (self.attributed, self.total, self.pct)]
        if self.unattributed:
            parts.append("%d unowned" % self.unattributed)
        if self.ambiguous:
            parts.append("%d claimed by more than one application" % self.ambiguous)
        return "; ".join(parts) + " — per-application totals exclude the remainder."


def _norm_arn(arn: str) -> str:
    return (arn or "").strip()


def attribute(
    resource: str,
    tags: Optional[Mapping[str, str]],
    account: str,
    apps: Sequence[Application],
) -> Attribution:
    """Resolve one resource to at most one application.

    Tiers are evaluated most-specific first and the search STOPS at the first tier
    that matches anything — including when that tier matches several applications,
    which yields AMBIGUOUS rather than falling through.
    """
    tags = tags or {}
    res = _norm_arn(resource)

    # T1 — explicit resource pin.
    hits = [a for a in apps if res and res in {_norm_arn(x) for x in a.resource_arns}]
    if hits:
        return _resolve(hits, RULE_RESOURCE, "resource pinned to %s" % hits[0].app_id
                        if len(hits) == 1 else "resource pinned by multiple applications")

    # T2 — tag selector.
    tag_hits: List[Application] = []
    reason = ""
    for a in apps:
        for key, val in a.tag_selectors:
            if tags.get(key) == val:
                tag_hits.append(a)
                if not reason:
                    reason = "tag %s=%s" % (key, val)
                break
    if tag_hits:
        return _resolve(tag_hits, RULE_TAG, reason)

    # T3 — whole-account ownership.
    acct_hits = [a for a in apps if account and account in a.accounts]
    if acct_hits:
        return _resolve(acct_hits, RULE_ACCOUNT, "account %s" % account)

    return Attribution(None, NONE,
                       "no resource pin, no matching tag selector, and no application "
                       "claims account %s" % (account or "<unknown>"))


def _resolve(hits: Sequence[Application], rule: str, basis: str) -> Attribution:
    ids = tuple(sorted({a.app_id for a in hits}))
    if len(ids) == 1:
        return Attribution(ids[0], rule, basis)
    return Attribution(
        None, AMBIGUOUS,
        "%d applications claim this resource by %s; ownership is contested and was "
        "not guessed" % (len(ids), rule),
        candidates=ids)


def attribute_findings(
    findings: Iterable,
    apps: Sequence[Application],
    tag_lookup: Optional[Callable[[str], Optional[Mapping[str, str]]]] = None,
) -> Tuple[Dict[str, List], AttributionCoverage]:
    """Bucket findings by application, returning coverage alongside.

    ``findings`` are duck-typed on ``.resource`` and ``.account`` (mappings work
    too). ``tag_lookup`` maps a resource ARN to its tags; absent, only the pin and
    account tiers can fire, and coverage will say so by attributing nothing to the
    tag rule.

    Returns ``(buckets, coverage)``. ``buckets`` always contains
    :data:`UNATTRIBUTED` when anything failed to attribute — the caller cannot
    forget it by iterating only the applications it knows about.
    """
    buckets: Dict[str, List] = {}
    by_rule: Dict[str, int] = {r: 0 for r in RULES}
    gap: Dict[str, int] = {}
    total = attributed = unattributed = ambiguous = 0

    for f in findings:
        total += 1
        resource = _get(f, "resource", "")
        account = _get(f, "account", "")
        tags = tag_lookup(resource) if tag_lookup else None
        att = attribute(resource, tags, account, apps)
        by_rule[att.rule] = by_rule.get(att.rule, 0) + 1
        if att.attributed:
            attributed += 1
            buckets.setdefault(att.app_id, []).append((f, att))
        else:
            if att.rule == AMBIGUOUS:
                ambiguous += 1
            else:
                unattributed += 1
            gap[account] = gap.get(account, 0) + 1
            buckets.setdefault(UNATTRIBUTED, []).append((f, att))

    coverage = AttributionCoverage(
        total=total, attributed=attributed, unattributed=unattributed,
        ambiguous=ambiguous, by_rule=dict(by_rule),
        gap_accounts=tuple(sorted(gap.items(), key=lambda kv: (-kv[1], kv[0]))))
    return buckets, coverage


def _get(obj, name: str, default=""):
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


@dataclass(frozen=True)
class HealthIssue:
    app_id: str
    kind: str
    detail: str


def attribution_health(
    apps: Sequence[Application],
    buckets: Optional[Mapping[str, Sequence]] = None,
) -> Tuple[HealthIssue, ...]:
    """Report registry defects that make attribution quietly wrong.

    A selector that matches nothing is the dangerous case: the application looks
    configured, its scorecard renders, and it reports zero findings — which is
    indistinguishable from a clean application right up until someone acts on it.
    """
    issues: List[HealthIssue] = []
    for a in sorted(apps, key=lambda x: x.app_id):
        if not a.owner:
            issues.append(HealthIssue(
                a.app_id, "no-owner",
                "application has no accountable owner, so its scorecard cannot be "
                "delivered to anyone (OW2-SC-001)"))
        if not (a.accounts or a.tag_selectors or a.resource_arns):
            issues.append(HealthIssue(
                a.app_id, "no-selectors",
                "application claims no accounts, tags or resources; it can never "
                "match a finding and will always score as clean"))
        if a.criticality == "unclassified":
            issues.append(HealthIssue(
                a.app_id, "unclassified",
                "criticality is unset, so this application is excluded from "
                "crown-jewel prioritisation (AD-03)"))
        if buckets is not None and a.app_id not in buckets:
            issues.append(HealthIssue(
                a.app_id, "matched-nothing",
                "selectors matched no finding in this scan — a clean scorecard here "
                "is indistinguishable from a mis-scoped selector"))
    return tuple(issues)


def owner_of(app_id: Optional[str], apps: Sequence[Application]) -> str:
    """Owner for a bucket id, or empty for the unattributed bucket. Empty is
    returned rather than a placeholder so a caller cannot mail a scorecard to a
    string that looks like an address."""
    if not app_id or app_id == UNATTRIBUTED:
        return ""
    for a in apps:
        if a.app_id == app_id:
            return a.owner
    return ""
