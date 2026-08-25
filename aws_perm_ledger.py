#!/usr/bin/env python3
"""aws_perm_ledger.py — what each IAM action buys, and what declining it forfeits.

Every CNAPP asks for permissions. Almost none of them tell you what each one is FOR,
and none of them tell you what you lose by refusing one. The result is a policy
document a security reviewer must take on trust, and — worse — a scan that quietly
degrades when an action is missing, reporting a check as *passed* when it was never
*evaluated*. Those two are indistinguishable in every product output we have seen,
including, until recently, our own.

This module makes both legible:

* **The ledger** maps each check to the IAM actions it needs, computes which checks the
  role can actually evaluate, and emits the MINIMAL additive policy with a per-action
  justification — ``bedrock:GetKnowledgeBase → enables AGT-03``. Decline any single
  action and it names exactly which findings you forfeit.
* **The coverage manifest** is the negative-assurance artefact: what we enumerated, what
  we could not and why, which checks were *not evaluated* as opposed to *evaluated and
  passed*, and which regions were never looked at.

WHY THIS EARNS ITS PLACE. It is the mechanism by which a permission is *sold* rather
than demanded, and it is the natural completion of "an open, auditable scoring engine":
a product that shows its reasoning should also show its blind spots. For a sovereign
buyer whose security review goes line by line through an IAM policy, a per-action
justification is the difference between a one-day approval and a six-week one.

It is also a guard against a mistake this codebase has made twice. Both the roadmap and
an earlier analysis asserted that the AI pillar was broadly AccessDenied-degraded under
the documented role. Checking the actual attached policies showed the real gap was three
actions. Reasoning about permissions from memory is unreliable; computing them from the
policy documents is not.

Pure and boto3-free: it consumes the normalized statement shape that
``aws_live_scanner._policy_to_statements`` already produces, the same shape
``aws_effperm`` and ``aws_aispm`` consume::

    {"effect": "Allow"|"Deny", "actions": set[str], "resources": set[str],
     "not_resources": set[str], "condition": dict|None}

with actions and resources lowercased.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

__all__ = [
    "Requirement", "REQUIREMENTS", "Ledger", "CoverageManifest",
    "granted", "evaluate", "requirements_for",
]


# ─── the requirement table ───────────────────────────────────────────────────
@dataclass(frozen=True)
class Requirement:
    """One IAM action a check needs, and what the check does with it."""
    action: str          # canonical case, e.g. "bedrock:GetKnowledgeBase"
    why: str             # what the operator buys by granting it

    @property
    def key(self) -> str:
        return self.action.lower()


def _req(action: str, why: str) -> Requirement:
    return Requirement(action=action, why=why)


# Scoped to the AI pillar today, and deliberately so: authoring a mapping for all 300+
# checks from memory would reproduce exactly the error this module exists to prevent.
# Every entry below was read off the call site, not recalled. Extend it the same way.
REQUIREMENTS: Mapping[str, Tuple[Requirement, ...]] = {
    "BDR-01": (
        _req("bedrock:GetModelInvocationLoggingConfiguration",
             "read whether Bedrock records model invocations at all — the only "
             "control in the AI pillar that produces evidence after an incident"),
    ),
    "BDR-02": (
        _req("bedrock:ListGuardrails",
             "enumerate guardrails so an account with none can be distinguished "
             "from an account we were not allowed to ask"),
    ),
    "BDR-03": (
        _req("bedrock:ListCustomModels", "find fine-tuned models"),
        _req("bedrock:GetCustomModel",
             "read each custom model's KMS key — a fine-tuned model embeds its "
             "training data, so its key custody is the training data's key custody"),
    ),
    "AIGRD-01": (
        _req("bedrock:GetGuardrail",
             "read each guardrail's filter strengths and actions — ListGuardrails\n             returns GuardrailSummary only and carries no filter configuration, so\n             without this the scanner can say a guardrail exists but not whether it\n             blocks anything"),
    ),
    "AIGRD-02": (
        _req("bedrock:GetGuardrail",
             "read inputAction/outputAction — the difference between a guardrail\n             that blocks and one that only reports"),
    ),
    "AIGRD-04": (
        _req("bedrock:GetGuardrail",
             "read the guardrail version, to tell a pinned guardrail from a DRAFT\n             that changes underneath its consumers"),
    ),
    # AIGRD-03 needs NO new action, and that is the point of it: enforcement is
    # decided from identity-policy statements the scanner already collects.
    "AIGRD-03": (),
    "AGT-01": (
        _req("bedrock:ListAgents", "find Bedrock agents"),
        _req("bedrock:GetAgent",
             "read the agent's customer-managed key, instructions and guardrail "
             "association"),
    ),
    "AGT-02": (
        _req("bedrock:GetAgent",
             "resolve the agent's execution role, whose permissions are the true "
             "blast radius of a successful prompt injection"),
    ),
    "AGT-03": (
        _req("bedrock:ListKnowledgeBases", "find RAG knowledge bases"),
        _req("bedrock:GetKnowledgeBase",
             "read the knowledge base's encryption configuration — the retrieval "
             "corpus is the material a model will quote back on request"),
        _req("bedrock:ListDataSources", "find each knowledge base's data sources"),
        _req("bedrock:GetDataSource",
             "read each data source's encryption — an encrypted knowledge base fed "
             "by an unencrypted source still leaves the source readable"),
    ),
    "AGT-04": (
        _req("bedrock:ListAgentActionGroups", "find the agent's tools"),
        _req("bedrock:GetAgentActionGroup",
             "resolve the Lambda an action group invokes — the mechanism by which "
             "model output becomes a real API call"),
        _req("lambda:GetPolicy",
             "read who else may invoke that Lambda, i.e. whether the agent is the "
             "only caller"),
    ),
    "AGT-05": (
        _req("bedrock:GetAgent",
             "read the agent's guardrail association and idle session TTL"),
    ),
    "SM-04": (
        _req("sagemaker:ListDomains", "find SageMaker Studio domains"),
        _req("sagemaker:DescribeDomain",
             "read the domain's network access type and default execution role"),
    ),
    "SM-06": (
        _req("sagemaker:ListEndpointConfigs", "find inference endpoint configs"),
        _req("sagemaker:DescribeEndpointConfig", "read endpoint KMS configuration"),
    ),
    "SM-07": (
        _req("sagemaker:ListNotebookInstances", "find notebook instances"),
        _req("sagemaker:DescribeNotebookInstance",
             "read direct-internet access, subnet attachment and volume encryption"),
    ),
    # AISPM-01..03 and AIPATH-01 need NO new action: they reason over the IAM
    # principals already cached from GetAccountAuthorizationDetails and over graph
    # edges other sections emitted. Recorded explicitly so the ledger can say
    # "these are free" rather than staying silent about them.
    "AISPM-01": (),
    "AISPM-02": (),
    "AISPM-03": (),
    "AIPATH-01": (),
}


def requirements_for(check_id: str) -> Tuple[Requirement, ...]:
    return REQUIREMENTS.get(check_id, ())


# ─── granted-action resolution ───────────────────────────────────────────────
def _matches(patterns: Iterable[str], action: str) -> bool:
    """Wildcard-aware IAM action match. ``bedrock:*`` and ``*`` both grant
    ``bedrock:GetKnowledgeBase``; ``bedrock:Get*`` grants it too."""
    a = action.lower()
    return any(fnmatch(a, p) for p in (patterns or ()))


def granted(statements: Iterable[Mapping], action: str) -> bool:
    """Is ``action`` allowed by these identity statements?

    An explicit Deny that matches wins outright, which mirrors IAM. Resource scoping
    is NOT modelled: an Allow on a narrower resource still counts as granted here,
    because this module answers "will the API call be refused outright", and a
    resource-scoped grant fails per-resource rather than per-action. Conditions are
    likewise not evaluated — a Condition-gated grant is reported as granted, because
    the call may succeed and the ledger's job is to find the actions that CANNOT.
    Both are documented over-approximations in the safe direction: the ledger will
    under-report missing actions rather than demand ones already held."""
    for st in statements or ():
        if st.get("effect") == "Deny" and _matches(st.get("actions", ()), action):
            return False
    for st in statements or ():
        if st.get("effect") == "Allow" and _matches(st.get("actions", ()), action):
            return True
    return False


# ─── the ledger ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Ledger:
    """Which checks this role can evaluate, and what the rest would cost."""
    evaluable: Tuple[str, ...]
    blocked: Mapping[str, Tuple[str, ...]]      # check_id -> missing actions
    free: Tuple[str, ...]                       # checks needing no action at all
    justification: Mapping[str, str]            # action -> why (canonical case)

    @property
    def missing_actions(self) -> Tuple[str, ...]:
        """Every action that would unblock at least one check, canonical case."""
        return tuple(sorted({a for acts in self.blocked.values() for a in acts}))

    def forfeit(self, declined: Iterable[str]) -> Tuple[str, ...]:
        """The checks lost by declining these actions — the number that makes an IAM
        review a decision rather than a leap of faith."""
        low = {d.lower() for d in declined}
        lost = [cid for cid, acts in self.blocked.items()
                if any(a.lower() in low for a in acts)]
        # a check already evaluable can still be lost if it needs a declined action
        for cid in self.evaluable:
            if any(r.key in low for r in requirements_for(cid)):
                lost.append(cid)
        return tuple(sorted(set(lost)))

    def additive_policy(self, sid: str = "CnappAIReadOnly") -> dict:
        """The minimal additive policy, and nothing more. Emitting only what is
        actually missing is the point: a reviewer can diff it against what they
        already grant, and every action in it has a justification below."""
        actions = self.missing_actions
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": sid,
                "Effect": "Allow",
                "Action": list(actions),
                "Resource": "*",
            }] if actions else [],
        }

    def annotated_policy(self, sid: str = "CnappAIReadOnly") -> List[dict]:
        """One row per requested action: what it is, why, and what is lost without
        it. This is the artefact the onboarding wizard renders."""
        rows = []
        for action in self.missing_actions:
            rows.append({
                "action": action,
                "why": self.justification.get(action, ""),
                "enables": [cid for cid, acts in sorted(self.blocked.items())
                            if action in acts],
                "forfeited_if_declined": list(self.forfeit([action])),
            })
        return rows

    def to_dict(self) -> dict:
        return {
            "evaluable": list(self.evaluable),
            "blocked": {k: list(v) for k, v in sorted(self.blocked.items())},
            "free": list(self.free),
            "missing_actions": list(self.missing_actions),
            "annotated_policy": self.annotated_policy(),
        }


def evaluate(statements: Iterable[Mapping],
             requirements: Optional[Mapping[str, Tuple[Requirement, ...]]] = None
             ) -> Ledger:
    """Compute the ledger for a role's normalized identity statements."""
    reqs = REQUIREMENTS if requirements is None else requirements
    statements = list(statements or ())
    evaluable, blocked, free, why = [], {}, [], {}

    for check_id, needs in sorted(reqs.items()):
        if not needs:
            free.append(check_id)
            evaluable.append(check_id)
            continue
        missing = []
        for r in needs:
            why[r.action] = r.why
            if not granted(statements, r.action):
                missing.append(r.action)
        if missing:
            blocked[check_id] = tuple(sorted(missing))
        else:
            evaluable.append(check_id)

    return Ledger(evaluable=tuple(sorted(evaluable)),
                  blocked=dict(sorted(blocked.items())),
                  free=tuple(sorted(free)),
                  justification=dict(sorted(why.items())))


# ─── the coverage manifest ───────────────────────────────────────────────────
@dataclass
class CoverageManifest:
    """Negative assurance: what this scan did NOT establish.

    Every field here exists because its absence produced a confident wrong answer at
    some point in this product's history. A check that returned AccessDenied and one
    that ran and passed are different claims about the world, and a report that renders
    them identically is the failure mode nobody re-reads."""
    scanned_regions: List[str] = field(default_factory=list)
    unscanned_regions: List[str] = field(default_factory=list)
    not_evaluated: Dict[str, str] = field(default_factory=dict)   # check_id -> reason
    missing_actions: List[str] = field(default_factory=list)
    enumerated: List[str] = field(default_factory=list)           # resource types seen
    not_enumerable: Dict[str, str] = field(default_factory=dict)  # type -> action

    def note_denied(self, check_id: str, action: str) -> None:
        """Record a check as NOT EVALUATED. Deliberately distinct from a PASS."""
        self.not_evaluated[check_id] = f"AccessDenied — missing {action}"
        if action not in self.missing_actions:
            self.missing_actions.append(action)

    @property
    def complete(self) -> bool:
        """True only if nothing was withheld, denied or skipped. A scan that is not
        complete is not a clean bill of health, and the console should not draw it
        as one."""
        return not (self.unscanned_regions or self.not_evaluated
                    or self.not_enumerable)

    def to_dict(self) -> dict:
        return {
            "complete": self.complete,
            "scanned_regions": sorted(self.scanned_regions),
            "unscanned_regions": sorted(self.unscanned_regions),
            "not_evaluated": dict(sorted(self.not_evaluated.items())),
            "missing_actions": sorted(self.missing_actions),
            "enumerated": sorted(self.enumerated),
            "not_enumerable": dict(sorted(self.not_enumerable.items())),
        }

    @classmethod
    def from_dict(cls, d: Mapping) -> "CoverageManifest":
        d = d or {}
        return cls(
            scanned_regions=list(d.get("scanned_regions", [])),
            unscanned_regions=list(d.get("unscanned_regions", [])),
            not_evaluated=dict(d.get("not_evaluated", {})),
            missing_actions=list(d.get("missing_actions", [])),
            enumerated=list(d.get("enumerated", [])),
            not_enumerable=dict(d.get("not_enumerable", {})),
        )
