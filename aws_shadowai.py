#!/usr/bin/env python3
"""aws_shadowai.py — Phase 4 · slice 4.4: AI nobody told the security team about.

Shadow AI has two halves and only one of them is visible from inside an AWS account.

**The half this module answers.** Somebody in the organization stood up a Bedrock agent,
a knowledge base or a guardrail. Whether that is shadow AI is not a property of the
resource — it is a property of *who created it* and *where*. A knowledge base built by
the ML platform team in the governed region is the system working; the same resource
built by an application role in a region nobody scans is the thing this slice exists to
surface. Both look identical in an inventory, which is why an inventory has never been
able to answer the question.

**The half it does not, and says so.** Employees pasting company data into a third-party
assistant is the shadow AI most organizations actually worry about, and it is
**not detectable from this vantage point**. The roadmap proposed a VPC flow-log query
for it. Flow logs record IP addresses, not hostnames, and the major AI providers sit
behind shared Cloudflare and Fastly ranges — so an IP allowlist would fire on every
CDN-fronted site in the estate while missing every provider that rotated an address. That
is a detection surface whose misses read as passes, which is precisely what slice 3.2
refused to build for injection phrasings. Refusing it once is worth nothing if the next
slice does it.

So the flow-log query is replaced by the config-only question underneath it — whether
Bedrock traffic even has a governed path — and ``SAAS_NOT_DETECTABLE`` states the gap
where a reader will otherwise assume it was covered.

WHAT MAKES THE CLOUDTRAIL HALF WORK
------------------------------------
Only **management** events. ``bedrock:InvokeModel`` is a data event, so
``LookupEvents`` never sees it — which is exactly what `AILOG-04` reports as a gap. That
limit is a feature here: creating an agent is a management event, and creation is the
moment shadow AI becomes visible. Usage is `AITHR-01`'s question, not this one.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Set, Tuple

__all__ = [
    "AI_CREATE_EVENTS", "BEDROCK_ENDPOINT_SERVICES", "SAAS_NOT_DETECTABLE",
    "creators", "undeclared_creators", "active_regions",
    "vpc_endpoint_posture", "describe_creator",
]

#: Management events that mean somebody STOOD UP AI, as opposed to used it. Creation is
#: the moment shadow AI becomes visible; usage is AITHR-01's question and needs data
#: events (AILOG-04) that most accounts do not have.
AI_CREATE_EVENTS: Tuple[str, ...] = (
    "CreateAgent", "CreateAgentActionGroup", "CreateAgentAlias",
    "CreateKnowledgeBase", "CreateDataSource",
    "CreateGuardrail", "CreateModelCustomizationJob",
    "CreateProvisionedModelThroughput", "CreateEvaluationJob",
    "PutModelInvocationLoggingConfiguration",
    "CreateFlow", "CreatePrompt",
)

#: Interface endpoint service-name suffixes for Bedrock. A VPC with none of these reaches
#: Bedrock over NAT or an internet gateway, which is the ungoverned path.
BEDROCK_ENDPOINT_SERVICES: Tuple[str, ...] = (
    "bedrock", "bedrock-runtime", "bedrock-agent", "bedrock-agent-runtime",
)

SAAS_NOT_DETECTABLE = (
    "third-party AI services reached from outside AWS — an employee pasting company "
    "data into a hosted assistant — are NOT detectable from an AWS account and this "
    "scan does not attempt it: VPC flow logs record IP addresses rather than "
    "hostnames, and the major providers sit behind shared CDN ranges, so an "
    "address-matching rule would fire on unrelated sites while missing any provider "
    "that rotated an address. Answering that question needs an egress proxy or a CASB"
)


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


def _principal(event: dict) -> str:
    """The identity behind an event, preferring the ARN over the ephemeral session."""
    ui = _d(event.get("userIdentity"))
    arn = ui.get("arn") or ""
    if ":assumed-role/" in arn:
        # Collapse a session to its role: ten sessions of one role are one creator, and
        # reporting them as ten would bury the answer in its own noise.
        head, _, rest = arn.partition(":assumed-role/")
        role = rest.split("/", 1)[0]
        acct = head.rsplit(":", 1)[-1] if ":" in head else ""
        return f"arn:aws:iam::{acct}:role/{role}" if acct else f"role/{role}"
    return arn or ui.get("userName") or ui.get("principalId") or ""


def creators(events: Optional[Sequence[dict]]) -> Dict[str, dict]:
    """Who created AI resources, what kinds, and where.

    Keyed by principal so the answer is a short list of identities rather than a long
    list of events — the operator's question is "who is doing this", not "how often"."""
    out: Dict[str, dict] = {}
    for e in (events or []):
        if not isinstance(e, dict):
            continue
        name = e.get("eventName") or ""
        if name not in AI_CREATE_EVENTS:
            continue
        who = _principal(e)
        if not who:
            continue
        row = out.setdefault(who, {"principal": who, "events": set(),
                                   "regions": set(), "count": 0})
        row["events"].add(name)
        if e.get("awsRegion"):
            row["regions"].add(e["awsRegion"])
        row["count"] += 1
    for row in out.values():
        row["events"] = sorted(row["events"])
        row["regions"] = sorted(row["regions"])
    return out


def undeclared_creators(found: Optional[Dict[str, dict]],
                        declared: Optional[Sequence[str]]) -> List[dict]:
    """Creators outside the operator's declared owner set.

    With NO declared set this returns nothing rather than everything. An operator who has
    not told OverWatch who owns AI would otherwise receive a finding for every legitimate
    creator on the first scan, and a check that fires on the correct configuration is one
    people turn off. The absence of a declared set is reported separately, as a question
    the operator has not answered rather than as a fault in the account."""
    if not declared:
        return []
    allow = {d.strip().lower() for d in declared if isinstance(d, str) and d.strip()}
    out = []
    for who, row in sorted((found or {}).items()):
        low = who.lower()
        if any(low == a or low.endswith("/" + a) or a in low for a in allow):
            continue
        out.append(row)
    return out


def active_regions(found: Optional[Dict[str, dict]]) -> Set[str]:
    """Every region an AI resource was created in."""
    out: Set[str] = set()
    for row in (found or {}).values():
        out.update(row.get("regions") or [])
    return out


def vpc_endpoint_posture(endpoints: Optional[Sequence[dict]],
                         vpc_ids: Optional[Sequence[str]] = None) -> dict:
    """Which VPCs can reach Bedrock privately, and which cannot.

    An interface endpoint keeps Bedrock traffic on the AWS network, where a VPC endpoint
    policy can bound it. Without one the traffic leaves through NAT or an internet
    gateway, which is the ungoverned path — and the path over which no endpoint policy
    can restrict which models are reachable.

    Matching is on the service-name SUFFIX because the full name is regional
    (``com.amazonaws.us-east-1.bedrock-runtime``), and hardcoding a region would make
    this silently find nothing everywhere else."""
    have: Dict[str, Set[str]] = defaultdict(set)
    for ep in (endpoints or []):
        if not isinstance(ep, dict):
            continue
        svc = (ep.get("ServiceName") or "").rsplit(".", 1)[-1].lower()
        if svc in BEDROCK_ENDPOINT_SERVICES and ep.get("VpcId"):
            have[ep["VpcId"]].add(svc)
    known = list(vpc_ids or []) or sorted(have)
    without = sorted(v for v in known if v not in have)
    return {"with_endpoint": {k: sorted(v) for k, v in sorted(have.items())},
            "without_endpoint": without,
            "any": bool(have),
            "checked": bool(known)}


def describe_creator(row: Optional[dict]) -> str:
    """One line an operator can act on: who, what, where."""
    r = _d(row)
    who = r.get("principal") or "an identity"
    kinds = ", ".join(r.get("events") or []) or "AI resources"
    where = ", ".join(r.get("regions") or []) or "an unrecorded region"
    return (f"{who} created {kinds} in {where} ({r.get('count', 0)} event(s)) and is "
            f"not in the declared AI owner set")
