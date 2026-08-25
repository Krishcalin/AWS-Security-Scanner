#!/usr/bin/env python3
"""aws_airules.py — LLMjacking and AI control-tampering detections from CloudTrail.

Two families, from management events the scanner role can already read:

**LLMjacking** — someone running inference on a stolen key. It has a recognisable
shape: enumerate the models, confirm the key is live without tripping AccessDenied,
then invoke, usually from a generic HTTP client and across several regions to spread
the quota. It is the only AI finding with a dollar sign attached, which is why it is
here rather than later.

**Control tampering** — the guardrail deleted, the invocation logging switched off, the
delivery bucket repointed. This is the family that protects every other control: a
weakened guardrail makes AGT-05 pass while meaning nothing, and disabled logging makes
the whole detection surface go quiet. An attacker who reads
``GetModelInvocationLoggingConfiguration`` before disabling it is checking whether they
will be recorded, and that read is higher signal than the write.

WHAT THIS IS NOT. It is not AIDR, and it does not get a pillar. It is a rule pack over
``aws_cdr``'s existing detection plane, feeding the same ``NormalizedDetection`` shape
GuardDuty and EDR findings already use. Naming it a product would buy a nav entry, a
dashboard and a quarter, for detections that live perfectly well beside the others.

THE SEVERITY JOIN IS THE POINT. Every log-analytics vendor can tell you an access key
invoked a model unusually. None of them can tell you that the key belongs to a SageMaker
execution role which can escalate privilege and read a crown-jewel bucket — because they
have the events and not the graph. GuardDuty rates its own AI findings Low for exactly
this reason: it does not know what the identity reaches. We do. :func:`rerank` is that
computation and it is the only part a competitor cannot copy from the log alone.

Pure and boto3-free. Consumes CloudTrail ``LookupEvents``-shaped dicts and returns
``aws_cdr.NormalizedDetection``. No prompt or completion content is read: the fields
below are identifiers, timings and configuration, which is what a management event
contains — and ``tests/test_zero_telemetry.py`` Section F asserts it stays that way.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import aws_cdr
import aws_deepplane

__all__ = ["detect", "rerank", "IAC_USER_AGENTS", "RECON_EVENTS", "TAMPER_EVENTS"]

# ─── vocabulary ──────────────────────────────────────────────────────────────
# Enumeration that precedes abuse. Harmless alone; meaningful immediately before
# a first-ever InvokeModel from the same key.
RECON_EVENTS = frozenset({
    "listfoundationmodels", "getfoundationmodelavailability",
    "putusecaseformodelaccess", "createfoundationmodelagreement",
    "listinferenceprofiles", "getmodelinvocationloggingconfiguration",
})

INVOKE_EVENTS = frozenset({"invokemodel", "invokemodelwithresponsestream",
                           "converse", "conversestream", "invokeagent"})

# Control-plane writes that reduce what the account can see or enforce.
TAMPER_EVENTS = {
    "deleteguardrail": ("ai-guardrail-deleted", 9.0,
                        "Bedrock guardrail deleted"),
    "updateguardrail": ("ai-guardrail-weakened", 8.0,
                        "Bedrock guardrail weakened"),
    "deletemodelinvocationloggingconfiguration": ("ai-logging-disabled", 9.0,
                                                  "Bedrock invocation logging disabled"),
    "putmodelinvocationloggingconfiguration": ("ai-logging-redirected", 7.0,
                                               "Bedrock invocation logging reconfigured"),
    "deleteknowledgebase": ("ai-knowledge-base-deleted", 7.0,
                            "Bedrock knowledge base deleted"),
    "updateagent": ("ai-agent-modified", 6.0, "Bedrock agent modified"),
    "createagentactiongroup": ("ai-agent-tool-added", 7.0,
                               "Bedrock agent action group added"),
    "updatefunctioncode": ("ai-agent-lambda-changed", 8.0,
                           "Action-group Lambda code replaced"),
}

# A Terraform or CloudFormation apply deletes and recreates resources constantly.
# Treating that as an attack is how a detection gets muted wholesale, so the shape
# that matters is a tamper event from a NON-automation principal.
IAC_USER_AGENTS = ("terraform", "cloudformation", "aws-cdk", "pulumi",
                   "serverless", "ansible", "cfn-")

# Generic HTTP clients. A human at a console produces `console.amazonaws.com`; the
# SDKs produce `aws-cli`, `Boto3`, `aws-sdk-*`. A raw HTTP library invoking Bedrock
# is the fingerprint of a reverse proxy reselling the key.
_PROXY_AGENTS = ("aiohttp", "axios", "python-requests", "okhttp", "node-fetch",
                 "got ", "curl/", "httpx", "unirest")

_WINDOW_RECON = timedelta(minutes=10)
_WINDOW_PROBE = timedelta(minutes=5)
_WINDOW_REGION = timedelta(hours=1)
_MIN_REGIONS = 3


# ─── event helpers ───────────────────────────────────────────────────────────
def _name(ev: Mapping) -> str:
    return str(ev.get("eventName") or ev.get("EventName") or "").lower()


def _when(ev: Mapping) -> Optional[datetime]:
    raw = ev.get("eventTime") or ev.get("EventTime")
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def _key_id(ev: Mapping) -> str:
    ui = ev.get("userIdentity") or {}
    return str(ui.get("accessKeyId") or "")


def _actor(ev: Mapping) -> str:
    ui = ev.get("userIdentity") or {}
    return str(ui.get("arn")
               or ((ui.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn")
               or "")


def _agent(ev: Mapping) -> str:
    return str(ev.get("userAgent") or "").lower()


def _is_automation(ev: Mapping) -> bool:
    a = _agent(ev)
    return any(tok in a for tok in IAC_USER_AGENTS)


def _eid(ev: Mapping, suffix: str) -> str:
    base = ev.get("eventID") or ev.get("EventId") or _name(ev)
    return f"ai:{suffix}:{base}"


# Every optional field any rule may attach. Enumerated rather than splatted so the
# complete evidence shape is readable in one place — and so a new rule cannot add a
# field without it appearing in a diff. tests/test_zero_telemetry.py Section F rejects
# the splat that would otherwise make this list unnecessary and unreviewable.
_EXTRA_FIELDS = ("recon_events", "recon_count", "probe_count", "regions",
                 "weakened", "function_name", "preceded_by_config_read")


def _det(ev: Mapping, *, rule: str, title: str, severity: float,
         extra: Optional[Mapping] = None) -> aws_cdr.NormalizedDetection:
    """Build one detection. Evidence is written out field by field — never splatted
    from the raw event — so a reviewer can see exactly what entered the product, and
    so no field of a future event shape arrives here unnoticed."""
    actor = _actor(ev)
    x = dict(extra or {})
    unknown = sorted(set(x) - set(_EXTRA_FIELDS))
    assert not unknown, f"rule {rule} attaches unlisted evidence fields: {unknown}"
    return aws_cdr.NormalizedDetection(
        id=_eid(ev, rule), source="cloudtrail-ai", type=f"ai:{rule}",
        title=title, severity=severity,
        band=aws_deepplane.severity_band(severity),
        node_kind="IAMPrincipal" if actor.startswith("arn:") else None,
        node_key=None,
        resource_arn=actor if actor.startswith("arn:") else None,
        first_seen=ev.get("eventTime") or ev.get("EventTime"),
        evidence={
            "event_name": ev.get("eventName"),
            "region": ev.get("awsRegion"),
            "source_ip": ev.get("sourceIPAddress"),
            "user_agent": ev.get("userAgent"),
            "access_key_id": _key_id(ev) or None,
            "error_code": ev.get("errorCode"),
            "rule": rule,
            "recon_events": x.get("recon_events"),
            "recon_count": x.get("recon_count"),
            "probe_count": x.get("probe_count"),
            "regions": x.get("regions"),
            "weakened": x.get("weakened"),
            "function_name": x.get("function_name"),
            "preceded_by_config_read": x.get("preceded_by_config_read"),
        },
    )


# ─── LLMjacking ──────────────────────────────────────────────────────────────
def _by_key(events: Sequence[Mapping]) -> Dict[str, List[Mapping]]:
    out: Dict[str, List[Mapping]] = defaultdict(list)
    for ev in events:
        k = _key_id(ev)
        if k:
            out[k].append(ev)
    for k in out:
        out[k].sort(key=lambda e: _when(e) or datetime.min.replace(tzinfo=timezone.utc))
    return out


def _recon_to_abuse(by_key) -> List[aws_cdr.NormalizedDetection]:
    """Enumerate the models, then invoke one — within minutes, on the same key. Each
    half is unremarkable; the sequence is the signal."""
    out = []
    for key, evs in by_key.items():
        recon = [e for e in evs if _name(e) in RECON_EVENTS]
        if not recon:
            continue
        for inv in (e for e in evs if _name(e) in INVOKE_EVENTS):
            t_inv = _when(inv)
            if t_inv is None:
                continue
            prior = [r for r in recon
                     if (t := _when(r)) and timedelta(0) <= t_inv - t <= _WINDOW_RECON]
            if prior:
                out.append(_det(
                    inv, rule="llmjacking-recon-to-abuse", severity=8.0,
                    title=("Model enumeration followed by invocation on the same "
                           "access key within 10 minutes"),
                    extra={"recon_events": sorted({_name(r) for r in prior}),
                           "recon_count": len(prior)}))
                break
    return out


def _validation_probe(by_key) -> List[aws_cdr.NormalizedDetection]:
    """A deliberately invalid InvokeModel confirms a key is live WITHOUT producing
    AccessDenied — which is what most alerting keys on. A ValidationException followed
    by a success is the probe-then-use pattern."""
    out = []
    for key, evs in by_key.items():
        probes = [e for e in evs
                  if _name(e) in INVOKE_EVENTS
                  and str(e.get("errorCode") or "").startswith("ValidationException")]
        if not probes:
            continue
        for ok in (e for e in evs if _name(e) in INVOKE_EVENTS and not e.get("errorCode")):
            t_ok = _when(ok)
            if t_ok is None:
                continue
            near = [p for p in probes
                    if (t := _when(p)) and timedelta(0) <= t_ok - t <= _WINDOW_PROBE]
            if near:
                out.append(_det(
                    ok, rule="llmjacking-validation-probe", severity=8.5,
                    title=("Invalid-parameter probe confirmed a live key, followed by "
                           "a successful model invocation"),
                    extra={"probe_count": len(near)}))
                break
    return out


def _proxy_fingerprint(events) -> List[aws_cdr.NormalizedDetection]:
    """A raw HTTP library invoking Bedrock. The SDKs and the console identify
    themselves; a reverse proxy reselling a key does not."""
    out = []
    for ev in events:
        if _name(ev) not in INVOKE_EVENTS:
            continue
        agent = _agent(ev)
        if any(tok in agent for tok in _PROXY_AGENTS):
            out.append(_det(
                ev, rule="llmjacking-proxy-client", severity=7.0,
                title=("Model invoked by a generic HTTP client rather than an AWS SDK "
                       "— the fingerprint of a reverse proxy")))
    return out


def _quota_dodging(by_key) -> List[aws_cdr.NormalizedDetection]:
    """One key invoking across three or more regions inside an hour. Legitimate
    workloads are pinned to a region; a reseller spreads load to dodge per-region
    quota."""
    out = []
    for key, evs in by_key.items():
        invokes = [e for e in evs if _name(e) in INVOKE_EVENTS and _when(e)]
        if len(invokes) < _MIN_REGIONS:
            continue
        for i, anchor in enumerate(invokes):
            t0 = _when(anchor)
            window = [e for e in invokes[i:]
                      if (t := _when(e)) and t - t0 <= _WINDOW_REGION]
            regions = {str(e.get("awsRegion") or "") for e in window} - {""}
            if len(regions) >= _MIN_REGIONS:
                out.append(_det(
                    anchor, rule="llmjacking-quota-dodging", severity=7.5,
                    title=(f"One access key invoked models across {len(regions)} "
                           f"regions within an hour"),
                    extra={"regions": sorted(regions)}))
                break
    return out


# ─── control tampering ───────────────────────────────────────────────────────
def _weakened(ev: Mapping) -> bool:
    """An UpdateGuardrail that lowers filter strength or turns PII off. Reading the
    request parameters, not the prompts they govern."""
    params = ev.get("requestParameters") or {}
    blob = str(params).lower()
    if '"none"' in blob or "'none'" in blob or ": none" in blob:
        return True
    if '"low"' in blob or "'low'" in blob:
        return True
    return False


def _tampering(events, *, lambda_allowlist) -> List[aws_cdr.NormalizedDetection]:
    out = []
    prior_logging_read: Dict[str, datetime] = {}

    for ev in sorted(events, key=lambda e: _when(e) or
                     datetime.min.replace(tzinfo=timezone.utc)):
        name = _name(ev)
        if name == "getmodelinvocationloggingconfiguration":
            k = _key_id(ev) or _actor(ev)
            t = _when(ev)
            if k and t:
                prior_logging_read[k] = t
            continue

        spec = TAMPER_EVENTS.get(name)
        if not spec:
            continue
        rule, severity, title = spec

        # An IaC principal churning resources during an apply is not an attack, and
        # firing on it is how a whole rule gets disabled by an operator.
        if _is_automation(ev):
            continue
        if ev.get("errorCode"):
            continue                        # a denied attempt is not a tamper

        extra: Dict[str, object] = {}
        if name == "updateguardrail":
            if not _weakened(ev):
                continue
            extra["weakened"] = True
        if name == "updatefunctioncode":
            fn = str(((ev.get("requestParameters") or {}).get("functionName")) or "")
            # No allowlist means we cannot tell an agent tool from any other
            # function, and firing on every Lambda deploy in the account is how the
            # whole pack gets muted. Silence is the correct answer to not knowing.
            if lambda_allowlist is None or fn not in lambda_allowlist:
                continue
            extra["function_name"] = fn or None
        if name == "putmodelinvocationloggingconfiguration":
            k = _key_id(ev) or _actor(ev)
            t = _when(ev)
            seen = prior_logging_read.get(k)
            if seen and t and timedelta(0) <= t - seen <= _WINDOW_RECON:
                # Checking whether you will be recorded, then changing where the
                # record goes. The read is what makes the write deliberate.
                severity = 9.0
                title = ("Invocation logging reconfigured minutes after the actor read "
                         "its current configuration")
                extra["preceded_by_config_read"] = True

        out.append(_det(ev, rule=rule, title=title, severity=severity, extra=extra))
    return out


# ─── the public surface ──────────────────────────────────────────────────────
def detect(events: Iterable[Mapping], *,
           lambda_allowlist: Optional[Iterable[str]] = None
           ) -> List[aws_cdr.NormalizedDetection]:
    """Every LLMjacking and control-tampering detection in these CloudTrail events.

    ``lambda_allowlist`` scopes the ``UpdateFunctionCode`` rule to the functions that
    are actually agent action-group targets; without it that rule stays silent rather
    than firing on every Lambda deploy in the account."""
    evs = [e for e in (events or []) if e]
    allow = set(lambda_allowlist) if lambda_allowlist is not None else None
    by_key = _by_key(evs)
    out: List[aws_cdr.NormalizedDetection] = []
    out += _recon_to_abuse(by_key)
    out += _validation_probe(by_key)
    out += _proxy_fingerprint(evs)
    out += _quota_dodging(by_key)
    out += _tampering(evs, lambda_allowlist=allow)
    return sorted(out, key=lambda d: (-d.severity, d.id))


def _wrap_blast_radius(literal: Mapping, prior: Mapping) -> dict:
    """Merge the blast-radius fields (a dict LITERAL at the call site) onto a
    detection's existing evidence. Named, so Section F can allow it the way it allows
    aws_edr._wrap_identity: the reviewable half stays a literal."""
    out = dict(prior or {})
    out.update(literal)
    return out


def rerank(detections: Iterable[aws_cdr.NormalizedDetection],
           reach: Callable[[str], Mapping]
           ) -> List[aws_cdr.NormalizedDetection]:
    """Re-rank by what the acting identity can actually reach.

    THIS IS THE PART THAT CANNOT BE COPIED FROM A LOG. Every vendor can say an access
    key behaved unusually. Saying that the key belongs to a role which can escalate
    privilege and read a crown-jewel bucket requires the graph, which is why GuardDuty
    rates its own AI findings Low — it has the event and not the environment.

    ``reach(identity_arn)`` returns ``{"privesc": str|None, "crown": str|None}``,
    exactly what ``aws_aispm.role_privesc_effective`` and ``role_reaches_crown``
    already compute. An identity we cannot resolve is left at its intrinsic severity:
    an unknown blast radius is not a large one."""
    out = []
    for det in detections or []:
        arn = det.resource_arn or ""
        info = {}
        if arn.startswith("arn:"):
            try:
                info = reach(arn) or {}
            except Exception:
                info = {}
        privesc, crown = info.get("privesc"), info.get("crown")
        if not (privesc or crown):
            out.append(det)
            continue
        bump = 1.5 if (privesc and crown) else 1.0
        sev = min(10.0, det.severity + bump)
        why = []
        if privesc:
            why.append("the identity can escalate privilege")
        if crown:
            why.append(f"it can read crown-jewel data ({crown})")
        out.append(aws_cdr.NormalizedDetection(
            id=det.id, source=det.source, type=det.type,
            title=det.title + " — " + " and ".join(why),
            severity=sev, band=aws_deepplane.severity_band(sev),
            node_kind=det.node_kind, node_key=det.node_key,
            resource_arn=det.resource_arn, first_seen=det.first_seen,
            evidence=_wrap_blast_radius({"blast_radius_privesc": privesc,
                                         "blast_radius_crown": crown,
                                         "severity_before_join": det.severity},
                                        det.evidence),
        ))
    return sorted(out, key=lambda d: (-d.severity, d.id))
