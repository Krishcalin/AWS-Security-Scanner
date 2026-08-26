#!/usr/bin/env python3
"""aws_mcp.py — Phase 3 · slice 3.3: MCP server provenance.

An AgentCore Gateway *is* an MCP server. What it publishes to an agent is decided by its
targets, and a target is one of four things under the pinned service model:
``openApiSchema``, ``smithyModel``, ``lambda`` — all of which describe an API **inside
this account** — or ``mcpServer``, which is an **endpoint somewhere else**. That fourth
one is the whole slice: it federates a tool provider the account does not run, does not
version, and cannot see inside.

WHAT THE PINNED MODEL ACTUALLY EXPOSES
--------------------------------------
Read from the pinned botocore's own ``service-2.json`` rather than the published API
reference. The difference decides what this module can honestly claim:

* ``McpServerTargetConfiguration`` has exactly ONE member: ``endpoint``. Not the tools,
  not a schema, not a version. The endpoint is the entire provenance record.
* ``MCPGatewayConfiguration`` has ``supportedVersions``, ``instructions``, ``searchType``.
  ``instructions`` is a free-text string (max 2048) handed to the model to tell it how to
  use the gateway — a server-level instruction channel that slice 3.2 does not cover,
  because 3.2 reads per-tool descriptions on Bedrock Agents action groups.

THE PIN MOVED, AND THIS MODULE'S PREMISE MOVED WITH IT
------------------------------------------------------
This module was written against botocore **1.40.51**, where two things did not exist:

* ``ListingMode`` (``DEFAULT`` = tools cached at the control plane, ``DYNAMIC`` =
  retrieved at listing time), so no field said whether a federated server's tool list
  was pinned or live; and
* the **Registry** — ``ListRegistries``, ``GetRegistryRecord`` and the
  ``DRAFT/PENDING_APPROVAL/APPROVED/REJECTED`` lifecycle — so there was no approval
  state to read.

**Both arrive in 1.43.51, which is now the pin.** ``MCP-04``'s finding below — that the
tool list of a federated server cannot be read, so its absence must be *stated* rather
than passed over — was correct under 1.40.51 and is no longer the whole truth. The
behaviour is deliberately UNCHANGED here: bumping a dependency and redesigning a check
are separate pieces of work, and doing both in one change would mean shipping a
rewritten finding nobody reviewed. What is not acceptable is leaving the old rationale
standing as though it still held, which is why it is written down rather than quietly
left. Reading ``ListingMode`` and the Registry approval state is the follow-on.

THE BLIND SPOT IS THE FINDING
-----------------------------
Those absences are not a reason to say less; they are the thing worth saying. For an
``mcpServer`` target, AWS records **where the server is and never what it serves**. A
rug pull — the server that presents benign tools until it is trusted, then changes what
those tools tell the model to do — would therefore leave *no trace anywhere in the
account*. No API returns the tool list, so no scan of any depth can diff it.

That is stated plainly rather than implied by silence, for the same reason 3.4 says out
loud that memory contents were not read: a reader who sees a federated MCP server
reported with no mention of its tools will assume the tools were checked.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Optional, Sequence, Tuple

import aws_checkdef as _cd
from aws_checkdef import CheckDef as _C, Perm as _P
from urllib.parse import urlsplit

__all__ = [
    "TARGET_KINDS", "FEDERATED_KIND", "AWS_SUFFIXES",
    "target_kind", "mcp_endpoint", "endpoint_provenance", "gateway_instructions",
    "assess_target", "surface_fingerprint", "describe", "blind_spot_note",
    "listing_mode", "registry_record", "LISTING_DEFAULT", "LISTING_DYNAMIC",
    "RECORD_APPROVED", "RECORD_REVIEWABLE",
]

#: The four target shapes in ``McpTargetConfiguration`` (botocore 1.40.51). Ordered as
#: the model declares them. Anything outside this tuple is a model the pin does not know,
#: which is reported as unrecognized rather than silently treated as safe.
TARGET_KINDS: Tuple[str, ...] = ("openApiSchema", "smithyModel", "lambda", "mcpServer")

#: The one kind that reaches outside the account for its tool definitions.
FEDERATED_KIND = "mcpServer"

#: Host suffixes AWS itself operates. A gateway endpoint under one of these is still a
#: third party to the ACCOUNT unless it is this account's own gateway, but it is not an
#: arbitrary internet host, and the distinction is worth keeping because the remediation
#: differs: one is a vendor question, the other is an AWS-resource question.
AWS_SUFFIXES: Tuple[str, ...] = (".amazonaws.com", ".aws.dev", ".on.aws")

# Provenance classes.
PROV_AWS = "AWS_HOSTED"
PROV_THIRD_PARTY = "THIRD_PARTY"
PROV_UNKNOWN = "UNKNOWN"

#: McpServerTargetConfiguration.listingMode, from botocore 1.43.51. DEFAULT caches the
#: tool list at the control plane -- so it IS recorded and CAN be diffed. DYNAMIC
#: retrieves it at listing time, so nothing is stored and nothing can be compared.
#: Under the previous pin neither this field nor mcpToolSchema existed, which is why
#: this module used to assert the tool list was never recorded at all.
LISTING_DEFAULT = "DEFAULT"
LISTING_DYNAMIC = "DYNAMIC"

#: RegistryRecordStatus. Only APPROVED means a record cleared the review the registry
#: exists to impose.
RECORD_APPROVED = "APPROVED"
RECORD_REVIEWABLE = ("DRAFT", "PENDING_APPROVAL", "REJECTED", "DEPRECATED")


def _mcp(container: Optional[dict], key: str) -> dict:
    """``{...: {"mcp": {...}}}`` -> the inner dict, tolerant of every wrong shape."""
    if not isinstance(container, dict):
        return {}
    inner = container.get(key)
    if not isinstance(inner, dict):
        return {}
    mcp = inner.get("mcp")
    return mcp if isinstance(mcp, dict) else {}


def target_kind(target: Optional[dict]) -> str:
    """Which of the four ``McpTargetConfiguration`` variants this target is.

    Returns ``""`` when the target carries no configuration — which is the shape
    ``ListGatewayTargets`` returns, and the reason this slice needs ``GetGatewayTarget``.
    An unrecognized key returns ``"unknown:<key>"`` rather than falling through to a
    default: a target variant added after the pin must read as *not understood*, never as
    *understood and fine*."""
    cfg = _mcp(target, "targetConfiguration")
    if not cfg:
        return ""
    for kind in TARGET_KINDS:
        if kind in cfg:
            return kind
    present = sorted(k for k in cfg if not k.startswith("_"))
    return f"unknown:{present[0]}" if present else ""


def mcp_endpoint(target: Optional[dict]) -> str:
    """The federated server's endpoint, or ``""`` for a target of any other kind."""
    cfg = _mcp(target, "targetConfiguration")
    server = cfg.get(FEDERATED_KIND)
    if not isinstance(server, dict):
        return ""
    ep = server.get("endpoint")
    return ep.strip() if isinstance(ep, str) else ""


def endpoint_provenance(endpoint: Optional[str]) -> dict:
    """Everything a URL can establish about who runs a tool provider — and no more.

    Deliberately narrow. A hostname does not tell you who operates a service, whether the
    operator is trustworthy, or whether it is the same organization: those are questions
    for the human reading the finding. What it does tell you is the transport, and
    whether the host sits under a domain AWS operates. Both are facts; anything richer
    would be a guess dressed as provenance."""
    raw = (endpoint or "").strip()
    if not raw:
        return {"endpoint": "", "scheme": "", "host": "", "plaintext": False,
                "provenance": PROV_UNKNOWN,
                "why": "no endpoint was configured"}
    try:
        parts = urlsplit(raw)
    except ValueError:
        return {"endpoint": raw, "scheme": "", "host": "", "plaintext": False,
                "provenance": PROV_UNKNOWN,
                "why": "the endpoint is not a URL this scan could parse"}
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if not host:
        return {"endpoint": raw, "scheme": scheme, "host": "", "plaintext": False,
                "provenance": PROV_UNKNOWN,
                "why": "the endpoint names no host"}
    aws_hosted = any(host == s.lstrip(".") or host.endswith(s) for s in AWS_SUFFIXES)
    # http:// is the finding. A bare scheme (host:port with no scheme) is NOT reported as
    # plaintext -- it is reported as unknown, because guessing which way it resolves would
    # either invent a finding or erase one.
    plaintext = scheme == "http"
    return {
        "endpoint": raw, "scheme": scheme, "host": host, "plaintext": plaintext,
        "provenance": PROV_AWS if aws_hosted else (
            PROV_THIRD_PARTY if scheme in ("http", "https") else PROV_UNKNOWN),
        "why": ("the endpoint is under a domain AWS operates" if aws_hosted else
                "the endpoint is not under any domain AWS operates" if scheme in
                ("http", "https") else
                f"the endpoint uses scheme '{scheme}', which this scan does not "
                f"recognize as a web transport"),
    }


def listing_mode(target: Optional[dict]) -> dict:
    """Whether a federated target's tool list is CACHED or fetched live.

    This field did not exist under the old pin, which is the whole reason MCP-04 used to
    say the tool list was never recorded. DEFAULT means the control plane holds it, so it
    is readable and diffable; DYNAMIC means it is fetched at listing time and nothing is
    stored, so there is genuinely nothing to compare against."""
    cfg = _mcp(target, "targetConfiguration").get(FEDERATED_KIND)
    cfg = cfg if isinstance(cfg, dict) else {}
    mode = cfg.get("listingMode") or ""
    schema = cfg.get("mcpToolSchema")
    return {
        "mode": mode,
        "known": mode in (LISTING_DEFAULT, LISTING_DYNAMIC),
        "dynamic": mode == LISTING_DYNAMIC,
        "schema_recorded": bool(schema),
    }


def gateway_instructions(gateway: Optional[dict]) -> str:
    """``protocolConfiguration.mcp.instructions`` — what the gateway tells the MODEL.

    A server-level instruction channel. The operator reading the console sees a field
    that documents how to use the gateway; the model reads it as direction. That is the
    same asymmetry slice 3.2 found in a tool's description, one level up, and it is why
    this string is handed to ``aws_toolpoison`` unchanged rather than pattern-matched
    here -- authoring injection phrasings is what 3.2 refuses to do, and refusing it once
    is worth nothing if the next module does it."""
    text = _mcp(gateway, "protocolConfiguration").get("instructions")
    return text if isinstance(text, str) else ""


def assess_target(target: Optional[dict]) -> dict:
    """One gateway target: what it is, and — if it federates — where from."""
    kind = target_kind(target)
    name = ""
    if isinstance(target, dict):
        name = str(target.get("name") or target.get("targetId") or "")
    out = {"name": name, "kind": kind, "federated": kind == FEDERATED_KIND,
           "readable": bool(kind), "endpoint": "", "provenance": PROV_UNKNOWN,
           "plaintext": False, "host": "", "why": "",
           "listing": {"mode": "", "known": False, "dynamic": False,
                       "schema_recorded": False}}
    if kind != FEDERATED_KIND:
        return out
    prov = endpoint_provenance(mcp_endpoint(target))
    out.update({"endpoint": prov["endpoint"], "provenance": prov["provenance"],
                "plaintext": prov["plaintext"], "host": prov["host"],
                "why": prov["why"],
                # listingMode and mcpToolSchema arrived with the SDK pin bump; under the
                # old pin neither existed, which is why this module used to assert the
                # tool list was never recorded.
                "listing": listing_mode(target)})
    return out


def blind_spot_note(assessment: Optional[dict]) -> str:
    """The sentence that keeps a federated target from reading as an audited one.

    Empty for every non-federated kind: an ``openApiSchema`` or ``lambda`` target has its
    tool definitions IN the account, so there is no blind spot to declare and saying
    otherwise would be alarm without content."""
    a = assessment or {}
    if not a.get("federated"):
        return ""
    lm = a.get("listing") or {}
    if lm.get("dynamic"):
        return ("this server's tool list is retrieved at listing time (listingMode "
                "DYNAMIC) rather than cached, so nothing about the tools is stored in "
                "this account and a change to what they tell the model to do leaves no "
                "trace here. Unlike a platform limit this IS a configuration choice: "
                "DEFAULT caches the schema, which makes it readable and diffable")
    if lm.get("known") and lm.get("schema_recorded"):
        return ""       # the schema IS recorded -- there is no blind spot to declare
    return ("no tool schema is recorded for this server, so a change to what its tools "
            "tell the model to do would leave no trace in this account. Where "
            "listingMode is DEFAULT the control plane caches the schema and it can be "
            "diffed; here there is nothing cached to compare against")


def describe(assessment: Optional[dict]) -> str:
    """One line an operator can act on."""
    a = assessment or {}
    if not a.get("readable"):
        return ("the target's configuration could not be read, so what it publishes to "
                "the agent is unknown")
    if not a.get("federated"):
        return (f"the target is a {a.get('kind')} defined inside this account")
    where = a.get("host") or "an endpoint this scan could not parse"
    lead = (f"the gateway federates a Model Context Protocol server at {where}, whose "
            f"tool definitions come from outside this account")
    if a.get("plaintext"):
        lead += (" over plaintext http — the tool definitions the model is handed, and "
                 "the arguments it sends back, cross the network in the clear, so "
                 "anyone on the path can rewrite what a tool claims to do")
    return lead


def registry_record(record: Optional[dict]) -> dict:
    """A registry record that never cleared approval.

    The AgentCore Registry and its DRAFT/PENDING_APPROVAL/APPROVED/REJECTED lifecycle
    did not exist under the old pin, so there was no approval state to read and this
    module said so. There is now."""
    r = record if isinstance(record, dict) else {}
    status = r.get("status") or ""
    return {
        "name": r.get("name") or r.get("recordId") or "",
        "record_id": r.get("recordId") or "",
        "status": status,
        "known": bool(status),
        "approved": status == RECORD_APPROVED,
        "awaiting_review": status in RECORD_REVIEWABLE,
        "statement": (
            f"AgentCore registry record {r.get('name') or r.get('recordId')} is in "
            f"status {status} rather than APPROVED. A registry exists to put a review "
            f"between an agent component and the fleet that will use it, so a record "
            f"sitting in {status} is either a component nobody finished approving or one "
            f"an approver actively turned down — and in both cases the registry is "
            f"reporting a governance step that did not complete"
            if status and status != RECORD_APPROVED else ""),
    }


def surface_fingerprint(gateway: Optional[dict],
                        targets: Optional[Sequence[dict]] = None) -> str:
    """A stable digest of everything configuration says decides the agent's tool surface.

    This is the rug-pull anchor: with no field naming whether a federated server's tool
    list is pinned, a CHANGE to the surface is what can still be established — but only
    across scans, and only for the part AWS records. Fingerprinting the endpoint catches
    a target repointed at a different server; it cannot catch the same server serving
    different tools, and ``blind_spot_note`` is what keeps that limit visible.

    Sorted and JSON-serialized with separators fixed, so the digest depends on the
    configuration and never on dict ordering or the SDK's serialization."""
    payload = {
        "instructions": gateway_instructions(gateway),
        "supported_versions": sorted(
            str(v) for v in (_mcp(gateway, "protocolConfiguration")
                             .get("supportedVersions") or [])
            if isinstance(v, (str, int, float))),
        "targets": sorted(
            [f"{a['name']}|{a['kind']}|{a['endpoint']}"
             for a in (assess_target(t) for t in (targets or []))]),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# MCP-06 — the AgentCore Registry, readable since the SDK pin moved to 1.43.51.
# Declared here rather than in an aws_extsvc module because it belongs to this
# module's subject: what the account can and cannot see about a federated agent
# component.
# ══════════════════════════════════════════════════════════════════════════════
CHECKS = _cd.register(
    _C(id="MCP-06", section="AGENTCORE", severity="MEDIUM",
       # CM-3 (Configuration Change Control) is the precise control and would be
       # the 39th member of a universe frozen at 38 -- the denominator the
       # evidence pack counts against. CM-5 (Access Restrictions for Change) is
       # the in-universe fit: an approval gate IS an access restriction on change.
       compliance={"PCI-DSS": "6.5.1", "HIPAA": "164.308(a)(1)", "SOC2": "CC8.1",
                   "NIST": "CM-5"},
       permissions=(
           _P("bedrock-agentcore:ListRegistries",
              "enumerate the AgentCore registries that govern which agent components "
              "may be used in this account"),
           _P("bedrock-agentcore:ListRegistryRecords",
              "read each record's approval status -- a registry exists to put a review "
              "between a component and the fleet that will use it"),
       ),
       remediation=(
           "Move the record through the approval it is waiting on, or remove it if it "
           "should not be there: aws bedrock-agentcore-control get-registry-record "
           "--registry-identifier <REG> --record-id <ID> to see why it is held, then "
           "aws bedrock-agentcore-control submit-registry-record-for-approval "
           "--registry-identifier <REG> --record-id <ID> to advance it, or aws "
           "bedrock-agentcore-control delete-registry-record --registry-identifier "
           "<REG> --record-id <ID> to withdraw it. A REJECTED record left in place is "
           "the one worth asking about"),
       risk=(
           "This AgentCore registry record is not in APPROVED status. A registry exists "
           "for one reason: to put a review between an agent component -- a tool, a "
           "gateway target, an MCP server -- and the fleet of agents that will act on "
           "what it returns. A record sitting in DRAFT or PENDING_APPROVAL is a "
           "component whose review never finished, and one in REJECTED is a component "
           "somebody actively turned down and which is still catalogued. Either way the "
           "registry is reporting a governance step that did not complete, and the "
           "danger is what a reviewer concludes from the registry's existence: that "
           "components are vetted. Worth noting what this check does NOT establish -- "
           "whether an unapproved record is actually in use by a running agent. The "
           "registry records the approval state, not the consumption, so treat this as "
           "a governance gap to resolve rather than as evidence that something "
           "unreviewed is live. This check was not possible before the SDK pin moved to "
           "botocore 1.43.51, where the Registry and its lifecycle first appear."),
       impact=("A component that never cleared review, or was rejected, remains "
               "catalogued in a registry whose existence implies components are vetted."),
       steps=(
           "Read why the record is held: aws bedrock-agentcore-control "
           "get-registry-record --registry-identifier <REG> --record-id <ID>",
           "Advance it if the review simply stalled: aws bedrock-agentcore-control "
           "submit-registry-record-for-approval --registry-identifier <REG> --record-id "
           "<ID>",
           "Withdraw it if it should not be catalogued: aws bedrock-agentcore-control "
           "delete-registry-record --registry-identifier <REG> --record-id <ID>",
           "Treat a REJECTED record left in place as the one worth asking about -- "
           "somebody looked at that component and said no.",
           "Check separately whether any agent actually consumes it; the registry "
           "records approval state, not consumption.")),
)
