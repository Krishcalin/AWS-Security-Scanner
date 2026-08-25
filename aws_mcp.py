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
Read from botocore **1.40.51**'s own ``service-2.json`` — the version this project pins —
not from the published API reference, which is well ahead of it. The difference decides
what this module can honestly claim:

* ``McpServerTargetConfiguration`` has exactly ONE member: ``endpoint``. Not the tools,
  not a schema, not a version. The endpoint is the entire provenance record.
* ``MCPGatewayConfiguration`` has ``supportedVersions``, ``instructions``, ``searchType``.
  ``instructions`` is a free-text string (max 2048) handed to the model to tell it how to
  use the gateway — a server-level instruction channel that slice 3.2 does not cover,
  because 3.2 reads per-tool descriptions on Bedrock Agents action groups.
* ``ListingMode`` (``DEFAULT`` = tools cached at the control plane, ``DYNAMIC`` = tools
  retrieved at listing time) does **not exist** in 1.40.51. It arrives in 1.43.51. Under
  the pin there is no configuration field that says whether a federated server's tool
  list is pinned or live.
* The Registry — ``ListRegistries``, ``GetRegistryRecord``, and the
  ``DRAFT/PENDING_APPROVAL/APPROVED/REJECTED`` lifecycle — does not exist in 1.40.51
  either. There is no approval state to read.

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
from urllib.parse import urlsplit

__all__ = [
    "TARGET_KINDS", "FEDERATED_KIND", "AWS_SUFFIXES",
    "target_kind", "mcp_endpoint", "endpoint_provenance", "gateway_instructions",
    "assess_target", "surface_fingerprint", "describe", "blind_spot_note",
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
           "plaintext": False, "host": "", "why": ""}
    if kind != FEDERATED_KIND:
        return out
    prov = endpoint_provenance(mcp_endpoint(target))
    out.update({"endpoint": prov["endpoint"], "provenance": prov["provenance"],
                "plaintext": prov["plaintext"], "host": prov["host"],
                "why": prov["why"]})
    return out


def blind_spot_note(assessment: Optional[dict]) -> str:
    """The sentence that keeps a federated target from reading as an audited one.

    Empty for every non-federated kind: an ``openApiSchema`` or ``lambda`` target has its
    tool definitions IN the account, so there is no blind spot to declare and saying
    otherwise would be alarm without content."""
    a = assessment or {}
    if not a.get("federated"):
        return ""
    return ("AWS records this server's endpoint and never the tools it serves, so a "
            "change to what those tools tell the model to do would leave no trace in "
            "this account — the tool list is not a thing any API here returns, which "
            "means no scan of any depth can diff it")


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
