"""Phase 3 · slice 3.1 — toxic flow: what an injected agent reaches.

The in-charter answer to "do you red team?" (decision D4). Rather than probing a
customer's model — which spends their inference budget and produces, in their own
CloudTrail, the exact signature ``AITHR-01`` exists to alarm on — this computes what an
injection WOULD reach, from configuration the scanner already holds.

Structurally it is attack-path analysis pointed at an agent, and it deliberately reuses
that engine's discipline rather than inventing a parallel one::

    entry  ->  agent  ->  tools + execution role  ->  terminal
    (gated)                (AGY, AISPM)              (crown data / admin)

THE GATE, AND WHY IT IS THE WHOLE DESIGN
----------------------------------------
``aws_correlate.enumerate_paths`` refuses to record a DATA terminal unless the chain owns
an exploitable host or is a direct public crown — compute the chain always, gate the
terminal on a proven entry. Toxic flow applies the same rule, and the agent equivalent of
a proven entry turns out to be readable:

* **PROVEN** — a knowledge base ingests content from outside the customer's control. A
  ``WEB`` data source crawls the open internet ("The configuration of web URLs to crawl",
  per the API reference). An ``S3`` data source whose bucket policy grants **write** to
  ``*`` or an external account means anyone so granted can place a document the agent
  will read. Neither is an assumption; both are configuration.

* **ASSUMED** — everything else. The flow is still computed and still reported, as
  ``CONDITIONAL``, saying plainly that it rests on an injection landing by a route this
  scanner cannot see. That is the class ``aws_epistemics`` defined in slice 0.4 and the
  honest home for this half.

WHAT THIS DELIBERATELY DOES NOT CLAIM
-------------------------------------
*That an injection has occurred.* Nothing here reads a prompt, a completion or a log.
Every finding is capability, and the ``PROVEN``/``ASSUMED`` split is about whether the
ENTRY is observable, never about whether the attack happened.

*That an attenuated flow is a safe one.* A mandatory blocking guardrail and a human
confirmation gate genuinely reduce a flow, and the computation says so — but neither is a
proof, and the reduction is bounded so a fully-attenuated flow never disappears. A tool
that let a guardrail zero out a path would be teaching operators that the guardrail is a
boundary, which is the belief `AIGRD-01` exists to correct.

Pure functions over dicts — no boto3, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ── entry ───────────────────────────────────────────────────────────────────
PROVEN = "PROVEN"
ASSUMED = "ASSUMED"
ENTRY_CLASSES = (PROVEN, ASSUMED)

#: Data-source types, from the Bedrock Agent DataSourceConfiguration reference.
DATA_SOURCE_TYPES = ("S3", "WEB", "CONFLUENCE", "SALESFORCE", "SHAREPOINT", "CUSTOM",
                     "REDSHIFT_METADATA", "MANAGED_KNOWLEDGE_BASE_CONNECTOR")

#: A crawler over the open web ingests content nobody in the account authored. That is
#: an observable untrusted-content path, not an assumption about one.
UNTRUSTED_BY_TYPE = ("WEB",)

#: Internal but MULTI-AUTHOR. Anyone who can write a Confluence page or a Salesforce note
#: can write into the agent's context. Real, and weaker than the open web, because the
#: authors are at least inside the organisation — so these raise the assumed flow's
#: ranking without making the entry proven.
MULTI_AUTHOR_BY_TYPE = ("CONFLUENCE", "SHAREPOINT", "SALESFORCE")

#: S3 write actions. A bucket policy granting any of these to a principal outside the
#: account means that principal can place a document the agent will later read.
_WRITE_ACTIONS = ("s3:putobject", "s3:put*", "s3:*", "*")

#: Principal scopes aws_live_scanner's bucket-policy classifier reports as reaching
#: outside the account. "org" is deliberately absent: an organisation is inside the trust
#: boundary for this purpose, and treating a sibling account as an attacker would fire on
#: the normal shape of a multi-account estate.
_EXTERNAL_SCOPES = ("public", "public_conditioned", "cross_account")


def _upper(v: Any) -> str:
    return str(v).upper() if isinstance(v, str) else ""


def source_is_untrusted(source: Optional[dict],
                        bucket_write_scope: Optional[str] = None) -> dict:
    """Is this data source a path for content the customer does not control?

    ``source`` is a ``get_data_source(...)["dataSource"]`` response.
    ``bucket_write_scope`` is what the bucket-policy classifier said about the statements
    granting WRITE on the backing bucket — ``public``, ``cross_account``, ``org`` or
    None. It is passed in rather than derived here so this module stays pure and the
    scanner keeps one implementation of bucket-policy reading."""
    s = source if isinstance(source, dict) else {}
    cfg = s.get("dataSourceConfiguration") or {}
    stype = _upper(cfg.get("type"))
    name = s.get("name") or s.get("dataSourceId") or "?"

    if stype in UNTRUSTED_BY_TYPE:
        return {"untrusted": True, "class": PROVEN, "type": stype, "name": name,
                "why": ("crawls web URLs, so its content is authored outside the "
                        "account entirely")}

    if stype == "S3" and bucket_write_scope in _EXTERNAL_SCOPES:
        bucket = ((cfg.get("s3Configuration") or {}).get("bucketArn") or "").split(
            ":::")[-1]
        return {"untrusted": True, "class": PROVEN, "type": stype, "name": name,
                "why": (f"its S3 bucket{' ' + bucket if bucket else ''} grants WRITE to "
                        f"{bucket_write_scope.replace('_', ' ')}, so anyone so granted "
                        f"can place a document the agent will read")}

    if stype in MULTI_AUTHOR_BY_TYPE:
        return {"untrusted": False, "class": ASSUMED, "type": stype, "name": name,
                "why": (f"{stype.title()} content has many authors inside the "
                        f"organisation, so the context is writable by more people than "
                        f"operate the agent")}

    return {"untrusted": False, "class": ASSUMED, "type": stype or "unknown",
            "name": name, "why": "content originates inside the account"}


def injection_surface(sources: Optional[Sequence[dict]] = None,
                      write_scopes: Optional[Dict[str, str]] = None) -> dict:
    """The agent's entry, classified.

    ``write_scopes`` maps a data source id to the principal scope of the WRITE grants on
    its backing bucket. Absent means we could not read the policy, which leaves the
    source ASSUMED rather than proven — an unreadable policy is not an open one."""
    ws = write_scopes or {}
    assessed = [source_is_untrusted(s, ws.get((s or {}).get("dataSourceId")))
                for s in (sources or []) if isinstance(s, dict)]
    proven = [a for a in assessed if a["untrusted"]]
    multi = [a for a in assessed if not a["untrusted"]
             and a["type"] in MULTI_AUTHOR_BY_TYPE]
    return {
        "entry_class": PROVEN if proven else ASSUMED,
        "proven": proven,
        "multi_author": multi,
        "sources": len(assessed),
        "types": sorted({a["type"] for a in assessed if a["type"]}),
    }


# ── attenuation ─────────────────────────────────────────────────────────────
#: What each control removes from a flow. Bounded on purpose: the product of every
#: attenuator can never reach zero, because neither control is a proof and a flow that
#: disappeared behind a guardrail would teach exactly the belief AIGRD-01 corrects.
_ATTEN_BLOCKING_GUARDRAIL = 0.6      # blocks prompt attacks at MEDIUM+ on input
_ATTEN_MANDATORY_GUARDRAIL = 0.75    # ...and cannot be omitted by the caller
_ATTEN_FULL_CONFIRMATION = 0.5       # every action needs a human
_ATTEN_PARTIAL_CONFIRMATION = 0.8
_ATTEN_FLOOR = 0.2                   # a fully-attenuated flow is reduced, never erased


def attenuation(*, guardrail_blocks: bool = False, guardrail_mandatory: bool = False,
                confirmation_gated: int = 0, confirmation_total: int = 0) -> dict:
    """How much the controls between the injection and the act reduce this flow.

    Each factor is a multiplier below 1.0 and the product is floored. The floor is the
    honest part: a guardrail raises the cost of an injection and does not make one
    impossible — AWS's own reference records that guardrail input tags can bypass the
    input check — and a confirmation gate only helps if a human actually reads it."""
    factor = 1.0
    applied: List[str] = []
    if guardrail_blocks:
        factor *= _ATTEN_BLOCKING_GUARDRAIL
        applied.append("a guardrail blocks prompt attacks on input")
        if guardrail_mandatory:
            factor *= _ATTEN_MANDATORY_GUARDRAIL
            applied.append("and IAM makes it mandatory, so a caller cannot omit it")
    if confirmation_total:
        if confirmation_gated >= confirmation_total:
            factor *= _ATTEN_FULL_CONFIRMATION
            applied.append("every action requires human confirmation")
        elif confirmation_gated:
            factor *= _ATTEN_PARTIAL_CONFIRMATION
            applied.append(f"{confirmation_gated} of {confirmation_total} actions "
                           f"require human confirmation")
    return {"factor": max(_ATTEN_FLOOR, round(factor, 3)),
            "applied": applied,
            "floored": factor < _ATTEN_FLOOR}


# ── the flow ────────────────────────────────────────────────────────────────
#: Terminal weights. Admin capability outranks crown data for the same reason
#: aws_correlate does it: reaching admin is reaching everything, including the data.
_W_ADMIN = 1.0
_W_CROWN = 0.85
#: A high-agency capability multiplies the flow because it converts an instruction into
#: an effect without touching the execution role at all.
_W_CAPABILITY = {"CRITICAL": 1.0, "HIGH": 0.8, "": 0.6}


def compute_flow(*, agent_name: str,
                 entry: Optional[dict] = None,
                 privesc: Optional[str] = None,
                 crown: Optional[str] = None,
                 capabilities: Optional[Sequence[str]] = None,
                 capability_severity: str = "",
                 atten: Optional[dict] = None) -> Optional[dict]:
    """One agent's toxic flow, or None when there is nothing to reach.

    A flow needs a terminal. An agent whose role can neither escalate nor read crown
    data, and which holds no high-agency capability, has no flow to report however
    reachable it is — an injection that arrives somewhere harmless is not a finding, and
    reporting one is how a flagship computation becomes noise."""
    caps = [c for c in (capabilities or []) if c]
    if not (privesc or crown or caps):
        return None

    # A non-dict entry reaches here whenever a stash field is malformed. Falling back to
    # ASSUMED rather than raising is the safe direction twice over: the emitter keeps
    # running for the other agents, and an unreadable entry never becomes a proven one.
    e = entry if isinstance(entry, dict) else {"entry_class": ASSUMED, "proven": [],
                                               "multi_author": []}
    a = atten if isinstance(atten, dict) else attenuation()

    terminals: List[str] = []
    weight = 0.0
    if privesc:
        terminals.append("admin capability")
        weight = max(weight, _W_ADMIN)
    if crown:
        terminals.append(f"crown-jewel data ({crown})")
        weight = max(weight, _W_CROWN)
    if caps and not terminals:
        terminals.append("direct execution via " + ", ".join(caps))
    if caps:
        weight = max(weight, _W_CAPABILITY.get(capability_severity, 0.6))

    proven = e.get("entry_class") == PROVEN
    # A proven entry is worth more than an assumed one because it is the difference
    # between an observed route in and a premise. It is a ranking input, not a licence
    # to call the assumed case an incident.
    entry_weight = 1.0 if proven else 0.55
    score = round(100 * weight * entry_weight * a["factor"])

    return {
        "agent": agent_name,
        "entry_class": e["entry_class"],
        "proven_via": [p["name"] for p in e.get("proven") or []],
        "proven_why": [p["why"] for p in e.get("proven") or []],
        "multi_author": [m["name"] for m in e.get("multi_author") or []],
        "terminals": terminals,
        "privesc": privesc,
        "crown": crown,
        "capabilities": caps,
        "attenuation": a,
        "score": max(0, min(100, score)),
    }


def describe(flow: Optional[dict]) -> str:
    """The sentence a report shows. Says what is known, what is assumed, and what
    stands between the two — in that order, because a reader who stops after the first
    clause should not come away with the wrong impression."""
    if not flow:
        return ""
    f = flow
    reach = " and ".join(f["terminals"]) or "nothing"
    if f["entry_class"] == PROVEN:
        head = (f"Agent '{f['agent']}' ingests content from outside this account "
                f"({', '.join(f['proven_via'])}) and reaches {reach}")
    else:
        head = (f"IF an injection reaches agent '{f['agent']}', it reaches {reach}. "
                f"No untrusted-content path is observable, so the entry is assumed")
    if f["attenuation"]["applied"]:
        head += ". Between the two: " + "; ".join(f["attenuation"]["applied"])
    else:
        head += ". Nothing stands between the instruction and the act"
    return head
