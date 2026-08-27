#!/usr/bin/env python3
"""aws_ailog.py — Phase 4 · slice 4.3: where the prompts land, and who saw the call.

Two gaps, one theme: OverWatch already tells operators to turn AI logging **on** and
never asks what that produces.

**`BDR-01` names a destination and stops there.** It checks that Bedrock model invocation
logging is configured and reports where it points. But when ``textDataDeliveryEnabled``
is true, that bucket or log group receives **every prompt and every completion** the
account produces. It becomes, on the day it is switched on, the most sensitive AI
artifact in the account — and nothing checked whether it is public, encrypted, or
retained forever.

That is not an argument against logging. `BDR-01` is right: invocation logs are the only
control in the AI pillar that produces evidence after an incident. The point is that
enabling them **creates a crown jewel**, and the crown jewel has to be treated as one.
This module is the second half of `BDR-01`'s own advice.

**`LOG-08` asks whether a trail records data events at all.** It cannot say *which*, so
an account can pass it while no trail anywhere records ``AWS::Bedrock::Model`` — meaning
there is no record of who invoked which model, with which identity, from where. That is
precisely the question `AITHR-01` needs answered to detect LLMjacking, and precisely the
question an incident responder asks first.

WHAT WAS VERIFIED RATHER THAN ASSUMED
--------------------------------------
* ``LoggingConfig`` carries four separate delivery switches — ``textDataDeliveryEnabled``,
  ``imageDataDeliveryEnabled``, ``embeddingDataDeliveryEnabled``,
  ``videoDataDeliveryEnabled`` — read off botocore 1.43.51. They are independent, so a
  config can log text and not images, and the sensitivity of the destination follows
  whichever are on.
* ``cloudWatchConfig`` carries ``largeDataDeliveryS3Config``: a **second** S3 destination
  used when a payload is too big for CloudWatch. It is easy to configure once and forget,
  and it receives exactly the large prompts most likely to contain a pasted document.
  Checking only ``s3Config`` would miss it.
* Bedrock data events need **advanced** event selectors. Basic ones accept only
  ``AWS::DynamoDB::Table``, ``AWS::Lambda::Function`` and ``AWS::S3::Object`` — so a trail
  with basic selectors can never carry Bedrock activity, however many data events it
  logs. ``BEDROCK_DATA_TYPES`` below is taken verbatim from the CloudTrail reference.

Pure functions over dicts. No boto3, no network, no I/O. This module reads logging
CONFIGURATION and never log contents: the whole reason the destination matters is that
it holds prompts, and a scanner that read them to check them would be the second copy of
the problem — the same reasoning as **D2** and **D8**.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

__all__ = [
    "DELIVERY_SWITCHES", "SENSITIVE_SWITCHES", "BEDROCK_DATA_TYPES",
    "AGENTCORE_DATA_TYPES", "MODEL_DATA_TYPE",
    "delivery_posture", "log_destinations", "trail_ai_data_events",
    "describe_delivery", "CONTENTS_NOT_READ",
]

#: The four independent delivery switches on LoggingConfig, in the order the model
#: declares them.
DELIVERY_SWITCHES: Tuple[str, ...] = (
    "textDataDeliveryEnabled", "imageDataDeliveryEnabled",
    "embeddingDataDeliveryEnabled", "videoDataDeliveryEnabled",
)

#: The switches whose payload is the user's own input or the model's own output. All four
#: are sensitive; these are the ones that make the destination a prompt store rather than
#: a metrics store, and they are what decides whether this slice raises anything.
SENSITIVE_SWITCHES: Tuple[str, ...] = (
    "textDataDeliveryEnabled", "imageDataDeliveryEnabled", "videoDataDeliveryEnabled",
)

#: CloudTrail advanced-event-selector resources.type for model invocation. The single
#: most important one: without it there is no record of who called which model.
MODEL_DATA_TYPE = "AWS::Bedrock::Model"

#: Bedrock data-event resource types, verbatim from the CloudTrail data-events reference.
#: Not exhaustive of the service -- these are the ones whose absence is a forensic gap
#: an AI incident actually runs into.
BEDROCK_DATA_TYPES: Tuple[str, ...] = (
    "AWS::Bedrock::Model",
    "AWS::Bedrock::AgentAlias",
    "AWS::Bedrock::KnowledgeBase",
    "AWS::Bedrock::Guardrail",
    "AWS::Bedrock::Session",
    "AWS::Bedrock::InlineAgent",
)

#: AgentCore data-event resource types. Separate from the Bedrock tuple because an
#: account can run one estate and not the other, and reporting a gap in a service the
#: customer does not use is noise.
AGENTCORE_DATA_TYPES: Tuple[str, ...] = (
    "AWS::BedrockAgentCore::Runtime",
    "AWS::BedrockAgentCore::Gateway",
    "AWS::BedrockAgentCore::Memory",
    "AWS::BedrockAgentCore::TokenVault",
    "AWS::BedrockAgentCore::CodeInterpreter",
    "AWS::BedrockAgentCore::Browser",
)

CONTENTS_NOT_READ = (
    "OverWatch reads the logging CONFIGURATION and never the logs: what the prompts say "
    "is not a question this scan asks"
)


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


def delivery_posture(config: Optional[dict]) -> dict:
    """Which modalities Bedrock is writing, and therefore how sensitive the sink is."""
    c = _d(config)
    on = [s for s in DELIVERY_SWITCHES if c.get(s) is True]
    sensitive = [s for s in on if s in SENSITIVE_SWITCHES]
    return {
        "enabled": bool(c),
        "delivering": on,
        "sensitive": sensitive,
        # The destination holds user input or model output, not just metadata.
        "carries_content": bool(sensitive),
        "modalities": [s.replace("DataDeliveryEnabled", "") for s in on],
    }


def log_destinations(config: Optional[dict]) -> List[dict]:
    """Every sink the logging config writes to.

    Returns a list because there can be THREE: an S3 bucket, a CloudWatch log group, and
    the ``largeDataDeliveryS3Config`` bucket CloudWatch overflows into. That last one is
    the one operators forget, and it receives the largest payloads — the pasted documents
    and long transcripts — which makes forgetting it the expensive case."""
    c = _d(config)
    out: List[dict] = []
    s3 = _d(c.get("s3Config"))
    if s3.get("bucketName"):
        out.append({"kind": "s3", "name": s3["bucketName"],
                    "prefix": s3.get("keyPrefix") or "", "role": "primary"})
    cw = _d(c.get("cloudWatchConfig"))
    if cw.get("logGroupName"):
        out.append({"kind": "cloudwatch", "name": cw["logGroupName"],
                    "prefix": "", "role": "primary"})
    large = _d(cw.get("largeDataDeliveryS3Config"))
    if large.get("bucketName"):
        out.append({"kind": "s3", "name": large["bucketName"],
                    "prefix": large.get("keyPrefix") or "",
                    "role": "large-payload overflow"})
    return out


def _selector_types(trail_selectors: Optional[dict]) -> set:
    """resources.type values a trail's ADVANCED selectors name.

    Basic ``EventSelectors`` are deliberately ignored: they accept only DynamoDB, Lambda
    and S3 object types, so a trail configured that way cannot carry Bedrock activity at
    all. Counting them would let a trail with S3 data events look like AI coverage."""
    out = set()
    for aes in (_d(trail_selectors).get("AdvancedEventSelectors") or []):
        if not isinstance(aes, dict):
            continue
        for fs in (aes.get("FieldSelectors") or []):
            if isinstance(fs, dict) and fs.get("Field") == "resources.type":
                out.update(v for v in (fs.get("Equals") or []) if isinstance(v, str))
    return out


def trail_ai_data_events(trails: Optional[Sequence[dict]]) -> dict:
    """Which AI resource types are covered by data events, across ALL trails.

    A union, because coverage is satisfied by any one trail: an account with a dedicated
    Bedrock trail and a broad management trail is correctly configured, and evaluating
    trails independently would report the management trail as a gap.

    ``trails`` is a sequence of ``{"name": str, "selectors": <GetEventSelectors output>}``.
    ``None`` means the selectors could not be read, which the caller keeps distinct from
    "read, and empty"."""
    covered, by_trail = set(), {}
    for t in (trails or []):
        if not isinstance(t, dict):
            continue
        types = _selector_types(t.get("selectors"))
        ai = {x for x in types
              if x in BEDROCK_DATA_TYPES or x in AGENTCORE_DATA_TYPES}
        if ai:
            by_trail[t.get("name") or "trail"] = sorted(ai)
        covered |= ai
    return {
        "covered": sorted(covered),
        "by_trail": by_trail,
        "model_invocations": MODEL_DATA_TYPE in covered,
        "bedrock_missing": [t for t in BEDROCK_DATA_TYPES if t not in covered],
        "agentcore_missing": [t for t in AGENTCORE_DATA_TYPES if t not in covered],
        "any": bool(covered),
    }


def describe_delivery(posture: Optional[dict], sinks: Optional[Sequence[dict]]) -> str:
    """One line saying what is being written and where, without quoting any of it."""
    p = _d(posture)
    if not p.get("carries_content"):
        return ""
    where = ", ".join(
        f"{s['name']}"
        + (f" ({s['role']})" if s.get("role") and s["role"] != "primary" else "")
        for s in (sinks or []))
    mods = " and ".join(p.get("modalities") or [])
    return (f"Bedrock is writing {mods} payloads — the prompts users send and the "
            f"completions the model returns — to {where or 'a configured destination'}")
