"""Phase 2 · slice 2.4 — excessive agency and the human-in-the-loop gate.

OWASP LLM06 splits "excessive agency" into three: too much functionality, too many
permissions, too much autonomy. OverWatch already covers the middle one — AISPM-01/02
grade what an agent's execution role reaches. This module covers the other two, and both
are readable straight from an agent's action-group configuration.

**Too much functionality.** ``parentActionSignature`` names the built-in capabilities an
action group grants, and the enum is more alarming than it first looks::

    AMAZON.UserInput | AMAZON.CodeInterpreter | ANTHROPIC.Computer
                     | ANTHROPIC.Bash | ANTHROPIC.TextEditor

``ANTHROPIC.Bash`` is shell execution. ``ANTHROPIC.Computer`` is desktop control — AWS
describes it as a beta capability that lets the model operate a machine. ``TextEditor``
reads and writes files. ``CodeInterpreter`` runs code. Only ``AMAZON.UserInput`` is
benign: it lets the agent ask a question back.

**Too much autonomy.** Each function carries ``requireConfirmation`` (``ENABLED |
DISABLED``), and AWS is explicit about both its purpose and its default. On purpose:
*"You can safeguard your application from malicious prompt injections by requesting
confirmation from your application users before invoking the action group function."* On
default: *"By default, user confirmation is DISABLED if this field is not specified."*

So the control AWS itself names as the prompt-injection safeguard is off unless somebody
turned it on, and nothing in a cloud inventory shows you which agents left it off.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
-----------------------------------------
*Infer consequence from a function's NAME.* It is tempting to flag ``delete_account`` or
``send_payment`` as high-consequence and let ``get_weather`` pass. That is a guess about
semantics dressed as a reading of configuration, it fails on every naming convention that
is not English, and the first false positive on a read-only function called ``purge_cache``
teaches an operator to stop reading the category. What is reported instead is the
configuration: which capabilities are granted, and how many functions are gated.

Pure functions over dicts — no boto3, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

# ── the vocabulary, from the Bedrock Agent API reference ────────────────────
CONFIRMATION_STATES = ("ENABLED", "DISABLED")
ACTION_GROUP_STATES = ("ENABLED", "DISABLED")
PARENT_SIGNATURES = ("AMAZON.UserInput", "AMAZON.CodeInterpreter",
                     "ANTHROPIC.Computer", "ANTHROPIC.Bash", "ANTHROPIC.TextEditor")

#: Built-in capabilities and what an agent holding one can actually do, with the
#: severity each earns on its own. UserInput is deliberately absent — it lets the agent
#: ask the user a question, which is the opposite of excessive agency.
HIGH_AGENCY: Dict[str, Dict[str, str]] = {
    "ANTHROPIC.Bash": {
        "severity": "CRITICAL",
        "grants": "shell command execution",
        "why": ("an injected instruction becomes a shell command on the machine the "
                "agent runs on"),
    },
    "ANTHROPIC.Computer": {
        "severity": "CRITICAL",
        "grants": "desktop control (screenshots, mouse, keyboard)",
        "why": ("the agent operates a machine as a user would, so anything that user "
                "can reach is reachable by an instruction the agent was given"),
    },
    "AMAZON.CodeInterpreter": {
        "severity": "HIGH",
        "grants": "arbitrary code execution in a sandbox",
        "why": ("a sandbox bounds the filesystem, not the credentials the code runs "
                "with or the network it can reach"),
    },
    "ANTHROPIC.TextEditor": {
        "severity": "HIGH",
        "grants": "file read and write",
        "why": ("writing files is how an injected instruction persists past the "
                "conversation that carried it"),
    },
}

BENIGN_SIGNATURES = ("AMAZON.UserInput",)

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


# ── functionality ───────────────────────────────────────────────────────────
def group_capabilities(group: Optional[dict]) -> dict:
    """The built-in capability an action group grants, if any.

    ``enabled`` is False for an action group whose ``actionGroupState`` is DISABLED: it
    is not invocable, and reporting a capability the agent cannot use would be a finding
    about configuration that has already been turned off."""
    # A non-dict reaches here whenever an API response shape shifts or a caller passes
    # a list element straight through. Raising would take down the whole BEDROCK_AGENTS
    # section for one malformed group, which is a worse outcome than reporting nothing
    # about that group.
    g = group if isinstance(group, dict) else {}
    sig = g.get("parentActionSignature") or ""
    state = (g.get("actionGroupState") or "ENABLED").upper()
    info = HIGH_AGENCY.get(sig)
    return {
        "signature": sig,
        "known_signature": sig in PARENT_SIGNATURES if sig else True,
        "enabled": state == "ENABLED",
        "state": state,
        "high_agency": bool(info) and state == "ENABLED",
        "severity": info["severity"] if info else "",
        "grants": info["grants"] if info else "",
        "why": info["why"] if info else "",
    }


# ── autonomy ────────────────────────────────────────────────────────────────
def _functions(group: Optional[dict]) -> List[dict]:
    fs = (group or {}).get("functionSchema") or {}
    if not isinstance(fs, dict):
        return []
    return [f for f in (fs.get("functions") or []) if isinstance(f, dict)]


def confirmation_coverage(groups: Optional[Sequence[dict]]) -> dict:
    """How much of an agent's action surface is behind a human confirmation gate.

    Shaped like the guardrail and EDR coverage feeds: a fraction, plus the ungated
    names. A per-function check would report a list of failures on an agent that gates
    nothing and say nothing at all about the estate; the fraction has an answer in
    exactly the case where the per-function view is least useful.

    An absent ``requireConfirmation`` counts as ungated, because AWS states the default:
    "By default, user confirmation is DISABLED if this field is not specified." That is
    a documented default rather than an assumption — the distinction that kept
    ``requireMMDSV2`` reported as unknown rather than false."""
    total = 0
    gated = 0
    ungated: List[str] = []
    api_schema_groups: List[str] = []

    for g in groups or []:
        if not isinstance(g, dict):
            continue
        if (g.get("actionGroupState") or "ENABLED").upper() != "ENABLED":
            continue
        gname = g.get("actionGroupName") or g.get("actionGroupId") or "?"

        fns = _functions(g)
        if not fns and g.get("apiSchema"):
            # An OpenAPI action group carries x-requireConfirmation inside the schema
            # payload, which may be an S3 reference we do not read. Recorded as
            # un-assessed rather than counted as ungated: guessing would either invent
            # a gap or hide one, and both are worse than naming the blind spot.
            api_schema_groups.append(gname)
            continue

        for f in fns:
            total += 1
            state = (f.get("requireConfirmation") or "DISABLED").upper()
            if state == "ENABLED":
                gated += 1
            else:
                ungated.append(f"{gname}/{f.get('name') or '?'}")

    return {
        "total": total,
        "gated": gated,
        "ungated": sorted(ungated),
        "pct": round(100.0 * gated / total, 1) if total else None,
        "openapi_groups_not_assessed": sorted(api_schema_groups),
    }


# ── the agent as a whole ────────────────────────────────────────────────────
def assess_agent(groups: Optional[Sequence[dict]]) -> dict:
    """Functionality and autonomy together, which is where the severity comes from.

    A high-agency capability is serious on its own. A high-agency capability that no
    human has to approve is the shape OWASP LLM06 is actually about: an agent that can
    be talked into doing something consequential, with nothing between the instruction
    and the act."""
    caps = [group_capabilities(g) for g in (groups or []) if isinstance(g, dict)]
    high = [c for c in caps if c["high_agency"]]
    cov = confirmation_coverage(groups)

    worst = ""
    for c in high:
        if _SEVERITY_RANK.get(c["severity"], 0) > _SEVERITY_RANK.get(worst, 0):
            worst = c["severity"]

    # Nothing gated AND a high-agency capability: the two failures compound, because the
    # capability is what makes the missing gate matter and the missing gate is what makes
    # the capability reachable by an instruction rather than by a person.
    ungated_high_agency = bool(high) and cov["total"] > 0 and cov["gated"] == 0
    if ungated_high_agency and worst == "HIGH":
        worst = "CRITICAL"

    return {
        "capabilities": high,
        "signatures": sorted({c["signature"] for c in high}),
        "coverage": cov,
        "worst_severity": worst,
        "ungated_high_agency": ungated_high_agency,
        # A capability with no functions at all still counts: the built-in signatures
        # carry their own behaviour and are not described by a function schema. So does
        # an OpenAPI group we could not assess — an agent whose entire action surface is
        # OpenAPI would otherwise return "no surface" and the blind spot would be
        # dropped in silence, which is the phantom pass wearing a different hat.
        "has_any_surface": (bool(high) or cov["total"] > 0
                            or bool(cov["openapi_groups_not_assessed"])),
    }
