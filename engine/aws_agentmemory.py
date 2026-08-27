"""Phase 3 · slice 3.4 — memory-poisoning exposure, the configuration half.

Agent memory is what makes a prompt injection outlive the conversation that carried it.
An instruction written into memory in one session is read back into the model's context in
the next, and by a different user where the memory is shared. Everything else in Phase 3
concerns what an injection reaches NOW; this concerns how long it keeps reaching.

THE HALF THIS DELIBERATELY DOES NOT DO
--------------------------------------
It does not read memory CONTENTS. Answering "is there a poisoned memory in here" means
reading stored conversation, which is exactly the escalation decision **D2** declined — a
one-line security review becomes a data-processing agreement, and the capability would
duplicate what a runtime guardrail owns better. The roadmap's own framing for this slice
is *"config half only"*, and that is the whole of it.

What configuration alone can establish is the EXPOSURE WINDOW and the CUSTODY:

* **How long a written memory survives.** Bedrock Agents carry ``memoryConfiguration
  .storageDays`` (0-365); AgentCore Memory carries ``eventExpiryDuration`` (1-365). Both
  are the number of days an instruction that reached memory keeps being read back. A
  90-day window is not a misconfiguration; it is a 90-day window, and an operator who has
  not been told the number cannot have decided it was the right one.

* **Who holds the key.** AgentCore Memory has ``encryptionKeyArn``. Absent means an
  AWS-managed key, which is the same custody question the token vault raised in 2.5: no
  revocation lever, no decrypt trail under a key policy you own.

Pure functions over dicts — no boto3, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

#: Both surfaces cap retention at a year, which is what makes a shared scale honest.
MAX_RETENTION_DAYS = 365

#: Bedrock Agents: the only value the enum currently admits.
BEDROCK_MEMORY_TYPES = ("SESSION_SUMMARY",)
#: AgentCore Memory strategy types, from the pinned service model.
AGENTCORE_STRATEGY_TYPES = ("SEMANTIC", "SUMMARIZATION", "USER_PREFERENCE", "CUSTOM")

#: Bands for the exposure window. Deliberately coarse and stated as a window rather than
#: a verdict: there is no correct number of days, only a number the operator should have
#: chosen on purpose.
_LONG_DAYS = 90
_EXTENDED_DAYS = 30


def _int(v: Any) -> Optional[int]:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def bedrock_agent_memory(detail: Optional[dict]) -> dict:
    """Memory posture from a ``get_agent(...)["agent"]`` response.

    ``enabled`` False is the common case and is not a finding: an agent with no memory
    cannot carry an instruction between sessions, which is the good outcome."""
    d = detail if isinstance(detail, dict) else {}
    cfg = d.get("memoryConfiguration")
    if not isinstance(cfg, dict) or not cfg:
        return {"enabled": False, "surface": "bedrock-agent", "days": None,
                "types": [], "known_days": False}
    days = _int(cfg.get("storageDays"))
    return {
        "enabled": True,
        "surface": "bedrock-agent",
        "days": days,
        # Absent is unknown rather than zero: the field is optional and the reference
        # states no default, so assuming one would invent an exposure window or erase it.
        "known_days": days is not None,
        "types": sorted(t for t in (cfg.get("enabledMemoryTypes") or [])
                        if isinstance(t, str)),
    }


def agentcore_memory(memory: Optional[dict]) -> dict:
    """Memory posture from a ``get_memory(...)["memory"]`` response."""
    m = memory if isinstance(memory, dict) else {}
    days = _int(m.get("eventExpiryDuration"))
    strategies = [s for s in (m.get("strategies") or []) if isinstance(s, dict)]
    return {
        "enabled": bool(m),
        "surface": "agentcore",
        "id": m.get("id") or m.get("arn") or "",
        "name": m.get("name") or m.get("id") or "memory",
        "days": days,
        "known_days": days is not None,
        "cmk": bool(m.get("encryptionKeyArn")),
        "status": (m.get("status") or "").upper(),
        "types": sorted({(s.get("type") or "").upper() for s in strategies
                         if s.get("type")}),
        # Reported as a count, not interpreted. A namespace template decides whether a
        # memory is per-actor or shared, but the template variables are operator-defined
        # and their semantics are not documented in the API reference — so the number is
        # a fact and any reading of it would be a guess.
        "namespaces": sum(len(s.get("namespaces") or []) for s in strategies),
    }


def exposure_window(posture: Optional[dict]) -> dict:
    """How long an instruction that reached memory keeps being read back.

    A band rather than a pass/fail. There is no correct retention period — a support
    assistant that remembers a customer for a year may be exactly right — so the finding
    states the window and lets the operator decide whether they chose it."""
    p = posture if isinstance(posture, dict) else {}
    if not p.get("enabled"):
        return {"band": "none", "days": None,
                "why": "no memory is configured, so nothing carries between sessions"}
    if not p.get("known_days"):
        return {"band": "unknown", "days": None,
                "why": ("memory is enabled but the retention field is absent, so the "
                        "window could not be established rather than being short")}
    days = p["days"]
    if days <= 0:
        return {"band": "none", "days": days,
                "why": "retention is zero, so nothing persists between sessions"}
    if days >= _LONG_DAYS:
        band = "long"
    elif days >= _EXTENDED_DAYS:
        band = "extended"
    else:
        band = "short"
    return {"band": band, "days": days,
            "why": (f"an instruction written into memory is read back into the model's "
                    f"context for {days} day(s)")}


def summarize(posture: Optional[dict], window: Optional[dict]) -> str:
    """The sentence a finding shows. Names the window and the custody, and says plainly
    that contents were not examined — otherwise a reader assumes a clean memory rather
    than an unexamined one."""
    p, w = posture or {}, window or {}
    if not p.get("enabled"):
        return ""
    bits = [w.get("why", "")]
    if p.get("surface") == "agentcore" and not p.get("cmk"):
        bits.append("and it is encrypted with an AWS-managed key, so there is no key you "
                    "can disable to cut access to it")
    if p.get("types"):
        bits.append(f"memory types: {', '.join(p['types'])}")
    bits.append("OverWatch reports the exposure window and does NOT read memory "
                "contents — whether anything poisoned is stored is not a question this "
                "scan asks")
    return ". ".join(b for b in bits if b)
