#!/usr/bin/env python3
"""aws_ingest_aidr.py — Phase 4 · slice 4.7: AI runtime detections, from anywhere.

WHAT THIS IS NOT, AND WHY THAT IS THE POINT
--------------------------------------------
The roadmap specified *"sibling Guardrail event ingest"*, and that could not be built.
**D7** measured the sibling — 11 commits, no Dockerfile, no console entry point, no
publish workflow — and ruled that OverWatch takes no dependency on it;
``test_decisions.py`` enforces the ruling by failing the build if any application module
so much as names it. Writing an ingest keyed to that product would have introduced
exactly the reference the test forbids, and made a capability OverWatch claims contingent
on a repo that runs from a clone.

D7 also wrote down the shape that *is* permitted: *"if the sibling is ever integrated, it
is as an optional detection source behind the existing connector plane — the same contract
as any third-party feed."* So this module is **vendor-neutral by construction**. It names
no product. It reads a documented generic schema that any AI-runtime detector can emit —
the sibling included, on the same footing as anything else — and OverWatch depends on
none of them.

That is not a workaround. A detection ingest that only accepts one vendor's format is a
dependency wearing an ingest's clothes.

THE CONTENT LINE, WHICH IS THE REASON THIS IS DELICATE
-------------------------------------------------------
An AI runtime detector sees prompts. That is its job — it sits in the request path and
decides whether an input is an injection attempt. So its natural output is *the most
content-dense payload any ingest in this product will ever be offered*, and the temptation
to carry "the prompt that triggered it" into a finding is enormous, because it would make
the finding so much more useful.

**D2 declined it, and this module is where that decision is either kept or quietly lost.**
So the schema has no field for a prompt, a completion, or a matched string — a mapping
that tried to carry one would have nowhere to put it — and every field this module reads
is named in ``DETECTION_FIELDS``. Anything else in the document is ignored, and the count
of ignored keys is reported so an operator can see that content was present and
deliberately left alone.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "SCHEMA", "DETECTION_FIELDS", "REQUIRED_FIELDS", "VERDICTS", "SEVERITIES",
    "CONTENT_FIELDS", "parse", "rate", "describe", "CONTENTS_NOT_READ",
]

#: The schema identifier an emitter must declare. Versioned so a future shape change is
#: a different document rather than a silently different meaning.
SCHEMA = "overwatch.ai-detection/v1"

#: Every field this module reads. An allowlist, not a denylist: a detector that invents
#: a field carrying prompt text finds nowhere to put it, and the invention is counted
#: rather than absorbed. This is the structural half of D2 — the same construction that
#: made slice 3.5 read garak's `eval` rows and never its `attempt` rows.
DETECTION_FIELDS: Tuple[str, ...] = (
    "id",           # the emitter's own identifier for this detection
    "detector",     # the tool that produced it
    "rule",         # which rule fired
    "verdict",      # BLOCKED | FLAGGED | ALLOWED
    "severity",     # CRITICAL | HIGH | MEDIUM | LOW | INFO
    "category",     # prompt_injection | jailbreak | data_exfiltration | ...
    "target",       # the ARN or identifier of what was protected
    "principal",    # the identity that made the request, if the detector knows it
    "count",        # how many times this fired in the window
    "first_seen",   # ISO 8601
    "last_seen",    # ISO 8601
)

REQUIRED_FIELDS: Tuple[str, ...] = ("detector", "verdict")

#: Field names a detector might reasonably use for content. Named ONLY so the parser can
#: count them and say they were skipped -- their values are never read. Naming them is
#: what makes the refusal visible rather than implicit.
CONTENT_FIELDS: Tuple[str, ...] = (
    "prompt", "prompts", "completion", "response", "input", "output",
    "matched_text", "match", "snippet", "payload", "body", "messages",
    "user_message", "assistant_message", "context",
)

#: BLOCKED means the detector stopped it; FLAGGED means it observed and allowed it.
#: The distinction decides whether a detection is evidence of a control working or of a
#: control absent, and collapsing them would make both unreadable.
VERDICTS: Tuple[str, ...] = ("BLOCKED", "FLAGGED", "ALLOWED")

SEVERITIES: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

CONTENTS_NOT_READ = (
    "OverWatch ingests the detector's VERDICT and never the prompt that triggered it: "
    "what the request said is not a question this scan asks"
)

_MAX_LEN = 200


def _clean(v: Any) -> str:
    """A short single-line identifier.

    Truncated rather than carried, because an oversized 'rule name' is precisely how
    prompt text arrives through a field nobody expected to carry it — the same reasoning
    as slice 3.5's ``_clean``."""
    s = str(v if v is not None else "").strip().replace("\n", " ").replace("\r", " ")
    return s[:_MAX_LEN]


def _num(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    return int(v) if isinstance(v, (int, float)) else None


def parse(doc: Optional[dict]) -> dict:
    """Read a detection document. Verdict fields only.

    Returns ``{"detections", "skipped_content_fields", "malformed", "error"}``.

    ``detector`` is required and travels into every finding: a detection that cannot say
    what produced it is one an operator cannot act on, which is the same rule slice 3.5
    applies to ``tool`` and slice 3.2 to a pattern set's ``source``."""
    d = doc if isinstance(doc, dict) else {}
    schema = _clean(d.get("schema"))
    if schema and schema != SCHEMA:
        return {"detections": [], "skipped_content_fields": 0, "malformed": 0,
                "error": (f"unknown schema {schema!r} — this reader accepts "
                          f"{SCHEMA!r}; a document of another shape may mean something "
                          f"different by the same field names")}

    rows = d.get("detections")
    if not isinstance(rows, list):
        return {"detections": [], "skipped_content_fields": 0, "malformed": 0,
                "error": "the document has no `detections` list"}

    out: List[dict] = []
    skipped = malformed = 0
    for row in rows:
        if not isinstance(row, dict):
            malformed += 1
            continue
        # Counted, never read. The operator learns content was present and left alone.
        skipped += sum(1 for k in row if str(k).lower() in CONTENT_FIELDS)

        verdict = _clean(row.get("verdict")).upper()
        detector = _clean(row.get("detector"))
        if not detector or verdict not in VERDICTS:
            malformed += 1
            continue
        sev = _clean(row.get("severity")).upper()
        out.append({
            "id": _clean(row.get("id")),
            "detector": detector,
            "rule": _clean(row.get("rule")),
            "verdict": verdict,
            "severity": sev if sev in SEVERITIES else "",
            "category": _clean(row.get("category")),
            "target": _clean(row.get("target")),
            "principal": _clean(row.get("principal")),
            "count": _num(row.get("count")) or 1,
            "first_seen": _clean(row.get("first_seen")),
            "last_seen": _clean(row.get("last_seen")),
        })
    return {"detections": out, "skipped_content_fields": skipped,
            "malformed": malformed, "error": ""}


def rate(detection: Optional[dict]) -> dict:
    """What this detection is evidence OF, which is not the same for every verdict.

    ``BLOCKED`` is evidence a control **worked** — it belongs in a report as assurance,
    not as a failure, and reporting it as a failure is how a team learns to switch the
    detector off. ``FLAGGED`` and ``ALLOWED`` are the findings: something was recognised
    as an attack and reached the model anyway."""
    r = detection if isinstance(detection, dict) else {}
    verdict = r.get("verdict")
    reached = verdict in ("FLAGGED", "ALLOWED")
    sev = r.get("severity") or ("MEDIUM" if reached else "INFO")
    return {
        "reached_the_model": reached,
        "control_held": verdict == "BLOCKED",
        "severity": sev,
        "count": r.get("count") or 1,
    }


def describe(detection: Optional[dict], rating: Optional[dict]) -> str:
    """One sentence, carrying no prompt and no model output."""
    r = detection if isinstance(detection, dict) else {}
    g = rating if isinstance(rating, dict) else {}
    who = r.get("detector") or "a detector"
    what = r.get("rule") or r.get("category") or "a rule"
    n = g.get("count") or 1
    times = "once" if n == 1 else f"{n} times"
    where = f" against {r['target']}" if r.get("target") else ""
    if g.get("control_held"):
        return (f"{who} BLOCKED {what}{where} {times} — evidence the control held, "
                f"reported as assurance rather than as a failure")
    return (f"{who} detected {what}{where} {times} and the request reached the model "
            f"anyway")
