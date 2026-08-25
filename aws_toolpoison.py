"""Phase 3 · slice 3.2 — tool-description poisoning.

A model reads a tool's DESCRIPTION to decide when to call it. That makes the description
an instruction channel: whoever can edit it can address the model directly, and the
person reviewing the agent in a console sees a field that looks like documentation.

The roadmap's constraint on this slice is the interesting part — *vendors patterns, does
not author them* — and it is right. Injection phrasings are unbounded, multilingual and
adversarially chosen. A regex list written here would be a detection product, and a poor
one: every phrasing it missed would read as a clean bill of health, and every phrasing it
over-matched would train an operator to stop reading the category. That is the same
reasoning D4 applied to red teaming and 2.6 applied to re-ranking rather than
re-detecting.

So this module reports two things it can establish as FACT, and runs a pattern set it
does not author:

**Chat-template delimiters.** ``<|im_start|>`` (ChatML, OpenAI and now Qwen/Phi),
``[INST]`` / ``<<SYS>>`` (Llama 2 and Mistral), ``<|start_header_id|>`` (Llama 3),
``\\n\\nHuman:`` (Anthropic's legacy Text Completions format). These are structural
tokens documented by model vendors, not phrasings. A field meant to say what a function
does has no reason to contain one, in the same way a configuration value has no reason to
begin ``AKIA``.

**Characters that hide text from the reviewer but not from the model.** Zero-width spaces,
bidirectional overrides, tag characters. A human reading the description in a console sees
one thing; the model receives another. This is a codepoint check, so it is objective, and
it is the signal most worth having: the whole premise of description poisoning is that
somebody looked at the field and saw nothing wrong.

**Vendored patterns.** An operator-supplied file, empty by default, whose hits are
attributed to the file rather than to OverWatch. Shipping zero patterns is deliberate and
documented, not an oversight.

Pure functions over dicts — no boto3, no I/O beyond reading a pattern file the operator
names.
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

#: Structural tokens from published chat templates. Each is a format marker, not a
#: phrasing — which is what makes looking for them a reading rather than a judgement.
CHAT_TEMPLATE_TOKENS: Tuple[Tuple[str, str], ...] = (
    ("<|im_start|>", "ChatML (OpenAI; also Qwen, Phi)"),
    ("<|im_end|>", "ChatML (OpenAI; also Qwen, Phi)"),
    ("<|start_header_id|>", "Llama 3 header format"),
    ("<|end_header_id|>", "Llama 3 header format"),
    ("<|eot_id|>", "Llama 3 header format"),
    ("[INST]", "Llama 2 / Mistral instruction format"),
    ("[/INST]", "Llama 2 / Mistral instruction format"),
    ("<<SYS>>", "Llama 2 system block"),
    ("<</SYS>>", "Llama 2 system block"),
    ("\n\nHuman:", "Anthropic legacy Text Completions format"),
    ("\n\nAssistant:", "Anthropic legacy Text Completions format"),
)

#: Codepoints that carry no visible glyph but are read by a tokenizer. A description
#: containing one shows the reviewer less than it shows the model, which is the entire
#: mechanism a poisoned description relies on.
_INVISIBLE = {
    "​": "zero-width space",
    "‌": "zero-width non-joiner",
    "‍": "zero-width joiner",
    "⁠": "word joiner",
    "﻿": "zero-width no-break space",
    "­": "soft hyphen",
}
#: Bidirectional overrides — the Trojan Source mechanism, applied to a config field.
_BIDI = {
    "‪": "left-to-right embedding", "‫": "right-to-left embedding",
    "‬": "pop directional formatting", "‭": "left-to-right override",
    "‮": "right-to-left override", "⁦": "left-to-right isolate",
    "⁧": "right-to-left isolate", "⁨": "first strong isolate",
    "⁩": "pop directional isolate",
}


def template_tokens(text: Optional[str]) -> List[dict]:
    """Chat-template delimiters present in a description."""
    if not isinstance(text, str) or not text:
        return []
    return [{"token": tok, "format": fmt}
            for tok, fmt in CHAT_TEMPLATE_TOKENS if tok in text]


def hidden_characters(text: Optional[str]) -> List[dict]:
    """Codepoints a reviewer cannot see and a tokenizer can.

    Reports the codepoint and its name rather than the surrounding text: the finding is
    that something is hidden, and quoting the field back would put the very content under
    suspicion into a report."""
    if not isinstance(text, str) or not text:
        return []
    out: Dict[str, dict] = {}
    for ch in text:
        why = _INVISIBLE.get(ch) or _BIDI.get(ch)
        if why is None and unicodedata.category(ch) == "Cf" and ch not in ("\n", "\r"):
            why = unicodedata.name(ch, "format character")
        if why is None:
            continue
        key = f"U+{ord(ch):04X}"
        rec = out.setdefault(key, {"codepoint": key, "name": why, "count": 0,
                                   "bidi": ch in _BIDI})
        rec["count"] += 1
    return [out[k] for k in sorted(out)]


# ── vendored patterns ───────────────────────────────────────────────────────
def load_patterns(path: Optional[str]) -> dict:
    """Load an operator-supplied pattern file.

    Shape: ``{"source": "...", "version": "...", "patterns": [{"id","regex","note"}]}``.
    ``source`` is required and echoed into every finding, because a pattern hit is only
    as good as the provenance of the pattern — a finding that cannot say where its rule
    came from is a finding an operator cannot argue with.

    Returns an empty set on any problem rather than raising: a malformed pattern file
    should cost the pattern check, not the scan."""
    if not path:
        return {"source": "", "version": "", "patterns": [], "error": ""}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:
        return {"source": "", "version": "", "patterns": [],
                "error": f"pattern file at {path} could not be read: {exc}"}
    if not isinstance(doc, dict) or not doc.get("source"):
        return {"source": "", "version": "", "patterns": [],
                "error": (f"pattern file at {path} declares no `source` — a pattern "
                          f"whose provenance is unknown is not one this product will "
                          f"attribute a finding to")}
    pats = []
    for p in doc.get("patterns") or []:
        if not isinstance(p, dict) or not p.get("regex"):
            continue
        try:
            rx = re.compile(p["regex"], re.I)
        except re.error:
            continue                      # a bad regex costs its own rule, nothing more
        pats.append({"id": p.get("id") or p["regex"][:32], "rx": rx,
                     "note": p.get("note") or ""})
    return {"source": str(doc["source"]), "version": str(doc.get("version") or ""),
            "patterns": pats, "error": ""}


def pattern_hits(text: Optional[str], patterns: Optional[dict]) -> List[dict]:
    """Rule ids that matched. Never the matched text: a finding that quotes the
    suspected instruction back into a report has moved the payload, not contained it."""
    if not isinstance(text, str) or not text or not patterns:
        return []
    return [{"id": p["id"], "note": p["note"]}
            for p in (patterns.get("patterns") or []) if p["rx"].search(text)]


# ── assessment ──────────────────────────────────────────────────────────────
def describable_fields(group: Optional[dict]) -> List[dict]:
    """Every description a model will read from one action group.

    The group's own description and each function's. Both reach the model, and a poisoned
    one is a poisoned one wherever it sits."""
    g = group if isinstance(group, dict) else {}
    gname = g.get("actionGroupName") or g.get("actionGroupId") or "?"
    out = []
    if g.get("description"):
        out.append({"where": f"{gname} (action group)", "text": g["description"]})
    fs = g.get("functionSchema") or {}
    if isinstance(fs, dict):
        for fn in fs.get("functions") or []:
            if isinstance(fn, dict) and fn.get("description"):
                out.append({"where": f"{gname}/{fn.get('name') or '?'}",
                            "text": fn["description"]})
    return out


def assess_text(text: Optional[str], where: str = "",
                patterns: Optional[dict] = None) -> dict:
    """All three signals over ONE string a model will read.

    Extracted from ``assess_group`` for slice 3.3, which needs the same three questions
    asked of an MCP gateway's ``instructions`` — a server-level string handed to the
    model, one level up from a tool's description. Sharing the implementation rather
    than restating it is the point: the rule that OverWatch authors no injection
    phrasings is only worth having if every caller inherits it."""
    toks = template_tokens(text)
    hidden = hidden_characters(text)
    hits = pattern_hits(text, patterns)
    return {
        "where": where,
        "length": len(text) if isinstance(text, str) else 0,
        "template_tokens": toks,
        "hidden": hidden,
        "pattern_hits": hits,
        "pattern_source": (patterns or {}).get("source", ""),
    }


def assess_group(group: Optional[dict],
                 patterns: Optional[dict] = None) -> List[dict]:
    """Findings for one action group's descriptions, one entry per affected field."""
    out = []
    for field in describable_fields(group):
        f = assess_text(field["text"], field["where"], patterns)
        if not (f["template_tokens"] or f["hidden"] or f["pattern_hits"]):
            continue
        out.append(f)
    return out


def summarize(finding: Optional[dict]) -> str:
    """One sentence, saying what was found and never quoting the description back."""
    if not finding:
        return ""
    bits = []
    if finding.get("template_tokens"):
        toks = ", ".join(sorted({t["token"] for t in finding["template_tokens"]}))
        fmts = ", ".join(sorted({t["format"] for t in finding["template_tokens"]}))
        bits.append(f"contains chat-template delimiters ({toks} — {fmts}), which a "
                    f"field describing a function has no reason to carry")
    if finding.get("hidden"):
        names = ", ".join(f"{h['count']}x {h['codepoint']} {h['name']}"
                          for h in finding["hidden"])
        bidi = any(h["bidi"] for h in finding["hidden"])
        bits.append(f"contains characters invisible to a reviewer but read by the model "
                    f"({names})" + (" including a bidirectional override, which can "
                                    "reorder what a human sees" if bidi else ""))
    if finding.get("pattern_hits"):
        ids = ", ".join(h["id"] for h in finding["pattern_hits"])
        src = finding.get("pattern_source") or "an operator-supplied set"
        bits.append(f"matched pattern(s) {ids} from {src}")
    return "; ".join(bits)
