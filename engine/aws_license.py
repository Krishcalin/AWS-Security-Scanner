#!/usr/bin/env python3
"""aws_license.py — SPDX license normalization, categorization, and policy evaluation.

PURE stdlib (no I/O, no boto3, no network). Turns a raw SBOM license string (an SPDX id,
an expression, a name, or NOASSERTION) into a canonical (spdx_id, category) pair, and a
config-driven policy into an allow / review / deny verdict — computed ON READ, so a policy
change never requires a re-ingest.

Expression semantics (the load-bearing correctness point):
  * ``A OR B`` — the consumer may CHOOSE either arm, so the effective obligation is the
    MOST PERMISSIVE arm (min category rank).
  * ``A AND B`` — the consumer must satisfy BOTH, so the effective obligation is the
    MOST RESTRICTIVE arm (max category rank).
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

# category → restrictiveness rank (lower = more permissive) — drives OR/AND resolution.
_RANK = {"permissive": 0, "weak_copyleft": 1, "strong_copyleft": 2,
         "network_copyleft": 3, "proprietary": 4, "unknown": 5}

_NULL = {"", "NOASSERTION", "NONE", "UNKNOWN"}

# Deprecated SPDX ids → their current canonical form.
_DEPRECATED = {
    "GPL-1.0": "GPL-1.0-only", "GPL-1.0+": "GPL-1.0-or-later",
    "GPL-2.0": "GPL-2.0-only", "GPL-2.0+": "GPL-2.0-or-later",
    "GPL-3.0": "GPL-3.0-only", "GPL-3.0+": "GPL-3.0-or-later",
    "LGPL-2.0": "LGPL-2.0-only", "LGPL-2.0+": "LGPL-2.0-or-later",
    "LGPL-2.1": "LGPL-2.1-only", "LGPL-2.1+": "LGPL-2.1-or-later",
    "LGPL-3.0": "LGPL-3.0-only", "LGPL-3.0+": "LGPL-3.0-or-later",
    "AGPL-1.0": "AGPL-1.0-only", "AGPL-3.0": "AGPL-3.0-only", "AGPL-3.0+": "AGPL-3.0-or-later",
}

# The strict default policy the operator confirmed. settings.yaml-overridable; deny/review
# lists are matched by CATEGORY, with an optional exact-id override map under "ids".
DEFAULT_POLICY: Dict[str, object] = {
    "deny": ["network_copyleft", "proprietary"],
    "review": ["strong_copyleft", "unknown"],
    "allow": ["permissive", "weak_copyleft"],
    "ids": {},
}


def _balanced(s: str) -> bool:
    depth = 0
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _split_top(expr: str, op: str) -> List[str]:
    """Split ``expr`` on ` op ` (OR/AND) at paren depth 0. Returns [expr] if absent."""
    out: List[str] = []
    depth, last, i = 0, 0, 0
    pat = f" {op} "
    n = len(pat)
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and expr[i:i + n].upper() == pat:
            out.append(expr[last:i])
            i += n
            last = i
            continue
        i += 1
    out.append(expr[last:])
    return [o.strip() for o in out]


def _fold_id(raw: str) -> str:
    """A single license token → canonical id: strip a ``WITH <exception>`` suffix and a
    trailing ``+``-form, fold deprecated ids."""
    tok = raw.strip().strip("()").strip()
    tok = re.split(r"\s+WITH\s+", tok, maxsplit=1, flags=re.IGNORECASE)[0].strip()
    return _DEPRECATED.get(tok, tok)


def category_of(spdx_id: str) -> str:
    """Classify a canonical SPDX id into a license category (keyword-based, so it degrades
    to ``unknown`` — never a false ``allow`` — on an id it doesn't recognize)."""
    s = (spdx_id or "").upper()
    if not s or s in _NULL:
        return "unknown"
    if s.startswith("AGPL") or s in ("OSL-3.0", "EUPL-1.1", "EUPL-1.2"):
        return "network_copyleft"
    if s.startswith(("SSPL", "BUSL", "ELASTIC", "CONFLUENT", "POLYFORM", "RSAL", "COMMONS-CLAUSE")):
        return "proprietary"
    if s.startswith("LGPL"):
        return "weak_copyleft"
    if s.startswith("GPL"):
        return "strong_copyleft"
    if s.startswith(("MPL", "EPL", "CDDL", "CPL", "MS-PL", "MS-RL", "APSL", "IPL", "ARTISTIC")):
        return "weak_copyleft"
    if s.startswith(("MIT", "BSD", "APACHE", "ISC", "ZLIB", "0BSD", "UNLICENSE", "BSL-1.0",
                     "BOOST", "PSF", "PYTHON", "WTFPL", "CC0", "POSTGRESQL", "NCSA", "X11",
                     "BLUEOAK", "UPL", "CC-BY-4", "FTL")):
        return "permissive"
    return "unknown"


def normalize_spdx(raw: Optional[str]) -> Tuple[str, str]:
    """(raw license string) → (canonical spdx id, category). Handles NOASSERTION/None,
    WITH-exceptions, deprecated ids, and OR/AND expressions."""
    if raw is None:
        return ("UNKNOWN", "unknown")
    s = str(raw).strip()
    if not s or s.upper() in _NULL:
        return ("UNKNOWN", "unknown")
    while s.startswith("(") and s.endswith(")") and _balanced(s[1:-1]):
        s = s[1:-1].strip()
    or_parts = _split_top(s, "OR")
    if len(or_parts) > 1:
        return min((normalize_spdx(a) for a in or_parts), key=lambda t: _RANK.get(t[1], 5))
    and_parts = _split_top(s, "AND")
    if len(and_parts) > 1:
        return max((normalize_spdx(a) for a in and_parts), key=lambda t: _RANK.get(t[1], 5))
    fid = _fold_id(s)
    return (fid, category_of(fid))


def evaluate_license(spdx_id: str, category: str, policy: Optional[Dict] = None) -> str:
    """→ 'allow' | 'review' | 'deny'. An exact-id override in ``policy['ids']`` wins;
    otherwise the category is matched against the deny/review lists (deny before review)."""
    p = policy or DEFAULT_POLICY
    ids = p.get("ids") or {}
    if spdx_id in ids and ids[spdx_id] in ("allow", "review", "deny"):
        return ids[spdx_id]
    if category in (p.get("deny") or []):
        return "deny"
    if category in (p.get("review") or []):
        return "review"
    return "allow"


def assess(raw: Optional[str], policy: Optional[Dict] = None) -> Dict[str, str]:
    """Convenience for the persistence layer: raw → {spdx_id, category, verdict}."""
    spdx_id, category = normalize_spdx(raw)
    return {"spdx_id": spdx_id, "category": category,
            "verdict": evaluate_license(spdx_id, category, policy)}
