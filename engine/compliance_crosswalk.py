#!/usr/bin/env python3
"""
compliance_crosswalk.py — the NIST 800-53 -> 30+ framework crosswalk loader
(CNAPP compliance-breadth slice).

Every OverWatch check already carries a NIST SP 800-53 Rev 5 control (the *spine*).
Rather than hand-tag 250 checks x 30 frameworks, we cross-walk each distinct NIST
control the product uses to the equivalent control(s) in every target framework, and
DERIVE per-framework coverage transitively (see ``aws_live_scanner.crosswalk_scorecard``).
A derived tag therefore always reads "satisfied via NIST 800-53 <ctrl> (crosswalk)".

This module is PURE reference data + a loader — exactly like ``COMPLIANCE_MAP``:
file-resident, loaded once, never per-tenant scan state. No boto3, no print, no
clock, no network. The reference file (``compliance/crosswalk.json``) is sourced
from authoritative crosswalks (NIST OLIR/CPRT, CIS v8->800-53, CSA CCM->800-53,
FedRAMP baselines, ISO 27001:2022->800-53, PCI DSS->NIST, etc.) with a per-edge
confidence tier and citations.

Accuracy guardrails (load-time, fail-loud at author time):
* the 5 NATIVE frameworks (CIS/PCI-DSS/HIPAA/SOC2/NIST) are never crosswalk-derived
  — an edge targeting a native framework is rejected;
* NIST is the spine and is never crosswalked to itself;
* every edge has >=1 non-blank target id + a confidence in {high,medium,low};
* framework ids are unique;
* a (nist, framework) pair with no authoritative equivalent simply has NO edge —
  there is never a placeholder / fabricated id.

Fail-OPEN in production: a missing/corrupt file makes ``get_crosswalk()`` return
empty structures, so ``crosswalk_scorecard`` yields ``{}`` and the entire native
pipeline (the 5 hand-tagged frameworks) is byte-identically unaffected.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Callable, Dict, Optional, Tuple

_CONFIDENCE = ("high", "medium", "low")
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}
_NATIVE_IDS = frozenset({"CIS", "PCI-DSS", "HIPAA", "SOC2", "NIST"})

_DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "compliance", "crosswalk.json")

# memoization (production loads once, like COMPLIANCE_MAP being import-time)
_CACHE: Optional[Tuple[dict, dict, str]] = None


class CrosswalkError(ValueError):
    """A structural / accuracy violation in the crosswalk reference data."""


def _max_conf(a: str, b: str) -> str:
    return a if _CONF_RANK.get(a, 0) >= _CONF_RANK.get(b, 0) else b


def _canonical_digest(frameworks: list, crosswalk: dict) -> str:
    """sha256 over normalized (sorted, canonical-JSON) content — stable across
    formatting (framework list order, whitespace), so it is a reproducible
    ``crosswalk_version`` stamp that only changes when the mappings themselves do."""
    norm_fw = sorted(frameworks, key=lambda m: str(m.get("id", "")))
    blob = json.dumps({"frameworks": norm_fw, "crosswalk": crosswalk},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "cw-" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def load_crosswalk(path: Optional[str] = None, *, overlay: Optional[dict] = None,
                   reader: Callable[[str], object] = None,
                   nist_universe: Optional[frozenset] = None
                   ) -> Tuple[Dict[str, dict], Dict[str, dict], str]:
    """PURE: path -> (CROSSWALK, FRAMEWORKS, digest). Raises ``CrosswalkError`` on
    any accuracy violation (fail-loud at author/CI time).

    * ``CROSSWALK``  = ``{nist_id: {framework_id: {nist, framework, targets,
      confidence, note, sources}}}`` — non-native frameworks only, indexed for the
      O(1) scorecard fold.
    * ``FRAMEWORKS`` = ``{framework_id: FrameworkMeta}`` (native + derived).
    * ``overlay``    = an optional customer file merged on top (add a framework,
      add/override edges by (nist, framework)); it may NOT flip an existing
      framework's ``native`` flag, and its edges pass every rule below.
    * ``nist_universe`` (optional) — when given, every ``edge.nist`` MUST be a
      member (the fabrication/drift guard; the CI accuracy test passes the real 38
      derived from ``COMPLIANCE_MAP``).
    """
    reader = reader or _read_json_file
    raw = reader(path or _DEFAULT_PATH)
    if not isinstance(raw, dict):
        raise CrosswalkError("crosswalk file must be a JSON object")
    if overlay:
        raw = _merge_overlay(raw, overlay)

    frameworks: Dict[str, dict] = {}
    for meta in raw.get("frameworks", []):
        fid = meta.get("id")
        if not fid or not isinstance(fid, str):
            raise CrosswalkError(f"framework missing a string id: {meta!r}")
        if fid in frameworks:
            raise CrosswalkError(f"duplicate framework id {fid!r}")
        frameworks[fid] = {
            "id": fid, "name": meta.get("name", fid), "version": meta.get("version", ""),
            "authority": meta.get("authority", ""), "family": meta.get("family", "general"),
            "native": bool(meta.get("native", False)),
            "near_identity": bool(meta.get("near_identity", False)),
            "description": meta.get("description", ""),
            "catalog_size": int(meta.get("catalog_size", 0) or 0),
            "sources": list(meta.get("sources", []) or []),
        }

    # The fabrication/drift guard runs in PRODUCTION too: the data file self-declares
    # its in-scope NIST universe, and an explicit nist_universe (the CI test passes the
    # real 38 from COMPLIANCE_MAP) tightens it further. Every edge.nist must be a member.
    file_universe = raw.get("nist_universe")
    guard = None
    if nist_universe is not None and file_universe is not None:
        guard = frozenset(nist_universe) & frozenset(file_universe)
    elif nist_universe is not None:
        guard = frozenset(nist_universe)
    elif file_universe is not None:
        guard = frozenset(file_universe)

    crosswalk: Dict[str, dict] = {}
    for nist, fwmap in (raw.get("crosswalk", {}) or {}).items():
        nist = str(nist).strip()
        if guard is not None and nist not in guard:
            raise CrosswalkError(f"edge references NIST control {nist!r} not in the "
                                 f"in-scope universe (fabrication/drift guard)")
        if not isinstance(fwmap, dict):
            raise CrosswalkError(f"crosswalk[{nist!r}] must be an object")
        for fid, edge in fwmap.items():
            if not isinstance(edge, dict):
                raise CrosswalkError(f"edge {nist}->{fid} must be an object")
            meta = frameworks.get(fid)
            if meta is None:
                raise CrosswalkError(f"edge {nist}->{fid} references an unknown framework")
            if meta["native"] or fid == "NIST":
                raise CrosswalkError(
                    f"edge {nist}->{fid} targets a NATIVE framework — natives are "
                    f"hand-tagged per check and never crosswalk-derived")
            targets = [t for t in (edge.get("targets") or []) if str(t).strip()]
            if not targets:
                raise CrosswalkError(f"edge {nist}->{fid} has no non-blank target ids")
            if "confidence" not in edge:
                raise CrosswalkError(f"edge {nist}->{fid} is missing a confidence tier")
            conf = edge["confidence"]
            if conf not in _CONFIDENCE:
                raise CrosswalkError(f"edge {nist}->{fid} confidence {conf!r} invalid")
            crosswalk.setdefault(nist, {})[fid] = {
                "nist": nist, "framework": fid, "targets": targets,
                "confidence": conf, "note": edge.get("note", ""),
                "sources": list(edge.get("sources", []) or []) or meta["sources"],
            }

    return crosswalk, frameworks, _canonical_digest(raw.get("frameworks", []),
                                                     raw.get("crosswalk", {}))


def _read_json_file(path: str) -> object:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _merge_overlay(base: dict, overlay: dict) -> dict:
    """Additive overlay: add frameworks + add/override edges by (nist, framework).
    Never flips an existing framework's native flag."""
    out = {"frameworks": list(base.get("frameworks", [])),
           "crosswalk": {k: dict(v) for k, v in (base.get("crosswalk", {}) or {}).items()},
           "nist_universe": base.get("nist_universe")}
    by_id = {f.get("id"): i for i, f in enumerate(out["frameworks"])}
    for meta in overlay.get("frameworks", []):
        fid = meta.get("id")
        if fid in by_id:
            existing = out["frameworks"][by_id[fid]]
            if bool(meta.get("native", existing["native"])) != existing["native"]:
                raise CrosswalkError(f"overlay may not change native flag of {fid!r}")
            merged = dict(existing); merged.update(meta); merged["native"] = existing["native"]
            out["frameworks"][by_id[fid]] = merged
        else:
            out["frameworks"].append(meta)
    for nist, fwmap in (overlay.get("crosswalk", {}) or {}).items():
        for fid, edge in fwmap.items():
            out["crosswalk"].setdefault(nist, {})[fid] = edge
    return out


def get_crosswalk(path: Optional[str] = None) -> Tuple[Dict[str, dict], Dict[str, dict], str]:
    """Memoized production accessor. FAIL-OPEN: a missing/corrupt file returns
    ``({}, {}, "")`` so the derived scorecard is empty and the native pipeline is
    untouched. Pass an explicit ``path`` to bypass the cache (tests use
    ``load_crosswalk`` directly)."""
    global _CACHE
    if path is not None:
        try:
            return load_crosswalk(path)
        except Exception:
            return {}, {}, ""
    if _CACHE is None:
        try:
            _CACHE = load_crosswalk(_DEFAULT_PATH)
        except Exception:
            _CACHE = ({}, {}, "")
    return _CACHE


def reset_cache() -> None:
    """Test helper — drop the memoized crosswalk."""
    global _CACHE
    _CACHE = None
