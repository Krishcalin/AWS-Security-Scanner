#!/usr/bin/env python3
"""aws_vex.py — standalone VEX ingest (OpenVEX + CSAF-VEX). PURE stdlib.

A VEX (Vulnerability Exploitability eXchange) document asserts, per (vulnerability,
product[, subcomponent]), whether the product is affected. OverWatch uses it to suppress
(or re-open) a CVE with an auditable justification. This module PARSES the two open
formats into a flat ``VexStatement`` list; owner resolution + persistence + suppression
live in the hub (cnapp_service). Fails soft — a malformed statement is skipped, never
crashes and never fabricates.

  * OpenVEX  — ``@context`` names openvex; ``statements[].{vulnerability, products[], status}``.
  * CSAF-VEX — ``document.category == 'csaf_vex'``; ``vulnerabilities[].product_status`` with
               product ids resolved to purls through ``product_tree``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

# CSAF product_status key → OverWatch VEX status
_CSAF_STATUS = {
    "known_not_affected": "not_affected",
    "known_affected": "affected",
    "fixed": "fixed",
    "first_fixed": "fixed",
    "under_investigation": "under_investigation",
}
_VALID = {"not_affected", "affected", "fixed", "under_investigation"}
# statuses that SUPPRESS a vuln (owner asserts it's not a live exposure).
SUPPRESSING = {"not_affected", "fixed"}


@dataclass(frozen=True)
class VexStatement:
    cve: str
    product: str                            # raw product/@id (image ref or purl)
    purl: Optional[str]                     # subcomponent purl (None = product-wide)
    status: str                             # not_affected | affected | fixed | under_investigation
    justification: Optional[str]


def sniff_vex(doc) -> Optional[str]:
    """Return 'openvex' | 'csaf' | None. Never claims a CycloneDX/SPDX doc."""
    if not isinstance(doc, dict) or doc.get("bomFormat") == "CycloneDX" or "spdxVersion" in doc:
        return None
    ctx = doc.get("@context")
    ctx_s = " ".join(str(c) for c in ctx) if isinstance(ctx, list) else str(ctx or "")
    if "openvex" in ctx_s.lower() and isinstance(doc.get("statements"), list):
        return "openvex"
    docmeta = doc.get("document")
    if isinstance(docmeta, dict):
        cat = str(docmeta.get("category", "")).lower()
        if "csaf_vex" in cat or (cat.startswith("csaf") and "vex" in cat):
            return "csaf"
    return None


def _norm_cve(v) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        return str(v.get("name") or v.get("cve") or v.get("@id") or "")
    return ""


def _as_purl(ref) -> Optional[str]:
    """A subcomponent ref → its package purl (any ``pkg:`` id)."""
    return ref if isinstance(ref, str) and ref.startswith("pkg:") else None


def _product_purl(ref) -> Optional[str]:
    """A PRODUCT-level ref → a scoping purl, or None for a product-wide subject. An image
    (``pkg:oci/`` / ``pkg:docker/``) or a plain image ref is the whole product (None); a
    package purl at product level is package-scoped."""
    if not isinstance(ref, str) or not ref.startswith("pkg:"):
        return None
    if ref.startswith(("pkg:oci/", "pkg:docker/")):
        return None
    return ref


def parse_openvex(doc: dict) -> List[VexStatement]:
    out: List[VexStatement] = []
    for st in doc.get("statements") or []:
        if not isinstance(st, dict):
            continue
        cve = _norm_cve(st.get("vulnerability"))
        status = str(st.get("status") or "").lower()
        if not cve or status not in _VALID:
            continue
        just = (st.get("justification") or st.get("impact_statement")
                or st.get("action_statement"))
        for p in st.get("products") or []:
            pid = p.get("@id") if isinstance(p, dict) else str(p)
            subs = (p.get("subcomponents") or []) if isinstance(p, dict) else []
            if subs:
                for sc in subs:                                # subcomponent-scoped
                    scid = sc.get("@id") if isinstance(sc, dict) else str(sc)
                    out.append(VexStatement(cve, pid or "", _as_purl(scid), status, just))
            else:                                              # product-level (image = product-wide)
                out.append(VexStatement(cve, pid or "", _product_purl(pid), status, just))
    return out


def _csaf_product_index(tree: dict) -> Dict[str, Optional[str]]:
    """product_id → purl (or None) from full_product_names + nested branches."""
    idx: Dict[str, Optional[str]] = {}

    def take(fpn):
        if isinstance(fpn, dict) and fpn.get("product_id"):
            purl = (fpn.get("product_identification_helper") or {}).get("purl")
            idx[fpn["product_id"]] = purl

    def walk(branches):
        for b in branches or []:
            take(b.get("product"))
            walk(b.get("branches"))

    walk(tree.get("branches"))
    for fpn in tree.get("full_product_names") or []:
        take(fpn)
    for rel in tree.get("relationships") or []:              # composite ids (Red Hat CSAF shape)
        take(rel.get("full_product_name"))
    return idx


def _csaf_cve(v: dict) -> str:
    """The vulnerability's CVE: the top-level ``cve``, else a CSAF ``ids[]`` entry whose
    ``system_name`` is CVE (its id lives in ``text``, which ``_norm_cve`` doesn't read)."""
    if v.get("cve"):
        return str(v["cve"])
    for i in v.get("ids") or []:
        if isinstance(i, dict) and str(i.get("system_name", "")).upper() == "CVE" and i.get("text"):
            return str(i["text"])
    return ""


def _csaf_justification(v: dict) -> Optional[str]:
    for f in v.get("flags") or []:
        if f.get("label"):
            return str(f["label"])
    for t in v.get("threats") or []:
        if t.get("details"):
            return str(t["details"])
    for n in v.get("notes") or []:
        if n.get("text"):
            return str(n["text"])
    return None


def parse_csaf_vex(doc: dict) -> List[VexStatement]:
    tree = _csaf_product_index(doc.get("product_tree") or {})
    out: List[VexStatement] = []
    for v in doc.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        cve = _csaf_cve(v)
        if not cve:
            continue
        just = _csaf_justification(v)
        status_map = v.get("product_status") or {}
        for key, status in _CSAF_STATUS.items():
            for pid in status_map.get(key) or []:
                out.append(VexStatement(cve, pid, tree.get(pid), status, just))
    return out


def parse_vex(doc: dict):
    """(doc) → (format | None, [VexStatement])."""
    fmt = sniff_vex(doc)
    if fmt == "openvex":
        return "openvex", parse_openvex(doc)
    if fmt == "csaf":
        return "csaf", parse_csaf_vex(doc)
    return None, []
