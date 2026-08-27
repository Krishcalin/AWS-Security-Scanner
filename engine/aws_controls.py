#!/usr/bin/env python3
"""aws_controls.py — saved-WQL-query-as-Control: the pure transform from a matched WQL result
into a synthetic finding_catalog entry.

A Control is a named, saved WQL query (config-driven, CNAPP_CONTROLS). When its query matches
one or more graph nodes in an account, it surfaces as a DISPLAY-ONLY finding: status is always
``WARN`` so it can never touch the FAIL-only posture score (which aws_correlate bakes at scan
time and this never re-runs). This module is the single source of truth for that finding shape,
imported by cnapp_service (the overlay), scripts/gen_wql_parity.py (the oracle), and mirrored
byte-for-byte in frontend/src/lib/controls.ts (SAMPLE==LIVE). Pure/stdlib, no graph import.
"""
from __future__ import annotations

from typing import List

CONTROL_SECTION = "Custom Controls"
CONTROL_PREFIX = "CONTROL-"
_SEV = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})


def control_severity(ctrl: dict) -> str:
    """A control's display severity, defaulting an unknown/absent value to MEDIUM."""
    s = ctrl.get("severity")
    return s if s in _SEV else "MEDIUM"


def control_finding(ctrl: dict, account_id: str, rows: List[dict]) -> dict:
    """Build the synthetic finding_catalog entry for a control that matched ``rows`` (the WQL
    node rows, already (kind,id)-sorted by aws_wql.evaluate). Never called with empty rows —
    a control that matches nothing is simply absent (it "passes"), not a PASS finding here."""
    affected = [r["id"] for r in rows]
    name = ctrl.get("name") or ctrl.get("id")
    return {
        "check_id": CONTROL_PREFIX + str(ctrl.get("id")),
        "section": ctrl.get("section") or CONTROL_SECTION,
        "severity": control_severity(ctrl),
        "status": "WARN",                                  # display-only; never FAIL
        "compliance": ctrl.get("compliance") or {},
        "remediation_cmd": ctrl.get("remediation_cmd") or "",
        "risk": ctrl.get("description") or f"Custom control '{name}' matched {len(rows)} resource(s).",
        "impact": ctrl.get("impact") or "",
        "steps": ctrl.get("steps") or [],
        "affected": affected,
        "count": len(rows),
        "distinct": len(set(affected)),
        "account": account_id,
    }


def control_meta(ctrl: dict) -> dict:
    """The normalized, display-safe control descriptor for the /controls list (no roll-up)."""
    return {
        "id": str(ctrl.get("id")),
        "name": ctrl.get("name") or str(ctrl.get("id")),
        "severity": control_severity(ctrl),
        "section": ctrl.get("section") or CONTROL_SECTION,
        "description": ctrl.get("description") or "",
        "query": ctrl.get("query"),
    }
