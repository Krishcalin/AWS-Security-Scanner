#!/usr/bin/env python3
"""cnapp_customcontrol.py — user-authored Controls as managed, persisted objects.

WHAT THIS ADDS, AND WHAT ALREADY EXISTED
-----------------------------------------
`aws_controls.py` already turns a saved WQL query into a synthetic finding, and
`cnapp_service._controls_for_account` already evaluates a control set against an
account's graph. What did NOT exist is any way for a *user* to author one: controls
arrived only from the `CNAPP_CONTROLS` environment variable, read once at process
start, identical for every workspace, and editable only by whoever can restart the
server. There was a GET route and nothing else.

This module makes a control a first-class object: created, edited and deleted through
the API, persisted per workspace, and optionally bound to a compliance framework
control so a customer's own check counts toward their own framework.

THE SECURITY BOUNDARY IS AT WRITE TIME
---------------------------------------
A control carries a WQL query, and WQL is the query language over the security graph.
`aws_wql.parse` is the typed, bounded validator that rejects unknown fields, operators
and predicates — there is no regex, no eval, no free-text path. This module calls it
**on write**, so a malformed or unsafe query is rejected with a 400 at authoring time
rather than becoming an inert control that silently matches nothing forever. The
read-time path in cnapp_service stays fail-safe as a second line of defence.

WHY A CUSTOM CONTROL STILL CANNOT MOVE THE POSTURE SCORE
---------------------------------------------------------
`aws_controls.control_finding` emits `status="WARN"`, and the posture score is baked
from FAIL findings at scan time. That is deliberate and this module does not change
it: a user-authored query that scores its own author's posture would make the number
meaningless as a comparison, and there is no way to validate a customer's check the
way the shipped 452 are validated. Custom controls surface, they do not grade.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Dict, List, Optional

import aws_controls

#: Severity bands a control may carry. Mirrors aws_controls._SEV rather than
#: redefining it — an author picking a band the finding renderer does not know
#: would render as MEDIUM and confuse them.
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

MAX_NAME = 120
MAX_DESCRIPTION = 2000
MAX_REMEDIATION = 4000
MAX_QUERY_BYTES = 16384          # a WQL object is small; this bounds a hostile payload
MAX_CONTROLS_PER_WORKSPACE = 500


class ControlError(ValueError):
    """A rejected control definition. Carries a message meant for the author."""


def _clean(value, field: str, limit: int, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ControlError(f"{field} must be a string")
    value = value.strip()
    if required and not value:
        raise ControlError(f"{field} is required")
    if len(value) > limit:
        raise ControlError(f"{field} exceeds {limit} characters")
    return value


def validate(body: dict, *, control_id: Optional[str] = None) -> dict:
    """Normalize and validate an authored control. Raises ControlError on anything
    malformed — including a WQL query that `aws_wql.parse` rejects.

    Returns the stored shape, which is deliberately the SAME shape
    `aws_controls.control_finding` already consumes, so no translation layer exists
    between what a user authors and what the finding renderer reads."""
    import aws_wql

    if not isinstance(body, dict):
        raise ControlError("control must be an object")

    name = _clean(body.get("name"), "name", MAX_NAME, required=True)
    description = _clean(body.get("description"), "description", MAX_DESCRIPTION)
    remediation = _clean(body.get("remediation_cmd"), "remediation_cmd", MAX_REMEDIATION)
    section = _clean(body.get("section"), "section", MAX_NAME) or aws_controls.CONTROL_SECTION

    severity = body.get("severity") or "MEDIUM"
    if severity not in SEVERITIES:
        raise ControlError(f"severity must be one of {', '.join(SEVERITIES)}")

    query = body.get("query")
    if query is None:
        raise ControlError("query is required")
    encoded = json.dumps(query, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > MAX_QUERY_BYTES:
        raise ControlError(f"query exceeds {MAX_QUERY_BYTES} bytes")
    try:
        # THE security boundary. Store the PARSED form: a control that round-trips
        # through the validator cannot later be read back as something it was not.
        parsed = aws_wql.parse(query)
    except aws_wql.WQLError as e:
        raise ControlError(f"query is not valid WQL: {e}") from e

    compliance = body.get("compliance") or {}
    if not isinstance(compliance, dict):
        raise ControlError("compliance must be an object of framework -> control id")
    for framework, control in compliance.items():
        if not isinstance(framework, str) or not isinstance(control, str):
            raise ControlError("compliance keys and values must both be strings")
        if len(framework) > 60 or len(control) > 60:
            raise ControlError("compliance framework and control ids are capped at 60 chars")

    return {
        "id": control_id or ("c-" + uuid.uuid4().hex[:12]),
        "name": name,
        "description": description,
        "section": section,
        "severity": severity,
        "query": parsed,
        "compliance": dict(compliance),
        "remediation_cmd": remediation,
        "enabled": bool(body.get("enabled", True)),
    }


class CustomControlStore:
    """Workspace-scoped CRUD over authored controls.

    Takes an injected connection factory rather than owning a database, matching
    ConnectorStore and WorkspaceStore. Every method is explicit about its workspace:
    there is no ambient tenant, because a control that leaked across a workspace
    boundary would surface one customer's findings inside another's console.
    """

    def __init__(self, backend, *, now=None) -> None:
        self._be = backend
        self._now = now or (lambda: int(time.time()))

    # ── read ────────────────────────────────────────────────────────────────
    def list(self, workspace_id: Optional[str], *, enabled_only: bool = False) -> List[dict]:
        sql = ("SELECT control_id, workspace_id, name, description, section, severity, "
               "query_json, compliance_json, remediation_cmd, enabled, created_by, "
               "created_at, updated_at FROM custom_controls")
        args: List = []
        clauses = []
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            args.append(workspace_id)
        if enabled_only:
            clauses.append("enabled = 1")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY name, control_id"
        return [self._row(dict(r)) for r in self._be.query_all(sql, args)]

    def get(self, workspace_id: Optional[str], control_id: str) -> Optional[dict]:
        for c in self.list(workspace_id):
            if c["id"] == control_id:
                return c
        return None

    # ── write ───────────────────────────────────────────────────────────────
    def create(self, workspace_id: str, body: dict, *, created_by: str = "") -> dict:
        ctrl = validate(body)
        existing = self.list(workspace_id)
        if len(existing) >= MAX_CONTROLS_PER_WORKSPACE:
            raise ControlError(
                f"workspace already has {len(existing)} controls "
                f"(limit {MAX_CONTROLS_PER_WORKSPACE})")
        if any(c["name"].lower() == ctrl["name"].lower() for c in existing):
            raise ControlError(f"a control named {ctrl['name']!r} already exists")
        ts = self._now()
        self._be.execute(
            "INSERT INTO custom_controls(control_id, workspace_id, name, description, "
            "section, severity, query_json, compliance_json, remediation_cmd, enabled, "
            "created_by, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ctrl["id"], workspace_id, ctrl["name"], ctrl["description"], ctrl["section"],
             ctrl["severity"], json.dumps(ctrl["query"], separators=(",", ":")),
             json.dumps(ctrl["compliance"], separators=(",", ":")),
             ctrl["remediation_cmd"], 1 if ctrl["enabled"] else 0, created_by, ts, ts))
        return self.get(workspace_id, ctrl["id"])

    def update(self, workspace_id: str, control_id: str, body: dict) -> Optional[dict]:
        current = self.get(workspace_id, control_id)
        if current is None:
            return None
        merged = {**current, **{k: v for k, v in (body or {}).items() if v is not None}}
        ctrl = validate(merged, control_id=control_id)
        clash = [c for c in self.list(workspace_id)
                 if c["name"].lower() == ctrl["name"].lower() and c["id"] != control_id]
        if clash:
            raise ControlError(f"a control named {ctrl['name']!r} already exists")
        self._be.execute(
            "UPDATE custom_controls SET name=?, description=?, section=?, severity=?, "
            "query_json=?, compliance_json=?, remediation_cmd=?, enabled=?, updated_at=? "
            "WHERE control_id=? AND workspace_id=?",
            (ctrl["name"], ctrl["description"], ctrl["section"], ctrl["severity"],
             json.dumps(ctrl["query"], separators=(",", ":")),
             json.dumps(ctrl["compliance"], separators=(",", ":")),
             ctrl["remediation_cmd"], 1 if ctrl["enabled"] else 0, self._now(),
             control_id, workspace_id))
        return self.get(workspace_id, control_id)

    def delete(self, workspace_id: str, control_id: str) -> bool:
        r = self._be.execute(
            "DELETE FROM custom_controls WHERE control_id=? AND workspace_id=?",
            (control_id, workspace_id))
        return r.rowcount > 0

    # ── row -> the shape aws_controls already consumes ──────────────────────
    @staticmethod
    def _row(r: dict) -> dict:
        def _json(raw, default):
            try:
                return json.loads(raw) if raw else default
            except (TypeError, ValueError):
                # A control whose stored JSON is unreadable must not take the whole list
                # down -- it degrades to an inert control, matching the read-time fail-safe
                # in cnapp_service.
                return default
        return {
            "id": r["control_id"], "workspace_id": r["workspace_id"], "name": r["name"],
            "description": r["description"], "section": r["section"],
            "severity": r["severity"],
            "query": _json(r["query_json"], None),
            "compliance": _json(r["compliance_json"], {}),
            "remediation_cmd": r["remediation_cmd"], "enabled": bool(r["enabled"]),
            "created_by": r["created_by"], "created_at": r["created_at"],
            "updated_at": r["updated_at"],
            "source": "custom",
        }
