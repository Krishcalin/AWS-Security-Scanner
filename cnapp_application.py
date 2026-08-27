#!/usr/bin/env python3
"""cnapp_application.py — the Application registry as a managed, persisted object.

WHAT THIS ADDS, AND WHAT ALREADY EXISTED
-----------------------------------------
`aws_ownership.py` already knows how to attribute a finding to an application and
how to report what it could not attribute. What did NOT exist is anywhere for an
application to *live*: `Application` was a dataclass a caller had to construct by
hand, so FR-2 scorecards had no registry to be per-application about, and AD-02 —
the dependency the SRS files as an assumption — stayed unsatisfiable in practice.

This is the storage half, and it follows `cnapp_customcontrol` deliberately:
workspace-scoped CRUD over an injected backend, no ambient tenant, and the same
name-uniqueness-per-workspace rule. Two tenants may each run an application called
"Payments" and neither should block the other.

────────────────────────────────────────────────────────────────────────────────
VALIDATION HAPPENS AT WRITE
────────────────────────────────────────────────────────────────────────────────
:func:`validate` constructs a real :class:`aws_ownership.Application`, so every
rule that dataclass enforces — no key-only tag selector, a known criticality tier —
becomes a message to the author at the moment they save, rather than an entry that
sits in the registry matching nothing.

That matters more here than it looks. A mis-scoped application does not fail
loudly: it renders a scorecard, reports zero findings, and is indistinguishable
from an application that is genuinely clean. :func:`warnings_for` therefore returns
the non-fatal problems — no owner, no selectors, unclassified criticality — so the
console can show them next to the save rather than leaving the author to discover
them from a suspiciously good grade three weeks later.

A **fatal** error rejects the write. A **warning** does not: an operator
mid-onboarding may legitimately create an application before its owner is known,
and refusing that would push the registry into a spreadsheet where nothing
validates it at all.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from typing import Dict, List, Optional, Sequence, Tuple

import aws_ownership

MAX_APPS_PER_WORKSPACE = 500
"""A registry larger than this is a CMDB, and AD-02 says the CMDB is upstream."""

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

COLS = ("app_id", "workspace_id", "name", "owner", "portfolio", "criticality",
        "accounts_json", "tag_selectors_json", "resource_arns_json",
        "created_by", "created_at", "updated_at")


class ApplicationError(ValueError):
    """A write the registry refuses. Carries a message meant for the author."""


def _clean_list(raw, field: str) -> Tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        raise ApplicationError(
            "%s must be a list, not a string — a comma-joined string silently "
            "becomes one long selector that matches nothing" % field)
    out = []
    for v in raw:
        v = str(v).strip()
        if v:
            out.append(v)
    return tuple(dict.fromkeys(out))          # de-dupe, order-preserving


def _clean_selectors(raw) -> Tuple[Tuple[str, str], ...]:
    """Accepts ``[["Key","Value"], ...]`` or ``[{"key":..,"value":..}, ...]``."""
    if raw is None:
        return ()
    out: List[Tuple[str, str]] = []
    for item in raw:
        if isinstance(item, dict):
            k, v = item.get("key"), item.get("value")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            k, v = item
        else:
            raise ApplicationError(
                "each tag selector must be a {key, value} object or a [key, value] "
                "pair; got %r" % (item,))
        k = str(k or "").strip()
        v = "" if v is None else str(v).strip()
        out.append((k, v))
    return tuple(dict.fromkeys(out))


def validate(body: dict, *, app_id: Optional[str] = None) -> dict:
    """Normalise and validate one application body.

    Raises :class:`ApplicationError` on anything that would store an entry the
    author did not mean. Returns the canonical dict the store persists.
    """
    body = dict(body or {})
    name = str(body.get("name") or "").strip()
    if not name:
        raise ApplicationError("an application needs a name")
    if len(name) > 120:
        raise ApplicationError("name is limited to 120 characters")

    aid = str(app_id or body.get("id") or body.get("app_id") or "").strip().lower()
    if not aid:
        aid = "app-" + uuid.uuid4().hex[:12]
    if not _ID_RE.match(aid):
        raise ApplicationError(
            "app id %r must be lowercase alphanumeric with . _ - (max 64)" % aid)

    accounts = _clean_list(body.get("accounts"), "accounts")
    for a in accounts:
        if not (a.isdigit() and len(a) == 12):
            raise ApplicationError(
                "account %r is not a 12-digit AWS account id; a typo here produces "
                "an application that silently owns nothing" % a)

    canonical = {
        "id": aid,
        "name": name,
        "owner": str(body.get("owner") or "").strip(),
        "portfolio": str(body.get("portfolio") or "").strip(),
        "criticality": str(body.get("criticality")
                           or aws_ownership.CRITICALITY[-1]).strip(),
        "accounts": accounts,
        "tag_selectors": _clean_selectors(body.get("tag_selectors")),
        "resource_arns": _clean_list(body.get("resource_arns"), "resource_arns"),
    }

    # The dataclass IS the rule set: constructing it applies every invariant
    # aws_ownership enforces, so the registry and the attributor can never
    # disagree about what a valid application is.
    try:
        as_application(canonical)
    except ValueError as exc:
        raise ApplicationError(str(exc)) from exc
    return canonical


def as_application(record: dict) -> aws_ownership.Application:
    """Build the `aws_ownership.Application` the attributor consumes."""
    return aws_ownership.Application(
        app_id=record["id"], name=record["name"], owner=record.get("owner", ""),
        portfolio=record.get("portfolio", ""),
        criticality=record.get("criticality", aws_ownership.CRITICALITY[-1]),
        accounts=tuple(record.get("accounts") or ()),
        tag_selectors=tuple(tuple(t) for t in (record.get("tag_selectors") or ())),
        resource_arns=tuple(record.get("resource_arns") or ()))


def warnings_for(record: dict) -> Tuple[str, ...]:
    """Non-fatal problems worth showing the author at save time.

    Reuses :func:`aws_ownership.attribution_health` rather than restating its rules,
    so the console warning and the scan-time health report cannot drift apart.
    """
    issues = aws_ownership.attribution_health([as_application(record)])
    return tuple(i.detail for i in issues)


class ApplicationStore:
    """Workspace-scoped CRUD over the application registry.

    Takes an injected backend rather than owning a database, matching
    ConnectorStore, WorkspaceStore and CustomControlStore. Every method is
    explicit about its workspace: an application leaking across a boundary would
    attribute one customer's findings to another customer's owner.
    """

    def __init__(self, backend, *, now=None) -> None:
        self._be = backend
        self._now = now or (lambda: int(time.time()))

    # ── read ────────────────────────────────────────────────────────────────
    def list(self, workspace_id: Optional[str]) -> List[dict]:
        sql = "SELECT %s FROM applications" % ", ".join(COLS)
        args: List = []
        if workspace_id is not None:
            sql += " WHERE workspace_id = ?"
            args.append(workspace_id)
        sql += " ORDER BY name, app_id"
        return [self._row(dict(r)) for r in self._be.query_all(sql, args)]

    def get(self, workspace_id: Optional[str], app_id: str) -> Optional[dict]:
        sql = "SELECT %s FROM applications WHERE app_id = ?" % ", ".join(COLS)
        args: List = [app_id]
        if workspace_id is not None:
            sql += " AND workspace_id = ?"
            args.append(workspace_id)
        rows = self._be.query_all(sql, args)
        return self._row(dict(rows[0])) if rows else None

    def applications(self, workspace_id: Optional[str]
                     ) -> Tuple[aws_ownership.Application, ...]:
        """The registry in the shape `aws_ownership.attribute_findings` wants."""
        return tuple(as_application(r) for r in self.list(workspace_id))

    # ── write ───────────────────────────────────────────────────────────────
    def create(self, workspace_id: str, body: dict, *, created_by: str = "") -> dict:
        rec = validate(body)
        existing = self.list(workspace_id)
        if len(existing) >= MAX_APPS_PER_WORKSPACE:
            raise ApplicationError(
                "workspace already has %d applications (limit %d)"
                % (len(existing), MAX_APPS_PER_WORKSPACE))
        if any(a["name"].lower() == rec["name"].lower() for a in existing):
            raise ApplicationError(
                "an application named %r already exists" % rec["name"])
        if any(a["id"] == rec["id"] for a in existing):
            raise ApplicationError("an application with id %r already exists"
                                   % rec["id"])
        ts = self._now()
        self._be.execute(
            "INSERT INTO applications(%s) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"
            % ", ".join(COLS),
            (rec["id"], workspace_id, rec["name"], rec["owner"], rec["portfolio"],
             rec["criticality"], _j(rec["accounts"]), _j(rec["tag_selectors"]),
             _j(rec["resource_arns"]), created_by, ts, ts))
        return self.get(workspace_id, rec["id"])

    def update(self, workspace_id: str, app_id: str, body: dict) -> Optional[dict]:
        current = self.get(workspace_id, app_id)
        if current is None:
            return None
        merged = {**current, **{k: v for k, v in (body or {}).items()
                                if v is not None}}
        rec = validate(merged, app_id=app_id)
        clash = [a for a in self.list(workspace_id)
                 if a["name"].lower() == rec["name"].lower() and a["id"] != app_id]
        if clash:
            raise ApplicationError(
                "an application named %r already exists" % rec["name"])
        self._be.execute(
            "UPDATE applications SET name=?, owner=?, portfolio=?, criticality=?, "
            "accounts_json=?, tag_selectors_json=?, resource_arns_json=?, "
            "updated_at=? WHERE app_id=? AND workspace_id=?",
            (rec["name"], rec["owner"], rec["portfolio"], rec["criticality"],
             _j(rec["accounts"]), _j(rec["tag_selectors"]), _j(rec["resource_arns"]),
             self._now(), app_id, workspace_id))
        return self.get(workspace_id, app_id)

    def delete(self, workspace_id: str, app_id: str) -> bool:
        r = self._be.execute(
            "DELETE FROM applications WHERE app_id=? AND workspace_id=?",
            (app_id, workspace_id))
        return r.rowcount > 0

    # ── row -> the canonical shape ──────────────────────────────────────────
    @staticmethod
    def _row(r: dict) -> dict:
        def _load(raw, default):
            try:
                return json.loads(raw) if raw else default
            except (TypeError, ValueError):
                # Unreadable stored JSON degrades that ONE selector list to empty
                # rather than taking the whole registry down -- the same read-time
                # fail-safe cnapp_customcontrol applies.
                return default
        sel = _load(r.get("tag_selectors_json"), [])
        return {
            "id": r["app_id"], "workspace_id": r["workspace_id"], "name": r["name"],
            "owner": r.get("owner", ""), "portfolio": r.get("portfolio", ""),
            "criticality": r.get("criticality", aws_ownership.CRITICALITY[-1]),
            "accounts": tuple(_load(r.get("accounts_json"), [])),
            "tag_selectors": tuple(tuple(t) for t in sel),
            "resource_arns": tuple(_load(r.get("resource_arns_json"), [])),
            "created_by": r.get("created_by") or "",
            "created_at": r.get("created_at"), "updated_at": r.get("updated_at"),
        }


def _j(value) -> str:
    return json.dumps(list(value), separators=(",", ":"))
