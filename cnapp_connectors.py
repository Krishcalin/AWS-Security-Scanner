#!/usr/bin/env python3
"""
cnapp_connectors.py — outbound notification/ticketing connector framework for the
hosted CNAPP (Phase-2 workflow plane).

Routes findings from a scan to the OPERATOR'S OWN tools — Jira, Slack, PagerDuty,
Splunk HEC, or a generic signed webhook — under a rule engine (severity floor /
section / check glob / account glob / on-attack-path / framework). It is the
"do something about it" layer on top of the read-only scanner.

READ-ONLY ON TARGETS PRESERVED
------------------------------
A connector makes **no** AWS call against any scanned account — no
``sts:AssumeRole`` into a spoke, no mutation of a customer resource. The only
outbound is HTTP to the operator's own endpoints. The new risk surface is purely
outbound HTTP + operator secrets, contained by the invariants below.

Security invariants (load-bearing)
----------------------------------
* **Secret as a ref only** — the operator credential (Jira token, Slack bot
  token / webhook URL, PagerDuty routing key, Splunk HEC token, webhook signing
  secret) arrives ONCE on create/rotate, is handed to the injected
  ``secret_writer`` and only the returned ``secretsmanager://`` / ``ssm://`` ref
  is persisted (validated, mirroring ``cnapp_onboarding``). It is resolved to
  plaintext only transiently inside :func:`dispatch`, immediately before the send,
  and is NEVER written to the ledger (errors are scrubbed) or returned over the API
  (:func:`ConnectorStore._mask_connector` pops it → ``secret_configured`` bool).
* **Admin-only, explicit-enable, safe by default** — connectors default
  ``enabled=0``; :func:`dispatch` is a hard no-op unless enabled. A disabled rule
  OR an absent/disabled connector yields ZERO actions.
* **Injected seams, offline-testable pure core** — the renderers, request builder,
  response interpreter, and the whole rules engine perform NO I/O, NO ``now()``,
  NO http. ``http_post`` + ``secret_reader`` + an injected ``now_epoch`` clock are
  the only seams (mirroring ``assume_role_fn`` / ``client_factory`` /
  ``secret_writer``). Tests pass a fake ``http_post`` and never touch a socket.
* **Idempotent delivery** — ``UNIQUE(connector_id, dedup_key)`` + claim-then-send
  means a re-run / retry / concurrent worker never double-sends.
* **Webhook SSRF guard + byte-stable signing** — webhook URLs are https-only and
  the IMDS address is always blocked; the envelope is serialized ONCE and those
  exact bytes are both HMAC-signed and posted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import string
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Sequence, Tuple, Union

from aws_state import finding_key
from aws_state import _glob as _glob            # fnmatchcase; NEVER pushed into SQL
from cnapp_onboarding import _RESOLVABLE_SCHEMES, SecretReader, SecretWriter

# Local copies of the two tiny aws_remediate primitives so this module stays a
# leaf (importing aws_remediate would drag the whole scanner/correlate graph in,
# defeating "offline-testable"). Kept identical in value on purpose.
_SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "": 0}
_CONNECTOR_TYPES = ("jira", "slack", "pagerduty", "splunk", "webhook")
_AFFECTED_CAP = 20              # truncate affected[] in a message body → "and K more"


class _SafeMap:
    """string.Template mapping: a missing/None key renders ``<KEY>`` so a
    message-template override never raises mid-scan (mirrors aws_remediate)."""

    def __init__(self, d: Dict):
        self._d = d or {}

    def __getitem__(self, k):
        v = self._d.get(k)
        return v if v is not None else "<" + str(k).upper() + ">"


def _safe_format(tmpl: Optional[str], params: Dict) -> str:
    if not tmpl:
        return ""
    return string.Template(tmpl).safe_substitute(_SafeMap(params))


def _sev_ge(sev: str, floor: str) -> bool:
    return _SEV_ORDER.get(sev or "", 0) >= _SEV_ORDER.get(floor or "", 0)


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat().replace("+00:00", "Z")


# ═══════════════════════════════════════════════════════════════════════════════
#  Models (frozen dataclasses — pure data)
# ═══════════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class HttpResp:
    """The tiny injected-seam return value — exactly what interpret_response needs."""
    status_code: int
    text: str = ""


@dataclass(frozen=True)
class HttpRequest:
    """A fully-built outbound request (auth header already injected from the
    transient secret). Webhook uses ``raw_body`` (the signed bytes); others use
    ``json_body``."""
    method: str
    url: str
    headers: Dict[str, str]
    json_body: Optional[dict] = None
    raw_body: Optional[bytes] = None
    timeout: float = 8.0


@dataclass(frozen=True)
class EnrichedFinding:
    """The rule unit = a finding_catalog entry + its account + the injected
    on_attack_path bool (the 3rd input alongside the entry + account)."""
    check_id: str
    section: str
    severity: str
    status: str
    compliance: Dict[str, str]
    remediation_cmd: str
    risk: str
    impact: str
    steps: List[str]
    affected: List[str]
    count: int
    distinct: int
    account: str
    on_attack_path: bool = False


@dataclass(frozen=True)
class Connector:
    connector_id: str
    type: str
    name: str
    enabled: bool
    config: Dict            # NON-secret settings only
    secret_ref: Optional[str] = None
    created_by: Optional[str] = None
    last_test_at: Optional[int] = None
    last_test_status: Optional[str] = None
    last_test_detail: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


@dataclass(frozen=True)
class ConnectorRule:
    id: int
    connector_id: str
    name: str = ""
    enabled: bool = True
    priority: int = 100
    min_severity: str = "HIGH"
    severities: List[str] = field(default_factory=list)
    sections: List[str] = field(default_factory=list)
    check_globs: List[str] = field(default_factory=list)
    not_check_globs: List[str] = field(default_factory=list)
    account_globs: List[str] = field(default_factory=list)
    on_attack_path: Optional[bool] = None
    statuses: List[str] = field(default_factory=lambda: ["FAIL"])
    frameworks: List[str] = field(default_factory=list)
    controls: List[str] = field(default_factory=list)
    min_count: int = 0
    min_distinct: int = 0
    dedup_mode: str = "notify_once"       # notify_once | renotify
    throttle_seconds: int = 0
    renotify_on_escalation: bool = True
    notify_on_resolve: bool = False
    stop_on_match: bool = False
    connector_ids: List[str] = field(default_factory=list)   # =[connector_id]+extra
    tags: List[str] = field(default_factory=list)
    message_template: Optional[str] = None
    severity_override: Optional[str] = None
    created_by: str = ""
    created_at: int = 0
    updated_at: int = 0


@dataclass(frozen=True)
class ConnectorAction:
    """One unit of intended outbound work; collapsed per (connector_id, dedup_key)."""
    connector_id: str
    rule_id: int
    account: str
    check_id: str
    identity: str
    dedup_key: str
    fingerprint: str
    severity: str
    kind: str = "new"           # new|retry|reopened|escalated|reminder|resolved
    event_id: str = ""
    finding: Optional[EnrichedFinding] = None
    template: Optional[str] = None


@dataclass(frozen=True)
class DispatchResult:
    ok: bool
    http_status: int = 0
    external_ref: Optional[str] = None
    error: Optional[str] = None       # SCRUBBED of any secret
    detail: str = ""


@dataclass(frozen=True)
class LedgerRow:
    connector_id: str
    dedup_key: str
    account: str
    check_id: str
    rule_id: int
    state: str
    kind: str
    fingerprint: str
    first_notified_epoch: Optional[int]
    last_notified_epoch: Optional[int]
    notify_count: int
    status: str = "pending"
    id: Optional[int] = None
    finding_key: Optional[str] = None
    external_ref: Optional[str] = None


@dataclass(frozen=True)
class LedgerUpsert:
    """The delta plan()/resolve_stale return for the impure runner to persist."""
    action: ConnectorAction
    is_new: bool
    state: str
    kind: str
    fingerprint: str
    notify_epoch: int
    notify_count: int


@dataclass(frozen=True)
class RunResult:
    sent: int = 0
    suppressed: int = 0
    resolved: int = 0
    failed: int = 0
    digested: int = 0
    actions: List[ConnectorAction] = field(default_factory=list)
    results: List[DispatchResult] = field(default_factory=list)


# Injected seam contracts
HttpPost = Callable[..., HttpResp]     # http_post(url, *, headers, json_body=, data=, timeout=)
Clock = Callable[[], int]


# ═══════════════════════════════════════════════════════════════════════════════
#  Adapter: finding_catalog entry -> EnrichedFinding
# ═══════════════════════════════════════════════════════════════════════════════
def to_finding(entry: Dict, account: str, on_attack_path: bool) -> EnrichedFinding:
    """PURE. The enriched rule unit = a finding_catalog entry (verbatim) + account
    + the injected on_attack_path bool."""
    return EnrichedFinding(
        check_id=str(entry.get("check_id", "")),
        section=str(entry.get("section", "")),
        severity=str(entry.get("severity", "")),
        status=str(entry.get("status", "")),
        compliance=dict(entry.get("compliance", {}) or {}),
        remediation_cmd=str(entry.get("remediation_cmd", "") or ""),
        risk=str(entry.get("risk", "") or ""),
        impact=str(entry.get("impact", "") or ""),
        steps=list(entry.get("steps", []) or []),
        affected=list(entry.get("affected", []) or []),
        count=int(entry.get("count", 0) or 0),
        distinct=int(entry.get("distinct", 0) or 0),
        account=str(account),
        on_attack_path=bool(on_attack_path),
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  Pure renderers — build the operator-tool payload (no secret, no now(), no http)
# ═══════════════════════════════════════════════════════════════════════════════
def _title(f: EnrichedFinding) -> str:
    """A one-line human title from the finding's risk (first sentence) or check id."""
    risk = (f.risk or "").strip()
    if risk:
        m = risk.split(". ")[0].strip().rstrip(".")
        if m:
            return m[:160]
    return f.check_id


def _tmpl_params(f: EnrichedFinding) -> Dict:
    return {"check_id": f.check_id, "section": f.section, "severity": f.severity,
            "account": f.account, "risk": f.risk, "impact": f.impact,
            "status": f.status, "count": f.count, "distinct": f.distinct,
            "title": _title(f)}


def _affected_lines(f: EnrichedFinding) -> Tuple[List[str], int]:
    shown = list(f.affected[:_AFFECTED_CAP])
    more = max(0, f.distinct - len(shown))
    return shown, more


_JIRA_PRIORITY = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium",
                  "LOW": "Low", "INFO": "Lowest"}


def _adf_text(t: str) -> dict:
    return {"type": "paragraph", "content": [{"type": "text", "text": (t or "")[:1500]}]}


def _adf_heading(t: str) -> dict:
    return {"type": "heading", "attrs": {"level": 3},
            "content": [{"type": "text", "text": t}]}


def _jira_label(s: str) -> str:
    """Jira labels cannot contain spaces — collapse to a single token."""
    return "".join(ch if ch.isalnum() or ch in "-_.:" else "-" for ch in str(s)).strip("-")


def render_jira(connector: Connector, f: EnrichedFinding, *, template: str = None,
                fingerprint: str = "") -> dict:
    """PURE. Jira Cloud v3 create-issue body. description MUST be an ADF object
    (a plain string → 400). priority is best-effort (may be locked by the project
    scheme; the sender retries without it on that error)."""
    cfg = connector.config or {}
    project = ({"id": cfg["project_id"]} if cfg.get("project_id")
               else {"key": cfg.get("project_key", "SEC")})
    issuetype = ({"id": cfg["issue_type_id"]} if cfg.get("issue_type_id")
                 else {"name": cfg.get("issue_type", "Task")})
    shown, more = _affected_lines(f)
    content: List[dict] = []
    if f.risk:
        content += [_adf_heading("Risk"), _adf_text(f.risk)]
    if f.impact:
        content += [_adf_heading("Business impact"), _adf_text(f.impact)]
    if f.steps:
        content.append(_adf_heading("Remediation"))
        content.append({"type": "orderedList", "content": [
            {"type": "listItem", "content": [_adf_text(s)]} for s in f.steps[:20]]})
    if f.remediation_cmd:
        content.append({"type": "codeBlock", "attrs": {},
                        "content": [{"type": "text", "text": f.remediation_cmd[:1500]}]})
    if shown:
        content.append(_adf_heading(f"Affected resources ({f.distinct})"))
        items = [{"type": "listItem", "content": [_adf_text(r)]} for r in shown]
        if more:
            items.append({"type": "listItem", "content": [_adf_text(f"…and {more} more")]})
        content.append({"type": "bulletList", "content": items})
    if not content:
        content = [_adf_text(_title(f))]

    labels = ["overwatch", f"sev-{(f.severity or '').lower()}", f"acct-{_jira_label(f.account)}"]
    if f.on_attack_path:
        labels.append("attack-path")
    for fw, ctrl in (f.compliance or {}).items():
        labels.append(_jira_label(f"{fw}-{ctrl}"))
    if fingerprint:
        labels.append(f"owfp-{fingerprint[:12]}")

    sev = connector_severity(connector, f, template_override=None)
    summary = _safe_format(template, _tmpl_params(f)) if template else \
        f"[OverWatch] {f.check_id} · {_title(f)} (acct {f.account})"
    body = {"fields": {
        "project": project, "issuetype": issuetype,
        "summary": summary[:255],
        "description": {"type": "doc", "version": 1, "content": content},
        "labels": labels[:40],
    }}
    prio = _JIRA_PRIORITY.get(sev)
    if prio and cfg.get("set_priority", True):
        body["fields"]["priority"] = {"name": prio}
    return body


_SLACK_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def _slack_field(label: str, value: str) -> dict:
    return {"type": "mrkdwn", "text": f"*{label}:*\n{(value or '—')[:1900]}"}


def render_slack(connector: Connector, f: EnrichedFinding, *, template: str = None,
                 hub_base: str = "") -> dict:
    """PURE. Block Kit body + a top-level ``text`` fallback (ALWAYS). Header is
    plain_text ≤150 chars; a section's fields ≤10, each ≤2000; section text ≤3000."""
    cfg = connector.config or {}
    emoji = _SLACK_EMOJI.get(f.severity, "⚪")
    header = f"{emoji} {f.severity} · {f.check_id}"[:150]
    shown, more = _affected_lines(f)
    aff = f"{f.distinct} resource(s)" + (f", +{more} more" if more else "")
    fields = [
        _slack_field("Section", f.section),
        _slack_field("Account", f.account),
        _slack_field("Status", f.status),
        _slack_field("On attack path", "Yes" if f.on_attack_path else "No"),
        _slack_field("Affected", aff),
    ]
    if f.compliance:
        fields.append(_slack_field("Compliance",
                                   " · ".join(f"{k} {v}" for k, v in list(f.compliance.items())[:6])))
    blocks: List[dict] = [
        {"type": "header", "text": {"type": "plain_text", "emoji": True, "text": header}},
        {"type": "section", "fields": fields[:10]},
    ]
    if f.risk:
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn", "text": f"*Risk:* {f.risk[:2900]}"}})
    if hub_base:
        url = f"{hub_base.rstrip('/')}/findings/{f.check_id}?account={f.account}"
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "style": "primary",
             "text": {"type": "plain_text", "text": "View in OverWatch"}, "url": url}]})
    fallback = (_safe_format(template, _tmpl_params(f)) if template
                else f"{f.severity} · {f.check_id} · account {f.account}")
    body: Dict = {"text": fallback[:3000], "blocks": blocks}
    if (cfg.get("mode", "webhook") == "chat") and cfg.get("channel"):
        body["channel"] = cfg["channel"]     # chat.postMessage only; omit for webhook
    return body


_PD_SEVERITY = {"CRITICAL": "critical", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "info", "INFO": "info"}


def render_pagerduty(connector: Connector, f: EnrichedFinding, *,
                     event_action: str = "trigger", template: str = None,
                     hub_base: str = "") -> dict:
    """PURE. Events API v2 enqueue body WITHOUT routing_key (injected at send).
    payload.severity is a strict lowercase enum via the map."""
    sev = connector_severity(connector, f, template_override=None)
    dedup = f"overwatch:{f.account}:{f.check_id}"
    if event_action in ("resolve", "acknowledge"):
        return {"event_action": event_action, "dedup_key": dedup}
    shown, more = _affected_lines(f)
    summary = (_safe_format(template, _tmpl_params(f)) if template
               else f"[{sev}] {f.check_id} {f.section}: {_title(f)} ({f.count} affected)")
    body = {
        "event_action": "trigger",
        "dedup_key": dedup,
        "client": "OverWatch CNAPP",
        "payload": {
            "summary": summary[:1024],
            "source": f"aws:{f.account}",
            "severity": _PD_SEVERITY.get(sev, "warning"),
            "component": f.section,
            "class": f.check_id,
            "group": "attack-path" if f.on_attack_path else f.account,
            "custom_details": {
                "check_id": f.check_id, "section": f.section, "status": f.status,
                "severity": f.severity, "count": f.count, "distinct": f.distinct,
                "on_attack_path": f.on_attack_path, "compliance": f.compliance,
                "remediation_cmd": f.remediation_cmd, "risk": f.risk, "impact": f.impact,
                "steps": f.steps[:20], "affected": shown,
                "affected_more": more,
            },
        },
    }
    if hub_base:
        link = f"{hub_base.rstrip('/')}/findings/{f.check_id}?account={f.account}"
        body["client_url"] = link
        body["links"] = [{"href": link, "text": "View finding in OverWatch"}]
    return body


_SPLUNK_SEV_NUM = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def render_splunk(connector: Connector, f: EnrichedFinding, *, template: str = None) -> dict:
    """PURE. HEC /services/collector/event envelope. No token (injected at send).
    ``time`` is OMITTED so HEC uses receipt time (avoids the ms-vs-seconds trap)."""
    cfg = connector.config or {}
    shown, more = _affected_lines(f)
    event = {
        "check_id": f.check_id, "section": f.section, "severity": f.severity,
        "severity_num": _SPLUNK_SEV_NUM.get(f.severity, 0), "status": f.status,
        "account_id": f.account, "on_attack_path": f.on_attack_path,
        "count": f.count, "distinct": f.distinct, "affected": shown, "affected_more": more,
        "compliance": f.compliance, "risk": f.risk, "impact": f.impact,
        "remediation_cmd": f.remediation_cmd, "steps": f.steps[:20],
    }
    envelope = {
        "host": "overwatch", "source": "overwatch-cnapp",
        "sourcetype": cfg.get("sourcetype", "overwatch:finding"),
        "event": event,
        # index-time fields MUST be flat scalars/strings (compliance dict stays in event)
        "fields": {"check_id": f.check_id, "severity": f.severity,
                   "account_id": f.account, "on_attack_path": str(f.on_attack_path).lower()},
    }
    if cfg.get("index"):
        envelope["index"] = cfg["index"]
    return envelope


def render_webhook(connector: Connector, f: EnrichedFinding, *, event_id: str,
                   now_epoch: int, hub_base: str = "", type_override: str = None) -> bytes:
    """PURE + byte-stable. The OverWatch event envelope, serialized ONCE to minified
    sorted UTF-8 bytes — the EXACT bytes that get signed AND sent. ``event_id`` /
    ``now_epoch`` are INPUTS (never uuid()/now() inside) so a retry is idempotent
    for the receiver and golden output is deterministic."""
    link = (f"{hub_base.rstrip('/')}/findings/{f.check_id}?account={f.account}"
            if hub_base else "")
    entry = {
        "check_id": f.check_id, "section": f.section, "severity": f.severity,
        "status": f.status, "compliance": f.compliance,
        "remediation_cmd": f.remediation_cmd, "risk": f.risk, "impact": f.impact,
        "steps": f.steps, "affected": f.affected[:_AFFECTED_CAP],
        "count": f.count, "distinct": f.distinct,
    }
    envelope = {
        "specversion": "overwatch/v1",
        "id": event_id,
        "type": type_override or "overwatch.finding",
        "timestamp": _iso(now_epoch),
        "ts_epoch": int(now_epoch),
        "source": "overwatch",
        "account": f.account,
        "on_attack_path": f.on_attack_path,
        "severity": f.severity,
        "severity_rank": _SEV_ORDER.get(f.severity, 0),
        "link": link,
        "data": entry,
    }
    return json.dumps(envelope, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False).encode("utf-8")


RENDERERS = {"jira": render_jira, "slack": render_slack, "pagerduty": render_pagerduty,
             "splunk": render_splunk, "webhook": render_webhook}


def connector_severity(connector: Connector, f: EnrichedFinding, *,
                       template_override=None) -> str:
    """The effective severity for priority mapping (rule severity_override wins,
    else the finding's own). Kept a function so the value is one source of truth."""
    return (template_override or f.severity or "").upper() or "INFO"


def render(connector: Connector, f: EnrichedFinding, *, template: str = None,
           event_id: str = "", now_epoch: int = 0, event_action: str = "trigger",
           fingerprint: str = "", hub_base: str = "") -> Union[dict, bytes]:
    """Dispatch on connector.type. Returns a dict for API-JSON connectors, bytes
    for the webhook (the signed envelope)."""
    t = connector.type
    if t == "jira":
        return render_jira(connector, f, template=template, fingerprint=fingerprint)
    if t == "slack":
        return render_slack(connector, f, template=template, hub_base=hub_base)
    if t == "pagerduty":
        return render_pagerduty(connector, f, event_action=event_action,
                                template=template, hub_base=hub_base)
    if t == "splunk":
        return render_splunk(connector, f, template=template)
    if t == "webhook":
        return render_webhook(connector, f, event_id=event_id, now_epoch=now_epoch,
                              hub_base=hub_base)
    raise ValueError(f"unknown connector type {t!r}")


# ═══════════════════════════════════════════════════════════════════════════════
#  Request assembly (pure given the already-resolved secret) + response decode
# ═══════════════════════════════════════════════════════════════════════════════
_JSON_HDR = {"Content-Type": "application/json", "Accept": "application/json"}


def _pd_host(cfg: Dict) -> str:
    return ("https://events.eu.pagerduty.com/v2/enqueue"
            if (cfg.get("region", "us") == "eu")
            else "https://events.pagerduty.com/v2/enqueue")


def request_for(connector: Connector, payload: Union[dict, bytes], secret: Optional[str],
                *, event_id: str = "", now_epoch: int = 0) -> HttpRequest:
    """PURE given the resolved secret. Assemble method/url/headers/body per type,
    building the auth header HERE from the transient secret (never logged)."""
    t, cfg = connector.type, (connector.config or {})
    if t == "jira":
        site = cfg.get("site", "").rstrip("/")
        email = cfg.get("email", "")
        token = secret or ""
        basic = base64.b64encode(f"{email}:{token}".encode("utf-8")).decode("ascii")
        return HttpRequest("POST", f"{site}/rest/api/3/issue",
                           {**_JSON_HDR, "Authorization": f"Basic {basic}"},
                           json_body=payload)
    if t == "slack":
        if cfg.get("mode", "webhook") == "chat":
            return HttpRequest("POST", "https://slack.com/api/chat.postMessage",
                               {**_JSON_HDR, "Authorization": f"Bearer {secret or ''}"},
                               json_body=payload)
        # webhook mode: the secret IS the full hooks.slack.com URL
        return HttpRequest("POST", secret or "", dict(_JSON_HDR), json_body=payload)
    if t == "pagerduty":
        body = dict(payload) if isinstance(payload, dict) else {}
        body["routing_key"] = secret or ""     # auth lives in the BODY, not a header
        return HttpRequest("POST", _pd_host(cfg), {"Content-Type": "application/json"},
                           json_body=body)
    if t == "splunk":
        scheme = cfg.get("scheme", "https")
        host = cfg.get("host", "")
        port = cfg.get("port", 8088)
        url = f"{scheme}://{host}:{port}/services/collector/event"
        return HttpRequest("POST", url,
                           {"Content-Type": "application/json",
                            "Authorization": f"Splunk {secret or ''}"},
                           json_body=payload)
    if t == "webhook":
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "OverWatch-Connector/1"}
        if secret:
            ts = str(int(now_epoch))
            wid = event_id or hashlib.sha1(raw).hexdigest()[:24]
            key = secret.encode("utf-8")
            signed_content = f"{wid}.{ts}.".encode("utf-8") + raw
            sig = base64.b64encode(hmac.new(key, signed_content, hashlib.sha256).digest()).decode()
            gh = hmac.new(key, raw, hashlib.sha256).hexdigest()
            headers.update({"webhook-id": wid, "webhook-timestamp": ts,
                            "webhook-signature": f"v1,{sig}",
                            "X-Hub-Signature-256": f"sha256={gh}"})
        return HttpRequest("POST", cfg.get("url", ""), headers, raw_body=raw)
    raise ValueError(f"unknown connector type {t!r}")


def _try_json(text: str) -> Optional[dict]:
    try:
        v = json.loads(text or "")
        return v if isinstance(v, dict) else None
    except (ValueError, TypeError):
        return None


def interpret_response(connector: Connector, resp: HttpResp) -> DispatchResult:
    """PURE per-type success/error decode."""
    t, cfg = connector.type, (connector.config or {})
    sc, text = resp.status_code, resp.text or ""
    if t == "jira":
        if sc == 201:
            j = _try_json(text) or {}
            key = j.get("key")
            ref = key
            site = cfg.get("site", "").rstrip("/")
            detail = f"{site}/browse/{key}" if (site and key) else (key or "created")
            return DispatchResult(True, sc, external_ref=ref, detail=detail)
        j = _try_json(text) or {}
        msgs = j.get("errorMessages") or list((j.get("errors") or {}).values())
        return DispatchResult(False, sc, error="; ".join(str(m) for m in msgs) or f"HTTP {sc}")
    if t == "slack":
        if cfg.get("mode", "webhook") == "chat":
            j = _try_json(text) or {}
            if sc == 200 and j.get("ok") is True:
                return DispatchResult(True, sc, external_ref=f"{j.get('channel')}:{j.get('ts')}")
            return DispatchResult(False, sc, error=str(j.get("error") or f"HTTP {sc}"))
        # webhook: real HTTP status + literal 'ok' body
        if sc == 200 and text.strip() == "ok":
            return DispatchResult(True, sc, detail="ok")
        return DispatchResult(False, sc, error=(text.strip() or f"HTTP {sc}"))
    if t == "pagerduty":
        j = _try_json(text) or {}
        if sc == 202 and j.get("status") == "success":
            return DispatchResult(True, sc, external_ref=j.get("dedup_key"))
        errs = j.get("errors") or []
        return DispatchResult(False, sc, error="; ".join(str(e) for e in errs) or
                              str(j.get("message") or f"HTTP {sc}"))
    if t == "splunk":
        j = _try_json(text) or {}
        if sc == 200 and j.get("code") == 0:
            return DispatchResult(True, sc, detail="Success")
        return DispatchResult(False, sc, error=str(j.get("text") or f"HTTP {sc}") +
                              (f" (code {j.get('code')})" if j.get("code") is not None else ""))
    if t == "webhook":
        if 200 <= sc < 300:
            return DispatchResult(True, sc, detail="delivered")
        return DispatchResult(False, sc, error=(text.strip()[:200] or f"HTTP {sc}"))
    return DispatchResult(False, sc, error=f"unknown connector type {connector.type!r}")


# ═══════════════════════════════════════════════════════════════════════════════
#  Injected outbound seam + secret helpers
# ═══════════════════════════════════════════════════════════════════════════════
def store_secret(connector_id: str, plaintext: str, *, secret_writer: SecretWriter) -> str:
    """Write path mirroring init_onboarding's ExternalId flow: hand the one-time
    plaintext to the injected secret_writer, validate the returned ref against
    ``_RESOLVABLE_SCHEMES`` (else raise), return ONLY the ref. Plaintext is never
    persisted/logged/returned."""
    if not plaintext:
        raise ValueError("empty secret")
    # A connector credential is always a long token/URL. Rejecting sub-8-char
    # values keeps a pathologically short secret from ever being persisted (and so
    # from slipping past _scrub, which would otherwise have to over-redact common
    # short substrings out of every error string).
    if len(plaintext) < 8:
        raise ValueError("secret too short — connector credentials are long tokens (min 8 chars)")
    ref = secret_writer(connector_id, plaintext)
    if not ref or not str(ref).startswith(_RESOLVABLE_SCHEMES):
        raise ValueError(
            f"secret_writer must return a resolvable {_RESOLVABLE_SCHEMES} reference")
    return ref


def _scrub(text: Optional[str], *secrets: Optional[str]) -> Optional[str]:
    """Remove ANY resolved secret substring from a string before it is persisted /
    surfaced. Load-bearing: an operator tool can echo the token in a 4xx body. No
    length gate — a redacted (even over-redacted) message always beats a leaked
    credential; store_secret already guarantees secrets are long."""
    if text is None:
        return None
    out = str(text)
    for s in secrets:
        if s:
            out = out.replace(s, "***")
    return out


def _is_blocked_host(host: str) -> bool:
    host = (host or "").strip("[]").lower()
    if host in ("169.254.169.254", "metadata.google.internal"):
        return True
    if host.startswith("169.254."):        # link-local / IMDS range
        return True
    return False


def default_http_post(url: str, *, headers: Dict[str, str], json_body: dict = None,
                      data: bytes = None, timeout: float = 8.0, method: str = "POST") -> HttpResp:
    """Production impl over urllib (no new dep). Enforces the webhook/any SSRF
    guard (https-only, blocks the IMDS address, no cross-host 3xx follow). ``method``
    defaults to POST (every real send); the harmless Jira connectivity test needs a
    GET (/myself), so the seam carries the verb. Imported lazily; never touched by
    offline tests."""
    import urllib.request
    import urllib.error
    from urllib.parse import urlparse

    p = urlparse(url)
    if p.scheme != "https":
        raise ValueError("connector endpoints must be https")
    if _is_blocked_host(p.hostname or ""):
        raise ValueError("blocked endpoint host (link-local / instance metadata)")

    body = data if data is not None else (
        json.dumps(json_body).encode("utf-8") if json_body is not None else None)
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    class _NoCrossHost(urllib.request.HTTPRedirectHandler):
        # never follow a 3xx to another host — that would leak the signed body+sig
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            np = urlparse(newurl)
            if np.scheme != "https" or _is_blocked_host(np.hostname or ""):
                return None
            if (np.hostname or "").lower() != (urlparse(req.full_url).hostname or "").lower():
                return None
            return super().redirect_request(req, fp, code, msg, hdrs, newurl)

    opener = urllib.request.build_opener(_NoCrossHost())
    try:
        with opener.open(req, timeout=timeout) as r:
            return HttpResp(r.status, r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:        # 4xx/5xx carry a useful body
        try:
            txt = e.read().decode("utf-8", "replace")
        except Exception:
            txt = ""
        return HttpResp(e.code, txt)


def _resolve_secret(connector: Connector, secret_reader: SecretReader) -> Optional[str]:
    if not connector.secret_ref:
        return None
    return secret_reader(connector.secret_ref)


def dispatch(connector: Connector, f: EnrichedFinding, *, http_post: HttpPost,
             secret_reader: SecretReader, now_epoch: int, event_id: str = "",
             event_action: str = "trigger", template: str = None, fingerprint: str = "",
             hub_base: str = "") -> DispatchResult:
    """Impure boundary, fully injected. SAFE-BY-DEFAULT gate: a no-op unless the
    connector is enabled. render → resolve secret transiently → request_for →
    http_post EXACTLY once → interpret_response. The secret lives only in the local
    frame; only http_status/external_ref/scrubbed-error are returned."""
    if not connector.enabled:
        return DispatchResult(False, 0, error="connector disabled", detail="skipped")
    secret = None
    try:
        payload = render(connector, f, template=template, event_id=event_id,
                         now_epoch=now_epoch, event_action=event_action,
                         fingerprint=fingerprint, hub_base=hub_base)
        secret = _resolve_secret(connector, secret_reader)
        req = request_for(connector, payload, secret, event_id=event_id, now_epoch=now_epoch)
        resp = http_post(req.url, headers=req.headers, json_body=req.json_body,
                         data=req.raw_body, timeout=req.timeout)
        res = interpret_response(connector, resp)
        # Jira priority may be locked by the project scheme → retry once without it.
        if (connector.type == "jira" and not res.ok and _looks_like_priority_error(res.error)
                and isinstance(payload, dict)):
            payload["fields"].pop("priority", None)
            req = request_for(connector, payload, secret, event_id=event_id, now_epoch=now_epoch)
            resp = http_post(req.url, headers=req.headers, json_body=req.json_body,
                             data=req.raw_body, timeout=req.timeout)
            res = interpret_response(connector, resp)
        return replace(res, error=_scrub(res.error, secret), detail=_scrub(res.detail, secret) or "")
    except Exception as e:                              # noqa: BLE001
        return DispatchResult(False, 0, error=_scrub(f"{type(e).__name__}: {e}", secret),
                              detail="dispatch error")


def _looks_like_priority_error(err: Optional[str]) -> bool:
    e = (err or "").lower()
    return "priority" in e and ("cannot be set" in e or "not on the appropriate screen" in e
                                or "unknown" in e)


def test_ping(connector: Connector, *, http_post: HttpPost, secret_reader: SecretReader,
              now_epoch: int) -> DispatchResult:
    """The one harmless 'test'. Exactly one logical round-trip through http_post;
    contacts only the operator tool, zero scanned AWS accounts. Requires the
    connector to be enabled (safe-by-default)."""
    if not connector.enabled:
        return DispatchResult(False, 0, error="enable the connector before testing",
                              detail="disabled")
    t, cfg = connector.type, (connector.config or {})
    secret = None
    try:
        secret = _resolve_secret(connector, secret_reader)
        if t == "jira":       # GET /myself — creates nothing, proves creds + reachability
            site = cfg.get("site", "").rstrip("/")
            basic = base64.b64encode(f"{cfg.get('email','')}:{secret or ''}".encode()).decode("ascii")
            resp = http_post(f"{site}/rest/api/3/myself", method="GET",
                             headers={**_JSON_HDR, "Authorization": f"Basic {basic}"},
                             json_body=None, data=None, timeout=8.0)
            j = _try_json(resp.text) or {}
            if resp.status_code == 200 and j.get("accountId"):
                return DispatchResult(True, 200, external_ref=j.get("accountId"),
                                      detail=f"authenticated as {j.get('displayName','?')}")
            return DispatchResult(False, resp.status_code,
                                  error=_scrub(resp.text[:200] or f"HTTP {resp.status_code}", secret))
        # everything else: a synthetic INFO finding through the real render path
        f = _test_finding(connector)
        if t == "pagerduty":
            # trigger then immediately resolve so no incident lingers
            trg = dispatch(connector, f, http_post=http_post, secret_reader=secret_reader,
                           now_epoch=now_epoch, event_action="trigger")
            _payload = {"event_action": "resolve", "dedup_key": f"overwatch:{f.account}:{f.check_id}",
                        "routing_key": secret or ""}
            http_post(_pd_host(cfg), headers={"Content-Type": "application/json"},
                      json_body=_payload, data=None, timeout=8.0)
            return trg
        return dispatch(connector, f, http_post=http_post, secret_reader=secret_reader,
                        now_epoch=now_epoch)
    except Exception as e:                              # noqa: BLE001
        return DispatchResult(False, 0, error=_scrub(f"{type(e).__name__}: {e}", secret),
                              detail="test error")


def _test_finding(connector: Connector) -> EnrichedFinding:
    return EnrichedFinding(
        check_id="OVERWATCH-TEST", section="TEST", severity="INFO", status="INFO",
        compliance={}, remediation_cmd="", risk="OverWatch connector test — please ignore.",
        impact="", steps=[], affected=[], count=0, distinct=0,
        account="connectivity-test", on_attack_path=False)


# ═══════════════════════════════════════════════════════════════════════════════
#  Rules engine (PURE)
# ═══════════════════════════════════════════════════════════════════════════════
def finding_identity(f: EnrichedFinding) -> str:
    """PURE. identity = 'account|check_id' — the finding_catalog is ALREADY deduped
    per (check, account), so this is the natural, stable per-finding-per-account key."""
    return f"{f.account}|{f.check_id}"


def dedup_key(connector_id: str, identity: str) -> str:
    """PURE. Stable across scans, PER destination — keyed on (connector_id, identity)
    ONLY, NOT the rule. dedup is about "this finding to this destination"; if it
    embedded rule_id, a change of which overlapping rule wins would re-key the same
    finding and spuriously re-send + false-resolve it. rule_id is recorded on the
    ledger row for audit, never in the idempotency key."""
    return hashlib.sha1(f"{connector_id}|{identity}".encode("utf-8")).hexdigest()


def fingerprint(f: EnrichedFinding) -> str:
    """PURE. sha1 over MATERIAL mutable attrs only — severity|status|on_attack_path
    (NOT count/distinct which churn). A change = material escalation."""
    raw = f"{f.severity}|{f.status}|{int(bool(f.on_attack_path))}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _event_id(connector_id: str, identity: str) -> str:
    return "ow_evt_" + hashlib.sha1(f"{connector_id}|{identity}".encode()).hexdigest()[:16]


def rule_matches(rule: ConnectorRule, f: EnrichedFinding) -> bool:
    """PURE. AND across condition groups, OR within a list. An unspecified group is
    a wildcard. not_check_globs is a VETO. on_attack_path is tri-state (None=any)."""
    if f.status not in (rule.statuses or ["FAIL"]):
        return False
    # severities is an EXPLICIT allowlist and is authoritative when set — it must
    # override the min_severity floor (which defaults to 'HIGH'), else a rule
    # authored for LOW/MEDIUM alerts alone silently matches nothing.
    if rule.severities:
        if f.severity not in rule.severities:
            return False
    elif rule.min_severity and not _sev_ge(f.severity, rule.min_severity):
        return False
    if rule.sections and f.section not in rule.sections:
        return False
    if rule.check_globs and not any(_glob(g, f.check_id) for g in rule.check_globs):
        return False
    if rule.not_check_globs and any(_glob(g, f.check_id) for g in rule.not_check_globs):
        return False
    if rule.account_globs and not any(_glob(g, f.account) for g in rule.account_globs):
        return False
    if rule.on_attack_path is not None and bool(f.on_attack_path) != rule.on_attack_path:
        return False
    if rule.frameworks and not any(fw in (f.compliance or {}) for fw in rule.frameworks):
        return False
    if rule.controls:
        vals = [str(v) for v in (f.compliance or {}).values()]
        if not any(_glob(c, v) for c in rule.controls for v in vals):
            return False
    if rule.min_count and f.count < rule.min_count:
        return False
    if rule.min_distinct and f.distinct < rule.min_distinct:
        return False
    return True


def match_finding(rules: Sequence[ConnectorRule], f: EnrichedFinding,
                  connectors: Dict[str, Connector]) -> List[ConnectorAction]:
    """THE pure core. Evaluate enabled rules by (priority, rule_id); each match fans
    out to each connector_id that EXISTS and is enabled. Collapses per
    (connector_id, dedup_key) so two rules to the same destination for the same
    finding send ONCE (highest-priority body wins). stop_on_match halts lower rules."""
    ordered = sorted((r for r in rules if r.enabled), key=lambda r: (r.priority, r.id))
    # Collapse per (connector_id, identity): two rules routing the SAME finding to
    # the SAME destination send ONCE (the dedup_key namespaces rule_id for the
    # ledger, so we collapse on identity — the finding — not on the rule-scoped key).
    collapsed: Dict[Tuple[str, str], ConnectorAction] = {}
    fp = fingerprint(f)
    sev = (f.severity or "").upper()
    for rule in ordered:
        if not rule_matches(rule, f):
            continue
        targets = rule.connector_ids or [rule.connector_id]
        for cid in targets:
            c = connectors.get(cid)
            if not c or not c.enabled:
                continue                    # hard gate — absent/disabled ⇒ no action
            identity = finding_identity(f)
            dk = dedup_key(cid, identity)
            key = (cid, identity)
            if key in collapsed:
                continue                    # highest-priority rule already claimed it
            collapsed[key] = ConnectorAction(
                connector_id=cid, rule_id=rule.id, account=f.account, check_id=f.check_id,
                identity=identity, dedup_key=dk, fingerprint=fp,
                severity=rule.severity_override or sev, kind="new",
                event_id=_event_id(cid, identity), finding=f,
                template=rule.message_template)
        if rule.stop_on_match:
            break
    return list(collapsed.values())


# ═══════════════════════════════════════════════════════════════════════════════
#  Dedup / throttle state machine (PURE, injected clock)
# ═══════════════════════════════════════════════════════════════════════════════
def plan(actions: Sequence[ConnectorAction], ledger: Dict[str, LedgerRow], *,
         now_epoch: int, rules_by_id: Dict[int, ConnectorRule] = None
         ) -> Tuple[List[ConnectorAction], List[LedgerUpsert]]:
    """PURE. Per action keyed by dedup_key against the prior ledger snapshot:
      (1) no open row               → NEW send
      (2) prior resolved            → REOPENED send (state=open)
      (3) open + fingerprint worse  → ESCALATED send (if renotify_on_escalation)
      (4) open + renotify + window  → REMINDER send
      (5) else                      → SUPPRESSED (no send, window untouched)
    Returns (send_actions, ledger_upserts). Re-running an unchanged scan → 0 sends."""
    rules_by_id = rules_by_id or {}
    sends: List[ConnectorAction] = []
    upserts: List[LedgerUpsert] = []
    for a in actions:
        rule = rules_by_id.get(a.rule_id)
        renotify = bool(rule and rule.dedup_mode == "renotify")
        esc = bool(rule.renotify_on_escalation) if rule else True
        throttle = int(rule.throttle_seconds) if rule else 0
        row = ledger.get(a.dedup_key)
        if row is None or row.id is None:
            kind = "new"
        elif row.state == "resolved":
            kind = "reopened"
        elif row.status in ("failed", "pending"):
            kind = "retry"                  # a prior delivery never landed — re-send
        elif esc and row.fingerprint and row.fingerprint != a.fingerprint:
            kind = "escalated"
        elif renotify and (int(now_epoch) - int(row.last_notified_epoch or 0)) >= throttle:
            kind = "reminder"
        else:
            continue                        # SUPPRESSED (delivered + unchanged)
        first = (row.first_notified_epoch if (row and row.first_notified_epoch) else now_epoch)
        cnt = (int(row.notify_count) + 1) if row else 1
        sends.append(replace(a, kind=kind))
        upserts.append(LedgerUpsert(action=replace(a, kind=kind),
                                    is_new=(row is None or row.id is None),
                                    state="open", kind=kind, fingerprint=a.fingerprint,
                                    notify_epoch=int(now_epoch), notify_count=cnt))
        # keep the in-memory snapshot coherent if the same key appears twice
        ledger[a.dedup_key] = LedgerRow(
            connector_id=a.connector_id, dedup_key=a.dedup_key, account=a.account,
            check_id=a.check_id, rule_id=a.rule_id, state="open", kind=kind,
            fingerprint=a.fingerprint, first_notified_epoch=first,
            last_notified_epoch=int(now_epoch), notify_count=cnt, id=(row.id if row else -1))
    return sends, upserts


def resolve_stale(open_rows: Sequence[LedgerRow], present_dedup_keys: set,
                  scan_coverage: set, rules_by_id: Dict[int, ConnectorRule], *,
                  now_epoch: int) -> Tuple[List[ConnectorAction], List[str]]:
    """PURE coverage-gated auto-resolve. For each OPEN ledger row whose
    (account, check_id) was COVERED this scan but whose finding is NOT present →
    mark resolved (returns its dedup_key to free); if the rule has notify_on_resolve,
    emit a RESOLVED action. Coverage-gating stops a partial scan from mass-closing."""
    actions: List[ConnectorAction] = []
    freed: List[str] = []
    for row in open_rows:
        if row.state != "open":
            continue
        if (row.account, row.check_id) not in scan_coverage:
            continue                        # not inspected → leave it open
        if row.dedup_key in present_dedup_keys:
            continue                        # still failing → leave it open
        freed.append(row.dedup_key)
        rule = rules_by_id.get(row.rule_id)
        if rule and rule.notify_on_resolve:
            actions.append(ConnectorAction(
                connector_id=row.connector_id, rule_id=row.rule_id, account=row.account,
                check_id=row.check_id, identity=f"{row.account}|{row.check_id}",
                dedup_key=row.dedup_key, fingerprint=row.fingerprint or "",
                severity="INFO", kind="resolved", event_id=_event_id(
                    row.connector_id, f"{row.account}|{row.check_id}"),
                finding=None))
    return actions, freed


# NOTE: a per-connector rate-cap that folds an overflow of NEW findings into ONE
# digest message is intentionally DEFERRED. A partial/lossy digest is worse than
# none (it silently drops findings), and cross-scan flooding is already prevented
# by notify_once idempotency — only a first scan surfacing hundreds of NEW findings
# would fan out, which is honest. A future digest must carry EVERY folded finding
# into a real per-type summary card, not a single mislabeled one.


# ═══════════════════════════════════════════════════════════════════════════════
#  Persistence — ConnectorStore over a cnapp_backend.Backend
# ═══════════════════════════════════════════════════════════════════════════════
CONNECTOR_COLS = ["connector_id", "type", "name", "enabled", "config_json", "secret_ref",
                  "created_by", "last_test_at", "last_test_status", "last_test_detail",
                  "created_at", "updated_at"]

RULE_COLS = ["connector_id", "name", "enabled", "priority", "min_severity", "check_glob",
             "section", "account_glob", "on_attack_path", "status_filter",
             "dedup_window_sec", "options_json", "created_by", "created_at", "updated_at"]

NOTIFY_COLS = ["connector_id", "dedup_key", "rule_id", "account", "check_id", "finding_key",
               "state", "kind", "fingerprint", "first_notified_epoch", "last_notified_epoch",
               "notify_count", "status", "attempts", "http_status", "error", "external_ref",
               "created_at", "sent_at"]

DIGEST_COLS = ["connector_id", "digest_key", "account", "scan_id", "window_id", "new_count",
               "resolved_count", "reopened_count", "posture_delta", "material", "status",
               "attempts", "http_status", "error", "external_ref", "created_at", "sent_at"]

# rich list-valued predicates live in options_json (queryable ones are first-class columns)
_RULE_OPTION_KEYS = ["severities", "sections", "check_globs", "not_check_globs",
                     "account_globs", "frameworks", "controls", "min_count", "min_distinct",
                     "dedup_mode", "throttle_seconds", "renotify_on_escalation",
                     "notify_on_resolve", "stop_on_match", "connector_ids", "tags",
                     "message_template", "severity_override"]


class ConnectorStore:
    """Dual-dialect persistence for connectors / rules / the notification ledger,
    over a `cnapp_backend` Backend — structured exactly like AccountRegistry."""

    def __init__(self, backend):
        self._be = backend
        self._c = backend.raw

    @classmethod
    def open(cls, url: str = ":memory:") -> "ConnectorStore":
        import cnapp_backend
        return cls(cnapp_backend.backend_for(url, check_same_thread=False))

    def close(self) -> None:
        self._be.close()

    # ── connectors ────────────────────────────────────────────────────────────
    def upsert_connector(self, connector_id: str, *, now_epoch: int, type: str = None,
                         name: str = None, config: dict = None, secret_ref: str = None,
                         enabled: bool = None, created_by: str = None) -> None:
        """Insert or partial-update. On conflict ONLY supplied fields update (plus
        updated_at); secret_ref is rewritten ONLY when explicitly supplied (rotate).
        created_at/created_by/last_test_* are preserved by omission."""
        provided: Dict[str, object] = {}
        if type is not None:
            if type not in _CONNECTOR_TYPES:
                raise ValueError(f"invalid connector type {type!r}")
            provided["type"] = type
        if name is not None:
            provided["name"] = name
        if config is not None:
            provided["config_json"] = json.dumps(config)
        if secret_ref is not None:
            provided["secret_ref"] = secret_ref
        if enabled is not None:
            provided["enabled"] = 1 if enabled else 0
        if created_by is not None:
            provided["created_by"] = created_by
        insert = {
            "connector_id": connector_id,
            "type": provided.get("type", "webhook"),
            "name": provided.get("name", connector_id),
            "enabled": provided.get("enabled", 0),
            "config_json": provided.get("config_json", "{}"),
            "secret_ref": provided.get("secret_ref"),
            "created_by": provided.get("created_by"),
            "last_test_at": None, "last_test_status": None, "last_test_detail": None,
            "created_at": int(now_epoch), "updated_at": int(now_epoch),
        }
        update_cols = list(provided.keys()) + ["updated_at"]
        self._be.upsert("connectors", CONNECTOR_COLS, ["connector_id"], update_cols,
                        [insert[c] for c in CONNECTOR_COLS])

    def set_enabled(self, connector_id: str, enabled: bool, now_epoch: int) -> None:
        self._be.execute("UPDATE connectors SET enabled=?, updated_at=? WHERE connector_id=?",
                         (1 if enabled else 0, int(now_epoch), connector_id))

    def rotate_secret(self, connector_id: str, secret_ref: str, now_epoch: int) -> None:
        self._be.execute("UPDATE connectors SET secret_ref=?, updated_at=? WHERE connector_id=?",
                         (secret_ref, int(now_epoch), connector_id))

    def record_test(self, connector_id: str, status: str, detail: str, now_epoch: int) -> None:
        self._be.execute(
            "UPDATE connectors SET last_test_at=?, last_test_status=?, last_test_detail=?, "
            "updated_at=? WHERE connector_id=?",
            (int(now_epoch), status, (detail or "")[:500], int(now_epoch), connector_id))

    def get_connector(self, connector_id: str) -> Optional[Connector]:
        return _hydrate_connector(self._be.query_one(
            "SELECT * FROM connectors WHERE connector_id=?", (connector_id,)))

    def list_connectors(self) -> List[Connector]:
        return [_hydrate_connector(r) for r in
                self._be.query_all("SELECT * FROM connectors ORDER BY name, connector_id")]

    def delete_connector(self, connector_id: str) -> None:
        # Atomic all-or-nothing. notification_log has a NOT-NULL FK to connectors with
        # NO cascade, so its rows MUST be cleared first or (with PRAGMA foreign_keys=ON)
        # the connector delete raises FOREIGN KEY constraint failed and half-deletes.
        with self._be.transaction():
            self._be.execute("DELETE FROM digest_log WHERE connector_id=?", (connector_id,))
            self._be.execute("DELETE FROM notification_log WHERE connector_id=?", (connector_id,))
            self._be.execute("DELETE FROM connector_rules WHERE connector_id=?", (connector_id,))
            self._be.execute("DELETE FROM connectors WHERE connector_id=?", (connector_id,))

    # ── rules ─────────────────────────────────────────────────────────────────
    def upsert_rule(self, connector_id: str, *, now_epoch: int, rule_id: int = None,
                    spec: dict = None) -> int:
        """Create (rule_id=None) or replace a rule. ``spec`` carries the full rule
        shape; queryable predicates go to columns, the rich list-valued ones to
        options_json. Returns the rule id."""
        spec = spec or {}
        options = {k: spec[k] for k in _RULE_OPTION_KEYS if k in spec}
        cols = {
            "connector_id": connector_id,
            "name": spec.get("name", ""),
            "enabled": 1 if spec.get("enabled", True) else 0,
            "priority": int(spec.get("priority", 100)),
            "min_severity": spec.get("min_severity", "HIGH"),
            "check_glob": spec.get("check_glob"),
            "section": spec.get("section"),
            "account_glob": spec.get("account_glob", "*"),
            "on_attack_path": (None if spec.get("on_attack_path") is None
                               else (1 if spec.get("on_attack_path") else 0)),
            "status_filter": ",".join(spec["statuses"]) if spec.get("statuses") else
                             spec.get("status_filter", "FAIL"),
            "dedup_window_sec": spec.get("dedup_window_sec"),
            "options_json": json.dumps(options),
            "created_by": spec.get("created_by", ""),
            "updated_at": int(now_epoch),
        }
        if rule_id is None:
            vals = [cols["connector_id"], cols["name"], cols["enabled"], cols["priority"],
                    cols["min_severity"], cols["check_glob"], cols["section"],
                    cols["account_glob"], cols["on_attack_path"], cols["status_filter"],
                    cols["dedup_window_sec"], cols["options_json"], cols["created_by"],
                    int(now_epoch), int(now_epoch)]
            ph = ",".join(["?"] * len(RULE_COLS))
            return self._be.insert_returning_id(
                f"INSERT INTO connector_rules({','.join(RULE_COLS)}) VALUES({ph})", vals)
        sets = ("name=?, enabled=?, priority=?, min_severity=?, check_glob=?, section=?, "
                "account_glob=?, on_attack_path=?, status_filter=?, dedup_window_sec=?, "
                "options_json=?, updated_at=?")
        self._be.execute(
            f"UPDATE connector_rules SET {sets} WHERE id=? AND connector_id=?",
            (cols["name"], cols["enabled"], cols["priority"], cols["min_severity"],
             cols["check_glob"], cols["section"], cols["account_glob"], cols["on_attack_path"],
             cols["status_filter"], cols["dedup_window_sec"], cols["options_json"],
             int(now_epoch), rule_id, connector_id))
        return rule_id

    def get_rule(self, rule_id: int) -> Optional[ConnectorRule]:
        return _hydrate_rule(self._be.query_one(
            "SELECT * FROM connector_rules WHERE id=?", (rule_id,)))

    def list_rules(self, connector_id: str = None, *, enabled_only: bool = False
                   ) -> List[ConnectorRule]:
        sql, params = "SELECT * FROM connector_rules", []
        clauses = []
        if connector_id:
            clauses.append("connector_id=?"); params.append(connector_id)
        if enabled_only:
            clauses.append("enabled=1")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY priority, id"
        return [_hydrate_rule(r) for r in self._be.query_all(sql, params)]

    def delete_rule(self, connector_id: str, rule_id: int) -> None:
        self._be.execute("DELETE FROM connector_rules WHERE id=? AND connector_id=?",
                         (rule_id, connector_id))

    # ── notification ledger ─────────────────────────────────────────────────────
    def claim_notification(self, up: LedgerUpsert, *, now_epoch: int,
                           finding_key_str: str = None) -> Optional[int]:
        """Claim-then-send. INSERT a fresh ledger row; the UNIQUE(connector_id,
        dedup_key) index makes a concurrent/duplicate claim fail → return None (skip).
        A returned id means we WON the claim and must dispatch exactly once."""
        a = up.action
        vals = [a.connector_id, a.dedup_key, a.rule_id, a.account, a.check_id,
                finding_key_str, up.state, up.kind, up.fingerprint, up.notify_epoch,
                up.notify_epoch, up.notify_count, "pending", 0, None, None, None,
                int(now_epoch), None]
        ph = ",".join(["?"] * len(NOTIFY_COLS))
        try:
            return self._be.insert_returning_id(
                f"INSERT INTO notification_log({','.join(NOTIFY_COLS)}) VALUES({ph})", vals)
        except Exception as e:                          # noqa: BLE001
            if _is_unique_violation(e):
                return None
            raise

    def bump_notification(self, up: LedgerUpsert) -> Optional[int]:
        """Update an EXISTING open row for a reopen/escalate/reminder — returns the
        row id, or None if it vanished (treat like a fresh claim upstream)."""
        a = up.action
        row = self._be.query_one(
            "SELECT id FROM notification_log WHERE connector_id=? AND dedup_key=?",
            (a.connector_id, a.dedup_key))
        if not row:
            return None
        rid = row["id"]
        self._be.execute(
            "UPDATE notification_log SET state=?, kind=?, fingerprint=?, "
            "last_notified_epoch=?, notify_count=?, status='pending' WHERE id=?",
            (up.state, up.kind, up.fingerprint, up.notify_epoch, up.notify_count, rid))
        return rid

    def mark_sent(self, notif_id: int, res: DispatchResult, now_epoch: int) -> None:
        self._be.execute(
            "UPDATE notification_log SET status='sent', http_status=?, external_ref=?, "
            "error=NULL, attempts=attempts+1, sent_at=? WHERE id=?",
            (res.http_status, res.external_ref, int(now_epoch), notif_id))

    def mark_failed(self, notif_id: int, res: DispatchResult, now_epoch: int) -> None:
        self._be.execute(
            "UPDATE notification_log SET status='failed', http_status=?, error=?, "
            "attempts=attempts+1 WHERE id=?",
            (res.http_status, (res.error or "")[:500], notif_id))

    def resolve_ledger(self, connector_id: str, dedup_key: str, now_epoch: int) -> None:
        self._be.execute(
            "UPDATE notification_log SET state='resolved' WHERE connector_id=? AND dedup_key=?",
            (connector_id, dedup_key))

    def open_rows(self, connector_id: str = None) -> List[LedgerRow]:
        sql = "SELECT * FROM notification_log WHERE state='open'"
        params: List = []
        if connector_id:
            sql += " AND connector_id=?"; params.append(connector_id)
        return [_hydrate_ledger(r) for r in self._be.query_all(sql, params)]

    def ledger_snapshot(self, connector_ids: Sequence[str]) -> Dict[str, LedgerRow]:
        """The prior ledger (open AND resolved) for the given connectors, keyed by
        dedup_key — plan()'s input."""
        out: Dict[str, LedgerRow] = {}
        for cid in set(connector_ids):
            for r in self._be.query_all(
                    "SELECT * FROM notification_log WHERE connector_id=?", (cid,)):
                out[r["dedup_key"]] = _hydrate_ledger(r)
        return out

    def list_deliveries(self, connector_id: str = None, *, account: str = None,
                        status: str = None) -> List[dict]:
        sql, params, clauses = "SELECT * FROM notification_log", [], []
        if connector_id:
            clauses.append("connector_id=?"); params.append(connector_id)
        if account:
            clauses.append("account=?"); params.append(account)
        if status:
            clauses.append("status=?"); params.append(status)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC, id DESC"
        return [dict(r) for r in self._be.query_all(sql, params)]

    # ── drift-digest ledger (separate from the per-finding notification_log) ────
    def claim_digest(self, connector_id: str, digest: dict, digest_key: str, *,
                     now_epoch: int) -> Optional[int]:
        """Claim-then-send for a per-window digest. INSERT a fresh digest_log row; the
        UNIQUE(connector_id, digest_key) index makes a duplicate window fail → None
        (idempotent skip). A returned id means we WON the claim and must dispatch once."""
        counts = digest.get("counts", {})
        vals = [connector_id, digest_key, digest.get("account", ""), digest.get("scan_id", ""),
                digest.get("window_id", ""), int(counts.get("new", 0)),
                int(counts.get("resolved", 0)), int(counts.get("reopened", 0)),
                digest.get("posture_delta"), 1 if digest.get("material_change") else 0,
                "pending", 0, None, None, None, int(now_epoch), None]
        ph = ",".join(["?"] * len(DIGEST_COLS))
        try:
            return self._be.insert_returning_id(
                f"INSERT INTO digest_log({','.join(DIGEST_COLS)}) VALUES({ph})", vals)
        except Exception as e:                          # noqa: BLE001
            if not _is_unique_violation(e):
                raise
            # window already claimed — RETRY it iff the prior attempt never landed
            # (failed/pending), so one transient error doesn't drop the digest forever
            # (at-least-once, mirroring plan()'s failed→retry). A 'sent' row → None (skip).
            row = self._be.query_one(
                "SELECT id, status FROM digest_log WHERE connector_id=? AND digest_key=?",
                (connector_id, digest_key))
            if row and row["status"] in ("failed", "pending"):
                return row["id"]
            return None

    def mark_digest_sent(self, digest_id: int, res: DispatchResult, now_epoch: int) -> None:
        self._be.execute(
            "UPDATE digest_log SET status='sent', http_status=?, external_ref=?, error=NULL, "
            "attempts=attempts+1, sent_at=? WHERE id=?",
            (res.http_status, res.external_ref, int(now_epoch), digest_id))

    def mark_digest_failed(self, digest_id: int, res: DispatchResult, now_epoch: int) -> None:
        self._be.execute(
            "UPDATE digest_log SET status='failed', http_status=?, error=?, "
            "attempts=attempts+1 WHERE id=?",
            (res.http_status, (res.error or "")[:500], digest_id))

    def list_digests(self, connector_id: str = None, *, account: str = None,
                     status: str = None) -> List[dict]:
        sql, params, clauses = "SELECT * FROM digest_log", [], []
        if connector_id:
            clauses.append("connector_id=?"); params.append(connector_id)
        if account:
            clauses.append("account=?"); params.append(account)
        if status:
            clauses.append("status=?"); params.append(status)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC, id DESC"
        return [dict(r) for r in self._be.query_all(sql, params)]

    @staticmethod
    def _mask_connector(c: Connector) -> dict:
        """The ONLY shape any GET/LIST route returns — secret_ref popped →
        secret_configured bool. There is no read path for the plaintext."""
        return {
            "connector_id": c.connector_id, "type": c.type, "name": c.name,
            "enabled": c.enabled, "config": c.config,
            "secret_configured": bool(c.secret_ref),
            "created_by": c.created_by, "last_test_at": c.last_test_at,
            "last_test_status": c.last_test_status, "last_test_detail": c.last_test_detail,
            "created_at": c.created_at, "updated_at": c.updated_at,
        }


# ── hydration helpers ─────────────────────────────────────────────────────────
def _hydrate_connector(row) -> Optional[Connector]:
    if row is None:
        return None
    d = dict(row)
    try:
        config = json.loads(d.get("config_json") or "{}")
    except (ValueError, TypeError):
        config = {}
    return Connector(
        connector_id=d["connector_id"], type=d["type"], name=d["name"],
        enabled=bool(d["enabled"]), config=config, secret_ref=d.get("secret_ref"),
        created_by=d.get("created_by"), last_test_at=d.get("last_test_at"),
        last_test_status=d.get("last_test_status"), last_test_detail=d.get("last_test_detail"),
        created_at=d.get("created_at", 0), updated_at=d.get("updated_at", 0))


def _hydrate_rule(row) -> Optional[ConnectorRule]:
    if row is None:
        return None
    d = dict(row)
    try:
        opts = json.loads(d.get("options_json") or "{}")
    except (ValueError, TypeError):
        opts = {}
    statuses = [s for s in (d.get("status_filter") or "FAIL").split(",") if s]
    oap = d.get("on_attack_path")
    connector_ids = opts.get("connector_ids") or [d["connector_id"]]
    if d["connector_id"] not in connector_ids:
        connector_ids = [d["connector_id"]] + [c for c in connector_ids if c != d["connector_id"]]
    return ConnectorRule(
        id=d["id"], connector_id=d["connector_id"], name=d.get("name") or "",
        enabled=bool(d["enabled"]), priority=int(d.get("priority", 100)),
        min_severity=d.get("min_severity", "HIGH"),
        severities=list(opts.get("severities", [])), sections=list(opts.get("sections", [])),
        check_globs=(list(opts["check_globs"]) if opts.get("check_globs")
                     else ([d["check_glob"]] if d.get("check_glob") else [])),
        not_check_globs=list(opts.get("not_check_globs", [])),
        account_globs=(list(opts["account_globs"]) if opts.get("account_globs")
                       else ([d["account_glob"]] if d.get("account_glob") and d["account_glob"] != "*" else [])),
        on_attack_path=(None if oap is None else bool(oap)),
        statuses=statuses or ["FAIL"], frameworks=list(opts.get("frameworks", [])),
        controls=list(opts.get("controls", [])), min_count=int(opts.get("min_count", 0)),
        min_distinct=int(opts.get("min_distinct", 0)),
        dedup_mode=opts.get("dedup_mode", "notify_once"),
        throttle_seconds=int(opts.get("throttle_seconds", d.get("dedup_window_sec") or 0)),
        renotify_on_escalation=bool(opts.get("renotify_on_escalation", True)),
        notify_on_resolve=bool(opts.get("notify_on_resolve", False)),
        stop_on_match=bool(opts.get("stop_on_match", False)),
        connector_ids=connector_ids, tags=list(opts.get("tags", [])),
        message_template=opts.get("message_template"),
        severity_override=opts.get("severity_override"),
        created_by=d.get("created_by") or "", created_at=d.get("created_at", 0),
        updated_at=d.get("updated_at", 0))


def _hydrate_ledger(row) -> LedgerRow:
    d = dict(row)
    return LedgerRow(
        id=d.get("id"), connector_id=d["connector_id"], dedup_key=d["dedup_key"],
        account=d["account"], check_id=d.get("check_id") or "", rule_id=d.get("rule_id") or 0,
        state=d.get("state", "open"), kind=d.get("kind") or "", fingerprint=d.get("fingerprint") or "",
        first_notified_epoch=d.get("first_notified_epoch"),
        last_notified_epoch=d.get("last_notified_epoch"),
        notify_count=int(d.get("notify_count", 0)), status=d.get("status", "pending"),
        finding_key=d.get("finding_key"), external_ref=d.get("external_ref"))


def _is_unique_violation(e: Exception) -> bool:
    name = type(e).__name__.lower()
    msg = str(e).lower()
    return ("unique" in name or "integrity" in name or "unique" in msg
            or "duplicate key" in msg)


# ═══════════════════════════════════════════════════════════════════════════════
#  Orchestrator — run_rules (impure, admin-only, all seams injected)
# ═══════════════════════════════════════════════════════════════════════════════
def run_rules(store: ConnectorStore, findings: Sequence[EnrichedFinding],
              scan_coverage: set, *, http_post: HttpPost, secret_reader: SecretReader,
              now_epoch: int, hub_base: str = "") -> RunResult:
    """Impure orchestrator (called by the worker after results.put, or a manual
    /notify). Load enabled rules + connectors; match across findings; plan against
    the ledger snapshot; then per send-action: claim/bump → dispatch →
    mark_sent/mark_failed; finally coverage-gated resolve_stale. Delivery counts out."""
    connectors = {c.connector_id: c for c in store.list_connectors()}
    rules = store.list_rules(enabled_only=True)
    rules_by_id = {r.id: r for r in rules}

    # 1. match every finding → collapsed actions
    actions: List[ConnectorAction] = []
    for f in findings:
        actions.extend(match_finding(rules, f, connectors))

    involved = {a.connector_id for a in actions} | {c for c in connectors}
    snapshot = store.ledger_snapshot(list(involved))
    present = {a.dedup_key for a in actions}

    send_actions, upserts = plan(actions, snapshot, now_epoch=now_epoch, rules_by_id=rules_by_id)
    ups_by_key = {u.action.dedup_key: u for u in upserts}

    sent = suppressed = failed = digested = resolved = 0
    results: List[DispatchResult] = []
    for a in send_actions:
        c = connectors.get(a.connector_id)
        if not c or not a.finding:
            continue
        up = ups_by_key.get(a.dedup_key)
        if up is None:
            continue
        fkey = finding_key(a.check_id, a.finding.affected[0] if a.finding.affected else "")
        if up.is_new:
            nid = store.claim_notification(up, now_epoch=now_epoch, finding_key_str=fkey)
        else:
            nid = store.bump_notification(up)
            if nid is None:
                nid = store.claim_notification(up, now_epoch=now_epoch, finding_key_str=fkey)
        if nid is None:
            suppressed += 1                 # lost the claim race — already delivered
            continue
        res = dispatch(c, a.finding, http_post=http_post, secret_reader=secret_reader,
                       now_epoch=now_epoch, event_id=a.event_id, template=a.template,
                       fingerprint=a.fingerprint, hub_base=hub_base)
        results.append(res)
        if res.ok:
            store.mark_sent(nid, res, now_epoch); sent += 1
        else:
            store.mark_failed(nid, res, now_epoch); failed += 1

    # 2. coverage-gated auto-resolve
    open_rows = store.open_rows()
    res_actions, freed = resolve_stale(open_rows, present, scan_coverage, rules_by_id,
                                       now_epoch=now_epoch)
    for dk in freed:
        row = next((r for r in open_rows if r.dedup_key == dk), None)
        if row:
            store.resolve_ledger(row.connector_id, dk, now_epoch)
    for a in res_actions:
        c = connectors.get(a.connector_id)
        if not c or not c.enabled:
            continue
        rf = _resolve_finding(a)
        res = dispatch(c, rf, http_post=http_post, secret_reader=secret_reader,
                       now_epoch=now_epoch, event_id=a.event_id, event_action="resolve",
                       hub_base=hub_base)
        results.append(res)
        if res.ok:
            resolved += 1

    return RunResult(sent=sent, suppressed=suppressed, resolved=resolved, failed=failed,
                     digested=digested, actions=send_actions + res_actions, results=results)


def _resolve_finding(a: ConnectorAction) -> EnrichedFinding:
    """A minimal finding for a resolve dispatch (PagerDuty resolve / Jira close)."""
    return EnrichedFinding(
        check_id=a.check_id, section="", severity="INFO", status="INFO", compliance={},
        remediation_cmd="", risk="", impact="", steps=[], affected=[], count=0, distinct=0,
        account=a.account, on_attack_path=False)


# ═══════════════════════════════════════════════════════════════════════════════
#  Drift digests — ONE summary per (account, window) delivered through the connectors
#  (a sibling path to the per-finding run_rules; own ledger digest_log; own dedup key).
# ═══════════════════════════════════════════════════════════════════════════════
_DIGEST_SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "": 5}


def digest_window(frequency: str, scan_id: str, scan_epoch: int) -> str:
    """PURE. The idempotency window: per_scan (default) → the unique scan_id; daily →
    a UTC day bucket (folds several same-day scans into one digest)."""
    if frequency == "daily":
        return "d:" + datetime.fromtimestamp(int(scan_epoch), tz=timezone.utc).strftime("%Y%m%d")
    return scan_id


def digest_dedup_key(connector_id: str, account: str, window_id: str) -> str:
    """PURE. Stable per (connector, account, window). Disjoint namespace from the
    per-finding dedup_key (a sha1 hex), and lives in a separate table."""
    return f"digest:{connector_id}:{account}:{window_id}"


def compliance_delta(prev: Optional[dict], cur: Optional[dict]) -> Optional[list]:
    """PURE. Per-framework pass_rate change + newly-failed controls between two native
    compliance scorecards. None when either side is missing (first scan / restart)."""
    if not prev or not cur:
        return None
    out = []
    for fw, c in cur.items():
        p = prev.get(fw)
        if not p:
            continue
        d = round(float(c.get("pass_rate", 0)) - float(p.get("pass_rate", 0)), 1)
        newly = sorted(set(c.get("failed_controls", [])) - set(p.get("failed_controls", [])))
        if d != 0 or newly:
            out.append({"framework": fw, "pass_rate_delta": d, "newly_failed_controls": newly})
    return out or None


def _digest_findings(keys: Sequence[str], catalog_by_check: dict, onpath: set) -> List[dict]:
    """finding-keys (check_id|resource) → deduped-by-check entries with severity + on-path."""
    seen, out = set(), []
    for fk in keys:
        cid = fk.split("|", 1)[0]
        if cid in seen:
            continue
        seen.add(cid)
        e = catalog_by_check.get(cid, {})
        out.append({"check_id": cid, "severity": e.get("severity", ""),
                    "resource": fk.split("|", 1)[1] if "|" in fk else "",
                    "on_attack_path": cid in onpath})
    # severity first; on-attack-path wins ties so the CTEM signal is favored in the top cut
    return sorted(out, key=lambda x: (_DIGEST_SEV.get(x["severity"], 5), 0 if x["on_attack_path"] else 1))


def build_drift_digest(*, account: str, scan_id: str, scan_epoch: int, drift: dict,
                       trend: list, mttr: dict, catalog_by_check: dict, onpath: set,
                       compliance_delta: Optional[list] = None, window_id: str,
                       top: int = 10, hub_base: str = "") -> dict:
    """PURE. Assemble the drift digest from already-computed inputs (the classify_and_diff
    drift dict, trend, mttr, the finding catalog, the on-attack-path set). ``counts``
    carry EVERY folded change (lossless len()); only the displayed lists truncate.
    ``material_change`` is derived from the PERSISTED drift so it survives a restart."""
    cur = trend[-1] if trend else {}
    counts = {
        "new": len(drift.get("new", [])), "resolved": len(drift.get("resolved", [])),
        "reopened": len(drift.get("reopened", [])), "mutated": len(drift.get("mutated", [])),
        "still_open": drift.get("still_open", 0), "suppressed": drift.get("suppressed_count", 0),
    }
    posture_delta = drift.get("posture_delta")
    sev_delta = {}
    if len(trend) >= 2:
        prev = trend[-2]
        for k in ("crit", "high", "med", "low"):
            sev_delta[k] = int(cur.get(k, 0)) - int(prev.get(k, 0))
    material = (any(counts[k] for k in ("new", "resolved", "reopened", "mutated"))
                or (posture_delta not in (None, 0, 0.0)) or bool(compliance_delta))
    newly = _digest_findings(drift.get("new", []), catalog_by_check, onpath)
    resolved_wins = _digest_findings(drift.get("resolved", []), catalog_by_check, onpath)
    reopened = _digest_findings(drift.get("reopened", []), catalog_by_check, onpath)
    mean_s = mttr.get("mean_seconds")
    parts = [f"+{counts['new']} new", f"-{counts['resolved']} resolved"]
    if counts["reopened"]:
        parts.append(f"{counts['reopened']} reopened")
    if posture_delta:
        parts.append(f"posture {'▼' if posture_delta < 0 else '▲'}{abs(posture_delta)}")
    return {
        "account": account, "scan_id": scan_id, "ts_epoch": int(scan_epoch),
        "ts_iso": _iso(scan_epoch), "window_id": window_id,
        "posture_score": cur.get("posture_score"), "posture_grade": cur.get("grade"),
        "posture_delta": posture_delta, "counts": counts, "sev_delta": sev_delta,
        "material_change": material,
        # newly_on_path is derived from the SAME truncated list, so it is always a
        # strict subset of newly_exposed (the on-path tie-break keeps them in the cut).
        "newly_exposed": newly[:top], "newly_on_path": [x for x in newly[:top] if x["on_attack_path"]],
        "resolved_wins": resolved_wins[:top], "reopened": reopened[:top],
        "sla": {"open_over_sla": mttr.get("open_over_sla"), "sla_days": mttr.get("sla_days")},
        "mttr_days_mean": round(mean_s / 86400, 1) if mean_s else None,
        "compliance_delta": compliance_delta,
        "headline": f"Drift · acct {account} · " + " · ".join(parts),
        "link": f"{hub_base.rstrip('/')}/accounts/{account}" if hub_base else "",
    }


# ── per-type digest renderers (pure) ────────────────────────────────────────────
def _digest_posture_str(digest: dict) -> str:
    d = digest.get("posture_delta")
    return (f"{digest.get('posture_score', '?')} ({digest.get('posture_grade', '?')})"
            + (f" Δ{d}" if d else ""))


def render_slack_digest(connector: Connector, digest: dict, *, hub_base: str = "") -> dict:
    cfg = connector.config or {}
    d = digest.get("posture_delta") or 0
    emoji = "🔻" if d < 0 else "🔺" if d > 0 else "🔎"
    c = digest["counts"]
    fields = [_slack_field("New", str(c["new"])), _slack_field("Resolved", str(c["resolved"])),
              _slack_field("Reopened", str(c["reopened"])), _slack_field("Posture", _digest_posture_str(digest))]
    if digest["sla"].get("open_over_sla") is not None:
        fields.append(_slack_field("Over SLA", str(digest["sla"]["open_over_sla"])))
    blocks: List[dict] = [
        {"type": "header", "text": {"type": "plain_text", "emoji": True,
                                    "text": f"{emoji} Drift · acct {digest['account']}"[:150]}},
        {"type": "section", "fields": fields[:10]}]
    if digest["newly_on_path"]:
        txt = "\n".join(f"• {x['check_id']} ({x['severity']})" for x in digest["newly_on_path"][:5])
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Newly exposed on attack path:*\n{txt[:2900]}"}})
    if digest.get("link"):
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "style": "primary", "text": {"type": "plain_text", "text": "View in OverWatch"}, "url": digest["link"]}]})
    body: Dict = {"text": digest.get("headline", "drift digest")[:3000], "blocks": blocks}
    if (cfg.get("mode", "webhook") == "chat") and cfg.get("channel"):
        body["channel"] = cfg["channel"]
    return body


def render_jira_digest(connector: Connector, digest: dict) -> dict:
    cfg = connector.config or {}
    project = ({"id": cfg["project_id"]} if cfg.get("project_id") else {"key": cfg.get("project_key", "SEC")})
    issuetype = ({"id": cfg["issue_type_id"]} if cfg.get("issue_type_id") else {"name": cfg.get("issue_type", "Task")})
    c = digest["counts"]
    content = [_adf_text(digest.get("headline", "")),
               _adf_heading("Change since last scan"),
               _adf_text(f"New {c['new']} · Resolved {c['resolved']} · Reopened {c['reopened']} · "
                         f"Mutated {c['mutated']} · Still open {c['still_open']} · Posture {_digest_posture_str(digest)}")]
    if digest["newly_on_path"]:
        content.append(_adf_heading("Newly exposed on an attack path"))
        content.append({"type": "bulletList", "content": [
            {"type": "listItem", "content": [_adf_text(f"{x['check_id']} ({x['severity']})")]}
            for x in digest["newly_on_path"][:15]]})
    return {"fields": {"project": project, "issuetype": issuetype,
                       "summary": digest.get("headline", "OverWatch drift digest")[:255],
                       "description": {"type": "doc", "version": 1, "content": content},
                       "labels": ["overwatch", "drift-digest", f"owdigest-{digest['scan_id']}"[:255]]}}


def render_pagerduty_digest(connector: Connector, digest: dict, *, hub_base: str = "") -> dict:
    d = digest.get("posture_delta") or 0
    sev = "error" if d < -10 else "warning" if d < 0 else "info"
    body = {
        "event_action": "trigger",
        "dedup_key": f"overwatch:digest:{digest['account']}:{digest['window_id']}",
        "client": "OverWatch CNAPP",
        "payload": {"summary": digest.get("headline", "OverWatch drift digest")[:1024],
                    "source": f"aws:{digest['account']}", "severity": sev, "component": "drift-digest",
                    "custom_details": {"counts": digest["counts"], "posture_delta": d,
                                       "newly_on_path": digest["newly_on_path"], "sla": digest["sla"]}},
    }
    if digest.get("link"):
        body["client_url"] = digest["link"]
        body["links"] = [{"href": digest["link"], "text": "View in OverWatch"}]
    return body


def render_splunk_digest(connector: Connector, digest: dict) -> dict:
    cfg = connector.config or {}
    envelope = {"host": "overwatch", "source": "overwatch-cnapp",
                "sourcetype": cfg.get("digest_sourcetype", "overwatch:drift"), "event": digest,
                "fields": {"account_id": digest["account"], "material": str(digest["material_change"]).lower(),
                           "new": str(digest["counts"]["new"])}}
    if cfg.get("index"):
        envelope["index"] = cfg["index"]
    return envelope


def render_webhook_digest(connector: Connector, digest: dict, *, event_id: str,
                          now_epoch: int) -> bytes:
    envelope = {"specversion": "overwatch/v1", "id": event_id, "type": "overwatch.drift_digest",
                "timestamp": _iso(now_epoch), "ts_epoch": int(now_epoch), "source": "overwatch",
                "account": digest["account"], "data": digest}
    return json.dumps(envelope, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def render_digest(connector: Connector, digest: dict, *, event_id: str = "", now_epoch: int = 0,
                  hub_base: str = "") -> Union[dict, bytes]:
    t = connector.type
    if t == "slack":
        return render_slack_digest(connector, digest, hub_base=hub_base)
    if t == "jira":
        return render_jira_digest(connector, digest)
    if t == "pagerduty":
        return render_pagerduty_digest(connector, digest, hub_base=hub_base)
    if t == "splunk":
        return render_splunk_digest(connector, digest)
    if t == "webhook":
        return render_webhook_digest(connector, digest, event_id=event_id, now_epoch=now_epoch)
    raise ValueError(f"unknown connector type {t!r}")


def dispatch_digest(connector: Connector, digest: dict, *, http_post: HttpPost,
                    secret_reader: SecretReader, now_epoch: int, event_id: str = "",
                    hub_base: str = "") -> DispatchResult:
    """Impure boundary — reuses request_for / interpret_response / _resolve_secret /
    _scrub unchanged (they are per-type + payload-shape-agnostic), so the SSRF guard,
    byte-stable webhook signing, and secret-scrubbing all carry over."""
    if not connector.enabled:
        return DispatchResult(False, 0, error="connector disabled", detail="skipped")
    secret = None
    try:
        payload = render_digest(connector, digest, event_id=event_id, now_epoch=now_epoch, hub_base=hub_base)
        secret = _resolve_secret(connector, secret_reader)
        req = request_for(connector, payload, secret, event_id=event_id, now_epoch=now_epoch)
        resp = http_post(req.url, headers=req.headers, json_body=req.json_body,
                         data=req.raw_body, timeout=req.timeout)
        res = interpret_response(connector, resp)
        return replace(res, error=_scrub(res.error, secret), detail=_scrub(res.detail, secret) or "")
    except Exception as e:                              # noqa: BLE001
        return DispatchResult(False, 0, error=_scrub(f"{type(e).__name__}: {e}", secret),
                              detail="digest dispatch error")


def _digest_opt_in(c: Connector, account: str) -> bool:
    d = (c.config or {}).get("digest") or {}
    if not d.get("enabled"):
        return False
    globs = d.get("account_globs")
    return True if not globs else any(_glob(g, account) for g in globs)


def run_digest(store: ConnectorStore, digest: dict, *, http_post: HttpPost,
               secret_reader: SecretReader, now_epoch: int, hub_base: str = "") -> RunResult:
    """Impure orchestrator (sibling to run_rules). For each enabled connector that
    opts into digests (config.digest.enabled): apply the material/min_new gates, then
    claim-then-send exactly once per (connector, account, window)."""
    conns = [c for c in store.list_connectors() if c.enabled and _digest_opt_in(c, digest["account"])]
    digested = failed = 0
    results: List[DispatchResult] = []
    for c in conns:
        d = (c.config or {}).get("digest") or {}
        if d.get("only_on_material_change", True) and not digest["material_change"]:
            continue
        if digest["counts"]["new"] < int(d.get("min_new", 0)):
            continue
        dk = digest_dedup_key(c.connector_id, digest["account"], digest["window_id"])
        nid = store.claim_digest(c.connector_id, digest, dk, now_epoch=now_epoch)
        if nid is None:
            continue                                    # window already sent → idempotent skip
        eid = "ow_dig_" + hashlib.sha1(dk.encode()).hexdigest()[:16]
        res = dispatch_digest(c, digest, http_post=http_post, secret_reader=secret_reader,
                              now_epoch=now_epoch, event_id=eid, hub_base=hub_base)
        results.append(res)
        if res.ok:
            store.mark_digest_sent(nid, res, now_epoch); digested += 1
        else:
            store.mark_digest_failed(nid, res, now_epoch); failed += 1
    return RunResult(digested=digested, failed=failed, results=results)
