"""Phase 1 · slice 1.5 — a local, read-only MCP server over a finished OverWatch scan.

Decision D6 settled how this ships. The SERVER is inside the OverWatch boundary; the
CLIENT — Claude Code, Cursor, Claude Desktop — never is, and there is no version of this
product where we control it. Whatever model the operator's client is configured with
receives everything this server returns, and our zero-telemetry guarantee does not and
cannot cover that hop.

The roadmap proposed shipping with a warning inside the tool descriptions. Those are read
by the MODEL, not by the engineer editing a config file, which makes them a disclaimer
rather than a boundary. D6 was ruled the other way: the boundary is ENFORCED.

    1. FAIL-CLOSED START. Without OVERWATCH_MCP_ACK_CLIENT_EGRESS=1 the server refuses to
       run and explains why on stderr. This does not make anyone safer by itself — it
       makes the egress a decision somebody made rather than a default nobody noticed.

    2. IDENTIFIERS REDACTED BY DEFAULT. The analysis travels ("a public path reaches a
       crown datastore"); the identifiers do not ("which bucket, in which account").
       Serving real ARNs, account IDs and IPs needs a second deliberate flag. This
       follows the "hashed by default" line already drawn for D2.

    3. EVERY CALL AUDITED. We cannot audit what the client did with a response. We can
       audit exactly what left this server, and that is the honest half of the promise.

WHAT THIS CHANGES, AND WHAT IT DOES NOT
---------------------------------------
It does not create the ability to send scan data to a cloud model. A scan already writes
a complete JSON report to disk — every finding, ARN, account id and attack path — and any
client can be pointed at that file today. What an MCP server adds is CONVENIENCE, and our
name on the path. That is a smaller delta than it first appears, and it is not nothing:
defaults drive behaviour, and one config line is a different act from deliberately
pasting a security report into a chat window.

It is also invisible to the existing tripwire. Sections A-F of ``test_zero_telemetry.py``
all constrain OUR code — telemetry SDKs, network primitives, egress hosts, ingest
content. A local stdio server passes every one of them trivially while being the largest
data-egress decision in the product. Section G exists to pin what CAN be pinned: that
this module is stdio-only and imports nothing that could reach a network.

Implementation notes
--------------------
Stdlib only, and deliberately so. MCP over stdio is newline-delimited JSON-RPC 2.0, which
is a couple of hundred lines; taking the SDK would add a dependency whose transitive
imports could contain network code, and Section G's guarantee is only as good as what it
can see.

This server READS A FINISHED REPORT. It never runs a scan, never constructs a boto3
client, and never touches AWS. Beyond keeping it honestly read-only, that avoids a
protocol hazard: the scanner prints coloured progress to stdout, and the spec is explicit
that "The server MUST NOT write anything to its stdout that is not a valid MCP message."
Importing the scanner at all would put that one stray print away from a corrupted stream.
All diagnostics here go to stderr, which the spec permits.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

VERSION = "1.0.0"
SERVER_NAME = "overwatch"

#: Protocol revision this server implements. On a mismatch the spec says to answer with
#: a version we DO support rather than erroring, and let the client decide.
PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")

ACK_ENV = "OVERWATCH_MCP_ACK_CLIENT_EGRESS"
IDENTIFIERS_ENV = "OVERWATCH_MCP_SERVE_IDENTIFIERS"
REPORT_ENV = "OVERWATCH_MCP_REPORT"
AUDIT_ENV = "OVERWATCH_MCP_AUDIT"

DEFAULT_AUDIT = os.path.join("evidence", "mcp_audit.jsonl")

REFUSAL = f"""OverWatch MCP server: refusing to start.

An MCP client is OUTSIDE the OverWatch boundary. Whatever model your client is
configured with will receive the scan data this server returns -- findings, and
(if you enable them) account IDs, ARNs and resource names. OverWatch cannot see
or control that hop, and the zero-telemetry guarantee does not cover it.

This is a deliberate gate, not a licence check. Acknowledge it to proceed:

    {ACK_ENV}=1

Identifiers are REDACTED by default: you will get "a public S3 bucket reaches a
crown datastore", not which bucket in which account. To serve real ARNs, account
IDs and IP addresses, additionally set:

    {IDENTIFIERS_ENV}=1

Sovereign, air-gapped or regulated estates: run a local model instead of a hosted
one. See docs/MCP.md ("Running against a local model") -- that is the only
configuration in which this server's output stays inside your boundary.
"""

# ── the egress warning carried in every tool description ────────────────────
# Belt and braces on top of the start gate. A model that reads this may decline or
# caveat; the gate is what actually stops an unconsidered deployment.
_EGRESS_NOTE = ("NOTE: results leave the OverWatch boundary via this MCP client and "
                "reach whatever model it is configured with. ")


# ── redaction ───────────────────────────────────────────────────────────────
_ARN = re.compile(r"arn:aws[a-z\-]*:([a-z0-9\-]*):([a-z0-9\-]*):(\d{12})?:(\S+)")
_ACCOUNT = re.compile(r"(?<!\d)(\d{12})(?!\d)")
_IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")


class Redactor:
    """Stable pseudonyms for identifiers, scoped to one server process.

    Stable so an analyst can correlate ``s3-7f3a2b`` across several answers in one
    conversation. Process-scoped rather than global so the pseudonyms cannot be used to
    link one session's transcript to another's, which matters precisely because the
    transcripts end up somewhere we do not control.

    ``enabled=False`` passes text through untouched — the operator asked for real
    identifiers with a second explicit flag, and it is their estate to disclose."""

    def __init__(self, enabled: bool = True, salt: Optional[bytes] = None):
        self.enabled = enabled
        # os.urandom, not a fixed constant: a fixed salt would make the pseudonyms
        # global and reversible by anyone holding the same wordlist.
        self.salt = salt if salt is not None else os.urandom(16)
        self._seen: Dict[str, str] = {}

    def _pseudo(self, kind: str, value: str) -> str:
        key = f"{kind}:{value}"
        if key not in self._seen:
            h = hashlib.blake2s(self.salt + key.encode("utf-8"),
                                digest_size=3).hexdigest()
            self._seen[key] = f"{kind}-{h}"
        return self._seen[key]

    def text(self, s: str) -> str:
        if not self.enabled or not s:
            return s

        def _arn(m):
            service = m.group(1) or "aws"
            return f"arn:aws:{service}:::{self._pseudo(service or 'res', m.group(0))}"

        s = _ARN.sub(_arn, s)
        s = _ACCOUNT.sub(lambda m: self._pseudo("acct", m.group(1)), s)
        s = _IPV4.sub(lambda m: self._pseudo("ip", m.group(1)), s)
        return s

    def walk(self, obj: Any) -> Any:
        """Redact every string in a nested structure, keys included.

        Keys are redacted too because report payloads are keyed by ARN in places, and a
        redactor that cleaned values while leaving keys would be the kind of partial
        control that reads as protection and is not."""
        if not self.enabled:
            return obj
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {self.text(k) if isinstance(k, str) else k: self.walk(v)
                    for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.walk(v) for v in obj]
        return obj


# ── the gate ────────────────────────────────────────────────────────────────
def gate(env: Optional[Dict[str, str]] = None) -> Tuple[bool, bool]:
    """``(may_start, serve_identifiers)`` read from the environment.

    Split out as a pure function so the refusal is testable without spawning a process —
    the gate is the whole point of the slice, and a gate nobody tests is a comment."""
    e = os.environ if env is None else env
    return (e.get(ACK_ENV, "").strip() == "1",
            e.get(IDENTIFIERS_ENV, "").strip() == "1")


# ── tools ───────────────────────────────────────────────────────────────────
def _obj(props: Dict[str, Any], required: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"type": "object", "properties": props, "required": required or []}


TOOLS: List[Dict[str, Any]] = [
    {
        "name": "overwatch_scan_summary",
        "title": "Scan summary",
        "description": (_EGRESS_NOTE +
                        "Posture score and grade, finding counts by severity, and when "
                        "the scan ran. Start here before asking for findings."),
        "inputSchema": _obj({}),
    },
    {
        "name": "overwatch_coverage",
        "title": "What the scan could NOT see",
        "description": (_EGRESS_NOTE +
                        "Checks that were refused or skipped, and the exact IAM action "
                        "missing for each. READ THIS BEFORE CONCLUDING AN ACCOUNT IS "
                        "CLEAN: an absence of findings in an unevaluated area is not "
                        "evidence of absence, and this tool is how you tell the two "
                        "apart."),
        "inputSchema": _obj({}),
    },
    {
        "name": "overwatch_findings",
        "title": "Findings",
        "description": (_EGRESS_NOTE +
                        "Scan findings, newest scan only, filterable by severity, "
                        "status, section or check id. Returns at most `limit` items."),
        "inputSchema": _obj({
            "severity": {"type": "string",
                         "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                         "description": "Only findings at this severity."},
            "status": {"type": "string", "enum": ["FAIL", "WARN", "PASS", "INFO"],
                       "description": "Only findings with this status."},
            "section": {"type": "string", "description": "Section, e.g. IAM, S3, DATA."},
            "check_id": {"type": "string", "description": "Exact check id, e.g. IAM-01."},
            "limit": {"type": "integer", "description": "Max findings (default 50)."},
        }),
    },
    {
        "name": "overwatch_attack_paths",
        "title": "Attack paths",
        "description": (_EGRESS_NOTE +
                        "Correlated attack paths and choke points: where an external "
                        "entry reaches something that matters, and the single edges that "
                        "break the most paths at once."),
        "inputSchema": _obj({
            "limit": {"type": "integer", "description": "Max paths (default 20)."},
        }),
    },
    {
        "name": "overwatch_check_reference",
        "title": "Check reference",
        "description": (
            "Risk, impact and remediation steps for a check id. This is OverWatch "
            "reference material and contains NO customer data, so it is served in full "
            "whether or not identifiers are redacted."),
        "inputSchema": _obj({"check_id": {"type": "string",
                                          "description": "e.g. AIGRD-03"}},
                            ["check_id"]),
    },
]

PROMPTS: List[Dict[str, Any]] = [
    {"name": "triage_worst_first",
     "title": "Triage worst-first",
     "description": "Rank what to fix first, coverage gaps accounted for.",
     "arguments": []},
    {"name": "explain_a_check",
     "title": "Explain a check",
     "description": "Explain one check id and what to do about it.",
     "arguments": [{"name": "check_id", "description": "e.g. AIGRD-03",
                    "required": True}]},
    {"name": "audit_readiness",
     "title": "Audit readiness",
     "description": "Summarise posture against a compliance framework.",
     "arguments": [{"name": "framework", "description": "PCI-DSS | HIPAA | SOC2 | NIST",
                    "required": False}]},
]

_PROMPT_TEXT = {
    "triage_worst_first": (
        "Using overwatch_scan_summary and overwatch_findings, rank the findings by what "
        "an attacker would reach first, not by severity label alone. Call "
        "overwatch_coverage FIRST and state plainly which areas were not evaluated -- do "
        "not describe an account as clean in an area the scan could not see."),
    "explain_a_check": (
        "Call overwatch_check_reference for {check_id} and explain, in order: what the "
        "check detects, why it matters, and the exact commands to remediate. Then call "
        "overwatch_findings with check_id={check_id} to say whether this estate is "
        "actually affected."),
    "audit_readiness": (
        "Summarise this estate's posture for {framework}. Use overwatch_findings for "
        "failures and overwatch_coverage for what was not evaluated. An unevaluated "
        "control is NOT a passing control; list those separately and say so."),
}


# ── report access ───────────────────────────────────────────────────────────
class Report:
    """A finished scan report, loaded from disk. Read-only by construction."""

    def __init__(self, path: Optional[str]):
        self.path = path
        self.data: Dict[str, Any] = {}
        self.error: Optional[str] = None
        if not path:
            self.error = (f"No scan report configured. Point the server at one with "
                          f"--report <path> or {REPORT_ENV}=<path>.")
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except FileNotFoundError:
            self.error = f"Scan report not found: {path}. Run a scan first."
        except (OSError, ValueError) as exc:
            self.error = f"Scan report at {path} could not be read: {exc}"

    @property
    def results(self) -> List[dict]:
        return [r for r in (self.data.get("results") or []) if isinstance(r, dict)]


def _tool_summary(rep: Report, _args: dict) -> Any:
    d = rep.data
    return {
        "scanned_at": d.get("timestamp"),
        "posture_score": d.get("posture_score"),
        "posture_grade": d.get("posture_grade"),
        "summary": d.get("summary"),
        "accounts": d.get("accounts") or d.get("account"),
        "attack_path_count": len(d.get("attack_paths") or []),
        "coverage_complete": (d.get("coverage") or {}).get("complete"),
    }


def _tool_coverage(rep: Report, _args: dict) -> Any:
    cov = rep.data.get("coverage") or {}
    ledger = rep.data.get("permission_ledger") or {}
    return {
        "complete": cov.get("complete"),
        "not_evaluated": cov.get("not_evaluated") or {},
        "unscanned_regions": cov.get("unscanned_regions") or [],
        "missing_actions": ledger.get("missing_actions") or [],
        "blocked_checks": ledger.get("blocked") or {},
        "note": ("A check listed here did not run. Absence of findings for it is not "
                 "evidence that the estate is clean in that area."),
    }


def _tool_findings(rep: Report, args: dict) -> Any:
    limit = args.get("limit")
    limit = 50 if not isinstance(limit, int) or limit <= 0 else min(limit, 500)
    out = []
    for r in rep.results:
        if args.get("severity") and r.get("severity") != args["severity"]:
            continue
        if args.get("status") and r.get("status") != args["status"]:
            continue
        if args.get("section") and r.get("section") != args["section"]:
            continue
        if args.get("check_id") and r.get("check_id") != args["check_id"]:
            continue
        out.append(r)
    return {"count": len(out), "returned": min(len(out), limit),
            "findings": out[:limit]}


def _tool_paths(rep: Report, args: dict) -> Any:
    limit = args.get("limit")
    limit = 20 if not isinstance(limit, int) or limit <= 0 else min(limit, 200)
    paths = rep.data.get("attack_paths") or []
    return {"count": len(paths), "returned": min(len(paths), limit),
            "attack_paths": paths[:limit],
            "choke_points": rep.data.get("choke_points") or []}


def _tool_reference(rep: Report, args: dict) -> Any:
    """Reference material for one check. Contains no customer data.

    The catalog travels with the report, so this needs no import of the scanner and
    stays correct for the version that produced the report rather than the version of
    the code that happens to be checked out."""
    cid = (args.get("check_id") or "").strip().upper()
    if not cid:
        raise ValueError("check_id is required")
    catalog = rep.data.get("finding_catalog") or {}
    entry = catalog.get(cid) if isinstance(catalog, dict) else None
    if not entry:
        raise ValueError(f"No reference entry for {cid} in this report")
    return {"check_id": cid, "reference": entry}


HANDLERS = {
    "overwatch_scan_summary": (_tool_summary, True),
    "overwatch_coverage": (_tool_coverage, True),
    "overwatch_findings": (_tool_findings, True),
    "overwatch_attack_paths": (_tool_paths, True),
    # False: reference text is OverWatch's own, carries no customer identifiers, and
    # redacting it would mangle the example ARNs in remediation commands.
    "overwatch_check_reference": (_tool_reference, False),
}


# ── audit ───────────────────────────────────────────────────────────────────
class Audit:
    """One JSONL line per tool call.

    Records WHAT was served, not the content: a digest and the counts, never a second
    copy of the customer's findings. We cannot audit what the client did with a
    response; we can say exactly what left here, and that is the part we can honour."""

    def __init__(self, path: Optional[str], identifiers: bool):
        self.path = path
        self.identifiers = identifiers

    def record(self, tool: str, args: dict, payload: Any, error: str = "") -> None:
        if not self.path:
            return
        try:
            blob = json.dumps(payload, default=str, sort_keys=True)
        except Exception:
            blob = ""
        row = {
            "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tool": tool,
            "arguments": {k: v for k, v in (args or {}).items()},
            "identifiers_served": bool(self.identifiers),
            "bytes": len(blob),
            "sha256": hashlib.sha256(blob.encode("utf-8")).hexdigest() if blob else "",
            "error": error,
        }
        try:
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
        except OSError as exc:                      # auditing must never break serving
            _log(f"audit write failed: {exc}")


def _log(msg: str) -> None:
    """Diagnostics go to STDERR. stdout carries MCP messages and nothing else."""
    try:
        sys.stderr.write(f"[overwatch-mcp] {msg}\n")
        sys.stderr.flush()
    except Exception:
        pass


# ── JSON-RPC ────────────────────────────────────────────────────────────────
def _result(rid: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _error(rid: Any, code: int, message: str, data: Any = None) -> dict:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": rid, "error": err}


def _text_result(payload: Any, is_error: bool = False) -> dict:
    return {
        "content": [{"type": "text",
                     "text": json.dumps(payload, indent=2, default=str)}],
        "isError": is_error,
    }


class Server:
    def __init__(self, report: Report, redactor: Redactor, audit: Audit):
        self.report = report
        self.redactor = redactor
        self.audit = audit
        self.initialized = False

    # ── dispatch ────────────────────────────────────────────────────────────
    def handle(self, msg: dict) -> Optional[dict]:
        """One JSON-RPC message in, at most one out. Notifications return None."""
        rid = msg.get("id")
        method = msg.get("method") or ""
        params = msg.get("params") or {}
        is_notification = "id" not in msg

        if method == "initialize":
            return _result(rid, self._initialize(params))
        if method in ("notifications/initialized", "initialized"):
            self.initialized = True
            return None
        if method == "ping":
            return _result(rid, {})
        if method == "tools/list":
            return _result(rid, {"tools": TOOLS})
        if method == "prompts/list":
            return _result(rid, {"prompts": PROMPTS})
        if method == "prompts/get":
            return self._prompt_get(rid, params)
        if method == "tools/call":
            return self._tools_call(rid, params)
        if is_notification:
            return None                     # unknown notification: ignore, per spec
        return _error(rid, -32601, f"Method not found: {method}")

    def _initialize(self, params: dict) -> dict:
        asked = params.get("protocolVersion")
        # Spec: answer with the same version if we support it, otherwise with the
        # latest we do support and let the client decide whether to continue.
        version = asked if asked in SUPPORTED_PROTOCOLS else PROTOCOL_VERSION
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False},
                             "prompts": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "title": "OverWatch (read-only)",
                           "version": VERSION},
            "instructions": (
                "Read-only access to a FINISHED OverWatch scan report. This server "
                "cannot scan, change or reach AWS.\n\n"
                "Everything returned here leaves the OverWatch boundary and reaches "
                "the model behind this client; OverWatch's zero-telemetry guarantee "
                "does not cover that hop.\n\n"
                + ("Identifiers are REDACTED: ARNs, account IDs and IP addresses appear "
                   "as stable pseudonyms such as s3-7f3a2b. Pseudonyms are consistent "
                   "within this session only. Ask the operator to set "
                   f"{IDENTIFIERS_ENV}=1 if real identifiers are needed.\n\n"
                   if self.redactor.enabled else
                   "Identifiers are being served in FULL: real ARNs, account IDs and IP "
                   "addresses are present in these responses.\n\n")
                + "Call overwatch_coverage before concluding anything is clean: it "
                  "lists what the scan was not permitted to evaluate."),
        }

    def _prompt_get(self, rid: Any, params: dict) -> dict:
        name = params.get("name")
        if name not in _PROMPT_TEXT:
            return _error(rid, -32602, f"Unknown prompt: {name}")
        args = params.get("arguments") or {}
        text = _PROMPT_TEXT[name]
        for k, v in args.items():
            text = text.replace("{" + str(k) + "}", str(v))
        text = re.sub(r"\{(\w+)\}", r"<\1>", text)      # unfilled placeholders
        return _result(rid, {
            "description": next((p["description"] for p in PROMPTS
                                 if p["name"] == name), ""),
            "messages": [{"role": "user",
                          "content": {"type": "text", "text": text}}],
        })

    def _tools_call(self, rid: Any, params: dict) -> dict:
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            return _error(rid, -32602, "arguments must be an object")
        entry = HANDLERS.get(name)
        if entry is None:
            # Unknown tool is a PROTOCOL error, per the spec; a failure inside a known
            # tool is a RESULT with isError, so the model can read and react to it.
            return _error(rid, -32602, f"Unknown tool: {name}")
        fn, redactable = entry

        if self.report.error:
            self.audit.record(name, args, None, error=self.report.error)
            return _result(rid, _text_result({"error": self.report.error}, True))
        try:
            payload = fn(self.report, args)
        except ValueError as exc:
            self.audit.record(name, args, None, error=str(exc))
            return _result(rid, _text_result({"error": str(exc)}, True))
        except Exception as exc:                       # never take the server down
            _log(f"tool {name} failed: {exc}")
            self.audit.record(name, args, None, error=repr(exc))
            return _result(rid, _text_result(
                {"error": f"{name} failed: {exc}"}, True))

        if redactable:
            payload = self.redactor.walk(payload)
        self.audit.record(name, args, payload)
        return _result(rid, _text_result(payload))

    # ── the stdio loop ──────────────────────────────────────────────────────
    def serve(self, stdin=None, stdout=None) -> None:
        """Newline-delimited JSON-RPC. Per the spec, messages must not contain embedded
        newlines, so every response is written compactly on exactly one line."""
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                self._write(stdout, _error(None, -32700, "Parse error"))
                continue
            if not isinstance(msg, dict):
                self._write(stdout, _error(None, -32600, "Invalid Request"))
                continue
            try:
                out = self.handle(msg)
            except Exception as exc:                   # a bug must not kill the session
                _log(f"handler error: {exc}")
                out = _error(msg.get("id"), -32603, "Internal error")
            if out is not None:
                self._write(stdout, out)

    @staticmethod
    def _write(stream, msg: dict) -> None:
        stream.write(json.dumps(msg, default=str, separators=(",", ":")) + "\n")
        stream.flush()


# ── entry point ─────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="overwatch-mcp",
        description="Local read-only MCP server over a finished OverWatch scan report.")
    p.add_argument("--report", default=os.environ.get(REPORT_ENV),
                   help="Path to a scan JSON report (or set %s)." % REPORT_ENV)
    p.add_argument("--audit", default=os.environ.get(AUDIT_ENV, DEFAULT_AUDIT),
                   help="JSONL audit log of every tool call.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    may_start, identifiers = gate()
    if not may_start:
        sys.stderr.write(REFUSAL)
        sys.stderr.flush()
        return 2

    report = Report(args.report)
    if report.error:
        _log(report.error)                  # start anyway; tools report it as isError
    _log(f"serving {'FULL identifiers' if identifiers else 'redacted identifiers'}"
         f"{' | report: ' + str(args.report) if args.report else ''}")
    Server(report, Redactor(enabled=not identifiers),
           Audit(args.audit, identifiers)).serve()
    return 0


if __name__ == "__main__":                              # pragma: no cover
    sys.exit(main())
