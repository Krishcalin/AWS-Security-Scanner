#!/usr/bin/env python3
"""aws_flowlog.py — Layer B of the network-segmentation slice: turn OBSERVED VPC
Flow-Log traffic into evidence-based micro-segmentation recommendations.

Kept **boto3-free and pure** (like ``aws_exposure`` / ``aws_kube``) except for the
single socket-touching function :func:`default_flow_read`, which is the injected
read seam the scanner binds to ``self._flow_read`` (mirrors ``aws_kube.default_k8s_get``
and ``cnapp_connectors.default_http_post``). Tests replace the seam with a fake
returning canned CloudWatch-Logs-Insights rows, so the whole FP/FN catalogue —
custom LogFormat, REJECT-only logs, empty window, NAT src-rewrite, IPv6 — runs
with no AWS.

Design invariants:
  * Reading flow-log CONTENT is a NEW, OPTIONAL, resource-scoped grant
    (``logs:StartQuery`` + ``logs:GetQueryResults``) NOT in SecurityAudit/ViewOnlyAccess.
    Layer B is therefore opt-in + FAIL-OPEN: any unavailability → FLOW-00 INFO
    (naming the exact prereq), never a phantom PASS, and ``default_flow_read``
    returns ``None`` on any failure so the caller degrades gracefully.
  * All aggregation happens SERVER-SIDE via ``stats ... by`` so the query scans,
    not transfers, the window (Insights bills per GB scanned).
  * Reachability is never asserted from flow evidence alone; the overlay ANNOTATES
    the 4-gate ``compute_exposure`` edges, it does not create traversable paths.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

import aws_exposure

# Default v2 flow-log record fields, in order (used when LogFormat is empty/default).
FLOW_FIELDS_DEFAULT: List[str] = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport",
    "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status",
]
# Fields the analysis cannot run without (sanitized alias names).
REQUIRED_FIELDS: Set[str] = {"srcaddr", "dstaddr", "dstport", "action", "interface_id"}
# A 0.0.0.0/0 rule whose observed accepts collapse to at most this many /24s is a
# safe scope-down recommendation (few real sources behind a world-open rule).
MAX_SCOPE_CIDRS = 8
# Observation window defaults (hours) and delivery-lag margin (minutes).
WINDOW_HOURS = 72
DELIVERY_LAG_MIN = 10


# ─── flow-log config gate (from the already-fetched describe_flow_logs) ───────
def flow_readability(fl: dict) -> dict:
    """Decide whether a single ``describe_flow_logs`` FlowLog is readable via
    CloudWatch Logs Insights, and what traffic it can evidence. Returns a dict:
    ``{attemptable, reason, log_group, has_accept, has_reject, traffic_type}``.
    Only ``cloud-watch-logs``-delivered, healthy logs are attemptable; S3 and
    Firehose destinations fail open (they need ``s3:GetObject`` / are unqueryable)."""
    dest = fl.get("LogDestinationType", "cloud-watch-logs")
    status = fl.get("DeliverLogsStatus")
    lg = fl.get("LogGroupName")
    tt = (fl.get("TrafficType") or "ALL").upper()
    out = {"attemptable": False, "reason": "", "log_group": lg,
           "has_accept": False, "has_reject": False, "traffic_type": tt}
    if dest != "cloud-watch-logs":
        out["reason"] = (f"destination '{dest}' is not agentlessly readable "
                         f"(only CloudWatch-Logs-delivered flow logs are queryable via Insights)")
        return out
    if not lg:
        out["reason"] = "flow log has no LogGroupName"
        return out
    if status and status != "SUCCESS":
        out["reason"] = f"DeliverLogsStatus={status} (log delivery is not healthy)"
        return out
    out["attemptable"] = True
    out["has_accept"] = tt in ("ALL", "ACCEPT")
    out["has_reject"] = tt in ("ALL", "REJECT")
    return out


def parse_log_format(log_format: Optional[str]) -> List[str]:
    """Ordered field tokens of a flow-log ``LogFormat`` template (``${field} ...``).
    An empty/None format is the AWS default v2 layout. A non-empty format with no
    ``${...}`` tokens is malformed → returns ``[]`` (caller then fails open)."""
    if not log_format or not log_format.strip():
        return list(FLOW_FIELDS_DEFAULT)
    return re.findall(r"\$\{([^}]+)\}", log_format)


def _alias(field: str) -> str:
    """CWLI-safe identifier for a flow-log field (hyphens ⇒ underscores)."""
    return re.sub(r"[^0-9a-zA-Z]", "_", field.strip())


def required_fields_present(fields: List[str]) -> bool:
    """True when the (possibly custom) field list carries everything the deciders
    need. A custom LogFormat omitting srcaddr/dstaddr/dstport/action/interface-id
    makes evidence-based tightening impossible → the scanner emits FLOW-00."""
    return REQUIRED_FIELDS <= {_alias(f) for f in fields}


# ─── server-side Insights query builders (parse @message → stats … by) ───────
def build_queries(fields: List[str]) -> dict:
    """Build the three aggregation queryStrings from the flow-log field order.
    A leading ``parse @message`` maps positional fields to named columns so BOTH
    default and custom LogFormats are handled identically (never assume default
    offsets). Prefers ``pkt-srcaddr`` (true origin behind NAT/EKS) when present."""
    aliases = [_alias(f) for f in fields]
    stars = " ".join("*" for _ in aliases)
    base = f'parse @message "{stars}" as {", ".join(aliases)}'
    srcfield = "pkt_srcaddr" if "pkt_srcaddr" in aliases else "srcaddr"
    scopedown = (
        f'{base} | filter action="ACCEPT" and isValidIpV4({srcfield}) '
        f'| parse {srcfield} "*.*.*.*" as o1, o2, o3, o4 '
        f'| stats count(*) as flows, count_distinct({srcfield}) as distinctSrc '
        f'by interface_id, dstport, o1, o2, o3 | sort flows desc | limit 2000')
    accept_set = (
        f'{base} | filter action="ACCEPT" '
        f'| stats count(*) as accepts by interface_id, dstport | limit 10000')
    reject = (
        f'{base} | filter action="REJECT" '
        f'| stats count(*) as attempts, count_distinct(dstport) as portsProbed '
        f'by {srcfield} | sort attempts desc | limit 100')
    return {"scopedown": scopedown, "accept_set": accept_set, "reject": reject,
            "srcfield": srcfield}


# ─── static join structure: world-open single ports per ENI ──────────────────
def world_open_single_ports(enis: List[dict], sg_perms: Dict[str, list]) -> Dict[str, Set[int]]:
    """``{interface_id: {port, …}}`` for ports a 0.0.0.0/0 (v4 or v6) SG rule opens
    on each ENI, restricted to SINGLE ports (``lo==hi``) — the actionable case for
    FLOW-01/02. Wide ranges are SEG-02's job. Reuses the vetted ``sg_public_ports``."""
    out: Dict[str, Set[int]] = defaultdict(set)
    for e in enis:
        eni_id = e.get("NetworkInterfaceId")
        if not eni_id:
            continue
        perms: List[dict] = []
        for grp in e.get("Groups", []):
            perms += sg_perms.get(grp.get("GroupId"), [])
        world = (aws_exposure.sg_public_ports(perms, "ipv4")
                 | aws_exposure.sg_public_ports(perms, "ipv6"))
        for proto, lo, hi in world:
            if proto in ("tcp", "udp") and lo == hi:
                out[eni_id].add(lo)
    return dict(out)


# ─── deciders (canned aggregated rows in, recommendations out) ────────────────
def recommend_scopedown(scopedown_rows: List[dict], world_open: Dict[str, Set[int]],
                        max_cidrs: int = MAX_SCOPE_CIDRS) -> List[dict]:
    """FLOW-01: for each ENI/port that an SG opens to 0.0.0.0/0, if the observed
    ACCEPT sources collapse to a small set of /24s, recommend replacing the world
    rule with those prefixes. Rows: ``{interface_id, dstport, o1, o2, o3, flows}``."""
    cidrs: Dict[Tuple[str, int], Set[str]] = defaultdict(set)
    flows: Dict[Tuple[str, int], int] = defaultdict(int)
    for r in scopedown_rows:
        eni = r.get("interface_id")
        try:
            port = int(r.get("dstport"))
        except (TypeError, ValueError):
            continue
        o1, o2, o3 = r.get("o1"), r.get("o2"), r.get("o3")
        if None in (eni, o1, o2, o3):
            continue
        cidrs[(eni, port)].add(f"{o1}.{o2}.{o3}.0/24")
        flows[(eni, port)] += _int(r.get("flows"))
    out = []
    for (eni, port), cs in cidrs.items():
        if port in world_open.get(eni, set()) and 0 < len(cs) <= max_cidrs:
            out.append({"eni": eni, "port": port, "cidrs": sorted(cs),
                        "flows": flows[(eni, port)]})
    return sorted(out, key=lambda d: (d["eni"], d["port"]))


def unused_allowed_ports(accept_rows: List[dict],
                         world_open: Dict[str, Set[int]]) -> List[dict]:
    """FLOW-02: an SG-allowed world-open port with ZERO observed accepts over the
    window is a removal candidate — but ONLY on an ENI that saw SOME accepts (an
    idle ENI yields no evidence). Rows: ``{interface_id, dstport, accepts}``."""
    accepts_by_eni: Dict[str, Set[int]] = defaultdict(set)
    for r in accept_rows:
        try:
            port = int(r.get("dstport"))
        except (TypeError, ValueError):
            continue
        if _int(r.get("accepts")) > 0 and r.get("interface_id"):
            accepts_by_eni[r["interface_id"]].add(port)
    out = []
    for eni, ports in world_open.items():
        if eni not in accepts_by_eni:            # idle ENI → not enough evidence → skip
            continue
        for port in sorted(ports):
            if port not in accepts_by_eni[eni]:
                out.append({"eni": eni, "port": port})
    return out


def top_reject_talkers(reject_rows: List[dict], srcfield: str = "srcaddr",
                       top: int = 10) -> List[dict]:
    """FLOW-03: rank blocked-inbound source addresses by attempt count (recon signal).
    Rows: ``{<srcfield>, attempts, portsProbed}``."""
    talkers = []
    for r in reject_rows:
        src = r.get(srcfield) or r.get("srcaddr") or r.get("pkt_srcaddr")
        if not src:
            continue
        talkers.append({"src": src, "attempts": _int(r.get("attempts")),
                        "ports_probed": _int(r.get("portsProbed"))})
    talkers.sort(key=lambda t: (-t["attempts"], t["src"]))
    return talkers[:top]


def _int(v) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def window_bounds(now_s: float, hours: int = WINDOW_HOURS,
                  lag_min: int = DELIVERY_LAG_MIN) -> Tuple[int, int]:
    """Epoch-SECONDS (start, end) for the observation window, ending a few minutes
    in the past to clear delivery lag. Insights uses SECONDS (the raw-events APIs
    use MILLISECONDS — do not mix)."""
    end = int(now_s) - lag_min * 60
    return end - hours * 3600, end


# ─── the ONLY socket-touching function — the injected read seam ──────────────
def default_flow_read(logs_client, log_group_names, query_string, start_s, end_s,
                      limit=10000, max_wait_s=75, poll_s=1.0,
                      _sleep=None, _clock=None) -> Optional[List[dict]]:
    """Run one CloudWatch Logs Insights query: ``start_query`` → poll
    ``get_query_results`` until ``Complete`` → flattened rows (``{field: value}``).
    Returns ``None`` on ANY failure (denied, Failed/Timeout, max-wait exceeded,
    exception) so the caller FAILS OPEN. Bounded by ``max_wait_s``; calls
    ``stop_query`` to release the concurrency slot when it gives up.

    ``_sleep``/``_clock`` are injection points for tests (default ``time.sleep`` /
    ``time.monotonic``)."""
    import time as _time
    sleep = _sleep or _time.sleep
    clock = _clock or _time.monotonic
    try:
        resp = logs_client.start_query(
            logGroupNames=list(log_group_names)[:50], startTime=int(start_s),
            endTime=int(end_s), queryString=query_string, limit=limit)
        qid = resp.get("queryId")
        if not qid:
            return None
        t0 = clock()
        while True:
            r = logs_client.get_query_results(queryId=qid)
            status = r.get("status")
            if status == "Complete":
                return [{c["field"]: c["value"] for c in row}
                        for row in r.get("results", [])]
            if status in ("Failed", "Cancelled", "Timeout", "Unknown"):
                return None
            if clock() - t0 > max_wait_s:
                try:
                    logs_client.stop_query(queryId=qid)
                except Exception:
                    pass
                return None
            sleep(poll_s)
    except Exception:
        return None
