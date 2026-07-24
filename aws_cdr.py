#!/usr/bin/env python3
"""aws_cdr.py — CDR-lite: normalize live detection events and fold them onto the
STORED attack-path graph as THREAT_ON annotations, escalating any detection that
sits on a crown / internet-to-crown attack-path node into a ranked incident.

Boto3-free and pure (plain dicts + a SecurityGraph in, dataclasses/dicts out),
mirroring aws_ingest.py's external-vuln plane. Three normalizers cover the
detection sources OverWatch can read read-only:

  * ``normalize_guardduty``  — reuses ``aws_deepplane.map_guardduty_finding``
    (already filters archived + [SAMPLE]); extends the AccessKey branch so an
    IAM-principal detection can bind to the real principal node.
  * ``normalize_asff``       — Security Hub ASFF, skipping ARCHIVED / SUPPRESSED /
    RESOLVED / [SAMPLE] so closed findings never poison prioritization.
  * ``normalize_cloudtrail_anomaly`` — control-plane anomaly signals derivable from
    ONE CloudTrail management event (root usage, security-tooling tamper,
    credential creation, denied-sensitive-action). Lights the reserved THREAT-02
    semantics.

Node resolution reuses the ``resolve_owner`` discipline (exact ARN → graph node,
else instance-id / bucket / principal lookup; cross-account ARN → ``ValueError``;
unmapped → a flagged synthetic node, never dropped). Escalation reuses the ingest
reachability stack UNCHANGED (``aws_ingest._ingest_predicates`` +
``aws_correlate.enumerate_paths``), so a CDR verdict and a native/ingest verdict
can never disagree. NO new graph edge kind and NO ``aws_correlate`` change: a
detection node is only ever the SOURCE of a ``THREAT_ON`` edge (deliberately out of
E_PATH), never a traversable hop.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import aws_deepplane


# ── normalized detection ─────────────────────────────────────────────────────
@dataclass
class NormalizedDetection:
    id: str
    source: str                    # guardduty | securityhub | cloudtrail
    type: str
    title: str
    severity: float                # 0..10 (guardduty) or mapped from an ASFF label
    band: str                      # Critical | High | Medium | Low | Unknown
    node_kind: Optional[str] = None
    node_key: Optional[str] = None
    resource_arn: Optional[str] = None
    first_seen: Optional[str] = None
    evidence: dict = field(default_factory=dict)


_ASFF_SKIP_WORKFLOW = {"SUPPRESSED", "RESOLVED"}
_ASFF_LABEL_BAND = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
                    "LOW": "Low", "INFORMATIONAL": "Low"}
_ASFF_LABEL_SEV = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0,
                   "INFORMATIONAL": 0.5}

# CloudTrail control-plane events that tamper with defenses or mint credentials.
_CT_TAMPER = {"stoplogging", "deletetrail", "updatetrail", "deletedetector",
              "disablesecurityhub", "deleteflowlogs", "deletebucketpolicy",
              "putbucketpolicy", "disableebsencryptionbydefault",
              "deleteloggroup", "putlifecycleconfiguration"}
_CT_CRED = {"createaccesskey", "createloginprofile", "updateloginprofile",
            "createuser", "attachrolepolicy", "attachuserpolicy",
            "putrolepolicy", "putuserpolicy", "updateassumerolepolicy",
            "createpolicyversion"}
_CT_DENY_MARKERS = ("accessdenied", "unauthorized")

_CT_SIGNAL_SEV = {"security-tooling-tamper": (8.0, "High"),
                  "root-usage": (7.0, "High"),
                  "credential-creation": (6.0, "Medium"),
                  "unauthorized-denied": (4.0, "Medium")}

# off-path detections rank by intrinsic band only, capped below the reachability
# bands (mirrors aws_ingest._exploitability_only_score — reachability outranks band)
_BAND_SCORE = {"Critical": 45, "High": 40, "Medium": 30, "Low": 15, "Unknown": 10}

_ARN_ACCT_RE = re.compile(r"^arn:[^:]*:[^:]*:[^:]*:(\d{12})?:")


def _is_sample(*strings) -> bool:
    return any("[SAMPLE]" in (s or "") for s in strings)


def _band_score(band: str) -> int:
    return _BAND_SCORE.get(band, 10)


def _kind_from_arn(arn: str) -> str:
    parts = arn.split(":")
    svc = parts[2] if len(parts) > 2 else ""
    return {"s3": "S3Bucket", "ec2": "EC2Instance", "iam": "IAMPrincipal",
            "sts": "IAMPrincipal", "dynamodb": "DynamoDBTable", "rds": "RDSInstance",
            "lambda": "LambdaFunction"}.get(svc, "Resource")


# ── normalizers ──────────────────────────────────────────────────────────────
def normalize_guardduty(f: dict) -> Optional[NormalizedDetection]:
    """GuardDuty finding → NormalizedDetection, reusing map_guardduty_finding
    (which filters archived + [SAMPLE]). Carries AccessKeyId/PrincipalId so an
    IAM-principal detection (map returns node_key=UserName) can bind to a real
    principal node in resolve_detection_node."""
    m = aws_deepplane.map_guardduty_finding(f)
    if not m or not m.get("id"):
        return None
    res = f.get("Resource") or {}
    ak = res.get("AccessKeyDetails") or {}
    return NormalizedDetection(
        id=m["id"], source="guardduty", type=m["type"] or "",
        title=f.get("Title", "") or (m["type"] or ""),
        severity=float(m["severity"] or 0.0), band=m["band"],
        node_kind=m["node_kind"], node_key=m["node_key"], resource_arn=None,
        first_seen=(f.get("Service") or {}).get("EventFirstSeen") or f.get("CreatedAt"),
        evidence={"access_key_id": ak.get("AccessKeyId"),
                  "principal_id": ak.get("PrincipalId")},
    )


def normalize_asff(f: dict) -> Optional[NormalizedDetection]:
    """Security Hub ASFF finding → NormalizedDetection. Skips ARCHIVED /
    SUPPRESSED / RESOLVED / [SAMPLE] so closed or sample findings never poison
    prioritization (mirrors the GuardDuty hygiene)."""
    if not f:
        return None
    if f.get("RecordState") == "ARCHIVED":
        return None
    if (f.get("Workflow") or {}).get("Status") in _ASFF_SKIP_WORKFLOW:
        return None
    title = f.get("Title", "") or ""
    types = f.get("Types") or []
    if _is_sample(title, *types):
        return None
    sev = f.get("Severity") or {}
    label = (sev.get("Label") or "").upper()
    if label:
        band = _ASFF_LABEL_BAND.get(label, "Unknown")
        score = _ASFF_LABEL_SEV.get(label, 0.0)
    else:
        norm = sev.get("Normalized")
        score = (float(norm) / 10.0) if isinstance(norm, (int, float)) else 0.0
        band = aws_deepplane.severity_band(score)
    arn = None
    for r in (f.get("Resources") or []):
        rid = r.get("Id", "") or ""
        if rid.startswith("arn:"):
            arn = rid
            break
    fid = f.get("Id") or arn or title
    if not fid:
        return None
    return NormalizedDetection(
        id=fid, source="securityhub", type=(types[0] if types else ""),
        title=title, severity=score, band=band,
        node_kind=None, node_key=None, resource_arn=arn,
        first_seen=f.get("FirstObservedAt") or f.get("CreatedAt"),
        evidence={"product_arn": f.get("ProductArn"),
                  "workflow": (f.get("Workflow") or {}).get("Status")},
    )


def detect_cloudtrail_signals(event: dict) -> List[str]:
    """Anomaly signals derivable from ONE CloudTrail management event with no
    baseline/history: root usage, security-tooling tamper, credential creation,
    denied sensitive action. (Impossible-travel / new-region need a baseline and
    are intentionally out of scope for a single-event pure classifier.)"""
    if not event:
        return []
    signals: List[str] = []
    ui = event.get("userIdentity") or {}
    if (ui.get("type") or "") == "Root":
        signals.append("root-usage")
    ev = (event.get("eventName") or "").lower()
    if ev in _CT_TAMPER:
        signals.append("security-tooling-tamper")
    if ev in _CT_CRED:
        signals.append("credential-creation")
    err = (event.get("errorCode") or "").lower()
    if err and any(mk in err for mk in _CT_DENY_MARKERS):
        signals.append("unauthorized-denied")
    return signals


def normalize_cloudtrail_anomaly(event: dict,
                                 signals: Optional[List[str]] = None
                                 ) -> Optional[NormalizedDetection]:
    """Map a control-plane CloudTrail event that carries at least one anomaly
    signal onto the ACTING principal (else no node). Lights the reserved THREAT-02
    control-plane semantics. ``signals`` defaults to ``detect_cloudtrail_signals``."""
    if not event:
        return None
    sigs = list(signals) if signals is not None else detect_cloudtrail_signals(event)
    if not sigs:
        return None
    sev, band = max((_CT_SIGNAL_SEV.get(s, (1.0, "Low")) for s in sigs),
                    key=lambda t: t[0])
    ui = event.get("userIdentity") or {}
    actor = ui.get("arn") or ((ui.get("sessionContext") or {})
                              .get("sessionIssuer") or {}).get("arn")
    eid = event.get("eventID") or event.get("EventId") or f"ct:{event.get('eventName', '')}"
    node_kind = "IAMPrincipal" if (actor or "").startswith("arn:") else None
    sig_str = ", ".join(sorted(sigs))
    return NormalizedDetection(
        id=eid, source="cloudtrail", type="cloudtrail:" + ",".join(sorted(sigs)),
        title=f"Control-plane anomaly ({sig_str}) via {event.get('eventName', '?')}",
        severity=sev, band=band,
        node_kind=node_kind, node_key=None,
        resource_arn=actor if node_kind else None,
        first_seen=event.get("eventTime") or event.get("EventTime"),
        evidence={"event_name": event.get("eventName"),
                  "source_ip": event.get("sourceIPAddress"),
                  "region": event.get("awsRegion"),
                  "error_code": event.get("errorCode")},
    )


# ── node resolution (reuses the resolve_owner join discipline) ────────────────
def _find_node(graph, kind: str, key) -> Optional[str]:
    """Best-effort join of a GuardDuty node_kind/node_key onto an existing graph
    node (the native scan keys EC2 by instance ARN, S3 by bucket ARN, IAM by
    principal ARN). Returns the node id, or None if not present."""
    key_l = str(key).lower()
    if kind == "EC2Instance":
        for n in graph.nodes():
            if (n.get("props") or {}).get("instance_id") == key \
                    or n["id"].lower().endswith("instance/" + key_l):
                return n["id"]
    elif kind == "S3Bucket":
        for n in graph.nodes():
            nid = n["id"].lower()
            if (n.get("props") or {}).get("name") == key \
                    or nid.endswith(":::" + key_l) or nid == key_l:
                return n["id"]
    elif kind == "IAMPrincipal":
        for n in graph.nodes():
            nid = n["id"].lower()
            # Bind ONLY to genuine principals — a node whose kind says so, or whose ARN is a
            # user/role ARN. Deliberately EXCLUDES other iam-namespace ARNs (instance-profile,
            # policy, group, mfa, *-provider): a UserName that merely equals such a node's tail
            # must fall through to the honest cdr:unmapped node, never a phantom incident.
            is_principal = (n["kind"] in ("IAMRole", "IAMUser", "IAMPrincipal")
                            or ":user/" in nid or ":role/" in nid)
            if not is_principal:
                continue
            if ((n.get("props") or {}).get("name") == key
                    or nid.endswith(":user/" + key_l) or nid.endswith(":role/" + key_l)
                    or nid.endswith("/" + key_l)):
                return n["id"]
    return None


def resolve_detection_node(graph, det: NormalizedDetection,
                           account: Optional[str] = None) -> Tuple[str, str, str]:
    """Resolve a detection to the graph node it names → ``(node_id, node_kind,
    mapping_status)``. Order: explicit ARN, then GuardDuty node_kind/node_key
    lookup, then a safely-synthesizable canonical id (bucket), else a flagged
    synthetic ``cdr:unmapped:<id>`` node (never dropped). Raises ``ValueError`` on
    a cross-account ARN so one account can never fold a detection onto another's
    node."""
    arn = det.resource_arn
    if arn and arn.startswith("arn:"):
        m = _ARN_ACCT_RE.match(arn)
        if account and m and m.group(1) and m.group(1) != account:
            raise ValueError(f"cross-account detection ARN {arn} != account {account}")
        nd = graph.node(arn)
        if nd:
            return arn, nd["kind"], "resolved"
        return arn, det.node_kind or _kind_from_arn(arn), "resolved"

    kind, key = det.node_kind, det.node_key
    if kind and key:
        found = _find_node(graph, kind, key)
        if found:
            return found, graph.node(found)["kind"], "resolved"
        if kind == "S3Bucket":
            return ("arn:aws:s3:::" + str(key)).lower(), "S3Bucket", "resolved"

    return f"cdr:unmapped:{det.id}", kind or "CdrUnmapped", "unmapped"


def emit_threat_edges(graph, node_id: str, node_kind: str,
                      det: NormalizedDetection) -> str:
    """Add a ``CdrDetection`` source node + a ``THREAT_ON`` edge INTO the owner
    node (MERGE-idempotent, mirrors _check_threat's ThreatFinding→THREAT_ON). No
    new edge kind. Returns the detection node id."""
    tnode = f"cdr:{det.id}"
    graph.add_node(tnode, "CdrDetection", source=det.source, type=det.type,
                   severity=det.severity, band=det.band, title=det.title)
    graph.add_node(node_id, node_kind or "Unknown")
    graph.add_edge(tnode, node_id, "THREAT_ON", source=det.source, type=det.type,
                   severity=det.severity, band=det.band)
    return tnode


# ── reachability re-run (escalation) ─────────────────────────────────────────
def compute_detection_verdicts(graph_dict: Optional[dict],
                               detections: List[NormalizedDetection],
                               account: Optional[str] = None
                               ) -> Tuple[Dict[str, dict], List[dict], "object"]:
    """Rebuild ``graph_dict`` → fold each detection as a THREAT_ON edge → re-run the
    native ``enumerate_paths`` with the IDENTICAL ingest predicates → per-detection
    verdict + the ranked incident list.

    Returns ``({detection_id: verdict}, [incident,...], graph)``. A detection is an
    incident (escalated) when it sits on an internet→crown/admin attack path
    (``on_attack_path``) or directly on a crown datastore (``hits_crown_node``).
    When the graph has no ``internet`` node (no native scan yet), reachability
    collapses honestly to unknown (``on_attack_path=False``) and detections rank by
    their own band — never a fabricated path."""
    from aws_graph import SecurityGraph
    import aws_correlate
    import aws_ingest

    g = SecurityGraph.from_dict(graph_dict or {})
    resolved: List[Tuple[NormalizedDetection, str, str, str]] = []
    for det in detections:
        node_id, node_kind, status = resolve_detection_node(g, det, account)
        emit_threat_edges(g, node_id, node_kind, det)
        resolved.append((det, node_id, node_kind, status))

    crown_ids = aws_correlate.crown_nodes(g)
    paths: List = []
    reach_internet: set = set()
    if g.node("internet") is not None:
        admin_id, cids, is_uncond, node_has_threat = aws_ingest._ingest_predicates(g)
        paths = aws_correlate.enumerate_paths(
            g, {"internet"}, admin_id, cids, is_uncond,
            aws_deepplane.is_exploitable, node_has_threat)
        reach_internet = set(g.reachable("internet", aws_correlate.E_PATH,
                                         max_hops=64).keys())

    node_paths: Dict[str, list] = defaultdict(list)
    for p in paths:
        for nid in p.nodes:
            node_paths[nid].append(p)

    verdicts: Dict[str, dict] = {}
    incidents: List[dict] = []
    for det, node_id, node_kind, status in resolved:
        if det.id in verdicts:                              # dedup by detection id
            continue
        ps = node_paths.get(node_id, [])
        on_path = bool(ps)
        hits_crown = node_id in crown_ids
        reaches_crown = any(p.terminal_kind == "data" for p in ps)
        from_inet = node_id in reach_internet
        if ps:
            best = max(ps, key=lambda p: p.score)
            score = int(best.score)
            driving = " -> ".join(best.nodes)
        elif hits_crown:
            score = max(_band_score(det.band), 55)          # detection ON a crown store
            driving = None
        else:
            score = _band_score(det.band)                   # off-path: band only
            driving = None
        incident = on_path or hits_crown
        v = {
            "id": det.id, "source": det.source, "type": det.type, "title": det.title,
            "node_id": node_id, "node_kind": node_kind, "node_key": det.node_key,
            "mapping_status": status,
            "severity": det.severity, "band": det.band,
            "on_attack_path": on_path, "reaches_crown": reaches_crown,
            "hits_crown_node": hits_crown, "reachable_from_internet": from_inet,
            "priority_score": score, "priority_band": aws_correlate._severity(score),
            "driving_path": driving, "incident": incident,
            "first_seen": det.first_seen,
        }
        verdicts[det.id] = v
        if incident:
            incidents.append(v)
    incidents.sort(key=lambda x: x["priority_score"], reverse=True)
    return verdicts, incidents, g
