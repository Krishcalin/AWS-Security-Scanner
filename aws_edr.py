#!/usr/bin/env python3
"""aws_edr.py — runtime-sensor (EDR / CWPP) ingest + coverage correlator.

The IN-CHARTER substitute for a runtime sensor: OverWatch never deploys an agent or
eBPF sensor (that would break agentless + zero-telemetry and fail test_zero_telemetry);
instead it INGESTS the customer's EXISTING runtime sensor output and correlates it onto
the byte-frozen attack-path graph. Two feeds:

  * DETECTIONS (CrowdStrike Falcon, Falco, GuardDuty Runtime Monitoring, generic OCSF
    2004) — normalized to aws_cdr.NormalizedDetection, resolved to a workload node, and
    folded as a THREAT_ON annotation (reusing aws_cdr; THREAT_ON is deliberately OUT of
    E_PATH, so aws_correlate is never traversed differently and stays byte-frozen), then
    re-run through the identical reachability stack so a runtime alert on an
    internet->crown/admin path escalates to a ranked incident.

  * SENSOR INVENTORY (which workloads have a healthy sensor RIGHT NOW) — a coverage feed,
    distinct from detections (a quiet, well-covered host fires no detection). It stamps
    runtime_monitored=True on the workloads a sensor watches and surfaces the workloads
    the EDR is BLIND to — the honest coverage gap, ranked by attack-path exposure.

Pure / stdlib / boto3-free (plain dicts in, dataclasses/dicts out), mirroring
aws_cdr.py + aws_ingest.py. Reuses aws_cdr (NormalizedDetection, resolve_detection_node,
emit_threat_edges, severity helpers) and aws_correlate reachability READ-ONLY. NO new
E_PATH edge kind and NO aws_correlate edit.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import aws_cdr
import aws_deepplane

# ── the workload kinds a runtime/endpoint sensor can cover (the coverage denominator).
# Deliberately NARROWER than aws_correlate._EXPLOIT_KINDS: that set is about vuln-carrying
# workloads (adds ECRImage/LambdaFunction); this is about sensor-hostable RUNNING workloads.
# LambdaFunction is excluded by default (serverless; most EDR/CWPP agents don't run there).
EXPECTED_RUNTIME_KINDS = frozenset({"EC2Instance", "ECSFargateTask", "KubePod"})

RUNTIME_SOURCES = frozenset({"crowdstrike", "falco", "guardduty-runtime", "ocsf"})

# Anti-storm gate: EDR/Falco are far higher volume than GuardDuty, so only Medium+ runtime
# detections are ingested/folded (an Info/Low runtime alert would 1.5x-boost many paths and
# spawn incident noise). Bands come from aws_deepplane.severity_band.
_BAND_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
RUNTIME_MIN_BAND = "Medium"

# statuses that mean a detection is closed/handled — never fold a resolved alert. Includes
# CrowdStrike 'ignored'/'muted' (analyst-dismissed) so a triaged-away alert can't re-escalate.
_CLOSED_STATUS = {"closed", "resolved", "suppressed", "dismissed", "false_positive",
                  "falsepositive", "benign", "reopened_closed", "ignored", "muted"}
# OCSF status_id (2004) closed values — 3 Suppressed, 4 Resolved — so a finding that carries only
# the integer status_id (not the string status) is still filtered.
_OCSF_CLOSED_IDS = frozenset({3, 4})
# sensor-health statuses that mean the agent is NOT actively protecting: such a host is NOT
# "covered" even though a fresh inventory row exists (else coverage is inflated + a blind spot
# is hidden). Absent/unknown status is treated as healthy (many feeds don't report it).
_UNHEALTHY_SENSOR = {"offline", "contained", "degraded", "error", "uninstalled", "disabled",
                     "reduced_functionality_mode", "rfm", "unhealthy", "inactive", "stopped"}

# OCSF severity_id (2004 Detection Finding) -> 0..10, mirroring severity_band thresholds.
_OCSF_SEV = {0: 0.0, 1: 1.0, 2: 3.0, 3: 5.0, 4: 7.5, 5: 9.0, 6: 10.0}
# CrowdStrike SeverityName / generic label -> 0..10.
_LABEL_SEV = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0,
              "INFORMATIONAL": 0.5, "INFO": 0.5, "NONE": 0.0}
# Falco priority -> 0..10 (Emergency..Debug).
_FALCO_SEV = {"EMERGENCY": 10.0, "ALERT": 9.0, "CRITICAL": 9.0, "ERROR": 7.5,
              "WARNING": 5.0, "NOTICE": 3.0, "INFORMATIONAL": 1.0, "INFO": 1.0, "DEBUG": 0.5}


# ── workload identity + sensor-inventory record ───────────────────────────────
@dataclass
class SensorRecord:
    """One 'this workload has a healthy runtime sensor' fact from an inventory feed."""
    vendor: str
    last_seen: Optional[str] = None          # ISO-8601 (freshness-gated at read time)
    instance_id: Optional[str] = None        # strongest workload key (EC2)
    resource_arn: Optional[str] = None
    ecs_task_arn: Optional[str] = None
    pod_name: Optional[str] = None
    pod_namespace: Optional[str] = None
    hostname: Optional[str] = None
    sensor_id: Optional[str] = None          # agent/device id (provenance)
    status: Optional[str] = None             # healthy | degraded | offline
    cloud_account: Optional[str] = None


def _band_ok(band: str, floor: str = RUNTIME_MIN_BAND) -> bool:
    return _BAND_RANK.get(band, 0) >= _BAND_RANK.get(floor, 0)


def _is_closed(status) -> bool:
    return str(status or "").strip().lower().replace(" ", "_") in _CLOSED_STATUS


def _sensor_live(rec: "SensorRecord") -> bool:
    """A sensor covers its workload only when it is actively protecting — an offline / degraded /
    contained / RFM agent is NOT coverage. Absent status is treated as healthy."""
    return str(rec.status or "").strip().lower().replace(" ", "_") not in _UNHEALTHY_SENSOR


def _mk_id(*parts) -> str:
    return "rt:" + hashlib.sha256("|".join(str(p or "") for p in parts).encode()).hexdigest()[:24]


def _identity_to_det_keys(ident: dict):
    """Pick the strongest (node_kind, node_key, resource_arn) for aws_cdr resolution from a
    workload identity dict. Order: explicit ARN, EC2 instance-id, ECS task ARN, EKS pod. A pod
    key is namespaced (``namespace/name``) when the namespace is known, so two same-named pods in
    different namespaces don't mis-bind (aws_cdr._find_node matches the namespaced form)."""
    arn = ident.get("resource_arn") or ident.get("ecs_task_arn")
    if arn and str(arn).startswith("arn:"):
        return None, None, arn
    if ident.get("instance_id"):
        return "EC2Instance", ident["instance_id"], None
    if ident.get("pod_name"):
        ns = ident.get("pod_namespace")
        return "KubePod", (f"{ns}/{ident['pod_name']}" if ns else ident["pod_name"]), None
    return None, None, None


def _wrap_identity(evidence: dict, ident: dict) -> dict:
    evidence = dict(evidence or {})
    evidence["identity"] = {k: v for k, v in ident.items() if v is not None}
    return evidence


# ── normalizers (raw vendor dict -> aws_cdr.NormalizedDetection | None) ────────
def normalize_crowdstrike(f: dict) -> Optional[aws_cdr.NormalizedDetection]:
    """CrowdStrike Falcon detection/alert (Detects/Alerts API) -> NormalizedDetection.
    device.instance_id is the reliable EC2 join for cloud hosts."""
    if not f:
        return None
    if _is_closed(f.get("status")):
        return None
    behaviors = f.get("behaviors") or []
    b0 = behaviors[0] if behaviors else {}
    title = (f.get("DetectDescription") or b0.get("description") or f.get("name")
             or b0.get("scenario") or "CrowdStrike detection")
    if aws_cdr._is_sample(title, f.get("name")):
        return None
    raw_sev = f.get("max_severity")
    if isinstance(raw_sev, (int, float)):
        sev = float(raw_sev) / 10.0                       # CS 1..100 -> 0..10
    else:
        sev = _LABEL_SEV.get(str(f.get("max_severity_displayname") or
                                 f.get("SeverityName") or "").upper(), 0.0)
    band = aws_deepplane.severity_band(sev)
    if not _band_ok(band):
        return None
    dev = f.get("device") or {}
    ident = {"instance_id": dev.get("instance_id"), "hostname": dev.get("hostname"),
             "cloud_account": dev.get("service_provider_account_id"),
             "container_id": b0.get("container_id")}
    node_kind, node_key, arn = _identity_to_det_keys(ident)
    fid = f.get("composite_id") or f.get("detection_id") or f.get("id") or _mk_id(title, dev.get("device_id"))
    return aws_cdr.NormalizedDetection(
        id=str(fid), source="crowdstrike", type=(b0.get("technique") or f.get("name") or ""),
        title=str(title), severity=sev, band=band, node_kind=node_kind, node_key=node_key,
        resource_arn=arn, first_seen=f.get("first_behavior") or f.get("created_timestamp"),
        evidence=_wrap_identity({"tactic": b0.get("tactic"), "technique": b0.get("technique_id"),
                                 "agent_id": dev.get("device_id"), "status": f.get("status")}, ident))


def normalize_falco(f: dict) -> Optional[aws_cdr.NormalizedDetection]:
    """Falco alert (-o json_output) -> NormalizedDetection. No native stable id or
    instance-id: id is synthesized; identity is pod/container/host (exercises the
    KubePod join + the unmapped lane)."""
    if not f:
        return None
    rule = f.get("rule") or ""
    if aws_cdr._is_sample(rule, f.get("output")):
        return None
    sev = _FALCO_SEV.get(str(f.get("priority") or "").upper(), 0.0)
    band = aws_deepplane.severity_band(sev)
    if not _band_ok(band):
        return None
    of = f.get("output_fields") or {}
    ident = {"hostname": f.get("hostname") or of.get("container.host"),
             "container_id": of.get("container.id"),
             "pod_name": of.get("k8s.pod.name"), "pod_namespace": of.get("k8s.ns.name"),
             "image": of.get("container.image.repository")}
    node_kind, node_key, arn = _identity_to_det_keys(ident)
    fid = _mk_id(f.get("hostname"), rule, f.get("time"), of.get("container.id"))
    tags = f.get("tags") or []
    technique = next((t for t in tags if isinstance(t, str) and t[:1] == "T" and t[1:2].isdigit()), None)
    return aws_cdr.NormalizedDetection(
        id=fid, source="falco", type=rule, title=(f.get("output") or rule)[:300],
        severity=sev, band=band, node_kind=node_kind, node_key=node_key, resource_arn=arn,
        first_seen=f.get("time"),
        evidence=_wrap_identity({"technique": technique, "priority": f.get("priority"),
                                 "tags": tags}, ident))


def normalize_guardduty_runtime(f: dict) -> Optional[aws_cdr.NormalizedDetection]:
    """GuardDuty Runtime Monitoring finding -> NormalizedDetection. Reuses
    map_guardduty_finding (archived + [SAMPLE] hygiene) and extends resource extraction
    to the runtime resource shapes (EKS/ECS/Container), preferring the underlying EC2
    host instance-id when present (the reliable join)."""
    m = aws_deepplane.map_guardduty_finding(f)
    if not m or not m.get("id"):
        return None
    ftype = m.get("type") or ""
    band = m.get("band")
    if not _band_ok(band):
        return None
    res = f.get("Resource") or {}
    inst = (res.get("InstanceDetails") or {}).get("InstanceId") or m.get("node_key")
    eks = (res.get("EksClusterDetails") or {}).get("Name")
    kube = res.get("KubernetesDetails") or {}
    kwl = (kube.get("KubernetesWorkloadDetails") or {})
    ecs = res.get("EcsClusterDetails") or {}
    cont = res.get("ContainerDetails") or {}
    ident = {"instance_id": inst if m.get("node_kind") == "EC2Instance" or inst else None,
             "eks_cluster": eks, "pod_name": kwl.get("Name"), "pod_namespace": kwl.get("Namespace"),
             "ecs_cluster_arn": ecs.get("Arn"), "container_id": cont.get("Id"),
             "image": cont.get("Image")}
    node_kind, node_key, arn = _identity_to_det_keys(ident)
    # MITRE tactic/technique often ride the Type "Tactic:Resource/Technique.Variant"
    tactic = ftype.split(":")[0] if ":" in ftype else None
    return aws_cdr.NormalizedDetection(
        id=m["id"], source="guardduty-runtime", type=ftype,
        title=f.get("Title", "") or ftype, severity=float(m.get("severity") or 0.0), band=band,
        node_kind=node_kind, node_key=node_key, resource_arn=arn,
        first_seen=(f.get("Service") or {}).get("EventFirstSeen") or f.get("CreatedAt"),
        evidence=_wrap_identity({"tactic": tactic}, ident))


def normalize_ocsf(f: dict) -> Optional[aws_cdr.NormalizedDetection]:
    """Generic OCSF Detection Finding (class_uid 2004) -> NormalizedDetection. The
    universal passthrough (subsumes SentinelOne, Security Lake, Sysdig, ...)."""
    if not f:
        return None
    fi = f.get("finding_info") or {}
    title = fi.get("title") or f.get("message") or "OCSF detection"
    if aws_cdr._is_sample(title):
        return None
    sid = f.get("status_id")
    if _is_closed(f.get("status")) or (isinstance(sid, int) and sid in _OCSF_CLOSED_IDS):
        return None
    sid = f.get("severity_id")
    sev = _OCSF_SEV.get(sid) if isinstance(sid, int) else _LABEL_SEV.get(str(f.get("severity") or "").upper(), 0.0)
    band = aws_deepplane.severity_band(sev)
    if not _band_ok(band):
        return None
    dev = f.get("device") or {}
    cloud = f.get("cloud") or {}
    cont = f.get("container") or {}
    img = cont.get("image") or {}
    resources = f.get("resources") or []
    arn = next((r.get("uid") for r in resources if str(r.get("uid") or "").startswith("arn:")), None)
    ident = {"instance_id": dev.get("instance_uid") or cloud.get("instance_uid"),
             "resource_arn": arn, "hostname": dev.get("hostname"),
             "container_id": cont.get("uid"), "image": (img.get("name")),
             "image_digest": img.get("uid"), "cloud_account": (cloud.get("account") or {}).get("uid")}
    node_kind, node_key, ark = _identity_to_det_keys(ident)
    attacks = fi.get("attacks") or []
    a0 = attacks[0] if attacks else {}
    return aws_cdr.NormalizedDetection(
        id=str(fi.get("uid") or f.get("uid") or _mk_id(title, dev.get("hostname"))),
        source="ocsf", type=(fi.get("types") or [f.get("activity_name")])[0] or "",
        title=str(title), severity=sev, band=band, node_kind=node_kind, node_key=node_key,
        resource_arn=ark, first_seen=fi.get("first_seen_time") or f.get("time"),
        evidence=_wrap_identity({"tactic": (a0.get("tactic") or {}).get("name"),
                                 "technique": (a0.get("technique") or {}).get("uid")}, ident))


NORMALIZERS = {
    "crowdstrike": normalize_crowdstrike,
    "falco": normalize_falco,
    "guardduty-runtime": normalize_guardduty_runtime,
    "ocsf": normalize_ocsf,
}


def normalize(source: str, events: List[dict]) -> List[aws_cdr.NormalizedDetection]:
    """Dispatch a batch of raw vendor events through the source's normalizer, dropping
    the ones that fail the [SAMPLE]/closed/band filters. Unknown source -> ValueError."""
    fn = NORMALIZERS.get(source)
    if fn is None:
        raise ValueError(f"unknown runtime source: {source!r} (known: {sorted(NORMALIZERS)})")
    out = []
    for e in events or []:
        try:
            d = fn(e)
        except Exception:
            d = None                                       # fail-soft per event (never crash a batch)
        if d is not None:
            out.append(d)
    return out


# ── sensor-inventory -> workload-node join + coverage ─────────────────────────
def _sensor_to_det(rec: SensorRecord) -> aws_cdr.NormalizedDetection:
    """Adapt a SensorRecord into the minimal NormalizedDetection shape so it reuses
    aws_cdr.resolve_detection_node (one join for detections AND coverage)."""
    ident = {"instance_id": rec.instance_id, "resource_arn": rec.resource_arn,
             "ecs_task_arn": rec.ecs_task_arn, "pod_name": rec.pod_name,
             "pod_namespace": rec.pod_namespace}
    node_kind, node_key, arn = _identity_to_det_keys(ident)
    return aws_cdr.NormalizedDetection(
        id=f"sensor:{rec.vendor}:{rec.instance_id or rec.pod_name or rec.resource_arn or rec.sensor_id}",
        source=rec.vendor, type="sensor", title="runtime sensor", severity=0.0, band="Unknown",
        node_kind=node_kind, node_key=node_key, resource_arn=arn)


def resolve_sensor_node(graph, rec: SensorRecord, account: Optional[str] = None) -> Optional[str]:
    """Resolve a sensor inventory record to the id of an EXISTING workload node, or None
    when it maps to no node in the current graph (a sensor for an un-scanned host). Reuses
    aws_cdr.resolve_detection_node; the cross-account ARN guard is inherited."""
    node_id, _, status = aws_cdr.resolve_detection_node(graph, _sensor_to_det(rec), account)
    if status == "unmapped" or graph.node(node_id) is None:
        return None
    kind = graph.node(node_id)["kind"]
    return node_id if kind in EXPECTED_RUNTIME_KINDS else node_id  # keep even if odd kind; caller filters


def monitored_node_ids(graph, sensors: List[SensorRecord], account: Optional[str] = None) -> set:
    """The set of graph workload-node ids that a live sensor covers (the numerator)."""
    out = set()
    for rec in sensors:
        if not _sensor_live(rec):
            continue                                       # offline/degraded agent is NOT coverage
        try:
            nid = resolve_sensor_node(graph, rec, account)
        except ValueError:
            continue                                       # cross-account sensor row — ignore
        if nid is not None:
            out.add(nid)
    return out


def apply_runtime_monitored(graph, sensors: List[SensorRecord], account: Optional[str] = None) -> int:
    """Stamp runtime_monitored=True (MERGE, in place) on every workload node a sensor covers.
    Read-time overlay: the caller rehydrates graph_full, applies this, then queries — so
    graph_full stays the pristine native seed and aws_correlate is never touched. Returns
    the count stamped. This is what makes the WQL runtime_monitored prop real."""
    ids = monitored_node_ids(graph, sensors, account)
    for nid in ids:
        nd = graph.node(nid)
        if nd:
            graph.add_node(nid, nd["kind"], runtime_monitored=True)
    return len(ids)


def compute_coverage(graph, sensors: List[SensorRecord], account: Optional[str] = None) -> dict:
    """Runtime sensor-coverage over the workload universe. Returns
    ``{overall:{monitored,total,pct}, per_kind:{kind:{monitored,total,pct}}, gaps:[...]}``
    where gaps are the UNMONITORED workloads ranked by attack-path exposure (an unmonitored
    workload that is internet-reachable and on a path to crown is the headline gap). Gap
    ranking reuses aws_correlate reachability UNCHANGED — no scoring added."""
    import aws_correlate

    monitored = monitored_node_ids(graph, sensors, account)
    workloads = [n for n in graph.nodes() if n["kind"] in EXPECTED_RUNTIME_KINDS]

    # reachability context (only when a native scan planted an internet node)
    reach_internet: set = set()
    reach_crown: set = set()
    if graph.node("internet") is not None:
        reach_internet = set(graph.reachable("internet", aws_correlate.E_PATH, max_hops=64).keys())
        for cid in aws_correlate.crown_nodes(graph):
            reach_crown |= set(graph.reverse_reachable(cid, aws_correlate.E_PATH, max_hops=64).keys())

    per_kind: Dict[str, dict] = {}
    for k in sorted(EXPECTED_RUNTIME_KINDS):
        tot = [n for n in workloads if n["kind"] == k]
        mon = sum(1 for n in tot if n["id"] in monitored)
        per_kind[k] = {"monitored": mon, "total": len(tot),
                       "pct": round(100.0 * mon / len(tot), 1) if tot else None}

    gaps = []
    for n in workloads:
        if n["id"] in monitored:
            continue
        exposed = n["id"] in reach_internet
        to_crown = n["id"] in reach_crown
        # exposure rank: exposed & crown-bound (3) > crown-bound (2) > exposed (1) > isolated (0)
        rank = (2 if to_crown else 0) + (1 if exposed else 0)
        props = n.get("props") or {}
        gaps.append({"node_id": n["id"], "kind": n["kind"],
                     "label": props.get("name") or n["id"].rsplit("/", 1)[-1].rsplit(":", 1)[-1],
                     "reachable_from_internet": exposed, "reaches_crown": to_crown,
                     "exposure_rank": rank})
    gaps.sort(key=lambda g: (-g["exposure_rank"], g["kind"], g["node_id"]))

    total = len(workloads)
    return {
        "overall": {"monitored": len(monitored & {n["id"] for n in workloads}),
                    "total": total,
                    "pct": round(100.0 * len(monitored & {n["id"] for n in workloads}) / total, 1) if total else None},
        "per_kind": per_kind,
        "gaps": gaps,
    }
