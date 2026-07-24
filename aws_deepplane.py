#!/usr/bin/env python3
"""aws_deepplane.py — pure parsing/classification core for CNAPP Phase 3 (deep-plane ingestion).

Phase 3 BUYS commodity deep-plane signal from AWS-native services rather than
building snapshot side-scanning: Amazon Inspector v2 (package CVEs + EPSS + KEV),
Amazon Macie (S3 sensitive-data classification), IAM Access Analyzer (authoritative
external access), and GuardDuty (live threat detections). Each becomes a graph edge
that, together with the Phase 1/2 identity + exposure subgraphs, materializes the
FLAGSHIP toxic combination:

    Internet → exposed EC2 → exploitable/KEV CVE → over-privileged role → crown-jewel data

This module holds the boto3-FREE logic — finding parsers, the crown-jewel score-trap
classifier, the CAN_READ_DATA object-probe matcher, and the GuardDuty resource mapper —
so the whole false-positive/false-negative catalog (esp. "service disabled → no signal,
never a false positive") runs without AWS. The thin, enablement-gated collectors live in
aws_live_scanner.py and call these functions. Grounded in a verified AWS-API research pass.
"""
from __future__ import annotations

from fnmatch import fnmatch
from typing import Dict, List, Optional, Tuple

# ─── sensitive-service ports / thresholds ────────────────────────────────────
# Macie automated sensitivity score is 0-100; ~50 is the neutral "not-yet-analyzed"
# default, -1 is a classification error, 1 is an empty bucket. Only a real score
# strictly above the default, on a bucket with classifiable objects, is a crown jewel.
MACIE_DEFAULT_SCORE = 50
# FIRST.org EPSS is a probability 0..1 (NOT a 0..100 percentile). Exploit-likely at >=0.5.
EPSS_HIGH = 0.5


# ─── Inspector v2 → HAS_VULN ─────────────────────────────────────────────────
def parse_inspector_finding(f: dict) -> Optional[Dict]:
    """Normalize one Inspector2 PACKAGE_VULNERABILITY finding into the fields we
    graph. Returns None if it carries no CVE. EPSS (`epss.score`) and
    `exploitAvailable` are native on list_findings; the authoritative CISA-KEV
    flag is NOT — it needs a `batch_get_finding_details` second hop (see
    `finding_kev`). Never invents exploit/kev when absent (fail closed)."""
    if not f:
        return None
    pvd = f.get("packageVulnerabilityDetails") or {}
    cve = pvd.get("vulnerabilityId")
    if not cve:
        return None
    resources = f.get("resources") or []
    res = resources[0] if resources else {}
    epss = None
    epss_obj = f.get("epss")
    if isinstance(epss_obj, dict):
        epss = epss_obj.get("score")
    cvss_base = None
    for c in pvd.get("cvss") or []:
        if c.get("baseScore") is not None:
            cvss_base = c["baseScore"]
            break
    fixed_in = None
    for p in pvd.get("vulnerablePackages") or []:
        if p.get("fixedInVersion"):
            fixed_in = p["fixedInVersion"]
            break
    return {
        "cve": str(cve).upper(),
        "severity": f.get("severity", "UNTRIAGED"),
        "epss": epss,
        "cvss_base": cvss_base,
        "exploit_available": f.get("exploitAvailable"),   # "YES" | "NO" | None
        "fix_available": f.get("fixAvailable"),
        "fixed_in": fixed_in,
        "inspector_score": f.get("inspectorScore"),
        "finding_arn": f.get("findingArn"),
        "resource_id": res.get("id"),                     # bare i-… / image ARN / fn ARN
        "resource_type": res.get("type"),                 # AWS_EC2_INSTANCE | ...
    }


def finding_kev(finding_details: Optional[dict]) -> bool:
    """True iff a `batch_get_finding_details` record puts the CVE on the CISA KEV
    catalog (`cisaData.dateAdded` present). KEV is the strong in-the-wild signal;
    do NOT equate it with `exploitAvailable==YES`."""
    if not finding_details:
        return False
    cd = finding_details.get("cisaData")
    return bool(cd and cd.get("dateAdded"))


def is_exploitable(vuln: dict) -> bool:
    """A vuln node is 'exploitable' for attack-path pivoting if it is on KEV, has
    an exploit available, or a high EPSS probability."""
    if vuln.get("kev"):
        return True
    if str(vuln.get("exploit_available", "")).upper() == "YES":
        return True
    epss = vuln.get("epss")
    return isinstance(epss, (int, float)) and epss >= EPSS_HIGH


def vuln_finding_id(vuln: dict) -> str:
    """VULN-02 (CRITICAL) for KEV/in-the-wild; VULN-01 (HIGH) for other
    active exploitable/high-severity package vulns."""
    return "VULN-02" if vuln.get("kev") else "VULN-01"


# ─── Macie → crown-jewel classification ──────────────────────────────────────
def is_crown_jewel(bucket: dict, has_sensitive_finding: bool = False) -> Optional[Dict]:
    """Decide if a Macie `describe_buckets` entry is a crown jewel (holds sensitive
    data). Handles the score-semantics traps: -1 (classification error), 1 (empty),
    50 (default / not-yet-analyzed), and `classifiableObjectCount == 0` are all
    treated as UNKNOWN — never crown-jewel — to avoid false positives. A real
    automated score strictly above the neutral default on a bucket with classifiable
    objects, OR a confirmed non-archived SensitiveData finding, qualifies. Returns
    the node props, or None if not a (known) crown jewel."""
    if not bucket:
        return None
    cnt = bucket.get("classifiableObjectCount", 0) or 0
    score = bucket.get("sensitivityScore")
    crown = False
    if has_sensitive_finding:
        crown = True
    elif isinstance(score, (int, float)) and cnt > 0 and score > MACIE_DEFAULT_SCORE:
        crown = True
    if not crown:
        return None
    pub = (bucket.get("publicAccess") or {}).get("effectivePermission") == "PUBLIC"
    shared = bucket.get("sharedAccess") == "EXTERNAL"
    sse = (bucket.get("serverSideEncryption") or {}).get("type", "NONE")
    return {
        "crown_jewel": True,
        "sensitivity": score if isinstance(score, (int, float)) else None,
        "public": pub,
        "shared": shared,
        "encrypted": sse != "NONE",
    }


# ─── CAN_READ_DATA: identity-policy → crown-jewel S3 ─────────────────────────
def _actions_match(action_patterns, action: str) -> bool:
    return any(fnmatch(action, p) for p in action_patterns)


def role_can_read_bucket(statements: List[dict], bucket_arn: str) -> Optional[Dict]:
    """Decide whether a principal's effective identity statements grant OBJECT read
    on a bucket, and return `{conditioned: bool}` or None.

    The load-bearing trick is a WILDCARD-FREE object probe `arn:aws:s3:::bucket/probe`:
    a policy Resource of `…:bucket/*` or `*` matches it (real GetObject grant), while a
    bare bucket ARN `…:bucket` does NOT — so `s3:ListBucket` (scoped to the bucket ARN,
    not the object namespace) can never masquerade as data read. Deny wins over Allow.
    Statement actions/resources are the lowercased forms produced by the policy parser.
    Identity-policy read is necessary-not-sufficient (bucket policy / SCP / boundary /
    BPA are deferred), so the edge is always 'paths-to-verify'.
    """
    barn = bucket_arn.lower().rstrip("/")
    probe = barn + "/probe"                       # concrete object ARN, no wildcards
    READ = "s3:getobject"

    def _covers(patterns) -> bool:
        # An empty/absent set covers NOTHING for a concrete probe (no '*' fallback):
        # a malformed empty Resource must not read as "all objects".
        return any(p == "*" or fnmatch(probe, p) for p in (patterns or set()))

    allow = deny = False
    conditioned_all = True
    for st in statements:
        if not _actions_match(st.get("actions", set()), READ):
            continue
        if not _covers(st.get("resources")):
            continue
        # NotResource guardrail: `Allow s3:GetObject NotResource crown/*` grants
        # everything EXCEPT the crown jewel — so if the probe is excluded, no read.
        if _covers(st.get("not_resources")):
            continue
        if st.get("effect") == "Deny":
            deny = True
        elif st.get("effect") == "Allow":
            allow = True
            if not st.get("condition"):
                conditioned_all = False
    if deny or not allow:
        return None                                # Deny precedence / no grant
    return {"conditioned": conditioned_all}


# ─── Phase 7 DSPM: tag-driven crown jewels + non-S3 CAN_READ_DATA ─────────────
_DSPM_CLASSIFICATION_KEYS = frozenset({
    "dataclassification", "classification", "sensitivity", "datasensitivity",
    "compliance", "datacategory", "confidentiality"})
_DSPM_BOOLEAN_KEYS = frozenset({"pii", "phi", "crownjewel"})
_DSPM_SENSITIVE_VALUES = frozenset({
    "sensitive", "confidential", "restricted", "pii", "phi", "pci", "secret",
    "critical", "high",
    # regulated-data compliance frameworks (as a Compliance=<framework> tag value)
    "hipaa", "gdpr", "sox", "glba", "ferpa", "pci-dss", "pcidss"})
_DSPM_TRUTHY = frozenset({"true", "yes", "1", "enabled", "y", "t"})


def _dspm_norm_key(raw: str) -> str:
    """Normalize a tag key for classification lookup: lowercase + drop the separators
    that distinguish otherwise-identical keys (``Data-Classification`` / ``data_classification``
    / ``Data Classification`` all fold to ``dataclassification``)."""
    k = (raw or "").strip().lower()
    for sep in ("-", "_", " ", "."):
        k = k.replace(sep, "")
    return k

# read-action sets per crown datastore kind (lowercased for fnmatch vs `dynamodb:*` etc.)
DSPM_READ_ACTIONS = {
    "dynamodbtable": frozenset({"dynamodb:getitem", "dynamodb:query", "dynamodb:scan",
                                "dynamodb:batchgetitem", "dynamodb:partiqlselect"}),
    "efsfilesystem": frozenset({"elasticfilesystem:clientmount"}),
    "redshiftcluster": frozenset({"redshift:getclustercredentials",
                                  "redshift-data:executestatement",
                                  "redshift-data:batchexecutestatement",
                                  "redshift-data:getstatementresult",
                                  "redshift-serverless:getcredentials"}),
    "rdsinstance": frozenset({"rds-db:connect", "rds-data:executestatement",
                              "rds-data:batchexecutestatement", "rds-data:executesql"}),
    "rdscluster": frozenset({"rds-db:connect", "rds-data:executestatement",
                             "rds-data:batchexecutestatement", "rds-data:executesql"}),
    # ── Slice 1: expanded DSPM datastore surfaces ────────────────────────────
    # es:ESHttp* authorizes on the domain's HTTP PATH sub-resource (arn:...:domain/<name>/*),
    # NOT the bare domain ARN — so the collector probes a path sub-resource (see
    # _dspm_opensearch read_probe), otherwise the AWS-documented `domain/<name>/*` reader
    # grant is a false negative. (kinesis/timestream below DO authorize on the bare ARN.)
    "opensearchdomain": frozenset({"es:eshttpget", "es:eshttphead", "es:eshttppost"}),
    # PRECISE — a real IAM data action whose resource is the store's own (bare) ARN:
    "kinesisstream": frozenset({"kinesis:getrecords", "kinesis:getsharditerator",
                                "kinesis:subscribetoshard"}),
    "timestreamtable": frozenset({"timestream:select"}),
    # COARSE (neptune-db:* actions authorize on a dbuser resource, not the cluster ARN,
    # so only *-or-service-wildcard grants match the cluster probe — a conservative FN,
    # same class as the RDS/Redshift credential actions above):
    "neptunecluster": frozenset({"neptune-db:connect", "neptune-db:readdataviaquery",
                                 "neptune-db:getquerystatus"}),
    # NO IAM data action (Mongo user auth / Redis ACL / NFS+SMB posix auth are all
    # out-of-band) → empty set → role_can_read_store returns None → the crown node is
    # emitted but carries NO CAN_READ_DATA edge (documented false-negative):
    "docdbcluster": frozenset(),
    "memorydbcluster": frozenset(),
    "fsxfilesystem": frozenset(),
}


def is_crown_jewel_by_tags(tags, extra_keys=frozenset(), extra_values=frozenset()
                           ) -> Optional[Dict]:
    """Conservative tag-driven crown-jewel classifier (no Macie needed). Two tiers:
    CLASSIFICATION keys (DataClassification/Classification/Sensitivity/…) require an
    EXACT sensitive value (so 'high-availability' != 'high' — no substring FP); BOOLEAN
    keys (pii/phi/crownjewel) qualify on a truthy value OR any sensitive value.
    ``tags`` is a list of ``{'Key','Value'}`` dicts. ``environment=prod`` deliberately
    does NOT qualify (too broad — an operator opts it in via ``extra_keys``). Returns
    ``{crown, sensitivity, matched:(Key,Value)}`` or None."""
    class_keys = _DSPM_CLASSIFICATION_KEYS | {_dspm_norm_key(k) for k in extra_keys}
    sens_values = _DSPM_SENSITIVE_VALUES | {v.strip().lower() for v in extra_values}
    for t in tags or []:
        key = _dspm_norm_key(t.get("Key"))          # F5: fold -/_/space/. separators
        val = (t.get("Value") or "").strip().lower()
        if key in class_keys and val in sens_values:
            return {"crown": True, "sensitivity": val,
                    "matched": (t.get("Key"), t.get("Value"))}
        if key in _DSPM_BOOLEAN_KEYS and (val in _DSPM_TRUTHY or val in sens_values):
            return {"crown": True,
                    "sensitivity": (val if val in sens_values else "flagged"),
                    "matched": (t.get("Key"), t.get("Value"))}
    return None


def role_can_read_store(statements: List[dict], resource_arn: str,
                        read_actions) -> Optional[Dict]:
    """Sibling of ``role_can_read_bucket`` for the Phase-7 DSPM datastores. ``read_actions``
    is the lowercased action set for the store kind. The probe is the store's OWN ARN:
    DynamoDB/EFS match PRECISELY; RDS/Redshift credential actions have a dbuser-ARN real
    resource, so only ``*``/service-wildcard grants match the instance/cluster ARN — a
    coarse-but-safe result (narrowly-scoped dbuser policies drop the edge: a conservative
    FN, documented). Deny wins over Allow; NotResource excludes; identity-only so the edge
    is always 'paths-to-verify'."""
    probe = resource_arn.lower().rstrip("/")

    def _covers(patterns) -> bool:
        return any(p == "*" or fnmatch(probe, p) for p in (patterns or set()))

    def _grants(st_actions) -> bool:
        return any(_actions_match(st_actions, ra) for ra in read_actions)

    allow = deny = False
    conditioned_all = True
    for st in statements:
        if not _grants(st.get("actions", set())):
            continue
        if not _covers(st.get("resources")):
            continue
        if _covers(st.get("not_resources")):          # NotResource excludes the store -> no read
            continue
        if st.get("effect") == "Deny":
            deny = True
        elif st.get("effect") == "Allow":
            allow = True
            if not st.get("condition"):
                conditioned_all = False
    if deny or not allow:
        return None                                   # Deny precedence / no grant
    return {"conditioned": conditioned_all}


# ─── GuardDuty → THREAT_ON ───────────────────────────────────────────────────
def severity_band(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Unknown"
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    return "Low"


def map_guardduty_finding(f: dict) -> Optional[Dict]:
    """Map an active GuardDuty finding onto the graph node it names. Returns
    `{id, type, severity, band, node_kind, node_key}` (node_kind/key may be None
    when the finding type carries no mappable resource — kept as context, no
    THREAT_ON edge). Filters out archived and [SAMPLE] findings (the latter poison
    prioritization). Branches strictly on `Resource.ResourceType` to avoid
    KeyError/None on the type-specific sub-objects."""
    if not f:
        return None
    if (f.get("Service") or {}).get("Archived"):
        return None
    if "[SAMPLE]" in (f.get("Title", "") or "") or "[SAMPLE]" in (f.get("Type", "") or ""):
        return None
    sev = f.get("Severity", 0.0)
    res = f.get("Resource") or {}
    rtype = res.get("ResourceType", "")
    node_kind = node_key = None
    if rtype == "Instance":
        iid = (res.get("InstanceDetails") or {}).get("InstanceId")
        if iid:
            node_kind, node_key = "EC2Instance", iid
    elif rtype == "S3Bucket":
        buckets = res.get("S3BucketDetails") or []
        if buckets and buckets[0].get("Name"):
            node_kind, node_key = "S3Bucket", buckets[0]["Name"]
    elif rtype == "AccessKey":
        ak = res.get("AccessKeyDetails") or {}
        if ak.get("UserName"):
            node_kind, node_key = "IAMPrincipal", ak["UserName"]
    return {
        "id": f.get("Id"),
        "type": f.get("Type"),
        "severity": sev,
        "band": severity_band(sev),
        "node_kind": node_kind,
        "node_key": node_key,
    }


# ─── IAM Access Analyzer (external access) ───────────────────────────────────
def classify_external_access(detail: dict) -> Optional[Dict]:
    """Normalize a get_finding_v2 ExternalAccess detail into
    `{is_public, principal, action}`. `is_public` (Principal AWS '*') originates
    from the internet; otherwise it is a named cross-account external principal."""
    if not detail:
        return None
    ext = detail.get("externalAccessDetails")
    if not ext:
        return None
    principal = ext.get("principal") or {}
    is_public = bool(ext.get("isPublic")) or principal.get("AWS") == "*"
    actions = ext.get("action") or []
    return {
        "is_public": is_public,
        "principal": principal,
        "action": actions[0] if actions else None,
    }
