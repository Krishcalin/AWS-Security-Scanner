#!/usr/bin/env python3
"""
aws_remediate.py — Remediation engine (CNAPP Phase 7, the "close the loop" pillar).

Turns findings + ranked attack paths + choke points into ACTION: a prioritized,
deduplicated remediation PLAN that fixes the choke points first (max attack-path
severance per fix), with remediation-as-code (Terraform / CloudFormation / AWS
CLI) for each action, plus export formats (markdown runbook, JSON, GitHub issue,
PR body).

Design invariants
-----------------
* **Pure** — stdlib + ``import aws_correlate`` only; NO boto3, NO I/O, NO
  ``now()``/``uuid`` inside the plan body (the scanner envelope owns timestamps),
  so golden output is byte-stable. Consumes already-materialized in-memory objects
  (Result duck-typed via ``.status/.check_id/.section/.resource/.message/.severity``,
  ``AttackPath``, ``ChokePoint``) and returns strings/dicts.
* **Reuse, don't re-rank** — ``aws_correlate.minimal_cut`` (greedy set-cover over
  CRITICAL/HIGH paths) IS the remediation priority; ``ChokePoint`` supplies every
  impact number. We never re-implement scoring.
* **Read-only** — GENERATES artifacts only. It never applies a change to the cloud
  or a repo, never opens a PR. (Any live mutation is a separate, loud, future opt-in.)
* **Severance honesty** — "removing this node severs the path" is a graph-topology
  claim; the generated code may not fully neutralize the specific edge, so every
  action carries a "residual: re-scan to confirm" note.
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import aws_correlate as C

_SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "": 0}


# ── safe template substitution ($name; missing -> '<NAME>', never raises) ─────
class _SafeMap:
    """Mapping for string.Template: a missing/None key renders as ``<KEY>`` (the
    REMEDIATION_MAP placeholder convention) so codegen never raises mid-scan.
    ``string.Template`` ($name) is used, not str.format, because Terraform/CFN
    snippets are full of literal braces."""

    def __init__(self, d: Dict):
        self._d = d or {}

    def __getitem__(self, k):
        v = self._d.get(k)
        return v if v is not None else "<" + str(k).upper() + ">"


def _safe_format(tmpl: str, params: Dict) -> str:
    if not tmpl:
        return ""
    # safe_substitute never raises: a missing $name -> '<NAME>' (via _SafeMap), and
    # a non-identifier sequence ('$?', '${aws_s3_bucket.b.id}', '${AWS::Region}')
    # passes through literally instead of raising ValueError.
    return string.Template(tmpl).safe_substitute(_SafeMap(params))


# ── codegen templates ─────────────────────────────────────────────────────────
@dataclass(frozen=True)
class FixTemplate:
    fix_key: str
    title: str
    category: str          # network|iam|data|encryption|patch|exposure|logging|other
    effort: str            # low|med|high
    blast_radius: str
    cli: str = ""
    terraform: str = ""
    cloudformation: str = ""
    manual: str = ""
    iac_managed: bool = True


@dataclass(frozen=True)
class CodeArtifact:
    cli: str
    terraform: str
    cloudformation: str
    manual: str
    iac_managed: bool

    def to_dict(self) -> dict:
        return {"cli": self.cli, "terraform": self.terraform,
                "cloudformation": self.cloudformation, "manual": self.manual,
                "iac_managed": self.iac_managed}


TEMPLATES: Dict[str, FixTemplate] = {
    "sg_scope_ingress": FixTemplate(
        "sg_scope_ingress", "Scope the open security-group ingress", "network", "med",
        "may drop legitimate clients on 0.0.0.0/0 — confirm the intended source range first",
        cli=("aws ec2 revoke-security-group-ingress --group-id $sg_id --protocol tcp "
             "--port $port --cidr 0.0.0.0/0\n"
             "# then re-add scoped to the intended source:\n"
             "aws ec2 authorize-security-group-ingress --group-id $sg_id --protocol tcp "
             "--port $port --cidr $cidr"),
        terraform=("# aws_security_group $sg_id — replace the open ingress CIDR:\n"
                   "- cidr_blocks = [\"0.0.0.0/0\"]\n"
                   "+ cidr_blocks = [\"$cidr\"]"),
        cloudformation=("# AWS::EC2::SecurityGroup ingress — replace CidrIp:\n"
                        "- CidrIp: 0.0.0.0/0\n+ CidrIp: $cidr")),
    "iam_boundary": FixTemplate(
        "iam_boundary", "Cap the over-privileged role with a permission boundary", "iam", "med",
        "boundary is a ceiling — verify the role's legitimate actions are within it before attaching",
        cli=("aws iam put-role-permissions-boundary --role-name $role_name "
             "--permissions-boundary $boundary_arn"),
        terraform=("# aws_iam_role $role_name:\n+ permissions_boundary = aws_iam_policy.cnapp_boundary.arn"),
        cloudformation=("# AWS::IAM::Role $role_name Properties:\n+ PermissionsBoundary: !Ref CnappBoundary")),
    "iam_scope_data": FixTemplate(
        "iam_scope_data", "Scope the role's data access + attach a boundary", "iam", "med",
        "removes broad s3:Get*/List* — confirm the role's real data needs first",
        cli=("# Tighten the role's S3 policy to the specific bucket/prefix, then:\n"
             "aws iam put-role-permissions-boundary --role-name $role_name "
             "--permissions-boundary $boundary_arn"),
        terraform="# Scope the aws_iam_role_policy for $role_name to the specific bucket ARN + prefix."),
    "patch_cve": FixTemplate(
        "patch_cve", "Patch the vulnerable package / rebuild the AMI", "patch", "high",
        "requires a maintenance window or a rolling AMI replacement", iac_managed=False,
        cli=("aws ssm send-command --document-name AWS-RunPatchBaseline "
             "--targets Key=instanceids,Values=$instance_id "
             "--parameters Operation=Install\n"
             "# then bake a patched AMI and roll the fleet"),
        terraform=("# Update the AMI id the instance/launch-template uses to a patched build:\n"
                   "- ami = \"ami-OLD\"\n+ ami = \"ami-PATCHED\"  # $cve fixed in $fixed_version"),
        manual="Patch $package to $fixed_version on $instance_id ($cve), then rebuild the AMI."),
    "s3_block_public": FixTemplate(
        "s3_block_public", "Block public access on the S3 bucket", "data", "low",
        "safe for private data buckets; do NOT apply to an intentional static-website/public bucket",
        cli=("aws s3api put-public-access-block --bucket $bucket "
             "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
             "BlockPublicPolicy=true,RestrictPublicBuckets=true"),
        terraform=("resource \"aws_s3_bucket_public_access_block\" \"$bucket\" {\n"
                   "  bucket = aws_s3_bucket.$bucket.id\n"
                   "  block_public_acls = true\n  ignore_public_acls = true\n"
                   "  block_public_policy = true\n  restrict_public_buckets = true\n}"),
        cloudformation=("# AWS::S3::Bucket $bucket Properties:\n"
                        "  PublicAccessBlockConfiguration:\n    BlockPublicAcls: true\n"
                        "    IgnorePublicAcls: true\n    BlockPublicPolicy: true\n"
                        "    RestrictPublicBuckets: true")),
    "encrypt_at_rest": FixTemplate(
        "encrypt_at_rest", "Enable encryption at rest", "encryption", "low",
        "new writes are encrypted; existing objects/volumes may need re-encryption",
        cli=("aws s3api put-bucket-encryption --bucket $bucket "
             "--server-side-encryption-configuration "
             "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'"),
        terraform=("# Add default encryption to the resource:\n"
                   "+ server_side_encryption_configuration { rule { "
                   "apply_server_side_encryption_by_default { sse_algorithm = \"aws:kms\" } } }")),
    "disable_public_access": FixTemplate(
        "disable_public_access", "Disable public accessibility", "exposure", "med",
        "confirm no external consumer relies on the public endpoint",
        cli="aws rds modify-db-instance --db-instance-identifier $resource --no-publicly-accessible --apply-immediately",
        terraform="# on the db/cluster resource $resource:\n- publicly_accessible = true\n+ publicly_accessible = false"),
    "_generic": FixTemplate(
        "_generic", "Remediate the finding", "other", "med",
        "review the finding before applying", iac_managed=False,
        cli="$remediation_cmd", manual="$message"),
}


# ── data shapes ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class RemediationAction:
    rank: int
    action_id: str
    title: str
    category: str
    effort: str
    fix_key: str
    target_node: str
    target_kind: Optional[str]
    target_resource: str
    is_choke: bool
    is_true_choke: bool
    paths_severed: int
    total_paths: int
    admin_paths_severed: int
    jewels_protected: Tuple[str, ...]
    severity: str
    resolved_check_ids: Tuple[str, ...]
    resolved_findings: Tuple[str, ...]
    resolved_edges: Tuple[str, ...]
    blast_radius: str
    code: CodeArtifact
    rationale: str
    iac_target: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "rank": self.rank, "action_id": self.action_id, "title": self.title,
            "category": self.category, "effort": self.effort, "fix_key": self.fix_key,
            "target_node": self.target_node, "target_kind": self.target_kind,
            "target_resource": self.target_resource, "is_choke": self.is_choke,
            "is_true_choke": self.is_true_choke, "paths_severed": self.paths_severed,
            "total_paths": self.total_paths, "admin_paths_severed": self.admin_paths_severed,
            "jewels_protected": list(self.jewels_protected), "severity": self.severity,
            "resolved_check_ids": list(self.resolved_check_ids),
            "resolved_findings": list(self.resolved_findings),
            "resolved_edges": list(self.resolved_edges), "blast_radius": self.blast_radius,
            "code": self.code.to_dict(), "rationale": self.rationale,
            "iac_target": self.iac_target,
        }


@dataclass(frozen=True)
class RemediationPlan:
    actions: Tuple[RemediationAction, ...]
    total_critical_paths: int
    critical_paths_cut_by_topk: Dict[int, int]
    n_choke_actions: int
    n_posture_actions: int
    generated_from: dict

    def headline(self) -> str:
        if self.n_choke_actions and self.total_critical_paths:
            k = self.n_choke_actions
            cut = self.critical_paths_cut_by_topk.get(k, 0)
            pct = round(100 * cut / self.total_critical_paths)
            return (f"Fix {k} item{'s' if k != 1 else ''} to cut {pct}% of critical "
                    f"attack paths ({cut}/{self.total_critical_paths})")
        if self.actions:
            return f"No correlated attack paths; {self.n_posture_actions} posture fix(es)"
        return "No findings to remediate"

    def to_dict(self) -> dict:
        return {
            "headline": self.headline(),
            "total_critical_paths": self.total_critical_paths,
            "critical_paths_cut_by_topk": {str(k): v for k, v in
                                           sorted(self.critical_paths_cut_by_topk.items())},
            "n_choke_actions": self.n_choke_actions,
            "n_posture_actions": self.n_posture_actions,
            "generated_from": self.generated_from,
            "actions": [a.to_dict() for a in self.actions],
        }


# ── helpers ───────────────────────────────────────────────────────────────────
def _sev_ge(sev: str, floor: str) -> bool:
    return _SEV_ORDER.get(sev, 0) >= _SEV_ORDER.get(floor, 0)


def _resource_keys(node_id: str, node_props: Dict) -> set:
    """Identifiers a finding's `resource` might use for this graph node."""
    keys = {node_id}
    if "/" in node_id:
        keys.add(node_id.rsplit("/", 1)[-1])
    if ":" in node_id:
        keys.add(node_id.rsplit(":", 1)[-1])
    props = node_props or {}
    for k in ("instance_id", "name", "bucket", "role_name"):
        if props.get(k):
            keys.add(str(props[k]))
    if node_id.startswith("arn:aws:s3:::"):
        keys.add(node_id[len("arn:aws:s3:::"):].split("/")[0])
    return {k for k in keys if k}


_SECTION_KIND = {"S3": "S3Bucket", "EC2": "EC2Instance", "RDS": "RDS",
                 "LAMBDA": "Lambda", "DYNAMODB": "DynamoDB"}


def _canon_kind_for_result(r) -> str:
    """A code-to-cloud canonical kind for a posture finding, from its ARN/section,
    so the matcher is type-gated (never an empty type that would match any type)."""
    res = _res_of_result(r)
    if ":role/" in res:
        return "IAMRole"
    if ":user/" in res:
        return "IAMUser"
    return _SECTION_KIND.get(getattr(r, "section", ""), "")


def _res_of_result(r) -> str:
    """The resource a Result points at (its .resource, or the '| <res>' suffix)."""
    res = getattr(r, "resource", "") or ""
    msg = getattr(r, "message", "") or ""
    if "|" in msg:
        tail = msg.rsplit("|", 1)[-1].strip()
        if tail:
            return tail
    return res


def _select_fix_key(kind: Optional[str], edge_kinds: set, check_ids: set) -> str:
    """Pick the fix template. For a GRAPH NODE, its kind + own out-edges are
    decisive (a role's fix is a boundary regardless of what CVE sits elsewhere on
    the path); `check_ids` is only the fallback for a posture action (kind=None)."""
    # 1. graph-node kind + its OWN out-edges are decisive
    if kind in ("NetworkInterface", "SecurityGroup") or "EXPOSED_TO" in edge_kinds:
        return "sg_scope_ingress"
    if kind in ("IAMRole", "InstanceProfile") or "CAN_PRIVESC_TO" in edge_kinds:
        return "iam_boundary"           # a boundary caps privesc AND data access
    if "CAN_READ_DATA" in edge_kinds:
        return "iam_scope_data"
    if "HAS_VULN" in edge_kinds:        # patch ONLY when a vuln actually gates the path
        return "patch_cve"
    if kind == "EC2Instance":
        # an exposed instance with no vuln on it — the severed path is privilege/
        # reachability driven, so the fix is on the role it can reach, NOT a
        # nonsensical "patch <CVE>" with no CVE.
        return "iam_boundary" if "HAS_INSTANCE_PROFILE" in edge_kinds else "_generic"
    if kind == "S3Bucket":
        return "s3_block_public"
    # 2. check-id fallback (posture actions have no graph node)
    if check_ids & {"VULN-01", "VULN-02", "CWPP-01", "CWPP-02"}:
        return "patch_cve"
    if any(c.startswith("IAMPE-") for c in check_ids) or "ATTACK-01" in check_ids:
        return "iam_boundary"
    if "EXTACCESS-03" in check_ids:
        return "iam_scope_data"
    if check_ids & {"S3-01", "DATA-02", "EXTACCESS-01"}:
        return "s3_block_public"
    if check_ids & {"S3-03", "DATA-03", "EBS-01", "EBS-02", "EC2-06", "ENC-03"}:
        return "encrypt_at_rest"
    if check_ids & {"RDS-02", "RS-02", "OSR-04"}:
        return "disable_public_access"
    if check_ids & {"EXPOSURE-01", "EXPOSURE-02", "VPC-01"}:
        return "sg_scope_ingress"
    return "_generic"


def _extract_params(node_id, node_props, out_edges, resolved_results, region, account) -> Dict:
    props = node_props or {}
    params: Dict[str, object] = {
        "region": region or "<REGION>", "account": account or "<ACCOUNT>",
        "role_name": props.get("name") or props.get("role_name"),
        "instance_id": props.get("instance_id"),
        "boundary_arn": f"arn:aws:iam::{account or '<ACCOUNT>'}:policy/cnapp-boundary",
    }
    if node_id.startswith("arn:aws:s3:::"):
        params["bucket"] = node_id[len("arn:aws:s3:::"):].split("/")[0]
    params.setdefault("bucket", props.get("bucket"))
    params["resource"] = props.get("name") or props.get("instance_id") or node_id
    # from edges: security-group id, port, cve
    for e in out_edges or []:
        ep = e.get("props", {})
        if e.get("kind") == "EXPOSED_TO":
            params.setdefault("sg_id", ep.get("sg_id") or (ep.get("sg_ids") or [None])[0]
                              if isinstance(ep.get("sg_ids"), list) else ep.get("sg_id"))
            ports = ep.get("ports", "")
            if isinstance(ports, str) and "/" in ports:
                params.setdefault("port", ports.split("/")[-1])
        if e.get("kind") == "HAS_VULN":
            params.setdefault("cve", ep.get("cve"))
            params.setdefault("fixed_version", ep.get("fixed_version"))
            params.setdefault("package", ep.get("package"))
    # from resolved findings (cve in message)
    for r in resolved_results:
        msg = getattr(r, "message", "") or ""
        if "CVE-" in msg and not params.get("cve"):
            import re
            m = re.search(r"CVE-\d{4}-\d+", msg)
            if m:
                params["cve"] = m.group(0)
    params.setdefault("port", "0")
    params.setdefault("cidr", "<YOUR_CIDR>")
    params.setdefault("remediation_cmd",
                      next((getattr(r, "remediation_cmd", "") for r in resolved_results
                            if getattr(r, "remediation_cmd", "")), ""))
    params.setdefault("message",
                      next((getattr(r, "message", "") for r in resolved_results), ""))
    return params


def render(fix_key: str, params: Dict, templates: Optional[Dict] = None) -> CodeArtifact:
    reg = templates or TEMPLATES
    t = reg.get(fix_key) or reg["_generic"]
    return CodeArtifact(
        cli=_safe_format(t.cli, params), terraform=_safe_format(t.terraform, params),
        cloudformation=_safe_format(t.cloudformation, params),
        manual=_safe_format(t.manual, params), iac_managed=t.iac_managed)


# ── the plan builder ──────────────────────────────────────────────────────────
def build_plan(results: Sequence, attack_paths: Sequence, choke_points: Sequence,
               node_kind: Callable[[str], Optional[str]], label_of: Optional[Callable] = None, *,
               node_props: Optional[Callable] = None, out_edges: Optional[Callable] = None,
               templates: Optional[Dict] = None, min_severity: str = "MEDIUM",
               include_posture: bool = True, effperm: Optional[Callable] = None,
               iac_matcher: Optional[Callable] = None, region: str = "",
               account: str = "") -> RemediationPlan:
    """Build a prioritized remediation plan. Choke actions come first (ordered by
    ``minimal_cut``), then a deduped posture long-tail. Pure + deterministic."""
    results = list(results or [])
    attack_paths = list(attack_paths or [])
    choke_points = list(choke_points or [])
    props_of = node_props or (lambda n: {})
    edges_of = out_edges or (lambda n: [])
    label = label_of or (lambda n: n)

    crit_hi = [p for p in attack_paths if getattr(p, "severity", "") in ("CRITICAL", "HIGH")]
    crit_paths = [p for p in attack_paths if getattr(p, "severity", "") == "CRITICAL"]
    total_critical = len(crit_paths)

    # Build a resource -> results index for the resource join.
    res_index: Dict[str, List] = {}
    for r in results:
        if getattr(r, "status", "") in ("FAIL", "WARN"):
            res_index.setdefault(_res_of_result(r), []).append(r)

    cut = C.minimal_cut(attack_paths, node_kind)
    choke_by = {c.node_id: c for c in choke_points}

    actions: List[RemediationAction] = []
    used_findings: set = set()
    # first-cover attribution: which cut node first covers each critical path
    covered_crit: set = set()
    cut_cover_by_rank: Dict[int, int] = {}

    for i, node in enumerate(cut, start=1):
        kind = node_kind(node)
        props = props_of(node) or {}
        oe = edges_of(node) or []
        edge_kinds = {e.get("kind") for e in oe}
        thru = [p for p in crit_hi if node in set(getattr(p, "nodes", ())[1:-1])]

        ch = choke_by.get(node)
        if ch is not None:
            paths_severed, total_paths = ch.paths_severed, ch.total_paths
            jewels = ch.targets_fully_blocked
            is_true = ch.is_true_choke
        else:                                   # defensive synthesis
            paths_severed = len(thru)
            total_paths = len(crit_hi)
            jewels = tuple(sorted({p.terminal for p in thru
                                   if getattr(p, "terminal_kind", "") == "data"}))
            is_true = False
        admin_severed = sum(1 for p in thru if getattr(p, "terminal_kind", "") == "admin")

        # resolved findings: resource join + path join
        keys = _resource_keys(node, props)
        resolved_results = []
        for k in keys:
            resolved_results += res_index.get(k, [])
        # fix-key selection uses the node's OWN findings only (resource join), not
        # the whole path's driving_findings (which describe other hops).
        own_check_ids = {getattr(r, "check_id", "") for r in resolved_results}
        own_check_ids.discard("")
        check_ids: set = set(own_check_ids)
        for p in thru:
            for df in getattr(p, "driving_findings", ()):
                check_ids.add(str(df).split(":")[0])
        check_ids.discard("")

        fix_key = _select_fix_key(kind, edge_kinds, own_check_ids)
        params = _extract_params(node, props, oe, resolved_results, region, account)
        if effperm and kind in ("IAMRole", "InstanceProfile"):
            try:
                acts = effperm(node)
                if acts:
                    params["boundary_actions"] = ",".join(sorted(acts))
            except Exception:
                pass
        code = render(fix_key, params, templates)
        tmpl = (templates or TEMPLATES).get(fix_key, TEMPLATES["_generic"])

        resolved_findings = tuple(sorted(
            f"{getattr(r, 'check_id', '')}@{_res_of_result(r)}" for r in resolved_results))
        for r in resolved_results:
            used_findings.add((getattr(r, "check_id", ""), _res_of_result(r)))

        # first-cover accounting for the headline
        for p in thru:
            if getattr(p, "severity", "") == "CRITICAL":
                pid = id(p)
                if pid not in covered_crit:
                    covered_crit.add(pid)
                    cut_cover_by_rank[i] = cut_cover_by_rank.get(i, 0) + 1

        iac_target = None
        if iac_matcher is not None:
            try:
                m = iac_matcher(params.get("resource", node), kind or "", props.get("tags", {}))
                iac_target = m.to_dict() if m is not None else None
            except Exception:
                iac_target = None

        sev = "CRITICAL" if any(getattr(p, "severity", "") == "CRITICAL" for p in thru) else \
              ("HIGH" if thru else "MEDIUM")
        actions.append(RemediationAction(
            rank=i, action_id=f"REMED-{i:03d}", title=tmpl.title, category=tmpl.category,
            effort=tmpl.effort, fix_key=fix_key, target_node=node, target_kind=kind,
            target_resource=label(node) if callable(label) else node,
            is_choke=ch is not None, is_true_choke=is_true, paths_severed=paths_severed,
            total_paths=total_paths, admin_paths_severed=admin_severed, jewels_protected=jewels,
            severity=sev, resolved_check_ids=tuple(sorted(check_ids)),
            resolved_findings=resolved_findings, resolved_edges=tuple(sorted(edge_kinds - {None})),
            blast_radius=tmpl.blast_radius, code=code,
            rationale=(f"Choke point: fixing {label(node)} severs {paths_severed}/"
                       f"{total_paths} attack path(s)" + (", removing every known path to "
                       f"{len(jewels)} crown jewel(s)" if is_true and jewels else "") +
                       ". residual: re-scan to confirm the edge is gone."),
            iac_target=iac_target))

    n_choke = len(actions)

    # cumulative first-cover: paths cut by the top-k choke actions
    cut_by_topk: Dict[int, int] = {}
    running = 0
    for k in range(1, n_choke + 1):
        running += cut_cover_by_rank.get(k, 0)
        cut_by_topk[k] = running

    # posture long-tail (deduped by fix_key+resource), excluding already-resolved
    n_posture = 0
    if include_posture:
        posture: Dict[Tuple[str, str], List] = {}
        for r in results:
            if getattr(r, "status", "") not in ("FAIL", "WARN"):
                continue
            if not _sev_ge(getattr(r, "severity", ""), min_severity):
                continue
            key = (getattr(r, "check_id", ""), _res_of_result(r))
            if key in used_findings:
                continue
            cid = getattr(r, "check_id", "")
            fk = _select_fix_key(None, set(), {cid})
            posture.setdefault((fk, _res_of_result(r)), []).append(r)

        def _psev(group):
            return max((_SEV_ORDER.get(getattr(r, "severity", ""), 0) for r in group), default=0)

        ordered = sorted(posture.items(), key=lambda kv: (-_psev(kv[1]), kv[0][0], kv[0][1]))
        for (fk, res), group in ordered:
            n_posture += 1
            rank = n_choke + n_posture
            r0 = group[0]
            params = _extract_params(res, {}, [], group, region, account)
            code = render(fk, params, templates)
            tmpl = (templates or TEMPLATES).get(fk, TEMPLATES["_generic"])
            worst = max(group, key=lambda r: _SEV_ORDER.get(getattr(r, "severity", ""), 0))
            iac_target = None
            if iac_matcher is not None:
                try:
                    m = iac_matcher(res, _canon_kind_for_result(worst), {})
                    iac_target = m.to_dict() if m is not None else None
                except Exception:
                    iac_target = None
            actions.append(RemediationAction(
                rank=rank, action_id=f"REMED-{rank:03d}", title=tmpl.title, category=tmpl.category,
                effort=tmpl.effort, fix_key=fk, target_node=res, target_kind=None,
                target_resource=res, is_choke=False, is_true_choke=False, paths_severed=0,
                total_paths=len(crit_hi), admin_paths_severed=0, jewels_protected=(),
                severity=getattr(worst, "severity", "") or "MEDIUM",
                resolved_check_ids=tuple(sorted({getattr(r, "check_id", "") for r in group})),
                resolved_findings=tuple(sorted(f"{getattr(r, 'check_id', '')}@{_res_of_result(r)}"
                                               for r in group)),
                resolved_edges=(), blast_radius=tmpl.blast_radius, code=code,
                rationale=f"Posture fix: {getattr(r0, 'message', '')[:120]}", iac_target=iac_target))

    return RemediationPlan(
        actions=tuple(actions), total_critical_paths=total_critical,
        critical_paths_cut_by_topk=cut_by_topk, n_choke_actions=n_choke,
        n_posture_actions=n_posture,
        generated_from={"attack_paths": len(attack_paths), "choke_points": len(choke_points),
                        "findings": sum(1 for r in results
                                        if getattr(r, "status", "") in ("FAIL", "WARN")),
                        "min_severity": min_severity})


# ── exports (deterministic) ──────────────────────────────────────────────────
def plan_to_json(plan: RemediationPlan) -> dict:
    return plan.to_dict()


def _code_block(code: CodeArtifact, prefer: str = "cli") -> str:
    lang = {"cli": "bash", "terraform": "hcl", "cloudformation": "yaml"}.get(prefer, "text")
    body = getattr(code, prefer, "") or code.cli or code.manual
    return f"```{lang}\n{body}\n```"


def to_markdown(plan: RemediationPlan, *, title: str = "Remediation Runbook",
                top_k: Optional[int] = None) -> str:
    lines = [f"# {title}", "", f"**{plan.headline()}**", ""]
    acts = plan.actions[:top_k] if top_k else plan.actions
    if plan.n_choke_actions:
        lines.append(f"Fixing the top {plan.n_choke_actions} choke point(s) below severs the "
                     f"most critical attack paths first.\n")
    for a in acts:
        tag = "🔴 CHOKE" if a.is_choke else "posture"
        lines.append(f"## {a.rank}. {a.title}  ·  {a.severity}  ·  effort: {a.effort}  ·  {tag}")
        lines.append(f"- **Target**: `{a.target_resource}` ({a.target_kind or 'resource'})")
        if a.is_choke:
            lines.append(f"- **Impact**: severs {a.paths_severed}/{a.total_paths} attack path(s)"
                         + (f", protects {len(a.jewels_protected)} crown jewel(s)"
                            if a.jewels_protected else "")
                         + (f", {a.admin_paths_severed} to admin" if a.admin_paths_severed else ""))
        if a.resolved_check_ids:
            lines.append(f"- **Resolves**: {', '.join(a.resolved_check_ids)}")
        if a.iac_target:
            lines.append(f"- **IaC source**: `{a.iac_target.get('file')}:"
                         f"{a.iac_target.get('line')}` ({a.iac_target.get('confidence')})")
        lines.append(f"- **Blast radius**: {a.blast_radius}")
        lines.append("")
        prefer = "terraform" if (a.iac_target and a.code.iac_managed and a.code.terraform) else "cli"
        lines.append(_code_block(a.code, prefer))
        lines.append("")
    return "\n".join(lines)


def to_github_issue(plan: RemediationPlan, *, top_k: int = 10) -> str:
    lines = [f"### {plan.headline()}", ""]
    for a in plan.actions[:top_k]:
        impact = (f" — severs {a.paths_severed}/{a.total_paths} path(s)"
                  if a.is_choke else "")
        lines.append(f"- [ ] **{a.title}** on `{a.target_resource}` "
                     f"({a.severity}, effort {a.effort}){impact}")
    return "\n".join(lines)


def to_github_pr_body(plan: RemediationPlan, *, iac: str = "terraform") -> str:
    lines = [f"## {plan.headline()}", "",
             "Auto-generated remediation proposals (review before merging — the scanner "
             "does not apply changes).", ""]
    for a in plan.actions:
        if not (a.code.iac_managed and getattr(a.code, iac, "")):
            continue
        anchor = (f" — `{a.iac_target.get('file')}:{a.iac_target.get('line')}`"
                  if a.iac_target else "")
        lines.append(f"### {a.rank}. {a.title}{anchor}")
        lines.append(_code_block(a.code, iac))
        lines.append("")
    return "\n".join(lines)
