#!/usr/bin/env python3
"""
aws_codetocloud.py — map a live cloud finding back to the IaC resource that
declared it (CNAPP Phase 7, the 2nd "close the loop" pillar). PURE: stdlib only
(json always; yaml best-effort if installed), string-fixture testable, NO boto3.

Why: remediation should target the SOURCE, not the runtime. When a live finding
maps to a Terraform/CloudFormation resource, the remediation engine can propose
the IaC DIFF (edit the source block) anchored to file:line, instead of a
one-off runtime CLI fix.

Matching is TIERED by confidence (never guesses — a wrong match is worse than no
match, because it would propose editing the wrong code):
  T1 HIGH   exact physical-name (bucket/role/function/db name == IaC physical name)
  T2 HIGH   unique tag match (a distinctive tag shared with exactly one resource)
  T3 MEDIUM CloudFormation logical-id provenance (aws:cloudformation:logical-id tag)
  T4 MEDIUM naming heuristic (normalized token containment), unique candidate
  T5 LOW    type-only, exactly one resource of that type in the whole index
Anything ambiguous returns None.

Terraform has no structured resource model in the offline scanner (it is regex
SAST), so a NEW lightweight brace-balanced HCL block extractor is included here;
CloudFormation is parsed structurally (Resources map).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

try:
    import yaml  # optional; CFN JSON always works without it
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

SKIP_DIRS = {".git", ".terraform", "node_modules", "__pycache__", ".venv", "venv"}

# graph-kind / section / arn-prefix -> the IaC resource types that declare it
CANON: Dict[str, set] = {
    "S3Bucket": {"aws_s3_bucket", "AWS::S3::Bucket"},
    "S3": {"aws_s3_bucket", "AWS::S3::Bucket"},
    "EC2Instance": {"aws_instance", "AWS::EC2::Instance"},
    "EC2": {"aws_instance", "AWS::EC2::Instance"},
    "IAMRole": {"aws_iam_role", "AWS::IAM::Role"},
    "IAMUser": {"aws_iam_user", "AWS::IAM::User"},
    "NetworkInterface": {"aws_security_group", "AWS::EC2::SecurityGroup"},
    "SecurityGroup": {"aws_security_group", "AWS::EC2::SecurityGroup"},
    "RDS": {"aws_db_instance", "AWS::RDS::DBInstance"},
    "Lambda": {"aws_lambda_function", "AWS::Lambda::Function"},
    "DynamoDB": {"aws_dynamodb_table", "AWS::DynamoDB::Table"},
}

_TF_NAME_ATTRS = ("bucket", "name", "function_name", "role_name", "identifier",
                  "cluster_identifier", "domain_name", "table_name")

# Tag keys too common to identify a specific resource (T2 must not match on these).
_NON_IDENTIFYING = {"environment", "env", "stage", "name", "team", "owner", "project",
                    "costcenter", "department", "managedby", "terraform", "application",
                    "app", "tier", "role", "service"}


@dataclass(frozen=True)
class IacResource:
    iac_kind: str                 # terraform | cloudformation
    file: str
    line: int
    resource_type: str            # aws_s3_bucket | AWS::S3::Bucket
    logical_id: str               # tf local name or CFN logical id
    physical_name: Optional[str]
    tags: Dict[str, str] = field(default_factory=dict)
    raw_props: Dict = field(default_factory=dict)


@dataclass(frozen=True)
class IacMatch:
    iac_resource: IacResource
    confidence: str               # high | medium | low
    evidence: str

    @property
    def file(self) -> str:
        return self.iac_resource.file

    @property
    def line(self) -> int:
        return self.iac_resource.line

    def to_dict(self) -> dict:
        r = self.iac_resource
        return {"file": r.file, "line": r.line, "iac_kind": r.iac_kind,
                "resource_type": r.resource_type, "logical_id": r.logical_id,
                "physical_name": r.physical_name, "confidence": self.confidence,
                "evidence": self.evidence}


# ── normalization ─────────────────────────────────────────────────────────────
def _norm(name: str) -> str:
    if not name:
        return ""
    s = str(name)
    if s.startswith("arn:aws:s3:::"):
        s = s[len("arn:aws:s3:::"):].split("/")[0]
    elif s.startswith("arn:"):
        s = s.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    return s.strip().lower()


# ── Terraform brace-balanced block extractor (NEW; pure) ─────────────────────
# Per-type physical-name attribute so an aws_iam_role never picks up a following
# aws_s3_bucket's `bucket =` (the cross-type name-bleed guard).
_TYPE_NAME_ATTR = {
    "aws_s3_bucket": "bucket", "aws_iam_role": "name", "aws_iam_user": "name",
    "aws_lambda_function": "function_name", "aws_db_instance": "identifier",
    "aws_dynamodb_table": "name", "aws_security_group": "name",
}


def _balanced(text: str, brace_pos: int):
    """Return the body between a matching brace pair starting at ``brace_pos``,
    string/comment/heredoc AWARE: a '{' or '}' inside a quoted string, a #/// or
    /* */ comment, or a <<TAG heredoc does NOT change depth. Without this a lone
    brace in a string value over-captures into the next resource block."""
    depth = 0
    i = brace_pos
    n = len(text)
    while i < n:
        c = text[i]
        if c in ('"', "'"):                       # quoted string — skip to close
            q = c
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if c == "#" or text[i:i + 2] == "//":     # line comment
            nl = text.find("\n", i)
            i = n if nl < 0 else nl
            continue
        if text[i:i + 2] == "/*":                 # block comment
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if text[i:i + 2] == "<<":                 # heredoc
            hm = re.match(r"<<[-~]?(\w+)", text[i:])
            if hm:
                tag = hm.group(1)
                nl = text.find("\n", i)
                if nl < 0:
                    break
                em = re.search(r"\n[ \t]*" + re.escape(tag) + r"\b", text[nl:])
                i = n if not em else nl + em.end()
                continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[brace_pos + 1:i]
        i += 1
    return text[brace_pos + 1:]


def _tf_attr(body: str, names) -> Optional[str]:
    for n in names:
        if not n:
            continue
        m = re.search(rf'(?m)^\s*{n}\s*=\s*"([^"]+)"', body)
        if m:
            return m.group(1)
    return None


def _tf_tags(body: str) -> Dict[str, str]:
    """Extract the tags map, brace-balanced (so a ``${var.env}`` interpolation or a
    nested map inside the block no longer truncates it), then harvest only the
    top-level scalar key=values."""
    tags: Dict[str, str] = {}
    m = re.search(r"tags\s*=?\s*\{", body)
    if not m:
        return tags
    inner = _balanced(body, m.end() - 1)
    # drop nested map literals (key = { ... }) so inner keys aren't harvested
    stripped = re.sub(r"[A-Za-z0-9_]+\s*=\s*\{[^{}]*\}", "", inner)
    for km in re.finditer(r'"?([A-Za-z0-9_:.\-]+)"?\s*=\s*"([^"]*)"', stripped):
        tags[km.group(1)] = km.group(2)
    return tags


def _scan_tf_blocks(text: str, file: str) -> List[IacResource]:
    out: List[IacResource] = []
    for m in re.finditer(r'resource\s+"(aws_[a-z0-9_]+)"\s+"([A-Za-z0-9_.\-]+)"\s*\{', text):
        rtype, name = m.group(1), m.group(2)
        body = _balanced(text, m.end() - 1)
        line = text[:m.start()].count("\n") + 1
        # per-type physical-name attr (never try 'bucket' for a non-bucket type)
        attr = _TYPE_NAME_ATTR.get(rtype, "name")
        out.append(IacResource("terraform", file, line, rtype, name,
                               _tf_attr(body, [attr]), _tf_tags(body), {}))
    return out


# ── CloudFormation structural parse (pure) ───────────────────────────────────
_CFN_PHYS = {"AWS::S3::Bucket": "BucketName", "AWS::IAM::Role": "RoleName",
             "AWS::Lambda::Function": "FunctionName", "AWS::RDS::DBInstance": "DBInstanceIdentifier",
             "AWS::DynamoDB::Table": "TableName", "AWS::IAM::User": "UserName"}


def _cfn_tags(props: Dict) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    tl = props.get("Tags")
    if isinstance(tl, list):
        for t in tl:
            if isinstance(t, dict) and "Key" in t:
                tags[str(t["Key"])] = str(t.get("Value", ""))
    return tags


def _scan_cfn(doc: Dict, file: str) -> List[IacResource]:
    out: List[IacResource] = []
    resources = (doc or {}).get("Resources")
    if not isinstance(resources, dict):
        return out
    for logical_id, res in resources.items():
        if not isinstance(res, dict):
            continue
        rtype = res.get("Type", "")
        props = res.get("Properties", {}) if isinstance(res.get("Properties"), dict) else {}
        phys_key = _CFN_PHYS.get(rtype)
        phys = props.get(phys_key) if phys_key else None
        phys = phys if isinstance(phys, str) else None
        out.append(IacResource("cloudformation", file, 0, rtype, str(logical_id),
                               phys, _cfn_tags(props), props))
    return out


def _load_iac_file(path: str) -> List[IacResource]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    if path.endswith(".tf"):
        return _scan_tf_blocks(text, path)
    if path.endswith((".json", ".yaml", ".yml", ".template")):
        doc = None
        try:
            doc = json.loads(text)
        except Exception:
            if _HAS_YAML:
                try:
                    doc = yaml.safe_load(text)
                except Exception:
                    doc = None
        if isinstance(doc, dict) and "Resources" in doc:
            return _scan_cfn(doc, path)
    return []


# ── index + matcher ───────────────────────────────────────────────────────────
class IacIndex:
    def __init__(self, resources: List[IacResource]):
        self.resources = resources

    def _candidates(self, live_type: str) -> List[IacResource]:
        # An empty/unknown live_type must NOT fall back to all resources — that
        # would let T1/T5 anchor a finding to an IaC resource of a DIFFERENT AWS
        # type (a wrong-code false match). Unknown type -> no candidates -> None.
        types = CANON.get(live_type)
        if not types:
            return []
        return [r for r in self.resources if r.resource_type in types]

    def matcher(self) -> Callable:
        return lambda res, typ, tags: match_to_iac(res, typ, tags or {}, self)


def build_iac_index(iac_dirs) -> IacIndex:
    """Walk one or more dirs (or files) and build the IaC resource index. Parse
    errors on a single file are skipped, never fatal."""
    if isinstance(iac_dirs, str):
        iac_dirs = [iac_dirs]
    resources: List[IacResource] = []
    for root in iac_dirs or []:
        if os.path.isfile(root):
            resources += _load_iac_file(root)
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if fn.endswith((".tf", ".json", ".yaml", ".yml", ".template")):
                    resources += _load_iac_file(os.path.join(dirpath, fn))
    return IacIndex(resources)


def match_to_iac(live_resource: str, live_type: str, live_tags: Dict,
                 index: IacIndex) -> Optional[IacMatch]:
    live_tags = live_tags or {}
    candidates = index._candidates(live_type)
    if not candidates:
        return None
    norm = _norm(live_resource)

    # T1 — exact physical name
    if norm:
        hits = [r for r in candidates if r.physical_name and _norm(r.physical_name) == norm]
        if len(hits) == 1:
            return IacMatch(hits[0], "high", "T1 exact physical-name")

    # T2 — unique DISTINCTIVE tag match. A common tag (Environment/Name/Team/…)
    # whose value merely happens to be unique must NOT anchor a match; require a
    # non-denylisted key AND value uniqueness across the WHOLE index (not just the
    # type-filtered candidates), else per-env layouts produce wrong-code matches.
    for k, v in live_tags.items():
        if not v or k.lower() in _NON_IDENTIFYING or k.lower().startswith("aws:"):
            continue
        if sum(1 for r in index.resources if r.tags.get(k) == v) != 1:
            continue
        th = [r for r in candidates if r.tags.get(k) == v]
        if len(th) == 1:
            return IacMatch(th[0], "high", f"T2 unique tag {k}={v}")

    # T3 — CloudFormation logical-id provenance (authoritative when present)
    lid = live_tags.get("aws:cloudformation:logical-id")
    if lid:
        lh = [r for r in candidates if r.logical_id == lid]
        if len(lh) == 1:
            return IacMatch(lh[0], "medium", "T3 cfn logical-id")

    # T4 — naming heuristic (token containment), only if it resolves uniquely.
    # Require a meaningful token length (>=4) so a tiny name/id (e.g. "t") can't
    # spuriously substring-match an unrelated resource.
    def _contains(a: str, b: str) -> bool:
        return len(a) >= 4 and a in b

    if norm:
        nh = [r for r in candidates
              if (_norm(r.physical_name or "") and
                  (_contains(norm, _norm(r.physical_name)) or _contains(_norm(r.physical_name), norm)))
              or (r.logical_id and
                  (_contains(_norm(r.logical_id), norm) or _contains(norm, _norm(r.logical_id))))]
        if len(nh) == 1:
            return IacMatch(nh[0], "medium", "T4 naming heuristic")

    # T5 — type-only, exactly one of that type
    if len(candidates) == 1:
        return IacMatch(candidates[0], "low", "T5 type-only (single resource)")
    return None
