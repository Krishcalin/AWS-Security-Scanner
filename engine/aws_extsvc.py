#!/usr/bin/env python3
"""aws_extsvc.py — extended AWS service coverage, batch 1.

OverWatch instantiates 60 boto3 clients. botocore ships service models for **426**
services, and 116 of the uncovered ones expose read APIs that answer a real security
question. This module is the first batch off that gap analysis, chosen by
*impact x readability*: each check below reads a field that AWS itself defines, and each
one is a finding a reviewer would act on rather than a metric.

Every service here was verified against the botocore service model before a line was
written — the operation exists, the field exists, and the enum values are AWS's. That
matters because the alternative is a check that greps for a field nobody returns, which
looks like a clean pass forever.

WHAT EACH SERVICE CONTRIBUTES
------------------------------
* **IoT Core** — the single largest gap (123 read operations, none covered). An IoT
  policy granting ``iot:*`` on ``*`` is the device-fleet equivalent of an admin role
  handed to every thing you own; ``disableAllLogs`` turns off the only record of what
  they did; and a CA with ``autoRegistrationStatus=ENABLE`` lets any certificate that CA
  signs join the fleet without a human approving it.
* **EMR** — ``BlockPublicSecurityGroupRules`` is an account-level guardrail AWS added
  precisely because EMR clusters kept ending up on the internet. ``VisibleToAllUsers``
  makes a cluster manageable by every IAM principal in the account.
* **CodeBuild** — ``projectVisibility=PUBLIC_READ`` publishes build logs and artifacts to
  anyone; build logs are where credentials and internal hostnames go to be discovered.
  ``artifacts.encryptionDisabled`` is an explicit opt-out, not a default.
* **DocumentDB** — a cluster snapshot whose ``restore`` attribute contains ``all`` is
  **public**: any AWS account can restore your database. This is one of the few checks
  in OverWatch that is a direct observation rather than an inference.
* **EC2 Image Builder** — an image resource policy is how an AMI pipeline's output gets
  shared; a permissive one shares whatever was baked into the image.
* **Transfer Family** — ``FTP`` in ``Protocols`` is credentials and file contents in
  cleartext. A ``PUBLIC`` endpoint type is internet-reachable by design, which is
  legitimate for many servers and is reported as context rather than as a defect.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional, Sequence
from urllib.parse import unquote

__all__ = [
    "iot_policy_risk", "iot_logging_posture", "iot_ca_posture",
    "emr_block_public_access", "emr_cluster_posture",
    "codebuild_posture", "docdb_snapshot_exposure", "docdb_cluster_posture",
    "imagebuilder_policy_exposure", "transfer_posture",
    "PUBLIC_READ", "PUBLIC", "CLEARTEXT_PROTOCOLS", "parse_doc",
]

#: Verified enum values, from the botocore service models.
PUBLIC_READ = "PUBLIC_READ"          # codebuild ProjectVisibilityType
PUBLIC = "PUBLIC"                    # transfer EndpointType
AUTO_REGISTER_ON = "ENABLE"          # iot AutoRegistrationStatus
SHARE_ALL = "all"                    # rds/docdb snapshot attribute value meaning PUBLIC
RESTORE = "restore"                  # the attribute name that governs snapshot sharing

#: transfer Protocol enum is (SFTP, FTP, FTPS, AS2). FTP alone is unencrypted.
CLEARTEXT_PROTOCOLS = ("FTP",)


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


def _l(v) -> list:
    return list(v) if isinstance(v, (list, tuple)) else []


def parse_doc(doc) -> dict:
    """A policy document as a dict, from a dict / JSON string / URL-encoded string."""
    if isinstance(doc, dict):
        return doc
    if not isinstance(doc, (str, bytes, bytearray)):
        return {}
    if isinstance(doc, (bytes, bytearray)):
        try:
            doc = doc.decode("utf-8")
        except Exception:
            return {}
    for cand in (doc, unquote(doc)):
        try:
            v = json.loads(cand)
            return v if isinstance(v, dict) else {}
        except Exception:
            continue
    return {}


def _statements(doc) -> List[dict]:
    st = parse_doc(doc).get("Statement")
    if isinstance(st, dict):
        st = [st]
    return [s for s in (st or []) if isinstance(s, dict)]


def _wild(values) -> bool:
    return any(str(v).strip() == "*" for v in _l(values) or
               ([values] if isinstance(values, str) else []))


# ── AWS IoT Core ────────────────────────────────────────────────────────────
def iot_policy_risk(policy_name: str, document) -> dict:
    """An IoT policy that grants every action on every resource.

    IoT policies attach to certificates and Cognito identities, so one over-broad policy
    is not one over-privileged principal — it is every device carrying that certificate.
    ``iot:*`` on ``*`` lets any of them publish to any topic, subscribe to any other
    device's topics, and call the control plane."""
    stmts = _statements(document)
    hits = []
    for s in stmts:
        if s.get("Effect") != "Allow":
            continue
        if _wild(s.get("Action")) and _wild(s.get("Resource")):
            hits.append(s)
    return {
        "policy": policy_name or "",
        "parsed": bool(stmts),
        "wildcard": bool(hits),
        "statements": len(stmts),
        "statement": (
            f"IoT policy {policy_name} allows every action (iot:*) on every resource (*) "
            f"— it attaches to certificates, so every device carrying one holds this"
            if hits else ""),
    }


def iot_logging_posture(v2_logging: Optional[dict]) -> dict:
    """``disableAllLogs`` is an explicit switch, so absent is not the same as off."""
    d = _d(v2_logging)
    raw = d.get("disableAllLogs")
    known = isinstance(raw, bool)
    return {
        "known": known,
        "disabled": raw is True,
        "default_level": d.get("defaultLogLevel") or "",
        "statement": ("IoT logging is disabled account-wide (disableAllLogs=true) — no "
                      "record exists of what any device did"
                      if raw is True else ""),
    }


def iot_ca_posture(ca: Optional[dict]) -> dict:
    """A CA with auto-registration on admits any certificate it signs, unreviewed."""
    d = _d(ca)
    status = d.get("autoRegistrationStatus") or ""
    return {
        "certificate_id": d.get("certificateId") or "",
        "status": d.get("status") or "",
        "known": bool(status),
        "auto_register": status == AUTO_REGISTER_ON,
        "statement": (
            f"IoT CA certificate {d.get('certificateId')} has auto-registration ENABLED "
            f"— any device certificate this CA signs joins the fleet without review"
            if status == AUTO_REGISTER_ON else ""),
    }


# ── Amazon EMR ──────────────────────────────────────────────────────────────
def emr_block_public_access(cfg: Optional[dict]) -> dict:
    """AWS added this account-level guardrail because EMR clusters kept reaching the
    internet. ``BlockPublicSecurityGroupRules`` absent is unknown, not off."""
    d = _d(cfg)
    raw = d.get("BlockPublicSecurityGroupRules")
    return {
        "known": isinstance(raw, bool),
        "blocked": raw is True,
        "exceptions": len(_l(d.get("PermittedPublicSecurityGroupRuleRanges"))),
        "statement": ("EMR block-public-access is OFF for this account — nothing stops a "
                      "cluster being launched with a security group open to the internet"
                      if raw is False else ""),
    }


def emr_cluster_posture(cluster: Optional[dict]) -> dict:
    """``VisibleToAllUsers`` and the presence of a named security configuration."""
    d = _d(cluster)
    vis = d.get("VisibleToAllUsers")
    sec = d.get("SecurityConfiguration") or ""
    return {
        "id": d.get("Id") or "",
        "name": d.get("Name") or "",
        "visible_all_known": isinstance(vis, bool),
        "visible_to_all": vis is True,
        "security_configuration": sec,
        "has_security_configuration": bool(sec),
        "kerberos": bool(_d(d.get("KerberosAttributes"))),
        "statement": (
            f"EMR cluster {d.get('Id')} has no named security configuration — the "
            f"at-rest/in-transit encryption and authentication settings a security "
            f"configuration carries are simply not applied to it"
            if not sec else ""),
    }


# ── AWS CodeBuild ───────────────────────────────────────────────────────────
def codebuild_posture(project: Optional[dict]) -> dict:
    """``PUBLIC_READ`` publishes build logs and artifacts to anyone.

    Build logs are where credentials, internal hostnames and dependency URLs surface, so
    a public project is a disclosure channel rather than a convenience."""
    d = _d(project)
    vis = d.get("projectVisibility") or ""
    arts = _d(d.get("artifacts"))
    enc_off = arts.get("encryptionDisabled")
    return {
        "name": d.get("name") or "",
        "visibility": vis,
        "vis_known": bool(vis),
        "public": vis == PUBLIC_READ,
        "artifact_encryption_known": isinstance(enc_off, bool),
        "artifact_encryption_disabled": enc_off is True,
        "has_vpc": bool(_d(d.get("vpcConfig")).get("vpcId")),
        "statement": (
            f"CodeBuild project {d.get('name')} is PUBLIC_READ — its build logs and "
            f"artifacts are readable by anyone, and build logs routinely contain "
            f"credentials, internal hostnames and dependency URLs"
            if vis == PUBLIC_READ else ""),
        "artifact_statement": (
            f"CodeBuild project {d.get('name')} has artifact encryption explicitly "
            f"DISABLED — this is an opt-out, not a default"
            if enc_off is True else ""),
    }


# ── Amazon DocumentDB ───────────────────────────────────────────────────────
def docdb_snapshot_exposure(snapshot_id: str,
                            attributes: Optional[Sequence]) -> dict:
    """A snapshot whose ``restore`` attribute contains ``all`` is PUBLIC.

    One of the few OverWatch checks that is a direct observation rather than an
    inference: the attribute either lists ``all`` or it does not, and if it does then any
    AWS account can restore the database."""
    shared_accounts, public = [], False
    seen = False
    for a in _l(attributes):
        ad = _d(a)
        if (ad.get("AttributeName") or "").lower() != RESTORE:
            continue
        seen = True
        for v in _l(ad.get("AttributeValues")):
            if str(v) == SHARE_ALL:
                public = True
            elif str(v):
                shared_accounts.append(str(v))
    return {
        "snapshot": snapshot_id or "",
        "known": seen,
        "public": public,
        "shared_accounts": tuple(sorted(set(shared_accounts))),
        "statement": (
            f"DocumentDB cluster snapshot {snapshot_id} is shared with ALL AWS accounts "
            f"(restore attribute contains 'all') — any AWS account can restore it and "
            f"read every record it holds"
            if public else ""),
        "shared_statement": (
            f"DocumentDB cluster snapshot {snapshot_id} is shared with "
            f"{len(set(shared_accounts))} external account(s): "
            f"{', '.join(sorted(set(shared_accounts)))}"
            if shared_accounts and not public else ""),
    }


def docdb_cluster_posture(cluster: Optional[dict]) -> dict:
    """Storage encryption, audit-log export and deletion protection."""
    d = _d(cluster)
    enc = d.get("StorageEncrypted")
    logs = [str(x) for x in _l(d.get("EnabledCloudwatchLogsExports"))]
    dp = d.get("DeletionProtection")
    return {
        "id": d.get("DBClusterIdentifier") or "",
        "encryption_known": isinstance(enc, bool),
        "encrypted": enc is True,
        "audit_enabled": "audit" in [x.lower() for x in logs],
        "log_exports": tuple(logs),
        "deletion_protection_known": isinstance(dp, bool),
        "deletion_protection": dp is True,
        "statement": (
            f"DocumentDB cluster {d.get('DBClusterIdentifier')} is not encrypted at rest "
            f"— DocumentDB storage encryption can only be set at creation, so this "
            f"cannot be switched on in place"
            if enc is False else ""),
        "audit_statement": (
            f"DocumentDB cluster {d.get('DBClusterIdentifier')} does not export audit "
            f"logs — there is no record of who connected or what they queried"
            if "audit" not in [x.lower() for x in logs] else ""),
    }


# ── EC2 Image Builder ───────────────────────────────────────────────────────
def imagebuilder_policy_exposure(resource_arn: str, policy) -> dict:
    """A permissive Image Builder resource policy shares whatever the image contains."""
    stmts = _statements(policy)
    wide = []
    for s in stmts:
        if s.get("Effect") != "Allow":
            continue
        p = s.get("Principal")
        if p == "*" or _d(p).get("AWS") == "*" or _wild(_d(p).get("AWS")):
            wide.append(s)
    return {
        "arn": resource_arn or "",
        "has_policy": bool(stmts),
        "public": bool(wide),
        "statement": (
            f"Image Builder resource {resource_arn} has a resource policy granting a "
            f"wildcard principal — the image and everything baked into it (packages, "
            f"configuration, any embedded secret) is shared beyond your account"
            if wide else ""),
    }


# ── AWS Transfer Family ─────────────────────────────────────────────────────
def transfer_posture(server: Optional[dict]) -> dict:
    """Cleartext FTP, endpoint reachability, and whether anything is logged."""
    d = _d(server)
    protos = [str(p).upper() for p in _l(d.get("Protocols"))]
    cleartext = [p for p in protos if p in CLEARTEXT_PROTOCOLS]
    etype = d.get("EndpointType") or ""
    logging_role = d.get("LoggingRole") or ""
    return {
        "server_id": d.get("ServerId") or d.get("Arn") or "",
        "protocols": tuple(protos),
        "cleartext": tuple(cleartext),
        "endpoint_type": etype,
        "endpoint_known": bool(etype),
        "public": etype == PUBLIC,
        "logging": bool(logging_role),
        "security_policy": d.get("SecurityPolicyName") or "",
        "statement": (
            f"Transfer Family server {d.get('ServerId')} accepts plain FTP — credentials "
            f"and file contents cross the network unencrypted. FTPS or SFTP carry the "
            f"same workflow over an encrypted channel"
            if cleartext else ""),
        "logging_statement": (
            f"Transfer Family server {d.get('ServerId')} has no logging role — there is "
            f"no record of who connected or which files moved"
            if not logging_role else ""),
        "endpoint_statement": (
            f"Transfer Family server {d.get('ServerId')} uses a PUBLIC endpoint, so it is "
            f"internet-reachable. That is the intended mode for many servers and is "
            f"reported as context rather than as a defect — pair it with the identity "
            f"provider and security policy when judging it"
            if etype == PUBLIC else ""),
    }
