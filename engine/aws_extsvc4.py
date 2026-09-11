#!/usr/bin/env python3
"""aws_extsvc4.py — extended AWS service coverage, batch 4.

Fourth batch off the 426-service gap analysis. Every field below was verified against the
botocore service model before the classifier was written.

MEDIASTORE IS DELIBERATELY ABSENT
----------------------------------
AWS Elemental MediaStore was in the requested set and is **not** built here. AWS ended
support for it on **13 November 2025**, nine months before this batch. Its container and
CORS policies would have been reasonable checks while the service existed; against a
discontinued service they can never fire, and they would still cost the same wiring,
deploy grants, ledger entries and tests as a live one. A check that cannot fire is worse
than no check: it reads as coverage.

WHAT EACH SERVICE CONTRIBUTES
------------------------------
* **Lake Formation** — the single most consequential setting in the batch.
  ``IAM_ALLOWED_PRINCIPALS`` in the default database or table permissions means Lake
  Formation's own grants are **not consulted at all** and plain IAM governs the data. The
  console still shows a fully configured Lake Formation, which is what makes it worth
  detecting rather than assuming.
* **WorkSpaces Web** — a managed browser that exists to reach internal applications. A
  portal with no IP access settings can be used from anywhere, and one with no user
  access logging leaves no record of what was reached through it.
* **Storage Gateway** — an NFS file share whose ``ClientList`` contains ``0.0.0.0/0`` is
  mountable by anything that can route to the gateway, and the share is a window onto S3.
* **Payment Cryptography** — keys here protect card data under PCI. ``Exportable`` on
  such a key means the key material can leave the HSM boundary that justifies the
  service existing.
* **Managed Blockchain** — a member with no log publishing has no record of its
  certificate authority's activity, and the CA is what admits identities to the network.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional, Sequence
from urllib.parse import unquote

from engine import aws_checkdef as _cd
from engine.aws_checkdef import CheckDef as _C, Perm as _P

__all__ = [
    "lf_default_permissions", "lf_grants", "wsw_portal", "sgw_nfs_share",
    "sgw_share_encryption", "paycrypt_key", "paycrypt_policy", "mbc_member",
    "IAM_ALLOWED_PRINCIPALS", "WORLD_V4", "parse_doc", "MEDIASTORE_EOL",
]

#: The sentinel principal that turns Lake Formation grants off for a resource.
IAM_ALLOWED_PRINCIPALS = "IAM_ALLOWED_PRINCIPALS"
WORLD_V4 = "0.0.0.0/0"

#: Recorded so the omission is a documented decision rather than an oversight.
MEDIASTORE_EOL = "2025-11-13"


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


def _l(v) -> list:
    return list(v) if isinstance(v, (list, tuple)) else []


def parse_doc(doc) -> dict:
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


def _wide_principal(stmt: dict) -> bool:
    if stmt.get("Effect") != "Allow":
        return False
    p = stmt.get("Principal")
    if p == "*":
        return True
    aws = _d(p).get("AWS")
    if isinstance(aws, str):
        return aws.strip() == "*"
    return any(str(x).strip() == "*" for x in _l(aws))


# ── AWS Lake Formation ──────────────────────────────────────────────────────
def _principals(rows: Optional[Sequence]) -> List[str]:
    out = []
    for r in _l(rows):
        p = _d(_d(r).get("Principal")).get("DataLakePrincipalIdentifier")
        if p:
            out.append(str(p))
    return out


def lf_default_permissions(settings: Optional[dict]) -> dict:
    """``IAM_ALLOWED_PRINCIPALS`` in the defaults switches Lake Formation off.

    Not metaphorically: when a database or table carries that grant, Lake Formation does
    not evaluate its own permissions for it at all, and access falls back to whatever IAM
    says. The console still presents a configured Lake Formation, so nothing looks
    wrong."""
    s = _d(settings)
    db = _principals(s.get("CreateDatabaseDefaultPermissions"))
    tbl = _principals(s.get("CreateTableDefaultPermissions"))
    open_db = IAM_ALLOWED_PRINCIPALS in db
    open_tbl = IAM_ALLOWED_PRINCIPALS in tbl
    where = [n for n, v in (("databases", open_db), ("tables", open_tbl)) if v]
    return {
        "admins": tuple(_principals(s.get("DataLakeAdmins"))),
        "database_defaults": tuple(db),
        "table_defaults": tuple(tbl),
        "known": bool(db or tbl or s),
        "bypassed": bool(where),
        "where": tuple(where),
        "statement": (
            f"Lake Formation default permissions for new {' and '.join(where)} grant "
            f"IAM_ALLOWED_PRINCIPALS — for anything created with that default Lake "
            f"Formation does NOT evaluate its own grants, and plain IAM governs the "
            f"data. The console still shows a configured Lake Formation"
            if where else ""),
    }


def lf_grants(permissions: Optional[Sequence]) -> dict:
    """Existing per-resource grants to the same bypass principal."""
    hits = []
    for row in _l(permissions):
        r = _d(row)
        p = _d(r.get("Principal")).get("DataLakePrincipalIdentifier")
        if str(p) == IAM_ALLOWED_PRINCIPALS:
            res = _d(r.get("Resource"))
            name = (_d(res.get("Table")).get("Name")
                    or _d(res.get("Database")).get("Name")
                    or _d(res.get("Catalog")).get("Id") or "resource")
            hits.append(str(name))
    return {
        "resources": tuple(sorted(set(hits))),
        "bypassed": bool(hits),
        "statement": (
            f"{len(set(hits))} Lake Formation resource(s) carry a grant to "
            f"IAM_ALLOWED_PRINCIPALS ({', '.join(sorted(set(hits))[:5])}) — for those, "
            f"Lake Formation permissions are not consulted and IAM alone decides who "
            f"reads the data"
            if hits else ""),
    }


# ── Amazon WorkSpaces Web ───────────────────────────────────────────────────
def wsw_portal(portal: Optional[dict]) -> dict:
    """A managed browser reaching internal applications."""
    p = _d(portal)
    ip_rules = p.get("ipAccessSettingsArn") or ""
    logging = p.get("userAccessLoggingSettingsArn") or ""
    session = p.get("sessionLoggerArn") or ""
    return {
        "arn": p.get("portalArn") or "",
        "name": p.get("displayName") or p.get("portalArn") or "",
        "auth": p.get("authenticationType") or "",
        "ip_restricted": bool(ip_rules),
        "user_logging": bool(logging),
        "session_logging": bool(session),
        "statement": (
            f"WorkSpaces Web portal {p.get('displayName') or p.get('portalArn')} has no "
            f"IP access settings — the managed browser can be opened from any network, "
            f"and its whole purpose is reaching internal applications, so the browser "
            f"session is the path in"
            if not ip_rules else ""),
        "logging_statement": (
            f"WorkSpaces Web portal {p.get('displayName') or p.get('portalArn')} has "
            f"neither user access logging nor a session logger — there is no record of "
            f"who used the managed browser or what they reached through it"
            if not logging and not session else ""),
    }


# ── AWS Storage Gateway ─────────────────────────────────────────────────────
def sgw_nfs_share(share: Optional[dict]) -> dict:
    """``ClientList`` is the NFS allow-list; ``0.0.0.0/0`` admits anything routable."""
    s = _d(share)
    clients = [str(c) for c in _l(s.get("ClientList"))]
    world = WORLD_V4 in clients
    return {
        "arn": s.get("FileShareARN") or s.get("FileShareId") or "",
        "clients": tuple(clients),
        "world_open": world,
        "read_only": s.get("ReadOnly") is True,
        "statement": (
            f"Storage Gateway NFS share {s.get('FileShareId')} allows clients from "
            f"0.0.0.0/0 — anything that can route to the gateway can mount it, and the "
            f"share is a window onto the S3 bucket behind it"
            if world else ""),
    }


def sgw_share_encryption(share: Optional[dict]) -> dict:
    """``KMSEncrypted`` distinguishes a CMK from the service default."""
    s = _d(share)
    raw = s.get("KMSEncrypted")
    return {
        "arn": s.get("FileShareARN") or s.get("FileShareId") or "",
        "known": isinstance(raw, bool),
        "cmk": raw is True,
        "key": s.get("KMSKey") or "",
        "statement": (
            f"Storage Gateway file share {s.get('FileShareId')} does not use a "
            f"customer-managed key, so objects it writes to S3 are under the service "
            f"default with no separately-administered key to revoke"
            if raw is False else ""),
    }


# ── AWS Payment Cryptography ────────────────────────────────────────────────
def paycrypt_key(key: Optional[dict]) -> dict:
    """``Exportable`` on a payment key means the material can leave the HSM."""
    k = _d(key)
    exportable = k.get("Exportable")
    return {
        "arn": k.get("KeyArn") or "",
        "state": k.get("KeyState") or "",
        "enabled": k.get("Enabled") is True,
        "known": isinstance(exportable, bool),
        "exportable": exportable is True,
        "usage": _d(k.get("KeyAttributes")).get("KeyUsage") or "",
        "statement": (
            f"Payment Cryptography key {k.get('KeyArn')} is EXPORTABLE — its material "
            f"can be taken out of the HSM. Keys in this service exist to protect card "
            f"data inside a hardware boundary, and an exportable key is that boundary "
            f"made optional"
            if exportable is True else ""),
    }


def paycrypt_policy(arn: str, policy) -> dict:
    """A resource policy sharing a payment key beyond the account."""
    doc = parse_doc(policy)
    stmts = doc.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    wide = [s for s in (stmts or []) if isinstance(s, dict) and _wide_principal(s)]
    return {
        "arn": arn or "",
        "has_policy": bool(stmts),
        "public": bool(wide),
        "statement": (
            f"Payment Cryptography key {arn} has a resource policy granting a wildcard "
            f"principal — anyone matching it can use a key that protects card data, and "
            f"use of the key is the whole control"
            if wide else ""),
    }


# ── Amazon Managed Blockchain ───────────────────────────────────────────────
def mbc_member(member: Optional[dict]) -> dict:
    """A member's certificate authority is what admits identities to the network."""
    m = _d(member)
    logs = _d(_d(m.get("LogPublishingConfiguration")).get("Fabric"))
    ca_logs = _d(logs.get("CaLogs"))
    enabled = _d(ca_logs.get("Cloudwatch")).get("Enabled")
    key = m.get("KmsKeyArn") or ""
    return {
        "id": m.get("Id") or "",
        "name": m.get("Name") or m.get("Id") or "",
        "ca_logging_known": isinstance(enabled, bool),
        "ca_logging": enabled is True,
        "cmk": bool(key),
        "statement": (
            f"Managed Blockchain member {m.get('Name') or m.get('Id')} does not publish "
            f"certificate-authority logs — the CA is what admits identities to the "
            f"network, so there is no record of which identities were enrolled or by whom"
            if enabled is False else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Declarations
# ══════════════════════════════════════════════════════════════════════════════
_ACC = {"PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"}
_NET = {"PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"}
_ENC = {"PCI-DSS": "3.5.1", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1",
        "NIST": "SC-28"}
_LOG = {"PCI-DSS": "10.2.1", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"}
_KEY = {"PCI-DSS": "3.6.1", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1",
        "NIST": "SC-12"}

CHECKS = _cd.register(
    _C(id="LF-01", section="LAKEFORMATION", severity="HIGH", compliance=_ACC,
       permissions=(
           _P("lakeformation:GetDataLakeSettings",
              "read CreateDatabaseDefaultPermissions and CreateTableDefaultPermissions "
              "-- IAM_ALLOWED_PRINCIPALS there means Lake Formation grants are not "
              "consulted at all for anything created with that default"),
       ),
       remediation=(
           "Remove IAM_ALLOWED_PRINCIPALS from the Lake Formation defaults so new "
           "databases and tables are actually governed by Lake Formation: aws "
           "lakeformation get-data-lake-settings to read the current state, then aws "
           "lakeformation put-data-lake-settings --data-lake-settings "
           "file://settings.json with both CreateDatabaseDefaultPermissions and "
           "CreateTableDefaultPermissions set to an empty list. Existing resources keep "
           "their grants -- fix those separately (see LF-02)"),
       risk=(
           "Lake Formation's default permissions for new databases or tables grant the "
           "IAM_ALLOWED_PRINCIPALS principal. That sentinel does something more drastic "
           "than it reads: where it is present, Lake Formation does not evaluate its own "
           "permissions for that resource AT ALL, and access falls back entirely to IAM. "
           "Every fine-grained grant the data team believes they configured -- "
           "column-level, row-level, tag-based -- is simply not consulted. The reason "
           "this is worth a check rather than a note is that nothing looks wrong: the "
           "Lake Formation console shows the databases, the permissions pages show the "
           "grants, and queries succeed for the people who should be able to run them. "
           "It is only when somebody who should NOT have access runs a query and it also "
           "succeeds that the setting becomes visible, and by then the data has been "
           "read. This is the default Lake Formation ships with for backwards "
           "compatibility, so an estate reaches this state by not changing anything."),
       impact=("Lake Formation grants are bypassed for affected resources and plain IAM "
               "governs the data, so column-, row- and tag-level controls are not "
               "evaluated."),
       steps=(
           "Read the current settings: aws lakeformation get-data-lake-settings",
           "Clear both default permission lists: aws lakeformation put-data-lake-settings "
           "--data-lake-settings file://settings.json with "
           "CreateDatabaseDefaultPermissions and CreateTableDefaultPermissions empty.",
           "Confirm Lake Formation administrators are actually set in DataLakeAdmins "
           "before tightening, or nobody will be able to grant anything afterwards.",
           "Fix existing resources separately -- clearing the default does not revoke "
           "grants already made (see LF-02).",
           "Re-run queries for a representative set of roles: this change makes Lake "
           "Formation authoritative, so anything that relied on the IAM fallback will "
           "start failing.")),

    _C(id="LF-02", section="LAKEFORMATION", severity="HIGH", compliance=_ACC,
       permissions=(
           _P("lakeformation:ListPermissions",
              "enumerate existing Lake Formation grants and find resources still "
              "granted to IAM_ALLOWED_PRINCIPALS, where LF permissions are bypassed"),
       ),
       remediation=(
           "Revoke the IAM_ALLOWED_PRINCIPALS grant from each affected resource so Lake "
           "Formation starts governing it: aws lakeformation list-permissions "
           "--principal DataLakePrincipalIdentifier=IAM_ALLOWED_PRINCIPALS to find them, "
           "then aws lakeformation revoke-permissions --principal "
           "DataLakePrincipalIdentifier=IAM_ALLOWED_PRINCIPALS --resource "
           "file://resource.json --permissions ALL . Grant real principals first, or "
           "access stops"),
       risk=(
           "One or more existing Lake Formation resources carry a grant to "
           "IAM_ALLOWED_PRINCIPALS, which means Lake Formation permissions are not "
           "consulted for them and IAM alone decides who reads the data. This is the "
           "same bypass as the default-permissions setting, but for resources that "
           "already exist -- and clearing the default does nothing about them, which is "
           "the part most often missed: an estate can correct the setting, believe the "
           "problem solved, and leave every table created before that day still "
           "bypassed. The practical consequence is that a broad IAM policy such as "
           "glue:GetTable plus s3:GetObject on the data location is sufficient to read "
           "the table, regardless of what Lake Formation was told. Revoking needs care "
           "in the other direction: real principals must be granted before the sentinel "
           "is removed, or queries that worked yesterday stop."),
       impact=("For the affected resources, Lake Formation grants are not evaluated and "
               "broad IAM permissions are sufficient to read the data."),
       steps=(
           "Find every affected resource: aws lakeformation list-permissions --principal "
           "DataLakePrincipalIdentifier=IAM_ALLOWED_PRINCIPALS",
           "Grant the real principals FIRST -- revoking before granting stops access: "
           "aws lakeformation grant-permissions --principal "
           "DataLakePrincipalIdentifier=<ROLE_ARN> --resource file://resource.json "
           "--permissions SELECT",
           "Then revoke the sentinel: aws lakeformation revoke-permissions --principal "
           "DataLakePrincipalIdentifier=IAM_ALLOWED_PRINCIPALS --resource "
           "file://resource.json --permissions ALL",
           "Work through it table by table with the data owners; this changes who can "
           "read what, which is not a change to make in bulk unattended.")),

    _C(id="WSW-01", section="WORKSPACESWEB", severity="MEDIUM", compliance=_NET,
       permissions=(
           _P("workspaces-web:ListPortals",
              "enumerate the managed browser portals published in this account"),
           _P("workspaces-web:GetPortal",
              "read whether a portal has IP access settings and user access logging "
              "attached -- a managed browser exists to reach internal applications"),
       ),
       remediation=(
           "Attach IP access settings so the managed browser can only be opened from "
           "expected networks: aws workspaces-web create-ip-access-settings "
           "--ip-rules ipRange=<CIDR> --display-name <NAME>, then aws workspaces-web "
           "associate-ip-access-settings --portal-arn <PORTAL_ARN> "
           "--ip-access-settings-arn <ARN>"),
       risk=(
           "This WorkSpaces Web portal has no IP access settings, so the managed browser "
           "can be opened from any network. What makes that matter more than it would "
           "for an ordinary web application is what the service is FOR: WorkSpaces Web "
           "exists to give users a browser that sits inside your network and can reach "
           "internal applications -- intranet sites, admin consoles, line-of-business "
           "systems that were never meant to be internet-facing. The portal is therefore "
           "a deliberate, sanctioned path from outside to inside, and the IP access "
           "settings are the control that decides where that path may be opened from. "
           "Without them, an authenticated user, or anyone holding their credentials, "
           "reaches the internal estate from an internet cafe as readily as from the "
           "office. The browser is doing exactly what it was built to do."),
       impact=("The managed browser -- a sanctioned path to internal applications -- can "
               "be opened from any network by anyone holding valid credentials."),
       steps=(
           "Establish the networks users should legitimately connect from before "
           "writing rules; this control fails closed.",
           "Create the settings: aws workspaces-web create-ip-access-settings --ip-rules "
           "ipRange=<CIDR> --display-name <NAME>",
           "Associate them with the portal: aws workspaces-web "
           "associate-ip-access-settings --portal-arn <PORTAL_ARN> "
           "--ip-access-settings-arn <ARN>",
           "Pair this with the identity provider: IP restriction bounds where, "
           "authentication bounds who, and neither substitutes for the other.")),

    # CIS-EUC 3.1 is the ONLY recommendation in that benchmark's WorkSpaces Web
    # section, and this check already answered it before the benchmark was read.
    # The key is spliced onto a COPY of _LOG rather than added to _LOG itself,
    # which a dozen unrelated logging checks share -- mutating the shared dict
    # would tag every one of them with a WorkSpaces Web recommendation.
    _C(id="WSW-02", section="WORKSPACESWEB", severity="MEDIUM",
       compliance={**_LOG, "CIS-EUC": "3.1"},
       permissions=(
           _P("workspaces-web:GetPortal",
              "read whether any user access logging or session logger is attached to "
              "the portal -- without one there is no record of what the managed browser "
              "reached"),
       ),
       remediation=(
           "Attach user access logging so portal activity leaves a record: aws "
           "workspaces-web create-user-access-logging-settings --kinesis-stream-arn "
           "<STREAM_ARN>, then aws workspaces-web "
           "associate-user-access-logging-settings --portal-arn <PORTAL_ARN> "
           "--user-access-logging-settings-arn <ARN>"),
       risk=(
           "This WorkSpaces Web portal has neither user access logging nor a session "
           "logger, so there is no record of who used the managed browser or what they "
           "reached through it. The gap is specific and awkward: because the browser "
           "runs inside AWS and reaches internal applications from there, the traffic it "
           "generates does not appear where an investigator would normally look. It is "
           "not on a corporate proxy, it is not in an endpoint agent's history, and the "
           "internal application's own logs record a connection from the WorkSpaces Web "
           "fleet rather than from a person. The portal's logging is therefore the only "
           "place the association between a named user and what they browsed exists at "
           "all. Without it, an investigation into misuse of internal systems through "
           "the portal has nothing to work with beyond the fact that the portal exists."),
       impact=("No record exists linking a named user to what they reached through the "
               "managed browser, and internal application logs show only the service "
               "fleet."),
       steps=(
           "Create user access logging against a Kinesis stream: aws workspaces-web "
           "create-user-access-logging-settings --kinesis-stream-arn <STREAM_ARN>",
           "Associate it: aws workspaces-web associate-user-access-logging-settings "
           "--portal-arn <PORTAL_ARN> --user-access-logging-settings-arn <ARN>",
           "Consider a session logger as well if session-level detail is required; the "
           "two answer different questions.",
           "Confirm records actually arrive rather than assuming, and set retention to "
           "match your investigation window.")),

    _C(id="SGW-01", section="STORAGEGATEWAY", severity="HIGH", compliance=_NET,
       permissions=(
           _P("storagegateway:ListFileShares",
              "enumerate the file shares published by gateways in this account"),
           _P("storagegateway:DescribeNFSFileShares",
              "read ClientList -- the NFS allow-list, where 0.0.0.0/0 admits anything "
              "able to route to the gateway"),
       ),
       remediation=(
           "Replace the world-open NFS client list with the specific clients that should "
           "mount the share: aws storagegateway update-nfs-file-share --file-share-arn "
           "<ARN> --client-list <CIDR_1> <CIDR_2> . Confirm afterwards with aws "
           "storagegateway describe-nfs-file-shares --file-share-arn-list <ARN>"),
       risk=(
           "This Storage Gateway NFS file share allows clients from 0.0.0.0/0, so "
           "anything able to route to the gateway can mount it. The consequence is "
           "larger than a single misconfigured share because of what a file gateway IS: "
           "it presents an S3 bucket as an NFS mount, so mounting the share is reading "
           "and, unless the share is read-only, writing the bucket behind it -- through "
           "a path where none of S3's own controls apply. There is no bucket policy "
           "evaluation, no IAM principal, and no CloudTrail data event naming a caller; "
           "the gateway uses its own role and the NFS client list is the entire access "
           "control. NFS also authenticates by network position rather than identity, so "
           "the allow-list is not one control among several, it is the control."),
       impact=("Anything able to route to the gateway can mount the share and read -- "
               "and usually write -- the S3 bucket behind it, bypassing bucket policy "
               "and IAM entirely."),
       steps=(
           "Establish which clients legitimately mount the share before narrowing it.",
           "Replace the allow-list: aws storagegateway update-nfs-file-share "
           "--file-share-arn <ARN> --client-list <CIDR_1> <CIDR_2>",
           "Consider whether the share should be read-only: aws storagegateway "
           "update-nfs-file-share --file-share-arn <ARN> --read-only",
           "Check the gateway's own network position too -- an allow-list is only as "
           "meaningful as the set of things that can reach the gateway at all.",
           "Review the bucket the share fronts: access through the gateway leaves no "
           "per-caller trail, so treat the exposure window as unbounded.")),

    _C(id="SGW-02", section="STORAGEGATEWAY", severity="MEDIUM", compliance=_ENC,
       permissions=(
           _P("storagegateway:DescribeSMBFileShares",
              "read KMSEncrypted on SMB shares to establish whether objects written "
              "through the gateway are under a customer-managed key"),
       ),
       remediation=(
           "Point the share at a customer-managed key so there is a separately "
           "administered control over the objects it writes: aws storagegateway "
           "update-smb-file-share --file-share-arn <ARN> --kms-encrypted --kms-key "
           "<KEY_ARN> (use update-nfs-file-share for NFS shares)"),
       risk=(
           "This Storage Gateway file share does not use a customer-managed key, so "
           "objects it writes to S3 sit under the service default. As with other "
           "default-encryption findings the data is encrypted either way and the "
           "question is how many independent controls exist -- but a file gateway is a "
           "case where the second control is worth more than usual. Access through the "
           "gateway does not carry an IAM principal and does not produce a per-caller "
           "CloudTrail data event, so the usual ways of establishing who read an object "
           "do not apply to anything that came through the mount. A customer-managed key "
           "at least gives a separately administered gate that can be revoked without "
           "touching the gateway or the bucket, and its grants are auditable in a place "
           "the gateway's own configuration is not."),
       impact=("Objects written through the gateway are under the service default key, "
               "with no separately-administered control over them and no per-caller "
               "trail for access through the mount."),
       steps=(
           "Create or choose a CMK whose key policy names the gateway role and the "
           "roles that legitimately read the bucket.",
           "Apply it: aws storagegateway update-smb-file-share --file-share-arn <ARN> "
           "--kms-encrypted --kms-key <KEY_ARN>",
           "Use update-nfs-file-share for NFS shares -- the flag is the same but the "
           "command differs.",
           "Note this governs objects written from now on; existing objects keep the "
           "key they were written with.")),

    _C(id="PAY-01", section="PAYMENTCRYPTO", severity="HIGH", compliance=_KEY,
       permissions=(
           _P("payment-cryptography:ListKeys",
              "enumerate the payment cryptography keys held in this account"),
           _P("payment-cryptography:GetKey",
              "read Exportable -- whether a key protecting card data can have its "
              "material taken out of the HSM boundary the service exists to provide"),
       ),
       remediation=(
           "Exportability is fixed when a key is created and cannot be changed, so this "
           "is a re-key rather than a setting change. Create a non-exportable "
           "replacement: aws payment-cryptography create-key --exportable false "
           "--key-attributes file://attrs.json --key-check-value-algorithm CMAC, migrate "
           "the workload to it, then aws payment-cryptography delete-key --key-identifier "
           "<OLD_ARN>"),
       risk=(
           "This AWS Payment Cryptography key is marked exportable, meaning its key "
           "material can be taken out of the service. The whole reason this service "
           "exists rather than KMS is the hardware boundary: keys used for PIN "
           "translation, card verification and data encryption under PCI PIN and PCI DSS "
           "are expected to live inside an HSM and never appear in the clear outside it. "
           "An exportable key makes that boundary optional -- the material can be "
           "wrapped out under another key and moved somewhere with weaker controls, and "
           "from a compliance standpoint the assurance the HSM was providing no longer "
           "holds in the same way. There are legitimate uses for exportability, chiefly "
           "key exchange with an acquirer or processor under a documented key ceremony, "
           "so this is worth reviewing rather than assuming wrong. What it should not be "
           "is incidental, and exportability cannot be revoked after creation."),
       impact=("The key material can be moved outside the HSM boundary that the service "
               "exists to provide, weakening the assurance behind card-data protection."),
       steps=(
           "Establish whether exportability is deliberate -- key exchange with an "
           "acquirer under a documented ceremony is a legitimate reason.",
           "If it is not, create a non-exportable replacement: aws payment-cryptography "
           "create-key --exportable false --key-attributes file://attrs.json "
           "--key-check-value-algorithm CMAC",
           "Migrate the workload and verify with a test transaction before removing the "
           "old key.",
           "Delete the old key once nothing uses it: aws payment-cryptography delete-key "
           "--key-identifier <OLD_ARN>",
           "Record the decision either way; a PCI assessor will ask why an exportable "
           "key exists, and 'nobody chose it' is the answer that costs time.")),

    _C(id="MBC-01", section="MANAGEDBLOCKCHAIN", severity="MEDIUM", compliance=_LOG,
       permissions=(
           _P("managedblockchain:ListMembers",
              "enumerate the blockchain network members owned by this account"),
           _P("managedblockchain:GetMember",
              "read LogPublishingConfiguration -- whether the member's certificate "
              "authority publishes logs, the CA being what admits identities to the "
              "network"),
       ),
       remediation=(
           "Turn on certificate-authority log publishing so identity enrolment leaves a "
           "record: aws managedblockchain update-member --network-id <NETWORK_ID> "
           "--member-id <MEMBER_ID> --log-publishing-configuration "
           "'{\"Fabric\":{\"CaLogs\":{\"Cloudwatch\":{\"Enabled\":true}}}}'"),
       risk=(
           "This Managed Blockchain member does not publish certificate-authority logs. "
           "In a Hyperledger Fabric network the member's CA is the component that "
           "enrols identities: every user and every application that transacts on the "
           "network holds a certificate the CA issued, and enrolment is therefore the "
           "moment at which access to the ledger is granted. Without CA logs there is no "
           "record of which identities were enrolled, when, or by whom -- which matters "
           "more here than for an ordinary audit trail, because a blockchain network is "
           "usually shared with other organisations and the ledger itself is immutable. "
           "A transaction written by an identity that should never have been enrolled "
           "cannot be undone, and without the enrolment record you cannot establish when "
           "the unauthorised identity appeared or what else it did. The ledger tells you "
           "what happened; the CA log is what tells you who was allowed to."),
       impact=("No record exists of which identities were enrolled on the network or by "
               "whom, and ledger entries written by an unauthorised identity cannot be "
               "traced back to its enrolment."),
       steps=(
           "Enable CA log publishing: aws managedblockchain update-member --network-id "
           "<NETWORK_ID> --member-id <MEMBER_ID> --log-publishing-configuration "
           "'{\"Fabric\":{\"CaLogs\":{\"Cloudwatch\":{\"Enabled\":true}}}}'",
           "Enable peer node logs as well for the transaction side of the picture: aws "
           "managedblockchain update-node --network-id <NETWORK_ID> --member-id "
           "<MEMBER_ID> --node-id <NODE_ID> --log-publishing-configuration file://cfg.json",
           "Set a retention period on the log groups that matches the network's "
           "governance agreement, not just your own policy.",
           "Reconcile currently-enrolled identities against your own records now, since "
           "the log will only cover enrolments from this point forward.")),
)
