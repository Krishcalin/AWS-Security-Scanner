#!/usr/bin/env python3
"""aws_extsvc6.py — extended AWS service coverage, batch 6.

Sixth batch off the gap analysis. The ranking was recomputed rather than reused, because
coverage had grown by 32 services since it was last generated — and recomputing turned up
three things worth recording before the checks themselves.

THE TOP THREE SCORERS WERE ALL UNBUILDABLE
-------------------------------------------
``mediastore`` (20) reached end of life on 2025-11-13 and was already declined in batch
4. ``waf`` and ``waf-regional`` (17 each) are **AWS WAF Classic**, whose support ended on
**2025-09-30**; OverWatch covers ``wafv2``, which is the successor. Three of the four
highest-ranked "gaps" were therefore services no account can still have. Checking
liveness before building became routine after MediaStore, and this batch is why it
should stay routine.

``es`` (16) was a false positive **in the ranking tool itself**: both ``es`` and
``opensearch`` sign as ``es`` — they are the same service at different API versions, and
the covered ``opensearch`` client already sees those domains. The analysis keyed on
client directory names rather than on signing names, so it counted one service twice.
That is fixed in the tool rather than worked around here.

WHAT EACH SERVICE CONTRIBUTES
------------------------------
* **Verified Permissions** — a Cedar policy store IS the authorization logic for an
  application. With schema validation ``OFF``, a policy may reference entity types that
  do not exist; it will not error, it will simply never match, and a policy that never
  matches is indistinguishable from one that was never written.
* **CloudHSM** — the cluster whose whole purpose is that key material never leaves it.
  Backups are the one thing that does leave, so their retention and sharing are the
  boundary.
* **Cloud WAN / Network Manager** — the core network policy is the segmentation of a
  global network; a resource policy on it shares the ability to read that topology.
* **Managed Grafana** — a workspace reaches *into* accounts to read data sources.
  ``ORGANIZATION`` access type means it reads across the organization.
* **Aurora DSQL** — deletion protection on a distributed SQL cluster.
* **IoT FleetWise** — vehicle telemetry: location traces, driver behaviour and
  diagnostics, which is personal data in most jurisdictions that have an opinion.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional, Sequence
from urllib.parse import unquote

from engine import aws_checkdef as _cd
from engine.aws_checkdef import CheckDef as _C, Perm as _P

__all__ = [
    "vp_policy_store", "hsm_cluster", "hsm_policy", "nwm_policy",
    "grafana_workspace", "dsql_cluster", "fleetwise_encryption", "fleetwise_logging",
    "VALIDATION_OFF", "ORG_ACCESS", "FW_DEFAULT", "LOG_OFF", "parse_doc",
    "DISCONTINUED",
]

# ── verified enum values ────────────────────────────────────────────────────
VALIDATION_OFF = "OFF"                       # verifiedpermissions ValidationMode
VALIDATION_STRICT = "STRICT"
PROTECTION_DISABLED = "DISABLED"             # verifiedpermissions DeletionProtection
ORG_ACCESS = "ORGANIZATION"                  # grafana AccountAccessType
FW_DEFAULT = "FLEETWISE_DEFAULT_ENCRYPTION"  # iotfleetwise EncryptionType
FW_KMS = "KMS_BASED_ENCRYPTION"
LOG_OFF = "OFF"                              # iotfleetwise LogType

#: Services that scored high in the gap analysis and are NOT built because AWS has
#: discontinued them. Recorded so the omissions are decisions with dates attached.
DISCONTINUED = {
    "mediastore": "2025-11-13",
    "waf": "2025-09-30",            # AWS WAF Classic; wafv2 is covered
    "waf-regional": "2025-09-30",
}


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


def _wildcard_policy(doc) -> bool:
    stmts = parse_doc(doc).get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    return any(_wide_principal(s) for s in (stmts or []) if isinstance(s, dict))


# ── Amazon Verified Permissions ─────────────────────────────────────────────
def vp_policy_store(store: Optional[dict]) -> dict:
    """Schema validation OFF lets a policy reference entities that do not exist."""
    s = _d(store)
    mode = _d(s.get("validationSettings")).get("mode") or ""
    protection = s.get("deletionProtection") or ""
    return {
        "id": s.get("policyStoreId") or "",
        "mode": mode,
        "mode_known": bool(mode),
        "validation_off": mode == VALIDATION_OFF,
        "protection": protection,
        "protection_known": bool(protection),
        "unprotected": protection == PROTECTION_DISABLED,
        "statement": (
            f"Verified Permissions policy store {s.get('policyStoreId')} has schema "
            f"validation OFF. A Cedar policy referencing an entity type that does not "
            f"exist is then accepted without error — it simply never matches, and a "
            f"policy that never matches is indistinguishable from one that was never "
            f"written. This store IS the authorization logic for whatever application "
            f"uses it"
            if mode == VALIDATION_OFF else ""),
        "protection_statement": (
            f"Verified Permissions policy store {s.get('policyStoreId')} has deletion "
            f"protection disabled — the authorization logic for an application can be "
            f"removed in one call, and what fails afterwards is every authorization "
            f"decision that depended on it"
            if protection == PROTECTION_DISABLED else ""),
    }


# ── AWS CloudHSM ────────────────────────────────────────────────────────────
def hsm_cluster(cluster: Optional[dict]) -> dict:
    """Backups are the one thing that leaves an HSM, so retention is the boundary."""
    c = _d(cluster)
    retention = _d(c.get("BackupRetentionPolicy"))
    days = retention.get("Value")
    return {
        "id": c.get("ClusterId") or "",
        "state": c.get("State") or "",
        "backup_policy": c.get("BackupPolicy") or "",
        "retention_days": days,
        "retention_known": bool(retention),
        "statement": (
            f"CloudHSM cluster {c.get('ClusterId')} has no backup retention policy set, "
            f"so the retention of its backups is whatever the service default happens to "
            f"be rather than a decision. Backups are the ONE artefact that leaves an HSM "
            f"— the entire premise of the service is that key material does not — so how "
            f"long they exist and who can reach them is the boundary that matters"
            if not retention else ""),
    }


def hsm_policy(cluster_or_backup: str, policy) -> dict:
    """A resource policy on an HSM backup shares restorable key material."""
    return {
        "resource": cluster_or_backup or "",
        "has_policy": bool(parse_doc(policy).get("Statement")),
        "public": _wildcard_policy(policy),
        "statement": (
            f"CloudHSM resource {cluster_or_backup} has a resource policy granting a "
            f"wildcard principal. A CloudHSM backup can be restored into another "
            f"cluster, so sharing one shares the key material it contains — which is the "
            f"single thing the service exists to prevent leaving"
            if _wildcard_policy(policy) else ""),
    }


# ── AWS Cloud WAN / Network Manager ─────────────────────────────────────────
def nwm_policy(network_id: str, policy) -> dict:
    """A resource policy on a global network shares the topology itself."""
    return {
        "network": network_id or "",
        "has_policy": bool(parse_doc(policy).get("Statement")),
        "public": _wildcard_policy(policy),
        "statement": (
            f"Cloud WAN global network {network_id} has a resource policy granting a "
            f"wildcard principal. The core network policy is the segmentation of the "
            f"whole global network — which segments exist, what may route between them, "
            f"and where every attachment lands — so reading it is reading the map an "
            f"attacker would otherwise have to build"
            if _wildcard_policy(policy) else ""),
    }


# ── Amazon Managed Grafana ──────────────────────────────────────────────────
def grafana_workspace(workspace: Optional[dict],
                      auth: Optional[dict] = None) -> dict:
    """``ORGANIZATION`` access reaches across accounts to read data sources."""
    w = _d(workspace)
    access = w.get("accountAccessType") or ""
    providers = [str(p) for p in _l(_d(auth).get("providers"))]
    return {
        "id": w.get("id") or "",
        "name": w.get("name") or w.get("id") or "",
        "access_type": access,
        "access_known": bool(access),
        "organization_wide": access == ORG_ACCESS,
        "providers": tuple(providers),
        "auth_known": bool(auth),
        "sources": tuple(str(d) for d in _l(w.get("dataSources"))),
        "statement": (
            f"Managed Grafana workspace {w.get('name') or w.get('id')} uses "
            f"ORGANIZATION account access, so its role reaches into other accounts in "
            f"the organization to read data sources. A Grafana workspace is a read path "
            f"into observability data across the estate, and anyone who can sign in to "
            f"it inherits that reach"
            if access == ORG_ACCESS else ""),
    }


# ── Amazon Aurora DSQL ──────────────────────────────────────────────────────
def dsql_cluster(cluster: Optional[dict]) -> dict:
    c = _d(cluster)
    dp = c.get("deletionProtectionEnabled")
    return {
        "id": c.get("identifier") or "",
        "status": c.get("status") or "",
        "protection_known": isinstance(dp, bool),
        "protected": dp is True,
        "encryption": _d(c.get("encryptionDetails")).get("encryptionType") or "",
        "statement": (
            f"Aurora DSQL cluster {c.get('identifier')} has deletion protection "
            f"disabled. DSQL is a distributed SQL database intended for workloads that "
            f"cannot be down, and a cluster deleted by an errant script or a compromised "
            f"credential takes its data with it — deletion protection is the control "
            f"that turns that from one API call into a deliberate act"
            if dp is False else ""),
    }


# ── AWS IoT FleetWise ───────────────────────────────────────────────────────
def fleetwise_encryption(config: Optional[dict]) -> dict:
    c = _d(config)
    t = c.get("encryptionType") or ""
    return {
        "type": t,
        "known": bool(t),
        "cmk": t == FW_KMS,
        "key": c.get("kmsKeyId") or "",
        "status": c.get("encryptionStatus") or "",
        "statement": (
            "IoT FleetWise uses the default service encryption rather than a "
            "customer-managed key. FleetWise carries vehicle telemetry — location "
            "traces, driver behaviour, diagnostic trouble codes — which is personal data "
            "in every jurisdiction that has an opinion about it, and a location history "
            "is among the most re-identifiable datasets there is"
            if t == FW_DEFAULT else ""),
    }


def fleetwise_logging(options: Optional[dict]) -> dict:
    o = _d(options)
    log_type = _d(o.get("cloudWatchLogDelivery")).get("logType") or ""
    return {
        "log_type": log_type,
        "known": bool(log_type),
        "off": log_type == LOG_OFF,
        "statement": (
            "IoT FleetWise log delivery is OFF, so campaign and data-collection errors "
            "are not recorded. A collection scheme that silently stops working looks "
            "identical to a fleet with nothing to report, and the gap only becomes "
            "visible when somebody asks for data that was never gathered"
            if log_type == LOG_OFF else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Declarations
# ══════════════════════════════════════════════════════════════════════════════
_ACC = {"PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"}
_ENC = {"PCI-DSS": "3.5.1", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1",
        "NIST": "SC-28"}
_LOG = {"PCI-DSS": "10.2.1", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"}
_KEY = {"PCI-DSS": "3.6.1", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1",
        "NIST": "SC-12"}
_AVL = {"PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(7)", "SOC2": "A1.2", "NIST": "CP-9"}
_CFG = {"PCI-DSS": "6.5.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC8.1", "NIST": "CM-6"}

CHECKS = _cd.register(
    _C(id="VP-01", section="VERIFIEDPERMISSIONS", severity="HIGH", compliance=_CFG,
       permissions=(
           _P("verifiedpermissions:ListPolicyStores",
              "enumerate the Cedar policy stores that hold application authorization "
              "logic in this account"),
           _P("verifiedpermissions:GetPolicyStore",
              "read validationSettings.mode -- with validation OFF a policy may "
              "reference entity types that do not exist and will silently never match"),
       ),
       remediation=(
           "Turn schema validation on so a policy referencing a nonexistent entity type "
           "is rejected at write time rather than silently never matching: aws "
           "verifiedpermissions update-policy-store --policy-store-id <ID> "
           "--validation-settings mode=STRICT. Expect existing policies to fail "
           "validation -- that is the point, and each failure is a policy that was not "
           "doing what it appeared to"),
       risk=(
           "This Verified Permissions policy store has Cedar schema validation set to "
           "OFF. The consequence is specific and quiet. With validation off, a policy "
           "that references an entity type or attribute which does not exist in the "
           "schema is accepted without complaint. It does not error at write time and it "
           "does not error at evaluation time -- it simply never matches. A policy that "
           "never matches is indistinguishable, from the outside, from a policy that was "
           "never written: the store lists it, a reviewer reads it and concludes the "
           "rule is in force, and the authorization decision it was meant to govern "
           "falls through to whatever else applies. Because a policy store IS the "
           "authorization logic for the application using it, a typo in an entity type "
           "is not a broken rule in a config file, it is an access control that exists "
           "only on paper. Validation is the only thing that turns that from silent into "
           "loud."),
       impact=("A policy referencing a nonexistent entity is accepted and never matches, "
               "so an authorization rule that appears to be in force governs nothing."),
       steps=(
           "Read the current setting: aws verifiedpermissions get-policy-store "
           "--policy-store-id <ID>",
           "Ensure a schema is actually defined first, or STRICT will reject everything: "
           "aws verifiedpermissions get-schema --policy-store-id <ID>",
           "Turn validation on: aws verifiedpermissions update-policy-store "
           "--policy-store-id <ID> --validation-settings mode=STRICT",
           "Work through the policies that now fail validation -- each one is a rule "
           "that was not doing what it appeared to, so treat the list as findings rather "
           "than as breakage.")),

    _C(id="VP-02", section="VERIFIEDPERMISSIONS", severity="MEDIUM", compliance=_AVL,
       permissions=(
           _P("verifiedpermissions:GetPolicyStore",
              "read deletionProtection -- whether the authorization logic for an "
              "application can be deleted in a single call"),
       ),
       remediation=(
           "Enable deletion protection on the policy store: aws verifiedpermissions "
           "update-policy-store --policy-store-id <ID> --deletion-protection "
           "mode=ENABLED. Confirm with aws verifiedpermissions get-policy-store "
           "--policy-store-id <ID>"),
       risk=(
           "This Verified Permissions policy store has deletion protection disabled, so "
           "it can be removed in a single API call. What makes that worth a check rather "
           "than a shrug is what fails afterwards. A policy store is not data the "
           "application can rebuild or do without -- it is the authorization logic, and "
           "an application whose policy store has vanished does not fail open or closed "
           "in some predictable way, it fails however that application happens to handle "
           "an authorization backend that has stopped existing. For an errant script "
           "that is an outage; for a compromised credential it is a way to disable "
           "access control across an application without touching the application at "
           "all, and without the noise that editing individual policies would make."),
       impact=("The authorization logic for an application can be deleted in one call, "
               "with the failure mode depending entirely on how that application handles "
               "a missing authorization backend."),
       steps=(
           "Enable it: aws verifiedpermissions update-policy-store --policy-store-id "
           "<ID> --deletion-protection mode=ENABLED",
           "Confirm: aws verifiedpermissions get-policy-store --policy-store-id <ID>",
           "Check who holds verifiedpermissions:DeletePolicyStore while you are here; "
           "protection raises the bar rather than removing the permission.")),

    _C(id="HSM-01", section="CLOUDHSM", severity="MEDIUM", compliance=_AVL,
       permissions=(
           _P("cloudhsm:DescribeClusters",
              "read the backup retention policy on each CloudHSM cluster -- backups are "
              "the one artefact that leaves an HSM"),
       ),
       remediation=(
           "Set an explicit backup retention policy rather than relying on whatever the "
           "default happens to be: aws cloudhsmv2 modify-cluster --cluster-id "
           "<CLUSTER_ID> --hsm-type <TYPE> --backup-retention-policy "
           "Type=DAYS,Value=<DAYS>. Review existing backups for ones marked NeverExpires "
           "with aws cloudhsmv2 describe-backups"),
       risk=(
           "This CloudHSM cluster has no explicit backup retention policy, so how long "
           "its backups persist is whatever the service default happens to be rather "
           "than a decision anybody made. The reason this matters more for CloudHSM than "
           "for an ordinary backup setting is the premise of the service: a hardware "
           "security module exists so that key material never leaves it in usable form, "
           "and the backup is the single exception -- an encrypted artefact that CAN be "
           "restored into another cluster and therefore carries the keys with it. "
           "Retention is thus not a storage question but the answer to how long "
           "restorable copies of your key material exist and how many of them there are. "
           "Backups marked NeverExpires are the sharp end of this: they persist "
           "indefinitely, outliving the cluster, the workload and usually the people who "
           "knew why they were kept."),
       impact=("The number and lifetime of restorable copies of the cluster's key "
               "material is set by a default rather than by a decision."),
       steps=(
           "Read the current state: aws cloudhsmv2 describe-clusters",
           "Set an explicit policy: aws cloudhsmv2 modify-cluster --cluster-id "
           "<CLUSTER_ID> --hsm-type <TYPE> --backup-retention-policy "
           "Type=DAYS,Value=<DAYS>",
           "Audit existing backups, particularly any with NeverExpires set: aws "
           "cloudhsmv2 describe-backups",
           "Confirm who can call cloudhsm:RestoreBackup and cloudhsm:CopyBackupToRegion "
           "-- retention bounds how long a backup exists, those bound who can use it.")),

    _C(id="HSM-02", section="CLOUDHSM", severity="HIGH", compliance=_KEY,
       permissions=(
           _P("cloudhsm:GetResourcePolicy",
              "read the resource policy on CloudHSM backups -- a shared backup can be "
              "restored elsewhere, and restoring it restores the key material"),
       ),
       remediation=(
           "Remove the wildcard principal from the CloudHSM resource policy: aws "
           "cloudhsmv2 get-resource-policy --resource-arn <ARN> to read it, then aws "
           "cloudhsmv2 put-resource-policy --resource-arn <ARN> --policy "
           "file://scoped-policy.json naming specific accounts. Treat the key material "
           "as having been shareable for as long as the policy stood"),
       risk=(
           "This CloudHSM resource has a policy granting a wildcard principal. A "
           "CloudHSM backup is restorable into a different cluster, which means sharing "
           "one is not sharing a copy of some data -- it is sharing the key material "
           "itself, in a form the recipient can bring back to life. That is precisely "
           "and only the thing the service exists to prevent: the entire security "
           "argument for a hardware security module is that keys do not leave it in a "
           "usable form, and a shared backup is an exception to that argument granted by "
           "a policy statement. The consequences do not stop at the keys either. "
           "Whatever those keys protect -- database encryption, payment processing, "
           "certificate issuance, document signing -- inherits the exposure, and unlike "
           "a leaked credential there is no rotation that undoes a backup somebody "
           "already copied."),
       impact=("Restorable key material is shared beyond the account, and everything "
               "those keys protect inherits the exposure with no rotation that undoes a "
               "copy already taken."),
       steps=(
           "Read the policy: aws cloudhsmv2 get-resource-policy --resource-arn <ARN>",
           "Replace it with one naming specific accounts, or remove it: aws cloudhsmv2 "
           "put-resource-policy --resource-arn <ARN> --policy file://scoped-policy.json",
           "Establish how long it stood, from CloudTrail PutResourcePolicy events, and "
           "treat the key material as exposed for that window.",
           "Plan key rotation for anything the cluster protects -- a backup that was "
           "copied cannot be un-copied, so the keys themselves are what has to change.")),

    _C(id="NWM-01", section="CLOUDWAN", severity="MEDIUM", compliance=_ACC,
       permissions=(
           _P("networkmanager:DescribeGlobalNetworks",
              "enumerate the Cloud WAN global networks this account owns"),
           _P("networkmanager:GetResourcePolicy",
              "read the resource policy -- the core network policy it governs is the "
              "segmentation map of the entire global network"),
       ),
       remediation=(
           "Remove the wildcard principal from the global network resource policy: aws "
           "networkmanager get-resource-policy --resource-arn <ARN> to read it, then aws "
           "networkmanager put-resource-policy --resource-arn <ARN> --policy-document "
           "file://scoped-policy.json naming specific accounts or an aws:PrincipalOrgID "
           "condition"),
       risk=(
           "This Cloud WAN global network has a resource policy granting a wildcard "
           "principal. What that exposes is the core network policy, and a core network "
           "policy is not configuration in the ordinary sense -- it is the segmentation "
           "design of the entire global network written down in one document: which "
           "segments exist, which may route to which, where every VPC and every "
           "on-premises connection attaches, and which attachments are isolated from the "
           "rest. For anyone planning lateral movement that is the map they would "
           "otherwise have to assemble slowly and noisily from the inside, handed over "
           "in a single read. It also reveals the shape of the organisation itself: "
           "segment names and attachment layout tend to mirror business units, "
           "environments and acquisitions in a way no diagram is ever kept as current as."),
       impact=("The segmentation design of the whole global network -- segments, routing "
               "between them, and every attachment -- is readable outside the account."),
       steps=(
           "Read the policy: aws networkmanager get-resource-policy --resource-arn <ARN>",
           "Replace it with one naming specific accounts, or gated on "
           "aws:PrincipalOrgID: aws networkmanager put-resource-policy --resource-arn "
           "<ARN> --policy-document file://scoped-policy.json",
           "Review the core network policy itself while you are here for segments that "
           "route more widely than intended: aws networkmanager get-core-network-policy "
           "--core-network-id <ID>",
           "Confirm cross-account attachments were each approved deliberately: aws "
           "networkmanager list-attachments --core-network-id <ID>")),

    _C(id="GRF-01", section="MANAGEDGRAFANA", severity="MEDIUM", compliance=_ACC,
       permissions=(
           _P("grafana:ListWorkspaces",
              "enumerate the Managed Grafana workspaces in this account"),
           _P("grafana:DescribeWorkspace",
              "read accountAccessType -- ORGANIZATION means the workspace role reaches "
              "into other accounts to read data sources"),
       ),
       remediation=(
           "Narrow the workspace to the current account unless organization-wide reach "
           "is deliberate: aws grafana update-workspace --workspace-id <ID> "
           "--account-access-type CURRENT_ACCOUNT. If it must stay organization-wide, "
           "scope the workspace role and review who can sign in with aws grafana "
           "describe-workspace-authentication --workspace-id <ID>"),
       risk=(
           "This Managed Grafana workspace uses ORGANIZATION account access, so its role "
           "reaches into other accounts across the organization to read data sources. "
           "That is a supported and sometimes intended configuration, which is why this "
           "is worth reviewing rather than assuming wrong -- but the reach is easy to "
           "underestimate. A Grafana workspace is a read path into observability data "
           "across the estate: CloudWatch metrics and logs, Prometheus, OpenSearch, "
           "Athena, Redshift. Logs in particular are the least curated data any "
           "organisation holds, routinely containing request payloads, identifiers and "
           "occasionally credentials that nobody intended to persist. Anyone who can "
           "sign in to the workspace inherits that reach, so the effective audience is "
           "decided by the workspace's authentication configuration rather than by IAM, "
           "and the two are administered by different people more often than not."),
       impact=("The workspace role reads observability data across the organization, and "
               "everyone who can sign in to the workspace inherits that reach."),
       steps=(
           "Establish whether organization-wide access is deliberate before changing it "
           "-- narrowing it will break dashboards.",
           "If it is not: aws grafana update-workspace --workspace-id <ID> "
           "--account-access-type CURRENT_ACCOUNT",
           "Review who can actually sign in, which is where the audience is really set: "
           "aws grafana describe-workspace-authentication --workspace-id <ID>",
           "Check the workspace role's permissions against the data sources it genuinely "
           "needs rather than the ones it was granted at setup.")),

    _C(id="DSQL-01", section="AURORADSQL", severity="MEDIUM", compliance=_AVL,
       permissions=(
           _P("dsql:ListClusters",
              "enumerate the Aurora DSQL clusters in this account and region"),
           _P("dsql:GetCluster",
              "read deletionProtectionEnabled on each cluster, which decides whether "
              "deletion is one API call or a deliberate act"),
       ),
       remediation=(
           "Enable deletion protection on the cluster: aws dsql update-cluster "
           "--identifier <CLUSTER_ID> --deletion-protection-enabled. Confirm with aws "
           "dsql get-cluster --identifier <CLUSTER_ID>"),
       risk=(
           "This Aurora DSQL cluster has deletion protection disabled, so it can be "
           "deleted in a single API call. DSQL is a distributed SQL database aimed "
           "squarely at workloads that are expected to stay up, which shapes both halves "
           "of the risk: the data in it is usually operational rather than archival, and "
           "the application in front of it usually has no path that tolerates the "
           "database not being there. An accidental deletion by an over-broad script is "
           "the common case and is bad enough. The deliberate case is worse and is why "
           "this is a security check rather than an operational one: destroying data is "
           "a recognised objective in its own right for ransomware and for an attacker "
           "covering their tracks, and a cluster that deletes on one unprotected call is "
           "the cheapest possible way to achieve it."),
       impact=("The cluster and its data can be destroyed in a single API call, by an "
               "errant script or by a credential holder who intends it."),
       steps=(
           "Enable protection: aws dsql update-cluster --identifier <CLUSTER_ID> "
           "--deletion-protection-enabled",
           "Confirm: aws dsql get-cluster --identifier <CLUSTER_ID>",
           "Review who holds dsql:DeleteCluster -- protection raises the bar, it does "
           "not remove the permission.",
           "Confirm a restore path exists that does not depend on the cluster itself.")),

    _C(id="FW-01", section="FLEETWISE", severity="HIGH", compliance=_ENC,
       permissions=(
           _P("iotfleetwise:GetEncryptionConfiguration",
              "read encryptionType -- whether vehicle telemetry, which is personal data "
              "in most jurisdictions, sits under a customer-managed key"),
       ),
       remediation=(
           "Move IoT FleetWise to a customer-managed key: aws iotfleetwise "
           "put-encryption-configuration --kms-key-id <KEY_ARN> --encryption-type "
           "KMS_BASED_ENCRYPTION. Confirm with aws iotfleetwise "
           "get-encryption-configuration, since the change reports a status"),
       risk=(
           "IoT FleetWise is using the default service encryption rather than a "
           "customer-managed key. FleetWise carries vehicle telemetry, and vehicle "
           "telemetry is a category worth naming precisely: location traces, speed and "
           "braking behaviour, diagnostic trouble codes, and whatever else the signal "
           "catalogue collects. In most jurisdictions with an opinion on the matter that "
           "is personal data, and location history specifically is among the most "
           "re-identifiable datasets that exists -- a handful of points is generally "
           "enough to identify an individual, because the place someone sleeps and the "
           "place they work are together close to unique. That makes the difference "
           "between a service-owned key and a customer-managed one more consequential "
           "here than for most datastores: a CMK is a separately administered gate whose "
           "grants can be audited and revoked without touching FleetWise."),
       impact=("Vehicle location traces and driver behaviour data sit under a "
               "service-owned key, with no separately-administered control over who "
               "reads them."),
       steps=(
           "Create or choose a CMK whose key policy names only the roles that "
           "legitimately read fleet data.",
           "Apply it: aws iotfleetwise put-encryption-configuration --kms-key-id "
           "<KEY_ARN> --encryption-type KMS_BASED_ENCRYPTION",
           "Confirm the status rather than assuming: aws iotfleetwise "
           "get-encryption-configuration",
           "Review the signal catalogue against what you actually need: the strongest "
           "control over personal data is not collecting it, and catalogues tend to grow "
           "by accretion.")),

    _C(id="FW-02", section="FLEETWISE", severity="MEDIUM", compliance=_LOG,
       permissions=(
           _P("iotfleetwise:GetLoggingOptions",
              "read the CloudWatch log delivery type -- OFF means campaign and "
              "collection errors are not recorded anywhere"),
       ),
       remediation=(
           "Turn log delivery on so collection failures are recorded: aws iotfleetwise "
           "put-logging-options --cloud-watch-log-delivery "
           "logType=ERROR,logGroupName=<LOG_GROUP>. Confirm with aws iotfleetwise "
           "get-logging-options"),
       risk=(
           "IoT FleetWise log delivery is set to OFF, so campaign and data-collection "
           "errors are not recorded. The failure this hides is a quiet one: a collection "
           "scheme that has stopped working produces exactly the same observable as a "
           "fleet with nothing to report -- no data. Nobody is paged, no alarm fires, and "
           "the gap only becomes visible much later when somebody asks a question of "
           "data that was never gathered. For fleet telemetry that question is often a "
           "safety investigation or a warranty dispute, where the absence of data is not "
           "neutral. There is a security reading too, and it is the same shape as "
           "elsewhere in this codebase: with no error record, a campaign that was "
           "tampered with, misconfigured or quietly disabled is indistinguishable from "
           "one that is working."),
       impact=("Collection failures go unrecorded, so a campaign that has stopped working "
               "is indistinguishable from a fleet with nothing to report."),
       steps=(
           "Enable delivery: aws iotfleetwise put-logging-options --cloud-watch-log-"
           "delivery logType=ERROR,logGroupName=<LOG_GROUP>",
           "Confirm: aws iotfleetwise get-logging-options",
           "Alarm on the log group rather than only writing to it -- an unwatched error "
           "log answers the question afterwards but does not raise it.",
           "Reconcile expected against received vehicle counts periodically; that is the "
           "check that catches silent collection loss.")),
)
