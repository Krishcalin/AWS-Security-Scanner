#!/usr/bin/env python3
"""aws_extsvc3.py — extended AWS service coverage, batch 3.

Third batch off the 426-service gap analysis, and the first written on the registry from
the start rather than retrofitted onto it. Each check is one ``CheckDef``; the severity,
compliance mapping, remediation, detail page and permission-ledger entry all fall out of
it, and a half-declared check will not import.

Every field was verified against the botocore service model before the classifier was
written — the operation exists, the field exists, and the enum values below are AWS's.

WHAT EACH SERVICE CONTRIBUTES
------------------------------
* **S3 Tables** — a table bucket is S3 with an Iceberg catalog on top, holding analytical
  data. It has its *own* policy and its *own* encryption settings, entirely separate from
  the S3 checks OverWatch already runs, so an S3 audit says nothing about it.
* **VPC Lattice** — ``authType`` has exactly two values, and one of them is ``NONE``.
  A Lattice service with ``NONE`` accepts requests from anything that can reach it on the
  network, with no caller identity involved at all.
* **CodeArtifact** — a permissive domain or repository policy makes your internal package
  registry readable by accounts you do not control. Package registries are a supply-chain
  position: reading them reveals your dependency graph and your internal library names.
* **Directory Service** — ``LDAPSStatus`` of ``Disabled`` means directory traffic is
  plain LDAP: credentials and directory contents in cleartext. Directories are also
  shareable across accounts, which extends an authentication boundary.
* **Managed Prometheus** — a workspace with no ``kmsKeyArn`` is on an AWS-owned key, and
  metrics are more sensitive than they look: they leak topology, hostnames and traffic
  patterns.
* **X-Ray** — ``Type`` of ``NONE`` means default encryption rather than a CMK. Traces
  carry URLs, headers and SQL fragments.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional, Sequence
from urllib.parse import unquote

from engine import aws_checkdef as _cd
from engine.aws_checkdef import CheckDef as _C, Perm as _P

__all__ = [
    "table_bucket_policy", "table_bucket_encryption",
    "lattice_auth", "lattice_auth_policy",
    "codeartifact_policy", "directory_ldaps", "directory_sharing",
    "amp_workspace", "amp_logging", "xray_encryption",
    "AUTH_NONE", "LDAPS_DISABLED", "ENC_NONE", "AES256", "parse_doc",
]

# ── verified enum values ────────────────────────────────────────────────────
AUTH_NONE = "NONE"              # vpc-lattice AuthType: NONE | AWS_IAM
AUTH_IAM = "AWS_IAM"
LDAPS_DISABLED = "Disabled"     # ds LDAPSStatus: Enabling|Enabled|EnableFailed|Disabled
LDAPS_ENABLED = "Enabled"
ENC_NONE = "NONE"               # xray EncryptionType: NONE | KMS
ENC_KMS = "KMS"
AES256 = "AES256"               # s3tables sseAlgorithm; the KMS value is aws:kms
SSE_KMS = "aws:kms"


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


def _stmts(doc) -> List[dict]:
    st = parse_doc(doc).get("Statement")
    if isinstance(st, dict):
        st = [st]
    return [s for s in (st or []) if isinstance(s, dict)]


def _wild(v) -> bool:
    if isinstance(v, str):
        return v.strip() == "*"
    return any(str(x).strip() == "*" for x in _l(v))


def _wide_principal(stmt: dict) -> bool:
    if stmt.get("Effect") != "Allow":
        return False
    p = stmt.get("Principal")
    return p == "*" or _wild(p) or _wild(_d(p).get("AWS"))


# ── Amazon S3 Tables ────────────────────────────────────────────────────────
def table_bucket_policy(arn: str, policy) -> dict:
    """A table bucket has its OWN policy, separate from every S3 check already run."""
    stmts = _stmts(policy)
    wide = [s for s in stmts if _wide_principal(s)]
    return {
        "arn": arn or "",
        "has_policy": bool(stmts),
        "public": bool(wide),
        "statement": (
            f"S3 Tables bucket {arn} has a resource policy granting a wildcard principal "
            f"— a table bucket holds analytical data behind its own Iceberg catalog, and "
            f"its policy is entirely separate from the S3 bucket policies audited "
            f"elsewhere, so nothing else in this scan covers it"
            if wide else ""),
    }


def table_bucket_encryption(arn: str, config: Optional[dict]) -> dict:
    """``sseAlgorithm`` of AES256 is SSE-S3; a CMK requires aws:kms."""
    c = _d(config)
    alg = c.get("sseAlgorithm") or ""
    key = c.get("kmsKeyArn") or ""
    return {
        "arn": arn or "",
        "algorithm": alg,
        "known": bool(alg),
        "kms": alg == SSE_KMS,
        "key": key,
        "statement": (
            f"S3 Tables bucket {arn} uses {alg} rather than a customer-managed KMS key, "
            f"so access to the data is governed by the bucket policy alone with no "
            f"second, key-level control to revoke"
            if alg and alg != SSE_KMS else ""),
    }


# ── Amazon VPC Lattice ──────────────────────────────────────────────────────
def lattice_auth(service: Optional[dict]) -> dict:
    """``authType`` has two values and one of them is NONE."""
    s = _d(service)
    at = s.get("authType") or ""
    return {
        "id": s.get("id") or "",
        "name": s.get("name") or s.get("id") or "",
        "auth_type": at,
        "known": bool(at),
        "unauthenticated": at == AUTH_NONE,
        "statement": (
            f"VPC Lattice service {s.get('name') or s.get('id')} has authType NONE — it "
            f"accepts requests from anything that can reach it on the network, with no "
            f"caller identity involved at all. Lattice exists to connect services across "
            f"VPC and account boundaries, so 'anything that can reach it' is a wider set "
            f"than a single VPC"
            if at == AUTH_NONE else ""),
    }


def lattice_auth_policy(name: str, policy) -> dict:
    """An AWS_IAM service whose auth policy still allows any principal."""
    stmts = _stmts(policy)
    wide = [s for s in stmts if _wide_principal(s)]
    return {
        "service": name or "",
        "has_policy": bool(stmts),
        "permissive": bool(wide),
        "statement": (
            f"VPC Lattice service {name} requires IAM auth but its auth policy allows a "
            f"wildcard principal — the authentication is real and the authorization "
            f"admits everyone, so requiring IAM buys only that the caller has some AWS "
            f"identity"
            if wide else ""),
    }


# ── AWS CodeArtifact ────────────────────────────────────────────────────────
def codeartifact_policy(kind: str, name: str, policy) -> dict:
    """Domain and repository policies share a shape; ``kind`` names which."""
    stmts = _stmts(policy)
    wide = [s for s in stmts if _wide_principal(s)]
    return {
        "kind": kind or "",
        "name": name or "",
        "has_policy": bool(stmts),
        "public": bool(wide),
        "statement": (
            f"CodeArtifact {kind} {name} has a permissions policy granting a wildcard "
            f"principal — your internal package registry is readable outside your "
            f"account. Reading it exposes the dependency graph and the names of internal "
            f"libraries, which is the reconnaissance a dependency-confusion attack needs"
            if wide else ""),
    }


# ── AWS Directory Service ───────────────────────────────────────────────────
def directory_ldaps(directory_id: str, settings: Optional[Sequence]) -> dict:
    """``LDAPSStatus`` of Disabled means plain LDAP: cleartext on the wire."""
    rows = [_d(x) for x in _l(settings)]
    statuses = [str(r.get("LDAPSStatus") or "") for r in rows if r.get("LDAPSStatus")]
    disabled = [s for s in statuses if s == LDAPS_DISABLED]
    failed = [s for s in statuses if s == "EnableFailed"]
    return {
        "directory": directory_id or "",
        "statuses": tuple(statuses),
        "known": bool(statuses),
        "disabled": bool(disabled),
        "failed": bool(failed),
        "statement": (
            f"Directory {directory_id} has LDAPS disabled — directory traffic is plain "
            f"LDAP, so bind credentials and directory contents cross the network in "
            f"cleartext. A directory is the authentication source for everything joined "
            f"to it, which makes those credentials unusually valuable"
            if disabled else
            f"Directory {directory_id} has LDAPS in EnableFailed state — it is NOT "
            f"protecting traffic, and the failure is easy to miss because the setting "
            f"looks configured"
            if failed else ""),
    }


def directory_sharing(directory_id: str, shared: Optional[Sequence],
                      owned_accounts: Optional[Sequence] = None) -> dict:
    """Directories shared to accounts outside a known set."""
    trusted = {str(a) for a in _l(owned_accounts)}
    external = []
    for sh in _l(shared):
        d = _d(sh)
        acct = str(d.get("SharedAccountId") or "")
        if acct and acct not in trusted:
            external.append(acct)
    return {
        "directory": directory_id or "",
        "shared_with": tuple(sorted(set(external))),
        "shared": bool(external),
        "statement": (
            f"Directory {directory_id} is shared with account(s) "
            f"{', '.join(sorted(set(external)))} — sharing a directory extends an "
            f"AUTHENTICATION boundary, so principals in those accounts can join "
            f"resources to your directory and authenticate against it"
            if external else ""),
    }


# ── Amazon Managed Service for Prometheus ───────────────────────────────────
def amp_workspace(workspace: Optional[dict]) -> dict:
    """No ``kmsKeyArn`` means the workspace is on an AWS-owned key."""
    w = _d(workspace)
    key = w.get("kmsKeyArn") or ""
    return {
        "id": w.get("workspaceId") or "",
        "alias": w.get("alias") or "",
        "cmk": bool(key),
        "key": key,
        "statement": (
            f"Prometheus workspace {w.get('workspaceId')} has no customer-managed KMS "
            f"key, so its metrics sit under an AWS-owned key you cannot audit or revoke. "
            f"Metrics are more sensitive than they look: they carry hostnames, service "
            f"topology and traffic patterns, which is a map of the estate"
            if not key else ""),
    }


def amp_logging(workspace_id: str, config: Optional[dict]) -> dict:
    """A workspace with no log destination."""
    c = _d(config)
    dest = _d(c.get("logGroupArn")) if isinstance(c.get("logGroupArn"), dict) else c.get("logGroupArn")
    has = bool(dest)
    return {
        "id": workspace_id or "",
        "logging": has,
        "statement": (
            f"Prometheus workspace {workspace_id} has no logging configuration, so rule "
            f"evaluation failures and ingestion errors are not recorded anywhere — a "
            f"silently broken alerting rule looks identical to one that never fired"
            if not has else ""),
    }


# ── AWS X-Ray ───────────────────────────────────────────────────────────────
def xray_encryption(config: Optional[dict]) -> dict:
    """``Type`` of NONE means default encryption rather than a CMK."""
    c = _d(config)
    t = c.get("Type") or ""
    return {
        "type": t,
        "status": c.get("Status") or "",
        "known": bool(t),
        "cmk": t == ENC_KMS,
        "key": c.get("KeyId") or "",
        "statement": (
            "X-Ray traces are encrypted with the default AWS-owned key rather than a "
            "customer-managed one (EncryptionConfig Type is NONE). Traces are not "
            "metadata: they routinely carry full request URLs with query strings, header "
            "values, and annotated SQL fragments, so they are a readable record of what "
            "the application does with its data"
            if t == ENC_NONE else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Declarations
# ══════════════════════════════════════════════════════════════════════════════
_ENC = {"PCI-DSS": "3.5.1", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1",
        "NIST": "SC-28"}
_ACC = {"PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"}
_NET = {"PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"}
_TLS = {"PCI-DSS": "4.2.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-8"}
_LOG = {"PCI-DSS": "10.2.1", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"}

CHECKS = _cd.register(
    _C(id="S3T-01", section="S3TABLES", severity="HIGH", compliance=_ACC,
       permissions=(
           _P("s3tables:ListTableBuckets",
              "enumerate S3 Tables buckets, which are separate resources from S3 "
              "buckets and are not covered by any existing S3 check"),
           _P("s3tables:GetTableBucketPolicy",
              "read the table bucket resource policy, which is distinct from an S3 "
              "bucket policy and governs the analytical data behind it"),
       ),
       remediation=(
           "Remove the wildcard principal from the table bucket policy — this is a "
           "separate policy from any S3 bucket policy: aws s3tables "
           "get-table-bucket-policy --table-bucket-arn <ARN> to read it, then aws "
           "s3tables put-table-bucket-policy --table-bucket-arn <ARN> --resource-policy "
           "file://scoped-policy.json naming specific principals or an "
           "aws:PrincipalOrgID condition"),
       risk=(
           "This S3 Tables bucket has a resource policy granting a wildcard principal. "
           "S3 Tables is worth checking separately rather than folding into the S3 "
           "review, because a table bucket is a distinct resource type with its own "
           "policy API, its own encryption settings and its own permission model -- the "
           "S3 bucket-policy checks OverWatch already runs do not see it at all, so an "
           "account can pass every S3 check while its analytical data is world-readable. "
           "What sits behind a table bucket also tends to be the aggregated end of the "
           "data estate: Iceberg tables built for analytics generally contain the joined "
           "and enriched version of whatever the operational stores hold, which makes a "
           "single table more revealing than the individual sources it was built from."),
       impact=("The table bucket's analytical data is readable outside your account "
               "through a policy no existing S3 check inspects."),
       steps=(
           "Read the current policy: aws s3tables get-table-bucket-policy "
           "--table-bucket-arn <ARN>",
           "Replace it with one naming specific principals, or gated on "
           "aws:PrincipalOrgID: aws s3tables put-table-bucket-policy --table-bucket-arn "
           "<ARN> --resource-policy file://scoped-policy.json",
           "Check the individual tables too -- they carry their own policies: aws "
           "s3tables get-table-policy --table-bucket-arn <ARN> --namespace <NS> --name "
           "<TABLE>",
           "Treat the data as disclosed for the period the policy was open, and note "
           "that reads leave no per-caller trail unless CloudTrail data events were on.")),

    _C(id="S3T-02", section="S3TABLES", severity="MEDIUM", compliance=_ENC,
       permissions=(
           _P("s3tables:GetTableBucketEncryption",
              "read sseAlgorithm to establish whether analytical data is under a "
              "customer-managed key or only SSE-S3"),
       ),
       remediation=(
           "Move the table bucket to a customer-managed key so there is a second, "
           "key-level control independent of the bucket policy: aws s3tables "
           "put-table-bucket-encryption --table-bucket-arn <ARN> "
           "--encryption-configuration sseAlgorithm=aws:kms,kmsKeyArn=<KEY_ARN>"),
       risk=(
           "This S3 Tables bucket is encrypted with SSE-S3 rather than a customer-managed "
           "KMS key. The data is encrypted at rest either way, so this is not an "
           "exposure on its own -- what differs is how many independent controls stand "
           "between a principal and the plaintext. With SSE-S3 the bucket policy is the "
           "whole story: anyone the policy admits reads the data, because the service "
           "decrypts transparently. With a CMK there is a second gate that is "
           "administered separately and can be revoked without touching the bucket, "
           "which matters most in exactly the situation where you need it -- a policy "
           "mistake, or a principal who turns out to have had more access than intended. "
           "For analytical data, which is usually the joined and enriched version of the "
           "operational stores, that second gate is generally worth having."),
       impact=("Access to the analytical data rests on the bucket policy alone, with no "
               "separately-administered key-level control to revoke."),
       steps=(
           "Create or choose a CMK with a key policy naming the roles that legitimately "
           "read this data.",
           "Apply it: aws s3tables put-table-bucket-encryption --table-bucket-arn <ARN> "
           "--encryption-configuration sseAlgorithm=aws:kms,kmsKeyArn=<KEY_ARN>",
           "Confirm the analytics roles are in the key policy, or queries will start "
           "failing with KMS access denials rather than S3 ones.")),

    _C(id="LATT-01", section="VPCLATTICE", severity="HIGH", compliance=_ACC,
       permissions=(
           _P("vpc-lattice:ListServices",
              "enumerate the Lattice services published in this account"),
           _P("vpc-lattice:GetService",
              "read authType -- NONE means the service accepts requests with no caller "
              "identity involved at all"),
       ),
       remediation=(
           "Require IAM authentication on the Lattice service instead of accepting "
           "anonymous callers: aws vpc-lattice update-service --service-identifier <ID> "
           "--auth-type AWS_IAM, then attach an auth policy scoping which principals may "
           "call it: aws vpc-lattice put-auth-policy --resource-identifier <ID> --policy "
           "file://auth-policy.json . Setting AWS_IAM without a policy denies everything, "
           "so stage both together"),
       risk=(
           "This VPC Lattice service has authType NONE, which means it performs no "
           "caller authentication whatsoever: any request that reaches it on the network "
           "is served. The reason this matters more than an unauthenticated endpoint "
           "inside a single VPC is what Lattice is for. It exists specifically to connect "
           "services across VPC and account boundaries without the usual peering and "
           "routing work, so the set of things that can reach a Lattice service is "
           "typically much larger than the set that could reach an ordinary internal "
           "endpoint -- often every workload in every associated VPC across several "
           "accounts. The service mesh is doing exactly what it was asked to do, which "
           "is make the service broadly reachable; the authentication that was supposed "
           "to be the compensating control is simply absent."),
       impact=("Any workload in any VPC associated with the service network can call "
               "this service with no identity, so network reachability is the only "
               "control."),
       steps=(
           "Write the auth policy FIRST -- switching to AWS_IAM without one denies "
           "everything: aws vpc-lattice put-auth-policy --resource-identifier <ID> "
           "--policy file://auth-policy.json",
           "Then require authentication: aws vpc-lattice update-service "
           "--service-identifier <ID> --auth-type AWS_IAM",
           "Check the service network's own auth type as well -- both layers evaluate: "
           "aws vpc-lattice get-service-network --service-network-identifier <ID>",
           "Watch for 403s from legitimate callers during rollout; a missing principal "
           "in the auth policy fails closed, which is the right direction but is "
           "disruptive if it is discovered in production.")),

    _C(id="LATT-02", section="VPCLATTICE", severity="MEDIUM", compliance=_ACC,
       permissions=(
           _P("vpc-lattice:GetAuthPolicy",
              "read the auth policy of an AWS_IAM service -- requiring authentication "
              "buys little if the authorization admits every principal"),
       ),
       remediation=(
           "Scope the Lattice auth policy to the principals that should actually call "
           "the service: aws vpc-lattice get-auth-policy --resource-identifier <ID> to "
           "read it, then aws vpc-lattice put-auth-policy --resource-identifier <ID> "
           "--policy file://scoped-auth-policy.json naming specific roles or gating on "
           "aws:PrincipalOrgID"),
       risk=(
           "This VPC Lattice service requires IAM authentication, and then its auth "
           "policy allows a wildcard principal. The combination is worth reporting "
           "separately from an unauthenticated service because it looks correct in a "
           "configuration review: authType is AWS_IAM, an auth policy exists, and both "
           "facts appear in any inventory as evidence the service is protected. What the "
           "policy actually says is that any caller holding any AWS identity may proceed "
           "-- which, for a service reachable across account boundaries, is a much larger "
           "set than the workloads that were meant to call it. Authentication and "
           "authorization are separate questions, and this configuration answers the "
           "first properly while leaving the second open."),
       impact=("Any caller with any AWS identity that can reach the service is "
               "authorized, so requiring IAM establishes only that the caller exists."),
       steps=(
           "Read the policy: aws vpc-lattice get-auth-policy --resource-identifier <ID>",
           "Identify the roles that legitimately call this service before narrowing it "
           "-- the policy fails closed, so an incomplete list breaks callers.",
           "Apply a scoped policy: aws vpc-lattice put-auth-policy --resource-identifier "
           "<ID> --policy file://scoped-auth-policy.json",
           "Prefer naming principals or an aws:PrincipalOrgID condition over a wildcard "
           "with an unrelated condition, which is easy to write and hard to reason "
           "about.")),

    _C(id="CART-01", section="CODEARTIFACT", severity="HIGH", compliance=_ACC,
       permissions=(
           _P("codeartifact:ListDomains",
              "enumerate CodeArtifact domains, which hold the package repositories"),
           _P("codeartifact:GetDomainPermissionsPolicy",
              "read the domain policy -- it governs every repository in the domain at "
              "once, so a permissive one is the broadest possible grant"),
           _P("codeartifact:ListRepositories",
              "enumerate the package repositories in each domain"),
           _P("codeartifact:GetRepositoryPermissionsPolicy",
              "read each repository policy to find grants to principals outside the "
              "account"),
       ),
       remediation=(
           "Remove the wildcard principal from the CodeArtifact policy: aws codeartifact "
           "get-domain-permissions-policy --domain <DOMAIN> to read it, then aws "
           "codeartifact put-domain-permissions-policy --domain <DOMAIN> --policy-document "
           "file://scoped-policy.json . Do the same per repository with "
           "get-repository-permissions-policy / put-repository-permissions-policy"),
       risk=(
           "This CodeArtifact domain or repository has a permissions policy granting a "
           "wildcard principal, which makes your internal package registry readable "
           "outside the account. The immediate consequence is that private code is "
           "readable, and internal packages routinely contain more than code -- embedded "
           "configuration, endpoint addresses, occasionally credentials committed into a "
           "library nobody expected to leave the building. The second consequence is the "
           "one that persists after you fix the first: reading a package registry reveals "
           "your complete dependency graph and the exact names and versions of your "
           "internal libraries. That is precisely the reconnaissance a "
           "dependency-confusion attack needs, and unlike the code itself, the names "
           "cannot be un-learned once seen. A domain policy is the broader of the two, "
           "since it governs every repository in the domain at once."),
       impact=("Private packages are readable outside the account, exposing internal "
               "library names and the dependency graph that a dependency-confusion "
               "attack requires."),
       steps=(
           "Read the domain policy first -- it covers every repository: aws codeartifact "
           "get-domain-permissions-policy --domain <DOMAIN>",
           "Replace it with one naming specific accounts or an aws:PrincipalOrgID "
           "condition: aws codeartifact put-domain-permissions-policy --domain <DOMAIN> "
           "--policy-document file://scoped-policy.json",
           "Then check each repository: aws codeartifact "
           "get-repository-permissions-policy --domain <DOMAIN> --repository <REPO>",
           "Claim your internal package namespaces on the public registries as well -- "
           "the names are now known, and that is what makes dependency confusion work.")),

    _C(id="DIRSVC-01", section="DIRECTORYSERVICE", severity="HIGH", compliance=_TLS,
       permissions=(
           _P("ds:DescribeDirectories",
              "enumerate the managed directories in this account and region"),
           _P("ds:DescribeLDAPSSettings",
              "read LDAPSStatus -- Disabled means bind credentials and directory "
              "contents cross the network as plain LDAP"),
       ),
       remediation=(
           "Enable LDAPS so directory traffic stops being cleartext. It needs a "
           "certificate registered against the directory first: aws ds "
           "register-certificate --directory-id <DIR_ID> --certificate-data "
           "file://cert.pem, then aws ds enable-ldaps --directory-id <DIR_ID> --type "
           "Client. Confirm with aws ds describe-ldaps-settings --directory-id <DIR_ID>, "
           "because the status can come back EnableFailed"),
       risk=(
           "This managed directory has LDAPS disabled, so directory traffic is plain "
           "LDAP: bind credentials and directory contents cross the network unencrypted. "
           "A directory is not an ordinary application datastore -- it is the "
           "authentication source for everything joined to it, which typically means the "
           "Windows fleet, the file shares, and often application authentication as well. "
           "Credentials captured from an LDAP bind are therefore not credentials to one "
           "system but to the identity layer underneath many, and a bind from a service "
           "account is usually a privileged one. The practical attacker position is "
           "inside the VPC rather than on the internet, which is exactly the position "
           "reached after any initial foothold, and it turns a single compromised "
           "instance into directory-wide credential capture. Note also that a status of "
           "EnableFailed is reported here, because it looks configured and protects "
           "nothing."),
       impact=("Directory bind credentials and directory contents are readable by "
               "anything able to observe VPC traffic, giving access to the "
               "authentication layer for every joined system."),
       steps=(
           "Register a certificate against the directory -- LDAPS cannot be enabled "
           "without one: aws ds register-certificate --directory-id <DIR_ID> "
           "--certificate-data file://cert.pem",
           "Enable it: aws ds enable-ldaps --directory-id <DIR_ID> --type Client",
           "Verify the status rather than assuming, since it can land in EnableFailed: "
           "aws ds describe-ldaps-settings --directory-id <DIR_ID>",
           "Treat service-account credentials that bound over plain LDAP as exposed and "
           "rotate them, prioritising any with delegated directory rights.")),

    # LOW, not MEDIUM: the check emits WARN/PASS only -- a shared directory is a fact
    # to verify, not a defect the scanner can call. `_add` forces a WARN to LOW, so a
    # MEDIUM here advertised a severity the check could never render. See CHANGELOG
    # (bucket B) and docs/CHECK_FIRING.md.
    _C(id="DIRSVC-02", section="DIRECTORYSERVICE", severity="LOW", compliance=_ACC,
       permissions=(
           _P("ds:DescribeSharedDirectories",
              "read which accounts a directory is shared with -- sharing a directory "
              "extends an authentication boundary rather than granting access to one "
              "resource"),
       ),
       remediation=(
           "Review who the directory is shared with and withdraw anything unintended: "
           "aws ds describe-shared-directories --owner-directory-id <DIR_ID> to list "
           "them, then aws ds unshare-directory --directory-id <DIR_ID> --unshare-target "
           "Id=<ACCOUNT_ID>,Type=ACCOUNT"),
       risk=(
           "This directory is shared with one or more other AWS accounts. Directory "
           "sharing is a legitimate and common pattern -- it is how a central identity "
           "account serves workload accounts -- so this is reported for review rather "
           "than as a defect. What makes it worth reviewing is that sharing a directory "
           "is categorically different from sharing an ordinary resource: it extends an "
           "AUTHENTICATION boundary. Principals in the consuming account can join "
           "instances to your directory and authenticate against it, which means the "
           "security of your identity layer now depends on the security of every account "
           "you have shared it with. A share made for a project that ended, or to an "
           "account whose ownership has since changed, is the case worth finding -- and "
           "shares are quiet, because nothing in the owning account changes when the "
           "consuming account's posture does."),
       impact=("Principals in the consuming accounts can join resources to your "
               "directory and authenticate against it, so your identity layer depends on "
               "their security posture."),
       steps=(
           "List the shares and confirm each is still intended: aws ds "
           "describe-shared-directories --owner-directory-id <DIR_ID>",
           "Withdraw any that are not: aws ds unshare-directory --directory-id <DIR_ID> "
           "--unshare-target Id=<ACCOUNT_ID>,Type=ACCOUNT",
           "For shares that stay, confirm the consuming account is inside your "
           "organization and subject to the same controls.",
           "Re-review on a schedule -- nothing in this account changes when the "
           "consuming account's posture does.")),

    _C(id="AMP-01", section="PROMETHEUS", severity="MEDIUM", compliance=_ENC,
       permissions=(
           _P("aps:ListWorkspaces",
              "enumerate Managed Prometheus workspaces in this account and region"),
           _P("aps:DescribeWorkspace",
              "read kmsKeyArn -- whether metrics sit under a customer-managed key or an "
              "AWS-owned one that cannot be audited or revoked"),
       ),
       remediation=(
           "A Prometheus workspace's KMS key is set at creation and cannot be changed "
           "in place, so create a replacement with a CMK and cut the remote-write "
           "targets over: aws amp create-workspace --alias <ALIAS> --kms-key-arn "
           "<KEY_ARN>, then repoint your Prometheus servers and delete the old workspace "
           "with aws amp delete-workspace --workspace-id <OLD_ID>"),
       risk=(
           "This Managed Prometheus workspace has no customer-managed KMS key, so its "
           "metrics are held under an AWS-owned key that you cannot audit, rotate on "
           "your own schedule, or revoke. The usual objection is that metrics are not "
           "sensitive data, and for the numeric values that is broadly true. The labels "
           "are the problem: Prometheus metrics carry hostnames, container and pod "
           "names, service names, namespaces, availability zones, and frequently "
           "customer or tenant identifiers in multi-tenant systems. Taken together that "
           "is an accurate, continuously-updated map of the estate -- what exists, what "
           "talks to what, when load moves, and which components are failing. It is "
           "reconnaissance material of a quality an attacker would otherwise spend "
           "considerable effort assembling, and unlike a datastore it is rarely "
           "considered when access is reviewed."),
       impact=("Metric labels -- hostnames, service topology, tenant identifiers -- sit "
               "under a key you cannot audit or revoke, with no key-level control over "
               "who reads them."),
       steps=(
           "Note that the key is fixed at creation: this is a migration rather than a "
           "setting change.",
           "Create a replacement with a CMK: aws amp create-workspace --alias <ALIAS> "
           "--kms-key-arn <KEY_ARN>",
           "Repoint the Prometheus remote-write targets at the new workspace endpoint, "
           "and move any alert manager and rule-group definitions across.",
           "Delete the old workspace once the new one is receiving data: aws amp "
           "delete-workspace --workspace-id <OLD_ID>")),

    _C(id="XRAY-01", section="XRAY", severity="MEDIUM", compliance=_ENC,
       permissions=(
           _P("xray:GetEncryptionConfig",
              "read EncryptionConfig Type -- NONE means traces are under the default "
              "AWS-owned key rather than a customer-managed one"),
       ),
       remediation=(
           "Move X-Ray to a customer-managed key so trace contents are under a key you "
           "administer: aws xray put-encryption-config --type KMS --key-id <KEY_ARN>. "
           "The setting is Region-wide, so apply it in every Region where the service is "
           "used, and confirm with aws xray get-encryption-config"),
       risk=(
           "X-Ray is using default encryption rather than a customer-managed key. As "
           "with other default-encryption findings the data is encrypted at rest either "
           "way, and the question is who can read it and what control you have over "
           "that. Traces deserve more attention than their reputation as telemetry "
           "suggests: an X-Ray segment routinely records the full request URL including "
           "query string, selected headers, the downstream calls a request made, and any "
           "annotations or metadata the application chose to attach -- which in practice "
           "often includes identifiers, and sometimes SQL fragments or payload excerpts "
           "added during debugging and never removed. A trace store is therefore a "
           "readable log of what the application does with its data, assembled without "
           "anyone deciding it should exist. A CMK gives a second, separately-"
           "administered gate over that. Note the setting is Region-wide rather than "
           "per-resource, so it is easy to set in one Region and forget elsewhere."),
       impact=("Trace contents -- request URLs, headers, annotations, sometimes SQL "
               "fragments -- are under an AWS-owned key with no key-level control over "
               "who reads them."),
       steps=(
           "Create or choose a CMK whose key policy names the roles that legitimately "
           "read traces.",
           "Apply it: aws xray put-encryption-config --type KMS --key-id <KEY_ARN>",
           "Repeat in every Region where X-Ray is used -- the setting is Region-wide, "
           "not global.",
           "Confirm it took effect, since the change is asynchronous and reports a "
           "status: aws xray get-encryption-config",
           "Separately, review what your application annotates onto traces; a CMK "
           "controls who reads them but not what goes in.")),
)
