#!/usr/bin/env python3
"""aws_cis_foundations.py — the CIS AWS Foundations Benchmark v7.0.0 controls that
OverWatch did not already hold.

WHAT THIS MODULE IS FOR. `engine/aws_cis_foundations_map.py` maps all 70 recommendations
in v7.0.0 against the catalogue. Fifty-one were already decided by checks that existed —
Foundations is the benchmark this product has always been built around — and nineteen were
not. Those nineteen are declared here.

Most of them are new because the RECOMMENDATION is new. v7.0.0 adds a whole Organizations
subsection (2.1.1–2.1.6), a cross-service resource-policy control, access logging on
managed HTTP front ends, VPC endpoints, and SMB. The rest are older recommendations this
product had simply never reached: log-file validation, the support role, MFA Delete.

ELEVEN OF THE NINETEEN ANSWER A **MANUAL** RECOMMENDATION. That is the interesting number
in this batch. The benchmark marks a recommendation Manual when it does not believe a
single API read settles it, and an auditor working the document by hand pays for each one
in console time. Where the control plane does in fact answer the question — and for
centralized root access, the security contact, delegated administration and MFA Delete it
answers it outright — automating it is worth more than automating an Automated one.

WHAT IS **NOT** HERE, AND WHY THAT MATTERS MORE THAN WHAT IS. Nothing in this module
invents a check for a recommendation the control plane cannot decide. 2.1.4 asks whether an
OU tree is structured by environment and sensitivity; ORG-04 decides the readable half (an
account in no OU at all) and the mapping records it as PARTIAL rather than claiming the
judgement. 2.2 asks whether contact details are current; ACCT-01 decides POPULATED and says
so. A check that quietly narrows its control and then reports PASS is worse than no check,
because it converts an open question into a false answer.

ORGANIZATIONS READS ARE GLOBAL AND USUALLY DENIED. Only the management account can read the
organisation, so six of these nineteen return "not evaluated" in every member account. That
is a coverage statement, not a pass — the distinction `_check_organizations` is careful
about, for the same reason CREDEXP-00 exists.

ON THE SOURCE DOCUMENT. CIS Benchmarks may not be redistributed, so the PDF is not in this
repository and no title, rationale, audit, impact or remediation prose is copied from it.
What is cited is the recommendation NUMBER, which is a reference; every description below
is written from the underlying AWS behaviour.

Pure. No boto3, no network, no I/O. The scanner passes in what it already fetched.
"""
from __future__ import annotations

import re
from typing import Dict, List, Mapping, Optional, Sequence

from engine import aws_checkdef as _cd
from engine.aws_checkdef import CheckDef as _C, Perm as _P

__all__ = [
    # 2.1 Organizations
    "central_root_access", "authorization_guardrails", "management_account_workloads",
    "accounts_outside_an_ou", "delegated_policy_admin", "delegated_service_admins",
    # 2.2 / 2.3 account contacts
    "contact_details", "security_contact",
    # IAM
    "root_mfa_is_virtual", "user_attached_policies", "support_role",
    "federated_human_access", "cloudshell_access",
    # compute / storage / logging / network
    "instance_without_role", "bucket_mfa_delete", "trail_log_validation",
    "trail_bucket_access_logging", "peering_route_scope", "vpc_endpoint_usage",
    "CHECKS", "ROOT_MFA_VIRTUAL_ARN", "REMOTE_ADMIN_PORTS",
]

#: A virtual MFA device's serial number IS an ARN in the account's own IAM namespace; a
#: hardware device's serial is the vendor's, and never matches this. That asymmetry is the
#: whole of 2.6's audit, and it is why the control is decidable at all.
ROOT_MFA_VIRTUAL_ARN = re.compile(r"^arn:aws[a-z\-]*:iam::\d+:mfa/", re.I)

#: The AWS-managed policy that grants unrestricted CloudShell, which carries file upload
#: and download and therefore a data path out of the account.
_CLOUDSHELL_POLICY = "AWSCloudShellFullAccess"

#: The AWS-managed policy 2.15 asks for a role to carry.
_SUPPORT_POLICY = "AWSSupportAccess"

#: Ports 6.1.2, 6.2, 6.3 and 6.4 call remote server administration, kept here so the
#: Foundations meaning of the phrase is written down once.
REMOTE_ADMIN_PORTS = (22, 3389, 445)

#: The policy AWS attaches to every root and OU by default. It allows every action, so an
#: account whose entire inherited policy set is this one is governed by nothing — which is
#: the state 2.1.2 is about, and the state that most looks compliant from a console.
_FULL_ACCESS = "p-FullAWSAccess"


def _unknown(reason: str) -> dict:
    """A read that did not happen. NOT a pass, and never rendered as one."""
    return {"applicable": False, "unknown": True, "reason": reason, "statement": ""}


def _ok() -> dict:
    return {"applicable": True, "unknown": False, "failed": False, "statement": ""}


def _fail(statement: str, **extra) -> dict:
    d = {"applicable": True, "unknown": False, "failed": True, "statement": statement}
    d.update(extra)
    return d


# ══════════════════════════════════════════════════════════════════════════════
# 2.1 Organizations — new in v7.0.0
# ══════════════════════════════════════════════════════════════════════════════
def central_root_access(features: Optional[Sequence[str]],
                        org_available: bool = True) -> dict:
    """ORG-01 / 2.1.1 — member-account root credentials are not centrally managed.

    ``features`` is what ``iam:ListOrganizationsFeatures`` returned. Two features matter
    and they are NOT the same thing: ``RootCredentialsManagement`` removes the root
    password and keys from member accounts, and ``RootSessions`` lets the management
    account take a scoped root action when one is genuinely required. Enabling the second
    without the first leaves every member root credential exactly where it was, so this
    reports them separately rather than as one boolean."""
    if not org_available:
        return _unknown("this account is not in an AWS Organization, so there is no "
                        "central root management to enable")
    if features is None:
        return _unknown("iam:ListOrganizationsFeatures could not be read")
    have = {str(f) for f in features}
    missing = [f for f in ("RootCredentialsManagement", "RootSessions") if f not in have]
    if not missing:
        return _ok()
    if "RootCredentialsManagement" not in have:
        return _fail(
            "Root credentials are still present in every member account. Each one is a "
            "standing credential that no SCP can restrict, that MFA and password policy "
            "are configured per-account, and that nothing in the organisation can "
            "inventory or rotate centrally. Centralizing removes the credential rather "
            "than guarding it", missing=missing)
    return _fail(
        "Root credentials are centrally managed but privileged root sessions are not "
        "enabled, so the supported path for the few actions that still require root is "
        "unavailable and operators will be tempted to restore a root password to do them",
        missing=missing)


def authorization_guardrails(account_policies: Optional[Mapping[str, Sequence[str]]],
                             org_available: bool = True) -> dict:
    """ORG-02 / 2.1.2 — an account sits under no restrictive authorization policy.

    ``account_policies`` maps account id -> the policy ids that reach it, service-control
    and resource-control alike.

    THE FAILURE IS "ONLY FullAWSAccess", NOT "NO POLICY". Organizations attaches
    ``p-FullAWSAccess`` to every root, OU and account and does not let you detach the last
    policy, so *every* account always has one attached. An audit that checks for the
    presence of an SCP therefore passes universally and measures nothing — which is the
    trap this control is worth automating to avoid."""
    if not org_available:
        return _unknown("this account is not in an AWS Organization, so service-control "
                        "and resource-control policies do not apply")
    if account_policies is None:
        return _unknown("the organisation's policy attachments could not be read")
    bare = sorted(a for a, pols in account_policies.items()
                  if not [p for p in pols if p != _FULL_ACCESS])
    if not bare:
        return _ok()
    return _fail(
        f"{len(bare)} account(s) inherit no authorization policy other than the default "
        f"FullAWSAccess, so nothing in the organisation constrains what any principal in "
        f"them may do. This is the state that reads as governed from a console — a policy "
        f"IS attached — while restricting nothing at all",
        accounts=bare)


def management_account_workloads(is_management: Optional[bool],
                                 workloads: Optional[Mapping[str, int]] = None) -> dict:
    """ORG-03 / 2.1.3 — the management account is running workloads.

    ``is_management`` is None when the organisation could not be read.

    DECIDABLE ONLY FROM INSIDE THE MANAGEMENT ACCOUNT, which is the opposite of the usual
    Organizations problem: the other five controls here need the management account's
    *permissions*, this one needs to BE it. Scanning a member account tells you nothing
    about what the management account runs, and returning a pass in that case would be
    inventing evidence."""
    if is_management is None:
        return _unknown("the organisation could not be read, so which account is the "
                        "management account is unknown")
    if not is_management:
        return _unknown("this is a member account; whether the management account runs "
                        "workloads can only be decided by scanning it")
    counts = {k: int(v) for k, v in (workloads or {}).items() if v}
    if not counts:
        return _ok()
    detail = ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
    return _fail(
        f"The management account is running workloads ({detail}). It is the one account "
        f"whose compromise is the compromise of the whole organisation: it can create and "
        f"detach policies for every member, and no service-control policy applies to it. "
        f"Every workload here is an additional way to reach that",
        workloads=counts)


def accounts_outside_an_ou(root_accounts: Optional[Sequence[str]],
                           ou_count: Optional[int] = None,
                           org_available: bool = True) -> dict:
    """ORG-04 / 2.1.4 — accounts parented directly to the organisation root.

    WHAT THIS DELIBERATELY DOES NOT DECIDE. The recommendation asks that OUs be structured
    by environment and sensitivity. Whether ``ou-prod-1`` means production is a judgement
    about a name, and this function does not make it — a check that scored OU names would
    be scoring a naming convention and calling it a control.

    What it does decide is objective and is the precondition for all of it: an account
    parented to the root is in no OU, so no OU-scoped guardrail can ever reach it, and
    every policy meant for its tier has to be attached to it by hand."""
    if not org_available:
        return _unknown("this account is not in an AWS Organization")
    if root_accounts is None:
        return _unknown("the organisation's account tree could not be read")
    stray = sorted(root_accounts)
    if not stray:
        return _ok()
    return _fail(
        f"{len(stray)} account(s) sit directly under the organisation root rather than in "
        f"an organizational unit, so no OU-scoped service-control policy reaches them and "
        f"every guardrail meant for their tier has to be attached individually — which is "
        f"the step that gets missed when an account is added in a hurry"
        + (f". The organisation has {ou_count} OU(s)" if ou_count is not None else ""),
        accounts=stray)


def delegated_policy_admin(delegated: Optional[Sequence[Mapping]],
                           resource_policy: Optional[str] = None,
                           org_available: bool = True) -> dict:
    """ORG-05 / 2.1.5 — Organizations policy administration is not delegated.

    Delegation is expressed as an Organizations *resource policy* naming a member account,
    so ``resource_policy`` being absent is the finding. ``delegated`` is the delegated-
    administrator list, carried so the message can say whether ANY delegation exists."""
    if not org_available:
        return _unknown("this account is not in an AWS Organization")
    if resource_policy is None and delegated is None:
        return _unknown("the organisation's delegation configuration could not be read")
    if resource_policy:
        return _ok()
    n = len(delegated or [])
    return _fail(
        "No Organizations resource policy delegates policy administration, so creating, "
        "attaching or detaching a service-control policy can only be done from the "
        "management account. That forces routine governance work to be done while signed "
        "in to the account with the largest blast radius in the organisation"
        + (f". {n} account(s) are delegated administrators for other services" if n
           else ""),
        delegated_count=n)


def delegated_service_admins(trusted_services: Optional[Sequence[str]],
                             delegated_services: Optional[Sequence[str]] = None,
                             org_available: bool = True) -> dict:
    """ORG-06 / 2.1.6 — an Organizations-integrated service has no delegated administrator.

    The recommendation is open-ended: it names one service as an example and asks the
    reader to repeat the audit for every other integrated service in use. So this reports
    the services that HAVE trusted access enabled and no delegated administrator, naming
    them, rather than reducing an open-ended question to a single number."""
    if not org_available:
        return _unknown("this account is not in an AWS Organization")
    if trusted_services is None:
        return _unknown("organizations:ListAWSServiceAccessForOrganization could not "
                        "be read")
    have = {str(s) for s in (delegated_services or [])}
    missing = sorted(str(s) for s in trusted_services if str(s) not in have)
    if not missing:
        return _ok()
    shown = ", ".join(missing[:6]) + (" …" if len(missing) > 6 else "")
    return _fail(
        f"{len(missing)} service(s) with organisation-wide trusted access have no "
        f"delegated administrator ({shown}), so administering each one means signing in "
        f"to the management account. Delegation moves that day-to-day work into an "
        f"account that a service-control policy can actually constrain",
        services=missing)


# ══════════════════════════════════════════════════════════════════════════════
# 2.2 / 2.3 — account contacts
# ══════════════════════════════════════════════════════════════════════════════
_CONTACT_FIELDS = ("FullName", "AddressLine1", "City", "PostalCode", "CountryCode",
                   "PhoneNumber")


def contact_details(contact: Optional[Mapping]) -> dict:
    """ACCT-01 / 2.2 — the account's primary contact information is incomplete.

    DECIDES "POPULATED", NOT "CURRENT". The recommendation asks for details that are
    current; no API returns when a field was last verified, or whether the number still
    reaches a person. Reporting a fully populated record as compliant would be answering
    an easier question than the one asked, so the finding says which half was checked."""
    if contact is None:
        return _unknown("account:GetContactInformation could not be read")
    missing = [f for f in _CONTACT_FIELDS if not str(contact.get(f) or "").strip()]
    if not missing:
        return _ok()
    return _fail(
        f"The account's primary contact record is missing {', '.join(missing)}. AWS uses "
        f"it to reach an owner about suspected compromise, service disruption and account "
        f"recovery, and an incomplete record fails exactly when it is needed. Note that "
        f"only completeness is checked here — whether the details are still CURRENT is "
        f"not readable from any API",
        missing=missing)


def security_contact(contact: Optional[Mapping], readable: bool = True) -> dict:
    """ACCT-02 / 2.3 — no SECURITY alternate contact is registered.

    ``readable=False`` distinguishes "the call failed" from "the call succeeded and the
    contact is not set", which the AWS API itself conflates by raising
    ResourceNotFoundException for the second."""
    if not readable:
        return _unknown("account:GetAlternateContact could not be read")
    if contact and str(contact.get("EmailAddress") or "").strip():
        return _ok()
    return _fail(
        "No SECURITY alternate contact is registered on this account. It is the address "
        "AWS uses to report abuse originating from the account, exposed credentials it "
        "has detected, and security bulletins that need action. Without it those notices "
        "go to the root email — typically an individual's mailbox, and often one nobody "
        "is monitoring")


# ══════════════════════════════════════════════════════════════════════════════
# IAM
# ══════════════════════════════════════════════════════════════════════════════
def root_mfa_is_virtual(root_serial: Optional[str], mfa_enabled: bool = True) -> dict:
    """IAM-11 / 2.6 — root MFA is a virtual device rather than a hardware one.

    SEPARATE FROM IAM-01 ON PURPOSE. IAM-01 fires when root has no MFA at all, which is a
    CRITICAL. This fires when root has MFA and it is virtual, which is a MEDIUM. Merging
    them would either inflate "virtual MFA" to critical or deflate "no MFA" to medium, and
    both are wrong. If MFA is off entirely this returns silent, because IAM-01 has already
    said the more important thing."""
    if not mfa_enabled:
        return _unknown("root has no MFA device at all — IAM-01 reports that, and it is "
                        "the more serious finding")
    if root_serial is None:
        return _unknown("the root MFA device serial could not be read")
    if not ROOT_MFA_VIRTUAL_ARN.match(str(root_serial)):
        return _ok()
    return _fail(
        "The root user's MFA is a virtual device — an authenticator app whose seed lives "
        "on a phone. That phone is itself protected by a password and a cloud backup, so "
        "the second factor can be phished, restored onto an attacker's device, or lost "
        "with the handset. A hardware key cannot be copied and cannot be handed over by "
        "somebody who has been talked into it")


def user_attached_policies(user: str,
                           attached: Optional[Sequence[str]],
                           inline: Optional[Sequence[str]]) -> dict:
    """IAM-12 / 2.13 — an IAM user carries permissions that do not come from a group.

    WHY THIS IS A GOVERNANCE FINDING AND NOT AN ACCESS ONE, and therefore LOW. Whether the
    permissions are excessive is IAMPE's question and it asks it directly. This one is
    about where they are ATTACHED: permissions granted per-user are invisible in every
    group-based review, cannot be revoked by removing someone from a group, and are the
    ones that survive a leaver process."""
    if attached is None and inline is None:
        return _unknown(f"the policies attached to {user} could not be read")
    names = sorted([*(attached or []), *(inline or [])])
    if not names:
        return _ok()
    shown = ", ".join(names[:5]) + (" …" if len(names) > 5 else "")
    return _fail(
        f"IAM user {user} holds {len(names)} policy/policies directly rather than through "
        f"a group ({shown}). Direct grants do not appear in a group-membership review, "
        f"are not removed when the user is taken out of a group, and drift apart from the "
        f"peers the user is supposed to match",
        policies=names)


def support_role(entities: Optional[Mapping]) -> dict:
    """IAM-13 / 2.15 — no principal can raise an AWS Support case.

    ``entities`` is what ``iam:ListEntitiesForPolicy`` returned for AWSSupportAccess, or
    None if the read failed. Roles, users and groups all count: the control asks that
    somebody be able to open a case without being an administrator, and any of the three
    satisfies that."""
    if entities is None:
        return _unknown(f"iam:ListEntitiesForPolicy could not be read for "
                        f"{_SUPPORT_POLICY}")
    n = (len(entities.get("PolicyRoles") or [])
         + len(entities.get("PolicyUsers") or [])
         + len(entities.get("PolicyGroups") or []))
    if n:
        return _ok()
    return _fail(
        f"No role, user or group has the {_SUPPORT_POLICY} policy, so raising a support "
        f"case requires an administrator. During an incident that is precisely the wrong "
        f"constraint: the people triaging are the people who most need a case open, and "
        f"granting them administrator to get one is how an incident becomes two")


def federated_human_access(console_users: Optional[Sequence[str]],
                           identity_sources: Optional[Sequence[str]]) -> dict:
    """IAM-14 / 2.19 — human sign-in still goes through IAM users.

    SCOPED TO USERS WITH A CONSOLE PASSWORD, which is the whole design of this check. An
    IAM user with no password is a service account: it is not a human bypassing
    federation, and failing it would push an operator toward a migration that improves
    nothing and breaks a running integration. The recommendation is about people."""
    if console_users is None:
        return _unknown("the credential report could not be read, so console users could "
                        "not be enumerated")
    users = sorted(console_users)
    if not users:
        return _ok()
    srcs = sorted(identity_sources or [])
    shown = ", ".join(users[:5]) + (" …" if len(users) > 5 else "")
    where = (f"An identity source is already configured ({', '.join(srcs)}), so these "
             f"users are a parallel path around it"
             if srcs else
             "No IAM Identity Center instance, SAML provider or OIDC provider is "
             "configured, so every one of these is a local credential with its own "
             "password, its own MFA state and its own lifecycle")
    return _fail(
        f"{len(users)} IAM user(s) can sign in to the console with a password ({shown}). "
        f"{where}. A person leaving the company is removed from the directory and keeps "
        f"working here until somebody remembers this account exists",
        users=users, sources=srcs)


def cloudshell_access(entities: Optional[Mapping]) -> dict:
    """IAM-15 / 2.20 — AWSCloudShellFullAccess is broadly attached.

    CloudShell full access includes file upload and download, so it is a bidirectional
    data path between a workstation and the account that no VPC control, endpoint policy
    or flow log sees."""
    if entities is None:
        return _unknown(f"iam:ListEntitiesForPolicy could not be read for "
                        f"{_CLOUDSHELL_POLICY}")
    names = sorted(
        [str(r.get("RoleName")) for r in (entities.get("PolicyRoles") or [])]
        + [str(u.get("UserName")) for u in (entities.get("PolicyUsers") or [])]
        + [str(g.get("GroupName")) for g in (entities.get("PolicyGroups") or [])])
    if not names:
        return _ok()
    shown = ", ".join(names[:6]) + (" …" if len(names) > 6 else "")
    return _fail(
        f"{_CLOUDSHELL_POLICY} is attached to {len(names)} principal(s) ({shown}). The "
        f"policy carries CloudShell's file upload and download actions, which together "
        f"are a two-way transfer channel between an operator's workstation and this "
        f"account — one that leaves no VPC flow log, crosses no endpoint policy, and is "
        f"attributed only in CloudTrail",
        principals=names)


# ══════════════════════════════════════════════════════════════════════════════
# compute / storage / logging / network
# ══════════════════════════════════════════════════════════════════════════════
def instance_without_role(instance: Mapping) -> dict:
    """EC2-18 / 2.16 — a running instance has no instance profile.

    WHAT IT CANNOT SEE, stated because the gap matters. An instance with no role either
    needs no AWS access — fine — or is reaching AWS with a static key that was baked into
    the AMI, dropped in user data, or written to disk by a configuration tool. This check
    cannot tell those two apart; EC2-07 finds keys in user data, and neither sees a key on
    the filesystem. The finding therefore reports the absence, not the conclusion."""
    if (instance.get("IamInstanceProfile") or {}).get("Arn"):
        return _ok()
    iid = instance.get("InstanceId", "?")
    return _fail(
        f"Instance {iid} has no IAM instance profile. If it calls any AWS API it is doing "
        f"so with a long-lived access key that had to be put on the host somehow and has "
        f"to be rotated by hand — and a key on an instance survives the instance, in the "
        f"AMI and in every snapshot taken of it. An instance role issues credentials that "
        f"rotate automatically and cannot leave the instance")


def bucket_mfa_delete(bucket: str, versioning: Optional[Mapping]) -> dict:
    """S3-11 / 3.1.2 — MFA Delete is not enabled on a bucket.

    STATES THE PRECONDITION RATHER THAN FAILING PAST IT. MFA Delete is a property of
    versioning: on an unversioned bucket it cannot be set at all, so "enable MFA Delete" is
    not actionable and the finding says the actionable thing instead — enable versioning
    first. Emitting the same message for both states would send an operator to a console
    page where the option is greyed out."""
    if versioning is None:
        return _unknown(f"s3:GetBucketVersioning could not be read for {bucket}")
    status = str(versioning.get("Status") or "")
    if str(versioning.get("MFADelete") or "") == "Enabled":
        return _ok()
    if status != "Enabled":
        return _fail(
            f"Bucket {bucket} has no MFA Delete, and cannot have it: versioning is "
            f"{status or 'not enabled'}, and MFA Delete is a versioning property. Without "
            f"versioning a delete is final, so the control this recommendation asks for "
            f"has no foundation to sit on — enable versioning first",
            versioning=False)
    return _fail(
        f"Bucket {bucket} is versioned but MFA Delete is off, so any principal holding "
        f"s3:DeleteObjectVersion can permanently remove object versions and, with "
        f"s3:PutBucketVersioning, suspend versioning first. MFA Delete requires the root "
        f"user's physical second factor for those two operations, which is what makes it "
        f"a control an attacker holding a stolen role cannot satisfy",
        versioning=True)


def trail_log_validation(trail: Mapping) -> dict:
    """LOG-11 / 4.2 — CloudTrail log file validation is disabled.

    Validation makes CloudTrail write a signed digest for each delivered file. Without it
    a log file can be altered or removed from its bucket and nothing distinguishes the
    result from a period with no activity — which is exactly the state an intruder wants
    the record left in."""
    if trail.get("LogFileValidationEnabled"):
        return _ok()
    name = trail.get("Name") or trail.get("TrailARN") or "?"
    return _fail(
        f"Trail {name} has log file validation disabled, so CloudTrail publishes no signed "
        f"digest of the files it delivers. An edited or deleted log file is then "
        f"indistinguishable from a quiet hour, and the audit trail cannot be shown to be "
        f"complete — which is the property that makes it evidence rather than telemetry")


def trail_bucket_access_logging(trail_name: str, bucket: Optional[str],
                                logging_cfg: Optional[Mapping]) -> dict:
    """LOG-12 / 4.4 — the CloudTrail bucket does not record who reads it.

    SCOPED TO THE TRAIL'S OWN BUCKET, which is the difference between this and S3-05.
    S3-05 warns about access logging on every bucket as general hygiene and never fails.
    This one fails, because the bucket in question holds the record of everything anyone
    did in the account, and reads of it are the reads most worth having a record of."""
    if not bucket:
        return _unknown(f"trail {trail_name} does not name an S3 bucket")
    if logging_cfg is None:
        return _unknown(f"s3:GetBucketLogging could not be read for {bucket}")
    if (logging_cfg.get("LoggingEnabled") or {}).get("TargetBucket"):
        return _ok()
    return _fail(
        f"The CloudTrail bucket {bucket} (trail {trail_name}) has S3 server access logging "
        f"disabled, so there is no record of who read or downloaded the audit logs. "
        f"Reading the trail is how an intruder learns what was recorded about them and "
        f"decides what to remove, and it is the one access to this bucket that leaves no "
        f"trace unless this is on")


def peering_route_scope(route_table: Mapping,
                        peering_cidrs: Optional[Mapping[str, str]] = None) -> dict:
    """VPC-07 / 6.6 — a peering route carries an entire peer CIDR.

    ``peering_cidrs`` maps pcx-id -> the peer's CIDR, used only to make the message
    concrete; the finding does not depend on it.

    WHAT "LEAST ACCESS" MEANS HERE, since the phrase is doing real work. A peering
    connection is not a firewall: every route pointed at it makes the whole of that
    destination prefix reachable, subject only to security groups at the far end. A /16
    route says "any host in the peer VPC", and the usual intent was "the three subnets
    running the shared service"."""
    routes = route_table.get("Routes") or []
    wide = []
    for r in routes:
        pcx = r.get("VpcPeeringConnectionId")
        if not pcx or str(r.get("State") or "active") != "active":
            continue
        dest = r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock")
        if not dest:
            continue
        try:
            prefix = int(str(dest).rsplit("/", 1)[1])
        except (IndexError, ValueError):
            continue
        is_v6 = ":" in str(dest)
        # /16 or wider on IPv4, /56 or wider on IPv6 — the sizes AWS hands out for a
        # whole VPC, as opposed to the /24-ish a single subnet occupies.
        if (is_v6 and prefix <= 56) or (not is_v6 and prefix <= 16):
            wide.append((str(dest), str(pcx)))
    if not wide:
        return _ok()
    rtb = route_table.get("RouteTableId", "?")
    shown = ", ".join(f"{d} via {p}" for d, p in wide[:4])
    return _fail(
        f"Route table {rtb} sends whole-VPC prefixes across peering connections "
        f"({shown}). A peering route is not filtered — everything in that prefix becomes "
        f"reachable, and the far side's security groups are the only thing left deciding "
        f"who answers. Routing the specific subnets that host the shared service keeps "
        f"the rest of the peer VPC unreachable by construction",
        routes=wide)


def vpc_endpoint_usage(vpc_id: str, endpoint_count: int,
                       has_internet_path: bool) -> dict:
    """VPC-08 / 6.8 — a VPC reaches AWS services over the public path.

    BOTH CONDITIONS ARE REQUIRED, and the second is what keeps this from being noise. A
    VPC with no internet gateway and no NAT is not sending anything over the public
    network regardless of its endpoint list — its instances either use endpoints or have
    no AWS connectivity at all. Failing it would produce an unfixable finding on every
    isolated VPC in the estate."""
    if not has_internet_path:
        return _ok()
    if endpoint_count:
        return _ok()
    return _fail(
        f"VPC {vpc_id} has a path to the internet and no VPC endpoints, so every call its "
        f"workloads make to S3, DynamoDB, KMS, Secrets Manager or any other AWS service "
        f"leaves through the gateway and traverses the public network to reach an AWS "
        f"endpoint. An interface or gateway endpoint keeps that traffic on the AWS "
        f"network and — the part that is a security control rather than a routing one — "
        f"lets an endpoint policy restrict which resources can be reached at all")


# ══════════════════════════════════════════════════════════════════════════════
# the declarations
# ══════════════════════════════════════════════════════════════════════════════
CHECKS = _cd.register(
    # ── 2.1 Organizations ────────────────────────────────────────────────────
    _C(id="ORG-01", section="ORGANIZATIONS", severity="HIGH",
       compliance={"CIS": "2.1.1", "PCI-DSS": "8.2.2", "HIPAA": "164.312(a)(1)",
                   "SOC2": "CC6.1", "NIST": "AC-6(5)"},
       remediation=(
           "Enable centralized root access from the management account: "
           "aws iam enable-organizations-root-credentials-management ; then "
           "aws iam enable-organizations-root-sessions to keep a supported path for the "
           "few actions that still require root. Confirm with "
           "aws iam list-organizations-features . Removing the credential is the control; "
           "guarding a credential that still exists in 300 accounts is not"),
       risk=("Every member account in an AWS Organization is created with its own root "
             "user. That credential is outside the reach of every service-control policy, "
             "has its own password and its own MFA state, is not inventoried anywhere "
             "central, and cannot be rotated by any mechanism the organisation controls. "
             "Centralized root access removes the password and access keys from member "
             "accounts outright, so there is no longer a credential to guard, phish or "
             "forget. Root sessions then provide the narrow, logged, time-bound path for "
             "the handful of operations that genuinely require root."),
       impact=("Every member account keeps a standing privileged credential that no "
               "organisation-level control can restrict, monitor or rotate."),
       steps=("Sign in to the management account and confirm the organisation has all "
              "features enabled: aws organizations describe-organization",
              "Enable centralized management: aws iam "
              "enable-organizations-root-credentials-management",
              "Enable privileged sessions so genuine root tasks stay possible: aws iam "
              "enable-organizations-root-sessions",
              "Verify both are listed: aws iam list-organizations-features"),
       permissions=(_P("iam:ListOrganizationsFeatures",
                       "reads which organisation-wide root credential features are "
                       "enabled; without it ORG-01 cannot tell centralized root "
                       "management from a member account that simply denied the call"),)),

    _C(id="ORG-02", section="ORGANIZATIONS", severity="HIGH",
       compliance={"CIS": "2.1.2", "PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)",
                   "SOC2": "CC6.3", "NIST": "AC-3"},
       remediation=(
           "Attach a restrictive service-control policy to the OU or account: "
           "aws organizations create-policy --type SERVICE_CONTROL_POLICY --name "
           "baseline-guardrails --content file://scp.json , then "
           "aws organizations attach-policy --policy-id <POLICY_ID> --target-id "
           "<OU_OR_ACCOUNT_ID> . List what actually reaches an account with "
           "aws organizations list-policies-for-target --target-id <ACCOUNT_ID> --filter "
           "SERVICE_CONTROL_POLICY -- FullAWSAccess alone is not a guardrail"),
       risk=("AWS Organizations attaches the FullAWSAccess policy to every root, "
             "organizational unit and account, and does not allow the last policy to be "
             "detached. Every account therefore always has a service-control policy "
             "attached, and an audit that checks for the presence of one passes "
             "universally while measuring nothing. An account whose entire inherited "
             "policy set is FullAWSAccess is governed by no organisational control at "
             "all: nothing prevents a principal there from disabling CloudTrail, leaving "
             "the approved regions, or removing the account from the organisation."),
       impact=("Nothing at the organisation level constrains what principals in the "
               "account may do, including disabling the controls that would report it."),
       steps=("List the policies that actually reach each account: aws organizations "
              "list-policies-for-target --target-id <ACCOUNT_ID> --filter "
              "SERVICE_CONTROL_POLICY",
              "Author a baseline denying region escape, CloudTrail tampering and root "
              "usage, and create it: aws organizations create-policy --type "
              "SERVICE_CONTROL_POLICY --name baseline-guardrails --content file://scp.json",
              "Attach it to the OU rather than to each account: aws organizations "
              "attach-policy --policy-id <POLICY_ID> --target-id <OU_ID>",
              "Re-list the target's policies and confirm something other than "
              "FullAWSAccess is now returned"),
       permissions=(_P("organizations:ListPolicies",
                       "enumerates the service-control and resource-control policies in "
                       "the organisation, which is the set ORG-02 tests each account "
                       "against"),
                    _P("organizations:ListPoliciesForTarget",
                       "returns the policies that actually reach a given account, which "
                       "is the only way to tell an inherited guardrail from an attached "
                       "one that restricts nothing"),
                    _P("organizations:ListAccounts",
                       "enumerates the accounts in the organisation so ORG-02 reports "
                       "which ones are ungoverned rather than only that some are"))),

    _C(id="ORG-03", section="ORGANIZATIONS", severity="MEDIUM",
       compliance={"CIS": "2.1.3", "PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)",
                   "SOC2": "CC6.1", "NIST": "AC-6"},
       remediation=(
           "Move the workloads out of the management account into a member account: "
           "create one with aws organizations create-account --email <EMAIL> "
           "--account-name <NAME> , migrate the resources, and keep the management "
           "account for organisation administration only. Inventory what is there first: "
           "aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' "
           "and aws lambda list-functions --query 'Functions[].FunctionName'"),
       risk=("The management account can create, attach and detach policies for every "
             "member account, close accounts, and change the organisation's structure. No "
             "service-control policy applies to it, so the usual organisational guardrails "
             "do not constrain a principal that reaches it. Any workload running there "
             "adds attack surface to the one account whose compromise is the compromise of "
             "every other: an exploitable instance, an over-permissive Lambda execution "
             "role or a public bucket in the management account is not a contained "
             "incident."),
       impact=("A workload compromise in the management account escalates directly to "
               "control of every account in the organisation."),
       steps=("Inventory the workload resources currently in the management account "
              "(instances, functions, databases, buckets holding application data)",
              "Create or choose a member account to host them: aws organizations "
              "create-account --email <EMAIL> --account-name <NAME>",
              "Migrate the workloads, then remove the originals from the management "
              "account",
              "Re-run the scan against the management account and confirm ORG-03 passes"),
       permissions=(_P("organizations:DescribeOrganization",
                       "returns the management account id, which is the only way to know "
                       "whether the account being scanned is the management account at "
                       "all"),)),

    _C(id="ORG-04", section="ORGANIZATIONS", severity="LOW",
       compliance={"CIS": "2.1.4", "PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)",
                   "SOC2": "CC6.3", "NIST": "AC-3"},
       remediation=(
           "Create organizational units that reflect environment and sensitivity and move "
           "the stray accounts into them: aws organizations create-organizational-unit "
           "--parent-id <ROOT_ID> --name Production , then "
           "aws organizations move-account --account-id <ACCOUNT_ID> --source-parent-id "
           "<ROOT_ID> --destination-parent-id <OU_ID> . Attach the tier's guardrails to "
           "the OU rather than to each account"),
       risk=("An account parented directly to the organisation root is in no "
             "organizational unit, so no OU-scoped service-control policy can reach it. "
             "Every guardrail intended for its tier has to be attached to that account "
             "individually, which is the step that gets skipped when an account is created "
             "in a hurry or by a different team. The result is an account that looks like "
             "part of the organisation on every inventory and is governed like a "
             "standalone one. Note that this check decides only whether accounts are in "
             "an OU; whether the OU structure genuinely reflects environment and "
             "sensitivity is a judgement about names that no API can settle."),
       impact=("OU-scoped guardrails do not reach the account, so its governance depends "
               "on somebody remembering to attach policies by hand."),
       steps=("List what sits directly under the root: aws organizations "
              "list-accounts-for-parent --parent-id <ROOT_ID>",
              "Create OUs for the environment and sensitivity tiers you actually operate: "
              "aws organizations create-organizational-unit --parent-id <ROOT_ID> --name "
              "<TIER>",
              "Move each stray account: aws organizations move-account --account-id "
              "<ACCOUNT_ID> --source-parent-id <ROOT_ID> --destination-parent-id <OU_ID>",
              "Confirm the tier's policies now reach it: aws organizations "
              "list-policies-for-target --target-id <ACCOUNT_ID> --filter "
              "SERVICE_CONTROL_POLICY"),
       permissions=(_P("organizations:ListRoots",
                       "returns the organisation root id, which is the parent every "
                       "ungoverned account is attached to and the anchor for the whole "
                       "OU walk"),
                    _P("organizations:ListAccountsForParent",
                       "lists the accounts attached directly to the root, which is "
                       "exactly the finding ORG-04 reports"),
                    _P("organizations:ListOrganizationalUnitsForParent",
                       "counts the OUs that do exist, so the finding can say whether the "
                       "organisation has no structure at all or a structure some accounts "
                       "are missing from"))),

    _C(id="ORG-05", section="ORGANIZATIONS", severity="LOW",
       compliance={"CIS": "2.1.5", "PCI-DSS": "7.2.1", "HIPAA": "164.308(a)(3)(ii)(A)",
                   "SOC2": "CC6.3", "NIST": "AC-6(5)"},
       remediation=(
           "Delegate policy administration to a dedicated member account with an "
           "Organizations resource policy: aws organizations put-resource-policy "
           "--content file://delegation.json , naming the member account and the "
           "organizations: policy actions it may perform. Verify with "
           "aws organizations describe-resource-policy"),
       risk=("Without a delegation resource policy, every routine governance action — "
             "creating a service-control policy, attaching one to an OU, reviewing what "
             "reaches an account — can only be performed while signed in to the "
             "management account. That is the account with the largest blast radius in "
             "the organisation, and the effect is to make people work in it regularly for "
             "ordinary tasks. Sessions there become normal, monitoring of them becomes "
             "noise, and the separation between organisation administration and "
             "organisation governance is lost."),
       impact=("Routine policy work must be done from the management account, normalising "
               "sign-in to the highest-privilege account in the organisation."),
       steps=("Choose or create a member account to own policy administration",
              "Author a delegation policy naming that account and the organizations: "
              "actions it may perform",
              "Apply it: aws organizations put-resource-policy --content "
              "file://delegation.json",
              "Confirm it is in place: aws organizations describe-resource-policy"),
       permissions=(_P("organizations:DescribeResourcePolicy",
                       "returns the delegation policy, which is the mechanism that moves "
                       "policy administration off the management account and the only "
                       "place that delegation is recorded"),
                    _P("organizations:ListDelegatedAdministrators",
                       "lists accounts already delegated for other services, so the "
                       "finding can say whether delegation is unused entirely or merely "
                       "unused for policy administration"))),

    _C(id="ORG-06", section="ORGANIZATIONS", severity="LOW",
       compliance={"CIS": "2.1.6", "PCI-DSS": "7.2.1", "HIPAA": "164.308(a)(3)(ii)(A)",
                   "SOC2": "CC6.3", "NIST": "AC-6"},
       remediation=(
           "Register a delegated administrator for each integrated service in use, for "
           "example: aws organizations register-delegated-administrator --account-id "
           "<MEMBER_ACCOUNT_ID> --service-principal cloudtrail.amazonaws.com . List what "
           "has trusted access with aws organizations "
           "list-aws-service-access-for-organization and what is already delegated with "
           "aws organizations list-delegated-administrators"),
       risk=("A service with organisation-wide trusted access but no delegated "
             "administrator can only be administered from the management account. In "
             "practice that means the team that runs CloudTrail, GuardDuty, Security Hub "
             "or Config for the organisation is given access to the account that controls "
             "every other account, in order to do work that has nothing to do with "
             "organisation administration. Delegation moves that work into a member "
             "account, where a service-control policy can constrain it and where a "
             "compromise is contained."),
       impact=("Operating organisation-wide services requires access to the management "
               "account, widening who can reach it and why."),
       steps=("List the services with trusted access: aws organizations "
              "list-aws-service-access-for-organization",
              "List the ones already delegated: aws organizations "
              "list-delegated-administrators",
              "For each service in use with no delegated administrator, register one: aws "
              "organizations register-delegated-administrator --account-id <ACCOUNT_ID> "
              "--service-principal <SERVICE_PRINCIPAL>",
              "Confirm the service now appears against the delegated account"),
       permissions=(_P("organizations:ListAWSServiceAccessForOrganization",
                       "lists the services granted organisation-wide trusted access, "
                       "which is the set the recommendation asks to be delegated"),
                    _P("organizations:ListDelegatedServicesForAccount",
                       "returns the services a member account already administers, "
                       "without which ORG-06 would report every trusted service as "
                       "undelegated"))),

    # ── 2.2 / 2.3 account contacts ───────────────────────────────────────────
    _C(id="ACCT-01", section="ORGANIZATIONS", severity="LOW",
       compliance={"CIS": "2.2", "PCI-DSS": "12.5.1", "HIPAA": "164.308(a)(2)",
                   "SOC2": "CC2.2", "NIST": "CM-8"},
       remediation=(
           "Populate the account's primary contact record: aws account "
           "put-contact-information --contact-information "
           "'{\"FullName\":\"<NAME>\",\"AddressLine1\":\"<ADDRESS>\",\"City\":\"<CITY>\","
           "\"PostalCode\":\"<POSTCODE>\",\"CountryCode\":\"<CC>\","
           "\"PhoneNumber\":\"<PHONE>\"}' . Read it back with "
           "aws account get-contact-information"),
       risk=("The primary contact record is how AWS reaches an account owner about "
             "suspected compromise, service disruption, billing enforcement and account "
             "recovery. An incomplete record fails at exactly the moment it is needed, "
             "and the failure is silent: nothing in the console warns that a missing "
             "phone number means a recovery request cannot be verified. This check "
             "decides completeness only. Whether the details are still current — whether "
             "the named person still works here, whether the number still rings — is not "
             "exposed by any API and is not claimed."),
       impact=("AWS cannot reach an owner about compromise or recovery, and account "
               "ownership is not recorded anywhere authoritative."),
       steps=("Read the current record: aws account get-contact-information",
              "Populate every field, naming a role or team rather than an individual "
              "where possible: aws account put-contact-information --contact-information "
              "'{...}'",
              "Add a calendar reminder to re-verify the details, since completeness is "
              "all this check can measure"),
       permissions=(_P("account:GetContactInformation",
                       "reads the account's primary contact record; without it ACCT-01 "
                       "cannot distinguish an unpopulated record from an unreadable one"),)),

    _C(id="ACCT-02", section="ORGANIZATIONS", severity="MEDIUM",
       compliance={"CIS": "2.3", "PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(6)(ii)",
                   "SOC2": "CC7.3", "NIST": "SI-4"},
       remediation=(
           "Register a monitored security contact, ideally a team distribution list "
           "rather than a person: aws account put-alternate-contact "
           "--alternate-contact-type SECURITY --email-address <TEAM_EMAIL> --name "
           "<TEAM_NAME> --title 'Security Team' --phone-number <PHONE> . Verify with "
           "aws account get-alternate-contact --alternate-contact-type SECURITY"),
       risk=("The SECURITY alternate contact is the address AWS uses to report abuse "
             "originating from the account, credentials it has found exposed in public "
             "repositories, and security bulletins that require action. With no alternate "
             "contact set, those notices go to the root user's email address — typically "
             "an individual's mailbox, often created when the account was opened, and "
             "frequently no longer monitored by anyone. AWS detecting a leaked key and "
             "telling nobody who is listening is the worst possible outcome of a control "
             "that costs one API call to set."),
       impact=("AWS security notices about this account, including exposed credentials it "
               "has detected, go to an address nobody is monitoring."),
       steps=("Check the current setting: aws account get-alternate-contact "
              "--alternate-contact-type SECURITY",
              "Set a monitored team address: aws account put-alternate-contact "
              "--alternate-contact-type SECURITY --email-address <TEAM_EMAIL> --name "
              "<TEAM_NAME> --title 'Security Team' --phone-number <PHONE>",
              "Confirm the mailbox is monitored and routes to an on-call rota, not to a "
              "folder"),
       permissions=(_P("account:GetAlternateContact",
                       "reads the SECURITY alternate contact; the API raises "
                       "ResourceNotFound when none is set, so the read is also how "
                       "ACCT-02 tells 'not set' from 'not permitted'"),)),

    # ── IAM ──────────────────────────────────────────────────────────────────
    _C(id="IAM-11", section="IAM", severity="MEDIUM",
       compliance={"CIS": "2.6", "PCI-DSS": "8.4.1", "HIPAA": "164.312(d)",
                   "SOC2": "CC6.1", "NIST": "IA-2(1)"},
       remediation=(
           "Replace the root user's virtual MFA with a hardware device. Confirm what is "
           "registered: aws iam list-virtual-mfa-devices --assignment-status Assigned "
           "(a virtual device's SerialNumber is an arn:aws:iam:: ARN; a hardware one's is "
           "not). Then register the hardware key in the console under Security "
           "credentials, and deregister the virtual device only after the hardware key is "
           "confirmed working"),
       risk=("A virtual MFA device is a shared secret held in an authenticator app. That "
             "app sits on a phone protected by a screen lock and, in most configurations, "
             "backed up to a cloud account — so the second factor can be restored onto "
             "another device by anyone who compromises that cloud account, and it can be "
             "phished in real time by a relay site. A hardware security key cannot be "
             "copied, cannot be restored elsewhere, and is bound to the origin it was "
             "registered against, so it does not authenticate to a phishing proxy. For "
             "the root user, whose credential cannot be restricted by any policy, that "
             "difference is the whole control."),
       impact=("The root user's second factor can be phished or restored onto an "
               "attacker's device, leaving no policy able to restrict what follows."),
       steps=("Confirm the root device is virtual: aws iam list-virtual-mfa-devices "
              "--assignment-status Assigned and look for a SerialNumber ending in "
              ":mfa/root-account-mfa-device",
              "Obtain a FIDO2 security key and register it on the root user in the "
              "console under My Security Credentials",
              "Test a root sign-in with the hardware key before removing anything",
              "Deregister the virtual device once the hardware key is proven"),
       permissions=(_P("iam:ListVirtualMFADevices",
                       "returns the assigned virtual MFA devices; the presence of the "
                       "root user in that list is precisely what distinguishes a virtual "
                       "root factor from a hardware one"),)),

    _C(id="IAM-12", section="IAM", severity="LOW",
       compliance={"CIS": "2.13", "PCI-DSS": "7.2.2", "HIPAA": "164.308(a)(4)(ii)(B)",
                   "SOC2": "CC6.3", "NIST": "AC-6"},
       remediation=(
           "Move the permissions to a group and detach them from the user: "
           "aws iam add-user-to-group --group-name <GROUP> --user-name <USER> ; "
           "aws iam detach-user-policy --user-name <USER> --policy-arn <POLICY_ARN> ; "
           "for inline policies aws iam delete-user-policy --user-name <USER> "
           "--policy-name <NAME> . Confirm with aws iam list-attached-user-policies "
           "--user-name <USER>"),
       risk=("Permissions attached directly to a user do not appear in any group-based "
             "access review, are not removed when the user is taken out of a group, and "
             "drift away from the peers the user is nominally equivalent to. The practical "
             "consequence shows up during a leaver or role-change process: removing "
             "someone from every group looks like removing their access, and the direct "
             "grants survive it. This is a governance finding rather than an access one — "
             "whether the permissions themselves are excessive is a separate question that "
             "the privilege-escalation checks answer directly, which is why this is rated "
             "LOW."),
       impact=("Access reviews and leaver processes that work through group membership "
               "silently miss these grants."),
       steps=("List what the user holds directly: aws iam list-attached-user-policies "
              "--user-name <USER> and aws iam list-user-policies --user-name <USER>",
              "Create or identify a group that represents the user's actual role and "
              "attach the policy there: aws iam attach-group-policy --group-name <GROUP> "
              "--policy-arn <POLICY_ARN>",
              "Add the user to the group: aws iam add-user-to-group --group-name <GROUP> "
              "--user-name <USER>",
              "Detach the direct grants and re-list to confirm nothing remains"),
       permissions=(_P("iam:ListAttachedUserPolicies",
                       "returns the managed policies attached straight to a user, which "
                       "is half of what 2.13 asks about and is invisible from group "
                       "membership alone"),
                    _P("iam:ListUserPolicies",
                       "returns inline user policies, the half that no policy-ARN "
                       "inventory can find because an inline policy has no ARN"))),

    _C(id="IAM-13", section="IAM", severity="LOW",
       compliance={"CIS": "2.15", "PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(6)(ii)",
                   "SOC2": "CC7.3", "NIST": "AC-6"},
       remediation=(
           "Create a role that can raise support cases and nothing else: "
           "aws iam create-role --role-name AWSSupportRole --assume-role-policy-document "
           "file://trust.json ; aws iam attach-role-policy --role-name AWSSupportRole "
           "--policy-arn arn:aws:iam::aws:policy/AWSSupportAccess . Verify with "
           "aws iam list-entities-for-policy --policy-arn "
           "arn:aws:iam::aws:policy/AWSSupportAccess"),
       risk=("With nobody holding AWSSupportAccess, opening a support case requires an "
             "administrator. That constraint bites hardest during an incident, when the "
             "people triaging are the people who most need a case open with AWS and the "
             "only way to give them one is to grant administrator access under time "
             "pressure. The policy itself is narrow — it permits support case operations "
             "and nothing else — so the role is a genuinely least-privileged way to make "
             "escalation to AWS possible without widening anyone's access."),
       impact=("Raising a support case during an incident requires granting somebody "
               "administrator access to do it."),
       steps=("Check whether anything holds the policy: aws iam list-entities-for-policy "
              "--policy-arn arn:aws:iam::aws:policy/AWSSupportAccess",
              "Create a role trusted by the responders who need it: aws iam create-role "
              "--role-name AWSSupportRole --assume-role-policy-document file://trust.json",
              "Attach the managed policy: aws iam attach-role-policy --role-name "
              "AWSSupportRole --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess",
              "Confirm the role now appears in list-entities-for-policy"),
       permissions=(_P("iam:ListEntitiesForPolicy",
                       "returns the roles, users and groups carrying a managed policy; "
                       "it is how IAM-13 and IAM-15 decide whether AWSSupportAccess and "
                       "AWSCloudShellFullAccess are held, and by whom"),)),

    _C(id="IAM-14", section="IAM", severity="MEDIUM",
       compliance={"CIS": "2.19", "PCI-DSS": "8.2.1", "HIPAA": "164.312(a)(2)(i)",
                   "SOC2": "CC6.1", "NIST": "IA-2"},
       remediation=(
           "Move human sign-in to IAM Identity Center or an existing federation, then "
           "remove the console passwords: aws sso-admin list-instances to find or confirm "
           "an Identity Center instance, and aws iam delete-login-profile --user-name "
           "<USER> once the person can sign in through the directory. Leave "
           "password-less service users alone — they are not the subject of this control"),
       risk=("An IAM user with a console password is a local credential with its own "
             "password, its own MFA state and its own lifecycle, none of which the "
             "corporate directory governs. When someone leaves, they are disabled in the "
             "directory and this account keeps working until somebody remembers it exists. "
             "Federation makes the directory the single point of both grant and revocation, "
             "so joiner, mover and leaver processes reach AWS automatically. This check is "
             "deliberately scoped to users that have a console password: an IAM user "
             "without one is a service account, not a person bypassing federation, and "
             "failing it would push operators toward a migration that improves nothing."),
       impact=("Human access to AWS survives removal from the corporate directory, "
               "because it does not depend on it."),
       steps=("List the users with console passwords from the credential report: aws iam "
              "generate-credential-report then aws iam get-credential-report",
              "Confirm or create an identity source: aws sso-admin list-instances , or "
              "aws iam list-saml-providers",
              "Migrate each person to a permission set or federated role, and verify they "
              "can sign in that way",
              "Remove the console password: aws iam delete-login-profile --user-name <USER>"),
       permissions=(_P("iam:ListSAMLProviders",
                       "shows whether SAML federation is configured, which decides "
                       "whether IAM-14 reports console users as a parallel path around "
                       "an existing identity source or as the only path there is"),
                    _P("iam:ListOpenIDConnectProviders",
                       "the OIDC half of the same question; an estate federating through "
                       "OIDC has an identity source that a SAML-only read would miss"),
                    _P("sso:ListInstances",
                       "reports whether IAM Identity Center is in use, the most common "
                       "identity source of the three and the one AWS now recommends"))),

    _C(id="IAM-15", section="IAM", severity="MEDIUM",
       compliance={"CIS": "2.20", "PCI-DSS": "7.2.2", "HIPAA": "164.312(a)(1)",
                   "SOC2": "CC6.3", "NIST": "AC-6(1)"},
       remediation=(
           "Detach AWSCloudShellFullAccess and grant only the CloudShell actions actually "
           "needed: aws iam detach-role-policy --role-name <ROLE> --policy-arn "
           "arn:aws:iam::aws:policy/AWSCloudShellFullAccess (or detach-user-policy / "
           "detach-group-policy). Where CloudShell is required without file transfer, "
           "attach a custom policy that denies cloudshell:GetFileDownloadUrls and "
           "cloudshell:GetFileUploadUrls"),
       risk=("AWSCloudShellFullAccess grants every CloudShell action, and two of them — "
             "GetFileUploadUrls and GetFileDownloadUrls — together form a bidirectional "
             "file transfer channel between an operator's workstation and the AWS "
             "environment. That channel does not traverse a VPC, so it appears in no flow "
             "log; it is not subject to any VPC endpoint policy; and it is attributed only "
             "in CloudTrail, where it looks like ordinary console activity. A principal "
             "with this policy and read access to sensitive data has an egress path that "
             "none of the network controls in the account can see or stop."),
       impact=("Holders gain a two-way file transfer path in and out of the account that "
               "no network control observes."),
       steps=("List who holds it: aws iam list-entities-for-policy --policy-arn "
              "arn:aws:iam::aws:policy/AWSCloudShellFullAccess",
              "For each principal that does not need CloudShell, detach it: aws iam "
              "detach-role-policy --role-name <ROLE> --policy-arn "
              "arn:aws:iam::aws:policy/AWSCloudShellFullAccess",
              "For those that do, replace it with a policy that denies "
              "cloudshell:GetFileUploadUrls and cloudshell:GetFileDownloadUrls",
              "Re-run list-entities-for-policy and confirm the remaining holders are "
              "intended"),
       permissions=(_P("iam:ListEntitiesForPolicy",
                       "returns who holds AWSCloudShellFullAccess. Declared here as well "
                       "as on IAM-13 on purpose: the ledger is read by someone deciding "
                       "one grant at a time, and a check whose action is only declared "
                       "elsewhere looks like it needs nothing"),)),

    # ── compute / storage / logging / network ────────────────────────────────
    _C(id="EC2-18", section="EC2", severity="MEDIUM",
       compliance={"CIS": "2.16", "PCI-DSS": "8.6.1", "HIPAA": "164.312(a)(2)(i)",
                   "SOC2": "CC6.1", "NIST": "IA-5"},
       remediation=(
           "Attach an instance profile so the instance gets rotating credentials instead "
           "of a static key: aws ec2 associate-iam-instance-profile --instance-id "
           "<INSTANCE_ID> --iam-instance-profile Name=<PROFILE_NAME> . Then remove any "
           "static key from the host and its AMI, and deactivate it: aws iam "
           "update-access-key --user-name <USER> --access-key-id <KEY_ID> --status "
           "Inactive"),
       risk=("An EC2 instance with no instance profile that nonetheless calls AWS APIs is "
             "using a long-lived access key that had to be placed on the host by some "
             "means — baked into the AMI, passed through user data, or written by a "
             "configuration tool. Such a key does not rotate, is readable by any process "
             "or person on the instance, and outlives the instance itself: it persists in "
             "the AMI it was baked into and in every snapshot taken from that volume. An "
             "instance role issues short-lived credentials that AWS rotates automatically "
             "and that cannot be exported off the instance. This check reports the absence "
             "of a profile, not the presence of a key — EC2-07 finds keys in user data, "
             "and neither can see one written to the filesystem."),
       impact=("Any AWS access this instance has is backed by a static credential that "
               "does not rotate and survives in every image taken of the host."),
       steps=("Determine whether the instance calls AWS APIs at all; if not, no profile "
              "is needed and the finding can be accepted",
              "Create a least-privilege role for what it does call, and an instance "
              "profile for it: aws iam create-instance-profile --instance-profile-name "
              "<PROFILE_NAME>",
              "Attach it: aws ec2 associate-iam-instance-profile --instance-id "
              "<INSTANCE_ID> --iam-instance-profile Name=<PROFILE_NAME>",
              "Remove the static key from the host, rebuild the AMI without it, and "
              "deactivate the key in IAM"),
       permissions=(_P("ec2:DescribeInstances",
                       "returns each instance's IamInstanceProfile, which is the whole "
                       "of what 2.16 asks; without it EC2-18 cannot tell an instance "
                       "with no role from an instance that was not listed"),)),

    _C(id="S3-11", section="S3", severity="LOW",
       compliance={"CIS": "3.1.2", "PCI-DSS": "10.3.2", "HIPAA": "164.312(c)(1)",
                   "SOC2": "CC6.1", "NIST": "CP-9"},
       remediation=(
           "Enable versioning and MFA Delete together — MFA Delete requires root "
           "credentials and an MFA code, so this cannot be done with a role: "
           "aws s3api put-bucket-versioning --bucket <BUCKET> --versioning-configuration "
           "Status=Enabled,MFADelete=Enabled --mfa '<MFA_SERIAL> <CODE>' . Verify with "
           "aws s3api get-bucket-versioning --bucket <BUCKET>"),
       risk=("Without MFA Delete, any principal holding s3:DeleteObjectVersion can "
             "permanently remove individual object versions, and one holding "
             "s3:PutBucketVersioning can suspend versioning first and then delete freely. "
             "Both are ordinary permissions that a compromised application role plausibly "
             "carries. MFA Delete requires the root user's physical second factor for "
             "exactly those two operations, which makes it a control that an attacker "
             "holding a stolen role credential cannot satisfy — the rare case where a "
             "bucket setting defends against an already-authenticated adversary rather "
             "than an unauthenticated one."),
       impact=("Object versions and the versioning setting itself can be destroyed by any "
               "principal with routine S3 write permissions."),
       steps=("Confirm versioning state: aws s3api get-bucket-versioning --bucket <BUCKET>",
              "Enable versioning first if it is off, since MFA Delete depends on it",
              "Using ROOT credentials and an MFA code, enable MFA Delete: aws s3api "
              "put-bucket-versioning --bucket <BUCKET> --versioning-configuration "
              "Status=Enabled,MFADelete=Enabled --mfa '<MFA_SERIAL> <CODE>'",
              "Re-read the configuration and confirm MFADelete is Enabled"),
       permissions=(_P("s3:GetBucketVersioning",
                       "returns MFADelete alongside the versioning Status in one call, "
                       "which is why S3-11 can state the precondition rather than "
                       "advising an operator to enable a setting the console greys out"),)),

    _C(id="LOG-11", section="LOGGING", severity="MEDIUM",
       compliance={"CIS": "4.2", "PCI-DSS": "10.3.2", "HIPAA": "164.312(c)(1)",
                   "SOC2": "CC7.2", "NIST": "AU-9"},
       remediation=(
           "Turn on log file validation for the trail: aws cloudtrail update-trail --name "
           "<TRAIL_NAME> --enable-log-file-validation . Confirm with aws cloudtrail "
           "get-trail-status --name <TRAIL_NAME> and validate a range later with "
           "aws cloudtrail validate-logs --trail-arn <TRAIL_ARN> --start-time <TIME>"),
       risk=("Log file validation makes CloudTrail write a signed digest file for each "
             "hour of delivered logs, hash-chained to the previous one. Without it, a log "
             "file that has been altered or removed from the bucket is indistinguishable "
             "from an hour in which nothing happened — there is no record of what should "
             "have been there. That is precisely the state an intruder wants the audit "
             "trail left in, and it is also the property that separates an audit trail "
             "usable as evidence from one that merely describes activity. Enabling it "
             "costs nothing and is a single API call."),
       impact=("Deletion or alteration of CloudTrail log files cannot be detected, so the "
               "audit record cannot be shown to be complete."),
       steps=("Identify trails without validation: aws cloudtrail describe-trails --query "
              "'trailList[?LogFileValidationEnabled==`false`].Name'",
              "Enable it: aws cloudtrail update-trail --name <TRAIL_NAME> "
              "--enable-log-file-validation",
              "Confirm digest files begin appearing under the CloudTrail-Digest prefix in "
              "the bucket",
              "Spot-check a period: aws cloudtrail validate-logs --trail-arn <TRAIL_ARN> "
              "--start-time <TIME>"),
       permissions=(_P("cloudtrail:DescribeTrails",
                       "returns LogFileValidationEnabled on each trail, and the bucket "
                       "name LOG-12 then resolves; both controls are decided from this "
                       "one listing"),)),

    _C(id="LOG-12", section="LOGGING", severity="MEDIUM",
       compliance={"CIS": "4.4", "PCI-DSS": "10.3.1", "HIPAA": "164.312(b)",
                   "SOC2": "CC7.2", "NIST": "AU-9"},
       remediation=(
           "Enable S3 server access logging on the trail's bucket, targeting a DIFFERENT "
           "bucket so the logs cannot be edited by whoever can reach the originals: "
           "aws s3api put-bucket-logging --bucket <TRAIL_BUCKET> "
           "--bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":"
           "\"<LOG_BUCKET>\",\"TargetPrefix\":\"cloudtrail-access/\"}}' . Verify with "
           "aws s3api get-bucket-logging --bucket <TRAIL_BUCKET>"),
       risk=("The bucket holding CloudTrail logs contains the record of everything anyone "
             "did in the account. Reading it is how an intruder learns what was captured "
             "about them and decides what to remove or how to proceed, and a GetObject "
             "against that bucket is not itself a management event — so without S3 server "
             "access logging it leaves no trace at all. Enabling access logging on this "
             "one bucket turns reads of the audit trail into evidence in their own right. "
             "The target must be a different bucket, or an attacker who can reach the logs "
             "can also edit the record of having reached them."),
       impact=("Reads and downloads of the CloudTrail logs are unrecorded, so "
               "reconnaissance of the audit trail is invisible."),
       steps=("Find the trail's bucket: aws cloudtrail describe-trails --query "
              "'trailList[].[Name,S3BucketName]'",
              "Check the current setting: aws s3api get-bucket-logging --bucket "
              "<TRAIL_BUCKET>",
              "Enable logging to a separate bucket: aws s3api put-bucket-logging --bucket "
              "<TRAIL_BUCKET> --bucket-logging-status '{...}'",
              "Confirm access log objects begin arriving under the chosen prefix"),
       permissions=(_P("s3:GetBucketLogging",
                       "reads whether server access logging is configured on the "
                       "CloudTrail bucket specifically; the trail's own APIs do not "
                       "report anything about the bucket's settings"),)),

    _C(id="VPC-07", section="VPC", severity="MEDIUM",
       compliance={"CIS": "6.6", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)",
                   "SOC2": "CC6.6", "NIST": "SC-7"},
       remediation=(
           "Replace the whole-VPC route with routes to the specific subnets that host the "
           "shared service: aws ec2 delete-route --route-table-id <RTB_ID> "
           "--destination-cidr-block <WIDE_CIDR> , then aws ec2 create-route "
           "--route-table-id <RTB_ID> --destination-cidr-block <SUBNET_CIDR> "
           "--vpc-peering-connection-id <PCX_ID> for each one. Review what is there with "
           "aws ec2 describe-route-tables --route-table-ids <RTB_ID>"),
       risk=("A VPC peering connection carries no filtering of its own: whatever a route "
             "points at it becomes reachable, and the far side's security groups are the "
             "only remaining control over who answers. A route for the peer's entire VPC "
             "CIDR therefore makes every host in that VPC reachable from this one, when "
             "the intent is almost always a specific shared service in a few subnets. The "
             "practical effect is that a compromise on either side of the peering has the "
             "whole of the other side available to scan, and neither team's security group "
             "review shows the exposure, because the route is in a table nobody thinks of "
             "as a firewall."),
       impact=("Every host in the peer VPC is reachable across the peering connection "
               "rather than only the intended service."),
       steps=("List the peering routes: aws ec2 describe-route-tables --route-table-ids "
              "<RTB_ID>",
              "Identify the subnets that actually host the shared service on the far side",
              "Delete the wide route: aws ec2 delete-route --route-table-id <RTB_ID> "
              "--destination-cidr-block <WIDE_CIDR>",
              "Add specific routes: aws ec2 create-route --route-table-id <RTB_ID> "
              "--destination-cidr-block <SUBNET_CIDR> --vpc-peering-connection-id "
              "<PCX_ID>"),
       permissions=(_P("ec2:DescribeVpcPeeringConnections",
                       "resolves each peering connection so the finding can name the peer "
                       "CIDR a route exposes rather than only the route's destination"),)),

    _C(id="VPC-08", section="VPC", severity="LOW",
       compliance={"CIS": "6.8", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)",
                   "SOC2": "CC6.6", "NIST": "SC-7"},
       remediation=(
           "Create endpoints for the services the VPC actually uses. Gateway endpoints are "
           "free: aws ec2 create-vpc-endpoint --vpc-id <VPC_ID> --service-name "
           "com.amazonaws.<REGION>.s3 --route-table-ids <RTB_ID> . Interface endpoints "
           "cover the rest: aws ec2 create-vpc-endpoint --vpc-id <VPC_ID> "
           "--vpc-endpoint-type Interface --service-name com.amazonaws.<REGION>.kms "
           "--subnet-ids <SUBNETS> --security-group-ids <SG>"),
       risk=("Without VPC endpoints, every call a workload makes to S3, DynamoDB, KMS, "
             "Secrets Manager or any other AWS service leaves the VPC through its internet "
             "gateway or NAT and reaches AWS over the public network. Two things follow. "
             "The traffic is exposed to whatever sits on that path, and — the part that is "
             "a security control rather than a routing preference — there is no endpoint "
             "policy, so nothing constrains WHICH buckets, keys or secrets the workload "
             "may reach. An endpoint policy is the only mechanism that can say 'this VPC "
             "may reach these buckets and no others', independently of what the instance's "
             "role permits."),
       impact=("AWS service traffic traverses the public network and cannot be restricted "
               "to specific resources by an endpoint policy."),
       steps=("List the VPC's endpoints: aws ec2 describe-vpc-endpoints --filters "
              "Name=vpc-id,Values=<VPC_ID>",
              "Identify the AWS services the workloads in the VPC actually call",
              "Create gateway endpoints for S3 and DynamoDB first — they are free and "
              "cover the highest-volume traffic",
              "Add interface endpoints for the remaining services, then attach endpoint "
              "policies restricting which resources may be reached"),
       permissions=(_P("ec2:DescribeVpcEndpoints",
                       "lists the endpoints attached to each VPC, which is the whole of "
                       "what 6.8 asks and is not derivable from route tables alone"),)),
)
