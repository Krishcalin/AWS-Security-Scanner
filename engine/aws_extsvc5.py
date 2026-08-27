#!/usr/bin/env python3
"""aws_extsvc5.py — extended AWS service coverage, batch 5.

Fifth batch off the 426-service gap analysis, and the first authored after the SDK pin
moved to botocore 1.43.51 — so for the first time the models these checks were verified
against are the models the product actually ships.

Every service here was confirmed **live** before anything was written. That check became
routine after batch 4, where AWS Elemental MediaStore turned out to have reached end of
life nine months earlier and was dropped rather than built.

WHAT EACH SERVICE CONTRIBUTES
------------------------------
* **Amazon WorkMail** — a mailbox is a credential store: password resets, MFA enrolment
  links and signed approvals all arrive there. Without access control rules any client
  from any network may connect; without mobile device rules any personal phone may sync
  the whole mailbox; without a retention policy nothing ever ages out, so a compromise
  in 2026 exposes 2019.
* **IoT SiteWise** — industrial telemetry from physical plant. The default encryption is
  a service key, and logging defaults to ``OFF``.
* **IoT Managed Integrations** — the newest service in the batch (2025 API), and it
  ships with ``MANAGED_INTEGRATIONS_DEFAULT_ENCRYPTION`` until somebody changes it.
* **SES Mail Manager** — a traffic policy with ``DefaultAction=ALLOW`` fails **open**:
  mail matching none of the policy statements is delivered rather than rejected.
* **CodeGuru Profiler** — profiles are stack traces from production, and the method
  names in them describe your internal architecture.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional, Sequence
from urllib.parse import unquote

from engine import aws_checkdef as _cd
from engine.aws_checkdef import CheckDef as _C, Perm as _P

__all__ = [
    "workmail_access_rules", "workmail_retention", "workmail_device_rules",
    "sitewise_encryption", "sitewise_logging", "imi_encryption",
    "mailmanager_policy", "codeguru_policy",
    "SITEWISE_DEFAULT", "IMI_DEFAULT", "LOG_OFF", "ALLOW", "parse_doc",
]

# ── verified enum values ────────────────────────────────────────────────────
SITEWISE_DEFAULT = "SITEWISE_DEFAULT_ENCRYPTION"     # iotsitewise EncryptionType
SITEWISE_KMS = "KMS_BASED_ENCRYPTION"
IMI_DEFAULT = "MANAGED_INTEGRATIONS_DEFAULT_ENCRYPTION"
IMI_CMK = "CUSTOMER_KEY_ENCRYPTION"
LOG_OFF = "OFF"                                      # iotsitewise LoggingLevel
ALLOW = "ALLOW"                                      # mailmanager AcceptAction


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


# ── Amazon WorkMail ─────────────────────────────────────────────────────────
def workmail_access_rules(org_id: str, rules: Optional[Sequence]) -> dict:
    """Access control rules bound WHO may connect and from WHERE."""
    rs = [_d(r) for r in _l(rules)]
    restrictive = [r for r in rs
                   if r.get("Effect") == "DENY" or r.get("IpRanges")
                   or r.get("NotIpRanges") or r.get("UserIds")]
    return {
        "organization": org_id or "",
        "count": len(rs),
        "restrictive": len(restrictive),
        "unrestricted": not restrictive,
        "statement": (
            f"WorkMail organization {org_id} has no access control rules that restrict "
            f"anything — every protocol is reachable by every user from any network. A "
            f"mailbox is where password resets and MFA enrolment links arrive, so it is "
            f"a credential store with a login page"
            if not restrictive else ""),
    }


def workmail_retention(org_id: str, policy: Optional[dict], readable=True) -> dict:
    """A default retention policy is what makes old mail stop existing."""
    p = _d(policy)
    folders = _l(p.get("FolderConfigurations"))
    return {
        "organization": org_id or "",
        "has_policy": bool(p.get("Id")) or bool(folders),
        "folders": len(folders),
        "known": readable,
        "statement": (
            f"WorkMail organization {org_id} has no default retention policy, so mail is "
            f"kept indefinitely. Retention is a security control as much as a storage "
            f"one: a mailbox compromised today exposes every message the organization "
            f"has ever sent, and nothing that was never deleted can be un-exposed"
            if readable and not (p.get("Id") or folders) else ""),
    }


def workmail_device_rules(org_id: str, rules: Optional[Sequence]) -> dict:
    """Mobile device access rules decide which devices may sync a whole mailbox."""
    rs = [_d(r) for r in _l(rules)]
    return {
        "organization": org_id or "",
        "count": len(rs),
        "unrestricted": not rs,
        "statement": (
            f"WorkMail organization {org_id} has no mobile device access rules — any "
            f"device that can authenticate may sync an entire mailbox to local storage, "
            f"including personal phones outside any device-management programme. The "
            f"copy on the device outlives the session"
            if not rs else ""),
    }


# ── AWS IoT SiteWise ────────────────────────────────────────────────────────
def sitewise_encryption(config: Optional[dict]) -> dict:
    c = _d(config)
    t = c.get("encryptionType") or ""
    return {
        "type": t,
        "known": bool(t),
        "cmk": t == SITEWISE_KMS,
        "key": c.get("kmsKeyArn") or "",
        "statement": (
            "IoT SiteWise uses the default service encryption rather than a "
            "customer-managed key. SiteWise holds industrial telemetry from physical "
            "plant — asset hierarchies, sensor histories and process values — which is "
            "both operationally sensitive and, in a regulated plant, evidentiary"
            if t == SITEWISE_DEFAULT else ""),
    }


def sitewise_logging(options: Optional[dict]) -> dict:
    o = _d(options)
    level = (_d(o.get("loggingOptions")).get("level") if o.get("loggingOptions")
             else o.get("level")) or ""
    return {
        "level": level,
        "known": bool(level),
        "off": level == LOG_OFF,
        "statement": (
            "IoT SiteWise logging is set to OFF, so there is no record of gateway "
            "activity, ingestion failures or configuration changes. On an industrial "
            "estate the first sign that telemetry has been tampered with is usually an "
            "ingestion anomaly, and with logging off there is nowhere for that to appear"
            if level == LOG_OFF else ""),
    }


# ── AWS IoT Managed Integrations ────────────────────────────────────────────
def imi_encryption(config: Optional[dict]) -> dict:
    c = _d(config)
    t = c.get("encryptionType") or ""
    return {
        "type": t,
        "known": bool(t),
        "cmk": t == IMI_CMK,
        "key": c.get("kmsKeyArn") or "",
        "status": c.get("configurationStatus") or "",
        "statement": (
            "IoT Managed Integrations uses the default service encryption rather than a "
            "customer-managed key. This is the value the service ships with, so an "
            "account reaches it by not choosing — and what it holds is the credential "
            "and connection material for third-party device clouds"
            if t == IMI_DEFAULT else ""),
    }


# ── SES Mail Manager ────────────────────────────────────────────────────────
def mailmanager_policy(name: str, policy: Optional[dict]) -> dict:
    """``DefaultAction=ALLOW`` delivers whatever matched no statement."""
    p = _d(policy)
    default = p.get("DefaultAction") or ""
    statements = _l(p.get("PolicyStatements"))
    return {
        "name": name or p.get("TrafficPolicyName") or "",
        "default_action": default,
        "known": bool(default),
        "fails_open": default == ALLOW,
        "statements": len(statements),
        "statement": (
            f"SES Mail Manager traffic policy {name or p.get('TrafficPolicyName')} has "
            f"DefaultAction=ALLOW — mail matching none of its {len(statements)} "
            f"statement(s) is DELIVERED rather than rejected. The policy therefore "
            f"blocks only what it was explicitly told about, which is the opposite of "
            f"how a mail filter is usually assumed to work"
            if default == ALLOW else ""),
    }


# ── Amazon CodeGuru Profiler ────────────────────────────────────────────────
def codeguru_policy(group: str, policy) -> dict:
    """Profiles are production stack traces; the method names describe the estate."""
    doc = parse_doc(policy)
    stmts = doc.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    wide = [s for s in (stmts or []) if isinstance(s, dict) and _wide_principal(s)]
    return {
        "group": group or "",
        "has_policy": bool(stmts),
        "public": bool(wide),
        "statement": (
            f"CodeGuru Profiler group {group} has a resource policy granting a wildcard "
            f"principal. A profile is a set of stack traces captured from production, so "
            f"reading one reveals internal class and method names, the frameworks in "
            f"use, and which code paths carry load — a map of the application that no "
            f"amount of endpoint hardening hides"
            if wide else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Declarations
# ══════════════════════════════════════════════════════════════════════════════
_ACC = {"PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"}
_NET = {"PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"}
_ENC = {"PCI-DSS": "3.5.1", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1",
        "NIST": "SC-28"}
_LOG = {"PCI-DSS": "10.2.1", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"}
# NIST here is a SUBSTITUTION, and worth naming. SI-12 (Information Management
# and Retention) is the precise control for WM-02, and it is the 39th -- the
# universe is frozen at 38 on purpose, because it is the denominator the
# evidence pack counts against. Growing it is a compliance-reporting decision,
# not something a coverage batch should do on its way past. SC-28 is the
# defensible in-universe fit (retention bounds what exists at rest), and the
# PCI and HIPAA cells carry the precise meaning.
_RET = {"PCI-DSS": "3.2.1", "HIPAA": "164.316(b)(2)", "SOC2": "CC6.5",
        "NIST": "SC-28"}

CHECKS = _cd.register(
    _C(id="WM-01", section="WORKMAIL", severity="MEDIUM", compliance=_NET,
       permissions=(
           _P("workmail:ListOrganizations",
              "enumerate the WorkMail organizations hosted in this account"),
           _P("workmail:ListAccessControlRules",
              "read the rules bounding which users, protocols and source networks may "
              "connect to a mailbox"),
       ),
       remediation=(
           "Add an access control rule so mailbox access is bounded by network and "
           "protocol rather than open to anything that can authenticate: aws workmail "
           "put-access-control-rule --organization-id <ORG_ID> --name RestrictSources "
           "--effect ALLOW --ip-ranges <CIDR> --description 'corporate networks'. Add a "
           "matching DENY for legacy protocols you do not use"),
       risk=(
           "This WorkMail organization has no access control rules that restrict "
           "anything, so every supported protocol is reachable by every user from any "
           "network. It is worth being concrete about why a mailbox matters more than "
           "its contents suggest: a mailbox is a credential store with a login page. "
           "Password reset links arrive there, MFA enrolment and recovery codes arrive "
           "there, and signed approvals for payments and access requests arrive there. "
           "An attacker who reads mail can generally obtain whatever else they want by "
           "asking for it through the normal process, which is why mailbox compromise is "
           "so often the first step rather than the objective. Access control rules are "
           "the only place in WorkMail where 'from where' and 'over which protocol' can "
           "be constrained, and legacy protocols in particular tend to remain enabled "
           "long after the clients that needed them are gone."),
       impact=("Any authenticated user can reach every mailbox protocol from any "
               "network, so a stolen credential is immediately usable from anywhere."),
       steps=(
           "Establish which networks and protocols are genuinely in use before writing "
           "rules -- these apply organization-wide and fail closed.",
           "Restrict by source: aws workmail put-access-control-rule --organization-id "
           "<ORG_ID> --name RestrictSources --effect ALLOW --ip-ranges <CIDR> "
           "--description 'corporate networks'",
           "Deny protocols you do not use, rather than leaving them reachable: aws "
           "workmail put-access-control-rule --organization-id <ORG_ID> --name "
           "DenyLegacy --effect DENY --actions <ACTION> --description 'unused protocols'",
           "Verify with aws workmail get-access-control-effect --organization-id "
           "<ORG_ID> --ip-address <IP> --action <ACTION> --user-id <USER> before "
           "relying on the rule.")),

    _C(id="WM-02", section="WORKMAIL", severity="MEDIUM", compliance=_RET,
       permissions=(
           _P("workmail:GetDefaultRetentionPolicy",
              "read whether mail ages out at all, or accumulates indefinitely so a "
              "future compromise exposes the entire history"),
       ),
       remediation=(
           "Set a default retention policy so mail stops accumulating without limit: "
           "aws workmail put-retention-policy --organization-id <ORG_ID> --name Default "
           "--folder-configurations 'Name=INBOX,Action=DELETE,Period=1095' "
           "'Name=SENT_ITEMS,Action=DELETE,Period=1095' . Agree the periods with legal "
           "before applying -- deletion is not reversible"),
       risk=(
           "This WorkMail organization has no default retention policy, so mail is kept "
           "indefinitely. Retention is usually filed under storage cost or legal policy, "
           "and it is genuinely both, but it is also a security control and that is the "
           "part most often missed. The quantity of data exposed by a mailbox compromise "
           "is decided years in advance by the retention policy: an account taken over "
           "today exposes every message the organization has ever sent or received "
           "through it, because nothing ever aged out. Old mail is also disproportionately "
           "valuable to an attacker -- it contains the historical org chart, past "
           "contract negotiations, credentials that were emailed once and never rotated, "
           "and the writing style needed to make a convincing business email compromise. "
           "Nothing that was never deleted can be un-exposed after the fact."),
       impact=("A mailbox compromise exposes the organization's complete mail history "
               "rather than a bounded recent window."),
       steps=(
           "Agree retention periods with legal and compliance first; deletion is not "
           "reversible and litigation holds may apply.",
           "Apply the policy: aws workmail put-retention-policy --organization-id "
           "<ORG_ID> --name Default --folder-configurations "
           "'Name=INBOX,Action=DELETE,Period=1095'",
           "Cover the folders that actually accumulate -- SENT_ITEMS and DELETED_ITEMS "
           "are frequently larger than INBOX.",
           "Confirm it applied: aws workmail get-default-retention-policy "
           "--organization-id <ORG_ID>")),

    _C(id="WM-03", section="WORKMAIL", severity="MEDIUM", compliance=_ACC,
       permissions=(
           _P("workmail:ListMobileDeviceAccessRules",
              "read which devices may synchronise a whole mailbox to local storage, "
              "where the copy outlives the session"),
       ),
       remediation=(
           "Add mobile device access rules so an arbitrary personal device cannot "
           "synchronise a mailbox: aws workmail create-mobile-device-access-rule "
           "--organization-id <ORG_ID> --name ManagedOnly --effect ALLOW "
           "--device-types <TYPE> . Review effect for a specific device first with aws "
           "workmail get-mobile-device-access-effect"),
       risk=(
           "This WorkMail organization has no mobile device access rules, so any device "
           "that can authenticate may synchronise an entire mailbox to local storage. "
           "The distinction that matters is between access and COPY: a web session ends, "
           "but a synchronised mailbox is a full local replica that persists on the "
           "device afterwards, and it keeps working offline. If that device is a "
           "personal phone outside any device-management programme -- which is the usual "
           "case when no rules exist -- then the organization has no way to wipe it, no "
           "way to know it exists, and no way to establish what it holds. Revoking the "
           "user's credentials at some later date does nothing about the copy. Device "
           "rules are the only control point WorkMail offers here, and their absence is "
           "silent because synchronisation looks like ordinary mail access in every log."),
       impact=("Any authenticating device, managed or not, can hold a persistent offline "
               "replica of a full mailbox that survives credential revocation."),
       steps=(
           "Decide the device policy with whoever owns endpoint management before "
           "writing rules; this can cut off working phones.",
           "Create a rule allowing only managed device types: aws workmail "
           "create-mobile-device-access-rule --organization-id <ORG_ID> --name "
           "ManagedOnly --effect ALLOW --device-types <TYPE>",
           "Check the effect for a specific device before enforcing: aws workmail "
           "get-mobile-device-access-effect --organization-id <ORG_ID> --device-type "
           "<TYPE> --device-operating-system <OS>",
           "Review existing overrides, which bypass the rules: aws workmail "
           "list-mobile-device-access-overrides --organization-id <ORG_ID>")),

    _C(id="SW-01", section="SITEWISE", severity="MEDIUM", compliance=_ENC,
       permissions=(
           _P("iotsitewise:DescribeDefaultEncryptionConfiguration",
              "read encryptionType -- whether industrial telemetry sits under a "
              "customer-managed key or the SiteWise service default"),
       ),
       remediation=(
           "Move IoT SiteWise to a customer-managed key: aws iotsitewise "
           "put-default-encryption-configuration --encryption-type KMS_BASED_ENCRYPTION "
           "--kms-key-id <KEY_ARN>. Confirm with aws iotsitewise "
           "describe-default-encryption-configuration, since the change is asynchronous "
           "and reports a status"),
       risk=(
           "IoT SiteWise is using the default service encryption rather than a "
           "customer-managed key. What SiteWise holds makes this worth more attention "
           "than a generic default-encryption finding: it is the operational record of "
           "physical plant -- asset hierarchies that describe how a facility is built, "
           "sensor histories showing how it actually ran, and process values that in a "
           "regulated industry are evidentiary rather than merely operational. That data "
           "answers questions an ordinary application datastore does not: what a site "
           "produces, at what rate, with what inputs, and when it deviated. For a "
           "competitor that is commercially valuable, and for an attacker planning "
           "physical disruption it is reconnaissance. A customer-managed key adds a "
           "separately administered gate over it that can be revoked without touching "
           "SiteWise itself."),
       impact=("Industrial telemetry and asset hierarchies sit under a service-owned key "
               "with no separately-administered control over who can read them."),
       steps=(
           "Create or choose a CMK whose key policy names the roles that legitimately "
           "read SiteWise data.",
           "Apply it: aws iotsitewise put-default-encryption-configuration "
           "--encryption-type KMS_BASED_ENCRYPTION --kms-key-id <KEY_ARN>",
           "Confirm the status rather than assuming -- the change is asynchronous: aws "
           "iotsitewise describe-default-encryption-configuration",
           "Check that gateway and ingestion roles are in the key policy, or data "
           "arrival will fail with KMS denials rather than SiteWise ones.")),

    _C(id="SW-02", section="SITEWISE", severity="MEDIUM", compliance=_LOG,
       permissions=(
           _P("iotsitewise:DescribeLoggingOptions",
              "read the logging level -- OFF means no record of gateway activity, "
              "ingestion failures or configuration change"),
       ),
       remediation=(
           "Turn SiteWise logging on so gateway and ingestion activity leaves a record: "
           "aws iotsitewise put-logging-options --logging-options level=INFO. Use ERROR "
           "if INFO is too voluminous, but not OFF"),
       risk=(
           "IoT SiteWise logging is set to OFF, so there is no record of gateway "
           "activity, ingestion failures or configuration changes. In an industrial "
           "context the practical consequence is specific: tampering with telemetry "
           "rarely announces itself as a security event. It appears first as an "
           "ingestion anomaly -- a gateway that stops reporting, a property that starts "
           "receiving values from an unexpected source, a configuration change nobody "
           "recognises -- and with logging off there is nowhere for any of that to "
           "surface. The data itself will look plausible, because whoever altered it "
           "chose the values. This also matters in the ordinary case with no attacker at "
           "all: a silently failing gateway means the historical record has a hole in "
           "it, and in a regulated plant that record is the evidence of how the process "
           "ran."),
       impact=("No record exists of gateway activity, ingestion failure or configuration "
               "change, so tampering and silent data loss look identical to normal "
               "operation."),
       steps=(
           "Enable logging: aws iotsitewise put-logging-options --logging-options "
           "level=INFO",
           "Use ERROR rather than OFF if INFO is too voluminous for the estate size -- "
           "volume is the usual reason logging gets switched off again.",
           "Confirm: aws iotsitewise describe-logging-options",
           "Alarm on gateway disconnection and ingestion errors, so the logs are watched "
           "rather than merely written.")),

    _C(id="IMI-01", section="IOTMANAGEDINT", severity="MEDIUM", compliance=_ENC,
       permissions=(
           _P("iotmanagedintegrations:GetDefaultEncryptionConfiguration",
              "read encryptionType -- the service ships with its own default key, so "
              "an account reaches that state by not choosing"),
       ),
       remediation=(
           "Move IoT Managed Integrations to a customer-managed key: aws "
           "iotmanagedintegrations put-default-encryption-configuration "
           "--encryption-type CUSTOMER_KEY_ENCRYPTION --kms-key-arn <KEY_ARN>. Verify "
           "with aws iotmanagedintegrations get-default-encryption-configuration"),
       risk=(
           "IoT Managed Integrations is using MANAGED_INTEGRATIONS_DEFAULT_ENCRYPTION "
           "rather than a customer-managed key. This is the value the service ships "
           "with, so an account arrives here by not making a choice rather than by "
           "making a wrong one -- which is exactly why it is worth surfacing. What the "
           "service holds is the connection and credential material for THIRD-PARTY "
           "device clouds: the tokens and configuration that let your account speak to "
           "vendor platforms on behalf of devices you have onboarded. That material is a "
           "lateral path outward, into systems whose security posture you do not control "
           "and whose logs you cannot read. A customer-managed key gives a separately "
           "administered control over it, and the ability to revoke access to that "
           "material without renegotiating anything with the vendor."),
       impact=("Third-party device-cloud connection and credential material sits under a "
               "service-owned key, with no separately-administered control to revoke."),
       steps=(
           "Create or choose a CMK whose key policy names the roles that operate the "
           "integration.",
           "Apply it: aws iotmanagedintegrations put-default-encryption-configuration "
           "--encryption-type CUSTOMER_KEY_ENCRYPTION --kms-key-arn <KEY_ARN>",
           "Confirm: aws iotmanagedintegrations get-default-encryption-configuration",
           "Review which third-party clouds are connected while you are here -- each is "
           "an outward path, and the list tends to grow without review.")),

    _C(id="MM-01", section="MAILMANAGER", severity="HIGH", compliance=_NET,
       permissions=(
           _P("ses:ListTrafficPolicies",
              "enumerate SES Mail Manager traffic policies -- note the IAM prefix is "
              "ses, not the mailmanager client name"),
           _P("ses:GetTrafficPolicy",
              "read DefaultAction -- ALLOW delivers mail that matched no policy "
              "statement, so the filter blocks only what it was told about"),
       ),
       remediation=(
           "Change the traffic policy default so unmatched mail is rejected rather than "
           "delivered: aws mailmanager update-traffic-policy --traffic-policy-id <ID> "
           "--default-action DENY. Add explicit ALLOW statements for the senders and "
           "conditions you intend to accept BEFORE flipping the default, or legitimate "
           "mail stops"),
       risk=(
           "This SES Mail Manager traffic policy has DefaultAction set to ALLOW, which "
           "means mail matching none of its statements is delivered rather than "
           "rejected. The policy therefore blocks only what it was explicitly told "
           "about. That is the opposite of how a mail filter is generally assumed to "
           "work, and the assumption is the dangerous part: a reviewer looking at a "
           "traffic policy with a substantial list of DENY statements will reasonably "
           "conclude that mail is being filtered, when what is actually happening is "
           "that a specific enumerated set is being filtered and everything else is "
           "waved through. Mail is the primary delivery vector for phishing and business "
           "email compromise, so a fail-open filter in front of it is a control that "
           "reports success while doing considerably less than intended. Flipping the "
           "default is not a small change and needs the ALLOW statements written first."),
       impact=("Mail matching no policy statement is delivered, so the filter constrains "
               "only explicitly enumerated cases and everything else passes."),
       steps=(
           "Read the current policy and its statements: aws mailmanager "
           "get-traffic-policy --traffic-policy-id <ID>",
           "Write the ALLOW statements for traffic you intend to accept FIRST -- "
           "flipping the default before that stops legitimate mail.",
           "Then change the default: aws mailmanager update-traffic-policy "
           "--traffic-policy-id <ID> --default-action DENY",
           "Watch rejections closely after the change; a missing ALLOW fails closed, "
           "which is the right direction and still disruptive if found in production.")),

    _C(id="CGP-01", section="CODEGURUPROFILER", severity="MEDIUM", compliance=_ACC,
       permissions=(
           _P("codeguru-profiler:ListProfilingGroups",
              "enumerate profiling groups -- note the IAM prefix is codeguru-profiler, "
              "with a hyphen, not the codeguruprofiler client name"),
           _P("codeguru-profiler:GetPolicy",
              "read the resource policy on each profiling group, since a profile is a "
              "set of production stack traces"),
       ),
       remediation=(
           "Remove the wildcard principal from the profiling group policy: aws "
           "codeguru-profiler get-policy --profiling-group-name <NAME> to read it, then "
           "aws codeguru-profiler put-permission --profiling-group-name <NAME> "
           "--action-group agentPermissions --principals <ROLE_ARN> naming specific "
           "principals"),
       risk=(
           "This CodeGuru Profiler group has a resource policy granting a wildcard "
           "principal. A profiling group holds profiles: sets of stack traces sampled "
           "from the application while it runs in production. Reading one is unusually "
           "informative because a stack trace is not a summary, it is the actual call "
           "path -- internal class and method names, the frameworks and library versions "
           "in use, the structure of the request handling, and which code paths carry "
           "load. Taken together that is an accurate map of the application's internals, "
           "assembled from the running system rather than from documentation, and it is "
           "exactly the reconnaissance that makes finding an exploitable path cheap. It "
           "is also information no amount of endpoint hardening conceals, because it "
           "does not come from the endpoints at all. Profiles occasionally carry more "
           "directly sensitive material too, where method or parameter names embed "
           "identifiers."),
       impact=("Production stack traces are readable outside the account, revealing "
               "internal class and method names, framework versions and which code paths "
               "carry load."),
       steps=(
           "Read the policy: aws codeguru-profiler get-policy --profiling-group-name "
           "<NAME>",
           "Re-grant to specific principals: aws codeguru-profiler put-permission "
           "--profiling-group-name <NAME> --action-group agentPermissions --principals "
           "<ROLE_ARN>",
           "Or remove the grant entirely if nothing external needs it: aws "
           "codeguru-profiler remove-permission --profiling-group-name <NAME> "
           "--action-group agentPermissions --revision-id <REV>",
           "Check the other profiling groups in the account -- policies here are usually "
           "copied between groups.")),
)
