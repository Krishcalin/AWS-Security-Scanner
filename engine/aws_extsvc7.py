#!/usr/bin/env python3
"""aws_extsvc7.py — extended AWS service coverage, batch 7.

Seventh batch, and the first chosen **against** the ranking rather than from the top of
it. By batch 7 the highest remaining score was 14, and the heuristic — which reads
operation NAMES — had stopped discriminating: it scores CloudFormation and Firewall
Manager at 5, below AWS Wickr at 14, because their security significance is not visible
in a method name. ``GetStackPolicy`` and ``GetPolicy`` are unremarkable strings attached
to the two most consequential services in this batch.

That is a limit of the tool rather than a fault in it, and the response is to say so and
choose deliberately, not to invent a cleverer regex.

A NOTE ON THE PREFIX
--------------------
CloudFormation's checks are ``STACK-*``, not ``CFN-*``. ``CFN-01`` through ``CFN-06``
already exist in this codebase and are **CloudFront** — their remediations call
``aws cloudfront update-distribution``. Anyone reaching for ``CFN`` for CloudFormation
would have silently overwritten six live checks, which is precisely the ``SEG-01``
defect this codebase has been bitten by once already.

WHAT EACH SERVICE CONTRIBUTES
------------------------------
* **CloudFormation** — a stack is the definition of the infrastructure it owns. Without
  a stack policy, any principal who can call ``UpdateStack`` can replace or delete any
  resource in it; without a service role, stack operations run with the **caller's**
  permissions rather than a scoped one.
* **Firewall Manager** — an org-wide policy that detects non-compliance and does not
  remediate is a report, not a control, and one with no notification channel is a report
  nobody receives.
* **ECR Public** — everything in a public registry is readable by design, so the finding
  is never "it can be read". It is a policy that lets someone outside the account
  **push**.
* **Multi-Party Approval** — an approval team requiring one approver is not multi-party
  approval; it is a single point of approval with extra steps.
* **AWS Wickr** — data retention on an end-to-end encrypted messenger changes the threat
  model, in both directions. Reported as context.
* **MediaPackage v2** — a channel policy governs who may ingest to a live video channel.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import json
from typing import Dict, List, Mapping, Optional, Sequence
from urllib.parse import unquote

from engine import aws_checkdef as _cd
from engine.aws_checkdef import CheckDef as _C, Perm as _P

__all__ = [
    "stack_policy", "stack_service_role", "fms_policy", "fms_notification",
    "ecr_public_policy", "mpa_approval_team", "wickr_retention",
    "mediapackage_policy", "WRITE_ACTIONS", "parse_doc",
]

#: ECR actions that mean WRITE. A public registry is readable by design, so a wildcard
#: grant only matters when it carries one of these.
WRITE_ACTIONS = (
    "ecr-public:*", "ecr-public:putimage", "ecr-public:initiatelayerupload",
    "ecr-public:uploadlayerpart", "ecr-public:completelayerupload",
    "ecr-public:batchdeleteimage", "ecr-public:setrepositorypolicy", "*",
)


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
    return any(_wide_principal(s) for s in _stmts(doc))


# ── AWS CloudFormation ──────────────────────────────────────────────────────
def stack_policy(stack_name: str, body) -> dict:
    """A stack policy is what stops an update replacing a database."""
    has = bool(str(body or "").strip())
    return {
        "stack": stack_name or "",
        "has_policy": has,
        "statement": (
            f"CloudFormation stack {stack_name} has no stack policy, so any principal "
            f"able to call UpdateStack can replace or delete any resource the stack "
            f"owns. A stack is the definition of its infrastructure, and without a "
            f"policy an update is not bounded by what it is allowed to touch"
            if not has else ""),
    }


def stack_service_role(stack: Optional[dict]) -> dict:
    """No ``RoleARN`` means stack operations run with the CALLER's permissions."""
    s = _d(stack)
    role = s.get("RoleARN") or ""
    caps = [str(c) for c in _l(s.get("Capabilities"))]
    return {
        "stack": s.get("StackName") or s.get("StackId") or "",
        "role": role,
        "has_role": bool(role),
        "capabilities": tuple(caps),
        "iam_capable": any("IAM" in c for c in caps),
        "statement": (
            f"CloudFormation stack {s.get('StackName')} has no service role, so its "
            f"operations run with the permissions of whoever calls them rather than a "
            f"scoped role"
            + (" — and the stack is acknowledged for IAM capabilities "
               f"({', '.join(c for c in caps if 'IAM' in c)}), so a template change can "
               f"create identities with whatever the caller could have created"
               if any("IAM" in c for c in caps) else "")
            if not role else ""),
    }


# ── AWS Firewall Manager ────────────────────────────────────────────────────
def fms_policy(policy: Optional[dict]) -> dict:
    """A policy that detects and does not remediate is a report, not a control."""
    p = _d(policy)
    remediate = p.get("RemediationEnabled")
    return {
        "id": p.get("PolicyId") or "",
        "name": p.get("PolicyName") or p.get("PolicyId") or "",
        "type": p.get("SecurityServiceType") or "",
        "known": isinstance(remediate, bool),
        "remediates": remediate is True,
        "statement": (
            f"Firewall Manager policy {p.get('PolicyName') or p.get('PolicyId')} has "
            f"remediation disabled — it evaluates accounts across the organization and "
            f"reports what does not comply, and then changes nothing. The protection it "
            f"describes is not in force anywhere it was not already"
            if remediate is False else ""),
    }


def fms_notification(channel: Optional[dict], readable=True) -> dict:
    """A report nobody receives."""
    c = _d(channel)
    topic = c.get("SnsTopicArn") or ""
    return {
        "topic": topic,
        "known": readable,
        "configured": bool(topic),
        "statement": (
            "Firewall Manager has no notification channel configured, so nothing is sent "
            "when a policy finds a non-compliant account or when Firewall Manager itself "
            "cannot act. Its whole value is noticing across accounts you are not looking "
            "at, which requires somebody being told"
            if readable and not topic else ""),
    }


# ── Amazon ECR Public ───────────────────────────────────────────────────────
def ecr_public_policy(repository: str, policy) -> dict:
    """A public registry is readable by design; WRITE is the finding."""
    writers = []
    for s in _stmts(policy):
        if not _wide_principal(s):
            continue
        actions = [str(a).lower() for a in _l(s.get("Action"))] or \
                  ([str(s.get("Action")).lower()] if s.get("Action") else [])
        if any(a in WRITE_ACTIONS or a.endswith(":*") for a in actions):
            writers.append(s)
    return {
        "repository": repository or "",
        "has_policy": bool(_stmts(policy)),
        "public_write": bool(writers),
        "statement": (
            f"ECR Public repository {repository} has a policy granting WRITE to a "
            f"wildcard principal. Everything in a public registry is readable by design, "
            f"so readability is never the finding — this is: anyone can push an image "
            f"under your organization's name, and consumers pulling it have no way to "
            f"tell it apart from one you built"
            if writers else ""),
    }


# ── AWS Multi-Party Approval ────────────────────────────────────────────────
def mpa_approval_team(team: Optional[dict]) -> dict:
    """One approver is not multi-party approval."""
    t = _d(team)
    strategy = _d(t.get("ApprovalStrategy"))
    minimum = _d(strategy.get("MofN")).get("MinApprovalsRequired")
    approvers = t.get("NumberOfApprovers")
    return {
        "name": t.get("Name") or t.get("Arn") or "",
        "minimum": minimum,
        "known": isinstance(minimum, int),
        "single_approver": minimum == 1,
        "approvers": approvers,
        "statement": (
            f"Multi-Party Approval team {t.get('Name')} requires only ONE approval. The "
            f"service exists so that a consequential action needs more than one person, "
            f"and a team of one approver is a single point of approval with extra steps "
            f"— it still produces the audit trail and the sense that a control is in "
            f"place, while any single compromised or mistaken approver is sufficient"
            if minimum == 1 else ""),
    }


# ── AWS Wickr ───────────────────────────────────────────────────────────────
def _wickr_settings(settings) -> dict:
    """Normalise `GetNetworkSettings` output to a mapping.

    THE SHAPE AWS ACTUALLY RETURNS is ``{"settings": [{optionName, value, type}, ...]}``
    — a LIST of name/value pairs where every value is a STRING — not the nested object
    this module was written against. The scanner compounded it by reading
    ``networkSettings``, a key the operation does not have, so on real AWS this function
    always received ``{}`` and WKR-01 could never fire.

    Neither half could be caught by a fixture: the fixture was written from the same
    misunderstanding as the code. `tests/test_aws_api_contract.py` found it by checking
    the key against botocore's own service model, which is the only description of the
    API that nobody here wrote.

    The dict form is still accepted, because the option NAMES below are free-form
    strings the model does not enumerate — they cannot be verified offline, so they are
    left exactly as they were rather than guessed at again."""
    if isinstance(settings, Mapping):
        return dict(settings)
    out: Dict[str, object] = {}
    for item in (settings or []):
        if not isinstance(item, Mapping):
            continue
        name = item.get("optionName")
        if not name:
            continue
        raw = item.get("value")
        # Values arrive as strings; "true"/"false" are the only ones this reads.
        if isinstance(raw, str) and raw.strip().lower() in ("true", "false"):
            out[str(name)] = raw.strip().lower() == "true"
        else:
            out[str(name)] = raw
    return out


def wickr_retention(network_id: str, settings) -> dict:
    """Retention on an end-to-end encrypted messenger: context, not a defect."""
    s = _wickr_settings(settings)
    retention = _d(s.get("dataRetention"))
    enabled = retention.get("enabled") if "enabled" in retention else s.get("dataRetention")
    on = enabled is True
    return {
        "network": network_id or "",
        "retention_on": on,
        "known": isinstance(enabled, bool),
        "trusted_data_format": s.get("enableTrustedDataFormat") is True,
        "statement": (
            f"Wickr network {network_id} has data retention ENABLED, so message content "
            f"is captured to a retention bot. This is reported as CONTEXT rather than a "
            f"defect because it cuts both ways: retention is frequently a regulatory "
            f"requirement, and it is also the one configuration that takes an "
            f"end-to-end encrypted messenger and puts plaintext somewhere else. Whether "
            f"it should be on is a policy question; whether everyone using the network "
            f"knows it is on is the part worth checking"
            if on else ""),
    }


# ── AWS Elemental MediaPackage v2 ───────────────────────────────────────────
def mediapackage_policy(resource: str, policy) -> dict:
    """A channel policy governs who may ingest to a live video channel."""
    return {
        "resource": resource or "",
        "has_policy": bool(_stmts(policy)),
        "public": _wildcard_policy(policy),
        "statement": (
            f"MediaPackage channel {resource} has a policy granting a wildcard "
            f"principal. A channel policy governs who may INGEST, so a wildcard means "
            f"anyone can push content into a live stream that goes out under your name"
            if _wildcard_policy(policy) else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Declarations
# ══════════════════════════════════════════════════════════════════════════════
_ACC = {"PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"}
_PRIV = {"PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-6"}
_CFG = {"PCI-DSS": "6.5.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC8.1", "NIST": "CM-6"}
_CHG = {"PCI-DSS": "6.5.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC8.1", "NIST": "CM-5"}
_LOG = {"PCI-DSS": "10.2.1", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"}
_INT = {"PCI-DSS": "6.3.2", "HIPAA": "164.312(c)(1)", "SOC2": "CC6.8", "NIST": "SI-7"}

CHECKS = _cd.register(
    _C(id="STACK-01", section="CLOUDFORMATION", severity="MEDIUM", compliance=_CHG,
       permissions=(
           _P("cloudformation:ListStacks",
              "enumerate the CloudFormation stacks that define infrastructure in this "
              "account and region"),
           _P("cloudformation:GetStackPolicy",
              "read the stack policy -- without one, any caller who can UpdateStack can "
              "replace or delete any resource the stack owns"),
       ),
       remediation=(
           "Attach a stack policy that denies Update:Replace and Update:Delete on the "
           "resources that must not be destroyed by an update: aws cloudformation "
           "set-stack-policy --stack-name <STACK> --stack-policy-body "
           "file://stack-policy.json. Verify with aws cloudformation get-stack-policy "
           "--stack-name <STACK>"),
       risk=(
           "This CloudFormation stack has no stack policy. A stack is the definition of "
           "the infrastructure it owns, and an update to it is not a text change -- it "
           "is an instruction to make reality match the new template, which can mean "
           "replacing or deleting live resources. A stack policy is the control that "
           "says which resources an update may not touch, and without one every "
           "principal who can call UpdateStack can replace the database, delete the "
           "bucket, or swap the security group, simply by submitting a different "
           "template. The failure is usually accidental: a parameter change that turns "
           "out to force replacement of a resource nobody intended to recreate, "
           "discovered when the data is already gone. The deliberate version is worse "
           "and quieter, because a template change reads as ordinary infrastructure work "
           "in a way that a DeleteBucket call does not."),
       impact=("Any principal able to update the stack can replace or delete any "
               "resource it owns by submitting a different template."),
       steps=(
           "Write a policy denying Update:Replace and Update:Delete on the stateful "
           "resources -- databases, buckets, anything holding data.",
           "Apply it: aws cloudformation set-stack-policy --stack-name <STACK> "
           "--stack-policy-body file://stack-policy.json",
           "Confirm: aws cloudformation get-stack-policy --stack-name <STACK>",
           "Remember a stack policy governs UPDATES only -- DeleteStack is a separate "
           "action, so pair it with termination protection: aws cloudformation "
           "update-termination-protection --stack-name <STACK> "
           "--enable-termination-protection")),

    _C(id="STACK-02", section="CLOUDFORMATION", severity="MEDIUM", compliance=_PRIV,
       permissions=(
           _P("cloudformation:DescribeStacks",
              "read RoleARN and Capabilities -- without a service role, stack "
              "operations run with the permissions of whoever calls them"),
       ),
       remediation=(
           "Give the stack a scoped service role so its operations stop running with the "
           "caller's permissions: aws cloudformation update-stack --stack-name <STACK> "
           "--role-arn <ROLE_ARN> --use-previous-template --capabilities "
           "CAPABILITY_NAMED_IAM. The role needs exactly what the template creates and "
           "nothing more"),
       risk=(
           "This CloudFormation stack has no service role, which means its operations "
           "execute with the permissions of whichever principal invokes them rather than "
           "with a role scoped to what the stack actually needs. Two consequences follow "
           "and the second is the one that matters. First, the blast radius of a stack "
           "operation is set by the caller, so an administrator running an update gives "
           "that update administrator rights over everything, not just the stack's "
           "resources. Second, and more consequential where the stack is acknowledged "
           "for IAM capabilities, a template is a way to create identities: a modified "
           "template can mint a role with whatever permissions the caller could have "
           "granted directly, and it does so through a change that looks like ordinary "
           "infrastructure work in review. A scoped service role turns both of those "
           "from 'whatever the caller has' into 'what this stack is allowed to do'."),
       impact=("Stack operations run with the caller's permissions, so their blast radius "
               "is whatever that principal holds rather than what the stack needs."),
       steps=(
           "Work out what the template actually creates before writing the role -- an "
           "under-scoped role fails the next deployment.",
           "Attach it: aws cloudformation update-stack --stack-name <STACK> --role-arn "
           "<ROLE_ARN> --use-previous-template --capabilities CAPABILITY_NAMED_IAM",
           "Pay particular attention to stacks acknowledged for CAPABILITY_NAMED_IAM: "
           "those are the ones that can create identities.",
           "Consider denying cloudformation:UpdateStack without a role-arn condition in "
           "an SCP, so the scoped role cannot be bypassed by omitting it.")),

    _C(id="FMS-01", section="FIREWALLMANAGER", severity="MEDIUM", compliance=_CFG,
       permissions=(
           _P("fms:ListPolicies",
              "enumerate the Firewall Manager policies applied across the organization"),
           _P("fms:GetPolicy",
              "read RemediationEnabled -- a policy that detects and does not remediate "
              "reports non-compliance without changing it"),
       ),
       remediation=(
           "Turn remediation on so the policy enforces rather than merely reports: aws "
           "fms put-policy --policy file://policy.json with RemediationEnabled set to "
           "true. Read the current definition first with aws fms get-policy --policy-id "
           "<ID>, and expect it to start changing resources in member accounts"),
       risk=(
           "This Firewall Manager policy has remediation disabled. Firewall Manager "
           "exists to apply a security configuration -- a WAF web ACL, a security group "
           "baseline, a Shield protection -- consistently across every account in an "
           "organization, including the ones nobody is currently looking at. With "
           "remediation off it still evaluates those accounts and still reports which "
           "ones do not comply, and then does nothing about it. The distinction matters "
           "because the policy's existence is what people rely on: a security review "
           "that finds Firewall Manager configured with a WAF policy across the "
           "organization will reasonably conclude the WAF is applied organization-wide, "
           "when what is actually true is that non-compliance is being counted somewhere "
           "nobody reads. A control that reports is useful; a control that reports while "
           "being mistaken for one that enforces is worse than neither."),
       impact=("Non-compliant accounts are detected and left non-compliant, while the "
               "policy's existence suggests the protection is applied organization-wide."),
       steps=(
           "Read the current policy: aws fms get-policy --policy-id <ID>",
           "Understand what enabling remediation will change in member accounts before "
           "doing it -- it will start modifying resources.",
           "Enable it: aws fms put-policy --policy file://policy.json with "
           "RemediationEnabled true.",
           "Check compliance afterwards rather than assuming: aws fms "
           "get-compliance-detail --policy-id <ID> --member-account <ACCOUNT_ID>")),

    _C(id="FMS-02", section="FIREWALLMANAGER", severity="MEDIUM", compliance=_LOG,
       permissions=(
           _P("fms:GetNotificationChannel",
              "read whether an SNS topic is configured -- without one nothing is sent "
              "when a policy finds a non-compliant account"),
       ),
       remediation=(
           "Configure a notification channel so Firewall Manager findings reach someone: "
           "aws fms put-notification-channel --sns-topic-arn <TOPIC_ARN> --sns-role-name "
           "<ROLE_NAME>. Subscribe a real destination to the topic rather than leaving it "
           "unsubscribed"),
       risk=(
           "Firewall Manager has no notification channel configured, so nothing is sent "
           "when a policy finds a non-compliant account or when Firewall Manager itself "
           "fails to apply a protection. The entire value of the service is noticing "
           "things in accounts nobody is watching -- a new account created by a team "
           "that skipped the baseline, a security group opened in a subsidiary's "
           "environment, a WAF association removed. Noticing only helps if somebody is "
           "told, and here the finding lands in a console that, by construction, is not "
           "where anyone is looking. This compounds with remediation being disabled: a "
           "policy that neither fixes nor reports outward is a control that exists "
           "entirely on paper while appearing in every architecture review as evidence "
           "of organization-wide enforcement."),
       impact=("Non-compliance findings and Firewall Manager's own failures are recorded "
               "only in a console nobody is watching."),
       steps=(
           "Create or choose an SNS topic with a real subscriber -- an unsubscribed "
           "topic is the same gap one step further along.",
           "Configure it: aws fms put-notification-channel --sns-topic-arn <TOPIC_ARN> "
           "--sns-role-name <ROLE_NAME>",
           "Confirm: aws fms get-notification-channel",
           "Check whether remediation is also disabled on the policies -- the two "
           "together mean the control does nothing at all.")),

    _C(id="ECRPUB-01", section="ECRPUBLIC", severity="HIGH", compliance=_INT,
       permissions=(
           _P("ecr-public:DescribeRepositories",
              "enumerate the public container repositories this account publishes"),
           _P("ecr-public:GetRepositoryPolicy",
              "read the repository policy -- a public registry is readable by design, so "
              "the finding is a wildcard grant that carries WRITE"),
       ),
       remediation=(
           "Remove the wildcard write grant from the public repository policy: aws "
           "ecr-public get-repository-policy --repository-name <REPO> to read it, then "
           "aws ecr-public set-repository-policy --repository-name <REPO> --policy-text "
           "file://scoped-policy.json naming only the principals that should push. Then "
           "audit every image tag currently published"),
       risk=(
           "This ECR Public repository has a policy granting write actions to a wildcard "
           "principal. It is worth being precise about what is and is not the problem: "
           "everything in a public registry is readable by anyone, deliberately, so "
           "readability is never the finding. Write is. Anyone matching that wildcard can "
           "push an image into a repository published under your organization's name, "
           "and consumers pulling it have no way to distinguish it from an image you "
           "built -- the registry namespace IS the provenance signal for a public image, "
           "which is exactly why supply-chain attacks target it. The attacker does not "
           "need to compromise your build pipeline if they can publish through it. "
           "Overwriting an existing tag is the sharpest version, because everything "
           "already pulling that tag gets the new content without any action or "
           "awareness on the consumer's part."),
       impact=("Anyone can publish images under your organization's public namespace, and "
               "consumers cannot distinguish them from images you built."),
       steps=(
           "Read the policy: aws ecr-public get-repository-policy --repository-name "
           "<REPO>",
           "Replace it with one naming only the principals that should push: aws "
           "ecr-public set-repository-policy --repository-name <REPO> --policy-text "
           "file://scoped-policy.json",
           "Audit what is currently published, particularly tags that were overwritten: "
           "aws ecr-public describe-images --repository-name <REPO>",
           "Sign images so consumers can verify provenance independently of the registry "
           "namespace, which is the durable fix rather than the immediate one.")),

    _C(id="MPA-01", section="MULTIPARTYAPPROVAL", severity="HIGH", compliance=_ACC,
       permissions=(
           _P("mpa:ListApprovalTeams",
              "enumerate the Multi-Party Approval teams configured in this account"),
           _P("mpa:GetApprovalTeam",
              "read MinApprovalsRequired -- a team requiring one approval is a single "
              "point of approval rather than multi-party approval"),
       ),
       remediation=(
           "Raise the approval threshold above one, which is what makes it multi-party: "
           "aws mpa update-approval-team --arn <TEAM_ARN> --approval-strategy "
           "MofN={MinApprovalsRequired=2} --approvers file://approvers.json. Confirm the "
           "team has enough distinct approvers that two is actually achievable"),
       risk=(
           "This Multi-Party Approval team requires only one approval. The service exists "
           "for a single purpose: to make a consequential action require more than one "
           "person, so that no individual -- compromised, mistaken, or acting alone -- "
           "can carry it out. A team with a threshold of one does not do that. What makes "
           "it worth a check rather than a shrug is that it is worse than having no "
           "approval workflow at all, because it produces every artefact of one: the "
           "action is submitted, an approval is recorded, an audit trail exists, and a "
           "reviewer looking at the configuration sees a multi-party approval control in "
           "place. The protection people believe they have is separation of duties; what "
           "they actually have is a logging mechanism with a confirmation dialog. A "
           "single compromised approver credential is sufficient, and the resulting "
           "record looks entirely legitimate."),
       impact=("A single approver -- or a single compromised approver credential -- can "
               "authorise the action the team exists to require multiple people for."),
       steps=(
           "Confirm the team has enough distinct approvers for a higher threshold to be "
           "workable before raising it, or approvals will stall.",
           "Raise it: aws mpa update-approval-team --arn <TEAM_ARN> --approval-strategy "
           "MofN={MinApprovalsRequired=2} --approvers file://approvers.json",
           "Check the approvers are genuinely different people rather than several "
           "identities belonging to one -- the threshold counts approvals, not humans.",
           "Review what the team actually gates: a threshold of two on a trivial action "
           "and one on a consequential one is the pattern worth finding.")),

    _C(id="WKR-01", section="WICKR", severity="INFO", compliance=_LOG,
       permissions=(
           _P("wickr:ListNetworks",
              "enumerate the Wickr networks in this account"),
           _P("wickr:GetNetworkSettings",
              "read whether data retention is enabled -- on an end-to-end encrypted "
              "messenger that changes the threat model in both directions"),
       ),
       remediation=(
           "This is context rather than a defect, so the action is to confirm the "
           "setting matches the policy you intend. Read it with aws wickr "
           "get-network-settings --network-id <ID>; change it only deliberately with aws "
           "wickr update-network-settings --network-id <ID>. If retention is on, confirm "
           "users are informed and the retention bot's storage is protected accordingly"),
       risk=(
           "This Wickr network has data retention enabled, which means message content is "
           "captured to a retention bot rather than existing only between endpoints. This "
           "is reported as CONTEXT rather than as a defect, deliberately, because it cuts "
           "both ways and which way depends entirely on the organization. Retention is "
           "frequently a hard regulatory requirement -- financial communications "
           "supervision, legal hold, records management -- and a regulated firm running "
           "Wickr without it has a compliance problem rather than a security one. At the "
           "same time it is the single configuration that takes an end-to-end encrypted "
           "messenger and puts plaintext somewhere durable, which changes what a "
           "compromise of that somewhere is worth and moves the confidentiality boundary "
           "from the endpoints to a bot and its storage. The question worth asking is not "
           "whether retention should be on, but whether the people using the network know "
           "that it is, and whether the retention store is protected like the sensitive "
           "archive it now is."),
       impact=("Message content is captured to a retention bot, moving the "
               "confidentiality boundary from the endpoints to that bot's storage."),
       steps=(
           "Confirm the setting matches intended policy: aws wickr get-network-settings "
           "--network-id <ID>",
           "If retention is required, treat the retention store as a sensitive archive: "
           "encrypt it with a customer-managed key and restrict who can read it.",
           "Confirm users are informed that retention is active -- in several "
           "jurisdictions that is a legal requirement rather than a courtesy.",
           "If retention is not required, disable it deliberately rather than leaving it "
           "on by inheritance: aws wickr update-network-settings --network-id <ID>")),

    _C(id="MPV-01", section="MEDIAPACKAGE", severity="MEDIUM", compliance=_INT,
       permissions=(
           _P("mediapackagev2:ListChannelGroups",
              "enumerate MediaPackage channel groups in this account"),
           _P("mediapackagev2:GetChannelPolicy",
              "read the channel policy -- it governs who may INGEST to a live video "
              "channel, not merely who may watch it"),
       ),
       remediation=(
           "Remove the wildcard principal from the channel policy so only your encoders "
           "may ingest: aws mediapackagev2 get-channel-policy --channel-group-name "
           "<GROUP> --channel-name <CHANNEL> to read it, then aws mediapackagev2 "
           "put-channel-policy --channel-group-name <GROUP> --channel-name <CHANNEL> "
           "--policy file://scoped-policy.json"),
       risk=(
           "This MediaPackage channel has a policy granting a wildcard principal. A "
           "channel policy governs INGEST rather than playback, which is the part worth "
           "being clear about: the finding is not that people can watch the stream, it is "
           "that people can feed it. Anyone matching the wildcard can push content into a "
           "live channel that is distributed under your organization's name, to whatever "
           "audience the stream reaches, in real time. For live video the timing is the "
           "problem — content that goes out during a broadcast has already reached the "
           "audience by the time anyone notices, and the usual remedies for a defaced "
           "asset do not apply because there is nothing to take down after the fact. It "
           "also inherits your distribution's trust: viewers have no way to distinguish "
           "injected content from the intended feed."),
       impact=("Anyone can push content into a live stream distributed under your name, "
               "reaching the audience in real time with no opportunity to intercept it."),
       steps=(
           "Read the policy: aws mediapackagev2 get-channel-policy --channel-group-name "
           "<GROUP> --channel-name <CHANNEL>",
           "Replace it with one naming only your encoders or ingest roles: aws "
           "mediapackagev2 put-channel-policy --channel-group-name <GROUP> "
           "--channel-name <CHANNEL> --policy file://scoped-policy.json",
           "Check the origin endpoint policies separately -- those govern playback and "
           "are a different question: aws mediapackagev2 get-origin-endpoint-policy",
           "Confirm ingest credentials are scoped per channel rather than shared across "
           "the estate.")),
)
