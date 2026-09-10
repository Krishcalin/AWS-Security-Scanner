#!/usr/bin/env python3
"""aws_nhi.py — non-human identity: telling machines from people, and saying how sure.

NHI stopped being a niche in a single quarter of 2026, when the three category leaders
were absorbed by platform vendors within three months of each other. It is now an RFP
line item, and almost all of it is answerable from configuration — which is why it fits
here at all.

OverWatch already had the hard parts scattered across the estate: an effective-permissions
solver, unused-access analysis, IAM privilege-escalation primitives, external-access
checks, IRSA and Pod Identity bindings. What it did not have is the thing every one of
those becomes an NHI finding only *because of*: *is this principal a machine or a person?*
Nothing in the codebase answered that, and a pillar that reports on "non-human identities"
without being able to name one is a category label, not a capability.

CLASSIFICATION IS INFERENCE, AND THIS MODULE NEVER FORGETS IT
--------------------------------------------------------------
AWS does not record whether a principal is a machine. There is no flag. So this reasons
from structure, and the reasoning is graded, because the signals are not equally good:

  CONFIGURED  A trust policy naming a service principal (``ec2.amazonaws.com``) is a
              machine identity by construction -- a person cannot assume it. An IAM user
              with a login profile can be operated by a person, by construction. These
              are read off an API, not guessed.
  INFERRED    A web-identity/OIDC trust says CI, a SAML trust says human federation, an
              instance profile says workload. Strong, structural, still an interpretation.
  WEAK        A name that looks like ``svc-*`` or ``*-lambda-role``. Real signal, and by
              itself never enough to act on. Emitted with its confidence attached so a
              reader can see the verdict rests on a naming convention.

A principal whose evidence is only WEAK is returned as ``ambiguous``, not as a machine.
Guessing wrong in the machine direction is how a tool ends up telling somebody to delete
a person's access; guessing wrong the other way hides the identity the whole pillar exists
to surface. Neither error is acceptable, so the unknown case stays unknown and says why.

WHAT THIS MODULE DOES NOT DO
-----------------------------
It does not decide whether an identity is *over-permissioned* -- ``aws_effperm`` and
``aws_leastpriv`` already do that far better than a name-based heuristic could. It
classifies, and it derives only the risks that are specifically NHI risks: a machine with
a console login, a machine with a credential nobody rotates, a machine nobody owns, a
third-party trust with no external id, a federated trust with no subject condition.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import re
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from engine import aws_epistemics

__all__ = [
    "MACHINE", "HUMAN", "AMBIGUOUS", "WEAK",
    "Signal", "classify_principal", "nhi_findings", "summarize",
    "SERVICE_PRINCIPAL_SUFFIX", "NHI_CHECKS",
]

MACHINE = "machine"
HUMAN = "human"
AMBIGUOUS = "ambiguous"

#: A third confidence band below aws_epistemics' three, for evidence that is real but
#: insufficient on its own. Kept distinct rather than folded into INFERRED so a caller
#: can refuse to act on naming alone -- which is exactly what `classify_principal` does.
WEAK = "weak"

SERVICE_PRINCIPAL_SUFFIX = ".amazonaws.com"

#: Federated issuers that mean "a workload authenticated", not "a person signed in".
_MACHINE_ISSUERS = (
    "token.actions.githubusercontent.com",      # GitHub Actions
    "gitlab.com",                               # GitLab CI
    "oidc.eks.",                                # EKS IRSA
    "container.googleapis.com",
    "vstoken.dev.azure.com",                    # Azure DevOps
    "buildkite.com", "app.circleci.com", "token.terraform.io",
)

#: Naming conventions that suggest a machine. WEAK by construction: a role called
#: `svc-payments` is probably a service, and `alice-svc-test` is probably not.
_MACHINE_NAME = re.compile(
    r"(^|[-_])(svc|service|bot|automation|ci|cd|pipeline|deploy|lambda|task|worker|"
    r"agent|daemon|runner|terraform|jenkins|github|gitlab|robot|machine|app)([-_]|$)",
    re.I)

#: Naming conventions that suggest a person. Also WEAK, and deliberately narrow:
#: over-matching here means classifying a service as a person and hiding it.
_HUMAN_NAME = re.compile(r"(^|[-_])(admin|user|dev|developer|engineer|analyst|breakglass|"
                         r"break[-_]?glass|oncall|human)([-_]|$)", re.I)

Signal = Tuple[str, str, str]        # (verdict, confidence, evidence sentence)


def _is_normalized(trust) -> bool:
    """True for `aws_live_scanner.parse_trust_policy` output rather than a raw document.

    The scanner normalizes a trust policy to
    ``[{effect, aws, service, federated, wildcard, actions, has_condition}]`` for its
    graph edges, and that form keeps only a BOOLEAN for conditions. Condition contents
    are exactly what NHI-04 (sts:ExternalId) and NHI-05 (:sub) need, so recognising the
    shape is what lets those checks report themselves unevaluated instead of quietly
    never firing -- which would read as "no such risk here"."""
    return (isinstance(trust, (list, tuple)) and trust
            and isinstance(trust[0], Mapping)
            and ("service" in trust[0] or "federated" in trust[0] or "aws" in trust[0]))


def _trust_statements(trust) -> List[dict]:
    """Statements from EITHER shape, rendered as the raw-document form used below.

    Accepting only the raw document would make this module inapplicable to the estate
    data the product actually collects; accepting only the normalized form would lose the
    conditions. So both are read, and `_conditions_readable` records which one arrived."""
    if _is_normalized(trust):
        out = []
        for st in trust:
            principal: Dict[str, List[str]] = {}
            if st.get("service"):
                principal["Service"] = list(st["service"])
            if st.get("federated"):
                principal["Federated"] = list(st["federated"])
            if st.get("aws"):
                principal["AWS"] = list(st["aws"])
            out.append({"Effect": st.get("effect", "Allow"), "Principal": principal,
                        # Deliberately NOT a Condition dict: has_condition says one
                        # exists, never which. Fabricating a plausible-looking Condition
                        # here would let the :sub and ExternalId checks read it and
                        # conclude something the data cannot support.
                        "_has_condition": bool(st.get("has_condition"))})
        return out
    if not isinstance(trust, Mapping):
        return []
    stmts = trust.get("Statement")
    if isinstance(stmts, Mapping):
        return [dict(stmts)]
    return [dict(s) for s in (stmts or []) if isinstance(s, Mapping)]


def _conditions_readable(trust) -> bool:
    """Whether condition CONTENTS are available. False for the normalized form."""
    return not _is_normalized(trust)


def _principal_values(stmt: Mapping) -> Dict[str, List[str]]:
    """{principal-type: [values]} from one statement, tolerating string-or-list."""
    p = stmt.get("Principal")
    out: Dict[str, List[str]] = {}
    if isinstance(p, str):
        return {"*": [p]} if p == "*" else {}
    if not isinstance(p, Mapping):
        return out
    for k, v in p.items():
        out[str(k)] = [v] if isinstance(v, str) else [str(x) for x in (v or [])]
    return out


def classify_principal(principal: Optional[Mapping]) -> dict:
    """Machine, human, or honestly unknown -- with every signal that fed the verdict.

    `principal` is a dict as the estate records it: at minimum a `kind`
    ('IAMRole' / 'IAMUser') and `name`; optionally `trust_policy`, `has_login_profile`,
    `has_instance_profile`, `access_key_count`, `tags`.

    Returns {verdict, confidence, signals[], reason}. A verdict of `ambiguous` is a real
    answer, not a failure: the alternative is a tool that tells somebody to revoke a
    colleague's access because a role was called `deploy`.
    """
    p = dict(principal or {})
    name = str(p.get("name") or "")
    kind = str(p.get("kind") or "")
    signals: List[Signal] = []

    # ── CONFIGURED: read off an API, not interpreted ────────────────────────
    for stmt in _trust_statements(p.get("trust_policy")):
        princ = _principal_values(stmt)
        for svc in princ.get("Service", []):
            if svc.endswith(SERVICE_PRINCIPAL_SUFFIX):
                signals.append((MACHINE, aws_epistemics.CONFIGURED,
                                f"trust policy names the service principal {svc}, which "
                                f"only an AWS service can assume"))
        for fed in princ.get("Federated", []):
            low = fed.lower()
            if any(iss in low for iss in _MACHINE_ISSUERS):
                signals.append((MACHINE, aws_epistemics.INFERRED,
                                f"federated trust to {fed}, a workload-identity issuer"))
            elif "saml" in low or ":saml-provider/" in low:
                signals.append((HUMAN, aws_epistemics.INFERRED,
                                f"SAML federation via {fed}, the shape used for staff "
                                f"single sign-on"))

    if p.get("has_login_profile") is True:
        # A console password is definitionally a human affordance. It does not prove a
        # person uses it -- but a machine identity holding one is itself the finding.
        signals.append((HUMAN, aws_epistemics.CONFIGURED,
                        "has a console login profile, which only a person can use"))
    if p.get("has_instance_profile") is True:
        signals.append((MACHINE, aws_epistemics.INFERRED,
                        "attached to an instance profile, so a workload assumes it"))

    # ── WEAK: naming. Never sufficient alone; see the gate below. ───────────
    if name:
        if _MACHINE_NAME.search(name):
            signals.append((MACHINE, WEAK,
                            f"the name {name!r} follows a service-account convention"))
        if _HUMAN_NAME.search(name):
            signals.append((HUMAN, WEAK,
                            f"the name {name!r} follows a personal-account convention"))

    strong = [s for s in signals if s[1] != WEAK]
    machine_strong = [s for s in strong if s[0] == MACHINE]
    human_strong = [s for s in strong if s[0] == HUMAN]

    if machine_strong and not human_strong:
        best = aws_epistemics.CONFIGURED if any(
            s[1] == aws_epistemics.CONFIGURED for s in machine_strong) else aws_epistemics.INFERRED
        return _verdict(MACHINE, best, signals,
                        "Structural evidence identifies this as a workload identity.")
    if human_strong and not machine_strong:
        best = aws_epistemics.CONFIGURED if any(
            s[1] == aws_epistemics.CONFIGURED for s in human_strong) else aws_epistemics.INFERRED
        return _verdict(HUMAN, best, signals,
                        "Structural evidence identifies this as a person-operated identity.")
    if machine_strong and human_strong:
        # BOTH is not a tie to be broken -- it is usually the finding. A role a service
        # assumes that also carries a console login is exactly what NHI-01 reports.
        return _verdict(AMBIGUOUS, aws_epistemics.INFERRED, signals,
                        "Carries both machine and human structural evidence, which is "
                        "itself worth investigating.")

    # Nothing structural. An IAM user with no login profile and keys is *probably* a
    # service account, but "probably" is where this module stops and says so.
    if kind == "IAMUser" and p.get("has_login_profile") is False and p.get("access_key_count"):
        return _verdict(MACHINE, aws_epistemics.INFERRED, signals + [
            (MACHINE, aws_epistemics.INFERRED,
             "an IAM user with access keys and no console login is the classic "
             "long-lived service-account shape")],
            "No console login, but holds access keys.")

    return _verdict(AMBIGUOUS, WEAK, signals,
                    "No structural evidence either way. Naming conventions alone are not "
                    "enough to classify an identity, so this is reported as unknown "
                    "rather than guessed.")


def _verdict(verdict: str, confidence: str, signals: Sequence[Signal], reason: str) -> dict:
    return {"verdict": verdict, "confidence": confidence, "reason": reason,
            "signals": [{"points_to": v, "confidence": c, "evidence": e}
                        for v, c, e in signals]}


#: The NHI-specific checks. Deliberately short: over-permission and unused access are
#: already answered better elsewhere, and duplicating them here would double-count.
NHI_CHECKS: Dict[str, str] = {
    "NHI-01": "Machine identity holds a console login",
    "NHI-02": "Machine identity credential is not rotated",
    "NHI-03": "Machine identity has no recorded owner",
    "NHI-04": "Third-party trust without an external id",
    "NHI-05": "Federated trust without a subject condition",
}


def nhi_findings(principal: Optional[Mapping], *,
                 classification: Optional[Mapping] = None,
                 known_accounts: Sequence[str] = (),
                 max_key_age_days: int = 90) -> List[dict]:
    """The risks that are NHI risks specifically, for one principal.

    Every finding names the classification confidence that led to it, because a finding
    derived from a WEAK verdict deserves to be read differently from one derived from a
    service-principal trust policy.
    """
    p = dict(principal or {})
    cls = dict(classification or classify_principal(p))
    verdict, conf = cls.get("verdict"), cls.get("confidence")
    out: List[dict] = []

    def add(check: str, severity: str, detail: str, **extra):
        out.append({"check_id": check, "title": NHI_CHECKS[check], "severity": severity,
                    "detail": detail, "classification": verdict,
                    "classification_confidence": conf, **extra})

    is_machine = verdict == MACHINE

    if is_machine and p.get("has_login_profile") is True:
        add("NHI-01", "HIGH",
            "This identity is assumed by a workload but also carries a console password. "
            "A machine does not need one, and its existence widens the identity's attack "
            "surface to password reuse and phishing.")

    age = p.get("oldest_key_age_days")
    if is_machine and isinstance(age, (int, float)) and age > max_key_age_days:
        add("NHI-02", "MEDIUM",
            f"The oldest access key on this machine identity is {int(age)} days old, past "
            f"the {max_key_age_days}-day threshold. Machine credentials are rarely rotated "
            f"because nothing prompts a person to do it.",
            key_age_days=int(age))

    tags = p.get("tags") or {}
    if is_machine and not any(k.lower() in ("owner", "team", "contact", "maintainer")
                              for k in (tags if isinstance(tags, Mapping) else {})):
        add("NHI-03", "LOW",
            "No owner, team, contact or maintainer tag. An unowned machine identity is "
            "the one nobody revokes when the system it served is decommissioned.")

    # Third-party trust: an AWS account outside the estate. `known_accounts` is what the
    # caller believes it owns -- an empty list means we cannot judge, so we say nothing
    # rather than reporting every legitimate internal trust as third-party.
    known = {str(a) for a in known_accounts}
    readable = _conditions_readable(p.get("trust_policy"))
    if known and not readable:
        out.append({
            "check_id": "NHI-04", "title": NHI_CHECKS["NHI-04"], "severity": "INFO",
            "status": "NOT_EVALUATED", "classification": verdict,
            "classification_confidence": conf,
            "detail": "Third-party trust could not be assessed: the trust policy arrived "
                      "in the graph's normalized form, which records that a condition "
                      "exists but not what it says. An sts:ExternalId guard is a "
                      "condition, so its presence is unknowable from this input. Re-run "
                      "against the raw AssumeRolePolicyDocument to evaluate it."})
    if known and readable:
        for stmt in _trust_statements(p.get("trust_policy")):
            princ = _principal_values(stmt)
            cond = stmt.get("Condition") or {}
            has_ext_id = "sts:ExternalId" in str(cond)
            for arn in princ.get("AWS", []):
                m = re.search(r"arn:aws[a-z-]*:iam::(\d{12}):", str(arn))
                acct = m.group(1) if m else (str(arn) if str(arn).isdigit() else None)
                if acct and acct not in known and not has_ext_id:
                    add("NHI-04", "HIGH",
                        f"Account {acct} can assume this role and no sts:ExternalId "
                        f"condition guards it. Without one, a vendor with your role ARN "
                        f"is exposed to the confused-deputy problem.",
                        external_account=acct)

    for stmt in _trust_statements(p.get("trust_policy")):
        princ = _principal_values(stmt)
        cond_text = str(stmt.get("Condition") or {})
        if not readable and princ.get("Federated"):
            out.append({
                "check_id": "NHI-05", "title": NHI_CHECKS["NHI-05"], "severity": "INFO",
                "status": "NOT_EVALUATED", "classification": verdict,
                "classification_confidence": conf,
                "detail": "Federated-trust scoping could not be assessed: the subject "
                          "(:sub) condition that pins WHICH workload may assume this role "
                          "is a condition, and this input records only that some condition "
                          "exists. Re-run against the raw AssumeRolePolicyDocument."})
            continue
        for fed in princ.get("Federated", []):
            low = str(fed).lower()
            if not any(iss in low for iss in _MACHINE_ISSUERS):
                continue
            # ':sub' is the claim that pins WHICH workload. ':aud' alone pins only the
            # audience, which every workflow on the issuer shares.
            if ":sub" not in cond_text:
                add("NHI-05", "HIGH",
                    f"Trust to {fed} has no subject (:sub) condition, so any workload on "
                    f"that issuer can assume this role -- not only yours. An :aud "
                    f"condition alone does not narrow it.",
                    issuer=str(fed))
    return out


def summarize(principals: Optional[Sequence[Mapping]]) -> dict:
    """Estate-level counts. `unknown` is reported as prominently as the rest: it is the
    measure of how much of the identity surface this pillar could not classify, and a
    summary that hid it would overstate its own coverage."""
    counts = {MACHINE: 0, HUMAN: 0, AMBIGUOUS: 0}
    by_conf: Dict[str, int] = {}
    for p in principals or []:
        c = classify_principal(p)
        counts[c["verdict"]] = counts.get(c["verdict"], 0) + 1
        by_conf[c["confidence"]] = by_conf.get(c["confidence"], 0) + 1
    total = sum(counts.values())
    return {
        "total": total,
        "machine": counts[MACHINE], "human": counts[HUMAN],
        "unclassified": counts[AMBIGUOUS],
        "by_confidence": by_conf,
        "coverage_note": (
            f"{counts[AMBIGUOUS]} of {total} principals could not be classified from "
            f"configuration. That is a limit of what AWS records, not a clean result: "
            f"an unclassified identity may well be a machine."
        ) if counts[AMBIGUOUS] else "",
    }


# ══════════════════════════════════════════════════════════════════════════════
# Check declarations. Registered here rather than in an aws_extsvc module because
# they belong to this module's subject, and because the registry derives all five
# projections (severity, compliance, remediation, detail, permission ledger) from
# ONE declaration -- which is what keeps the now-empty lockstep backlog empty.
#
# NO NEW GRANT. Every one of these reads data the IAM section already collects:
# `_iam_principals` carries the parsed trust policy, instance profiles and boundary.
# The ledger entries name calls the estate walk already makes rather than widening
# the ask to suit a new pillar.
# ══════════════════════════════════════════════════════════════════════════════
from engine import aws_checkdef as _cd                                            # noqa: E402
from engine.aws_checkdef import CheckDef as _C, Perm as _P                   # noqa: E402

_IAM_READ = (
    _P("iam:GetAccountAuthorizationDetails",
       "enumerate roles and users with their trust policies -- the single call the "
       "machine-vs-human classification reads"),
    _P("iam:ListInstanceProfilesForRole",
       "establish that a workload assumes the role, the strongest machine signal short "
       "of a service-principal trust"),
)

CHECKS = _cd.register(
    # No `CIS` key: a machine identity that also holds a console password is a real
    # finding with no CIS AWS Foundations recommendation. It used to cite 1.4, which is
    # specifically "the ROOT user has no access keys" -- a different identity entirely.
    _C(id="NHI-01", section="NHI", severity="HIGH",
       compliance={"PCI-DSS": "8.2.1", "HIPAA": "164.312(a)(2)(i)",
                   "SOC2": "CC6.1", "NIST": "AC-6"},
       permissions=_IAM_READ,
       remediation=(
           "Remove the console password from the machine identity: aws iam "
           "delete-login-profile --user-name <USER>. Check first whether anything "
           "depended on it -- a person using a shared service account is the usual "
           "reason one exists, and that is its own finding worth resolving separately"),
       risk=(
           "This identity is assumed by a workload and also carries a console password. "
           "A machine cannot use one, so the password exists for a person -- meaning "
           "either a human is operating a shared service account, or the credential is "
           "simply left over. Both are worth ending. A console password widens the "
           "identity to exactly the techniques automation is otherwise immune to: "
           "phishing, password reuse, and credential stuffing against the sign-in page. "
           "It also destroys attribution, because console actions and workload actions "
           "then arrive under the same principal and cannot be told apart afterwards. "
           "Note what this rests on: the finding is raised only when STRUCTURAL evidence "
           "-- a service-principal trust, a workload-identity issuer, or an instance "
           "profile -- established the identity as a machine. A naming convention alone "
           "never triggers it, because acting on a name is how a tool ends up telling "
           "somebody to delete a colleague access."),
       impact=("A workload identity carries a human-usable credential, widening its "
               "attack surface and destroying attribution between console and machine "
               "activity."),
       steps=(
           "Confirm it really is a machine: aws iam get-role --role-name <ROLE> --query "
           "Role.AssumeRolePolicyDocument should name a service principal or a workload "
           "issuer.",
           "Check whether the password is in use before removing it -- the credential "
           "report password_last_used column tells you.",
           "Remove it: aws iam delete-login-profile --user-name <USER>",
           "If a person was using it, give them their own identity rather than "
           "re-adding the password to the shared one.",
           "Prevent recurrence: an SCP denying iam:CreateLoginProfile on principals "
           "tagged as machine identities.")),

    _C(id="NHI-02", section="NHI", severity="MEDIUM",
       compliance={"CIS": "2.12", "PCI-DSS": "8.3.9", "HIPAA": "164.308(a)(5)(ii)(D)",
                   "SOC2": "CC6.1", "NIST": "IA-5"},
       permissions=_IAM_READ,
       remediation=(
           "Rotate without an outage by overlapping: aws iam create-access-key "
           "--user-name <USER>, deploy the new key, confirm the old key LastUsedDate "
           "stops advancing, then aws iam update-access-key --user-name <USER> "
           "--access-key-id <OLD> --status Inactive and delete once sure. Better: give "
           "the workload a role it assumes, which removes the rotation problem rather "
           "than rescheduling it"),
       risk=(
           "The oldest access key on this machine identity is past the rotation "
           "threshold. Machine credentials are the ones that do not get rotated, and the "
           "reason is structural rather than negligent: nothing prompts anybody. A "
           "person password expires and they are told; a service account key simply "
           "keeps working, often long after the engineer who created it has moved on, "
           "and after the key has been copied into a CI variable, a laptop, a runbook "
           "and a backup. Age is not compromise, but it is a fair proxy for how many "
           "places a secret has had time to reach, and long-lived static keys are the "
           "credential class most often named in breach post-mortems. The durable fix is "
           "not a faster schedule but removing the static key: a role issues short-lived "
           "credentials and has nothing to rotate."),
       impact=("A long-lived static credential has had time to spread into logs, CI "
               "configuration and developer machines, and nothing revokes it when the "
               "person who created it leaves."),
       steps=(
           "Find the key and its last use: aws iam list-access-keys --user-name <USER> "
           "then aws iam get-access-key-last-used --access-key-id <KEY>",
           "Prefer elimination: if the workload runs on AWS, give it a role and drop the "
           "static key entirely.",
           "If a key is genuinely required, overlap the rotation rather than swapping in "
           "place.",
           "Deactivate before deleting, so a missed consumer fails loudly and "
           "reversibly: aws iam update-access-key --access-key-id <OLD> --status Inactive",
           "Prevent recurrence: the AWS Config rule access-keys-rotated, rather than a "
           "calendar reminder.")),

    _C(id="NHI-03", section="NHI", severity="LOW",
       compliance={"PCI-DSS": "12.5.1", "HIPAA": "164.308(a)(2)", "SOC2": "CC1.3",
                   "NIST": "CM-8"},
       permissions=_IAM_READ,
       remediation=(
           "Tag the identity so somebody is accountable for it: aws iam tag-role "
           "--role-name <ROLE> --tags Key=Owner,Value=<team-or-email>. If nobody can be "
           "found to own it, that is the more useful finding -- an identity with no "
           "owner and no known consumer is a candidate for removal"),
       risk=(
           "This machine identity carries no owner, team, contact or maintainer tag. "
           "Ownership is the control that makes every other identity control work: an "
           "unowned identity is the one nobody rotates, nobody reviews, and above all "
           "nobody revokes when the system it served is decommissioned. That is how an "
           "estate accumulates live credentials for services that no longer exist -- not "
           "through a decision, but because deletion needs somebody who knows it is safe "
           "and there is nobody to ask. This is deliberately LOW: a missing tag is not "
           "itself exploitable. Its value is as the input to the question that is, which "
           "is whether anything still uses this identity at all."),
       impact=("Nobody is accountable for the identity, so it survives the decommission "
               "of whatever it was created for and keeps its permissions indefinitely."),
       steps=(
           "Establish whether anything still uses it: aws iam get-role --role-name "
           "<ROLE> --query Role.RoleLastUsed, plus CloudTrail for recent AssumeRole "
           "calls.",
           "If it is in use, record the owner: aws iam tag-role --role-name <ROLE> "
           "--tags Key=Owner,Value=<team>",
           "If nobody claims it, detach policies before deleting so a missed consumer "
           "fails reversibly.",
           "Prevent recurrence: require the tag at creation with an SCP condition on "
           "aws:RequestTag/Owner for iam:CreateRole.")),

    # 2.21, not 2.14: a role's trust policy IS a resource policy, and an external account
    # able to assume it with no ExternalId condition is exactly the unrestricted grant
    # that recommendation is about. 1.16 (now 2.14) is about attached "*:*" policies.
    _C(id="NHI-04", section="NHI", severity="HIGH",
       compliance={"CIS": "2.21", "PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)",
                   "SOC2": "CC6.3", "NIST": "AC-3"},
       permissions=_IAM_READ,
       remediation=(
           "Add an external id so the vendor must present a secret only you and they "
           "know: aws iam update-assume-role-policy --role-name <ROLE> "
           "--policy-document with a Condition of {\"StringEquals\":{\"sts:ExternalId\":\"<unguessable-value>\"}}, then give that "
           "value to the vendor through their console. GENERATE IT YOURSELF -- a "
           "vendor-supplied value identical across their customers restores the problem "
           "it was meant to solve"),
       risk=(
           "An AWS account outside this estate can assume this role, and no "
           "sts:ExternalId condition guards it. This is the confused-deputy problem and "
           "it is specific to third-party access: the vendor you granted access to holds "
           "role ARNs for many customers, so anyone who learns YOUR role ARN and can "
           "induce that vendor to act on their behalf reaches your account. A role ARN "
           "is not a secret -- it appears in documentation, tickets, Terraform state and "
           "support threads. The external id closes the gap by requiring a value the "
           "caller must also present, so knowing the ARN is no longer enough."),
       impact=("A third party compromise, or anyone who can induce them to act, reaches "
               "into this account with whatever the role grants."),
       steps=(
           "Identify who can assume it: aws iam get-role --role-name <ROLE> --query "
           "Role.AssumeRolePolicyDocument",
           "Confirm the external account is a vendor you deliberately integrated with, "
           "not a leftover from an evaluation.",
           "Generate an unguessable external id yourself rather than accepting one the "
           "vendor issues to every customer.",
           "Apply it: aws iam update-assume-role-policy --role-name <ROLE> "
           "--policy-document file://trust.json",
           "Give the value to the vendor, then confirm their integration still works.",
           "Separately, scope the role permissions to what the vendor actually needs -- "
           "external access and least privilege are different controls.")),

    _C(id="NHI-05", section="NHI", severity="HIGH",
       compliance={"CIS": "2.21", "PCI-DSS": "7.1.2", "HIPAA": "164.312(a)(1)",
                   "SOC2": "CC6.3", "NIST": "AC-3"},
       permissions=_IAM_READ,
       remediation=(
           "Pin the subject claim so only your workload can assume the role: aws iam "
           "update-assume-role-policy --role-name <ROLE> --policy-document "
           "file://trust.json, where the federated statement carries a Condition. For "
           "GitHub "
           "Actions, a Condition of {\"StringEquals\":{\"token.actions.githubusercontent.com:aud\":\"sts.amazonaws.com\",\"token.actions.githubusercontent.com:sub\":\"repo:<ORG>/<REPO>:ref:refs/heads/main\"}}. Use StringEquals rather than "
           "StringLike wherever the value is fully known -- a trailing wildcard in :sub "
           "is how an org-wide trust gets written by accident"),
       risk=(
           "This role trusts a public workload-identity issuer with no subject (:sub) "
           "condition, so any workload that issuer will mint a token for can assume it "
           "-- not only yours. For GitHub Actions that means any repository on "
           "github.com; for a shared CI provider it means any customer of that provider. "
           "This is a well-exercised supply-chain entry point precisely because it looks "
           "configured: the trust names a specific issuer, and an :aud condition is "
           "often present, which reads like scoping. It is not. Every workflow on the "
           "issuer shares the audience; only the subject claim identifies WHICH one. "
           "Nothing appears wrong until somebody else pipeline assumes your role."),
       impact=("Any workload on the trusted issuer -- including repositories and "
               "pipelines belonging to other organisations -- can assume this role."),
       steps=(
           "Read the current trust: aws iam get-role --role-name <ROLE> --query "
           "Role.AssumeRolePolicyDocument",
           "Identify the exact subject your workload presents. For GitHub Actions it is "
           "repo:<ORG>/<REPO>:ref:refs/heads/<BRANCH> or "
           "repo:<ORG>/<REPO>:environment:<ENV>.",
           "Add a StringEquals condition on the issuer :sub claim alongside the existing "
           ":aud condition -- :aud alone narrows nothing.",
           "Avoid a trailing wildcard unless you genuinely need every branch: "
           ":ref:refs/heads/* trusts any branch, including one a contributor opens.",
           "Verify from the pipeline that the assume still succeeds, and from a "
           "different repo that it now fails.",
           "Prevent recurrence: a Config rule rejecting federated trusts whose condition "
           "block has no :sub key.")),
)
