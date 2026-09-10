#!/usr/bin/env python3
"""aws_cis_foundations_map.py — the CIS AWS Foundations Benchmark v7.0.0 mapping, as DATA.

All 70 recommendations across the benchmark's five numbered sections, and what OverWatch
does about each one. `scripts/cis_foundations_benchmark.py` renders it into
`docs/CIS_FOUNDATIONS_BENCHMARK.md`; `tests/test_cis_foundations_mapping.py` asserts the
properties that make it worth quoting.

WHY THIS MODULE EXISTS AT ALL, WHEN `CIS` KEYS ALREADY EXISTED. They did, and they were
anchored to **v3.0**, four major versions back — `compliance/crosswalk.json` said so and a
test asserted the rendered citation read "CIS AWS Foundations Benchmark v3.0/1.5". That is
not drift; it is an honest citation of an old edition. But v7.0.0 renumbers *every* section
(see ``RENUMBERED``), so an estate audited against the current document could not reconcile
a single OverWatch citation with it, and the mapping had never been checked in the round.
Checking it in the round found citations that were wrong against v3.0 as well — those are
in ``MISCITED``.

ON THE SOURCE DOCUMENT. CIS Benchmarks may not be redistributed, and the PDF is
deliberately not in this repository — the document's own terms state it is never acceptable
to host a CIS Benchmark in any format on a non-CIS site. What is recorded below is the
recommendation NUMBER, which is a reference, and a SHORT LABEL WRITTEN FROM THE UNDERLYING
AWS BEHAVIOUR. No title, rationale, audit, impact or remediation text is copied from the
benchmark; every description here is this project's own, written from what the AWS API
actually exposes. ``tests/test_cis_foundations_mapping.py`` enforces that.

WHY `CIS` AND NOT A NEW KEY. The Compute and Database benchmarks got their own keys
(`CIS-COMPUTE`, `CIS-DB`) because they are *sibling documents* that reuse the same section
numbers for unrelated controls. v7.0.0 is not a sibling — it is the same document, a later
edition. A new key would present one benchmark as two frameworks and double-count coverage
in every export. So `CIS` keeps its meaning and moves to the current edition, and the
edition is declared once, in the framework registry.
"""
from __future__ import annotations

from typing import Dict, Tuple

__all__ = [
    "COVERED", "PARTIAL", "ELSEWHERE", "NO_CHECK", "DECLINED", "PROCESS", "VACUOUS",
    "NARROWED", "VERDICTS", "AUTOMATED", "MANUAL", "RECOMMENDATIONS", "SECTIONS",
    "RENUMBERED", "REPOINTED", "MISCITED", "EKS_NUMBERED", "HOME_OVERRIDE",
    "checks_for", "recommendation_for", "verdict_for",
]

# ─── verdicts ────────────────────────────────────────────────────────────────────
#: A named check decides this recommendation and can FAIL on it.
COVERED = "covered"
#: A check reads the setting but cannot FAIL on it — it PASSes or WARNs. Real coverage of
#: the *observation*, not of the *finding*: a check that cannot fail can never tell an
#: operator they are non-compliant, so it is never counted as covered.
PARTIAL = "partial"
#: A check decides a defensible SUBSET of the recommendation and CAN fail on it, while the
#: remainder is not decidable from the control plane at all.
#:
#: THIS IS A DIFFERENT THING FROM `PARTIAL` AND THE DISTINCTION IS LOAD-BEARING. A partial
#: check cannot tell an operator anything is wrong. A narrowed one can, and does — it just
#: answers a smaller question than the benchmark asked, and says so in its own finding.
#: The two were one verdict in the first draft of this file, and merging them had a
#: concrete cost: a narrowed check is a real citation and needs a home in COMPLIANCE_MAP,
#: and a partial one must never have one. Two recommendations are narrowed. 2.1.4 asks for
#: an OU structure reflecting environment and sensitivity, and ORG-04 decides only that
#: accounts are in an OU at all; grading OU NAMES would be scoring a naming convention and
#: calling it a control. 2.2 asks for contact details that are current, and ACCT-01 decides
#: only that they are populated; no API says whether a phone number still reaches anybody.
NARROWED = "narrowed"
#: Decided, but by a check whose own home is a different recommendation, so the citation
#: lives there and this row only records that the fact is known.
ELSEWHERE = "elsewhere"
#: Decidable from the control plane, not currently checked. The honest backlog.
NO_CHECK = "gap"
#: Deliberately not built, with the reason recorded in the note.
DECLINED = "declined"
#: Asks about a human process — a review cadence, a design exercise, an organisational
#: decision no API read can settle.
PROCESS = "process"
#: True of every modern account by construction, so a check would pass universally and
#: measure nothing.
VACUOUS = "vacuous"

VERDICTS = (COVERED, NARROWED, PARTIAL, ELSEWHERE, NO_CHECK, DECLINED, PROCESS, VACUOUS)

#: The verdicts that make a check the OWNER of a recommendation, and therefore give it a
#: `CIS` key. Ordered: a check named on both a COVERED and a NARROWED row is homed on the
#: COVERED one, because that is the row it fully decides.
_OWNING = (COVERED, NARROWED)

#: The benchmark's own assessment-status field. It is worth carrying because it changes
#: what a verdict MEANS: a gap on an Automated recommendation is coverage this product
#: should have and does not, while a gap on a Manual one is usually the benchmark saying
#: the control cannot be settled by a single API read. Automating a Manual recommendation
#: is the more interesting result, and there are eleven of those below.
AUTOMATED = "Automated"
MANUAL = "Manual"

#: (number, name, recommendation count). Section 1 is the Introduction and carries no
#: recommendations at all, which is the single fact that invalidates every pre-existing
#: `1.x` citation in this product.
SECTIONS: Tuple[Tuple[str, str, int], ...] = (
    ("2", "Identity and Access Management", 26),
    ("3", "Storage", 9),
    ("4", "Logging", 10),
    ("5", "Monitoring", 16),
    ("6", "Networking", 9),
)

#: number -> (label, profile, verdict, checks, note). The label is this project's own
#: one-line description of the control, NOT the benchmark's title.
RECOMMENDATIONS: Dict[str, Tuple[str, str, str, Tuple[str, ...], str]] = {

    # ══ 2 Identity and Access Management ═════════════════════════════════════════
    # 2.1 is new in v7.0.0 and is the largest single addition the edition makes: six
    # recommendations about the organisation rather than about the account. Everything
    # here reads from the management account, which is why all six degrade to a stated
    # coverage gap rather than a PASS when the scan runs in a member account.
    "2.1.1": ("Root credentials removed from member accounts and managed centrally",
              MANUAL, COVERED, ("ORG-01",),
              "Central root management is readable — iam:ListOrganizationsFeatures "
              "returns the enabled feature set — so this is one of the Manual "
              "recommendations OverWatch decides automatically"),
    "2.1.2": ("Every account sits under an authorization guardrail (SCP or RCP)",
              MANUAL, COVERED, ("ORG-02",),
              "ORG-02 fails an account whose inherited policy set is nothing but the "
              "FullAWSAccess default, which is the state that LOOKS governed -- a policy "
              "IS attached -- while restricting nothing"),
    "2.1.3": ("The management account runs no workloads", MANUAL, COVERED, ("ORG-03",),
              "Decidable only while scanning the management account itself, and ORG-03 "
              "says which of the two it did rather than reporting a silent pass from a "
              "member account"),
    "2.1.4": ("Accounts are organised into OUs rather than parented to the root",
              MANUAL, NARROWED, ("ORG-04",),
              "Whether an OU tree reflects environment and sensitivity is a judgement "
              "about names, and ORG-04 does not make it. What it decides is the "
              "objectively readable half: an account parented directly to the root is in "
              "no OU, so no OU-scoped guardrail can reach it"),
    "2.1.5": ("Organizations policy administration is delegated off the management "
              "account", MANUAL, COVERED, ("ORG-05",), ""),
    "2.1.6": ("Organizations-integrated services have a delegated administrator",
              MANUAL, COVERED, ("ORG-06",),
              "The recommendation is per-service and open-ended, so ORG-06 reports the "
              "services that have trusted access enabled AND no delegated administrator, "
              "naming them rather than asserting a total"),

    "2.2": ("Account contact details are populated and current", MANUAL, NARROWED,
            ("ACCT-01",),
            "ACCT-01 decides POPULATED. Nothing in the API says whether a phone number "
            "still reaches anybody, so CURRENT is not readable and the check does not "
            "claim it"),
    "2.3": ("A security alternate contact is registered", MANUAL, COVERED, ("ACCT-02",),
            "account:GetAlternateContact answers this outright, so a second Manual "
            "recommendation is decided automatically"),
    "2.4": ("The root user has no access keys", AUTOMATED, COVERED, ("IAM-02",), ""),
    "2.5": ("MFA is enabled on the root user", AUTOMATED, COVERED, ("IAM-01",), ""),
    "2.6": ("Root MFA is a hardware device rather than a virtual one", MANUAL, COVERED,
            ("IAM-11",),
            "The distinction is readable: a virtual device's serial number is an "
            "arn:aws:iam::<account>:mfa/... ARN, a hardware one's is not. IAM-11 is "
            "deliberately separate from IAM-01 -- rating 'no MFA at all' and 'MFA, but "
            "virtual' the same would be wrong in both directions"),
    "2.7": ("The root user is not used for day-to-day work", MANUAL, COVERED,
            ("IAM-07",), ""),
    "2.8": ("Password policy requires at least 14 characters", AUTOMATED, COVERED,
            ("IAM-05",), "IAM-05 decides 2.8 and 2.9 in one read of the account policy; "
            "the citation lives on 2.8 by the precedence rule below"),
    "2.9": ("Password policy prevents reuse of the last 24 passwords", AUTOMATED,
            ELSEWHERE, ("IAM-05",),
            "Same check, same single API call. Listed so the row is not empty, keyed on "
            "2.8 so one check does not appear to provide two independent coverages"),
    "2.10": ("Every IAM user with a console password has MFA", AUTOMATED, COVERED,
             ("IAM-04",), ""),
    "2.11": ("Credentials unused for 45 days or more are disabled", AUTOMATED, COVERED,
             ("IAM-08",), ""),
    "2.12": ("Access keys are rotated at least every 90 days", AUTOMATED, COVERED,
             ("IAM-06", "NHI-02", "CREDEXP-01"),
             "CREDEXP-01 is here because a live key found in a breach corpus is a key "
             "whose rotation is overdue by any reading, and rotation is its remediation. "
             "It is corroborating evidence for this control, not a second one"),
    "2.13": ("IAM users hold no directly attached policies", AUTOMATED, COVERED,
             ("IAM-12",), ""),
    "2.14": ("No policy granting Action:* on Resource:* is attached to anything",
             AUTOMATED, COVERED, ("IAMPE-19", "IDENTITY-01", "SSO-01"),
             "IAMPE-19 decides it for IAM principals and evaluates the policy's DEFAULT "
             "version, which is what v7.0.0 clarified this edition. SSO-01 decides the "
             "same shape for an IAM Identity Center permission set, which an audit that "
             "only reads iam: APIs never sees"),
    "2.15": ("A role exists for raising AWS Support cases", AUTOMATED, COVERED,
             ("IAM-13",), ""),
    "2.16": ("EC2 instances reach AWS through an instance role, not a static key",
             AUTOMATED, COVERED, ("EC2-18",),
             "EC2-18 fails the absence of an instance profile. It cannot see a key baked "
             "into an AMI or fetched at boot; EC2-07 is the check that finds those, and "
             "the two are separate because the remediations differ"),
    "2.17": ("No expired certificate is left in ACM", AUTOMATED, COVERED, ("ACM-01",),
             "v7.0.0 rescoped this to ACM. The IAM certificate store it used to name is "
             "a legacy surface most estates never populate, so the old form passed "
             "vacuously nearly everywhere"),
    "2.18": ("IAM Access Analyzer is enabled in every region", AUTOMATED, COVERED,
             ("IAM-10",), ""),
    "2.19": ("Human access arrives through federation rather than IAM users", MANUAL,
             COVERED, ("IAM-14",),
             "IAM-14 fails on IAM users that carry a console password while an identity "
             "source exists, which is the state the recommendation is about. A "
             "service-only IAM user with no password is not a human bypassing "
             "federation, and failing it would push operators toward a change that "
             "improves nothing"),
    "2.20": ("CloudShell full access is not broadly granted", MANUAL, COVERED,
             ("IAM-15",), ""),
    "2.21": ("No resource policy grants Principal:* without a restricting condition",
             MANUAL, COVERED,
             ("S3-09", "S3T-01", "LMB-01", "SNS-02", "SQS-02", "KMS-02", "SEC-05",
              "IMGB-01", "IAMPE-22", "IAMPE-23", "NHI-04", "NHI-05"),
             "New in v7.0.0 and the most cross-cutting control in the document. A role "
             "TRUST policy is a resource policy, which is why the four IAM rows are "
             "here: a trust policy naming Principal '*' or a public OIDC issuer with no "
             "subject condition is the same defect on the one resource whose compromise "
             "grants the others"),

    # ══ 3 Storage ════════════════════════════════════════════════════════════════
    "3.1.1": ("Bucket policy denies requests that are not over TLS", AUTOMATED, COVERED,
              ("S3-07",),
              "S3-07 reads the policy for an effective deny on aws:SecureTransport "
              "false, rather than for the presence of a policy, because a policy that "
              "grants TLS access without denying plaintext satisfies neither the control "
              "nor the threat"),
    "3.1.2": ("MFA Delete is enabled on the bucket", MANUAL, COVERED, ("S3-11",),
              "Readable from GetBucketVersioning, which returns MFADelete alongside "
              "Status. S3-11 states the precondition when versioning is off, because "
              "MFA Delete is unreachable without it and 'enable MFA Delete' is not "
              "actionable advice on an unversioned bucket"),
    "3.1.3": ("Sensitive S3 data is discovered and classified", MANUAL, COVERED,
              ("DATA-01",),
              "DATA-01 is a Macie consumer, so it decides this only where Macie runs. "
              "That is the same precondition the recommendation itself has"),
    "3.1.4": ("Block Public Access is on and no bucket policy defeats it", AUTOMATED,
              COVERED, ("S3-01", "S3-09", "EXTACCESS-01", "DATA-02"),
              "Four checks because the control has three failure modes and one "
              "authority: the account/bucket switch (S3-01), a policy that would be "
              "public without it (S3-09), and Access Analyzer's authoritative verdict "
              "(EXTACCESS-01), which is the only one of the three that is not an "
              "inference"),
    "3.2.1": ("RDS storage and snapshots are encrypted at rest", AUTOMATED, COVERED,
              ("RDS-01", "RDS-11", "AUR-01", "AUR-05"),
              "The two snapshot checks are here on purpose: a snapshot outlives the "
              "instance and is the copy that leaves production"),
    "3.2.2": ("Auto minor version upgrade is enabled", AUTOMATED, COVERED, ("RDS-03",),
              ""),
    "3.2.3": ("RDS instances are not publicly accessible", AUTOMATED, COVERED,
              ("RDS-02",), ""),
    "3.2.4": ("Multi-AZ is used where availability warrants it", MANUAL, PARTIAL,
              ("RDS-03",),
              "RDS-03 reads MultiAZ and reports it without ever failing on it, which is "
              "the right shape for a recommendation that does not claim single-AZ is "
              "wrong. Counting it as covered would claim an enforcement this product "
              "deliberately does not do"),
    "3.3.1": ("EFS file systems are encrypted at rest", AUTOMATED, COVERED, ("EFS-01",),
              "EFS-01 has existed since before this mapping and carried no CIS key at "
              "all -- coverage the product had and did not claim, which is the quieter "
              "half of a mapping error"),

    # ══ 4 Logging ════════════════════════════════════════════════════════════════
    "4.1": ("A multi-region CloudTrail is enabled and logging", MANUAL, COVERED,
            ("LOG-01", "LOG-10"),
            "LOG-10 is here because a trail can be configured correctly and silently "
            "failing to deliver, which reads as compliant to every audit that stops at "
            "the trail's own configuration"),
    "4.2": ("CloudTrail log file validation is enabled", AUTOMATED, COVERED,
            ("LOG-11",), ""),
    "4.3": ("AWS Config is recording in every region", AUTOMATED, COVERED, ("LOG-03",),
            "v7.0.0 accepts central management through Control Tower or a landing zone "
            "as satisfying this, so a member account with no local recorder is no longer "
            "automatically non-compliant -- see the note in the generated document"),
    "4.4": ("Server access logging is on the CloudTrail bucket", MANUAL, COVERED,
            ("LOG-12",),
            "LOG-12 resolves the trail's own bucket and checks that one, rather than "
            "reporting on every bucket in the account. S3-05 is the broader hygiene "
            "check and stays a WARN"),
    "4.5": ("CloudTrail logs are encrypted with a customer-managed KMS key", AUTOMATED,
            COVERED, ("LOG-07",), ""),
    "4.6": ("Automatic rotation is enabled on customer-managed symmetric keys",
            AUTOMATED, COVERED, ("ENC-03",), ""),
    "4.7": ("Flow logging is enabled on every VPC", AUTOMATED, COVERED, ("VPC-03",), ""),
    "4.8": ("Object-level write events are logged for S3 buckets", AUTOMATED, COVERED,
            ("LOG-08",),
            "One data-event selector decides 4.8 and 4.9, so LOG-08 reads it once and "
            "reports which of the two event types is missing"),
    "4.9": ("Object-level read events are logged for S3 buckets", AUTOMATED, ELSEWHERE,
            ("LOG-08",), "As 4.8 — same selector, same call, keyed on 4.8"),
    "4.10": ("AWS-managed HTTP front ends write access logs", MANUAL, COVERED,
             ("ELB-01", "CFN-04", "APIGW-01", "AGW2-01"),
             "New in v7.0.0, and the four services it names each already had a check. "
             "The recommendation is what connects them: individually they read as "
             "service hygiene, together they are the question of whether any request "
             "can reach the estate without leaving a record"),

    # ══ 5 Monitoring ═════════════════════════════════════════════════════════════
    # Fifteen metric-filter-and-alarm controls with one shared precondition, plus
    # Security Hub. CW-01 is that precondition and is cited on 5.1 rather than given a
    # row of its own, because the benchmark does not have a row for it.
    "5.1": ("Unauthorized API calls raise an alarm", MANUAL, COVERED,
            ("CW-01", "CW-02"),
            "CW-01 decides the precondition the whole section rests on -- a multi-region "
            "trail delivering into a CloudWatch Logs group. Without it every filter in "
            "5.1-5.15 can exist and match nothing, so a section that is 100% compliant "
            "on paper can be entirely inert"),
    "5.2": ("Console sign-in without MFA raises an alarm", MANUAL, COVERED, ("CW-03",),
            ""),
    "5.3": ("Root user activity raises an alarm", MANUAL, COVERED, ("CW-04",), ""),
    "5.4": ("IAM policy changes raise an alarm", MANUAL, COVERED, ("CW-05",), ""),
    "5.5": ("CloudTrail configuration changes raise an alarm", MANUAL, COVERED,
            ("CW-06",), ""),
    "5.6": ("Console authentication failures raise an alarm", MANUAL, COVERED,
            ("CW-07",), ""),
    "5.7": ("Disabling or scheduling deletion of a CMK raises an alarm", MANUAL,
            COVERED, ("CW-08",), ""),
    "5.8": ("S3 bucket policy changes raise an alarm", MANUAL, COVERED, ("CW-09",), ""),
    "5.9": ("AWS Config changes raise an alarm", MANUAL, COVERED, ("CW-10",), ""),
    "5.10": ("Security group changes raise an alarm", MANUAL, COVERED, ("CW-11",),
             "v7.0.0 adds ModifySecurityGroupRules to the expected pattern. It is the "
             "API the console has used since 2021, so a filter written to the older list "
             "misses the way most rule changes are actually made -- see CW-11's own "
             "note on why it accepts either form"),
    "5.11": ("Network ACL changes raise an alarm", MANUAL, COVERED, ("CW-12",), ""),
    "5.12": ("Network gateway changes raise an alarm", MANUAL, COVERED, ("CW-13",), ""),
    "5.13": ("Route table changes raise an alarm", MANUAL, COVERED, ("CW-14",), ""),
    "5.14": ("VPC changes raise an alarm", MANUAL, COVERED, ("CW-15",), ""),
    "5.15": ("AWS Organizations changes raise an alarm", MANUAL, COVERED, ("CW-16",),
             ""),
    "5.16": ("Security Hub is enabled", AUTOMATED, COVERED, ("LOG-05",), ""),

    # ══ 6 Networking ═════════════════════════════════════════════════════════════
    "6.1.1": ("EBS encryption by default is on, and volumes are encrypted", AUTOMATED,
              COVERED, ("EBS-01", "EBS-02", "EC2-06", "AMI-02"),
              "EBS-01 decides the regional default and EBS-02 the volumes that already "
              "exist. Only checking the default would pass an account that turned it on "
              "yesterday and has a thousand unencrypted volumes from before"),
    "6.1.2": ("SMB/CIFS is not reachable from untrusted networks", AUTOMATED, COVERED,
              ("VPC-01",),
              "New in v7.0.0, and already decided: port 445 has been in VPC-01's "
              "risky-port set since before this mapping, so the check that answers it "
              "predates the recommendation"),
    "6.2": ("No network ACL admits remote administration ports from anywhere",
            AUTOMATED, COVERED, ("VPC-05",),
            "v7.0.0 now accepts an effective-ruleset argument here -- a DENY ordered "
            "before the ALLOW closes the finding. VPC-05 already evaluates rule order "
            "rather than matching the ALLOW alone, which is why it needed no change"),
    "6.3": ("No security group admits remote administration ports from 0.0.0.0/0",
            AUTOMATED, COVERED, ("VPC-01", "SEG-01", "SEG-02", "SEG-05"),
            "v7.0.0 explicitly REFUSES the effective-ruleset argument it accepts for "
            "6.2, and it is right to: a security group has no deny rules and no "
            "ordering, so there is nothing that can precede an allow"),
    "6.4": ("No security group admits remote administration ports from ::/0", AUTOMATED,
            ELSEWHERE, ("VPC-01",),
            "VPC-01 evaluates IPv4 and IPv6 ranges in the same pass. Keyed on 6.3 so one "
            "check is not counted as two coverages"),
    "6.5": ("The default security group of every VPC carries no rules", AUTOMATED,
            COVERED, ("VPC-04",), ""),
    "6.6": ("VPC peering routes are scoped rather than whole-CIDR", MANUAL, COVERED,
            ("VPC-07",),
            "VPC-07 fails a route that sends an entire peer CIDR across the connection. "
            "VPC-06 is a different question -- who owns the VPC at the other end -- and "
            "answering that one was not answering this one"),
    "6.7": ("Instance metadata requires IMDSv2", AUTOMATED, COVERED,
            ("EC2-04", "EC2-08", "ASG-01", "LT-01"),
            "The launch-template and Auto Scaling checks matter more than the instance "
            "check for this control: fixing running instances without fixing what "
            "launches them means the finding returns at the next scale-out"),
    "6.8": ("AWS service traffic uses VPC endpoints rather than the public path",
            MANUAL, COVERED, ("VPC-08",),
            "VPC-08 fails a VPC that has no endpoint at all AND has a path to the "
            "internet, which is the state the recommendation is about. A VPC with no "
            "internet path is not reaching AWS services over the public network no "
            "matter what its endpoint list says"),
}

# ─── the renumbering ─────────────────────────────────────────────────────────────
#: v3.0 number -> v7.0.0 number, for every recommendation OverWatch cited. This is the
#: table that makes the change auditable: a reader holding an older report can see where
#: each citation went, and `tests/test_cis_foundations_mapping.py` checks that every value
#: is a recommendation that exists in v7.0.0.
#:
#: The shape of the move is worth stating once. v7.0.0 inserts the Introduction as
#: section 1, so IAM 1.x becomes 2.x, Storage 2.x becomes 3.x, Logging 3.x becomes 4.x,
#: Monitoring 4.x becomes 5.x and Networking 5.x becomes 6.x. Inside IAM the offset is not
#: constant, because two recommendations were eliminated on the way -- "do not create
#: access keys during initial setup" (named in the change log) and "only one active access
#: key per user". So 1.12 lands on 2.11 and 1.14 on 2.12, and anyone who assumed a uniform
#: +1 shift would mis-cite both.
RENUMBERED: Dict[str, str] = {
    "1.4": "2.4",       # root access keys
    "1.5": "2.5",       # root MFA
    "1.7": "2.7",       # root used for daily tasks
    "1.8": "2.8",       # password length
    "1.10": "2.10",     # console-user MFA
    "1.12": "2.11",     # credentials unused 45 days   (NOT 2.12 -- two were eliminated)
    "1.14": "2.12",     # access key rotation
    "1.16": "2.14",     # full "*:*" administrative privileges
    "1.20": "2.18",     # IAM Access Analyzer
    "2.1.4": "3.1.4",   # S3 Block Public Access
    "2.2.1": "6.1.1",   # EBS encryption -- LEFT Storage entirely, into Networking/EC2
    "2.3.1": "3.2.1",   # RDS encryption at rest
    "2.3.2": "3.2.3",   # RDS public access        (NOT 3.2.2 -- 2.3.2 and 2.3.3 swapped)
    "2.3.3": "3.2.2",   # auto minor version upgrade
    "3.1": "4.1",       # CloudTrail multi-region
    "3.5": "4.3",       # AWS Config
    "3.6": "4.4",       # server access logging on the CloudTrail bucket
    "3.8": "4.6",       # CMK rotation
    "3.10": "4.8",      # S3 object-level logging
    "4.1": "5.1", "4.2": "5.2", "4.3": "5.3", "4.4": "5.4", "4.5": "5.5",
    "4.6": "5.6", "4.7": "5.7", "4.8": "5.8", "4.9": "5.9", "4.10": "5.10",
    "4.11": "5.11", "4.12": "5.12", "4.13": "5.13", "4.14": "5.14", "4.15": "5.15",
    "4.16": "5.16",     # Security Hub
    "5.1": "6.2",       # network ACLs
    "5.2": "6.3",       # security groups
    "5.4": "6.5",       # default security group
    "5.6": "6.7",       # IMDSv2
}

#: Citations that were wrong against v3.0 as well, and are therefore removed rather than
#: renumbered: check -> (the number it carried, why it was wrong).
#:
#: These are the reason this mapping was worth doing as a mapping rather than as a
#: search-and-replace. Every one of them renders today as a real-looking citation into a
#: real document, at a control about something else — the failure mode that survives
#: review precisely because the number is well-formed.
MISCITED: Dict[str, Tuple[str, str]] = {
    "COG-01": ("1.5", "Cognito user-pool MFA is not the AWS account root user. The "
                      "control is about one identity that cannot be deleted; this "
                      "check is about an application's end users"),
    "NHI-01": ("1.4", "a machine identity holding a console password is a real finding "
                      "with no Foundations control; 1.4 is specifically root access "
                      "keys"),
    # The privilege-escalation primitives, all seventeen of them, carried 1.16 -- the
    # "*:*" administrative-privileges control. Exactly one of them decides it: IAMPE-19,
    # which fires on a principal that IS effectively an administrator. The rest fire on a
    # principal that could BECOME one, which is a different and usually more urgent
    # finding, and one this benchmark has no recommendation for. Citing 2.14 on
    # "this principal may call iam:CreateAccessKey" tells an auditor the finding is an
    # attached wildcard policy, and it sends them looking for a policy that is not there.
    **{c: ("1.16", "a privilege-escalation primitive is a path TO administrator, not an "
                   "attached '*:*' policy; IAMPE-19 is the one that decides 2.14")
       for c in ("IAMPE-01", "IAMPE-02", "IAMPE-03", "IAMPE-04", "IAMPE-05", "IAMPE-06",
                 "IAMPE-07", "IAMPE-08", "IAMPE-10", "IAMPE-11", "IAMPE-12", "IAMPE-13",
                 "IAMPE-14", "IAMPE-16", "IAMPE-18", "IAMPE-20", "IAMPE-21")},
    "S3-03": ("2.1.1", "default bucket encryption. Foundations dropped its S3 "
                       "encryption-at-rest control once SSE-S3 became unconditional, "
                       "and 2.1.1 was the deny-HTTP control even in v3.0"),
    "DATA-03": ("2.1.1", "as S3-03, on a Macie-identified bucket"),
    "S3-08": ("2.1.3", "bucket versioning. 2.1.3 was the Macie classification control; "
                       "versioning is a precondition for MFA Delete and not a control "
                       "in its own right in this document"),
    "CFN-01": ("2.1.2", "CloudFront viewer protocol policy is not an S3 control"),
    "CFN-02": ("2.1.2", "CloudFront minimum TLS version is not an S3 control"),
    "EBS-04": ("2.2.1", "a publicly restorable snapshot is a sharing grant, not an "
                        "encryption setting"),
    "AMI-01": ("2.3.3", "a publicly shared AMI is not the RDS minor-version control"),
    "RDS-04": ("2.3.3", "deletion protection is not the minor-version control, and "
                        "Foundations has no deletion-protection recommendation"),
    "RSS-01": ("2.3.2", "Redshift public accessibility. Foundations covers RDS only"),
    "AUR-04": ("2.3.4", "v7.0.0 has no snapshot-sharing recommendation at all"),
    "RDS-06": ("2.3.4", "as AUR-04"),
    "LMB-02": ("2.7.2", "a Lambda outside a VPC is a design choice; no such control"),
    "LOG-09": ("3.3", "eliminated in v7.0.0. Block Public Access made a dedicated "
                      "'CloudTrail bucket is not public' control near-vacuous, and the "
                      "general form is now 3.1.4"),
    "LOG-04": ("4.15", "GuardDuty. 4.15 was the Organizations-changes alarm, and "
                       "Foundations has never had a GuardDuty recommendation"),
    "THREAT-01": ("4.15", "as LOG-04, on an individual GuardDuty finding"),
    "LOG-06": ("4.16", "GuardDuty protection plans. 4.16 was Security Hub"),
    "ELB-02": ("4.10", "a plaintext HTTP listener is not an access-logging control. "
                       "v7.0.0's new 4.10 IS about load balancer logging, which is "
                       "ELB-01"),
    "S3-05": ("3.6", "re-scoped, not dropped: 4.4 asks about the CloudTrail bucket "
                     "specifically. S3-05 warns on every bucket and never fails, so it "
                     "observes the control without deciding it; LOG-12 decides it"),
    "EC2-05": ("5.1", "a public IP on an instance is not the network-ACL control"),
    "ATTACK-01": ("5.2", "an attack path is derived from primitive findings; citing the "
                         "benchmark on both the primitive and the derivation counts the "
                         "same coverage twice"),
    "ATTACK-02": ("5.2", "as ATTACK-01"),
    "CHOKEPOINT-01": ("5.2", "as ATTACK-01"),
    "EXPOSURE-01": ("5.2", "as ATTACK-01; VPC-01 and the SEG- checks are the primitives"),
    "EXPOSURE-02": ("5.2", "as EXPOSURE-01"),
    "EXPOSURE-03": ("5.2", "an internet-facing L7 front end is not an administration-"
                           "port control"),
    "FLOW-01": ("5.2", "as ATTACK-01: this is VPC-01's finding with flow-log evidence "
                       "attached, not a separate coverage"),
}

#: Citations that were kept but sent somewhere ``RENUMBERED`` would not predict:
#: check -> (old number, new number, why the plain renumber is not the answer).
#:
#: The distinction from ``MISCITED`` is the point. A removed citation is a claim this
#: product no longer makes. A re-pointed one is a claim it still makes, about a DIFFERENT
#: control — and a reader reconciling an old report needs to know which, because for these
#: nine the renumbering table gives the wrong answer. Six of them land on 2.21, which is
#: new in v7.0.0 and had no predecessor to be renumbered from.
REPOINTED: Dict[str, Tuple[str, str, str]] = {
    "IDENTITY-01": ("1.14", "2.14",
                    "an admin-capable IAM user is the '*:*' control, not key rotation. "
                    "1.14 renumbers to 2.12, which is where IAM-06 and NHI-02 correctly "
                    "went; this one was in the wrong place to begin with"),
    "IAMPE-22": ("1.16", "2.21",
                 "a role trust policy IS a resource policy, so a trust policy naming "
                 "Principal '*' is the new resource-policy control rather than the "
                 "attached-'*:*'-policy one 1.16 renumbers to"),
    "IAMPE-23": ("1.16", "2.21", "as IAMPE-22, for a public OIDC issuer with no subject "
                                 "condition"),
    "NHI-04": ("1.16", "2.21", "as IAMPE-22, for an external account with no ExternalId "
                               "condition"),
    "NHI-05": ("1.16", "2.21", "as IAMPE-22, for a public workload-identity issuer"),
    "SEC-05": ("1.16", "2.21",
               "a Secrets Manager resource policy granting a wildcard principal is a "
               "resource policy, not an attached identity policy"),
    "LMB-01": ("2.7.1", "2.21",
               "there is no section 2.7 in any edition of Foundations, so the old number "
               "resolved to nothing — but a Lambda resource policy granting the world is "
               "squarely the new 2.21"),
    "S3-07": ("2.1.2", "3.1.1",
              "2.1.2 was MFA Delete even in v3.0; the deny-non-TLS control was 2.1.1, "
              "which renumbers to 3.1.1. The old citation was off by one row in a "
              "section where both rows are about S3 buckets"),
    "VPC-03": ("3.7", "4.7",
               "3.7 was CloudTrail KMS encryption, which is LOG-07's control and "
               "renumbers to 4.5. Flow logging was 3.9 in v3.0 and is 4.7 now"),
}

#: Checks that were tagged with CIS Amazon EKS Benchmark numbering while carrying the
#: Foundations `CIS` key: check -> the number it carried.
#:
#: Kept as data rather than silently deleted, because the numbers are not nonsense — they
#: are coherent against a DIFFERENT CIS document (4.1.x RBAC, 4.2.x pod security, 4.3.x
#: network policy, 5.4.x cluster networking). v7.0.0's section 4 is a flat Logging list
#: and its section 5 a flat Monitoring list, so none of these can be Foundations numbers.
#:
#: They are removed rather than re-keyed to a new `CIS-EKS` framework DELIBERATELY. This
#: repository does not hold the EKS benchmark, and registering a framework whose numbering
#: nobody here has checked against its source would replace a citation that is provably
#: wrong with one that is merely unverified — which is worse, because it reads as
#: confirmed. Building the CIS-EKS mapping properly is recorded as follow-on work.
EKS_NUMBERED: Dict[str, str] = {
    "EKS-01": "5.4.1", "EKS-08": "3.1",
    "KIEM-01": "4.1.1", "KIEM-02": "4.1.3", "KIEM-03": "4.1.2", "KIEM-04": "4.1.1",
    "KSPM-01": "4.1.7", "KSPM-02": "4.1.3", "KSPM-03": "4.1.1", "KSPM-04": "4.1.5",
    "KSPM-05": "4.2.1", "KSPM-06": "4.3.2", "KSPM-07": "4.2.1",
}

# ─── lookups ─────────────────────────────────────────────────────────────────────
#: A check may inform several recommendations; exactly one of them is its HOME, and the
#: home is the one that carries the `CIS` key in COMPLIANCE_MAP. The default rule is the
#: same one the Database mapping uses: the lowest-numbered recommendation whose verdict is
#: COVERED and that names the check. A recommendation marked ELSEWHERE never becomes a
#: home, which is exactly what makes 2.9, 4.9 and 6.4 shareable without double-counting.
#:
#: Two checks need the rule overridden, and both for the same reason: the lowest number is
#: the NARROWER control, and citing it would understate what the check decides.
HOME_OVERRIDE: Dict[str, str] = {
    #: 6.1.2 (SMB from untrusted networks) sorts before 6.3, and VPC-01 does decide it —
    #: but 6.3 is the control VPC-01 exists for, and 445 is one entry in its port table.
    #: Citing 6.1.2 would tell an auditor that a finding about an exposed database port
    #: came from the CIFS recommendation.
    "VPC-01": "6.3",
    #: 2.21 is the general resource-policy control and S3-09 belongs in its covering set,
    #: but S3-09 is an S3 check and 3.1.4 is the S3 control. The Database mapping settled
    #: this precedence already: a check is keyed within its own service's section.
    "S3-09": "3.1.4",
}

_HOME_CACHE: Dict[str, str] = {}


def _homes() -> Dict[str, str]:
    if _HOME_CACHE:
        return _HOME_CACHE
    for owning in _OWNING:                  # COVERED wins over NARROWED, then by number
        for rec in sorted(RECOMMENDATIONS, key=_sort_key):
            _label, _profile, verdict, checks, _note = RECOMMENDATIONS[rec]
            if verdict != owning:
                continue
            for c in checks:
                _HOME_CACHE.setdefault(c, rec)
    _HOME_CACHE.update(HOME_OVERRIDE)
    return _HOME_CACHE


def _sort_key(rec: str) -> Tuple[int, ...]:
    parts = [int(p) for p in rec.split(".")]
    return tuple(parts + [0] * (4 - len(parts)))


def checks_for(rec: str) -> Tuple[str, ...]:
    """The checks this recommendation names, in declaration order."""
    entry = RECOMMENDATIONS.get(rec)
    return entry[3] if entry else ()


def recommendation_for(check_id: str) -> str:
    """The recommendation ``check_id`` is keyed to, or ``""`` if it answers none."""
    return _homes().get(check_id, "")


def verdict_for(rec: str) -> str:
    entry = RECOMMENDATIONS.get(rec)
    return entry[2] if entry else ""
