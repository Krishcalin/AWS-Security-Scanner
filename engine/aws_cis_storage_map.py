"""CIS AWS Storage Services Benchmark v1.0.0 -> OverWatch, all 56 recommendations.

`scripts/cis_storage_benchmark.py` renders this into `docs/CIS_STORAGE_BENCHMARK.md`.
Same discipline as the three sibling mappings: the rows are DATA, the document is
GENERATED, and `tests/test_cis_storage_mapping.py` asserts both directions so the
mapping and the catalogue cannot drift apart.

THIS BENCHMARK IS NOT LIKE THE OTHER THREE, and the mapping would misrepresent it if
it pretended otherwise. Three facts decide almost everything below.

FIRST: CIS MARKS ALL 56 RECOMMENDATIONS "Manual". Not one is Automated. The
benchmark's own definitions reserve "Automated" for controls whose assessment "can be
fully automated and validated to a pass/fail state", so the authors are saying up
front that none of this reduces to a pass/fail read. By contrast the Foundations,
Compute and Database benchmarks carry substantial Automated sets. A scanner mapping
this document is working against the grain of it.

SECOND: SEVEN RECOMMENDATIONS HAVE NO AUDIT PROCEDURE AT ALL -- the heading is
present and the body is empty. That is not a gap and not a decline: there is no
stated test to build. It gets its own verdict (`NO_AUDIT`) because folding those
seven into `gap` would advertise a backlog nobody can work, and folding them into
`declined` would imply a judgement this project made rather than a hole in the
source. Roughly thirty more have an empty Remediation, which does not stop a check
being written but does mean the document cannot tell an operator what to do once it
fires.

THIRD: TWO RECOMMENDATIONS WOULD REDUCE SECURITY IF FOLLOWED. That is why `UNSAFE`
exists here and in none of the sibling mappings.

  * 2.2's audit procedure directs the reader to open SSH, HTTP and HTTPS and to
    allow traffic from anywhere. `SEG-01`, `SEG-06` and `VPC-05` FAIL on exactly that
    condition, and so does CIS Foundations. Citing 2.2 on a finding would put this
    product's name behind guidance recommending world-open SSH.
  * 3.5 directs the reader to restrict EFS mount-target ingress to SSH on port 22.
    EFS mount targets serve NFS on 2049. Following it breaks the file system and
    secures nothing.

Recording those two as `gap` would have implied somebody should build them. Naming
them is the whole value of having read the document.

WHY `CIS-STORAGE` AND NOT `CIS`. The same reason `CIS-COMPUTE`, `CIS-DB` and
`CIS-AL2` have their own keys, now with four documents in play: `2.2` is the account
contact record in Foundations v7.0.0, EBS encryption in Compute, Aurora encryption at
rest in Database, and security-group configuration here. One shared key would
mis-cite every mapping in every direction at once.

ON THE SOURCE DOCUMENT. CIS Benchmarks may not be redistributed and the PDF is not in
this repository. What is recorded below is the recommendation NUMBER, which is a
reference, plus a short label and a note written from the underlying AWS behaviour.
No recommendation title, rationale, audit or remediation text is reproduced.

WHAT THE BENCHMARK NEVER ASKS. Section 1 asks repeatedly that backups be created and
never once asks whether they survive the loss of the region or the compromise of the
account. `BCK-04` (no copy out of the region or account) and `BCK-05` (vault on an
AWS-owned key) answer no recommendation here, and are deliberately carried without a
`CIS-STORAGE` key rather than being force-fitted onto 1.2.
"""
from __future__ import annotations

from typing import Dict, Tuple

__all__ = [
    "COVERED", "ELSEWHERE", "NO_CHECK", "BLOCKED", "DECLINED", "PROCESS",
    "VACUOUS", "NO_AUDIT", "UNSAFE", "VERDICTS", "SECTIONS", "RECOMMENDATIONS",
    "FAMILY_SECTION", "BLOCKERS", "checks_for", "recommendation_for", "by_verdict",
]

# ─── verdicts ────────────────────────────────────────────────────────────────
#: A named check decides this recommendation and can FAIL on it.
COVERED = "covered"
#: Decided, but by a check outside this benchmark's storage services -- the IAM,
#: segmentation or logging pillars. Six of section 2's thirteen "EBS"
#: recommendations are generic IAM and land here.
ELSEWHERE = "elsewhere"
#: Decidable from the AWS control plane, not currently checked. The real backlog.
NO_CHECK = "gap"
#: Needs state inside an instance -- an installed package, a running kernel, a mount.
#: NOT a gap: no read-only control-plane path to it exists. See BLOCKERS.
BLOCKED = "blocked"
#: Deliberately not built, with the reason recorded in the row's note.
DECLINED = "declined"
#: Asks about a human process -- a drill, a review cadence, a documented plan. No API
#: read decides it and inventing a check would be theatre.
PROCESS = "process"
#: True by construction, or not a security property at all. A check would pass
#: universally and measure nothing.
VACUOUS = "vacuous"
#: The source recommendation's Audit section is EMPTY. Nothing is specified to test,
#: so this is neither a gap nor a decline -- it is a hole in the document.
NO_AUDIT = "no-audit"
#: Following the source's own guidance would REDUCE security. Never to be built;
#: recorded so nobody files it as a backlog item later.
UNSAFE = "unsafe"

VERDICTS = (COVERED, ELSEWHERE, NO_CHECK, BLOCKED, DECLINED, PROCESS, VACUOUS,
            NO_AUDIT, UNSAFE)

#: What each BLOCKED row is waiting on. One blocker, because every blocked row here
#: is the same problem: the benchmark's FSx and DRS sections audit the inside of an
#: instance, and `aws_sidescan_fs.DissectExtractor` raises `SideScanUnavailable` on
#: purpose rather than return a guessed inventory. This is the same ceiling that caps
#: CIS Amazon Linux 2 at 35 of 287 -- see engine/aws_cis_al2_map.py.
BLOCKERS: Dict[str, str] = {
    "FILESYSTEM": (
        "reading state inside the instance -- an installed package, the running "
        "kernel, a mount table. The seam exists (aws_sidescan.FilesystemExtractor "
        "over the EBS block plane) and its production implementation refuses to "
        "guess. Pinning dissect.target, committing golden ext4/xfs images and "
        "validating on a Linux CI runner lifts every row below."),
}

SECTIONS: Tuple[Tuple[str, str, int], ...] = (
    ("1", "AWS Backup", 6),
    ("2", "Elastic Block Store (EBS)", 13),
    ("3", "Elastic File System (EFS)", 12),
    ("4", "FSx", 9),
    ("5", "Simple Storage Service (S3)", 3),
    ("6", "Elastic Disaster Recovery", 13),
)

#: Which section a check family calls home, for `recommendation_for`.
FAMILY_SECTION: Dict[str, str] = {
    "BCK": "1", "EBS": "2", "EFS": "3", "FSX": "4", "S3": "5", "DRS": "6",
}

#: number -> (label, verdict, checks, note). The label is this project's own one-line
#: description of what the control reaches for, not the benchmark's title.
RECOMMENDATIONS: Dict[str, Tuple[str, str, Tuple[str, ...], str]] = {

    # ── 1 AWS Backup ─────────────────────────────────────────────────────────
    "1.1": ("AWS Backup exists as a managed service", NO_AUDIT, (),
            "Audit and Remediation are both empty in the source. The body describes "
            "what the service is; nothing is asserted about an account"),
    "1.2": ("The administrator owns alerting, credentials, plan design, recovery "
            "capability and user familiarity", PROCESS, (),
            "Six organisational responsibilities. The audit procedure underneath "
            "them walks through CREATING a backup rather than assessing one, so "
            "even the parts that sound testable have no stated test"),
    "1.3": ("A backup plan exists and actually selects resources, and the vault "
            "holding them restricts access", COVERED, ("BCK-01", "BCK-03"),
            "BCK-01 is deliberately not satisfied by a plan that merely exists: a "
            "plan with no resource selection backs up nothing, which is the failure "
            "this recommendation is closest to naming. BCK-03 answers the vault "
            "access half"),
    "1.4": ("IAM policies scope who may manipulate backups", ELSEWHERE,
            ("IAMPE-01",),
            "The audit steps under this number are ROLE-creation steps, and they are "
            "the same steps printed verbatim under 1.5. Whether the policies that "
            "exist are over-privileged is the CIEM pillar's question"),
    "1.5": ("An IAM role exists for AWS Backup", ELSEWHERE, ("IAMPE-01",),
            "Duplicate of 1.4 -- identical audit text under a different number. The "
            "existence of a role is not a security property; a role granting "
            "backup:* to everyone satisfies it"),
    "1.6": ("AWS Backup uses a service-linked role", VACUOUS, (),
            "The audit says AWS creates the service-linked role automatically when "
            "it is needed and recreates it if deleted, so the condition is true of "
            "every account that has ever used the service"),

    # ── 2 Elastic Block Store ────────────────────────────────────────────────
    "2.1": ("An EC2 instance is launched with an attached EBS volume", VACUOUS, (),
            "A console walkthrough for launching an instance. Every running instance "
            "has a root volume, so the stated condition cannot be false. Rationale "
            "and Remediation are both empty"),
    "2.2": ("Security groups control inbound and outbound traffic", UNSAFE, (),
            "The audit procedure directs the reader to open SSH, HTTP and HTTPS and "
            "to allow traffic from anywhere. SEG-01 (world-open sensitive port), "
            "SEG-06 (world-open ingress plus unrestricted egress) and VPC-05 "
            "(world-open admin port on a NACL) all FAIL on that state, as does CIS "
            "Foundations. Not buildable in the direction the source states it"),
    "2.3": ("EBS storage is configured appropriately", NO_AUDIT, (),
            "Audit is empty. The Remediation underneath is a console walkthrough for "
            "creating, attaching, formatting and mounting a volume -- a procedure "
            "for building one, with no criterion for judging one"),
    "2.4": ("A data volume is encrypted with KMS and survives instance termination",
            COVERED, ("EBS-02", "EC2-17"),
            "Both halves are decided: EBS-02 FAILs an unencrypted volume, EC2-17 "
            "reports volumes set to delete on termination. This is the strongest "
            "recommendation in section 2 and the only one that names a real, "
            "checkable property of a volume"),
    "2.5": ("EBS snapshots exist and are encrypted", COVERED, ("EBS-03",),
            "EBS-03 decides encryption of the snapshots that exist. The audit also "
            "asks for a Data Lifecycle Manager policy and for snapshot recency; "
            "neither is read, and both are decidable from dlm:GetLifecyclePolicies "
            "and ec2:DescribeSnapshots"),
    "2.6": ("IAM roles and MFA govern EC2 access", ELSEWHERE, ("IAM-04", "IAMPE-01"),
            "Generic IAM, already Foundations territory. Nothing in it is about EBS"),
    "2.7": ("IAM users are created deliberately and their keys rotated", ELSEWHERE,
            ("IAM-06", "IAM-08"),
            "Generic IAM. IAM-06 decides stale keys and IAM-08 unused credentials"),
    "2.8": ("IAM groups carry the permissions rather than users", ELSEWHERE,
            ("IAMPE-01",),
            "Generic IAM, and an organisational preference rather than a state that "
            "is right or wrong"),
    "2.9": ("IAM policies are scoped to specific resources and actions", ELSEWHERE,
            ("IAMPE-01",),
            "Generic IAM. The privilege-escalation pillar decides over-broad grants "
            "against effective permissions rather than against policy text"),
    "2.10": ("Access is granted through tag-based conditions", ELSEWHERE,
             ("IAMPE-01",),
             "Generic IAM, and a design preference: a tag condition is one way to "
             "scope a policy, not a property every policy must have"),
    "2.11": ("An account password policy is enforced", ELSEWHERE, ("IAM-05",),
             "Generic IAM, decided by IAM-05 against the account password policy. "
             "Six of section 2's thirteen recommendations are IAM rather than EBS"),
    "2.12": ("CloudWatch alarms watch EC2 and EBS", NO_CHECK, (),
             "Decidable from cloudwatch:DescribeAlarms -- whether any alarm has an "
             "EBS or EC2 dimension. The CW-xx family covers CloudTrail metric "
             "filters for Foundations section 5 and reads nothing about volumes"),
    "2.13": ("An SNS subscription delivers alarm notifications to a human", NO_CHECK,
             (),
             "Decidable from sns:ListSubscriptionsByTopic -- an alarm wired to a "
             "topic with no confirmed subscription notifies nobody. The source "
             "describes creating a subscription; Rationale and Remediation are empty"),

    # ── 3 Elastic File System ────────────────────────────────────────────────
    "3.1": ("EFS is used as the file system", VACUOUS, (),
            "Choosing a managed service is not a control. The audit is a creation "
            "walkthrough"),
    "3.2": ("EFS data is encrypted at rest", COVERED, ("EFS-01",),
            "EFS-01 decides it. The source's own audit notes encryption is applied "
            "automatically at creation, which is true of the console default and not "
            "of the API, where --encrypted must be passed"),
    "3.3": ("Mount targets exist in every availability zone the VPC uses", NO_CHECK,
            (),
            "Decidable from elasticfilesystem:DescribeMountTargets against the "
            "VPC's subnets. A file system reachable from one AZ is a single point of "
            "failure for every workload in the others"),
    "3.4": ("Network access to EFS is controlled", NO_AUDIT, (),
            "Audit is empty; the Remediation is one sentence restating the title"),
    "3.5": ("Mount-target security groups restrict ingress", UNSAFE, (),
            "The audit directs the reader to restrict mount-target ingress to SSH on "
            "port 22 and to accept all egress. EFS mount targets serve NFS on 2049, "
            "so a group built to this instruction blocks every legitimate mount and "
            "admits nothing an attacker wants. Wrong in both directions at once"),
    "3.6": ("Only approved ports and protocols reach storage services", ELSEWHERE,
            ("SEG-01", "VPC-03", "VPC-05"),
            "An eight-step audit spanning security groups, NACLs, flow logs, IAM, "
            "CloudTrail, penetration testing, encryption in transit and staff "
            "training. The parts a scanner can decide are already decided by the "
            "segmentation and logging pillars"),
    "3.7": ("Mount targets act as the file-level access boundary", NO_AUDIT, (),
            "Audit is empty. The Remediation is one sentence restating the title"),
    "3.8": ("Mount-target security groups are reviewed and maintained", NO_CHECK, (),
            "Decidable from DescribeMountTargetSecurityGroups joined to the security "
            "group rules. The source's audit is console navigation with no criterion "
            "-- it says where to click, never what a correct answer looks like"),
    "3.9": ("EFS traffic uses an interface VPC endpoint", NO_CHECK, (),
            "Decidable from ec2:DescribeVpcEndpoints -- whether a VPC carrying EFS "
            "mount targets has an elasticfilesystem interface endpoint"),
    "3.10": ("EFS access points scope what a client may reach", NO_CHECK, (),
             "Decidable from DescribeAccessPoints: whether an access point enforces "
             "a POSIX user and a root directory, which is what makes it a boundary "
             "rather than a convenience"),
    "3.11": ("The file-system policy scopes access by access-point ARN", NO_CHECK,
             (),
             "The read already exists -- EFS-02 fetches the file-system policy to "
             "decide TLS enforcement -- so only the predicate is missing. A policy "
             "granting ClientMount to a principal with no AccessPointArn condition "
             "hands that principal the whole file system"),
    "3.12": ("IAM is configured for Elastic Disaster Recovery", ELSEWHERE,
             ("IAMPE-01",),
             "MISFILED: a disaster-recovery recommendation sitting in the EFS "
             "section, and a near-verbatim duplicate of 6.5. The same defect class "
             "as CIS-DB 5.8 and 5.9, which sit in ElastiCache and walk the Keyspaces "
             "console"),

    # ── 4 FSx ────────────────────────────────────────────────────────────────
    "4.1": ("Amazon File Cache provides high-speed access to remote data", NO_AUDIT,
            (),
            "Audit is empty. The body describes what the service is and what it may "
            "be linked to"),
    "4.2": ("File Cache is available in the region and the OS is compatible",
            VACUOUS, (),
            "A list of regions and a list of supported Linux distributions. Neither "
            "is a property of an account, and both are stale the moment AWS adds a "
            "region"),
    "4.3": ("The S3 bucket backing the cache blocks public access and is versioned",
            ELSEWHERE, ("S3-01", "S3-08", "S3-09"),
            "Already decided for every bucket in the account, not just this one. "
            "S3-01 reads account Block Public Access, S3-09 a public bucket policy, "
            "S3-08 versioning"),
    "4.4": ("The cache encrypts data at rest with a KMS key", NO_CHECK, (),
            "The one genuinely new, genuinely decidable thing section 4 asks for. "
            "fsx:DescribeFileCaches and fsx:DescribeFileSystems both return "
            "KmsKeyId, so whether a cache is on an AWS-owned key or a customer key "
            "is a plain read. OverWatch has no FSx section at all today"),
    "4.5": ("The Lustre client is installed on the compute instance", BLOCKED, (),
            "An installed package inside the instance"),
    "4.6": ("The instance kernel is one the Lustre client supports", BLOCKED, (),
            "The running kernel inside the instance. A disk image would show what is "
            "configured to boot, not what is running"),
    "4.7": ("The cache is mounted at the expected path", BLOCKED, (),
            "The mount table inside the instance"),
    "4.8": ("A file written to the mount is archived out to S3", BLOCKED, (),
            "Requires writing a file inside the instance and observing the result. "
            "The source's reference for this step points at ElastiCache backup "
            "documentation rather than FSx, and its command is 'lsm hsm_archive' "
            "where the Lustre command is 'lfs hsm_archive'"),
    "4.9": ("FSx resources created for the walkthrough are deleted", PROCESS, (),
            "Cleaning up the tutorial's own resources. Section 4 creates a cache, "
            "installs a client, downgrades a kernel, mounts, writes a test file and "
            "then deletes it all; this is the last step of that sequence rather than "
            "a control over an estate"),

    # ── 5 Simple Storage Service ─────────────────────────────────────────────
    "5.1": ("S3 stores objects in buckets and access is denied by default", VACUOUS,
            (),
            "A description of how the service works. OverWatch carries eight S3 "
            "checks against this section's three recommendations"),
    "5.2": ("Access points are reviewed for public or cross-account exposure",
            ELSEWHERE, ("S3-09", "S3-10", "IAM-10"),
            "The exposure the audit is reaching for is decided at bucket level by "
            "S3-09 and S3-10, and IAM-10 decides whether Access Analyzer -- the tool "
            "the audit names -- is switched on at all. Access-point-level policies "
            "specifically are not read"),
    "5.3": ("Storage classes match the access pattern", NO_AUDIT, (),
            "Audit and Remediation are both empty, and the subject is cost and "
            "latency rather than security. Its CIS Controls mapping is to DMARC"),

    # ── 6 Elastic Disaster Recovery ──────────────────────────────────────────
    "6.1": ("Replication is enabled and healthy for the servers that matter",
            COVERED, ("DRS-03",),
            "The audit's second step -- confirm backups are enabled for all critical "
            "servers -- is the one testable claim in a six-part procedure whose "
            "other parts are plan review, drills, RTO/RPO comparison and compliance "
            "documentation. DRS-03 decides it from the replication state"),
    "6.2": ("The DRS network path is understood", NO_AUDIT, (),
            "Rationale, Audit and Remediation are all three empty. The body is a "
            "prose description of ports and subnets"),
    "6.3": ("Endpoint detection and response is effective", DECLINED, (),
            "The title and description are about ENDPOINT detection and response -- "
            "threat detection, zero-day exploits, malware. The audit steps beneath "
            "them are disaster-recovery replication setup. Two unrelated "
            "technologies under one number, because the document abbreviates Elastic "
            "Disaster Recovery as EDR (and elsewhere as DRS, and elsewhere again as "
            "EDS). Implementing either reading would misrepresent the other"),
    "6.4": ("Replication staging volumes are encrypted and traffic stays private",
            COVERED, ("DRS-01", "DRS-02"),
            "The best recommendation in the document. Both halves are real settings "
            "on the replication configuration template: ebsEncryption carries a "
            "genuine NONE value, and dataPlaneRouting decides whether replication "
            "crosses the public internet, which the source itself warns against"),
    "6.5": ("IAM users exist for the replication and failback agents", ELSEWHERE,
            ("IAMPE-01",),
            "Duplicate of 3.12. Creating a user with an AWS managed policy attached "
            "is a setup step; whether the resulting grants are over-broad is the "
            "CIEM question"),
    "6.6": ("The replication agent is installed on the source server", BLOCKED, (),
            "An installed agent inside the source server. DRS reports an "
            "agentVersion once a server is registered, but a server that never had "
            "the agent installed does not appear in DRS at all -- so the absence "
            "this recommendation is about is exactly what the control plane cannot "
            "see"),
    "6.7": ("Launch settings produce a usable recovery instance", NO_CHECK, (),
            "Decidable from drs:DescribeLaunchConfigurationTemplates. Recorded as a "
            "gap rather than built, because the obvious finding contradicts the "
            "document: the audit tells the reader to enable auto-assign public IP, "
            "and 6.11 then lists a public IP on the recovery instance as a failback "
            "PREREQUISITE. Flagging it would flag a documented requirement"),
    "6.8": ("A recovery drill has actually been run", COVERED, ("DRS-04",),
            "lastLaunchResult carries NOT_STARTED until a drill or a real recovery "
            "has been launched, so 'never tested' is a plain read rather than an "
            "inference. A DR capability nobody has exercised is a plan, not a "
            "capability"),
    "6.9": ("Disaster recovery is operated continuously", PROCESS, (),
            "A nine-part audit: plan review, backup settings, drills, log review, "
            "RTO/RPO evaluation, access review, compliance, post-mortems and "
            "training cadence. DRS-03 and DRS-04 decide the two configuration parts; "
            "the rest is a programme, not a setting"),
    "6.10": ("A failover has been executed", PROCESS, (),
             "An action performed by an operator, not a state an account holds. "
             "DRS-04 reads the closest observable -- whether any launch has ever "
             "succeeded -- and is already claimed by 6.8, which asks it directly"),
    "6.11": ("A failback has been executed", PROCESS, (),
             "An action, like 6.10, and one that requires booting an ISO on the "
             "original server. Nothing in the control plane records that it went "
             "well"),
    "6.12": ("CloudWatch alarms and dashboards watch the DRS service", NO_CHECK, (),
             "Decidable from cloudwatch:DescribeAlarms for alarms carrying a DRS "
             "dimension. Same shape as 2.12, and unbuilt for the same reason"),
    "6.13": ("DRS works", DECLINED, (),
             "Description, Rationale and Remediation are all empty, and the audit "
             "steps are the same steps printed under 6.3. Nothing distinguishes it "
             "from that recommendation, so implementing it would double-count one "
             "control under two numbers"),
}


def checks_for(recommendation: str) -> Tuple[str, ...]:
    """The checks named against one recommendation, or () if none."""
    row = RECOMMENDATIONS.get(recommendation)
    return row[2] if row else ()


def by_verdict(verdict: str) -> Tuple[str, ...]:
    """Every recommendation carrying one verdict, in numeric order."""
    return tuple(sorted(
        (rec for rec, row in RECOMMENDATIONS.items() if row[1] == verdict),
        key=lambda r: tuple(int(p) for p in r.split(".")),
    ))


def recommendation_for(check_id: str) -> str:
    """The one recommendation a check calls home, or '' if it answers none.

    Same precedence rule as the Database mapping, for the same reason: a check can be
    named against several recommendations and only one of them belongs in
    COMPLIANCE_MAP, so the choice is made by a stated rule rather than by dict order.

      1. the recommendation in the check's OWN service section;
      2. a verdict of COVERED over any weaker one;
      3. the entry where the check is listed FIRST, i.e. is the primary answer;
      4. failing all of that, the lowest recommendation number.
    """
    fam = check_id.rsplit("-", 1)[0]
    own = FAMILY_SECTION.get(fam, "")
    candidates = []
    for rec, (_label, verdict, checks, _note) in RECOMMENDATIONS.items():
        if check_id in checks:
            candidates.append((
                0 if rec.split(".", 1)[0] == own else 1,
                0 if verdict == COVERED else 1,
                checks.index(check_id),
                tuple(int(p) for p in rec.split(".")),
                rec,
            ))
    return min(candidates)[-1] if candidates else ""
