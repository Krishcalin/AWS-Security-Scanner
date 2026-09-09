#!/usr/bin/env python3
"""aws_cis_db_map.py — the CIS AWS Database Services Benchmark v2.0.0 mapping, as DATA.

All 98 recommendations across the benchmark's ten services, and what OverWatch does about
each one. This is the join `docs/CIS_DATABASE_INVENTORY.md` was built as the left-hand
column of, and `scripts/cis_db_benchmark.py` renders it into `docs/CIS_DATABASE_BENCHMARK.md`.

WHY THIS IS DATA AND NOT A HAND-WRITTEN TABLE. A 98-row mapping typed into a markdown file
sits next to a catalogue that moves, and stops being true the first time a check is
renamed. Holding it as data lets `tests/test_cis_db_mapping.py` assert the properties that
make it worth trusting: every check id named here exists in the catalogue, every
recommendation appears exactly once, the numbering is complete and gap-free per section,
and — the one that matters most — the CIS-DB compliance keys in
`aws_live_scanner.COMPLIANCE_MAP` agree with this table in BOTH directions. A mapping that
can disagree with the thing it maps is worse than no mapping, because it is quoted in
audit conversations.

ON THE SOURCE DOCUMENT. CIS Benchmarks may not be redistributed, and the PDF is
deliberately not in this repository. What is recorded below is the recommendation NUMBER,
which is a reference, and a SHORT LABEL WRITTEN FROM THE UNDERLYING AWS BEHAVIOUR. No
rationale, audit, impact or remediation text is copied from the benchmark; the reasons and
descriptions here are this project's own, written from what the AWS API actually exposes.

WHY `CIS-DB` AND NOT `CIS`. Exactly the reason `CIS-COMPUTE` exists. 123 checks already
carry a `CIS` key and every one is CIS AWS *Foundations* numbering. This benchmark reuses
the same section numbers for unrelated controls — Foundations 2.2 is about CloudTrail
log-file validation, Database 2.2 is Aurora encryption at rest — so folding them together
would silently mis-cite every mapping in both directions.
"""
from __future__ import annotations

from typing import Dict, Tuple

__all__ = [
    "COVERED", "PARTIAL", "ELSEWHERE", "NO_CHECK", "DECLINED", "PROCESS", "VACUOUS",
    "VERDICTS", "RECOMMENDATIONS", "SECTIONS", "checks_for", "recommendation_for",
]

# ─── verdicts ────────────────────────────────────────────────────────────────
#: A named check decides this recommendation and can FAIL on it.
COVERED = "covered"
#: A check reads the setting but cannot FAIL on it — it PASSes or WARNs. Real coverage of
#: the *observation*, not of the *finding*: a check that cannot fail can never tell an
#: operator they are non-compliant, so it is never counted as covered.
PARTIAL = "partial"
#: Decided, but by a check outside this benchmark's services (segmentation, CloudTrail,
#: IAM) or — in two cases — by the wrong check entirely. See the instance-filter defect.
ELSEWHERE = "elsewhere"
#: Decidable from the control plane, not currently checked. These are the real backlog.
NO_CHECK = "gap"
#: Deliberately not built, with the reason recorded in aws_cis_db.NOT_DETERMINABLE or
#: DECLINED_AS_NOT_A_FINDING.
DECLINED = "declined"
#: Asks about a human process — a review cadence, a design exercise, a procurement
#: decision. No API read can decide it, and inventing a check would be theatre.
PROCESS = "process"
#: True of every modern account by construction, so a check would pass universally and
#: measure nothing. Named rather than silently skipped.
VACUOUS = "vacuous"

VERDICTS = (COVERED, PARTIAL, ELSEWHERE, NO_CHECK, DECLINED, PROCESS, VACUOUS)

SECTIONS: Tuple[Tuple[str, str, int], ...] = (
    ("2", "Amazon Aurora", 11),
    ("3", "Amazon RDS", 14),
    ("4", "Amazon DynamoDB", 9),
    ("5", "Amazon ElastiCache", 13),
    ("6", "Amazon MemoryDB for Redis", 7),
    ("7", "Amazon DocumentDB", 12),
    ("8", "Amazon Keyspaces", 4),
    ("9", "Amazon Neptune", 11),
    ("10", "Amazon Timestream", 10),
    ("11", "Amazon QLDB", 7),
)

#: number -> (label, verdict, checks, note). The label is this project's own one-line
#: description of the control, not the benchmark's title.
RECOMMENDATIONS: Dict[str, Tuple[str, str, Tuple[str, ...], str]] = {

    # ── 2 Aurora ─────────────────────────────────────────────────────────────
    "2.1": ("A security group is attached to the cluster", VACUOUS, (),
            "AWS attaches the VPC default security group when none is named, so 'at "
            "least one is attached' is true of every cluster that exists. What the "
            "control is reaching for -- restrictive rules -- is decided by the "
            "segmentation pillar and by RDS-02"),
    "2.2": ("Cluster storage and its snapshots encrypted at rest", COVERED,
            ("AUR-01", "AUR-05"),
            "AUR-01 reads the cluster; AUR-05 reads manual snapshots, which outlive the "
            "cluster and are the copy that actually leaves production"),
    "2.3": ("Non-TLS client connections refused by the engine", COVERED, ("AUR-06",),
            "The distinction this recommendation draws -- that the database must REFUSE "
            "cleartext, not merely offer TLS -- is why AUR-06 reads the cluster "
            "parameter group rather than a boolean on the cluster"),
    "2.4": ("An IAM role exists for managing the cluster", PROCESS, (),
            "The existence of a role is not a security property: a role granting "
            "rds:* to everyone satisfies it. Whether the roles that DO exist are "
            "over-privileged is the CIEM pillar's question, not a per-cluster one"),
    "2.5": ("Database activity is recorded", PARTIAL, ("RDS-05",),
            "RDS-05 reads log exports and enhanced monitoring on instances and reports "
            "them, but never FAILs -- so it observes this rather than enforcing it. "
            "There is no Aurora cluster-level Database Activity Streams check"),
    "2.6": ("Master passwords rotated on a schedule", PROCESS, (),
            "No RDS API returns when a master password was last changed, so rotation "
            "cadence cannot be read at all. AUR-08 answers the stronger form of the "
            "same concern by removing the static password from the loop"),
    "2.7": ("Least privilege inside the database", PROCESS, (),
            "GRANTs live inside the engine and are reachable only by connecting and "
            "querying, which is a data-plane read this product does not do"),
    "2.8": ("Automated backups enabled with a retention period", COVERED, ("AUR-07",),
            "AUR-07 fails below 7 days rather than at 0, because an Aurora cluster's "
            "minimum retention is 1 -- so a literal 'backups off' state is unreachable "
            "and checking for it would be a check that can never fire"),
    "2.9": ("Cluster instances not publicly accessible", ELSEWHERE, ("RDS-02",),
            "Aurora members are returned by rds:DescribeDBInstances, so RDS-02 does "
            "decide this -- correctly, since Aurora IS RDS here"),
    "2.10": ("IAM database authentication enabled", COVERED, ("AUR-08",),
             "AUR-08 stays silent on engines that do not offer IAM auth rather than "
             "failing them for lacking a feature they cannot have"),
    "2.11": ("Deletion protection enabled", COVERED, ("AUR-02",), ""),

    # ── 3 RDS ────────────────────────────────────────────────────────────────
    "3.1": ("Choose an appropriate engine", PROCESS, (),
            "A procurement decision. The benchmark ships this one with its Description "
            "and Rationale fields empty, which is a fair summary of how much of it is "
            "a technical control"),
    "3.2": ("Choose single-AZ or Multi-AZ deliberately", PARTIAL, ("RDS-03",),
            "The recommendation says outright that either answer can be correct, so "
            "there is nothing to fail. RDS-03 reads MultiAZ and reports it as PASS or "
            "WARN and never FAIL, which is the right shape for a control whose own "
            "text declines to prefer an answer"),
    "3.3": ("The instance is in a VPC", VACUOUS, (),
            "EC2-Classic is gone; every RDS instance created today is in a VPC"),
    "3.4": ("Security groups configured", VACUOUS, (), "As 2.1"),
    "3.5": ("Storage and snapshots encrypted at rest", COVERED, ("RDS-01", "RDS-11"),
            ""),
    "3.6": ("Non-TLS client connections refused by the engine", COVERED, ("RDS-14",),
            "The benchmark's own audit text for this one describes an 'Encryption in "
            "Transit' console section and ACM certificate options that RDS does not "
            "present. RDS-14 implements the enforceable reading -- the engine "
            "parameter -- which is what 2.3 asks for on the Aurora side"),
    "3.7": ("Access control and authentication implemented", PARTIAL, ("RDS-08",),
            "3.13 asks the same question in a decidable form, and RDS-08 answers it. "
            "This one's audit text walks a 'Users' menu the RDS console does not have"),
    "3.8": ("Engine patched and supported", COVERED, ("RDS-12", "RDS-04"),
            "RDS-12 fails an engine past standard support; RDS-04 fails when automatic "
            "minor version upgrades are off, which is how patches arrive at all"),
    "3.9": ("Monitoring and logging enabled", PARTIAL, ("RDS-05",),
            "Observed, never failed -- see 2.5"),
    "3.10": ("Automated backups enabled", COVERED, ("RDS-03",), ""),
    "3.11": ("Security configuration reviewed regularly", PROCESS, (),
             "A cadence, not a state. This product is a way of doing it, not a thing "
             "it can check"),
    "3.12": ("Instance not publicly accessible", COVERED, ("RDS-02",), ""),
    "3.13": ("IAM database authentication enabled", COVERED, ("RDS-08",),
             "The benchmark audits this with rds:DescribeDBClusters, which returns "
             "nothing for the standalone instances that make up most RDS estates. "
             "RDS-08 reads the instance, where the flag actually lives"),
    "3.14": ("Deletion protection enabled", COVERED, ("RDS-04",),
             "Same cluster-versus-instance defect in the benchmark's audit text as 3.13"),

    # ── 4 DynamoDB ───────────────────────────────────────────────────────────
    "4.1": ("Access to tables controlled by IAM", COVERED, ("DDB-05",),
            "Read as its contrapositive, which is the decidable half: DDB-05 fails a "
            "table whose RESOURCE policy grants a wildcard principal, because such a "
            "table is reachable without the IAM control this recommendation assumes"),
    "4.2": ("Fine-grained (item- and attribute-level) access control", NO_CHECK, (),
            "Decidable in principle by reading dynamodb:LeadingKeys and "
            "dynamodb:Attributes conditions out of attached policies, which the "
            "effective-permissions engine already parses. Not built"),
    "4.3": ("Encryption at rest", PARTIAL, ("DDB-01",),
            "DynamoDB is encrypted at rest unconditionally, so the recommendation as "
            "literally stated cannot fail. The only decidable question left is key "
            "ownership, and DDB-01 reports that as PASS or WARN"),
    "4.4": ("Encryption in transit", VACUOUS, (),
            "The DynamoDB endpoint is HTTPS-only and the SDKs offer no cleartext "
            "option. There is no setting to read"),
    "4.5": ("VPC endpoints configured", NO_CHECK, (),
            "Decidable from ec2:DescribeVpcEndpoints. Not built, and worth noting it "
            "is a routing preference rather than an access control -- the gateway "
            "endpoint keeps traffic off the internet but grants nothing"),
    "4.6": ("Streams and Lambda wired up for compliance checking", PROCESS, (),
            "A recommendation to build a bespoke compliance pipeline, not a "
            "configuration of the table. An estate that runs this product has already "
            "answered the underlying need"),
    "4.7": ("Activity monitored and audited", ELSEWHERE, (),
            "CloudTrail data events for DynamoDB are decided by the logging pillar, "
            "which reads the trail rather than the table"),
    "4.8": ("Deletion protection enabled", COVERED, ("DDB-04",), ""),
    "4.9": ("Point-in-time recovery or scheduled backups", COVERED, ("DDB-02",),
            "DDB-02 decides PITR. The AWS Backup half of the recommendation is the "
            "backup pillar's territory"),

    # ── 5 ElastiCache ────────────────────────────────────────────────────────
    "5.1": ("Access to the cache authenticated and restricted", COVERED,
            ("ELC-03", "ELC-06"),
            "ELC-03 fails a group with no AUTH token at all; ELC-06 fails one that has "
            "a token but no RBAC user group, where a single leaked secret is total "
            "access"),
    "5.2": ("Network security configured", ELSEWHERE, (),
            "Security groups and NACLs are the segmentation pillar's subject"),
    "5.3": ("Encryption at rest and in transit", COVERED, ("ELC-01", "ELC-02"), ""),
    "5.4": ("Engine kept patched", COVERED, ("ELC-05",),
            "ELC-05 fails an end-of-life engine. The recommendation asks for the "
            "AutoMinorVersionUpgrade flag, which for ElastiCache Redis AWS applies "
            "regardless of its value -- so the flag is a weaker question than the one "
            "ELC-05 answers"),
    "5.5": ("The cluster is in a VPC", VACUOUS, (), "As 3.3"),
    "5.6": ("Monitoring and logging enabled", NO_CHECK, (),
            "Decidable from the LogDeliveryConfigurations on the replication group. "
            "Not built"),
    "5.7": ("Security configuration reviewed regularly", PROCESS, (),
            "Shares its title verbatim with 5.10 -- see the defects section"),
    "5.8": ("Authentication and access control", NO_CHECK, (),
            "MISFILED IN THE BENCHMARK: filed under ElastiCache, but its audit steps "
            "walk the Amazon Keyspaces console. Read as an ElastiCache control the "
            "intent duplicates 5.1, which ELC-03 and ELC-06 decide"),
    "5.9": ("Audit logging enabled", NO_CHECK, (),
            "MISFILED IN THE BENCHMARK: the audit steps walk the Keyspaces console"),
    "5.10": ("Security configuration reviewed regularly", PROCESS, (),
             "MISFILED IN THE BENCHMARK, and a duplicate of 5.7's title"),
    "5.11": ("Cluster mode enabled", DECLINED, (),
             "Readable, and judged not a security defect: cluster mode is a scaling and "
             "sharding decision. Recorded in DECLINED_AS_NOT_A_FINDING"),
    "5.12": ("Deployed across multiple availability zones", COVERED,
             ("ELC-08", "ELC-04"),
             "ELC-08 reads MultiAZ; ELC-04 reads automatic failover, which the "
             "recommendation's own remediation names as a prerequisite -- Multi-AZ "
             "without failover has nowhere to fail over to"),
    "5.13": ("Automatic backups enabled", COVERED, ("ELC-07",),
             "Memcached cannot take snapshots at all, so this recommendation is "
             "unsatisfiable for a Memcached cluster -- see the defects section"),

    # ── 6 MemoryDB ───────────────────────────────────────────────────────────
    "6.1": ("Network security configured", ELSEWHERE, (), "As 5.2"),
    "6.2": ("Data at rest and in transit encrypted", COVERED, ("MDB-01", "MDB-04"),
            "MDB-01 is the in-transit half and is a genuine failure state. The at-rest "
            "half cannot fail -- MemoryDB always encrypts -- so MDB-04 reports key "
            "ownership instead, at LOW"),
    "6.3": ("Authentication and access control", COVERED, ("MDB-02",),
            "The strongest match in this benchmark. MemoryDB ships a passwordless ACL "
            "user by default, and MDB-02 reads Authentication.Type directly -- an "
            "observation, not an inference"),
    "6.4": ("Audit logging enabled", NO_CHECK, (),
            "Decidable from the cluster's SNS and log-delivery configuration. "
            "Not built"),
    "6.5": ("Security configuration reviewed regularly", PROCESS, (), ""),
    "6.6": ("Monitoring and alerting enabled", NO_CHECK, (), "As 6.4"),
    "6.7": ("Automatic backups enabled", COVERED, ("MDB-03",), ""),

    # ── 7 DocumentDB ─────────────────────────────────────────────────────────
    "7.1": ("Network architecture planned", PROCESS, (),
            "A design exercise. There is no state to read"),
    "7.2": ("VPC security configured", ELSEWHERE, (), "As 5.2"),
    "7.3": ("Encryption at rest", COVERED, ("DOCDB-02", "DOCDB-05"),
            "The benchmark's remediation for this one describes enabling encryption on "
            "an existing cluster, which DocumentDB does not permit -- see the defects "
            "section"),
    "7.4": ("Non-TLS client connections refused by the engine", COVERED, ("DOCDB-06",),
            "DocumentDB spells this as the `tls` cluster parameter"),
    "7.5": ("Access control and authentication", PROCESS, (),
            "DocumentDB users live inside the engine, reachable only by connecting"),
    "7.6": ("Audit logging enabled", COVERED, ("DOCDB-03",), ""),
    "7.7": ("Engine kept patched", NO_CHECK, (),
            "Decidable the same way ELC-05 and RDS-12 are, from the engine version. "
            "Not built for DocumentDB"),
    "7.8": ("Monitoring and alerting implemented", NO_CHECK, (), "As 6.4"),
    "7.9": ("Backup and disaster recovery implemented", NO_CHECK, (),
            "A real gap, and the most substantive one in this benchmark: "
            "BackupRetentionPeriod is right there on the DocumentDB cluster and "
            "nothing reads it. AUR-07 does exactly this for Aurora"),
    "7.10": ("A backup window is configured", PROCESS, (),
             "A window always exists -- AWS assigns one. Choosing a quiet one is an "
             "operational preference, not a security state"),
    "7.11": ("Security assessments conducted", PROCESS, (),
             "This product is a way of doing it"),
    "7.12": ("Deletion protection enabled", COVERED, ("DOCDB-04",), ""),

    # ── 8 Keyspaces ──────────────────────────────────────────────────────────
    "8.1": ("Keyspace security configured", DECLINED, (),
            "All four Keyspaces controls are declined together: the service authorises "
            "its control-plane reads under cassandra:Select, the same action that reads "
            "table rows, and AWS offers no metadata-only alternative"),
    "8.2": ("Network security configured", DECLINED, (), "As 8.1"),
    "8.3": ("Data at rest and in transit encrypted", DECLINED, (),
            "Was built as KS-02 and withdrawn -- encryptionSpecification.type is a "
            "plain enum, so this is a decision about the GRANT, not about feasibility"),
    "8.4": ("Point-in-time recovery enabled", DECLINED, (),
            "Was built as KS-01 and withdrawn. PITR is the ONLY backup Keyspaces "
            "offers, which makes the decline genuinely costly and worth revisiting "
            "behind an opt-in permission block"),

    # ── 9 Neptune ────────────────────────────────────────────────────────────
    "9.1": ("Network security configured", ELSEWHERE, (), "As 5.2"),
    "9.2": ("Cluster storage and snapshots encrypted at rest", COVERED,
            ("NEP-01", "NEP-04"), ""),
    "9.3": ("Non-TLS client connections refused by the engine", COVERED, ("NEP-05",),
            "Neptune spells this as the `neptune_enforce_ssl` cluster parameter"),
    "9.4": ("IAM database authentication enabled", NO_CHECK, (),
            "A real gap: IAMDatabaseAuthenticationEnabled is on the Neptune cluster and "
            "nothing reads it. AUR-08 does exactly this for Aurora"),
    "9.5": ("Audit logging enabled", NO_CHECK, (),
            "Decidable from EnabledCloudwatchLogsExports. DOCDB-03 does exactly this "
            "for DocumentDB"),
    "9.6": ("Security configuration reviewed regularly", PROCESS, (), ""),
    "9.7": ("Monitoring and alerting enabled", NO_CHECK, (), "As 6.4"),
    "9.8": ("Instances not publicly accessible", ELSEWHERE, ("RDS-02",),
            "Decided, but under the WRONG ID. Neptune instances are returned by "
            "rds:DescribeDBInstances, so RDS-02 fires on them and reports a Neptune "
            "exposure as an RDS finding with RDS remediation. See the defects section"),
    "9.9": ("Automated backups enabled", ELSEWHERE, ("RDS-03",),
            "Same defect as 9.8: RDS-03 reads the Neptune instance's retention period "
            "and reports it as an RDS finding"),
    "9.10": ("Deletion protection enabled", COVERED, ("NEP-02",), ""),
    "9.11": ("Deployed across multiple availability zones", NO_CHECK, (),
             "Decidable from the cluster's MultiAZ field. ELC-08 and MDB-06 do exactly "
             "this for their services"),

    # ── 10 Timestream ────────────────────────────────────────────────────────
    "10.1": ("Data ingestion path secured", COVERED, ("TS-02", "TS-01"),
             "TS-02 fails a table whose magnetic-store writes are on with nowhere for "
             "rejected records to go, so failures vanish silently; TS-01 fails when "
             "the bucket they DO go to is not under a KMS key"),
    "10.2": ("Data at rest encrypted", DECLINED, (),
             "Timestream always encrypts, and the API cannot distinguish a "
             "customer-managed key from the AWS-managed one -- both return a KmsKeyId "
             "of the same shape. Recorded in NOT_DETERMINABLE"),
    "10.3": ("Encryption in transit", VACUOUS, (), "HTTPS-only endpoint, as 4.4"),
    "10.4": ("Access control and authentication", ELSEWHERE, (),
             "IAM policy quality is the CIEM pillar's subject"),
    "10.5": ("Fine-grained access control", NO_CHECK, (), "As 4.2"),
    "10.6": ("Audit logging enabled", ELSEWHERE, (), "CloudTrail, as 4.7"),
    "10.7": ("Updates and patches installed", VACUOUS, (),
             "Timestream is serverless. There is no engine version to be behind on, "
             "and the recommendation's own audit text is a patch-management process "
             "for a thing the customer does not run"),
    "10.8": ("Monitoring and alerting enabled", NO_CHECK, (), "As 6.4"),
    "10.9": ("Security configuration reviewed and updated", PROCESS, (), ""),
    "10.10": ("Automated backups enabled via AWS Backup", NO_CHECK, (),
              "Decidable by resolving AWS Backup selections to table ARNs. The "
              "recommendation carries leftover PITR text from a neighbouring control "
              "-- see the defects section"),

    # ── 11 QLDB ──────────────────────────────────────────────────────────────
    "11.1": ("IAM implemented for the ledger", DECLINED,  (),
             "All seven QLDB controls are declined on the same evidence: the pinned "
             "botocore ships NO service model for qldb, so boto3 cannot construct a "
             "client and none of section 11 is buildable"),
    "11.2": ("Network access secured", DECLINED, (), "As 11.1"),
    "11.3": ("Data at rest encrypted", DECLINED, (), "As 11.1"),
    "11.4": ("Data in transit encrypted", DECLINED, (), "As 11.1"),
    "11.5": ("Access control and authentication implemented", DECLINED, (), "As 11.1"),
    "11.6": ("Monitoring and logging enabled", DECLINED, (), "As 11.1"),
    "11.7": ("Backup and recovery enabled", DECLINED, (), "As 11.1"),
}


def checks_for(rec: str) -> Tuple[str, ...]:
    """The check ids that answer one recommendation, in the order they were listed."""
    entry = RECOMMENDATIONS.get(rec)
    return entry[2] if entry else ()


#: check family -> the benchmark section that owns that service. Used to pick a check's
#: HOME recommendation when it is named against several.
FAMILY_SECTION: Dict[str, str] = {
    "AUR": "2", "RDS": "3", "DDB": "4", "ELC": "5", "MDB": "6",
    "DOCDB": "7", "KS": "8", "NEP": "9", "TS": "10", "QLDB": "11",
}


def recommendation_for(check_id: str) -> str:
    """The one recommendation a check calls home, or '' if it answers none.

    A check can legitimately be named against several: RDS-02 decides 3.12, and is also
    what incidentally decides Neptune's 9.8. Only one of those belongs in COMPLIANCE_MAP,
    so the choice is made by a stated rule rather than by listing order, in this
    precedence:

      1. the recommendation in the check's OWN service section — RDS-02 is an RDS check,
         so 3.12 beats 2.9 and 9.8;
      2. a verdict of COVERED over any weaker one — RDS-03 fully answers 3.10 and only
         partly answers 3.2;
      3. the entry where the check is listed FIRST, i.e. is the primary answer rather
         than a supporting one — RDS-04 leads 3.14 and merely supports 3.8;
      4. failing all of that, the lowest recommendation number.

    Ties are broken deterministically at every step, so this never depends on dict order.
    """
    fam = check_id.rsplit("-", 1)[0]
    own = FAMILY_SECTION.get(fam, "")
    candidates = []
    for rec, (_label, verdict, checks, _note) in RECOMMENDATIONS.items():
        if check_id in checks:
            candidates.append((
                0 if rec.split(".", 1)[0] == own else 1,   # 1. own section first
                0 if verdict == COVERED else 1,            # 2. covered beats partial
                checks.index(check_id),                    # 3. primary beats supporting
                tuple(int(p) for p in rec.split(".")),     # 4. lowest number
                rec,
            ))
    return min(candidates)[-1] if candidates else ""
