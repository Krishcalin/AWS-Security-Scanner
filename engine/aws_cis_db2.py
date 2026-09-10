#!/usr/bin/env python3
"""aws_cis_db2.py — tranche 2 of the CIS AWS Database Services Benchmark v2.0.0 mapping:
the gaps tranche 1 recorded, closed or correctly reclassified.

WHY A SECOND MODULE RATHER THAN MORE OF THE FIRST. ``aws_cis_db.py`` is the tranche-1
module and is 246 lines of pure rules plus two decline registers. Adding nine CheckDefs to
it would make the registers hard to find inside a file three times the size, and the repo
already uses numbered siblings (``aws_extsvc2``..``aws_extsvc7``) for exactly this. The two
are read together; the mapping in ``aws_cis_db_map.py`` is the join.

WHAT TRANCHE 1 LEFT, AND WHAT ACTUALLY HAPPENED TO IT. Thirteen recommendations were
recorded as ``gap`` — decidable in principle, not built. Working through them against the
source document and against the **shipped botocore models** turned four of the thirteen
into something else, and that is the more useful half of this tranche:

  * **5.8 and 5.9 are misfiled and unbuildable.** Both sit in section 5 (ElastiCache) and
    both walk the Amazon **Keyspaces** console. Read charitably as Keyspaces controls they
    run straight into a decision this product already made and recorded: Keyspaces
    authorises its control-plane reads under ``cassandra:Select``, the same action that
    reads table rows, so covering it would put a customer-data read in the default
    scanning role. Declined, not deferred.
  * **6.4 is not exposed by the SDK.** MemoryDB audit logging is configurable in the
    console, and the pinned botocore model has no log-delivery member on ``Cluster`` and
    no log-delivery shape anywhere in the service. A check would have to read a field AWS
    does not return.
  * **10.8 is a process control.** Its audit reads "Define Monitoring Objectives" and
    "Choose Monitoring Tools". There is no Timestream setting to inspect: CloudWatch
    metrics are emitted unconditionally and are not configurable per table.

That leaves nine, all built here, all verified against the models the product ships.
Checking the model rather than assuming caught a real error before it shipped: MemoryDB's
member is ``SnsTopicArn``, not ``SNSTopicArn``, and a check written to the obvious spelling
would have read ``None`` on every cluster and failed all of them.

ON THE SOURCE DOCUMENT. CIS Benchmarks may not be redistributed, so the PDF is not in this
repository and no title, rationale, audit, impact or remediation prose is copied from it.
What is cited is the recommendation NUMBER, which is a reference; every description here is
written from the underlying AWS behaviour.

Pure. No boto3, no network, no I/O. The scanner passes in what it already fetched.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set

from engine import aws_checkdef as _cd
from engine.aws_checkdef import CheckDef as _C, Perm as _P

__all__ = [
    "dynamodb_fine_grained_access", "dynamodb_vpc_endpoint",
    "elasticache_log_delivery", "memorydb_notifications",
    "docdb_pending_maintenance", "cluster_event_subscription",
    "timestream_fine_grained_access", "timestream_backup_coverage",
    "DDB_DATA_ACTIONS", "TIMESTREAM_DATA_ACTIONS", "FGAC_CONDITION_KEYS",
    "CHECKS",
]

#: The DynamoDB actions that read or write ITEMS, as opposed to managing tables. These are
#: the ones 4.2's conditions constrain; a grant of dynamodb:DescribeTable is metadata and
#: is not what fine-grained access control is about.
DDB_DATA_ACTIONS = frozenset({
    "dynamodb:getitem", "dynamodb:batchgetitem", "dynamodb:query", "dynamodb:scan",
    "dynamodb:putitem", "dynamodb:updateitem", "dynamodb:deleteitem",
    "dynamodb:batchwriteitem", "dynamodb:partiqlselect", "dynamodb:partiqlinsert",
    "dynamodb:partiqlupdate", "dynamodb:partiqldelete",
})

#: The Timestream equivalents. Timestream splits read and write across two API prefixes,
#: which is why both appear.
TIMESTREAM_DATA_ACTIONS = frozenset({
    "timestream:select", "timestream:selectvalues", "timestream:writerecords",
    "timestream:describetable", "timestream:listmeasures",
})

#: The condition keys that make a grant fine-grained rather than table-wide. Lower-cased,
#: because IAM condition keys are matched case-insensitively and a policy written
#: ``dynamodb:leadingkeys`` is valid and equivalent.
FGAC_CONDITION_KEYS = frozenset({
    "dynamodb:leadingkeys", "dynamodb:attributes", "dynamodb:select",
    "timestream:selectvalues",
})

#: A resource ARN that reaches every table in the account. ``arn:aws:dynamodb:*:*:table/*``
#: and a bare ``*`` are the same grant for this purpose.
_WILDCARD_RESOURCE = re.compile(r"^\*$|^arn:[^:]*:[^:]*:[^:]*:[^:]*:table/\*$"
                                r"|^arn:[^:]*:[^:]*:[^:]*:[^:]*:\*$"
                                r"|^arn:[^:]*:[^:]*:[^:]*:[^:]*:database/\*$", re.I)


def _unknown(reason: str) -> dict:
    return {"applicable": False, "unknown": True, "reason": reason, "statement": ""}


def _ok() -> dict:
    return {"applicable": True, "unknown": False, "failed": False, "statement": ""}


def _fail(statement: str, **extra) -> dict:
    d = {"applicable": True, "unknown": False, "failed": True, "statement": statement}
    d.update(extra)
    return d


def _condition_keys(condition) -> Set[str]:
    """Every condition KEY named anywhere in a statement's Condition block, lower-cased.

    An IAM Condition is ``{operator: {key: value}}`` and may nest an operator like
    ``ForAllValues:StringEquals``. Only the keys matter here, not the operators or the
    values: the question 4.2 asks is whether the grant is constrained by the row and
    attribute keys at all, not what it constrains them to."""
    keys: Set[str] = set()
    if not isinstance(condition, Mapping):
        return keys
    for _op, kv in condition.items():
        if isinstance(kv, Mapping):
            keys |= {str(k).lower() for k in kv}
    return keys


def _unscoped_data_grants(statements: Optional[Sequence[Mapping]],
                          data_actions: Iterable[str]) -> List[str]:
    """Allow statements granting item-level data actions on EVERY table, unconditioned.

    THE SCOPE IS DELIBERATELY NARROW, and the narrowing is the whole design. A role holding
    ``dynamodb:GetItem`` on one named table is the normal, correct shape for a service that
    owns its data, and firing on it would put a finding on almost every application role in
    the estate — noise that trains people to filter the id out. What is worth reporting is
    a grant that reaches EVERY table with no condition narrowing it, which is both an
    over-permission in its own right and the state 4.2 exists to prevent.
    """
    wanted = {a.lower() for a in data_actions}
    hits: List[str] = []
    for st in statements or []:
        if st.get("effect") != "Allow":
            continue
        actions = {str(a).lower() for a in (st.get("actions") or set())}
        # fnmatch, not equality plus a ':*' special case. IAM action patterns wildcard
        # anywhere -- `dynamodb:Get*`, `dynamodb:*Item`, `dynamo*:*` are all valid and all
        # reach item-level operations. Matching only exact names and a trailing ':*' reads
        # `dynamodb:Get*` as covering nothing, which under-reports the exact grant shape a
        # policy author reaches for when they want "the read half of DynamoDB".
        matched = sorted(
            a for a in actions
            if a in wanted or fnmatch.filter(sorted(wanted), a))
        if not matched:
            continue
        resources = {str(r) for r in (st.get("resources") or set())}
        if not any(_WILDCARD_RESOURCE.match(r) for r in resources):
            continue
        if _condition_keys(st.get("condition")) & FGAC_CONDITION_KEYS:
            continue                       # constrained by row/attribute keys: compliant
        hits.append(matched[0] if len(matched) == 1 else f"{matched[0]} +{len(matched)-1}")
    return hits


# ══════════════════════════════════════════════════════════════════════════════
# 4 DynamoDB
# ══════════════════════════════════════════════════════════════════════════════
def dynamodb_fine_grained_access(principal: Mapping) -> dict:
    """DDB-06 / 4.2 — item-level DynamoDB access to every table, with no FGAC condition."""
    hits = _unscoped_data_grants(principal.get("statements"), DDB_DATA_ACTIONS)
    if not hits:
        return _ok()
    name = principal.get("name") or principal.get("arn") or "?"
    return _fail(
        f"{principal.get('type', 'principal')} {name} is granted DynamoDB item-level "
        f"actions ({', '.join(hits[:3])}) on EVERY table in the account with no "
        f"dynamodb:LeadingKeys or dynamodb:Attributes condition narrowing it. Anything "
        f"that assumes this identity can read and write every row of every table, "
        f"including tables created after the grant was written",
        grants=hits)


def dynamodb_vpc_endpoint(vpc_id: str, has_tables: bool, has_internet_path: bool,
                          endpoint_services: Optional[Iterable[str]]) -> dict:
    """DDB-07 / 4.5 — DynamoDB traffic leaves the VPC over the public path.

    THREE CONDITIONS, and each removes a class of unfixable finding. No tables in the
    account means there is no DynamoDB traffic to keep private. No internet path means the
    VPC is not reaching anything over the public network whatever its endpoint list says.
    And an endpoint that already exists is the compliant state."""
    if not has_tables:
        return _ok()
    if not has_internet_path:
        return _ok()
    svcs = {str(s).lower() for s in (endpoint_services or [])}
    if any(s.endswith(".dynamodb") for s in svcs):
        return _ok()
    return _fail(
        f"VPC {vpc_id} has a path to the internet and no DynamoDB gateway endpoint, so "
        f"every call its workloads make to DynamoDB leaves through the gateway and "
        f"crosses the public network to reach the service. A gateway endpoint costs "
        f"nothing, keeps the traffic on the AWS network, and — the part that is a "
        f"security control rather than a routing one — accepts an endpoint policy that "
        f"can restrict which tables are reachable at all")


# ══════════════════════════════════════════════════════════════════════════════
# 5 ElastiCache
# ══════════════════════════════════════════════════════════════════════════════
def elasticache_log_delivery(group: Mapping) -> dict:
    """ELC-09 / 5.6 — no log delivery configured on a replication group.

    RATED LOW, AND THE REASON MATTERS. The sibling audit-log checks (DOCDB-03, NEP-09) are
    MEDIUM because they cover a record of who connected and what they ran. ElastiCache log
    delivery carries the slow log and the engine log, which is observability rather than an
    access audit trail. Rating it alongside a real audit-log gap would overstate it."""
    configs = group.get("LogDeliveryConfigurations")
    if configs is None:
        return _unknown("the replication group's log delivery configuration was not read")
    active = [c for c in configs
              if str(c.get("Status", "")).lower() in ("active", "enabling", "modifying")]
    if active:
        return _ok()
    gid = group.get("ReplicationGroupId", "?")
    return _fail(
        f"ElastiCache replication group {gid} delivers no logs. The slow log and engine "
        f"log are the only record of what the cache was asked to do; without delivery "
        f"they stay inside the node and are lost with it, so a performance incident or an "
        f"unexpected access pattern leaves nothing to investigate afterwards",
        group=gid)


# ══════════════════════════════════════════════════════════════════════════════
# 6 MemoryDB
# ══════════════════════════════════════════════════════════════════════════════
def memorydb_notifications(cluster: Mapping) -> dict:
    """MDB-07 / 6.6 — no SNS notification topic on a MemoryDB cluster.

    THE MEMBER IS ``SnsTopicArn``, NOT ``SNSTopicArn``. Reading the shipped botocore model
    rather than assuming the obvious spelling is what caught that; the assumed name would
    have read None on every cluster and failed all of them, which is the worst kind of
    check — one that is always right for the wrong reason."""
    arn = str(cluster.get("SnsTopicArn") or "").strip()
    status = str(cluster.get("SnsTopicStatus") or "").strip().lower()
    name = cluster.get("Name", "?")
    if arn and status in ("active", ""):
        return _ok()
    if arn and status != "active":
        return _fail(
            f"MemoryDB cluster {name} has an SNS topic configured but its status is "
            f"'{status}', so cluster events are not being delivered. A topic that is "
            f"attached and inactive is worse than none: the console shows a topic and "
            f"nobody is being told about failovers, node replacements or scaling events",
            name=name)
    return _fail(
        f"MemoryDB cluster {name} has no SNS notification topic, so failovers, node "
        f"replacements, scheduled maintenance and scaling events are recorded in the "
        f"event log and announced to nobody. MemoryDB is a primary datastore rather than "
        f"a cache, so an unnoticed failover is an availability event with data behind it",
        name=name)


# ══════════════════════════════════════════════════════════════════════════════
# 7 DocumentDB / 9 Neptune
# ══════════════════════════════════════════════════════════════════════════════
def docdb_pending_maintenance(cluster_id: str,
                              actions: Optional[Sequence[Mapping]]) -> dict:
    """DOCDB-09 / 7.7 — pending maintenance actions the cluster has not taken.

    WHAT THIS IS A PROXY FOR, stated because the recommendation's own audit is a process
    ("stay informed", "plan a maintenance window") with nothing to inspect. The decidable
    fact underneath it is whether AWS has queued an update this cluster has not applied.
    That is a real, dated, per-cluster signal and it is the closest the control plane comes
    to answering "is this engine patched"."""
    if actions is None:
        return _unknown(f"pending maintenance actions for {cluster_id} were not read")
    pending = []
    for entry in actions:
        for d in entry.get("PendingMaintenanceActionDetails") or []:
            act = str(d.get("Action") or "")
            if act:
                pending.append(act)
    if not pending:
        return _ok()
    return _fail(
        f"DocumentDB cluster {cluster_id} has {len(pending)} pending maintenance "
        f"action(s) ({', '.join(sorted(set(pending))[:3])}) that have not been applied. "
        f"AWS queues engine patches here, including security fixes, and they stay pending "
        f"until a maintenance window runs or they are applied by hand — so a cluster can "
        f"sit on a known-vulnerable engine version indefinitely while looking healthy",
        actions=sorted(set(pending)))


def cluster_event_subscription(cluster_id: str, service: str,
                               subscriptions: Optional[Sequence[Mapping]]) -> dict:
    """DOCDB-10 / 7.8 and NEP-11 / 9.7 — nothing is subscribed to this cluster's events.

    ONE FUNCTION FOR TWO RECOMMENDATIONS because DocumentDB and Neptune share the RDS
    control plane and the event-subscription shape is identical. The two checks stay
    separate ids so each cites its own service's recommendation, which is the precedence
    rule the CIS-DB mapping already uses.

    DISTINCT FROM THE AUDIT-LOG CHECKS. DOCDB-03 and NEP-09 ask whether the cluster
    RECORDS what happened. This asks whether anyone is TOLD when something happens —
    a failover, a deletion, a parameter change. A cluster can log perfectly and notify
    nobody."""
    if subscriptions is None:
        return _unknown(f"{service} event subscriptions were not read")
    for sub in subscriptions:
        if not sub.get("Enabled", True):
            continue
        src_type = str(sub.get("SourceType") or "").lower()
        ids = [str(i) for i in (sub.get("SourceIdsList") or [])]
        # No SourceIdsList means the subscription covers EVERY source of its type, which
        # is the common and correct configuration for an estate-wide alerting topic.
        if src_type in ("db-cluster", "") and (not ids or cluster_id in ids):
            return _ok()
    return _fail(
        f"{service} cluster {cluster_id} is covered by no enabled event subscription, so "
        f"failovers, parameter-group changes, deletions and maintenance events are written "
        f"to the event log and announced to nobody. The event log is only read by somebody "
        f"who already suspects a problem, which is the opposite of what an alert is for",
        cluster=cluster_id)


# ══════════════════════════════════════════════════════════════════════════════
# 10 Timestream
# ══════════════════════════════════════════════════════════════════════════════
def timestream_fine_grained_access(principal: Mapping) -> dict:
    """TS-03 / 10.5 — Timestream data actions on every table, with no condition."""
    hits = _unscoped_data_grants(principal.get("statements"), TIMESTREAM_DATA_ACTIONS)
    if not hits:
        return _ok()
    name = principal.get("name") or principal.get("arn") or "?"
    return _fail(
        f"{principal.get('type', 'principal')} {name} is granted Timestream data actions "
        f"({', '.join(hits[:3])}) across every database and table with no condition "
        f"narrowing them. Timestream holds operational and monitoring time series, which "
        f"is exactly the data an intruder reads to learn what is watched and how often",
        grants=hits)


def timestream_backup_coverage(table_arn: str,
                               protected: Optional[Iterable[str]]) -> dict:
    """TS-04 / 10.10 — a Timestream table no AWS Backup plan protects.

    AWS BACKUP IS THE ONLY OPTION HERE, which is why this is rated above the other
    backup-hygiene checks in this benchmark. Timestream has no native snapshot, no
    point-in-time restore and no automated backup of its own: a table that no backup plan
    selects has no recovery path at all, and a DeleteTable is final."""
    if protected is None:
        return _unknown("the AWS Backup protected-resource list was not read")
    arns = {str(a).lower() for a in protected}
    if str(table_arn).lower() in arns:
        return _ok()
    return _fail(
        f"Timestream table {table_arn} is protected by no AWS Backup plan. Timestream has "
        f"no native backup, snapshot or point-in-time restore, so AWS Backup is the only "
        f"recovery path there is — without a plan selecting this table, an accidental "
        f"DeleteTable or a bad ingest is unrecoverable",
        table=table_arn)


# ══════════════════════════════════════════════════════════════════════════════
# the declarations
# ══════════════════════════════════════════════════════════════════════════════
CHECKS = _cd.register(
    _C(id="DDB-06", section="DYNAMODB", severity="MEDIUM",
       compliance={"CIS-DB": "4.2", "PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)",
                   "SOC2": "CC6.3", "NIST": "AC-6"},
       remediation=(
           "Scope the grant to the tables the identity actually uses, and add a "
           "fine-grained condition where rows belong to different tenants or users: "
           "aws iam put-role-policy --role-name <ROLE> --policy-name ddb-scoped "
           "--policy-document file://scoped.json , with Resource set to the specific "
           "table ARNs and a Condition of ForAllValues:StringEquals on "
           "dynamodb:LeadingKeys. Confirm what the identity holds today with "
           "aws iam list-attached-role-policies --role-name <ROLE>"),
       risk=("A policy granting DynamoDB item-level actions on every table in the account "
             "gives whatever assumes that identity the ability to read and write every row "
             "of every table, including tables that did not exist when the grant was "
             "written. DynamoDB supports narrowing this at the row and attribute level "
             "through the dynamodb:LeadingKeys and dynamodb:Attributes condition keys, so "
             "a multi-tenant table can be restricted to the caller's own partition key "
             "rather than trusting application code to filter. This check is deliberately "
             "scoped to grants that reach EVERY table with no such condition: a role with "
             "GetItem on one named table is the normal, correct shape for a service that "
             "owns its data, and reporting it would put a finding on nearly every "
             "application role in the estate."),
       impact=("Anything assuming this identity can read and write every row of every "
               "DynamoDB table in the account, including tables created later."),
       steps=("List what the identity holds: aws iam list-attached-role-policies "
              "--role-name <ROLE> and aws iam list-role-policies --role-name <ROLE>",
              "Replace the wildcard Resource with the specific table ARNs the workload "
              "uses",
              "Where rows belong to different tenants or users, add a "
              "ForAllValues:StringEquals condition on dynamodb:LeadingKeys",
              "Re-run the scan and confirm DDB-06 no longer fires for the identity"),
       permissions=(_P("iam:GetPolicyVersion",
                       "reads the policy document behind an attached managed policy; the "
                       "Condition block is what decides 4.2, and no listing API returns "
                       "it"),)),

    _C(id="DDB-07", section="DYNAMODB", severity="LOW",
       compliance={"CIS-DB": "4.5", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)",
                   "SOC2": "CC6.6", "NIST": "SC-7"},
       remediation=(
           "Create a gateway endpoint for DynamoDB and attach it to the VPC's route "
           "tables — gateway endpoints are free: aws ec2 create-vpc-endpoint --vpc-id "
           "<VPC_ID> --service-name com.amazonaws.<REGION>.dynamodb --route-table-ids "
           "<RTB_IDS> . Then restrict what it can reach with an endpoint policy: "
           "aws ec2 modify-vpc-endpoint --vpc-endpoint-id <VPCE_ID> --policy-document "
           "file://endpoint-policy.json"),
       risk=("Without a gateway endpoint, every DynamoDB call a workload makes leaves the "
             "VPC through its internet gateway or NAT and traverses the public network to "
             "reach the service endpoint. Two consequences follow. The traffic is exposed "
             "to whatever sits on that path, and — the part that is a security control "
             "rather than a routing preference — there is no endpoint policy, so nothing "
             "constrains WHICH tables the VPC may reach. An endpoint policy is the only "
             "mechanism that can say 'workloads in this VPC may reach these tables and no "
             "others', independently of what any instance role permits. DynamoDB uses "
             "gateway endpoints rather than interface endpoints, so there is no hourly "
             "charge for this."),
       impact=("DynamoDB traffic crosses the public network and cannot be restricted to "
               "specific tables by an endpoint policy."),
       steps=("List the VPC's endpoints: aws ec2 describe-vpc-endpoints --filters "
              "Name=vpc-id,Values=<VPC_ID>",
              "Create the gateway endpoint: aws ec2 create-vpc-endpoint --vpc-id <VPC_ID> "
              "--service-name com.amazonaws.<REGION>.dynamodb --route-table-ids <RTB_IDS>",
              "Confirm the prefix-list route appears in each named route table",
              "Attach an endpoint policy restricting which table ARNs may be reached"),
       permissions=(_P("ec2:DescribeVpcEndpoints",
                       "lists each VPC's endpoints and their service names, which is the "
                       "only way to tell a VPC that reaches DynamoDB privately from one "
                       "that does not"),)),

    _C(id="ELC-09", section="ELASTICACHE", severity="LOW",
       compliance={"CIS-DB": "5.6", "PCI-DSS": "10.2.1", "HIPAA": "164.312(b)",
                   "SOC2": "CC7.2", "NIST": "AU-2"},
       remediation=(
           "Enable slow-log and engine-log delivery to CloudWatch Logs: "
           "aws elasticache modify-replication-group --replication-group-id <RGID> "
           "--log-delivery-configurations "
           "'[{\"LogType\":\"slow-log\",\"DestinationType\":\"cloudwatch-logs\","
           "\"DestinationDetails\":{\"CloudWatchLogsDetails\":{\"LogGroup\":\"<GROUP>\"}},"
           "\"LogFormat\":\"json\",\"Enabled\":true}]' --apply-immediately"),
       risk=("An ElastiCache replication group with no log delivery keeps its slow log and "
             "engine log inside the node, where they are lost when the node is replaced — "
             "which happens on every failover, scaling event and maintenance window. The "
             "slow log is the only record of what the cache was actually asked to do, so "
             "an unexplained latency incident, an unexpected access pattern or a "
             "key-enumeration sweep leaves nothing behind to investigate. This is rated "
             "LOW rather than alongside the DocumentDB and Neptune audit-log checks on "
             "purpose: those carry a record of who connected and what they ran, whereas "
             "ElastiCache log delivery is observability rather than an access audit trail, "
             "and rating them the same would overstate this one."),
       impact=("The slow and engine logs are lost with the node, so cache incidents cannot "
               "be reconstructed afterwards."),
       steps=("Create or choose a CloudWatch log group for the cache logs",
              "Enable delivery: aws elasticache modify-replication-group "
              "--replication-group-id <RGID> --log-delivery-configurations '[...]' "
              "--apply-immediately",
              "Confirm the configuration reports Status=active: aws elasticache "
              "describe-replication-groups --replication-group-id <RGID>"),
       permissions=(_P("elasticache:DescribeReplicationGroups",
                       "returns LogDeliveryConfigurations alongside the encryption and "
                       "failover settings the other ELC checks read, so 5.6 costs no "
                       "additional API call"),)),

    _C(id="MDB-07", section="MEMORYDB", severity="LOW",
       compliance={"CIS-DB": "6.6", "PCI-DSS": "10.4.1", "HIPAA": "164.312(b)",
                   "SOC2": "CC7.2", "NIST": "SI-4"},
       remediation=(
           "Attach an SNS topic so cluster events reach somebody: aws memorydb "
           "update-cluster --cluster-name <NAME> --sns-topic-arn <TOPIC_ARN> , then "
           "subscribe a monitored destination: aws sns subscribe --topic-arn <TOPIC_ARN> "
           "--protocol email --notification-endpoint <TEAM_EMAIL> . Verify with "
           "aws memorydb describe-clusters --cluster-name <NAME>"),
       risk=("A MemoryDB cluster with no SNS topic records its failovers, node "
             "replacements, scheduled maintenance and scaling events in the event log and "
             "announces them to nobody. The event log is read only by somebody who already "
             "suspects a problem, which is the opposite of what an alert is for. MemoryDB "
             "matters more here than ElastiCache does: it is a durable primary datastore "
             "rather than a cache, so an unnoticed failover is an availability event with "
             "real data behind it rather than a warm-up cost. A topic that is attached but "
             "whose status is not active is reported separately and is arguably worse than "
             "none, because the console shows a topic while nothing is being delivered."),
       impact=("Failovers and maintenance on a primary datastore happen unannounced."),
       steps=("Create or choose an SNS topic that routes to an on-call destination",
              "Attach it: aws memorydb update-cluster --cluster-name <NAME> "
              "--sns-topic-arn <TOPIC_ARN>",
              "Subscribe a monitored endpoint: aws sns subscribe --topic-arn <TOPIC_ARN> "
              "--protocol email --notification-endpoint <TEAM_EMAIL>",
              "Confirm SnsTopicStatus reads active: aws memorydb describe-clusters "
              "--cluster-name <NAME>"),
       permissions=(_P("memorydb:DescribeClusters",
                       "returns SnsTopicArn and SnsTopicStatus alongside the TLS and ACL "
                       "settings the other MDB checks read, so 6.6 costs no extra call"),)),

    _C(id="DOCDB-09", section="DOCDB", severity="MEDIUM",
       compliance={"CIS-DB": "7.7", "PCI-DSS": "6.3.3", "HIPAA": "164.308(a)(5)(ii)(B)",
                   "SOC2": "CC7.1", "NIST": "SI-2"},
       remediation=(
           "Apply the queued action, in a window you choose rather than the one AWS "
           "eventually forces: aws docdb apply-pending-maintenance-action "
           "--resource-identifier <CLUSTER_ARN> --apply-action system-update "
           "--opt-in-type immediate . Review what is queued first with "
           "aws docdb describe-pending-maintenance-actions"),
       risk=("AWS queues engine updates for a DocumentDB cluster as pending maintenance "
             "actions, and they stay pending until a maintenance window runs or somebody "
             "applies them. Security fixes arrive this way, so a cluster can sit on a "
             "known-vulnerable engine version indefinitely while every other health "
             "signal reads normal. The recommendation this answers is written as a process "
             "control — stay informed, plan a window — with nothing to inspect; the "
             "decidable fact underneath it is whether AWS has queued something this "
             "cluster has not taken, which is a real, dated, per-cluster signal and the "
             "closest the control plane comes to answering whether the engine is patched."),
       impact=("The cluster may be running a known-vulnerable engine version with the fix "
               "already queued and unapplied."),
       steps=("List what is queued: aws docdb describe-pending-maintenance-actions",
              "Read the action's description and its auto-applied-after date — that date "
              "is when AWS will force it whether or not the window suits you",
              "Apply it deliberately: aws docdb apply-pending-maintenance-action "
              "--resource-identifier <CLUSTER_ARN> --apply-action system-update "
              "--opt-in-type immediate",
              "Re-run describe-pending-maintenance-actions and confirm it is gone"),
       # rds:, NOT docdb:. DocumentDB shares the RDS control plane AND its IAM namespace:
       # the boto3 CLIENT is named docdb, and the ACTION that authorises it is rds:. The
       # two namespaces are different and conflating them produces a grant request for an
       # action that does not exist -- caught by
       # tests/test_iam_surface.py::test_every_declared_action_uses_a_real_iam_prefix.
       permissions=(_P("rds:DescribePendingMaintenanceActions",
                       "returns the engine updates AWS has queued for a DocumentDB "
                       "cluster and the date each is force-applied; nothing on the "
                       "cluster description reveals that a patch is outstanding"),)),

    _C(id="DOCDB-10", section="DOCDB", severity="LOW",
       compliance={"CIS-DB": "7.8", "PCI-DSS": "10.4.1", "HIPAA": "164.312(b)",
                   "SOC2": "CC7.2", "NIST": "SI-4"},
       remediation=(
           "Subscribe an SNS topic to the cluster's events: aws docdb "
           "create-event-subscription --subscription-name docdb-events --sns-topic-arn "
           "<TOPIC_ARN> --source-type db-cluster --event-categories failover maintenance "
           "configuration-change deletion . Omit --source-ids to cover every cluster, "
           "including ones created later"),
       risk=("A DocumentDB cluster covered by no event subscription writes its failovers, "
             "parameter-group changes, deletions and maintenance events to the event log "
             "and tells nobody. The event log is only ever read by somebody who already "
             "suspects a problem, which is the opposite of what an alert is for. This is "
             "distinct from the audit-log control DOCDB-03 covers: that one asks whether "
             "the cluster RECORDS what happened inside it, this one asks whether anyone is "
             "TOLD when something happens to it. A cluster can log perfectly and notify "
             "nobody, and the two failures need different fixes."),
       impact=("Failover, deletion and configuration events on the cluster are recorded "
               "but never announced."),
       steps=("Create or choose an SNS topic routed to an on-call destination",
              "Subscribe to cluster events: aws docdb create-event-subscription "
              "--subscription-name docdb-events --sns-topic-arn <TOPIC_ARN> --source-type "
              "db-cluster",
              "Leave --source-ids off so clusters created later are covered automatically",
              "Confirm with aws docdb describe-event-subscriptions"),
       permissions=(_P("rds:DescribeEventSubscriptions",
                       "lists the subscriptions and the sources each covers, which is the "
                       "only way to tell an estate-wide subscription from one scoped to "
                       "other clusters. rds:, not docdb: -- DocumentDB shares the RDS IAM "
                       "namespace even though its client is named separately"),)),

    _C(id="NEP-11", section="NEPTUNE", severity="LOW",
       compliance={"CIS-DB": "9.7", "PCI-DSS": "10.4.1", "HIPAA": "164.312(b)",
                   "SOC2": "CC7.2", "NIST": "SI-4"},
       remediation=(
           "Subscribe an SNS topic to the cluster's events: aws neptune "
           "create-event-subscription --subscription-name neptune-events --sns-topic-arn "
           "<TOPIC_ARN> --source-type db-cluster . Omit --source-ids so clusters created "
           "later are covered too, then confirm with aws neptune "
           "describe-event-subscriptions"),
       risk=("A Neptune cluster covered by no event subscription writes its failovers, "
             "parameter-group changes, deletions and maintenance events to the event log "
             "and announces them to nobody, so the first sign of a problem is usually an "
             "application error rather than an alert. This is distinct from the audit-log "
             "control NEP-09 covers: that asks whether the cluster records the queries run "
             "against it, this asks whether anyone is told when something happens to the "
             "cluster itself. Neptune deserves the notification more than most, because a "
             "graph database is usually a single cluster with no read-replica fleet to "
             "absorb a failover quietly."),
       impact=("Failover, deletion and configuration events on the graph cluster are "
               "recorded but never announced."),
       steps=("Create or choose an SNS topic routed to an on-call destination",
              "Subscribe to cluster events: aws neptune create-event-subscription "
              "--subscription-name neptune-events --sns-topic-arn <TOPIC_ARN> "
              "--source-type db-cluster",
              "Leave --source-ids off so clusters created later are covered automatically",
              "Confirm with aws neptune describe-event-subscriptions"),
       permissions=(_P("rds:DescribeEventSubscriptions",
                       "lists the subscriptions and their covered sources; a subscription "
                       "scoped to other clusters looks identical to none from the cluster "
                       "description alone. rds:, not neptune: -- Neptune is authorised "
                       "under the RDS namespace it shares a control plane with"),)),

    _C(id="TS-03", section="TIMESTREAM", severity="MEDIUM",
       compliance={"CIS-DB": "10.5", "PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)",
                   "SOC2": "CC6.3", "NIST": "AC-6"},
       remediation=(
           "Scope the grant to the databases and tables the identity actually queries: "
           "aws iam put-role-policy --role-name <ROLE> --policy-name timestream-scoped "
           "--policy-document file://scoped.json , with Resource set to the specific "
           "table ARNs rather than '*'. Review what is held today with "
           "aws iam list-attached-role-policies --role-name <ROLE>"),
       risk=("A policy granting Timestream data actions across every database and table "
             "lets whatever assumes that identity query all of the estate's time-series "
             "data. That data is operational and monitoring telemetry, which is precisely "
             "what an intruder reads to learn what is instrumented, how often it is "
             "sampled and therefore what would and would not be noticed. As with the "
             "DynamoDB equivalent, this is scoped to grants that reach EVERY table with no "
             "narrowing condition — a role querying one named table is the normal shape "
             "for a dashboard or an alerting job, and reporting it would bury the real "
             "finding."),
       impact=("Anything assuming this identity can query every time series in the "
               "account, including the telemetry that would reveal it."),
       steps=("List what the identity holds: aws iam list-attached-role-policies "
              "--role-name <ROLE>",
              "Replace the wildcard Resource with the specific database and table ARNs",
              "Where a consumer only reads, drop the timestream:WriteRecords action "
              "entirely",
              "Re-run the scan and confirm TS-03 no longer fires for the identity"),
       permissions=(_P("iam:GetPolicyVersion",
                       "reads the policy document behind an attached managed policy. The "
                       "Condition block is what decides 10.5, and no listing API returns "
                       "it -- the same read DDB-06 needs for the DynamoDB equivalent"),)),

    _C(id="TS-04", section="TIMESTREAM", severity="MEDIUM",
       compliance={"CIS-DB": "10.10", "PCI-DSS": "10.5.1", "HIPAA": "164.308(a)(7)(ii)(A)",
                   "SOC2": "A1.2", "NIST": "CP-9"},
       remediation=(
           "Bring the table into an AWS Backup plan: aws backup create-backup-selection "
           "--backup-plan-id <PLAN_ID> --backup-selection "
           "'{\"SelectionName\":\"timestream\",\"IamRoleArn\":\"<ROLE_ARN>\","
           "\"Resources\":[\"<TABLE_ARN>\"]}' . Confirm the table appears with "
           "aws backup list-protected-resources"),
       risk=("Amazon Timestream has no native backup: no snapshot, no point-in-time "
             "restore, no automated backup of its own. AWS Backup is the only recovery "
             "path the service has, so a table that no backup plan selects cannot be "
             "restored at all — an accidental DeleteTable, a bad ingest that overwrites "
             "measures, or a retention-policy change that ages data out early are all "
             "final. That is why this is rated above the backup-retention checks elsewhere "
             "in this benchmark: for RDS, Aurora, DocumentDB and Neptune a short retention "
             "period limits how far back you can go, whereas here the absence of a plan "
             "means there is no 'back' at all."),
       impact=("The table has no recovery path whatsoever; a delete or a bad ingest is "
               "unrecoverable."),
       steps=("Confirm the table is unprotected: aws backup list-protected-resources "
              "--query \"Results[?ResourceType=='Timestream']\"",
              "Create or choose a backup plan with a schedule and lifecycle suited to the "
              "data's value",
              "Add a selection covering the table: aws backup create-backup-selection "
              "--backup-plan-id <PLAN_ID> --backup-selection '{...}'",
              "Verify a recovery point appears after the first scheduled run: aws backup "
              "list-recovery-points-by-backup-vault --backup-vault-name <VAULT>"),
       permissions=(_P("backup:ListProtectedResources",
                       "returns every resource an AWS Backup plan covers, which is the "
                       "only way to tell a protected Timestream table from an unprotected "
                       "one -- the Timestream APIs expose no backup state at all"),)),
)
