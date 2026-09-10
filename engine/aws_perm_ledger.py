#!/usr/bin/env python3
"""aws_perm_ledger.py — what each IAM action buys, and what declining it forfeits.

Every CNAPP asks for permissions. Almost none of them tell you what each one is FOR,
and none of them tell you what you lose by refusing one. The result is a policy
document a security reviewer must take on trust, and — worse — a scan that quietly
degrades when an action is missing, reporting a check as *passed* when it was never
*evaluated*. Those two are indistinguishable in every product output we have seen,
including, until recently, our own.

This module makes both legible:

* **The ledger** maps each check to the IAM actions it needs, computes which checks the
  role can actually evaluate, and emits the MINIMAL additive policy with a per-action
  justification — ``bedrock:GetKnowledgeBase → enables AGT-03``. Decline any single
  action and it names exactly which findings you forfeit.
* **The coverage manifest** is the negative-assurance artefact: what we enumerated, what
  we could not and why, which checks were *not evaluated* as opposed to *evaluated and
  passed*, and which regions were never looked at.

WHY THIS EARNS ITS PLACE. It is the mechanism by which a permission is *sold* rather
than demanded, and it is the natural completion of "an open, auditable scoring engine":
a product that shows its reasoning should also show its blind spots. For a sovereign
buyer whose security review goes line by line through an IAM policy, a per-action
justification is the difference between a one-day approval and a six-week one.

It is also a guard against a mistake this codebase has made twice. Both the roadmap and
an earlier analysis asserted that the AI pillar was broadly AccessDenied-degraded under
the documented role. Checking the actual attached policies showed the real gap was three
actions. Reasoning about permissions from memory is unreliable; computing them from the
policy documents is not.

Pure and boto3-free: it consumes the normalized statement shape that
``aws_live_scanner._policy_to_statements`` already produces, the same shape
``aws_effperm`` and ``aws_aispm`` consume::

    {"effect": "Allow"|"Deny", "actions": set[str], "resources": set[str],
     "not_resources": set[str], "condition": dict|None}

with actions and resources lowercased.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

__all__ = [
    "Requirement", "REQUIREMENTS", "Ledger", "CoverageManifest",
    "granted", "evaluate", "requirements_for",
]


# ─── the requirement table ───────────────────────────────────────────────────
@dataclass(frozen=True)
class Requirement:
    """One IAM action a check needs, and what the check does with it."""
    action: str          # canonical case, e.g. "bedrock:GetKnowledgeBase"
    why: str             # what the operator buys by granting it

    @property
    def key(self) -> str:
        return self.action.lower()


def _req(action: str, why: str) -> Requirement:
    return Requirement(action=action, why=why)


# Scoped to the AI pillar today, and deliberately so: authoring a mapping for all 300+
# checks from memory would reproduce exactly the error this module exists to prevent.
# Every entry below was read off the call site, not recalled. Extend it the same way.
# ── SageMaker requirement groups (slice 4.1) ─────────────────────────────────
# Named tuples rather than repeated literals: twenty-five checks draw on eleven API
# pairs, and writing each pair out per check is how one of them ends up naming an
# action the call site does not make.
_NOTEBOOK = (
    _req("sagemaker:ListNotebookInstances", "find notebook instances"),
    _req("sagemaker:DescribeNotebookInstance",
         "read direct-internet access, root access, subnet attachment, volume "
         "encryption and the platform identifier -- five checks off one call"),
)
_DOMAIN = (
    _req("sagemaker:ListDomains", "find SageMaker Studio domains"),
    _req("sagemaker:DescribeDomain",
         "read the domain's app network access type and home-EFS key custody"),
)
_ENDPOINT_CONFIG = (
    _req("sagemaker:ListEndpointConfigs", "find inference endpoint configs"),
    _req("sagemaker:DescribeEndpointConfig",
         "read storage key custody and production-variant instance counts -- "
         "KmsKeyId appears on this call and on no other"),
)
_MODEL = (
    _req("sagemaker:ListModels", "find hosted models"),
    _req("sagemaker:DescribeModel",
         "read network isolation and each container's RepositoryAccessMode -- "
         "whether the image running your inference came from a registry you control"),
)
_DATA_QUALITY = (
    _req("sagemaker:ListDataQualityJobDefinitions", "find data quality job definitions"),
    _req("sagemaker:DescribeDataQualityJobDefinition",
         "read NetworkConfig -- isolation and inter-container encryption for a job "
         "pointed at production inference data"),
)
_EXPLAINABILITY = (
    _req("sagemaker:ListModelExplainabilityJobDefinitions",
         "find model explainability job definitions"),
    _req("sagemaker:DescribeModelExplainabilityJobDefinition",
         "read NetworkConfig -- isolation and inter-container encryption"),
)
_BIAS = (
    _req("sagemaker:ListModelBiasJobDefinitions", "find model bias job definitions"),
    _req("sagemaker:DescribeModelBiasJobDefinition",
         "read NetworkConfig and the cluster instance count, which is what decides "
         "whether the encryption control applies at all"),
)
_MODEL_QUALITY = (
    _req("sagemaker:ListModelQualityJobDefinitions",
         "find model quality job definitions"),
    _req("sagemaker:DescribeModelQualityJobDefinition",
         "read NetworkConfig -- isolation and inter-container encryption"),
)
_SCHEDULE = (
    _req("sagemaker:ListMonitoringSchedules", "find monitoring schedules"),
    _req("sagemaker:DescribeMonitoringSchedule",
         "read the schedule's inline MonitoringJobDefinition.NetworkConfig, which is "
         "one level deeper than a job definition's"),
)
_FEATURE_GROUP = (
    _req("sagemaker:ListFeatureGroups", "find feature groups"),
    _req("sagemaker:DescribeFeatureGroup",
         "read offline and online store key custody -- the offline store is the "
         "historical record of every feature value your models trained on"),
)
_INFERENCE_EXPERIMENT = (
    _req("sagemaker:ListInferenceExperiments", "find inference experiments"),
    _req("sagemaker:DescribeInferenceExperiment",
         "read instance-storage and captured-data key custody; a shadow test runs "
         "production traffic, so the captured payload is production traffic"),
)
_APP_IMAGE_CONFIG = (
    _req("sagemaker:ListAppImageConfigs", "find app image configurations"),
    _req("sagemaker:ListTags", "read the tags that make a resource attributable"),
)
_IMAGE = (
    _req("sagemaker:ListImages", "find SageMaker images"),
    _req("sagemaker:ListTags", "read the tags that make a resource attributable"),
)


REQUIREMENTS: Mapping[str, Tuple[Requirement, ...]] = {
    "BDR-01": (
        _req("bedrock:GetModelInvocationLoggingConfiguration",
             "read whether Bedrock records model invocations at all — the only "
             "control in the AI pillar that produces evidence after an incident"),
    ),
    "BDR-02": (
        _req("bedrock:ListGuardrails",
             "enumerate guardrails so an account with none can be distinguished "
             "from an account we were not allowed to ask"),
    ),
    "BDR-03": (
        _req("bedrock:ListCustomModels", "find fine-tuned models"),
        _req("bedrock:GetCustomModel",
             "read each custom model's KMS key — a fine-tuned model embeds its "
             "training data, so its key custody is the training data's key custody"),
    ),
    # AgentCore is a separate service with its own IAM prefix (bedrock-agentcore, NOT
    # the bedrock-agentcore-control endpoint name). SecurityAudit predates it, so the
    # managed policies grant none of this -- the ledger is what makes that visible
    # before a scan, rather than surprising at runtime.
    "AGC-01": (
        _req("bedrock-agentcore:ListAgentRuntimes",
             "find AgentCore runtimes -- an entire agent estate that a Bedrock Agents "
             "inventory never sees"),
        _req("bedrock-agentcore:GetAgentRuntime",
             "read metadataConfiguration.requireMMDSV2 -- whether the microVM metadata "
             "service answers a request the agent was induced to make, which is the "
             "credential-theft path prompt injection already walks"),
    ),
    "AGC-02": (
        _req("bedrock-agentcore:ListAgentRuntimes",
             "reach each runtime whose environment must be checked for a pasted "
             "credential -- there is no way to read one without first listing them"),
        _req("bedrock-agentcore:GetAgentRuntime",
             "read environmentVariables to find secret-SHAPED names -- names only, "
             "never values"),
    ),
    "AGC-03": (
        _req("bedrock-agentcore:ListOauth2CredentialProviders",
             "count the OAuth2 credentials the agent estate holds for systems OUTSIDE "
             "AWS, where no IAM policy, CloudTrail record or KMS key applies"),
        _req("bedrock-agentcore:ListApiKeyCredentialProviders",
             "count the raw API keys the estate stores for third-party systems -- the "
             "same exposure as the OAuth2 providers, without even a token lifetime"),
        _req("bedrock-agentcore:ListWorkloadIdentities",
             "resolve the agent identities those credentials bind to"),
    ),
    "AGC-04": (
        _req("bedrock-agentcore:ListCodeInterpreters",
             "find code-interpreter sandboxes -- arbitrary code execution carrying the "
             "agent's own identity"),
        _req("bedrock-agentcore:ListBrowsers",
             "find headless browsers -- arbitrary URL fetching, and the most direct "
             "route from an injected instruction to an outbound request"),
        _req("bedrock-agentcore:ListGateways",
             "find the gateways that publish tools to agents"),
        _req("bedrock-agentcore:ListMemories",
             "find memory stores -- where an injected instruction can be made to "
             "persist across sessions"),
    ),
    # Slice 2.4 adds NO new action: get_agent_action_group is already called for
    # AGT-04 and was granted in slice 1.2. Recorded so declining that one action
    # names everything it costs, which is the whole contract of the ledger.
    # Slice 3.1 adds NO new action. Every input is already read: GetDataSource for
    # the entry (granted in 1.2), GetAgent for the role, and the bucket policies the
    # S3 section already reads. The flagship computation is a composition of things
    # the scanner holds, which is what made it affordable.
    # AMEM-01 is the first check in this table that spans TWO surfaces, and the
    # distinction matters enough to write down. The retention window lives on
    # memoryConfiguration.storageDays for a Bedrock agent (GetAgent, granted in 1.2)
    # and on eventExpiryDuration for an AgentCore memory (GetMemory, granted by
    # nothing). evaluate() is AND-semantics -- one missing action blocks the whole
    # check -- so naming GetMemory here would have made the preflight announce
    # "AMEM-01 will NOT be evaluated" in a report that then carries AMEM-01 findings
    # for every Bedrock agent. That is a phantom GAP: the mirror of the phantom pass,
    # and just as wrong. The requirement is therefore the action the check needs to
    # produce ANY answer; the AgentCore half degrades to a scoped AccessDenied that
    # _audit_agentcore_memory records at runtime, naming the surface it lost.
    "AMEM-01": (
        _req("bedrock:GetAgent",
             "read memoryConfiguration.storageDays -- how long an instruction that "
             "reached an agent's memory keeps being read back into later sessions"),
    ),
    # AMEM-02 has no Bedrock-agent half: only AgentCore Memory exposes an encryption
    # key at all, so declining GetMemory forfeits the whole check rather than half.
    "AMEM-02": (
        _req("bedrock-agentcore:GetMemory",
             "read encryptionKeyArn -- whether the store carrying instructions "
             "between sessions is on a key the customer can disable"),
    ),
    "TFLOW-01": (
        _req("bedrock:GetDataSource",
             "read each knowledge-base data source type -- a WEB crawler or an "
             "externally-writable S3 bucket is an OBSERVABLE untrusted-content "
             "path, which is what separates a proven flow from an assumed one"),
    ),
    "TFLOW-02": (
        _req("bedrock:GetAgent",
             "resolve the agent execution role whose reach IS the flow -- with no "
             "observable entry this is the half that is certainly true"),
    ),
    "AITHR-03": (
        _req("guardduty:ListFindings",
             "find the AI Protection findings the main THREAT query cannot see -- "
             "it filters at severity >= 4 and all three types ship at Low"),
        _req("guardduty:GetFindings",
             "read the acting identity and the models touched, so the Low can be "
             "re-decided against what that identity can actually reach"),
    ),
    "AITHR-04": (
        _req("guardduty:GetFindings",
             "read contentPolicyFilters[].action -- whether the guardrail blocked "
             "the prompt attack it detected, or was configured only to report it"),
    ),
    # MCP-03 adds NO new action: the instructions string is on GetGateway, already
    # bought for AGC-05/06. Recorded so declining that one action names everything it
    # costs, which is the whole contract of the ledger.
    "MCP-03": (
        _req("bedrock-agentcore:GetGateway",
             "read protocolConfiguration.mcp.instructions -- the server-level string "
             "handed to the model as direction, which a reviewer sees as documentation"),
    ),
    # Slice 4.2 -- the RAG vector store. None of these are in SecurityAudit or
    # ViewOnlyAccess: aoss and s3vectors both postdate those managed policies, so the
    # ledger is what makes the gap visible BEFORE a scan rather than at runtime.
    #
    # Every action here is a CONFIG read. s3vectors:GetVectors and ListVectors are
    # deliberately absent and always will be -- see D8. Asking for them would be asking
    # for the customer's corpus.
    # Slice 4.3. GetModelInvocationLoggingConfiguration is already granted (BDR-01);
    # what is new is cloudtrail:GetEventSelectors, which the scanner already CALLS for
    # LOG-08 but which was never in the ledger -- so declining it silently cost a check
    # nobody was told about. Recorded now for both.
    # Slice 4.4. Both actions are already granted and already called -- LookupEvents
    # for AITHR-01, DescribeVpcEndpoints under SecurityAudit's ec2:Describe*. Recorded
    # anyway so declining either one names everything it costs, which is the whole
    # contract of this table. The third-party SaaS half of shadow AI needs no action at
    # all because it is not attempted; see D9.
    # Slice 4.6. The CONFIG half adds no action: DescribeModel was already granted for
    # SM-09/10/11, and the bucket-policy read is the one S3-09 already performs. Only
    # MART-04 crosses, and it crosses into the s3:GetObject action class the charter
    # excludes -- so it ships in the FLOW-00 shape, behind its own named policy and its
    # own flag, or it does not ship. See D10.
    # Slice 4.7 needs NO IAM action at all: the input is a file the operator supplies
    # from their own detector. Recorded as a deliberate absence rather than an omission,
    # the same way slice 3.5's pen-test ingest is -- a reader checking why AIDR-01 has no
    # entry should find the reason here rather than assume it was forgotten.
    # ── Batch 1 of the 426-service coverage gap analysis ────────────────────
    # SecurityAudit predates none of these services, but it grants only a subset:
    # iot:List*/Get*/Describe* and elasticmapreduce:Describe*/List* are covered,
    # codebuild:BatchGetProjects and imagebuilder:GetImagePolicy are NOT. Recorded so
    # a declined grant names what it costs rather than silently becoming a clean pass.
    "IOT-01": (
        _req("iot:ListPolicies",
         "enumerate the IoT policies attached to device certificates"),
        _req("iot:GetPolicy",
             "read each policy document to see whether it grants iot:* on * -- IoT "
             "policies attach to certificates, so a wildcard is every device at once"),
    ),
    "IOT-02": (
        _req("iot:GetV2LoggingOptions",
             "read disableAllLogs -- whether any record exists of what devices did"),
    ),
    "IOT-03": (
        _req("iot:ListCACertificates",
         "enumerate the certificate authorities that can admit devices"),
        _req("iot:DescribeCACertificate",
             "read autoRegistrationStatus -- whether any certificate the CA signs "
             "joins the fleet without review"),
    ),
    "EMR-01": (
        _req("elasticmapreduce:GetBlockPublicAccessConfiguration",
             "read the account-level guardrail AWS added because EMR clusters kept "
             "reaching the internet"),
    ),
    "EMR-02": (
        _req("elasticmapreduce:ListClusters",
         "enumerate clusters in a running or starting state"),
        _req("elasticmapreduce:DescribeCluster",
             "read SecurityConfiguration -- without one, no at-rest or in-transit "
             "encryption and no per-user identity applies to the cluster"),
    ),
    "CB-01": (
        _req("codebuild:ListProjects",
         "enumerate CodeBuild projects so each one can be graded"),
        _req("codebuild:BatchGetProjects",
             "read projectVisibility -- PUBLIC_READ publishes build logs, which is "
             "where credentials and internal hostnames surface"),
    ),
    "CB-02": (
        _req("codebuild:BatchGetProjects",
             "read artifacts.encryptionDisabled -- an explicit opt-out, not a default"),
    ),
    "DOCDB-01": (
        _req("rds:DescribeDBClusterSnapshots",
         "enumerate manual DocumentDB cluster snapshots, which are the copies "
         "that get shared and moved between accounts"),
        _req("rds:DescribeDBClusterSnapshotAttributes",
             "read the restore attribute -- a value of 'all' means ANY AWS account can "
             "restore the database, which is an observation rather than an inference"),
    ),
    "DOCDB-02": (
        _req("rds:DescribeDBClusters",
             "read StorageEncrypted -- DocumentDB encryption is creation-time only, so "
             "this determines whether a migration is required"),
    ),
    "DOCDB-03": (
        _req("rds:DescribeDBClusters",
             "read EnabledCloudwatchLogsExports -- whether any record exists of who "
             "connected and what they queried"),
    ),
    "DOCDB-04": (
        _req("rds:DescribeDBClusters",
             "read DeletionProtection -- whether a single DeleteDBCluster call can "
             "destroy the cluster and its automated backups together"),
    ),
    "DOCDB-05": (
        _req("rds:DescribeDBClusterSnapshots",
             "read StorageEncrypted on manual snapshots -- encryption is inherited at "
             "creation and cannot be added later, so a plaintext snapshot is permanent"),
    ),
    # Neptune shares the RDS control plane, and its IAM actions are rds:* -- a role that
    # can already read RDS clusters needs NO new grant for NEP-01..04. The actions are
    # listed anyway so the ledger states what each check reads rather than leaving it to
    # be inferred from the service the client was built for.
    "NEP-01": (
        _req("rds:DescribeDBClusters",
             "read StorageEncrypted -- Neptune encryption is creation-time only, so this "
             "determines whether a snapshot-restore migration is required"),
    ),
    "NEP-02": (
        _req("rds:DescribeDBClusters",
             "read DeletionProtection -- for a graph the recovery path after an "
             "accidental delete is usually a full re-ingest, not a restore"),
    ),
    "NEP-03": (
        _req("rds:DescribeDBClusterSnapshots",
             "enumerate manual Neptune cluster snapshots, which are the copies that get "
             "shared and moved between accounts"),
        _req("rds:DescribeDBClusterSnapshotAttributes",
             "read the restore attribute -- a value of 'all' means ANY AWS account can "
             "restore the graph, which is an observation rather than an inference"),
    ),
    "NEP-04": (
        _req("rds:DescribeDBClusterSnapshots",
             "read StorageEncrypted on manual snapshots -- an unencrypted snapshot is a "
             "plaintext copy of the graph that outlives the cluster it came from"),
    ),
    # AUR-07/08 and ELC-07/08 read fields already present in responses the scanner
    # fetches for AUR-01..03 and ELC-01..04, so they cost NO new call and NO new grant.
    # Listed anyway, because the ledger's job is to say what each check reads.
    "AUR-07": (
        _req("rds:DescribeDBClusters",
             "read BackupRetentionPeriod from the CLUSTER -- for Aurora this is where "
             "it lives, and a Serverless v1 cluster has no instance to read instead"),
    ),
    "AUR-08": (
        _req("rds:DescribeDBClusters",
             "read IAMDatabaseAuthenticationEnabled from the CLUSTER -- whether "
             "applications hold a static DB password or a 15-minute IAM token"),
    ),
    "ELC-07": (
        _req("elasticache:DescribeReplicationGroups",
             "read SnapshotRetentionLimit -- whether anything exists to restore a "
             "flushed or corrupted Redis dataset from"),
    ),
    "ELC-08": (
        _req("elasticache:DescribeReplicationGroups",
             "read MultiAZ -- whether an availability-zone failure removes the whole "
             "cache, which also decides whether ELC-04's failover has anywhere to go"),
    ),
    # ── Timestream, likewise uncovered ───────────────────────────────────────
    # Keyspaces is NOT here on purpose: its only control-plane read action is
    # cassandra:Select, which also authorises reading table ROWS. See
    # aws_cis_db.NOT_DETERMINABLE['keyspaces-needs-a-data-read-grant'].
    "TS-01": (
        _req("timestream:ListDatabases",
             "enumerate Timestream databases, which is the only way to reach tables"),
        _req("timestream:ListTables",
             "read MagneticStoreWriteProperties -- the encryption option on the bucket "
             "the SERVICE writes rejected customer records to"),
    ),
    "TS-02": (
        _req("timestream:ListTables",
             "read whether magnetic-store writes have a rejected-data location at all; "
             "without one, records that fail validation are dropped silently"),
    ),
    # ── MemoryDB, which had no posture coverage at all ───────────────────────
    # Three NEW actions. memorydb:* is its own IAM prefix, so a role that can read RDS
    # and ElastiCache can read none of this -- the grant has to be added deliberately.
    "MDB-01": (
        _req("memorydb:DescribeClusters",
             "read TLSEnabled -- set at creation and unchangeable afterwards, so this "
             "decides whether the cluster needs rebuilding rather than reconfiguring"),
    ),
    "MDB-02": (
        _req("memorydb:DescribeClusters",
             "read ACLName, which is the only thing on the cluster naming its access "
             "control"),
        _req("memorydb:DescribeUsers",
             "read Authentication.Type -- a value of 'no-password' is unauthenticated "
             "access as an observation rather than an inference"),
        _req("memorydb:DescribeACLs",
             "resolve the cluster's ACL to the users it grants, since the cluster names "
             "the ACL and not its members"),
    ),
    "MDB-03": (
        _req("memorydb:DescribeClusters",
             "read SnapshotRetentionLimit -- MemoryDB is a durable datastore, so this "
             "is the difference between recoverable and lost"),
    ),
    "MDB-04": (
        _req("memorydb:DescribeClusters",
             "read KmsKeyId -- MemoryDB is always encrypted, so this is key ownership "
             "and not whether the data is protected"),
    ),
    "MDB-05": (
        _req("memorydb:DescribeClusters",
             "read AutoMinorVersionUpgrade -- whether engine security fixes arrive on "
             "their own or wait for somebody to schedule them"),
    ),
    "MDB-06": (
        _req("memorydb:DescribeClusters",
             "read AvailabilityMode -- single-AZ discards the multi-AZ durability that "
             "is the reason to choose MemoryDB over ElastiCache"),
    ),
    # ── TLS enforcement (CIS AWS Database Services v2.0.0) ───────────────────
    # The first checks in the product to read a DB parameter group. Two NEW actions on
    # the scanning role, and they are the whole cost of covering a control that spans
    # four services: nothing in DescribeDBInstances or DescribeDBClusters says whether
    # the database requires TLS or merely accepts it.
    "RDS-14": (
        _req("rds:DescribeDBParameters",
             "read rds.force_ssl / require_secure_transport from the INSTANCE parameter "
             "group -- the only place that says whether TLS is required or optional"),
    ),
    "AUR-06": (
        _req("rds:DescribeDBClusterParameters",
             "read rds.force_ssl / require_secure_transport from the CLUSTER parameter "
             "group, which is where Aurora holds it and where a Serverless v1 cluster "
             "with no instances holds it too"),
    ),
    "DOCDB-06": (
        _req("rds:DescribeDBClusterParameters",
             "read the tls cluster parameter -- DocumentDB ships with it enabled, so "
             "finding it disabled means somebody turned it off deliberately"),
    ),
    "NEP-05": (
        _req("rds:DescribeDBClusterParameters",
             "read neptune_enforce_ssl -- whether Gremlin/SPARQL queries and their "
             "results cross the network in cleartext"),
    ),
    # ── credential exposure joined to identity ───────────────────────────────
    # THE ONE NEW ACTION IN THIS TRANCHE, and the reason it is worth the line in an
    # IAM review: ListAccessKeys returns key IDs, owner, status and creation date. It
    # does NOT return secret access keys -- those are returned exactly once, at
    # creation, and by no API afterwards -- so this stays inside read-only-of-CONFIG,
    # and a key id is an identifier of the same kind as a role ARN.
    #
    # It is NOT the credential report, which NHI-02 already reads. That report carries
    # key AGE and rotation dates and no key IDs at all, so it cannot answer the one
    # question this exists for: is the key in this corpus a key in this account?
    #
    # CREDEXP-02 and -03 need nothing new -- they match against principals already
    # enumerated by GetAccountAuthorizationDetails.
    "CREDEXP-01": (
        _req("iam:ListAccessKeys",
             "list live access key IDs so a key id found in a breach corpus can be "
             "matched against a key that actually exists here -- without it the "
             "highest-value join in the whole feed cannot happen, and an empty "
             "result reads as 'clean' when it means 'not looked at'"),
    ),
    # ── the sibling-service gaps the CIS Database mapping exposed ────────────
    # Five of these seven need NO new action at all: they read fields off the
    # DescribeDBClusters response the section already fetches, so the entire cost of
    # closing four CIS-DB recommendations is one action -- rds:DescribeDBInstances --
    # which most scanning roles already hold for RDS itself. Recorded per check anyway,
    # so a reviewer sees what each grant buys rather than inferring it from the service
    # the client was built for. Neptune and DocumentDB both authorise under rds:*.
    "NEP-06": (
        _req("rds:DescribeDBInstances",
             "read PubliclyAccessible on Neptune INSTANCES -- the cluster response does "
             "not carry it, and Neptune has no database users, so on a cluster without "
             "IAM auth the security group is the whole of access control"),
    ),
    "NEP-07": (
        _req("rds:DescribeDBClusters",
             "read BackupRetentionPeriod -- how far back a recovery can reach on a "
             "cluster whose only other recovery path is a full re-ingest"),
    ),
    "NEP-08": (
        _req("rds:DescribeDBClusters",
             "read IAMDatabaseAuthenticationEnabled -- for Neptune this is not one "
             "authentication option among several, it is the only one the engine has"),
    ),
    "NEP-09": (
        _req("rds:DescribeDBClusters",
             "read EnabledCloudwatchLogsExports -- whether any record of which "
             "traversals were run survives the cluster"),
    ),
    "NEP-10": (
        _req("rds:DescribeDBClusters",
             "read MultiAZ -- Neptune storage already spans three zones, so this asks "
             "the different question of whether an instance is left to serve it"),
    ),
    "DOCDB-07": (
        _req("rds:DescribeDBInstances",
             "read PubliclyAccessible on DocumentDB INSTANCES -- a document holds a "
             "whole entity rather than a joinable fragment, so one authentication "
             "against a public endpoint returns complete records"),
    ),
    "DOCDB-08": (
        _req("rds:DescribeDBClusters",
             "read BackupRetentionPeriod -- a document store has no schema to reject a "
             "bad write, so the window has to outlast a slow discovery"),
    ),
    "IMGB-01": (
        _req("imagebuilder:ListImages",
         "enumerate golden images this account owns and builds"),
        _req("imagebuilder:GetImagePolicy",
             "read the resource policy -- a wildcard principal shares the image and "
             "everything baked into it"),
    ),
    "XFER-01": (
        _req("transfer:ListServers",
         "enumerate Transfer Family file-transfer servers"),
        _req("transfer:DescribeServer",
             "read Protocols -- plain FTP carries credentials and file contents in "
             "cleartext (FTPS is NOT this finding)"),
    ),
    "XFER-02": (
        _req("transfer:DescribeServer",
             "read LoggingRole -- without one the service writes no audit trail at all"),
    ),
    "XFER-03": (
        _req("transfer:DescribeServer",
             "read EndpointType -- context for the other two findings on the server"),
    ),
    # Slice 5.2 -- the data perimeter. ListPoliciesForTarget/DescribePolicy are
    # normally callable only from the management or a delegated-admin account, so a
    # member-account scan will legitimately be denied these and report the perimeter as
    # UNREADABLE. That is the correct outcome and the reason these are recorded: a
    # declined grant must name what it costs rather than silently becoming a clean pass.
    "PERIM-01": (
        _req("organizations:ListPoliciesForTarget",
             "list the Resource Control Policies attached from the account up to the "
             "org root -- the policy type AWS names for the trusted-identities "
             "perimeter (an SCP cannot implement it)"),
        _req("organizations:DescribePolicy",
             "read each policy's document to see whether it carries aws:PrincipalOrgID"),
    ),
    "PERIM-02": (
        _req("organizations:ListPoliciesForTarget",
             "list the Service Control Policies attached up to the org root -- the "
             "policy type AWS names for the trusted-resources perimeter"),
        _req("organizations:DescribePolicy",
             "read each policy's document to see whether it carries aws:ResourceOrgID"),
    ),
    "PERIM-03": (
        _req("organizations:ListPoliciesForTarget",
             "list SCPs and RCPs -- both implement the expected-networks perimeter, and "
             "only an RCP reaches AWS service principals"),
        _req("organizations:DescribePolicy",
             "read each policy's document for aws:SourceIp / aws:SourceVpc"),
    ),
    # Slice 5.3 needs no NEW action: ec2:DescribeInstanceTypes falls under
    # SecurityAudit's ec2:Describe*. Recorded so declining it names what it costs, and
    # because the ZTMM Networks/Traffic encryption function depends on these two.
    "NITRO-01": (
        _req("ec2:DescribeInstanceTypes",
             "read NetworkInfo.EncryptionInTransitSupported -- whether the instance "
             "TYPE automatically encrypts in-transit traffic between instances, which "
             "is the only readable answer to whether east-west traffic is encrypted "
             "below the application"),
    ),
    "NITRO-02": (
        _req("ec2:DescribeInstanceTypes",
             "read Hypervisor -- whether the instance predates the Nitro platform "
             "generation and its isolation guarantees"),
    ),
    "MART-01": (
        _req("sagemaker:DescribeModel",
             "read ModelDataUrl and ModelDataSource.S3Uri -- WHERE the container loads "
             "executable model code from"),
        _req("s3:GetBucketPolicy",
             "read who may WRITE to that bucket; whoever can is who executes code "
             "inside the endpoint on its next deploy"),
    ),
    "MART-02": (
        _req("sagemaker:DescribeModel",
             "read ModelDataSource.ETag -- whether the artifact reference is pinned to "
             "a version, or resolves to whatever sits at the URI at deploy time"),
    ),
    "MART-03": (
        _req("sagemaker:DescribeModel",
             "read the artifact URI's bucket, to tell an in-account artifact from one "
             "loaded out of somebody else's account"),
    ),
    # MART-04 has NO entry here, deliberately. It needs s3:GetObject, which crosses the
    # read-only-of-CONFIG line by action class -- and this table feeds the ALWAYS-ON
    # additive policy, which is the ask an operator approves once and forgets. Putting
    # a content read there would smuggle the crossing into the default grant.
    #
    # The guard caught this: test_the_additive_policy_contains_only_read_actions names
    # s3:GetObject and logs:StartQuery explicitly as belonging to "the separate opt-in
    # blocks". VPC flow logs set that precedent in FLOW-00 and MART-04 follows it --
    # the action is documented in deploy/cnapp-scanner-role.yaml as its own named
    # policy, granted only by an operator who ran --scan-model-artifacts on purpose.
    # See D10.
    "MART-05": (
        _req("sagemaker:DescribeModel",
             "read the artifact URI's suffix, which is enough to say the format can "
             "execute on load without reading a byte of it"),
    ),
    "SHAI-01": (
        _req("cloudtrail:LookupEvents",
             "read AI resource CREATION events -- who stood up an agent, a knowledge "
             "base or a guardrail, which is the moment shadow AI becomes visible"),
    ),
    "SHAI-02": (
        _req("cloudtrail:LookupEvents",
             "read the regions AI was created in, including regions this scan never "
             "enumerated and therefore never assessed"),
    ),
    "SHAI-03": (
        _req("ec2:DescribeVpcEndpoints",
             "read whether Bedrock traffic has a governed path -- without an interface "
             "endpoint it leaves via NAT or an internet gateway, where no endpoint "
             "policy can bound which models are reachable"),
    ),
    "AILOG-01": (
        _req("bedrock:GetModelInvocationLoggingConfiguration",
             "read s3Config and cloudWatchConfig -- WHERE the prompts and completions "
             "are written, which is the destination this check then assesses"),
    ),
    "AILOG-02": (
        _req("bedrock:GetModelInvocationLoggingConfiguration",
             "identify the prompt-log destination whose key custody is in question"),
    ),
    "AILOG-03": (
        _req("bedrock:GetModelInvocationLoggingConfiguration",
             "identify the prompt-log destination whose retention is in question"),
    ),
    "AILOG-04": (
        _req("cloudtrail:DescribeTrails", "enumerate the trails in the account"),
        _req("cloudtrail:GetEventSelectors",
             "read each trail's ADVANCED event selectors -- whether any of them names "
             "AWS::Bedrock::Model, without which there is no record of who invoked "
             "which model"),
    ),
    "AILOG-05": (
        _req("cloudtrail:GetEventSelectors",
             "read which Bedrock resource types are covered by data events"),
    ),
    "AILOG-06": (
        _req("cloudtrail:GetEventSelectors",
             "read which AgentCore resource types are covered -- an agent's own "
             "actions leave no data-plane record without them"),
    ),
    "VEC-01": (
        _req("aoss:ListCollections", "find OpenSearch Serverless collections"),
        _req("aoss:BatchGetCollection",
             "read collectionType, which is what separates a VECTORSEARCH store -- the "
             "agent's memory -- from a log-analytics collection this slice ignores"),
        _req("aoss:ListSecurityPolicies",
             "enumerate the network policies, ALL of which must be read: a public "
             "rule in any policy matching a collection overrides a private rule in "
             "another, so reading one of them is not reading the answer"),
        _req("aoss:GetSecurityPolicy",
             "read AllowFromPublic and SourceVPCEs -- whether the corpus endpoint is "
             "reachable from the internet"),
    ),
    "VEC-02": (
        _req("aoss:ListAccessPolicies",
             "enumerate the data access policies, which are the control that "
             "actually decides retrieval -- the network only decides who can reach "
             "the endpoint"),
        _req("aoss:GetAccessPolicy",
             "read the principals a data access policy grants -- the control that "
             "decides who can READ the vectors, independent of the network"),
    ),
    "VEC-03": (
        _req("aoss:GetSecurityPolicy", "the reach half of the composition"),
        _req("aoss:GetAccessPolicy", "the read half of the composition"),
    ),
    "VEC-04": (
        _req("aoss:BatchGetCollection",
             "read kmsKeyArn -- whether the corpus is on a key the customer can revoke"),
    ),
    "VEC-05": (
        _req("s3vectors:ListVectorBuckets",
             "find S3 Vectors buckets -- the other place a RAG corpus lives, and "
             "one no existing OverWatch section enumerates"),
        _req("s3vectors:GetVectorBucketPolicy",
             "read the resource policy -- whether the corpus is exposed to anyone"),
    ),
    "VEC-06": (
        _req("s3vectors:GetVectorBucketPolicy",
             "read named external principals, reported apart from public because a "
             "partner integration is frequently deliberate"),
    ),
    "VEC-07": (
        _req("s3vectors:GetVectorBucket",
             "read encryptionConfiguration -- sseType AES256 is SSE-S3 and aws:kms "
             "without an ARN is still AWS-managed; neither is a key you can disable"),
    ),
    "AGC-07": (
        _req("bedrock-agentcore:GetTokenVault",
             "read whether the store holding every agent credential for systems "
             "outside AWS is on a key the customer can revoke, audit and bound, or "
             "on one they cannot"),
    ),
    "AGC-08": (
        _req("bedrock-agentcore:GetWorkloadIdentity",
             "read allowedResourceOauth2ReturnUrls -- where an OAuth flow may hand "
             "an authorization code back, and whether any of those hand-backs "
             "happen over plaintext"),
    ),
    "AGY-01": (
        _req("bedrock:GetAgentActionGroup",
             "read parentActionSignature -- whether an agent holds a shell or "
             "desktop-control capability, which is excessive agency in the form "
             "OWASP LLM06 calls excessive functionality"),
    ),
    "AGY-02": (
        _req("bedrock:GetAgentActionGroup",
             "read parentActionSignature for the code-execution and file-access "
             "capabilities, whose reach is the execution role rather than the "
             "sandbox around them"),
    ),
    "AGY-03": (
        _req("bedrock:GetAgentActionGroup",
             "read requireConfirmation on each function -- the control AWS names as "
             "the prompt-injection safeguard, and which is DISABLED unless set"),
    ),
    "AGC-05": (
        _req("bedrock-agentcore:GetGatewayTarget",
             "read each target's credentialProviderConfigurations -- the field the "
             "verdict actually turns on, and which appears on NO other response"),
        _req("bedrock-agentcore:GetGateway",
             "read authorizerType and the policy-engine/interceptor configuration -- whether the gateway authorizes its callers, or admits them and lets something else decide"),
        _req("bedrock-agentcore:ListGatewayTargets",
             "read each target's outbound credential type, which is what decides whether a permissive inbound mode is a delegated design or an open door"),
    ),
    # Slice 3.3. GetGatewayTarget is the ONLY response carrying
    # credentialProviderConfigurations and targetConfiguration -- ListGatewayTargets
    # returns TargetSummary, which has neither. AGC-05 is listed here because it grades
    # on the credential field: without this action it can no longer be graded, which is
    # a correction to a check that previously read the field off the summaries and got
    # [] for every gateway in existence.
    "MCP-01": (
        _req("bedrock-agentcore:GetGatewayTarget",
             "read targetConfiguration.mcp.mcpServer.endpoint -- whether a gateway "
             "federates a tool provider from outside this account, which is the only "
             "provenance record AWS keeps for one"),
    ),
    "MCP-02": (
        _req("bedrock-agentcore:GetGatewayTarget",
             "read the federated endpoint's scheme -- over plaintext, anyone on the "
             "path rewrites what a tool claims to do"),
    ),
    "MCP-04": (
        _req("bedrock-agentcore:GetGatewayTarget",
             "establish that a target federates at all, which is what makes the "
             "un-recorded tool list a blind spot worth declaring"),
    ),
    "AGC-06": (
        _req("bedrock-agentcore:GetGateway",
             "read exceptionLevel -- whether the gateway returns granular exception detail describing its targets to whoever provoked an error"),
    ),
    "AIGRD-01": (
        _req("bedrock:GetGuardrail",
             "read each guardrail's filter strengths and actions — ListGuardrails\n             returns GuardrailSummary only and carries no filter configuration, so\n             without this the scanner can say a guardrail exists but not whether it\n             blocks anything"),
    ),
    "AIGRD-02": (
        _req("bedrock:GetGuardrail",
             "read inputAction/outputAction — the difference between a guardrail\n             that blocks and one that only reports"),
    ),
    "AIGRD-04": (
        _req("bedrock:GetGuardrail",
             "read the guardrail version, to tell a pinned guardrail from a DRAFT\n             that changes underneath its consumers"),
    ),
    # AIGRD-03 needs NO new action, and that is the point of it: enforcement is
    # decided from identity-policy statements the scanner already collects.
    "AIGRD-03": (),
    "AGT-01": (
        _req("bedrock:ListAgents", "find Bedrock agents"),
        _req("bedrock:GetAgent",
             "read the agent's customer-managed key, instructions and guardrail "
             "association"),
    ),
    "AGT-02": (
        _req("bedrock:GetAgent",
             "resolve the agent's execution role, whose permissions are the true "
             "blast radius of a successful prompt injection"),
    ),
    "AGT-03": (
        _req("bedrock:ListKnowledgeBases", "find RAG knowledge bases"),
        _req("bedrock:GetKnowledgeBase",
             "read the knowledge base's encryption configuration — the retrieval "
             "corpus is the material a model will quote back on request"),
        _req("bedrock:ListDataSources", "find each knowledge base's data sources"),
        _req("bedrock:GetDataSource",
             "read each data source's encryption — an encrypted knowledge base fed "
             "by an unencrypted source still leaves the source readable"),
    ),
    "AGT-04": (
        _req("bedrock:ListAgentActionGroups", "find the agent's tools"),
        _req("bedrock:GetAgentActionGroup",
             "resolve the Lambda an action group invokes — the mechanism by which "
             "model output becomes a real API call"),
        _req("lambda:GetPolicy",
             "read who else may invoke that Lambda, i.e. whether the agent is the "
             "only caller"),
    ),
    "AGT-05": (
        _req("bedrock:GetAgent",
             "read the agent's guardrail association and idle session TTL"),
    ),
    # ── SageMaker (slice 4.1) ─────────────────────────────────────────────────
    # The three entries that were here before were ROTATED BY ONE: "SM-04" (notebook
    # VPC deployment) held the Studio DOMAIN actions, "SM-06" (Studio home-EFS key)
    # held the ENDPOINT-CONFIG actions, and "SM-07" (endpoint-config key) held the
    # NOTEBOOK actions. Every one of them named a different check's resource.
    #
    # The consequence was the ledger telling an operator the opposite of the truth:
    # declining sagemaker:ListNotebookInstances was reported as costing SM-07 alone,
    # when it actually costs SM-01, SM-02, SM-03, SM-04 and SM-12 -- every notebook
    # check there is. "Declining an action names exactly what it costs" is the whole
    # contract of this module, and for SageMaker it was naming the wrong things.
    #
    # Corrected below and extended to all 25 checks. Grouped by the API pair each set
    # of checks shares, because that is the unit an operator actually grants.
    "SM-01": _NOTEBOOK, "SM-02": _NOTEBOOK, "SM-03": _NOTEBOOK, "SM-04": _NOTEBOOK,
    "SM-12": _NOTEBOOK,
    "SM-05": _DOMAIN, "SM-06": _DOMAIN,
    "SM-07": _ENDPOINT_CONFIG, "SM-08": _ENDPOINT_CONFIG,
    "SM-09": _MODEL, "SM-10": _MODEL, "SM-11": _MODEL,
    "SM-13": _DATA_QUALITY, "SM-14": _DATA_QUALITY,
    "SM-15": _EXPLAINABILITY, "SM-16": _EXPLAINABILITY,
    "SM-17": _BIAS, "SM-18": _BIAS,
    "SM-19": _MODEL_QUALITY, "SM-20": _MODEL_QUALITY,
    "SM-21": _SCHEDULE, "SM-22": _SCHEDULE,
    "SM-23": _FEATURE_GROUP, "SM-24": _FEATURE_GROUP,
    "SM-25": _INFERENCE_EXPERIMENT, "SM-26": _INFERENCE_EXPERIMENT,
    "SM-27": _APP_IMAGE_CONFIG,
    "SM-28": _IMAGE,
    # AISPM-01..03 and AIPATH-01 need NO new action: they reason over the IAM
    # principals already cached from GetAccountAuthorizationDetails and over graph
    # edges other sections emitted. Recorded explicitly so the ledger can say
    # "these are free" rather than staying silent about them.
    "AISPM-01": (),
    "AISPM-02": (),
    "AISPM-03": (),
    "AIPATH-01": (),
}

# Ledger entries for checks declared via aws_checkdef. The registry stays free of any
# import of this module, so it builds Requirements through the factory passed in.
from engine import aws_checkdef          # noqa: E402
from engine import aws_cis_compute
from engine import aws_nhi
from engine import aws_extsvc2
from engine import aws_extsvc3
from engine import aws_extsvc4
from engine import aws_extsvc5
from engine import aws_extsvc6
from engine import aws_extsvc7
from engine import aws_mcp           # noqa: E402,F401  (imported for its registrations)

aws_checkdef.merge_requirements(REQUIREMENTS, _req)



def requirements_for(check_id: str) -> Tuple[Requirement, ...]:
    return REQUIREMENTS.get(check_id, ())


# ─── granted-action resolution ───────────────────────────────────────────────
def _matches(patterns: Iterable[str], action: str) -> bool:
    """Wildcard-aware IAM action match. ``bedrock:*`` and ``*`` both grant
    ``bedrock:GetKnowledgeBase``; ``bedrock:Get*`` grants it too."""
    a = action.lower()
    return any(fnmatch(a, p) for p in (patterns or ()))


def granted(statements: Iterable[Mapping], action: str) -> bool:
    """Is ``action`` allowed by these identity statements?

    An explicit Deny that matches wins outright, which mirrors IAM. Resource scoping
    is NOT modelled: an Allow on a narrower resource still counts as granted here,
    because this module answers "will the API call be refused outright", and a
    resource-scoped grant fails per-resource rather than per-action. Conditions are
    likewise not evaluated — a Condition-gated grant is reported as granted, because
    the call may succeed and the ledger's job is to find the actions that CANNOT.
    Both are documented over-approximations in the safe direction: the ledger will
    under-report missing actions rather than demand ones already held."""
    for st in statements or ():
        if st.get("effect") == "Deny" and _matches(st.get("actions", ()), action):
            return False
    for st in statements or ():
        if st.get("effect") == "Allow" and _matches(st.get("actions", ()), action):
            return True
    return False


# ─── the ledger ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Ledger:
    """Which checks this role can evaluate, and what the rest would cost."""
    evaluable: Tuple[str, ...]
    blocked: Mapping[str, Tuple[str, ...]]      # check_id -> missing actions
    free: Tuple[str, ...]                       # checks needing no action at all
    justification: Mapping[str, str]            # action -> why (canonical case)

    @property
    def missing_actions(self) -> Tuple[str, ...]:
        """Every action that would unblock at least one check, canonical case."""
        return tuple(sorted({a for acts in self.blocked.values() for a in acts}))

    def forfeit(self, declined: Iterable[str]) -> Tuple[str, ...]:
        """The checks lost by declining these actions — the number that makes an IAM
        review a decision rather than a leap of faith."""
        low = {d.lower() for d in declined}
        lost = [cid for cid, acts in self.blocked.items()
                if any(a.lower() in low for a in acts)]
        # a check already evaluable can still be lost if it needs a declined action
        for cid in self.evaluable:
            if any(r.key in low for r in requirements_for(cid)):
                lost.append(cid)
        return tuple(sorted(set(lost)))

    def additive_policy(self, sid: str = "CnappAIReadOnly") -> dict:
        """The minimal additive policy, and nothing more. Emitting only what is
        actually missing is the point: a reviewer can diff it against what they
        already grant, and every action in it has a justification below."""
        actions = self.missing_actions
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": sid,
                "Effect": "Allow",
                "Action": list(actions),
                "Resource": "*",
            }] if actions else [],
        }

    def annotated_policy(self, sid: str = "CnappAIReadOnly") -> List[dict]:
        """One row per requested action: what it is, why, and what is lost without
        it. This is the artefact the onboarding wizard renders."""
        rows = []
        for action in self.missing_actions:
            rows.append({
                "action": action,
                "why": self.justification.get(action, ""),
                "enables": [cid for cid, acts in sorted(self.blocked.items())
                            if action in acts],
                "forfeited_if_declined": list(self.forfeit([action])),
            })
        return rows

    def to_dict(self) -> dict:
        return {
            "evaluable": list(self.evaluable),
            "blocked": {k: list(v) for k, v in sorted(self.blocked.items())},
            "free": list(self.free),
            "missing_actions": list(self.missing_actions),
            "annotated_policy": self.annotated_policy(),
        }


def evaluate(statements: Iterable[Mapping],
             requirements: Optional[Mapping[str, Tuple[Requirement, ...]]] = None
             ) -> Ledger:
    """Compute the ledger for a role's normalized identity statements."""
    reqs = REQUIREMENTS if requirements is None else requirements
    statements = list(statements or ())
    evaluable, blocked, free, why = [], {}, [], {}

    for check_id, needs in sorted(reqs.items()):
        if not needs:
            free.append(check_id)
            evaluable.append(check_id)
            continue
        missing = []
        for r in needs:
            why[r.action] = r.why
            if not granted(statements, r.action):
                missing.append(r.action)
        if missing:
            blocked[check_id] = tuple(sorted(missing))
        else:
            evaluable.append(check_id)

    return Ledger(evaluable=tuple(sorted(evaluable)),
                  blocked=dict(sorted(blocked.items())),
                  free=tuple(sorted(free)),
                  justification=dict(sorted(why.items())))


# ─── the coverage manifest ───────────────────────────────────────────────────
@dataclass
class CoverageManifest:
    """Negative assurance: what this scan did NOT establish.

    Every field here exists because its absence produced a confident wrong answer at
    some point in this product's history. A check that returned AccessDenied and one
    that ran and passed are different claims about the world, and a report that renders
    them identically is the failure mode nobody re-reads."""
    scanned_regions: List[str] = field(default_factory=list)
    unscanned_regions: List[str] = field(default_factory=list)
    not_evaluated: Dict[str, str] = field(default_factory=dict)   # check_id -> reason
    missing_actions: List[str] = field(default_factory=list)
    enumerated: List[str] = field(default_factory=list)           # resource types seen
    not_enumerable: Dict[str, str] = field(default_factory=dict)  # type -> action

    def note_denied(self, check_id: str, action: str,
                    scope: Optional[str] = None) -> None:
        """Record a check as NOT EVALUATED. Deliberately distinct from a PASS.

        `scope` names the SURFACE the denial cost us, for a check that reads more than
        one. Without it the sentence "AMEM-01 was not evaluated" is false in a report
        that carries AMEM-01 findings for the surface that was readable — a reader
        who cannot tell "no answer" from "no answer for AgentCore" will read the
        Bedrock findings as the whole picture."""
        self.not_evaluated[check_id] = (
            f"AccessDenied for {scope} — missing {action}" if scope
            else f"AccessDenied — missing {action}")
        if action not in self.missing_actions:
            self.missing_actions.append(action)

    @property
    def complete(self) -> bool:
        """True only if nothing was withheld, denied or skipped. A scan that is not
        complete is not a clean bill of health, and the console should not draw it
        as one."""
        return not (self.unscanned_regions or self.not_evaluated
                    or self.not_enumerable)

    def to_dict(self) -> dict:
        return {
            "complete": self.complete,
            "scanned_regions": sorted(self.scanned_regions),
            "unscanned_regions": sorted(self.unscanned_regions),
            "not_evaluated": dict(sorted(self.not_evaluated.items())),
            "missing_actions": sorted(self.missing_actions),
            "enumerated": sorted(self.enumerated),
            "not_enumerable": dict(sorted(self.not_enumerable.items())),
        }

    @classmethod
    def from_dict(cls, d: Mapping) -> "CoverageManifest":
        d = d or {}
        return cls(
            scanned_regions=list(d.get("scanned_regions", [])),
            unscanned_regions=list(d.get("unscanned_regions", [])),
            not_evaluated=dict(d.get("not_evaluated", {})),
            missing_actions=list(d.get("missing_actions", [])),
            enumerated=list(d.get("enumerated", [])),
            not_enumerable=dict(d.get("not_enumerable", {})),
        )
