# CnappScannerRole — the read-only cross-account scanner role, byte-equivalent to
# deploy/cnapp-scanner-role.yaml. `terraform apply` is the IaC alternative to the CFN
# Launch-Stack quick-create produced by cnapp_onboarding. Assumable ONLY by the CNAPP hub
# role, ONLY under the per-tenant sts:ExternalId (confused-deputy guard). Grants read-only
# describe/list of config + IAM — NO customer workload DATA reads, NO write actions.

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "AllowCnappHubAssumeWithExternalId"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.hub_role_arn] # the HUB ROLE, never account-root
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_role" "scanner" {
  name                 = "CnappScannerRole" # fixed name => predictable per-account ARN
  max_session_duration = 3600
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  tags                 = { "cnapp:managed" = "true" }
}

# SecurityAudit + ViewOnlyAccess ONLY. Deliberately NOT ReadOnlyAccess — that grants
# workload DATA reads (s3:GetObject, dynamodb:GetItem, ...) which violate the
# read-only-of-CONFIG contract.
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# the read-only extras SecurityAudit/ViewOnly miss: CIEM last-accessed, a few config
# reads, and the three Bedrock config reads the AI pillar needs (see AiConfigReadGaps)
data "aws_iam_policy_document" "extras" {
  statement {
    sid    = "CiemLastAccessed"
    effect = "Allow"
    actions = [
      "iam:GenerateServiceLastAccessedDetails",
      "iam:GetServiceLastAccessedDetails",
      "iam:GetServiceLastAccessedDetailsWithEntities",
    ]
    resources = ["*"]
  }
  statement {
    sid    = "ConfigReadGapsManagedPoliciesMiss"
    effect = "Allow"
    actions = [
      "ec2:GetEbsEncryptionByDefault",
      "ec2:GetEbsDefaultKmsKeyId",
      "ec2:GetSnapshotBlockPublicAccessState",
      "access-analyzer:ValidatePolicy",
      # Batch 1 of the 426-service coverage gap analysis. Requested explicitly
      # rather than assumed: SecurityAudit may cover some, but that was not
      # verified against the published policy document, and a check that
      # silently degrades to a coverage note everywhere is worse than one that
      # asks. All read-only. Kept byte-identical to cnapp-scanner-role.yaml --
      # test_terraform_parity enforces that the two never drift.
      "iot:ListPolicies",
      "iot:GetPolicy",
      "iot:GetV2LoggingOptions",
      "iot:ListCACertificates",
      "iot:DescribeCACertificate",
      "elasticmapreduce:GetBlockPublicAccessConfiguration",
      "elasticmapreduce:ListClusters",
      "elasticmapreduce:DescribeCluster",
      "codebuild:ListProjects",
      "codebuild:BatchGetProjects",
      "rds:DescribeDBClusters",
      "rds:DescribeDBClusterSnapshots",
      "rds:DescribeDBClusterSnapshotAttributes",
      "imagebuilder:ListImages",
      "imagebuilder:GetImagePolicy",
      "transfer:ListServers",
      "transfer:DescribeServer",
      # Batch 2. IAM prefix for Identity Center is `sso`, not the
      # `sso-admin` client name. Kept byte-identical to the CFN
      # template -- test_terraform_parity enforces no drift.
      "network-firewall:ListFirewalls",
      "network-firewall:DescribeFirewall",
      "network-firewall:DescribeFirewallPolicy",
      "network-firewall:DescribeLoggingConfiguration",
      "lightsail:GetInstances",
      "lightsail:GetInstancePortStates",
      "lightsail:GetRelationalDatabases",
      "acm-pca:ListCertificateAuthorities",
      "acm-pca:GetPolicy",
      "quicksight:DescribeAccountSettings",
      "sso:ListInstances",
      "sso:ListPermissionSets",
      "sso:GetInlinePolicyForPermissionSet",
      "glue:GetDataCatalogEncryptionSettings",
      "glue:GetDevEndpoints",
      # Batch 3. IAM prefix for Managed Prometheus is `aps`, not
      # the `amp` client name. Byte-identical to the CFN template.
      "s3tables:ListTableBuckets",
      "s3tables:GetTableBucketPolicy",
      "s3tables:GetTableBucketEncryption",
      "vpc-lattice:ListServices",
      "vpc-lattice:GetService",
      "vpc-lattice:GetAuthPolicy",
      "codeartifact:ListDomains",
      "codeartifact:GetDomainPermissionsPolicy",
      "codeartifact:ListRepositories",
      "codeartifact:GetRepositoryPermissionsPolicy",
      "ds:DescribeDirectories",
      "ds:DescribeLDAPSSettings",
      "ds:DescribeSharedDirectories",
      "aps:ListWorkspaces",
      "aps:DescribeWorkspace",
      "xray:GetEncryptionConfig",
      # Batch 4. MediaStore omitted: support ended 2025-11-13.
      # Byte-identical to the CFN template.
      "lakeformation:GetDataLakeSettings",
      "lakeformation:ListPermissions",
      "workspaces-web:ListPortals",
      "workspaces-web:GetPortal",
      "storagegateway:ListFileShares",
      "storagegateway:DescribeNFSFileShares",
      "storagegateway:DescribeSMBFileShares",
      "payment-cryptography:ListKeys",
      "payment-cryptography:GetKey",
      "managedblockchain:ListNetworks",
      "managedblockchain:ListMembers",
      "managedblockchain:GetMember",
      # Batch 5. Mail Manager signs as `ses`; CodeGuru Profiler's
      # IAM prefix is `codeguru-profiler`. Byte-identical to CFN.
      "workmail:ListOrganizations",
      "workmail:ListAccessControlRules",
      "workmail:GetDefaultRetentionPolicy",
      "workmail:ListMobileDeviceAccessRules",
      "iotsitewise:DescribeDefaultEncryptionConfiguration",
      "iotsitewise:DescribeLoggingOptions",
      "iotmanagedintegrations:GetDefaultEncryptionConfiguration",
      "ses:ListTrafficPolicies",
      "ses:GetTrafficPolicy",
      "codeguru-profiler:ListProfilingGroups",
      "codeguru-profiler:GetPolicy",
      # Batch 6. CloudHSM's IAM prefix is `cloudhsm`, not the
      # cloudhsmv2 client name. Byte-identical to CFN.
      "verifiedpermissions:ListPolicyStores",
      "verifiedpermissions:GetPolicyStore",
      "cloudhsm:DescribeClusters",
      "cloudhsm:GetResourcePolicy",
      "networkmanager:DescribeGlobalNetworks",
      "networkmanager:GetResourcePolicy",
      "grafana:ListWorkspaces",
      "grafana:DescribeWorkspace",
      "dsql:ListClusters",
      "dsql:GetCluster",
      "iotfleetwise:GetEncryptionConfiguration",
      "iotfleetwise:GetLoggingOptions",
      # Batch 7. Byte-identical to the CFN template.
      "cloudformation:ListStacks",
      "cloudformation:DescribeStacks",
      "cloudformation:GetStackPolicy",
      "fms:ListPolicies",
      "fms:GetPolicy",
      "fms:GetNotificationChannel",
      "ecr-public:DescribeRepositories",
      "ecr-public:GetRepositoryPolicy",
      "mpa:ListApprovalTeams",
      "mpa:GetApprovalTeam",
      "wickr:ListNetworks",
      "wickr:GetNetworkSettings",
      "mediapackagev2:ListChannelGroups",
      "mediapackagev2:ListChannels",
      "mediapackagev2:GetChannelPolicy",
    ]
    resources = ["*"]
  }
  # Bedrock + AgentCore CONFIG reads SecurityAudit v92 does not grant. The
  # bedrock-agentcore actions are a SEPARATE service (AgentCore) whose IAM prefix is
  # bedrock-agentcore, not the bedrock-agentcore-control endpoint name -- a policy
  # written with the endpoint grants nothing and looks correct in review.
  # Originally four Bedrock CONFIG reads SecurityAudit v92 does not grant. Verified against the
  # published policy document: it grants GetAgentKnowledgeBase (a KB association on an
  # agent) but not GetKnowledgeBase, ListAgentActionGroups but not GetAgentActionGroup,
  # ListDataSources but not GetDataSource. Without them AGT-03 and AGT-04 are refused
  # at runtime and, before the preflight ledger existed, reported as if they had run.
  # Always-on rather than opt-in: these read configuration, not content.
  statement {
    sid    = "AiConfigReadGaps"
    effect = "Allow"
    actions = [
      "bedrock:GetKnowledgeBase",
      "bedrock:GetDataSource",
      "bedrock:GetAgentActionGroup",
      "bedrock:GetGuardrail",
      "bedrock-agentcore:ListAgentRuntimes",
      "bedrock-agentcore:GetAgentRuntime",
      "bedrock-agentcore:ListGateways",
      "bedrock-agentcore:GetGateway",
      "bedrock-agentcore:ListGatewayTargets",
      "bedrock-agentcore:ListWorkloadIdentities",
      "bedrock-agentcore:GetTokenVault",
      "bedrock-agentcore:GetWorkloadIdentity",
      "bedrock-agentcore:ListOauth2CredentialProviders",
      "bedrock-agentcore:ListApiKeyCredentialProviders",
      "bedrock-agentcore:ListMemories",
      "bedrock-agentcore:GetGatewayTarget",
      "bedrock-agentcore:GetMemory",
      "bedrock-agentcore:ListBrowsers",
      "bedrock-agentcore:ListCodeInterpreters",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "extras" {
  name   = "CnappScannerReadOnlyExtras"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.extras.json
}


# Generated from engine/aws_call_surface.py -- see the CloudFormation twin.
data "aws_iam_policy_document" "service_reads" {
  statement {
    sid       = "ComputeAndContainerReads"
    effect    = "Allow"
    actions   = [
      "apprunner:DescribeService",
      "apprunner:ListServices",
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeLaunchConfigurations",
      "batch:DescribeJobDefinitions",
      "ec2:DescribeAddresses",
      "ec2:DescribeImageAttribute",
      "ec2:DescribeImages",
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeInstances",
      "ec2:DescribeLaunchTemplateVersions",
      "ec2:DescribeLaunchTemplates",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeRegions",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVolumes",
      "ec2:DescribeVpcEndpoints",
      "ec2:DescribeVpcPeeringConnections",
      "ec2:DescribeVpcs",
      "ecr:DescribeImageScanFindings",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetLifecyclePolicy",
      "ecr:GetRegistryScanningConfiguration",
      "ecr:GetRepositoryPolicy",
      "ecr:GetSigningConfiguration",
      "ecs:DescribeClusters",
      "ecs:DescribeServices",
      "ecs:DescribeTaskDefinition",
      "ecs:DescribeTaskSets",
      "ecs:DescribeTasks",
      "ecs:ListClusters",
      "ecs:ListTaskDefinitions",
      "ecs:ListTasks",
      "eks:DescribeAccessEntry",
      "eks:DescribeCluster",
      "eks:DescribeFargateProfile",
      "eks:DescribeNodegroup",
      "eks:ListAccessEntries",
      "eks:ListAssociatedAccessPolicies",
      "eks:ListClusters",
      "eks:ListFargateProfiles",
      "eks:ListNodegroups",
      "eks:ListPodIdentityAssociations",
      "elasticbeanstalk:DescribeConfigurationSettings",
      "elasticbeanstalk:DescribeEnvironments",
      "imagebuilder:GetDistributionConfiguration",
      "imagebuilder:GetImageRecipe",
      "imagebuilder:ListDistributionConfigurations",
      "imagebuilder:ListImageRecipes",
      "lambda:GetCodeSigningConfig",
      "lambda:GetFunctionCodeSigningConfig",
      "lambda:GetFunctionConcurrency",
      "lambda:GetFunctionRecursionConfig",
      "lambda:GetFunctionUrlConfig",
      "lambda:GetLayerVersionPolicy",
      "lambda:GetPolicy",
      "lambda:ListFunctions",
      "lightsail:GetBuckets",
      "states:DescribeStateMachine",
      "states:ListStateMachines",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "IdentityAndOrgReads"
    effect    = "Allow"
    actions   = [
      "access-analyzer:GetFindingV2",
      "access-analyzer:ListAnalyzers",
      "access-analyzer:ListFindingsV2",
      "account:GetAlternateContact",
      "account:GetContactInformation",
      "cognito-identity:DescribeIdentityPool",
      "cognito-identity:GetIdentityPoolRoles",
      "cognito-identity:ListIdentityPools",
      "cognito-idp:DescribeUserPool",
      "cognito-idp:ListUserPools",
      "iam:GenerateCredentialReport",
      "iam:GetAccountAuthorizationDetails",
      "iam:GetAccountPasswordPolicy",
      "iam:GetAccountSummary",
      "iam:GetCredentialReport",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAccessKeys",
      "iam:ListAttachedRolePolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListEntitiesForPolicy",
      "iam:ListOpenIDConnectProviders",
      "iam:ListOrganizationsFeatures",
      "iam:ListPolicies",
      "iam:ListRolePolicies",
      "iam:ListSAMLProviders",
      "iam:ListUserPolicies",
      "iam:ListVirtualMFADevices",
      "organizations:DescribeOrganization",
      "organizations:DescribePolicy",
      "organizations:DescribeResourcePolicy",
      "organizations:ListParents",
      "organizations:ListPoliciesForTarget",
      "sso:DescribePermissionSet",
      "sts:GetCallerIdentity",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "DataStoreConfigReads"
    effect    = "Allow"
    actions   = [
      "backup:DescribeBackupVault",
      "backup:GetBackupPlan",
      "backup:GetBackupVaultAccessPolicy",
      "backup:ListBackupPlans",
      "backup:ListBackupVaults",
      "drs:DescribeReplicationConfigurationTemplates",
      "drs:DescribeSourceServers",
      "dynamodb:DescribeContinuousBackups",
      "dynamodb:DescribeTable",
      "dynamodb:GetResourcePolicy",
      "dynamodb:ListTables",
      "dynamodb:ListTagsOfResource",
      "elasticache:DescribeCacheClusters",
      "elasticache:DescribeReplicationGroups",
      "elasticfilesystem:DescribeBackupPolicy",
      "elasticfilesystem:DescribeFileSystemPolicy",
      "elasticfilesystem:DescribeFileSystems",
      "es:DescribeDomain",
      "es:ListDomainNames",
      "es:ListTags",
      "glacier:GetVaultAccessPolicy",
      "glacier:GetVaultLock",
      "glacier:GetVaultNotifications",
      "glacier:ListVaults",
      "memorydb:DescribeUsers",
      "rds:DescribeDBInstances",
      "rds:DescribeDBSnapshotAttributes",
      "rds:DescribeDBSnapshots",
      "redshift-serverless:ListNamespaces",
      "redshift-serverless:ListWorkgroups",
      "redshift:DescribeClusterParameters",
      "redshift:DescribeClusters",
      "redshift:DescribeLoggingStatus",
      "s3:GetBucketEncryption",
      "s3:GetBucketLogging",
      "s3:GetBucketPolicy",
      "s3:GetBucketVersioning",
      "s3:GetPublicAccessBlock",
      "s3:HeadBucket",
      "s3:ListBuckets",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "EdgeAndDnsReads"
    effect    = "Allow"
    actions   = [
      "acm:DescribeCertificate",
      "acm:ListCertificates",
      "apigateway:GetApis",
      "apigateway:GetIntegrations",
      "apigateway:GetRestApis",
      "apigateway:GetRoutes",
      "apigateway:GetStages",
      "cloudfront:GetDistributionConfig",
      "cloudfront:ListDistributions",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeLoadBalancerPolicies",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "route53:GetDNSSEC",
      "route53:ListHealthChecks",
      "route53:ListHostedZones",
      "route53:ListQueryLoggingConfigs",
      "route53:ListResourceRecordSets",
      "route53domains:GetDomainDetail",
      "route53domains:ListDomains",
      "route53resolver:ListFirewallRuleGroupAssociations",
      "route53resolver:ListResolverQueryLogConfigs",
      "wafv2:ListResourcesForWebACL",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "ObservabilityAndSecurityReads"
    effect    = "Allow"
    actions   = [
      "bedrock:GetAgent",
      "bedrock:GetCustomModel",
      "bedrock:GetModelInvocationLoggingConfiguration",
      "bedrock:ListAgentActionGroups",
      "bedrock:ListAgentKnowledgeBases",
      "bedrock:ListAgents",
      "bedrock:ListCustomModels",
      "bedrock:ListDataSources",
      "bedrock:ListGuardrails",
      "bedrock:ListKnowledgeBases",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetEventSelectors",
      "cloudtrail:GetTrailStatus",
      "codeartifact:ListRepositoriesInDomain",
      "config:DescribeConfigurationRecorderStatus",
      "inspector2:BatchGetAccountStatus",
      "inspector2:BatchGetFindingDetails",
      "inspector2:ListFindings",
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListKeys",
      "logs:DescribeLogGroups",
      "logs:DescribeMetricFilters",
      "macie2:DescribeBuckets",
      "macie2:GetMacieSession",
      "monitoring:DescribeAlarmsForMetric",
      "monitoring:GetMetricStatistics",
      "sagemaker:DescribeDomain",
      "sagemaker:DescribeEndpointConfig",
      "sagemaker:DescribeFeatureGroup",
      "sagemaker:DescribeInferenceExperiment",
      "sagemaker:DescribeModel",
      "sagemaker:DescribeNotebookInstance",
      "sagemaker:ListDomains",
      "sagemaker:ListEndpointConfigs",
      "sagemaker:ListNotebookInstances",
      "sagemaker:ListTags",
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:ListSecrets",
      "securityhub:GetEnabledStandards",
      "sns:GetTopicAttributes",
      "sns:ListSubscriptions",
      "sns:ListSubscriptionsByTopic",
      "sqs:GetQueueAttributes",
      "sqs:ListQueues",
      "ssm:DescribeInstanceInformation",
      "ssm:DescribeInstancePatchStates",
      "ssm:DescribeInstancePatches",
      "ssm:ListInventoryEntries",
    ]
    resources = ["*"]
  }

  # Managed desktops and streamed applications (CIS AWS End User Compute v1.2.0).
  # `workdocs:` is deliberately absent and must stay absent -- see the CloudFormation
  # twin and tests/test_cis_euc_mapping.py.
  statement {
    sid       = "EndUserComputeReads"
    effect    = "Allow"
    actions   = [
      "workspaces:DescribeWorkspaceDirectories",
      "workspaces:DescribeWorkspaces",
      "workspaces:DescribeWorkspacesConnectionStatus",
      "appstream:DescribeFleets",
      "appstream:DescribeStacks",
      "appstream:DescribeImages",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "service_reads" {
  name   = "CnappScannerServiceReads"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.service_reads.json
}

# ── OPT-IN grants (default OFF). Each reproduces the corresponding commented CFN block. ──

# Agentless EBS side-scan READ-ONLY (pre-existing snapshots) — the key for the DEFAULT
# read-only mode (--side-scan-snapshot-mode existing). Pure EBS-direct block reads +
# ec2:DescribeSnapshots; NO write on the scanned account, so pre-existing mode needs no
# write IAM at all. (Create mode uses CnappSideScanSnapshotOps below, which is a superset.)
resource "aws_iam_role_policy" "sidescan_read" {
  count = var.enable_sidescan_read ? 1 : 0
  name  = "CnappSideScanReadOnly"
  role  = aws_iam_role.scanner.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Resource = "*", Action = [
        "ebs:ListSnapshotBlocks", "ebs:ListChangedBlocks", "ebs:GetSnapshotBlock",
      "ec2:DescribeSnapshots"] },
    ]
  })
}

# Agentless EBS side-scan snapshot lifecycle (WRITES, tag-scoped to cnapp:sidescan) for
# point-in-time create mode (--side-scan-snapshot-mode create). Superset: also carries the
# block reads, so create mode needs only this key.
resource "aws_iam_role_policy" "sidescan" {
  count = var.enable_sidescan ? 1 : 0
  name  = "CnappSideScanSnapshotOps"
  role  = aws_iam_role.scanner.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Resource = "*", Action = [
        "ebs:ListSnapshotBlocks", "ebs:ListChangedBlocks", "ebs:GetSnapshotBlock",
      "ec2:DescribeSnapshots"] },
      { Effect = "Allow", Resource = "arn:aws:ec2:*:*:volume/*", Action = ["ec2:CreateSnapshot"] },
      { Effect = "Allow", Resource = "arn:aws:ec2:*:*:snapshot/*",
        Action = ["ec2:CreateTags", "ec2:CopySnapshot", "ec2:ModifySnapshotAttribute", "ec2:DeleteSnapshot"],
      Condition = { StringEquals = { "aws:ResourceTag/cnapp:sidescan" = "true" } } },
    ]
  })
}

# VPC Flow-Log CloudWatch Logs Insights reads (--flow-logs), scoped to the log-group ARNs.
resource "aws_iam_role_policy" "flowlog_insights" {
  count = var.enable_flowlog_insights ? 1 : 0
  name  = "CnappFlowLogInsights"
  role  = aws_iam_role.scanner.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["logs:StartQuery"], Resource = var.flow_log_group_arns },
      # GetQueryResults/StopQuery authorize on the queryId, not a log-group ARN
      { Effect = "Allow", Action = ["logs:GetQueryResults", "logs:StopQuery"], Resource = "*" },
    ]
  })
}

# Expanded DSPM datastore surfaces (Kinesis/MemoryDB/FSx/Timestream describe/list; metadata only).
resource "aws_iam_role_policy" "dspm_surfaces" {
  count = var.enable_dspm_surfaces ? 1 : 0
  name  = "CnappDspmSurfaces"
  role  = aws_iam_role.scanner.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Resource = "*", Action = [
      "kinesis:ListStreams", "kinesis:DescribeStreamSummary", "kinesis:ListTagsForStream",
      "memorydb:DescribeClusters", "memorydb:ListTags",
      "fsx:DescribeFileSystems",
      "timestream:ListDatabases", "timestream:ListTables", "timestream:ListTagsForResource",
    ] }]
  })
}

# CDR + cloud-forensics reads (GuardDuty/Security Hub/CloudTrail; mgmt-events only, no data read).
resource "aws_iam_role_policy" "cdr_forensics" {
  count = var.enable_cdr_forensics ? 1 : 0
  name  = "CnappCdrForensicsRead"
  role  = aws_iam_role.scanner.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Resource = "*", Action = [
      "cloudtrail:LookupEvents", "securityhub:GetFindings",
      "guardduty:ListDetectors", "guardduty:GetDetector",
      "guardduty:ListFindings", "guardduty:GetFindings",
    ] }]
  })
}

# ECR registry image layer-pull (Slice-5 Tier B, --side-scan-images): reads image layer
# BYTES (a workload-DATA read), tag-scoped to cnapp:imagescan. GetAuthorizationToken has no
# resource-level support so it takes Resource = "*".
resource "aws_iam_role_policy" "image_layer_pull" {
  count = var.enable_image_layer_pull ? 1 : 0
  name  = "CnappImageLayerPull"
  role  = aws_iam_role.scanner.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
      { Effect = "Allow", Resource = "arn:aws:ecr:*:*:repository/*",
        Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"],
      Condition = { StringEquals = { "aws:ResourceTag/cnapp:imagescan" = "true" } } },
    ]
  })
}

# ── OPT-IN: EKS KSPM/KIEM read-only access ENTRY (a per-cluster access grant, NOT an IAM
# policy — mirrors the CFN comment). Run once at onboarding; the scanner never GETs beyond
# what AmazonEKSViewPolicy allows (pods/SA/PSA/NetworkPolicy; excludes secrets).
resource "aws_eks_access_entry" "scanner" {
  for_each      = var.enable_eks_kspm ? toset(var.eks_cluster_names) : toset([])
  cluster_name  = each.value
  principal_arn = aws_iam_role.scanner.arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "scanner_view" {
  for_each      = var.enable_eks_kspm ? toset(var.eks_cluster_names) : toset([])
  cluster_name  = each.value
  principal_arn = aws_iam_role.scanner.arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
  access_scope { type = "cluster" }
  depends_on = [aws_eks_access_entry.scanner]
}
