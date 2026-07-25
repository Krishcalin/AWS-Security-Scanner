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

# the two read-only extras SecurityAudit/ViewOnly miss (CIEM last-accessed + a few config reads)
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
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "extras" {
  name   = "CnappScannerReadOnlyExtras"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.extras.json
}

# ── OPT-IN grants (default OFF). Each reproduces the corresponding commented CFN block. ──

# Agentless EBS side-scan snapshot lifecycle (WRITES, tag-scoped to cnapp:sidescan).
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
