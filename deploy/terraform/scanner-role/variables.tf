variable "external_id" {
  type        = string
  sensitive   = true
  description = "Per-customer STS ExternalId issued by the CNAPP hub at onboarding (server-generated — never invent your own). Mirrors the CFN ExternalId parameter."
  validation {
    condition     = length(var.external_id) >= 16
    error_message = "external_id must be at least 16 characters (mirrors CFN MinLength: 16)."
  }
}

variable "hub_role_arn" {
  type        = string
  default     = "arn:aws:iam::HUB_ACCOUNT_ID:role/CnappHubRole"
  description = "The CNAPP hub role ARN — the sole trusted principal allowed to assume this role."
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/.+$", var.hub_role_arn))
    error_message = "hub_role_arn must be an arn:aws:iam::<12-digit-account>:role/<name> (mirrors CFN AllowedPattern)."
  }
}

# ── opt-in grants (default OFF; each gates a policy that reproduces a commented CFN block) ──

# Two-key EBS side-scan (see aws_sidescan_ebs). The DEFAULT read-only mode (--side-scan-
# snapshot-mode existing) reads PRE-EXISTING snapshots and needs only enable_sidescan_read
# (zero write on the scanned account). Point-in-time create mode (--side-scan-snapshot-mode
# create) additionally needs enable_sidescan (the snapshot-lifecycle WRITES).
variable "enable_sidescan_read" {
  type        = bool
  default     = false
  description = "Agentless EBS side-scan READ-ONLY (pre-existing snapshots): ebs:*SnapshotBlock + ec2:DescribeSnapshots. No writes on the scanned account. This is the key for the default read-only side-scan mode."
}

variable "enable_sidescan" {
  type        = bool
  default     = false
  description = "Agentless EBS side-scan snapshot-lifecycle WRITES (ec2:CreateSnapshot/CopySnapshot/DeleteSnapshot, tag-scoped to cnapp:sidescan) for point-in-time create mode. A superset that also carries the block reads, so create mode needs only this key."
}

variable "enable_flowlog_insights" {
  type        = bool
  default     = false
  description = "VPC Flow-Log CloudWatch Logs Insights reads (--flow-logs)."
}

variable "flow_log_group_arns" {
  type        = list(string)
  default     = ["*"]
  description = "Log-group ARN(s) logs:StartQuery is scoped to when enable_flowlog_insights=true. Scope to your flow-log log groups; default '*' is a convenience, not least-privilege."
}

variable "enable_dspm_surfaces" {
  type        = bool
  default     = false
  description = "Expanded DSPM datastore surfaces (Kinesis/MemoryDB/FSx/Timestream describe/list; metadata only)."
}

variable "enable_cdr_forensics" {
  type        = bool
  default     = false
  description = "CDR + cloud-forensics reads (GuardDuty/Security Hub/CloudTrail; mgmt-events only, no data read)."
}

variable "enable_eks_kspm" {
  type        = bool
  default     = false
  description = "Create a read-only EKS access entry (AmazonEKSViewPolicy) for the KSPM/KIEM in-cluster layer on each cluster in eks_cluster_names."
}

variable "enable_image_layer_pull" {
  type        = bool
  default     = false
  description = "ECR registry image layer-pull (Slice-5 Tier B, --side-scan-images): reads image layer bytes (a workload-DATA read class) tag-scoped to cnapp:imagescan. Off by default."
}

variable "eks_cluster_names" {
  type        = list(string)
  default     = []
  description = "EKS clusters to grant the scanner a read-only access entry on (when enable_eks_kspm=true)."
}
