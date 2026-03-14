#!/usr/bin/env python3
"""
AWS IaC Security Scanner v1.1.0
Static analysis of AWS Infrastructure-as-Code files for security
misconfigurations mapped to CIS AWS Benchmark and AWS Well-Architected
Framework Security Pillar.

Supported inputs:
  - CloudFormation templates (.yaml, .yml, .json with 'Resources' key)
  - Terraform configuration files (.tf)

No AWS credentials required — pure static analysis.
"""

import os
import re
import sys
import json
import html as html_mod
import argparse
from pathlib import Path
from datetime import datetime

try:
    import yaml

    # CloudFormation templates use custom YAML tags (!Ref, !Sub, !GetAtt, etc.)
    # Register passthrough constructors so safe_load does not raise on them.
    def _cf_tag_constructor(loader, tag_suffix, node):
        """Return a plain Python value for any CloudFormation intrinsic tag."""
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_mapping(node, deep=True)

    _CF_LOADER = yaml.SafeLoader
    _CF_LOADER.add_multi_constructor("!", _cf_tag_constructor)

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

VERSION = "1.1.0"

# ============================================================
# TERRAFORM SAST RULES  (regex applied to .tf file content)
# ============================================================
TF_SAST_RULES = [

    # ── S3 ──────────────────────────────────────────────────
    {
        "id": "AWS-S3-TF-001",
        "category": "S3: Public Access",
        "name": "S3 bucket ACL allows full public read-write",
        "severity": "CRITICAL",
        "pattern": r'acl\s*=\s*"public-read-write"',
        "description": "Setting acl=public-read-write grants every internet user read and write access to all bucket objects.",
        "cwe": "CWE-732",
        "recommendation": "Remove the public ACL. Enable S3 Block Public Access at the bucket and account level.",
    },
    {
        "id": "AWS-S3-TF-002",
        "category": "S3: Public Access",
        "name": "S3 bucket ACL allows public read",
        "severity": "HIGH",
        "pattern": r'acl\s*=\s*"public-read"',
        "description": "Setting acl=public-read allows any internet user to list and download all bucket objects.",
        "cwe": "CWE-732",
        "recommendation": "Remove the public ACL. Use pre-signed URLs or CloudFront OAC for public content delivery.",
    },
    {
        "id": "AWS-S3-TF-003",
        "category": "S3: Public Access",
        "name": "S3 Block Public ACLs disabled",
        "severity": "HIGH",
        "pattern": r'block_public_acls\s*=\s*false',
        "description": "Disabling block_public_acls allows public ACLs to be applied, potentially exposing objects.",
        "cwe": "CWE-732",
        "recommendation": "Set block_public_acls = true in aws_s3_bucket_public_access_block.",
    },
    {
        "id": "AWS-S3-TF-004",
        "category": "S3: Public Access",
        "name": "S3 Block Public Policy disabled",
        "severity": "HIGH",
        "pattern": r'block_public_policy\s*=\s*false',
        "description": "Disabling block_public_policy allows bucket policies granting public access to be applied.",
        "cwe": "CWE-732",
        "recommendation": "Set block_public_policy = true in aws_s3_bucket_public_access_block.",
    },
    {
        "id": "AWS-S3-TF-005",
        "category": "S3: Public Access",
        "name": "S3 Ignore Public ACLs disabled",
        "severity": "HIGH",
        "pattern": r'ignore_public_acls\s*=\s*false',
        "description": "Setting ignore_public_acls=false means existing public ACLs on objects remain active.",
        "cwe": "CWE-732",
        "recommendation": "Set ignore_public_acls = true to ignore any public ACLs on the bucket and objects.",
    },
    {
        "id": "AWS-S3-TF-006",
        "category": "S3: Public Access",
        "name": "S3 Restrict Public Buckets disabled",
        "severity": "HIGH",
        "pattern": r'restrict_public_buckets\s*=\s*false',
        "description": "Disabling restrict_public_buckets allows cross-account policies granting public access.",
        "cwe": "CWE-732",
        "recommendation": "Set restrict_public_buckets = true to block public and cross-account access policies.",
    },

    # ── IAM ──────────────────────────────────────────────────
    {
        "id": "AWS-IAM-TF-001",
        "category": "IAM: Overly Permissive Policy",
        "name": "IAM policy uses wildcard Action '*'",
        "severity": "CRITICAL",
        "pattern": r'"Action"\s*:\s*"\*"',
        "description": "A wildcard action grants the identity full access to every AWS action, violating least-privilege.",
        "cwe": "CWE-269",
        "recommendation": "Replace Action: '*' with an explicit list of required actions. Use IAM Access Analyzer to identify minimum permissions.",
    },
    {
        "id": "AWS-IAM-TF-002",
        "category": "IAM: Overly Permissive Policy",
        "name": "IAM policy wildcard Action in list ['*']",
        "severity": "CRITICAL",
        "pattern": r'"Action"\s*:\s*\[\s*"\*"',
        "description": "A wildcard action in the action list grants the identity full access to all AWS actions.",
        "cwe": "CWE-269",
        "recommendation": "Replace the wildcard with an explicit list of required actions following least-privilege principle.",
    },
    {
        "id": "AWS-IAM-TF-003",
        "category": "IAM: Overly Permissive Policy",
        "name": "IAM policy Principal '*' — public access granted",
        "severity": "CRITICAL",
        "pattern": r'"Principal"\s*:\s*"\*"',
        "description": "Setting Principal: '*' grants every AWS account, IAM user, or anonymous user access to this resource.",
        "cwe": "CWE-284",
        "recommendation": "Replace '*' with specific AWS account IDs, IAM roles, or service principals. Never use '*' without Condition constraints.",
    },
    {
        "id": "AWS-IAM-TF-004",
        "category": "IAM: Password Policy",
        "name": "IAM user login profile does not require password reset",
        "severity": "MEDIUM",
        "pattern": r'password_reset_required\s*=\s*false',
        "description": "Not requiring a password reset on new IAM user accounts may leave default passwords in use.",
        "cwe": "CWE-255",
        "recommendation": "Set password_reset_required = true for all new IAM user login profiles.",
    },

    # ── EC2 Security Groups ──────────────────────────────────
    {
        "id": "AWS-SG-TF-001",
        "category": "EC2: Security Group",
        "name": "Security Group allows SSH (22) from any IP",
        "severity": "CRITICAL",
        "pattern": r'(?:cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[[^\]]*(?:0\.0\.0\.0/0|::/0)[^\]]*\]',
        "description": "A security group ingress rule permits SSH access from the entire internet (0.0.0.0/0 or ::/0), enabling brute-force and exploitation attacks.",
        "cwe": "CWE-284",
        "recommendation": "Restrict SSH access to specific trusted IP ranges or use AWS Systems Manager Session Manager to eliminate the need for SSH.",
    },
    {
        "id": "AWS-SG-TF-002",
        "category": "EC2: Security Group",
        "name": "Security Group allows RDP (3389) from any IP",
        "severity": "CRITICAL",
        "pattern": r'from_port\s*=\s*3389[^}]*cidr_blocks',
        "description": "Allowing RDP from the internet exposes Windows instances to brute-force attacks and exploitation.",
        "cwe": "CWE-284",
        "recommendation": "Restrict RDP to specific trusted IPs or use a VPN/bastion host. Consider AWS Session Manager for Windows instances.",
    },
    {
        "id": "AWS-SG-TF-003",
        "category": "EC2: Security Group",
        "name": "Security Group allows all protocols from any IP (from_port=0, to_port=0)",
        "severity": "HIGH",
        "pattern": r'from_port\s*=\s*0[^}]*to_port\s*=\s*0[^}]*(?:0\.0\.0\.0/0)',
        "description": "Allowing all traffic from 0.0.0.0/0 with port range 0-0 effectively opens all ports to the internet.",
        "cwe": "CWE-284",
        "recommendation": "Apply least-privilege to security group rules. Only allow specific ports and protocols from specific sources.",
    },
    {
        "id": "AWS-EC2-TF-001",
        "category": "EC2: Instance Metadata",
        "name": "EC2 IMDSv1 enabled — instance metadata service token not required",
        "severity": "HIGH",
        "pattern": r'http_tokens\s*=\s*"optional"',
        "description": "IMDSv1 allows any code running on the instance to access instance metadata and IAM credentials without authentication, enabling SSRF-to-credential-theft attacks.",
        "cwe": "CWE-306",
        "recommendation": "Set http_tokens = 'required' in metadata_options to enforce IMDSv2 and prevent SSRF attacks.",
    },
    {
        "id": "AWS-EC2-TF-002",
        "category": "EC2: Encryption",
        "name": "EBS volume not encrypted",
        "severity": "HIGH",
        "pattern": r'encrypted\s*=\s*false',
        "description": "Unencrypted EBS volumes expose data if the underlying storage is compromised or the snapshot is shared.",
        "cwe": "CWE-311",
        "recommendation": "Set encrypted = true on all EBS volumes. Enable account-level EBS encryption by default in AWS settings.",
    },
    {
        "id": "AWS-EC2-TF-003",
        "category": "EC2: Public Exposure",
        "name": "EC2 instance assigned public IP address",
        "severity": "MEDIUM",
        "pattern": r'associate_public_ip_address\s*=\s*true',
        "description": "Directly assigning a public IP increases attack surface. Instances should use NAT gateways or load balancers for outbound/inbound traffic.",
        "cwe": "CWE-749",
        "recommendation": "Use private subnets for EC2 instances. Route traffic through NAT gateways and application load balancers.",
    },

    # ── RDS ──────────────────────────────────────────────────
    {
        "id": "AWS-RDS-TF-001",
        "category": "RDS: Public Access",
        "name": "RDS instance publicly accessible",
        "severity": "HIGH",
        "pattern": r'publicly_accessible\s*=\s*true',
        "description": "Making the RDS instance publicly accessible exposes the database endpoint to the internet, enabling brute-force and injection attacks.",
        "cwe": "CWE-284",
        "recommendation": "Set publicly_accessible = false. Place RDS instances in private subnets accessible only from application tier.",
    },
    {
        "id": "AWS-RDS-TF-002",
        "category": "RDS: Encryption",
        "name": "RDS storage not encrypted",
        "severity": "HIGH",
        "pattern": r'storage_encrypted\s*=\s*false',
        "description": "Unencrypted RDS storage exposes database data if the underlying storage is compromised or snapshots are shared.",
        "cwe": "CWE-311",
        "recommendation": "Set storage_encrypted = true and specify a KMS key with kms_key_id.",
    },
    {
        "id": "AWS-RDS-TF-003",
        "category": "RDS: Availability",
        "name": "RDS deletion protection disabled",
        "severity": "MEDIUM",
        "pattern": r'deletion_protection\s*=\s*false',
        "description": "Without deletion protection, the database can be accidentally or maliciously deleted, causing data loss.",
        "cwe": "CWE-693",
        "recommendation": "Set deletion_protection = true for all production RDS instances.",
    },
    {
        "id": "AWS-RDS-TF-004",
        "category": "RDS: Backup",
        "name": "RDS final snapshot skipped — data loss risk on deletion",
        "severity": "MEDIUM",
        "pattern": r'skip_final_snapshot\s*=\s*true',
        "description": "Setting skip_final_snapshot=true means no backup is taken before the database is destroyed, risking permanent data loss.",
        "cwe": "CWE-693",
        "recommendation": "Set skip_final_snapshot = false and specify a final_snapshot_identifier.",
    },
    {
        "id": "AWS-RDS-TF-005",
        "category": "RDS: Backup",
        "name": "RDS automated backup retention disabled (0 days)",
        "severity": "MEDIUM",
        "pattern": r'backup_retention_period\s*=\s*0',
        "description": "Setting backup_retention_period=0 disables automated backups, preventing point-in-time recovery.",
        "cwe": "CWE-693",
        "recommendation": "Set backup_retention_period to at least 7 days (35 for compliance-sensitive workloads).",
    },
    {
        "id": "AWS-RDS-TF-006",
        "category": "RDS: Availability",
        "name": "RDS Multi-AZ not enabled — single point of failure",
        "severity": "LOW",
        "pattern": r'multi_az\s*=\s*false',
        "description": "Single-AZ RDS instances have no automatic failover, causing downtime during maintenance or AZ failures.",
        "cwe": "CWE-693",
        "recommendation": "Set multi_az = true for production databases to enable automatic failover.",
    },

    # ── CloudTrail ───────────────────────────────────────────
    {
        "id": "AWS-CT-TF-001",
        "category": "CloudTrail: Audit Logging",
        "name": "CloudTrail log file validation disabled",
        "severity": "HIGH",
        "pattern": r'enable_log_file_validation\s*=\s*false',
        "description": "Without log file validation, CloudTrail logs can be silently tampered with, undermining audit integrity.",
        "cwe": "CWE-345",
        "recommendation": "Set enable_log_file_validation = true to enable SHA-256 hash validation of log files.",
    },
    {
        "id": "AWS-CT-TF-002",
        "category": "CloudTrail: Audit Logging",
        "name": "CloudTrail not configured as multi-region trail",
        "severity": "MEDIUM",
        "pattern": r'is_multi_region_trail\s*=\s*false',
        "description": "A single-region CloudTrail misses API activity in other regions, creating blind spots for attackers.",
        "cwe": "CWE-778",
        "recommendation": "Set is_multi_region_trail = true to capture API activity in all AWS regions.",
    },
    {
        "id": "AWS-CT-TF-003",
        "category": "CloudTrail: Audit Logging",
        "name": "CloudTrail global service events not included",
        "severity": "MEDIUM",
        "pattern": r'include_global_service_events\s*=\s*false',
        "description": "Excluding global services (IAM, STS, CloudFront) from CloudTrail creates blind spots for IAM activity.",
        "cwe": "CWE-778",
        "recommendation": "Set include_global_service_events = true to capture IAM, STS, and CloudFront API calls.",
    },

    # ── KMS ──────────────────────────────────────────────────
    {
        "id": "AWS-KMS-TF-001",
        "category": "KMS: Key Management",
        "name": "KMS key automatic rotation disabled",
        "severity": "HIGH",
        "pattern": r'enable_key_rotation\s*=\s*false',
        "description": "Without automatic rotation, long-lived KMS keys increase the blast radius of key compromise.",
        "cwe": "CWE-324",
        "recommendation": "Set enable_key_rotation = true to rotate KMS symmetric keys annually.",
    },

    # ── CloudFront ───────────────────────────────────────────
    {
        "id": "AWS-CF-TF-001",
        "category": "CloudFront: Transport Security",
        "name": "CloudFront viewer protocol policy allows plain HTTP",
        "severity": "HIGH",
        "pattern": r'viewer_protocol_policy\s*=\s*"allow-all"',
        "description": "Allowing HTTP exposes content and cookies to interception during transit.",
        "cwe": "CWE-319",
        "recommendation": "Set viewer_protocol_policy = 'redirect-to-https' or 'https-only'.",
    },
    {
        "id": "AWS-CF-TF-002",
        "category": "CloudFront: Transport Security",
        "name": "CloudFront minimum TLS version below TLSv1.2",
        "severity": "HIGH",
        "pattern": r'minimum_protocol_version\s*=\s*"TLSv1(?!\.2|\.3)[^"]*"',
        "description": "TLS 1.0 and 1.1 are deprecated with known vulnerabilities (BEAST, POODLE). Connections using old TLS versions can be attacked.",
        "cwe": "CWE-326",
        "recommendation": "Set minimum_protocol_version = 'TLSv1.2_2021' or higher.",
    },

    # ── ElastiCache ──────────────────────────────────────────
    {
        "id": "AWS-ECACHE-TF-001",
        "category": "ElastiCache: Encryption",
        "name": "ElastiCache at-rest encryption disabled",
        "severity": "HIGH",
        "pattern": r'at_rest_encryption_enabled\s*=\s*false',
        "description": "Unencrypted ElastiCache data is exposed if the underlying storage is compromised.",
        "cwe": "CWE-311",
        "recommendation": "Set at_rest_encryption_enabled = true for all ElastiCache replication groups.",
    },
    {
        "id": "AWS-ECACHE-TF-002",
        "category": "ElastiCache: Encryption",
        "name": "ElastiCache in-transit encryption disabled",
        "severity": "HIGH",
        "pattern": r'transit_encryption_enabled\s*=\s*false',
        "description": "Without in-transit encryption, data between application and cache is sent in plaintext over the network.",
        "cwe": "CWE-319",
        "recommendation": "Set transit_encryption_enabled = true and configure auth_token for Redis clusters.",
    },

    # ── ECS ──────────────────────────────────────────────────
    {
        "id": "AWS-ECS-TF-001",
        "category": "ECS: Container Security",
        "name": "ECS container running in privileged mode",
        "severity": "CRITICAL",
        "pattern": r'privileged\s*=\s*true',
        "description": "A privileged container has root access to the host EC2 instance, enabling full host compromise.",
        "cwe": "CWE-250",
        "recommendation": "Remove privileged = true. Use task IAM roles for specific AWS permissions instead of privileged mode.",
    },
    {
        "id": "AWS-ECS-TF-002",
        "category": "ECS: Container Security",
        "name": "ECS container root filesystem is writable",
        "severity": "MEDIUM",
        "pattern": r'read_only_root_filesystem\s*=\s*false',
        "description": "A writable root filesystem allows attackers to persist malware or modify container binaries.",
        "cwe": "CWE-732",
        "recommendation": "Set read_only_root_filesystem = true and use explicit volume mounts for writable paths.",
    },

    # ── OpenSearch ───────────────────────────────────────────
    {
        "id": "AWS-OS-TF-001",
        "category": "OpenSearch: Transport Security",
        "name": "OpenSearch domain does not enforce HTTPS",
        "severity": "HIGH",
        "pattern": r'enforce_https\s*=\s*false',
        "description": "Allowing HTTP connections to OpenSearch exposes search queries and indexed data to interception.",
        "cwe": "CWE-319",
        "recommendation": "Set enforce_https = true in domain_endpoint_options.",
    },
    {
        "id": "AWS-OS-TF-002",
        "category": "OpenSearch: Encryption",
        "name": "OpenSearch node-to-node encryption disabled",
        "severity": "HIGH",
        "pattern": r'node_to_node_encryption\s*\{[^}]*enabled\s*=\s*false',
        "description": "Without node-to-node encryption, data traveling between cluster nodes is unencrypted and can be intercepted.",
        "cwe": "CWE-319",
        "recommendation": "Set enabled = true inside the node_to_node_encryption block.",
    },

    # ── Redshift ─────────────────────────────────────────────
    {
        "id": "AWS-RS-TF-001",
        "category": "Redshift: Public Access",
        "name": "Redshift cluster publicly accessible",
        "severity": "HIGH",
        "pattern": r'(?:aws_redshift_cluster[^}]*publicly_accessible\s*=\s*true)',
        "description": "A publicly accessible Redshift cluster exposes the data warehouse to the internet.",
        "cwe": "CWE-284",
        "recommendation": "Set publicly_accessible = false. Access Redshift from within the VPC only.",
    },
    {
        "id": "AWS-RS-TF-002",
        "category": "Redshift: Encryption",
        "name": "Redshift cluster not encrypted",
        "severity": "HIGH",
        "pattern": r'(?:aws_redshift_cluster[^}]*encrypted\s*=\s*false)',
        "description": "Unencrypted Redshift clusters expose data warehouse contents if storage is compromised.",
        "cwe": "CWE-311",
        "recommendation": "Set encrypted = true and specify a KMS key with kms_key_id.",
    },

    # ── ECR ──────────────────────────────────────────────────
    {
        "id": "AWS-ECR-TF-001",
        "category": "ECR: Container Registry",
        "name": "ECR repository uses mutable image tags",
        "severity": "MEDIUM",
        "pattern": r'image_tag_mutability\s*=\s*"MUTABLE"',
        "description": "Mutable image tags allow container images to be silently replaced, enabling supply chain attacks.",
        "cwe": "CWE-829",
        "recommendation": "Set image_tag_mutability = 'IMMUTABLE' to prevent image tag overwriting.",
    },

    # ── DynamoDB ─────────────────────────────────────────────
    {
        "id": "AWS-DDB-TF-001",
        "category": "DynamoDB: Encryption",
        "name": "DynamoDB table server-side encryption disabled",
        "severity": "HIGH",
        "pattern": r'server_side_encryption\s*\{[^}]*enabled\s*=\s*false',
        "description": "Without SSE, DynamoDB data at rest is only protected by AWS default encryption (no customer-managed key).",
        "cwe": "CWE-311",
        "recommendation": "Set enabled = true inside the server_side_encryption block and specify a KMS key.",
    },

    # ── Lambda ───────────────────────────────────────────────
    {
        "id": "AWS-LAM-TF-001",
        "category": "Lambda: Availability",
        "name": "Lambda function reserved concurrency set to 0 — function throttled",
        "severity": "MEDIUM",
        "pattern": r'reserved_concurrent_executions\s*=\s*0',
        "description": "Setting reserved_concurrent_executions=0 disables all invocations of the Lambda function, causing an application outage.",
        "cwe": "CWE-400",
        "recommendation": "Remove or increase reserved_concurrent_executions. Use provisioned concurrency for latency-sensitive functions.",
    },

    # ── API Gateway ──────────────────────────────────────────
    {
        "id": "AWS-APIGW-TF-001",
        "category": "API Gateway: Logging",
        "name": "API Gateway stage logging disabled",
        "severity": "MEDIUM",
        "pattern": r'logging_level\s*=\s*"OFF"',
        "description": "Disabling API Gateway logging eliminates visibility into API usage, errors, and potential attacks.",
        "cwe": "CWE-778",
        "recommendation": "Set logging_level = 'INFO' or 'ERROR' and configure an execution log group.",
    },

    # ── Secrets ──────────────────────────────────────────────
    {
        "id": "AWS-CRED-TF-001",
        "category": "Credentials: Hardcoded Secrets",
        "name": "Hardcoded AWS access key ID in Terraform config",
        "severity": "CRITICAL",
        "pattern": r'(?:access_key|aws_access_key_id)\s*=\s*"AKIA[A-Z0-9]{16}"',
        "description": "Hardcoded AWS access key IDs committed to version control expose the credentials to anyone with repository access.",
        "cwe": "CWE-798",
        "recommendation": "Remove hardcoded credentials. Use IAM roles, environment variables, or AWS Secrets Manager.",
    },
    {
        "id": "AWS-CRED-TF-002",
        "category": "Credentials: Hardcoded Secrets",
        "name": "Hardcoded password or secret in Terraform resource",
        "severity": "HIGH",
        "pattern": r'(?:password|master_password|auth_token|secret)\s*=\s*"[^$\{\}"]{8,}"',
        "description": "Hardcoded passwords or secrets in Terraform files are exposed to anyone with access to the code repository.",
        "cwe": "CWE-798",
        "recommendation": "Use AWS Secrets Manager or SSM Parameter Store with data sources to inject secrets at runtime.",
    },

    # ── CloudWatch / Logs ────────────────────────────────────
    {
        "id": "AWS-CW-TF-001",
        "category": "CloudWatch: Log Retention",
        "name": "CloudWatch log group has no retention policy",
        "severity": "MEDIUM",
        "pattern": r'resource\s+"aws_cloudwatch_log_group"[^}]*\}(?![^\{]*retention_in_days)',
        "description": "Log groups without a retention policy retain logs indefinitely, leading to unbounded storage costs and stale data.",
        "cwe": "CWE-532",
        "recommendation": "Set retention_in_days to a value matching your compliance requirements (e.g., 90 or 365).",
    },
    {
        "id": "AWS-CW-TF-002",
        "category": "CloudWatch: Encryption",
        "name": "CloudWatch log group not encrypted with KMS CMK",
        "severity": "MEDIUM",
        "pattern": r'resource\s+"aws_cloudwatch_log_group"[^}]*\}(?![^\{]*kms_key_id)',
        "description": "Without a customer-managed KMS key, CloudWatch log data is encrypted with the AWS-managed key, limiting access control.",
        "cwe": "CWE-311",
        "recommendation": "Specify kms_key_id pointing to a CMK with appropriate key policy for CloudWatch Logs.",
    },
    {
        "id": "AWS-CW-TF-003",
        "category": "CloudWatch: Alarm Actions",
        "name": "CloudWatch alarm has no actions configured",
        "severity": "LOW",
        "pattern": r'resource\s+"aws_cloudwatch_metric_alarm"[^}]*\}(?![^\{]*alarm_actions)',
        "description": "A CloudWatch alarm with no actions does not notify on-call teams or trigger remediation when thresholds are breached.",
        "cwe": "CWE-778",
        "recommendation": "Add alarm_actions pointing to an SNS topic that notifies your operations team.",
    },

    # ── VPC ──────────────────────────────────────────────────
    {
        "id": "AWS-VPC-TF-001",
        "category": "VPC: Flow Logs",
        "name": "VPC has no flow logs enabled",
        "severity": "HIGH",
        "pattern": r'resource\s+"aws_vpc"[^}]*\}(?![^\{]*aws_flow_log)',
        "description": "Without VPC flow logs, network traffic to and from the VPC is not captured, hindering threat detection and forensics.",
        "cwe": "CWE-778",
        "recommendation": "Create an aws_flow_log resource targeting this VPC with traffic_type = 'ALL'.",
    },
    {
        "id": "AWS-VPC-TF-002",
        "category": "VPC: Public Subnet",
        "name": "Subnet configured to assign public IP addresses automatically",
        "severity": "MEDIUM",
        "pattern": r'map_public_ip_on_launch\s*=\s*true',
        "description": "Subnets that auto-assign public IPs expose every launched instance to the internet by default.",
        "cwe": "CWE-284",
        "recommendation": "Set map_public_ip_on_launch = false. Explicitly assign Elastic IPs only where required.",
    },

    # ── WAF ──────────────────────────────────────────────────
    {
        "id": "AWS-WAF-TF-001",
        "category": "WAF: Default Action",
        "name": "WAFv2 WebACL default action is ALLOW",
        "severity": "HIGH",
        "pattern": r'default_action\s*\{\s*allow\s*\{\s*\}',
        "description": "A WAF with a default ALLOW action passes all unmatched requests, reducing protection against web attacks.",
        "cwe": "CWE-284",
        "recommendation": "Set the default_action to block{}. Explicitly allow known-good traffic with rule-based allow statements.",
    },

    # ── GuardDuty ────────────────────────────────────────────
    {
        "id": "AWS-GD-TF-001",
        "category": "GuardDuty: Threat Detection",
        "name": "GuardDuty detector disabled",
        "severity": "HIGH",
        "pattern": r'resource\s+"aws_guardduty_detector"[^}]*enable\s*=\s*false',
        "description": "A disabled GuardDuty detector stops all threat intelligence and anomaly detection for the account/region.",
        "cwe": "CWE-778",
        "recommendation": "Set enable = true and enable optional features (S3 protection, EKS runtime monitoring).",
    },

    # ── AWS Config ───────────────────────────────────────────
    {
        "id": "AWS-CFG-TF-001",
        "category": "Config: Coverage",
        "name": "AWS Config recorder does not record all resource types",
        "severity": "MEDIUM",
        "pattern": r'all_supported\s*=\s*false',
        "description": "Limiting Config to specific resource types creates blind spots in compliance monitoring and change tracking.",
        "cwe": "CWE-778",
        "recommendation": "Set all_supported = true and include_global_resource_types = true inside the recording_group block.",
    },
    {
        "id": "AWS-CFG-TF-002",
        "category": "Config: Coverage",
        "name": "AWS Config recorder excludes global resource types (IAM)",
        "severity": "MEDIUM",
        "pattern": r'include_global_resource_types\s*=\s*false',
        "description": "Excluding global resources (e.g., IAM) from Config leaves critical identity changes untracked.",
        "cwe": "CWE-778",
        "recommendation": "Set include_global_resource_types = true inside the recording_group block.",
    },

    # ── Elastic Beanstalk ────────────────────────────────────
    {
        "id": "AWS-EB-TF-001",
        "category": "Elastic Beanstalk: HTTPS",
        "name": "Elastic Beanstalk load balancer listener uses HTTP",
        "severity": "HIGH",
        "pattern": r'"aws:elb:listener"[^}]*"ListenerProtocol"\s*,\s*"HTTP"',
        "description": "An HTTP listener on the Elastic Beanstalk load balancer transmits user data in plaintext.",
        "cwe": "CWE-319",
        "recommendation": "Configure an HTTPS listener with an ACM certificate. Redirect port 80 to 443.",
    },
    {
        "id": "AWS-EB-TF-002",
        "category": "Elastic Beanstalk: Updates",
        "name": "Elastic Beanstalk managed platform updates disabled",
        "severity": "MEDIUM",
        "pattern": r'"ManagedActionsEnabled"\s*,\s*"false"',
        "description": "Disabling managed platform updates leaves the Elastic Beanstalk environment running outdated, potentially vulnerable platform versions.",
        "cwe": "CWE-1104",
        "recommendation": "Enable managed platform updates with a maintenance window to keep the platform patched.",
    },

    # ── SageMaker ────────────────────────────────────────────
    {
        "id": "AWS-SM-TF-001",
        "category": "SageMaker: Network",
        "name": "SageMaker notebook instance allows direct internet access",
        "severity": "HIGH",
        "pattern": r'direct_internet_access\s*=\s*"Enabled"',
        "description": "Enabling direct internet access for a SageMaker notebook allows data exfiltration and bypasses VPC security controls.",
        "cwe": "CWE-284",
        "recommendation": "Set direct_internet_access = 'Disabled' and route traffic through a VPC with a NAT gateway.",
    },
    {
        "id": "AWS-SM-TF-002",
        "category": "SageMaker: Encryption",
        "name": "SageMaker notebook instance storage not encrypted with CMK",
        "severity": "MEDIUM",
        "pattern": r'resource\s+"aws_sagemaker_notebook_instance"[^}]*\}(?![^\{]*kms_key_id)',
        "description": "Without a customer-managed KMS key, SageMaker notebook EBS storage uses the AWS-managed key.",
        "cwe": "CWE-311",
        "recommendation": "Specify kms_key_id with a CMK. Apply a key policy restricting access to the notebook role.",
    },

    # ── EBS Volume ───────────────────────────────────────────
    {
        "id": "AWS-EBS-TF-001",
        "category": "EBS: Encryption",
        "name": "EBS volume not encrypted",
        "severity": "HIGH",
        "pattern": r'resource\s+"aws_ebs_volume"[^}]*encrypted\s*=\s*false',
        "description": "Unencrypted EBS volumes expose data at rest if the underlying physical storage is compromised.",
        "cwe": "CWE-311",
        "recommendation": "Set encrypted = true and specify a kms_key_id. Enable account-level EBS encryption by default.",
    },

    # ── Step Functions ───────────────────────────────────────
    {
        "id": "AWS-SFN-TF-001",
        "category": "Step Functions: Logging",
        "name": "Step Functions state machine logging is OFF",
        "severity": "MEDIUM",
        "pattern": r'level\s*=\s*"OFF"',
        "description": "With logging disabled on a state machine, execution history and errors are not captured, hampering debugging and auditing.",
        "cwe": "CWE-778",
        "recommendation": "Set level = 'ALL' or 'ERROR' inside the logging_configuration block and specify a CloudWatch log group.",
    },
    {
        "id": "AWS-SFN-TF-002",
        "category": "Step Functions: Tracing",
        "name": "Step Functions X-Ray tracing disabled",
        "severity": "LOW",
        "pattern": r'tracing_configuration\s*\{[^}]*enabled\s*=\s*false',
        "description": "Without X-Ray tracing, distributed execution traces across Lambda and other services are unavailable.",
        "cwe": "CWE-778",
        "recommendation": "Set enabled = true inside the tracing_configuration block.",
    },

    # ── Bedrock ──────────────────────────────────────────────
    {
        "id": "AWS-BR-TF-001",
        "category": "Bedrock: Guardrails",
        "name": "Bedrock agent has no guardrail configured",
        "severity": "HIGH",
        "pattern": r'resource\s+"aws_bedrockagent_agent"[^}]*\}(?![^\{]*guardrail)',
        "description": "A Bedrock agent without guardrails can produce harmful, biased, or policy-violating content.",
        "cwe": "CWE-284",
        "recommendation": "Attach a guardrail with content filters, topic policies, and sensitive information redaction.",
    },
]


# ============================================================
# Finding data class
# ============================================================
class Finding:
    def __init__(self, rule_id, name, category, severity,
                 file_path, line_num, line_content,
                 description, recommendation, cwe=None, cve=None):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.file_path = str(file_path)
        self.line_num = line_num
        self.line_content = line_content.strip() if line_content else ""
        self.description = description
        self.recommendation = recommendation
        self.cwe = cwe
        self.cve = cve


# ============================================================
# Main scanner class
# ============================================================
class AWSIaCScanner:
    SKIP_DIRS = {
        ".git", "node_modules", "target", "build", ".gradle",
        ".idea", "__pycache__", ".next", "dist", "out",
        ".terraform", ".terragrunt-cache",
    }

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[94m",
        "LOW":      "\033[92m",
        "INFO":     "\033[97m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    # Map CF resource type → check method name
    CF_DISPATCH = {
        "AWS::IAM::Role":                           "_cf_iam_role",
        "AWS::IAM::Policy":                         "_cf_iam_policy",
        "AWS::IAM::ManagedPolicy":                  "_cf_iam_policy",
        "AWS::IAM::User":                           "_cf_iam_user",
        "AWS::S3::Bucket":                          "_cf_s3_bucket",
        "AWS::EC2::SecurityGroup":                  "_cf_sg",
        "AWS::EC2::Instance":                       "_cf_ec2_instance",
        "AWS::RDS::DBInstance":                     "_cf_rds_instance",
        "AWS::RDS::DBCluster":                      "_cf_rds_cluster",
        "AWS::Lambda::Function":                    "_cf_lambda",
        "AWS::CloudTrail::Trail":                   "_cf_cloudtrail",
        "AWS::CloudFront::Distribution":            "_cf_cloudfront",
        "AWS::ElasticLoadBalancingV2::Listener":    "_cf_elb_listener",
        "AWS::ApiGateway::Stage":                   "_cf_api_stage",
        "AWS::ApiGatewayV2::Stage":                 "_cf_api_stage",
        "AWS::KMS::Key":                            "_cf_kms_key",
        "AWS::SQS::Queue":                          "_cf_sqs_queue",
        "AWS::SNS::Topic":                          "_cf_sns_topic",
        "AWS::DynamoDB::Table":                     "_cf_dynamodb",
        "AWS::ElastiCache::ReplicationGroup":       "_cf_elasticache",
        "AWS::EKS::Cluster":                        "_cf_eks",
        "AWS::ECS::TaskDefinition":                 "_cf_ecs_task",
        "AWS::Cognito::UserPool":                   "_cf_cognito",
        "AWS::OpenSearchService::Domain":           "_cf_opensearch",
        "AWS::Elasticsearch::Domain":               "_cf_opensearch",
        "AWS::Redshift::Cluster":                   "_cf_redshift",
        "AWS::ECR::Repository":                     "_cf_ecr",
        "AWS::SecretsManager::Secret":              "_cf_secrets_manager",
        # ── High-priority gap services (v1.1.0) ──────────────
        "AWS::CloudWatch::Alarm":                   "_cf_cloudwatch_alarm",
        "AWS::Logs::LogGroup":                      "_cf_log_group",
        "AWS::EC2::VPC":                            "_cf_vpc",
        "AWS::EC2::Subnet":                         "_cf_subnet",
        "AWS::EC2::FlowLog":                        "_cf_flow_log",
        "AWS::WAFv2::WebACL":                       "_cf_waf",
        "AWS::GuardDuty::Detector":                 "_cf_guardduty",
        "AWS::Config::ConfigurationRecorder":       "_cf_config_recorder",
        "AWS::ElasticBeanstalk::Environment":       "_cf_elasticbeanstalk",
        "AWS::SageMaker::NotebookInstance":         "_cf_sagemaker_notebook",
        "AWS::SageMaker::Domain":                   "_cf_sagemaker_domain",
        "AWS::Bedrock::Agent":                      "_cf_bedrock_agent",
        "AWS::EC2::Volume":                         "_cf_ebs_volume",
        "AWS::StepFunctions::StateMachine":         "_cf_stepfunctions",
    }

    def __init__(self, verbose=False):
        self.findings = []
        self.verbose = verbose
        self.scanned_files = 0

    # ----------------------------------------------------------
    # Entry points
    # ----------------------------------------------------------
    def scan_path(self, path):
        path = Path(path)
        if path.is_file():
            self._dispatch_file(path)
        elif path.is_dir():
            self._scan_directory(path)
        else:
            print(f"[-] Path not found: {path}", file=sys.stderr)

    def _scan_directory(self, directory):
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            for filename in files:
                self._dispatch_file(Path(root) / filename)

    def _dispatch_file(self, filepath):
        name = filepath.name.lower()
        suffix = filepath.suffix.lower()
        if suffix == ".tf":
            self._scan_terraform(filepath)
        elif suffix in (".yaml", ".yml"):
            self._scan_cloudformation(filepath)
        elif suffix == ".json" and name not in ("package.json", "package-lock.json", "tsconfig.json"):
            self._scan_cloudformation(filepath)

    # ----------------------------------------------------------
    # Terraform SAST scanning
    # ----------------------------------------------------------
    def _scan_terraform(self, filepath):
        try:
            text = filepath.read_text(errors="replace")
        except OSError:
            return
        self.scanned_files += 1
        self._vprint(f"  [tf] {filepath}")
        self._sast_scan(text, TF_SAST_RULES, filepath)

    def _sast_scan(self, text, rules, filepath):
        compiled = [(rule, re.compile(rule["pattern"], re.MULTILINE | re.DOTALL)) for rule in rules]
        lines = text.splitlines()
        for lineno, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//")):
                continue
            for rule, rx in compiled:
                if rx.search(line):
                    self._add(Finding(
                        rule_id=rule["id"],
                        name=rule["name"],
                        category=rule["category"],
                        severity=rule["severity"],
                        file_path=str(filepath),
                        line_num=lineno,
                        line_content=line.rstrip(),
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        cwe=rule.get("cwe"),
                    ))

    # ----------------------------------------------------------
    # CloudFormation structural scanning
    # ----------------------------------------------------------
    def _scan_cloudformation(self, filepath):
        try:
            text = filepath.read_text(errors="replace")
        except OSError:
            return

        # Determine if this looks like a CF template before parsing
        if "Resources" not in text:
            return

        # Parse
        data = None
        if filepath.suffix.lower() in (".yaml", ".yml"):
            if not HAS_YAML:
                self._warn(f"pyyaml not installed — skipping {filepath}. Install with: pip install pyyaml")
                return
            try:
                data = yaml.load(text, Loader=_CF_LOADER)  # noqa: S506 — custom safe loader with CF tag support
            except Exception as e:
                self._warn(f"YAML parse error in {filepath}: {e}")
                return
        else:
            try:
                data = json.loads(text)
            except (json.JSONDecodeError, ValueError) as e:
                self._warn(f"JSON parse error in {filepath}: {e}")
                return

        if not isinstance(data, dict) or "Resources" not in data:
            return

        resources = data.get("Resources", {})
        if not isinstance(resources, dict):
            return

        self.scanned_files += 1
        self._vprint(f"  [cf] {filepath}")

        for resource_id, resource_def in resources.items():
            if not isinstance(resource_def, dict):
                continue
            rtype = resource_def.get("Type", "")
            props = resource_def.get("Properties", {}) or {}
            method_name = self.CF_DISPATCH.get(rtype)
            if method_name:
                getattr(self, method_name)(resource_id, props, filepath)

    # ----------------------------------------------------------
    # CF check methods — IAM
    # ----------------------------------------------------------
    def _cf_iam_role(self, rid, props, fp):
        # Check AssumeRolePolicyDocument for wildcard principal
        doc = props.get("AssumeRolePolicyDocument", {})
        for stmt in doc.get("Statement", []):
            principal = stmt.get("Principal", {})
            if principal == "*" or (isinstance(principal, dict) and "*" in str(principal)):
                self._add(Finding(
                    rule_id="AWS-IAM-001",
                    name=f"IAM role '{rid}' trust policy allows any principal ('*')",
                    category="IAM: Overly Permissive Trust Policy",
                    severity="CRITICAL",
                    file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                    description="An IAM role with Principal: '*' in its trust policy can be assumed by any AWS entity or anonymous user.",
                    recommendation="Restrict the Principal to specific accounts, services, or ARNs. Add Condition constraints if cross-account access is needed.",
                    cwe="CWE-284",
                ))
        # Check for admin managed policy
        managed = props.get("ManagedPolicyArns", [])
        if isinstance(managed, list):
            for arn in managed:
                if isinstance(arn, str) and "AdministratorAccess" in arn:
                    self._add(Finding(
                        rule_id="AWS-IAM-002",
                        name=f"IAM role '{rid}' has AdministratorAccess managed policy",
                        category="IAM: Overly Permissive Policy",
                        severity="HIGH",
                        file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                        description="Attaching AdministratorAccess grants full unrestricted access to all AWS services and resources.",
                        recommendation="Replace AdministratorAccess with a least-privilege policy scoped to required actions and resources.",
                        cwe="CWE-269",
                    ))

    def _cf_iam_policy(self, rid, props, fp):
        doc = props.get("PolicyDocument", {})
        for stmt in doc.get("Statement", []):
            effect = stmt.get("Effect", "Allow")
            if effect != "Allow":
                continue
            action = stmt.get("Action", [])
            resource = stmt.get("Resource", [])
            action_is_wildcard = action == "*" or action == ["*"]
            resource_is_wildcard = resource == "*" or resource == ["*"]
            if action_is_wildcard and resource_is_wildcard:
                self._add(Finding(
                    rule_id="AWS-IAM-003",
                    name=f"IAM policy '{rid}' allows all actions on all resources (Action:* / Resource:*)",
                    category="IAM: Overly Permissive Policy",
                    severity="CRITICAL",
                    file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                    description="Allow with Action:* and Resource:* grants full administrator access. This is equivalent to AdministratorAccess.",
                    recommendation="Use specific actions and resource ARNs. Run IAM Access Analyzer to determine minimum required permissions.",
                    cwe="CWE-269",
                ))
            elif action_is_wildcard:
                self._add(Finding(
                    rule_id="AWS-IAM-004",
                    name=f"IAM policy '{rid}' uses wildcard Action ('*')",
                    category="IAM: Overly Permissive Policy",
                    severity="HIGH",
                    file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                    description="A wildcard action grants access to all AWS API actions for the specified resource.",
                    recommendation="Replace Action: '*' with an explicit list of required API actions.",
                    cwe="CWE-269",
                ))

    def _cf_iam_user(self, rid, props, fp):
        # Direct inline policies on users are a bad practice
        if props.get("Policies"):
            self._add(Finding(
                rule_id="AWS-IAM-005",
                name=f"IAM user '{rid}' has inline policies attached directly",
                category="IAM: Policy Management",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Attaching policies directly to users makes permission management difficult and error-prone. Policies should be attached to groups or roles.",
                recommendation="Remove inline user policies. Create IAM groups with appropriate policies and add users to groups.",
                cwe="CWE-269",
            ))

    # ----------------------------------------------------------
    # CF check methods — S3
    # ----------------------------------------------------------
    def _cf_s3_bucket(self, rid, props, fp):
        # Public access block
        pab = props.get("PublicAccessBlockConfiguration", {})
        missing_blocks = [
            k for k in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")
            if not pab.get(k, False)
        ]
        if not pab or missing_blocks:
            self._add(Finding(
                rule_id="AWS-S3-001",
                name=f"S3 bucket '{rid}' public access block not fully configured",
                category="S3: Public Access",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description=f"S3 public access block configuration is missing or has these settings disabled: {', '.join(missing_blocks) or 'all'}. This may allow public access via ACLs or bucket policies.",
                recommendation="Set all four PublicAccessBlockConfiguration values to true: BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets.",
                cwe="CWE-732",
            ))
        # Public ACL
        acl = props.get("AccessControl", "")
        if acl in ("PublicRead", "PublicReadWrite", "AuthenticatedRead"):
            sev = "CRITICAL" if acl == "PublicReadWrite" else "HIGH"
            self._add(Finding(
                rule_id="AWS-S3-002",
                name=f"S3 bucket '{rid}' has public ACL: {acl}",
                category="S3: Public Access",
                severity=sev,
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description=f"AccessControl: {acl} makes bucket contents publicly accessible to the internet.",
                recommendation="Remove the public ACL. Use pre-signed URLs or CloudFront with OAC for controlled content delivery.",
                cwe="CWE-732",
            ))
        # Encryption
        enc = props.get("BucketEncryption", {})
        if not enc:
            self._add(Finding(
                rule_id="AWS-S3-003",
                name=f"S3 bucket '{rid}' server-side encryption not configured",
                category="S3: Encryption",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without default encryption, objects uploaded without explicit encryption are stored in plaintext.",
                recommendation="Add BucketEncryption with SSEAlgorithm: aws:kms and a KMS key ARN.",
                cwe="CWE-311",
            ))
        # Versioning
        versioning = props.get("VersioningConfiguration", {})
        if not versioning or versioning.get("Status", "") != "Enabled":
            self._add(Finding(
                rule_id="AWS-S3-004",
                name=f"S3 bucket '{rid}' versioning not enabled",
                category="S3: Data Protection",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without versioning, accidentally deleted or overwritten objects cannot be recovered.",
                recommendation="Enable versioning: VersioningConfiguration: Status: Enabled. Enable MFA delete for critical buckets.",
                cwe="CWE-693",
            ))
        # Logging
        logging_cfg = props.get("LoggingConfiguration", {})
        if not logging_cfg:
            self._add(Finding(
                rule_id="AWS-S3-005",
                name=f"S3 bucket '{rid}' access logging not enabled",
                category="S3: Audit Logging",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without access logging, there is no record of who accessed or modified bucket objects.",
                recommendation="Add LoggingConfiguration with a DestinationBucketName pointing to a separate logging bucket.",
                cwe="CWE-778",
            ))

    # ----------------------------------------------------------
    # CF check methods — EC2 Security Group
    # ----------------------------------------------------------
    def _cf_sg(self, rid, props, fp):
        sensitive_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                           27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
        for rule in props.get("SecurityGroupIngress", []):
            cidr = rule.get("CidrIp", "") or rule.get("CidrIpv6", "")
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            ip_proto = rule.get("IpProtocol", "-1")
            is_open = cidr in ("0.0.0.0/0", "::/0")
            if not is_open:
                continue
            # All traffic
            if ip_proto == "-1":
                self._add(Finding(
                    rule_id="AWS-SG-001",
                    name=f"Security Group '{rid}' allows all traffic from internet",
                    category="EC2: Security Group",
                    severity="HIGH",
                    file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                    description=f"An ingress rule allows all protocols from {cidr}, exposing every port to the internet.",
                    recommendation="Remove the catch-all rule and apply least-privilege ingress rules.",
                    cwe="CWE-284",
                ))
                continue
            # Check sensitive ports
            for port, name in sensitive_ports.items():
                if isinstance(from_port, int) and isinstance(to_port, int):
                    if from_port <= port <= to_port:
                        sev = "CRITICAL" if port in (22, 3389) else "HIGH"
                        self._add(Finding(
                            rule_id="AWS-SG-002",
                            name=f"Security Group '{rid}' allows {name} (port {port}) from internet",
                            category="EC2: Security Group",
                            severity=sev,
                            file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                            description=f"Inbound {name} (port {port}) is accessible from {cidr}, exposing the service to internet-wide attacks.",
                            recommendation=f"Restrict {name} access to specific trusted IP ranges or use a bastion host / SSM Session Manager.",
                            cwe="CWE-284",
                        ))

    # ----------------------------------------------------------
    # CF check methods — EC2 Instance
    # ----------------------------------------------------------
    def _cf_ec2_instance(self, rid, props, fp):
        # IMDSv2
        metadata = props.get("MetadataOptions", {})
        if metadata.get("HttpTokens", "optional") != "required":
            self._add(Finding(
                rule_id="AWS-EC2-001",
                name=f"EC2 instance '{rid}' uses IMDSv1 (HttpTokens not required)",
                category="EC2: Instance Metadata",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="IMDSv1 allows SSRF attacks to steal IAM credentials via the metadata service without authentication.",
                recommendation="Set MetadataOptions.HttpTokens: required to enforce IMDSv2.",
                cwe="CWE-306",
            ))
        # IAM profile
        if not props.get("IamInstanceProfile"):
            self._add(Finding(
                rule_id="AWS-EC2-002",
                name=f"EC2 instance '{rid}' has no IAM instance profile",
                category="EC2: IAM",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without an IAM instance profile, the instance cannot use IAM roles for AWS API calls, leading to hardcoded credentials.",
                recommendation="Assign an IamInstanceProfile with a least-privilege IAM role.",
                cwe="CWE-255",
            ))

    # ----------------------------------------------------------
    # CF check methods — RDS
    # ----------------------------------------------------------
    def _cf_rds_instance(self, rid, props, fp):
        if props.get("PubliclyAccessible", False):
            self._add(Finding(
                rule_id="AWS-RDS-001",
                name=f"RDS instance '{rid}' is publicly accessible",
                category="RDS: Public Access",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="PubliclyAccessible: true exposes the database endpoint to the internet.",
                recommendation="Set PubliclyAccessible: false. Place the RDS instance in a private subnet.",
                cwe="CWE-284",
            ))
        if not props.get("StorageEncrypted", False):
            self._add(Finding(
                rule_id="AWS-RDS-002",
                name=f"RDS instance '{rid}' storage not encrypted",
                category="RDS: Encryption",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="StorageEncrypted: false leaves database data unencrypted at rest.",
                recommendation="Set StorageEncrypted: true and KmsKeyId to a CMK.",
                cwe="CWE-311",
            ))
        if not props.get("DeletionProtection", False):
            self._add(Finding(
                rule_id="AWS-RDS-003",
                name=f"RDS instance '{rid}' deletion protection disabled",
                category="RDS: Availability",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without deletion protection, the database can be accidentally or maliciously deleted.",
                recommendation="Set DeletionProtection: true for all production RDS instances.",
                cwe="CWE-693",
            ))
        backup = props.get("BackupRetentionPeriod", 1)
        if isinstance(backup, int) and backup == 0:
            self._add(Finding(
                rule_id="AWS-RDS-004",
                name=f"RDS instance '{rid}' automated backups disabled",
                category="RDS: Backup",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="BackupRetentionPeriod: 0 disables automated backups, preventing point-in-time recovery.",
                recommendation="Set BackupRetentionPeriod to at least 7 days.",
                cwe="CWE-693",
            ))
        if not props.get("MultiAZ", False):
            self._add(Finding(
                rule_id="AWS-RDS-005",
                name=f"RDS instance '{rid}' Multi-AZ not enabled",
                category="RDS: Availability",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Single-AZ deployment has no automatic failover on hardware failure or AZ outage.",
                recommendation="Set MultiAZ: true for production databases.",
                cwe="CWE-693",
            ))

    def _cf_rds_cluster(self, rid, props, fp):
        if not props.get("DeletionProtection", False):
            self._add(Finding(
                rule_id="AWS-RDS-006",
                name=f"RDS cluster '{rid}' deletion protection disabled",
                category="RDS: Availability",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without deletion protection the cluster can be accidentally destroyed.",
                recommendation="Set DeletionProtection: true.",
                cwe="CWE-693",
            ))
        if not props.get("StorageEncrypted", False):
            self._add(Finding(
                rule_id="AWS-RDS-007",
                name=f"RDS cluster '{rid}' storage not encrypted",
                category="RDS: Encryption",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Unencrypted Aurora cluster storage exposes data if the underlying storage is compromised.",
                recommendation="Set StorageEncrypted: true and specify KmsKeyId.",
                cwe="CWE-311",
            ))

    # ----------------------------------------------------------
    # CF check methods — Lambda
    # ----------------------------------------------------------
    def _cf_lambda(self, rid, props, fp):
        # Dead letter queue
        if not props.get("DeadLetterConfig"):
            self._add(Finding(
                rule_id="AWS-LAM-001",
                name=f"Lambda function '{rid}' has no dead letter queue configured",
                category="Lambda: Error Handling",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without a DLQ, failed Lambda invocations are silently dropped, causing data loss.",
                recommendation="Add a DeadLetterConfig pointing to an SQS queue or SNS topic.",
                cwe="CWE-755",
            ))
        # X-Ray tracing
        tracing = props.get("TracingConfig", {})
        if tracing.get("Mode", "PassThrough") == "PassThrough":
            self._add(Finding(
                rule_id="AWS-LAM-002",
                name=f"Lambda function '{rid}' X-Ray tracing disabled",
                category="Lambda: Observability",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without X-Ray tracing, diagnosing performance issues and security anomalies in Lambda is more difficult.",
                recommendation="Set TracingConfig.Mode: Active to enable AWS X-Ray tracing.",
                cwe="CWE-778",
            ))
        # Env vars with secret-like names
        env_vars = props.get("Environment", {}).get("Variables", {})
        secret_pattern = re.compile(
            r'(?:password|passwd|secret|api_key|apikey|token|credential|private_key)', re.IGNORECASE
        )
        for key in env_vars:
            if secret_pattern.search(key):
                self._add(Finding(
                    rule_id="AWS-LAM-003",
                    name=f"Lambda function '{rid}' may have sensitive value in environment variable '{key}'",
                    category="Lambda: Secret Management",
                    severity="MEDIUM",
                    file_path=str(fp), line_num=None, line_content=f"Resource: {rid}, Env: {key}",
                    description=f"Environment variable '{key}' may contain a secret. Lambda environment variables are visible to anyone with lambda:GetFunction permission.",
                    recommendation="Store secrets in AWS Secrets Manager or SSM Parameter Store and retrieve them at runtime.",
                    cwe="CWE-312",
                ))

    # ----------------------------------------------------------
    # CF check methods — CloudTrail
    # ----------------------------------------------------------
    def _cf_cloudtrail(self, rid, props, fp):
        if not props.get("IsLogging", True):
            self._add(Finding(
                rule_id="AWS-CT-001",
                name=f"CloudTrail trail '{rid}' logging is disabled",
                category="CloudTrail: Audit Logging",
                severity="CRITICAL",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="IsLogging: false stops all API activity recording, creating a complete audit blind spot.",
                recommendation="Set IsLogging: true to enable CloudTrail logging.",
                cwe="CWE-778",
            ))
        if not props.get("EnableLogFileValidation", False):
            self._add(Finding(
                rule_id="AWS-CT-002",
                name=f"CloudTrail trail '{rid}' log file validation disabled",
                category="CloudTrail: Log Integrity",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without log file validation, tampering with CloudTrail logs cannot be detected.",
                recommendation="Set EnableLogFileValidation: true.",
                cwe="CWE-345",
            ))
        if not props.get("IsMultiRegionTrail", False):
            self._add(Finding(
                rule_id="AWS-CT-003",
                name=f"CloudTrail trail '{rid}' not multi-region",
                category="CloudTrail: Coverage",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="A single-region trail misses API activity in other regions.",
                recommendation="Set IsMultiRegionTrail: true.",
                cwe="CWE-778",
            ))
        if not props.get("KMSKeyId"):
            self._add(Finding(
                rule_id="AWS-CT-004",
                name=f"CloudTrail trail '{rid}' logs not encrypted with KMS",
                category="CloudTrail: Encryption",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="CloudTrail log files stored in S3 without KMS encryption rely only on S3 default encryption.",
                recommendation="Specify a KMSKeyId to encrypt CloudTrail logs with a customer-managed KMS key.",
                cwe="CWE-311",
            ))

    # ----------------------------------------------------------
    # CF check methods — CloudFront
    # ----------------------------------------------------------
    def _cf_cloudfront(self, rid, props, fp):
        dist_config = props.get("DistributionConfig", {})
        # Default cache behaviour protocol
        default_cache = dist_config.get("DefaultCacheBehavior", {})
        proto_policy = default_cache.get("ViewerProtocolPolicy", "allow-all")
        if proto_policy == "allow-all":
            self._add(Finding(
                rule_id="AWS-CF-001",
                name=f"CloudFront distribution '{rid}' allows plain HTTP connections",
                category="CloudFront: Transport Security",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="ViewerProtocolPolicy: allow-all permits unencrypted HTTP, exposing content and cookies to interception.",
                recommendation="Set ViewerProtocolPolicy: redirect-to-https or https-only.",
                cwe="CWE-319",
            ))
        # Viewer certificate minimum TLS
        cert = dist_config.get("ViewerCertificate", {})
        min_proto = cert.get("MinimumProtocolVersion", "TLSv1")
        if min_proto in ("TLSv1", "TLSv1_2016", "TLSv1.1_2016"):
            self._add(Finding(
                rule_id="AWS-CF-002",
                name=f"CloudFront distribution '{rid}' uses deprecated TLS version: {min_proto}",
                category="CloudFront: Transport Security",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description=f"MinimumProtocolVersion {min_proto} supports deprecated TLS 1.0/1.1 with known vulnerabilities (BEAST, POODLE).",
                recommendation="Set MinimumProtocolVersion: TLSv1.2_2021 or TLSv1.2_2019.",
                cwe="CWE-326",
            ))
        # WAF
        if not dist_config.get("WebACLId"):
            self._add(Finding(
                rule_id="AWS-CF-003",
                name=f"CloudFront distribution '{rid}' has no WAF WebACL associated",
                category="CloudFront: WAF",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without a WAF, the CloudFront distribution has no protection against common web attacks (SQLi, XSS, etc.).",
                recommendation="Associate an AWS WAFv2 WebACL with the distribution.",
                cwe="CWE-693",
            ))
        # Logging
        if not dist_config.get("Logging"):
            self._add(Finding(
                rule_id="AWS-CF-004",
                name=f"CloudFront distribution '{rid}' access logging disabled",
                category="CloudFront: Audit Logging",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without access logging, there is no record of requests served by the distribution.",
                recommendation="Enable Logging with a Bucket pointing to an S3 logging bucket.",
                cwe="CWE-778",
            ))

    # ----------------------------------------------------------
    # CF check methods — ELB Listener
    # ----------------------------------------------------------
    def _cf_elb_listener(self, rid, props, fp):
        protocol = props.get("Protocol", "HTTPS")
        if protocol == "HTTP":
            self._add(Finding(
                rule_id="AWS-ELB-001",
                name=f"ELB listener '{rid}' uses plain HTTP",
                category="ELB: Transport Security",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="An HTTP listener transmits data and session tokens without encryption.",
                recommendation="Change Protocol to HTTPS and add a certificate ARN. Add an HTTP->HTTPS redirect action.",
                cwe="CWE-319",
            ))
        ssl_policy = props.get("SslPolicy", "")
        deprecated = ("ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS-1-0")
        if any(d in ssl_policy for d in deprecated):
            self._add(Finding(
                rule_id="AWS-ELB-002",
                name=f"ELB listener '{rid}' uses deprecated SSL policy: {ssl_policy}",
                category="ELB: Transport Security",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description=f"SSL policy {ssl_policy} supports TLS 1.0 which has known vulnerabilities.",
                recommendation="Use ELBSecurityPolicy-TLS13-1-2-2021-06 or ELBSecurityPolicy-FS-1-2-Res-2020-10.",
                cwe="CWE-326",
            ))

    # ----------------------------------------------------------
    # CF check methods — API Gateway Stage
    # ----------------------------------------------------------
    def _cf_api_stage(self, rid, props, fp):
        if not props.get("TracingEnabled", False):
            self._add(Finding(
                rule_id="AWS-APIGW-001",
                name=f"API Gateway stage '{rid}' X-Ray tracing disabled",
                category="API Gateway: Observability",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without X-Ray tracing, API latency and error patterns are harder to diagnose.",
                recommendation="Set TracingEnabled: true.",
                cwe="CWE-778",
            ))
        method_settings = props.get("MethodSettings", [])
        if not method_settings:
            self._add(Finding(
                rule_id="AWS-APIGW-002",
                name=f"API Gateway stage '{rid}' has no method-level logging configured",
                category="API Gateway: Audit Logging",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without method-level logging, API access patterns and errors are not recorded.",
                recommendation="Add MethodSettings with LoggingLevel: INFO or ERROR and DataTraceEnabled.",
                cwe="CWE-778",
            ))

    # ----------------------------------------------------------
    # CF check methods — KMS
    # ----------------------------------------------------------
    def _cf_kms_key(self, rid, props, fp):
        if not props.get("EnableKeyRotation", False):
            self._add(Finding(
                rule_id="AWS-KMS-001",
                name=f"KMS key '{rid}' automatic rotation disabled",
                category="KMS: Key Management",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without automatic rotation, long-lived KMS keys increase the blast radius of key compromise.",
                recommendation="Set EnableKeyRotation: true to rotate symmetric keys annually.",
                cwe="CWE-324",
            ))

    # ----------------------------------------------------------
    # CF check methods — SQS
    # ----------------------------------------------------------
    def _cf_sqs_queue(self, rid, props, fp):
        if not props.get("KmsMasterKeyId") and not props.get("SqsManagedSseEnabled", False):
            self._add(Finding(
                rule_id="AWS-SQS-001",
                name=f"SQS queue '{rid}' server-side encryption not configured",
                category="SQS: Encryption",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Messages at rest are not protected by SSE. Sensitive data in queued messages is exposed.",
                recommendation="Set KmsMasterKeyId or enable SqsManagedSseEnabled: true.",
                cwe="CWE-311",
            ))
        if not props.get("RedrivePolicy"):
            self._add(Finding(
                rule_id="AWS-SQS-002",
                name=f"SQS queue '{rid}' has no dead-letter queue (redrive policy)",
                category="SQS: Error Handling",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without a DLQ, failed message processing leads to silent message loss.",
                recommendation="Add a RedrivePolicy pointing to a DLQ with an appropriate maxReceiveCount.",
                cwe="CWE-755",
            ))

    # ----------------------------------------------------------
    # CF check methods — SNS
    # ----------------------------------------------------------
    def _cf_sns_topic(self, rid, props, fp):
        if not props.get("KmsMasterKeyId"):
            self._add(Finding(
                rule_id="AWS-SNS-001",
                name=f"SNS topic '{rid}' server-side encryption not configured",
                category="SNS: Encryption",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without SSE, messages stored in the SNS topic are not encrypted at rest.",
                recommendation="Set KmsMasterKeyId to a KMS CMK ARN.",
                cwe="CWE-311",
            ))

    # ----------------------------------------------------------
    # CF check methods — DynamoDB
    # ----------------------------------------------------------
    def _cf_dynamodb(self, rid, props, fp):
        sse = props.get("SSESpecification", {})
        if not sse.get("SSEEnabled", False):
            self._add(Finding(
                rule_id="AWS-DDB-001",
                name=f"DynamoDB table '{rid}' server-side encryption not enabled",
                category="DynamoDB: Encryption",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without SSE, table data at rest uses the default AWS-owned key with no customer control.",
                recommendation="Set SSESpecification.SSEEnabled: true and SSEType: KMS with a CMK.",
                cwe="CWE-311",
            ))
        pitr = props.get("PointInTimeRecoverySpecification", {})
        if not pitr.get("PointInTimeRecoveryEnabled", False):
            self._add(Finding(
                rule_id="AWS-DDB-002",
                name=f"DynamoDB table '{rid}' point-in-time recovery not enabled",
                category="DynamoDB: Backup",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without PITR, tables cannot be restored to any second within the last 35 days after data corruption.",
                recommendation="Set PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled: true.",
                cwe="CWE-693",
            ))

    # ----------------------------------------------------------
    # CF check methods — ElastiCache
    # ----------------------------------------------------------
    def _cf_elasticache(self, rid, props, fp):
        if not props.get("AtRestEncryptionEnabled", False):
            self._add(Finding(
                rule_id="AWS-ECACHE-001",
                name=f"ElastiCache replication group '{rid}' at-rest encryption disabled",
                category="ElastiCache: Encryption",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Cache data at rest is unencrypted and exposed if the underlying storage is compromised.",
                recommendation="Set AtRestEncryptionEnabled: true.",
                cwe="CWE-311",
            ))
        if not props.get("TransitEncryptionEnabled", False):
            self._add(Finding(
                rule_id="AWS-ECACHE-002",
                name=f"ElastiCache replication group '{rid}' in-transit encryption disabled",
                category="ElastiCache: Encryption",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Data between application and cache is sent in plaintext, enabling interception.",
                recommendation="Set TransitEncryptionEnabled: true and configure an AuthToken.",
                cwe="CWE-319",
            ))
        if not props.get("AuthToken"):
            self._add(Finding(
                rule_id="AWS-ECACHE-003",
                name=f"ElastiCache replication group '{rid}' has no AUTH token",
                category="ElastiCache: Authentication",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without an AUTH token, any client that can reach the cache endpoint can read and write all data.",
                recommendation="Set AuthToken to a strong secret (>= 16 characters). Store the token in AWS Secrets Manager.",
                cwe="CWE-306",
            ))

    # ----------------------------------------------------------
    # CF check methods — EKS
    # ----------------------------------------------------------
    def _cf_eks(self, rid, props, fp):
        resources_vpc = props.get("ResourcesVpcConfig", {})
        if resources_vpc.get("EndpointPublicAccess", True):
            public_cidrs = resources_vpc.get("PublicAccessCidrs", ["0.0.0.0/0"])
            if "0.0.0.0/0" in public_cidrs or not public_cidrs:
                self._add(Finding(
                    rule_id="AWS-EKS-001",
                    name=f"EKS cluster '{rid}' API server publicly accessible from 0.0.0.0/0",
                    category="EKS: API Server Access",
                    severity="HIGH",
                    file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                    description="The Kubernetes API server is accessible from the entire internet with no CIDR restriction.",
                    recommendation="Set EndpointPublicAccess: false and use EndpointPrivateAccess: true, or restrict PublicAccessCidrs to known IPs.",
                    cwe="CWE-284",
                ))
        logging_config = props.get("Logging", {}).get("ClusterLogging", {}).get("EnabledTypes", [])
        if not logging_config:
            self._add(Finding(
                rule_id="AWS-EKS-002",
                name=f"EKS cluster '{rid}' control plane logging not enabled",
                category="EKS: Audit Logging",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without control plane logging, Kubernetes API activity and authentication events are not recorded.",
                recommendation="Enable all log types: api, audit, authenticator, controllerManager, scheduler.",
                cwe="CWE-778",
            ))

    # ----------------------------------------------------------
    # CF check methods — ECS Task Definition
    # ----------------------------------------------------------
    def _cf_ecs_task(self, rid, props, fp):
        network_mode = props.get("NetworkMode", "")
        if network_mode == "host":
            self._add(Finding(
                rule_id="AWS-ECS-001",
                name=f"ECS task definition '{rid}' uses host network mode",
                category="ECS: Container Security",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Host network mode shares the host's network namespace with the container, bypassing network isolation.",
                recommendation="Use awsvpc network mode for task-level network isolation.",
                cwe="CWE-250",
            ))
        for container in props.get("ContainerDefinitions", []):
            cname = container.get("Name", rid)
            if container.get("Privileged", False):
                self._add(Finding(
                    rule_id="AWS-ECS-002",
                    name=f"ECS container '{cname}' in task '{rid}' runs in privileged mode",
                    category="ECS: Container Security",
                    severity="CRITICAL",
                    file_path=str(fp), line_num=None, line_content=f"Resource: {rid}, Container: {cname}",
                    description="A privileged container has root-level access to the host EC2 instance.",
                    recommendation="Remove Privileged: true. Use task IAM roles for AWS API access instead.",
                    cwe="CWE-250",
                ))
            if not container.get("LogConfiguration"):
                self._add(Finding(
                    rule_id="AWS-ECS-003",
                    name=f"ECS container '{cname}' in task '{rid}' has no log configuration",
                    category="ECS: Observability",
                    severity="MEDIUM",
                    file_path=str(fp), line_num=None, line_content=f"Resource: {rid}, Container: {cname}",
                    description="Without LogConfiguration, container stdout/stderr is not forwarded to CloudWatch Logs.",
                    recommendation="Add LogConfiguration with LogDriver: awslogs pointing to a CloudWatch log group.",
                    cwe="CWE-778",
                ))

    # ----------------------------------------------------------
    # CF check methods — Cognito
    # ----------------------------------------------------------
    def _cf_cognito(self, rid, props, fp):
        mfa = props.get("MfaConfiguration", "OFF")
        if mfa == "OFF":
            self._add(Finding(
                rule_id="AWS-COG-001",
                name=f"Cognito user pool '{rid}' MFA is disabled",
                category="Cognito: Authentication",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without MFA, user accounts are vulnerable to credential stuffing and password spraying attacks.",
                recommendation="Set MfaConfiguration: ON or OPTIONAL. Configure SmsConfiguration or SoftwareTokenMfaConfiguration.",
                cwe="CWE-308",
            ))
        pw_policy = props.get("Policies", {}).get("PasswordPolicy", {})
        min_len = pw_policy.get("MinimumLength", 8)
        if isinstance(min_len, int) and min_len < 12:
            self._add(Finding(
                rule_id="AWS-COG-002",
                name=f"Cognito user pool '{rid}' password minimum length too short ({min_len})",
                category="Cognito: Password Policy",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description=f"Minimum password length of {min_len} characters is below the recommended 12 characters.",
                recommendation="Set MinimumLength to at least 12 and enable RequireUppercase, RequireLowercase, RequireNumbers, RequireSymbols.",
                cwe="CWE-521",
            ))

    # ----------------------------------------------------------
    # CF check methods — OpenSearch
    # ----------------------------------------------------------
    def _cf_opensearch(self, rid, props, fp):
        node2node = props.get("NodeToNodeEncryptionOptions", {})
        if not node2node.get("Enabled", False):
            self._add(Finding(
                rule_id="AWS-OS-001",
                name=f"OpenSearch domain '{rid}' node-to-node encryption disabled",
                category="OpenSearch: Encryption",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without node-to-node encryption, data between cluster nodes is sent in plaintext.",
                recommendation="Set NodeToNodeEncryptionOptions.Enabled: true.",
                cwe="CWE-319",
            ))
        at_rest = props.get("EncryptionAtRestOptions", {})
        if not at_rest.get("Enabled", False):
            self._add(Finding(
                rule_id="AWS-OS-002",
                name=f"OpenSearch domain '{rid}' encryption at rest disabled",
                category="OpenSearch: Encryption",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Data at rest in the OpenSearch domain is not encrypted.",
                recommendation="Set EncryptionAtRestOptions.Enabled: true and specify a KMS key.",
                cwe="CWE-311",
            ))
        endpoint_options = props.get("DomainEndpointOptions", {})
        if not endpoint_options.get("EnforceHTTPS", False):
            self._add(Finding(
                rule_id="AWS-OS-003",
                name=f"OpenSearch domain '{rid}' HTTPS not enforced",
                category="OpenSearch: Transport Security",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without enforcing HTTPS, search queries and results are transmitted in plaintext.",
                recommendation="Set DomainEndpointOptions.EnforceHTTPS: true and TLSSecurityPolicy: Policy-Min-TLS-1-2-2019-07.",
                cwe="CWE-319",
            ))

    # ----------------------------------------------------------
    # CF check methods — Redshift
    # ----------------------------------------------------------
    def _cf_redshift(self, rid, props, fp):
        if props.get("PubliclyAccessible", False):
            self._add(Finding(
                rule_id="AWS-RS-001",
                name=f"Redshift cluster '{rid}' is publicly accessible",
                category="Redshift: Public Access",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="A publicly accessible Redshift cluster exposes the data warehouse endpoint to the internet.",
                recommendation="Set PubliclyAccessible: false and access Redshift from within the VPC.",
                cwe="CWE-284",
            ))
        if not props.get("Encrypted", False):
            self._add(Finding(
                rule_id="AWS-RS-002",
                name=f"Redshift cluster '{rid}' not encrypted",
                category="Redshift: Encryption",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Unencrypted Redshift clusters expose data warehouse contents.",
                recommendation="Set Encrypted: true and specify KmsKeyId.",
                cwe="CWE-311",
            ))

    # ----------------------------------------------------------
    # CF check methods — ECR
    # ----------------------------------------------------------
    def _cf_ecr(self, rid, props, fp):
        if props.get("ImageTagMutability", "MUTABLE") == "MUTABLE":
            self._add(Finding(
                rule_id="AWS-ECR-001",
                name=f"ECR repository '{rid}' image tags are mutable",
                category="ECR: Container Registry",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Mutable image tags allow container images to be silently replaced, enabling supply chain attacks.",
                recommendation="Set ImageTagMutability: IMMUTABLE.",
                cwe="CWE-829",
            ))
        scan_config = props.get("ImageScanningConfiguration", {})
        if not scan_config.get("ScanOnPush", False):
            self._add(Finding(
                rule_id="AWS-ECR-002",
                name=f"ECR repository '{rid}' scan-on-push not enabled",
                category="ECR: Image Security",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without scan-on-push, container images with known CVEs may be deployed without detection.",
                recommendation="Set ImageScanningConfiguration.ScanOnPush: true.",
                cwe="CWE-1104",
            ))

    # ----------------------------------------------------------
    # CF check methods — Secrets Manager
    # ----------------------------------------------------------
    def _cf_secrets_manager(self, rid, props, fp):
        if not props.get("KmsKeyId"):
            self._add(Finding(
                rule_id="AWS-SM-001",
                name=f"Secrets Manager secret '{rid}' not encrypted with CMK",
                category="Secrets Manager: Encryption",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without a CMK, the secret is encrypted with the AWS-managed default key, limiting key access control.",
                recommendation="Specify a KmsKeyId pointing to a customer-managed KMS key.",
                cwe="CWE-311",
            ))

    # ----------------------------------------------------------
    # CF check methods — CloudWatch Alarm (v1.1.0)
    # ----------------------------------------------------------
    def _cf_cloudwatch_alarm(self, rid, props, fp):
        if not props.get("AlarmActions") and not props.get("OKActions") and not props.get("InsufficientDataActions"):
            self._add(Finding(
                rule_id="AWS-CW-001",
                name=f"CloudWatch alarm '{rid}' has no actions configured",
                category="CloudWatch: Alarm Actions",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="An alarm with no actions does not notify teams or trigger remediation when thresholds are breached.",
                recommendation="Add AlarmActions pointing to an SNS topic. Configure OKActions to signal recovery.",
                cwe="CWE-778",
            ))

    # ----------------------------------------------------------
    # CF check methods — CloudWatch Log Group (v1.1.0)
    # ----------------------------------------------------------
    def _cf_log_group(self, rid, props, fp):
        if not props.get("RetentionInDays"):
            self._add(Finding(
                rule_id="AWS-CW-002",
                name=f"CloudWatch log group '{rid}' has no retention policy",
                category="CloudWatch: Log Retention",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Log groups with no retention policy store logs indefinitely, increasing storage costs and retaining sensitive data longer than required.",
                recommendation="Set RetentionInDays (e.g., 90, 180, or 365) to match your compliance policy.",
                cwe="CWE-532",
            ))
        if not props.get("KmsKeyId"):
            self._add(Finding(
                rule_id="AWS-CW-003",
                name=f"CloudWatch log group '{rid}' not encrypted with CMK",
                category="CloudWatch: Encryption",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without a customer-managed KMS key, log data is protected only by the AWS-managed key, limiting access control.",
                recommendation="Specify KmsKeyId with a CMK that grants kms:Encrypt/Decrypt to the CloudWatch Logs service principal.",
                cwe="CWE-311",
            ))

    # ----------------------------------------------------------
    # CF check methods — VPC (v1.1.0)
    # ----------------------------------------------------------
    def _cf_vpc(self, rid, props, fp):
        # Flow logs check is done indirectly via CF_DISPATCH on FlowLog resources;
        # flag if EnableDnsSupport or EnableDnsHostnames are explicitly disabled
        if props.get("EnableDnsHostnames") is False:
            self._add(Finding(
                rule_id="AWS-VPC-001",
                name=f"VPC '{rid}' has DNS hostnames disabled",
                category="VPC: DNS Configuration",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Disabling DNS hostnames prevents EC2 instances from receiving public DNS names, complicating connectivity and monitoring.",
                recommendation="Set EnableDnsHostnames: true unless you have a specific reason to disable it.",
                cwe="CWE-1188",
            ))
        if props.get("EnableDnsSupport") is False:
            self._add(Finding(
                rule_id="AWS-VPC-002",
                name=f"VPC '{rid}' has DNS support disabled",
                category="VPC: DNS Configuration",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Disabling DNS support in a VPC breaks name resolution for AWS service endpoints and private hosted zones.",
                recommendation="Set EnableDnsSupport: true.",
                cwe="CWE-1188",
            ))

    # ----------------------------------------------------------
    # CF check methods — Subnet (v1.1.0)
    # ----------------------------------------------------------
    def _cf_subnet(self, rid, props, fp):
        if props.get("MapPublicIpOnLaunch") is True:
            self._add(Finding(
                rule_id="AWS-VPC-003",
                name=f"Subnet '{rid}' auto-assigns public IPs on launch",
                category="VPC: Public Subnet",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Subnets with MapPublicIpOnLaunch=true expose every launched instance to the internet by default, increasing attack surface.",
                recommendation="Set MapPublicIpOnLaunch: false. Assign Elastic IPs explicitly only to instances that require public access.",
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # CF check methods — VPC Flow Log (v1.1.0)
    # ----------------------------------------------------------
    def _cf_flow_log(self, rid, props, fp):
        traffic_type = props.get("TrafficType", "").upper()
        if traffic_type not in ("ALL", "REJECT"):
            self._add(Finding(
                rule_id="AWS-VPC-004",
                name=f"VPC Flow Log '{rid}' does not capture REJECT or ALL traffic",
                category="VPC: Flow Logs",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Capturing only ACCEPT traffic misses blocked connection attempts, which are often indicators of reconnaissance or attacks.",
                recommendation="Set TrafficType: ALL to capture both accepted and rejected flows.",
                cwe="CWE-778",
            ))

    # ----------------------------------------------------------
    # CF check methods — WAFv2 WebACL (v1.1.0)
    # ----------------------------------------------------------
    def _cf_waf(self, rid, props, fp):
        default_action = props.get("DefaultAction", {})
        if "Allow" in default_action and "Block" not in default_action:
            self._add(Finding(
                rule_id="AWS-WAF-001",
                name=f"WAFv2 WebACL '{rid}' default action is ALLOW",
                category="WAF: Default Action",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="A WAF with a default ALLOW action passes all unmatched requests, providing minimal protection.",
                recommendation="Change DefaultAction to Block. Use explicit Allow rules for known-good traffic.",
                cwe="CWE-284",
            ))
        rules = props.get("Rules", [])
        if not rules:
            self._add(Finding(
                rule_id="AWS-WAF-002",
                name=f"WAFv2 WebACL '{rid}' has no rules configured",
                category="WAF: Rules",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="A WAF WebACL with no rules provides no protection against web attacks.",
                recommendation="Add AWS Managed Rule Groups (e.g., AWSManagedRulesCommonRuleSet, AWSManagedRulesKnownBadInputsRuleSet).",
                cwe="CWE-284",
            ))
        visibility = props.get("VisibilityConfig", {})
        if not visibility.get("CloudWatchMetricsEnabled", True):
            self._add(Finding(
                rule_id="AWS-WAF-003",
                name=f"WAFv2 WebACL '{rid}' CloudWatch metrics disabled",
                category="WAF: Logging",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Disabling CloudWatch metrics removes visibility into WAF rule matches and blocked requests.",
                recommendation="Set CloudWatchMetricsEnabled: true in VisibilityConfig and enable sampled requests.",
                cwe="CWE-778",
            ))

    # ----------------------------------------------------------
    # CF check methods — GuardDuty Detector (v1.1.0)
    # ----------------------------------------------------------
    def _cf_guardduty(self, rid, props, fp):
        if props.get("Enable") is False:
            self._add(Finding(
                rule_id="AWS-GD-001",
                name=f"GuardDuty detector '{rid}' is disabled",
                category="GuardDuty: Threat Detection",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="A disabled GuardDuty detector stops all threat intelligence and anomaly detection for the account and region.",
                recommendation="Set Enable: true. Enable optional data sources: S3 protection, EKS audit log monitoring, RDS login activity.",
                cwe="CWE-778",
            ))
        features = props.get("Features", [])
        s3_enabled = any(
            f.get("Name") == "S3_DATA_EVENTS" and f.get("Status") == "ENABLED"
            for f in features
        )
        if not s3_enabled and props.get("Enable") is not False:
            self._add(Finding(
                rule_id="AWS-GD-002",
                name=f"GuardDuty detector '{rid}' S3 protection not enabled",
                category="GuardDuty: Threat Detection",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without S3 protection, GuardDuty does not monitor for suspicious S3 API calls such as unusual data access or exfiltration.",
                recommendation="Enable the S3_DATA_EVENTS feature in the Features list.",
                cwe="CWE-778",
            ))

    # ----------------------------------------------------------
    # CF check methods — AWS Config Recorder (v1.1.0)
    # ----------------------------------------------------------
    def _cf_config_recorder(self, rid, props, fp):
        recording_group = props.get("RecordingGroup", {})
        if not recording_group.get("AllSupported", False):
            self._add(Finding(
                rule_id="AWS-CFG-001",
                name=f"Config recorder '{rid}' does not record all resource types",
                category="Config: Coverage",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Limiting Config to specific resource types creates blind spots in compliance monitoring and change tracking.",
                recommendation="Set AllSupported: true and IncludeGlobalResourceTypes: true in RecordingGroup.",
                cwe="CWE-778",
            ))
        if not recording_group.get("IncludeGlobalResourceTypes", False):
            self._add(Finding(
                rule_id="AWS-CFG-002",
                name=f"Config recorder '{rid}' excludes global resource types (IAM)",
                category="Config: Coverage",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Excluding global resources (e.g., IAM users, roles, policies) from Config leaves critical identity changes untracked.",
                recommendation="Set IncludeGlobalResourceTypes: true in RecordingGroup.",
                cwe="CWE-778",
            ))

    # ----------------------------------------------------------
    # CF check methods — Elastic Beanstalk Environment (v1.1.0)
    # ----------------------------------------------------------
    def _cf_elasticbeanstalk(self, rid, props, fp):
        option_settings = props.get("OptionSettings", [])
        settings_map = {
            (s.get("Namespace", ""), s.get("OptionName", "")): s.get("Value", "")
            for s in option_settings
        }
        # Check for HTTPS listener
        listener_protocol = settings_map.get(("aws:elb:listener", "ListenerProtocol"), "")
        if listener_protocol.upper() == "HTTP":
            self._add(Finding(
                rule_id="AWS-EB-001",
                name=f"Elastic Beanstalk environment '{rid}' uses HTTP listener",
                category="Elastic Beanstalk: HTTPS",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="An HTTP load balancer listener transmits user data including session tokens in plaintext.",
                recommendation="Configure an HTTPS listener with an ACM certificate. Add a redirect rule for port 80 -> 443.",
                cwe="CWE-319",
            ))
        # Check managed updates
        managed_actions = settings_map.get(("aws:elasticbeanstalk:managedactions", "ManagedActionsEnabled"), "true")
        if str(managed_actions).lower() == "false":
            self._add(Finding(
                rule_id="AWS-EB-002",
                name=f"Elastic Beanstalk environment '{rid}' managed platform updates disabled",
                category="Elastic Beanstalk: Updates",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Disabling managed updates leaves the environment running outdated platform versions with known vulnerabilities.",
                recommendation="Enable ManagedActionsEnabled and set a maintenance window for automatic platform updates.",
                cwe="CWE-1104",
            ))
        # Check enhanced health reporting
        health_system = settings_map.get(("aws:elasticbeanstalk:healthreporting:system", "SystemType"), "enhanced")
        if str(health_system).lower() == "basic":
            self._add(Finding(
                rule_id="AWS-EB-003",
                name=f"Elastic Beanstalk environment '{rid}' uses basic health reporting",
                category="Elastic Beanstalk: Monitoring",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Basic health reporting provides limited metrics, reducing visibility into environment health and performance.",
                recommendation="Set SystemType: enhanced for detailed health metrics and CloudWatch integration.",
                cwe="CWE-778",
            ))

    # ----------------------------------------------------------
    # CF check methods — SageMaker Notebook Instance (v1.1.0)
    # ----------------------------------------------------------
    def _cf_sagemaker_notebook(self, rid, props, fp):
        if props.get("DirectInternetAccess", "Enabled") == "Enabled":
            self._add(Finding(
                rule_id="AWS-SAGE-001",
                name=f"SageMaker notebook '{rid}' has direct internet access enabled",
                category="SageMaker: Network",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Direct internet access allows data exfiltration and bypasses VPC-level security controls.",
                recommendation="Set DirectInternetAccess: Disabled. Route outbound traffic through a VPC with a NAT gateway.",
                cwe="CWE-284",
            ))
        if not props.get("KmsKeyId"):
            self._add(Finding(
                rule_id="AWS-SAGE-002",
                name=f"SageMaker notebook '{rid}' EBS volume not encrypted with CMK",
                category="SageMaker: Encryption",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without a CMK, the notebook's EBS volume uses the AWS-managed key, limiting key access control.",
                recommendation="Specify KmsKeyId with a customer-managed KMS key.",
                cwe="CWE-311",
            ))
        if not props.get("SubnetId"):
            self._add(Finding(
                rule_id="AWS-SAGE-003",
                name=f"SageMaker notebook '{rid}' not placed in a VPC subnet",
                category="SageMaker: Network",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Notebooks not placed in a VPC use direct internet routing, bypassing network security controls.",
                recommendation="Specify SubnetId and SecurityGroupIds to place the notebook inside your VPC.",
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # CF check methods — SageMaker Domain (v1.1.0)
    # ----------------------------------------------------------
    def _cf_sagemaker_domain(self, rid, props, fp):
        app_network = props.get("AppNetworkAccessType", "PublicInternetOnly")
        if app_network == "PublicInternetOnly":
            self._add(Finding(
                rule_id="AWS-SAGE-004",
                name=f"SageMaker Domain '{rid}' app network access is PublicInternetOnly",
                category="SageMaker: Network",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Public internet access for SageMaker Studio applications bypasses VPC controls and exposes ML workloads to the internet.",
                recommendation="Set AppNetworkAccessType: VpcOnly and configure appropriate VPC, subnets, and security groups.",
                cwe="CWE-284",
            ))
        default_user = props.get("DefaultUserSettings", {})
        if not default_user.get("ExecutionRole"):
            self._add(Finding(
                rule_id="AWS-SAGE-005",
                name=f"SageMaker Domain '{rid}' default user has no execution role",
                category="SageMaker: IAM",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without a defined execution role, SageMaker Studio users may inherit overly permissive default permissions.",
                recommendation="Specify an ExecutionRole with least-privilege permissions in DefaultUserSettings.",
                cwe="CWE-269",
            ))

    # ----------------------------------------------------------
    # CF check methods — Bedrock Agent (v1.1.0)
    # ----------------------------------------------------------
    def _cf_bedrock_agent(self, rid, props, fp):
        if not props.get("GuardrailConfiguration"):
            self._add(Finding(
                rule_id="AWS-BR-001",
                name=f"Bedrock agent '{rid}' has no guardrail configured",
                category="Bedrock: Guardrails",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="A Bedrock agent without guardrails can produce harmful, biased, or policy-violating content with no safety controls.",
                recommendation="Attach a GuardrailConfiguration with content filters, topic policies, and sensitive data redaction enabled.",
                cwe="CWE-284",
            ))
        idle_timeout = props.get("IdleSessionTTLInSeconds")
        if idle_timeout is None or int(idle_timeout) > 3600:
            self._add(Finding(
                rule_id="AWS-BR-002",
                name=f"Bedrock agent '{rid}' session TTL exceeds 1 hour or not set",
                category="Bedrock: Session Management",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Long or unlimited session TTLs keep agent conversations active longer than necessary, increasing exposure to session hijacking.",
                recommendation="Set IdleSessionTTLInSeconds to 3600 (1 hour) or less.",
                cwe="CWE-613",
            ))

    # ----------------------------------------------------------
    # CF check methods — EBS Volume (v1.1.0)
    # ----------------------------------------------------------
    def _cf_ebs_volume(self, rid, props, fp):
        if props.get("Encrypted") is not True:
            self._add(Finding(
                rule_id="AWS-EBS-001",
                name=f"EBS volume '{rid}' is not encrypted",
                category="EBS: Encryption",
                severity="HIGH",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Unencrypted EBS volumes expose data at rest if the underlying physical storage media is accessed outside AWS.",
                recommendation="Set Encrypted: true. Specify KmsKeyId with a CMK. Enable account-level EBS encryption by default in the EC2 console.",
                cwe="CWE-311",
            ))
        if props.get("Encrypted") is True and not props.get("KmsKeyId"):
            self._add(Finding(
                rule_id="AWS-EBS-002",
                name=f"EBS volume '{rid}' encrypted with AWS-managed key, not CMK",
                category="EBS: Encryption",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Using the AWS-managed key (alias/aws/ebs) limits key rotation control and access auditing compared to a CMK.",
                recommendation="Specify KmsKeyId with a customer-managed KMS key for full control over key policy and rotation.",
                cwe="CWE-311",
            ))

    # ----------------------------------------------------------
    # CF check methods — Step Functions State Machine (v1.1.0)
    # ----------------------------------------------------------
    def _cf_stepfunctions(self, rid, props, fp):
        logging_config = props.get("LoggingConfiguration", {})
        log_level = logging_config.get("Level", "OFF")
        if log_level == "OFF":
            self._add(Finding(
                rule_id="AWS-SFN-001",
                name=f"Step Functions state machine '{rid}' logging is OFF",
                category="Step Functions: Logging",
                severity="MEDIUM",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="With logging disabled, execution history and errors are not captured to CloudWatch Logs, hampering debugging and auditing.",
                recommendation="Set Level to ALL or ERROR in LoggingConfiguration and specify a CloudWatch log group destination.",
                cwe="CWE-778",
            ))
        tracing = props.get("TracingConfiguration", {})
        if tracing.get("Enabled") is not True:
            self._add(Finding(
                rule_id="AWS-SFN-002",
                name=f"Step Functions state machine '{rid}' X-Ray tracing disabled",
                category="Step Functions: Tracing",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="Without X-Ray tracing, distributed execution traces across Lambda and other integrated services are unavailable.",
                recommendation="Set Enabled: true in TracingConfiguration.",
                cwe="CWE-778",
            ))
        definition = props.get("DefinitionString", "") or ""
        if isinstance(definition, dict):
            definition = json.dumps(definition)
        if definition and '"Catch"' not in definition and '"Retry"' not in definition:
            self._add(Finding(
                rule_id="AWS-SFN-003",
                name=f"Step Functions state machine '{rid}' has no error handling (Catch/Retry)",
                category="Step Functions: Resilience",
                severity="LOW",
                file_path=str(fp), line_num=None, line_content=f"Resource: {rid}",
                description="State machines without Catch or Retry blocks will fail silently on transient errors, causing data loss or stuck workflows.",
                recommendation="Add Retry with exponential backoff and Catch clauses to all task states.",
                cwe="CWE-755",
            ))

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------
    def _add(self, finding):
        self.findings.append(finding)

    def _vprint(self, msg):
        if self.verbose:
            print(msg)

    def _warn(self, msg):
        print(f"  [!] {msg}", file=sys.stderr)

    # ----------------------------------------------------------
    # Reporting
    # ----------------------------------------------------------
    def summary(self):
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_severity):
        threshold = self.SEVERITY_ORDER.get(min_severity, 4)
        self.findings = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(f.severity, 4) <= threshold
        ]

    def print_report(self):
        B, R = self.BOLD, self.RESET
        print(f"\n{B}{'='*72}{R}")
        print(f"{B}  AWS IaC Security Scanner v{VERSION}  \u2014  Scan Report{R}")
        print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Scanned   : {self.scanned_files} file(s)")
        print(f"  Findings  : {len(self.findings)}")
        print(f"{B}{'='*72}{R}\n")

        if not self.findings:
            print("  [+] No issues found.\n")
            return

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.file_path, f.line_num or 0),
        )

        for f in sorted_findings:
            color = self.SEVERITY_COLOR.get(f.severity, "")
            loc = f.file_path + (f":{f.line_num}" if f.line_num else "")
            print(f"{color}{B}[{f.severity}]{R}  {f.rule_id}  {f.name}")
            print(f"  Location : {loc}")
            if f.line_content:
                snippet = f.line_content[:120]
                print(f"  Context  : {snippet}")
            if f.cwe:
                print(f"  CWE      : {f.cwe}")
            print(f"  Issue    : {f.description}")
            print(f"  Fix      : {f.recommendation}")
            print()

        counts = self.summary()
        print(f"{B}{'='*72}{R}")
        print(f"{B}  SUMMARY{R}")
        print(f"{'='*72}")
        for sev in self.SEVERITY_ORDER:
            n = counts.get(sev, 0)
            if n:
                color = self.SEVERITY_COLOR.get(sev, "")
                print(f"  {color}{sev:<10}{R}  {n}")
        print(f"{'='*72}\n")

    def save_json(self, output_path):
        report = {
            "scanner": f"AWS IaC Security Scanner v{VERSION}",
            "generated": datetime.now().isoformat(),
            "files_scanned": self.scanned_files,
            "total_findings": len(self.findings),
            "summary": self.summary(),
            "findings": [
                {
                    "id":             f.rule_id,
                    "name":           f.name,
                    "category":       f.category,
                    "severity":       f.severity,
                    "file":           f.file_path,
                    "line":           f.line_num,
                    "code":           f.line_content,
                    "description":    f.description,
                    "recommendation": f.recommendation,
                    "cwe":            f.cwe,
                    "cve":            f.cve,
                }
                for f in self.findings
            ],
        }
        with open(output_path, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"[+] JSON report saved to: {output_path}")

    def save_html(self, output_path):
        counts = self.summary()
        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        sev_colors = {
            "CRITICAL": "#c0392b", "HIGH": "#e67e22",
            "MEDIUM": "#2980b9",   "LOW": "#27ae60", "INFO": "#7f8c8d",
        }

        def chip(sev):
            c = sev_colors.get(sev, "#555")
            n = counts.get(sev, 0)
            return (f'<span style="background:{c};color:#fff;padding:3px 10px;'
                    f'border-radius:12px;margin:2px;font-weight:bold;font-size:13px;">'
                    f'{sev} {n}</span>')

        chips_html = "".join(chip(s) for s in self.SEVERITY_ORDER if counts.get(s, 0) > 0)

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.file_path, f.line_num or 0),
        )

        rows = []
        for f in sorted_findings:
            c = sev_colors.get(f.severity, "#555")
            loc = html_mod.escape(f.file_path) + (f":{f.line_num}" if f.line_num else "")
            code_cell = f'<code style="font-size:11px">{html_mod.escape(f.line_content[:100])}</code>' if f.line_content else ""
            rows.append(f"""
<tr>
  <td><span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">{html_mod.escape(f.severity)}</span></td>
  <td style="font-family:monospace;font-size:12px">{html_mod.escape(f.rule_id)}</td>
  <td>{html_mod.escape(f.category)}</td>
  <td><strong>{html_mod.escape(f.name)}</strong><br><small style="color:#aaa">{html_mod.escape(f.description)}</small></td>
  <td style="font-size:12px">{loc}<br>{code_cell}</td>
  <td style="font-size:12px;color:#5dade2">{html_mod.escape(f.recommendation)}</td>
  <td style="font-size:12px">{html_mod.escape(f.cwe or "")}</td>
</tr>""")

        rows_html = "".join(rows)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AWS IaC Security Scan Report</title>
<style>
  body{{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
  .header{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:20px}}
  .header h1{{margin:0 0 8px;color:#58a6ff;font-size:22px}}
  .meta{{color:#8b949e;font-size:13px;margin:4px 0}}
  .chips{{margin:12px 0}}
  table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;border:1px solid #30363d}}
  th{{background:#21262d;color:#8b949e;padding:10px 8px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #30363d}}
  td{{padding:10px 8px;border-bottom:1px solid #21262d;vertical-align:top;font-size:13px}}
  tr:hover td{{background:#1c2128}}
  .filter-bar{{margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap}}
  .filter-btn{{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:5px 14px;border-radius:6px;cursor:pointer;font-size:13px}}
  .filter-btn.active{{border-color:#58a6ff;color:#58a6ff}}
  input[type=text]{{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:6px 12px;border-radius:6px;font-size:13px;width:300px}}
</style>
</head>
<body>
<div class="header">
  <h1>&#x1F6E1; AWS IaC Security Scanner v{VERSION} — Scan Report</h1>
  <div class="meta">Generated: {generated}</div>
  <div class="meta">Files scanned: {self.scanned_files} &nbsp;|&nbsp; Total findings: {len(self.findings)}</div>
  <div class="chips">{chips_html}</div>
</div>
<div class="filter-bar">
  <input type="text" id="searchBox" onkeyup="filterTable()" placeholder="Search findings...">
  <button class="filter-btn active" onclick="setSev('')">All</button>
  <button class="filter-btn" style="color:#c0392b" onclick="setSev('CRITICAL')">CRITICAL</button>
  <button class="filter-btn" style="color:#e67e22" onclick="setSev('HIGH')">HIGH</button>
  <button class="filter-btn" style="color:#2980b9" onclick="setSev('MEDIUM')">MEDIUM</button>
  <button class="filter-btn" style="color:#27ae60" onclick="setSev('LOW')">LOW</button>
</div>
<table id="findingsTable">
<thead>
<tr>
  <th>Severity</th><th>Rule ID</th><th>Category</th>
  <th>Finding</th><th>Location</th><th>Recommendation</th><th>CWE</th>
</tr>
</thead>
<tbody>{rows_html}</tbody>
</table>
<script>
var activeSev = '';
function setSev(s){{
  activeSev = s;
  document.querySelectorAll('.filter-btn').forEach(function(b){{b.classList.remove('active')}});
  event.target.classList.add('active');
  filterTable();
}}
function filterTable(){{
  var q = document.getElementById('searchBox').value.toLowerCase();
  var rows = document.getElementById('findingsTable').getElementsByTagName('tr');
  for(var i=1;i<rows.length;i++){{
    var t = rows[i].innerText.toLowerCase();
    var sevCell = rows[i].cells[0]? rows[i].cells[0].innerText:'';
    var sevMatch = activeSev==='' || sevCell.indexOf(activeSev)>=0;
    rows[i].style.display = (sevMatch && (!q || t.indexOf(q)>=0))? '':'none';
  }}
}}
</script>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"[+] HTML report saved to: {output_path}")


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description=f"AWS IaC Security Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
AWS services covered:
  IAM, S3, EC2 (instances + security groups), RDS, Lambda, CloudTrail,
  CloudFront, ELB/ALB, API Gateway, KMS, SQS, SNS, DynamoDB,
  ElastiCache, EKS, ECS, Cognito, OpenSearch, Redshift, ECR, Secrets Manager

IaC formats supported:
  CloudFormation  .yaml / .yml / .json  (requires pyyaml for YAML files)
  Terraform       .tf

Examples:
  python3 aws_scanner.py /path/to/infra/
  python3 aws_scanner.py template.yaml --html report.html
  python3 aws_scanner.py main.tf --json findings.json --severity HIGH
  python3 aws_scanner.py /path/to/cf/ --verbose --severity MEDIUM
""",
    )
    parser.add_argument("target", help="File or directory containing CloudFormation templates or Terraform files")
    parser.add_argument("--json",     metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--html",     metavar="FILE", help="Write HTML report to FILE")
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Only report findings at this severity or above",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show files as they are scanned")
    parser.add_argument("--version",       action="version", version=f"aws_scanner v{VERSION}")
    args = parser.parse_args()

    if not HAS_YAML:
        print("[!] Warning: pyyaml not installed. CloudFormation YAML files will be skipped.", file=sys.stderr)
        print("[!]          Install with: pip install pyyaml\n", file=sys.stderr)

    print(f"[*] AWS IaC Security Scanner v{VERSION}")
    print(f"[*] Target: {args.target}\n")

    scanner = AWSIaCScanner(verbose=args.verbose)
    scanner.scan_path(args.target)

    if args.severity:
        scanner.filter_severity(args.severity)

    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)

    if args.html:
        scanner.save_html(args.html)

    counts = scanner.summary()
    sys.exit(1 if (counts.get("CRITICAL", 0) or counts.get("HIGH", 0)) else 0)


if __name__ == "__main__":
    main()
