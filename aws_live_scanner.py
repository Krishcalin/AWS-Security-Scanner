#!/usr/bin/env python3
"""
AWS Live Security Scanner v2.1.0
Read-only live audit of AWS environments via boto3.

Aligned to: CIS AWS Foundations Benchmark v3.0
            AWS Well-Architected Framework — Security Pillar
            PCI DSS v4.0 · HIPAA · SOC 2 · NIST 800-53 Rev 5

25 service domains:
  IAM · S3 · VPC/Network · Logging & Monitoring · KMS · EC2
  ECR · Backup · RDS · Glacier · SNS · SQS · CloudFront
  Route 53 · Bedrock · Bedrock Agents · Lambda · EKS · ECS
  Secrets Manager · WAF · ElastiCache · OpenSearch · DynamoDB
  Step Functions

Requirements: pip install boto3
Credentials : AWS CLI profile, environment variables, or IAM instance role
              Minimum permission: SecurityAudit managed policy

Usage:
  python aws_live_scanner.py [--region eu-west-1]
  python aws_live_scanner.py --region us-east-1 --json report.json --html report.html
  python aws_live_scanner.py --sections IAM,S3,RDS --output-dir evidence/
  python aws_live_scanner.py --verbose

Author: Krishnendu De with support from Claude.AI
"""

import os
import sys
import json
import csv
import io
import base64
import time
import fnmatch
import argparse
from urllib.parse import unquote
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

VERSION = "2.1.0"

# ─── Terminal colours ─────────────────────────────────────────────────────────
RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE   = "\033[0;34m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

STATUS_COLOR = {"PASS": GREEN, "FAIL": RED, "WARN": YELLOW, "INFO": BLUE}
STATUS_ICON  = {"PASS": "[PASS]", "FAIL": "[FAIL]", "WARN": "[WARN]", "INFO": "[INFO]"}

# ─── Section registry ─────────────────────────────────────────────────────────
SECTIONS = [
    "IAM", "S3", "VPC", "LOGGING", "KMS", "EC2",
    "ECR", "BACKUP", "RDS", "GLACIER", "SNS", "SQS",
    "CLOUDFRONT", "ROUTE53", "BEDROCK", "BEDROCK_AGENTS",
    "LAMBDA", "EKS", "ECS", "SECRETS", "WAF",
    "ELASTICACHE", "OPENSEARCH", "DYNAMODB", "STEPFUNCTIONS",
    "APIGATEWAY", "ELB", "EBS", "REDSHIFT", "EFS", "ACM",
    "SAGEMAKER", "COGNITO", "APIGATEWAYV2", "IAMPRIVESC",
]

SECTION_LABELS = {
    "IAM":            "IDENTITY & ACCESS MANAGEMENT",
    "S3":             "S3 SECURITY",
    "VPC":            "NETWORK SECURITY",
    "LOGGING":        "LOGGING & MONITORING",
    "KMS":            "ENCRYPTION & KMS",
    "EC2":            "COMPUTE SECURITY",
    "ECR":            "CONTAINER SECURITY",
    "BACKUP":         "BACKUP & DR",
    "RDS":            "AMAZON RDS",
    "GLACIER":        "AMAZON S3 GLACIER",
    "SNS":            "AMAZON SNS",
    "SQS":            "AMAZON SQS",
    "CLOUDFRONT":     "AMAZON CLOUDFRONT",
    "ROUTE53":        "AMAZON ROUTE 53",
    "BEDROCK":        "AWS BEDROCK",
    "BEDROCK_AGENTS": "AWS BEDROCK AGENT CORE",
    "LAMBDA":         "AWS LAMBDA",
    "EKS":            "AMAZON EKS",
    "ECS":            "AMAZON ECS",
    "SECRETS":        "AWS SECRETS MANAGER",
    "WAF":            "AWS WAF",
    "ELASTICACHE":    "AMAZON ELASTICACHE",
    "OPENSEARCH":     "AMAZON OPENSEARCH",
    "DYNAMODB":       "AMAZON DYNAMODB",
    "STEPFUNCTIONS":  "AWS STEP FUNCTIONS",
    "APIGATEWAY":     "AMAZON API GATEWAY",
    "ELB":            "ELASTIC LOAD BALANCING",
    "EBS":            "EBS VOLUMES & SNAPSHOTS",
    "REDSHIFT":       "AMAZON REDSHIFT",
    "EFS":            "AMAZON EFS",
    "ACM":            "AWS CERTIFICATE MANAGER",
    "SAGEMAKER":      "AMAZON SAGEMAKER",
    "COGNITO":        "AMAZON COGNITO",
    "APIGATEWAYV2":   "API GATEWAY (HTTP APIs)",
    "IAMPRIVESC":     "IAM PRIVILEGE ESCALATION",
}


# ─── Result dataclass ─────────────────────────────────────────────────────────
@dataclass
class Result:
    status:   str   # PASS | FAIL | WARN | INFO
    check_id: str   # e.g. IAM-01
    section:  str   # e.g. IAM
    resource: str   # resource identifier
    message:  str   # human-readable finding
    severity:       str = ""               # CRITICAL | HIGH | MEDIUM | LOW | INFO
    compliance:     Dict = field(default_factory=dict)
    remediation_cmd: str = ""

# ─── Severity weights for risk scoring ───────────────────────────────────────
SEVERITY_WEIGHTS = {"CRITICAL": 15, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0}

# Map check_id → default severity when status is FAIL
CHECK_SEVERITY = {
    "IAM-01": "CRITICAL", "IAM-02": "CRITICAL", "IAM-04": "HIGH",
    "IAM-05": "MEDIUM", "IAM-06": "HIGH", "IAM-10": "MEDIUM",
    "S3-01": "HIGH", "S3-03": "HIGH", "S3-05": "MEDIUM",
    "VPC-01": "HIGH", "VPC-03": "MEDIUM",
    "LOG-01": "CRITICAL", "LOG-03": "HIGH", "LOG-04": "CRITICAL", "LOG-05": "MEDIUM",
    "ENC-03": "MEDIUM",
    "EC2-04": "HIGH", "EC2-05": "MEDIUM", "EC2-06": "HIGH",
    "CNT-01": "MEDIUM",
    "BCK-01": "MEDIUM",
    "RDS-01": "HIGH", "RDS-02": "CRITICAL", "RDS-03": "MEDIUM",
    "RDS-04": "MEDIUM", "RDS-05": "LOW", "RDS-06": "CRITICAL",
    "GLC-01": "CRITICAL", "GLC-02": "MEDIUM", "GLC-03": "LOW",
    "SNS-01": "MEDIUM", "SNS-02": "HIGH", "SNS-03": "HIGH", "SNS-04": "MEDIUM",
    "SQS-01": "HIGH", "SQS-02": "CRITICAL", "SQS-03": "MEDIUM", "SQS-04": "LOW",
    "CFN-01": "HIGH", "CFN-02": "HIGH", "CFN-03": "HIGH",
    "CFN-04": "MEDIUM", "CFN-05": "HIGH",
    "R53-01": "MEDIUM", "R53-02": "MEDIUM", "R53-03": "HIGH",
    "R53-04": "LOW", "R53-05": "MEDIUM",
    "BDR-01": "HIGH", "BDR-02": "HIGH", "BDR-03": "MEDIUM",
    "BDR-04": "MEDIUM", "BDR-05": "HIGH",
    "AGT-01": "MEDIUM", "AGT-02": "HIGH", "AGT-03": "MEDIUM",
    "AGT-04": "HIGH", "AGT-05": "HIGH",
    "LMB-01": "HIGH", "LMB-02": "MEDIUM", "LMB-03": "HIGH",
    "LMB-04": "MEDIUM", "LMB-05": "MEDIUM",
    "EKS-01": "HIGH", "EKS-02": "HIGH", "EKS-03": "MEDIUM",
    "EKS-04": "MEDIUM", "EKS-05": "MEDIUM",
    "ECS-01": "CRITICAL", "ECS-02": "HIGH", "ECS-03": "MEDIUM",
    "ECS-04": "HIGH", "ECS-05": "MEDIUM",
    "SEC-01": "HIGH", "SEC-02": "HIGH", "SEC-03": "MEDIUM", "SEC-04": "MEDIUM",
    "WAF-01": "HIGH", "WAF-02": "MEDIUM", "WAF-03": "MEDIUM", "WAF-04": "MEDIUM",
    "ELC-01": "HIGH", "ELC-02": "HIGH", "ELC-03": "HIGH", "ELC-04": "MEDIUM",
    "OSR-01": "HIGH", "OSR-02": "HIGH", "OSR-03": "MEDIUM",
    "OSR-04": "HIGH", "OSR-05": "HIGH",
    "DDB-01": "HIGH", "DDB-02": "HIGH", "DDB-03": "MEDIUM", "DDB-04": "MEDIUM",
    "SFN-01": "MEDIUM", "SFN-02": "LOW", "SFN-03": "MEDIUM",
    "APIGW-01": "MEDIUM", "APIGW-02": "MEDIUM", "APIGW-03": "HIGH", "APIGW-04": "LOW",
    "ELB-01": "MEDIUM", "ELB-02": "HIGH", "ELB-03": "MEDIUM",
    "ELB-04": "LOW", "ELB-05": "MEDIUM",
    "EBS-01": "HIGH", "EBS-02": "HIGH", "EBS-03": "MEDIUM", "EBS-04": "CRITICAL",
    "RS-01": "HIGH", "RS-02": "HIGH", "RS-03": "MEDIUM", "RS-04": "MEDIUM", "RS-05": "LOW",
    "EFS-01": "HIGH", "EFS-02": "MEDIUM", "EFS-03": "LOW",
    "ACM-01": "HIGH", "ACM-02": "MEDIUM", "ACM-03": "LOW",
    "SM-01": "HIGH", "SM-02": "MEDIUM", "SM-03": "MEDIUM", "SM-04": "MEDIUM",
    "COG-01": "HIGH", "COG-02": "MEDIUM", "COG-03": "MEDIUM", "COG-04": "LOW",
    "AGW2-01": "MEDIUM", "AGW2-02": "HIGH", "AGW2-03": "LOW",
    # IAM privilege-escalation primitives
    "IAMPE-01": "CRITICAL", "IAMPE-02": "HIGH", "IAMPE-03": "CRITICAL",
    "IAMPE-04": "CRITICAL", "IAMPE-05": "HIGH", "IAMPE-06": "HIGH",
    "IAMPE-07": "HIGH", "IAMPE-08": "HIGH", "IAMPE-10": "HIGH",
    "IAMPE-11": "HIGH", "IAMPE-12": "HIGH", "IAMPE-13": "HIGH",
    "IAMPE-14": "HIGH", "IAMPE-16": "HIGH", "IAMPE-18": "MEDIUM",
    "IAMPE-19": "CRITICAL", "IAMPE-20": "MEDIUM",
}

# ─── Compliance mapping: check_id → { framework: control } ──────────────────
COMPLIANCE_MAP = {
    # IAM
    "IAM-01": {"CIS": "1.5", "PCI-DSS": "8.3.1", "HIPAA": "164.312(d)", "SOC2": "CC6.1", "NIST": "IA-2(1)"},
    "IAM-02": {"CIS": "1.4", "PCI-DSS": "8.2.2", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.1", "NIST": "IA-2"},
    "IAM-04": {"CIS": "1.10", "PCI-DSS": "8.3.1", "HIPAA": "164.312(d)", "SOC2": "CC6.1", "NIST": "IA-2(1)"},
    "IAM-05": {"CIS": "1.8", "PCI-DSS": "8.3.6", "HIPAA": "164.312(a)(2)(i)", "SOC2": "CC6.1", "NIST": "IA-5(1)"},
    "IAM-06": {"CIS": "1.14", "PCI-DSS": "8.6.3", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.2", "NIST": "IA-5(1)"},
    "IAM-10": {"CIS": "1.20", "PCI-DSS": "11.5", "HIPAA": "164.312(b)", "SOC2": "CC7.1", "NIST": "AC-6"},
    # S3
    "S3-01": {"CIS": "2.1.4", "PCI-DSS": "1.3.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.1", "NIST": "AC-3"},
    "S3-03": {"CIS": "2.1.1", "PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "S3-05": {"CIS": "3.6", "PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    # VPC
    "VPC-01": {"CIS": "5.2", "PCI-DSS": "1.3.2", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "VPC-03": {"CIS": "3.7", "PCI-DSS": "10.6", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-12"},
    # Logging
    "LOG-01": {"CIS": "3.1", "PCI-DSS": "10.1", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "LOG-03": {"CIS": "3.5", "PCI-DSS": "10.5.3", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "CM-8"},
    "LOG-04": {"CIS": "4.15", "PCI-DSS": "11.4", "HIPAA": "164.312(b)", "SOC2": "CC7.3", "NIST": "SI-4"},
    "LOG-05": {"CIS": "4.16", "PCI-DSS": "11.5", "HIPAA": "164.312(b)", "SOC2": "CC7.3", "NIST": "SI-4"},
    # KMS
    "ENC-03": {"CIS": "3.8", "PCI-DSS": "3.6.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-12"},
    # EC2
    "EC2-04": {"CIS": "5.6", "PCI-DSS": "2.2.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.1", "NIST": "CM-6"},
    "EC2-05": {"CIS": "5.1", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "EC2-06": {"CIS": "2.2.1", "PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    # RDS
    "RDS-01": {"CIS": "2.3.1", "PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "RDS-02": {"CIS": "2.3.2", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "RDS-03": {"CIS": "2.3.3", "PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(7)", "SOC2": "A1.2", "NIST": "CP-9"},
    "RDS-04": {"CIS": "2.3.3", "PCI-DSS": "2.2.1", "HIPAA": "164.308(a)(7)", "SOC2": "A1.2", "NIST": "CM-6"},
    "RDS-06": {"CIS": "2.3.4", "PCI-DSS": "1.3.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.1", "NIST": "AC-3"},
    # CloudFront
    "CFN-01": {"CIS": "2.1.2", "PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-8"},
    "CFN-02": {"CIS": "2.1.2", "PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-8(1)"},
    "CFN-03": {"PCI-DSS": "6.6", "SOC2": "CC6.6", "NIST": "SC-7(8)"},
    # New sections
    "LMB-01": {"CIS": "2.7.1", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "LMB-02": {"CIS": "2.7.2", "PCI-DSS": "1.3.4", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "LMB-03": {"PCI-DSS": "6.5.3", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "LMB-04": {"PCI-DSS": "6.3.2", "SOC2": "CC7.1", "NIST": "SI-2"},
    "EKS-01": {"CIS": "5.4.1", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "EKS-02": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "EKS-03": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "ECS-01": {"PCI-DSS": "2.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "CM-7"},
    "ECS-02": {"PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-6"},
    "ECS-03": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-6"},
    "SEC-01": {"PCI-DSS": "3.6.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-12(1)"},
    "SEC-02": {"PCI-DSS": "3.6.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-12(1)"},
    "WAF-01": {"PCI-DSS": "6.6", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7(8)"},
    "WAF-02": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "ELC-01": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "ELC-02": {"PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-8"},
    "ELC-03": {"PCI-DSS": "8.2.1", "HIPAA": "164.312(d)", "SOC2": "CC6.1", "NIST": "IA-5"},
    "OSR-01": {"PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-8"},
    "OSR-02": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "OSR-04": {"PCI-DSS": "1.3.4", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "OSR-05": {"PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-6"},
    "DDB-01": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "DDB-02": {"PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(7)", "SOC2": "A1.2", "NIST": "CP-9"},
    # API Gateway
    "APIGW-01": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "APIGW-02": {"PCI-DSS": "6.6", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7(8)"},
    "APIGW-03": {"PCI-DSS": "4.1", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    # Elastic Load Balancing
    "ELB-01": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "ELB-02": {"CIS": "4.10", "PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-8"},
    "ELB-03": {"PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-8(1)"},
    "ELB-05": {"PCI-DSS": "6.6", "SOC2": "CC6.6", "NIST": "SC-7(8)"},
    # EBS
    "EBS-01": {"CIS": "2.2.1", "PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "EBS-02": {"CIS": "2.2.1", "PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "EBS-03": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "EBS-04": {"CIS": "2.2.1", "PCI-DSS": "1.3.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.1", "NIST": "AC-3"},
    # Redshift
    "RS-01": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "RS-02": {"PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "RS-03": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "RS-04": {"PCI-DSS": "1.3.4", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    # EFS
    "EFS-01": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "EFS-02": {"PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-8"},
    "EFS-03": {"PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(7)", "SOC2": "A1.2", "NIST": "CP-9"},
    # ACM
    "ACM-01": {"PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-12"},
    "ACM-02": {"PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-13"},
    # SageMaker
    "SM-01": {"PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "SM-02": {"PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-6"},
    "SM-03": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "SM-04": {"PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    # Cognito
    "COG-01": {"CIS": "1.5", "PCI-DSS": "8.3.1", "HIPAA": "164.312(d)", "SOC2": "CC6.1", "NIST": "IA-2(1)"},
    "COG-02": {"PCI-DSS": "8.3.6", "HIPAA": "164.312(a)(2)(i)", "SOC2": "CC6.1", "NIST": "IA-5(1)"},
    "COG-03": {"PCI-DSS": "11.4", "HIPAA": "164.312(b)", "SOC2": "CC7.1", "NIST": "SI-4"},
    # API Gateway v2 (HTTP APIs)
    "AGW2-01": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "AGW2-02": {"PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"},
    # IAM privilege escalation — all map to least-privilege / separation-of-duties controls
    **{f"IAMPE-{n:02d}": {"CIS": "1.16", "PCI-DSS": "7.1.1",
                          "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-6(1)"}
       for n in (1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 16, 18, 19, 20)},
}

# ─── Remediation commands: check_id → AWS CLI command ────────────────────────
REMEDIATION_MAP = {
    "IAM-01": "Enable virtual MFA for root: aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa && aws iam enable-mfa-device --user-name root --serial-number <MFA_ARN> --authentication-code1 <CODE1> --authentication-code2 <CODE2>",
    "IAM-02": "Delete root access keys: aws iam delete-access-key --access-key-id <KEY_ID>",
    "IAM-04": "Enable MFA for user: aws iam enable-mfa-device --user-name <USER> --serial-number <MFA_ARN> --authentication-code1 <CODE1> --authentication-code2 <CODE2>",
    "IAM-05": "Update password policy: aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --max-password-age 90 --password-reuse-prevention 24",
    "IAM-06": "Deactivate stale key: aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name <USER>",
    "IAM-10": "Create Access Analyzer: aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT --region <REGION>",
    "S3-01": "Enable account BPA: aws s3control put-public-access-block --account-id <ACCT> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    "S3-03": "Enable bucket encryption: aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'",
    "S3-05": "Enable access logging: aws s3api put-bucket-logging --bucket <BUCKET> --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"<LOG_BUCKET>\",\"TargetPrefix\":\"s3-logs/\"}}'",
    "VPC-01": "Revoke risky SG rule: aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port <PORT> --cidr 0.0.0.0/0",
    "VPC-03": "Enable VPC Flow Logs: aws ec2 create-flow-logs --resource-type VPC --resource-ids <VPC_ID> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name vpc-flow-logs",
    "LOG-01": "Create multi-region trail: aws cloudtrail create-trail --name org-trail --s3-bucket-name <BUCKET> --is-multi-region-trail --enable-log-file-validation && aws cloudtrail start-logging --name org-trail",
    "LOG-03": "Start Config recorder: aws configservice start-configuration-recorder --configuration-recorder-name default",
    "LOG-04": "Enable GuardDuty: aws guardduty create-detector --enable",
    "LOG-05": "Enable Security Hub: aws securityhub enable-security-hub --enable-default-standards",
    "ENC-03": "Enable key rotation: aws kms enable-key-rotation --key-id <KEY_ID>",
    "EC2-04": "Enforce IMDSv2: aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens required --http-endpoint enabled",
    "EC2-06": "Enable default EBS encryption: aws ec2 enable-ebs-encryption-by-default",
    "RDS-01": "Create encrypted copy: aws rds create-db-snapshot --db-instance-identifier <DB_ID> --db-snapshot-identifier pre-encrypt-snap && aws rds copy-db-snapshot --source-db-snapshot-identifier pre-encrypt-snap --target-db-snapshot-identifier encrypted-snap --kms-key-id <KMS_KEY>",
    "RDS-02": "Disable public access: aws rds modify-db-instance --db-instance-identifier <DB_ID> --no-publicly-accessible",
    "RDS-04": "Enable deletion protection: aws rds modify-db-instance --db-instance-identifier <DB_ID> --deletion-protection",
    "RDS-06": "Remove public access from snapshot: aws rds modify-db-snapshot-attribute --db-snapshot-identifier <SNAP_ID> --attribute-name restore --values-to-remove all",
    "CFN-01": "Enforce HTTPS: aws cloudfront update-distribution --id <DIST_ID> --default-cache-behavior '{\"ViewerProtocolPolicy\":\"https-only\"}'",
    "CFN-03": "Associate WAF: aws cloudfront update-distribution --id <DIST_ID> --web-acl-id <WAF_ACL_ARN>",
    "LMB-01": "Remove public access: aws lambda remove-permission --function-name <FUNC> --statement-id <SID>",
    "LMB-02": "Add VPC config: aws lambda update-function-configuration --function-name <FUNC> --vpc-config SubnetIds=<SUBNETS>,SecurityGroupIds=<SGS>",
    "EKS-01": "Disable public endpoint: aws eks update-cluster-config --name <CLUSTER> --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true",
    "EKS-02": "Enable logging: aws eks update-cluster-config --name <CLUSTER> --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'",
    "EKS-03": "Enable secrets encryption: aws eks associate-encryption-config --cluster-name <CLUSTER> --encryption-config '[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"<KMS_ARN>\"}}]'",
    "SEC-01": "Enable rotation: aws secretsmanager rotate-secret --secret-id <SECRET_ID> --rotation-lambda-arn <LAMBDA_ARN> --rotation-rules AutomaticallyAfterDays=30",
    "SEC-02": "Update rotation schedule: aws secretsmanager rotate-secret --secret-id <SECRET_ID> --rotation-rules AutomaticallyAfterDays=90",
    "ELC-01": "Enable at-rest encryption on new cluster: aws elasticache create-replication-group --replication-group-id <ID> --at-rest-encryption-enabled",
    "ELC-02": "Enable in-transit encryption on new cluster: aws elasticache create-replication-group --replication-group-id <ID> --transit-encryption-enabled",
    "OSR-01": "Enforce HTTPS: aws opensearch update-domain-config --domain-name <DOMAIN> --domain-endpoint-options EnforceHTTPS=true,TLSSecurityPolicy=Policy-Min-TLS-1-2-2019-07",
    "OSR-02": "Enable encryption at rest: aws opensearch update-domain-config --domain-name <DOMAIN> --encrypt-at-rest-options Enabled=true",
    "OSR-04": "Configure VPC: aws opensearch update-domain-config --domain-name <DOMAIN> --vpc-options SubnetIds=<SUBNETS>,SecurityGroupIds=<SGS>",
    "DDB-01": "Enable CMK encryption: aws dynamodb update-table --table-name <TABLE> --sse-specification Enabled=true,SSEType=KMS",
    "DDB-02": "Enable PITR: aws dynamodb update-continuous-backups --table-name <TABLE> --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true",
    "DDB-04": "Enable deletion protection: aws dynamodb update-table --table-name <TABLE> --deletion-protection-enabled",
    "WAF-01": "Associate WAF with ALB: aws wafv2 associate-web-acl --web-acl-arn <ACL_ARN> --resource-arn <ALB_ARN>",
    "WAF-02": "Enable WAF logging: aws wafv2 put-logging-configuration --logging-configuration ResourceArn=<ACL_ARN>,LogDestinationConfigs=<LOG_ARN>",
    "SFN-01": "Enable logging: aws stepfunctions update-state-machine --state-machine-arn <ARN> --logging-configuration '{\"level\":\"ALL\",\"includeExecutionData\":true,\"destinations\":[{\"cloudWatchLogsLogGroup\":{\"logGroupArn\":\"<LOG_ARN>\"}}]}'",
    "APIGW-01": "Enable stage logging: aws apigateway update-stage --rest-api-id <API_ID> --stage-name <STAGE> --patch-operations op=replace,path=/accessLogSettings/destinationArn,value=<LOG_GROUP_ARN> op=replace,path=/*/*/logging/loglevel,value=INFO",
    "APIGW-02": "Associate WAF: aws wafv2 associate-web-acl --web-acl-arn <ACL_ARN> --resource-arn arn:aws:apigateway:<REGION>::/restapis/<API_ID>/stages/<STAGE>",
    "APIGW-03": "Encrypt cache: aws apigateway update-stage --rest-api-id <API_ID> --stage-name <STAGE> --patch-operations op=replace,path=/*/*/caching/dataEncrypted,value=true",
    "ELB-01": "Enable access logs: aws elbv2 modify-load-balancer-attributes --load-balancer-arn <LB_ARN> --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<BUCKET>",
    "ELB-02": "Redirect HTTP to HTTPS: aws elbv2 modify-listener --listener-arn <LISTENER_ARN> --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'",
    "ELB-03": "Use strong TLS policy: aws elbv2 modify-listener --listener-arn <LISTENER_ARN> --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06",
    "ELB-05": "Drop invalid headers: aws elbv2 modify-load-balancer-attributes --load-balancer-arn <LB_ARN> --attributes Key=routing.http.drop_invalid_header_fields.enabled,Value=true",
    "EBS-01": "Enable default encryption: aws ec2 enable-ebs-encryption-by-default",
    "EBS-02": "Encrypt volume: aws ec2 create-snapshot --volume-id <VOL_ID> then aws ec2 copy-snapshot --source-snapshot-id <SNAP> --encrypted --kms-key-id <KMS> and restore a new encrypted volume",
    "EBS-03": "Encrypt snapshot: aws ec2 copy-snapshot --source-snapshot-id <SNAP_ID> --source-region <REGION> --encrypted --kms-key-id <KMS_KEY>",
    "EBS-04": "Remove public access: aws ec2 reset-snapshot-attribute --snapshot-id <SNAP_ID> --attribute createVolumePermission",
    "RS-01": "Encrypt cluster: aws redshift modify-cluster --cluster-identifier <CLUSTER> --encrypted --kms-key-id <KMS_KEY>",
    "RS-02": "Disable public access: aws redshift modify-cluster --cluster-identifier <CLUSTER> --no-publicly-accessible",
    "RS-03": "Enable audit logging: aws redshift enable-logging --cluster-identifier <CLUSTER> --bucket-name <LOG_BUCKET>",
    "RS-04": "Enable enhanced VPC routing: aws redshift modify-cluster --cluster-identifier <CLUSTER> --enhanced-vpc-routing",
    "EFS-01": "Recreate encrypted: aws efs create-file-system --encrypted --kms-key-id <KMS_KEY> (encryption can only be set at creation; migrate data via DataSync)",
    "EFS-02": "Enforce TLS in policy: aws efs put-file-system-policy --file-system-id <FS_ID> --policy '{\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}'",
    "EFS-03": "Enable backups: aws efs put-backup-policy --file-system-id <FS_ID> --backup-policy Status=ENABLED",
    "ACM-01": "Renew/replace certificate before expiry: aws acm request-certificate --domain-name <DOMAIN> --validation-method DNS",
    "ACM-02": "Reissue with strong key: aws acm request-certificate --domain-name <DOMAIN> --validation-method DNS --key-algorithm RSA_2048",
    "SM-01": "Disable direct internet: aws sagemaker update-notebook-instance --notebook-instance-name <NB> --direct-internet-access Disabled (recreate may be required; attach to a private subnet)",
    "SM-02": "Disable root access: aws sagemaker update-notebook-instance --notebook-instance-name <NB> --root-access Disabled",
    "SM-03": "Set KMS key at creation: aws sagemaker create-notebook-instance --notebook-instance-name <NB> --kms-key-id <KMS_KEY> --instance-type ml.t3.medium --role-arn <ROLE>",
    "SM-04": "Attach to VPC subnet: aws sagemaker update-notebook-instance --notebook-instance-name <NB> --subnet-id <SUBNET> (recreate if subnet not set)",
    "COG-01": "Require MFA: aws cognito-idp set-user-pool-mfa-config --user-pool-id <POOL_ID> --mfa-configuration ON --software-token-mfa-configuration Enabled=true",
    "COG-02": "Strengthen password policy: aws cognito-idp update-user-pool --user-pool-id <POOL_ID> --policies PasswordPolicy='{MinimumLength=12,RequireUppercase=true,RequireLowercase=true,RequireNumbers=true,RequireSymbols=true}'",
    "COG-03": "Enable threat protection: aws cognito-idp update-user-pool --user-pool-id <POOL_ID> --user-pool-add-ons AdvancedSecurityMode=ENFORCED",
    "AGW2-01": "Enable access logging: aws apigatewayv2 update-stage --api-id <API_ID> --stage-name <STAGE> --access-log-settings DestinationArn=<LOG_GROUP_ARN>,Format='$context.requestId'",
    "AGW2-02": "Add an authorizer to routes: aws apigatewayv2 update-route --api-id <API_ID> --route-key '<ROUTE>' --authorization-type JWT --authorizer-id <AUTHORIZER_ID>",
    "IAMPE-01": "Find where the grant lives (aws iam list-entities-for-policy --policy-arn <ARN>), remove iam:CreatePolicyVersion, and constrain the principal: aws iam put-user-permissions-boundary --user-name <USER> --permissions-boundary <BOUNDARY_ARN>",
    "IAMPE-03": "Remove iam:Attach*Policy from the principal and apply a permissions boundary: aws iam put-user-permissions-boundary --user-name <USER> --permissions-boundary <BOUNDARY_ARN>",
    "IAMPE-04": "Remove the inline grant (aws iam delete-user-policy --user-name <USER> --policy-name <INLINE>) and apply a permissions boundary",
    "IAMPE-07": "Remove iam:CreateLoginProfile/UpdateLoginProfile and bound the principal: aws iam put-user-permissions-boundary --user-name <USER> --permissions-boundary <BOUNDARY_ARN>",
    "IAMPE-08": "Remove iam:UpdateAssumeRolePolicy and bound the principal: aws iam put-user-permissions-boundary --user-name <USER> --permissions-boundary <BOUNDARY_ARN>",
    "IAMPE-10": "Scope iam:PassRole to specific role ARNs with an iam:PassedToService condition, then bound the principal: aws iam put-user-permissions-boundary --user-name <USER> --permissions-boundary <BOUNDARY_ARN>",
    "IAMPE-11": "Scope iam:PassRole to specific role ARNs and restrict lambda:CreateFunction; bound the principal: aws iam put-user-permissions-boundary --user-name <USER> --permissions-boundary <BOUNDARY_ARN>",
    "IAMPE-16": "Restrict lambda:UpdateFunctionCode to specific function ARNs and require code signing: aws lambda put-function-code-signing-config --function-name <FUNC> --code-signing-config-arn <CSC_ARN>",
    "IAMPE-19": "Remove the wildcard '*' grant and replace with least-privilege policies; as an immediate guardrail bound the principal: aws iam put-user-permissions-boundary --user-name <USER> --permissions-boundary <BOUNDARY_ARN>",
    "IAMPE-20": "Scope sts:AssumeRole to specific trusted role ARNs instead of '*': edit the policy Resource, then bound the principal: aws iam put-user-permissions-boundary --user-name <USER> --permissions-boundary <BOUNDARY_ARN>",
}


# ─── IAM privilege-escalation primitives ─────────────────────────────────────
# Action-level model (Rhino Security Labs / PMapper technique set). Each rule's
# `all_of` is a list of requirements; a requirement is satisfied if the principal
# is allowed ANY of its alternative actions. A rule fires when EVERY requirement
# is satisfied. Matching is at the action level only — resource ARNs and policy
# conditions are NOT evaluated, so findings are *potential* paths to verify.
IAM_PRIVESC_RULES = [
    {"id": "IAMPE-01", "name": "Modify a managed policy version",
     "all_of": [["iam:CreatePolicyVersion"]],
     "desc": "Can create a new default version of an attached managed policy and grant itself admin"},
    {"id": "IAMPE-02", "name": "Set default policy version",
     "all_of": [["iam:SetDefaultPolicyVersion"]],
     "desc": "Can roll a managed policy back to a more permissive existing version"},
    {"id": "IAMPE-03", "name": "Attach an administrator policy",
     "all_of": [["iam:AttachUserPolicy", "iam:AttachGroupPolicy", "iam:AttachRolePolicy"]],
     "desc": "Can attach AdministratorAccess to a user/group/role it controls"},
    {"id": "IAMPE-04", "name": "Inline an administrator policy",
     "all_of": [["iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy"]],
     "desc": "Can write an inline admin policy onto a user/group/role"},
    {"id": "IAMPE-05", "name": "Add user to a privileged group",
     "all_of": [["iam:AddUserToGroup"]],
     "desc": "Can add itself to a group that has elevated permissions"},
    {"id": "IAMPE-06", "name": "Create access keys for another user",
     "all_of": [["iam:CreateAccessKey"]],
     "desc": "Can mint API keys for a more privileged user"},
    {"id": "IAMPE-07", "name": "Set a console password for another user",
     "all_of": [["iam:CreateLoginProfile", "iam:UpdateLoginProfile"]],
     "desc": "Can set/replace the console login profile of a privileged user"},
    {"id": "IAMPE-08", "name": "Modify a role trust policy",
     "all_of": [["iam:UpdateAssumeRolePolicy"]],
     "desc": "Can rewrite a role's trust policy to assume it, then sts:AssumeRole"},
    {"id": "IAMPE-10", "name": "PassRole to a new EC2 instance",
     "all_of": [["iam:PassRole"], ["ec2:RunInstances"]],
     "desc": "Can launch an EC2 instance with a privileged instance profile"},
    {"id": "IAMPE-11", "name": "PassRole to a new Lambda function",
     "all_of": [["iam:PassRole"], ["lambda:CreateFunction"],
                ["lambda:InvokeFunction", "lambda:AddPermission",
                 "lambda:CreateEventSourceMapping"]],
     "desc": "Can create and invoke a Lambda running a privileged execution role"},
    {"id": "IAMPE-12", "name": "PassRole to a Glue dev endpoint",
     "all_of": [["iam:PassRole"], ["glue:CreateDevEndpoint"]],
     "desc": "Can create a Glue dev endpoint with a privileged role"},
    {"id": "IAMPE-13", "name": "PassRole to a CloudFormation stack",
     "all_of": [["iam:PassRole"], ["cloudformation:CreateStack"]],
     "desc": "Can deploy a CloudFormation stack with a privileged role"},
    {"id": "IAMPE-14", "name": "PassRole to a SageMaker resource",
     "all_of": [["iam:PassRole"],
                ["sagemaker:CreateNotebookInstance", "sagemaker:CreateTrainingJob",
                 "sagemaker:CreateProcessingJob"]],
     "desc": "Can run a SageMaker notebook/job with a privileged role"},
    {"id": "IAMPE-16", "name": "Overwrite a privileged Lambda's code",
     "all_of": [["lambda:UpdateFunctionCode"]],
     "desc": "Can replace the code of an existing function that runs a privileged role"},
    {"id": "IAMPE-18", "name": "Run commands on EC2 via SSM",
     "all_of": [["ssm:SendCommand", "ssm:StartSession"]],
     "desc": "Can execute commands on instances that carry privileged roles"},
]

# Sentinel rule applied first: principal already holds full admin (*)
IAM_PRIVESC_FULL_ADMIN = {
    "id": "IAMPE-19", "name": "Full administrative access",
    "desc": "Principal is allowed Action '*' on all resources (effective administrator)",
}


def _action_allowed(action: str, allow: set, deny: set) -> bool:
    """True if `action` is matched by an allow pattern and not by a deny pattern.
    Wildcards (*, ?) in policy patterns are honoured; matching is case-insensitive."""
    a = action.lower()
    allowed = any(fnmatch.fnmatch(a, p) for p in allow)
    denied = any(fnmatch.fnmatch(a, p) for p in deny)
    return allowed and not denied


def evaluate_privesc(allow: set, deny: set) -> List[Dict]:
    """Return the list of privesc rules a principal (given its effective allow/deny
    action sets) can satisfy. Full-admin short-circuits to a single finding.
    Action-level only — see evaluate_privesc_scoped() for resource-aware scoping."""
    # Full admin: allowed literal "*" and not explicitly denied "*"
    if "*" in allow and "*" not in deny:
        return [IAM_PRIVESC_FULL_ADMIN]
    matched = []
    for rule in IAM_PRIVESC_RULES:
        if all(any(_action_allowed(act, allow, deny) for act in req)
               for req in rule["all_of"]):
            matched.append(rule)
    return matched


# ─── Resource-aware evaluation ───────────────────────────────────────────────
# sts:AssumeRole is extremely common when scoped to specific roles, so it is only
# flagged when granted account-wide (Resource "*") — exactly the false positive
# that resource awareness removes.
IAM_PRIVESC_ASSUMEROLE = {
    "id": "IAMPE-20", "name": "Assume any role (sts:AssumeRole on *)",
    "desc": "Can assume ANY role in the account (role chaining); only flagged when unrestricted",
}


def _stmt_actions_match(stmt: Dict, action: str) -> bool:
    return any(fnmatch.fnmatch(action, p) for p in stmt["actions"])


def _arn_service(arn: str) -> str:
    """Service segment of an ARN (arn:partition:service:...), or '' if not an ARN."""
    parts = arn.split(":")
    return parts[2] if len(parts) >= 3 else ""


def _resource_applies(resource: str, action_service: str) -> bool:
    """A resource is relevant to an action only if it is '*' or an ARN of the same
    service. This suppresses e.g. Action '*' scoped to an S3 bucket being treated as
    granting iam:* (the action does not apply to that resource type)."""
    if resource == "*":
        return True
    svc = _arn_service(resource)
    return svc in (action_service, "*", "")


def resource_scope(statements: List[Dict], action: str):
    """For a concrete `action`, return (label, arns) describing the resources it is
    allowed on, counting only resources of the action's own service (or '*'):
    ("account-wide", None) if granted on "*", ("resource-scoped", [arns]) if only on
    specific same-service ARNs, ("none", None) if not actually grantable.
    A missing/empty Resource is treated as "*" (broad) to avoid under-reporting."""
    a = action.lower()
    svc = a.split(":")[0] if ":" in a else a
    allow_res = set()
    for st in statements:
        if st["effect"] != "Allow" or not _stmt_actions_match(st, a):
            continue
        for r in (st["resources"] or {"*"}):
            if _resource_applies(r, svc):
                allow_res.add(r)
    if not allow_res:
        return ("none", None)
    if "*" in allow_res:
        return ("account-wide", None)
    return ("resource-scoped", sorted(allow_res))


def _has_full_admin(statements: List[Dict]) -> bool:
    """True only for Action '*' on Resource '*' (real admin), not Action '*' scoped
    to a single resource. An explicit Deny '*'/'*' revokes it."""
    deny_all = any(st["effect"] == "Deny" and "*" in st["actions"]
                   and "*" in (st["resources"] or {"*"}) for st in statements)
    if deny_all:
        return False
    return any(st["effect"] == "Allow" and "*" in st["actions"]
               and "*" in (st["resources"] or {"*"}) for st in statements)


def _pivot_action(rule: Dict, allow: set, deny: set) -> str:
    """The granting action of a rule that the principal actually holds — taken from
    the rule's first requirement (e.g. iam:PassRole for the PassRole primitives)."""
    for alt in rule["all_of"][0]:
        if _action_allowed(alt, allow, deny):
            return alt.lower()
    return rule["all_of"][0][0].lower()


def evaluate_privesc_scoped(statements: List[Dict]) -> List[Dict]:
    """Resource-aware privesc evaluation. Returns matched rules annotated with
    `scope` (account-wide | resource-scoped) and `scope_arns`. Reduces false
    positives vs the action-level model: full admin requires Action '*' on
    Resource '*', and sts:AssumeRole is only flagged when unrestricted."""
    if _has_full_admin(statements):
        return [{**IAM_PRIVESC_FULL_ADMIN, "scope": "account-wide",
                 "scope_arns": None, "pivot": "*"}]

    allow, deny = set(), set()
    for st in statements:
        if st["effect"] == "Allow":
            allow |= st["actions"]
        elif st["effect"] == "Deny":
            deny |= st["actions"]

    findings = []
    for rule in IAM_PRIVESC_RULES:
        if all(any(_action_allowed(act, allow, deny) for act in req)
               for req in rule["all_of"]):
            pivot = _pivot_action(rule, allow, deny)
            label, arns = resource_scope(statements, pivot)
            if label == "none":
                continue  # pivot action not grantable on any compatible resource
            findings.append({**rule, "scope": label, "scope_arns": arns, "pivot": pivot})

    # IAMPE-20: only when sts:AssumeRole is granted account-wide
    if _action_allowed("sts:assumerole", allow, deny):
        label, arns = resource_scope(statements, "sts:assumerole")
        if label == "account-wide":
            findings.append({**IAM_PRIVESC_ASSUMEROLE, "scope": label,
                             "scope_arns": None, "pivot": "sts:assumerole"})
    return findings


# ─── Risk scoring ────────────────────────────────────────────────────────────
def compute_risk_score(results: List[Result]) -> float:
    """Compute posture score: 100 − (CRIT×15 + HIGH×5 + MED×2 + LOW×0.5).
    Clamped to 0–100.  Only FAIL results count as penalties."""
    penalty = 0.0
    for r in results:
        if r.status == "FAIL" and r.severity:
            penalty += SEVERITY_WEIGHTS.get(r.severity, 0)
    return max(0.0, min(100.0, round(100 - penalty, 1)))


def score_to_grade(score: float) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


# ─── Workflow-integration helpers (SARIF / ASFF / gating / diff) ─────────────
# Ordinal ranking so we can compare severities for --fail-on thresholds.
SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "": 0}

# Map internal severity → SARIF result level.
SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
               "LOW": "note", "INFO": "none", "": "warning"}

# Map internal severity → AWS Security Finding Format (ASFF) severity label.
ASFF_SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                 "LOW": "LOW", "INFO": "INFORMATIONAL", "": "INFORMATIONAL"}

# Map status → ASFF Compliance.Status.
ASFF_COMPLIANCE_STATUS = {"FAIL": "FAILED", "WARN": "WARNING",
                          "PASS": "PASSED", "INFO": "NOT_AVAILABLE"}


def finding_key(check_id: str, resource: str) -> str:
    """Stable identity for a finding, used for diffing and fingerprints."""
    return f"{check_id}|{resource}"


def fails_threshold(results: List[Result], threshold: str) -> bool:
    """True if any FAIL result is at or above `threshold` severity."""
    floor = SEVERITY_ORDER.get(threshold.upper(), 0)
    return any(r.status == "FAIL"
               and SEVERITY_ORDER.get(r.severity, 0) >= floor
               for r in results)


def diff_findings(current: List[Result], baseline_results: List[Dict]) -> Dict:
    """Compare current findings against a previously-saved JSON report's results.
    Only FAIL/WARN entries are treated as findings. Returns new + resolved lists
    keyed by (check_id, resource)."""
    def _key_set(items, getter):
        return {finding_key(getter(i, "check_id"), getter(i, "resource")): i
                for i in items
                if getter(i, "status") in ("FAIL", "WARN")}

    cur = _key_set(current, lambda r, a: getattr(r, a))
    base = _key_set(baseline_results, lambda d, a: d.get(a, ""))

    new_keys = cur.keys() - base.keys()
    resolved_keys = base.keys() - cur.keys()
    return {
        "new": [cur[k] for k in sorted(new_keys)],
        "resolved": [base[k] for k in sorted(resolved_keys)],
    }


# ─── Scanner ──────────────────────────────────────────────────────────────────
class AWSLiveScanner:
    """Live, read-only AWS security audit scanner."""

    def __init__(
        self,
        region:   str = "eu-west-1",
        verbose:  bool = False,
        sections: Optional[List[str]] = None,
    ):
        self.region   = region
        self.verbose  = verbose
        self.sections = [s.upper() for s in sections] if sections else list(SECTIONS)
        self.results:  List[Result] = []
        self.account   = ""
        self._clients: Dict[str, object] = {}
        self._cred_report:  Optional[List[Dict]] = None
        self._all_regions:  Optional[List[str]]  = None
        self._iam_principals: Optional[List[Dict]] = None
        self._managed_policy_cache: Dict[str, tuple] = {}

    # ── boto3 client factory (lazy, cached) ───────────────────────────────────
    def _client(self, service: str, region: Optional[str] = None):
        if not HAS_BOTO3:
            raise ImportError(
                "boto3 is not installed. Run: pip install boto3"
            )
        key = f"{service}:{region or self.region}"
        if key not in self._clients:
            self._clients[key] = boto3.client(  # type: ignore[name-defined]
                service, region_name=region or self.region
            )
        return self._clients[key]

    # ── Result helpers ────────────────────────────────────────────────────────
    def _add(self, status: str, check_id: str, section: str,
             resource: str, message: str):
        severity = ""
        compliance = {}
        remediation = ""
        if status == "FAIL":
            severity = CHECK_SEVERITY.get(check_id, "MEDIUM")
            compliance = COMPLIANCE_MAP.get(check_id, {})
            remediation = REMEDIATION_MAP.get(check_id, "")
        elif status == "WARN":
            severity = "LOW"
            compliance = COMPLIANCE_MAP.get(check_id, {})
        self.results.append(Result(
            status, check_id, section, resource, message,
            severity, compliance, remediation,
        ))
        if self.verbose or status in ("FAIL", "WARN"):
            col = STATUS_COLOR.get(status, RESET)
            res = f" | {resource}" if resource else ""
            sev_tag = f" [{severity}]" if severity else ""
            print(f"  {col}{STATUS_ICON[status]}{RESET} {check_id}{sev_tag}: {message}{res}")

    def _log(self, msg: str):
        print(f"{BLUE}[*]{RESET} {msg}")

    def _section_header(self, section: str):
        label = SECTION_LABELS.get(section, section)
        print(f"\n{BOLD}{BLUE}══ {label} ══{RESET}")

    # ── IAM credential report (cached) ───────────────────────────────────────
    def _get_credential_report(self) -> List[Dict]:
        if self._cred_report is not None:
            return self._cred_report
        try:
            iam = self._client("iam")
            iam.generate_credential_report()
            time.sleep(6)
            resp    = iam.get_credential_report()
            content = base64.b64decode(resp["Content"]).decode("utf-8")
            self._cred_report = list(csv.DictReader(io.StringIO(content)))
        except Exception as e:
            self._log(f"Could not generate credential report: {e}")
            self._cred_report = []
        return self._cred_report

    # ── All enabled regions (cached) ─────────────────────────────────────────
    def _get_all_regions(self) -> List[str]:
        if self._all_regions is not None:
            return self._all_regions
        try:
            ec2 = self._client("ec2")
            self._all_regions = [
                r["RegionName"]
                for r in ec2.describe_regions()["Regions"]
            ]
        except Exception:
            self._all_regions = [self.region]
        return self._all_regions

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 1: IDENTITY & ACCESS MANAGEMENT
    # ══════════════════════════════════════════════════════════════════════════
    def _check_iam(self):
        self._section_header("IAM")
        iam = self._client("iam")

        # IAM-01 / IAM-02 — Root account MFA and access keys
        self._log("IAM-01/02: Root account MFA and access keys")
        try:
            summary   = iam.get_account_summary()["SummaryMap"]
            root_mfa  = summary.get("AccountMFAEnabled", 0)
            root_keys = summary.get("AccountAccessKeysPresent", 0)
            if root_mfa == 1:
                self._add("PASS", "IAM-01", "IAM", "root", "Root MFA is enabled")
            else:
                self._add("FAIL", "IAM-01", "IAM", "root",
                          "Root MFA is NOT enabled — CRITICAL")
            if root_keys == 0:
                self._add("PASS", "IAM-02", "IAM", "root",
                          "No root access keys present")
            else:
                self._add("FAIL", "IAM-02", "IAM", "root",
                          "Root access keys EXIST — CRITICAL: remove immediately")
        except Exception as e:
            self._add("FAIL", "IAM-01", "IAM", "root",
                      f"Could not check root account: {e}")

        # IAM-04 — Console users without MFA
        self._log("IAM-04: Console users without MFA")
        no_mfa_found = False
        for row in self._get_credential_report():
            if row.get("user") == "<root_account>":
                continue
            if (row.get("password_enabled") == "true"
                    and row.get("mfa_active") == "false"):
                self._add("FAIL", "IAM-04", "IAM", row["user"],
                          f"Console user WITHOUT MFA: {row['user']}")
                no_mfa_found = True
        if not no_mfa_found:
            self._add("PASS", "IAM-04", "IAM", "all-users",
                      "All console users have MFA enabled")

        # IAM-05 — Password policy
        self._log("IAM-05: Password policy")
        try:
            p      = iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if p.get("MinimumPasswordLength", 0) < 14:
                issues.append(
                    f"MinLength={p.get('MinimumPasswordLength')} (need ≥14)"
                )
            if not p.get("RequireSymbols"):
                issues.append("RequireSymbols=false")
            if not p.get("RequireNumbers"):
                issues.append("RequireNumbers=false")
            if not p.get("RequireUppercaseCharacters"):
                issues.append("RequireUppercase=false")
            if p.get("MaxPasswordAge", 999) > 90:
                issues.append(f"MaxAge={p.get('MaxPasswordAge')} (need ≤90)")
            if not p.get("PreventPasswordReuse") or \
                    p.get("PasswordReusePrevention", 0) < 24:
                issues.append("PasswordReuse<24")
            if issues:
                self._add("FAIL", "IAM-05", "IAM", "password-policy",
                          f"Password policy issues: {', '.join(issues)}")
            else:
                self._add("PASS", "IAM-05", "IAM", "password-policy",
                          "Password policy meets CIS requirements")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                self._add("FAIL", "IAM-05", "IAM", "password-policy",
                          "No account password policy set")
            else:
                self._add("FAIL", "IAM-05", "IAM", "password-policy", str(e))

        # IAM-06 — Stale access keys (>90 days)
        self._log("IAM-06: Stale access keys (>90 days)")
        for row in self._get_credential_report():
            for k in ["access_key_1", "access_key_2"]:
                if row.get(f"{k}_active") == "true":
                    rotated = row.get(f"{k}_last_rotated", "")
                    if rotated and rotated not in ("N/A", "no_information"):
                        age = (
                            datetime.now(timezone.utc)
                            - datetime.fromisoformat(rotated)
                        ).days
                        user = row["user"]
                        if age > 90:
                            self._add("FAIL", "IAM-06", "IAM",
                                      f"{user}/{k}",
                                      f"{user} {k} is {age} days old — rotate immediately")
                        else:
                            self._add("PASS", "IAM-06", "IAM",
                                      f"{user}/{k}",
                                      f"{user} {k} age={age}d OK")

        # IAM-10 — Access Analyzer in all regions
        self._log("IAM-10: Access Analyzer enabled in all regions")
        for rgn in self._get_all_regions():
            try:
                aa    = self._client("accessanalyzer", region=rgn)
                count = len(aa.list_analyzers()["analyzers"])
                if count > 0:
                    self._add("PASS", "IAM-10", "IAM", rgn,
                              f"Access Analyzer active in {rgn}")
                else:
                    self._add("FAIL", "IAM-10", "IAM", rgn,
                              f"No Access Analyzer in {rgn}")
            except Exception as e:
                self._add("WARN", "IAM-10", "IAM", rgn,
                          f"Could not check Access Analyzer in {rgn}: {e}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 2: S3 SECURITY
    # ══════════════════════════════════════════════════════════════════════════
    def _check_s3(self):
        self._section_header("S3")
        s3  = self._client("s3")
        s3c = self._client("s3control")

        # S3-01 — Account-level Block Public Access
        self._log("S3-01: Account-level Block Public Access")
        try:
            cfg = s3c.get_public_access_block(AccountId=self.account)[
                "PublicAccessBlockConfiguration"
            ]
            if all(cfg.values()):
                self._add("PASS", "S3-01", "S3", "account",
                          "Account-level Block Public Access fully enabled")
            else:
                disabled = [k for k, v in cfg.items() if not v]
                self._add("FAIL", "S3-01", "S3", "account",
                          f"Block Public Access not fully enabled — Disabled: {disabled}")
        except Exception as e:
            self._add("FAIL", "S3-01", "S3", "account",
                      f"Could not retrieve account-level BPA: {e}")

        # Per-bucket checks
        self._log("S3-01/S3-03/S3-05: Per-bucket security scan")
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            self._add("FAIL", "S3-01", "S3", "all-buckets",
                      f"Cannot list S3 buckets: {e}")
            return

        for b in buckets:
            bname = b["Name"]

            # BPA per bucket
            try:
                bpa = s3.get_public_access_block(Bucket=bname)[
                    "PublicAccessBlockConfiguration"
                ]
                if all(bpa.values()):
                    self._add("PASS", "S3-01", "S3", bname,
                              f"BPA fully enabled | {bname}")
                else:
                    self._add("FAIL", "S3-01", "S3", bname,
                              f"BPA NOT fully enabled | {bname}")
            except Exception:
                self._add("FAIL", "S3-01", "S3", bname,
                          f"No BPA config | {bname}")

            # Encryption
            try:
                enc = s3.get_bucket_encryption(Bucket=bname)[
                    "ServerSideEncryptionConfiguration"
                ]
                alg = enc["Rules"][0]["ApplyServerSideEncryptionByDefault"][
                    "SSEAlgorithm"
                ]
                self._add("PASS", "S3-03", "S3", bname,
                          f"Encryption={alg} | {bname}")
            except Exception:
                self._add("FAIL", "S3-03", "S3", bname,
                          f"No default encryption | {bname}")

            # Access logging
            try:
                log_cfg = s3.get_bucket_logging(Bucket=bname).get(
                    "LoggingEnabled"
                )
                if log_cfg:
                    self._add("PASS", "S3-05", "S3", bname,
                              f"Access logging enabled | {bname}")
                else:
                    self._add("WARN", "S3-05", "S3", bname,
                              f"Access logging disabled | {bname}")
            except Exception:
                pass

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 3: NETWORK SECURITY
    # ══════════════════════════════════════════════════════════════════════════
    def _check_vpc(self):
        self._section_header("VPC")
        ec2 = self._client("ec2")

        RISKY_PORTS = {
            22:    "SSH",   3389: "RDP",     1433: "MSSQL",
            3306:  "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
            6379:  "Redis", 9200: "Elasticsearch", 9300: "Elasticsearch",
            8080:  "HTTP-alt", 445: "SMB",
        }

        # VPC-01 — Security groups with risky ports open to 0.0.0.0/0 or ::/0
        self._log("VPC-01: Security Groups — risky ports open to 0.0.0.0/0 or ::/0")
        found_any = False
        try:
            for sg in ec2.describe_security_groups()["SecurityGroups"]:
                for perm in sg.get("IpPermissions", []):
                    fp = perm.get("FromPort", 0)
                    tp = perm.get("ToPort", 65535)
                    open_cidrs = (
                        [r["CidrIp"]   for r in perm.get("IpRanges",   [])
                         if r["CidrIp"]   == "0.0.0.0/0"]
                        + [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])
                           if r["CidrIpv6"] == "::/0"]
                    )
                    if open_cidrs:
                        for port, svc in RISKY_PORTS.items():
                            if fp <= port <= tp:
                                self._add(
                                    "FAIL", "VPC-01", "VPC",
                                    f"{sg['GroupId']} ({sg.get('GroupName', '')})",
                                    f"Exposes port {port}/{svc} to "
                                    f"{', '.join(open_cidrs)}",
                                )
                                found_any = True
        except Exception as e:
            self._add("FAIL", "VPC-01", "VPC", "security-groups", str(e))

        if not found_any:
            self._add("PASS", "VPC-01", "VPC", "all-sgs",
                      "No Security Groups expose high-risk ports to 0.0.0.0/0 or ::/0")

        # VPC-03 — VPC Flow Logs
        self._log("VPC-03: VPC Flow Logs enabled on all VPCs")
        try:
            vpcs   = {v["VpcId"]: v for v in ec2.describe_vpcs()["Vpcs"]}
            fl_ids = {
                fl["ResourceId"]
                for fl in ec2.describe_flow_logs()["FlowLogs"]
            }
            for vid, vpc in vpcs.items():
                is_default = vpc.get("IsDefault", False)
                if vid in fl_ids:
                    self._add("PASS", "VPC-03", "VPC", vid,
                              f"Flow Logs enabled | {vid}")
                elif is_default:
                    self._add("WARN", "VPC-03", "VPC", vid,
                              f"No Flow Logs on default VPC | {vid}")
                else:
                    self._add("FAIL", "VPC-03", "VPC", vid,
                              f"No Flow Logs | {vid}")
        except Exception as e:
            self._add("FAIL", "VPC-03", "VPC", "vpcs", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 4: LOGGING & MONITORING
    # ══════════════════════════════════════════════════════════════════════════
    def _check_logging(self):
        self._section_header("LOGGING")

        # LOG-01 — CloudTrail
        self._log("LOG-01: CloudTrail configuration")
        try:
            ct     = self._client("cloudtrail")
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
            if not trails:
                self._add("FAIL", "LOG-01", "LOGGING", "cloudtrail",
                          "No CloudTrail trails configured — CRITICAL")
            else:
                for t in trails:
                    issues = []
                    if not t.get("IsMultiRegionTrail"):
                        issues.append("not multi-region")
                    if not t.get("LogFileValidationEnabled"):
                        issues.append("log validation OFF")
                    try:
                        status = ct.get_trail_status(Name=t["Name"])
                        if not status.get("IsLogging"):
                            issues.append("LOGGING IS OFF")
                    except Exception:
                        issues.append("could not get trail status")
                    if issues:
                        self._add("FAIL", "LOG-01", "LOGGING", t["Name"],
                                  f"Trail '{t['Name']}' issues: {', '.join(issues)}")
                    else:
                        self._add("PASS", "LOG-01", "LOGGING", t["Name"],
                                  f"Trail '{t['Name']}' OK (multi-region, "
                                  "validation enabled, logging active)")
        except Exception as e:
            self._add("FAIL", "LOG-01", "LOGGING", "cloudtrail", str(e))

        # LOG-03 — AWS Config recorder
        self._log("LOG-03: AWS Config recorder status")
        try:
            cfg  = self._client("config")
            recs = cfg.describe_configuration_recorder_status()[
                "ConfigurationRecordersStatus"
            ]
            if not recs:
                self._add("FAIL", "LOG-03", "LOGGING", "config",
                          "No AWS Config recorders found")
            for r in recs:
                if r.get("recording"):
                    self._add("PASS", "LOG-03", "LOGGING", r["name"],
                              f"AWS Config recording | {r['name']}")
                else:
                    self._add("FAIL", "LOG-03", "LOGGING", r["name"],
                              f"AWS Config NOT recording | {r['name']}")
        except Exception as e:
            self._add("FAIL", "LOG-03", "LOGGING", "config", str(e))

        # LOG-04 — GuardDuty
        self._log("LOG-04: GuardDuty enabled in current region")
        try:
            gd   = self._client("guardduty")
            dids = gd.list_detectors().get("DetectorIds", [])
            if not dids:
                self._add("FAIL", "LOG-04", "LOGGING", "guardduty",
                          "GuardDuty NOT enabled — CRITICAL")
            else:
                for did in dids:
                    d      = gd.get_detector(DetectorId=did)
                    status = d.get("Status", "DISABLED")
                    if status == "ENABLED":
                        self._add("PASS", "LOG-04", "LOGGING", did,
                                  f"GuardDuty ENABLED | {did}")
                    else:
                        self._add("FAIL", "LOG-04", "LOGGING", did,
                                  f"GuardDuty {status} | {did}")
        except Exception as e:
            self._add("FAIL", "LOG-04", "LOGGING", "guardduty", str(e))

        # LOG-05 — Security Hub standards
        self._log("LOG-05: Security Hub standards")
        try:
            sh        = self._client("securityhub")
            standards = sh.get_enabled_standards()["StandardsSubscriptions"]
            if not standards:
                self._add("FAIL", "LOG-05", "LOGGING", "securityhub",
                          "Security Hub enabled but no standards subscribed")
            else:
                for s in standards:
                    std_name = s.get("StandardsArn", "").split("/")[-2]
                    self._add("PASS", "LOG-05", "LOGGING", std_name,
                              f"Security Hub standard: {std_name} — "
                              f"{s.get('StandardsStatus', '')}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("InvalidAccessException", "AccessDeniedException"):
                self._add("FAIL", "LOG-05", "LOGGING", "securityhub",
                          "Security Hub not enabled in this region")
            else:
                self._add("FAIL", "LOG-05", "LOGGING", "securityhub", str(e))
        except Exception as e:
            self._add("FAIL", "LOG-05", "LOGGING", "securityhub", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 5: ENCRYPTION & KMS
    # ══════════════════════════════════════════════════════════════════════════
    def _check_kms(self):
        self._section_header("KMS")
        self._log("ENC-03: Customer-managed KMS key rotation")
        kms   = self._client("kms")
        found = False
        try:
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for key in page["Keys"]:
                    kid = key["KeyId"]
                    try:
                        meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
                        if (meta.get("KeyManager") == "CUSTOMER"
                                and meta.get("KeyState") == "Enabled"):
                            found    = True
                            rotation = kms.get_key_rotation_status(
                                KeyId=kid
                            ).get("KeyRotationEnabled", False)
                            desc = meta.get("Description") or kid[:8]
                            if rotation:
                                self._add("PASS", "ENC-03", "KMS", kid,
                                          f"Key rotation=ON | {desc}")
                            else:
                                self._add("FAIL", "ENC-03", "KMS", kid,
                                          f"Key rotation=OFF | {desc}")
                    except Exception:
                        pass
            if not found:
                self._add("WARN", "ENC-03", "KMS", "all-keys",
                          "No customer-managed KMS keys found")
        except Exception as e:
            self._add("FAIL", "ENC-03", "KMS", "kms", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 6: COMPUTE / EC2
    # ══════════════════════════════════════════════════════════════════════════
    def _check_ec2(self):
        self._section_header("EC2")
        ec2 = self._client("ec2")

        # EC2-04 — IMDSv2 enforcement
        self._log("EC2-04: IMDSv2 enforcement on all instances")
        all_pass = True
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{
                    "Name":   "instance-state-name",
                    "Values": ["running", "stopped"],
                }]
            ):
                for res in page["Reservations"]:
                    for i in res["Instances"]:
                        iid    = i["InstanceId"]
                        name   = next(
                            (t["Value"] for t in i.get("Tags", [])
                             if t["Key"] == "Name"),
                            iid,
                        )
                        tokens = i.get("MetadataOptions", {}).get(
                            "HttpTokens", "optional"
                        )
                        if tokens != "required":
                            self._add("FAIL", "EC2-04", "EC2", name,
                                      f"IMDSv2 not enforced "
                                      f"(HttpTokens={tokens}) | {name}")
                            all_pass = False
            if all_pass:
                self._add("PASS", "EC2-04", "EC2", "all-instances",
                          "All EC2 instances enforce IMDSv2")
        except Exception as e:
            self._add("FAIL", "EC2-04", "EC2", "ec2", str(e))

        # EC2-06 — EBS volume encryption
        self._log("EC2-06: EBS volume encryption")
        try:
            volumes    = ec2.describe_volumes()["Volumes"]
            enc_count  = sum(1 for v in volumes if v.get("Encrypted", False))
            unenc_vols = [v for v in volumes if not v.get("Encrypted", False)]
            if enc_count:
                self._add("PASS", "EC2-06", "EC2", "ebs-volumes",
                          f"Encrypted volumes: {enc_count}")
            for v in unenc_vols:
                self._add("FAIL", "EC2-06", "EC2", v["VolumeId"],
                          f"UNENCRYPTED EBS volume: {v['VolumeId']} "
                          f"State={v['State']}")
        except Exception as e:
            self._add("FAIL", "EC2-06", "EC2", "ebs", str(e))

        # EC2-05 — EC2 instances with public IPs
        self._log("EC2-05: EC2 instances with public IPs")
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{
                    "Name": "instance-state-name", "Values": ["running"]
                }]
            ):
                for res in page["Reservations"]:
                    for i in res["Instances"]:
                        if i.get("PublicIpAddress"):
                            name = next(
                                (t["Value"] for t in i.get("Tags", [])
                                 if t["Key"] == "Name"),
                                i["InstanceId"],
                            )
                            self._add("WARN", "EC2-05", "EC2", name,
                                      f"Public IP {i['PublicIpAddress']} on "
                                      f"{name} — verify if intentional")
        except Exception as e:
            self._add("FAIL", "EC2-05", "EC2", "ec2", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 7: CONTAINER SECURITY (ECR)
    # ══════════════════════════════════════════════════════════════════════════
    def _check_ecr(self):
        self._section_header("ECR")
        self._log("CNT-01: ECR scan-on-push and encryption")
        try:
            ecr   = self._client("ecr")
            repos = ecr.describe_repositories()["repositories"]
            if not repos:
                self._add("WARN", "CNT-01", "ECR", "ecr",
                          "No ECR repositories found")
                return
            for repo in repos:
                rname = repo["repositoryName"]
                scan  = repo.get("imageScanningConfiguration", {}).get(
                    "scanOnPush", False
                )
                enc   = repo.get("encryptionConfiguration", {}).get(
                    "encryptionType", "AES256"
                )
                if scan:
                    self._add("PASS", "CNT-01", "ECR", rname,
                              f"Scan-on-push=ON enc={enc} | {rname}")
                else:
                    self._add("FAIL", "CNT-01", "ECR", rname,
                              f"Scan-on-push=OFF enc={enc} | {rname}")
        except Exception as e:
            self._add("WARN", "CNT-01", "ECR", "ecr", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 8: BACKUP & DR
    # ══════════════════════════════════════════════════════════════════════════
    def _check_backup(self):
        self._section_header("BACKUP")
        self._log("BCK-01: AWS Backup vaults and plans")
        try:
            bk     = self._client("backup")
            vaults = bk.list_backup_vaults()["BackupVaultList"]
            if vaults:
                for v in vaults:
                    self._add("PASS", "BCK-01", "BACKUP",
                              v["BackupVaultName"],
                              f"Vault: {v['BackupVaultName']} "
                              f"(RecoveryPoints: {v.get('NumberOfRecoveryPoints', 0)})")
            else:
                self._add("FAIL", "BCK-01", "BACKUP", "vaults",
                          "No AWS Backup vaults configured")
            plans = bk.list_backup_plans()["BackupPlansList"]
            if not plans:
                self._add("FAIL", "BCK-01", "BACKUP", "plans",
                          "No AWS Backup plans configured")
            else:
                for p in plans:
                    self._add("PASS", "BCK-01", "BACKUP", p["BackupPlanName"],
                              f"Backup plan: {p['BackupPlanName']}")
        except Exception as e:
            self._add("WARN", "BCK-01", "BACKUP", "backup", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 9: AMAZON RDS
    # ══════════════════════════════════════════════════════════════════════════
    def _check_rds(self):
        self._section_header("RDS")
        rds = self._client("rds")

        def _rds_instances():
            try:
                paginator = rds.get_paginator("describe_db_instances")
                for page in paginator.paginate():
                    yield from page["DBInstances"]
            except Exception:
                return

        # RDS-01 — Encryption at rest
        self._log("RDS-01: RDS instances — encryption at rest")
        found = False
        for db in _rds_instances():
            found  = True
            iid    = db["DBInstanceIdentifier"]
            engine = db.get("Engine", "unknown")
            if db.get("StorageEncrypted", False):
                self._add("PASS", "RDS-01", "RDS", iid,
                          f"Storage encryption=ON | {iid} ({engine})")
            else:
                self._add("FAIL", "RDS-01", "RDS", iid,
                          f"Storage encryption=OFF | {iid} ({engine})")
        if not found:
            self._add("WARN", "RDS-01", "RDS", "rds",
                      "No RDS instances found in this region")

        # RDS-02 — Publicly accessible
        self._log("RDS-02: RDS instances — publicly accessible")
        all_private = True
        for db in _rds_instances():
            iid    = db["DBInstanceIdentifier"]
            engine = db.get("Engine", "unknown")
            if db.get("PubliclyAccessible", False):
                self._add("FAIL", "RDS-02", "RDS", iid,
                          f"DB PUBLICLY ACCESSIBLE | {iid} ({engine}) — CRITICAL")
                all_private = False
        if all_private:
            self._add("PASS", "RDS-02", "RDS", "all-dbs",
                      "No RDS instances are publicly accessible")

        # RDS-03 — Backup retention + Multi-AZ
        self._log("RDS-03: Backup retention (≥7 days) and Multi-AZ")
        for db in _rds_instances():
            iid       = db["DBInstanceIdentifier"]
            retention = db.get("BackupRetentionPeriod", 0)
            multi_az  = db.get("MultiAZ", False)
            if retention == 0:
                self._add("FAIL", "RDS-03", "RDS", iid,
                          f"Automated backups DISABLED | {iid}")
            elif retention < 7:
                self._add("WARN", "RDS-03", "RDS", iid,
                          f"Backup retention={retention}d (recommend ≥7) | {iid}")
            else:
                self._add("PASS", "RDS-03", "RDS", iid,
                          f"Backup retention={retention}d | {iid}")
            if multi_az:
                self._add("PASS", "RDS-03", "RDS", iid, f"Multi-AZ=ON | {iid}")
            else:
                self._add("WARN", "RDS-03", "RDS", iid, f"Multi-AZ=OFF | {iid}")

        # RDS-04 — Deletion protection + auto minor upgrade
        self._log("RDS-04: Deletion protection and auto minor version upgrade")
        for db in _rds_instances():
            iid        = db["DBInstanceIdentifier"]
            del_prot   = db.get("DeletionProtection", False)
            auto_minor = db.get("AutoMinorVersionUpgrade", False)
            if del_prot:
                self._add("PASS", "RDS-04", "RDS", iid,
                          f"Deletion protection=ON | {iid}")
            else:
                self._add("FAIL", "RDS-04", "RDS", iid,
                          f"Deletion protection=OFF | {iid}")
            if auto_minor:
                self._add("PASS", "RDS-04", "RDS", iid,
                          f"Auto minor upgrade=ON | {iid}")
            else:
                self._add("WARN", "RDS-04", "RDS", iid,
                          f"Auto minor upgrade=OFF | {iid}")

        # RDS-05 — Enhanced monitoring + CloudWatch log exports
        self._log("RDS-05: Enhanced monitoring and CloudWatch log exports")
        for db in _rds_instances():
            iid        = db["DBInstanceIdentifier"]
            monitoring = db.get("MonitoringInterval", 0)
            logs       = db.get("EnabledCloudwatchLogsExports", [])
            if monitoring > 0:
                self._add("PASS", "RDS-05", "RDS", iid,
                          f"Enhanced monitoring interval={monitoring}s | {iid}")
            else:
                self._add("WARN", "RDS-05", "RDS", iid,
                          f"Enhanced monitoring=OFF | {iid}")
            if logs:
                self._add("PASS", "RDS-05", "RDS", iid,
                          f"CloudWatch log exports={logs} | {iid}")
            else:
                self._add("WARN", "RDS-05", "RDS", iid,
                          f"No CloudWatch log exports | {iid}")

        # RDS-06 — Public snapshot visibility
        self._log("RDS-06: RDS snapshot public visibility")
        try:
            snaps        = rds.describe_db_snapshots(
                SnapshotType="manual"
            )["DBSnapshots"]
            public_snaps = []
            for s in snaps:
                try:
                    attrs = rds.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=s["DBSnapshotIdentifier"]
                    )["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]
                    for a in attrs:
                        if (a["AttributeName"] == "restore"
                                and "all" in a.get("AttributeValues", [])):
                            public_snaps.append(s["DBSnapshotIdentifier"])
                except Exception:
                    pass
            if public_snaps:
                for snap in public_snaps:
                    self._add("FAIL", "RDS-06", "RDS", snap,
                              f"RDS snapshot PUBLICLY ACCESSIBLE: {snap}")
            else:
                self._add("PASS", "RDS-06", "RDS", "snapshots",
                          f"No public RDS snapshots "
                          f"({len(snaps)} manual snapshots checked)")
        except Exception as e:
            self._add("FAIL", "RDS-06", "RDS", "rds-snapshots", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 10: AMAZON S3 GLACIER
    # ══════════════════════════════════════════════════════════════════════════
    def _check_glacier(self):
        self._section_header("GLACIER")
        glacier = self._client("glacier")

        try:
            vaults = glacier.list_vaults(accountId="-")["VaultList"]
        except Exception as e:
            self._add("FAIL", "GLC-01", "GLACIER", "glacier", str(e))
            return

        if not vaults:
            self._add("WARN", "GLC-01", "GLACIER", "glacier",
                      "No Glacier vaults found in this region")
            return

        for v in vaults:
            vname = v["VaultName"]
            count = v.get("NumberOfArchives", 0)
            size  = v.get("SizeInBytes", 0)
            self._add("INFO", "GLC-00", "GLACIER", vname,
                      f"Vault: {vname} Archives={count} "
                      f"Size={size / 1024 / 1024:.1f}MB")

            # GLC-01 — Access policy wildcard check
            try:
                policy = glacier.get_vault_access_policy(
                    accountId="-", vaultName=vname
                )
                doc  = json.loads(policy["policy"]["Policy"])
                wild = False
                for stmt in doc.get("Statement", []):
                    principal = stmt.get("Principal", {})
                    effect    = stmt.get("Effect", "")
                    p_val     = (
                        principal
                        if isinstance(principal, str)
                        else principal.get("AWS", "")
                    )
                    if effect == "Allow" and p_val in ("*", ["*"]):
                        self._add("FAIL", "GLC-01", "GLACIER", vname,
                                  f"Vault '{vname}' has wildcard Allow in "
                                  "access policy — CRITICAL")
                        wild = True
                if not wild:
                    self._add("PASS", "GLC-01", "GLACIER", vname,
                              f"Vault '{vname}' access policy scoped "
                              "(no wildcard principal)")
            except glacier.exceptions.ResourceNotFoundException:
                self._add("WARN", "GLC-01", "GLACIER", vname,
                          f"Vault '{vname}' has no access policy — "
                          "verify intentional")
            except Exception as e:
                self._add("WARN", "GLC-01", "GLACIER", vname,
                          f"Could not read policy for '{vname}': {e}")

            # GLC-02 — Vault Lock (WORM) status
            try:
                lock  = glacier.get_vault_lock(accountId="-", vaultName=vname)
                state = lock.get("State", "Unknown")
                cd    = (lock.get("CreationDate", "N/A") or "N/A")[:10]
                if state == "Locked":
                    self._add("PASS", "GLC-02", "GLACIER", vname,
                              f"Vault Lock=Locked | {vname} (created: {cd})")
                else:
                    self._add("WARN", "GLC-02", "GLACIER", vname,
                              f"Vault Lock state={state} | {vname}")
            except glacier.exceptions.ResourceNotFoundException:
                self._add("WARN", "GLC-02", "GLACIER", vname,
                          f"No Vault Lock on '{vname}' — WORM protection absent")
            except Exception as e:
                self._add("WARN", "GLC-02", "GLACIER", vname, str(e))

            # GLC-03 — SNS notifications
            try:
                notif  = glacier.get_vault_notifications(
                    accountId="-", vaultName=vname
                )
                topic  = notif["vaultNotificationConfig"].get("SNSTopic", "None")
                events = notif["vaultNotificationConfig"].get("Events", [])
                self._add("PASS", "GLC-03", "GLACIER", vname,
                          f"Notifications configured | {vname} → {topic} "
                          f"| Events: {events}")
            except glacier.exceptions.ResourceNotFoundException:
                self._add("WARN", "GLC-03", "GLACIER", vname,
                          f"No SNS notifications on '{vname}' — "
                          "job completion alerts absent")
            except Exception as e:
                self._add("WARN", "GLC-03", "GLACIER", vname, str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 11: AMAZON SNS
    # ══════════════════════════════════════════════════════════════════════════
    def _check_sns(self):
        self._section_header("SNS")
        sns = self._client("sns")

        def _topics():
            try:
                paginator = sns.get_paginator("list_topics")
                for page in paginator.paginate():
                    yield from page["Topics"]
            except Exception:
                return

        topics = list(_topics())
        if not topics:
            self._add("WARN", "SNS-01", "SNS", "sns",
                      "No SNS topics found in this region")
            return

        # SNS-01 — SSE-KMS encryption
        self._log("SNS-01: SNS topics — SSE-KMS encryption")
        for t in topics:
            arn  = t["TopicArn"]
            name = arn.split(":")[-1]
            try:
                attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
                kms   = attrs.get("KmsMasterKeyId", "")
                if kms:
                    self._add("PASS", "SNS-01", "SNS", name,
                              f"SSE-KMS={kms} | {name}")
                else:
                    self._add("WARN", "SNS-01", "SNS", name,
                              f"SSE-KMS=OFF | {name}")
            except Exception as e:
                self._add("FAIL", "SNS-01", "SNS", name, str(e))

        # SNS-02 — Access policy wildcard check
        self._log("SNS-02: SNS topics — access policy (no wildcard Principal)")
        for t in topics:
            arn  = t["TopicArn"]
            name = arn.split(":")[-1]
            try:
                attrs  = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
                policy = json.loads(attrs.get("Policy", '{"Statement":[]}'))
                issues = []
                for stmt in policy.get("Statement", []):
                    principal = stmt.get("Principal", {})
                    effect    = stmt.get("Effect", "")
                    condition = stmt.get("Condition", {})
                    p_val = (
                        principal
                        if isinstance(principal, str)
                        else (
                            principal.get("AWS", "")
                            or principal.get("Service", "")
                        )
                    )
                    if (effect == "Allow"
                            and p_val in ("*", ["*"])
                            and not condition):
                        issues.append(
                            f"Action={stmt.get('Action', '*')} allows "
                            "wildcard with no Condition"
                        )
                if issues:
                    for i in issues:
                        self._add("FAIL", "SNS-02", "SNS", name,
                                  f"Overly permissive policy: {i}")
                else:
                    self._add("PASS", "SNS-02", "SNS", name,
                              f"Access policy OK (no unconstrained wildcard) "
                              f"| {name}")
            except Exception as e:
                self._add("FAIL", "SNS-02", "SNS", name, str(e))

        # SNS-03 — No insecure HTTP subscriptions
        self._log("SNS-03: SNS topics — no HTTP subscriptions")
        for t in topics:
            arn  = t["TopicArn"]
            name = arn.split(":")[-1]
            try:
                subs = sns.list_subscriptions_by_topic(
                    TopicArn=arn
                ).get("Subscriptions", [])
                for sub in subs:
                    protocol = sub.get("Protocol", "")
                    endpoint = sub.get("Endpoint", "")
                    if protocol == "http":
                        self._add("FAIL", "SNS-03", "SNS", name,
                                  f"Insecure HTTP subscription on '{name}' "
                                  f"→ {endpoint}")
                    elif protocol == "https":
                        self._add("PASS", "SNS-03", "SNS", name,
                                  f"HTTPS subscription on '{name}' "
                                  f"→ {endpoint[:60]}")
            except Exception as e:
                self._add("FAIL", "SNS-03", "SNS", name, str(e))

        # SNS-04 — Cross-account subscriptions
        self._log("SNS-04: SNS cross-account subscriptions")
        try:
            paginator = sns.get_paginator("list_subscriptions")
            for page in paginator.paginate():
                for sub in page["Subscriptions"]:
                    endpoint = sub.get("Endpoint", "")
                    if endpoint.startswith("arn:aws") and ":" in endpoint:
                        parts = endpoint.split(":")
                        if (len(parts) > 4
                                and parts[4]
                                and parts[4] != self.account):
                            topic_name = sub["TopicArn"].split(":")[-1]
                            self._add("WARN", "SNS-04", "SNS", topic_name,
                                      f"Cross-account subscription | "
                                      f"Topic={topic_name} → Account={parts[4]}")
        except Exception as e:
            self._add("FAIL", "SNS-04", "SNS", "sns", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 12: AMAZON SQS
    # ══════════════════════════════════════════════════════════════════════════
    def _check_sqs(self):
        self._section_header("SQS")
        sqs = self._client("sqs")

        try:
            queues = sqs.list_queues().get("QueueUrls", [])
        except Exception as e:
            self._add("FAIL", "SQS-01", "SQS", "sqs", str(e))
            return

        if not queues:
            self._add("WARN", "SQS-01", "SQS", "sqs",
                      "No SQS queues found in this region")
            return

        # SQS-01 — Encryption at rest
        self._log("SQS-01: SQS queues — encryption at rest")
        for url in queues:
            name = url.split("/")[-1]
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=url, AttributeNames=["All"]
                )["Attributes"]
                kms = attrs.get("KmsMasterKeyId", "")
                sse = attrs.get("SqsManagedSseEnabled", "false")
                if kms:
                    self._add("PASS", "SQS-01", "SQS", name,
                              f"SSE-KMS={kms} | {name}")
                elif sse.lower() == "true":
                    self._add("PASS", "SQS-01", "SQS", name,
                              f"SSE-SQS (managed) enabled | {name}")
                else:
                    self._add("FAIL", "SQS-01", "SQS", name,
                              f"No encryption at rest | {name}")
            except Exception as e:
                self._add("FAIL", "SQS-01", "SQS", name, str(e))

        # SQS-02 — Access policy (no unauthenticated public access)
        self._log("SQS-02: SQS queues — no unauthenticated public access")
        for url in queues:
            name = url.split("/")[-1]
            try:
                attrs      = sqs.get_queue_attributes(
                    QueueUrl=url, AttributeNames=["Policy"]
                )["Attributes"]
                policy_str = attrs.get("Policy", "")
                if not policy_str:
                    self._add("WARN", "SQS-02", "SQS", name,
                              f"No resource policy on '{name}' — "
                              "access governed by IAM only")
                    continue
                policy = json.loads(policy_str)
                issues = []
                for stmt in policy.get("Statement", []):
                    effect    = stmt.get("Effect", "")
                    principal = stmt.get("Principal", {})
                    condition = stmt.get("Condition", {})
                    p_val     = (
                        principal
                        if isinstance(principal, str)
                        else principal.get("AWS", "")
                    )
                    if (effect == "Allow"
                            and p_val in ("*", ["*"])
                            and not condition):
                        issues.append(stmt.get("Action", "*"))
                if issues:
                    self._add("FAIL", "SQS-02", "SQS", name,
                              f"Queue '{name}' allows unauthenticated access "
                              f"to: {issues}")
                else:
                    self._add("PASS", "SQS-02", "SQS", name,
                              f"Queue policy OK | {name}")
            except Exception as e:
                self._add("FAIL", "SQS-02", "SQS", name, str(e))

        # SQS-03 — Dead Letter Queue configured
        self._log("SQS-03: SQS queues — Dead Letter Queue configured")
        for url in queues:
            name = url.split("/")[-1]
            if (name.endswith("-dlq") or name.endswith("_dlq")
                    or "dead" in name.lower()):
                continue  # skip DLQs themselves
            try:
                attrs   = sqs.get_queue_attributes(
                    QueueUrl=url, AttributeNames=["RedrivePolicy"]
                )["Attributes"]
                redrive = attrs.get("RedrivePolicy", "")
                if redrive:
                    dlq_arn = json.loads(redrive).get(
                        "deadLetterTargetArn", "N/A"
                    )
                    self._add("PASS", "SQS-03", "SQS", name,
                              f"DLQ configured | {name} → "
                              f"{dlq_arn.split(':')[-1]}")
                else:
                    self._add("WARN", "SQS-03", "SQS", name,
                              f"No DLQ for queue '{name}' — "
                              "unprocessed messages may be lost")
            except Exception as e:
                self._add("FAIL", "SQS-03", "SQS", name, str(e))

        # SQS-04 — Message retention and visibility timeout
        self._log("SQS-04: SQS queues — retention and visibility timeout")
        for url in queues:
            name = url.split("/")[-1]
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=url,
                    AttributeNames=["MessageRetentionPeriod",
                                    "VisibilityTimeout"],
                )["Attributes"]
                retention  = int(attrs.get("MessageRetentionPeriod", 0))
                visibility = int(attrs.get("VisibilityTimeout", 0))
                ret_days   = retention / 86400
                if ret_days > 14:
                    self._add("WARN", "SQS-04", "SQS", name,
                              f"Retention={ret_days:.1f}d (>14d may indicate "
                              f"stuck messages) VisibilityTimeout={visibility}s"
                              f" | {name}")
                else:
                    self._add("PASS", "SQS-04", "SQS", name,
                              f"Retention={ret_days:.1f}d "
                              f"VisibilityTimeout={visibility}s | {name}")
            except Exception as e:
                self._add("FAIL", "SQS-04", "SQS", name, str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 13: AMAZON CLOUDFRONT
    # ══════════════════════════════════════════════════════════════════════════
    def _check_cloudfront(self):
        self._section_header("CLOUDFRONT")
        # CloudFront is a global service — must use us-east-1
        cf = self._client("cloudfront", region="us-east-1")

        INSECURE_PROTOS = {"SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"}

        try:
            dists = cf.list_distributions().get(
                "DistributionList", {}
            ).get("Items", [])
        except Exception as e:
            self._add("FAIL", "CFN-01", "CLOUDFRONT", "cloudfront", str(e))
            return

        if not dists:
            self._add("WARN", "CFN-01", "CLOUDFRONT", "cloudfront",
                      "No CloudFront distributions found")
            return

        # CFN-01 — HTTPS-only viewer protocol policy
        self._log("CFN-01: CloudFront distributions — HTTPS-only viewer protocol")
        for d in dists:
            did        = d["Id"]
            domain     = d.get("DomainName", did)
            status     = d.get("Status", "Unknown")
            viewer_pol = d.get("DefaultCacheBehavior", {}).get(
                "ViewerProtocolPolicy", "allow-all"
            )
            if viewer_pol == "allow-all":
                self._add("FAIL", "CFN-01", "CLOUDFRONT", domain,
                          f"HTTP allowed (allow-all) | {domain} [{status}]")
            elif viewer_pol == "redirect-to-https":
                self._add("WARN", "CFN-01", "CLOUDFRONT", domain,
                          f"HTTP redirects to HTTPS (consider https-only) "
                          f"| {domain}")
            else:
                self._add("PASS", "CFN-01", "CLOUDFRONT", domain,
                          f"HTTPS-only enforced | {domain} [{status}]")
            for cb in d.get("CacheBehaviors", {}).get("Items", []):
                path = cb.get("PathPattern", "?")
                pol  = cb.get("ViewerProtocolPolicy", "allow-all")
                if pol == "allow-all":
                    self._add("FAIL", "CFN-01", "CLOUDFRONT", domain,
                              f"HTTP allowed on path '{path}' | {domain}")

        # CFN-02 — Minimum TLS version
        self._log("CFN-02: CloudFront — minimum TLS protocol version")
        for d in dists:
            domain      = d.get("DomainName", d["Id"])
            viewer_cert = d.get("ViewerCertificate", {})
            min_proto   = viewer_cert.get("MinimumProtocolVersion", "TLSv1")
            cert_src    = viewer_cert.get("CertificateSource", "cloudfront")
            if min_proto in INSECURE_PROTOS:
                self._add("FAIL", "CFN-02", "CLOUDFRONT", domain,
                          f"Insecure TLS version '{min_proto}' | {domain}")
            else:
                self._add("PASS", "CFN-02", "CLOUDFRONT", domain,
                          f"TLS min={min_proto} cert={cert_src} | {domain}")

        # CFN-03 — WAF Web ACL association
        self._log("CFN-03: CloudFront — WAF Web ACL association")
        for d in dists:
            domain = d.get("DomainName", d["Id"])
            waf    = d.get("WebACLId", "")
            if waf:
                self._add("PASS", "CFN-03", "CLOUDFRONT", domain,
                          f"WAF Web ACL attached | {domain}")
            else:
                self._add("FAIL", "CFN-03", "CLOUDFRONT", domain,
                          f"No WAF Web ACL | {domain} — at risk from OWASP/DDoS")

        # CFN-04 — Access logging
        self._log("CFN-04: CloudFront — access logging enabled")
        for d in dists:
            did    = d["Id"]
            domain = d.get("DomainName", did)
            try:
                config  = cf.get_distribution_config(Id=did)["DistributionConfig"]
                logging = config.get("Logging", {})
                if logging.get("Enabled", False):
                    self._add("PASS", "CFN-04", "CLOUDFRONT", domain,
                              f"Access logging → {logging.get('Bucket', '')} "
                              f"| {domain}")
                else:
                    self._add("FAIL", "CFN-04", "CLOUDFRONT", domain,
                              f"Access logging DISABLED | {domain}")
            except Exception as e:
                self._add("WARN", "CFN-04", "CLOUDFRONT", domain, str(e))

        # CFN-05 — Origin protocol policy (HTTPS to origin)
        self._log("CFN-05: CloudFront — origin protocol (HTTPS to origin)")
        for d in dists:
            domain = d.get("DomainName", d["Id"])
            for origin in d.get("Origins", {}).get("Items", []):
                oid          = origin.get("Id", "N/A")
                custom_cfg   = origin.get("CustomOriginConfig", {})
                origin_proto = custom_cfg.get("OriginProtocolPolicy", "")
                if origin_proto == "http-only":
                    self._add("FAIL", "CFN-05", "CLOUDFRONT", domain,
                              f"Origin '{oid}' uses HTTP-only | {domain}")
                elif origin_proto == "match-viewer":
                    self._add("WARN", "CFN-05", "CLOUDFRONT", domain,
                              f"Origin '{oid}' uses match-viewer "
                              "(may allow HTTP) | {domain}")
                elif origin_proto == "https-only":
                    self._add("PASS", "CFN-05", "CLOUDFRONT", domain,
                              f"Origin '{oid}' enforces HTTPS | {domain}")
                elif not origin_proto:
                    # S3 origins — check OAC/OAI
                    oac_id = origin.get("OriginAccessControlId", "")
                    oai_id = origin.get("S3OriginConfig", {}).get(
                        "OriginAccessIdentity", ""
                    )
                    if oac_id:
                        self._add("PASS", "CFN-05", "CLOUDFRONT", domain,
                                  f"S3 origin '{oid}' uses OAC | {domain}")
                    elif oai_id:
                        self._add("WARN", "CFN-05", "CLOUDFRONT", domain,
                                  f"S3 origin '{oid}' uses legacy OAI "
                                  "(migrate to OAC) | {domain}")
                    else:
                        self._add("FAIL", "CFN-05", "CLOUDFRONT", domain,
                                  f"S3 origin '{oid}' has no OAC/OAI — "
                                  f"bucket may be publicly accessible | {domain}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 14: AMAZON ROUTE 53
    # ══════════════════════════════════════════════════════════════════════════
    def _check_route53(self):
        self._section_header("ROUTE53")
        # Route 53 public APIs are in us-east-1
        r53 = self._client("route53", region="us-east-1")

        # R53-01 — Query logging on hosted zones
        self._log("R53-01: Route 53 hosted zones — query logging")
        try:
            zones = r53.list_hosted_zones()["HostedZones"]
            if not zones:
                self._add("WARN", "R53-01", "ROUTE53", "route53",
                          "No Route 53 hosted zones found")
            try:
                log_configs  = r53.list_query_logging_configs()[
                    "QueryLoggingConfigs"
                ]
                logged_zones = {c["HostedZoneId"] for c in log_configs}
            except Exception:
                logged_zones = set()
            for z in zones:
                zid    = z["Id"].split("/")[-1]
                zname  = z["Name"]
                is_prv = z.get("Config", {}).get("PrivateZone", False)
                tag    = "[private]" if is_prv else "[public]"
                if zid in logged_zones:
                    self._add("PASS", "R53-01", "ROUTE53", zname,
                              f"Query logging enabled | {zname} {tag}")
                elif is_prv:
                    self._add("WARN", "R53-01", "ROUTE53", zname,
                              f"Query logging DISABLED | {zname} {tag}")
                else:
                    self._add("FAIL", "R53-01", "ROUTE53", zname,
                              f"Query logging DISABLED | {zname} {tag}")
        except Exception as e:
            self._add("FAIL", "R53-01", "ROUTE53", "route53", str(e))

        # R53-02 — DNSSEC signing on public zones
        self._log("R53-02: Route 53 — DNSSEC signing on public hosted zones")
        try:
            zones        = r53.list_hosted_zones()["HostedZones"]
            public_zones = [
                z for z in zones
                if not z.get("Config", {}).get("PrivateZone", False)
            ]
            if not public_zones:
                self._add("WARN", "R53-02", "ROUTE53", "route53",
                          "No public hosted zones found")
            for z in public_zones:
                zid   = z["Id"].split("/")[-1]
                zname = z["Name"]
                try:
                    dnssec = r53.get_dnssec(HostedZoneId=zid)
                    status = dnssec.get("Status", {}).get(
                        "ServeSignature", "NOT_SIGNING"
                    )
                    ksks = dnssec.get("KeySigningKeys", [])
                    if status == "SIGNING":
                        self._add("PASS", "R53-02", "ROUTE53", zname,
                                  f"DNSSEC signing ACTIVE | {zname} "
                                  f"KSKs={len(ksks)}")
                    else:
                        self._add("WARN", "R53-02", "ROUTE53", zname,
                                  f"DNSSEC NOT signing (status={status}) "
                                  f"| {zname} — susceptible to cache poisoning")
                except Exception as de:
                    self._add("WARN", "R53-02", "ROUTE53", zname,
                              f"Could not check DNSSEC for '{zname}': {de}")
        except Exception as e:
            self._add("FAIL", "R53-02", "ROUTE53", "route53", str(e))

        # R53-03 — Domain transfer lock + auto-renewal
        self._log("R53-03: Route 53 — domain transfer lock and auto-renewal")
        try:
            r53d    = self._client("route53domains", region="us-east-1")
            domains = r53d.list_domains().get("Domains", [])
            if not domains:
                self._add("WARN", "R53-03", "ROUTE53", "domains",
                          "No Route 53 registered domains "
                          "(may be registered elsewhere)")
            for dom in domains:
                dname  = dom["DomainName"]
                detail = r53d.get_domain_detail(DomainName=dname)
                locked     = detail.get("StatusList", [])
                xfer_lock  = "TRANSFER_LOCK" in locked
                auto_renew = detail.get("AutoRenew", False)
                expiry     = str(detail.get("ExpirationDate", "N/A"))[:10]
                if xfer_lock:
                    self._add("PASS", "R53-03", "ROUTE53", dname,
                              f"Transfer lock=ON | {dname} (expires: {expiry})")
                else:
                    self._add("FAIL", "R53-03", "ROUTE53", dname,
                              f"Transfer lock=OFF | {dname} (expires: {expiry})")
                if auto_renew:
                    self._add("PASS", "R53-03", "ROUTE53", dname,
                              f"Auto-renew=ON | {dname}")
                else:
                    self._add("WARN", "R53-03", "ROUTE53", dname,
                              f"Auto-renew=OFF | {dname}")
        except Exception as e:
            self._add("WARN", "R53-03", "ROUTE53", "domains",
                      f"Route 53 Domains — {e}")

        # R53-04 — Health checks
        self._log("R53-04: Route 53 — health checks configured")
        try:
            checks = r53.list_health_checks()["HealthChecks"]
            if not checks:
                self._add("WARN", "R53-04", "ROUTE53", "health-checks",
                          "No Route 53 health checks — failover routing "
                          "may not function")
            else:
                self._add("INFO", "R53-04", "ROUTE53", "health-checks",
                          f"Total health checks: {len(checks)}")
                for hc in checks:
                    hcid  = hc["Id"]
                    cfg   = hc["HealthCheckConfig"]
                    htype = cfg.get("Type", "")
                    port  = cfg.get("Port", 0)
                    if htype == "HTTP" or port == 80:
                        self._add("WARN", "R53-04", "ROUTE53", hcid,
                                  f"Health check {hcid} uses HTTP "
                                  "(port 80) — consider HTTPS")
                    else:
                        self._add("PASS", "R53-04", "ROUTE53", hcid,
                                  f"Health check {hcid} type={htype} "
                                  f"port={port}")
        except Exception as e:
            self._add("FAIL", "R53-04", "ROUTE53", "health-checks", str(e))

        # R53-05 — Resolver DNS Firewall + query logging
        self._log("R53-05: Route 53 Resolver — DNS Firewall and query logging")
        try:
            r53r   = self._client("route53resolver")
            assocs = r53r.list_firewall_rule_group_associations().get(
                "FirewallRuleGroupAssociations", []
            )
            if assocs:
                for a in assocs:
                    self._add("PASS", "R53-05", "ROUTE53",
                              a.get("Name", "N/A"),
                              f"DNS Firewall rule group associated | "
                              f"{a.get('Name', 'N/A')} "
                              f"Status={a.get('Status', 'N/A')}")
            else:
                self._add("WARN", "R53-05", "ROUTE53", "dns-firewall",
                          "No Route 53 Resolver DNS Firewall associations — "
                          "DNS exfiltration protection absent")
            configs = r53r.list_resolver_query_log_configs().get(
                "ResolverQueryLogConfigs", []
            )
            active = [c for c in configs if c.get("Status") == "CREATED"]
            if active:
                for c in active:
                    self._add("PASS", "R53-05", "ROUTE53", c["Name"],
                              f"Resolver query logging active | {c['Name']} "
                              f"→ {c.get('DestinationArn', 'N/A').split(':')[-1]}")
            else:
                self._add("FAIL", "R53-05", "ROUTE53", "resolver-logging",
                          "Route 53 Resolver query logging NOT configured — "
                          "DNS activity blind spot")
        except Exception as e:
            self._add("WARN", "R53-05", "ROUTE53", "route53resolver",
                      f"Resolver checks — {e}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 15: AWS BEDROCK
    # ══════════════════════════════════════════════════════════════════════════
    def _check_bedrock(self):
        self._section_header("BEDROCK")
        try:
            bedrock = self._client("bedrock")
        except Exception as e:
            self._add("WARN", "BDR-01", "BEDROCK", "bedrock",
                      f"Bedrock client error: {e}")
            return

        # BDR-01 — Model invocation logging
        self._log("BDR-01: Bedrock — model invocation logging")
        try:
            config = bedrock.get_model_invocation_logging_configuration().get(
                "loggingConfig", {}
            )
            if not config:
                self._add("FAIL", "BDR-01", "BEDROCK", "bedrock",
                          "Model invocation logging NOT configured — "
                          "no audit trail for LLM calls")
            else:
                cw = config.get("cloudWatchConfig", {}).get("logGroupName", "")
                s3 = config.get("s3Config", {}).get("bucketName", "")
                if cw or s3:
                    dest = f"CW={cw}" if cw else f"S3={s3}"
                    self._add("PASS", "BDR-01", "BEDROCK", "bedrock",
                              f"Invocation logging enabled → {dest}")
                    if not config.get("textDataDeliveryEnabled", False):
                        self._add("WARN", "BDR-01", "BEDROCK", "bedrock",
                                  "Text data delivery logging is disabled — "
                                  "prompt/response content not captured")
                else:
                    self._add("FAIL", "BDR-01", "BEDROCK", "bedrock",
                              "Invocation logging config present but "
                              "no destination (CW/S3) configured")
        except Exception as e:
            self._add("WARN", "BDR-01", "BEDROCK", "bedrock",
                      f"Bedrock may not be available in this region: {e}")

        # BDR-02 — Guardrails configured
        self._log("BDR-02: Bedrock — Guardrails configured")
        try:
            guardrails = bedrock.list_guardrails().get("guardrails", [])
            if not guardrails:
                self._add("FAIL", "BDR-02", "BEDROCK", "bedrock",
                          "No Bedrock Guardrails — prompt injection, PII, "
                          "and content risks unmitigated")
            else:
                for g in guardrails:
                    self._add("PASS", "BDR-02", "BEDROCK",
                              g.get("name", "N/A"),
                              f"Guardrail '{g.get('name')}' "
                              f"id={g.get('id')} status={g.get('status')}")
        except Exception as e:
            self._add("WARN", "BDR-02", "BEDROCK", "bedrock", str(e))

        # BDR-03 — Custom model KMS encryption
        self._log("BDR-03: Bedrock — custom model encryption (KMS)")
        try:
            models = bedrock.list_custom_models().get("modelSummaries", [])
            if not models:
                self._add("INFO", "BDR-03", "BEDROCK", "bedrock",
                          "No custom Bedrock models found")
            else:
                for m in models:
                    mname = m.get("modelName", "N/A")
                    marn  = m.get("modelArn", "")
                    try:
                        detail = bedrock.get_custom_model(
                            modelIdentifier=marn
                        )
                        kms = detail.get("modelKmsKeyArn", "")
                        if kms:
                            self._add("PASS", "BDR-03", "BEDROCK", mname,
                                      f"KMS=CUSTOMER "
                                      f"({kms.split('/')[-1]}) | {mname}")
                        else:
                            self._add("WARN", "BDR-03", "BEDROCK", mname,
                                      f"KMS=AWS-managed | {mname}")
                    except Exception:
                        self._add("WARN", "BDR-03", "BEDROCK", mname,
                                  f"Could not get KMS details for '{mname}'")
        except Exception as e:
            self._add("WARN", "BDR-03", "BEDROCK", "bedrock", str(e))

        # BDR-04 — VPC endpoint (PrivateLink)
        self._log("BDR-04: Bedrock — VPC endpoint (PrivateLink)")
        try:
            ec2 = self._client("ec2")
            eps = ec2.describe_vpc_endpoints(
                Filters=[
                    {"Name": "service-name",        "Values": ["*bedrock*"]},
                    {"Name": "vpc-endpoint-state",   "Values": ["available",
                                                                 "pending"]},
                ]
            )["VpcEndpoints"]
            if eps:
                for ep in eps:
                    svc = ep["ServiceName"].split(".")[-1]
                    self._add("PASS", "BDR-04", "BEDROCK",
                              ep["VpcEndpointId"],
                              f"Bedrock VPC endpoint | "
                              f"{ep['VpcEndpointId']} svc={svc}")
            else:
                self._add("WARN", "BDR-04", "BEDROCK", "bedrock",
                          "No Bedrock VPC endpoints — traffic uses public "
                          "internet; consider PrivateLink for data isolation")
        except Exception as e:
            self._add("FAIL", "BDR-04", "BEDROCK", "bedrock", str(e))

        # BDR-05 — IAM least privilege for Bedrock
        self._log("BDR-05: Bedrock — IAM permissions wildcard check")
        try:
            iam          = self._client("iam")
            paginator    = iam.get_paginator("list_policies")
            found_issues = False
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    parn = policy["Arn"]
                    vid  = policy["DefaultVersionId"]
                    try:
                        doc = iam.get_policy_version(
                            PolicyArn=parn, VersionId=vid
                        )["PolicyVersion"]["Document"]
                        for stmt in doc.get("Statement", []):
                            if stmt.get("Effect") != "Allow":
                                continue
                            actions  = stmt.get("Action", [])
                            resource = stmt.get("Resource", "")
                            if isinstance(actions, str):
                                actions = [actions]
                            bedrock_wild = any(
                                a in ("bedrock:*", "*") for a in actions
                            )
                            broad_invoke = (
                                any(a == "bedrock:InvokeModel" for a in actions)
                                and resource == "*"
                            )
                            if bedrock_wild or broad_invoke:
                                self._add("WARN", "BDR-05", "BEDROCK",
                                          policy["PolicyName"],
                                          f"Overly broad Bedrock permission in "
                                          f"policy '{policy['PolicyName']}' "
                                          f"Action={actions} "
                                          f"Resource={resource}")
                                found_issues = True
                    except Exception:
                        pass
            if not found_issues:
                self._add("PASS", "BDR-05", "BEDROCK", "iam",
                          "No wildcard Bedrock permissions in "
                          "customer-managed policies")
        except Exception as e:
            self._add("FAIL", "BDR-05", "BEDROCK", "iam", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 16: AWS BEDROCK AGENT CORE
    # ══════════════════════════════════════════════════════════════════════════
    def _check_bedrock_agents(self):
        self._section_header("BEDROCK_AGENTS")
        try:
            ba = self._client("bedrock-agent")
        except Exception as e:
            self._add("WARN", "AGT-01", "BEDROCK_AGENTS", "bedrock-agent",
                      f"Bedrock Agent client error: {e}")
            return

        try:
            agents = ba.list_agents().get("agentSummaries", [])
        except Exception as e:
            self._add("WARN", "AGT-01", "BEDROCK_AGENTS", "bedrock-agent",
                      f"Bedrock Agents may not be available in this region: {e}")
            return

        if not agents:
            self._add("INFO", "AGT-01", "BEDROCK_AGENTS", "bedrock-agent",
                      "No Bedrock Agents found in this region")
            return

        iam = self._client("iam")
        lmb = self._client("lambda")

        for a in agents:
            aid   = a["agentId"]
            aname = a.get("agentName", aid)
            try:
                detail = ba.get_agent(agentId=aid)["agent"]
            except Exception as e:
                self._add("WARN", "AGT-01", "BEDROCK_AGENTS", aname,
                          f"Could not get details for agent '{aname}': {e}")
                continue

            # AGT-01 — KMS encryption
            kms    = detail.get("customerEncryptionKeyArn", "")
            status = detail.get("agentStatus", "N/A")
            if kms:
                self._add("PASS", "AGT-01", "BEDROCK_AGENTS", aname,
                          f"KMS=CUSTOMER ({kms.split('/')[-1]}) "
                          f"Status={status} | {aname}")
            else:
                self._add("WARN", "AGT-01", "BEDROCK_AGENTS", aname,
                          f"KMS=AWS-managed Status={status} | {aname}")

            # AGT-02 — IAM execution role least privilege
            role_arn = detail.get("agentResourceRoleArn", "")
            if not role_arn:
                self._add("FAIL", "AGT-02", "BEDROCK_AGENTS", aname,
                          f"No execution role found for agent '{aname}'")
            else:
                role_name = role_arn.split("/")[-1]
                self._add("PASS", "AGT-02", "BEDROCK_AGENTS", aname,
                          f"Agent '{aname}' uses role '{role_name}'")
                try:
                    inline = iam.list_role_policies(
                        RoleName=role_name
                    ).get("PolicyNames", [])
                    for pname in inline:
                        doc = iam.get_role_policy(
                            RoleName=role_name, PolicyName=pname
                        )["PolicyDocument"]
                        for stmt in doc.get("Statement", []):
                            if stmt.get("Effect") == "Allow":
                                actions  = stmt.get("Action", [])
                                resource = stmt.get("Resource", "")
                                if isinstance(actions, str):
                                    actions = [actions]
                                if "*" in actions or (
                                    resource == "*"
                                    and any(
                                        "bedrock" in str(act)
                                        for act in actions
                                    )
                                ):
                                    self._add("WARN", "AGT-02",
                                              "BEDROCK_AGENTS", aname,
                                              f"Agent '{aname}' role "
                                              f"'{role_name}' policy "
                                              f"'{pname}' has broad "
                                              "permissions")
                except Exception as e:
                    self._add("WARN", "AGT-02", "BEDROCK_AGENTS", aname,
                              f"Could not audit role for '{aname}': {e}")

            # AGT-03 — Knowledge Bases encryption and data sources
            try:
                kbs = ba.list_knowledge_bases().get(
                    "knowledgeBaseSummaries", []
                )
                if not kbs:
                    self._add("INFO", "AGT-03", "BEDROCK_AGENTS", aname,
                              "No Bedrock Knowledge Bases found")
                for kb in kbs:
                    kbid      = kb["knowledgeBaseId"]
                    kbname    = kb.get("name", kbid)
                    kb_detail = ba.get_knowledge_base(
                        knowledgeBaseId=kbid
                    )["knowledgeBase"]
                    kms_kb = kb_detail.get(
                        "serverSideEncryptionConfiguration", {}
                    ).get("kmsKeyArn", "")
                    if kms_kb:
                        self._add("PASS", "AGT-03", "BEDROCK_AGENTS", kbname,
                                  f"KB '{kbname}' KMS=SET "
                                  f"Status={kb.get('status', 'N/A')}")
                    else:
                        self._add("WARN", "AGT-03", "BEDROCK_AGENTS", kbname,
                                  f"KB '{kbname}' KMS=AWS-managed "
                                  f"Status={kb.get('status', 'N/A')}")
                    sources = ba.list_data_sources(
                        knowledgeBaseId=kbid
                    ).get("dataSourceSummaries", [])
                    for ds in sources:
                        dsid      = ds["dataSourceId"]
                        dsname    = ds.get("name", dsid)
                        ds_detail = ba.get_data_source(
                            knowledgeBaseId=kbid, dataSourceId=dsid
                        )["dataSource"]
                        ds_kms = ds_detail.get(
                            "serverSideEncryptionConfiguration", {}
                        ).get("kmsKeyArn", "")
                        if ds_kms:
                            self._add("PASS", "AGT-03", "BEDROCK_AGENTS",
                                      dsname,
                                      f"DataSource '{dsname}' KMS=SET")
                        else:
                            self._add("WARN", "AGT-03", "BEDROCK_AGENTS",
                                      dsname,
                                      f"DataSource '{dsname}' KMS=not set")
            except Exception as e:
                self._add("WARN", "AGT-03", "BEDROCK_AGENTS", aname, str(e))

            # AGT-04 — Action Group Lambda security
            try:
                groups = ba.list_agent_action_groups(
                    agentId=aid, agentVersion="DRAFT"
                ).get("actionGroupSummaries", [])
                for grp in groups:
                    gname = grp.get("actionGroupName", "N/A")
                    gid   = grp.get("actionGroupId", "")
                    grp_detail = ba.get_agent_action_group(
                        agentId=aid, agentVersion="DRAFT", actionGroupId=gid
                    )["agentActionGroup"]
                    lambda_arn = grp_detail.get(
                        "actionGroupExecutor", {}
                    ).get("lambda", "")
                    if lambda_arn:
                        fn_name = lambda_arn.split(":")[-1]
                        try:
                            pol_doc = json.loads(
                                lmb.get_policy(
                                    FunctionName=fn_name
                                )["Policy"]
                            )
                            for stmt in pol_doc.get("Statement", []):
                                p_val = str(stmt.get("Principal", {}))
                                if (stmt.get("Effect") == "Allow"
                                        and "*" in p_val):
                                    self._add("FAIL", "AGT-04",
                                              "BEDROCK_AGENTS", fn_name,
                                              f"Lambda '{fn_name}' for "
                                              f"'{gname}' has wildcard "
                                              "invoke principal")
                                else:
                                    self._add("PASS", "AGT-04",
                                              "BEDROCK_AGENTS", fn_name,
                                              f"Lambda '{fn_name}' policy "
                                              f"scoped | {gname}")
                        except lmb.exceptions.ResourceNotFoundException:
                            self._add("PASS", "AGT-04", "BEDROCK_AGENTS",
                                      fn_name,
                                      f"Lambda '{fn_name}' no resource "
                                      f"policy (IAM-only) | {gname}")
            except Exception as e:
                self._add("WARN", "AGT-04", "BEDROCK_AGENTS", aname,
                          f"Could not audit action groups for "
                          f"'{aname}': {e}")

            # AGT-05 — Guardrail on agent + session TTL
            try:
                bedrock = self._client("bedrock")
                grail   = detail.get(
                    "guardrailConfiguration", {}
                ).get("guardrailIdentifier", "")
                if grail:
                    self._add("PASS", "AGT-05", "BEDROCK_AGENTS", aname,
                              f"Guardrail applied to agent '{aname}' "
                              f"(id={grail})")
                else:
                    self._add("FAIL", "AGT-05", "BEDROCK_AGENTS", aname,
                              f"No Guardrail on agent '{aname}' — "
                              "prompt injection and content policy "
                              "risks unmitigated")
                session_ttl = detail.get("idleSessionTTLInSeconds", 0)
                if session_ttl > 3600:
                    self._add("WARN", "AGT-05", "BEDROCK_AGENTS", aname,
                              f"Session TTL={session_ttl}s (>3600s) on "
                              f"'{aname}' — long session window "
                              "increases hijack risk")
                else:
                    self._add("PASS", "AGT-05", "BEDROCK_AGENTS", aname,
                              f"Session TTL={session_ttl}s | {aname}")
            except Exception as e:
                self._add("WARN", "AGT-05", "BEDROCK_AGENTS", aname, str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 17: AWS LAMBDA
    # ══════════════════════════════════════════════════════════════════════════
    def _check_lambda(self):
        self._section_header("LAMBDA")
        lmb = self._client("lambda")

        try:
            paginator = lmb.get_paginator("list_functions")
            funcs = []
            for page in paginator.paginate():
                funcs.extend(page["Functions"])
        except Exception as e:
            self._add("FAIL", "LMB-01", "LAMBDA", "lambda", str(e))
            return
        if not funcs:
            self._add("INFO", "LMB-01", "LAMBDA", "lambda",
                      "No Lambda functions in this region")
            return

        # LMB-01 — Public access via resource policy
        self._log("LMB-01: Lambda functions — public access check")
        for fn in funcs:
            fname = fn["FunctionName"]
            try:
                pol = json.loads(lmb.get_policy(FunctionName=fname)["Policy"])
                for stmt in pol.get("Statement", []):
                    p = stmt.get("Principal", {})
                    p_val = p if isinstance(p, str) else p.get("AWS", "")
                    if stmt.get("Effect") == "Allow" and p_val == "*" \
                            and not stmt.get("Condition"):
                        self._add("FAIL", "LMB-01", "LAMBDA", fname,
                                  f"Lambda '{fname}' has public invoke access")
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    self._add("WARN", "LMB-01", "LAMBDA", fname, str(e))

        # LMB-02 — VPC connectivity
        self._log("LMB-02: Lambda functions — VPC configuration")
        for fn in funcs:
            fname = fn["FunctionName"]
            vpc = fn.get("VpcConfig", {})
            if not vpc or not vpc.get("SubnetIds"):
                self._add("WARN", "LMB-02", "LAMBDA", fname,
                          f"Lambda '{fname}' not in VPC — has public internet access")

        # LMB-03 — Environment variable secrets
        self._log("LMB-03: Lambda functions — plaintext secrets in env vars")
        secret_patterns = ["PASSWORD", "SECRET", "API_KEY", "TOKEN",
                           "DB_PASS", "PRIVATE_KEY", "CREDENTIALS"]
        for fn in funcs:
            fname = fn["FunctionName"]
            env = fn.get("Environment", {}).get("Variables", {})
            for k in env:
                if any(p in k.upper() for p in secret_patterns):
                    self._add("FAIL", "LMB-03", "LAMBDA", fname,
                              f"Potential secret in env var '{k}' on '{fname}'"
                              " — use Secrets Manager or SSM Parameter Store")
                    break

        # LMB-04 — Deprecated runtime
        self._log("LMB-04: Lambda functions — deprecated runtimes")
        deprecated = {"python2.7", "python3.6", "python3.7", "nodejs10.x",
                      "nodejs12.x", "dotnetcore2.1", "dotnetcore3.1",
                      "ruby2.5", "ruby2.7", "java8", "go1.x"}
        for fn in funcs:
            fname = fn["FunctionName"]
            runtime = fn.get("Runtime", "")
            if runtime in deprecated:
                self._add("FAIL", "LMB-04", "LAMBDA", fname,
                          f"Deprecated runtime '{runtime}' on '{fname}'")

        # LMB-05 — Reserved concurrency / throttle protection
        self._log("LMB-05: Lambda functions — reserved concurrency")
        for fn in funcs:
            fname = fn["FunctionName"]
            try:
                cc = lmb.get_function_concurrency(FunctionName=fname)
                if cc.get("ReservedConcurrentExecutions") is None:
                    self._add("WARN", "LMB-05", "LAMBDA", fname,
                              f"No reserved concurrency on '{fname}'")
            except Exception:
                pass

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 18: AMAZON EKS
    # ══════════════════════════════════════════════════════════════════════════
    def _check_eks(self):
        self._section_header("EKS")
        eks = self._client("eks")

        try:
            clusters = eks.list_clusters().get("clusters", [])
        except Exception as e:
            self._add("WARN", "EKS-01", "EKS", "eks", str(e))
            return
        if not clusters:
            self._add("INFO", "EKS-01", "EKS", "eks",
                      "No EKS clusters in this region")
            return

        for cname in clusters:
            try:
                c = eks.describe_cluster(name=cname)["cluster"]
            except Exception as e:
                self._add("WARN", "EKS-01", "EKS", cname, str(e))
                continue

            # EKS-01 — Public endpoint
            vpc_cfg = c.get("resourcesVpcConfig", {})
            if vpc_cfg.get("endpointPublicAccess", True):
                cidrs = vpc_cfg.get("publicAccessCidrs", ["0.0.0.0/0"])
                if "0.0.0.0/0" in cidrs:
                    self._add("FAIL", "EKS-01", "EKS", cname,
                              f"EKS '{cname}' API endpoint public to 0.0.0.0/0")
                else:
                    self._add("WARN", "EKS-01", "EKS", cname,
                              f"EKS '{cname}' API endpoint public (restricted CIDRs)")

            # EKS-02 — Control plane logging
            logging_cfg = c.get("logging", {}).get("clusterLogging", [])
            enabled_types = []
            for lc in logging_cfg:
                if lc.get("enabled"):
                    enabled_types.extend(lc.get("types", []))
            expected = {"api", "audit", "authenticator", "controllerManager", "scheduler"}
            missing = expected - set(enabled_types)
            if missing:
                self._add("FAIL", "EKS-02", "EKS", cname,
                          f"EKS '{cname}' missing log types: {', '.join(missing)}")
            else:
                self._add("PASS", "EKS-02", "EKS", cname,
                          f"EKS '{cname}' all control plane logging enabled")

            # EKS-03 — Secrets encryption
            enc_cfg = c.get("encryptionConfig", [])
            secrets_enc = any("secrets" in e.get("resources", [])
                              for e in enc_cfg)
            if secrets_enc:
                self._add("PASS", "EKS-03", "EKS", cname,
                          f"EKS '{cname}' Kubernetes secrets encrypted with KMS")
            else:
                self._add("FAIL", "EKS-03", "EKS", cname,
                          f"EKS '{cname}' Kubernetes secrets NOT encrypted with KMS")

            # EKS-04 — Platform version
            version = c.get("version", "")
            platform = c.get("platformVersion", "")
            self._add("INFO", "EKS-04", "EKS", cname,
                      f"EKS '{cname}' version={version} platform={platform}")

            # EKS-05 — Security groups
            sg_ids = vpc_cfg.get("securityGroupIds", [])
            if not sg_ids:
                self._add("WARN", "EKS-05", "EKS", cname,
                          f"EKS '{cname}' no additional security groups configured")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 19: AMAZON ECS
    # ══════════════════════════════════════════════════════════════════════════
    def _check_ecs(self):
        self._section_header("ECS")
        ecs = self._client("ecs")

        try:
            cluster_arns = ecs.list_clusters().get("clusterArns", [])
        except Exception as e:
            self._add("WARN", "ECS-01", "ECS", "ecs", str(e))
            return
        if not cluster_arns:
            self._add("INFO", "ECS-01", "ECS", "ecs",
                      "No ECS clusters in this region")
            return

        # Check task definitions for security issues
        self._log("ECS-01/02/03: ECS task definition security")
        try:
            td_arns = ecs.list_task_definitions(status="ACTIVE"
                          ).get("taskDefinitionArns", [])
        except Exception:
            td_arns = []

        for td_arn in td_arns[:50]:  # cap at 50 to avoid rate limits
            try:
                td = ecs.describe_task_definition(
                    taskDefinition=td_arn
                )["taskDefinition"]
            except Exception:
                continue
            td_name = td.get("family", td_arn.split("/")[-1])
            for cd in td.get("containerDefinitions", []):
                cname = cd.get("name", "unknown")
                # ECS-01 — Privileged mode
                if cd.get("privileged", False):
                    self._add("FAIL", "ECS-01", "ECS", f"{td_name}/{cname}",
                              f"Container '{cname}' runs in privileged mode")
                # ECS-02 — Root user
                user = cd.get("user", "")
                if not user or user == "root" or user == "0":
                    self._add("WARN", "ECS-02", "ECS", f"{td_name}/{cname}",
                              f"Container '{cname}' runs as root (no user set)")
                # ECS-03 — Log configuration
                if not cd.get("logConfiguration"):
                    self._add("FAIL", "ECS-03", "ECS", f"{td_name}/{cname}",
                              f"Container '{cname}' has no log driver configured")
                # ECS-04 — Secrets as env vars
                env = cd.get("environment", [])
                secret_patterns = ["PASSWORD", "SECRET", "API_KEY", "TOKEN"]
                for e in env:
                    if any(p in e.get("name", "").upper() for p in secret_patterns):
                        self._add("FAIL", "ECS-04", "ECS", f"{td_name}/{cname}",
                                  f"Plaintext secret in env var '{e['name']}' "
                                  f"on '{cname}' — use secrets or SSM")
                        break
                # ECS-05 — Read-only root filesystem
                if not cd.get("readonlyRootFilesystem", False):
                    self._add("WARN", "ECS-05", "ECS", f"{td_name}/{cname}",
                              f"Container '{cname}' root filesystem is writable")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 20: AWS SECRETS MANAGER
    # ══════════════════════════════════════════════════════════════════════════
    def _check_secrets(self):
        self._section_header("SECRETS")
        sm = self._client("secretsmanager")

        try:
            paginator = sm.get_paginator("list_secrets")
            secrets = []
            for page in paginator.paginate():
                secrets.extend(page["SecretList"])
        except Exception as e:
            self._add("FAIL", "SEC-01", "SECRETS", "secrets", str(e))
            return
        if not secrets:
            self._add("INFO", "SEC-01", "SECRETS", "secrets",
                      "No secrets found in Secrets Manager")
            return

        now = datetime.now(timezone.utc)
        for s in secrets:
            sname = s.get("Name", "unknown")
            # SEC-01 — Rotation enabled
            if not s.get("RotationEnabled", False):
                self._add("FAIL", "SEC-01", "SECRETS", sname,
                          f"Secret '{sname}' rotation NOT enabled")
            else:
                # SEC-02 — Rotation frequency
                rules = s.get("RotationRules", {})
                days = rules.get("AutomaticallyAfterDays", 0)
                if days > 90:
                    self._add("WARN", "SEC-02", "SECRETS", sname,
                              f"Secret '{sname}' rotation interval={days}d "
                              "(recommend ≤90)")
                else:
                    self._add("PASS", "SEC-02", "SECRETS", sname,
                              f"Secret '{sname}' rotation every {days}d")
            # SEC-03 — KMS encryption
            kms_id = s.get("KmsKeyId", "")
            if not kms_id or kms_id == "aws/secretsmanager":
                self._add("WARN", "SEC-03", "SECRETS", sname,
                          f"Secret '{sname}' uses AWS-managed KMS key "
                          "(consider CMK)")
            else:
                self._add("PASS", "SEC-03", "SECRETS", sname,
                          f"Secret '{sname}' encrypted with CMK")
            # SEC-04 — Last accessed / unused
            last_accessed = s.get("LastAccessedDate")
            if last_accessed:
                age = (now - last_accessed).days
                if age > 90:
                    self._add("WARN", "SEC-04", "SECRETS", sname,
                              f"Secret '{sname}' not accessed in {age} days")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 21: AWS WAF
    # ══════════════════════════════════════════════════════════════════════════
    def _check_waf(self):
        self._section_header("WAF")
        waf = self._client("wafv2")

        for scope in ("REGIONAL", "CLOUDFRONT"):
            region = "us-east-1" if scope == "CLOUDFRONT" else None
            client = self._client("wafv2", region=region) if region else waf
            try:
                acls = client.list_web_acls(Scope=scope).get("WebACLs", [])
            except Exception as e:
                self._add("WARN", "WAF-01", "WAF", scope, str(e))
                continue

            if not acls:
                self._add("WARN", "WAF-01", "WAF", scope,
                          f"No WAFv2 Web ACLs ({scope})")
                continue

            for acl in acls:
                aname = acl.get("Name", "unknown")
                acl_arn = acl.get("ARN", "")
                # WAF-02 — Logging
                try:
                    log_cfg = client.get_logging_configuration(
                        ResourceArn=acl_arn
                    ).get("LoggingConfiguration", {})
                    if log_cfg:
                        self._add("PASS", "WAF-02", "WAF", aname,
                                  f"WAF logging enabled | {aname}")
                    else:
                        self._add("FAIL", "WAF-02", "WAF", aname,
                                  f"WAF logging NOT enabled | {aname}")
                except ClientError:
                    self._add("FAIL", "WAF-02", "WAF", aname,
                              f"WAF logging NOT configured | {aname}")

                # WAF-03 — Rules count
                try:
                    detail = client.get_web_acl(
                        Name=aname, Scope=scope, Id=acl.get("Id", "")
                    ).get("WebACL", {})
                    rules = detail.get("Rules", [])
                    if not rules:
                        self._add("FAIL", "WAF-03", "WAF", aname,
                                  f"WAF '{aname}' has no rules defined")
                    else:
                        self._add("PASS", "WAF-03", "WAF", aname,
                                  f"WAF '{aname}' has {len(rules)} rule(s)")
                    # WAF-04 — Default action
                    default_action = detail.get("DefaultAction", {})
                    if "Allow" in default_action:
                        self._add("WARN", "WAF-04", "WAF", aname,
                                  f"WAF '{aname}' default action is ALLOW "
                                  "(consider BLOCK)")
                except Exception:
                    pass

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 22: AMAZON ELASTICACHE
    # ══════════════════════════════════════════════════════════════════════════
    def _check_elasticache(self):
        self._section_header("ELASTICACHE")
        ec = self._client("elasticache")

        try:
            clusters = ec.describe_replication_groups().get(
                "ReplicationGroups", [])
        except Exception as e:
            self._add("WARN", "ELC-01", "ELASTICACHE", "elasticache", str(e))
            return
        if not clusters:
            self._add("INFO", "ELC-01", "ELASTICACHE", "elasticache",
                      "No ElastiCache replication groups found")
            return

        for rg in clusters:
            rgid = rg.get("ReplicationGroupId", "unknown")
            # ELC-01 — Encryption at rest
            if rg.get("AtRestEncryptionEnabled", False):
                self._add("PASS", "ELC-01", "ELASTICACHE", rgid,
                          f"Encryption at rest=ON | {rgid}")
            else:
                self._add("FAIL", "ELC-01", "ELASTICACHE", rgid,
                          f"Encryption at rest=OFF | {rgid}")
            # ELC-02 — Encryption in transit
            if rg.get("TransitEncryptionEnabled", False):
                self._add("PASS", "ELC-02", "ELASTICACHE", rgid,
                          f"Encryption in transit=ON | {rgid}")
            else:
                self._add("FAIL", "ELC-02", "ELASTICACHE", rgid,
                          f"Encryption in transit=OFF | {rgid}")
            # ELC-03 — Auth token (password)
            if rg.get("AuthTokenEnabled", False):
                self._add("PASS", "ELC-03", "ELASTICACHE", rgid,
                          f"AUTH token=ON | {rgid}")
            else:
                self._add("FAIL", "ELC-03", "ELASTICACHE", rgid,
                          f"AUTH token=OFF (unauthenticated access) | {rgid}")
            # ELC-04 — Auto failover
            if rg.get("AutomaticFailover", "") == "enabled":
                self._add("PASS", "ELC-04", "ELASTICACHE", rgid,
                          f"Auto failover=ON | {rgid}")
            else:
                self._add("WARN", "ELC-04", "ELASTICACHE", rgid,
                          f"Auto failover=OFF | {rgid}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 23: AMAZON OPENSEARCH
    # ══════════════════════════════════════════════════════════════════════════
    def _check_opensearch(self):
        self._section_header("OPENSEARCH")
        osr = self._client("opensearch")

        try:
            domains = osr.list_domain_names().get("DomainNames", [])
        except Exception as e:
            self._add("WARN", "OSR-01", "OPENSEARCH", "opensearch", str(e))
            return
        if not domains:
            self._add("INFO", "OSR-01", "OPENSEARCH", "opensearch",
                      "No OpenSearch domains found")
            return

        for d in domains:
            dname = d["DomainName"]
            try:
                cfg = osr.describe_domain(DomainName=dname)["DomainStatus"]
            except Exception as e:
                self._add("WARN", "OSR-01", "OPENSEARCH", dname, str(e))
                continue

            # OSR-01 — HTTPS enforcement
            ep_opts = cfg.get("DomainEndpointOptions", {})
            if ep_opts.get("EnforceHTTPS", False):
                tls = ep_opts.get("TLSSecurityPolicy", "")
                self._add("PASS", "OSR-01", "OPENSEARCH", dname,
                          f"HTTPS enforced (TLS={tls}) | {dname}")
            else:
                self._add("FAIL", "OSR-01", "OPENSEARCH", dname,
                          f"HTTPS NOT enforced | {dname}")
            # OSR-02 — Encryption at rest
            enc = cfg.get("EncryptionAtRestOptions", {})
            if enc.get("Enabled", False):
                self._add("PASS", "OSR-02", "OPENSEARCH", dname,
                          f"Encryption at rest=ON | {dname}")
            else:
                self._add("FAIL", "OSR-02", "OPENSEARCH", dname,
                          f"Encryption at rest=OFF | {dname}")
            # OSR-03 — Node-to-node encryption
            n2n = cfg.get("NodeToNodeEncryptionOptions", {})
            if n2n.get("Enabled", False):
                self._add("PASS", "OSR-03", "OPENSEARCH", dname,
                          f"Node-to-node encryption=ON | {dname}")
            else:
                self._add("FAIL", "OSR-03", "OPENSEARCH", dname,
                          f"Node-to-node encryption=OFF | {dname}")
            # OSR-04 — VPC deployment
            vpc_opts = cfg.get("VPCOptions", {})
            if vpc_opts.get("SubnetIds"):
                self._add("PASS", "OSR-04", "OPENSEARCH", dname,
                          f"Deployed in VPC | {dname}")
            else:
                self._add("FAIL", "OSR-04", "OPENSEARCH", dname,
                          f"Public endpoint (not in VPC) | {dname}")
            # OSR-05 — Fine-grained access control
            adv = cfg.get("AdvancedSecurityOptions", {})
            if adv.get("Enabled", False):
                self._add("PASS", "OSR-05", "OPENSEARCH", dname,
                          f"Fine-grained access control=ON | {dname}")
            else:
                self._add("FAIL", "OSR-05", "OPENSEARCH", dname,
                          f"Fine-grained access control=OFF | {dname}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 24: AMAZON DYNAMODB
    # ══════════════════════════════════════════════════════════════════════════
    def _check_dynamodb(self):
        self._section_header("DYNAMODB")
        ddb = self._client("dynamodb")

        try:
            tables = []
            paginator = ddb.get_paginator("list_tables")
            for page in paginator.paginate():
                tables.extend(page.get("TableNames", []))
        except Exception as e:
            self._add("FAIL", "DDB-01", "DYNAMODB", "dynamodb", str(e))
            return
        if not tables:
            self._add("INFO", "DDB-01", "DYNAMODB", "dynamodb",
                      "No DynamoDB tables found")
            return

        for tname in tables:
            try:
                t = ddb.describe_table(TableName=tname)["Table"]
            except Exception as e:
                self._add("WARN", "DDB-01", "DYNAMODB", tname, str(e))
                continue

            # DDB-01 — Encryption (CMK vs AWS-owned)
            sse = t.get("SSEDescription", {})
            sse_type = sse.get("SSEType", "")
            if sse_type == "KMS":
                self._add("PASS", "DDB-01", "DYNAMODB", tname,
                          f"CMK encryption | {tname}")
            else:
                self._add("WARN", "DDB-01", "DYNAMODB", tname,
                          f"AWS-owned encryption (consider CMK) | {tname}")
            # DDB-02 — Point-in-time recovery
            try:
                pitr = ddb.describe_continuous_backups(TableName=tname
                    )["ContinuousBackupsDescription"]
                status = pitr.get("PointInTimeRecoveryDescription", {}).get(
                    "PointInTimeRecoveryStatus", "DISABLED")
                if status == "ENABLED":
                    self._add("PASS", "DDB-02", "DYNAMODB", tname,
                              f"PITR enabled | {tname}")
                else:
                    self._add("FAIL", "DDB-02", "DYNAMODB", tname,
                              f"PITR disabled | {tname}")
            except Exception:
                self._add("WARN", "DDB-02", "DYNAMODB", tname,
                          f"Could not check PITR for {tname}")
            # DDB-03 — Auto scaling / on-demand
            billing = t.get("BillingModeSummary", {}).get(
                "BillingMode", "PROVISIONED")
            if billing == "PAY_PER_REQUEST":
                self._add("PASS", "DDB-03", "DYNAMODB", tname,
                          f"On-demand billing (auto scales) | {tname}")
            else:
                self._add("INFO", "DDB-03", "DYNAMODB", tname,
                          f"Provisioned billing — ensure auto scaling | {tname}")
            # DDB-04 — Deletion protection
            if t.get("DeletionProtectionEnabled", False):
                self._add("PASS", "DDB-04", "DYNAMODB", tname,
                          f"Deletion protection=ON | {tname}")
            else:
                self._add("FAIL", "DDB-04", "DYNAMODB", tname,
                          f"Deletion protection=OFF | {tname}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 25: AWS STEP FUNCTIONS
    # ══════════════════════════════════════════════════════════════════════════
    def _check_stepfunctions(self):
        self._section_header("STEPFUNCTIONS")
        sfn = self._client("stepfunctions")

        try:
            machines = sfn.list_state_machines().get("stateMachines", [])
        except Exception as e:
            self._add("WARN", "SFN-01", "STEPFUNCTIONS", "stepfunctions", str(e))
            return
        if not machines:
            self._add("INFO", "SFN-01", "STEPFUNCTIONS", "stepfunctions",
                      "No Step Functions state machines found")
            return

        for sm in machines:
            sname = sm.get("name", "unknown")
            arn = sm.get("stateMachineArn", "")
            try:
                detail = sfn.describe_state_machine(stateMachineArn=arn)
            except Exception as e:
                self._add("WARN", "SFN-01", "STEPFUNCTIONS", sname, str(e))
                continue

            # SFN-01 — Logging
            log_cfg = detail.get("loggingConfiguration", {})
            level = log_cfg.get("level", "OFF")
            if level == "OFF":
                self._add("FAIL", "SFN-01", "STEPFUNCTIONS", sname,
                          f"Logging disabled on '{sname}'")
            else:
                self._add("PASS", "SFN-01", "STEPFUNCTIONS", sname,
                          f"Logging level={level} | {sname}")
            # SFN-02 — X-Ray tracing
            tracing = detail.get("tracingConfiguration", {})
            if tracing.get("enabled", False):
                self._add("PASS", "SFN-02", "STEPFUNCTIONS", sname,
                          f"X-Ray tracing=ON | {sname}")
            else:
                self._add("WARN", "SFN-02", "STEPFUNCTIONS", sname,
                          f"X-Ray tracing=OFF | {sname}")
            # SFN-03 — Encryption
            enc_cfg = detail.get("encryptionConfiguration", {})
            kms = enc_cfg.get("kmsKeyId", "")
            if kms:
                self._add("PASS", "SFN-03", "STEPFUNCTIONS", sname,
                          f"KMS encryption | {sname}")
            else:
                self._add("WARN", "SFN-03", "STEPFUNCTIONS", sname,
                          f"AWS-managed encryption | {sname}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 26: AMAZON API GATEWAY
    # ══════════════════════════════════════════════════════════════════════════
    def _check_apigateway(self):
        self._section_header("APIGATEWAY")
        apigw = self._client("apigateway")

        try:
            apis = apigw.get_rest_apis().get("items", [])
        except Exception as e:
            self._add("WARN", "APIGW-01", "APIGATEWAY", "apigateway", str(e))
            return
        if not apis:
            self._add("INFO", "APIGW-01", "APIGATEWAY", "apigateway",
                      "No API Gateway REST APIs found")
            return

        for api in apis:
            api_id = api.get("id", "unknown")
            api_nm = api.get("name", api_id)
            try:
                stages = apigw.get_stages(restApiId=api_id).get("item", [])
            except Exception as e:
                self._add("WARN", "APIGW-01", "APIGATEWAY", api_nm, str(e))
                continue
            if not stages:
                self._add("INFO", "APIGW-01", "APIGATEWAY", api_nm,
                          f"No deployed stages | {api_nm}")
                continue

            for st in stages:
                stage = st.get("stageName", "unknown")
                label = f"{api_nm}/{stage}"
                method_settings = st.get("methodSettings", {}).get("*/*", {})

                # APIGW-01 — Stage logging (access logs or execution logging)
                access_log = st.get("accessLogSettings", {}).get("destinationArn")
                log_level  = method_settings.get("loggingLevel", "OFF")
                if access_log or log_level not in ("OFF", ""):
                    self._add("PASS", "APIGW-01", "APIGATEWAY", label,
                              f"Logging enabled (level={log_level or 'access'}) | {label}")
                else:
                    self._add("FAIL", "APIGW-01", "APIGATEWAY", label,
                              f"No access/execution logging | {label}")

                # APIGW-02 — WAF Web ACL associated with stage
                if st.get("webAclArn"):
                    self._add("PASS", "APIGW-02", "APIGATEWAY", label,
                              f"WAF Web ACL associated | {label}")
                else:
                    self._add("FAIL", "APIGW-02", "APIGATEWAY", label,
                              f"No WAF Web ACL associated | {label}")

                # APIGW-03 — Cache data encryption (when caching enabled)
                if st.get("cacheClusterEnabled", False):
                    if method_settings.get("cacheDataEncrypted", False):
                        self._add("PASS", "APIGW-03", "APIGATEWAY", label,
                                  f"Cache encryption=ON | {label}")
                    else:
                        self._add("FAIL", "APIGW-03", "APIGATEWAY", label,
                                  f"Cache enabled but data NOT encrypted | {label}")
                else:
                    self._add("INFO", "APIGW-03", "APIGATEWAY", label,
                              f"Stage caching disabled | {label}")

                # APIGW-04 — X-Ray tracing
                if st.get("tracingEnabled", False):
                    self._add("PASS", "APIGW-04", "APIGATEWAY", label,
                              f"X-Ray tracing=ON | {label}")
                else:
                    self._add("WARN", "APIGW-04", "APIGATEWAY", label,
                              f"X-Ray tracing=OFF | {label}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 27: ELASTIC LOAD BALANCING
    # ══════════════════════════════════════════════════════════════════════════
    # TLS policies considered weak (allow TLS 1.0/1.1 or legacy ciphers)
    _WEAK_TLS_POLICIES = {
        "ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-2016-08",
        "ELBSecurityPolicy-TLS-1-0-2015-04", "ELBSecurityPolicy-TLS-1-1-2017-01",
        "ELBSecurityPolicy-FS-2018-06", "ELBSecurityPolicy-FS-1-1-2019-08",
    }

    def _check_elb(self):
        self._section_header("ELB")
        elb = self._client("elbv2")

        try:
            lbs = elb.describe_load_balancers().get("LoadBalancers", [])
        except Exception as e:
            self._add("WARN", "ELB-01", "ELB", "elb", str(e))
            return
        if not lbs:
            self._add("INFO", "ELB-01", "ELB", "elb",
                      "No Application/Network Load Balancers found")
            return

        for lb in lbs:
            arn   = lb.get("LoadBalancerArn", "")
            name  = lb.get("LoadBalancerName", "unknown")
            lbtype = lb.get("Type", "application")

            # Attributes (access logs, deletion protection, drop invalid headers)
            attrs = {}
            try:
                for a in elb.describe_load_balancer_attributes(
                        LoadBalancerArn=arn).get("Attributes", []):
                    attrs[a.get("Key")] = a.get("Value")
            except Exception as e:
                self._add("WARN", "ELB-01", "ELB", name, str(e))

            # ELB-01 — Access logging
            if attrs.get("access_logs.s3.enabled") == "true":
                self._add("PASS", "ELB-01", "ELB", name,
                          f"Access logging=ON | {name}")
            else:
                self._add("FAIL", "ELB-01", "ELB", name,
                          f"Access logging=OFF | {name}")

            # ELB-04 — Deletion protection
            if attrs.get("deletion_protection.enabled") == "true":
                self._add("PASS", "ELB-04", "ELB", name,
                          f"Deletion protection=ON | {name}")
            else:
                self._add("WARN", "ELB-04", "ELB", name,
                          f"Deletion protection=OFF | {name}")

            # ELB-05 — Drop invalid HTTP headers (ALB only)
            if lbtype == "application":
                if attrs.get("routing.http.drop_invalid_header_fields.enabled") == "true":
                    self._add("PASS", "ELB-05", "ELB", name,
                              f"Drop invalid headers=ON | {name}")
                else:
                    self._add("FAIL", "ELB-05", "ELB", name,
                              f"Drop invalid headers=OFF | {name}")

            # Listener-level checks (TLS)
            try:
                listeners = elb.describe_listeners(
                    LoadBalancerArn=arn).get("Listeners", [])
            except Exception as e:
                self._add("WARN", "ELB-02", "ELB", name, str(e))
                continue

            for ls in listeners:
                proto = ls.get("Protocol", "")
                port  = ls.get("Port", "")
                llabel = f"{name}:{port}/{proto}"

                # ELB-02 — Plaintext listener without HTTPS redirect
                if proto == "HTTP":
                    actions = ls.get("DefaultActions", [])
                    redirects = any(a.get("Type") == "redirect" and
                                    a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
                                    for a in actions)
                    if redirects:
                        self._add("PASS", "ELB-02", "ELB", llabel,
                                  f"HTTP listener redirects to HTTPS | {llabel}")
                    else:
                        self._add("FAIL", "ELB-02", "ELB", llabel,
                                  f"HTTP listener does NOT redirect to HTTPS | {llabel}")

                # ELB-03 — Weak TLS policy on HTTPS/TLS listeners
                if proto in ("HTTPS", "TLS"):
                    policy = ls.get("SslPolicy", "")
                    if policy in self._WEAK_TLS_POLICIES:
                        self._add("FAIL", "ELB-03", "ELB", llabel,
                                  f"Weak TLS policy '{policy}' | {llabel}")
                    else:
                        self._add("PASS", "ELB-03", "ELB", llabel,
                                  f"TLS policy '{policy}' | {llabel}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 28: EBS VOLUMES & SNAPSHOTS
    # ══════════════════════════════════════════════════════════════════════════
    def _check_ebs(self):
        self._section_header("EBS")
        ec2 = self._client("ec2")

        # EBS-01 — Account-level encryption by default
        try:
            ebd = ec2.get_ebs_encryption_by_default().get(
                "EbsEncryptionByDefault", False)
            if ebd:
                self._add("PASS", "EBS-01", "EBS", "account",
                          "EBS encryption by default=ON")
            else:
                self._add("FAIL", "EBS-01", "EBS", "account",
                          "EBS encryption by default=OFF")
        except Exception as e:
            self._add("WARN", "EBS-01", "EBS", "account", str(e))

        # EBS-02 — Unencrypted volumes
        try:
            unenc = []
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page.get("Volumes", []):
                    if not vol.get("Encrypted", False):
                        unenc.append(vol.get("VolumeId", "unknown"))
            if unenc:
                for vid in unenc:
                    self._add("FAIL", "EBS-02", "EBS", vid,
                              f"Unencrypted EBS volume | {vid}")
            else:
                self._add("PASS", "EBS-02", "EBS", "all-volumes",
                          "All EBS volumes are encrypted")
        except Exception as e:
            self._add("WARN", "EBS-02", "EBS", "volumes", str(e))

        # EBS-03 — Unencrypted owned snapshots
        try:
            unenc_snaps = []
            paginator = ec2.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                for snap in page.get("Snapshots", []):
                    if not snap.get("Encrypted", False):
                        unenc_snaps.append(snap.get("SnapshotId", "unknown"))
            if unenc_snaps:
                for sid in unenc_snaps:
                    self._add("FAIL", "EBS-03", "EBS", sid,
                              f"Unencrypted EBS snapshot | {sid}")
            else:
                self._add("PASS", "EBS-03", "EBS", "all-snapshots",
                          "All owned EBS snapshots are encrypted")
        except Exception as e:
            self._add("WARN", "EBS-03", "EBS", "snapshots", str(e))

        # EBS-04 — Publicly restorable snapshots
        try:
            public = []
            paginator = ec2.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"],
                                           RestorableByUserIds=["all"]):
                for snap in page.get("Snapshots", []):
                    public.append(snap.get("SnapshotId", "unknown"))
            if public:
                for sid in public:
                    self._add("FAIL", "EBS-04", "EBS", sid,
                              f"PUBLIC EBS snapshot (restorable by anyone) | {sid}")
            else:
                self._add("PASS", "EBS-04", "EBS", "all-snapshots",
                          "No public EBS snapshots")
        except Exception as e:
            self._add("WARN", "EBS-04", "EBS", "snapshots", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 29: AMAZON REDSHIFT
    # ══════════════════════════════════════════════════════════════════════════
    def _check_redshift(self):
        self._section_header("REDSHIFT")
        rs = self._client("redshift")

        try:
            clusters = rs.describe_clusters().get("Clusters", [])
        except Exception as e:
            self._add("WARN", "RS-01", "REDSHIFT", "redshift", str(e))
            return
        if not clusters:
            self._add("INFO", "RS-01", "REDSHIFT", "redshift",
                      "No Redshift clusters found")
            return

        for c in clusters:
            cid = c.get("ClusterIdentifier", "unknown")

            # RS-01 — Encryption at rest
            if c.get("Encrypted", False):
                self._add("PASS", "RS-01", "REDSHIFT", cid,
                          f"Encryption at rest=ON | {cid}")
            else:
                self._add("FAIL", "RS-01", "REDSHIFT", cid,
                          f"Encryption at rest=OFF | {cid}")

            # RS-02 — Public accessibility
            if c.get("PubliclyAccessible", False):
                self._add("FAIL", "RS-02", "REDSHIFT", cid,
                          f"Cluster is publicly accessible | {cid}")
            else:
                self._add("PASS", "RS-02", "REDSHIFT", cid,
                          f"Not publicly accessible | {cid}")

            # RS-03 — Audit logging
            try:
                logging = rs.describe_logging_status(ClusterIdentifier=cid)
                if logging.get("LoggingEnabled", False):
                    self._add("PASS", "RS-03", "REDSHIFT", cid,
                              f"Audit logging=ON | {cid}")
                else:
                    self._add("FAIL", "RS-03", "REDSHIFT", cid,
                              f"Audit logging=OFF | {cid}")
            except Exception as e:
                self._add("WARN", "RS-03", "REDSHIFT", cid, str(e))

            # RS-04 — Enhanced VPC routing
            if c.get("EnhancedVpcRouting", False):
                self._add("PASS", "RS-04", "REDSHIFT", cid,
                          f"Enhanced VPC routing=ON | {cid}")
            else:
                self._add("FAIL", "RS-04", "REDSHIFT", cid,
                          f"Enhanced VPC routing=OFF | {cid}")

            # RS-05 — Default admin username
            if c.get("MasterUsername", "").lower() == "awsuser":
                self._add("WARN", "RS-05", "REDSHIFT", cid,
                          f"Default master username 'awsuser' in use | {cid}")
            else:
                self._add("PASS", "RS-05", "REDSHIFT", cid,
                          f"Non-default master username | {cid}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 30: AMAZON EFS
    # ══════════════════════════════════════════════════════════════════════════
    def _check_efs(self):
        self._section_header("EFS")
        efs = self._client("efs")

        try:
            filesystems = efs.describe_file_systems().get("FileSystems", [])
        except Exception as e:
            self._add("WARN", "EFS-01", "EFS", "efs", str(e))
            return
        if not filesystems:
            self._add("INFO", "EFS-01", "EFS", "efs",
                      "No EFS file systems found")
            return

        for fs in filesystems:
            fsid = fs.get("FileSystemId", "unknown")
            name = fs.get("Name") or fsid

            # EFS-01 — Encryption at rest
            if fs.get("Encrypted", False):
                self._add("PASS", "EFS-01", "EFS", name,
                          f"Encryption at rest=ON | {name}")
            else:
                self._add("FAIL", "EFS-01", "EFS", name,
                          f"Encryption at rest=OFF | {name}")

            # EFS-02 — File system policy enforces in-transit encryption
            try:
                policy = efs.describe_file_system_policy(
                    FileSystemId=fsid).get("Policy", "")
                if "aws:SecureTransport" in policy:
                    self._add("PASS", "EFS-02", "EFS", name,
                              f"Policy enforces TLS in transit | {name}")
                else:
                    self._add("FAIL", "EFS-02", "EFS", name,
                              f"Policy does NOT enforce TLS (aws:SecureTransport) | {name}")
            except Exception:
                self._add("FAIL", "EFS-02", "EFS", name,
                          f"No file system policy enforcing TLS | {name}")

            # EFS-03 — Automatic backups
            try:
                bp = efs.describe_backup_policy(
                    FileSystemId=fsid).get("BackupPolicy", {})
                if bp.get("Status") in ("ENABLED", "ENABLING"):
                    self._add("PASS", "EFS-03", "EFS", name,
                              f"Automatic backups=ON | {name}")
                else:
                    self._add("WARN", "EFS-03", "EFS", name,
                              f"Automatic backups=OFF | {name}")
            except Exception:
                self._add("WARN", "EFS-03", "EFS", name,
                          f"Automatic backups=OFF | {name}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 31: AWS CERTIFICATE MANAGER
    # ══════════════════════════════════════════════════════════════════════════
    # Key algorithms considered weak (below 2048-bit RSA strength)
    _WEAK_KEY_ALGORITHMS = {"RSA_1024"}

    def _check_acm(self):
        self._section_header("ACM")
        acm = self._client("acm")

        try:
            certs = acm.list_certificates().get("CertificateSummaryList", [])
        except Exception as e:
            self._add("WARN", "ACM-01", "ACM", "acm", str(e))
            return
        if not certs:
            self._add("INFO", "ACM-01", "ACM", "acm",
                      "No ACM certificates found")
            return

        now = datetime.now(timezone.utc)
        for summary in certs:
            arn = summary.get("CertificateArn", "")
            try:
                cert = acm.describe_certificate(
                    CertificateArn=arn).get("Certificate", {})
            except Exception as e:
                self._add("WARN", "ACM-01", "ACM", arn, str(e))
                continue

            domain = cert.get("DomainName", arn)

            # ACM-01 — Expiry
            not_after = cert.get("NotAfter")
            if not_after:
                if getattr(not_after, "tzinfo", None) is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
                days_left = (not_after - now).days
                if days_left < 0:
                    self._add("FAIL", "ACM-01", "ACM", domain,
                              f"Certificate EXPIRED {abs(days_left)}d ago | {domain}")
                elif days_left <= 30:
                    self._add("WARN", "ACM-01", "ACM", domain,
                              f"Certificate expires in {days_left}d | {domain}")
                else:
                    self._add("PASS", "ACM-01", "ACM", domain,
                              f"Certificate valid for {days_left}d | {domain}")
            else:
                self._add("INFO", "ACM-01", "ACM", domain,
                          f"Certificate not yet issued | {domain}")

            # ACM-02 — Key algorithm strength
            key_algo = cert.get("KeyAlgorithm", "")
            if key_algo in self._WEAK_KEY_ALGORITHMS:
                self._add("FAIL", "ACM-02", "ACM", domain,
                          f"Weak key algorithm '{key_algo}' | {domain}")
            elif key_algo:
                self._add("PASS", "ACM-02", "ACM", domain,
                          f"Key algorithm '{key_algo}' | {domain}")

            # ACM-03 — Unused certificate
            if cert.get("InUseBy"):
                self._add("PASS", "ACM-03", "ACM", domain,
                          f"Certificate in use | {domain}")
            else:
                self._add("WARN", "ACM-03", "ACM", domain,
                          f"Certificate not associated with any resource | {domain}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 32: AMAZON SAGEMAKER
    # ══════════════════════════════════════════════════════════════════════════
    def _check_sagemaker(self):
        self._section_header("SAGEMAKER")
        sm = self._client("sagemaker")

        try:
            notebooks = sm.list_notebook_instances().get(
                "NotebookInstances", [])
        except Exception as e:
            self._add("WARN", "SM-01", "SAGEMAKER", "sagemaker", str(e))
            return
        if not notebooks:
            self._add("INFO", "SM-01", "SAGEMAKER", "sagemaker",
                      "No SageMaker notebook instances found")
            return

        for nb in notebooks:
            name = nb.get("NotebookInstanceName", "unknown")
            try:
                detail = sm.describe_notebook_instance(
                    NotebookInstanceName=name)
            except Exception as e:
                self._add("WARN", "SM-01", "SAGEMAKER", name, str(e))
                continue

            # SM-01 — Direct internet access
            if detail.get("DirectInternetAccess", "Enabled") == "Disabled":
                self._add("PASS", "SM-01", "SAGEMAKER", name,
                          f"Direct internet access=Disabled | {name}")
            else:
                self._add("FAIL", "SM-01", "SAGEMAKER", name,
                          f"Direct internet access=Enabled | {name}")

            # SM-02 — Root access
            if detail.get("RootAccess", "Enabled") == "Disabled":
                self._add("PASS", "SM-02", "SAGEMAKER", name,
                          f"Root access=Disabled | {name}")
            else:
                self._add("FAIL", "SM-02", "SAGEMAKER", name,
                          f"Root access=Enabled | {name}")

            # SM-03 — KMS encryption of the storage volume
            if detail.get("KmsKeyId"):
                self._add("PASS", "SM-03", "SAGEMAKER", name,
                          f"KMS-encrypted volume | {name}")
            else:
                self._add("FAIL", "SM-03", "SAGEMAKER", name,
                          f"No KMS key (AWS-managed encryption only) | {name}")

            # SM-04 — VPC deployment
            if detail.get("SubnetId"):
                self._add("PASS", "SM-04", "SAGEMAKER", name,
                          f"Deployed in VPC | {name}")
            else:
                self._add("FAIL", "SM-04", "SAGEMAKER", name,
                          f"Not attached to a VPC subnet | {name}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 33: AMAZON COGNITO
    # ══════════════════════════════════════════════════════════════════════════
    def _check_cognito(self):
        self._section_header("COGNITO")
        cog = self._client("cognito-idp")

        try:
            pools = cog.list_user_pools(MaxResults=60).get("UserPools", [])
        except Exception as e:
            self._add("WARN", "COG-01", "COGNITO", "cognito", str(e))
            return
        if not pools:
            self._add("INFO", "COG-01", "COGNITO", "cognito",
                      "No Cognito user pools found")
            return

        for pool in pools:
            pid  = pool.get("Id", "unknown")
            name = pool.get("Name", pid)
            try:
                detail = cog.describe_user_pool(
                    UserPoolId=pid).get("UserPool", {})
            except Exception as e:
                self._add("WARN", "COG-01", "COGNITO", name, str(e))
                continue

            # COG-01 — MFA configuration
            mfa = detail.get("MfaConfiguration", "OFF")
            if mfa == "ON":
                self._add("PASS", "COG-01", "COGNITO", name,
                          f"MFA=ON (required) | {name}")
            elif mfa == "OPTIONAL":
                self._add("WARN", "COG-01", "COGNITO", name,
                          f"MFA=OPTIONAL (not enforced) | {name}")
            else:
                self._add("FAIL", "COG-01", "COGNITO", name,
                          f"MFA=OFF | {name}")

            # COG-02 — Password policy strength
            pw = detail.get("Policies", {}).get("PasswordPolicy", {})
            min_len = pw.get("MinimumLength", 0)
            complex_ok = all([
                pw.get("RequireUppercase", False),
                pw.get("RequireLowercase", False),
                pw.get("RequireNumbers", False),
                pw.get("RequireSymbols", False),
            ])
            if min_len >= 8 and complex_ok:
                self._add("PASS", "COG-02", "COGNITO", name,
                          f"Strong password policy (len>={min_len}) | {name}")
            else:
                self._add("FAIL", "COG-02", "COGNITO", name,
                          f"Weak password policy (len={min_len}, complexity={complex_ok}) | {name}")

            # COG-03 — Advanced security (threat protection)
            adv = detail.get("UserPoolAddOns", {}).get(
                "AdvancedSecurityMode", "OFF")
            if adv in ("ENFORCED", "AUDIT"):
                self._add("PASS", "COG-03", "COGNITO", name,
                          f"Advanced security={adv} | {name}")
            else:
                self._add("FAIL", "COG-03", "COGNITO", name,
                          f"Advanced security=OFF (no threat protection) | {name}")

            # COG-04 — Deletion protection
            if detail.get("DeletionProtection", "INACTIVE") == "ACTIVE":
                self._add("PASS", "COG-04", "COGNITO", name,
                          f"Deletion protection=ON | {name}")
            else:
                self._add("WARN", "COG-04", "COGNITO", name,
                          f"Deletion protection=OFF | {name}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 34: API GATEWAY (HTTP APIs / v2)
    # ══════════════════════════════════════════════════════════════════════════
    def _check_apigatewayv2(self):
        self._section_header("APIGATEWAYV2")
        api2 = self._client("apigatewayv2")

        try:
            apis = api2.get_apis().get("Items", [])
        except Exception as e:
            self._add("WARN", "AGW2-01", "APIGATEWAYV2", "apigatewayv2", str(e))
            return
        if not apis:
            self._add("INFO", "AGW2-01", "APIGATEWAYV2", "apigatewayv2",
                      "No API Gateway v2 (HTTP/WebSocket) APIs found")
            return

        for api in apis:
            api_id = api.get("ApiId", "unknown")
            api_nm = api.get("Name", api_id)

            # AGW2-01 — Stage access logging
            try:
                stages = api2.get_stages(ApiId=api_id).get("Items", [])
            except Exception as e:
                self._add("WARN", "AGW2-01", "APIGATEWAYV2", api_nm, str(e))
                stages = []
            if not stages:
                self._add("INFO", "AGW2-01", "APIGATEWAYV2", api_nm,
                          f"No stages deployed | {api_nm}")
            for st in stages:
                stage = st.get("StageName", "unknown")
                label = f"{api_nm}/{stage}"
                if st.get("AccessLogSettings", {}).get("DestinationArn"):
                    self._add("PASS", "AGW2-01", "APIGATEWAYV2", label,
                              f"Access logging enabled | {label}")
                else:
                    self._add("FAIL", "AGW2-01", "APIGATEWAYV2", label,
                              f"No access logging | {label}")
                # AGW2-03 — Default route throttling
                drs = st.get("DefaultRouteSettings", {})
                if drs.get("ThrottlingBurstLimit") or drs.get("ThrottlingRateLimit"):
                    self._add("PASS", "AGW2-03", "APIGATEWAYV2", label,
                              f"Default throttling configured | {label}")
                else:
                    self._add("WARN", "AGW2-03", "APIGATEWAYV2", label,
                              f"No default throttling limits | {label}")

            # AGW2-02 — Route authorization
            try:
                routes = api2.get_routes(ApiId=api_id).get("Items", [])
            except Exception as e:
                self._add("WARN", "AGW2-02", "APIGATEWAYV2", api_nm, str(e))
                continue
            open_routes = [r.get("RouteKey", "?") for r in routes
                           if r.get("AuthorizationType", "NONE") == "NONE"]
            if open_routes:
                self._add("FAIL", "AGW2-02", "APIGATEWAYV2", api_nm,
                          f"{len(open_routes)} route(s) with no authorization: "
                          f"{', '.join(open_routes[:5])} | {api_nm}")
            elif routes:
                self._add("PASS", "AGW2-02", "APIGATEWAYV2", api_nm,
                          f"All routes require authorization | {api_nm}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 35: IAM PRIVILEGE ESCALATION  (resource-aware path analysis)
    # ══════════════════════════════════════════════════════════════════════════
    @staticmethod
    def _policy_to_statements(doc) -> List[Dict]:
        """Parse an IAM policy document into a list of statements, each
        {effect, actions:set(lower), resources:set(lower)}. Handles URL-encoded
        string or dict; single or list statements; Action/NotAction and
        Resource/NotResource. NotAction+Allow -> actions {'*'}; missing Resource or
        NotResource -> resources {'*'} (broad, to avoid under-reporting)."""
        out: List[Dict] = []
        if not doc:
            return out
        if isinstance(doc, str):
            try:
                doc = json.loads(unquote(doc))
            except Exception:
                return out
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            effect = stmt.get("Effect", "")
            if effect not in ("Allow", "Deny"):
                continue
            if "Action" in stmt:
                av = stmt["Action"]
                av = [av] if isinstance(av, str) else list(av)
                actions = {str(a).lower() for a in av}
            elif "NotAction" in stmt and effect == "Allow":
                actions = {"*"}   # Allow on NotAction grants everything else
            else:
                continue
            if "Resource" in stmt:
                rv = stmt["Resource"]
                rv = [rv] if isinstance(rv, str) else list(rv)
                resources = {str(r).lower() for r in rv}
            else:
                resources = {"*"}  # missing Resource / NotResource -> broad
            out.append({"effect": effect, "actions": actions, "resources": resources})
        return out

    @staticmethod
    def _policy_to_action_sets(doc) -> tuple:
        """Derive (allow_patterns, deny_patterns) action sets from a policy document
        (action-level view; kept for backward compatibility)."""
        allow, deny = set(), set()
        for st in AWSLiveScanner._policy_to_statements(doc):
            if st["effect"] == "Allow":
                allow |= st["actions"]
            else:
                deny |= st["actions"]
        return allow, deny

    def _get_managed_policy_statements(self, arn: str) -> List[Dict]:
        """Fetch and cache a managed policy's default-version statements."""
        if arn in self._managed_policy_cache:
            return self._managed_policy_cache[arn]
        result: List[Dict] = []
        try:
            iam = self._client("iam")
            ver = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(
                PolicyArn=arn, VersionId=ver)["PolicyVersion"]["Document"]
            result = self._policy_to_statements(doc)
        except Exception:
            pass
        self._managed_policy_cache[arn] = result
        return result

    def _get_iam_principals(self) -> List[Dict]:
        """Enumerate IAM users and roles with their effective policy statements
        (attached managed + inline + group policies), plus derived allow/deny action
        sets. Cached. Read-only."""
        if self._iam_principals is not None:
            return self._iam_principals

        iam = self._client("iam")
        principals: List[Dict] = []

        def _paginate(method, key, **kwargs):
            try:
                paginator = iam.get_paginator(method)
                for page in paginator.paginate(**kwargs):
                    for item in page.get(key, []):
                        yield item
            except Exception:
                return

        def _finalize(ptype, name, arn, statements):
            allow, deny = set(), set()
            for st in statements:
                if st["effect"] == "Allow":
                    allow |= st["actions"]
                else:
                    deny |= st["actions"]
            principals.append({"type": ptype, "name": name, "arn": arn,
                               "statements": statements, "allow": allow, "deny": deny})

        # Pre-resolve group statements once
        group_stmts: Dict[str, List[Dict]] = {}
        for g in _paginate("list_groups", "Groups"):
            gname = g["GroupName"]
            stmts: List[Dict] = []
            try:
                for p in iam.list_attached_group_policies(
                        GroupName=gname).get("AttachedPolicies", []):
                    stmts += self._get_managed_policy_statements(p["PolicyArn"])
                for pn in iam.list_group_policies(
                        GroupName=gname).get("PolicyNames", []):
                    doc = iam.get_group_policy(
                        GroupName=gname, PolicyName=pn).get("PolicyDocument")
                    stmts += self._policy_to_statements(doc)
            except Exception:
                pass
            group_stmts[gname] = stmts

        # Users
        for u in _paginate("list_users", "Users"):
            name = u["UserName"]
            stmts = []
            try:
                for p in iam.list_attached_user_policies(
                        UserName=name).get("AttachedPolicies", []):
                    stmts += self._get_managed_policy_statements(p["PolicyArn"])
                for pn in iam.list_user_policies(
                        UserName=name).get("PolicyNames", []):
                    doc = iam.get_user_policy(
                        UserName=name, PolicyName=pn).get("PolicyDocument")
                    stmts += self._policy_to_statements(doc)
                for g in iam.list_groups_for_user(
                        UserName=name).get("Groups", []):
                    stmts += group_stmts.get(g["GroupName"], [])
            except Exception:
                pass
            _finalize("user", name, u.get("Arn", ""), stmts)

        # Roles (skip AWS service-linked roles)
        for r in _paginate("list_roles", "Roles"):
            if r.get("Path", "").startswith("/aws-service-role/"):
                continue
            name = r["RoleName"]
            stmts = []
            try:
                for p in iam.list_attached_role_policies(
                        RoleName=name).get("AttachedPolicies", []):
                    stmts += self._get_managed_policy_statements(p["PolicyArn"])
                for pn in iam.list_role_policies(
                        RoleName=name).get("PolicyNames", []):
                    doc = iam.get_role_policy(
                        RoleName=name, PolicyName=pn).get("PolicyDocument")
                    stmts += self._policy_to_statements(doc)
            except Exception:
                pass
            _finalize("role", name, r.get("Arn", ""), stmts)

        self._iam_principals = principals
        return principals

    def _check_iam_privesc(self):
        self._section_header("IAMPRIVESC")
        self._log("Resource-aware path analysis — each finding shows its scope "
                  "(account-wide vs resource-scoped); policy conditions, permission "
                  "boundaries, and SCPs are not evaluated")
        try:
            principals = self._get_iam_principals()
        except Exception as e:
            self._add("WARN", "IAMPE-01", "IAMPRIVESC", "iam",
                      f"Could not enumerate IAM principals: {e}")
            return
        if not principals:
            self._add("INFO", "IAMPE-01", "IAMPRIVESC", "iam",
                      "No IAM users or roles found")
            return

        found = False
        for p in principals:
            for f in evaluate_privesc_scoped(p["statements"]):
                found = True
                scope = f.get("scope", "")
                if scope == "account-wide":
                    scope_note = " [scope: account-wide]"
                elif scope == "resource-scoped" and f.get("scope_arns"):
                    arns = f["scope_arns"]
                    shown = arns[0] + (f" +{len(arns) - 1} more" if len(arns) > 1 else "")
                    scope_note = f" [scope: {shown}]"
                else:
                    scope_note = ""
                self._add("FAIL", f["id"], "IAMPRIVESC",
                          f"{p['type']}:{p['name']}",
                          f"{f['name']} — {f['desc']}{scope_note} | {p['type']} {p['name']}")
        if not found:
            self._add("PASS", "IAMPE-00", "IAMPRIVESC", "all-principals",
                      f"No privilege-escalation paths detected across "
                      f"{len(principals)} principals")

    # ══════════════════════════════════════════════════════════════════════════
    # ORCHESTRATION
    # ══════════════════════════════════════════════════════════════════════════
    def run(self):
        if not HAS_BOTO3:
            print(
                f"{RED}[ERROR]{RESET} boto3 is not installed.\n"
                "  Run: pip install boto3"
            )
            sys.exit(2)

        try:
            sts          = boto3.client("sts", region_name=self.region)
            identity     = sts.get_caller_identity()
            self.account = identity["Account"]
        except NoCredentialsError:
            print(
                f"{RED}[ERROR]{RESET} No AWS credentials found.\n"
                "  Configure via environment variables, "
                "~/.aws/credentials, or an IAM instance role."
            )
            sys.exit(2)
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Could not connect to AWS: {e}")
            sys.exit(2)

        print("=" * 70)
        print(f" {BOLD}AWS Live Security Audit  v{VERSION}{RESET}")
        print(f" Compliance: CIS · PCI-DSS · HIPAA · SOC2 · NIST 800-53")
        print(f" Account  : {self.account}")
        print(f" Region   : {self.region}")
        print(f" Sections : {', '.join(self.sections)} ({len(self.sections)} domains)")
        print("=" * 70)

        CHECK_MAP = {
            "IAM":            self._check_iam,
            "S3":             self._check_s3,
            "VPC":            self._check_vpc,
            "LOGGING":        self._check_logging,
            "KMS":            self._check_kms,
            "EC2":            self._check_ec2,
            "ECR":            self._check_ecr,
            "BACKUP":         self._check_backup,
            "RDS":            self._check_rds,
            "GLACIER":        self._check_glacier,
            "SNS":            self._check_sns,
            "SQS":            self._check_sqs,
            "CLOUDFRONT":     self._check_cloudfront,
            "ROUTE53":        self._check_route53,
            "BEDROCK":        self._check_bedrock,
            "BEDROCK_AGENTS": self._check_bedrock_agents,
            "LAMBDA":         self._check_lambda,
            "EKS":            self._check_eks,
            "ECS":            self._check_ecs,
            "SECRETS":        self._check_secrets,
            "WAF":            self._check_waf,
            "ELASTICACHE":    self._check_elasticache,
            "OPENSEARCH":     self._check_opensearch,
            "DYNAMODB":       self._check_dynamodb,
            "STEPFUNCTIONS":  self._check_stepfunctions,
            "APIGATEWAY":     self._check_apigateway,
            "ELB":            self._check_elb,
            "EBS":            self._check_ebs,
            "REDSHIFT":       self._check_redshift,
            "EFS":            self._check_efs,
            "ACM":            self._check_acm,
            "SAGEMAKER":      self._check_sagemaker,
            "COGNITO":        self._check_cognito,
            "APIGATEWAYV2":   self._check_apigatewayv2,
            "IAMPRIVESC":     self._check_iam_privesc,
        }

        for section in self.sections:
            fn = CHECK_MAP.get(section)
            if fn:
                try:
                    fn()
                except Exception as e:
                    self._add("FAIL", section, section, section,
                              f"Unhandled error in section {section}: {e}")

    # ══════════════════════════════════════════════════════════════════════════
    # REPORTING
    # ══════════════════════════════════════════════════════════════════════════
    def print_report(self) -> Dict[str, int]:
        counts = {
            "PASS": sum(1 for r in self.results if r.status == "PASS"),
            "FAIL": sum(1 for r in self.results if r.status == "FAIL"),
            "WARN": sum(1 for r in self.results if r.status == "WARN"),
            "INFO": sum(1 for r in self.results if r.status == "INFO"),
        }
        score = compute_risk_score(self.results)
        grade = score_to_grade(score)

        print("\n" + "=" * 70)
        print(f" {BOLD}POSTURE SCORE: {score}/100  (Grade {grade}){RESET}")
        print(
            f" {GREEN}PASS{RESET}: {counts['PASS']}  |  "
            f"{RED}FAIL{RESET}: {counts['FAIL']}  |  "
            f"{YELLOW}WARN{RESET}: {counts['WARN']}  |  "
            f"{BLUE}INFO{RESET}: {counts['INFO']}"
        )
        print(f" Total checks: {sum(counts.values())}")
        print("=" * 70)

        fails = [r for r in self.results if r.status == "FAIL"]
        if fails:
            print(f"\n{BOLD}{RED}CRITICAL FINDINGS:{RESET}")
            for r in fails:
                res = f" | {r.resource}" if r.resource else ""
                sev = f" [{r.severity}]" if r.severity else ""
                print(f"  {RED}[FAIL]{RESET}{sev} {r.check_id}: {r.message}{res}")
                if r.remediation_cmd:
                    print(f"         {BLUE}Remediation:{RESET} {r.remediation_cmd[:120]}")

        return counts

    def save_json(self, path: str):
        score = compute_risk_score(self.results)
        data = {
            "scanner":   f"AWS Live Security Scanner v{VERSION}",
            "account":   self.account,
            "region":    self.region,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "posture_score": score,
            "posture_grade": score_to_grade(score),
            "summary": {
                "PASS": sum(1 for r in self.results if r.status == "PASS"),
                "FAIL": sum(1 for r in self.results if r.status == "FAIL"),
                "WARN": sum(1 for r in self.results if r.status == "WARN"),
                "INFO": sum(1 for r in self.results if r.status == "INFO"),
            },
            "results": [
                {
                    "status":          r.status,
                    "check_id":        r.check_id,
                    "section":         r.section,
                    "resource":        r.resource,
                    "message":         r.message,
                    "severity":        r.severity,
                    "compliance":      r.compliance,
                    "remediation_cmd": r.remediation_cmd,
                }
                for r in self.results
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"{BLUE}[*]{RESET} JSON report saved: {path}")

    # ── Human-readable rule title for a check_id (used by SARIF) ──────────────
    @staticmethod
    def _rule_title(check_id: str) -> str:
        for rule in IAM_PRIVESC_RULES:
            if rule["id"] == check_id:
                return rule["name"]
        if check_id == IAM_PRIVESC_FULL_ADMIN["id"]:
            return IAM_PRIVESC_FULL_ADMIN["name"]
        return check_id

    def save_sarif(self, path: str):
        """Write a SARIF 2.1.0 report (FAIL + WARN findings) for GitHub code
        scanning and other SARIF consumers."""
        findings = [r for r in self.results if r.status in ("FAIL", "WARN")]

        # Build a unique rule per check_id that appears in findings.
        rules, rule_index = [], {}
        for r in findings:
            if r.check_id in rule_index:
                continue
            rule_index[r.check_id] = len(rules)
            tags = ["security", r.section.lower()]
            tags += [f"{fw}:{ctrl}" for fw, ctrl in (r.compliance or {}).items()]
            rules.append({
                "id": r.check_id,
                "name": self._rule_title(r.check_id).replace(" ", ""),
                "shortDescription": {"text": f"{r.check_id}: {self._rule_title(r.check_id)}"},
                "fullDescription": {"text": r.message},
                "helpUri": "https://github.com/Krishcalin/AWS-Security-Scanner",
                "defaultConfiguration": {
                    "level": SARIF_LEVEL.get(r.severity, "warning")},
                "properties": {
                    "tags": tags,
                    "security-severity": {
                        "CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5",
                        "LOW": "3.0", "INFO": "0.0"}.get(r.severity, "5.5"),
                },
            })

        results_json = []
        for r in findings:
            loc = f"{r.section}/{r.check_id}"
            results_json.append({
                "ruleId": r.check_id,
                "ruleIndex": rule_index[r.check_id],
                "level": SARIF_LEVEL.get(r.severity, "warning"),
                "message": {"text": f"{r.message}"
                            + (f" [resource: {r.resource}]" if r.resource else "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc},
                        "region": {"startLine": 1, "startColumn": 1},
                    },
                    "logicalLocations": [{
                        "name": r.resource or r.section,
                        "fullyQualifiedName": f"{self.account}/{self.region}/"
                                              f"{r.section}/{r.resource}",
                        "kind": "resource",
                    }],
                }],
                "partialFingerprints": {
                    "awsFinding": finding_key(r.check_id, r.resource)},
                "properties": {
                    "severity": r.severity,
                    "section": r.section,
                    "compliance": r.compliance,
                    "remediation": r.remediation_cmd,
                },
            })

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "AWS Live Security Scanner",
                    "version": VERSION,
                    "informationUri": "https://github.com/Krishcalin/AWS-Security-Scanner",
                    "rules": rules,
                }},
                "automationDetails": {
                    "id": f"aws-live-scanner/{self.account}/{self.region}"},
                "results": results_json,
            }],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, default=str)
        print(f"{BLUE}[*]{RESET} SARIF report saved: {path} "
              f"({len(results_json)} findings)")

    def save_asff(self, path: str):
        """Write AWS Security Finding Format (ASFF) findings for import into
        Security Hub via:  aws securityhub batch-import-findings --findings file://<path>
        (BatchImportFindings accepts max 100 findings per call — chunk if needed)."""
        now = datetime.now(timezone.utc).isoformat()
        product_arn = (f"arn:aws:securityhub:{self.region}:{self.account}:"
                       f"product/{self.account}/default")
        findings = []
        for r in self.results:
            if r.status not in ("FAIL", "WARN"):
                continue
            related = [f"{fw} {ctrl}" for fw, ctrl in (r.compliance or {}).items()]
            findings.append({
                "SchemaVersion": "2018-10-08",
                "Id": f"{self.region}/{r.check_id}/{r.resource or 'account'}",
                "ProductArn": product_arn,
                "GeneratorId": f"aws-live-scanner/{r.check_id}",
                "AwsAccountId": self.account,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "CreatedAt": now,
                "UpdatedAt": now,
                "Severity": {"Label": ASFF_SEVERITY.get(r.severity, "INFORMATIONAL")},
                "Title": f"{r.check_id}: {self._rule_title(r.check_id)}"[:256],
                "Description": r.message[:1024],
                "Resources": [{
                    "Type": "Other",
                    "Id": r.resource or f"{self.account}",
                    "Region": self.region,
                }],
                "Compliance": {
                    "Status": ASFF_COMPLIANCE_STATUS.get(r.status, "NOT_AVAILABLE"),
                    **({"RelatedRequirements": related} if related else {}),
                },
                "Remediation": {"Recommendation": {
                    "Text": (r.remediation_cmd or "Review and apply least privilege")[:512],
                    "Url": "https://github.com/Krishcalin/AWS-Security-Scanner",
                }},
                "ProductFields": {"Section": r.section, "CheckId": r.check_id},
                "RecordState": "ACTIVE",
            })
        with open(path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, default=str)
        print(f"{BLUE}[*]{RESET} ASFF findings saved: {path} "
              f"({len(findings)} findings)")

    def print_diff(self, baseline_path: str):
        """Compare this scan against a previously-saved JSON report and print
        new + resolved findings."""
        try:
            with open(baseline_path, "r", encoding="utf-8") as f:
                baseline = json.load(f)
        except Exception as e:
            print(f"{YELLOW}[!]{RESET} Could not read baseline {baseline_path}: {e}")
            return
        d = diff_findings(self.results, baseline.get("results", []))
        new, resolved = d["new"], d["resolved"]

        print("\n" + "=" * 70)
        print(f" {BOLD}CHANGES SINCE BASELINE{RESET}  ({baseline_path})")
        print(f" {RED}NEW{RESET}: {len(new)}   |   {GREEN}RESOLVED{RESET}: {len(resolved)}")
        print("=" * 70)
        if new:
            print(f"\n{BOLD}{RED}NEW findings:{RESET}")
            for r in new:
                res = f" | {r.resource}" if r.resource else ""
                sev = f" [{r.severity}]" if r.severity else ""
                print(f"  {RED}+{RESET}{sev} {r.check_id}: {r.message}{res}")
        if resolved:
            print(f"\n{BOLD}{GREEN}RESOLVED findings:{RESET}")
            for d_ in resolved:
                res = f" | {d_.get('resource')}" if d_.get("resource") else ""
                print(f"  {GREEN}-{RESET} {d_.get('check_id')}: {d_.get('message')}{res}")

    def save_html(self, path: str):
        STATUS_BADGE = {
            "PASS": '<span class="badge pass">PASS</span>',
            "FAIL": '<span class="badge fail">FAIL</span>',
            "WARN": '<span class="badge warn">WARN</span>',
            "INFO": '<span class="badge info">INFO</span>',
        }
        SEV_BADGE = {
            "CRITICAL": '<span class="sev crit">CRITICAL</span>',
            "HIGH":     '<span class="sev high">HIGH</span>',
            "MEDIUM":   '<span class="sev med">MEDIUM</span>',
            "LOW":      '<span class="sev low">LOW</span>',
        }
        counts = {
            "PASS": sum(1 for r in self.results if r.status == "PASS"),
            "FAIL": sum(1 for r in self.results if r.status == "FAIL"),
            "WARN": sum(1 for r in self.results if r.status == "WARN"),
            "INFO": sum(1 for r in self.results if r.status == "INFO"),
        }
        score = compute_risk_score(self.results)
        grade = score_to_grade(score)

        import html as html_mod
        rows = ""
        for r in self.results:
            badge = STATUS_BADGE.get(r.status, r.status)
            sev = SEV_BADGE.get(r.severity, "") if r.severity else ""
            comp = ", ".join(f"{k}:{v}" for k, v in r.compliance.items()) if r.compliance else ""
            rem = html_mod.escape(r.remediation_cmd) if r.remediation_cmd else ""
            rem_cell = f'<details><summary>CLI</summary><code>{rem}</code></details>' if rem else ""
            rows += (
                f"<tr class='row-{r.status.lower()}'>"
                f"<td>{badge}</td>"
                f"<td>{sev}</td>"
                f"<td>{html_mod.escape(r.check_id)}</td>"
                f"<td>{html_mod.escape(r.section)}</td>"
                f"<td>{html_mod.escape(r.resource)}</td>"
                f"<td>{html_mod.escape(r.message)}</td>"
                f"<td class='comp'>{html_mod.escape(comp)}</td>"
                f"<td>{rem_cell}</td>"
                f"</tr>\n"
            )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AWS Live Security Audit — {html_mod.escape(self.account)}</title>
  <style>
    body  {{ font-family:'Segoe UI',Arial,sans-serif; background:#0d1117;
             color:#c9d1d9; margin:0; }}
    h1    {{ background:#161b22; padding:20px 30px; margin:0; font-size:1.4em;
             border-bottom:1px solid #30363d; }}
    .summary {{ display:flex; gap:20px; padding:20px 30px;
                background:#161b22; flex-wrap:wrap; }}
    .card    {{ background:#21262d; border-radius:8px; padding:15px 25px;
                text-align:center; min-width:90px; }}
    .card .num {{ font-size:2em; font-weight:bold; }}
    .card .lbl {{ font-size:0.85em; color:#8b949e; }}
    .fail-num {{ color:#f85149; }} .pass-num {{ color:#3fb950; }}
    .warn-num {{ color:#d29922; }} .info-num {{ color:#58a6ff; }}
    table {{ width:100%; border-collapse:collapse; margin:0; }}
    th    {{ background:#161b22; padding:12px 15px; text-align:left;
             font-size:0.85em; color:#8b949e; border-bottom:1px solid #30363d;
             position:sticky; top:0; }}
    td    {{ padding:10px 15px; border-bottom:1px solid #21262d;
             font-size:0.9em; }}
    tr.row-fail {{ background:rgba(248,81,73,0.08); }}
    tr.row-warn {{ background:rgba(210,153,34,0.06); }}
    .badge {{ padding:3px 8px; border-radius:4px; font-size:0.8em;
              font-weight:bold; white-space:nowrap; }}
    .badge.pass {{ background:#1a4731; color:#3fb950; }}
    .badge.fail {{ background:#4d1f1f; color:#f85149; }}
    .badge.warn {{ background:#3d2e00; color:#d29922; }}
    .badge.info {{ background:#1c2e46; color:#58a6ff; }}
    .sev {{ padding:2px 6px; border-radius:3px; font-size:0.75em; font-weight:bold; }}
    .sev.crit {{ background:#4d1f1f; color:#f85149; }}
    .sev.high {{ background:#3d2e00; color:#d29922; }}
    .sev.med  {{ background:#2a2a00; color:#e3b341; }}
    .sev.low  {{ background:#1a3a1a; color:#3fb950; }}
    .comp {{ font-size:0.75em; color:#8b949e; max-width:200px; }}
    details summary {{ cursor:pointer; color:#58a6ff; font-size:0.8em; }}
    details code {{ display:block; margin-top:4px; font-size:0.75em;
                    white-space:pre-wrap; word-break:break-all; color:#c9d1d9;
                    background:#161b22; padding:6px; border-radius:4px; }}
    .meta {{ padding:8px 30px 16px; font-size:0.82em; color:#8b949e; }}
    .score {{ font-size:2.4em; font-weight:bold; }}
    .grade {{ font-size:1.4em; color:#8b949e; }}
    .tbl-wrap {{ overflow-x:auto; padding:0 20px 30px; }}
  </style>
</head>
<body>
<h1>AWS Live Security Audit &nbsp;·&nbsp;
    Account: {html_mod.escape(self.account)} &nbsp;·&nbsp;
    Region: {html_mod.escape(self.region)}</h1>
<div class="summary">
  <div class="card"><div class="score">{score}</div>
    <div class="grade">Grade {grade}</div><div class="lbl">POSTURE</div></div>
  <div class="card"><div class="num fail-num">{counts['FAIL']}</div>
    <div class="lbl">FAIL</div></div>
  <div class="card"><div class="num warn-num">{counts['WARN']}</div>
    <div class="lbl">WARN</div></div>
  <div class="card"><div class="num pass-num">{counts['PASS']}</div>
    <div class="lbl">PASS</div></div>
  <div class="card"><div class="num info-num">{counts['INFO']}</div>
    <div class="lbl">INFO</div></div>
  <div class="card"><div class="num">{sum(counts.values())}</div>
    <div class="lbl">TOTAL</div></div>
</div>
<p class="meta">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC
  &nbsp;|&nbsp; AWS Live Security Scanner v{VERSION}</p>
<div class="tbl-wrap">
<table>
  <thead>
    <tr>
      <th>Status</th><th>Severity</th><th>Check ID</th><th>Section</th>
      <th>Resource</th><th>Message</th><th>Compliance</th><th>Remediation</th>
    </tr>
  </thead>
  <tbody>
{rows}  </tbody>
</table>
</div>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"{BLUE}[*]{RESET} HTML report saved: {path}")

    def save_evidence(self, output_dir: str):
        """Save raw evidence artefacts: credential report CSV + audit manifest."""
        try:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(f"{RED}[ERROR]{RESET} Cannot create evidence directory "
                  f"'{output_dir}': {e}")
            return

        # Credential report CSV
        rows = self._get_credential_report()
        if rows:
            cred_path = os.path.join(output_dir, "credential_report.csv")
            try:
                with open(cred_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
                print(f"{BLUE}[*]{RESET} Credential report: {cred_path}")
            except OSError as e:
                print(f"{YELLOW}[WARN]{RESET} Could not write credential "
                      f"report: {e}")

        # Audit manifest
        counts = {
            "PASS": sum(1 for r in self.results if r.status == "PASS"),
            "FAIL": sum(1 for r in self.results if r.status == "FAIL"),
            "WARN": sum(1 for r in self.results if r.status == "WARN"),
            "INFO": sum(1 for r in self.results if r.status == "INFO"),
        }
        manifest_path = os.path.join(output_dir, "AUDIT_MANIFEST.txt")
        try:
            try:
                evidence_files = sorted(os.listdir(output_dir))
            except OSError:
                evidence_files = []
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write("AWS Live Security Audit — Evidence Manifest\n")
                f.write("=" * 45 + "\n")
                f.write(f"Account  : {self.account}\n")
                f.write(f"Region   : {self.region}\n")
                f.write(
                    f"Run Time : "
                    f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
                )
                f.write("Results Summary\n")
                f.write(f"  PASS  : {counts['PASS']}\n")
                f.write(f"  FAIL  : {counts['FAIL']}\n")
                f.write(f"  WARN  : {counts['WARN']}\n")
                f.write(f"  INFO  : {counts['INFO']}\n")
                f.write(f"  Total : {sum(counts.values())}\n\n")
                f.write("Service Domains Audited\n")
                for i, s in enumerate(self.sections, 1):
                    f.write(f"  {i:2d}. {SECTION_LABELS.get(s, s)}\n")
                f.write("\nEvidence Files\n")
                for fname in evidence_files:
                    if fname != "AUDIT_MANIFEST.txt":
                        f.write(f"  - {fname}\n")
            print(f"{BLUE}[*]{RESET} Audit manifest: {manifest_path}")
        except OSError as e:
            print(f"{YELLOW}[WARN]{RESET} Could not write audit manifest: {e}")
        print(f"{BLUE}[*]{RESET} Evidence directory: {output_dir}/")


# ─── CLI ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="aws_live_scanner",
        description=(
            f"AWS Live Security Scanner v{VERSION} — "
            "read-only audit of AWS environments via boto3.\n"
            f"Covers {len(SECTIONS)} service domains aligned to CIS, PCI-DSS, HIPAA, SOC2, NIST."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
sections available:
  {', '.join(SECTIONS)}

examples:
  python aws_live_scanner.py
  python aws_live_scanner.py --region us-east-1
  python aws_live_scanner.py --region eu-west-1 --json out.json --html out.html
  python aws_live_scanner.py --sections IAM,S3,IAMPRIVESC --output-dir evidence/
  python aws_live_scanner.py --sarif results.sarif --fail-on HIGH
  python aws_live_scanner.py --asff findings.asff.json
  python aws_live_scanner.py --json today.json --baseline yesterday.json
""",
    )
    parser.add_argument(
        "--region", "-r",
        default=os.environ.get("AWS_DEFAULT_REGION", "eu-west-1"),
        help="AWS region to audit (default: eu-west-1 or $AWS_DEFAULT_REGION)",
    )
    parser.add_argument(
        "--json", metavar="FILE",
        help="Save results as JSON to FILE",
    )
    parser.add_argument(
        "--html", metavar="FILE",
        help="Save results as HTML report to FILE",
    )
    parser.add_argument(
        "--sarif", metavar="FILE",
        help="Save findings as SARIF 2.1.0 to FILE (GitHub code scanning)",
    )
    parser.add_argument(
        "--asff", metavar="FILE",
        help="Save findings as AWS Security Finding Format (ASFF) JSON to FILE "
             "for Security Hub batch-import-findings",
    )
    parser.add_argument(
        "--baseline", metavar="FILE",
        help="Compare this scan against a previous JSON report and print "
             "new/resolved findings",
    )
    parser.add_argument(
        "--fail-on", metavar="SEVERITY", dest="fail_on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Exit non-zero only if a FAIL at or above this severity exists "
             "(default: exit 1 on any FAIL)",
    )
    parser.add_argument(
        "--output-dir", metavar="DIR",
        help="Directory for evidence artefacts (default: auto-named)",
    )
    parser.add_argument(
        "--sections", metavar="SECTIONS",
        help=(
            f"Comma-separated sections to run (default: all). "
            f"Options: {','.join(SECTIONS)}"
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print all findings including PASS",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    args     = parser.parse_args()
    sections = (
        [s.strip().upper() for s in args.sections.split(",")]
        if args.sections else None
    )

    scanner = AWSLiveScanner(
        region=args.region,
        verbose=args.verbose,
        sections=sections,
    )
    scanner.run()
    counts = scanner.print_report()

    if args.json:
        scanner.save_json(args.json)
    if args.html:
        scanner.save_html(args.html)
    if args.sarif:
        scanner.save_sarif(args.sarif)
    if args.asff:
        scanner.save_asff(args.asff)
    if args.baseline:
        scanner.print_diff(args.baseline)

    # Always save evidence (auto-name dir if not specified)
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = args.output_dir or f"aws_audit_{scanner.account}_{ts}"
    scanner.save_evidence(out_dir)

    # Exit code: gate on --fail-on threshold if given, else any FAIL.
    if args.fail_on:
        failed = fails_threshold(scanner.results, args.fail_on)
    else:
        failed = counts.get("FAIL", 0) > 0
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
