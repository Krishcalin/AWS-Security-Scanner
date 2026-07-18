#!/usr/bin/env python3
"""
AWS Live Security Scanner v2.2.0
Read-only live audit of AWS environments via boto3, evolving toward a CNAPP.

Aligned to: CIS AWS Foundations Benchmark v3.0
            AWS Well-Architected Framework — Security Pillar
            PCI DSS v4.0 · HIPAA · SOC 2 · NIST 800-53 Rev 5

35 service domains across IAM · S3 · VPC · Logging · KMS · EC2 · ECR · Backup ·
RDS · Glacier · SNS · SQS · CloudFront · Route 53 · Bedrock · Lambda · EKS · ECS ·
Secrets · WAF · ElastiCache · OpenSearch · DynamoDB · Step Functions · API Gateway ·
ELB · EBS · Redshift · EFS · ACM · SageMaker · Cognito · HTTP APIs — plus an IAM
privilege-escalation / attack-path engine.

CNAPP Phase 0/1 (v2.2.0):
  * Multi-account fan-out via AWS Organizations + STS AssumeRole (--org / --accounts)
  * Multi-region sweep for regional sections (--all-regions)
  * Per-framework compliance scorecard (control-level pass/fail rollup)
  * Security graph (aws_graph.SecurityGraph): CAN_ASSUME + CAN_PRIVESC_TO edges,
    transitive privilege-escalation chains, dangerous-trust detection, serialized
    to graph.json (--graph) as the Neptune migration seed.

Requirements: pip install boto3
Credentials : AWS CLI profile, environment variables, or IAM instance role
              Minimum permission: SecurityAudit managed policy
              Multi-account: sts:AssumeRole into a read-only role per target account

Usage:
  python aws_live_scanner.py [--region eu-west-1]
  python aws_live_scanner.py --region us-east-1 --json report.json --html report.html
  python aws_live_scanner.py --sections IAM,S3,RDS --output-dir evidence/
  python aws_live_scanner.py --all-regions --compliance --graph graph.json
  python aws_live_scanner.py --org --assume-role OrganizationAccountAccessRole --json org.json
  python aws_live_scanner.py --verbose

Author: Krishnendu De with support from Claude.AI
"""

import os
import sys
import json
import csv
import io
import gzip
import base64
import time
import fnmatch
import argparse
from urllib.parse import unquote
from collections import defaultdict
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

from aws_graph import SecurityGraph
import aws_exposure
import aws_deepplane
import aws_correlate
import aws_effperm
import aws_state
import aws_unused
import aws_sidescan
import aws_graph_neptune

VERSION = "2.11.1"

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
    "AMI", "ECR", "BACKUP", "RDS", "GLACIER", "SNS", "SQS",
    "CLOUDFRONT", "ROUTE53", "BEDROCK", "BEDROCK_AGENTS",
    "LAMBDA", "EKS", "ECS", "SECRETS", "WAF",
    "ELASTICACHE", "OPENSEARCH", "DYNAMODB", "STEPFUNCTIONS",
    "APIGATEWAY", "ELB", "EBS", "REDSHIFT", "EFS", "ACM",
    "SAGEMAKER", "COGNITO", "APIGATEWAYV2", "IAMPRIVESC", "EXPOSURE",
    "VULN", "THREAT", "DATA", "CORRELATE",
]

SECTION_LABELS = {
    "IAM":            "IDENTITY & ACCESS MANAGEMENT",
    "S3":             "S3 SECURITY",
    "VPC":            "NETWORK SECURITY",
    "LOGGING":        "LOGGING & MONITORING",
    "KMS":            "ENCRYPTION & KMS",
    "EC2":            "COMPUTE SECURITY",
    "AMI":            "MACHINE IMAGES (AMI)",
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
    "EXPOSURE":       "INTERNET EXPOSURE & ATTACK PATHS",
    "VULN":           "WORKLOAD VULNERABILITIES (INSPECTOR)",
    "THREAT":         "LIVE THREAT DETECTIONS (GUARDDUTY)",
    "DATA":           "DATA SECURITY & FLAGSHIP ATTACK PATHS",
    "CORRELATE":      "ATTACK-PATH CORRELATION & CHOKE POINTS",
    "SIDESCAN":       "AGENTLESS WORKLOAD SIDE-SCAN (EBS)",
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
    # Agentless side-scan (CWPP, Phase 6)
    "CWPP-01": "HIGH", "CWPP-02": "CRITICAL", "CWPP-03": "HIGH",
    "IAM-01": "CRITICAL", "IAM-02": "CRITICAL", "IAM-04": "HIGH",
    "IAM-05": "MEDIUM", "IAM-06": "HIGH", "IAM-10": "MEDIUM",
    "IAM-07": "MEDIUM", "IAM-08": "MEDIUM",
    "S3-01": "HIGH", "S3-03": "HIGH", "S3-05": "MEDIUM",
    "S3-07": "MEDIUM", "S3-08": "MEDIUM",
    "VPC-01": "HIGH", "VPC-03": "MEDIUM", "VPC-04": "MEDIUM",
    "LOG-01": "CRITICAL", "LOG-03": "HIGH", "LOG-04": "CRITICAL", "LOG-05": "MEDIUM",
    "LOG-06": "MEDIUM",
    "ENC-03": "MEDIUM",
    "KMS-03": "HIGH",
    "EC2-04": "HIGH", "EC2-05": "MEDIUM", "EC2-06": "HIGH",
    "EC2-07": "HIGH", "EC2-08": "HIGH",
    "AMI-01": "HIGH",
    "CNT-01": "MEDIUM", "CNT-02": "HIGH",
    "BCK-01": "MEDIUM",
    "RDS-01": "HIGH", "RDS-02": "CRITICAL", "RDS-03": "MEDIUM",
    "RDS-04": "MEDIUM", "RDS-05": "LOW", "RDS-06": "CRITICAL",
    "RDS-08": "MEDIUM", "RDS-11": "HIGH",
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
    "ELB-04": "LOW", "ELB-05": "MEDIUM", "ELB-07": "MEDIUM",
    "EBS-01": "HIGH", "EBS-02": "HIGH", "EBS-03": "MEDIUM", "EBS-04": "CRITICAL",
    "RS-01": "HIGH", "RS-02": "HIGH", "RS-03": "MEDIUM", "RS-04": "MEDIUM", "RS-05": "LOW",
    "EFS-01": "HIGH", "EFS-02": "MEDIUM", "EFS-03": "LOW",
    "ACM-01": "HIGH", "ACM-02": "MEDIUM", "ACM-03": "LOW",
    "ACM-04": "HIGH", "ACM-05": "MEDIUM",
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
    # Graph-derived (Phase 1): transitive chains + dangerous trust
    "IAMPE-21": "HIGH", "IAMPE-22": "HIGH",
    # Phase 2: effective internet exposure + attack paths
    "EXPOSURE-01": "HIGH", "EXPOSURE-02": "MEDIUM", "ATTACK-01": "CRITICAL",
    # Phase 3: deep-plane ingestion (vuln / data / threat) + flagship attack path
    "VULN-01": "HIGH", "VULN-02": "CRITICAL", "VULN-03": "HIGH",
    "VULN-04": "HIGH",
    "DATA-01": "MEDIUM", "DATA-02": "HIGH", "DATA-03": "MEDIUM",
    "EXTACCESS-01": "HIGH", "EXTACCESS-02": "MEDIUM", "EXTACCESS-03": "MEDIUM",
    "THREAT-01": "HIGH", "THREAT-02": "MEDIUM", "ATTACK-02": "CRITICAL",
    # Phase 4: correlation & choke points (HIGH — the toxic combos already carry
    # CRITICAL via ATTACK-01/02; CHOKEPOINT avoids double-weighting the same risk)
    "CHOKEPOINT-01": "HIGH",
    # Backfilled service checks (previously severity-less on FAIL)
    "CNT-01": "MEDIUM", "BCK-01": "MEDIUM",
    "SNS-01": "MEDIUM", "SNS-02": "HIGH", "SNS-03": "HIGH", "SNS-04": "MEDIUM",
    "SQS-01": "HIGH", "SQS-02": "CRITICAL", "SQS-03": "MEDIUM", "SQS-04": "LOW",
    "GLC-01": "CRITICAL", "GLC-02": "MEDIUM", "GLC-03": "LOW",
    "R53-01": "MEDIUM", "R53-02": "MEDIUM", "R53-03": "HIGH", "R53-04": "LOW", "R53-05": "MEDIUM",
    "DDB-03": "MEDIUM", "DDB-04": "MEDIUM",
    "EKS-04": "MEDIUM", "EKS-05": "MEDIUM",
    "ECS-04": "HIGH", "ECS-05": "MEDIUM",
    "SEC-03": "MEDIUM", "SEC-04": "MEDIUM",
    "WAF-03": "MEDIUM", "WAF-04": "MEDIUM",
    "ELC-04": "MEDIUM", "OSR-03": "MEDIUM",
    "SFN-01": "MEDIUM", "SFN-02": "LOW", "SFN-03": "MEDIUM",
    "APIGW-04": "LOW", "ELB-04": "LOW", "RS-05": "LOW",
    "ACM-03": "LOW", "COG-04": "LOW", "AGW2-03": "LOW",
    "LMB-05": "MEDIUM",
}

# ─── Compliance mapping: check_id → { framework: control } ──────────────────
COMPLIANCE_MAP = {
    # Agentless side-scan (CWPP, Phase 6)
    "CWPP-01": {"NIST": "RA-5", "PCI-DSS": "6.3.1", "SOC2": "CC7.1"},
    "CWPP-02": {"NIST": "SI-2", "PCI-DSS": "11.3.1", "SOC2": "CC7.1"},
    "CWPP-03": {"NIST": "IA-5", "PCI-DSS": "8.3.1", "SOC2": "CC6.1"},
    # IAM
    "IAM-01": {"CIS": "1.5", "PCI-DSS": "8.3.1", "HIPAA": "164.312(d)", "SOC2": "CC6.1", "NIST": "IA-2(1)"},
    "IAM-02": {"CIS": "1.4", "PCI-DSS": "8.2.2", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.1", "NIST": "IA-2"},
    "IAM-04": {"CIS": "1.10", "PCI-DSS": "8.3.1", "HIPAA": "164.312(d)", "SOC2": "CC6.1", "NIST": "IA-2(1)"},
    "IAM-05": {"CIS": "1.8", "PCI-DSS": "8.3.6", "HIPAA": "164.312(a)(2)(i)", "SOC2": "CC6.1", "NIST": "IA-5(1)"},
    "IAM-06": {"CIS": "1.14", "PCI-DSS": "8.6.3", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.2", "NIST": "IA-5(1)"},
    "IAM-07": {"CIS": "1.7", "SOC2": "CC6.1", "NIST": "AC-6(5)"},
    "IAM-08": {"CIS": "1.12", "PCI-DSS": "8.2.6", "HIPAA": "164.312(a)(2)(i)", "SOC2": "CC6.1", "NIST": "AC-2(3)"},
    "IAM-10": {"CIS": "1.20", "PCI-DSS": "11.5", "HIPAA": "164.312(b)", "SOC2": "CC7.1", "NIST": "AC-6"},
    # S3
    "S3-01": {"CIS": "2.1.4", "PCI-DSS": "1.3.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.1", "NIST": "AC-3"},
    "S3-03": {"CIS": "2.1.1", "PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "S3-05": {"CIS": "3.6", "PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "S3-07": {"CIS": "2.1.2", "PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-8"},
    "S3-08": {"CIS": "2.1.3", "PCI-DSS": "10.5.3", "HIPAA": "164.312(c)(1)", "SOC2": "A1.2", "NIST": "CP-9"},
    # VPC
    "VPC-01": {"CIS": "5.2", "PCI-DSS": "1.3.2", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "VPC-03": {"CIS": "3.7", "PCI-DSS": "10.6", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-12"},
    "VPC-04": {"CIS": "5.4", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    # Logging
    "LOG-01": {"CIS": "3.1", "PCI-DSS": "10.1", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "LOG-03": {"CIS": "3.5", "PCI-DSS": "10.5.3", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "CM-8"},
    "LOG-04": {"CIS": "4.15", "PCI-DSS": "11.4", "HIPAA": "164.312(b)", "SOC2": "CC7.3", "NIST": "SI-4"},
    "LOG-06": {"CIS": "4.16", "PCI-DSS": "11.4", "HIPAA": "164.312(b)", "SOC2": "CC7.3", "NIST": "SI-4"},
    "LOG-05": {"CIS": "4.16", "PCI-DSS": "11.5", "HIPAA": "164.312(b)", "SOC2": "CC7.3", "NIST": "SI-4"},
    # KMS
    "ENC-03": {"CIS": "3.8", "PCI-DSS": "3.6.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-12"},
    "KMS-03": {"NIST": "SC-12", "SOC2": "CC6.1", "HIPAA": "164.312(a)(2)(iv)"},
    # EC2
    "EC2-04": {"CIS": "5.6", "PCI-DSS": "2.2.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.1", "NIST": "CM-6"},
    "EC2-05": {"CIS": "5.1", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "EC2-08": {"CIS": "5.6", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "EC2-06": {"CIS": "2.2.1", "PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "EC2-07": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "IA-5"},
    "AMI-01": {"CIS": "2.3.3", "PCI-DSS": "1.3.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.1", "NIST": "AC-3"},
    # RDS
    "RDS-01": {"CIS": "2.3.1", "PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "RDS-02": {"CIS": "2.3.2", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "RDS-03": {"CIS": "2.3.3", "PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(7)", "SOC2": "A1.2", "NIST": "CP-9"},
    "RDS-04": {"CIS": "2.3.3", "PCI-DSS": "2.2.1", "HIPAA": "164.308(a)(7)", "SOC2": "A1.2", "NIST": "CM-6"},
    "RDS-06": {"CIS": "2.3.4", "PCI-DSS": "1.3.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.1", "NIST": "AC-3"},
    "RDS-08": {"PCI-DSS": "8.3.1", "HIPAA": "164.312(d)", "SOC2": "CC6.1", "NIST": "IA-2"},
    "RDS-11": {"CIS": "2.3.1", "PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
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
    "ELB-07": {"PCI-DSS": "6.6", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7(8)"},
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
       for n in (1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 16, 18, 19, 20, 21, 22)},
    # Phase 2 exposure / attack path
    "EXPOSURE-01": {"CIS": "5.2", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "EXPOSURE-02": {"CIS": "5.2", "PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "ATTACK-01":   {"CIS": "5.2", "PCI-DSS": "1.3.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    # Phase 3 deep-plane
    "VULN-01": {"PCI-DSS": "6.3.3", "HIPAA": "164.308(a)(1)(ii)(A)", "SOC2": "CC7.1", "NIST": "SI-2"},
    "VULN-02": {"PCI-DSS": "6.3.3", "HIPAA": "164.308(a)(1)(ii)(A)", "SOC2": "CC7.1", "NIST": "RA-5(2)"},
    "VULN-03": {"PCI-DSS": "6.3.3", "HIPAA": "164.308(a)(1)(ii)(A)", "SOC2": "CC7.1", "NIST": "SI-2"},
    "VULN-04": {"PCI-DSS": "6.3.3", "HIPAA": "164.308(a)(1)(ii)(A)", "SOC2": "CC7.1", "NIST": "SI-2"},
    "DATA-01": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "DATA-02": {"CIS": "2.1.4", "PCI-DSS": "1.3.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.1", "NIST": "AC-3"},
    "DATA-03": {"CIS": "2.1.1", "PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "EXTACCESS-01": {"CIS": "2.1.4", "PCI-DSS": "1.3.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.6", "NIST": "AC-3"},
    "EXTACCESS-02": {"PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"},
    "EXTACCESS-03": {"PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-6"},
    "THREAT-01": {"CIS": "4.15", "PCI-DSS": "11.4", "HIPAA": "164.312(b)", "SOC2": "CC7.3", "NIST": "SI-4"},
    "THREAT-02": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-6"},
    "ATTACK-02": {"CIS": "5.2", "PCI-DSS": "1.3.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "CHOKEPOINT-01": {"CIS": "5.2", "PCI-DSS": "1.3.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.6", "NIST": "CA-8"},
    # ── Backfill: FAIL-capable checks previously missing a compliance mapping ──
    "CNT-01": {"PCI-DSS": "6.3.2", "HIPAA": "164.308(a)(1)(ii)(A)", "SOC2": "CC7.1", "NIST": "RA-5"},
    "CNT-02": {"PCI-DSS": "6.3.3", "HIPAA": "164.308(a)(1)(ii)(A)", "SOC2": "CC7.1", "NIST": "RA-5"},
    "BCK-01": {"PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(7)", "SOC2": "A1.2", "NIST": "CP-9"},
    "SNS-01": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "SNS-02": {"PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"},
    "SNS-03": {"PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"},
    "SNS-04": {"PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-8"},
    "SQS-01": {"PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"},
    "SQS-02": {"PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"},
    "SQS-03": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "GLC-01": {"PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"},
    "GLC-02": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "R53-01": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "R53-02": {"PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-20"},
    "R53-03": {"PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-20"},
    "R53-05": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "DDB-03": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "DDB-04": {"PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(7)", "SOC2": "A1.2", "NIST": "CP-9"},
    "EKS-04": {"PCI-DSS": "6.3.3", "HIPAA": "164.308(a)(5)(ii)(B)", "SOC2": "CC7.1", "NIST": "SI-2"},
    "EKS-05": {"PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"},
    "ECS-04": {"PCI-DSS": "2.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "CM-7"},
    "ECS-05": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "SEC-03": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "SEC-04": {"PCI-DSS": "7.1.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"},
    "WAF-03": {"PCI-DSS": "6.6", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7(8)"},
    "WAF-04": {"PCI-DSS": "6.6", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7(8)"},
    "ELC-04": {"PCI-DSS": "8.2.1", "HIPAA": "164.312(d)", "SOC2": "CC6.1", "NIST": "IA-5"},
    "OSR-03": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "SFN-01": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"},
    "SFN-03": {"PCI-DSS": "3.4", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1", "NIST": "SC-28"},
    "APIGW-04": {"PCI-DSS": "10.2", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-12"},
    "ELB-04": {"PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(7)", "SOC2": "A1.2", "NIST": "CM-6"},
    "RS-05": {"PCI-DSS": "8.2.2", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.1", "NIST": "IA-2"},
    "ACM-03": {"PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-12"},
    "ACM-04": {"PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-12"},
    "ACM-05": {"PCI-DSS": "4.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.7", "NIST": "SC-12"},
    "COG-04": {"PCI-DSS": "12.10.1", "HIPAA": "164.308(a)(7)", "SOC2": "A1.2", "NIST": "CM-6"},
    "AGW2-03": {"PCI-DSS": "6.6", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "SC-5"},
    "LMB-05": {"PCI-DSS": "6.3.2", "HIPAA": "164.308(a)(5)(ii)(B)", "SOC2": "CC7.1", "NIST": "SI-2"},
}

# ─── Remediation commands: check_id → AWS CLI command ────────────────────────
REMEDIATION_MAP = {
    "CWPP-01": "Patch the vulnerable package (CVE reachable on an internet-exposed host — prioritize): aws ssm send-command --document-name AWS-RunPatchBaseline --targets Key=instanceids,Values=<INSTANCE_ID> --parameters Operation=Install, then rebuild the AMI from the patched instance.",
    "CWPP-02": "KEV/exploited CVE on a reachable host — patch immediately or isolate: aws ssm send-command --document-name AWS-RunPatchBaseline --targets Key=instanceids,Values=<INSTANCE_ID> --parameters Operation=Install ; consider aws ec2 stop-instances --instance-ids <INSTANCE_ID> until patched.",
    "CWPP-03": "Rotate/revoke the exposed credential and move it off disk: aws secretsmanager rotate-secret --secret-id <SECRET_ARN> (or aws iam update-access-key / delete-access-key), attach an instance role, and reference AWS Secrets Manager instead of the on-disk file.",
    "IAM-01": "Enable virtual MFA for root: aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa && aws iam enable-mfa-device --user-name root --serial-number <MFA_ARN> --authentication-code1 <CODE1> --authentication-code2 <CODE2>",
    "IAM-02": "Delete root access keys: aws iam delete-access-key --access-key-id <KEY_ID>",
    "IAM-04": "Enable MFA for user: aws iam enable-mfa-device --user-name <USER> --serial-number <MFA_ARN> --authentication-code1 <CODE1> --authentication-code2 <CODE2>",
    "IAM-05": "Update password policy: aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --max-password-age 90 --password-reuse-prevention 24",
    "IAM-06": "Deactivate stale key: aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name <USER>",
    "IAM-07": "Stop using the root user for daily tasks (use IAM roles) and alarm on root usage: aws cloudwatch put-metric-alarm --alarm-name root-account-usage --metric-name RootAccountUsage --namespace CISBenchmark --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold",
    "IAM-08": "Disable credentials unused for 45+ days: aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name <USER> (and remove console access if the password is unused)",
    "IAM-10": "Create Access Analyzer: aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT --region <REGION>",
    "S3-01": "Enable account BPA: aws s3control put-public-access-block --account-id <ACCT> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    "S3-03": "Enable bucket encryption: aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'",
    "S3-05": "Enable access logging: aws s3api put-bucket-logging --bucket <BUCKET> --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"<LOG_BUCKET>\",\"TargetPrefix\":\"s3-logs/\"}}'",
    "S3-07": "Attach a bucket policy that denies non-TLS requests (Effect=Deny, Condition Bool aws:SecureTransport=false) and apply it: aws s3api put-bucket-policy --bucket <BUCKET> --policy file://tls-only.json",
    "S3-08": "Enable versioning for rollback protection against overwrite/ransomware: aws s3api put-bucket-versioning --bucket <BUCKET> --versioning-configuration Status=Enabled",
    "VPC-01": "Revoke risky SG rule: aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port <PORT> --cidr 0.0.0.0/0",
    "VPC-03": "Enable VPC Flow Logs: aws ec2 create-flow-logs --resource-type VPC --resource-ids <VPC_ID> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name vpc-flow-logs",
    "VPC-04": "Strip all rules from each default SG so it denies all traffic (CIS 5.4): aws ec2 revoke-security-group-ingress --group-id <SG_ID> --ip-permissions ... and aws ec2 revoke-security-group-egress --group-id <SG_ID> --ip-permissions ... ; migrate workloads to purpose-built SGs",
    "LOG-01": "Create multi-region trail: aws cloudtrail create-trail --name org-trail --s3-bucket-name <BUCKET> --is-multi-region-trail --enable-log-file-validation && aws cloudtrail start-logging --name org-trail",
    "LOG-03": "Start Config recorder: aws configservice start-configuration-recorder --configuration-recorder-name default",
    "LOG-04": "Enable GuardDuty: aws guardduty create-detector --enable",
    "LOG-06": "Turn on the missing GuardDuty protection plan(s): aws guardduty update-detector --detector-id <DETECTOR_ID> --features '[{\"Name\":\"<FEATURE>\",\"Status\":\"ENABLED\"}]' (e.g. S3_DATA_EVENTS, RUNTIME_MONITORING, EBS_MALWARE_PROTECTION)",
    "LOG-05": "Enable Security Hub: aws securityhub enable-security-hub --enable-default-standards",
    "ENC-03": "Enable key rotation: aws kms enable-key-rotation --key-id <KEY_ID>",
    "KMS-03": "Cancel deletion if the CMK is still in use, or re-enable a disabled key: aws kms cancel-key-deletion --key-id <KEY_ID> ; aws kms enable-key --key-id <KEY_ID>",
    "EC2-04": "Enforce IMDSv2: aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens required --http-endpoint enabled",
    "EC2-06": "Enable default EBS encryption: aws ec2 enable-ebs-encryption-by-default",
    "EC2-07": "Remove the secret from user-data and rotate it; move it to SSM Parameter Store / Secrets Manager referenced at boot: aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --user-data file://sanitized-userdata.txt (stop the instance first)",
    "EC2-08": "Enforce IMDSv2 AND remove the public exposure (SSRF->credential path): aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens required --http-endpoint enabled ; then place the instance behind a load balancer / remove the public IP",
    "RDS-01": "Create encrypted copy: aws rds create-db-snapshot --db-instance-identifier <DB_ID> --db-snapshot-identifier pre-encrypt-snap && aws rds copy-db-snapshot --source-db-snapshot-identifier pre-encrypt-snap --target-db-snapshot-identifier encrypted-snap --kms-key-id <KMS_KEY>",
    "RDS-02": "Disable public access: aws rds modify-db-instance --db-instance-identifier <DB_ID> --no-publicly-accessible",
    "RDS-04": "Enable deletion protection: aws rds modify-db-instance --db-instance-identifier <DB_ID> --deletion-protection",
    "RDS-06": "Remove public access from snapshot: aws rds modify-db-snapshot-attribute --db-snapshot-identifier <SNAP_ID> --attribute-name restore --values-to-remove all",
    "RDS-08": "Enable IAM database authentication so short-lived IAM tokens replace static passwords: aws rds modify-db-instance --db-instance-identifier <DB_ID> --enable-iam-database-authentication --apply-immediately",
    "RDS-11": "Recreate the snapshot encrypted (copy with a KMS key, then delete the plaintext one): aws rds copy-db-snapshot --source-db-snapshot-identifier <SNAP_ID> --target-db-snapshot-identifier <SNAP_ID>-enc --kms-key-id <KMS_KEY>",
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
    "ELB-07": "Harden HTTP desync mitigation against request smuggling: aws elbv2 modify-load-balancer-attributes --load-balancer-arn <LB_ARN> --attributes Key=routing.http.desync_mitigation_mode,Value=defensive",
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
    "ACM-04": "Re-request the failed/revoked certificate: aws acm request-certificate --domain-name <DOMAIN> --validation-method DNS",
    "ACM-05": "Migrate imported / non-auto-renewing certs to an ACM-managed (auto-renewing) certificate: aws acm request-certificate --domain-name <DOMAIN> --validation-method DNS",
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
    "IAMPE-21": "Break the escalation chain at its weakest hop: remove the privesc-granting permission from the assumable target role, OR restrict who can assume it (aws iam update-assume-role-policy --role-name <ROLE> --policy-document <TIGHTER_TRUST>). Apply a permissions boundary to the chain's entry principal.",
    "IAMPE-22": "Restrict the role trust policy to specific principal ARNs (remove Principal '*'): aws iam update-assume-role-policy --role-name <ROLE> --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"<TRUSTED_ARN>\"},\"Action\":\"sts:AssumeRole\",\"Condition\":{\"StringEquals\":{\"sts:ExternalId\":\"<ID>\"}}}]}'",
    "CNT-01": "Enable scan-on-push and pull existing findings: aws ecr put-image-scanning-configuration --repository-name <REPO> --image-scanning-configuration scanOnPush=true",
    "CNT-02": "Rebuild the image on a patched base and push the new digest; delete the vulnerable image: aws ecr batch-delete-image --repository-name <REPO> --image-ids imageDigest=<DIGEST>. Enable Inspector enhanced scanning for continuous coverage.",
    "AMI-01": "Revoke public/cross-account AMI sharing (a public AMI exposes its full disk snapshot): aws ec2 modify-image-attribute --image-id <AMI_ID> --launch-permission '{\"Remove\":[{\"Group\":\"all\"}]}' ; audit remaining account-level shares.",
    "GLC-01": "Remove public Glacier vault access policy: aws glacier set-vault-access-policy --vault-name <VAULT> --policy '{\"Policy\":\"<LEAST_PRIVILEGE_POLICY>\"}'",
    "SQS-02": "Restrict the queue policy to trusted principals: aws sqs set-queue-attributes --queue-url <URL> --attributes Policy='<LEAST_PRIVILEGE_POLICY>'",
    "R53-03": "Enable DNSSEC signing: aws route53 enable-hosted-zone-dnssec --hosted-zone-id <ZONE_ID>",
    "DDB-04": "Enable deletion protection: aws dynamodb update-table --table-name <TABLE> --deletion-protection-enabled",
    "ECS-04": "Recreate the task definition with awsvpc network mode (drop host mode): aws ecs register-task-definition --network-mode awsvpc --cli-input-json file://taskdef.json",
    "EXPOSURE-01": "Restrict the security group ingress from 0.0.0.0/0 to known source ranges: aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port <PORT> --cidr 0.0.0.0/0  (then re-add a scoped CIDR)",
    "EXPOSURE-02": "Restrict the security group ingress from 0.0.0.0/0 to known source ranges or place the workload behind a load balancer/WAF: aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port <PORT> --cidr 0.0.0.0/0",
    "ATTACK-01": "Break the path at the exposure or the privilege: remove the public ingress (aws ec2 revoke-security-group-ingress ...) AND scope the instance-profile role to least privilege / apply a permissions boundary: aws iam put-role-permissions-boundary --role-name <ROLE> --permissions-boundary <BOUNDARY_ARN>",
    "VULN-01": "Patch the affected package to fixedInVersion, e.g. run the patch baseline: aws ssm send-command --document-name AWS-RunPatchBaseline --targets Key=InstanceIds,Values=<INSTANCE_ID> --parameters Operation=Install, then re-scan in Inspector.",
    "VULN-02": "PRIORITIZE — this CVE is on the CISA KEV catalog (actively exploited). Patch immediately (aws ssm send-command --document-name AWS-RunPatchBaseline --targets Key=InstanceIds,Values=<INSTANCE_ID> --parameters Operation=Install), and if internet-exposed isolate the host: aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <QUARANTINE_SG>",
    "VULN-03": "Rebuild the container image on a patched base and push; enable Inspector enhanced ECR scanning: aws inspector2 enable --resource-types ECR",
    "VULN-04": "Update the vulnerable dependency in the Lambda deployment package/layer and redeploy: aws lambda update-function-code --function-name <FUNCTION> --zip-file fileb://patched.zip, then re-scan in Inspector.",
    "DATA-01": "Confirm the sensitive data is intended here; restrict access, enable default encryption with a CMK, and enable S3 Block Public Access on the bucket: aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    "DATA-02": "Remove public/external access from the crown-jewel bucket: aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    "DATA-03": "Enable default encryption on the crown-jewel bucket: aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'",
    "EXTACCESS-01": "Remove the public bucket policy / ACL grant (Access Analyzer confirmed public): aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    "EXTACCESS-02": "Scope the bucket policy to remove the cross-account principal (or add an aws:PrincipalOrgID condition): aws s3api put-bucket-policy --bucket <BUCKET> --policy <SCOPED_POLICY_JSON>",
    "EXTACCESS-03": "Scope the role's S3 permissions to specific buckets/prefixes instead of s3:GetObject on '*' or 'bucket/*', and bound the role: aws iam put-role-permissions-boundary --role-name <ROLE> --permissions-boundary <BOUNDARY_ARN> (identity-policy only — also verify the bucket policy / SCP).",
    "THREAT-01": "Triage the GuardDuty finding, then isolate/rotate as needed: aws guardduty get-findings --detector-id <DETECTOR_ID> --finding-ids <FINDING_ID>; if confirmed, quarantine the resource and rotate exposed credentials. Do not archive without triage.",
    "THREAT-02": "Confirm whether the control-plane event was authorized (aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=<EVENT>), and enable continuous detection: aws guardduty create-detector --enable",
    "ATTACK-02": "Sever the flagship chain at ANY hop: patch the exploitable CVE, remove the public ingress (aws ec2 revoke-security-group-ingress --group-id <SG> --protocol tcp --port <PORT> --cidr 0.0.0.0/0), and scope the instance-profile role's data access (aws iam put-role-permissions-boundary --role-name <ROLE> --permissions-boundary <BOUNDARY_ARN>). Fixing the choke-point node breaks the whole path.",
    "CHOKEPOINT-01": "Remediate this single node to sever multiple attack paths at once: for an over-privileged role, aws iam put-role-permissions-boundary --role-name <ROLE> --permissions-boundary <BOUNDARY_ARN>; for an exposed host, patch the exploitable CVE or aws ec2 revoke-security-group-ingress ...; see the finding for the node kind and the count of paths/crown-jewels it severs.",
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


def _pivot_conditioned(statements: List[Dict], pivot: str) -> bool:
    """True when EVERY Allow statement that grants the pivot action carries a
    policy Condition. Such a path is only exploitable if the caller can satisfy
    the condition (MFA, tag, SourceIp, ExternalId…), so it is downgraded from a
    hard FAIL to a WARN ('verify the condition') rather than dropped."""
    granting = [st for st in statements
                if st["effect"] == "Allow" and _stmt_actions_match(st, pivot)]
    return bool(granting) and all(st.get("condition") for st in granting)


def parse_trust_policy(doc) -> List[Dict]:
    """Parse a role's AssumeRolePolicyDocument into normalized trust statements:
    ``[{effect, aws:[arns], service:[svcs], federated:[...], wildcard:bool,
    actions:set, has_condition:bool}]``. Accepts a URL-encoded string or a dict;
    ``Principal`` may be ``"*"``, a dict of AWS/Service/Federated, or a
    single/list value. Used to build CAN_ASSUME graph edges."""
    out: List[Dict] = []
    if not doc:
        return out
    if isinstance(doc, str):
        try:
            doc = json.loads(unquote(doc))
        except Exception:
            return out
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    def _as_list(v):
        return [v] if isinstance(v, str) else list(v)

    for st in stmts:
        if not isinstance(st, dict):
            continue
        eff = st.get("Effect", "")
        if eff not in ("Allow", "Deny"):
            continue
        pr = st.get("Principal", "")
        aws, svc, fed, wildcard = [], [], [], False
        if pr == "*":
            wildcard = True
        elif isinstance(pr, dict):
            if "AWS" in pr:
                for v in _as_list(pr["AWS"]):
                    if v == "*":
                        wildcard = True
                    else:
                        aws.append(v)
            if "Service" in pr:
                svc = _as_list(pr["Service"])
            if "Federated" in pr:
                fed = _as_list(pr["Federated"])
        av = st.get("Action", [])
        actions = {str(a).lower() for a in _as_list(av)} if av else set()
        out.append({"effect": eff, "aws": aws, "service": svc, "federated": fed,
                    "wildcard": wildcard, "actions": actions,
                    "has_condition": bool(st.get("Condition"))})
    return out


def _account_of(arn: str) -> str:
    """Account id segment of an ARN (arn:partition:service:region:account:...)."""
    parts = arn.split(":")
    return parts[4] if len(parts) >= 5 else ""


def evaluate_privesc_scoped(statements: List[Dict], boundary: Optional[List[Dict]] = None,
                            scp_levels: Optional[List] = None,
                            pruned: Optional[List[Dict]] = None) -> List[Dict]:
    """Resource-aware privesc evaluation. Returns matched rules annotated with
    `scope` (account-wide | resource-scoped) and `scope_arns`. Reduces false
    positives vs the action-level model: full admin requires Action '*' on
    Resource '*', and sts:AssumeRole is only flagged when unrestricted.

    Phase 5: when a permission `boundary` and/or `scp_levels` ceiling is supplied,
    each matched pivot is passed through the effective-permissions solver:
    a pivot the ceiling provably neutralizes (unconditional deny / not-allowed) is
    DROPPED (and recorded in `pruned` if given); a pivot gated only by a Condition
    on the boundary/SCP is downgraded to `conditioned`. With both ceilings None
    (the default), no pivot is ever dropped -> byte-for-byte identical to before.

    NB: when the '*' megapivot of a full-admin identity is itself capped by the
    ceiling, we do NOT return []; we fall through and enumerate the granular IAM
    pivots that survive the ceiling — otherwise a boundary/SCP-capped admin would
    hide every real escalation it still holds (the dangerous over-prune)."""

    def _verdict(pivot: str) -> str:
        return aws_effperm.pivot_effective(pivot, statements, boundary, scp_levels)

    def _record_drop(pivot: str, rule_id: str) -> None:
        if pruned is not None:
            pruned.append({"pivot": pivot, "rule": rule_id,
                           "reason": aws_effperm.drop_reason(
                               pivot, statements, boundary, scp_levels)})

    if _has_full_admin(statements):
        v = _verdict("*")
        if v != aws_effperm.DROP:
            return [{**IAM_PRIVESC_FULL_ADMIN, "scope": "account-wide",
                     "scope_arns": None, "pivot": "*",
                     "conditioned": _pivot_conditioned(statements, "*") or v == aws_effperm.CONDITIONED,
                     "effperm": v}]
        # Ceiling caps the '*' megapivot — record it, then fall through to find
        # the granular pivots (iam:AttachUserPolicy, PassRole, …) that survive.
        _record_drop("*", IAM_PRIVESC_FULL_ADMIN["id"])

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
            v = _verdict(pivot)
            if v == aws_effperm.DROP:
                _record_drop(pivot, rule["id"])   # ceiling neutralizes it
                continue
            findings.append({**rule, "scope": label, "scope_arns": arns,
                             "pivot": pivot,
                             "conditioned": _pivot_conditioned(statements, pivot)
                             or v == aws_effperm.CONDITIONED,
                             "effperm": v})

    # IAMPE-20: only when sts:AssumeRole is granted account-wide
    if _action_allowed("sts:assumerole", allow, deny):
        label, arns = resource_scope(statements, "sts:assumerole")
        if label == "account-wide":
            v = _verdict("sts:assumerole")
            if v == aws_effperm.DROP:
                _record_drop("sts:assumerole", IAM_PRIVESC_ASSUMEROLE["id"])
            else:
                findings.append({**IAM_PRIVESC_ASSUMEROLE, "scope": label,
                                 "scope_arns": None, "pivot": "sts:assumerole",
                                 "conditioned": _pivot_conditioned(statements, "sts:assumerole")
                                 or v == aws_effperm.CONDITIONED,
                                 "effperm": v})
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


# ─── Compliance rollup (per-framework control pass/fail) ─────────────────────
COMPLIANCE_FRAMEWORKS = ["CIS", "PCI-DSS", "HIPAA", "SOC2", "NIST"]


def compliance_scorecard(results: List[Result],
                         compliance_map: Optional[Dict] = None) -> Dict[str, Dict]:
    """Aggregate per-finding compliance tags into a per-framework control rollup.

    The control *universe* is every control declared in ``COMPLIANCE_MAP`` (so
    coverage is stable regardless of which checks fired). A control is marked
    FAILED if any FAIL or WARN result references it, otherwise PASSED. Returns
    ``{framework: {controls_total, controls_passed, controls_failed, pass_rate,
    failed_controls}}``.
    """
    cmap = compliance_map if compliance_map is not None else COMPLIANCE_MAP
    universe = {f: set() for f in COMPLIANCE_FRAMEWORKS}
    for comp in cmap.values():
        for f, ctrl in (comp or {}).items():
            if f in universe and ctrl:
                universe[f].add(ctrl)

    failed = {f: set() for f in COMPLIANCE_FRAMEWORKS}
    for r in results:
        if r.status in ("FAIL", "WARN"):
            for f, ctrl in (r.compliance or {}).items():
                if f in failed and ctrl:
                    failed[f].add(ctrl)

    out: Dict[str, Dict] = {}
    for f in COMPLIANCE_FRAMEWORKS:
        controls = universe[f] | failed[f]        # a stray tag still counts
        fail = failed[f] & controls
        total = len(controls)
        passed = total - len(fail)
        out[f] = {
            "controls_total":   total,
            "controls_passed":  passed,
            "controls_failed":  len(fail),
            "pass_rate":        round(100 * passed / total, 1) if total else 100.0,
            "failed_controls":  sorted(fail),
        }
    return out


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


# ─── IAM credential-report age helpers (used by IAM-06/07/08) ────────────────
def _cred_age_days(iso_ts: str) -> Optional[int]:
    """Days since an IAM credential-report timestamp, or None when the field is
    empty / 'N/A' / 'no_information' / 'not_supported' or unparseable."""
    if not iso_ts or iso_ts in ("N/A", "no_information", "not_supported"):
        return None
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(iso_ts)).days
    except Exception:
        return None


def _cred_idle_days(last_used: str, created: str) -> Optional[int]:
    """How long a credential has been idle: days since last use, or (if never used)
    days since it was created/rotated. None if neither timestamp is usable, so the
    caller skips the credential rather than false-flagging it."""
    d = _cred_age_days(last_used)
    return d if d is not None else _cred_age_days(created)


# ─── Scanner ──────────────────────────────────────────────────────────────────
class AWSLiveScanner:
    """Live, read-only AWS security audit scanner."""

    # Sections that enumerate global (region-agnostic) resources — run once even
    # when --all-regions sweeps every enabled region for the rest.
    GLOBAL_SECTIONS = {"IAM", "S3", "ROUTE53", "CLOUDFRONT", "IAMPRIVESC", "CORRELATE"}

    def __init__(
        self,
        region:   str = "eu-west-1",
        verbose:  bool = False,
        sections: Optional[List[str]] = None,
        session:  object = None,
        all_regions: bool = False,
    ):
        self.region   = region
        self.verbose  = verbose
        self.sections = [s.upper() for s in sections] if sections else list(SECTIONS)
        self.results:  List[Result] = []
        self.account   = ""
        self._session  = session          # boto3.Session for assumed-role scans; None = ambient creds
        self.all_regions_scan = all_regions
        self.graph: Optional[SecurityGraph] = None
        self.attack_paths: List = []       # ranked AttackPath objects (Phase 4 correlate)
        self.choke_points: List = []       # ranked ChokePoint objects
        self._clients: Dict[str, object] = {}
        self._cred_report:  Optional[List[Dict]] = None
        self._cred_report_ok: bool = False
        self._all_regions:  Optional[List[str]]  = None
        self._iam_principals: Optional[List[Dict]] = None
        self._managed_policy_cache: Dict[str, tuple] = {}
        # ── Phase 5: effective-permissions ceiling refinement ────────────────
        self._scp_context: Optional[List] = None    # ordered SCP levels root->acct
        self._scp_fetched = False                   # None is a valid result -> sentinel
        self._boundary_evaluated = False            # a boundary doc was resolved
        self._scp_evaluated = False                 # SCP layer was evaluated
        self._pruned_edges: List[Dict] = []         # edges dropped by the ceiling
        self._downgraded_edges: List[Dict] = []     # edges downgraded to conditioned
        self._state_report: Optional[Dict] = None   # lifecycle/drift/trend/mttr (if --state)
        self._unused_report: Optional[List] = None  # CIEM right-sizing signals
        # ── Phase 6: agentless side-scan + persistence/export metadata ───────
        self.side_scan = False                      # --side-scan opt-in
        self.side_scan_targets = "exposed"          # exposed | all | tagged
        self.side_scan_tags: List[str] = []
        self.side_scan_max = 20                     # hard target ceiling
        self.side_scan_secrets = True
        self.vuln_db_path: Optional[str] = None
        self._side_scan_report: Optional[Dict] = None
        self._backend_meta: Optional[Dict] = None
        self._graph_export_meta: Optional[Dict] = None
        self._sidescan_extractor_opener = None      # test seam: (vol_ids, iid) -> CM
        self._remediation_report: Optional[Dict] = None   # Phase 7 --remediate
        self._code_to_cloud_meta: Optional[Dict] = None

    # ── boto3 client factory (lazy, cached) ───────────────────────────────────
    def _client(self, service: str, region: Optional[str] = None):
        if not HAS_BOTO3:
            raise ImportError(
                "boto3 is not installed. Run: pip install boto3"
            )
        key = f"{service}:{region or self.region}"
        if key not in self._clients:
            factory = self._session or boto3  # assumed-role session or ambient creds
            self._clients[key] = factory.client(  # type: ignore[name-defined]
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
        # None (not []) records "could not evaluate" so credential checks can tell an
        # empty account apart from an unavailable report and avoid a false all-clear.
        self._cred_report_ok = False
        try:
            iam = self._client("iam")
            # generate_credential_report is async; poll its State rather than a fixed
            # sleep (a fresh/large account is not COMPLETE within a few seconds).
            for attempt in range(20):
                state = iam.generate_credential_report().get("State", "")
                if state == "COMPLETE":
                    break
                time.sleep(3)
            resp    = iam.get_credential_report()
            content = base64.b64decode(resp["Content"]).decode("utf-8")
            self._cred_report = list(csv.DictReader(io.StringIO(content)))
            self._cred_report_ok = True
        except Exception as e:
            # one retry: get_credential_report can still be ReportInProgress
            try:
                time.sleep(5)
                resp    = iam.get_credential_report()
                content = base64.b64decode(resp["Content"]).decode("utf-8")
                self._cred_report = list(csv.DictReader(io.StringIO(content)))
                self._cred_report_ok = True
            except Exception:
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

        # IAM-07 — Root account recent use (CIS 1.7); zero new API (cached report)
        self._log("IAM-07: Root account recent use")
        report = self._get_credential_report()
        root = next((r for r in report if r.get("user") == "<root_account>"), None)
        if root:
            recent = []
            for f in ("password_last_used", "access_key_1_last_used_date",
                      "access_key_2_last_used_date"):
                d = _cred_age_days(root.get(f, ""))
                if d is not None and d <= 30:
                    recent.append(f"{f.replace('_last_used_date','').replace('_',' ')}={d}d")
            if recent:
                self._add("FAIL", "IAM-07", "IAM", "root",
                          f"Root account used within 30 days ({', '.join(recent)}) — "
                          f"CIS 1.7: use IAM roles, not root, for daily tasks")
            else:
                self._add("PASS", "IAM-07", "IAM", "root",
                          "No root credential use in the last 30 days")
        elif not self._cred_report_ok:
            # never silently skip — tell the operator the root audit could not run
            self._add("WARN", "IAM-07", "IAM", "root",
                      "Credential report unavailable — IAM-07/08 root & unused-credential "
                      "audit could not be evaluated (retry the scan)")

        # IAM-08 — Credentials unused for 45+ days (CIS 1.12); zero new API
        self._log("IAM-08: Credentials unused for 45+ days")
        for row in self._get_credential_report():
            user = row.get("user", "")
            if user == "<root_account>":
                continue
            if row.get("password_enabled") == "true":
                # never-used fallback = the password's own age (password_last_changed),
                # not the user's age — a freshly set unused password isn't "45d unused".
                idle = _cred_idle_days(row.get("password_last_used", ""),
                                       row.get("password_last_changed", ""))
                if idle is not None and idle > 45:
                    self._add("FAIL", "IAM-08", "IAM", user,
                              f"Console password unused {idle}d (>45) — disable it | {user}")
            for k in ("access_key_1", "access_key_2"):
                if row.get(f"{k}_active") == "true":
                    idle = _cred_idle_days(row.get(f"{k}_last_used_date", ""),
                                           row.get(f"{k}_last_rotated", ""))
                    if idle is not None and idle > 45:
                        self._add("FAIL", "IAM-08", "IAM", f"{user}/{k}",
                                  f"{k} unused {idle}d (>45) — deactivate it | {user}")

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

            # S3-07 — TLS-only (deny non-SecureTransport) bucket policy
            try:
                pol   = json.loads(s3.get_bucket_policy(Bucket=bname)["Policy"])
                stmts = pol.get("Statement", [])
                if isinstance(stmts, dict):
                    stmts = [stmts]
                if any(self._stmt_denies_insecure_transport(st, bname) for st in stmts):
                    self._add("PASS", "S3-07", "S3", bname,
                              f"Bucket policy denies non-TLS access | {bname}")
                else:
                    self._add("WARN", "S3-07", "S3", bname,
                              f"Bucket policy does NOT enforce TLS "
                              f"(no aws:SecureTransport deny) | {bname}")
            except Exception:
                self._add("WARN", "S3-07", "S3", bname,
                          f"No bucket policy enforcing TLS-only access | {bname}")

            # S3-08 — Versioning (rollback protection vs overwrite/ransomware)
            try:
                ver = s3.get_bucket_versioning(Bucket=bname).get("Status")
                if ver == "Enabled":
                    self._add("PASS", "S3-08", "S3", bname,
                              f"Versioning enabled | {bname}")
                else:
                    self._add("WARN", "S3-08", "S3", bname,
                              f"Versioning not enabled — no rollback from object "
                              f"overwrite/ransomware | {bname}")
            except Exception:
                pass

    @staticmethod
    def _stmt_denies_insecure_transport(st: Dict, bucket: str = "") -> bool:
        """True only if a bucket-policy statement EFFECTIVELY denies all non-TLS
        access: Effect=Deny + aws:SecureTransport=false, applied to EVERY principal,
        ALL S3 actions, and at least the object-level resource (bucket/*). A
        narrowly-scoped deny (single action/principal/resource) does NOT count —
        plaintext HTTP to other actions/objects would still be possible."""
        if st.get("Effect") != "Deny":
            return False
        # (a) aws:SecureTransport=false condition (Bool / BoolIfExists, str or list)
        cond = st.get("Condition", {}) or {}
        has_cond = False
        for op in ("Bool", "BoolIfExists"):
            val = (cond.get(op) or {}).get("aws:SecureTransport")
            if val is None:
                continue
            vals = val if isinstance(val, list) else [val]
            if any(str(v).lower() == "false" for v in vals):
                has_cond = True
                break
        if not has_cond:
            return False
        # (b) every principal ("*" or {"AWS": "*"})
        princ = st.get("Principal")
        if princ != "*":
            if not isinstance(princ, dict):
                return False
            aws_p = princ.get("AWS")
            aws_list = aws_p if isinstance(aws_p, list) else [aws_p]
            if "*" not in aws_list:
                return False
        # (c) all S3 actions ("s3:*" or "*")
        actions = st.get("Action", [])
        actions = actions if isinstance(actions, list) else [actions]
        if not any(a in ("*", "s3:*") for a in actions):
            return False
        # (d) at least the object-level resource (bucket/*, an /* wildcard, or "*")
        res = st.get("Resource", [])
        res = res if isinstance(res, list) else [res]
        obj_arn = f"arn:aws:s3:::{bucket}/*" if bucket else None
        return any(r == "*" or (isinstance(r, str) and r.endswith("/*")) or r == obj_arn
                   for r in res)

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
        # VPC-04 — default Security Group must restrict all traffic (CIS 5.4)
        self._log("VPC-01: Security Groups — risky ports open to 0.0.0.0/0 or ::/0")
        found_any = False
        default_seen = False
        default_sg_issues = []
        try:
            for sg in self._paginate_all(ec2, "describe_security_groups", "SecurityGroups"):
                if sg.get("GroupName") == "default":
                    default_seen = True
                    inbound  = sg.get("IpPermissions", [])
                    outbound = sg.get("IpPermissionsEgress", [])
                    if inbound or outbound:
                        default_sg_issues.append(
                            (f"{sg['GroupId']} (vpc {sg.get('VpcId', '?')})",
                             len(inbound), len(outbound)))
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

        for res, ni, no in default_sg_issues:
            self._add("WARN", "VPC-04", "VPC", res,
                      f"Default SG has {ni} inbound / {no} outbound rule(s) — CIS 5.4 "
                      f"requires it to restrict ALL traffic | {res}")
        if default_seen and not default_sg_issues:
            self._add("PASS", "VPC-04", "VPC", "default-sgs",
                      "All default Security Groups restrict all traffic (no rules)")

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
                        self._check_guardduty_features(did, d)
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

    # GuardDuty protection plans expected enabled for full threat coverage
    _GD_FEATURES = {
        "S3_DATA_EVENTS":         "S3 Protection",
        "EKS_AUDIT_LOGS":         "EKS Audit Log Monitoring",
        "EBS_MALWARE_PROTECTION": "Malware Protection (EBS)",
        "RDS_LOGIN_EVENTS":       "RDS Protection",
        "LAMBDA_NETWORK_LOGS":    "Lambda Protection",
        "RUNTIME_MONITORING":     "Runtime Monitoring",
    }

    def _check_guardduty_features(self, did: str, detector: Dict) -> None:
        """LOG-06 — GuardDuty protection plans. An ENABLED detector still leaves
        S3/EKS/malware/RDS/Lambda/runtime coverage off unless each feature is
        explicitly enabled. Silent on the legacy API that omits the feature list."""
        feats = {f.get("Name"): f.get("Status") for f in detector.get("Features", [])}
        if not feats:
            return
        for name, label in self._GD_FEATURES.items():
            if name not in feats:
                continue
            if feats[name] == "ENABLED":
                self._add("PASS", "LOG-06", "LOGGING", f"{did}:{name}",
                          f"GuardDuty {label} ENABLED | {did}")
            else:
                self._add("WARN", "LOG-06", "LOGGING", f"{did}:{name}",
                          f"GuardDuty {label} DISABLED — reduced threat coverage | {did}")

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
                        # KMS-03 — CMK pending deletion / disabled (data-access risk)
                        if meta.get("KeyManager") == "CUSTOMER":
                            _st = meta.get("KeyState")
                            _dsc = meta.get("Description") or kid[:8]
                            if _st in ("PendingDeletion", "PendingReplicaDeletion"):
                                self._add("FAIL", "KMS-03", "KMS", kid,
                                          f"CMK scheduled for deletion "
                                          f"({meta.get('DeletionDate','')}) — irreversible "
                                          f"data loss if still in use | {_dsc}")
                            elif _st == "Disabled":
                                self._add("FAIL", "KMS-03", "KMS", kid,
                                          f"CMK is disabled — ciphertext under this key "
                                          f"cannot be decrypted | {_dsc}")
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
    def _scan_ec2_user_data(self, ec2, iid: str, name: str) -> None:
        """EC2-07 — secrets embedded in instance user-data. User-data is readable by
        anything that can reach IMDS on the host (and via the console/API), so an
        embedded credential is effectively plaintext-at-rest on every boot."""
        try:
            ud = ec2.describe_instance_attribute(
                InstanceId=iid, Attribute="userData"
            ).get("UserData", {}).get("Value")
        except Exception:
            return
        if not ud:
            return
        try:
            raw = base64.b64decode(ud)
        except Exception:
            return
        if raw[:2] == b"\x1f\x8b":                     # gzip (cloud-init) — best-effort inflate
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        for sec in aws_sidescan.scan_text_secrets(raw, source=f"userdata:{iid}"):
            self._add("FAIL", "EC2-07", "EC2", name,
                      f"Secret in user-data ({sec.kind}, preview {sec.match_preview}) "
                      f"— readable via IMDS/console | {iid}")

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
                        # EC2-08 — SSRF->credential choke: public IP + reachable IMDSv1
                        # + an attached role to steal (all facts in hand; no extra API).
                        endpoint = i.get("MetadataOptions", {}).get("HttpEndpoint", "enabled")
                        has_role = bool(i.get("IamInstanceProfile"))
                        if (tokens != "required" and endpoint == "enabled"
                                and i.get("PublicIpAddress") and has_role):
                            self._add("FAIL", "EC2-08", "EC2", name,
                                      f"SSRF-to-credential exposure: public IP "
                                      f"{i['PublicIpAddress']} + IMDSv1 "
                                      f"(HttpTokens={tokens}) + attached IAM role — an SSRF "
                                      f"on this host can read its role credentials | {name}")
                        # EC2-07 — plaintext secret embedded in instance user-data
                        self._scan_ec2_user_data(ec2, iid, name)
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
    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 7b: MACHINE IMAGES (AMI)
    # ══════════════════════════════════════════════════════════════════════════
    def _check_ami(self):
        self._section_header("AMI")
        self._log("AMI-01: self-owned AMIs shared publicly or cross-account "
                  "(a public AMI exposes its full root-volume snapshot to every AWS account)")
        try:
            ec2    = self._client("ec2")
            images = ec2.describe_images(Owners=["self"]).get("Images", [])
        except Exception as e:
            self._add("WARN", "AMI-01", "AMI", "ami", str(e))
            return
        if not images:
            self._add("INFO", "AMI-01", "AMI", "ami", "No self-owned AMIs in this region")
            return
        exposed = 0
        for img in images:
            aid  = img.get("ImageId", "ami-?")
            name = img.get("Name") or aid
            label = f"{name} ({aid})" if name != aid else aid
            if img.get("Public") is True:
                exposed += 1
                self._add("FAIL", "AMI-01", "AMI", label,
                          f"AMI shared PUBLICLY — root-volume snapshot readable by any AWS "
                          f"account | {aid}")
                continue
            # non-public: enumerate explicit cross-account launch shares
            try:
                perms = ec2.describe_image_attribute(
                    ImageId=aid, Attribute="launchPermission"
                ).get("LaunchPermissions", [])
            except Exception:
                perms = []
            accounts = [p.get("UserId") for p in perms if p.get("UserId")]
            # AMIs can also be shared to an entire AWS Organization / OU (GA feature) —
            # readable by every account in it, so treat those as cross-account shares too.
            orgs = [p.get("OrganizationArn") or p.get("OrganizationalUnitArn")
                    for p in perms if p.get("OrganizationArn") or p.get("OrganizationalUnitArn")]
            group_all = any(p.get("Group") == "all" for p in perms)
            if group_all:
                exposed += 1
                self._add("FAIL", "AMI-01", "AMI", label,
                          f"AMI launch permission grants Group=all (public) | {aid}")
            elif accounts or orgs:
                exposed += 1
                shared = accounts + orgs
                self._add("WARN", "AMI-01", "AMI", label,
                          f"AMI shared with {len(shared)} external principal(s): "
                          f"{', '.join(shared[:5])}{'…' if len(shared) > 5 else ''} | {aid}")
        if exposed == 0:
            self._add("PASS", "AMI-01", "AMI", "ami",
                      f"All {len(images)} self-owned AMI(s) are private (no public/cross-account share)")

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
                self._ingest_ecr_scan(ecr, repo)
        except Exception as e:
            self._add("WARN", "CNT-01", "ECR", "ecr", str(e))

    def _ingest_ecr_scan(self, ecr, repo: Dict) -> None:
        """CNT-02 — pull the ECR *native* image-scan findings for the newest image in a
        repo and project HIGH/CRITICAL CVEs into the graph as ECRImage --HAS_VULN-->.
        This is free basic-scan signal that surfaces even when Amazon Inspector
        (enhanced scanning) is disabled. Bounded and fully best-effort."""
        rname = repo["repositoryName"]
        ruri  = repo.get("repositoryUri", rname)
        try:
            imgs: List[Dict] = []
            for page in ecr.get_paginator("describe_images").paginate(
                repositoryName=rname, filter={"tagStatus": "ANY"}
            ):
                imgs.extend(page.get("imageDetails", []))
        except Exception:
            return
        if not imgs:
            return
        # imagePushedAt is a tz-aware datetime in real boto3 (and optional). Use a
        # comparable epoch sentinel so a missing field can't raise TypeError.
        _epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        latest = max(imgs, key=lambda d: d.get("imagePushedAt") or _epoch)
        digest = latest.get("imageDigest")
        if not digest:
            return
        try:
            resp = ecr.describe_image_scan_findings(
                repositoryName=rname, imageId={"imageDigest": digest}
            )
        except Exception:
            return   # ScanNotFoundException / not scanned yet — CNT-01 already flags this
        sf = resp.get("imageScanFindings", {}) or {}
        # normalise basic-scan (findings) and enhanced-scan (enhancedFindings) shapes
        norm: List[tuple] = []
        for f in sf.get("findings", []):
            norm.append((f.get("name", ""), (f.get("severity") or "").upper()))
        for ef in sf.get("enhancedFindings", []):
            cve = (ef.get("packageVulnerabilityDetails", {}) or {}).get("vulnerabilityId", "")
            norm.append((cve, (ef.get("severity") or "").upper()))
        cves = [(c, sev) for c, sev in norm if c and sev in ("CRITICAL", "HIGH")]
        if not cves:
            return
        g = self._ensure_graph()
        node = f"{ruri}@{digest}"
        g.add_node(node, "ECRImage", repository=rname, digest=digest, image_uri=ruri)
        tags = latest.get("imageTags") or []
        tag_s = f":{tags[0]}" if tags else ""
        for cve, sev in cves[:100]:
            # NB: prop key must NOT be "source"/"target"/"id"/"kind" — those collide
            # with the node-link endpoint keys in SecurityGraph.to_dict().
            g.add_node(cve, "Vulnerability", severity=sev, scan_source="ecr-native-scan")
            g.add_edge(node, cve, "HAS_VULN", cve=cve, severity=sev, scan_source="ecr-native-scan")
            self._add("FAIL", "CNT-02", "ECR", f"{rname}{tag_s}",
                      f"container-image {sev} {cve} in newest image of {rname} "
                      f"(ECR native scan) | {rname}@{digest[:19]}")

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

        # RDS-08 — IAM database authentication (defense-in-depth vs static passwords)
        self._log("RDS-08: IAM database authentication enabled")
        for db in _rds_instances():
            iid    = db["DBInstanceIdentifier"]
            engine = db.get("Engine", "")
            # IAM auth only applies to MySQL/PostgreSQL/MariaDB/Aurora engines
            if not any(e in engine for e in ("mysql", "postgres", "mariadb", "aurora")):
                continue
            if db.get("IAMDatabaseAuthenticationEnabled", False):
                self._add("PASS", "RDS-08", "RDS", iid,
                          f"IAM DB authentication=ON | {iid} ({engine})")
            else:
                self._add("WARN", "RDS-08", "RDS", iid,
                          f"IAM DB authentication=OFF — relies on static DB passwords "
                          f"| {iid} ({engine})")

        # RDS-06 — Public snapshot visibility  +  RDS-11 — snapshot encryption at rest
        self._log("RDS-06/RDS-11: RDS snapshot public visibility and encryption at rest")
        try:
            snaps = []
            for page in rds.get_paginator("describe_db_snapshots").paginate(
                SnapshotType="manual"
            ):
                snaps.extend(page.get("DBSnapshots", []))
            public_snaps = []
            unencrypted  = 0
            for s in snaps:
                sid = s["DBSnapshotIdentifier"]
                if not s.get("Encrypted", False):
                    unencrypted += 1
                    self._add("FAIL", "RDS-11", "RDS", sid,
                              f"Manual RDS snapshot NOT encrypted at rest: {sid} "
                              f"— plaintext DB data if the snapshot is shared/leaked")
                try:
                    attrs = rds.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=sid
                    )["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]
                    for a in attrs:
                        if (a["AttributeName"] == "restore"
                                and "all" in a.get("AttributeValues", [])):
                            public_snaps.append(sid)
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
            if snaps and unencrypted == 0:
                self._add("PASS", "RDS-11", "RDS", "snapshots",
                          f"All {len(snaps)} manual RDS snapshots encrypted at rest")
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
                          f"EKS '{cname}' missing log types: {', '.join(sorted(missing))}")
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
            lbs = self._paginate_all(elb, "describe_load_balancers", "LoadBalancers")
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

                # ELB-07 — HTTP desync mitigation mode (request-smuggling defense)
                mode = attrs.get("routing.http.desync_mitigation_mode", "defensive")
                if mode in ("defensive", "strictest"):
                    self._add("PASS", "ELB-07", "ELB", name,
                              f"Desync mitigation mode='{mode}' | {name}")
                else:
                    self._add("WARN", "ELB-07", "ELB", name,
                              f"Desync mitigation mode='{mode}' — HTTP request-smuggling "
                              f"exposure (recommend 'defensive' or 'strictest') | {name}")

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

        # ListCertificates defaults to RSA_1024/RSA_2048 ONLY — must pass keyTypes to
        # see ECDSA (EC_*) and RSA_3072/4096 certs — and it is paginated.
        _ACM_KEY_TYPES = ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
                          "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]
        try:
            certs = []
            for page in acm.get_paginator("list_certificates").paginate(
                Includes={"keyTypes": _ACM_KEY_TYPES}
            ):
                certs.extend(page.get("CertificateSummaryList", []))
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

            # ACM-04 — Unhealthy certificate status (TLS broken for the domain)
            status = cert.get("Status", "")
            if status in ("FAILED", "VALIDATION_TIMED_OUT", "REVOKED"):
                self._add("FAIL", "ACM-04", "ACM", domain,
                          f"Certificate status is {status} — TLS is broken for this "
                          f"domain | {domain}")

            # ACM-05 — Renewal risk (imported / ineligible for managed auto-renewal)
            ctype = cert.get("Type", "")
            if cert.get("RenewalEligibility") == "INELIGIBLE" and status == "ISSUED":
                self._add("WARN", "ACM-05", "ACM", domain,
                          f"Certificate is INELIGIBLE for managed renewal — it will "
                          f"expire without action | {domain}")
            elif ctype == "IMPORTED":
                self._add("WARN", "ACM-05", "ACM", domain,
                          f"Imported certificate — ACM will not auto-renew; rotate "
                          f"manually before expiry | {domain}")

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
            not_actions: set = set()
            if "Action" in stmt:
                av = stmt["Action"]
                av = [av] if isinstance(av, str) else list(av)
                actions = {str(a).lower() for a in av}
            elif "NotAction" in stmt:
                nav = stmt["NotAction"]
                nav = [nav] if isinstance(nav, str) else list(nav)
                not_actions = {str(a).lower() for a in nav}
                # Backward-compat: Allow+NotAction stays over-approximated to
                # actions={'*'} for the action-set/privesc consumers (unchanged);
                # Deny+NotAction (previously dropped) gets actions=set() so the
                # existing deny-building is unaffected. The effective-permissions
                # solver reads `not_actions` for correct inverse matching in both.
                actions = {"*"} if effect == "Allow" else set()
            else:
                continue
            not_resources: set = set()
            if "Resource" in stmt:
                rv = stmt["Resource"]
                rv = [rv] if isinstance(rv, str) else list(rv)
                resources = {str(r).lower() for r in rv}
            elif "NotResource" in stmt:
                nrv = stmt["NotResource"]
                nrv = [nrv] if isinstance(nrv, str) else list(nrv)
                not_resources = {str(r).lower() for r in nrv}
                resources = {"*"}   # broad for privesc reachability; NotResource captured separately
            else:
                resources = {"*"}   # truly missing Resource -> broad (avoid privesc under-reporting)
            out.append({"effect": effect, "actions": actions, "resources": resources,
                        "not_actions": not_actions, "not_resources": not_resources,
                        "condition": stmt.get("Condition") or None})
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

    def _get_scp_context(self) -> Optional[List]:
        """Build the ordered SCP levels (root -> ... -> account) that apply to
        THIS account, each level a list of that node's SCP statement-lists — the
        `scp_levels` the effective-permissions solver ANDs across.

        Read-only, cached, and *fail-open*: returns None (SCP layer not evaluated)
        for the management account, a non-ALL-features org, an org that is not in
        use, or ANY API/permission error. None => the solver can never prune on
        SCP grounds => prior behavior.

        Critically, if ANY level resolves to zero readable SCP docs (a
        list/describe call was denied or throttled), the WHOLE layer fails open
        (returns None) rather than treating that level as deny-all. In a
        FeatureSet=ALL org every node always carries at least the undetachable
        AWS-managed `FullAWSAccess`, so an empty resolved level can only mean
        'unreadable', never 'the action was carved out' — treating it as deny-all
        would mass-drop every escalation edge account-wide (the worst over-prune)."""
        if self._scp_fetched:
            return self._scp_context
        self._scp_fetched = True
        self._scp_context = None
        try:
            org = self._client("organizations")
        except Exception:
            return None
        try:
            info = org.describe_organization().get("Organization", {})
            master = info.get("MasterAccountId")
            if info.get("FeatureSet") != "ALL":
                self._log("SCP layer not evaluated (org FeatureSet != ALL)")
                return None
            if master and self.account and master == self.account:
                self._log("SCP layer not evaluated (management account is exempt)")
                return None
        except Exception:
            self._log("SCP layer not evaluated (Organizations not in use or access denied)")
            return None

        # Walk parents from the account up to the root.
        nodes: List[str] = [self.account]
        child = self.account
        guard = 0
        try:
            while guard < 20:
                guard += 1
                parents = org.list_parents(ChildId=child).get("Parents", [])
                if not parents:
                    break
                pid = parents[0].get("Id")
                ptype = parents[0].get("Type")
                if not pid:
                    break
                nodes.append(pid)
                if ptype == "ROOT":
                    break
                child = pid
        except Exception:
            return None

        # Resolve each node's SCPs (root first for evidence ordering). An empty
        # readable level (should be impossible with FullAWSAccess present) is
        # treated as UNREADABLE and fails the whole layer open.
        levels: List[List[List[Dict]]] = []
        try:
            for node in reversed(nodes):        # root -> ... -> account
                pols = self._paginate_all(
                    org, "list_policies_for_target", "Policies",
                    TargetId=node, Filter="SERVICE_CONTROL_POLICY")
                level_docs: List[List[Dict]] = []
                for pol in pols:
                    pid = pol.get("Id")
                    if not pid:
                        continue
                    try:
                        content = org.describe_policy(PolicyId=pid)["Policy"]["Content"]
                        level_docs.append(self._policy_to_statements(json.loads(content)))
                    except Exception:
                        continue
                if not level_docs:
                    # No readable SCP at this node -> cannot trust the ceiling.
                    self._log("SCP layer not evaluated (a node's policies were unreadable)")
                    return None
                levels.append(level_docs)
        except Exception:
            return None

        self._scp_context = levels
        self._scp_evaluated = True
        return levels

    def _get_iam_principals(self) -> List[Dict]:
        """Enumerate IAM users and roles with their effective policy statements
        (attached managed + inline + group policies) via a single paginated
        ``iam:GetAccountAuthorizationDetails`` call — which also returns managed
        policy documents inline and each role's trust policy, so trust edges and
        the identity graph are built with no extra API surface. Roles additionally
        carry ``trust`` (parsed AssumeRolePolicyDocument) and ``instance_profiles``.
        Cached. Read-only.
        """
        if self._iam_principals is not None:
            return self._iam_principals

        iam = self._client("iam")
        users: List[Dict] = []
        groups: List[Dict] = []
        roles: List[Dict] = []
        policy_stmts: Dict[str, List[Dict]] = {}   # managed policy ARN -> statements

        try:
            paginator = iam.get_paginator("get_account_authorization_details")
            for page in paginator.paginate():
                users  += page.get("UserDetailList", [])
                groups += page.get("GroupDetailList", [])
                roles  += page.get("RoleDetailList", [])
                for pol in page.get("Policies", []):
                    arn = pol.get("Arn", "")
                    default_ver = pol.get("DefaultVersionId")
                    doc = None
                    for v in pol.get("PolicyVersionList", []):
                        if v.get("IsDefaultVersion") or v.get("VersionId") == default_ver:
                            doc = v.get("Document")
                            break
                    if doc is not None:
                        policy_stmts[arn] = self._policy_to_statements(doc)
        except Exception:
            self._iam_principals = []
            return []

        principals: List[Dict] = []

        def _managed(attached):
            stmts: List[Dict] = []
            for ap in attached or []:
                stmts += policy_stmts.get(ap.get("PolicyArn", ""), [])
            return stmts

        def _inline(policy_list):
            stmts: List[Dict] = []
            for ip in policy_list or []:
                stmts += self._policy_to_statements(ip.get("PolicyDocument"))
            return stmts

        def _resolve_boundary(pb):
            """Resolve a principal's PermissionsBoundary to its statements, or
            None. An unresolvable/empty boundary returns None (fail open) — never
            an empty list, which the solver would read as deny-all and over-prune."""
            if not pb:
                return None
            barn = pb.get("PermissionsBoundaryArn")
            if not barn:
                return None
            stmts = policy_stmts.get(barn) or self._get_managed_policy_statements(barn)
            if not stmts:
                return None
            self._boundary_evaluated = True
            return stmts

        def _finalize(ptype, name, arn, statements, **extra):
            allow, deny = set(), set()
            for st in statements:
                if st["effect"] == "Allow":
                    allow |= st["actions"]
                else:
                    deny |= st["actions"]
            principals.append({"type": ptype, "name": name, "arn": arn,
                               "statements": statements, "allow": allow,
                               "deny": deny, **extra})

        # Pre-resolve group statements once (users inherit them)
        group_stmts: Dict[str, List[Dict]] = {}
        for g in groups:
            group_stmts[g.get("GroupName", "")] = (
                _managed(g.get("AttachedManagedPolicies"))
                + _inline(g.get("GroupPolicyList"))
            )

        for u in users:
            stmts = _managed(u.get("AttachedManagedPolicies")) + _inline(u.get("UserPolicyList"))
            for gname in u.get("GroupList", []):
                stmts += group_stmts.get(gname, [])
            _finalize("user", u.get("UserName", ""), u.get("Arn", ""), stmts,
                      groups=list(u.get("GroupList", [])),
                      boundary=_resolve_boundary(u.get("PermissionsBoundary")))

        for r in roles:
            if r.get("Path", "").startswith("/aws-service-role/"):
                continue
            stmts = _managed(r.get("AttachedManagedPolicies")) + _inline(r.get("RolePolicyList"))
            trust = parse_trust_policy(r.get("AssumeRolePolicyDocument"))
            inst_profiles = [ip.get("Arn", "") for ip in r.get("InstanceProfileList", [])]
            _finalize("role", r.get("RoleName", ""), r.get("Arn", ""), stmts,
                      trust=trust, instance_profiles=inst_profiles,
                      path=r.get("Path", ""),
                      boundary=_resolve_boundary(r.get("PermissionsBoundary")))

        self._iam_principals = principals
        return principals

    def _admin_cap_id(self) -> str:
        return f"capability:admin:{self.account or 'account'}"

    def _build_identity_graph(self, principals: List[Dict]) -> SecurityGraph:
        """Project principals + their trust and privesc facts onto a graph:
        IAM principal nodes, an AdminCapability node, ``CAN_PRIVESC_TO`` edges
        (principal → admin capability, one per principal that can escalate), and
        ``CAN_ASSUME`` edges (trusting-principal → role) parsed from each role's
        trust policy. Returns the graph (also stored on ``self.graph``)."""
        g = SecurityGraph()
        admin = self._admin_cap_id()
        g.add_node(admin, "AdminCapability", account=self.account)
        # Reset so a rebuild (e.g. graph requested before IAMPRIVESC ran) does not
        # double-count ceiling-pruned/downgraded edges.
        self._pruned_edges = []
        self._downgraded_edges = []

        # Phase 5: the SCP ceiling that applies to this account (None => fail open).
        scp = self._get_scp_context()
        arn_map = {p["arn"]: p for p in principals if p.get("arn")}

        # Nodes + privesc edges (ceiling-refined: a boundary/SCP-neutralized pivot
        # is dropped, a Condition-gated one downgraded to conditioned).
        for p in principals:
            arn = p["arn"] or f"{p['type']}:{p['name']}"
            p["_node"] = arn
            kind = "IAMUser" if p["type"] == "user" else "IAMRole"
            g.add_node(arn, kind, name=p["name"], account=self.account)
            pruned: List[Dict] = []
            findings = evaluate_privesc_scoped(
                p["statements"], boundary=p.get("boundary"),
                scp_levels=scp, pruned=pruned)
            p["_privesc"] = findings
            for pr in pruned:
                self._pruned_edges.append({"principal": arn, "edge": "CAN_PRIVESC_TO", **pr})
            if findings:
                unconditioned = [f for f in findings if not f.get("conditioned")]
                rules = sorted({f["id"] for f in findings})
                conditioned = not unconditioned
                g.add_edge(arn, admin, "CAN_PRIVESC_TO",
                           rules=rules, conditioned=conditioned)
                if conditioned:
                    self._downgraded_edges.append(
                        {"principal": arn, "edge": "CAN_PRIVESC_TO", "rules": rules})

        # Trust → CAN_ASSUME edges (a source principal whose own boundary/SCP
        # provably denies sts:AssumeRole cannot actually assume, so its edge is
        # dropped; a Condition-gated one is marked has_condition).
        def _assume_verdict(src_arn: str):
            """Ceiling verdict for an ENUMERATED in-account source principal, else
            None (external/wildcard/service/:root -> we lack its policy -> keep)."""
            src = arn_map.get(src_arn)
            if src is None:
                return None
            return aws_effperm.pivot_effective(
                "sts:assumerole", src["statements"], src.get("boundary"), scp)

        for p in principals:
            if p["type"] != "role":
                continue
            role_arn = p["_node"]
            for st in p.get("trust", []):
                if st["effect"] != "Allow":
                    continue
                cond = st["has_condition"]
                if st["wildcard"]:
                    any_id = "principal:*"
                    g.add_node(any_id, "AnyPrincipal")
                    g.add_edge(any_id, role_arn, "CAN_ASSUME",
                               has_condition=cond, wildcard=True)
                for src_arn in st["aws"]:
                    acct = _account_of(src_arn)
                    external = bool(acct) and bool(self.account) and acct != self.account
                    node_kind = "AWSAccount" if src_arn.endswith(":root") else "IAMPrincipalRef"
                    verdict = _assume_verdict(src_arn)
                    if verdict == aws_effperm.DROP:
                        self._pruned_edges.append(
                            {"principal": src_arn, "edge": "CAN_ASSUME",
                             "target": role_arn, "pivot": "sts:assumerole",
                             "reason": aws_effperm.drop_reason(
                                 "sts:assumerole", arn_map[src_arn]["statements"],
                                 arn_map[src_arn].get("boundary"), scp)})
                        continue
                    edge_cond = cond or verdict == aws_effperm.CONDITIONED
                    g.add_node(src_arn, node_kind, account=acct, external=external or None)
                    g.add_edge(src_arn, role_arn, "CAN_ASSUME",
                               has_condition=edge_cond, external=external or None)
                    if verdict == aws_effperm.CONDITIONED and not cond:
                        self._downgraded_edges.append(
                            {"principal": src_arn, "edge": "CAN_ASSUME", "target": role_arn})
                for svc in st["service"]:
                    g.add_node(f"service:{svc}", "ServicePrincipal", service=svc)
                    g.add_edge(f"service:{svc}", role_arn, "SERVICE_CAN_ASSUME",
                               has_condition=cond)
        self.graph = g
        return g

    def _check_iam_privesc(self):
        self._section_header("IAMPRIVESC")
        self._log("Resource-aware path analysis + identity graph (CAN_ASSUME / "
                  "CAN_PRIVESC_TO edges, transitive chains). Conditioned paths are "
                  "downgraded to WARN; permission boundaries and SCPs are evaluated as "
                  "a ceiling (a provably-neutralized escalation edge is dropped)")
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

        g = self._build_identity_graph(principals)
        found = False

        # 1) Per-principal privilege-escalation primitives (condition-aware)
        for p in principals:
            for f in p.get("_privesc", []):
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
                if f.get("conditioned"):
                    self._add("WARN", f["id"], "IAMPRIVESC",
                              f"{p['type']}:{p['name']}",
                              f"{f['name']} — {f['desc']}{scope_note} "
                              f"[conditioned: exploitable only if the policy Condition "
                              f"is satisfiable] | {p['type']} {p['name']}")
                else:
                    self._add("FAIL", f["id"], "IAMPRIVESC",
                              f"{p['type']}:{p['name']}",
                              f"{f['name']} — {f['desc']}{scope_note} | {p['type']} {p['name']}")

        # 2) Dangerous role trust — assumable by ANY AWS principal (IAMPE-22)
        for p in principals:
            if p["type"] != "role":
                continue
            for st in p.get("trust", []):
                if st["effect"] == "Allow" and st["wildcard"]:
                    found = True
                    if st["has_condition"]:
                        self._add("WARN", "IAMPE-22", "IAMPRIVESC",
                                  f"role:{p['name']}",
                                  f"Role trust allows ANY AWS principal (Principal '*') "
                                  f"but is Condition-guarded — verify the condition "
                                  f"(ExternalId/OrgID/SourceArn) | role {p['name']}")
                    else:
                        self._add("FAIL", "IAMPE-22", "IAMPRIVESC",
                                  f"role:{p['name']}",
                                  f"Role trust policy allows ANY AWS principal "
                                  f"(Principal '*') to assume it with no condition — "
                                  f"account takeover risk | role {p['name']}")

        # 3) Transitive escalation chains: principal → assume → … → can escalate (IAMPE-21)
        admin = self._admin_cap_id()
        for p in principals:
            start = p["_node"]
            reachable = g.reachable(start, {"CAN_ASSUME"}, max_hops=4)
            seen_targets = set()
            for target, path in reachable.items():
                if target in seen_targets or target == start:
                    continue
                if not g.has_out_edge(target, "CAN_PRIVESC_TO"):
                    continue
                seen_targets.add(target)
                found = True
                tnode = g.node(target) or {}
                tname = (tnode.get("props") or {}).get("name", target)
                hops = " → ".join(
                    (g.node(n) or {}).get("props", {}).get("name", n.split("/")[-1])
                    for n in path
                )
                self._add("FAIL", "IAMPE-21", "IAMPRIVESC",
                          f"{p['type']}:{p['name']}",
                          f"Transitive privilege-escalation chain: {hops} → (admin) — "
                          f"{p['type']} {p['name']} can reach escalation via role "
                          f"{tname} | {p['type']} {p['name']}")

        if not found:
            self._add("PASS", "IAMPE-00", "IAMPRIVESC", "all-principals",
                      f"No privilege-escalation paths detected across "
                      f"{len(principals)} principals")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 36: INTERNET EXPOSURE & ATTACK PATHS  (Phase 2)
    # ══════════════════════════════════════════════════════════════════════════
    def _paginate_all(self, client, method: str, key: str, **kwargs) -> List[Dict]:
        """Collect all items for a paginated (or single) describe call. Read-only."""
        out: List[Dict] = []
        try:
            paginator = client.get_paginator(method)
            for page in paginator.paginate(**kwargs):
                out += page.get(key, [])
            return out
        except Exception:
            try:
                out += getattr(client, method)(**kwargs).get(key, [])
            except Exception:
                pass
        return out

    def _instance_arn(self, instance_id: str) -> str:
        return f"arn:aws:ec2:{self.region}:{self.account}:instance/{instance_id}"

    # Managed ENIs whose exposure belongs to their service, not a customer workload.
    # NB: the EC2 API is inconsistent — NAT gateways report the camelCase
    # "natGateway" while most managed types are snake_case; include both forms.
    _MANAGED_IFACE = {
        "nat_gateway", "natGateway", "load_balancer", "vpc_endpoint",
        "transit_gateway", "global_accelerator_managed", "api_gateway_managed",
        "lambda", "gateway_load_balancer", "gateway_load_balancer_endpoint",
        "network_load_balancer", "aws_codestar_connections_managed",
    }

    @staticmethod
    def _edge_unconditioned(e: Dict) -> bool:
        """An escalation edge is only 'confirmed' if it is not gated by a policy
        Condition (privesc) or a trust Condition (assume-role)."""
        pr = e.get("props", {})
        return not pr.get("conditioned") and not pr.get("has_condition")

    def _check_exposure(self):
        self._section_header("EXPOSURE")
        self._log("Effective internet reachability (public IP AND igw route AND SG "
                  "ingress AND stateless NACL both directions) + Internet->EC2->role->admin "
                  "attack paths. L7 (ALB/NLB/CloudFront) deferred; direct-EC2 only.")
        ec2 = self._client("ec2")

        enis  = self._paginate_all(ec2, "describe_network_interfaces", "NetworkInterfaces")
        rtbs  = self._paginate_all(ec2, "describe_route_tables", "RouteTables")
        nacls = self._paginate_all(ec2, "describe_network_acls", "NetworkAcls")
        sgs   = self._paginate_all(ec2, "describe_security_groups", "SecurityGroups")
        instances: List[Dict] = []
        for r in self._paginate_all(ec2, "describe_instances", "Reservations"):
            instances += r.get("Instances", [])

        if not enis:
            self._add("INFO", "EXPOSURE-02", "EXPOSURE", "network",
                      "No elastic network interfaces found in this region")
            return

        sg_perms = {s.get("GroupId"): s.get("IpPermissions", []) for s in sgs}
        inst_by_id = {i.get("InstanceId"): i for i in instances}

        # Ensure the identity subgraph exists (so attack paths can chain into it)
        try:
            principals = self._get_iam_principals()
        except Exception:
            principals = []
        if self.graph is None:
            self._build_identity_graph(principals)
        g = self.graph
        internet = "internet"
        g.add_node(internet, "InternetSource", cidr="0.0.0.0/0")

        # instance-profile ARN -> role ARN (from GAAD-collected role.instance_profiles)
        profile_to_role = {}
        for p in principals:
            if p["type"] == "role":
                for prof in p.get("instance_profiles", []):
                    if prof:
                        profile_to_role[prof.lower()] = p["arn"]

        exposed_instances: set = set()
        any_finding = False

        for eni in enis:
            if eni.get("InterfaceType", "interface") in self._MANAGED_IFACE:
                continue
            subnet_id = eni.get("SubnetId", "")
            vpc_id = eni.get("VpcId", "")
            ipkind = aws_exposure.classify_public_ip(
                eni.get("Association"),
                [a.get("Ipv6Address") for a in eni.get("Ipv6Addresses", [])])
            if ipkind["ipv4"] is None and not ipkind["ipv6"]:
                continue                                # no public entry point at all
            rt   = aws_exposure.find_effective_route_table(subnet_id, vpc_id, rtbs)
            nacl = aws_exposure.find_governing_nacl(subnet_id, vpc_id, nacls)
            perms: List[Dict] = []
            for grp in eni.get("Groups", []):
                perms += sg_perms.get(grp.get("GroupId"), [])
            exposure = aws_exposure.compute_exposure(
                {"ipv4_public": ipkind["ipv4"], "ipv6_public": ipkind["ipv6"]},
                rt, nacl, perms)
            if not exposure:
                continue

            eni_id = eni.get("NetworkInterfaceId", "eni-?")
            instance_id = (eni.get("Attachment") or {}).get("InstanceId", "")
            g.add_node(eni_id, "NetworkInterface", subnet_id=subnet_id,
                       vpc_id=vpc_id, ipv4_kind=ipkind["ipv4"])
            if instance_id:
                target_arn = self._instance_arn(instance_id)
                g.add_node(target_arn, "EC2Instance", instance_id=instance_id, vpc_id=vpc_id)
                g.add_edge(eni_id, target_arn, "ATTACHED_TO")
                exposed_instances.add(instance_id)

            for family, ports in exposure.items():
                summary, hits = aws_exposure.iter_exposed_ports(ports)
                ipk = ipkind["ipv4"] if family == "ipv4" else "ipv6"
                g.add_edge(internet, eni_id, "EXPOSED_TO", family=family,
                           ports=summary, ip_kind=ipk, stable=(ipk == "eip"))
                res = instance_id or eni_id
                any_finding = True
                if hits:
                    sens = ", ".join(sorted({f"{name}({proto}/{port})"
                                             for proto, port, name in hits}))
                    self._add("FAIL", "EXPOSURE-01", "EXPOSURE", res,
                              f"Internet-reachable sensitive port(s) {sens} over "
                              f"{family} [{summary}] (public IP: {ipk}) | {res}")
                else:
                    self._add("FAIL", "EXPOSURE-02", "EXPOSURE", res,
                              f"Internet-reachable on {family} [{summary}] "
                              f"(public IP: {ipk}) | {res}")

        # Fire the first end-to-end attack paths: exposed EC2 -> instance role -> admin
        admin = self._admin_cap_id()
        for instance_id in sorted(exposed_instances):
            inst = inst_by_id.get(instance_id, {})
            prof_arn = (inst.get("IamInstanceProfile") or {}).get("Arn", "")
            if not prof_arn:
                continue
            target_arn = self._instance_arn(instance_id)
            g.add_node(prof_arn, "InstanceProfile", arn=prof_arn)
            g.add_edge(target_arn, prof_arn, "HAS_INSTANCE_PROFILE")
            role_arn = profile_to_role.get(prof_arn.lower())
            if not role_arn:
                continue
            g.add_edge(prof_arn, role_arn, "HAS_ROLE")
            # Condition-aware: CRITICAL only when admin is reachable over edges that
            # carry no policy/trust Condition; otherwise the path is exploitable only
            # if the attacker can satisfy the condition -> WARN (matches _check_iam_privesc).
            kinds = {"CAN_PRIVESC_TO", "CAN_ASSUME"}
            reach_confirmed = g.reachable(role_arn, kinds, max_hops=6,
                                          edge_filter=self._edge_unconditioned)
            rname = (g.node(role_arn) or {}).get("props", {}).get("name",
                                                                  role_arn.split("/")[-1])
            if admin in reach_confirmed:
                any_finding = True
                self._add("FAIL", "ATTACK-01", "EXPOSURE", instance_id,
                          f"ATTACK PATH: Internet -> exposed EC2 {instance_id} -> "
                          f"instance-profile role {rname} -> privilege escalation to admin. "
                          f"An attacker reaching this host inherits a role that can become "
                          f"account administrator. | {instance_id}")
            elif admin in g.reachable(role_arn, kinds, max_hops=6):
                any_finding = True
                self._add("WARN", "ATTACK-01", "EXPOSURE", instance_id,
                          f"ATTACK PATH (conditioned): Internet -> exposed EC2 {instance_id} "
                          f"-> instance-profile role {rname} -> admin is reachable ONLY via a "
                          f"Condition-guarded privesc/trust (MFA/ExternalId/tag/SourceIp) — "
                          f"exploitable only if the attacker can satisfy the condition. Verify. "
                          f"| {instance_id}")

        if not any_finding:
            self._add("PASS", "EXPOSURE-02", "EXPOSURE", "all-enis",
                      f"No internet-reachable workloads across {len(enis)} interface(s)")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTIONS 37-39: DEEP-PLANE INGESTION (Phase 3, buy-not-build)
    #   VULN (Inspector2) · THREAT (GuardDuty) · DATA (Macie + Access Analyzer +
    #   CAN_READ_DATA + the flagship ATTACK-02). Every collector is enablement-gated
    #   and degrades to a graceful INFO no-op when its AWS service is disabled —
    #   never a FAIL, crash, or phantom edge.
    # ══════════════════════════════════════════════════════════════════════════
    def _ensure_graph(self) -> SecurityGraph:
        """Ensure the identity subgraph exists (build it from principals if the
        IAMPRIVESC section hasn't run yet), so deep-plane edges can chain into it."""
        if self.graph is None:
            try:
                principals = self._get_iam_principals()
            except Exception:
                principals = []
            self._build_identity_graph(principals)
        return self.graph

    def _node_has_threat(self, node_id: str) -> bool:
        return any(e["dst"] == node_id for e in self.graph.edges("THREAT_ON"))

    # ── VULN: Amazon Inspector v2 → HAS_VULN ──────────────────────────────────
    def _inspector_kev(self, insp, finding_arns: List[str]) -> Dict[str, bool]:
        """Second hop for the authoritative CISA-KEV flag (not on list_findings).
        Batched (<=10/call) and capped to bound cost/throttling."""
        out: Dict[str, bool] = {}
        arns = [a for a in finding_arns if a][:300]
        for i in range(0, len(arns), 10):
            try:
                resp = insp.batch_get_finding_details(findingArns=arns[i:i + 10])
                for d in resp.get("findingDetails", []):
                    out[d.get("findingArn")] = aws_deepplane.finding_kev(d)
            except Exception:
                pass
        return out

    def _check_vuln(self):
        self._section_header("VULN")
        self._log("Amazon Inspector v2 package vulnerabilities -> HAS_VULN edges "
                  "(EPSS native; KEV via batch_get_finding_details). INFO no-op if disabled.")
        try:
            insp = self._client("inspector2")
        except Exception as e:
            self._add("INFO", "VULN-01", "VULN", "inspector2", f"Inspector2 unavailable: {e}")
            return
        try:
            st = (insp.batch_get_account_status(accountIds=[self.account]) if self.account
                  else insp.batch_get_account_status())
            rs = ((st.get("accounts") or [{}])[0]).get("resourceState") or {}
            ec2_on = (rs.get("ec2") or {}).get("status") == "ENABLED"
            ecr_on = (rs.get("ecr") or {}).get("status") == "ENABLED"
            # lambda / lambdaCode scan plans are independently toggleable — without
            # this, a Lambda-only Inspector account skips VULN-04 entirely.
            lambda_on = ((rs.get("lambda") or {}).get("status") == "ENABLED"
                         or (rs.get("lambdaCode") or {}).get("status") == "ENABLED")
        except Exception as e:
            self._add("INFO", "VULN-01", "VULN", "inspector2",
                      f"Amazon Inspector not enabled/accessible in {self.region}: {e}")
            return
        if not (ec2_on or ecr_on or lambda_on):
            self._add("INFO", "VULN-01", "VULN", "inspector2",
                      f"Amazon Inspector disabled in {self.region} (ec2/ecr/lambda not "
                      "ENABLED) — no vulnerability signal")
            return

        g = self._ensure_graph()
        fc = {"findingType":   [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
              "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
              "severity":      [{"comparison": "EQUALS", "value": "CRITICAL"},
                                {"comparison": "EQUALS", "value": "HIGH"}]}
        findings: List[Dict] = []
        try:
            for page in insp.get_paginator("list_findings").paginate(filterCriteria=fc):
                findings += page.get("findings", [])
        except Exception as e:
            self._add("INFO", "VULN-01", "VULN", "inspector2",
                      f"Inspector list_findings failed: {e}")
            return

        kev_map = self._inspector_kev(insp, [f.get("findingArn") for f in findings])
        count = 0
        for f in findings:
            v = aws_deepplane.parse_inspector_finding(f)
            if not v:
                continue
            v["kev"] = bool(kev_map.get(v["finding_arn"]))
            rtype, rid = v["resource_type"], v["resource_id"]
            if rtype == "AWS_EC2_INSTANCE" and rid:
                node = self._instance_arn(rid)
                g.add_node(node, "EC2Instance", instance_id=rid)
            elif rtype == "AWS_ECR_CONTAINER_IMAGE" and rid:
                node = rid
                g.add_node(node, "ECRImage")
            elif rtype == "AWS_LAMBDA_FUNCTION" and rid:
                node = rid
                g.add_node(node, "LambdaFunction", function_arn=rid)
            else:
                continue                                    # non-graphable resource
            g.add_node(v["cve"], "Vulnerability", severity=v["severity"], epss=v["epss"],
                       kev=v["kev"], exploit_available=v["exploit_available"],
                       fix_available=v["fix_available"])
            g.add_edge(node, v["cve"], "HAS_VULN", cve=v["cve"], severity=v["severity"],
                       epss=v["epss"], kev=v["kev"], exploit_available=v["exploit_available"],
                       fix_available=v["fix_available"], finding_arn=v["finding_arn"])
            count += 1
            if v["kev"]:
                fid, tag = "VULN-02", "KEV/in-the-wild"
            elif rtype == "AWS_ECR_CONTAINER_IMAGE":
                fid, tag = "VULN-03", "container-image"
            elif rtype == "AWS_LAMBDA_FUNCTION":
                fid, tag = "VULN-04", "lambda-dependency"
            else:
                fid, tag = "VULN-01", "exploitable" if aws_deepplane.is_exploitable(v) else "high/critical"
            self._add("FAIL", fid, "VULN", rid,
                      f"{tag} {v['severity']} {v['cve']} (EPSS {v['epss']}, "
                      f"exploit={v['exploit_available']}, fix={v['fix_available']}) on "
                      f"{(rtype or '').replace('AWS_', '').lower()} {rid} | {rid}")
        if count == 0:
            self._add("PASS", "VULN-01", "VULN", "all",
                      "Inspector enabled; no active high/critical package vulnerabilities")

    # ── THREAT: GuardDuty → THREAT_ON ─────────────────────────────────────────
    def _check_threat(self):
        self._section_header("THREAT")
        self._log("GuardDuty active detector findings -> THREAT_ON edges (boost path "
                  "priority). INFO no-op if GuardDuty is disabled.")
        try:
            gd = self._client("guardduty")
            detectors = gd.list_detectors().get("DetectorIds", [])
        except Exception as e:
            self._add("INFO", "THREAT-01", "THREAT", "guardduty",
                      f"GuardDuty not accessible in {self.region}: {e}")
            return
        if not detectors:
            self._add("INFO", "THREAT-01", "THREAT", "guardduty",
                      f"GuardDuty not enabled in {self.region} — no live threat signal")
            return
        det = detectors[0]
        try:
            if gd.get_detector(DetectorId=det).get("Status") != "ENABLED":
                self._add("INFO", "THREAT-01", "THREAT", "guardduty",
                          f"GuardDuty detector not ENABLED in {self.region}")
                return
        except Exception:
            pass

        g = self._ensure_graph()
        crit = {"Criterion": {"service.archived": {"Eq": ["false"]},
                              "severity": {"GreaterThanOrEqual": 4}}}
        ids: List[str] = []
        try:
            for page in gd.get_paginator("list_findings").paginate(DetectorId=det,
                                                                   FindingCriteria=crit):
                ids += page.get("FindingIds", [])
        except Exception as e:
            self._add("INFO", "THREAT-01", "THREAT", "guardduty",
                      f"GuardDuty list_findings failed: {e}")
            return

        count = 0
        for i in range(0, len(ids), 50):
            try:
                resp = gd.get_findings(DetectorId=det, FindingIds=ids[i:i + 50])
            except Exception:
                continue
            for f in resp.get("Findings", []):
                m = aws_deepplane.map_guardduty_finding(f)
                if not m:
                    continue
                tnode = f"threat:{m['id']}"
                g.add_node(tnode, "ThreatFinding", type=m["type"], severity=m["severity"],
                           band=m["band"])
                target = None
                if m["node_kind"] == "EC2Instance":
                    target = self._instance_arn(m["node_key"])
                elif m["node_kind"] == "S3Bucket":
                    target = ("arn:aws:s3:::" + m["node_key"]).lower()
                if target:
                    g.add_node(target, m["node_kind"])
                    g.add_edge(tnode, target, "THREAT_ON", type=m["type"],
                               severity=m["severity"], band=m["band"])
                self._add("FAIL", "THREAT-01", "THREAT", m["node_key"] or m["id"],
                          f"Active GuardDuty finding {m['type']} (severity {m['severity']}, "
                          f"{m['band']}) on {m['node_kind'] or 'account'} "
                          f"{m['node_key'] or ''} | {m['id']}")
                count += 1
        if count == 0:
            self._add("PASS", "THREAT-01", "THREAT", "all",
                      "GuardDuty enabled; no active findings (severity >= 4)")

    # ── DATA: Macie crown jewels + Access Analyzer + CAN_READ_DATA + ATTACK-02 ─
    def _check_data(self):
        self._section_header("DATA")
        self._log("Macie crown-jewel classification + Access Analyzer authoritative "
                  "exposure + CAN_READ_DATA edges + flagship ATTACK-02. INFO no-op when "
                  "Macie/Analyzer are disabled.")
        g = self._ensure_graph()
        crown = self._collect_macie(g)
        self._collect_access_analyzer(g)
        self._build_can_read_data(g, crown)
        self._correlate_flagship(g)

    def _collect_macie(self, g) -> set:
        crown: set = set()
        try:
            mac = self._client("macie2")
            sess = mac.get_macie_session()
        except Exception as e:
            self._add("INFO", "DATA-01", "DATA", "macie",
                      f"Macie not enabled in {self.region}: {e}")
            return crown
        if sess.get("status") != "ENABLED":
            self._add("INFO", "DATA-01", "DATA", "macie",
                      f"Macie not active (status={sess.get('status')}) in {self.region} "
                      "— no crown-jewel signal")
            return crown
        buckets: List[Dict] = []
        try:
            for page in mac.get_paginator("describe_buckets").paginate():
                buckets += page.get("buckets", [])
        except Exception as e:
            self._add("INFO", "DATA-01", "DATA", "macie",
                      f"Macie describe_buckets failed: {e}")
            return crown
        for b in buckets:
            cj = aws_deepplane.is_crown_jewel(b)
            if not cj:
                continue
            name = b.get("bucketName", "")
            arn = ("arn:aws:s3:::" + name).lower()
            crown.add(arn)
            g.add_node(arn, "S3Bucket", name=name, DataStore=True, crown_jewel=True,
                       sensitivity=cj["sensitivity"], public=cj["public"],
                       encrypted=cj["encrypted"])
            self._add("FAIL", "DATA-01", "DATA", name,
                      f"Crown-jewel S3 bucket (Macie sensitivity {cj['sensitivity']}) "
                      f"holds sensitive data | {name}")
            if cj["public"] or cj["shared"]:
                self._add("FAIL", "DATA-02", "DATA", name,
                          f"Crown-jewel bucket {name} is "
                          f"{'PUBLIC' if cj['public'] else 'externally shared'} | {name}")
            if not cj["encrypted"]:
                self._add("FAIL", "DATA-03", "DATA", name,
                          f"Crown-jewel bucket {name} is unencrypted | {name}")
        if not crown:
            self._add("INFO", "DATA-01", "DATA", "all",
                      "Macie enabled; no crown-jewel buckets identified")
        return crown

    def _collect_access_analyzer(self, g):
        try:
            aa = self._client("accessanalyzer")
            analyzers = aa.list_analyzers().get("analyzers", [])
        except Exception as e:
            self._add("INFO", "EXTACCESS-01", "DATA", "accessanalyzer",
                      f"Access Analyzer not accessible in {self.region}: {e}")
            return
        ext = [a for a in analyzers if a.get("status") == "ACTIVE"
               and a.get("type") in ("ACCOUNT", "ORGANIZATION")]
        if not ext:
            self._add("INFO", "EXTACCESS-01", "DATA", "accessanalyzer",
                      f"IAM Access Analyzer (external access) not enabled in {self.region}")
            return
        arn = ext[0].get("arn")
        if not arn:
            self._add("INFO", "EXTACCESS-01", "DATA", "accessanalyzer",
                      f"Access Analyzer analyzer has no ARN in {self.region}; skipping")
            return
        findings: List[Dict] = []
        try:
            for page in aa.get_paginator("list_findings_v2").paginate(
                    analyzerArn=arn, filter={"status": {"eq": ["ACTIVE"]}}):
                findings += page.get("findings", [])
        except Exception as e:
            self._add("INFO", "EXTACCESS-01", "DATA", "accessanalyzer",
                      f"Access Analyzer list_findings_v2 failed: {e}")
            return
        for f in findings:
            if f.get("resourceType") != "AWS::S3::Bucket":
                continue
            res = f.get("resource", "")
            detail = None
            try:
                detail = aa.get_finding_v2(analyzerArn=arn, id=f.get("id"))
            except Exception:
                pass
            cls = aws_deepplane.classify_external_access(detail) if detail else \
                {"is_public": f.get("isPublic", False), "principal": {}, "action": None}
            barn = res.lower() if res.startswith("arn:") else ("arn:aws:s3:::" + res).lower()
            g.add_node(barn, "S3Bucket", name=res.split(":::")[-1])
            if cls and cls.get("is_public"):
                g.add_edge("internet", barn, "EXPOSED_TO", basis="access-analyzer",
                           authoritative=True, confidence="confirmed")
                self._add("FAIL", "EXTACCESS-01", "DATA", res,
                          f"Access Analyzer: S3 bucket {res} is PUBLICLY accessible "
                          f"(authoritative) | {res}")
            else:
                self._add("FAIL", "EXTACCESS-02", "DATA", res,
                          f"Access Analyzer: S3 bucket {res} reachable by an external "
                          f"principal | {res}")

    def _build_can_read_data(self, g, crown: set):
        if not crown:
            return
        try:
            principals = self._get_iam_principals()
        except Exception:
            principals = []
        for p in principals:
            if p["type"] != "role":
                continue
            for barn in crown:
                r = aws_deepplane.role_can_read_bucket(p["statements"], barn)
                if r is None:
                    continue
                g.add_edge(p["arn"], barn, "CAN_READ_DATA", basis="identity-policy",
                           confidence="paths-to-verify", conditioned=r["conditioned"])
                bname = barn.split(":::")[-1]
                self._add("WARN" if r["conditioned"] else "FAIL", "EXTACCESS-03", "DATA",
                          f"role:{p['name']}",
                          f"Role {p['name']} can read crown-jewel data in {bname} "
                          f"(identity policy, paths-to-verify)"
                          f"{' [conditioned]' if r['conditioned'] else ''} | {p['name']}")

    def _correlate_flagship(self, g):
        """ATTACK-02 — the full flagship toxic combination: Internet → exposed EC2 →
        exploitable/KEV CVE → over-privileged instance-profile role → crown-jewel data.
        Requires the exposure (Phase 2), vuln (Inspector), and data (Macie) subgraphs
        to all have contributed; if any is absent (service off) it simply does not fire."""
        if g is None or g.node("internet") is None:
            return
        crown = {n["id"] for n in g.nodes("S3Bucket") if (n["props"] or {}).get("crown_jewel")}
        if not crown:
            return                                          # no data terminal (Macie off)
        reach = g.reachable("internet", {"EXPOSED_TO", "ATTACHED_TO"}, max_hops=3)
        exposed = [nid for nid in reach if (g.node(nid) or {}).get("kind") == "EC2Instance"]
        kinds = {"CAN_ASSUME", "CAN_PRIVESC_TO", "CAN_READ_DATA"}
        for inst in exposed:
            # Pivot on the SAME exploitability definition the VULN section uses
            # (KEV OR exploit-available OR high EPSS) — is_exploitable reads the edge props.
            vulns = [e for e in g.out_edges(inst, {"HAS_VULN"})
                     if aws_deepplane.is_exploitable(e["props"])]
            if not vulns:
                continue                                    # no compromise pivot
            role = None
            for e in g.out_edges(inst, {"HAS_INSTANCE_PROFILE"}):
                for e2 in g.out_edges(e["dst"], {"HAS_ROLE"}):
                    role = e2["dst"]
            if not role:
                continue
            conf = crown & set(g.reachable(role, kinds, max_hops=7,
                                           edge_filter=self._edge_unconditioned))
            anyb = crown & set(g.reachable(role, kinds, max_hops=7))
            if not anyb:
                continue
            cve = vulns[0]["props"].get("cve", "?")
            kev = any(v["props"].get("kev") for v in vulns)
            iid = (g.node(inst) or {}).get("props", {}).get("instance_id", inst)
            bucket = sorted(conf or anyb)[0].split(":::")[-1]
            boost = (" [ACTIVE THREAT on the path — TOP priority]"
                     if self._node_has_threat(inst) or self._node_has_threat(role) else "")
            if conf:
                self._add("FAIL", "ATTACK-02", "DATA", iid,
                          f"FLAGSHIP ATTACK PATH: Internet -> exposed EC2 {iid} -> "
                          f"exploitable{'/KEV' if kev else ''} {cve} -> instance-profile "
                          f"role -> reads crown-jewel data {bucket}.{boost} | {iid}")
            else:
                self._add("WARN", "ATTACK-02", "DATA", iid,
                          f"FLAGSHIP ATTACK PATH (conditioned): Internet -> exposed EC2 "
                          f"{iid} -> exploitable {cve} -> role -> crown-jewel data {bucket} "
                          f"reachable only via a Condition-guarded hop; verify.{boost} | {iid}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 40: ATTACK-PATH CORRELATION & CHOKE POINTS (Phase 4)
    # Read-only post-processor over the graph Phases 1-3 built. Ranks the graph
    # into the handful of scored, explainable attack paths and computes choke
    # points. ATTACK-01/ATTACK-02 emission stays in the exposure/data sections
    # (byte-for-byte) — this section only adds CHOKEPOINT-01 + a PATHS-01 rollup.
    # ══════════════════════════════════════════════════════════════════════════
    def _check_correlate(self):
        self._section_header("CORRELATE")
        self._log("Ranking attack paths (gated-multiplicative scoring) + choke-point "
                  "analysis ('fix one node -> sever N paths to M crown jewels').")
        g = self._ensure_graph()
        if g is None or g.node("internet") is None:
            self._add("INFO", "PATHS-01", "CORRELATE", "graph",
                      "No internet-facing attack surface in the graph; nothing to correlate")
            return
        crown = {n["id"] for n in g.nodes("S3Bucket")
                 if (n["props"] or {}).get("crown_jewel")}
        # Precompute the threat set ONCE — the enumerator calls node_has_threat per
        # edge expansion, so it must be O(1), not an O(E) scan of every graph edge.
        threatened = {e["dst"] for e in g.edges("THREAT_ON")}
        paths = aws_correlate.enumerate_paths(
            g, {"internet"}, self._admin_cap_id(), crown,
            self._edge_unconditioned, aws_deepplane.is_exploitable,
            lambda nid: nid in threatened)
        node_kind = lambda nid: (g.node(nid) or {}).get("kind")

        def _dominates(node, terminal):
            # Authoritative: is `terminal` unreachable from the internet once `node`
            # is removed? (Bounded enumeration alone can't certify a true dominator.)
            reach = g.reachable("internet", aws_correlate.E_PATH, max_hops=64,
                                edge_filter=lambda e: e["src"] != node and e["dst"] != node)
            return terminal not in reach

        chokes = aws_correlate.choke_points(
            paths, node_kind=node_kind,
            label_of=lambda nid: aws_correlate._label(g, nid), dominates=_dominates)
        self.attack_paths, self.choke_points = paths, chokes

        if not paths:
            self._add("PASS", "PATHS-01", "CORRELATE", "all",
                      "No end-to-end attack paths (internet -> crown-jewel/admin) found")
            return

        summ = aws_correlate.summarize(paths)
        self._add("INFO", "PATHS-01", "CORRELATE", "summary",
                  f"{summ['total']} attack path(s) ranked "
                  f"({summ['n_critical']} CRITICAL, {summ['n_conditioned']} conditioned); "
                  f"top score {summ['top_score']}: {summ['top_chain']}")

        # Emit the top choke points that sever at least one CRITICAL/HIGH path.
        for c in chokes[:3]:
            crit_hi = [p for p in paths if c.node_id in set(p.nodes[1:-1])
                       and p.severity in ("CRITICAL", "HIGH")]
            if not crit_hi:
                continue
            g.add_node(c.node_id, node_kind(c.node_id) or "Unknown",
                       choke_point=True, paths_severed=c.paths_severed)
            blocked = (f"; removes EVERY known path to {len(c.targets_fully_blocked)} "
                       f"target(s)" if c.is_true_choke else "")
            self._add("FAIL", "CHOKEPOINT-01", "CORRELATE", c.label,
                      f"CHOKE POINT: fixing {c.node_kind or 'node'} {c.label} severs "
                      f"{c.paths_severed}/{c.total_paths} attack path(s) "
                      f"({len(crit_hi)} CRITICAL/HIGH){blocked}. {c.remediation_hint} "
                      f"| {c.label}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 41: AGENTLESS WORKLOAD SIDE-SCAN  (Phase 6 · CWPP)
    # ══════════════════════════════════════════════════════════════════════════
    def _sidescan_scan_id(self) -> str:
        return f"{self.account or 'acct'}-sidescan"

    def _load_vuln_db(self):
        """Load the offline vulnerability feed from --vuln-db. Accepts a raw list
        of OSV records, or an object with {osv|records, epss, kev, exploits}.
        Returns (OSVFeed, epss_map, kev_set, exploit_set) or None (inventory +
        secrets still run; CVE match is simply skipped)."""
        if not self.vuln_db_path:
            return None
        try:
            with open(self.vuln_db_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as e:
            self._add("WARN", "CWPP-04", "SIDESCAN", "vuln-db",
                      f"could not load --vuln-db {self.vuln_db_path}: {e}")
            return None
        if isinstance(data, list):
            records, epss, kev, exploits = data, {}, set(), set()
        else:
            records = data.get("osv") or data.get("records") or []
            epss = data.get("epss") or {}
            kev = set(data.get("kev") or [])
            exploits = set(data.get("exploits") or [])
        return (aws_sidescan.OSVFeed.from_records(records), epss, set(kev), set(exploits))

    def _select_sidescan_targets(self, g):
        """In-scope instances for side-scan. Default 'exposed' reuses the Phase-2
        internet-reachable EC2 set (bounds cost to what actually matters); 'all'
        takes every EC2Instance node; 'tagged' is applied by the live extractor.
        Returns [(instance_id, volume_ids)], capped at side_scan_max."""
        exposed: List[str] = []
        if g is not None and g.node("internet") is not None:
            reach = g.reachable("internet", {"EXPOSED_TO", "ATTACHED_TO"}, max_hops=3)
            for nid in reach:
                node = g.node(nid) or {}
                if node.get("kind") == "EC2Instance":
                    iid = (node.get("props") or {}).get("instance_id")
                    if iid:
                        exposed.append(iid)
        if self.side_scan_targets == "all":
            chosen = [(n.get("props") or {}).get("instance_id")
                      for n in (g.nodes("EC2Instance") if g else [])]
        else:                                   # exposed (default) or tagged
            chosen = exposed
        seen: set = set()
        out: List = []
        for iid in chosen:
            if not iid or iid in seen:
                continue
            seen.add(iid)
            out.append((iid, []))               # volumes resolved by the live opener
            if len(out) >= self.side_scan_max:
                break
        return out

    def _default_extractor_opener(self, vol_ids, iid):
        """Live extractor factory (deferred): snapshot the volumes and mount them.
        Raises SideScanUnavailable (no boto3 / deferred fs extraction) so the
        caller emits a clean CWPP-04 INFO no-op."""
        import aws_sidescan_ebs
        try:
            ec2 = self._client("ec2")
            ebs = self._client("ebs")
        except Exception as e:
            raise aws_sidescan_ebs.SideScanUnavailable(str(e))
        return aws_sidescan_ebs.mounted_snapshots(ec2, ebs, vol_ids,
                                                  scan_id=self._sidescan_scan_id())

    def _check_side_scan(self):
        self._section_header("SIDESCAN")
        if not self.side_scan:
            return
        self._log("Agentless EBS-snapshot side-scan: OS-package CVEs + on-disk "
                  "secrets -> HAS_VULN edges feeding attack-path correlation "
                  "(Inspector-independent). Snapshots are scanner-owned + auto-cleaned.")
        import aws_sidescan_ebs
        feed_bundle = self._load_vuln_db()
        if feed_bundle is None and self.vuln_db_path is None:
            self._add("INFO", "CWPP-04", "SIDESCAN", "vuln-db",
                      "no --vuln-db supplied; inventory + secrets only, CVE match skipped")
        g = self._ensure_graph()
        targets = self._select_sidescan_targets(g)
        if not targets:
            self._add("INFO", "CWPP-04", "SIDESCAN", "sidescan",
                      f"no in-scope instances (target mode: {self.side_scan_targets})")
            return
        opener = self._sidescan_extractor_opener or self._default_extractor_opener
        feed = feed_bundle[0] if feed_bundle else None
        epss = feed_bundle[1] if feed_bundle else {}
        kev = feed_bundle[2] if feed_bundle else set()
        exploits = feed_bundle[3] if feed_bundle else set()
        scanned = 0
        per_instance: List[Dict] = []
        for iid, vol_ids in targets:
            arn = self._instance_arn(iid)
            try:
                with opener(vol_ids, iid) as extractor:
                    res = aws_sidescan.sidescan_filesystem(
                        extractor, feed, epss, kev, exploits,
                        instance_id=iid, do_secrets=self.side_scan_secrets)
            except aws_sidescan_ebs.SideScanUnavailable as e:
                self._add("INFO", "CWPP-04", "SIDESCAN", iid,
                          f"agentless side-scan unavailable for {iid} ({e})")
                continue
            except Exception as e:
                self._add("WARN", "CWPP-04", "SIDESCAN", iid,
                          f"side-scan of {iid} failed: {e}")
                continue
            scanned += 1
            n_edges = aws_sidescan.emit_vuln_edges(g, arn, iid, res.vulns,
                                                   snapshot_id=self._sidescan_scan_id())
            for m in res.vulns:
                fid = "CWPP-02" if m.kev else "CWPP-01"
                osname = res.os.ecosystem if res.os else "?"
                self._add("FAIL", fid, "SIDESCAN", iid,
                          f"agentless {m.severity} {m.cve} (EPSS {m.epss}, "
                          f"exploit={m.exploit_available}, "
                          f"fix={'YES' if m.fixed_version else 'NO'}) in {m.package} "
                          f"{m.installed_version} on {osname} | {iid}")
            for s in res.secrets:
                self._add("FAIL", "CWPP-03", "SIDESCAN", iid,
                          f"{s.kind} on disk at {s.path}:{s.line} ({s.match_preview}) | {iid}")
            for note in res.notes:
                self._add("INFO", "CWPP-04", "SIDESCAN", iid, f"{note} | {iid}")
            per_instance.append({
                "instance_id": iid, "os": res.os.ecosystem if res.os else None,
                "packages": len(res.packages), "vulns": len(res.vulns),
                "secrets": len(res.secrets), "edges_added": n_edges, "notes": res.notes})
        self._side_scan_report = {
            "enabled": True, "target_mode": self.side_scan_targets,
            "targets_selected": len(targets), "targets_scanned": scanned,
            "vuln_db": self.vuln_db_path, "per_instance": per_instance}
        if scanned == 0:
            self._add("INFO", "CWPP-04", "SIDESCAN", "sidescan",
                      f"selected {len(targets)} instance(s) but none could be read "
                      "(live EBS extraction is deferred to Phase 7)")

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
            sts          = (self._session or boto3).client("sts", region_name=self.region)
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
            "AMI":            self._check_ami,
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
            "EXPOSURE":       self._check_exposure,
            "SIDESCAN":       self._check_side_scan,
            "VULN":           self._check_vuln,
            "THREAT":         self._check_threat,
            "DATA":           self._check_data,
            "CORRELATE":      self._check_correlate,
        }

        base_region = self.region
        for section in self.sections:
            fn = CHECK_MAP.get(section)
            if not fn:
                continue
            for reg in self._regions_for_section(section):
                self.region = reg
                try:
                    fn()
                except Exception as e:
                    self._add("FAIL", section, section, section,
                              f"Unhandled error in section {section}"
                              f"{f' ({reg})' if reg != base_region else ''}: {e}")
            self.region = base_region

    def _regions_for_section(self, section: str) -> List[str]:
        """Regions to run a section in. Single-region by default; with
        --all-regions, regional sections sweep every enabled region while global
        sections (IAM/S3/Route53/CloudFront/IAMPRIVESC) still run once."""
        if not self.all_regions_scan or section in self.GLOBAL_SECTIONS:
            return [self.region]
        return self._get_all_regions()

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

    def print_compliance_rollup(self):
        """Per-framework control pass/fail scorecard (aggregates the compliance
        tags carried by every finding)."""
        card = compliance_scorecard(self.results)
        print(f"\n{BOLD}{BLUE}══ COMPLIANCE SCORECARD ══{RESET}")
        print(f"  {'Framework':<10} {'Pass':>5} {'Fail':>5} {'Total':>6} {'Rate':>7}")
        print(f"  {'-'*10} {'-'*5} {'-'*5} {'-'*6} {'-'*7}")
        for f in COMPLIANCE_FRAMEWORKS:
            c = card[f]
            rate = c["pass_rate"]
            col = GREEN if rate >= 80 else (YELLOW if rate >= 50 else RED)
            print(f"  {f:<10} {c['controls_passed']:>5} {c['controls_failed']:>5} "
                  f"{c['controls_total']:>6} {col}{rate:>6}%{RESET}")
        # Show the failed controls for the most-referenced framework (CIS/PCI)
        for f in ("CIS", "PCI-DSS"):
            failed = card[f]["failed_controls"]
            if failed:
                print(f"  {YELLOW}{f} failed controls:{RESET} {', '.join(failed[:12])}"
                      f"{f' +{len(failed)-12} more' if len(failed) > 12 else ''}")
        return card

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
            "compliance_scorecard": compliance_scorecard(self.results),
            "graph": self.graph.stats() if self.graph else None,
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "choke_points": [c.to_dict() for c in self.choke_points],
            # Phase 5: effective-permissions ceiling audit — always present so the
            # 'effective' verdicts never over-claim when the ceiling was unreadable.
            "effective_permissions": {
                "boundary_evaluated": self._boundary_evaluated,
                "scp_evaluated": self._scp_evaluated,
                "pruned_edges": self._pruned_edges,
                "downgraded_edges": self._downgraded_edges,
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
        # Phase 5: persistent-state blocks — only when a --state store ran, so
        # JSON consumers asserting the current key set are unaffected.
        if self._state_report:
            data.update(self._state_report)
        if self._unused_report is not None:
            data["unused_access"] = self._unused_report
        # Phase 6: side-scan / backend / graph-export blocks — present only when
        # their feature ran, so existing JSON consumers are unaffected.
        if self._side_scan_report:
            data["side_scan"] = self._side_scan_report
        if self._backend_meta:
            data["backend"] = self._backend_meta
        if self._graph_export_meta:
            data["graph_export"] = self._graph_export_meta
        # Phase 7: remediation plan / code-to-cloud — present only when generated.
        if self._remediation_report:
            data["remediation"] = self._remediation_report
        if self._code_to_cloud_meta:
            data["code_to_cloud"] = self._code_to_cloud_meta
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
# ─── Multi-account (AWS Organizations) orchestration ─────────────────────────
def assume_role_session(account_id: str, role: str, external_id: Optional[str] = None,
                        region: str = "us-east-1", base_session=None):
    """Assume ``role`` in ``account_id`` and return a boto3.Session with the
    temporary credentials. ``role`` may be a bare role name (resolved to
    ``arn:aws:iam::<account>:role/<role>``) or a full ARN. Read-only apart from
    the sts:AssumeRole itself."""
    base = base_session or boto3
    sts = base.client("sts", region_name=region)
    role_arn = role if role.startswith("arn:") else f"arn:aws:iam::{account_id}:role/{role}"
    kwargs = {"RoleArn": role_arn, "RoleSessionName": "cnapp-scan"}
    if external_id:
        kwargs["ExternalId"] = external_id
    creds = sts.assume_role(**kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def list_org_accounts(base_session=None, region: str = "us-east-1") -> List[str]:
    """Return the IDs of all ACTIVE accounts in the AWS Organization. Requires
    ``organizations:ListAccounts`` from the management or a delegated-admin account."""
    base = base_session or boto3
    org = base.client("organizations", region_name=region)
    ids: List[str] = []
    for page in org.get_paginator("list_accounts").paginate():
        for a in page.get("Accounts", []):
            if a.get("Status") == "ACTIVE":
                ids.append(a["Id"])
    return ids


def aggregate_results(scanners: List["AWSLiveScanner"]) -> "AWSLiveScanner":
    """Fold N per-account scanners into one aggregate scanner whose ``results``
    are all findings with each ``resource`` prefixed by its account id, and whose
    ``graph`` is the union of the per-account identity graphs. Lets every existing
    emitter (JSON/SARIF/ASFF/HTML/scorecard) work unchanged across a whole org."""
    agg = AWSLiveScanner(region=scanners[0].region if scanners else "us-east-1",
                         sections=scanners[0].sections if scanners else None)
    merged = SecurityGraph()
    for sc in scanners:
        for r in sc.results:
            resource = f"{sc.account}/{r.resource}" if r.resource else sc.account
            agg.results.append(Result(r.status, r.check_id, r.section, resource,
                                      r.message, r.severity, r.compliance,
                                      r.remediation_cmd))
        if sc.graph:
            merged.merge(sc.graph)
    agg.graph = merged if len(merged) else None
    agg.account = f"org:{len(scanners)}-accounts"
    return agg


def _parse_expires(when: Optional[str], created_epoch: int) -> Optional[int]:
    """Parse a waiver expiry: relative ('30d','12h','45m') or ISO8601 -> epoch.
    Returns None only when `when` is empty/omitted (deliberate = no expiry).
    Raises ValueError on a non-empty but unparseable value, so a typo can never
    silently downgrade a time-boxed waiver into a permanent suppression."""
    if not when:
        return None
    w = when.strip().lower()
    if w and w[-1] in ("d", "h", "m") and w[:-1].isdigit():
        mult = {"d": 86400, "h": 3600, "m": 60}[w[-1]]
        return created_epoch + int(w[:-1]) * mult
    try:
        dt = datetime.fromisoformat(when.replace("Z", "+00:00"))
    except Exception:
        raise ValueError("expected a relative window like '30d'/'12h'/'45m' or an "
                         "ISO8601 date")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _default_state_path() -> str:
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        return os.path.join(xdg, "cnapp", "state.db")
    return os.path.join(".cnapp", "state.db")


def _process_state(store, scanner, args, scan_epoch: int) -> List:
    """Run the persistent-state pipeline for ONE scanner (its own account):
    apply a --suppress waiver, classify this scan's findings (lifecycle + drift),
    record posture, attach a state report for save_json, and return the GATING
    results (suppressed findings removed). Prints a concise drift/trend summary."""
    acct = scanner.account
    ts = aws_state.make_scan_ts(scan_epoch)

    # A --suppress waiver is applied BEFORE classification so the first classified
    # scan already reflects it.
    if args.suppress:
        key = args.suppress
        if "|" in key:
            match = {"type": "exact", "finding_key": key, "account": acct}
        else:  # 'check:resource' glob form
            cg, _, rg = key.partition(":")
            match = {"type": "glob", "check_glob": cg or "*",
                     "resource_glob": rg or "*", "account": acct}
        wid = store.apply_waiver(match, approver=args.approver or "unknown",
                                 reason=args.reason or "", created_epoch=scan_epoch,
                                 expires_epoch=_parse_expires(args.expires, scan_epoch))
        print(f"{BLUE}[*]{RESET} Waiver #{wid} recorded for '{args.suppress}' "
              f"(approver: {args.approver}).")

    scan_id = f"{acct}-{scan_epoch}"
    counts = aws_state.severity_counts(scanner.results)
    store.record_scan(acct, scan_id, ts, compute_risk_score(scanner.results),
                      counts, region=scanner.region, scanner_version=VERSION)
    drift = store.classify_and_diff(acct, scan_id, ts, scanner.results,
                                    region=scanner.region,
                                    global_sections=AWSLiveScanner.GLOBAL_SECTIONS)
    store.record_posture(acct, scan_id, drift)

    trend = store.trend(acct)
    mttr = store.mttr(acct, by_severity=True, sla_days=args.sla_days, now_epoch=scan_epoch)
    scanner._state_report = {
        "drift": drift,
        "trend": trend,
        "mttr": mttr,
        "waivers": store.list_waivers(acct, scan_epoch=scan_epoch),
    }

    # Console summary
    print(f"\n{BOLD}{BLUE}══ DRIFT (account {acct}) ══{RESET}")
    print(f"  new: {len(drift['new'])}  resolved: {len(drift['resolved'])}  "
          f"reopened: {len(drift['reopened'])}  mutated: {len(drift['mutated'])}  "
          f"still-open: {drift['still_open']}  suppressed: {drift['suppressed_count']}")
    if drift["posture_delta"] is not None:
        arrow = "▲" if drift["posture_delta"] > 0 else ("▼" if drift["posture_delta"] < 0 else "=")
        print(f"  posture Δ vs previous scan: {arrow} {drift['posture_delta']:+}")
    if mttr.get("mean_seconds") is not None:
        print(f"  MTTR (mean): {mttr['mean_seconds'] / 86400:.1f}d over "
              f"{mttr['resolved_count']} resolved finding(s)")
    if mttr.get("open_over_sla"):
        print(f"  {YELLOW}{mttr['open_over_sla']} finding(s) open past the "
              f"{args.sla_days}d SLA{RESET}")

    gating, suppressed = store.filter_suppressed(acct, scanner.results, scan_epoch,
                                                 region=scanner.region)
    if suppressed:
        # A waiver is an accepted-risk GATING decision, not a remediation, so the
        # posture score legitimately stays depressed (the risk still exists).
        print(f"  {len(suppressed)} finding(s) suppressed by waivers "
              f"(excluded from --fail-on gating; still tracked and still counted "
              f"in the posture score).")
    return gating


def _run_ciem(scanner, args, scan_epoch: int, store=None) -> None:
    """CIEM right-sizing pass (opt-in --ciem). For each enumerated principal,
    resolve an unused-access signal (IAM SLAD + Access Analyzer), emit a LOW
    CIEM-01 right-sizing finding for dormant/over-permissioned principals, and
    apply a bounded, NON-mutating exploit-likelihood down-rank overlay to the
    ranked attack paths (impact untouched; a dormant path is never suppressed
    below the reporting threshold). Degrades gracefully: unknown dormancy => no
    down-rank => prior behavior. Persists usage to the state store when present."""
    try:
        principals = scanner._get_iam_principals()
    except Exception as e:
        print(f"{YELLOW}[WARN]{RESET} CIEM skipped (could not enumerate principals: {e}).")
        return
    if not principals:
        return
    try:
        iam = scanner._client("iam")
    except Exception:
        iam = None
    try:
        aa = scanner._client("accessanalyzer")
    except Exception:
        aa = None
    analyzer_arn = aws_unused.find_unused_access_analyzer(aa)
    signals, factor_by_arn, report = [], {}, []
    fresh_after = scan_epoch - 24 * 3600     # 24h usage-cache TTL
    for p in principals:
        arn = p.get("arn")
        if not arn:
            continue
        sig = None
        if store is not None:
            cached = store.get_usage(scanner.account, arn, fresh_after)
            if cached:
                sig = aws_unused.UnusedSignal(
                    arn=arn, source=cached.get("source") or "NONE",
                    dormant=None if cached.get("dormant") is None else bool(cached["dormant"]),
                    last_used_epoch=cached.get("last_used_epoch"),
                    last_used_iso=cached.get("last_used_iso"),
                    window_days=cached.get("window_days") or aws_unused.DORMANT_AGE_DAYS)
        if sig is None:
            sig = aws_unused.unused_signal_for(arn, iam, aa, scan_epoch,
                                               analyzer_arn=analyzer_arn)
            if store is not None:
                try:
                    store.record_usage(scanner.account, arn, sig.to_dict(), scan_epoch)
                except Exception:
                    pass
        signals.append(sig)
        factor_by_arn[arn] = aws_unused.dormancy_factor(sig, scan_epoch)
        rs = aws_unused.right_sizing_finding(sig)
        if rs:
            # Advisory 'review candidate' — WARN (LOW severity), never auto-delete.
            scanner._add("WARN", rs["check_id"], "IAMPRIVESC",
                         rs["resource"], rs["message"])
            report.append(sig.to_dict())
    scanner._unused_report = report
    overlay = aws_unused.downrank_overlay(scanner.attack_paths, factor_by_arn)
    if overlay:
        scanner._state_report = scanner._state_report or {}
        # attach as an annotation; the ranked paths themselves are unchanged
        scanner._state_report["path_downrank"] = overlay
        print(f"{BLUE}[*]{RESET} CIEM: {len(report)} right-sizing finding(s); "
              f"{len(overlay)} attack path(s) traverse a dormant principal "
              f"(exploit-likelihood down-ranked, still reported).")


def _backend_meta_for(args, scheme: str, available: bool, reason: Optional[str] = None):
    """Backend metadata for save_json — ONLY when the --backend feature ran.
    A plain --state / --list-waivers run (Phase-5 flags, default sqlite) must not
    inject a top-level 'backend' key that did not exist pre-Phase-6, so this
    returns None unless --backend was explicitly given."""
    if not getattr(args, "backend", None):
        return None
    meta = {"scheme": scheme, "available": available}
    if available:
        meta["url"] = args.backend
    else:
        meta["reason"] = reason
    return meta


def _apply_phase6_config(sc, args) -> None:
    """Copy the Phase-6 side-scan flags onto a scanner before it runs."""
    sc.side_scan = args.side_scan
    sc.side_scan_targets = args.side_scan_targets
    sc.side_scan_tags = args.side_scan_tag or []
    sc.side_scan_max = max(1, min(args.side_scan_max, 500))
    sc.side_scan_secrets = args.side_scan_secrets
    sc.vuln_db_path = args.vuln_db


def _export_graph_neptune(scanner, args) -> None:
    """Write Neptune bulk-load CSV and/or openCypher upsert files from the built
    graph (pure; no boto3). Fail-open to a WARN when no graph exists, exactly like
    --graph."""
    if not (args.graph_neptune_csv or args.graph_neptune_cypher):
        return
    if scanner.graph is None:
        print(f"{YELLOW}[WARN]{RESET} No graph built — cannot export to Neptune "
              "(include the IAMPRIVESC/EXPOSURE sections).")
        return
    meta: Dict = {}
    if args.graph_neptune_csv:
        bundle = aws_graph_neptune.to_gremlin_csv(scanner.graph)
        os.makedirs(args.graph_neptune_csv, exist_ok=True)
        written = []
        for label, text in bundle.vertex_files.items():
            p = os.path.join(args.graph_neptune_csv, f"vertices_{label}.csv")
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write(text)
            written.append(p)
        for label, text in bundle.edge_files.items():
            p = os.path.join(args.graph_neptune_csv, f"edges_{label}.csv")
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write(text)
            written.append(p)
        with open(os.path.join(args.graph_neptune_csv, "manifest.json"), "w",
                  encoding="utf-8") as f:
            json.dump(bundle.manifest, f, indent=2)
        meta["gremlin_csv"] = {"dir": args.graph_neptune_csv, "files": len(written)}
        print(f"{BLUE}[*]{RESET} Neptune bulk-load CSV exported: {len(written)} files "
              f"to {args.graph_neptune_csv}")
    if args.graph_neptune_cypher:
        plan = aws_graph_neptune.to_opencypher_upsert(scanner.graph)
        with open(args.graph_neptune_cypher, "w", encoding="utf-8") as f:
            json.dump([{"query": q, "params": p} for q, p in plan], f, indent=2)
        meta["opencypher"] = {"file": args.graph_neptune_cypher, "batches": len(plan)}
        print(f"{BLUE}[*]{RESET} openCypher upsert plan exported: {len(plan)} batches "
              f"to {args.graph_neptune_cypher}")
    scanner._graph_export_meta = meta


def _run_remediation(scanner, args) -> None:
    """Phase 7: build a prioritized remediation plan (reusing the correlate ranking)
    + remediation-as-code, and write the requested export artifacts. Read-only —
    generates artifacts only, never applies a change. Fail-open."""
    if not args.remediate:
        return
    try:
        import aws_remediate
        matcher = None
        if args.iac_dir:
            import aws_codetocloud
            idx = aws_codetocloud.build_iac_index(args.iac_dir)
            matcher = idx.matcher()
            scanner._code_to_cloud_meta = {"iac_dirs": list(args.iac_dir),
                                           "resources_indexed": len(idx.resources)}
        g = scanner.graph
        nk = (lambda nid: (g.node(nid) or {}).get("kind")) if g else (lambda nid: None)
        npf = (lambda nid: (g.node(nid) or {}).get("props", {})) if g else (lambda nid: {})
        oe = g.out_edges if g else (lambda nid, kinds=None: [])
        lo = (lambda nid: aws_correlate._label(g, nid)) if g else (lambda nid: nid)
        plan = aws_remediate.build_plan(
            scanner.results, scanner.attack_paths, scanner.choke_points,
            node_kind=nk, label_of=lo, node_props=npf, out_edges=oe,
            min_severity=args.remediate_min_severity, iac_matcher=matcher,
            region=scanner.region, account=scanner.account)
        scanner._remediation_report = aws_remediate.plan_to_json(plan)
        print(f"\n{BOLD}{BLUE}══ REMEDIATION ══{RESET}  {plan.headline()}")
        if args.remediate_out:
            os.makedirs(args.remediate_out, exist_ok=True)
            fmts = {f.strip().lower() for f in (args.remediate_format or "").split(",")}
            written = []
            if "json" in fmts:
                p = os.path.join(args.remediate_out, "remediation_plan.json")
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(aws_remediate.plan_to_json(plan), f, indent=2)
                written.append(p)
            if "md" in fmts:
                p = os.path.join(args.remediate_out, "remediation_runbook.md")
                with open(p, "w", encoding="utf-8") as f:
                    f.write(aws_remediate.to_markdown(plan))
                written.append(p)
            if "issue" in fmts:
                p = os.path.join(args.remediate_out, "remediation_issue.md")
                with open(p, "w", encoding="utf-8") as f:
                    f.write(aws_remediate.to_github_issue(plan))
                written.append(p)
            if "pr" in fmts:
                p = os.path.join(args.remediate_out, "remediation_pr.md")
                with open(p, "w", encoding="utf-8") as f:
                    f.write(aws_remediate.to_github_pr_body(plan))
                written.append(p)
            if written:
                print(f"{BLUE}[*]{RESET} Remediation artifacts written: {', '.join(written)}")
    except Exception as e:
        print(f"{YELLOW}[WARN]{RESET} Remediation unavailable ({e}); continuing.")


def _run_neptune_load(scanner, args) -> None:
    """Phase 7: push the Gremlin CSV export to a live Neptune cluster. Degrades to
    the file export (already written) when boto3 or the required args are absent."""
    if not args.graph_neptune_load:
        return
    if scanner.graph is None:
        print(f"{YELLOW}[WARN]{RESET} --graph-neptune-load: no graph built; skipped.")
        return
    if not (args.neptune_s3_bucket and args.neptune_iam_role):
        print(f"{YELLOW}[WARN]{RESET} --graph-neptune-load needs --neptune-s3-bucket "
              "and --neptune-iam-role; wrote local files only.")
        return
    try:
        import aws_graph_neptune_loader as loader
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        out = loader.run_gremlin_bulk_load(
            scanner.graph, s3=scanner._client("s3"),
            neptunedata=scanner._client("neptunedata"),
            bucket=args.neptune_s3_bucket, prefix="cnapp-graph",
            scan_id=f"{scanner.account}-{ts}", iam_role_arn=args.neptune_iam_role,
            region=args.neptune_region or scanner.region)
        scanner._graph_export_meta = {**(scanner._graph_export_meta or {}),
                                      "neptune_load": out}
        print(f"{BLUE}[*]{RESET} Neptune bulk load: {out['status']} "
              f"(loadId {out.get('loadId')})")
    except Exception as e:
        print(f"{YELLOW}[WARN]{RESET} Neptune load failed ({e}); local files still written.")


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
  python aws_live_scanner.py --all-regions --compliance --graph graph.json
  python aws_live_scanner.py --org --assume-role OrganizationAccountAccessRole --json org.json
  python aws_live_scanner.py --accounts 111122223333,444455556666 --assume-role AuditRole --external-id abc
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
        "--all-regions", dest="all_regions", action="store_true",
        help="Sweep every enabled region for regional sections "
             "(global sections still run once)",
    )
    parser.add_argument(
        "--assume-role", metavar="ROLE", dest="assume_role",
        help="Role name (or ARN) to assume in each target account for "
             "multi-account scanning (e.g. OrganizationAccountAccessRole)",
    )
    parser.add_argument(
        "--org", action="store_true",
        help="Enumerate all ACTIVE accounts via AWS Organizations and scan each "
             "(requires --assume-role)",
    )
    parser.add_argument(
        "--accounts", metavar="IDS",
        help="Comma-separated account IDs to scan (requires --assume-role); "
             "alternative to --org",
    )
    parser.add_argument(
        "--external-id", metavar="ID", dest="external_id",
        help="STS ExternalId to use when assuming the target role",
    )
    parser.add_argument(
        "--graph", metavar="FILE",
        help="Save the identity security graph (nodes/edges) as JSON to FILE "
             "— the Neptune migration seed",
    )
    parser.add_argument(
        "--compliance", action="store_true",
        help="Print the per-framework compliance scorecard (CIS/PCI/HIPAA/SOC2/NIST)",
    )
    # ── Phase 5: persistent state / drift / waivers ──────────────────────────
    parser.add_argument(
        "--state", metavar="FILE",
        help="SQLite state DB for finding lifecycle, drift, MTTR and posture "
             "trend across scans (default location ./.cnapp/state.db if omitted). "
             "Supersedes the ephemeral --baseline diff when given.",
    )
    parser.add_argument(
        "--suppress", metavar="KEY",
        help="Waive a finding so it stops failing the build (still tracked/open). "
             "KEY is an exact finding key 'check_id|resource' or a glob "
             "'check:resource'. Requires --approver and --state.",
    )
    parser.add_argument(
        "--approver", metavar="NAME",
        help="Approver recorded on a --suppress waiver (required with --suppress)",
    )
    parser.add_argument(
        "--reason", metavar="TEXT", default="",
        help="Reason recorded on a --suppress waiver",
    )
    parser.add_argument(
        "--expires", metavar="WHEN",
        help="Waiver expiry: relative ('30d','12h','45m') or ISO8601 date. Omit "
             "for no expiry. An expired waiver auto-reactivates on the next scan.",
    )
    parser.add_argument(
        "--list-waivers", dest="list_waivers", action="store_true",
        help="Print active/expired/revoked waivers for the account (requires --state)",
    )
    parser.add_argument(
        "--sla-days", metavar="N", dest="sla_days", type=int,
        help="SLA window in days — report the count of findings open past it",
    )
    parser.add_argument(
        "--ciem", action="store_true",
        help="CIEM right-sizing pass: flag dormant/over-permissioned principals "
             "(IAM service-last-accessed + Access Analyzer unused-access) and "
             "down-rank attack paths through them. Extra API calls; off by default.",
    )
    # ── Phase 6: agentless side-scan + persistence/export ────────────────────
    parser.add_argument(
        "--side-scan", dest="side_scan", action="store_true",
        help="Agentless EBS-snapshot side-scan: inventory OS packages + match CVEs "
             "+ find on-disk secrets, adding HAS_VULN edges to the attack-path graph "
             "(works even when Amazon Inspector is disabled). Off by default.",
    )
    parser.add_argument(
        "--side-scan-targets", dest="side_scan_targets", default="exposed",
        choices=["exposed", "all", "tagged"],
        help="Which instances to side-scan: exposed (internet-reachable, default) | "
             "all | tagged (requires --side-scan-tag)",
    )
    parser.add_argument(
        "--side-scan-tag", dest="side_scan_tag", action="append", metavar="K=V",
        help="Tag filter for --side-scan-targets tagged (repeatable)",
    )
    parser.add_argument(
        "--side-scan-max", dest="side_scan_max", type=int, default=20,
        help="Hard cap on instances to side-scan (default 20)",
    )
    parser.add_argument(
        "--no-side-scan-secrets", dest="side_scan_secrets", action="store_false",
        help="Skip the on-disk secret scan during side-scan (CVEs only)",
    )
    parser.add_argument(
        "--vuln-db", dest="vuln_db", metavar="FILE",
        help="Offline OSV vulnerability feed (JSON) for side-scan CVE matching. "
             "A raw OSV record list, or {osv,epss,kev,exploits}. Absent = inventory "
             "+ secrets only.",
    )
    parser.add_argument(
        "--backend", metavar="URL",
        help="State-store backend URL: sqlite:///path (default) or postgresql://... "
             "(Postgres is deferred to Phase 7 — a postgresql:// URL runs stateless). "
             "Overrides --state when given.",
    )
    parser.add_argument(
        "--graph-neptune-csv", dest="graph_neptune_csv", metavar="DIR",
        help="Export the security graph as Amazon Neptune bulk-load CSV files to DIR",
    )
    parser.add_argument(
        "--graph-neptune-cypher", dest="graph_neptune_cypher", metavar="FILE",
        help="Export the security graph as idempotent openCypher UNWIND/MERGE "
             "statements (JSON) to FILE",
    )
    # ── Phase 7: remediation / code-to-cloud ─────────────────────────────────
    parser.add_argument(
        "--remediate", action="store_true",
        help="Generate a prioritized remediation plan (fix the choke points that "
             "sever the most attack paths first) with remediation-as-code. Read-only "
             "— it produces artifacts, never applies changes.",
    )
    parser.add_argument(
        "--remediate-out", dest="remediate_out", metavar="DIR",
        help="Directory to write the remediation runbook/plan/PR artifacts to",
    )
    parser.add_argument(
        "--remediate-format", dest="remediate_format", metavar="FMT", default="md,json",
        help="Comma-separated remediation export formats: md,json,issue,pr (default md,json)",
    )
    parser.add_argument(
        "--remediate-min-severity", dest="remediate_min_severity", metavar="SEV",
        default="MEDIUM", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity for the posture long-tail of the remediation plan",
    )
    parser.add_argument(
        "--iac-dir", dest="iac_dir", metavar="DIR", action="append",
        help="Terraform/CloudFormation directory to enable code-to-cloud: map "
             "findings back to the IaC source resource + propose the diff (repeatable)",
    )
    parser.add_argument(
        "--graph-neptune-load", dest="graph_neptune_load", action="store_true",
        help="Push the Neptune graph export to a live cluster (needs boto3 + "
             "--neptune-s3-bucket/--neptune-iam-role); degrades to file export if absent",
    )
    parser.add_argument("--neptune-s3-bucket", dest="neptune_s3_bucket", metavar="BUCKET")
    parser.add_argument("--neptune-iam-role", dest="neptune_iam_role", metavar="ARN")
    parser.add_argument("--neptune-region", dest="neptune_region", metavar="REGION")
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

    # ── Phase 5 flag validation ──────────────────────────────────────────────
    if args.suppress and not (args.approver and args.state):
        print(f"{RED}[ERROR]{RESET} --suppress requires both --approver and --state.")
        sys.exit(2)
    if args.list_waivers and not args.state:
        print(f"{RED}[ERROR]{RESET} --list-waivers requires --state.")
        sys.exit(2)
    if args.expires:
        # Reject a malformed expiry BEFORE any scan work, so a typo never silently
        # becomes a permanent (never-expiring) suppression of a real FAIL.
        try:
            _parse_expires(args.expires, int(datetime.now(timezone.utc).timestamp()))
        except ValueError as e:
            print(f"{RED}[ERROR]{RESET} Invalid --expires '{args.expires}': {e}")
            sys.exit(2)

    # ── Phase 6 flag validation + section wiring ─────────────────────────────
    if args.side_scan:
        if args.side_scan_targets == "tagged" and not args.side_scan_tag:
            print(f"{RED}[ERROR]{RESET} --side-scan-targets tagged requires at least "
                  "one --side-scan-tag K=V.")
            sys.exit(2)
        if args.side_scan_max < 1:
            print(f"{RED}[ERROR]{RESET} --side-scan-max must be >= 1.")
            sys.exit(2)
        # SIDESCAN is not in the default SECTIONS set — wire it in explicitly so it
        # runs AFTER EXPOSURE (needs the EC2Instance nodes) and BEFORE VULN/DATA/CORRELATE.
        if sections is None:
            sections = list(SECTIONS)
        if "SIDESCAN" not in sections:
            if "VULN" in sections:
                sections.insert(sections.index("VULN"), "SIDESCAN")
            else:
                sections.append("SIDESCAN")

    # ── Multi-account (Organizations / explicit accounts) vs single-account ──
    if args.org or args.accounts:
        if not args.assume_role:
            print(f"{RED}[ERROR]{RESET} --org/--accounts require --assume-role "
                  "<role-name> to assume in each target account.")
            sys.exit(2)
        try:
            account_ids = (
                list_org_accounts(region=args.region) if args.org
                else [a.strip() for a in args.accounts.split(",") if a.strip()]
            )
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Could not enumerate target accounts: {e}")
            sys.exit(2)

        scanners: List[AWSLiveScanner] = []
        for acct in account_ids:
            try:
                sess = assume_role_session(acct, args.assume_role,
                                           args.external_id, args.region)
            except Exception as e:
                print(f"{YELLOW}[WARN]{RESET} Skipping {acct}: could not assume "
                      f"{args.assume_role} ({e})")
                continue
            sc = AWSLiveScanner(region=args.region, verbose=args.verbose,
                                sections=sections, session=sess,
                                all_regions=args.all_regions)
            _apply_phase6_config(sc, args)
            sc.run()
            sc.print_report()
            scanners.append(sc)

        if not scanners:
            print(f"{RED}[ERROR]{RESET} No accounts could be scanned.")
            sys.exit(2)
        scanner = aggregate_results(scanners)
        print(f"\n{BOLD}{BLUE}══ ORG-WIDE AGGREGATE ({len(scanners)} accounts) ══{RESET}")
        counts = scanner.print_report()
    else:
        scanner = AWSLiveScanner(
            region=args.region,
            verbose=args.verbose,
            sections=sections,
            all_regions=args.all_regions,
        )
        _apply_phase6_config(scanner, args)
        scanner.run()
        counts = scanner.print_report()

    if args.compliance:
        scanner.print_compliance_rollup()

    # ── Phase 5: persistent state / drift / waivers (per-account) ────────────
    # Applied BEFORE report generation so drift/trend/MTTR land in the JSON, and
    # the returned gating results drive the exit code. Fail-open: any state error
    # falls back to the raw results (prior behavior).
    gating_results = scanner.results
    scan_epoch = int(datetime.now(timezone.utc).timestamp())
    store = None
    state_url = args.backend or args.state
    want_state = bool(state_url) or args.list_waivers
    if want_state:
        import aws_state_dialect
        scheme = aws_state_dialect.parse_state_url(state_url or "")[0]
        try:
            store = aws_state.open(state_url or _default_state_path())
            scanner._backend_meta = _backend_meta_for(args, scheme, True)
            state_targets = scanners if (args.org or args.accounts) else [scanner]
            if args.list_waivers:
                seen = set()
                for tgt in state_targets:
                    if tgt.account in seen:
                        continue
                    seen.add(tgt.account)
                    print(f"\n{BOLD}Waivers — account {tgt.account}{RESET}")
                    for w in store.list_waivers(tgt.account, scan_epoch=scan_epoch):
                        match = w.get("finding_key") or f"{w.get('check_glob')}:{w.get('resource_glob')}"
                        print(f"  #{w['id']} [{w['state']}] {w['match_type']} {match} "
                              f"approver={w['approver']} expires={w.get('expires_epoch')}")
            if state_url:
                combined: List = []
                for tgt in state_targets:
                    combined += _process_state(store, tgt, args, scan_epoch)
                gating_results = combined
                # For the aggregate JSON, surface the per-account state reports.
                if state_targets and scanner is not state_targets[0]:
                    scanner._state_report = {
                        "accounts": [t.account for t in state_targets],
                        "per_account": {t.account: t._state_report
                                        for t in state_targets if t._state_report},
                    }
        except Exception as e:
            print(f"{YELLOW}[WARN]{RESET} State store unavailable ({e}); "
                  "continuing stateless.")
            scanner._backend_meta = _backend_meta_for(args, scheme, False, str(e))
            store = None

    # ── Phase 5C: CIEM right-sizing / dormancy down-rank (opt-in) ─────────────
    if args.ciem:
        try:
            ciem_targets = scanners if (args.org or args.accounts) else [scanner]
            for tgt in ciem_targets:
                _run_ciem(tgt, args, scan_epoch, store=store)
        except Exception as e:
            print(f"{YELLOW}[WARN]{RESET} CIEM pass failed ({e}); continuing.")

    if store is not None:
        store.close()

    # Phase 6: Neptune graph export (before save_json so its metadata lands there)
    _export_graph_neptune(scanner, args)
    # Phase 7: live Neptune load + remediation plan (before save_json)
    _run_neptune_load(scanner, args)
    _run_remediation(scanner, args)

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
    if args.graph:
        if scanner.graph:
            scanner.graph.save_json(args.graph)
            print(f"{BLUE}[*]{RESET} Security graph saved: {args.graph} "
                  f"({scanner.graph.stats()['nodes']} nodes, "
                  f"{scanner.graph.stats()['edges']} edges)")
        else:
            print(f"{YELLOW}[WARN]{RESET} No graph built — include the IAMPRIVESC "
                  "section (it is in the default set) to populate the identity graph.")

    # Always save evidence (auto-name dir if not specified)
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = args.output_dir or f"aws_audit_{scanner.account}_{ts}"
    scanner.save_evidence(out_dir)

    # Exit code: gate on --fail-on threshold if given, else any FAIL. Gating runs
    # on the waiver-filtered results, so a suppressed FAIL cannot fail the build.
    if args.fail_on:
        failed = fails_threshold(gating_results, args.fail_on)
    else:
        failed = any(r.status == "FAIL" for r in gating_results)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
