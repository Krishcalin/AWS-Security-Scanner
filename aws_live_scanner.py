#!/usr/bin/env python3
"""
AWS Live Security Scanner v1.0.0
Read-only live audit of AWS environments via boto3.

Aligned to: CIS AWS Foundations Benchmark v3.0
            AWS Well-Architected Framework — Security Pillar

16 service domains:
  IAM · S3 · VPC/Network · Logging & Monitoring · KMS · EC2
  ECR · Backup · RDS · Glacier · SNS · SQS · CloudFront
  Route 53 · Bedrock · Bedrock Agent Core

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
import argparse
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

VERSION = "1.0.0"

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
}


# ─── Result dataclass ─────────────────────────────────────────────────────────
@dataclass
class Result:
    status:   str   # PASS | FAIL | WARN | INFO
    check_id: str   # e.g. IAM-01
    section:  str   # e.g. IAM
    resource: str   # resource identifier
    message:  str   # human-readable finding


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
        self.results.append(Result(status, check_id, section, resource, message))
        if self.verbose or status in ("FAIL", "WARN"):
            col = STATUS_COLOR.get(status, RESET)
            res = f" | {resource}" if resource else ""
            print(f"  {col}{STATUS_ICON[status]}{RESET} {check_id}: {message}{res}")

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
        print(f" Account  : {self.account}")
        print(f" Region   : {self.region}")
        print(f" Sections : {', '.join(self.sections)}")
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
        print("\n" + "=" * 70)
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
                print(f"  {RED}[FAIL]{RESET} {r.check_id}: {r.message}{res}")

        return counts

    def save_json(self, path: str):
        data = {
            "scanner":   f"AWS Live Security Scanner v{VERSION}",
            "account":   self.account,
            "region":    self.region,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": {
                "PASS": sum(1 for r in self.results if r.status == "PASS"),
                "FAIL": sum(1 for r in self.results if r.status == "FAIL"),
                "WARN": sum(1 for r in self.results if r.status == "WARN"),
                "INFO": sum(1 for r in self.results if r.status == "INFO"),
            },
            "results": [
                {
                    "status":   r.status,
                    "check_id": r.check_id,
                    "section":  r.section,
                    "resource": r.resource,
                    "message":  r.message,
                }
                for r in self.results
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"{BLUE}[*]{RESET} JSON report saved: {path}")

    def save_html(self, path: str):
        STATUS_BADGE = {
            "PASS": '<span class="badge pass">PASS</span>',
            "FAIL": '<span class="badge fail">FAIL</span>',
            "WARN": '<span class="badge warn">WARN</span>',
            "INFO": '<span class="badge info">INFO</span>',
        }
        counts = {
            "PASS": sum(1 for r in self.results if r.status == "PASS"),
            "FAIL": sum(1 for r in self.results if r.status == "FAIL"),
            "WARN": sum(1 for r in self.results if r.status == "WARN"),
            "INFO": sum(1 for r in self.results if r.status == "INFO"),
        }

        import html as html_mod
        rows = ""
        for r in self.results:
            badge = STATUS_BADGE.get(r.status, r.status)
            rows += (
                f"<tr class='row-{r.status.lower()}'>"
                f"<td>{badge}</td>"
                f"<td>{html_mod.escape(r.check_id)}</td>"
                f"<td>{html_mod.escape(r.section)}</td>"
                f"<td>{html_mod.escape(r.resource)}</td>"
                f"<td>{html_mod.escape(r.message)}</td>"
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
    .meta {{ padding:8px 30px 16px; font-size:0.82em; color:#8b949e; }}
    .tbl-wrap {{ overflow-x:auto; padding:0 20px 30px; }}
  </style>
</head>
<body>
<h1>AWS Live Security Audit &nbsp;·&nbsp;
    Account: {html_mod.escape(self.account)} &nbsp;·&nbsp;
    Region: {html_mod.escape(self.region)}</h1>
<div class="summary">
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
<p class="meta">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
  &nbsp;|&nbsp; AWS Live Security Scanner v{VERSION}</p>
<div class="tbl-wrap">
<table>
  <thead>
    <tr>
      <th>Status</th><th>Check ID</th><th>Section</th>
      <th>Resource</th><th>Message</th>
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
                    f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
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
            "Covers 16 service domains aligned to CIS AWS Benchmark v3.0."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
sections available:
  {', '.join(SECTIONS)}

examples:
  python aws_live_scanner.py
  python aws_live_scanner.py --region us-east-1
  python aws_live_scanner.py --region eu-west-1 --json out.json --html out.html
  python aws_live_scanner.py --sections IAM,S3,RDS --output-dir evidence/
  python aws_live_scanner.py --verbose
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

    # Always save evidence (auto-name dir if not specified)
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = args.output_dir or f"aws_audit_{scanner.account}_{ts}"
    scanner.save_evidence(out_dir)

    sys.exit(1 if counts.get("FAIL", 0) > 0 else 0)


if __name__ == "__main__":
    main()
