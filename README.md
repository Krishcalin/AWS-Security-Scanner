<p align="center">
  <img src="docs/banner.svg" alt="AWS Security Scanner" width="800"/>
</p>

<p align="center">
  <strong>Security scanners for AWS cloud environments -- live account audit and IaC static analysis</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/license-GPL--3.0-orange?style=flat-square" alt="GPL-3.0 License"/>
  <img src="https://img.shields.io/badge/AWS-CIS%20Benchmark%20v3.0-ff9900?style=flat-square&logo=amazonaws&logoColor=white" alt="CIS AWS v3.0"/>
  <img src="https://img.shields.io/badge/compliance-CIS%20%7C%20PCI--DSS%20%7C%20HIPAA%20%7C%20SOC2%20%7C%20NIST-purple?style=flat-square" alt="5 Compliance Frameworks"/>
  <img src="https://img.shields.io/badge/checks-200%2B-red?style=flat-square" alt="200+ Checks"/>
  <img src="https://img.shields.io/badge/tests-56%20passing-brightgreen?style=flat-square" alt="56 Tests"/>
</p>

---

## Overview

This repository contains **two complementary AWS security scanners**:

| Scanner | File | Type | Input | Checks |
|---------|------|------|-------|--------|
| **IaC Security Scanner** | `aws_offline_scanner.py` | Static analysis | CloudFormation + Terraform files | 100+ (60+ TF regex + 42 CF structural) |
| **Live Audit Scanner** | `aws_live_scanner.py` | Live AWS API audit | Running AWS account | 145+ across 35 sections |

Use the **IaC scanner** to catch misconfigurations in CloudFormation templates and Terraform files before deployment. Use the **live scanner** to audit a running AWS account for CIS Benchmark compliance.

---

## IaC Security Scanner (`aws_offline_scanner.py`)

### What It Does

The IaC scanner performs **pure static analysis** of AWS Infrastructure-as-Code files -- no AWS credentials required. It scans CloudFormation templates (YAML/JSON) and Terraform configuration files (.tf) for security misconfigurations mapped to the CIS AWS Benchmark and AWS Well-Architected Security Pillar.

- **No AWS credentials required** -- analyses files locally
- **100+ security checks** -- 60+ Terraform regex rules + 42 CloudFormation structural checks
- **25+ AWS services covered** -- S3, IAM, EC2, RDS, Lambda, CloudTrail, and more
- **3 output formats** -- coloured console, JSON, interactive HTML
- **Optional dependency** -- `pyyaml` for CloudFormation YAML files (JSON works without it)

### Quick Start (IaC Scanner)

```bash
# Scan a directory of IaC files
python aws_offline_scanner.py /path/to/infra/

# Scan a single CloudFormation template
python aws_offline_scanner.py template.yaml --html report.html

# Scan Terraform files with severity filter
python aws_offline_scanner.py main.tf --json findings.json --severity HIGH

# Verbose mode
python aws_offline_scanner.py /path/to/cf/ --verbose --severity MEDIUM
```

### CLI Reference (IaC Scanner)

```
usage: aws_offline_scanner.py [-h] [--json FILE] [--html FILE]
                               [--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
                               [-v] [--version]
                               target

positional arguments:
  target                File or directory containing CloudFormation templates or Terraform files

options:
  --json FILE           Write JSON report to FILE
  --html FILE           Write HTML report to FILE
  --severity SEV        Only report findings at this severity or above
  -v, --verbose         Show files as they are scanned
  --version             Show scanner version
```

### Terraform SAST Rules (60+ Rules)

| Service | Rule IDs | Count | Key Checks |
|---------|----------|-------|------------|
| **S3** | AWS-S3-TF-001 to 006 | 6 | Public ACLs, Block Public Access settings |
| **IAM** | AWS-IAM-TF-001 to 004 | 4 | Wildcard actions/principals, password reset |
| **EC2/SG** | AWS-SG-TF-001 to 003, AWS-EC2-TF-001 to 003 | 6 | SSH/RDP from 0.0.0.0/0, IMDSv1, public IP, EBS encryption |
| **RDS** | AWS-RDS-TF-001 to 006 | 6 | Public access, encryption, backups, deletion protection, Multi-AZ |
| **CloudTrail** | AWS-CT-TF-001 to 003 | 3 | Log validation, multi-region, global events |
| **KMS** | AWS-KMS-TF-001 | 1 | Key rotation |
| **CloudFront** | AWS-CF-TF-001 to 002 | 2 | HTTPS enforcement, TLS version |
| **ElastiCache** | AWS-ECACHE-TF-001 to 002 | 2 | At-rest and in-transit encryption |
| **ECS** | AWS-ECS-TF-001 to 002 | 2 | Privileged mode, writable root filesystem |
| **OpenSearch** | AWS-OS-TF-001 to 002 | 2 | HTTPS enforcement, node-to-node encryption |
| **Redshift** | AWS-RS-TF-001 to 002 | 2 | Public access, encryption |
| **ECR** | AWS-ECR-TF-001 | 1 | Mutable image tags |
| **DynamoDB** | AWS-DDB-TF-001 | 1 | SSE encryption |
| **Lambda** | AWS-LAM-TF-001 | 1 | Reserved concurrency throttling |
| **API Gateway** | AWS-APIGW-TF-001 | 1 | Stage logging |
| **Credentials** | AWS-CRED-TF-001 to 002 | 2 | Hardcoded AWS keys, passwords |
| **CloudWatch** | AWS-CW-TF-001 to 003 | 3 | Log retention, KMS encryption, alarm actions |
| **VPC** | AWS-VPC-TF-001 to 002 | 2 | Flow logs, public subnet auto-assign |
| **WAF** | AWS-WAF-TF-001 | 1 | Default allow action |
| **GuardDuty** | AWS-GD-TF-001 | 1 | Detector disabled |
| **Config** | AWS-CFG-TF-001 to 002 | 2 | All resource types, global resources |
| **Elastic Beanstalk** | AWS-EB-TF-001 to 002 | 2 | HTTPS listener, managed updates |
| **SageMaker** | AWS-SM-TF-001 to 002 | 2 | Internet access, storage encryption |
| **EBS** | AWS-EBS-TF-001 | 1 | Volume encryption |
| **Step Functions** | AWS-SFN-TF-001 to 002 | 2 | Logging, X-Ray tracing |
| **Bedrock** | AWS-BR-TF-001 | 1 | Guardrails |

### CloudFormation Structural Checks (42 Resource Types)

| Service | Resource Types | Key Checks |
|---------|---------------|------------|
| **IAM** | Role, Policy, ManagedPolicy, User | Wildcard principal/action, AdministratorAccess, inline user policies |
| **S3** | Bucket | Public access block, versioning, encryption, logging |
| **EC2** | SecurityGroup, Instance | Open ports (22/3389/0-65535), IMDSv2, public IP |
| **RDS** | DBInstance, DBCluster | Public access, encryption, backups, deletion protection, Multi-AZ |
| **Lambda** | Function | Reserved concurrency, KMS encryption, tracing |
| **CloudTrail** | Trail | Log validation, multi-region, S3 encryption |
| **CloudFront** | Distribution | HTTPS, TLS 1.2+, WAF, logging, origin protocol |
| **ELB** | Listener | HTTPS protocol enforcement |
| **API Gateway** | Stage | Logging, stage variables |
| **KMS** | Key | Rotation enabled |
| **SQS** | Queue | KMS encryption |
| **SNS** | Topic | KMS encryption |
| **DynamoDB** | Table | Point-in-time recovery, SSE |
| **ElastiCache** | ReplicationGroup | Encryption (rest + transit), auth token |
| **EKS** | Cluster | Endpoint public access, logging, encryption |
| **ECS** | TaskDefinition | Privileged mode, read-only root, logging |
| **Cognito** | UserPool | MFA, password policy |
| **OpenSearch** | Domain | HTTPS, node-to-node encryption, encryption at rest |
| **Redshift** | Cluster | Public access, encryption, logging |
| **ECR** | Repository | Image tag mutability, scan on push |
| **Secrets Manager** | Secret | KMS encryption |
| **CloudWatch** | Alarm | Alarm actions |
| **Logs** | LogGroup | Retention, KMS encryption |
| **VPC/Subnet** | VPC, Subnet, FlowLog | Flow logs, public IP auto-assign |
| **WAFv2** | WebACL | Default action |
| **GuardDuty** | Detector | Enabled status |
| **Config** | ConfigurationRecorder | All supported types, global resources |
| **Elastic Beanstalk** | Environment | HTTPS, managed updates |
| **SageMaker** | NotebookInstance, Domain | Internet access, KMS encryption |
| **Bedrock** | Agent | Guardrails |
| **EBS** | Volume | Encryption |
| **Step Functions** | StateMachine | Logging, tracing |

---

## Live Audit Scanner (`aws_live_scanner.py`)

### What It Does

The live scanner connects to a running AWS account via **boto3**, performing **read-only** security checks aligned to multiple compliance frameworks. It produces colour-coded terminal output with PASS/FAIL/WARN verdicts, posture scoring, JSON/HTML reports, and saves evidence artefacts to a timestamped output directory.

- **Read-only by design** -- never modifies AWS resources
- **145+ security checks** across 35 audit sections
- **IAM privilege-escalation analysis** -- builds each principal's effective permission set and detects known escalation paths (action-level), not just per-resource misconfigurations
- **5 compliance frameworks** -- CIS AWS v3.0, PCI DSS v4.0, HIPAA, SOC 2, NIST 800-53 Rev 5
- **Risk scoring** -- Posture score 0-100 with letter grade (A-F), severity-weighted
- **AWS CLI remediation** -- actionable CLI commands for every failed check
- **3 output formats** -- coloured console, JSON report, interactive HTML report
- **Evidence collection** -- CSV/JSON artefact files saved per check
- **56 unit tests** -- full test suite with mock boto3, no AWS credentials needed

### Prerequisites (Live Scanner)

- **Python 3.10+** with `boto3` installed (`pip install boto3`)
- **AWS credentials** -- configured via `aws configure`, environment variables, or IAM role
- **IAM permissions** -- the executing identity needs the `SecurityAudit` AWS-managed policy (read-only)
- **Default region** -- `eu-west-1`; override via `--region` or `AWS_DEFAULT_REGION` environment variable

### Quick Start (Live Scanner)

```bash
# Run full audit (all 35 sections, 145+ checks)
python aws_live_scanner.py

# Target a specific region
python aws_live_scanner.py --region us-east-1

# Run specific sections only
python aws_live_scanner.py --sections IAM S3 VPC

# Save JSON + HTML reports and evidence artefacts
python aws_live_scanner.py --json report.json --html report.html --output-dir ./audit_output

# Verbose mode
python aws_live_scanner.py --verbose
```

### CLI Reference (Live Scanner)

```
usage: aws_live_scanner.py [-h] [--region REGION] [--json FILE] [--html FILE]
                            [--output-dir DIR]
                            [--sections {IAM,S3,VPC,LOGGING,KMS,EC2,ECR,BACKUP,
                                         RDS,GLACIER,SNS,SQS,CLOUDFRONT,ROUTE53,
                                         BEDROCK,BEDROCK_AGENTS,LAMBDA,EKS,ECS,
                                         SECRETS,WAF,ELASTICACHE,OPENSEARCH,
                                         DYNAMODB,STEPFUNCTIONS,APIGATEWAY,ELB,
                                         EBS,REDSHIFT,EFS,ACM,SAGEMAKER,COGNITO,
                                         APIGATEWAYV2,IAMPRIVESC} ...]
                            [-v] [--version]

options:
  --region REGION       AWS region to audit (default: eu-west-1)
  --json FILE           Write JSON report to FILE
  --html FILE           Write HTML report to FILE
  --output-dir DIR      Directory for evidence artefact files
  --sections SECTION…   Run only specified sections (space-separated)
  -v, --verbose         Print each check as it runs
  --version             Show scanner version
```

### Security Checks Coverage (145+ checks across 35 sections)

| Section | Check IDs | Description |
|---------|-----------|-------------|
| **IAM** | IAM-01/02, IAM-04/05/06/10 | Root MFA + access keys, console users without MFA, password policy, stale access keys, IAM Access Analyzer |
| **S3** | S3-01, S3-03, S3-05 | Account-level Block Public Access, per-bucket public access + ACLs + encryption |
| **VPC** | VPC-01, VPC-03 | Security groups with risky ports open to 0.0.0.0/0, VPC Flow Logs |
| **Logging** | LOG-01/03/04/05 | CloudTrail multi-region + validation, AWS Config, GuardDuty, Security Hub |
| **KMS** | ENC-03 | KMS customer-managed key rotation |
| **EC2** | EC2-04/05/06 | IMDSv2, public IP, EBS volume encryption |
| **ECR** | CNT-01 | ECR scan-on-push |
| **Backup** | BCK-01 | AWS Backup vaults and resource assignments |
| **RDS** | RDS-01 to 06 | Encryption, public access, backups, deletion protection, monitoring, public snapshots |
| **Glacier** | GLC-01 to 03 | Vault access policies, vault lock (WORM), SNS notifications |
| **SNS** | SNS-01 to 04 | SSE-KMS encryption, wildcard principal, HTTPS delivery, cross-account subscriptions |
| **SQS** | SQS-01 to 04 | SSE encryption, public access, DLQ, retention/visibility |
| **CloudFront** | CFN-01 to 05 | HTTPS-only, TLS version, WAF, access logging, origin protocol |
| **Route 53** | R53-01 to 05 | Query logging, DNSSEC, transfer lock, health checks, DNS firewall |
| **Bedrock** | BDR-01 to 05 | Model logging, guardrails, KMS encryption, VPC endpoint, IAM least privilege |
| **Bedrock Agents** | AGT-01 to 05 | Agent KMS encryption, execution role, KB security, Lambda security, prompt injection |
| **Lambda** | LMB-01 to 05 | Public access, VPC config, plaintext secrets in env vars, deprecated runtimes, concurrency |
| **EKS** | EKS-01 to 05 | Public API endpoint, control plane logging, secrets encryption, version, security groups |
| **ECS** | ECS-01 to 05 | Privileged containers, root user, log drivers, plaintext secrets, writable rootfs |
| **Secrets Manager** | SEC-01 to 04 | Rotation enabled, rotation frequency, KMS (CMK vs managed), unused secrets |
| **WAF** | WAF-01 to 04 | Web ACL presence, logging, rules count, default action |
| **ElastiCache** | ELC-01 to 04 | Encryption at rest, encryption in transit, AUTH token, auto failover |
| **OpenSearch** | OSR-01 to 05 | HTTPS enforcement, encryption at rest, node-to-node, VPC deployment, fine-grained access |
| **DynamoDB** | DDB-01 to 04 | CMK encryption, point-in-time recovery, billing mode, deletion protection |
| **Step Functions** | SFN-01 to 03 | Execution logging, X-Ray tracing, KMS encryption |
| **API Gateway** | APIGW-01 to 04 | Stage access/execution logging, WAF association, cache data encryption, X-Ray tracing |
| **Load Balancing** | ELB-01 to 05 | Access logging, HTTP→HTTPS redirect, TLS policy strength, deletion protection, drop invalid headers |
| **EBS** | EBS-01 to 04 | Encryption by default, unencrypted volumes, unencrypted snapshots, public snapshots |
| **Redshift** | RS-01 to 05 | Encryption at rest, public access, audit logging, enhanced VPC routing, default admin username |
| **EFS** | EFS-01 to 03 | Encryption at rest, in-transit TLS policy, automatic backups |
| **Certificate Manager** | ACM-01 to 03 | Certificate expiry, key algorithm strength, unused certificates |
| **SageMaker** | SM-01 to 04 | Notebook direct internet access, root access, KMS volume encryption, VPC deployment |
| **Cognito** | COG-01 to 04 | User-pool MFA enforcement, password policy strength, advanced security (threat protection), deletion protection |
| **API Gateway v2** | AGW2-01 to 03 | HTTP API stage access logging, route authorization, default throttling |
| **IAM Privilege Escalation** | IAMPE-01 to 19 | Action-level escalation-path analysis across all principals: policy-version/attach/inline-policy abuse, login-profile & access-key hijack, trust-policy edits, PassRole→(EC2/Lambda/Glue/CFN/SageMaker), UpdateFunctionCode, SSM, full-admin |

### Compliance Framework Mapping

Every finding is tagged with applicable controls from:

| Framework | Coverage |
|-----------|----------|
| **CIS AWS Foundations Benchmark v3.0** | IAM, S3, VPC, Logging, KMS, EC2, RDS, CloudFront, Lambda, EKS |
| **PCI DSS v4.0** | Requirements 1, 2, 3, 4, 6, 7, 8, 10, 11, 12 |
| **HIPAA** | 164.308, 164.312 (access control, audit, transmission, encryption) |
| **SOC 2 Type II** | CC6 (logical access), CC7 (monitoring), A1 (availability) |
| **NIST 800-53 Rev 5** | AC, AU, CM, CP, IA, SC, SI families |

### Risk Scoring

The scanner computes a **posture score** from 0-100:

```
Score = 100 − (CRITICAL × 15  +  HIGH × 5  +  MEDIUM × 2  +  LOW × 0.5)
```

| Grade | Score Range |
|-------|-------------|
| **A** | 90 -- 100 |
| **B** | 80 -- 89 |
| **C** | 70 -- 79 |
| **D** | 60 -- 69 |
| **F** | 0 -- 59 |

---

## When to Use Which Scanner

| Scenario | Recommended Scanner |
|----------|-------------------|
| Pre-deployment IaC review (CloudFormation / Terraform) | **IaC Scanner** (`aws_offline_scanner.py`) |
| Live AWS account security audit | **Live Scanner** (`aws_live_scanner.py`) |
| CI/CD pipeline gate for infrastructure code | **IaC Scanner** |
| Compliance assessment against CIS AWS Benchmark | **Live Scanner** |
| No AWS credentials available, only code to review | **IaC Scanner** |
| Comprehensive audit of a production account | **Both** -- IaC Scanner on templates, Live Scanner on live account |

---

## Project Structure

```
AWS-Security-Scanner/
├── aws_offline_scanner.py   # IaC Security Scanner (CloudFormation + Terraform, no credentials)
├── aws_live_scanner.py      # Live Audit Scanner v2.0.0 (35 sections, 5 compliance frameworks)
├── tests/
│   ├── test_live_scanner.py # 56 unit tests (mock boto3, no credentials needed)
│   └── samples/             # Sample IaC files and reports
├── docs/
│   └── banner.svg
├── CLAUDE.md                # Developer documentation
├── LICENSE                  # GPL-3.0
└── README.md
```

---

## Requirements

| Scanner | Requirements |
|---------|-------------|
| IaC Scanner (`aws_offline_scanner.py`) | Python 3.10+, optional `pyyaml` for CF YAML templates |
| Live Scanner (`aws_live_scanner.py`) | Python 3.10+, `boto3`, AWS credentials with `SecurityAudit` IAM policy |

---

## Disclaimer

These tools are for **authorised security assessments only**. The live scanner performs read-only API calls and never modifies AWS resources. The IaC scanner performs pure static analysis with no AWS connectivity. Always ensure you have explicit authorisation before scanning.

---

## License

GPL-3.0 License -- see [LICENSE](LICENSE).
