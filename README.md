<p align="center">
  <img src="docs/banner.svg" alt="OverWatch — Agentless AWS CNAPP · Attack-Path Graph" width="800"/>
</p>

<p align="center">
  <strong>OverWatch</strong> — an agentless <strong>AWS CNAPP</strong>: it collapses a whole cloud estate into the ranked
  handful of internet&nbsp;&rarr;&nbsp;exposed&nbsp;workload&nbsp;&rarr;&nbsp;exploitable&nbsp;CVE&nbsp;&rarr;&nbsp;over-privileged&nbsp;role&nbsp;&rarr;&nbsp;crown-jewel
  attack paths and names the <strong>choke point</strong> that severs the most &mdash; plus an IaC static-analysis scanner.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/license-GPL--3.0-orange?style=flat-square" alt="GPL-3.0 License"/>
  <img src="https://img.shields.io/badge/OverWatch-CNAPP%20v2.19.0-38bdf8?style=flat-square" alt="OverWatch CNAPP v2.19.0"/>
  <img src="https://img.shields.io/badge/pillars-CSPM%20%7C%20CIEM%20%7C%20CWPP%20%7C%20DSPM%20%7C%20CDR-6366f1?style=flat-square" alt="CNAPP pillars"/>
  <img src="https://img.shields.io/badge/compliance-CIS%20%7C%20PCI--DSS%20%7C%20HIPAA%20%7C%20SOC2%20%7C%20NIST-purple?style=flat-square" alt="5 Compliance Frameworks"/>
  <img src="https://img.shields.io/badge/checks-200%2B-red?style=flat-square" alt="200+ Checks"/>
  <img src="https://img.shields.io/badge/tests-571%20passing-brightgreen?style=flat-square" alt="571 Tests"/>
</p>

---

## Overview

**OverWatch** is the product name for the CNAPP: a full Cloud-Native Application Protection Platform for AWS
(CSPM + CIEM + agentless CWPP + DSPM + CDR-lite) built around a unified security graph and toxic-combination
**attack-path** correlation, with multi-account onboarding, choke-point remediation, and code-to-cloud mapping.
It ships as the live scanner (`aws_live_scanner.py`) + its `aws_*` / `cnapp_*` engine modules, and a hosted
platform backend (see [OverWatch — Hosted CNAPP Platform](#overwatch--hosted-cnapp-platform-multi-account-agentless)).

This repository contains **two complementary AWS security scanners**:

| Scanner | File | Type | Input | Checks |
|---------|------|------|-------|--------|
| **OverWatch** (Live CNAPP) | `aws_live_scanner.py` | Live AWS API audit + security graph + attack-path CNAPP | Running AWS account (multi-account via AssumeRole) | 267 across 44 sections |
| **IaC Security Scanner** | `aws_offline_scanner.py` | Static analysis | CloudFormation + Terraform files | 100+ (60+ TF regex + 42 CF structural) |

Use **OverWatch** to audit a running AWS estate — CIS/compliance posture, effective-permissions CIEM, agentless
workload vulnerabilities, and the ranked attack paths + choke points. Use the **IaC scanner** to catch
misconfigurations in CloudFormation templates and Terraform files before deployment.

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
- **267 security checks** across 44 audit sections (204 actionable, each with a detailed remediation write-up)
- **Effective internet-exposure engine** (CNAPP Phase 2) -- computes *true* reachability (`aws_exposure.py`): a workload is flagged internet-exposed only when a public IP/EIP/IPv6 **and** an active IGW route **and** open security-group ingress **and** a permissive stateless NACL (inbound + ephemeral return) all line up — killing the "SG allows 0.0.0.0/0" false positive. sg-references, NAT routes, private subnets and blocked-return NACLs are correctly *not* exposed
- **First attack path** -- `ATTACK-01` chains it end-to-end: `Internet → exposed EC2 → instance-profile role → privilege escalation to admin` (CRITICAL)
- **Deep-plane ingestion** (CNAPP Phase 3, buy-not-build) -- BUYS signal from AWS-native services as graph edges: **Amazon Inspector** CVEs with EPSS + CISA-KEV (`HAS_VULN`), **Macie** crown-jewel S3 classification, **IAM Access Analyzer** authoritative external access, **GuardDuty** live detections (`THREAT_ON`). Every collector degrades to a graceful no-op when its service is disabled -- never a false positive
- **Flagship attack path** -- `ATTACK-02` (CRITICAL): `Internet → exposed EC2 → exploitable/KEV CVE → over-privileged role → crown-jewel S3 data` -- the full toxic combination, condition-aware, escalated when a live GuardDuty threat sits on the chain
- **Attack-path correlation & choke points** (CNAPP Phase 4) -- collapses the whole graph into a *ranked handful* of scored, explainable attack paths (gated-multiplicative scoring: any missing factor collapses the path, killing the "high-CVSS but unexposed" false positive), then computes **choke points**: `CHOKEPOINT-01` names the single node whose fix severs the most paths to the most crown jewels. Ranked `attack_paths` + `choke_points` in the JSON report
- **Effective-permissions ceiling** (CNAPP Phase 5) -- evaluates the real AWS decision chain (identity ∩ **permission-boundary** ∩ **SCP**, explicit-deny-wins, condition-aware) so an escalation edge a boundary or SCP *provably neutralizes* is **dropped** from the graph — the ranked paths reflect genuinely-reachable escalation, not merely granted permissions. Fail-open: absent boundary/SCP data behaves exactly as before (`aws_effperm.py`)
- **Persistent state, drift & waivers** (CNAPP Phase 5) -- `--state cnapp.db` gives the scanner *memory*: finding lifecycle (open/resolved/**reopened**/**mutated**), coverage-gated resolve, **MTTR**, posture **trend**, and **waivers** (`--suppress` with approver/expiry — an accepted risk leaves `--fail-on` gating but stays tracked; expired waivers auto-reactivate) (`aws_state.py`)
- **CIEM right-sizing** (CNAPP Phase 5, opt-in `--ciem`) -- flags dormant/over-permissioned principals (Access Analyzer unused-access → service-last-accessed) as LOW `CIEM-01` review candidates and down-ranks the exploit-likelihood of attack paths through them (impact untouched) (`aws_unused.py`)
- **Agentless workload side-scan** (CNAPP Phase 6, opt-in `--side-scan`) -- the Wiz/Orca CWPP capability with *no agent*: inventory a workload's OS packages, match them against a vulnerability feed with ecosystem-correct (dpkg/rpm/apk) version comparison, and find on-disk secrets — adding `HAS_VULN` edges to the SAME graph so agentless CVEs **light up ATTACK-02 even when Amazon Inspector is disabled** (`CWPP-01/02/03`). Pure inventory/matching core + EBS Direct-API block plane; live disk extraction deferred (`aws_sidescan.py`, `aws_sidescan_ebs.py`)
- **Persistence backends** (CNAPP Phase 6) -- `--backend postgresql://...` (Postgres state store, deferred to Phase 7 → runs stateless) and `--graph-neptune-csv`/`--graph-neptune-cypher` export the security graph as Amazon Neptune bulk-load CSV or idempotent openCypher upserts (`aws_state_dialect.py`, `aws_graph_neptune.py`)
- **Remediation engine** (CNAPP Phase 7, opt-in `--remediate`) -- turns the ranked attack paths into a **prioritized fix plan** ("fix these K choke points to cut N% of critical paths"), reusing the correlation ranking, with **remediation-as-code** (Terraform/CloudFormation/CLI per finding) and exports (markdown runbook, JSON, GitHub issue, PR body). **Read-only — it generates artifacts, never applies changes** (`aws_remediate.py`)
- **Code-to-cloud** (CNAPP Phase 7, opt-in `--iac-dir`) -- maps a live cloud finding back to the **IaC resource that created it** (Terraform/CloudFormation) via a tiered confidence matcher that never guesses, so remediation targets the *source* and proposes the IaC diff at `file:line` (`aws_codetocloud.py`)
- **Security graph & attack-path chains** (CNAPP Phase 1) -- projects findings onto an ARN-keyed graph (`aws_graph.py`), builds `CAN_ASSUME` (trust) + `CAN_PRIVESC_TO` (privesc) edges, and surfaces **transitive privilege-escalation chains** (`user → assume role → escalate to admin`) plus roles assumable by *any* principal. Serialize with `--graph graph.json` (Neptune migration seed)
- **IAM privilege-escalation analysis** -- builds each principal's effective permission set (via `GetAccountAuthorizationDetails`) and detects known escalation paths with resource-aware scoping; condition-guarded paths are downgraded to WARN, boundary/SCP-neutralized paths dropped
- **Multi-account & multi-region** -- `--org` / `--accounts` fan out across an AWS Organization via `--assume-role`; `--all-regions` sweeps every enabled region for regional sections
- **Compliance scorecard** -- `--compliance` prints a per-framework control pass/fail rollup (CIS/PCI/HIPAA/SOC2/NIST), also embedded in the JSON report
- **5 compliance frameworks** -- CIS AWS v3.0, PCI DSS v4.0, HIPAA, SOC 2, NIST 800-53 Rev 5
- **Risk scoring** -- Posture score 0-100 with letter grade (A-F), severity-weighted
- **AWS CLI remediation** -- actionable CLI commands for every failed check
- **Detailed finding reports** -- every actionable check ships a full write-up (`aws_finding_detail.py`): the **risk** (what it is / how it's exploited / why it matters), the **business impact**, and **step-by-step remediation** with real AWS CLI, plus the mapped compliance controls. The JSON report carries a deduped, severity-ranked `finding_catalog`; the HTML report renders per-finding cards (risk -> impact -> numbered fix steps -> frameworks) above the full findings table. A check with no detailed entry falls back to its one-line CLI, so coverage grows without breaking rendering
- **5 output formats** -- coloured console, JSON, interactive HTML, **SARIF 2.1.0** (GitHub code scanning), **ASFF** (AWS Security Hub)
- **CI/CD gating** -- `--fail-on CRITICAL|HIGH|MEDIUM|LOW` for pipeline pass/fail control
- **Scan diff** -- `--baseline prev.json` surfaces only what's *new* or *resolved* since a previous run (superseded by `--state` DB-backed lifecycle when both are given)
- **Evidence collection** -- CSV/JSON artefact files saved per check
- **1128 unit tests** -- full test suite with mock boto3, no AWS credentials needed (incl. exposure, deep-plane, attack-path-scoring, Phase-5 effective-permissions/state/CIEM, Phase-6 side-scan version-comparator/OSV-matching/EBS-block-plane/backend-export, Phase-7 remediation/code-to-cloud false-positive/false-negative catalogs, and the detailed finding write-ups / `finding_catalog` rendering; a regression test backs every defect the adversarial-verification passes found)

### Prerequisites (Live Scanner)

- **Python 3.10+** with `boto3` installed (`pip install boto3`)
- **AWS credentials** -- configured via `aws configure`, environment variables, or IAM role
- **IAM permissions** -- the executing identity needs the `SecurityAudit` AWS-managed policy (read-only)
- **Default region** -- `eu-west-1`; override via `--region` or `AWS_DEFAULT_REGION` environment variable

### Quick Start (Live Scanner)

```bash
# Run full audit (all 44 sections, 267 checks)
python aws_live_scanner.py

# Target a specific region
python aws_live_scanner.py --region us-east-1

# Run specific sections only (comma-separated, single argument)
python aws_live_scanner.py --sections IAM,S3,VPC

# Run only the IAM privilege-escalation path analysis
python aws_live_scanner.py --sections IAMPRIVESC

# Save JSON + HTML reports and evidence artefacts
python aws_live_scanner.py --json report.json --html report.html --output-dir ./audit_output

# CI/CD: emit SARIF for GitHub code scanning and fail the build on HIGH+ findings
python aws_live_scanner.py --sarif results.sarif --fail-on HIGH

# Push findings into AWS Security Hub (ASFF)
python aws_live_scanner.py --asff findings.asff.json
aws securityhub batch-import-findings --findings file://findings.asff.json

# CNAPP: all regions, compliance scorecard, and export the identity security graph
python aws_live_scanner.py --all-regions --compliance --graph graph.json

# Multi-account: scan every account in the Organization via an assumable read-only role
python aws_live_scanner.py --org --assume-role OrganizationAccountAccessRole --json org.json

# Multi-account: scan an explicit account list with an ExternalId
python aws_live_scanner.py --accounts 111122223333,444455556666 --assume-role AuditRole --external-id my-id

# Show only what changed since the last scan
python aws_live_scanner.py --json today.json --baseline yesterday.json

# Verbose mode
python aws_live_scanner.py --verbose
```

### CLI Reference (Live Scanner)

```
usage: aws_live_scanner.py [-h] [--region REGION] [--json FILE] [--html FILE]
                            [--sarif FILE] [--asff FILE] [--baseline FILE]
                            [--fail-on {CRITICAL,HIGH,MEDIUM,LOW}] [--output-dir DIR]
                            [--sections {IAM,S3,VPC,LOGGING,KMS,EC2,ECR,BACKUP,
                                         RDS,GLACIER,SNS,SQS,CLOUDFRONT,ROUTE53,
                                         BEDROCK,BEDROCK_AGENTS,LAMBDA,EKS,ECS,
                                         SECRETS,WAF,ELASTICACHE,OPENSEARCH,
                                         DYNAMODB,STEPFUNCTIONS,APIGATEWAY,ELB,
                                         EBS,REDSHIFT,EFS,ACM,SAGEMAKER,COGNITO,
                                         APIGATEWAYV2,IAMPRIVESC,EXPOSURE,VULN,THREAT,DATA,CORRELATE}]
                            [--all-regions] [--compliance] [--graph FILE]
                            [--org] [--accounts IDS] [--assume-role ROLE]
                            [--external-id ID] [-v] [--version]

options:
  --region REGION       AWS region to audit (default: eu-west-1)
  --json FILE           Write JSON report to FILE
  --html FILE           Write HTML report to FILE
  --sarif FILE          Write SARIF 2.1.0 findings to FILE (GitHub code scanning)
  --asff FILE           Write ASFF findings to FILE (AWS Security Hub import)
  --baseline FILE       Diff against a previous JSON report (new/resolved)
  --fail-on SEVERITY    Exit 1 only on a FAIL at/above this severity
  --output-dir DIR      Directory for evidence artefact files
  --sections SECTIONS   Run only the named sections (single comma-separated value)
  --all-regions         Sweep every enabled region for regional sections
  --compliance          Print the per-framework compliance scorecard
  --graph FILE          Write the identity security graph to FILE (graph.json)
  --org                 Scan every ACTIVE account in the AWS Organization (needs --assume-role)
  --accounts IDS        Comma-separated account IDs to scan (needs --assume-role)
  --assume-role ROLE    Role name/ARN to assume in each target account
  --external-id ID      STS ExternalId for the assumed role
  -v, --verbose         Print each check as it runs
  --version             Show scanner version
```

### Security Checks Coverage (267 checks across 44 sections)

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
| **EKS** | EKS-01 to 08 | Public API endpoint, control plane logging, secrets encryption, version, security groups, worker-node SSH, EKS-Fargate profile boundary, **authentication mode** |
| **KSPM** | KSPM-00 to 07 | **Agentless CIS-EKS (K8s side)** — anonymous RBAC bindings, wildcard/cluster-admin RBAC, default-SA automount, Pod Security Admission, default-deny NetworkPolicy, privileged/host pods (fail-open when the K8s API is unreachable) |
| **KIEM** | KIEM-01 to 04 | **K8s identity/entitlement** — over-broad AWS→K8s cluster-admin grants (EKS Access Entries), namespace-admin/secret-read, and **IRSA / Pod-Identity cross-plane** (ServiceAccount → AWS role → admin/crown) |
| **ECS** | ECS-01 to 08, **FARGATE-01/02** | Privileged containers, root user, log drivers, plaintext secrets, writable rootfs, host-namespace/hostPath escapes, dangerous caps; **running Fargate tasks folded into the attack-path graph** + public-task-IP exposure |
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
| **IAM Privilege Escalation** | IAMPE-01 to 20 | Resource-aware escalation-path analysis across all principals (findings scoped account-wide vs resource-scoped): policy-version/attach/inline-policy abuse, login-profile & access-key hijack, trust-policy edits, PassRole→(EC2/Lambda/Glue/CFN/SageMaker), UpdateFunctionCode, SSM, sts:AssumeRole-on-\*, full-admin |

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

### CI/CD & AWS Security Hub Integration

The live scanner emits **SARIF 2.1.0** (GitHub code scanning) and **ASFF** (AWS
Security Hub), and gates pipelines via `--fail-on`:

```yaml
# .github/workflows/aws-audit.yml
jobs:
  aws-security-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write          # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::<ACCOUNT>:role/security-audit
          aws-region: eu-west-1
      - run: pip install boto3
      - run: python aws_live_scanner.py --sarif results.sarif --fail-on HIGH
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

- **SARIF** maps severity → level (CRITICAL/HIGH → `error`) and sets
  `security-severity` so findings surface in the GitHub Security tab.
- **ASFF** imports into Security Hub: `python aws_live_scanner.py --asff f.json &&
  aws securityhub batch-import-findings --findings file://f.json` (≤100/call).
- **Drift tracking**: `--baseline prev.json` prints only NEW and RESOLVED findings.

---

## OverWatch — Hosted CNAPP Platform (multi-account, agentless)

**OverWatch** is the product name for this CNAPP: the attack-path-graph layer that
collapses a whole AWS estate into the ranked handful of internet → exposed workload
→ exploitable CVE → over-privileged role → crown-jewel-data paths, and names the
**choke point** that severs the most.

Beyond the CLI, OverWatch ships a **self-hosted platform backend** for onboarding and
continuously scanning many AWS accounts — the Wiz/Orca model, agentless and with no
access keys.

**Architecture — hub & spoke.** One **hub** (an EC2 instance running the FastAPI
service + worker + Postgres/SQLite state, in a dedicated security account) reaches
every onboarded **spoke** account by assuming a **read-only cross-account role**
(`CnappScannerRole`) that trusts only the hub role under a per-account `sts:ExternalId`
(confused-deputy guard). Region/AZ are irrelevant to the API scan — control-plane
endpoints are reachable from anywhere; the hub's own AZ never constrains coverage.

**Onboarding.** Either deploy the single-account CloudFormation stack
([`deploy/cnapp-scanner-role.yaml`](deploy/cnapp-scanner-role.yaml)) via a one-click
Launch-Stack URL, or connect an entire **AWS Organization** with a service-managed
**StackSet** ([`deploy/cnapp-stackset.md`](deploy/cnapp-stackset.md)) that auto-enrolls
current and future member accounts. The role attaches only **SecurityAudit +
ViewOnlyAccess** (read-only of configuration/IAM — never workload data).

**Backend modules** (pure, dependency-injected, offline-testable):

| Module | Role |
|--------|------|
| `cnapp_onboarding.py` | Mint ExternalId (stored as a secret *reference*), build the CFN launch URL/CLI |
| `cnapp_validate.py` | `validate_connection`: assume → account-match hard stop → read canary → org list; health + backoff |
| `cnapp_registry.py` | `AccountRegistry` (accounts / scan_jobs / connection_health) over the dual-dialect state store |
| `cnapp_service.py` | `PlatformService` facade + `serialize_scanner` + org rollup |
| `cnapp_worker.py` | Async scan-job execution (traps engine exit, pre-validates creds, TOCTOU re-check) |
| `cnapp_api.py` | FastAPI routes + viewer/admin RBAC (fail-closed), guarded import |
| `cnapp_connectors.py` | **Connector framework** — route findings to Jira / Slack / PagerDuty / Splunk / webhook (pure renderers + injected `http_post` seam + rules engine + idempotent delivery ledger) |
| `compliance_crosswalk.py` | **Compliance breadth** — sourced NIST 800-53 → 30+ framework crosswalk loader (accuracy-gated, fail-open); `aws_live_scanner.crosswalk_scorecard` derives per-framework coverage |
| `aws_ingest.py` | **External-vuln ingest** — pure SARIF/CycloneDX/SPDX parsers (per-tool adapters) → own each CVE onto a graph node → enrich from OverWatch's own OSV/EPSS/KEV bundle → re-run reachability so CVEs rank by attack-path exploitability, not CVSS |

**HTTP surface** (all delegate to `PlatformService`; admin routes stay on the private
hub control plane): `POST /accounts` (onboard → launch URL), `POST /accounts/{id}/validate`,
`GET /accounts`, `POST /scans`, `GET /scans/{job_id}`,
`GET /accounts/{id}/summary|issues|findings|paths|graph`, `GET /org/overview`, `GET /org/findings`;
**connectors** — `POST/GET /connectors`, `PUT/DELETE /connectors/{id}`,
`POST /connectors/{id}/{enable,rotate-secret,test}`, `.../rules` CRUD,
`POST /connectors/rules/preview` (dry-run), `POST /accounts/{id}/notify`,
`GET /connectors/{id}/deliveries`, `GET /notifications`.

**Continuous scanning + drift digests (CTEM).** Set a per-account scan **cadence** (hourly /
daily / weekly / custom) and OverWatch scans on a schedule — a `scheduler_tick` enqueues due
accounts (a failing scan backs off exponentially, never flapping) and drains the queue. Each
scan folds into the finding-lifecycle store (**drift / trend / MTTR**), and one **drift digest**
— *"what changed since last scan"* (new / resolved / reopened, posture Δ, newly-exposed on an
attack path, SLA breaches, compliance drift) — is delivered per scan through the connectors, to
the connectors that opt in (`config.digest`). Digests are **idempotent** per window (a separate
`digest_log` ledger; a failed one is retried) and gated to **material change** so a quiet scan
sends nothing. The console shows a "What changed" + posture-trend card, a per-account cadence
selector, and a digest toggle per connector. Routes: `POST /scans/schedule-tick`,
`PUT /accounts/{id}/schedule`, `GET /accounts/{id}/{trend,mttr,drift}`, `GET /digests`,
`POST /accounts/{id}/digest/preview`.

**Compliance breadth — 30+ frameworks from one verifiable spine.** Every check is tagged
with a **NIST 800-53 Rev 5** control, so instead of hand-tagging every check against every
regime, OverWatch cross-walks its 38 in-use NIST controls to **34 more frameworks** (ISO
27001:2022, FedRAMP, NIST 800-171 / CMMC, NIST CSF 2.0, PCI-DSS 4.0, SWIFT, DORA, HIPAA,
HITRUST, GDPR/CCPA, CSA CCM v4, CIS Controls v8, COBIT, NIS2, ATT&CK-Cloud, …) and **derives**
coverage transitively — each derived control reads *"satisfied via NIST 800-53 AC-3
(crosswalk)"* with a per-mapping **confidence tier** and authoritative **source** citations.
The crosswalk was sourced from published authoritative mappings and **web-verified by an
adversarial review** (which caught + fixed real mapping errors); a CI accuracy validator gates
the shipped data (no fabricated ids, no native-framework targets). The 5 directly-tested
frameworks keep their per-check tags and are byte-identical; derived data is **informational**
(confirm scope with your assessor). Routes (viewer): `GET /compliance/frameworks`,
`GET /compliance/crosswalk`, `GET /accounts/{id}/compliance?min_confidence=`, `GET /org/compliance`.
Surfaced in the console **Compliance** screen (directly-tested vs crosswalk-derived, family +
confidence filters, per-control provenance, source links).

**Connectors — notify your own tools (agentless, read-only on targets).** OverWatch can
route findings to the **operator's own** Jira Cloud, Slack, PagerDuty (Events v2), Splunk
HEC, or a signed generic webhook, under a rules engine (severity floor / section / check
glob / account glob / on-attack-path / framework). It makes **no** AWS call against a
scanned account — the only outbound is HTTP to the operator's endpoints. Every credential is
stored **only as a `secretsmanager://`/`ssm://` reference** (never plaintext, never returned
over the API); connectors are **admin-only, disabled by default**, and delivery is
**idempotent** (a re-scan never re-sends an unchanged finding, and a failed send is retried).
Configured from the console **Settings → Integrations** screen (add/test/enable, per-connector
routing rules with a dry-run preview, and a deliveries audit log).

**External vulnerability ingest — rank CVEs by reachability, not CVSS.** Upload the
output of *any* SCA scanner — **SARIF** (Trivy / Grype / Snyk), **CycloneDX** (with a
`vulnerabilities[]` array or VEX `analysis.state`), or **SPDX / Syft** SBOMs — and OverWatch
**owns** each CVE against the AWS resource it belongs to, **dedups** it across sources (one
row per `(account, node_id, cve)`; N reporters = a `sources` set-union), and **enriches** it
from the **same** OSV / EPSS / KEV bundle a native side-scan uses (so KEV/EPSS/exploit are
byte-identical, never inferred from the doc). The owned CVE is attached as a `HAS_VULN` edge
and the attack-path engine is **re-run** — a membership check on the stored paths would
structurally miss the path a newly-reported KEV reveals — so an ingested KEV on an
internet-exposed, path-to-crown host earns the identical CRITICAL as a native one, while a
high-CVSS but **unreachable** CVE ranks as noise. VEX `not_affected` / `false_positive` is
**suppress-but-track** (owner VEX outranks a scanner's "exploitable"; the row is retained and
counted, never a silent hole); CodeQL SARIF (SAST, no CVE) is excluded. Reachable survivors
flow into the existing connectors as two check-level aggregates (`VULN-ING-KEV` / `VULN-ING`)
and a newly-reachable KEV rides the drift-digest `newly_on_path` signal. Read-only on scanned
accounts — it works purely off the uploaded doc + the stored graph. Routes: `POST
/accounts/{id}/ingest` (admin), `GET /accounts/{id}/vulns` (ranked, faceted by KEV / on-path /
source / band), `GET /accounts/{id}/vulns/{cve}`, `GET /accounts/{id}/ingest/docs`, `POST
/accounts/{id}/vulns/refresh` (admin), `GET /org/vulns`. Surfaced in the console
**Vulnerabilities** screen — a reachability-anchored inventory (the reachability chip, not
CVSS, is the visual weight) with a SARIF/CycloneDX/SPDX upload affordance and an Overview
roll-up (*N external CVEs · M reachable · K reachable-KEV*).

**Shared Postgres state.** Opening the state store with a `postgresql://` URL runs
the whole state plane (finding lifecycle/drift/waivers + the account registry) on a
real Postgres via psycopg3 — the shared store for the hub. Both stores route through
one `Backend` abstraction (`cnapp_backend.py`); the sqlite path is byte-identical and
a missing driver / unreachable server fails loudly rather than falling back to a
local file.

**Web console (`frontend/`).** A **React 19 + Vite + TypeScript + Tailwind** SPA over
the hub API — the operator surface, styled to match the exported HTML report. Five
screens over one design system: **Overview** (posture dashboard, org ↔ account scope),
**Attack Paths** (ranked toxic-combination worklist + an interactive graph explorer
showing each path's gated-multiplicative score breakdown), **Findings** (unified
deduped queue with source sub-tabs + a risk → business-impact → step-by-step
remediation detail panel), and **Cloud Accounts** with a keyless 5-step **onboarding
wizard** (server-minted ExternalId + CloudFormation / Org StackSet). It runs on
engine-shaped sample fixtures with **zero AWS**, and a `VITE_DATA_SOURCE=live` build
flips every screen to the live hub. `cnapp_api.create_hosted_app(service,
static_dir="frontend/dist")` serves the API under `/api` and the SPA at `/` (with a
history-API fallback) as one deployable. See [`frontend/README.md`](frontend/README.md).

```bash
cd frontend && npm install && npm run dev     # http://localhost:5173  (sample data, no AWS)
```

> Status: backend + onboarding + validation + registry + scan orchestration +
> **live Postgres state** + the **web console** (Overview / Attack Paths / Findings /
> Cloud Accounts + onboarding wizard, plus Inventory / Identity / Compliance / Remediation /
> Reports) + the **connector framework** (Jira / Slack / PagerDuty / Splunk / webhook +
> Settings screen) + **compliance breadth** (30+ frameworks via the NIST-800-53 crosswalk) +
> **continuous scheduled scanning + drift digests** (CTEM cadence + lifecycle drift/trend/MTTR
> + per-scan digests through the connectors) shipped. Remaining: a connection pool; unified
> SARIF/CycloneDX/SPDX ingestion + reachability-verified vuln prioritization.

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
├── aws_live_scanner.py      # Live Audit Scanner v2.19.0 (44 sections, graph, exposure+L7, deep-plane, correlate, effperm, state, ciem, sidescan, backends, remediate, codetocloud, finding-detail, engine-EOL, winvuln, DSPM)
├── aws_remediate.py         # Remediation engine — prioritized plan + remediation-as-code + exports, pure (read-only)
├── aws_codetocloud.py       # Code-to-cloud — IaC index + tiered T1–T5 matcher (TF/CFN → finding source), pure
├── aws_graph_neptune_loader.py # Neptune live loader — bulk-load/openCypher runners (mock-tested), pure builders
├── aws_exposure.py          # Internet-reachability oracle — 4-gate AND, pure/testable (stdlib)
├── aws_deepplane.py         # Deep-plane parsers (Inspector/Macie/GuardDuty/AA) + CAN_READ_DATA (stdlib)
├── aws_correlate.py         # Attack-path correlation engine — enumerate/score/rank/choke (stdlib)
├── aws_graph.py             # SecurityGraph — nodes/edges, bounded traversal, graph.json (stdlib)
├── aws_effperm.py           # Effective-permissions solver — identity∩boundary∩SCP, deny-wins (stdlib)
├── aws_state.py             # Persistent state store — lifecycle/drift/MTTR/waivers (pure sqlite3)
├── aws_unused.py            # CIEM unused-access/right-sizing — Access-Analyzer+SLAD, dormancy (stdlib)
├── aws_sidescan.py          # Agentless CWPP core — inventory + dpkg/rpm/apk vercmp + OSV match + secrets → HAS_VULN (stdlib)
├── aws_sidescan_ebs.py      # EBS Direct-API block plane — plan/delta/checksum/sparse/cleanup (stdlib; live I/O deferred)
├── aws_state_dialect.py     # Postgres/SQLite dialect — DDL/upsert/parse_state_url/row-shim (stdlib)
├── aws_graph_neptune.py     # Neptune export — Gremlin bulk-CSV + openCypher MERGE + round-trip (stdlib)
├── cnapp_onboarding.py · cnapp_validate.py · cnapp_registry.py · cnapp_service.py · cnapp_worker.py · cnapp_api.py · cnapp_backend.py  # Hosted platform backend
├── frontend/                # OverWatch web console — React 19 + Vite + TS + Tailwind SPA (Overview / Attack Paths / Findings / Cloud Accounts + onboarding wizard)
├── deploy/                  # CloudFormation scanner-role + Org StackSet + hub-role templates
├── tests/
│   ├── test_live_scanner.py # 69 unit tests (mock boto3, no credentials needed)
│   ├── test_cnapp_phase1.py # 32 unit tests (graph, chains, trust, org fan-out, compliance)
│   ├── test_exposure.py     # 35 unit tests (internet-exposure FP/FN catalog + attack path)
│   ├── test_deepplane.py    # 44 unit tests (deep-plane FP/FN catalog + collectors + flagship)
│   ├── test_correlate.py    # 22 unit tests (path enumeration + scoring + choke points)
│   ├── test_effperm.py      # 32 unit tests (eval-order truth table, SCP/boundary scenarios)
│   ├── test_state.py        # 22 unit tests (lifecycle, coverage-gated resolve, waivers, MTTR)
│   ├── test_unused.py       # 21 unit tests (dormancy, right-sizing, down-rank, collection)
│   ├── test_phase5_integration.py # 17 tests (ceiling edge-pruning + defect regressions)
│   ├── test_sidescan.py     # 63 unit tests (dpkg/rpm/apk vercmp, parsers, OSV match, secrets, edges)
│   ├── test_sidescan_ebs.py # 21 unit tests (plan/delta-zeroing/checksum/SparseImage/cleanup)
│   ├── test_graph_neptune.py     # 14 unit tests (Gremlin CSV, openCypher, round-trip)
│   ├── test_state_dialect.py     # 22 unit tests (URL parse, qmark→pyformat, upsert, DDL parity)
│   ├── test_phase6_integration.py # 15 tests (ATTACK-02-from-agentless pillar + defect regressions)
│   └── samples/             # Sample IaC files and reports
├── scripts/
│   └── validate_live.py     # Read-only live-account validation harness
├── docs/
│   └── banner.svg
├── CLAUDE.md                # Developer documentation
├── CHANGELOG.md             # Release notes
├── SECURITY.md              # Security policy / responsible disclosure
├── .gitignore
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
