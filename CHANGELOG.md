# Changelog

All notable changes to the **AWS Live Security Scanner** (`aws_live_scanner.py`)
are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

## [2.2.0] — 2026

**CNAPP Phase 0/1** — the first step from a single-account CSPM toward a
Cloud-Native Application Protection Platform: enterprise-scale collection plus
the foundation of the security graph and attack-path correlation. A new
`aws_graph.py` module (zero dependencies) holds an ARN-keyed property graph that
the scanner projects findings onto.

### Added — security graph & CIEM depth (`aws_graph.SecurityGraph`)
- **Identity graph** built during the IAMPRIVESC section: IAM principal nodes, an
  AdminCapability node, `CAN_PRIVESC_TO` edges (each escalating principal → admin),
  and `CAN_ASSUME` edges parsed from every role's trust policy.
- **`IAMPE-21` transitive privilege-escalation chains** — bounded, cycle-safe graph
  traversal surfaces `userA → assume roleB → escalate to admin` paths that
  per-principal analysis misses.
- **`IAMPE-22` dangerous role trust** — flags roles assumable by *any* AWS principal
  (`Principal: "*"`); downgraded to WARN when a Condition (ExternalId/OrgID) guards it.
- **Condition-aware privesc** — escalation paths whose granting statement carries a
  policy Condition are downgraded from FAIL to WARN ("verify the condition").
- `_get_iam_principals` now uses a single **`iam:GetAccountAuthorizationDetails`**
  call (principals + inline/managed policy docs + role trust docs in one paginated
  pull) instead of N per-principal calls.
- **`--graph FILE`** serializes the graph to node-link `graph.json` — the Neptune
  migration seed. Graph stats are embedded in the JSON report.

### Added — multi-account & multi-region (agentless scale)
- **`--org`** enumerates all ACTIVE accounts via AWS Organizations and scans each;
  **`--accounts`** scans an explicit list. Both use **`--assume-role`** (+ optional
  **`--external-id`**) to assume a read-only role per target account. Per-account
  results/graphs aggregate into one org-wide report (every existing emitter reused).
- **`--all-regions`** sweeps every enabled region for regional sections while global
  sections (IAM/S3/Route53/CloudFront/IAMPRIVESC) run once.

### Added — compliance rollup
- **`compliance_scorecard()`** + **`--compliance`**: per-framework control pass/fail
  rollup (CIS/PCI-DSS/HIPAA/SOC2/NIST), embedded in the JSON report. The control
  universe is the full `COMPLIANCE_MAP`; a control fails if any FAIL/WARN references it.
- Backfilled ~40 previously-unmapped FAIL-capable checks in `COMPLIANCE_MAP` and
  filled `CHECK_SEVERITY` gaps.

### Testing
- 69 → 101 unit tests (new `tests/test_cnapp_phase1.py`: graph, trust parsing,
  chains, wildcard trust, condition downgrade, GAAD collection, compliance rollup,
  Organizations fan-out, region iterator — all mocked, no AWS/boto3 required).

## [2.1.0] — 2026

A large feature release: broader service coverage, a new IAM attack-path engine
with resource-aware scoping, and machine-readable output for CI/CD and AWS Security Hub.

### Added — service sections (25 → 35)
- **API Gateway** (`APIGW-01..04`) — stage logging, WAF association, cache encryption, X-Ray tracing
- **Elastic Load Balancing** (`ELB-01..05`) — access logging, HTTP→HTTPS redirect, weak TLS policy, deletion protection, drop-invalid-headers
- **EBS** (`EBS-01..04`) — encryption-by-default, unencrypted volumes, unencrypted snapshots, public snapshots
- **Redshift** (`RS-01..05`) — encryption, public access, audit logging, enhanced VPC routing, default admin username
- **EFS** (`EFS-01..03`) — encryption at rest, in-transit TLS policy, automatic backups
- **ACM** (`ACM-01..03`) — certificate expiry, key algorithm strength, unused certificates
- **SageMaker** (`SM-01..04`) — notebook internet access, root access, KMS volume encryption, VPC deployment
- **Cognito** (`COG-01..04`) — user-pool MFA, password policy, advanced security, deletion protection
- **API Gateway v2 / HTTP APIs** (`AGW2-01..03`) — stage access logging, route authorization, default throttling

### Added — IAM privilege-escalation engine (`IAMPRIVESC`, `IAMPE-*`)
- New section that builds each principal's effective permission set (attached
  managed + inline + group policies) and matches it against the well-known
  privesc primitive catalog (Rhino Security Labs / PMapper).
- 16 action-level primitives: CreatePolicyVersion, SetDefaultPolicyVersion,
  Attach*/Put* policy, AddUserToGroup, CreateAccessKey, Create/UpdateLoginProfile,
  UpdateAssumeRolePolicy, PassRole→(EC2/Lambda/Glue/CloudFormation/SageMaker),
  UpdateFunctionCode, SSM, and a full-admin (`*`) short-circuit (`IAMPE-19`).
- **Resource-aware scoping**: findings are annotated `account-wide` vs
  `resource-scoped`; full admin now requires `Action:* on Resource:*` (Action `*`
  scoped to a single resource is no longer mis-flagged); actions are matched only
  against resources of their own service. Adds `IAMPE-20` (`sts:AssumeRole` on `*`),
  flagged only when unrestricted — removing the common scoped-AssumeRole false
  positive.

### Added — workflow integration
- `--sarif FILE`: SARIF 2.1.0 output for GitHub code scanning (severity→level,
  `security-severity`, partial fingerprints; FAIL+WARN only).
- `--asff FILE`: AWS Security Finding Format JSON for Security Hub
  `batch-import-findings`.
- `--fail-on CRITICAL|HIGH|MEDIUM|LOW`: gate the exit code on a severity threshold.
- `--baseline prev.json`: print NEW and RESOLVED findings vs a previous scan.

### Changed
- `--sections` documented as a single comma-separated value (matches the
  comma-split parsing); CLI examples and help corrected.
- Added `.gitignore`, `SECURITY.md`, and this `CHANGELOG.md`.

### Testing
- 28 → 69 unit tests (mocked boto3, no AWS credentials required).

## [2.0.0] — 2026

- Live AWS account audit via boto3 across 25 service sections / 100+ checks.
- Five compliance frameworks (CIS AWS v3.0, PCI DSS v4.0, HIPAA, SOC 2,
  NIST 800-53 Rev 5) mapped per check.
- Risk scoring (posture score 0–100, grade A–F) and per-check AWS CLI remediation.
- Console / JSON / HTML reports and an evidence artefact directory.
