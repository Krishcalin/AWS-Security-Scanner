# Changelog

All notable changes to the **AWS Live Security Scanner** (`aws_live_scanner.py`)
are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

## [2.4.0] — 2026

**CNAPP Phase 3 — Deep-Plane Ingestion (buy-not-build) + the flagship attack path.**
Rather than building agent-based scanning, this release BUYS commodity deep-plane
signal from AWS-native services and ingests it as graph edges, then materializes the
full flagship toxic combination. New `aws_deepplane.py` module (zero dependencies) is
a pure, fully unit-tested parsing/classification core.

**Correctness backbone:** these services (Inspector, Macie, GuardDuty, Access
Analyzer) are opt-in and frequently disabled. Every collector is enablement-gated and
**degrades to a graceful INFO no-op when its service is off — never a FAIL, crash, or
phantom edge**. That "service-disabled → no false positive" behavior heads the FP/FN
catalog and was adversarially verified.

### Added — deep-plane collectors (3 new sections: VULN · THREAT · DATA)
- **VULN — Amazon Inspector v2** (`inspector2`): active high/critical
  `PACKAGE_VULNERABILITY` findings become **`HAS_VULN`** edges on EC2/ECR nodes,
  carrying native **EPSS** + `exploitAvailable`, and the authoritative **CISA-KEV**
  flag via a cached `batch_get_finding_details` second hop. Findings `VULN-01`
  (exploitable high/crit), `VULN-02` (KEV / in-the-wild → CRITICAL), `VULN-03` (ECR image).
- **THREAT — GuardDuty**: active (non-archived, severity≥4) detector findings become
  **`THREAT_ON`** edges mapped onto EC2/S3/IAM nodes (`THREAT-01`); `[SAMPLE]` and
  archived findings filtered. Boosts the priority of any attack path they land on.
- **DATA — Macie + IAM Access Analyzer + CAN_READ_DATA**:
  - Macie automated `sensitivityScore` (score-trap-aware: -1/1/50-default and
    `classifiableObjectCount==0` are never crown-jewel) labels S3 **crown-jewel
    DataStore** nodes (`DATA-01/02/03`).
  - Access Analyzer external-access findings add **authoritative** `EXPOSED_TO`
    edges on public buckets (`EXTACCESS-01/02`), overriding heuristics.
  - **`CAN_READ_DATA`** edges (`EXTACCESS-03`) computed from each role's effective
    identity statements via a wildcard-free **object-probe** — so `s3:ListBucket`
    (bucket-scoped) can never masquerade as object read, with Deny precedence and
    condition-awareness. No API cost.

### Added — flagship attack path (`ATTACK-02`, CRITICAL)
- The full toxic combination: **`Internet → exposed EC2 → exploitable/KEV CVE →
  over-privileged instance-profile role → crown-jewel S3 data`**. Composes the Phase 1
  identity graph + Phase 2 exposure graph + the new vuln/data edges; requires all
  three hops (fails closed when a source service is off). Condition-aware (CRITICAL
  over unconditioned edges, else WARN) and escalated to TOP priority when a live
  GuardDuty `THREAT_ON` sits on the chain. `SecurityGraph.reachable` already supports
  the condition-aware `edge_filter` from Phase 2.

### Testing
- 136 → **180** unit tests (new `tests/test_deepplane.py`: pure FP/FN catalog +
  enablement/degradation no-op tests + flagship ATTACK-02, all mocked, no AWS/boto3).
- Grounded in a verified AWS-API research pass; hardened by an adversarial FP/FN sweep.

## [2.3.0] — 2026

**CNAPP Phase 2 — Effective Network Exposure Engine.** Computes *true* internet
reachability instead of "a security group allows 0.0.0.0/0", and fires the first
end-to-end **attack path**. New `aws_exposure.py` module (zero dependencies) is a
pure, fully unit-tested reachability oracle; the whole false-positive/false-negative
catalog runs without AWS.

### Added — the exposure oracle (`aws_exposure.py`)
- An ENI is judged internet-reachable only when the **4-gate AND** holds, per
  address family (IPv4 + IPv6), per ENI:
  1. **Public entry point** — auto-assigned public IPv4, an EIP, or a global IPv6.
  2. **IGW default route** — the subnet's *effective* route table (explicit
     association, else VPC main-table fallback) has an active `0.0.0.0/0`/`::/0`
     route to a real `igw-…` — not NAT / egress-only-IGW / blackhole.
  3. **SG public ports** — union of ingress rules open to `0.0.0.0/0` / `::/0`.
     `UserIdGroupPairs` (sg-references) and prefix-lists are **not** public (the
     #1 false positive); `IpProtocol='-1'` expands to all tcp+udp (the #1 FN).
  4. **Stateless NACL** — ordered first-match evaluation allows the inbound
     service port **AND** the outbound **ephemeral return** (1024-65535); a
     stateless NACL that blocks the return path is not reachable.
- L7 (ALB/NLB/CloudFront) and narrower-than-`/0` public CIDRs are deliberately
  deferred and **fail closed** (never emit a false positive).

### Added — exposure section + first attack path (`EXPOSURE`, 36th section)
- **`EXPOSURE-01`** internet-reachable *sensitive* port (SSH/RDP/DB/etc.),
  **`EXPOSURE-02`** internet-reachable service — emitted only when all four gates pass.
- **`ATTACK-01`** — the flagship toxic combination:
  `Internet → EXPOSED_TO → EC2 → instance-profile role → CAN_PRIVESC_TO admin`.
  Chains the exposure subgraph into the Phase 1 identity graph and fires when an
  exposed host's instance-profile role can reach `AdminCapability` (directly or via
  transitive assume/privesc). **Condition-aware**: CRITICAL/FAIL only when admin is
  reachable over *unconditioned* edges; if every path to admin crosses a
  Condition-guarded privesc/trust (MFA/ExternalId/tag/SourceIp) it is reported as
  WARN — consistent with the Phase-1 conditioned-privesc model.
- New graph node kinds (InternetSource, NetworkInterface, EC2Instance,
  InstanceProfile) and edges (`EXPOSED_TO`, `ATTACHED_TO`, `HAS_INSTANCE_PROFILE`,
  `HAS_ROLE`) added to `aws_graph`; serialized by `--graph`.

### Testing
- 101 → **136** unit tests: the full 14-case FP/FN catalog (`tests/test_exposure.py`)
  plus collector integration + attack-path tests, all mocked (no AWS/boto3).
- Grounded in a verified AWS-semantics research pass and hardened by an adversarial
  false-positive/false-negative sweep of the real code.

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
