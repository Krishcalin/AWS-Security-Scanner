# CLAUDE.md -- AWS Security Scanner

## Project Overview

Two complementary AWS security scanners, with the live scanner evolving toward a
full **CNAPP** (Cloud-Native Application Protection Platform) — see the CNAPP
blueprint/roadmap: the north star is AWS-deep **toxic-combination attack paths**
computed over a unified security graph.
- **IaC Scanner** (`aws_offline_scanner.py` v1.1.0) -- static analysis of CloudFormation + Terraform files (100+ checks, 25+ services)
- **Live Audit Scanner** (`aws_live_scanner.py` v2.4.0) -- live AWS account audit via boto3 (160+ checks, 39 sections, 5 compliance frameworks, risk scoring, **multi-account/region**, **security graph + attack-path chains**, **internet-exposure engine**, **deep-plane ingestion + flagship attack path**)
- **Security Graph** (`aws_graph.py`) -- dependency-free ARN-keyed property graph the live scanner projects findings onto (Neptune migration seed)
- **Exposure Oracle** (`aws_exposure.py`) -- pure, dependency-free internet-reachability core (SG ∩ stateless NACL ∩ IGW route ∩ public-IP)
- **Deep-Plane Core** (`aws_deepplane.py`) -- pure Inspector/Macie/GuardDuty/Access-Analyzer parsers + the CAN_READ_DATA object-probe matcher

## Repository Structure

```
AWS-Security-Scanner/
├── aws_offline_scanner.py   # IaC scanner v1.1.0 (static analysis, no credentials)
├── aws_live_scanner.py      # Live audit scanner v2.4.0 (boto3, graph, exposure, deep-plane)
├── aws_graph.py             # SecurityGraph — nodes/edges, bounded traversal, graph.json (stdlib)
├── aws_exposure.py          # Internet-reachability oracle — 4-gate AND, pure/testable (stdlib)
├── aws_deepplane.py         # Deep-plane parsers/classifiers (Inspector/Macie/GuardDuty/AA), pure (stdlib)
├── tests/
│   ├── test_live_scanner.py # 69 unit tests (mock boto3)
│   ├── test_cnapp_phase1.py # 32 unit tests (graph, chains, trust, org fan-out, compliance rollup)
│   ├── test_exposure.py     # 35 unit tests (14-case FP/FN catalog + collector + attack path)
│   ├── test_deepplane.py    # 44 unit tests (deep-plane FP/FN catalog + collectors + flagship ATTACK-02)
│   └── samples/             # Vulnerable IaC + sample reports
├── scripts/
│   └── validate_live.py     # Read-only live-account validation harness
├── docs/banner.svg
├── CLAUDE.md
├── SECURITY.md              # Security policy / responsible disclosure
├── CHANGELOG.md             # Release notes
├── .gitignore
├── LICENSE                  # GPL-3.0
└── README.md
```

## IaC Scanner (`aws_offline_scanner.py` v1.1.0)

- **Type**: Static analysis of AWS IaC files (no AWS credentials needed)
- **Lines**: ~2,473
- **Dependencies**: Optional `pyyaml` for CloudFormation YAML
- **Python**: 3.10+

### Two Scanning Engines

| Engine | Input | Approach |
|--------|-------|----------|
| Terraform | `.tf` files | Regex SAST rules (`TF_SAST_RULES`) |
| CloudFormation | `.yaml`/`.yml`/`.json` | Structural analysis (`CF_DISPATCH` -> check methods) |

### Terraform Rules: 60+ across 25 services
Rule ID format: `AWS-{SERVICE}-TF-{NNN}` (e.g. AWS-S3-TF-001, AWS-IAM-TF-003)

### CloudFormation Checks: 42 resource types
Rule ID format: `AWS-{SERVICE}-{NNN}` (e.g. AWS-IAM-001, AWS-S3-001)
- 28 base resource types (v1.0.0)
- 14 gap-service types added in v1.1.0

### Architecture
- Custom YAML loader (`_CF_LOADER`) for CF intrinsic tags (`!Ref`, `!Sub`, `!GetAtt`)
- `Finding` dataclass: rule_id, name, category, severity, file_path, line_num, line_content, description, recommendation, cwe, cve
- `AWSIaCScanner` class: `scan_path`, `_scan_directory`, `_dispatch_file`, `_scan_terraform`, `_scan_cloudformation`
- `_sast_scan()`: Applies regex rules line-by-line (skips comments)
- CF dispatch: `CF_DISPATCH` dict maps resource types -> `_cf_*` check methods (via `getattr`)
- Console + JSON + HTML reports (dark GitHub theme, severity/search filtering)
- Exit code: `1` if CRITICAL or HIGH, `0` otherwise

### CLI
```bash
python aws_offline_scanner.py <target> [--severity SEV] [--json FILE] [--html FILE] [-v] [--version]
```

## Live Audit Scanner (`aws_live_scanner.py` v2.4.0)

- **Type**: Live AWS account audit via boto3 (evolving toward CNAPP)
- **Lines**: ~5,400
- **Dependencies**: `boto3` (required), `aws_graph.py` + `aws_exposure.py` + `aws_deepplane.py` (bundled, stdlib), Python 3.10+
- **IAM permissions**: `SecurityAudit` AWS-managed policy (read-only) covers the deep-plane reads (Inspector2/Macie/GuardDuty/Access Analyzer); multi-account adds `sts:AssumeRole` into a read-only role per target account, and `organizations:ListAccounts` for `--org`
- **Compliance**: CIS AWS v3.0, PCI DSS v4.0, HIPAA, SOC 2, NIST 800-53 Rev 5

### CNAPP Phase 0/1 additions (v2.2.0)

- **Multi-account fan-out** — `--org` (AWS Organizations `list_accounts`) or `--accounts`
  + `--assume-role` (+ `--external-id`) assume a read-only role per account; each account
  scanned via its own `boto3.Session` (`AWSLiveScanner(session=...)`); results + graphs
  aggregate into one org-wide report via `aggregate_results()` (resources prefixed by
  account id). Module fns: `assume_role_session()`, `list_org_accounts()`.
- **Multi-region sweep** — `--all-regions` runs regional sections in every enabled region
  (`_regions_for_section()`); `GLOBAL_SECTIONS` (IAM/S3/ROUTE53/CLOUDFRONT/IAMPRIVESC) run once.
- **Compliance scorecard** — `compliance_scorecard(results)` + `--compliance` + JSON
  `compliance_scorecard` block: per-framework control pass/fail (universe = full
  `COMPLIANCE_MAP`; a control fails if any FAIL/WARN references it).
- **Security graph (`aws_graph.SecurityGraph`)** — `_build_identity_graph()` emits
  `CAN_ASSUME` (trust-policy) and `CAN_PRIVESC_TO` (privesc) edges over ARN-keyed nodes;
  `--graph FILE` writes node-link `graph.json` (Neptune seed). New findings:
  `IAMPE-21` (transitive escalation chains via bounded `graph.reachable()`),
  `IAMPE-22` (role assumable by any principal). Conditioned privesc/trust → WARN.
- **CIEM collection** — `_get_iam_principals()` now uses one `iam:GetAccountAuthorizationDetails`
  paginated call (principals + policy docs + trust docs); roles carry `trust` + `instance_profiles`.
  `parse_trust_policy()` normalizes AssumeRolePolicyDocument; `_policy_to_statements` captures
  `Condition`; `evaluate_privesc_scoped` annotates `conditioned`.

### CNAPP Phase 2 additions (v2.3.0) — effective internet exposure

- **Exposure oracle (`aws_exposure.py`, pure/stdlib)** — an ENI is internet-reachable
  only when the **4-gate AND** holds, per family (IPv4+IPv6): (1) public entry point
  (`classify_public_ip`), (2) active IGW default route (`find_effective_route_table`
  with VPC main-table fallback → `has_igw_default_route`, rejecting nat-/eigw-/blackhole),
  (3) SG public ports (`sg_public_ports`, excludes sg-refs/prefix-lists, expands proto
  `-1`, IPv6 `::/0`), (4) stateless NACL (`find_governing_nacl` → `nacl_permits_service`:
  ordered first-match inbound + full outbound ephemeral-return 1024-65535, via the
  `nacl_allowed_subranges` interval sweep). L7 (ALB/NLB/CloudFront) and sub-`/0` CIDRs
  are **deferred and fail closed** (never a false positive).
- **`EXPOSURE` section (36th)** — `_check_exposure` collects ENIs/instances/route-tables/
  NACLs/SGs (`_paginate_all`), computes exposure per ENI, and emits `EXPOSURE-01`
  (sensitive port, HIGH), `EXPOSURE-02` (service, MEDIUM). Regional (not global) — swept
  by `--all-regions`.
- **First attack path (`ATTACK-01`, CRITICAL)** — chains the exposure subgraph into the
  Phase 1 identity graph: `Internet → EXPOSED_TO → EC2 → HAS_INSTANCE_PROFILE →
  HAS_ROLE → (CAN_PRIVESC_TO / CAN_ASSUME)* → AdminCapability`. Instance-profile→role
  mapping reuses the GAAD-collected `role.instance_profiles`; fired via
  `graph.reachable(role, {CAN_PRIVESC_TO, CAN_ASSUME})`.
- New graph node kinds (InternetSource / NetworkInterface / EC2Instance / InstanceProfile)
  and edges (`EXPOSED_TO` / `ATTACHED_TO` / `HAS_INSTANCE_PROFILE` / `HAS_ROLE`).

### CNAPP Phase 3 additions (v2.4.0) — deep-plane ingestion (buy-not-build)

Three new sections BUY deep-plane signal from AWS-native services as graph edges;
each is **enablement-gated** and degrades to a graceful INFO no-op when its service is
off (never a FAIL/crash/phantom edge). Pure parsers live in `aws_deepplane.py`.

- **VULN (`_check_vuln`)** — Amazon Inspector v2. `batch_get_account_status` gate →
  `list_findings` (ACTIVE high/crit `PACKAGE_VULNERABILITY`) → `HAS_VULN` edges on
  EC2Instance (keyed via `_instance_arn`) / ECRImage nodes, with native EPSS +
  `exploitAvailable` and KEV via a cached `batch_get_finding_details` second hop
  (`_inspector_kev`). `VULN-01/02/03`.
- **THREAT (`_check_threat`)** — GuardDuty. `list_detectors`/`get_detector` gate →
  `list_findings`(non-archived, sev≥4)/`get_findings` → `THREAT_ON` edges via
  `aws_deepplane.map_guardduty_finding` (SAMPLE/archived filtered, ResourceType
  branch). `THREAT-01`.
- **DATA (`_check_data`)** — Macie + Access Analyzer + CAN_READ_DATA + flagship:
  - `_collect_macie` → `aws_deepplane.is_crown_jewel` (score-trap aware) → crown-jewel
    S3 nodes (`DATA-01/02/03`).
  - `_collect_access_analyzer` → authoritative external-access → `EXPOSED_TO` on public
    buckets (`EXTACCESS-01/02`).
  - `_build_can_read_data` → `aws_deepplane.role_can_read_bucket` (wildcard-free
    object-probe, Deny precedence, condition-aware) → `CAN_READ_DATA` edges (`EXTACCESS-03`).
  - `_correlate_flagship` → **`ATTACK-02`** (CRITICAL): `Internet → exposed EC2 →
    exploitable/KEV CVE → role → crown-jewel data`; requires all three hops,
    condition-aware, THREAT_ON boost. Runs last (in DATA) so all subgraphs exist.
- New node kinds (Vulnerability/CVE, ECRImage, S3Bucket/DataStore, ThreatFinding) and
  edges (`HAS_VULN`, `CAN_READ_DATA`, `THREAT_ON`). `_ensure_graph()` builds the
  identity subgraph if IAMPRIVESC hasn't run.
- **Deferred** (fail closed to no-signal): Lambda/EKS vuln planes, CloudTrail CDR-lite,
  unused-access down-ranking, ECR Basic-scan fallback, bucket-policy/SCP evaluation,
  external KEV/EPSS feeds.

### Architecture

```python
@dataclass
class Result:
    status: str           # PASS | FAIL | WARN | INFO
    check_id: str         # e.g. IAM-01
    section: str
    resource: str
    message: str
    severity: str = ""              # CRITICAL | HIGH | MEDIUM | LOW | INFO
    compliance: Dict = {}           # {"CIS": "1.5", "PCI-DSS": "8.3.1", ...}
    remediation_cmd: str = ""       # AWS CLI command

class AWSLiveScanner:
    def __init__(self, region, verbose, sections): ...
    def _client(self, service, region=None): ...   # lazy boto3 client cache
    def _add(self, status, check_id, section, resource, message): ...  # auto-populates severity/compliance/remediation
    def run(self): ...
    def save_json(self, path): ...   # includes posture_score, compliance, remediation
    def save_html(self, path): ...   # severity badges, compliance tags, CLI accordions
    def save_sarif(self, path): ...  # SARIF 2.1.0 (FAIL+WARN) for GitHub code scanning
    def save_asff(self, path): ...   # AWS Security Finding Format for Security Hub import
    def print_diff(self, baseline): ...  # new/resolved vs a prior JSON report
    def save_evidence(self, output_dir): ...
    def print_report(self): ...      # posture score + grade

# Module-level maps:
CHECK_SEVERITY = {...}    # check_id -> CRITICAL/HIGH/MEDIUM/LOW
COMPLIANCE_MAP = {...}    # check_id -> {CIS, PCI-DSS, HIPAA, SOC2, NIST}
REMEDIATION_MAP = {...}   # check_id -> AWS CLI command
compute_risk_score(results) -> float   # 100 - weighted penalties
score_to_grade(score) -> str           # A/B/C/D/F
fails_threshold(results, severity) -> bool   # --fail-on gating
diff_findings(current, baseline_results) -> {new, resolved}
```

- **CHECK_MAP**: Dict mapping 35 section names -> bound check methods
- **35 sections**: IAM, S3, VPC, LOGGING, KMS, EC2, ECR, BACKUP, RDS, GLACIER, SNS, SQS, CLOUDFRONT, ROUTE53, BEDROCK, BEDROCK_AGENTS, LAMBDA, EKS, ECS, SECRETS, WAF, ELASTICACHE, OPENSEARCH, DYNAMODB, STEPFUNCTIONS, APIGATEWAY, ELB, EBS, REDSHIFT, EFS, ACM, SAGEMAKER, COGNITO, APIGATEWAYV2, IAMPRIVESC
- **145+ checks** total; severity auto-assigned per check_id on FAIL
- **Risk scoring**: Score = 100 - (CRIT×15 + HIGH×5 + MED×2 + LOW×0.5), Grade A-F

### Check ID Prefixes
IAM-XX, S3-XX, VPC-XX, LOG-XX, ENC-XX, EC2-XX, CNT-XX, BCK-XX, RDS-XX, GLC-XX, SNS-XX, SQS-XX, CFN-XX, R53-XX, BDR-XX, AGT-XX, LMB-XX, EKS-XX, ECS-XX, SEC-XX, WAF-XX, ELC-XX, OSR-XX, DDB-XX, SFN-XX, APIGW-XX, ELB-XX, EBS-XX, RS-XX, EFS-XX, ACM-XX, SM-XX, COG-XX, AGW2-XX, IAMPE-XX

### IAM Privilege-Escalation Engine (`IAMPRIVESC` section, `IAMPE-XX`)

Distinct from the per-resource checks: instead of inspecting one resource at a
time, it builds each principal's **effective permission set** and matches it
against known escalation primitives.

- **Module-level**: `IAM_PRIVESC_RULES` (declarative primitive table — each rule
  has `all_of`, a list of any-of action requirements), `IAM_PRIVESC_FULL_ADMIN`
  and `IAM_PRIVESC_ASSUMEROLE` sentinels, `evaluate_privesc(allow, deny)`
  (action-level), `evaluate_privesc_scoped(statements)` (resource-aware),
  `resource_scope()`, `_has_full_admin()`, `_resource_applies()`,
  `_action_allowed()` (fnmatch wildcard matching, Deny overrides Allow).
- **Collector**: `_get_iam_principals()` (cached) enumerates users + roles and
  merges attached managed + inline + group policies into a per-principal
  `statements` list (+ derived allow/deny); `_get_managed_policy_statements(arn)`
  (cached) resolves managed policy documents; `_policy_to_statements(doc)` parses
  URL-encoded-string or dict documents, Action/NotAction, Resource/NotResource,
  single/list statements; `_policy_to_action_sets()` derives action sets from it.
- **Resource-aware scoping** (`evaluate_privesc_scoped`): each finding is annotated
  `account-wide` vs `resource-scoped`; full admin requires `Action:*` on
  `Resource:*` (Action `*` scoped to one resource is not flagged as admin); an
  action only counts against resources of its own service, suppressing
  Action-`*`-on-foreign-resource false positives. Conditions, permission
  boundaries, and SCPs are still not evaluated, so findings remain paths to verify.
- **Primitives**: IAMPE-01 CreatePolicyVersion, -02 SetDefaultPolicyVersion,
  -03 Attach\*Policy, -04 Put\*Policy, -05 AddUserToGroup, -06 CreateAccessKey,
  -07 Create/UpdateLoginProfile, -08 UpdateAssumeRolePolicy, -10..14 PassRole+
  (EC2/Lambda/Glue/CloudFormation/SageMaker), -16 UpdateFunctionCode,
  -18 SSM SendCommand/StartSession, -19 full admin, -20 sts:AssumeRole on `*`
  (flagged only when unrestricted). **Graph-derived (v2.2.0)**: -21 transitive
  escalation chains (assume → … → escalate), -22 role assumable by any principal.

### Workflow Integration (CI/CD & AWS-native)

Findings can be emitted in machine formats and used to gate pipelines:

- **SARIF 2.1.0** (`--sarif FILE`): one rule per `check_id`, FAIL+WARN as results,
  severity → SARIF level (CRITICAL/HIGH→error, MEDIUM→warning, LOW→note),
  `security-severity` property for GitHub code-scanning severity, stable
  `partialFingerprints`. PASS/INFO are excluded.
- **ASFF** (`--asff FILE`): AWS Security Finding Format JSON list for
  `aws securityhub batch-import-findings --findings file://FILE` (cap 100/call).
  Maps severity → ASFF label, status → Compliance.Status, compliance map →
  RelatedRequirements, remediation_cmd → Remediation.Recommendation.
- **CI gating** (`--fail-on CRITICAL|HIGH|MEDIUM|LOW`): exit 1 only if a FAIL at
  or above the threshold exists; default exits 1 on any FAIL. Uses
  `SEVERITY_ORDER` + `fails_threshold()`.
- **Scan diff** (`--baseline prev.json`): prints NEW and RESOLVED findings vs a
  previously-saved JSON report; findings keyed by `(check_id, resource)`,
  FAIL/WARN only.

### CLI
```bash
python aws_live_scanner.py [--region REGION] [--json FILE] [--html FILE] \
    [--sarif FILE] [--asff FILE] [--baseline FILE] [--fail-on SEVERITY] \
    [--output-dir DIR] [--sections SEC1,SEC2,...] \
    [--all-regions] [--compliance] [--graph FILE] \
    [--org | --accounts ID1,ID2] [--assume-role ROLE] [--external-id ID] \
    [-v] [--version]
# Note: --sections takes a single COMMA-separated value (e.g. --sections IAM,S3,IAMPRIVESC)
# --org/--accounts require --assume-role (a read-only role assumable in each target account)
```

## Tests

```bash
python -m pytest tests/ -v         # 180 tests, no AWS credentials needed
```

Tests use `unittest.mock` to simulate boto3 responses. Coverage includes:
- Data structures, risk scoring, compliance/remediation maps
- _add() method auto-population of severity/compliance
- IAM, S3, Lambda, EKS, DynamoDB, ElastiCache check logic
- API Gateway, ELB, EBS, Redshift, EFS, ACM check logic
- SageMaker, Cognito, API Gateway v2 (HTTP APIs) check logic
- IAM privilege-escalation engine (action-level path evaluation, policy parsing)
- Workflow outputs: SARIF structure, ASFF fields, --fail-on gating, baseline diff
- IAM privesc resource scoping (account-wide vs resource-scoped, service filtering)
- JSON report with new fields

## Conventions

- Both scanners are read-only -- `aws_live_scanner.py` uses only `describe`/`get`/`list` boto3 calls
- `aws_offline_scanner.py` is pure static analysis -- no AWS connectivity
- The primary branch is `main`
