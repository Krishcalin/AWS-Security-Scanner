# CLAUDE.md -- AWS Security Scanner

## Project Overview

Two complementary AWS security scanners, with the live scanner evolving toward a
full **CNAPP** (Cloud-Native Application Protection Platform) — see the CNAPP
blueprint/roadmap: the north star is AWS-deep **toxic-combination attack paths**
computed over a unified security graph.
- **IaC Scanner** (`aws_offline_scanner.py` v1.1.0) -- static analysis of CloudFormation + Terraform files (100+ checks, 25+ services)
- **Live Audit Scanner** (`aws_live_scanner.py` v2.8.0) -- live AWS account audit via boto3 (160+ checks, 40 sections, 5 compliance frameworks, risk scoring, **multi-account/region**, **security graph**, **internet-exposure engine**, **deep-plane ingestion + flagship attack path**, **attack-path correlation + choke points**, **effective-permissions ceiling (boundary∩SCP)**, **persistent state/drift/waivers**, **CIEM right-sizing**, **agentless EBS side-scan (CWPP)**, **Postgres/Neptune export**, **remediation engine + remediation-as-code**, **code-to-cloud IaC mapping**)
- **Security Graph** (`aws_graph.py`) -- dependency-free ARN-keyed property graph the live scanner projects findings onto (Neptune migration seed)
- **Exposure Oracle** (`aws_exposure.py`) -- pure, dependency-free internet-reachability core (SG ∩ stateless NACL ∩ IGW route ∩ public-IP)
- **Deep-Plane Core** (`aws_deepplane.py`) -- pure Inspector/Macie/GuardDuty/Access-Analyzer parsers + the CAN_READ_DATA object-probe matcher
- **Correlation Engine** (`aws_correlate.py`) -- pure attack-path enumeration + gated-multiplicative scoring + choke-point ranking
- **Effective-Permissions Solver** (`aws_effperm.py`) -- pure identity ∩ permission-boundary ∩ SCP evaluator (explicit-deny-wins, condition-aware, fail-open) that refines/drops escalation edges
- **State Store** (`aws_state.py`) -- pure stdlib-sqlite3 finding lifecycle / drift / MTTR / posture-trend / waivers (the scanner's memory)
- **CIEM Right-Sizing** (`aws_unused.py`) -- pure unused-access classification (Access Analyzer + SLAD) + dormancy down-rank overlay
- **Agentless Side-Scan** (`aws_sidescan.py` + `aws_sidescan_ebs.py`) -- pure CWPP core: OS-package inventory + ecosystem-correct (dpkg/rpm/apk) OSV vuln matching + on-disk secrets → HAS_VULN edges; EBS Direct-API block plane (plan/checksum/sparse-reassembly/cleanup) + live snapshot runner (guaranteed cleanup). Real fs extraction deferred
- **Persistence Backends** (`aws_state_dialect.py` + `aws_graph_neptune.py` + `aws_graph_neptune_loader.py`) -- pure Postgres DDL/upsert/dialect generators + Neptune Gremlin-CSV / openCypher graph export + live bulk-load/openCypher runners
- **Remediation Engine** (`aws_remediate.py`) -- pure prioritized fix plan (reuses `aws_correlate.minimal_cut`/`ChokePoint`) + remediation-as-code (Terraform/CFN/CLI) + runbook/JSON/issue/PR exports; read-only, never applies
- **Code-to-Cloud** (`aws_codetocloud.py`) -- pure IaC index (Terraform block extractor + CFN parse) + tiered T1–T5 matcher mapping a live finding to its source IaC resource

## Repository Structure

```
AWS-Security-Scanner/
├── aws_offline_scanner.py   # IaC scanner v1.1.0 (static analysis, no credentials)
├── aws_live_scanner.py      # Live audit scanner v2.8.0 (boto3, graph, exposure, deep-plane, correlate, effperm, state, ciem, sidescan, backends, remediate, codetocloud)
├── aws_remediate.py         # Remediation engine — prioritized plan (reuses minimal_cut/ChokePoint) + remediation-as-code + exports, pure
├── aws_codetocloud.py       # Code-to-cloud — IaC index (TF block extractor + CFN parse) + tiered T1–T5 matcher, pure
├── aws_graph_neptune_loader.py # Neptune live loader — S3 bulk-load + openCypher runners (mock-tested), pure builders
├── aws_graph.py             # SecurityGraph — nodes/edges, bounded traversal, graph.json (stdlib)
├── aws_exposure.py          # Internet-reachability oracle — 4-gate AND, pure/testable (stdlib)
├── aws_deepplane.py         # Deep-plane parsers/classifiers (Inspector/Macie/GuardDuty/AA), pure (stdlib)
├── aws_correlate.py         # Attack-path correlation engine — enumerate/score/rank/choke-points, pure (stdlib)
├── aws_effperm.py           # Effective-permissions solver — identity∩boundary∩SCP, deny-wins, pure (stdlib)
├── aws_state.py             # Persistent state store — lifecycle/drift/MTTR/waivers, pure sqlite3
├── aws_unused.py            # CIEM unused-access/right-sizing — Access-Analyzer+SLAD, dormancy down-rank, pure
├── aws_sidescan.py          # Agentless CWPP core — inventory parsers + dpkg/rpm/apk vercmp + OSV match + secrets + HAS_VULN edges, pure
├── aws_sidescan_ebs.py      # EBS Direct-API block plane — plan/delta/checksum/sparse-reassembly/cleanup, pure (live I/O deferred)
├── aws_state_dialect.py     # Postgres/SQLite dialect — DDL/upsert/parse_state_url/row-shim, pure
├── aws_graph_neptune.py     # Neptune export — Gremlin bulk-CSV + openCypher MERGE + round-trip loader, pure
├── tests/
│   ├── test_live_scanner.py # 69 unit tests (mock boto3)
│   ├── test_cnapp_phase1.py # 32 unit tests (graph, chains, trust, org fan-out, compliance rollup)
│   ├── test_exposure.py     # 35 unit tests (14-case FP/FN catalog + collector + attack path)
│   ├── test_deepplane.py    # 44 unit tests (deep-plane FP/FN catalog + collectors + flagship ATTACK-02)
│   ├── test_correlate.py    # 22 unit tests (path enumeration + scoring + choke points + section)
│   ├── test_effperm.py      # 32 unit tests (eval-order truth table, SCP scenarios, boundary cases)
│   ├── test_state.py        # 22 unit tests (lifecycle/coverage-gated resolve/waivers/MTTR/trend)
│   ├── test_unused.py       # 21 unit tests (dormancy/factor/right-sizing/down-rank/collection)
│   ├── test_phase5_integration.py # 17 tests (ceiling prunes edges end-to-end + defect regressions)
│   ├── test_sidescan.py     # dpkg/rpm/apk vercmp matrix, parsers, OSV match, secrets, edges, detect_fs
│   ├── test_sidescan_ebs.py # block plane + live snapshot runner + provenance-guarded cleanup
│   ├── test_remediate.py    # 22 tests (plan prioritization, codegen, exports, fix-key, determinism)
│   ├── test_codetocloud.py  # 24 tests (TF/CFN parse, tiered matcher, false-match regressions)
│   ├── test_neptune_loader.py # 11 tests (request builders + mock bulk-load/openCypher runners)
│   ├── test_phase7_integration.py # remediation wiring + default-path invariant
│   ├── test_graph_neptune.py     # 14 unit tests (Gremlin CSV types+escaping, openCypher, round-trip)
│   ├── test_state_dialect.py     # 22 unit tests (URL parse, qmark→pyformat, upsert, row-shim, DDL parity)
│   ├── test_phase6_integration.py # 15 tests (ATTACK-02-from-agentless pillar + wiring + defect regressions)
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

## Live Audit Scanner (`aws_live_scanner.py` v2.8.0)

- **Type**: Live AWS account audit via boto3 (evolving toward CNAPP)
- **Lines**: ~6,700
- **Dependencies**: `boto3` (required), `aws_graph.py` + `aws_exposure.py` + `aws_deepplane.py` + `aws_correlate.py` + `aws_effperm.py` + `aws_state.py` + `aws_unused.py` (bundled, stdlib), Python 3.10+
- **IAM permissions**: `SecurityAudit` AWS-managed policy (read-only) covers the deep-plane reads (Inspector2/Macie/GuardDuty/Access Analyzer) and the effective-permissions reads (`iam:GetAccountAuthorizationDetails` for boundaries, `organizations:Describe*/List*` for SCPs — all degrade gracefully); multi-account adds `sts:AssumeRole` into a read-only role per target account, and `organizations:ListAccounts` for `--org`. `--ciem` additionally uses `iam:GenerateServiceLastAccessedDetails` and `access-analyzer:ListFindingsV2`
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

### CNAPP Phase 4 additions (v2.5.0) — attack-path correlation & choke points

- **Correlation engine (`aws_correlate.py`, pure/stdlib)** — reads the graph and produces
  ranked attack paths + choke points. Predicates (`_edge_unconditioned`,
  `aws_deepplane.is_exploitable`, `_node_has_threat`) are INJECTED so it can never
  diverge from the ATTACK-01/02 emitters:
  - `enumerate_paths` — bounded simple-path DFS from `internet` to sinks (crown-jewel
    S3 + admin capability) over `E_PATH` edges; preserves the **ATTACK-02 vuln-pivot
    gate**; bounded by `MAX_HOPS`/`PER_PAIR_CAP`/`ENUM_BUDGET`; deterministic.
  - `_make_path` — **gated-multiplicative** score `E × X × max(P,I) × reach × T` with a
    conditioned cap(55)/unconditioned floor(80) that reproduces ATTACK-01/02's
    CRITICAL-vs-WARN, plus a KEV+data hard floor(90). Every score carries a `rationale`.
  - `choke_points` — severity-weighted path-frequency + `is_true_choke` dominator flag;
    `EXCLUDE_KINDS` structurally bars the internet/crown/admin nodes. `minimal_cut`
    greedy set-cover. `WEIGHTS` dict is tunable.
- **`CORRELATE` section (40th, in `GLOBAL_SECTIONS` so it runs ONCE, last)** —
  `_check_correlate` calls the engine, stores `self.attack_paths`/`self.choke_points`,
  emits `CHOKEPOINT-01` (HIGH, top≤3 chokes that sever a CRITICAL/HIGH path) + `PATHS-01`
  (INFO rollup), and annotates choke nodes on the graph. `save_json` gains ranked
  `attack_paths` + `choke_points` blocks (`self.attack_paths=[]` seeded in `__init__`).
- **ATTACK-01/ATTACK-02 stay byte-for-byte** in `_check_exposure`/`_correlate_flagship` —
  the engine is a read-only post-processor (no test edits to exposure/deep-plane).

### CNAPP Phase 5 additions (v2.6.0) — effective-permissions depth + persistent state

- **Effective-permissions solver (`aws_effperm.py`, pure/stdlib)** — models the AWS
  single-account decision chain so the identity graph reflects *effective* (not merely
  granted) escalation. `pivot_effective(action, identity, boundary, scp_levels)` →
  `KEEP`/`CONDITIONED`/`DROP`: unconditional explicit Deny wins everywhere; the
  permission boundary is a ceiling (intersection); SCP levels are AND-ed root→account
  (OR within a level). Only a *provable unconditional* denial prunes — a Condition-gated
  allow/deny downgrades to CONDITIONED, never a silent drop. **Fail-open**: `boundary=None`
  AND `scp_levels=None` can never DROP (graph identical to Phase 4).
- **Ceiling collection + edge refinement (`aws_live_scanner.py`)** — boundaries resolved
  per-principal from GAAD (`_resolve_boundary`, unresolvable/empty → None); `_get_scp_context`
  walks Organizations account→root and **fails the whole SCP layer open** on the mgmt
  account, non-ALL org, or ANY unreadable node (an unreadable ceiling must never read as
  deny-all). `evaluate_privesc_scoped(statements, boundary, scp_levels, pruned)` and the
  `CAN_ASSUME` gate drop/downgrade edges; a boundary/SCP-capped full-admin still enumerates
  the granular pivots that survive. `save_json` gains an `effective_permissions` audit block.
- **Persistent state store (`aws_state.py`, pure sqlite3)** — the scanner's memory:
  finding lifecycle (`open`/`resolved`/`reopened`), **NEW** as a read-time projection,
  **MUTATED** config-drift, **coverage-gated resolve** (a partial scan never mass-resolves
  what it didn't run; global-service findings use a stable `global` region), episode-based
  **MTTR**, **posture trend**, and **waivers** (approver/expiry as a live overlay →
  auto-reactivation on expiry, zero DB mutation). Wired via `_process_state` behind `--state`;
  suppressed findings leave `--fail-on` gating but stay in the posture score and the report.
- **CIEM right-sizing (`aws_unused.py`, opt-in `--ciem`)** — Access Analyzer unused-access →
  SLAD fallback → dormancy; emits LOW `CIEM-01` review-candidate findings and a bounded,
  non-mutating exploit-likelihood down-rank overlay for paths through dormant principals
  (impact untouched; unknown/stuck-job → no down-rank).
- **Verification** — an 18-agent adversarial FP/FN/scale hunt ran the real code and found
  9 defects (incl. 2 CRITICAL over-prunes: an unreadable-SCP deny-all and a full-admin
  short-circuit); all fixed and regression-tested before commit.

### CNAPP Phase 6 additions (v2.7.0) — agentless side-scan (CWPP) + persistence backends

- **Agentless side-scan (`aws_sidescan.py`, pure)** — the Wiz/Orca CWPP capability with
  no agent: OS-package inventory parsers (dpkg/apk/rpm sqlite-header + manifest), the
  THREE ecosystem-correct version comparators (dpkg/rpm/apk — never semver; a bug here is
  a silent missed-CVE FN, the most dangerous class), an OSV matcher over distro-advisory
  feeds with EPSS/KEV/exploit enrichment, and on-disk secret detection (entropy-gated,
  preview-only). `emit_vuln_edges` writes `HAS_VULN` edges shaped 1:1 with the Inspector
  plane, so agentless CVEs light up ATTACK-02 even when Inspector is OFF, and MERGE-converge
  with Inspector when both run. Raw ext4/xfs parsing is deferred behind an injected
  `FilesystemExtractor` (test impl `DictExtractor`).
- **EBS block plane (`aws_sidescan_ebs.py`, pure)** — EBS Direct-API fetch planning
  (full/delta with removed- AND capped-changed-block zeroing), base64-SHA256 checksum
  verify, `SparseImage` reassembly, token rebind-on-expiry, and provenance-guarded cleanup
  (`is_owned` — never delete a resource we did not tag). Live snapshot I/O + real fs
  extraction deferred to Phase 7 behind `HAS_BOTO3`.
- **Persistence backends (pure generators)** — `aws_state_dialect.py` renders the aws_state
  schema for Postgres (BIGINT epochs, IDENTITY, ON CONFLICT upserts + drift-counter reset,
  `?`→`%s`, hybrid Row shim, `parse_state_url`); a `postgresql://` URL routes to a clean
  `StateBackendUnavailable` → stateless (never a silent local sqlite). `aws_graph_neptune.py`
  exports Gremlin bulk-CSV (bool-before-int typing, per-label homogeneous columns, RFC-4180
  escaping) + idempotent openCypher UNWIND/MERGE + a round-trip loader. `aws_graph`/
  `aws_correlate` unchanged.
- **Integration** — a gated `SIDESCAN` section (after EXPOSURE, before VULN) over the
  internet-exposed EC2 set; CWPP-01..04 checks; CLI `--side-scan[/-targets/-tag/-max]`,
  `--no-side-scan-secrets`, `--vuln-db`, `--backend`, `--graph-neptune-csv/-cypher`;
  additive `save_json` blocks. Default path (no flags) is byte-for-byte unchanged.
- **Verification** — a read-only adversarial hunt found 3 defects (a HIGH dpkg-comparator
  missed-CVE FN, a MEDIUM `backend`-key default-path JSON leak, a LOW latent delta-cap
  stale-bytes trap); all fixed + regression-tested before merge.

### CNAPP Phase 7 additions (v2.8.0) — remediation + code-to-cloud ("close the loop")

- **Remediation engine (`aws_remediate.py`, pure)** — `build_plan(...)` REUSES
  `aws_correlate.minimal_cut` + `ChokePoint` (never re-ranks) to emit a prioritized,
  deduped plan: "fix K items to cut N% of critical attack paths." Each
  `RemediationAction` names the node to fix, the paths it severs, the crown jewels
  it protects, effort/blast-radius, and **remediation-as-code** (a ~9-template
  registry rendering Terraform + CloudFormation + AWS CLI; `_safe_format` uses
  `string.Template.safe_substitute` so a missing param → `<PLACEHOLDER>` and a
  `${…}`/`$` never raises). Exports: `to_markdown` runbook, `plan_to_json`,
  `to_github_issue`, `to_github_pr_body`. **Read-only — generates artifacts, never
  applies.** `_select_fix_key` picks the fix by node kind + own edges (patch_cve
  only when a vuln actually gates the path).
- **Code-to-cloud (`aws_codetocloud.py`, pure)** — `build_iac_index` (a NEW
  string/comment/heredoc-aware brace-balanced Terraform block extractor +
  structural CFN parse) + `match_to_iac` tiered T1–T5 confidence matcher (exact
  physical name / *distinctive* tag / CFN logical-id / naming heuristic / type-only).
  An empty/unknown type or ambiguous signal returns `None` — it NEVER anchors a
  finding to the wrong resource. Feeds the remediation engine the IaC source
  target + diff via `--iac-dir`.
- **Live loaders/runners (mock-tested; real infra deferred)** —
  `aws_graph_neptune_loader.py` (S3 bulk-load request builder with a fail-closed
  non-terminal allowlist + runners over injected s3/neptunedata),
  `aws_sidescan_ebs.run_snapshot_sidescan` (live snapshot lifecycle with
  guaranteed provenance-guarded cleanup on every error path; a truncated read is
  flagged INCOMPLETE), and `aws_sidescan.detect_fs` (magic sniffer so an
  encrypted/unknown volume is an honest INFO, not a false-clean).
- **Integration** — gated `--remediate` (+ `--remediate-out/-format/-min-severity`),
  `--iac-dir`, `--graph-neptune-load`. `save_json` gains `remediation`/`code_to_cloud`
  blocks. Default path (no flags) byte-for-byte unchanged; no `--remediate` → the
  modules are never imported.
- **Verification** — a read-only adversarial hunt found 7 defects (4 HIGH
  code-to-cloud false-match bugs: cross-type match on empty type, non-distinctive
  tag match, brace-in-string block bleed, `${…}` tag truncation; a HIGH nonsensical
  patch_cve without a vuln; a MEDIUM loader-hang; a LOW `_safe_format` raise) — all
  in the opt-in features, all fixed + regression-tested. Default path + cleanup
  safety verified clean.
- **Deferred** (fail-closed): live PostgresBackend StateStore rewiring (pure
  generators shipped Phase 6), rpm Berkeley-DB decode + real ext4/xfs parse
  (dissect), and any live cloud/repo mutation.

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
  FAIL/WARN only. Superseded by `--state` (DB-backed lifecycle) when both given.
- **Persistent state** (`--state cnapp.db`): SQLite finding lifecycle across scans —
  NEW/RESOLVED/REOPENED/MUTATED drift, MTTR, posture trend; `--sla-days N` reports
  findings open past the SLA. Prints a per-account drift summary.
- **Waivers** (`--suppress KEY --approver NAME [--reason T] [--expires 30d]`, needs
  `--state`): waive a finding out of `--fail-on` gating (stays open/tracked/scored);
  `--list-waivers` prints active/expired/revoked. A malformed `--expires` is rejected
  (exit 2), never a silent permanent waiver.

### CLI
```bash
python aws_live_scanner.py [--region REGION] [--json FILE] [--html FILE] \
    [--sarif FILE] [--asff FILE] [--baseline FILE] [--fail-on SEVERITY] \
    [--output-dir DIR] [--sections SEC1,SEC2,...] \
    [--all-regions] [--compliance] [--graph FILE] \
    [--org | --accounts ID1,ID2] [--assume-role ROLE] [--external-id ID] \
    [--state FILE] [--suppress KEY --approver NAME [--reason T] [--expires WHEN]] \
    [--list-waivers] [--sla-days N] [--ciem] \
    [--side-scan [--side-scan-targets exposed|all|tagged] [--side-scan-tag K=V] \
                 [--side-scan-max N] [--no-side-scan-secrets] [--vuln-db FILE]] \
    [--backend URL] [--graph-neptune-csv DIR] [--graph-neptune-cypher FILE] \
    [--graph-neptune-load --neptune-s3-bucket B --neptune-iam-role ARN] \
    [--remediate [--remediate-out DIR] [--remediate-format md,json,issue,pr] \
                 [--remediate-min-severity SEV]] [--iac-dir DIR] \
    [-v] [--version]
# Note: --sections takes a single COMMA-separated value (e.g. --sections IAM,S3,IAMPRIVESC)
# --org/--accounts require --assume-role (a read-only role assumable in each target account)
# --suppress requires --approver and --state; --list-waivers requires --state
# --side-scan-targets tagged requires --side-scan-tag; --backend postgresql:// runs stateless (Phase 7)
```

## Tests

```bash
python -m pytest tests/ -v         # 483 tests, no AWS credentials needed
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
- **Phase 5**: effective-permissions eval-order truth table + SCP/boundary scenarios;
  state lifecycle (coverage-gated resolve, MUTATED, REOPENED, idempotency), waiver
  suppression + expiry re-gating, MTTR/trend; CIEM dormancy/right-sizing/down-rank;
  end-to-end ceiling edge-pruning; and a regression test per adversarial-verify defect
- **Phase 7**: remediation-plan prioritization (reuses minimal_cut, first-cover
  headline), fix-key selection + codegen determinism, code-to-cloud TF/CFN parse +
  tiered matcher with false-match regressions (empty-type, non-distinctive tag,
  brace-in-string bleed, `${…}` truncation), Neptune loader fail-closed terminal
  detection, and the remediation wiring + default-path invariant
- **Phase 6**: dpkg/rpm/apk version-comparison matrices + OSV affected-range matching;
  inventory parsers + rpm-header struct decode; secrets FP/FN + exfil-safety; EBS
  plan/delta-zeroing/checksum/sparse-reassembly/provenance-cleanup; Postgres dialect
  (URL parse, qmark→pyformat, upsert, row-shim); Neptune CSV/openCypher + round-trip;
  the ATTACK-02-from-agentless pillar; and a regression per adversarial-verify defect

## Conventions

- Both scanners are read-only -- `aws_live_scanner.py` uses only `describe`/`get`/`list` boto3 calls
- `aws_offline_scanner.py` is pure static analysis -- no AWS connectivity
- The primary branch is `main`
