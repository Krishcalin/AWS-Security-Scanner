# Changelog

All notable changes to the **AWS Live Security Scanner** (`aws_live_scanner.py`)
are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

## [2.21.0] — 2026

**Fargate serverless-container workloads folded into the attack-path graph (Phase-3 · agentless coverage).**
An ECS-Fargate task's image CVEs now drive attack paths — closing the "KubeArmor's biggest AWS
gap" blind spot, agentlessly.

### Added — running Fargate workloads (`aws_live_scanner.py`)
- **`_check_fargate_tasks`** (called from `_check_ecs`, ECS#20): enumerate RUNNING Fargate tasks
  (`list_tasks(launchType=FARGATE, desiredStatus=RUNNING)` → `describe_tasks`, re-guarded for
  capacity-provider tasks), resolve each container image (reusing `parse_ecr_image_ref` /
  `ecr_image_node_ids`, `:tag`→digest via `describe_images`), the **task role** (`taskRoleArn`,
  not `executionRoleArn`), and the awsvpc **ENI / private IP**. The running task — not the
  task-definition — is the exposure + identity anchor a serverless-container attack path needs.
- New node kind **`ECSFargateTask`** with three edges the reachability engine already
  understands: `RUNS_IMAGE → ECRImage` (image CVEs), `HAS_ROLE → taskRoleArn` (→ the role's
  existing `CAN_PRIVESC_TO` / `CAN_READ_DATA` edges), and `LB -TARGETS→ task` /
  `eni -ATTACHED_TO→ task` (internet exposure). Resulting native path:
  `internet → LB → FargateTask → taskRole → admin`/`crown`, CVE-gated exactly like EC2.
- **Zero `aws_correlate.py` change** — the `runs_image_src` DFS ex-gate is kind-agnostic, so a
  Fargate task inherits image-CVE exploitability via `RUNS_IMAGE` for free (no `_EXPLOIT_KINDS`
  edit). Clobber-safe: a **separate** `_fargate_payloads` stash (ECS#20) replayed in
  `_replay_fargate_edges` (VULN#40) survives the IAMPRIVESC graph rebuild; the existing
  `ECSTaskDefinition` replay stays byte-identical.

### Added — exposure + attack paths
- The verified false-negative fixed: `ip_to_instance` only held ENIs with an `InstanceId`, so an
  ALB **IP target** pointing at a Fargate awsvpc ENI (no `InstanceId`) resolved to nothing. A
  parallel `(VpcId, ip)`-keyed `ip_to_fargate`, built region-locally from the already-fetched ENI
  list, now binds it — collision-safe (EC2 consulted first).
- **FARGATE-01** (LOW · inventory), **FARGATE-02** (HIGH · `assignPublicIp=ENABLED` direct
  internet exposure), plus **ATTACK-01 / ATTACK-02** reused for the Fargate path + flagship
  (`_correlate_flagship` gained a Fargate branch), and the reachable-service boost on the task's
  ECRImage nodes.

### Added — EKS-Fargate boundary
- **EKS-07** (INFO): enumerate EKS-Fargate profiles (`list_fargate_profiles` /
  `describe_fargate_profile`) — namespaces + pod-execution role — with an explicit documented
  boundary that running pod images / IPs / IRSA app-role bindings require the Kubernetes API and
  are deferred to the KSPM item (no inert graph node).

### Read-only on scanned targets
- All new calls are `describe`/`list` only, each in its own try/except → INFO/WARN no-op on a
  denied API. `VERSION` → 2.21.0.

## [2.20.0] — 2026

**OverWatch — external vulnerability ingest, ranked by reachability not CVSS (Phase-2 capstone).**
Upload any SCA scanner's output and OverWatch owns its CVEs against your AWS estate and ranks
them by *actual* attack-path exploitability.

### Added — `aws_ingest.py` (pure, offline, boto3-free)
- **Parsers** for **SARIF 2.1.0** (per-tool adapters — Trivy `ruleId==CVE`, Grype
  `{vulnID}-{artifactName}` suffix-strip, Snyk `SNYK-…` + regex CVE out of `fullDescription`;
  CodeQL SAST excluded), **CycloneDX 1.5/1.6** (`vulnerabilities[]` findings lane incl. VEX
  `analysis.state` + ratings-authority selection; components-only → inventory lane), and
  **SPDX 2.3 / Syft** SBOMs (inventory lane). `parse_purl` is the exact inverse of
  `aws_sidescan._purl` / `_lang_purl` / `_ECO` / `_pep503`, so an ingested package keys
  byte-identically against the same OSV feed a native side-scan uses.
- **Two lanes, one convergence** on `aws_sidescan.EnrichedMatch`: the *findings* lane enriches
  a doc-named CVE via `enrich_match` (native-parity severity/CVSS on a feed HIT, doc band on a
  MISS); the *inventory* lane runs purls through `match_vulns` (OverWatch's own matcher decides
  the CVEs). Either way KEV/EPSS/exploit come **only** from the shared vuln bundle — never
  inferred from the doc.
- **Own + dedup + VEX**: `resolve_owner` binds a doc to the graph node it belongs to (explicit
  ARN → image digest → repo:tag → synthetic *unmapped* fallback; cross-account ARN → 400);
  `build_cve_index`; `vex_suppressed` (suppress-but-track).
- **Reachability re-run**: ingested CVEs become `HAS_VULN` edges (`scan_source="ingest:<tool>"`)
  and `compute_reachability_verdicts` **re-runs** `aws_correlate.enumerate_paths` with the exact
  native `_check_correlate` predicates — a membership check on stored paths would miss the path a
  new KEV reveals. An ingested KEV-on-data-path earns the identical `hard_floor_kev_data=90`
  CRITICAL; an isolated/unreachable CVE collapses to an exploitability-only band. `diff_reachability`
  yields the newly-reachable delta for the drift digest.

### Added — `SecurityGraph.from_dict` (`aws_graph.py`)
- Loss-safe inverse of `to_dict` (reserved keys popped; MERGE-idempotent), so the hosted plane
  rebuilds a graph from stored `graph_full` before the re-run. `aws_graph_neptune.load_graph`
  now delegates to it.

### Added — persistence, service, API, console
- `aws_state` **v5**: `ingest_docs` + `ingested_vulns` twin DDL (sqlite + `aws_state_dialect`
  Postgres), `IF NOT EXISTS` migration (no ALTER), one owned row per `(account, node_id, cve)`
  with a `sources` set-union, verdict columns written separately so a re-upsert never clobbers a
  fresh reachability verdict.
- `PlatformService.ingest_document` / `list_vulns` / `get_vuln` / `refresh_vuln_reachability`
  / `org_vulns`; injected `vuln_bundle` (fail-open). Routes (RBAC): `POST /accounts/{id}/ingest`
  (admin), `GET /accounts/{id}/vulns`, `GET /accounts/{id}/vulns/{cve}`,
  `GET /accounts/{id}/ingest/docs`, `POST /accounts/{id}/vulns/refresh` (admin), `GET /org/vulns`.
- Reachable survivors surface as two check-level aggregates (`VULN-ING-KEV` / `VULN-ING`) routed
  through the existing `VULN-*` + on-attack-path connector rules; a newly-reachable KEV rides the
  drift-digest `newly_on_path` signal (`build_drift_digest` gained `extra_newly_on_path`; the
  worker refreshes reachability against the fresh graph and feeds the delta).
- Console **Vulnerabilities** screen (reachability chip as the visual anchor, KEV / on-path /
  source facets, SARIF/CycloneDX/SPDX upload) + an Overview reachable-CVE roll-up.

### Read-only on scanned targets
- The ingest path makes **zero** AWS API calls — it works purely off the uploaded document and
  the account's stored graph.

## [2.19.0] — 2026

**Detailed finding reports baked into the scanner.** Every scan now emits, for every
actionable check, a full write-up — the **risk**, the **business impact**, and
**step-by-step remediation** with real AWS CLI — not just a one-line command.

### Added — `aws_finding_detail.py` (pure, offline data module)
- `FINDING_DETAIL = {check_id: {risk, impact, steps[...]}}` for **all 204 actionable
  (FAIL-able) check IDs** — 100% coverage of `REMEDIATION_MAP`. Compliance references
  are **not** duplicated; they come from `COMPLIANCE_MAP`. `get_detail()` / `steps_for()`
  helpers. A check with no entry falls back to its one-line `REMEDIATION_MAP` CLI, so
  rendering never breaks as coverage grows.

### Changed — reports
- `save_json` adds a deduped, severity-ranked **`finding_catalog`** (per distinct
  FAIL/WARN check: risk / impact / steps / compliance / one-line CLI / affected
  resources / finding count / distinct-resource count), built by `_build_finding_catalog()`.
- `save_html` rewritten to a **light theme** (blue/white) with three sections: ranked
  **attack paths** → per-finding **detail cards** (risk → business impact → numbered
  remediation steps → frameworks) → the full findings table.

### Hardening (from a read-only adversarial verification — 5 confirmed, all fixed)
- **LMB-06**: `aws lambda update-function-code-signing-config` is not a real operation
  → `put-function-code-signing-config` (the enforce-mode signing config was never bound).
- **OSR-02**: `--encrypt-at-rest-options` is an invalid flag →
  `--encryption-at-rest-options` (encryption-at-rest was never enabled).
- **SM-01 / SM-04**: delete-and-recreate a SageMaker notebook (which destroys its
  persistent ML volume) with no back-up-first step → prepend a back-up/migrate step.
- **`+N more`** card meta counted total findings, not distinct affected resources
  → added an uncapped `distinct` count; the card now counts resources.
- Regression tests back all five (invalid-CLI-token denylist, notebook-delete-backs-up-first
  guard, distinct-vs-finding-count). **Full suite: 1128 passed.**

## [2.10.0] — 2026

**CNAPP Phase 9 — Live PostgresBackend.** The state plane (Phase-5 finding
lifecycle/drift/waivers/MTTR **and** the Phase-8 onboarding registry) now runs on a
real Postgres when opened with a `postgresql://` URL — the deferred "shared team
store" for the hosted hub. The SQL translation layer already existed (Phase-6
dialect); Phase 9 adds the missing connection/execution layer.

### Added — `cnapp_backend.py` (the Backend abstraction)
- One `Backend` that owns the connection, a reentrant lock, the dialect, and a
  transaction-depth counter. `StateStore` + `AccountRegistry` route **every**
  read/write through it (`execute` / `query_one` / `query_all` / `scalar` /
  `upsert` / `upsert_many` / `insert_returning_id` / `transaction` / `migrate`).
- **`SqliteBackend`** — a transparent identity wrapper (same PRAGMAs / `sqlite3.Row`
  / `BEGIN IMMEDIATE` / `PRAGMA user_version`). The sqlite path is **byte-identical**;
  the full suite is the regression gate.
- **`PostgresBackend`** — real **psycopg3** (+ `psycopg_pool` available): `?`→`%s`,
  `hybrid_row_factory` rows (positional **and** by-name **and** `dict`), `ON CONFLICT`
  upserts, `RETURNING` ids, a `schema_migrations` table. **`autocommit=True`** so a
  read never leaks "idle in transaction" and a failed statement never poisons the
  shared connection; atomic multi-statement blocks use psycopg's own
  `conn.transaction()`. A missing driver OR unreachable server →
  `StateBackendUnavailable`, **never** a silent sqlite fallback.

### Changed
- `aws_state.StateStore` + `cnapp_registry.AccountRegistry` no longer touch a raw
  `sqlite3.Connection`; `classify_and_diff`'s `BEGIN IMMEDIATE` block is now
  `with self._be.transaction()`. `SCHEMA_VERSION` / behavior unchanged.
- `Backend.upsert` uses `ON CONFLICT DO UPDATE` on **both** engines (the form that
  preserves omitted columns for re-onboard); `scans` stays behaviorally identical
  (update-all + reset-counters ≡ `INSERT OR REPLACE`).

### Hardening (from a read-only adversarial review — 6 confirmed, all fixed)
- `autocommit=True` + `conn.transaction()` (fixes the idle-in-transaction leak and
  the aborted-connection poison a single failed statement would cause on a shared
  psycopg connection); the SQLite ≥ 3.24 (`ON CONFLICT`) guard centralized in
  `backend_for` so `StateStore` fails pre-flight instead of mid-scan; `SqliteBackend`
  sets `row_factory` when wrapping a raw connection (the legacy `StateStore(conn)`
  contract). The sqlite-drift finder found **no** behavioral regression.

### Testing
- **571 tests** (+20 offline PG-path via an injected fake psycopg3 connection —
  conversion / `ON CONFLICT` upsert / migrate / `RETURNING` / transaction commit &
  rollback / `autocommit` / `StateBackendUnavailable` + a `scans` drift-reset
  self-check). No live server needed; the sqlite path stays byte-identical.

### Still deferred
- A `psycopg_pool.ConnectionPool` (a pure scalability optimization over the single
  serialized connection); the React UI.

---

## [2.9.0] — 2026

**CNAPP Phase 8 — Hosted multi-account platform (onboarding backend).** Turns the
CLI scanner into a **self-hosted web platform**: an EC2 hub in a dedicated security
account onboards many AWS accounts through a **read-only CloudFormation cross-account
role** (single-account stack or org-wide **service-managed StackSet** with
auto-enroll), validates each connection, and scans them on a schedule. The scan
engine is UNCHANGED — every new capability is a thin, dependency-injected, offline-
testable layer over the existing `assume_role_session` / `list_org_accounts` /
`aggregate_results` and the Phase-6 dual-dialect store. No access keys; agentless.

### Added — onboarding & validation (pure)
- **`cnapp_onboarding.py`** — mints a server-side **ExternalId** (confused-deputy
  guard), stores only a `secretsmanager://` / `ssm://` **reference** (never the
  plaintext), and builds the CloudFormation quick-create **Launch-Stack URL** + CLI.
  Idempotent re-onboard **reuses** the ExternalId rather than rotating it.
- **`cnapp_validate.py`** — pure `validate_connection`: `sts:AssumeRole` →
  `GetCallerIdentity` with a **hard account-match stop** (fail-closed on an empty or
  mismatched account) → SecurityAudit read canary → `organizations:ListAccounts`.
  4-state health (validating / healthy / degraded / unauthorized) + a failure
  taxonomy + exponential re-validation backoff. No boto3.

### Added — registry & orchestration
- **`cnapp_registry.py`** — `AccountRegistry` over the same state store (new
  `accounts`, `scan_jobs`, `connection_health` tables). Partial-update upsert that
  **preserves lifecycle + untouched config** on re-onboard; a `threading.Lock`
  serializes the shared connection so every multi-statement write (and the
  failure-count read-modify-write) is atomic.
- **`cnapp_service.py`** — `PlatformService` facade (all injected deps → unit-
  testable with fakes) + `serialize_scanner` (byte-lockstep with `save_json` plus
  `graph_full`) + `org_overview` rollup.
- **`cnapp_worker.py`** — async job drain that **traps the engine's `sys.exit(2)`**,
  pre-validates creds (wrong account → denied) fail-closed, and re-checks the
  account is still active before scanning (closes the enqueue→execute window).
- **`cnapp_api.py`** — thin FastAPI routers + viewer/admin **RBAC that fails closed**
  by default (a forgotten auth hook denies, never grants admin). Guarded import — the
  backend is fully usable/testable without FastAPI installed.

### Added — deployment artifacts (`deploy/`)
- `cnapp-scanner-role.yaml` (single-account), `cnapp-stackset.md` (org
  service-managed StackSet + auto-deploy), `cnapp-hub-role.yaml`. Read-only:
  **SecurityAudit + ViewOnlyAccess** only (never `ReadOnlyAccess`, which reads
  workload data); EBS side-scan snapshot writes are an opt-in second policy.

### Schema
- `aws_state` + `aws_state_dialect` gain the 3 onboarding tables (both dialects,
  `SCHEMA_VERSION` 1→2). Migration replays `IF NOT EXISTS` — non-destructive on a
  live v1 DB. `build_upsert` now renders `DO NOTHING` for an empty update set.

### Hardening (from a 19-agent read-only adversarial review — 12 confirmed, all fixed)
- Fail-closed account assertion on empty `GetCallerIdentity`; idempotent re-onboard
  (no silent ExternalId rotation); connection atomicity via a lock; ExternalId never
  echoed in an error message / persisted job error; fail-closed RBAC default;
  fail-closed pre-validate; enqueue→execute TOCTOU re-check; `KeyboardInterrupt` no
  longer swallowed; sort-order fallback preserves `DESC`; `next_revalidation` aligned
  to the persisted schedule; `last_scan_at` only on success; malformed input → 4xx.

### Testing
- **551 tests** (+68 offline: registry / validate / onboarding / service / worker /
  API / CFN + 15 regression tests for the adversarial findings). All boto3 / psycopg
  / FastAPI mocked; the whole backend runs offline.

### Still deferred
- Live PostgresBackend rewire (the registry already speaks both dialects — it is a
  wiring + live-server task); the React UI (prototype shipped as a design artifact).

---

## [2.8.0] — 2026

**CNAPP Phase 7 — Remediation + Code-to-Cloud ("close the loop").** Turns the
ranked attack-path analysis into ACTION: a prioritized remediation plan that fixes
the choke points which sever the most attack paths first, with remediation-as-code,
mapped back to the IaC resource that created each finding. Read-only — it generates
artifacts (runbook / plan / PR body), never applies changes. Plus productionized
versions of the live paths Phase 6 deferred. Five new modules; `aws_correlate.py`/
`aws_graph.py` unchanged.

### Added — remediation engine (`aws_remediate.py`, pure)
- A **prioritized, deduplicated plan** that **reuses `aws_correlate.minimal_cut` +
  `ChokePoint`** (never re-ranks): "fix K items to cut N% of critical attack
  paths," each action naming the node to fix, the paths it severs, the crown
  jewels it protects, and effort/blast-radius.
- **Remediation-as-code** — a template registry emitting Terraform + CloudFormation
  + AWS CLI per fix (scope an open SG, cap a role with a permission boundary, block
  public S3, patch a KEV CVE, …). A missing param renders as a `<PLACEHOLDER>`,
  never a crash.
- **Exports** — markdown runbook, JSON plan, GitHub issue checklist, PR body.
  Deterministic. Read-only — never opens a PR or applies a change.

### Added — code-to-cloud (`aws_codetocloud.py`, pure)
- Maps a live finding back to the **IaC resource that declared it** (a new
  brace-balanced Terraform block extractor + structural CloudFormation parse) via a
  tiered **T1–T5 confidence matcher** (exact physical name / distinctive tag / CFN
  logical-id / naming heuristic / type-only). Never guesses — an ambiguous match
  returns `None`, so remediation can propose the **IaC diff** at `file:line`.

### Added — productionized live paths (mock-tested; real infra still deferred)
- `aws_graph_neptune_loader.py` — S3-key layout + bulk-load request builder +
  `run_gremlin_bulk_load`/`run_opencypher_upsert` over injected s3/neptunedata.
- `aws_sidescan_ebs.run_snapshot_sidescan` — the live snapshot lifecycle
  (snapshot → copy/re-encrypt → fetch blocks → reassemble → extract) with
  **guaranteed provenance-guarded cleanup on every error path**; a truncated read
  is flagged INCOMPLETE (never a false clean bill).
- `aws_sidescan.detect_fs` — a magic-byte sniffer (ext/xfs/luks/gpt) so an
  encrypted/unsupported volume yields an honest INFO instead of a false-clean.

### Added — integration + CLI
- `--remediate` (+ `--remediate-out`/`--remediate-format`/`--remediate-min-severity`),
  `--iac-dir` (enables code-to-cloud), `--graph-neptune-load`
  (+ `--neptune-s3-bucket`/`--neptune-iam-role`/`--neptune-region`). `save_json`
  gains gated `remediation`/`code_to_cloud` blocks. Default path (no flags) is
  byte-for-byte unchanged.

### Fixed — pre-merge adversarial verification (read-only hunt → 7 defects)
All in the opt-in `--iac-dir`/`--remediate`/`--neptune-load` features; the default
path and the live-runner cleanup safety verified clean.
- **(HIGH ×4, code-to-cloud false match — the most dangerous class)** an empty/
  unknown resource type no longer matches across ALL IaC resources; the T2 tag
  tier requires a *distinctive* (non-denylisted, globally-unique) tag; the
  Terraform brace balancer is now string/comment/heredoc-aware (a `{` inside a
  string no longer bleeds a block into the next resource); and the tags extractor
  no longer truncates on a `${…}` interpolation. Together these stop remediation
  from proposing edits to the *wrong* IaC resource.
- **(HIGH)** `patch_cve` is only chosen when a vulnerability actually gates the
  severed path — an exposed instance with no CVE gets a privilege fix, not a
  nonsensical "patch `<CVE>`".
- **(MEDIUM)** the Neptune loader uses a fail-closed non-terminal allowlist so an
  unusual/failed status breaks the poll loop instead of hanging to timeout.
- **(LOW)** `_safe_format` uses `safe_substitute` so a `${…}`/bare `$` in a
  template passes through literally instead of raising.

### Changed
- Version → **2.8.0**.

### Scope — deferred (each fails closed to prior behavior)
- Live `PostgresBackend` StateStore rewiring (regression risk to the Phase-5
  lifecycle + not CI-verifiable without a server; the pure DDL/upsert generators
  shipped in Phase 6 and `postgresql://` already degrades to stateless).
- rpm Berkeley-DB/NDB decode and real ext4/xfs parsing (dissect) — orchestration
  ships mock-tested; the real binary/kernel parse is integration-only.
- Any live cloud/repo mutation (`--remediate` generates only; there is no apply).

### Testing
- **57 new tests** (`test_remediate.py`, `test_codetocloud.py`,
  `test_neptune_loader.py`, `test_phase7_integration.py`, + side-scan runner/
  detect_fs) → **483 total**, all green. A regression test backs every
  adversarial-verify defect. boto3/psycopg/gremlin/dissect remain uninstalled.

## [2.7.0] — 2026

**CNAPP Phase 6 — Agentless EBS Side-Scanning (CWPP) + Postgres/Neptune backends.**
Adds the Wiz/Orca-defining capability: scan a workload's disk for OS-package
vulnerabilities and on-disk secrets **with no agent**, feeding the findings into
the SAME security graph as `HAS_VULN` edges so agentless CVEs light up the
ATTACK-02 attack-path correlation **even when Amazon Inspector is disabled**. Plus
persistence-backend generators (Postgres state store, Neptune graph export). Five
new pure, dependency-free modules; `aws_correlate.py`/`aws_graph.py` unchanged.

### Added — agentless workload side-scan (`aws_sidescan.py`, pure/stdlib)
- OS-package **inventory parsers**: `/etc/os-release`, Debian/Ubuntu dpkg status,
  Alpine apk, RHEL/Rocky/Alma/Amazon rpm (modern sqlite rpmdb via a pure
  struct-unpack header decoder + a textual manifest fallback).
- The **three ecosystem-correct version comparators** — `dpkg_vercmp` /
  `rpm_vercmp` / `apk_vercmp` (semver is wrong for all three; this is where a
  missed-CVE false negative would hide) — with epoch/tilde/caret/suffix semantics.
- An **OSV matcher** against distro-advisory feeds (the key false-positive guard —
  a distro backport is not an upstream version), with EPSS/KEV/exploit enrichment
  producing `HAS_VULN` edge props identical to the Inspector plane.
- **On-disk secret detection** (known paths + entropy-gated content regexes,
  example-key denylist, first4…last4 preview only — never exfil the secret).
- The raw ext4/xfs/ntfs parse is deferred behind an injected `FilesystemExtractor`
  seam, so the whole core is unit-tested with an in-memory `DictExtractor`.

### Added — EBS block plane (`aws_sidescan_ebs.py`, pure/stdlib)
- EBS Direct API **fetch planning** (full + incremental delta with removed-block
  zeroing), base64-SHA-256 block **checksum verification**, **sparse reassembly**,
  token **rebind-on-expiry**, and **provenance-guarded cleanup** (`is_owned`
  ensures a resource we did not tag is never deleted). Live snapshot I/O + the real
  filesystem extractors are deferred to Phase 7 behind `HAS_BOTO3`.

### Added — persistence backends (pure generators; live drivers deferred)
- `aws_state_dialect.py` — Postgres DDL/upsert/dialect translation of the
  finding-lifecycle schema (BIGINT epochs, `GENERATED BY DEFAULT AS IDENTITY`,
  `ON CONFLICT` upserts with the drift-counter reset), `?`→`%s` conversion, a
  hybrid `sqlite3.Row` shim, `parse_state_url`, and a migration skeleton.
  `aws_state.open` now routes a `postgresql://` URL to a clean
  `StateBackendUnavailable` → stateless (never a silent local sqlite).
- `aws_graph_neptune.py` — Amazon Neptune **Gremlin bulk-load CSV** (bool-before-int
  typing, per-label homogeneous columns, RFC-4180 escaping, list scalarization) +
  idempotent **openCypher UNWIND/MERGE** upserts, deterministic ordering, and a
  round-trip loader. `aws_graph`/`aws_correlate` untouched.

### Added — integration + CLI (thin, gated, additive)
- A `SIDESCAN` section (runs after `EXPOSURE`, before `VULN`) targeting the
  internet-exposed EC2 set; **CWPP-01** (agentless CVE), **CWPP-02** (KEV/exploited
  CVE, CRITICAL), **CWPP-03** (secret on disk), **CWPP-04** (INFO/degradation) with
  severity/compliance/remediation maps. Emitted `HAS_VULN` edges MERGE-converge
  with Inspector on the same (instance, cve).
- CLI: `--side-scan` (`--side-scan-targets exposed|all|tagged`, `--side-scan-tag`,
  `--side-scan-max`, `--no-side-scan-secrets`), `--vuln-db FILE`, `--backend URL`
  (sqlite/postgresql), `--graph-neptune-csv DIR`, `--graph-neptune-cypher FILE`.
  `save_json` gains `side_scan`/`backend`/`graph_export` blocks, present only when
  their feature ran.

### Fixed — pre-merge adversarial verification (read-only agent hunt → 3 defects)
- **(HIGH, missed-CVE false negative)** the dpkg version comparator (`_deb_order`)
  ranked a digit above a letter instead of terminating the non-digit part
  (weight 0), inverting ordering at any aligned digit-vs-letter slot and silently
  judging a vulnerable Debian/Ubuntu package as not-affected. Fixed to match dpkg
  Policy 5.6.12; regression-tested with the `~snapshot`-before-`~rc` case.
- **(MEDIUM, JSON-contract regression)** a `--state`/`--list-waivers`-only run
  (no Phase-6 flags) leaked a new top-level `backend` key; `_backend_meta` is now
  gated on `--backend` actually being given.
- **(LOW, latent)** a capped delta fetch-plan left stale base bytes for changed
  blocks beyond the cap; they are now zeroed to a recognizable hole.

### Changed
- Version → **2.7.0**.

### Scope — deferred to Phase 7 (each fails closed to prior behavior)
- Live EBS snapshot I/O runner + real filesystem extractors (mount/loop/userspace);
  cross-account snapshot re-encryption. Live `PostgresBackend` (psycopg) + the
  StateStore refactor; live Neptune loader. rpm Berkeley-DB/NDB binary decode and
  language-ecosystem analyzers — surfaced as explicit INFO notes, never silent.

### Testing
- **121 new tests** (`test_sidescan.py`, `test_sidescan_ebs.py`,
  `test_graph_neptune.py`, `test_state_dialect.py`, `test_phase6_integration.py`)
  → **426 total**, all green. The ATTACK-02-from-agentless pillar and every
  adversarial-verify defect have dedicated regression tests. boto3/psycopg/gremlin
  remain uninstalled — the default path is byte-for-byte unchanged.

## [2.6.0] — 2026

**CNAPP Phase 5 — Effective-Permissions Depth + Persistent State, Drift & Waivers.**
Two capabilities that make the ranked attack paths *genuinely effective* and give
the scanner *memory*: (1) an IAM effective-permissions solver that evaluates the
real AWS decision chain (identity ∩ permission-boundary ∩ SCP, explicit-deny-wins)
so an escalation edge a boundary or SCP provably neutralizes is **dropped** from
the graph — tightening ATTACK-01/02 and the ranked paths; and (2) a stdlib-SQLite
state store tracking finding lifecycle, drift, MTTR, posture trend, and waivers.
Three new pure, dependency-free modules; `aws_correlate.py`/`aws_graph.py` unchanged.

### Added — effective-permissions solver (`aws_effperm.py`, pure)
- **`pivot_effective(action, identity, boundary, scp_levels)` → KEEP | CONDITIONED | DROP**
  modeling the AWS single-account chain: explicit unconditional Deny → DROP;
  permission boundary as a ceiling (intersection) — action not allowed there → DROP;
  SCP path root→OU→account (AND across levels, OR within a level) — any level that
  does not allow → DROP.
- **Explicit-deny-wins at every scope**, and a three-state model: only a *provable
  unconditional* denial prunes — a Condition-gated allow/deny downgrades the edge to
  **CONDITIONED** (WARN), never a silent drop.
- **`NotAction` inverse matching** (Deny/Allow guardrails) via a new `not_actions`
  set on parsed statements.
- **Fail-open invariant** — `boundary=None` AND `scp_levels=None` can never DROP an
  identity-allowed pivot: the graph is byte-for-byte identical to before.

### Added — boundary/SCP collection + graph edge refinement (`aws_live_scanner.py`)
- Permission boundaries resolved per-principal from `GetAccountAuthorizationDetails`
  (`PermissionsBoundary.PermissionsBoundaryArn` → cached managed-policy doc); an
  unresolvable/empty boundary → `None` (fail open), **never** an empty deny-all list.
- **`_get_scp_context()`** — read-only Organizations walk (account → OU → root) that
  degrades to `None` for the management account, a non-`ALL`-features org, an org not
  in use, any API/permission error, or any node whose SCPs are unreadable (an
  unreadable ceiling must never be mistaken for deny-all).
- `CAN_PRIVESC_TO` edges are ceiling-refined (neutralized → dropped, Condition-gated
  → downgraded) and `CAN_ASSUME` edges gated by the *source* principal's effective
  `sts:AssumeRole` (external/wildcard/service sources kept unchanged — fail open).
- `save_json` gains an always-present **`effective_permissions`** audit block
  (`boundary_evaluated`, `scp_evaluated`, `pruned_edges`, `downgraded_edges`).

### Added — persistent state, drift, MTTR & waivers (`aws_state.py`, pure sqlite3)
- **Finding lifecycle** (`open` → `resolved` → `reopened`) keyed by a stable
  `finding_key`; **NEW** is a read-time projection and **MUTATED** flags config
  drift (severity bump / message change) on an existing finding rather than
  resolve-and-recreate.
- **Coverage-gated resolve** — a partial (`--sections` / single-region) scan can
  never mass-resolve findings from checks it did not run; region-independent
  (IAM/S3/…) findings are stored under a stable `global` region so they resolve
  regardless of which region the scan carried.
- **MTTR** (episode-based, reopen-aware) + mean/median, by-severity, and
  open-past-SLA; **posture trend** with per-scan deltas.
- **Waivers** — approver + reason + expiry; suppression is a *live overlay* (the
  finding stays open/tracked), so an expired waiver auto-reactivates on the next
  scan with zero DB mutation. Suppressed findings are excluded from `--fail-on`
  gating (still counted in the posture score and never hidden).

### Added — CIEM unused-access / right-sizing (`aws_unused.py`, opt-in `--ciem`)
- IAM Access Analyzer *unused-access* (when enabled) → Service-Last-Accessed
  fallback (always) → dormancy classification; **never** reads analyzer-absent or a
  stuck SLAD job as "all used".
- A LOW **`CIEM-01`** right-sizing finding ("review candidate, not auto-delete") and
  a bounded, non-mutating exploit-likelihood **down-rank overlay** for attack paths
  through a dormant principal (impact untouched; floor `0.5`; unknown → no change).

### Added — CLI
- `--state FILE` (lifecycle/drift/MTTR/trend; supersedes the ephemeral `--baseline`
  when given), `--suppress KEY` (+ `--approver`, `--reason`, `--expires`),
  `--list-waivers`, `--sla-days N`, `--ciem`. Multi-account (`--org`) applies the
  state store **per underlying account**, never to the aggregate.

### Changed
- `evaluate_privesc_scoped(statements, boundary=None, scp_levels=None, pruned=None)`
  — new optional params; all existing single-arg callers are byte-for-byte identical.
- `_policy_to_statements` now emits a `not_actions` set; `Allow`+`NotAction` still
  over-approximates `actions={'*'}` for backward compatibility.
- Version → **2.6.0**.

### Fixed — pre-commit adversarial verification (18-agent hunt → 9 defects, all fixed + regression-tested)
- **(CRITICAL, over-prune)** SCP org-walk no longer appends an *unreadable* level as
  an empty deny-all that would mass-drop every escalation edge account-wide; an
  unreadable node fails the whole SCP layer open.
- **(CRITICAL, over-prune)** A full-admin identity whose `*` megapivot is capped by a
  boundary/SCP/`Deny NotAction` no longer returns *no* privesc — it now enumerates
  the granular IAM pivots that survive the ceiling.
- Permission boundary with only a Condition-gated Deny and no Allow now DROPs
  (implicit-deny of the ceiling) instead of keeping a conditioned edge.
- Region-independent (global-service) findings resolve across differing `--region`
  labels; regional findings stay region-gated (no cross-region mass-resolve).
- A stuck SLAD job (never completes) is classified UNKNOWN, not dormant.
- EKS-02 missing-log-types message is sorted (stable state fingerprint → no spurious
  `MUTATED` drift on unchanged clusters).
- Malformed `--expires` is rejected (exit 2) instead of silently becoming a permanent
  waiver; the waiver-suppression console message no longer overclaims posture exclusion.

### Testing
- **92 new tests** (`test_effperm.py` 32, `test_state.py` 22, `test_unused.py` 21,
  `test_phase5_integration.py` 17) → **294 total**, all green. Every adversarial-verify
  defect has a dedicated regression test.

## [2.5.0] — 2026

**CNAPP Phase 4 — Attack-Path Correlation & Prioritization ("ship the product").**
Reads the security graph Phases 1-3 built and collapses it into the ranked handful
of scored, explainable attack paths that matter, then computes **choke points** —
"remediate this one node and sever N attack paths to M crown jewels." New
`aws_correlate.py` module (zero dependencies) is a pure, fully unit-tested engine.

### Added — the correlation engine (`aws_correlate.py`)
- **Score the PATH, not the finding** — the unit of ranking is an end-to-end
  entry→target chain, which is what collapses thousands of flat findings into a few.
- **Gated-multiplicative scoring** — a toxic combination is a CONJUNCTION, so the
  score multiplies across dimensions (exposure × exploitability[KEV/EPSS/exploit] ×
  privilege-blast-radius × data-sensitivity) with a conditioned/compensating-control
  penalty and a bounded GuardDuty-threat amplifier. Any missing factor collapses the
  path — this kills the classic "high-CVSS but unexposed, no data path" false
  positive a weighted sum would surface as critical.
- **MAX-per-jewel aggregation** (never SUM) — the environment number is max-per-crown-jewel
  then summed across distinct jewels; prevents score inflation from shared hops.
- **Fully explainable** — every 0-100 score decomposes into its hop factors and the
  driving findings (`rationale` + `driving_findings` on each path).
- **Bounded, deterministic enumeration** — simple-path DFS with hop cap, per-pair
  cap, and an enumeration budget to prevent combinatorial blowup on dense IAM cliques.
- **Choke points** — severity-weighted path-frequency with an `is_true_choke`
  dominator flag (every path to a target passes through the node); `minimal_cut`
  greedy set-cover for the "fix these few nodes" follow-up. Entry/target node kinds
  are structurally excluded (never picks the internet/crown/admin node as the choke).

### Added — CORRELATE section (40th, runs last, once) + findings
- **`CHOKEPOINT-01`** (HIGH) — "fixing {node} severs N/M attack path(s) … removes
  EVERY known path to K crown jewels/admin." Emitted for the top choke points that
  sever a CRITICAL/HIGH path. HIGH (not CRITICAL) so it doesn't double-weight the
  toxic combo already scored CRITICAL by ATTACK-01/02.
- **`PATHS-01`** (INFO) — ranked-path rollup.
- Ranked `attack_paths` + `choke_points` blocks added to the JSON report.
- **ATTACK-01/ATTACK-02 emission is unchanged** — the engine is a read-only
  post-processor that only adds the new ids and re-expresses the same condition-aware
  and exploitable-pivot semantics for ranking (zero edits to the Phase 2/3 tests).

### Testing
- 180 → **202** unit tests (new `tests/test_correlate.py`: enumeration + ATTACK-02
  gate + direct-public-crown + conditioned floor/cap + KEV hard floor + additive-combiner
  regression + choke-point diamond/exclude + minimal_cut + empty-graph no-op +
  determinism + the CORRELATE section integration; all pure, no AWS/boto3).
- Grounded in a verified methodology research pass; hardened by an adversarial sweep.

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
