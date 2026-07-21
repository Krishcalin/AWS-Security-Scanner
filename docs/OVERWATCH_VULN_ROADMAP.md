# OverWatch — Vulnerability & Misconfiguration Coverage Roadmap

_Implementation plan of action for deepening vulnerability-detection + security-misconfiguration
detection across every AWS service OverWatch covers. Produced from a read-only 7-agent code audit
(line-cited) benchmarked against **CIS AWS Foundations Benchmark v3.0**, **AWS Foundational Security
Best Practices (FSBP)**, and open CNAPP catalogs (**Prowler / ScoutSuite / Trivy**). Baseline: v2.10.0,
~197 check IDs across 41 `_check_*` sections._

> Interactive version: OverWatch Coverage Roadmap artifact.

---

## Executive assessment

OverWatch is an architecturally sophisticated agentless AWS CNAPP with **genuinely best-in-class IAM
privilege-escalation analysis** (IAMPE-01..22 over GAAD-derived effective permissions with
boundary/SCP ceilings and transitive assume→privesc chains) and an **Inspector-shaped CWPP core**
(OSV range matching, ecosystem-correct dpkg/rpm/apk comparators, EPSS/KEV/exploit/fix enrichment
feeding reachability-gated attack paths). Misconfiguration/CSPM coverage is competent-to-strong.

The gap is on the **vulnerability axis** — three structural holes and one operational one that define
the roadmap:

1. **Container image-layer CVEs surface only when Inspector2 is enabled account-wide** (VULN-03) — no
   ECR-native-scan ingest, no agentless layer scan.
2. **Lambda dependency scanning is explicitly deferred** (`aws_live_scanner.py:4686` — `continue  # defer Lambda plane`).
3. **The side-scan inventories OS packages only** (no language/SBOM deps → Log4Shell-class app CVEs are
   invisible) **and is Linux-only** (Windows hosts get zero coverage).
4. **⚠ The entire CWPP is operationally DARK in production** — live EBS filesystem extraction always
   raises `SideScanUnavailable` (`aws_sidescan_ebs.py:550-555`), so CWPP-01/02/03 run only against a
   test `DictExtractor`. The Wiz/Orca-defining capability ships in code but never fires against real
   AWS. **Un-stubbing it is the single highest-leverage fix in the plan.**

On the misconfig axis, coverage is competent on encryption/public-exposure basics but shallow in depth,
with total blind spots at: AMIs, SSM patch state, launch-template/ASG scale-out drift, Aurora/DB-clusters
(`describe_db_clusters` absent), managed-engine EOL/CVE (`EngineVersion` never version-matched),
KMS key-policy exposure, Cognito Identity Pools, Route53 subdomain-takeover, and the entire CIS v3
section 4 CloudWatch monitoring layer.

## Current posture by CNAPP pillar

| Pillar | Rating | Read |
|--------|--------|------|
| **CSPM** (misconfig) | Strong | Strong on encryption + public-exposure basics; shallow depth (EC2 = 3 checks, S3 exposure by BPA only) + blind spots at AMI/SSM/launch-templates/CloudWatch. |
| **CIEM** (identity) | Best-in-class | IAMPE-01..22 privesc, condition-aware, boundary/SCP ceilings, transitive chains. Weak on federated OIDC/SAML trust, KMS/Secrets resource-policy, Cognito Identity Pools; credential-report `last_used` columns fetched but never read (CIS 1.7/1.12 free but unimplemented). |
| **CWPP** (workload vuln) | **Dark in prod** | Excellent engine, but Linux-only, OS-package-only, no image/Lambda scan — and operationally dark (live extraction stubbed); rpm Berkeley-DB undecodable (silent false-clean on EOL RHEL7/CentOS7/AL1). |
| **DSPM** (data sensitivity) | Thin | Macie crown-jewel classification exists but is S3-only; RDS/Redshift/DynamoDB/EFS have no data-sensitivity signal. |
| **CDR** (detect/respond) | Partial | GuardDuty + Inspector findings drive graph correlation, but sensor posture is thin and the CloudWatch metric-filter/alarm layer (CIS §4) is absent. |

## Highest-impact gaps (ranked)

| # | Gap | Kind | Sev |
|---|-----|------|-----|
| 1 | CWPP is test-only in prod — live EBS extraction raises `SideScanUnavailable` | vuln | Critical |
| 2 | No independent container image-layer CVE scan (ECR `describe_image_scan_findings` never ingested) | vuln | Critical |
| 3 | Lambda dependency (SCA) scanning absent (Inspector Lambda findings dropped at `:4686`) | vuln | Critical |
| 4 | No language-dependency / SBOM scanning anywhere (only dpkg/apk/rpm) | vuln | Critical |
| 5 | No RDS/Aurora/Redshift/OpenSearch/ElastiCache managed-engine EOL/CVE signal | vuln | Critical |
| 6 | Aurora / DB clusters never enumerated (`describe_db_clusters` absent) | both | Critical |
| 7 | No AMI security checks (public/shared AMI = full-disk-image leak) | both | Critical |
| 8 | KMS is rotation-only — no key-policy public/cross-account analysis | misconfig | Critical |
| 9 | Cognito Identity Pools (unauth AWS-credential issuance) entirely unscanned | vuln | Critical |
| 10 | Route53 dangling-record / subdomain-takeover absent | vuln | Critical |
| 11 | Entire CIS v3 §4 CloudWatch metric-filter + alarm layer missing | misconfig | Critical |
| 12 | Windows instances get zero agentless OS-vuln coverage | vuln | High |
| 13 | L7 reachability (ALB/NLB/CloudFront) deferred; REST v1 method-auth unchecked | both | High |
| 14 | Legacy rpm Berkeley-DB undecodable (silent false-clean on EOL RHEL family) | vuln | High |
| 15 | ECS escape primitives, Lambda Function-URL public, Backup Vault Lock, S3 policy/ACL eval | misconfig | High |

---

## The 8-phase plan

Sequenced by **risk-reduction-per-effort**: bank ~30 quick wins first, then the marquee critical
checks, then unlock the vuln engine **once** so container / Lambda / Windows scanners become thin
adapters onto the now-live pipeline. Every deliverable maps to a real check ID (in a named `_check_`
method or a CWPP/deep-plane/atomic hook), carries `COMPLIANCE_MAP` / `CHECK_SEVERITY` /
`REMEDIATION_MAP` entries, and projects graph edges that feed `aws_correlate` — agentless and
read-only throughout.

### Phase 1 — Quick-win sweep · **S**
Reuse data already in hand (zero/one new API each); ~30 checks that instantly widen CIS/FSBP coverage
and feed the graph, no new infrastructure.
- `EC2-07` user-data secret scan (`describe_instance_attribute userData` → reuse `aws_sidescan.scan_secrets`)
- `EC2-08` SSRF choke: public IP **and** `HttpTokens!='required'` → feed `(public-IP, IMDSv1, role)` into `aws_correlate` (zero new API)
- `EBS-05` cross-account snapshot sharing (`describe_snapshot_attribute createVolumePermission`)
- `AMI-01` public AMI (`describe_images Owners=self` + `describe_image_attribute launchPermission Group=='all'`) — seeds `_check_ami`
- `IAM-07/08` root recent-use (CIS 1.7) + unused-credential-45d (CIS 1.12) from the cached credential report `last_used` columns; `IAM-05` add `RequireLowercaseCharacters`; `SEC-04` never-accessed secrets
- `ACM-04/05` imported / `RenewalEligibility=INELIGIBLE` / wildcard / `FAILED`; `KMS-03` `KeyState` in {PendingDeletion, Disabled}
- **Un-drop Lambda** in `_check_vuln:4686` (add `AWS_LAMBDA_FUNCTION` + `CODE_VULNERABILITY` branch → `LambdaFunction` HAS_VULN via existing `parse_inspector_finding`); `LMB-06` Function-URL `AuthType=NONE`
- `CNT-02` ingest `ecr.describe_image_scan_findings` (free ECR basic scan) → `ECRImage` HAS_VULN even when Inspector2 off
- `ECS-06` host `networkMode/pidMode/ipcMode==host`; `CNT-03` `ecr.get_repository_policy` public/cross-account
- `APIGW-05` REST v1 method-authorization parity with `AGW2-02`
- `ELB-06` WAF-on-internet-facing-ALB; `ELB-07` desync mitigation; `VPC-04` empty default-SG; `VPC-01` broadening (`-1`, 0-65535, ~10 more ports); `S3-07` TLS-only; `S3-08` versioning+MFADelete
- `RDS-08` IAM DB auth, `RDS-10` cert expiry, `RDS-11` snapshot encryption; `OSR-06` AccessPolicies `Principal:*`
- Config completeness `LOG-03a/b`; GuardDuty protection plans `LOG-04a-f`; Security Hub `LOG-05a/b`; Bedrock `BDR-02` guardrail strength; `SFN-04`
- `CWPP-07` EOL-distro detection; fix `_cvss_base` to parse CVSS vector strings

### Phase 2 — Marquee critical misconfigs · **M** — ✅ SHIPPED (v2.12.0)
Highest-severity standalone blind spots that need a new method but no new infrastructure.
Delivered as 28 checks across 6 families (branch `overwatch-phase2-misconfigs`), scoped by a
6-agent research pass and hardened by an 11-defect read-only adversarial-verify pass.
- ✅ `KMS-02` (public, CRITICAL) + `KMS-04` (cross-account, HIGH) key-policy → PUBLIC_KMS / SHARED_KMS edges
- ✅ `_check_cognito_identity` `COG-05` (unauth AWS-credential issuance, HIGH) + `COG-06` (unauth role → admin, CRITICAL) → INTERNET→role CAN_ASSUME
- ✅ `R53-06` dangling-record / subdomain-takeover (S3-website + Beanstalk confirmed → CAN_TAKEOVER; CloudFront/ELB/API-GW → WARN)
- ✅ `_check_cloudwatch` `CW-01` gate + `CW-02..16` — CIS v3 §4 metric-filter + alarm layer (3-state, GLOBAL section)
- ✅ `SEC-05` Secrets resource-policy public/cross-account (CRITICAL) → SHARED_SECRET; `IAMPE-23` federated OIDC/SAML wildcard trust (CRITICAL) → FEDERATED_CAN_ASSUME
- ✅ CloudTrail depth `LOG-07` (SSE-KMS) / `LOG-08` (data events) / `LOG-09` (bucket public) / `LOG-10` (delivery health) — renumbered off the Phase-1 LOG-06 (GuardDuty plans)
- New shared classifier `classify_resource_policy_stmt` (operator-aware public/cross-account/org) reused by KMS/SEC/LOG-09; `parse_trust_policy` now carries the raw `condition`.

### Phase 3 — Vuln-engine unlock · **L** — 🟡 CORE SHIPPED (v2.13.0); live-I/O deferred
Turn the flagship side-scan from test-only to live; the shared foundation Phases 4 & 8 reuse verbatim.
- ✅ **Language-manifest → `CWPP-06` agentless app-dependency CVE** via the **unchanged** OSV matcher (the headline). 7 lockfile parsers (npm package-lock v1/v2/v3 + yarn v1/Berry, Pipfile.lock, poetry.lock, Cargo.lock, go.mod w/ replace-exclude, Gemfile.lock) + best-effort requirements.txt. 3 ecosystem-correct comparators (`semver_vercmp` npm/Go/crates, `pep440_vercmp` PyPI, `gem_vercmp` RubyGems) keyed by `cmp_for`. Two blocking matcher fixes: `_record_affects` now evaluates OSV **SEMVER** ranges (npm/Go were ~100% FN) and gates the EVR-strip fallback to rpm/dpkg. `collect_app_packages` walks the app tree; app deps scanned even on an OS-less scratch image.
- ✅ **CycloneDX 1.5 + SPDX 2.3 SBOM export** (`sbom_cyclonedx`/`sbom_spdx`, pure + deterministic).
- ⏸️ **DEFERRED — `parse_rpmdb_bdb`** (legacy RHEL7 Berkeley-DB walker): FP-risky binary format, needs a real captured fixture; still fails-open to an INFO note (never a false-clean).
- ⏸️ **DEFERRED — live `DissectExtractor` / `_LiveMountedSnapshots`** (userspace ext4/xfs over an EBS snapshot): needs the `dissect` library + a real snapshot, so it can't be offline-tested — kept out until it can be validated in a lab (matches the Phase-6/7 deferral of live filesystem I/O). The engine already runs against ANY `FilesystemExtractor`.
- Verified by a 3-agent scoping-research pass + a 10-defect (7-unique) read-only adversarial-verify pass (all fixed).

### Phase 4 — Container image + Lambda dependency scanning · **L** — ✅ SHIPPED (v2.14.0)
Agentless, Inspector-independent, reusing the Phase-3 extractor + SBOM pipeline verbatim.
- ✅ **`ImageLayerExtractor`** (`aws_sidescan.merge_layers`) — OCI/Docker gzip-tar layer overlay + whiteout (`.wh.`/`.wh..wh..opq`) → merged rootfs via the `FilesystemExtractor` Protocol → the whole Phase-3 pipeline → **`CWPP-05`** HAS_VULN on `ECRImage`. `aws_sidescan_image.fetch_ecr_layers` is the live bridge (batch_get_image → manifest-list linux/amd64 → get_download_url_for_layer via injected http_get, fail-closed).
- ✅ **`LambdaArtifactExtractor`** (`aws_sidescan_lambda`) — function zip → `/var/task`, layers → `/opt` → **`LMB-07`** vulnerable dependency; `fetch_lambda_artifact` live seam.
- ✅ **Installed-package-metadata recall** (`package.json`/`METADATA`/`.gemspec`) so images/Lambda with no lockfile still inventory — also lifts EBS recall.
- ✅ **`RUNS_IMAGE`** edges (ECS task-def images → `ECRImage`, dual-emit to both node-id conventions so image CVEs join attack paths) + ECR hygiene **`CNT-03`** (repo policy public/cross-account) / **`CNT-04`** (tag immutability) / **`CNT-05`** (lifecycle). EKS pod→image deferred (needs the k8s API).
- 3-agent scoping research + a 12-defect (1 blocker) read-only adversarial-verify (all fixed). The pure extractors subclass `DictExtractor`, so an image/Lambda scans byte-identically to the test double.

### Phase 5 — Managed-service vulnerability axis · **M** — ✅ SHIPPED (v2.15.0)
The "vulnerable managed service" signal + the invisible Aurora cluster shape. **16 checks**, folded
into the existing `_check_rds/_check_elasticache/_check_opensearch/_check_redshift` methods (no new
SECTIONS), scoped up front by a 7-agent research pass (botocore shapes verified offline) then hardened
by a read-only adversarial-verify (3 confirmed defects, all fixed) + a fix-verify.
- ✅ **Bundled `ENGINE_EOL` table + `managed_engine_cve()`** (`aws_engine_eol.py`, pure/deterministic —
  `today` injectable, no `now()`) → **synthetic honest `EOL-<engine>-<series>` signal, NOT real CVE ids**:
  AWS backports fixes into EOL engines out-of-band, so a CVE claim keyed on the visible EngineVersion is a
  near-guaranteed FP; an EOL date is a public deterministic fact. Feeds `emit_node_vuln_edges` → HAS_VULN
  edges byte-identical to the side-scan/Inspector shape. `engine_series()` handles the awkward real
  strings (`8.0.mysql_aurora.3.04.0`, `15.00.4322.2.v1`, `OpenSearch_2.11`).
- ✅ **EngineVersion vs EOL**: `RDS-12` (instance), `AUR-03` (Aurora cluster), `ELC-05` (ElastiCache, via
  `describe_cache_clusters` since replication groups carry no version), `OSR-07` (OpenSearch; all
  Elasticsearch = legacy). Live deprecated-version API deferred (`live_status` hook wired, defaults offline).
- ✅ **Aurora cluster enumeration** (`describe_db_clusters` — a plane the instance checks never touch, so
  Serverless-v1/headless clusters were unscanned): `AUR-01` encryption, `AUR-02` deletion-protection,
  `AUR-04` public cluster snapshot (fail-closed on a denied attribute read), `AUR-05` snapshot encryption.
- ✅ **Redshift Serverless** (`RSS-01..04`: public workgroup / CMK gap / require_ssl / enhanced-VPC),
  parameter-group `require_ssl` (`RS-06`) + version-pinning (`RS-07`), **Redis/Valkey 6+ RBAC** (`ELC-06`),
  OpenSearch min-TLS-1.2 depth (`OSR-06`).
- ✅ **Clobber-safe graph replay**: EOL HAS_VULN edges are stashed and replayed in `_check_vuln` (+ a run()
  epilogue) *after* IAMPRIVESC hard-replaces the graph, so they survive the rebuild. Managed nodes are
  intentionally correlate-**inert** in Phase 5 (attack-path participation is the Phase-7 unlock).

### Phase 6 — Per-service misconfig depth · **L** — ✅ SHIPPED (v2.16.0)
Closed the FSBP/CIS breadth backlog — **26 checks** folded into existing `_check_*` methods (NO new
SECTIONS, so `len(SECTIONS)==43` is untouched), scoped by a 7-agent research pass (botocore shapes
verified offline) and hardened by a read-only adversarial-verify. **All findings-only** — every
section runs before IAMPRIVESC's graph hard-replace, so graph edges are deferred to Phase 7.
- ✅ **Compute**: `SSM-01/02` (unmanaged instances + missing critical/security patches),
  `LT-01` launch-template IMDSv1, `ASG-01` the IMDSv2 **scale-out drift** (an ASG whose template
  allows IMDSv1 re-spawns v1 instances after you fix the live hosts), `AMI-02/03` (unencrypted
  snapshot, stale/past-deprecation).
- ✅ **Storage**: `S3-09/10` bucket-policy public (BPA-neutralization aware) + cross-account,
  `DDB-05` table resource-policy, `BCK-02/03` Vault Lock immutability + vault-policy exposure.
- ✅ **Containers**: `ECS-06/07/08` escape primitives (host namespaces / sensitive hostPath + docker.sock
  / dangerous capabilities), `EKS-06` world-open worker-node SSH, `CNT-06` ECR registry signing,
  `LMB-06` Lambda code-signing enforcement.
- ✅ **Network**: `CLB-01/02` Classic-ELB plaintext + weak SSL policy (elb v1), `VPC-05` NACL
  admin-port ingress (stateless RuleNumber first-match-wins), `VPC-06` cross-account peering,
  `WAF-05` managed-rule-group baseline, `CFN-06` CloudFront origin-side TLS.
- ✅ **AI/ML**: `SM-05/06/07` SageMaker Studio public egress + home-EFS CMK + endpoint-config CMK.
- Recurring hardening applied throughout: inline-paginate in own try/except (never the swallowing
  `_paginate_all`), empty→INFO, and **aggregate-PASS-must-count-evaluated-vs-unknown** (denied reads
  downgrade a summary all-clear to WARN).

### Phase 7 — L7 reachability + attack-path fusion + DSPM · **M** — ✅ SHIPPED (v2.17.0)
Wired every new node into the attack-path engine — the CNAPP differentiator that un-inerts
the Phase-5 managed nodes and Phase-6 findings into ranked paths. **4 new check IDs**
(EXPOSURE-03, IDENTITY-01, DSPM-01/02) folded into EXPOSURE#37 / DATA#41 / CORRELATE#42 +
the pure `aws_correlate`/`aws_deepplane` modules — **no new SECTIONS** (`len(SECTIONS)==43`
holds). Scoped by a 5-agent research pass (botocore shapes verified offline) then hardened by
a 48-agent read-only adversarial-verify (12 confirmed / 9 unique defects, all fixed) + a
fix-verify. 1066 tests.
- ✅ **L7 un-defer** (`_build_l7_exposure` in `_check_exposure`, post-IAMPRIVESC-clobber):
  internet-facing ALB/NLB/classic-ELB/CloudFront/API-GW → `LoadBalancer`/`CloudFrontDistribution`/
  `ApiGateway` nodes + `internet→EXPOSED_TO` + **`TARGETS`** edges (E_PATH-traversable) →
  `EXPOSURE-03`; LB target instance-ids folded into `exposed_instances` so an over-privileged
  LB-fronted host lights up **`ATTACK-01`** with zero duplicated emitter. Conservative
  internet-facing gate (Scheme + active + SG-open listener; NLB SG-less ok; APIGW EDGE/REGIONAL
  not PRIVATE); health-gated + open-listener-TG-restricted target resolution; TG-VpcId-scoped
  ip-target resolution (cross-VPC-collision-safe).
- ✅ **Component-level exploitability**: `_path_exploitability` + the DFS gate generalized
  EC2-only → EC2/ECRImage/Lambda + **RUNS_IMAGE CVE inheritance** (a workload inherits its
  image's CVEs; RUNS_IMAGE stashed-and-replayed past the clobber); `reachable_service` HAS_VULN
  prop (set when the workload is internet-exposed) → `X_reachable_boost` clamped `min(X_kev,·)`.
- ✅ **Identity fusion** (`IDENTITY-01`): a stale/long-unused ACTIVE access key on an
  admin-capable IAM user → `internet→EXPOSED_TO→IAMUser` → a **pre-auth account-takeover path**
  (ATTACK-01 semantics, scores CRITICAL via the unconditioned-admin floor). Admin-capability
  reuses the graph reachability test, so a boundary/SCP-neutralized user is correctly NOT flagged.
- ✅ **DSPM** (`DSPM-01/02`): crown-jewel tagging for RDS/RDSCluster/Redshift/DynamoDB/EFS via
  data-classification tags (no Macie) — `is_crown_jewel_by_tags` (separator-folding + synonym +
  compliance-framework aware, exact-value-safe) + `role_can_read_store` CAN_READ_DATA edges. Node
  ids reuse the Phase-5 EOL fallback so a tagged crown **merges** onto any vulnerable EOL node
  (a "vulnerable crown jewel"). `crown_nodes(g)` spans S3 + all DSPM stores for the flagship/correlate.

### Phase 8 — Windows agentless OS-vuln coverage · **L**
Extend the now-live side-scan to Windows; close the Linux-only blind spot.
- Windows branch in the EBS extractor (NTFS + SOFTWARE-registry-hive software/hotfix inventory)
- New `match_vulns` branch vs an MSRC/OSV KB→CVE feed → HAS_VULN edges
- SSM-CWPP fallback + interim explicit-WARN (removes the silent false-clean now)

---

## Architecture notes (how it slots into the existing patterns)

- Every new check is a `self._add(status, CHECK_ID, SECTION, resource, message)` call inside a
  `_check_<service>` method registered in `CHECK_MAP` — new methods (`_check_ami`, `_check_ssm`,
  `_check_launch_templates`, `_check_asg`, `_check_cloudwatch`, `_check_cognito_identity`,
  `_check_elb_classic`, `_check_image_scan`, …) follow the identical registration pattern as the existing 37.
- Each new CHECK_ID lands in all three maps in lockstep: `COMPLIANCE_MAP` (CIS v3 / FSBP / PCI-DSS /
  HIPAA / SOC2 / NIST), `CHECK_SEVERITY`, and `REMEDIATION_MAP`.
- **CWPP reuse is the central lever**: the `FilesystemExtractor` Protocol (`aws_sidescan.py:55`) is the
  seam — `DissectExtractor` (live EBS), `ImageLayerExtractor` (ECR), `LambdaArtifactExtractor`, and the
  Windows extractor all implement the same Protocol and feed the **unchanged** `sidescan_filesystem →
  collect_inventory → match_vulns → enrich_match → to_has_vuln_edges` pipeline; language-manifest
  parsers plug into `collect_inventory` alongside dpkg/apk/rpm, and `OSVFeed` already indexes
  `by_purl/by_name` for npm/PyPI/Maven/Go/RubyGems.
- Managed-service CVEs get a parallel deep-plane hook `managed_engine_cve(service, version)` emitting
  HAS_VULN edges shaped exactly like the side-scan/Inspector edges, so DB/search/cache engines become
  vulnerable-service graph nodes indistinguishable to `aws_correlate` from host/image nodes.
- New graph edge types are the currency of attack-path fusion: `PUBLIC_KMS/SHARED_KMS`, `SHARED_SECRET`,
  `DANGLING_DNS`, `HAS_STALE_KEY`, `RUNS_IMAGE`, `EXPOSED_TO/TARGETS` (L7), and `reachable_service`-tagged
  HAS_VULN — each projects an ARN-keyed node so `aws_correlate/aws_exposure` chain
  internet→ingress→vulnerable-workload→privileged-role and choke points feed `aws_remediate`.
- Correlation stays reachability-gated (`ATTACK-02`) to preserve the "high-CVSS but unexposed"
  false-positive suppression — new vuln sources feed exploitability only through the same exposed-node gate.
- Atomic YAML tests mirror each new check ID and pytest suites mirror source layout under `tests/`.
- **Read-only/agentless preserved everywhere**: describe/get/list + EBS-snapshot copy+block-read
  (provenance-guarded `is_owned` cleanup) + userspace filesystem parsing (dissect, no kernel mount).

## Risks

- The agentless/read-only contract is inviolable (userspace parse, no kernel mount, no code execution on targets).
- Parsing untrusted filesystems / container layers is an attack surface on the scanner — extraction must be sandboxed with resource caps and hardened parsers.
- Cost / API-throttle blowup from broad describe fan-out + snapshot copy + artifact downloads — need pagination backoff, per-service throttling, caching, and exposure-gated instance selection.
- False positives on legitimate cross-account sharing (EBS-05, AMI-02, KMS-02, SEC-05) — need an operator-supplied trusted-account allowlist.
- Language-dep matching without reachability can flood operators — ship with `reachable_service` tagging + behind the `ATTACK-02` gate.
- EOL / engine-CVE tables drift — need a refresh process (the `--vuln-db` feed).
- Windows KB→CVE feed fidelity is lower than Linux OSV — keep the interim explicit-WARN until validated.

## Coverage metrics

- Check-ID count growth from ~197, tracked per pillar (CSPM/CIEM/CWPP/DSPM/CDR) and per `_check_` method.
- CIS v3 control coverage % (§4 CloudWatch going 0% → target after Phase 2) and FSBP coverage %, from `COMPLIANCE_MAP`.
- **CWPP live-run rate**: fraction of in-scope EC2/EBS targets producing a real CWPP-01/02/03 result — ~0% today → near-100% post-Phase 3.
- Image-CVE signal independence (% of images with a CVE verdict without Inspector2): 0% → broad post-Phase 4.
- Lambda dependency-CVE coverage: 0% → full post-Phase 4.
- Managed-service EOL/CVE coverage + Aurora-cluster enumeration: 0% → full post-Phase 5.
- Windows host OS-vuln coverage: 0% → extractor coverage post-Phase 8.
- Attack-path fidelity: % of HAS_VULN findings carrying reachability context; count of L7-fronted paths previously invisible.
- Noise rate: findings suppressed by the `ATTACK-02` exposure gate + cross-account allowlists.
