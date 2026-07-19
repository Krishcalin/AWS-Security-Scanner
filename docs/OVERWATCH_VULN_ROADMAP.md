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

### Phase 4 — Container image + Lambda dependency scanning · **L**
Agentless, Inspector-independent, reusing the Phase-3 extractor + SBOM pipeline.
- `ImageLayerExtractor` (pull ECR layers, overlay/whiteout) → `CWPP-05` + HAS_VULN on `ECRImage`
- `LambdaArtifactExtractor` (download function zip + layers) → `LMB-07` vulnerable dependency
- `RUNS_IMAGE` edges (ECS/EKS images → `ECRImage`) so image CVEs drive attack paths; ECR hygiene (`CNT-04/05`)

### Phase 5 — Managed-service vulnerability axis · **M**
The "vulnerable managed service" signal + the invisible Aurora cluster shape.
- Bundled `ENGINE_EOL` table + `managed_engine_cve()` deep-plane hook → HAS_VULN edges shaped like the side-scan
- `RDS-07/OSR-07/ELC-05/RS-08` EngineVersion vs EOL + deprecated-version API
- Aurora cluster enumeration (`describe_db_clusters`) → RDS-01c/02c/03c + public cluster snapshots
- Redshift Serverless; parameter-group TLS; Redis 6+ RBAC

### Phase 6 — Per-service misconfig depth · **L**
Close the FSBP breadth backlog — partial → thorough, service by service.
- Compute: `_check_ami`, `_check_ssm` patch-state, `_check_launch_templates/asg` (IMDSv2 scale-out drift)
- Storage: S3 policy-layer eval, Backup Vault Lock, RDS PI encryption, DynamoDB resource-policy
- Containers: ECS escape primitives, EKS nodegroup→EC2 graphing, code-signing
- Network: Classic ELB, NACL/egress/peering, WAF rule quality, CloudFront depth; AI/ML: SageMaker depth

### Phase 7 — L7 reachability + attack-path fusion + DSPM · **M**
Wire every new node into the attack-path engine — the CNAPP differentiator.
- Un-defer L7 in `aws_exposure`: internet-facing ALB/NLB/CloudFront/API-GW → `LoadBalancer` node + TARGETS edges → `EXPOSURE-03` + LB-fronted `ATTACK-01`
- Component-level exploitability: boost when `HAS_VULN.reachable_service` **and** SG-open; ECRImage/Lambda CVEs on exposed workloads drive paths
- Identity fusion: leaked old key on an admin principal → CRITICAL pre-auth takeover
- DSPM: crown-jewel tagging for RDS/Redshift/DynamoDB/EFS (no Macie needed)

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
