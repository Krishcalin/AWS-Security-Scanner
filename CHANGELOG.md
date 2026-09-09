# Changelog

All notable changes to the **AWS Live Security Scanner** (`aws_live_scanner.py`)
are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed — a failed read is no longer reported as a security finding

Ten checks answered a failed AWS call with `_add("FAIL", <id>, ..., str(e))` — the
exception's text, as the finding. That was wrong twice over. A denied or throttled
call produced a **FAIL carrying that check's remediation**, telling an operator to fix
a misconfiguration nobody observed when their real problem was a missing grant. And
for all ten that error path was the check's **only** literal FAIL, so — because `_add`
reads severity, compliance and remediation from the catalogue for no other status —
the declared severity was reachable only by the call breaking, while the
misconfiguration the check exists to find emitted WARN, forced to LOW with no
remediation. The catalogue was describing the error handler.

Nothing asserted any of it: removing the whole shape broke no existing test.

- **`AWSLiveScanner._read_failed` replaces all ten sites** (BDR-04, BDR-05, DDB-01,
  EC2-05, R53-02, R53-04, SNS-01, SNS-04, SQS-03, SQS-04). A failed read now emits
  WARN — never silence, which would be a phantom pass — names the action that failed,
  and records the denial in the coverage ledger.
- **Two conditions earned a real FAIL.** `BDR-05` (a customer-managed policy allowing
  `bedrock:*` or `*` on `*`, the same class the IAM checks already FAIL for) and
  `SNS-04` (a cross-account subscription), the latter now gated on the
  trusted-account allowlist so a named partner account is a decision rather than a
  finding — the same gate as `LMB-14`, `AMI-05` and `ECS-14`.
- **Six severities corrected to LOW** — `BDR-04`, `DDB-01`, `EC2-05`, `R53-02`,
  `SNS-01`, `SQS-03`. Each describes a hardening preference or an
  honest could-not-determine ("consider PrivateLink", "consider CMK", "verify if
  intentional"), so the code was right and the catalogue was not. No scoring change:
  a WARN already rendered LOW. Three of the six were declared **twice** in
  `CHECK_SEVERITY`, so every occurrence was replaced — editing the first does nothing,
  silently.
- **Two tripwires.** No check declared above LOW may have its only FAIL inside an
  `except` handler (`S3-03` is exempt and justified: `get_bucket_encryption` raises
  when a bucket has no default encryption, so there the exception *is* the signal).
  And the count of FAIL findings whose message is just an exception's text is now
  ratcheted, shrink-only.

**Known remaining debt, named rather than left to be found:** 22 sites still report
exception text as a FAIL. Those checks also have real FAIL paths, so their severity is
at least reachable honestly, but a denied read on any of them still produces a
misleading finding. `S3-03` additionally does not distinguish
`ServerSideEncryptionConfigurationNotFoundError` from `AccessDenied` — the `S3-07`
defect fixed in the bucket-B pass, in a second place.

### Added — CIS AWS Compute Services Benchmark v2.0.0 (43 checks, 3 sections)

Full coverage of the benchmark's 82 recommendations: 33 were already covered, 44 are
covered by the 43 checks added here, and 5 cannot be decided from the AWS control plane
at all. `docs/CIS_COMPUTE_BENCHMARK.md` maps every recommendation to the check that
answers it, and names the reason for each of the five that has none.

- **New sections: `APPRUNNER`, `BATCH`, `BEANSTALK`.** These three services had no
  coverage of any kind. They are in the default run list, which costs one List plus one
  Describe each on every scan — a section registered in `CHECK_MAP` but absent from
  `SECTIONS` never runs, which is the defect that hid four AI sections.
- **New checks in existing sections.** AMI: `AMI-04` naming convention, `AMI-05` image
  provenance. EC2: `EC2-10`/`EC2-11` organizational tag policy, `EC2-12` instance age,
  `EC2-13` detailed monitoring, `EC2-14` default security group in use, `EC2-15`
  detached ENIs, `EC2-16` long-stopped instances, `EC2-17` volumes surviving
  termination, `ASG-02` tag propagation. ECS: `ECS-09` Fargate platform version,
  `ECS-10` Container Insights, `ECS-11`/`ECS-12`/`ECS-13` tagging, `ECS-14` image
  provenance, `ECS-15` task-set public IPs, `ECS-16` network mode, `ECS-17` ECS Exec
  session logging, `FARGATE-03` ephemeral-storage CMK. Lambda: `LMB-10` Insights,
  `LMB-11` shared execution roles, `LMB-12` missing execution roles, `LMB-13` admin
  execution roles, `LMB-14` unknown cross-account grants, `LMB-15` environment CMK,
  `LMB-16` public layers, `LMB-17` recursion detection. Lightsail: `LSAIL-03` IPv6,
  `LSAIL-04`..`LSAIL-07` buckets — which are invisible to the S3 API and to S3 Block
  Public Access. Image Builder: `IMGB-02` distribution configs, `IMGB-03` build cleanup.
- **`AMI-04` reports NOT EVALUATED until configured.** A naming convention is an
  organisational fact no AMI reveals; set `OVERWATCH_AMI_NAME_PATTERN` or
  `scanner.ami_name_pattern` to make it evaluate. Guessing a pattern would fail correct
  estates.
- **Compute-benchmark mappings use a `CIS-COMPUTE` compliance key**, not `CIS`. The 123
  existing `CIS` mappings are all AWS *Foundations* numbering, and the Compute benchmark
  re-uses those numbers for different controls.
- **All 43 arrived with driving tests.** `docs/CHECK_FIRING.md` goes 460 → 503
  registered and 331 → 374 proven-to-FAIL, with never-observed **down** from 62 to 61.
  `tests/test_cis_compute.py` asserts the same invariant over its own declarations, so a
  forty-fourth check without a driving test fails immediately.

### Changed — permissions

- **23 read actions added to the shipped role's requested surface** (App Runner, Batch,
  Beanstalk, the ECS cluster/service/task-set describes, two Image Builder reads, three
  Lambda reads, `lightsail:GetBuckets`, `organizations:ListPolicies`). All are
  `Describe`/`Get`/`List` — `aws_checkdef` rejects a write verb at construction — and
  each carries a written justification in the permission ledger.
  `tests/perm_ledger_baseline.py` was regenerated to record the widening.

### Changed — findings (BREAKING for anyone gating on counts or scores)

Both entries below come from `docs/CHECK_FIRING.md`, which measures which checks the
suite can actually make fire. `_add` reads severity, compliance and remediation from
the catalogue **only for a FAIL** — a WARN is forced to LOW and carries no
remediation — so a check registered MEDIUM or HIGH that can only WARN has never
rendered what the catalogue advertises for it. 46 checks were in that state.

- **21 checks now emit FAIL where they previously emitted WARN.** Each describes a
  definite misconfiguration and sat beside siblings in the same function that already
  FAIL for comparable conditions: `ECS-02` (container runs as root) and `ECS-05`
  (writable root filesystem) next to `ECS-01`/`ECS-03`; `SEC-02` (rotation interval
  past 90 days) next to `SEC-01` (rotation off); `WAF-04` (default action ALLOW) next
  to `WAF-03` (no rules). Also `S3-05`, `S3-07`, `S3-08`, `VPC-04` (CIS 5.4 default
  security group), `CNT-04`, `CFN-06`, `GLC-02`, `LOG-06`, `LOG-08`, `RDS-08`,
  `RSS-04`, `ELB-07`, `ELC-04`, `EKS-08`, `KIEM-02`, `KIEM-03`, `KSPM-04`.

  **Risk scores and failed-check counts will rise on existing estates**, because
  findings that scored 0.5 as a forced-LOW WARN now score at their declared severity.
  Anything gating CI on a failed-check count needs re-baselining.

- **22 checks are now declared LOW** to match what they can render, rather than
  advertising a severity they could never reach. Three kinds: a hardening
  **preference** rather than a defect (`SEC-03`, `SEC-04`, `SFN-03`, `RSS-02`,
  `BDR-03`, `AGT-01`, `AGT-03`, `LMB-02`, `LMB-05`, `DDB-03`, `RS-07`, `AGC-03`,
  `AGC-04`, `DIRSVC-02`); an honest **could-not-determine** (`WINVULN-03`, whose WARN
  exists specifically to remove a silent false-clean, plus `VPC-06`, `EKS-04`,
  `EKS-05`, `EKS-07`); and a **gradation** beneath a check that already FAILs
  (`AILOG-05`/`AILOG-06`, where `AILOG-04` owns the total-absence FAIL) or resting on
  evidence too weak to assert (`MART-03`, whose only ownership signal is whether a
  bucket NAME carries a different account id). No scoring change: a WARN already
  rendered LOW.

`WAF-01`, `SHAI-03` and `ACM-05` are deliberately untouched. Each needs a logic
change rather than a status flip — `WAF-01`'s only posture WARN is "no Web ACLs in
this scope", and a blanket FAIL would flag every account with nothing to protect.

### Fixed

- **`S3-07` reported "no bucket policy enforcing TLS-only access" on AccessDenied.**
  One exception handler answered two different questions: a missing policy (TLS is
  genuinely not enforced) and an unreadable one (we could not tell). It stated the
  first for both. The `S3-09` line immediately below it already drew exactly this
  distinction. Access-denied now WARNs as UNKNOWN; a genuinely absent policy FAILs.
- **Seven `CHECK_SEVERITY` entries were declared twice with different values.** The
  map re-declares some ids in a later "backfilled" block and a dict literal takes the
  last, so editing the first occurrence changed nothing, silently.
  `test_check_maps_lockstep.py` now fails on any duplicate whose values disagree
  unless it is named as an intentional override (`SM-02` and `SM-04`, which are
  raised to HIGH on purpose).

### Added

- **`NHI` section (SECTION 91) — `NHI-01`..`NHI-05` can now fire.**
  `engine/aws_nhi.py` shipped complete, with its own test file, and nothing ever
  called it: it was imported by three production modules (its CheckDefs register at
  import time, which is what put the five ids in all four metadata maps) and
  referenced by none of them. The checks were catalogued, counted in the published
  total, and unreachable. The section reads the principals `_get_iam_principals`
  already fetches and the credential report the IAM section already reads — **no new
  API call and no new IAM grant**. `_get_iam_principals` now also carries the raw
  `AssumeRolePolicyDocument` and resource tags, both already present on the same
  `GetAccountAuthorizationDetails` page; the raw document is what lets `NHI-04`
  (`sts:ExternalId`) and `NHI-05` (`:sub`) reach a verdict instead of reporting
  themselves `NOT_EVALUATED`.
- **`test_unreached_modules.py` now asks whether a module is CALLED, not merely
  imported.** An unused import satisfied the old ratchet, which is why `aws_nhi`
  hid in it. A module that registers CheckDefs must have a production caller.

## [3.0.0] — 2026-08-28

**A major version because the import surface changed, not because the product
did.** The 109 modules that sat flat in the repository root are now three
packages with an enforced dependency rule, and the container will no longer start
without being told how it authenticates. Both are breaking for anyone who
automated against the old shape, so the number says so.

The release also closes the three things that stood between this build and a
first production load — none of which a green test suite could see, because all
three were configuration.

### Breaking

- **Modules moved into `engine/` (89), `hub/` (17) and `store/` (3).** Imports
  are now `from engine import aws_live_scanner`, and the CLIs run as
  `python -m engine.aws_live_scanner` — a bare script path puts `engine/` on
  `sys.path` instead of the repository root and fails. Everything inside the repo
  is updated; anything outside it that imported these modules needs the new form.
- **`CNAPP_AUTH_MODE` is required.** The image's entry point is now
  `hub.cnapp_server:create_app`, which selects `local` or `idp` and **refuses to
  start** when unset. It previously defaulted to `create_app_from_env`, whose
  `current_principal` is `None` — every route 403. That was safe and
  indistinguishable from a broken deployment.
- **The uvicorn factory path is `hub.cnapp_server:...`**, not `cnapp_server:...`.

### Added

- **AWS Secrets Manager as the secret store** (`hub/cnapp_secrets.py`). Onboarding
  ExternalIds and connector tokens are written there and only the
  `secretsmanager://` reference is persisted. `build_service()` previously wired
  these seams to a function that raises, so a real deployment could not onboard an
  account or create a connector **at all**.
  - **Ownership is checked before any overwrite.** Rotation re-uses a secret's
    name, so the write path is create-or-update — and an update is a mutation.
    Every secret is tagged `cnapp:owner=overwatch` at creation and an update
    refuses without that tag, so a prefix collision with an operator's own secret
    fails loudly instead of replacing their value. Same provenance guard
    `aws_sidescan_ebs.is_owned()` applies to snapshots. A failed `DescribeSecret`
    refuses rather than proceeds: a check that fails open is not a check.
  - Unconfigured still **refuses** — no plaintext fallback, no silent no-op.
- **`CNAPP_COOKIE_SECURE`** (`auto` | `always` | `never`). `auto` is the previous
  behaviour and still the default.
- **ServiceDesk Plus connector** (`OW2-CC-020`) — outbound ticket creation, with
  the form-encoded `input_data` body and the logical-failure-inside-HTTP-200
  response contract both handled and named in tests.
- **Baseline alert rules ship enabled** (`OW2-AR-002`). Five rules seeded inside
  the connector-create transaction. Two of the five do not map onto an available
  action; each carries a stated `gap` that travels into the rule name, the console
  and the delivery ledger rather than being quietly redefined as done.
- **`tests/test_layering.py`** — the `hub → engine → store` rule enforced by AST.
  Zero back-edges, checked rather than asserted in a diagram.
- **The full suite runs in CI** (`.github/workflows/suite.yml`) on **ubuntu and
  windows**. Previously one unrelated test file ran.
- New guards: `tests/test_data_paths.py`, `tests/test_ci_integrations.py`,
  `tests/test_production_config.py`.

### Changed

- Both Dockerfiles copy `engine/ hub/ store/` instead of `*.py`; `.dockerignore`,
  compose, `local_server.py` and 24 documented invocations follow.
- `requirements-dev.txt` pins `httpx2`; `python-hcl2` removed (below).

### Fixed

- **Three repo-root paths resolved from `__file__`** broke when their modules
  moved one directory down. `compliance_crosswalk` failed loudly;
  `aws_live_scanner`'s report logo failed **silently** inside an
  `except Exception`; `cnapp_server`'s `frontend/dist` default failed **masked**
  behind `CNAPP_STATIC_DIR`.
- **`scripts/coverage_gap.py` globbed the root non-recursively** to decide which
  AWS services the scanner covers. After the move it would have read no modules
  and reported **the whole of AWS as an uncovered gap** — a confident wrong
  answer. It now scans the three layers and refuses on an empty scan.
- **Three root-walking guards could scan nothing and still report clean** —
  including the D11 mutation-surface ratchet, the control behind "OverWatch
  mutates only resources it created". Each now asserts a floor before it sweeps.
- **`requirements-dev.txt` was uninstallable**: `python-hcl2==7.4.0` exists on no
  platform (published versions jump 7.3.1 → 8.1.0), so
  `pip install -r requirements-dev.txt` failed and installed **nothing**. Nothing
  in the repo imports `hcl2`. Removed rather than re-pinned.
- **`extractor-fs-validation.yml` was invalid YAML** — a `run:` one-liner
  containing `": "`. GitHub parsed nothing, so the one workflow in the repo never
  ran. Predates the package move.
- **`test_correlate_frozen`'s pin was a Windows-only hash.** It hashed
  working-tree bytes, which with `core.autocrlf=true` are CRLF on Windows and LF
  elsewhere — the freeze would have failed on any Linux checkout. Newlines are
  normalised before hashing; the file's content never changed.
- **The Postgres `connectors` type CHECK** still listed five types, so an `sdp`
  connector could not be created on the deployed engine. `CREATE TABLE IF NOT
  EXISTS` leaves an existing table alone on both engines.
- **A CHECK violation was reported as "connector name already in use"** —
  `sqlite3.IntegrityError` covers UNIQUE and CHECK alike, sending an operator
  hunting a collision that did not exist.
- **Path-based integrations** repointed: the IaC gate action, the VS Code
  extension default, and the offline-bundle `VERSION` probe, which was returning
  empty and naming the release `overwatch-airgap-.tar.gz`.

### Documentation

- **`docs/ARCHITECTURE.md`** — the three layers, why `store/` exists (the
  persistence trio is mutually recursive and belongs to neither side), and why
  two modules sit in the package their imports demand rather than their prefix.
- **`docs/PRODUCTION.md`** — the settings with no safe default, the exact IAM
  actions for the hub's **own** task role, a pre-live checklist, and the gaps that
  remain at this version.

### Notes

- The cross-account scanning role is **unchanged and still read-only**. The
  Secrets Manager actions belong to the hub's own task role and are deliberately
  absent from `aws_perm_ledger`.
- Still open, named rather than left to be found: auto-fix execution withheld
  (D11), `aws_trend` and `aws_guardrail` unwired, inbound ticket sync not built
  (`OW2-CC-021`), `iam:ListAccessKeys` not collected.


## [2.39.0] — 2026-08-27

Slice 2 of the Phase II build, end to end: **registry → attribution → SLA → KRA →
risk model → scorecard → API → console.** FR-2 goes from a specification section to
something an application owner can be sent.

The release also closes the gap 2.39.0 exists to close. Of the seven modules
2.38.0 added, **four had zero non-test consumers** — six specification defects
fixed correctly, in libraries the product never reached. Five modules are wired
here; three remain deliberately parked and are named below rather than left to be
discovered.

### Added

- **Application registry** (`cnapp_application.py`, schema **v17**,
  `GET/POST/PUT/DELETE /applications`, `/applications` console route). AD-02 is
  filed in the SRS as an *assumption*; it is the load-bearing floor under FR-2,
  FR-6, `OW2-CC-012` filtering and every by-owner KRA, and nothing satisfied it.
  - **Validation runs on write, and `aws_ownership.Application` IS the rule set** —
    `validate()` constructs one, so the registry and the attributor cannot disagree
    about what is valid. A rule added to either is enforced by both.
  - **Fatal rejects, warning does not.** A mis-scoped application does not fail
    loudly: it saves, renders a scorecard, reports zero findings, and is
    indistinguishable from one that is genuinely clean. So `warnings_for()`
    surfaces no-owner / no-selectors / unclassified at save time and the API
    returns them **with the object** — but it warns rather than refuses, because
    somebody mid-onboarding may legitimately not know the owner yet, and refusing
    would push the registry into a spreadsheet where nothing validates it at all.
  - Input shapes that fail silently are rejected loudly instead: a comma-joined
    string where a list belongs, an 11-digit account id, a bare `"App=pay"`
    selector.

- **Scorecard assembly** (`aws_scorecard.py`, `GET /scorecards`, `/scorecards`
  console route) — `OW2-SC-002` through `OW2-SC-008`. The artefact that needs
  `aws_ownership`, `aws_sla`, `aws_kra` and `aws_riskscore` at once, which is why
  it is where four of them get wired.
  - A scorecard is **the most dangerous artefact this product produces**: every
    other output is read by someone who can go and check, and a scorecard is read
    by an owner who cannot. It is also a *filter*, and a filter deletes what it
    does not match while looking complete.
  - **The pack states its own coverage**, and unowned findings get their own row —
    no owner, no grade, sorted last, so it can never head a graded table even when
    it holds the most criticals.
  - **The closure rate never travels alone.** `sla_line()` renders the rate, the
    exception-assisted count and the deferred breaches together or not at all.
  - **Rank is refused without a denominator** (`OW2-SC-004`). Ranking on raw counts
    would be a league table ordered by size wearing the costume of a security
    measurement. A partially rankable portfolio reports `peers` as the number
    *actually* compared, so "3rd of 4" never silently means "3rd of the 4 we could
    measure, out of 11".
  - **Excepted findings are segregated, never merged** (`OW2-SC-008`). An exception
    is a decision to accept a risk, not evidence the risk went away; merging them
    would let an owner improve a grade by asking rather than by fixing.

- **Live risk factors** (`aws_factors.py`) — the five `FactorValue` inputs
  `aws_riskscore` has consumed since 2.38.0 and nothing produced, plus the
  **`ExposureGate` verdict that had no producer**. D2's rule — no quantity of
  tooling buys down a live exposure — had been enforced-by-*withholding* rather
  than enforced-by-*deciding* since it shipped.
  - The gate needs no new analysis: `AttackPath` already carries `conditioned`,
    `kev`, `direct_public_crown` and `terminal_kind`, so the four-gate exposure
    oracle stays the authority on reachability rather than getting a second,
    worse opinion.
  - **Every saturation point is published** via `saturation_points()`, and labelled
    a judgement rather than a derived truth. A factor normalised to [0, 1] has to
    decide what counts as 1.0, and that decision moves every score built on it
    while looking like arithmetic.
  - Four refusals, each with a plausible wrong answer that flatters: no
    vulnerability data is **not** exploitability 0.0 (that would reward never
    running a scanner); no graph is **not** exposure 0.0; `unclassified`
    criticality is **not** the bottom of the scale (that would reward declining to
    classify anything); one posture observation is **not** a flat trend.

- **`aws_state.findings_for_period()`** — open findings plus those resolved inside
  the period. `open_findings()` alone reports **0% closure for a team that closed
  everything**: wrong in the pessimistic direction rather than the flattering one,
  which makes it no more acceptable — a scorecard that understates an owner's work
  gets ignored, and an ignored scorecard measures nothing.

### Changed

- **No silent caps, anywhere.** Prompted by reading Qualys TotalCloud, whose docs
  publish their 10,000-record limit. Checking whether we did the same found our own
  principle written three lines below a cap that broke it:

  ```python
  "attack_paths": p.get("attack_paths", [])[:10],
  # What this scan did NOT establish, travelling with the number it did.
  # A grade rendered without it is a grade whose denominator is unknown.
  "coverage": p.get("coverage"),
  ```

  Ten attack paths could be ten of ten or ten of four hundred, and that payload
  carried no total at all.
  - `cnapp_service.capped()` emits `<field>`, `<field>_total` and
    `<field>_truncated` across eleven sites. `_total` is emitted even where a
    sibling count already carries it: a list that describes itself cannot be
    rendered without its denominator, whereas one relying on a neighbouring field
    can be, and eventually is.
  - **The console had the same defect and the AST ratchet could not see it** —
    including two caps inside the *exported HTML report*, which leaves the building
    and is read as complete by someone who cannot go and check. That table now
    captions "showing 25 of 214".
  - Both layers carry their own ratchet, so a new undeclared cap fails the build
    until its author either declares it or writes down why nothing is dropped.

- **The attack-path marker on a findings row now opens the path.** It already
  existed and was **inert** — inside the row's `onClick`, so clicking it opened the
  finding detail and never the graph. `pathLinks()` keeps a *count* alongside the
  destination, because a marker linking to one path while the finding drives five
  would imply the other four do not exist.

- `aws_policy.policy_finding` and its TypeScript twin both declare the `affected`
  cap. The cross-language parity test caught the one-sided change, which is what it
  is for.

### Fixed

- **D11–D13 answered and, for the first time, enforced.** Two of the three did not
  need the decision they appeared to need.
  - **D11 — auto-fix: governance built, execution withheld.** Answering it forced a
    correction to how this product describes itself. The blanket "read-only" claim
    is **false**: `aws_sidescan_ebs` calls `create_snapshot` / `detach_volume` /
    `delete_snapshot`. The rule actually kept is narrower and sharper —
    **OverWatch mutates only resources it created, never a customer's** — held true
    by `is_owned()` and the `cnapp:sidescan=<scan_id>` tag. Auto-fix would be the
    first time it touches a *customer* resource, which is a cleaner line than
    "read-only" ever was. A frozen `MUTATION_SURFACE` of three modules, each with a
    written reason, fails the build on a fourth.
  - **D12 — no widening needed.** `cnapp_connectors.py` is already allowlisted and
    already ships a signed SSRF-guarded webhook transport, a Splunk HEC renderer
    and a template override, so CEF/syslog is a renderer inside an allowlisted
    file. The guard that should have existed did not: `EGRESS_ALLOWLIST` was a plain
    set nothing pinned, so a fourth entry could be added in the same commit as the
    code excusing it. Now pinned.
  - **D13 — vendor-neutral, yes.** Not a new principle: `aws_ingest_aidr` and
    `aws_ingest_credexp` both made this call when their upstream contracts could not
    be verified. A principle with a precedent gets followed; one without gets
    re-argued.

### Notes

- **A false zero this release nearly shipped.** `aws_factors` reads `paths=[]` as
  "the graph was built and found nothing" and `paths=None` as "no graph exists".
  The first service wiring passed `[]` for every account including unscanned ones,
  so exposure scored a measured 0.0, weight coverage crossed the 50% floor, and an
  application with one HIGH finding and **no scan result at all graded B**. The
  grade was arithmetically correct and rested on a fact nobody established. An
  existing test caught it; a regression now pins it.
- **Still un-wired, deliberately:** `aws_trend`, `aws_guardrail`,
  `aws_ingest_credexp`. Each waits on something that does not exist yet — trend
  materialisation, a policy-evaluation engine, and an IAM access-key inventory
  respectively — and each *withholds* rather than assumes in the meantime.
- Console sample mode returns an **empty** registry with a note rather than
  fabricated applications. A demo that invents owners and grades teaches the reader
  that the numbers are decor.
- Suite: **5,458 passing**, up from 5,285.

## [2.38.0] — 2026-08-26

The **OverWatch Phase II SRS** (`OW2-SRS-001 v0.1`) arrived for review. Reading it
against the codebase produced two findings worth stating before the changelog proper.

First, the specification misjudges its own difficulty. Of its nine functional modules,
two were already substantially shipped in Phase I — FR-7 Digital Twin, scheduled last
in II-C, and FR-9 Identity/CIEM — while FR-2 Scorecards, scheduled earlier, started
from nothing. And the dependency the document files as an *assumption* (AD-02,
application-to-owner mapping) is the load-bearing floor under half of it.

Second, six defects in the specification would have survived into the built system and
been expensive to unwind. All six are fixed here, each with ratifiable replacement text
under `docs/`. The through-line is one failure mode in six costumes: **a number that
quietly narrows what it was computed over, and reads as good news for doing so.**

### Added

- **Ownership attribution** (`aws_ownership.py`) — the Application entity and three-tier
  attribution (explicit resource pin, then tag selector, then whole-account claim) that
  AD-02 assumes and nothing provided. A tier matching two applications stops as
  **ambiguous** rather than falling through to a vaguer tier that happens to be decisive;
  resolving a contradiction by widening the question is how a tool confidently bills the
  wrong team, and ownership must not depend on registry declaration order.
  - `AttributionCoverage` is returned **alongside the buckets, not optionally**. A
    scorecard is a filter, and a filter deletes what it does not match: attribute 400 of
    1,000 findings and the portfolio pack sums to a cleaner estate than the one that
    exists. That is a phantom pass by omission, and it is worse in a scorecard than in a
    check because an executive reads a scorecard as complete by default.
  - Unattributed findings land in a real bucket with a real empty owner slot. They are
    never dropped. `attribution_health` surfaces the dangerous defect — a selector
    matching nothing renders a clean scorecard indistinguishable from a mis-scoped one.

- **SLA clocks, MTTR and pre-breach warning** (`aws_sla.py`) — `OW2-CC-014`,
  `OW2-AR-031/032`, `OW2-PA-005`, `OW2-KM-001(a)`. **No `now()` anywhere:** an SLA state
  that reads the wall clock is not reproducible, so no auditor can recompute a published
  KRA. The caller supplies the clock.
  - Honest because `aws_state` resolves findings via a **coverage-gated** join — a finding
    closes only when a scan that provably executed that check failed to re-observe it.
    That already exceeds `OW2-AR-030`, and MTTR built on ticket closure would not.
  - `MttrReport` carries the excluded-open count and the oldest open age. MTTR over closed
    findings is a survivor statistic: the slowest remediations are the ones still open, so
    the mean *improves* as remediation stalls.

- **Composite Cloud Risk Score** (`aws_riskscore.py`, `docs/RISK_MODEL.md`) — `OW2-CC-001`
  through `006`, with three defects in Appendix B corrected. See **Fixed**, D1/D2.

- **KRA metric layer** (`aws_kra.py`, `docs/KRA_METRICS.md`) — the five metrics of
  `OW2-KM-001`, the derived metric dictionary `OW2-KM-002` requires, and the proposed
  requirement `OW2-KM-007`. See **Fixed**, D3.

- **CI/CD guardrail decision layer** (`aws_guardrail.py`,
  `docs/GUARDRAIL_FAILURE_MODE.md`) — enforcement modes, the declared failure mode,
  break-glass and the central record. See **Fixed**, D5.

- **Trend collection and sufficiency gating** (`aws_trend.py`,
  `docs/FORECAST_SEQUENCING.md`) — `OW2-PA-001`, `OW2-PA-006`, `OW2-PA-007`. See
  **Fixed**, D6.

- **Credential-exposure ingest** (`aws_ingest_credexp.py`) — joins breach-corpus records
  (a DeHashed export, or any equivalent) to cloud identities, so an administrator learns
  that an identity with estate access appears in a public dump. Three decisions, each
  recorded in the module:
  - **No network calls.** The zero-telemetry tripwire allows egress in exactly three
    files and this does not become a fourth. Querying a breach service sends the
    customer's *people* to a third party — the operator's decision, not the scanner's.
  - **Credential material never enters the product.** `normalize()` builds a new record
    from an allowlist, so an unrecognised future field is dropped by default rather than
    by recognition. A tool that stores leaked passwords becomes a more attractive target
    than the estate it watches.
  - **A hit is not a compromise.** Provenance is `OBSERVED` for the *corpus*, with an
    explicit note that it does not establish the credential still works.
  - Vendor-neutral by construction: DeHashed's API contract could not be verified, so
    field names live in an alias map rather than in the logic.

### Changed

- **The posture score now carries its coverage, and the letter grade is withheld below
  90%.** `compute_risk_score` counts only the FAILs it *saw*, so a check that returned
  AccessDenied contributed no penalty and the score went **up**: on a four-check example,
  losing `iam:ListUsers` moved an account from 75/C to **85/B**. The scan got worse and
  the grade improved — and that number feeds `scans.posture_score` and 24 months of trend.
  - **The arithmetic is unchanged, deliberately.** Silently re-weighting a shipped score
    rewrites every dashboard and every stored trend. For a complete scan the output is
    byte-identical and the caveat is empty; what changes is the letter grade, which is the
    artefact that gets copied into a board pack without its caveat.
  - `unassessed_penalty` is the honest middle: rather than scoring a refused check as a
    pass (previously) or as a failure (equally invented), it reports the band that could
    not be assessed. The reported score is a **ceiling**.

- **`aws_sla.closure_rate` returns a `ClosureRate` rather than a tuple.** The bare
  `(pct, in_sla, considered)` return is gone on purpose — a caller that *can* ask for the
  flattering number alone eventually will. See **Fixed**, D4.

### Fixed — six defects in OW2-SRS-001

- **D1 — Appendix B carries three defects, not one.** The weights sum to **95**, not 100.
  Every factor is one where *more means worse*, and the table then bands the result
  `A ≥ 90` — so **an estate with maximum severity, exploitability and exposure scored 95
  and earned an A**. And compensating controls were a sixth weight (see D2).
  - Normalisation moved **into the engine** rather than renumbering the table:
    renumbering fixes the instance, normalising fixes the class. Weights are now relative,
    so ratifying a tidier 100-sum table will not move anybody's published score.
  - Direction resolved: risk ascends, `posture = 100 − risk`, and the grade bands the
    posture — which is the convention `compute_risk_score` already used, so FR-1 and FR-2
    stop disagreeing and neither has to move.
  - A factor with no data is **excluded and its weight redistributed**, never scored
    `0.0`, which would lower the risk of an estate nobody measured. Below 50% weight
    coverage the composite is refused.

- **D2 — Compensating controls were credited into the wrong number.** `OW2-CC-002(e)`
  reduced the score for EDR presence or PAM vaulting. An EDR sensor does not make an
  internet-reachable unpatched host less reachable; it makes the consequence more likely
  to be *noticed*. Credited as a weight, an estate improved its published score by buying
  tooling without changing a single exposure.
  - The credit now applies **only to `CREDITABLE_FACTORS`** — `findings` alone. Exposure
    is never creditable and the model refuses construction if it is declared so.
  - **This does not preserve Appendix B's 15-point magnitude**, and that is the point: the
    honest effective ceiling is ~4.7 points. Keeping the size while fixing the instrument
    would have been having it both ways. The effective ceiling is published rather than
    left to be found by subtraction.
  - A **missing** exposure-gate verdict now withholds the credit rather than granting it.
    An unevaluated exposure is not a cleared one.

- **D3 — Nothing distinguished "clean" from "never looked at".** Every KRA is a ratio or
  count whose denominator comes from enumeration, and enumeration is exactly what fails
  when a permission is missing: lose `iam:ListUsers` and MFA coverage reports **100%**;
  lose a region and internet-exposed critical workloads reports **zero**. Both are the
  stated target. The reward for losing visibility was a better number.
  - A metric over a partial population now yields an **interval, not a value**, and a
    verdict is asserted only where the whole interval supports it. **`NOT_MET` survives
    incomplete data; `MET` does not.**
  - `NOT_ESTABLISHED` occupies its own column — folding it into *met* is the defect;
    folding it into *not met* blames the estate for a permissions problem.
  - Where the denominator itself is unreadable, **no value is reported at all**.

- **D4 — The exception workflow could carry the headline KRA alone.** `OW2-AR-031` pauses
  the SLA clock under an approved exception, so a CRITICAL finding remediated on **day
  200** against a 15-day window counted as closed-within-SLA. **One approval moved
  `OW2-KM-001(a)` from 0% to 100%.** `OW2-KM-004`'s register is right and insufficient —
  a register is not a metric, and only metrics reach the BBSC.
  - Pausing is **not removed**; exceptions exist for real reasons. The adjusted and
    unadjusted rates now render **together**, so the flattering figure cannot be emitted
    alone, and the gap between them is exactly how much of the headline an approval bought.
  - Two new KRAs, **both targeting zero and neither target arbitrary**: exception-assisted
    closures and deferred breaches. They measure the two places where an approval changes
    *what a number says* rather than *what the estate is*.
  - Serial renewal is surfaced — `OW2-KM-003`'s mandatory expiry stops an exception being
    *formally* permanent, not one assembled from individually reasonable approvals.

- **D5 — FR-5 never said what a blocking gate does when it is down.** `OW2-GR-003`
  defaults production to block; `OW2-IF-001` protects *scanning* and is silent on the
  pipeline. Fail-closed halts every production deploy including the fix for the outage;
  fail-open silently disables the control estate-wide behind green checks.
  - **An unavailable gate now does what its strictest configured mode would have done**,
    so losing the service can neither silently downgrade nor silently escalate enforcement.
  - Every permissive path is a *degraded allow* or an *attributed override* — both
    **exit 2**, neither ever rendered as a pass. Exit 2 mirrors the evidence verifier,
    where 2 already means *unauthenticated* rather than *failed*.
  - Break-glass is expensive on purpose (actor, real justification, mandatory expiry,
    weekly report) and an **expired override blocks** rather than degrading to a warning.
  - A pipeline that stops waiting treats the absence of a result as an incomplete
    evaluation, not consent. A CI config reading its own timeout as success is the
    cheapest way to disable the whole control while leaving every pipeline green.

- **D6 — FR-4 was scheduled to begin the month its data does.** AD-04 requires six months
  of clean trend data; §2.7 puts FR-4 in II-C, months 6–12, which *begins* when that data
  starts accumulating. Every Phase II forecast would carry the `OW2-PA-006` insufficiency
  label. Separately, the II-C gate requires accuracy tracking enabled — but a 30-day
  forecast made in month 12 resolves in month 13, **so the gate cannot be met as written**.
  - The code **refuses rather than labels**. A label is a string beside a number, and the
    number is what reaches the slide. Below three usable periods there is no projected
    value at all; the observed series is still reported, because what was measured is a
    fact and only the extrapolation is a claim.
  - **Six months elapsed is not six months of data.** Sufficiency counts *usable* periods,
    so a forecast built on six months of holes cannot report itself as production-grade —
    the D3 rule reaching forward into FR-4.

### Documentation

- `docs/RISK_MODEL.md` — replacement text for Appendix B (closes Appendix D item 2).
- `docs/KRA_METRICS.md` — proposed `OW2-KM-007` and `OW2-KM-001(f)/(g)`.
- `docs/GUARDRAIL_FAILURE_MODE.md` — proposed `OW2-GR-008/009/010`.
- `docs/FORECAST_SEQUENCING.md` — the FR-4a/FR-4b split and the II-C gate amendment.

### Notes

- **The new modules are libraries with no console surface yet.** `ExposureGate` has no
  producer, the risk score is not wired to live factor inputs, and the trend series is not
  wired to scan history. All three are safe un-wired — each *withholds* rather than
  assumes — but un-wired is un-wired, and slice 2 is where that changes.
- `VERSION` had drifted two releases behind the tags (2.35.0 against `v2.37.0`) and is
  corrected here.
- Suite: **5,285 passing**, up from 4,996.

## [2.37.0] — 2026-08-26

Four features, all additive, cut together because the CHANGELOG had drifted four
commits behind the `v2.36.0` tag — the same drift that release fixed, restarting.

### Added
- **Signed compliance evidence bundles** (`aws_evidence_bundle.py`,
  `scripts/overwatch_evidence.py`, `GET /accounts/{id}/evidence-bundle`).
  `aws_evidence.build_pack` already produced the artifact no competitor does — a
  control-by-control record including **which controls the scan never reached** — but it
  left the machine as a printout: it asserted things about a scan and nothing about it
  could be checked. The vendored Ed25519 already shipped too, used only to *verify* the
  offline vuln feed. This connects them, inverted: there the publisher signs and the
  runtime verifies; here the operator signs their own evidence and their auditor verifies.
  - **The coverage manifest is inside the signed root.** Stripping "these controls were
    never assessed" breaks verification. If signing made an incomplete scan easier to pass
    off as a clean one it would be worse than not signing at all.
  - **The bundle states what its own signature does not prove** — not completeness, not
    that the role could reach everything, not that the mappings are right — and that text
    is itself signed, so the limits cannot be edited out of a valid artifact.
  - `generated_at` is the generating host's clock, **not** a trusted timestamp. An RFC 3161
    TSA is a network call, which air-gap and zero-telemetry both forbid; the root digest is
    published for counter-signing instead.
  - A **digest tree** under the signature, so verification reports *which* section was
    edited. "Invalid" is not an actionable answer for an auditor.
  - The verifier is **stdlib-only** and runs with no OverWatch install, no AWS access and
    no network. An auditor should not have to trust the tool that produced the evidence in
    order to check it.
  - Signing happens on the **hub**, never in the browser: every other export on the Reports
    screen is assembled client-side, which is right for a JSON dump and catastrophic for a
    signature. The console requests a bundle; the key never leaves the server process.

- **Top Risks by Category** (`/top-risks`, `frontend/src/lib/toprisks.ts`) — the worst ten
  in each of ten risk domains on one screen, each card linking to its full-page roll-up.
  A row shows a **number only when a real one exists** (an attack-path score, or a
  published CVSS) and its severity band when it does not. The reference dashboard puts a
  1–10 to one decimal on every row; we do not compute one, and printing it would invent a
  precision the scan never produced.

- **Full-screen attack path view** (`frontend/src/components/AttackPathCanvas.tsx`,
  `frontend/src/lib/pathmodel.ts`) — pan/zoom, per-hop narrative, ATT&CK tactic per hop,
  and **the basis of every hop**: the graph already recorded *why* each edge exists
  ("0.0.0.0/0 security group", "instance profile", "iam:PassRole + sts:AssumeRole") and
  nothing rendered it. That string is the difference between "these two things are
  connected" and "here is the thing to revoke".

- **Authored Controls** (`cnapp_customcontrol.py`, schema **v16**, `POST`/`PUT`/`DELETE
  /controls`, `POST /controls/preview`). A saved WQL query became a managed object rather
  than an environment variable read once at boot and identical for every workspace. The
  WQL validator runs on **write**, so a bad query is a message to its author rather than an
  inert control that silently matches nothing; controls cannot cross a workspace; and an
  authored control renders **WARN, never FAIL**, so a customer's own query can never move
  the posture score it is being measured on.

### Fixed
- **An empty coverage section read as "nothing was missed."** `build_bundle(coverage=None)`
  emitted `{}`, which verified cleanly and told an auditor the scan had no gaps. Absence
  and emptiness are different facts, and collapsing them was the exact phantom pass the
  bundle exists to prevent. Absent coverage is now `{"available": false, "note": ...}`,
  and the flag is covered by the signature so it cannot be flipped.
- **`overwatch-evidence keygen` claimed `mode 0600` unconditionally.** Windows does not
  honour POSIX mode bits, so it wrote `0666` while telling the operator their signing key
  was protected. It now stats the file and reports what the filesystem actually did.
- **`overwatch-evidence verify` printed a bare `[OK]` without `--pub`** — the case a
  hurried auditor hits, and one a forger signing their own edited bundle satisfies exactly.
  It now prints `[OK, UNAUTHENTICATED]` with the caveat, and **exit 0 means "signed by the
  key I named"**; unauthenticated is exit 2, so a CI gate can tell them apart.
- **The demo seeder built its graph beside its paths rather than from them** — only
  `internet` appeared in both, so 1 of 11 path node ids existed in the graph and any view
  joining the two rendered empty. `_graph`'s own docstring claimed the opposite. Paths are
  now walked out of the graph, with three ratchets holding it.
- **A React hook was called after an early return** in the Reports screen, changing hook
  order between renders. Caught by the linter, not by me.

## [2.36.0] — 2026-08-26

### Added
- **Depth pass 2 — the lockstep backlog reaches zero.** `test_check_maps_lockstep`
  carried a shrink-only backlog of checks that scored while mapping to no framework,
  offering no remediation, and rendering an empty detail panel. Depth pass 1 took the
  16 CRITICAL/HIGH ones; this takes the remaining 52 (31 MEDIUM, 20 LOW, and `CFN-01`,
  which had a detail page but no remediation). **All 452 checks now have all three.**
  - Every entry was written from the check's **emission site**, not its name, because
    several read backwards from the name alone. `DDB-03` is a billing-mode observation
    that only ever emits INFO on the provisioned case, not a security control.
    `EKS-04` reports the Kubernetes version and deliberately does not judge it, because
    the EKS support calendar moves and a hard-coded threshold would be wrong within a
    release. `SQS-04` fires on retention **above** 14 days — a stalled-consumer signal,
    not a retention-too-short one. `SECRET-02`, `SEC-03` and `SFN-03` are all
    AWS-managed-key vs CMK findings: the value **is** encrypted, and `SECRET-01` is the
    plaintext one. `ELB-08` checks target *health*, so it reports either an orphaned
    load balancer or a live outage and the write-up has to separate them.
    `EBS-05`/`EC2-09`/`RDS-13`/`ELB-08` are cost hygiene — fail-open, no posture-score
    weight — and saying so matters, because a security framing would misrank them.
  - `IAMPE-18` fires on `ssm:SendCommand` **or** `ssm:StartSession` (one requirement,
    two alternatives) and matches at **action level only** — Resource ARNs and
    conditions are not evaluated, so a grant scoped to one development instance
    produces the same finding as `Resource: "*"`. The write-up leads with that, since
    ranking it without checking scope is the mistake it invites.
  - Filled the 7 checks that scored while mapping to **no framework at all**
    (`CFN-04`, `FARGATE-01`, `GLC-03`, `R53-04`, `RDS-05`, `SFN-02`, `SQS-04`). All 7
    NIST controls were verified against the frozen 38 in `compliance/crosswalk.json`
    **before** writing, rather than discovered to be outside it afterwards — which is
    how `SI-12` and `CM-3` were caught in the two previous passes.

- **`test_the_backlog_is_empty_and_stays_that_way`** — the ratchet's terminal state.
  The easy way to make the coverage ratchet pass is to add the failing id back to a
  backlog, which converts a hard failure into a silent one: the exact regression the
  backlog was introduced to end. Verified by injecting a repopulated backlog and
  confirming the guard fails, with an assertion that the mutation actually applied.

### Changed
- **`kubectl` now counts as a runnable remediation command**, in both copies of that
  assertion (`test_check_maps_lockstep` and the older `test_live_scanner`). `KSPM-04`
  fixes a Kubernetes object — `automountServiceAccountToken` — that no AWS API can
  touch. Inventing an `aws` command for it would have been worse than the prose the
  assertion exists to reject. `FARGATE-01` genuinely did have an AWS-CLI remediation
  and now names it.

### Removed
- **`coverage_gap.json` is no longer committed.** It was generated output with no
  currency test, which is the condition under which a stale ranking reads as a current
  one. Regenerate with `python scripts/coverage_gap.py`.

### Added
- **`tests/test_registry_import_order.py`** — registry projections must not depend on
  import order. `aws_checkdef` is populated as a *side effect* of importing the modules
  that declare checks, and the three consumer modules merge that registry at import
  time. A consumer that fails to import a declaring module therefore merges a **partial**
  registry, and which projections exist depends on what happened to be imported first.
  - That is the `MCP-06` defect, generalised: neither `aws_finding_detail` nor
    `aws_perm_ledger` imported `aws_mcp`, and the first verification imported `aws_mcp`
    first, so it reported everything present. A registry merge is invisible to the
    dict-literal ratchets, so this is the only place the coupling can be caught.
  - The check imports each consumer **alone, in a fresh interpreter** — the condition
    that actually failed — and separately asserts, from source, that every declaring
    module is imported by every consumer.
  - **Verified by reintroducing the defect**, and that verification needed fixing too:
    the first attempt reported success while changing nothing, because the injection
    string did not match and the script printed unconditionally. It now asserts the
    mutation applied before drawing any conclusion. A guard that has only been seen to
    pass is not a guard.

- **`MCP-06` — AgentCore registry approval state**, the other half of what the SDK pin
  unlocked. A registry exists to put a review between an agent component and the fleet
  that will use it, so a record in `DRAFT`, `PENDING_APPROVAL` or `REJECTED` is a
  governance step that did not complete — while the registry's existence implies
  components are vetted. The check is explicit about what it does **not** establish:
  the registry records approval state, not consumption, so an unapproved record is a
  governance gap rather than evidence something unreviewed is live.
- **Depth pass 1 — 16 CRITICAL/HIGH checks that scored with no remediation and no
  explanation** now have both, and their ids are deleted from the frozen backlog.
  `ECS-01/02`, `CFN-02/05`, `ELC-03`, `LMB-03`, `OSR-05`, `SNS-02/03`, `SQS-01` and six
  `IAMPE-*` privilege-escalation techniques. The lockstep test's own words are the
  reason: *"a check that scores but cannot be explained or fixed is worse than no check
  at all"* — 67 checks were exempt from that rule by a grandfather clause, and this
  removes the 16 worst.
  - Each was written from its **emission site**, not from its id. That mattered:
    `SQS-01` is encryption at rest, not public access, and would have been documented
    backwards from the name alone.
  - `CFN-05` also gained the compliance mapping it lacked. **51 checks still lack a
    detail page** — all MEDIUM or below.

- **Extended service coverage, batch 7** (`aws_extsvc7.py`, 6 sections, 8 checks) — the
  first batch chosen **against** the ranking rather than from the top of it. By this
  point the highest score was 14, and the heuristic reads operation *names*: it puts
  CloudFormation and Firewall Manager at 5, below AWS Wickr, because `GetStackPolicy`
  and `GetPolicy` are unremarkable strings attached to the two most consequential
  services in the batch. That is a limit of the tool, and the response is to say so and
  choose deliberately rather than to invent a cleverer regex.
  - **CloudFormation** (`STACK-01/02`) — a stack is the *definition* of its
    infrastructure, and an update is an instruction to make reality match a new template.
    Without a stack policy, anyone who can call `UpdateStack` can replace or delete any
    resource it owns; without a service role, operations run with the **caller's**
    permissions, and on an IAM-capable stack a template change can mint identities while
    reading as ordinary infrastructure work.
  - **Firewall Manager** (`FMS-01/02`) — a policy with remediation disabled evaluates
    every account and changes nothing. Its *existence* is what people rely on: a review
    finds an org-wide WAF policy and concludes the WAF is applied. With no notification
    channel as well, the control reports to a console nobody is watching.
  - **ECR Public** (`ECRPUB-01`) — a public registry is readable by design, so
    readability is never the finding. **Write** is: anyone can publish under your
    namespace, and the namespace *is* the provenance signal a consumer has.
  - **Multi-Party Approval** (`MPA-01`) — a team requiring one approval is worse than no
    approval workflow, because it produces every artefact of one: a submission, a
    recorded approval, an audit trail, and a reviewer who concludes separation of duties
    is in force.
  - **Wickr** (`WKR-01`, INFO) and **MediaPackage v2** (`MPV-01`) — retention on an
    end-to-end encrypted messenger, reported as *context* because it is often a
    regulatory requirement and also the one setting that puts plaintext somewhere
    durable; and channel policies, which govern who may **ingest** to a live stream.
  - **A prefix collision avoided by checking rather than by luck.** CloudFormation's
    checks are `STACK-*`, because `CFN-01` through `CFN-06` already exist and are
    **CloudFront** — their remediations call `aws cloudfront update-distribution`.
    Reaching for the obvious prefix would have silently overwritten six live checks,
    which is the `SEG-01` defect this codebase has shipped once already.

- **Extended service coverage, batch 6** (`aws_extsvc6.py`, 6 sections, 9 checks) —
  Verified Permissions, CloudHSM, Cloud WAN, Managed Grafana, Aurora DSQL, IoT FleetWise.
  - **Verified Permissions** (`VP-01/02`) — a Cedar policy store *is* an application's
    authorization logic. With schema validation `OFF`, a policy referencing an entity
    type that does not exist is accepted without error: it **never matches**, and a
    policy that never matches is indistinguishable from one that was never written. A
    reviewer reads it and concludes the rule is in force.
  - **CloudHSM** (`HSM-01/02`) — a backup is the *one* artefact that leaves an HSM, and
    it is restorable into another cluster. So retention decides how many restorable
    copies of your key material exist, and a wildcard resource policy shares the key
    material itself — the single thing the service exists to prevent. No rotation undoes
    a copy already taken.
  - **Cloud WAN** (`NWM-01`) — the core network policy is the segmentation design of an
    entire global network: segments, routing between them, every attachment. Reading it
    is reading the map an attacker would otherwise assemble slowly and noisily.
  - **Managed Grafana** (`GRF-01`) — `ORGANIZATION` access means the workspace role
    reaches *into* other accounts to read data sources, and logs are the least curated
    data any organisation holds. The effective audience is set by the workspace's
    authentication config rather than by IAM, and those are usually different people.
  - **Aurora DSQL** (`DSQL-01`) and **IoT FleetWise** (`FW-01/02`) — deletion protection;
    and vehicle telemetry, where a location history is among the most re-identifiable
    datasets that exists.

- **`scripts/coverage_gap.py`** — the ranking tool that drives this programme, promoted
  out of a scratch directory into the repo, because across six batches a fix to it lived
  nowhere. Two corrections came with it:
  - **It deduplicates by signing name now.** `es` scored 16 as an uncovered gap, and `es`
    and `opensearch` are the *same service* at different API versions — `opensearch` was
    already covered. Keying on client directories counted one service twice. That also
    shrank the catalogue from an apparent **426 services to 360**.
  - **It excludes discontinued services.** Three of the four highest-ranked remaining
    gaps could not be built at all: MediaStore (support ended **2025-11-13**, already
    declined in batch 4) and **AWS WAF Classic**'s two clients (**2025-09-30**; `wafv2`
    is the covered successor). Liveness checking became routine after MediaStore, and
    this batch is why it should stay routine.
  - Honest totals after both fixes: **89 of 360 services covered, 67 uncovered and live**
    — and the highest remaining score is now **14**, down from 87 when the programme
    started. The valuable tail is genuinely thinning.

- **Extended service coverage, batch 5** (`aws_extsvc5.py`, 5 sections, 8 checks) — the
  first batch authored *after* the SDK pin moved, so the models these were verified
  against are finally the models the product ships.
  - **Amazon WorkMail** (`WM-01/02/03`) — a mailbox is a credential store with a login
    page: password resets, MFA enrolment and signed approvals all arrive there, which is
    why mailbox compromise is usually the first step rather than the objective. Without
    access control rules any protocol is reachable from any network; without mobile
    device rules any personal phone holds a **persistent offline replica that survives
    credential revocation**; without retention, a compromise today exposes the entire
    history, because nothing that was never deleted can be un-exposed.
  - **AWS IoT SiteWise** (`SW-01/02`) — industrial telemetry from physical plant: asset
    hierarchies describing how a facility is built, process values that are evidentiary
    in a regulated plant. Logging defaults to `OFF`, and tampering with telemetry
    surfaces first as an ingestion anomaly — with nowhere to appear.
  - **AWS IoT Managed Integrations** (`IMI-01`) — a 2025 API that ships with its own
    default key, so an account arrives there by not choosing. It holds connection
    material for **third-party device clouds**: an outward path into systems whose logs
    you cannot read.
  - **SES Mail Manager** (`MM-01`) — `DefaultAction=ALLOW` fails **open**. A policy with
    a long list of DENY statements reads as filtering, when it is filtering an
    enumerated set and delivering everything else.
  - **Amazon CodeGuru Profiler** (`CGP-01`) — profiles are production stack traces, so
    the method names in them are a map of the application's internals assembled from the
    running system.
  - **Two more client-name/IAM-prefix traps, both caught automatically this time.** Mail
    Manager signs as **`ses`**, and CodeGuru Profiler's prefix is **`codeguru-profiler`**
    with a hyphen. These are the fourth and fifth instances; every previous one needed a
    human to notice, and `test_iam_surface` validated both without being asked.

- **Extended service coverage, batch 4** (`aws_extsvc4.py`, 5 sections, 8 checks).
  - **AWS Lake Formation** (`LF-01/02`) — the most consequential setting in the batch.
    `IAM_ALLOWED_PRINCIPALS` in the default database or table permissions means Lake
    Formation **does not evaluate its own grants at all** for those resources, and plain
    IAM governs the data: every column-, row- and tag-level grant the data team
    configured is simply not consulted. Nothing looks wrong — the console shows a fully
    configured Lake Formation — and it is the backwards-compatible default, so an estate
    arrives here by changing nothing. `LF-02` covers the half most often missed: clearing
    the default does **not** revoke grants already made.
  - **Amazon WorkSpaces Web** (`WSW-01/02`) — a managed browser that exists to reach
    internal applications, so it is a sanctioned path from outside to inside. Without IP
    access settings that path opens from anywhere; without logging there is no record of
    what was reached, and the internal application's own logs show only the service
    fleet.
  - **AWS Storage Gateway** (`SGW-01/02`) — an NFS share whose `ClientList` contains
    `0.0.0.0/0` is mountable by anything that can route to the gateway, and the share is
    a window onto S3 through a path where **no bucket policy, IAM principal or per-caller
    CloudTrail event applies**. NFS authenticates by network position, so the allow-list
    is not one control among several — it is the control.
  - **AWS Payment Cryptography** (`PAY-01`) — an `Exportable` key. The hardware boundary
    is the entire reason this service exists rather than KMS, and exportability makes it
    optional. Legitimate for a documented key ceremony with an acquirer; it should not be
    incidental, and it **cannot be revoked after creation**.
  - **Amazon Managed Blockchain** (`MBC-01`) — a member with no CA log publishing. The
    CA is what enrols identities onto a shared, immutable ledger: the ledger records what
    happened, the CA log is what records who was allowed to.
  - 12 read actions added to **both** deploy templates.

- **AWS Elemental MediaStore was requested and is deliberately NOT built.** AWS ended
  support for it on **13 November 2025**, nine months before this batch. Its container
  and CORS policies would have been reasonable checks while the service existed; against
  a discontinued service they can never fire, while costing the same wiring, deploy
  grants, ledger entries and tests as a live service. **A check that cannot fire is worse
  than no check, because it reads as coverage.** The omission is pinned by a test rather
  than left as an oversight.

- **The pinned permission expectations are generated, not hand-typed**
  (`tests/perm_ledger_baseline.py`). `test_perm_ledger` and `test_perm_ledger_wiring`
  pin the exact IAM actions the shipped role lacks and the checks that are blocked as a
  result. Pinning is right — the permission surface is what a customer approves — but
  *hand-maintaining* the lists produced the same class of mistake in all three
  service-coverage batches: `rds` sorts before `s3`, `codebuild` before `ec2`, and a
  block pattern that would not match a trailing bracket silently orphaned the last entry
  of every list it touched. Twice the lists had to be restored from git.
  - The data is now generated and committed, exactly like `test_suite_ratchet`:
    `python tests/perm_ledger_baseline.py --update`. **The ratchet survives** — a change
    lands in the diff where a reviewer sees it — while sorting, commas and brackets stop
    being anybody's problem.
  - Deliberately **not** a self-deriving assertion. Computing the expectation at test
    time would make it tautological and delete the thing it protects; instead the
    committed baseline is compared against a live evaluation, and adding a check fails
    the suite until somebody regenerates.
  - `--update` is checked for **idempotence**, because the suite ratchet's own `--update`
    once corrupted its file with an off-by-two slice.
  - Test names no longer state counts. `..._is_missing_exactly_thirtytwo_actions` became
    `thirtyfour`, then `fiftyone`, then `eightytwo` in a single session — a name that
    states a number is a durable lie waiting to happen, and a test now forbids the shape.
  - The literals were replaced using **`ast` node spans** rather than pattern matching.
    Three regex attempts produced three different corruptions; `ast` was correct first
    time, which is the lesson.

- **IAM prefixes are checked against botocore** (`tests/test_iam_surface.py`). Three
  times a boto3 *client name* has been mistaken for an IAM *prefix*:
  `bedrock-agentcore-control` vs `bedrock-agentcore`, `sso-admin` vs `sso`, and `amp` vs
  `aps`. Each would have produced a policy that **grants nothing while reading correctly
  in review**, and all three were caught by hand. botocore already knows the answer, so
  the fourth is caught by a test.
  - `signingName` **wins**, with `endpointPrefix` only as a fallback for services that
    omit it (EMR's client dir is `emr`; only `endpointPrefix` reveals the IAM prefix is
    `elasticmapreduce`). Taking both would have defeated the guard entirely — `amp` and
    `bedrock-agentcore-control` are their own `endpointPrefix`, so the table would have
    accepted exactly the spellings the test exists to reject. A negative test caught
    that in the first draft.
  - Also re-asserts the read-only charter over the **legacy** `REQUIREMENTS` literals,
    which predate `aws_checkdef` and so were never validated at declaration.

- **Extended service coverage, batch 3** (`aws_extsvc3.py`, 6 sections, 9 checks) — the
  first batch written on `aws_checkdef` from the start rather than retrofitted onto it.
  Both the check-map lockstep and the CFN/Terraform parity test **passed on the first
  run**; batches 1 and 2 each needed a corrective pass for one of those.
  - **S3 Tables** (`S3T-01/02`) — a table bucket is a distinct resource with its **own**
    policy API and its own encryption settings, so an account can pass every existing S3
    check while its analytical data is world-readable. What sits behind one is usually
    the joined and enriched end of the estate, which makes a single table more revealing
    than the sources it was built from.
  - **VPC Lattice** (`LATT-01/02`) — `authType` has two values and one is `NONE`: no
    caller identity at all. Lattice exists to connect services *across* VPC and account
    boundaries, so "anything that can reach it" is a far wider set than one VPC.
    `LATT-02` is the subtler case — `AWS_IAM` with a wildcard auth policy looks correct
    in review, and answers authentication properly while leaving authorization open.
  - **CodeArtifact** (`CART-01`) — a permissive domain or repository policy exposes
    private packages, and more durably the **dependency graph and internal library
    names**. That is the reconnaissance dependency confusion needs, and unlike the code
    it cannot be un-learned once seen.
  - **Directory Service** (`DIRSVC-01/02`) — `LDAPSStatus` of `Disabled` means plain
    LDAP: bind credentials in cleartext for the authentication layer under every joined
    system. `EnableFailed` is reported too, because it looks configured and protects
    nothing. Sharing is reported as WARN — it is a normal pattern, but it extends an
    **authentication** boundary rather than sharing one resource.
  - **Managed Prometheus** (`AMP-01`) — a workspace with no CMK. The numeric values are
    not the sensitive part; the **labels** are: hostnames, service topology, tenant
    identifiers — a continuously-updated map of the estate.
  - **X-Ray** (`XRAY-01`) — traces routinely carry full request URLs, headers and
    annotated SQL fragments, so a trace store is a readable log of what the application
    does with its data. The setting is Region-wide, which makes it easy to set once and
    forget elsewhere.
  - 16 read actions added to **both** deploy templates. Note the IAM prefix for Managed
    Prometheus is **`aps`**, not the `amp` client name — the third instance of that trap
    in this codebase after `bedrock-agentcore` and `sso`/`sso-admin`, and each time a
    policy written with the client name would grant nothing while looking correct.

- **`aws_checkdef.py` — declare a check once, derive every map from it.** A new check
  cost edits in five places: `CHECK_SEVERITY`, `COMPLIANCE_MAP` and `REMEDIATION_MAP` in
  `aws_live_scanner`, `FINDING_DETAIL` in `aws_finding_detail`, and `REQUIREMENTS` in
  `aws_perm_ledger`. At 385 checks that was tolerable; with 110 uncovered services still
  to go it had become the dominant cost of adding coverage — and five chances to get one
  check half-declared.
  - `test_check_maps_lockstep` already caught a half-declared check, and it is a good
    test — but it caught it *afterwards*. **A `CheckDef` cannot be constructed unless
    every projection is present and well-formed**, which moves the same invariant from
    test-time to definition-time: the failure stops being "someone forgot the detail
    page" and becomes "this does not import".
  - Validated at declaration: severity in the known set, **all four** compliance
    frameworks present (the evidence pack counts *controls*, so a gap silently shrinks a
    denominator), a remediation carrying a runnable `aws` command, a risk narrative long
    enough to decide on, and at least two remediation steps.
  - **The charter is enforced structurally.** A `Perm` naming anything but a read verb is
    rejected as a charter violation, so `read-only-of-CONFIG` stops being a convention
    that review has to catch.
  - **The collision guard is the point.** Merging by `dict.update` bypasses the
    duplicate-key ratchet, which parses dict *literals* as source and cannot see a
    registry merge — so `merge_*` refuses to overwrite an id that already exists. That is
    the `SEG-01` defect (a new check silently replacing a real one's remediation, with
    nothing failing anywhere) caught structurally rather than by a test that happened to
    be written.
  - It does **not** migrate the 399 existing checks. Rewriting nearly four hundred
    hand-authored entries to prove a point would be a large, risky diff with no
    behavioural benefit. This is an additive second path; the old literals keep working.

- **Extended service coverage, batch 2** (`aws_extsvc2.py`, 6 sections, 10 checks) — the
  first consumer of the registry. The clearest evidence it works is what is *absent*:
  batch 1 needed a hand-written detail page per check plus a lockstep test to catch the
  forgotten ones; batch 2's lockstep passed with no extra work at all.
  - **Network Firewall** (`NFW-01/02/03`) — a firewall with no `LogDestinationConfigs`
    inspects traffic and records none of it. A stateless default action of `aws:pass`
    means unmatched packets are **forwarded**, so the firewall fails *open* and the
    stateful rule groups are never consulted. Delete and change protection off means the
    inspection point can be removed rather than defeated — and detaching a firewall from
    its subnets is far quieter than deleting it.
  - **Lightsail** (`LSAIL-01/02`) — its own console and its own firewall model, which is
    *not* security groups, so these rules are invisible to an EC2 security-group audit
    including OverWatch's own. Plus publicly-accessible managed databases, where the
    master password is the only control in front of the data.
  - **ACM Private CA** (`PCA-01`) — a private CA is a **trust root**. A wildcard
    principal lets anyone mint certificates the estate trusts by construction, and the
    resulting certificates are genuine, so they appear in no list of compromised material.
  - **QuickSight** (`QS-01`) — `PublicSharingEnabled` permits dashboards over your
    warehouses to be published to anonymous readers. QuickSight reads the warehouse with
    its own credentials, so a public dashboard is a data export path that **bypasses the
    datastore's access controls entirely**.
  - **IAM Identity Center** (`SSO-01`) — a permission set granting `*` on `*` is
    administrator in every account it is provisioned into, for everyone assigned it. It
    is close to invisible from below: each account sees an ordinary IAM role with no
    indication the grant is central or who holds it.
  - **Glue** (`GLUE-01/02`) — `ReturnConnectionPasswordEncrypted=false` makes
    `glue:GetConnection` a **credential dispenser**: it returns stored database passwords
    in cleartext, typically for the production stores. A permission that reads like
    metadata access is not one. Plus catalog encryption mode, and dev endpoints with a
    public address — interactive shells holding the endpoint's IAM role.
  - 15 read actions added to **both** `deploy/cnapp-scanner-role.yaml` and the Terraform
    module. Note the IAM prefix for Identity Center is **`sso`**, not the `sso-admin`
    client name — the same trap as `bedrock-agentcore`, where a policy written with the
    client/endpoint name grants nothing and looks correct in review.

- **Extended service coverage, batch 1** (`aws_extsvc.py`, 6 new sections, 14 checks).
  OverWatch instantiated **60** boto3 clients. botocore ships service models for
  **426** services, and **116** of the uncovered ones expose read APIs that answer a
  real security question. This is the first batch off that gap analysis.
  - **The catalog page was the wrong source.** `aws.amazon.com/products` is
    JS-rendered and yields a handful of marketing names. The **botocore service models
    already on disk** are strictly better for this purpose: complete, versioned, and
    they name the exact operations and enum values. A service only has detectable
    *configuration* if it has a `Describe`/`Get`/`List` API — and a check written
    against a field nobody returns looks like a clean pass forever.
  - Uncovered services were **ranked by their actual security-relevant read surface**
    (resource-policy and public-access operations weighted highest, then encryption and
    network, then logging, auth, backup, TLS) rather than by intuition.
  - **AWS IoT Core** (`IOT-01/02/03`) — the largest single gap at 123 read operations.
    An IoT policy attaches to **certificates**, so `iot:*` on `*` is not one
    over-privileged principal, it is every device carrying that certificate — and
    device keys sit in flash on hardware strangers can buy. Also `disableAllLogs`, and
    CAs with `autoRegistrationStatus=ENABLE`, which admit anything they sign.
  - **Amazon EMR** (`EMR-01/02`) — `BlockPublicSecurityGroupRules`, the account-level
    guardrail AWS added because EMR clusters kept reaching the internet with
    unauthenticated cluster UIs; and clusters with no named security configuration,
    which have no at-rest/in-transit encryption and share one role across all users.
  - **AWS CodeBuild** (`CB-01/02`) — `projectVisibility=PUBLIC_READ` publishes build
    logs, which is where credentials, internal hostnames and dependency graphs surface;
    and `artifacts.encryptionDisabled`, an explicit opt-out rather than a default.
  - **Amazon DocumentDB** (`DOCDB-01/02/03`) — a snapshot whose `restore` attribute
    contains `all` is **public to every AWS account**. This is one of very few checks
    in OverWatch that is a direct **observation** rather than an inference, which is why
    it is the batch's only CRITICAL. Also creation-time-only storage encryption, and
    absent audit-log export.
  - **EC2 Image Builder** (`IMGB-01`) — wildcard-principal resource policies, which
    share the golden image and everything baked into it.
  - **AWS Transfer Family** (`XFER-01/02/03`) — plain `FTP` (verified enum
    `SFTP|FTP|FTPS|AS2`) carries credentials in cleartext; FTPS deliberately does **not**
    trigger it. Absent logging role, and a `PUBLIC` endpoint reported as **context
    rather than a defect** — it is the intended mode for many servers, and flagging it
    would flag the normal case.
  - Each is a **top-level section**, not nested inside an existing one. That is a direct
    response to the data-perimeter check, which was hooked inside `_check_iam` and took
    every IAM-section test with it when it spun. A self-contained section can only break
    itself, and a test asserts each one terminates against a bare `MagicMock`.
  - **17 read actions added to `deploy/cnapp-scanner-role.yaml`** as `Batch1ServiceReads`.
    Requested **explicitly rather than assumed**: SecurityAudit may already grant some
    (`rds:Describe*`, `iot:List*`), but that coverage was not verified against the
    published policy document, and a check that silently degrades to a coverage note in
    every real deployment is worse than one that asks for the grant it needs. All are
    read-only — no Put/Create/Delete/Modify appears in the list.

- **Phase 5 · slice 5.2 — data-perimeter posture** (`aws_perimeter.py`,
  `PERIM-01/02/03`). OverWatch has been *recommending* `aws:PrincipalOrgID` in some
  twenty remediation strings and has never once **checked** whether the estate has one.
  This reads the policies that would constitute a data perimeter and reports which of
  AWS's three objectives actually have controls.
  - **The matrix is AWS's, and it is asymmetric** — verified against the *Building a
    Data Perimeter on AWS* whitepaper rather than drawn from intuition, which would have
    produced a symmetric 3x3 and been confidently wrong:
    trusted **identities** -> RCP + VPC endpoint policy (*not* SCP);
    trusted **resources** -> SCP + VPC endpoint policy (*not* RCP);
    expected **networks** -> SCP + RCP.
    The asymmetry follows from what each type governs: an SCP bounds what *your*
    principals may do, so it cannot say who may reach your resources. **A control in the
    wrong policy type is not a weaker perimeter — it is not that perimeter**, and an SCP
    carrying `aws:PrincipalOrgID` is reported as *absent*, not partial.
  - **Presence and shape, never effect.** Establishing that a perimeter *holds* means
    evaluating authorization for every principal, resource and path — not a configuration
    read. A test asserts no emitted string ever says *enforced*, *prevented* or
    *blocked*.
  - **Absence requires a complete read, presence does not.** Positive evidence from one
    layer proves the control exists; claiming it is *missing* requires having read every
    policy type AWS names for that objective. A member-account scan reads the empty
    endpoint layer and is denied Organizations — calling that "no perimeter" would be a
    finding manufactured out of a permission error.
  - Four limits from AWS's own model are **stated in the output** rather than left for
    the reader to know: SCPs do not apply to the management account, service-linked roles
    or service principals; VPC endpoint policies only evaluate on same-Region calls;
    `aws:PrincipalIsAWSService` exceptions are *expected* rather than weaknesses; and
    unreadable is not absent.
  - `aws:VpcSourceIp` is **deliberately excluded** — verification against the
    condition-keys reference came back inconclusive, and asserting a key on a failed
    verification is the phantom the module exists to avoid.
  - **Composes with `5.1`**: `Data / Data access` and `Networks / Network segmentation`
    now reach **Optimal** through the perimeter. Everything previously mapped to those
    functions is a *per-resource* control; CISA's Optimal asks for enterprise-wide rules,
    which is exactly what a data perimeter is.

- **Phase 5 · slice 5.4 — segmentation derived from attack paths**
  (`aws_segmentation.py`, `SEGREC-00/01`). OverWatch already ranks **choke points**, but
  a choke point is usually something you cannot delete — a production role, an instance
  serving traffic. "This node is central" converts into no action. A **network hop** is
  different: a security-group rule is a thing an operator can change on a Tuesday
  afternoon without deleting anything.
  - **Verified, not asserted.** The naive number — count the paths crossing an edge —
    over-claims every time a parallel route exists, because removing the hop leaves the
    same target reachable another way. A path counts as severed only when no surviving
    path reaches the same `(entry, terminal)` pair without the cut edge, and **the gap
    between the naive count and the verified one is reported** rather than absorbed.
  - **Only two of the seven traversable edge kinds are cuttable** (`EXPOSED_TO`,
    `TARGETS`). No firewall rule severs an IAM trust policy. Paths made only of identity
    edges are counted and reported separately — "cutting X severs 8 of 10" while the
    other two are permanently untouchable by segmentation is true and misleading. A test
    asserts the two edge classes still exactly partition `E_PATH`, so a new edge kind
    cannot go silently unclassified.
  - `sg_ids` added to `NetworkInterface` graph nodes: advice that cannot name the
    security group to change is advice nobody can act on. Nothing is invented when the
    props are absent.
  - Emitted as **INFO**: the exposure is already reported by `EXPOSURE-01/02` and the
    paths by `PATHS-01`, so emitting advice as a failure would double-count and inflate
    the finding total with something that is not itself wrong. It is deliberately **not**
    mapped into ZTMM — a function cannot be scored on advice.

- **Phase 5 · slice 5.3 — platform traffic-encryption evidence** (`aws_nitro.py`,
  `NITRO-01/02`). Almost every answer a CNAPP gives about traffic encryption is about TLS
  at an **edge** — a listener, a certificate, a viewer policy. This is the layer
  *underneath*: whether the machines encrypt what they say to each other before any
  application gets a say.
  - AWS's Nitro System does it automatically, but only for supported instance types, and
    support is a property of the **type** rather than something an operator configures —
    so `DescribeInstanceTypes` → `NetworkInfo.EncryptionInTransitSupported` is a readable
    answer to a question almost nothing asks. **`NITRO-01`** reports instances whose type
    provides none; **`NITRO-02`** reports Xen-hypervisor instances, which predate the
    platform generation and cannot use automatic encryption, Nitro Enclaves or NitroTPM.
  - **It composes with `5.1` rather than stacking beside it.** CISA's *Optimal* for the
    ZTMM `Networks / Traffic encryption` function asks for encryption applied *"to the
    extent possible"*, and an edge certificate never touches traffic **between**
    instances. These two checks are the only readable evidence about that layer, so the
    function could not have reached Optimal before this slice existed — the mapping now
    carries them there.
  - **A capability claim, never an observation.** The field says the type encrypts
    automatically; it does not say any particular flow was encrypted, and OverWatch cannot
    watch a packet. A test asserts no finding ever says *"exposed"* or *"intercepted"*.
  - **An absent field is unknown, not unsupported**, and unknown is counted apart from
    unencrypted throughout: an instance whose type could not be described is not an
    unencrypted one, and folding the two together turns a coverage gap into a finding.
  - The **scope is AWS's, repeated rather than widened**: between instances in a VPC or
    peered VPC, and explicitly *not* a statement about S3, the internet, or NAT.
  - Both rated **LOW** deliberately — neither is a misconfiguration, and an application
    doing its own mutual TLS is in a fine position on a type that scores here.
  - **No new IAM action**: `ec2:DescribeInstanceTypes` falls under SecurityAudit's
    `ec2:Describe*`.

- **Phase 5 · slice 5.1 — CISA ZTMM v2 scoring, with its work shown** (`aws_ztmm.py`,
  written to `ztmm_scorecard.json`). *"Zero Trust CNAPP"* is not a build and no analyst
  market exists by that name. What is real is scoring an AWS estate against the published
  model **from configuration alone**, and showing the evidence behind every pillar score.
  - **The structure was verified, and the obvious inference was wrong.** Five pillars ×
    seven functions gives 35; the model has **37** — Applications and Data each carry a
    fifth pillar-specific function. Building on the assumption would have under-counted
    two pillars' denominators and reported better coverage than exists, which is exactly
    the failure slice `4.5` shipped and had to correct.
  - **No overall maturity score, deliberately and permanently.** An estate Advanced on
    four pillars and unscoreable on Devices does not *have* a maturity level — it has four
    maturity levels and a blind spot, and the single figure that hides which is the figure
    every competing product prints.
  - **A pillar takes its WEAKEST function, not its average.** Zero trust is a chain: an
    estate with Optimal authentication and Traditional access management is not Advanced,
    and averaging is how a scorer flatters an estate into a number nobody can act on.
  - **`Unscored` is not a stage** and is not on the scale at all. Calling a function
    nothing maps to *"Traditional"* would turn OverWatch's own blind spot into a finding
    about the customer. Stages are cumulative, so a gap stops the climb — passing the
    Optimal checks does not skip an unevidenced Advanced.
  - **The Devices problem is stated per function, not waved at.** Five of its seven
    functions need something running *on* an endpoint, which the charter forbids, and each
    carries its own reason; but `Asset and supply-chain risk management` and
    `Resource access` have genuine AWS-side signal, so *"Devices is unscoreable"* would
    have been too coarse a claim.
  - The shipped mapping covers **22 of 37** functions from **40 real check ids** —
    verified by a test that fails the build if one stops existing, because a table
    authored from a reading of a framework is exactly where invented identifiers appear
    (as slice `4.6`'s `builtins.open` demonstrated). The other 15 report `Unscored` **with
    a reason** rather than being quietly scored Traditional to fill the table.

- **Phase 4 · slice 4.7 — AI runtime detections, from anywhere** (`aws_ingest_aidr.py`,
  `AIDR-01`, `--ai-detections`). **Phase 4 complete.**
  - **The roadmap asked for "sibling Guardrail event ingest", and that could not be
    built.** `D7` measured the sibling — 11 commits, no Dockerfile, no console entry
    point, no publish workflow — and ruled OverWatch takes no dependency on it, with
    `test_decisions.py` failing the build if any application module so much as names it.
    A product-specific reader would have introduced exactly that reference. So this reads
    a **vendor-neutral** schema, `overwatch.ai-detection/v1`, that any AI-runtime detector
    can emit — the sibling on the same footing as anything else, and OverWatch depending
    on none of them. That is what D7's standing rule permits, and *a detection ingest
    that accepts only one vendor's format is a dependency wearing an ingest's clothes.*
  - **`AIDR-01`** (HIGH · SI-4) — the operator's own detector recognised a request as an
    attack **and the request reached the model anyway**. The detector is reporting rather
    than enforcing.
  - **A `BLOCKED` detection is never scored.** It is evidence a control *worked*, reported
    at INFO as assurance — turning a successful block into a finding is how a team learns
    to switch the detector off rather than to keep it.
  - **The content line, which is where this slice is delicate.** An AI runtime detector
    sits in the request path, so its natural output is the most content-dense payload any
    ingest in this product will ever be offered, and carrying "the prompt that triggered
    it" would make the finding far more useful. **D2 declined it.** The schema therefore
    has *no field* for a prompt, completion or matched string — a mapping that tried to
    carry one would have nowhere to put it — every field read is named in
    `DETECTION_FIELDS`, content fields present in the file are **counted and left
    unread**, and identifiers are truncated because an oversized "rule name" is precisely
    how prompt text arrives through a field nobody expected to carry it.
  - `aws_ingest_aidr.py` joins **Section F** of the zero-telemetry tripwire alongside
    `aws_ingest_pentest.py`, and for a stronger reason.
  - **No IAM action at all** — the input is a file the operator supplies. Recorded in the
    ledger as a deliberate absence rather than left to look like an omission.

- **Phase 4 · slice 4.6 — the model artifact as executable code** (`aws_modelartifact.py`,
  `MART-01`…`MART-05`, opt-in `--scan-model-artifacts`). A serialized model is **not
  data**: pickle encodes instructions and `REDUCE` calls whatever the stream names, so
  loading an artifact runs code holding the loader's credentials — in a SageMaker
  endpoint, the execution role.
  - **`MART-01`** (CRITICAL) — the artifact's S3 bucket is writable by an external
    principal. Whoever can write it has a scheduled **remote code execution** inside the
    endpoint: they replace the object and the next deploy runs their code, with nothing
    else compromised and no alert raised. This is `TFLOW-01`'s reasoning one layer down —
    that says whoever writes the corpus writes what the model *says*; this says whoever
    writes the artifact writes what the model **is**.
  - **`MART-02`** (MEDIUM) — no `ETag`, so the reference resolves at deploy time to
    whatever is at the URI. The `MCP-04` rug-pull shape applied to weights, and the reason
    `MART-01` is a code-execution finding rather than a data-integrity one. The legacy
    `ModelDataUrl` has no ETag field at all and is unpinned by construction.
  - **`MART-03`** (MEDIUM) cross-account artifact; **`MART-05`** (LOW) the format can
    execute at all — rated LOW because nearly every PyTorch checkpoint is in one, and
    reported as the *durable fix* for the rest of the family rather than a defect alone.
  - **`MART-04`** (CRITICAL, opt-in) — a static opcode scan finding a global with no
    explainable reason to be in a serialized model. **`EXECUTABLE` and `MALICIOUS` are
    separate verdicts**: almost every real checkpoint contains `REDUCE`, that being how
    the format rebuilds a tensor, and flagging them all is how a scanner gets switched off.
  - **The scan never unpickles.** `pickletools.genops` walks opcodes without running them
    — verified by a test that pickles a payload which opens a file, scans it, and asserts
    the file does not exist; and enforced by a test that `pickle.load`, `torch.load` and
    `joblib.load` never appear in executable code. The read is ranged and bounded to 8 MB,
    and a truncated stream is reported as truncated, never as clean.
  - **`D10`** records the crossing. The roadmap labelled 4.6 *"crossing · D2"*, and that
    was imprecise: D2 concerns prompt and completion content, which an artifact is not.
    The real crossing is the **`s3:GetObject` action class** — the one FLOW-00 crossed
    first — so it ships in the FLOW-00 shape: a separate named `CnappModelArtifactRead`
    policy, off by default, scoped to the artifact prefixes, failing open to `MART-00`.

- **Phase 4 · slice 4.5 — the AI compliance evidence pack** (`aws_evidence.py`, written
  to `ai_compliance_evidence.json` alongside the other evidence artefacts). An auditor
  does not want a list of failures. They want to know, control by control, whether it was
  assessed, by what, and what the answer rests on — and above all **what was not
  assessed**.
  - **The thing OverWatch can actually win on.** Every product maps controls to checks and
    paints the result green; almost none can say which controls their scan never reached,
    because they do not know. OverWatch does, from three artefacts it already maintains
    for exactly this reason: the **permission ledger** (which checks the role could not
    evaluate), the **coverage manifest** (regions never looked at, checks that returned
    AccessDenied), and **`aws_epistemics`** (whether a claim is `OBSERVED`, `CONFIGURED`,
    `INFERRED` or `CONDITIONAL`, so *"the guardrail is configured"* is not silently
    upgraded to *"the guardrail works"*).
  - **No status means "compliant".** The strongest available is `ASSESSED_PASS` — *these
    checks ran and none failed* — and its own text says it is *"not a determination that
    the control is satisfied"*. Whether it is satisfied is the auditor's judgement, and a
    tool that pre-empts it is selling an opinion as a fact. `PARTIAL` and `NOT_EVALUATED`
    keep *incomplete* and *could not look* apart from *clean*.
  - **Mapping provenance is carried, not dropped.** The crosswalk is candid that no
    official NIST 800-53 → AI RMF crosswalk exists and these are OverWatch's reading of
    two texts; every evidence row carries that note and the mapping's confidence. Where a
    control is reached through several spine controls it keeps the **lowest** confidence
    of them, so one confident mapping cannot launder several speculative ones.
  - Coverage is reported as **counts, never a percentage** — *"68% compliant"* is
    precisely the sentence this module exists to make impossible to write.

- **Phase 4 · slice 4.4 — shadow AI, the half that is actually visible**
  (`aws_shadowai.py`, `SHAI-01`…`SHAI-03`, new `SHADOW_AI` section, `--ai-owners`).
  Shadow AI is **not a property of a resource**. A knowledge base built by the ML platform
  team in the governed region is the system working; the identical resource built by an
  application role in a region nobody scans is the thing worth a conversation. An
  inventory cannot tell those apart, which is why this asks **who** and **where** rather
  than **what**.
  - **`SHAI-01`** (MEDIUM) — AI resources created by an identity outside the declared
    owner set. **Without `--ai-owners` it does not fire at all**, listing what it found as
    `SHAI-00` instead: a check that flags every legitimate creator on the first scan is
    one people turn off, and then it never fires on the one that mattered either.
  - **`SHAI-02`** (MEDIUM) — AI built in regions this scan never enumerated. A coverage
    statement rather than a misconfiguration, and the most consequential kind: for those
    resources the guardrail posture, network exposure and key custody are **unknown
    rather than clean**.
  - **`SHAI-03`** (MEDIUM) — VPCs with no Bedrock interface endpoint. Without one, Bedrock
    traffic leaves via NAT or an internet gateway and **no VPC endpoint policy applies** —
    the only place you can say which models a workload may invoke. Reported as a WARN and
    explicitly marked not-applicable for VPCs that do not use Bedrock, because
    configuration cannot tell which those are.
  - Only **management** events are read. `bedrock:InvokeModel` is a data event
    `LookupEvents` never sees — the gap `AILOG-04` reports — and that limit is a feature
    here: creation is the moment shadow AI becomes visible, and usage is `AITHR-01`'s
    question. Sessions collapse to their role, because ten sessions of one role are one
    creator.
  - **No new IAM action.** `cloudtrail:LookupEvents` was already used by `AITHR-01` and
    `ec2:DescribeVpcEndpoints` falls under SecurityAudit's `ec2:Describe*`; both are now
    recorded in the ledger so declining either names what it costs.

- **Phase 4 · slice 4.3 — where the prompts land, and who saw the call**
  (`aws_ailog.py`, `AILOG-01`…`AILOG-06`, new `AI_LOGGING` section). Both halves close a
  gap in advice OverWatch already gives.
  - **`BDR-01` names a destination and stops there.** It is right that invocation logging
    should be on — it is the only control in the AI pillar producing evidence after an
    incident. But with `textDataDeliveryEnabled`, that bucket or log group receives
    **every prompt and every completion in the account**. Turning logging on *creates a
    crown jewel*, and nothing asked whether the crown jewel was locked.
    **`AILOG-01`** (CRITICAL) a publicly-accessible prompt-log bucket; **`AILOG-02`**
    (HIGH) key custody on the sink; **`AILOG-03`** (MEDIUM) a log group with no retention
    — prompt logs are evidence, and evidence with no expiry is also a growing liability.
  - **`LOG-08` asks whether a trail records data events; it cannot say which.** An account
    passes it while logging only S3 object activity, so **`AILOG-04`** (HIGH) asks whether
    any trail names `AWS::Bedrock::Model` — without it there is no record of who invoked
    which model, which is both `AITHR-01`'s LLMjacking signal and the first question after
    any AI incident. **`AILOG-05`/`AILOG-06`** (MEDIUM) report the remaining Bedrock and
    AgentCore gaps.
  - **Three things verified rather than assumed.** The four delivery switches are
    independent; `cloudWatchConfig.largeDataDeliveryS3Config` is a **third** destination
    that receives the biggest payloads and is the one operators forget; and Bedrock data
    events require **advanced** event selectors — basic ones accept only DynamoDB, Lambda
    and S3 object types, so a trail full of S3 data events carries no AI coverage at all.
  - **Restraint where the question was not asked.** A CloudWatch destination gets no
    `AILOG-01` (a log group has no public-access concept, and a PASS would answer a
    question nobody asked); a bucket owned by another account is a coverage note, never a
    verdict; an account with no AgentCore gets no AgentCore finding; and an account with
    no AI data events at all is told once, not three times.
  - Configuration only, and stated: the reason the destination matters is that it holds
    prompts, and a scanner that read them to check them would be the second copy of the
    problem — the same reasoning as **D2** and **D8**.

- **Phase 4 · slice 4.2 — the RAG vector store, from configuration** (`aws_vectorstore.py`,
  `VEC-01`…`VEC-07`, new `VECTORSTORE` section). A retrieval-augmented agent answers from
  what its vector store holds, which makes that store the agent's memory of the
  organization's documents — the same reasoning that already makes `TFLOW-01` treat a
  writable knowledge-base source as a **proven** injection entry. This slice asks the
  layer beneath: who can reach the corpus, and who holds its key.
  - **The two gates are kept apart, and only their composition is CRITICAL.** The
    OpenSearch Serverless reference is explicit — *"network access only determines which
    networks can reach the collection endpoint; data access policies determine which
    principals can perform operations on the data."* So **`VEC-01`** (HIGH) reports
    *reach*, **`VEC-02`** (HIGH) reports *read*, and **`VEC-03`** (CRITICAL) claims both
    only when each was separately established. Collapsing them would assert a terminal
    never proved, which is the failure `ATT&CK-02` exists to prevent.
  - **`VEC-04`** (MEDIUM) collection key custody; **`VEC-05`** (HIGH) public S3 Vectors
    bucket policy; **`VEC-06`** (MEDIUM) *named* cross-account grants, reported apart
    from public because a partner integration is frequently deliberate and a CRITICAL on
    a working design is how a category gets ignored; **`VEC-07`** (MEDIUM) bucket key
    custody, where **both** `AES256` and `aws:kms` *without* a `kmsKeyArn` fail — neither
    is a key the customer can disable.
  - **Three readings taken from the reference rather than guessed**, each of which would
    have produced a wrong answer: **public wins** (a public rule in *any* matching policy
    overrides a private one, and `AllowFromPublic` makes the service ignore `SourceVPCEs`
    entirely, so the verdict is a union across policies); **`collection` and `dashboard`
    are different doors to the same room** (a private API endpoint with a public
    Dashboards endpoint is still reachable); and **`bedrock.amazonaws.com` in
    `SourceServices` is the correct architecture**, never a finding.
  - Scope is **`VECTORSEARCH` collections only**. A `SEARCH` or `TIMESERIES` collection is
    not an agent's corpus, and putting AI findings on every log-analytics collection in
    the account is how operators learn to skip the category.
  - A collection matched by **no** network policy is an INFO, not a PASS: reachability
    *could not be established* rather than being private.
  - **Nine new IAM actions** (`aoss:` ×6, `s3vectors:` ×3), all config reads, in the
    always-on additive policy rather than behind a flag. Both services postdate
    SecurityAudit and ViewOnlyAccess, so neither managed policy grants any of them.

- **Phase 4 · slice 4.1 — SageMaker depth to Security Hub parity** (`aws_sagemaker.py`,
  `SM-08`…`SM-28`). OverWatch shipped seven SageMaker checks; four answered a published
  control (SageMaker.1/2/3/21) and three are ours with no Security Hub equivalent. That
  left **21 of the 25 published controls unanswered**, across eight resource types the
  scanner never opened: models, feature groups, inference experiments, four kinds of
  monitoring job definition, monitoring schedules, app image configs and images.
  - **Parity is now a checkable claim, not an assertion.** `SECURITY_HUB_PARITY` maps
    every one of the 25 controls to the check that answers it, with **AWS's own
    severity**, and a test fails the build if a control is listed without a check behind
    it. A second test fails if our severity disagrees with the standard — a scanner that
    claims parity and then quietly re-rates a control is disagreeing where nobody can see
    it. `OVERWATCH_ORIGINAL` names our three extras separately, because *"we go beyond
    the standard"* and *"we have an unmapped check"* are opposite facts that look
    identical in a coverage count.
  - **Twelve of the 21 collapse into one classifier.** Data-quality, model-bias,
    model-explainability and model-quality job definitions plus monitoring schedules all
    carry the same two flags — `EnableNetworkIsolation` and
    `EnableInterContainerTrafficEncryption`. `MONITORING_KINDS` is the table both the
    scanner and the tests walk; five hand-written copies is how one of them stops
    matching the other four and nobody notices which.
  - **Absent means *disabled* here, and only here.** The documented exception to this
    codebase's absent-means-unknown rule: SageMaker.14 fails a schedule whose flag is
    "set to false **or not configured**". Sourced, not stylistic, and pinned by a test so
    it is not later "fixed" into consistency with the wrong rule.
  - **Four controls are conditional, and the finding is withheld rather than dismissed**
    — no encryption finding on a single instance (no inter-container traffic exists), no
    pipeline finding on a single-container model, no captured-data finding with capture
    off, no redundancy finding on a serverless-only endpoint config. In each case a FAIL
    would name a risk the configuration cannot have and a PASS would be one it did not
    earn.
  - **`SM-02` and `SM-04` are raised MEDIUM → HIGH.** SageMaker.2 (custom VPC) and
    SageMaker.3 (root access) are both High in the standard and were MEDIUM here. This
    **moves the posture score** of any account running notebooks — called out rather than
    slipped in with a batch of new ids.
  - Verified against botocore **1.40.51**, the pinned version: unlike slice 3.3, every
    operation this slice needs is present, so nothing is deferred. `MonitoringResources`
    vs `JobResources` was caught during that pass — reading only the latter returns
    instance count 0 for every schedule, which would have made SageMaker.22 inapplicable
    everywhere, and a conditional check that never fires reads exactly like one that
    always passes.
  - SageMaker.8's supported-platform list and the control snapshot are both **dated** in
    `aws_sagemaker.py`; AWS adds controls and ages platforms out, and an undated snapshot
    silently becomes a false parity claim.

- **Phase 3 · slice 3.3 — MCP server provenance** (`aws_mcp.py`, `MCP-01/02/03/04`). An
  AgentCore Gateway **is** an MCP server, and what it publishes to an agent is decided by
  its targets. Three of the four target kinds — `openApiSchema`, `smithyModel`, `lambda`
  — describe an API inside the account. The fourth, `mcpServer`, is an endpoint somewhere
  else, and that asymmetry is the slice.
  - **`MCP-01`** (HIGH · SI-7) — the gateway **federates a third-party MCP server**. Not
    a defect: a vendor MCP server is often exactly what you want. What it reports is that
    the tool definitions the model acts on now come from a party the account cannot see
    inside, bounded by the gateway execution role rather than by anything the provider
    agreed to.
  - **`MCP-02`** (CRITICAL · SC-8) — that endpoint is **plaintext `http`**. The rare AI
    finding needing no AI reasoning: rewriting a tool description on the wire is prompt
    injection carried out with a network position instead of a prompt, and it is
    invisible to every control in the pillar — nothing is misconfigured on the gateway
    side, and the instruction reaches the model through the channel it is built to trust.
  - **`MCP-03`** (HIGH · SI-7) — the gateway's **`instructions`** string carries a
    chat-template delimiter, an invisible codepoint, or a hit from the operator's pattern
    set. This is `3.2`'s channel one level up: what the *server* tells the model about
    using the whole gateway, while the operator reading the console sees a field that
    documents how to use it. `aws_toolpoison.assess_text()` was extracted so the same
    classifier serves both — the rule that **OverWatch authors no injection phrasings** is
    only worth having if every caller inherits it. The finding never quotes the string
    back.
  - **`MCP-04`** (LOW · SI-7) — **the blind spot, stated rather than implied.** For a
    federated server AWS records the *endpoint* and never the *tools it serves*. No API
    in the account returns the tool list, so no scan — not this one, not a deeper one,
    not one with more permissions — can diff what that server offers today against last
    week. That is precisely the **rug pull**: benign tools until trusted, then changed.
    The finding exists because the alternative is worse: a reader who sees a federated
    server reported with no mention of its tools assumes the tools were checked and were
    clean — a phantom pass produced by omission. It carries LOW because its job is to be
    **read**, not to rank; nobody can remediate a limit of what AWS records.
  - **Verified against the pinned model, and the pin decided the design.** Read from
    botocore **1.40.51**'s own `service-2.json`, not the published API reference:
    `McpServerTargetConfiguration` has exactly one member, `endpoint`. **`ListingMode`
    (`DEFAULT`/`DYNAMIC`) does not exist in 1.40.51** — it arrives in 1.43.51, where AWS
    documents DYNAMIC targets as having their tool list *"dynamically retrieved when
    listing tools"* rather than cached at the control plane, which would have made
    rug-pull exposure a pure config read. Neither does the **Registry** and its
    `DRAFT/PENDING_APPROVAL/APPROVED/REJECTED` lifecycle. Bumping the pin is a dependency
    decision beyond this slice — the CHANGELOG already records `botocore==1.43.51`
    breaking the offline build once, since `boto3==1.40.51` requires `botocore<1.41.0`.
  - **`MCP-05`** (HIGH · CM-5) — **the rug-pull half, behind `--state`.** MCP-04 states
    what nobody can see; this is what the account *can*: a target repointed, added or
    removed, or the gateway's own instructions rewritten. All are recorded, so all are
    diffable. New table `mcp_surface` (schema **v15**, sqlite + Postgres twins) holds one
    digest per gateway.
    - **A first sighting is not a change.** Reporting one would light up every gateway in
      the account the first time an operator passes `--state` — the noise that teaches
      people to ignore a category. Same distinction `aws_state` already makes by
      projecting `NEW` rather than storing it.
    - **The finding asks rather than asserts.** The common case is the operator's own
      deployment, so it says *"confirm it was yours"* — a finding that announced a breach
      on every deployment would be wrong far more often than right.
    - **The scan path stays stateless.** The comparison runs in `_process_state`, the one
      seam that already holds the store, and before `classify_and_diff` so MCP-05 enters
      the lifecycle like any other finding. Without a state DB the check simply does not
      run, and MCP-01..04 are unaffected — the config half is never hostage to an opt-in
      flag. `first_seen_epoch` is deliberately excluded from the update set: including it
      would reset every gateway's age on each run.
    - Every gateway is stashed, **federated or not**, so a gateway that gains its *first*
      federated target is caught — a comparison that only stored gateways already
      federating would miss precisely that moment.
  - `surface_fingerprint()` is the anchor, and a test pins its limit: identical
    configuration digests identically no matter what the far end is actually serving, so
    nobody later reads it as covering more than it does.
  - **One new action**: `bedrock-agentcore:GetGatewayTarget`, added to the ledger and both
    deploy paths. `MCP-03` adds none — `instructions` is on `GetGateway`, already bought
    for `AGC-05/06`.

- **Phase 3 · slice 3.5 — adversarial-test ingest** (`aws_ingest_pentest.py`,
  `PENT-01/02`, `--pentest-results`). **Decision D4's third leg.** OverWatch will not
  probe a customer's models; when the customer probes their own, the **results** land on
  the same graph as everything else, so a probe that succeeded can be read next to what
  the probed identity actually reaches.
  - **`PENT-01`** (HIGH · CA-8) — a probe that got through in **at least half** its
    attempts. **`PENT-02`** (MEDIUM · CA-8) — one that got through in a minority. A
    partial rate is a finding rather than noise: a probe that works one time in ten works
    reliably given ten attempts. A probe that never succeeded is **not** a finding —
    ingesting every row would turn a 1000-probe garak run into 1000 rows and bury the
    handful that mattered.
  - **The operator's own `severity` wins** over the computed one. They know what the
    probe was aimed at; this module does not. A 1-in-10 success against an agent that
    reaches production data is not the same finding as a 1-in-10 against a sandbox.
  - **The verdict is ingested; the transcript is not.** garak's `report.jsonl`
    interleaves `eval` rows (verdicts) with `attempt` rows (the attack prompt and the
    model's response). Only the first kind is parsed — **structural**, not a filter — and
    the count of skipped rows is reported as `PENT-00`, because silence would let a
    reader conclude the file held no transcript. **D2 in force**: this is the one place a
    file containing prompts and completions is handed to the product, and it is the place
    the boundary had to be built rather than assumed. `aws_ingest_pentest.py` is policed
    by Section F of the zero-telemetry tripwire.
  - **Provenance is stated in the finding text** — *"this is a result you produced,
    ingested as reported"*. A row reading like OverWatch's own verdict, in a product that
    refuses to probe, is a claim it did not earn. For the same reason a generic result
    file that declares no `tool` is **refused outright**, exactly as `3.2` refuses a
    pattern set without a `source`.
  - The format is detected **by content, not by extension**: an operator who renamed the
    file still gets the right parser, and a wrong guess would read a transcript file as a
    verdict file. A missing or malformed file costs the ingest and not the scan.
  - **Onto the graph, with an edge.** A successful probe becomes a `PentestResult` node
    joined to the probed resource by a new **`PROBED`** edge — being on the graph as an
    orphan node is being on it in name only, and the edge is what lets a probe that got
    through be read next to what the probed identity reaches. The edge is drawn **only to
    a node this scan actually enumerated** (exact ARN, or the same ARN retyped):
    `add_edge` auto-creates a missing endpoint as `Unknown`, so binding to an
    operator-typed string would put a resource on the graph that exists nowhere else.
    An unresolved target is **said** — *"does not match any resource this scan
    enumerated — the probe is recorded, its reach is not"* — rather than dropped, because
    *"succeeded against arn:…:agent/A1"* in a report where nothing links the two invites
    the reader to assume the link was checked. `PROBED` is an **annotation**, like
    `HAS_VULN` and `THREAT_ON`, and is deliberately kept out of `E_PATH`: a probe the
    operator ran is not a capability an attacker holds.
  - **No new API call and no new IAM permission** — the input is a file the operator
    supplies.
- **Phase 3 · slice 3.4 — memory-poisoning exposure, the configuration half**
  (`aws_agentmemory.py`, `AMEM-01/02`). Agent memory is what lets a prompt injection
  **outlive the conversation that carried it**: an instruction written in one session is
  read back in the next. Everything else in Phase 3 asks what an injection reaches *now*;
  this asks **how long it keeps reaching**.
  - **`AMEM-01`** (MEDIUM · SC-28) — the **exposure window**, read from
    `memoryConfiguration.storageDays` on a Bedrock agent and `eventExpiryDuration` on an
    AgentCore memory. Banded `none` / `short` (< 30d) / `extended` (30–89d) /
    `long` (≥ 90d), both surfaces capping at a year. There is **no correct retention
    period** — a support assistant that remembers a customer for a year may be exactly
    right — so the finding states the number rather than pronouncing on it. What it
    reports is that a number exists which somebody should have chosen on purpose.
  - **`AMEM-02`** (HIGH · SC-28) — AgentCore Memory on an **AWS-managed key**. The same
    custody question `AGC-07` raises for the token vault, and it lands harder here
    because of what memory holds: the material that carries between sessions, which is
    precisely the channel an injection uses to persist. In an incident the containment
    question is whether you can cut access to what the agent remembers; with a
    service-managed key it has no answer.
  - **The config half is the whole slice, and the finding says so.** Whether anything
    poisoned is *stored* is a question about memory **contents**, and reading those is
    the escalation **D2** declined. A memory finding with no mention of contents would be
    read as *contents checked, contents clean* — a **phantom pass produced by omission**
    rather than by assertion — so every one of them states that contents were not read.
  - **An unreadable window is not a short one.** `storageDays` is optional and the
    reference states no default, so an agent with memory enabled and no retention value
    emits `AMEM-00` (INFO) rather than a PASS. Same rule that kept `requireMMDSV2`
    unknown in `2.2`.
  - **Namespaces are counted, not interpreted.** A namespace template decides whether
    memory is per-actor or shared, but the template variables are operator-defined and
    their semantics are not in the API reference. The count is a fact; a reading of it
    would be a guess.

### Fixed
- **`MCP-04` was asserting something that had become false.** It emitted, verbatim,
  *"the tool list is not a thing any API here returns, which means no scan of any depth
  can diff it"*. Under botocore 1.40.51 that was true. Under 1.43.51 —
  the pin since the previous change — `McpServerTargetConfiguration` carries
  `mcpToolSchema` and `listingMode`, and `listingMode=DEFAULT` means the tool schema **is**
  cached at the control plane and therefore diffable. A live check stating a falsehood is
  the phantom this codebase exists to prevent.
  - The note is now conditioned on what is actually readable, and the distinction is
    useful: `DEFAULT` + a recorded schema declares **no** blind spot; `DYNAMIC` declares
    one and says it is a **configuration choice** rather than a platform limit, because
    switching to `DEFAULT` closes it.
  - `MCP-04`'s remediation opened *"No action closes this one"*. For `DYNAMIC` that is
    now wrong, and it says so.
  - **Two pre-existing tests pinned the false sentence.** Their intent — a federated
    target whose tools are not recorded must *say* so rather than read as audited — is
    kept; the pin on the wording is gone, and a new test asserts the opposite case.
- **`aws_finding_detail` and `aws_perm_ledger` did not import `aws_mcp`**, so whether
  `MCP-06`'s projections existed depended on import order. Caught because the first
  verification imported `aws_mcp` first and masked it.
- **`overwatch-phase2-misconfigs` deleted — it was never at risk.** It had been flagged
  repeatedly as the only unmerged branch and therefore holding work that existed nowhere
  else. `git cherry` shows **both** its commits already in `main` by patch-id: the
  content had been applied separately. `git branch --no-merged` reports on commit
  ancestry, not content, and the two are not the same thing.

- **The SDK pin: botocore 1.40.51 -> 1.43.51, both SDKs moving together.** The pin had
  been deferred twice as "a dependency decision beyond this slice", and investigating it
  turned up something larger than a stale version.
  - **The development environment was already on 1.43.51.** Every service model consulted
    while authoring checks — including the entire 426-service gap analysis behind four
    coverage batches — was read from a botocore three minor versions ahead of what a
    fresh install would get. Nothing compared the declared pin to the installed one, so
    nothing said so. (`boto3` was not installed at all; the scanner's `HAS_BOTO3` guard
    meant that never surfaced.)
  - **The pair must move together.** The CHANGELOG records `botocore==1.43.51` breaking
    the offline build once, because `boto3==1.40.51` caps `botocore<1.41.0`. `boto3
    1.43.51` requires `botocore>=1.43.51,<1.44.0`, so pinning both at 1.43.51 is
    internally consistent — verified against PyPI rather than assumed, since boto3 and
    botocore do **not** track patch-for-patch (the latest boto3 is 1.43.80).
  - **What the bump unlocks**: `ListingMode` (`DEFAULT`/`DYNAMIC`) and the AgentCore
    **Registry** with its `DRAFT/PENDING_APPROVAL/APPROVED/REJECTED` lifecycle. Both were
    unreadable rather than absent under the old pin — the distinction this codebase
    enforces everywhere else.
  - **`MCP-04`'s premise moved with the pin, and is written down rather than left
    standing.** That finding exists because a federated MCP server's tool list could not
    be read, so its absence had to be *stated* rather than passed over. Under 1.43.51 it
    partly can be. The check's **behaviour is deliberately unchanged** — bumping a
    dependency and redesigning a finding are separate pieces of work, and doing both at
    once ships a rewritten finding nobody reviewed — but the module now says so instead
    of asserting a blind spot that no longer holds. Reading `ListingMode` and the
    Registry approval state is the follow-on.
  - **`tests/test_sdk_pin.py`** guards both failure modes: the two pins must name the
    same version, the two requirements files must agree, the **installed** botocore must
    match the pin, and the Registry and `ListingMode` must actually be present in the
    installed models — asserted against the models, not inferred from a version string.
    A further test fails if any module still describes 1.40.51 as the current pin.

- **The credential-report poll cost roughly two thirds of every test run.**
  `_get_credential_report` polls an asynchronous AWS API. Against a mocked client the
  state never reaches `COMPLETE`, so every test reaching the method burned the full
  retry budget — nine two-second polls plus a five-second retry, about **23 seconds
  each**. `tests/test_exposure.py` alone took **3m50s**.
  - It also cost real debugging time: the suite stalled at the same 29% mark on three
    consecutive runs and *looked hung*. That was misdiagnosed as a product bug and two
    runs were killed before anyone profiled it. The profile put 23 of 23.6 seconds in
    `time.sleep`.
  - The timings are now module constants (`CRED_REPORT_ATTEMPTS`,
    `CRED_REPORT_POLL_SECONDS`, `CRED_REPORT_RETRY_SECONDS`) which
    `tests/conftest.py` zeroes for the session. **Shipped behaviour is unchanged** and
    `test_credential_report_timing.py` pins the shipped values, so a test-only speedup
    cannot quietly become what ships — a scan that stopped waiting would read the report
    before it is ready on exactly the fresh accounts where it takes longest.
  - A **non-string `State` now short-circuits the poll**: it can never become
    `"COMPLETE"`, so there is nothing to wait for. An *absent* State still polls, because
    it defaults to `""` — which is a string, and a report that is genuinely still
    generating is the case that must keep waiting.
  - A guard asserts no unparameterised `time.sleep` remains in the scanner, so a new
    fixed sleep cannot reintroduce the tax.
  - **Full suite: 369s -> 120s.** `test_exposure.py`: 230.33s -> 0.32s.

- **A new check silently overwrote an existing one's remediation.** Slice 5.4 was first
  written as `SEG-01`, which is already a real check (world-open sensitive port on a
  security group). Python dict literals accept duplicate keys with no error and the
  **last one wins**, so the new remediation string replaced the real check's and nothing
  failed anywhere. Renamed to `SEGREC-01`, and a **ratchet now parses the check maps as
  source** and fails on any *new* duplicate id. Auditing for it turned up 43
  pre-existing duplicates: 40 are harmless repeats of an identical value, one
  (`REMEDIATION_MAP` / `DDB-04`) likewise, and `SM-02`/`SM-04` are a deliberate
  CHANGELOG-documented severity override that uses last-wins shadowing on purpose. Those
  are frozen as a baseline rather than cleaned up — reverting someone else's intentional
  decision is not this slice's business; catching the next accidental collision is.
- **`_paginate_all` swallows every exception and returns `[]`.** Routing the
  Organizations walk through it would have turned a denied `ListPoliciesForTarget` into
  "no policies exist" — a clean-looking absence produced by a permission error. The
  perimeter section paginates by hand so denials actually reach the caller and become
  coverage notes.
- **Graph props are nested under `props`** on both nodes and edges. Reading the outer
  dict yielded no `sg_ids` and no `ports`, and the segmentation recommendation quietly
  degraded to naming neither — a silent loss of specificity rather than an error.

- **The botocore wheel ships nine EC2 API versions, and the first one is from 2014.**
  Reading the service model by taking the first `/ec2/` match landed on `2014-09-01`,
  which predates `DescribeInstanceTypes` entirely — so the operation and the
  `EncryptionInTransitSupported` field both appeared not to exist. The correct version is
  **`2016-11-15`**, and it is now recorded as a constant in `aws_nitro.py` with a test,
  because a silently-empty verification is worse than a failed one: it looks like an
  answer.

- **The pickle danger table was authored from memory and wrong where it mattered most.**
  It listed `builtins.open` — a pair pickle **never emits**, because `open` pickles as
  **`_io.open`**. The most common malicious payload there is would have been missed by a
  table that read perfectly plausibly. Likewise `os.system` pickles as `posix.system` on
  Linux and `nt.system` on Windows; both are now listed, because the platform that matters
  is the one the **artifact** was built on, not the one the scanner runs on. The table is
  now driven by observation, with a test that pickles each dangerous callable and asserts
  the table names what CPython actually emits — so it cannot drift back into
  plausible-looking fiction.
- **The permission ledger's own guard caught `MART-04` being smuggled into the always-on
  ask.** `test_the_additive_policy_contains_only_read_actions` names `s3:GetObject` and
  `logs:StartQuery` as belonging to "the separate opt-in blocks", and rejected the first
  attempt to give `MART-04` a ledger entry. That policy is what an operator approves once
  and forgets; a content read has no business in it. `MART-04` now has **no** ledger entry
  by design, and its action is documented only in the deploy template's opt-in block.

- **The evidence pack shipped with the exact failure it was written to prevent.** A
  framework control only enters the pack if the crosswalk already maps it, so the mapped
  set is N-of-N *by construction*: against the real crosswalk the summary read
  **"12 of 12 reached"** for NIST AI RMF — a framework with **72** controls. A reader
  would have taken one sixth of a framework for all of it. That is the phantom pass at
  framework scale, reproduced in the module whose entire purpose is to stop it.
  `coverage_summary()` now takes the framework's own `catalog_size` as the denominator
  and reports *"mapped 12 of 72 … the remaining 60 are not reached by the crosswalk at
  all and were NOT looked at"*. With no catalog size supplied it states the fraction as
  **UNKNOWN** rather than computing one from its own reach, because silence is what
  produced the bug.
- **`get_crosswalk()` returns `(crosswalk, frameworks, digest)`** — the crosswalk first.
  The signature is `Tuple[Dict, Dict, str]`, which is ambiguous, and the first authoring
  of the evidence pack had it backwards. It was caught because a test runs against the
  **shipped crosswalk file** rather than a fixture, so a wrong assumption about the API
  failed in the suite instead of in a customer's audit.

- **`docs/DECISIONS.md` **D9** records a refused detection surface.** Slice 4.4 specified
  "one CloudTrail query, one flow-log query", and the flow-log half cannot work from this
  vantage point: VPC flow logs record **IP addresses, not hostnames**, and the major AI
  providers front their APIs with **shared Cloudflare and Fastly ranges**. An
  address-matching rule would fire on every CDN-fronted site in the estate while missing
  any provider that rotated an address — *a detection surface whose misses read as passes*,
  which is the exact objection slice `3.2` raised against shipping injection phrasings.
  Refusing it once is worth nothing if the next slice does it. `SHAI-03` ships the
  config-only question underneath instead, and `SHAI-00` states the gap on **every scan**
  so a reader cannot mistake silence for coverage.
- **The permission ledger's read-verb guard rejected `Lookup`.** `cloudtrail:LookupEvents`
  is CloudTrail's read verb, and the distinction it raised is now written down: it reads
  the account's **own audit trail** — who called which API — not any workload payload.
  That is the class of `DescribeInstances`, emphatically **not** the class of
  `s3:GetObject` or `logs:StartQuery`, which read customer content and belong in the
  separate opt-in blocks. Third naming convention this guard has forced an examination of,
  which is the guard working.

- **The public-bucket branch of `AILOG-01` could never have fired.** It tested
  `verdict["scope"]`, and `classify_resource_policy_stmt` returns **`kind`** — an
  invented field name, the same class of error as the invented
  `_classify_policy_principal` before it. A wrong key silently yields `None`, which reads
  as "not public": a check that always passes. Corrected against the function rather than
  from memory, with the real values (`public`, `public_conditioned`) written down.
- **The ledger-rebuild helper was resetting a test's name on every run.** Its regex
  matched *any* `test_the_shipped_role_is_missing_exactly_<word>_actions` and always wrote
  back `eighteen`, so the name had been wrong for three slices while the real gap climbed
  to thirty. A test name is documentation, and documentation that silently reverts is
  worse than none. The helper now derives the word from the computed count.
- **`cloudtrail:GetEventSelectors` was never in the permission ledger**, despite the
  scanner calling it for `LOG-08` since long before this slice — so declining it silently
  cost a check nobody was told about. That is precisely the gap the ledger exists to
  close, and it is now recorded for both `LOG-08`'s successor checks and `AILOG-04`.

- **The roadmap's *boundary* label on 4.2 was wrong, and `docs/DECISIONS.md` **D8** now
  records why.** Verification came before design: every security question worth asking
  about a RAG store is answerable from configuration. Only `s3vectors:GetVectors` /
  `ListVectors` cross the line, and what they return is **embeddings** — vectors computed
  from the customer's documents and partially invertible back toward them. That is the
  escalation **D2** declined for prompt text, and the argument transfers unchanged: a
  security product that ingests the corpus it audits has become a second copy of the
  thing at risk. So 4.2 ships **in-charter**, with no FLOW-00 opt-in block, and the
  refusal is stated rather than implied — every `VEC-*` finding carries *"this check
  reads configuration only and does NOT read the stored vectors"*, the same way `MCP-04`
  states its blind spot. A test asserts the module never names those operations in
  executable code, after first being narrowed so it stops firing on the docstring that
  explains the refusal.
- **The permission ledger's read-verb guard rejected `BatchGet`.** `aoss:BatchGetCollection`
  is how that service spells `DescribeCollection`, and the guard did its job — a new
  service's naming convention got examined rather than waved through — but the allow-list
  was missing a legitimate read verb. Extended in both places that check it.

- **The permission ledger was lying about SageMaker, and had been since the checks
  shipped.** Its three entries were **rotated by one**: `SM-04` (notebook VPC deployment)
  held the Studio *domain* actions, `SM-06` (Studio home-EFS key) held the
  *endpoint-config* actions, and `SM-07` (endpoint-config key) held the *notebook*
  actions. Every entry named a different check's resource.
  - The visible consequence: declining `sagemaker:ListNotebookInstances` was reported as
    costing `SM-07` alone — a check that reads no notebook at all — when it actually costs
    `SM-01`, `SM-02`, `SM-03`, `SM-04` and now `SM-12`, every notebook check there is.
    *"Declining an action names exactly what it costs"* is this module's whole contract,
    and for SageMaker it was naming the wrong things.
  - Corrected and extended to all 28 SageMaker checks via 13 shared requirement groups,
    with a test asserting **every ledger action is one the scanner actually calls** — the
    defect class this replaces.

- **Slice 3.3 destroyed slice 1.5's test module, and the suite reported green.**
  `tests/test_mcp.py` already existed — 402 lines covering **decision D6**, the
  enforcement boundary on OverWatch's own local MCP server: that it *refuses to start*
  without an explicit acknowledgement, redacts identifiers by default, and audits every
  call. Writing the 3.3 classifier tests over that path took it from **34 test functions
  to 22**.
  - It survived review because the total went **up** — 3,060 → 3,097 — as the new slice
    added more tests than the overwrite removed. Both full runs were accurate about what
    they ran and blind to what had left the repo. **A rising test count is not evidence
    that nothing was lost.**
  - 1.5's suite is restored; the 3.3 classifier tests now live in
    `tests/test_mcp_provenance.py`. Both merges were checked for any other file that lost
    content — `tests/test_mcp.py` was the only one. True count: **3,131**.
- **`tests/test_suite_ratchet.py` — a ratchet on the test suite itself.** Every guard in
  this codebase exists because a confident wrong answer shipped once: the check-map
  lockstep, node parity, the permission ledger, the zero-telemetry tripwire. The tests
  were the one load-bearing artefact with no such guard, which is how the enforcement
  tests for a deliberate product decision came to be deleted by accident.
  - Each of the 181 test modules carries a floor. Dropping below it fails; losing a whole
    module fails; a new module with no floor fails; and a floor that has **fallen behind**
    fails, because a floor that never rises decays into permission to delete everything
    added after it. `python tests/test_suite_ratchet.py --update` re-ratchets, and only
    ever *raises* a floor — lowering one is a decision somebody makes in a commit message,
    never a side effect of running a script.
  - Counted with `ast` rather than by collecting through pytest, so the floor does not
    depend on fixtures importing cleanly and an unparseable module is reported rather than
    silently read as zero. Memoized: the un-cached version re-parsed the whole tree per
    parametrized case — 6m13s, versus 4.8s now. A guard that doubles the suite's runtime
    is a guard people start skipping.
- **`AGC-05` was a phantom finding — a CRITICAL false positive on the architecture AWS
  documents as correct.** `credentialProviderConfigurations` lives on **`GetGatewayTarget`
  and on no other response**; `ListGatewayTargets` returns `TargetSummary` — `targetId`,
  `name`, `status`, `description`, `createdAt`, `updatedAt` — in *every* SDK version
  checked. The scanner fed the grader those summaries, so `_target_outbound_types()`
  returned `[]` for every gateway in existence, the `DELEGATED` branch was unreachable,
  and **every** gateway with permissive inbound and at least one target drew a CRITICAL
  claiming its targets "use the gateway's own credentials" — a claim nothing had
  established. That is the mirror of the phantom pass, on exactly the case slice 2.3's own
  docstring says the check exists to avoid failing.
  - The scanner now calls `GetGatewayTarget` per target; `targets_are_graded()` detects
    summaries-where-details-were-needed and resolves to **`UNKNOWN`**, never to `OPEN` —
    the same treatment the refused-read path already gave, for the same reason.
  - `OUTBOUND_CARRIES_CALLER` was **invented**. Read off `CredentialProviderType` in the
    service model: pinned 1.40.51 is `GATEWAY_IAM_ROLE | OAUTH | API_KEY` and has **no
    caller-carrying value at all**; 1.43.51 adds exactly `CALLER_IAM_CREDENTIALS` and
    `JWT_PASSTHROUGH`. `OAUTH_TOKEN_EXCHANGE` exists in neither and is gone. Under the pin
    a gateway therefore *cannot* be graded DELEGATED — a limit of what is knowable, which
    is why it resolves to UNKNOWN.
  - **The tests passed because the fixture was wrong.** `_ac()` returned full targets from
    the *list* call — a response AWS never sends — so every gateway test exercised a shape
    that does not occur. The fixture now returns `TargetSummary` from the list call and
    full detail from `GetGatewayTarget`, and a regression test pins summaries-alone to
    UNKNOWN.
- **`SA-9` (External System Services) is the on-point NIST control for `MCP-01/04` and is
  deliberately not used** — it sits outside the frozen 38-control universe, and adding it
  means authoring a sourced mapping for each of the 40+ frameworks in the crosswalk. That
  is its own work with its own sourcing burden. `SI-7` carries them meanwhile and carries
  them honestly: both findings are about acting on information whose integrity cannot be
  verified, which is the same reason `TPOIS` uses it one level down.

- **`--pentest-results` was inert.** The flag parsed into `args.pentest_results` and was
  never read: `_load_pentest_results` had no caller, `_pentest_results` stayed `{}`, and
  `_emit_pentest_results` returned immediately — the whole of `3.5` was unreachable from
  the command line. It is now loaded in `_apply_phase6_config`, the one seam both the org
  and single-account paths pass through, alongside `3.2`'s pattern set. The wiring tests
  had missed it by setting `_pentest_results` directly, which exercised the emitter and
  skipped the only thing that had to be true for any of it to run; a test now crosses
  that seam.
- **The permission ledger no longer reports a phantom *gap*.** `AMEM-01` is the first
  check spanning **two surfaces** — the Bedrock-agent window (`bedrock:GetAgent`, granted
  since `1.2`) and the AgentCore one (`bedrock-agentcore:GetMemory`, granted by nothing).
  `evaluate()` is AND-semantics, so naming `GetMemory` as a requirement made the preflight
  announce *"AMEM-01 will NOT be evaluated"* into a report that then carried an `AMEM-01`
  row for every Bedrock agent. That is the **mirror of the phantom pass**: a check
  reported as unevaluated when it ran. The requirement is now the action the check needs
  to produce *any* answer, and `CoverageManifest.note_denied()` takes a `scope` so the
  AgentCore denial reads *"AccessDenied for AgentCore memories"* — narrowing the claim
  without softening it (coverage is still incomplete).

- **Phase 3 · slice 3.2 — tool-description poisoning** (`aws_toolpoison.py`,
  `TPOIS-01/02/03`, `--tool-patterns`). A model reads a tool's **description** to decide
  when to call it, which makes the description an instruction channel: whoever can edit
  one addresses the model directly, while the reviewer sees a field that looks like
  documentation.
  - **`TPOIS-01`** (HIGH · SI-7) — the description contains **chat-template delimiters**:
    `<|im_start|>` (ChatML), `[INST]`/`<<SYS>>` (Llama 2, Mistral),
    `<|start_header_id|>` (Llama 3), Anthropic's legacy `Human:` turn marker. These are
    *structural tokens published by model vendors*, not phrasings — a field describing a
    function has no reason to carry one, the way a config value has no reason to begin
    `AKIA`.
  - **`TPOIS-02`** (HIGH · SI-7) — characters **invisible to a reviewer and visible to a
    tokenizer**: zero-width spaces, tag characters, bidirectional overrides (Trojan
    Source applied to a config field). This is the signal most worth having, because the
    entire premise of description poisoning is that somebody looked at the field and saw
    nothing wrong. Any Unicode category `Cf` character is caught, not just a named list.
  - **`TPOIS-03`** (HIGH · SI-7) — a hit from a pattern set **the operator supplies**,
    attributed to the `source` that file declares. A set without a `source` is refused
    outright: a finding that cannot say where its rule came from is one nobody can argue
    with.
  - **OverWatch authors no injection phrasings, and that is the product position.** They
    are unbounded, multilingual and adversarially chosen; a list written here would be a
    detection product whose every miss reads as a clean bill of health and whose every
    over-match teaches operators to skip the category. A test asserts no phrasing creeps
    into the module. Same reasoning as **D4** on red teaming and **2.6** on re-ranking
    rather than re-detecting.
  - **No finding ever quotes the description back.** A report that prints the payload has
    moved it into the ticket and the chat window of whoever triages it. Enforced by tests
    at both the classifier and the scanner surface.
  - Charter-checked before building: a tool description is **configuration**, not
    conversation content — `_CONTENT_KEYS` names conversation payloads and deliberately
    excludes `description`, and `_INGEST_MODULES` covers third-party payload ingest,
    which a config read is not. **No new API call and no new IAM permission**: it reads
    the action-group detail `AGT-04` already fetches.
- **Phase 3 · slice 3.1 — toxic flow** (`aws_toxicflow.py`, `TFLOW-01`, `TFLOW-02`). The
  in-charter answer to *"do you red team?"* (**decision D4**): rather than probing a
  customer's model — which spends their inference budget and produces, in their own
  CloudTrail, the exact signature `AITHR-01` exists to alarm on — compute what an
  injection **would** reach, from configuration already held.
  - **The entry is gated, exactly as `ATT&CK-02` gates a data terminal.** Compute the
    chain always; require a proven entry for the strong finding.
    - **PROVEN** — a knowledge-base data source of type `WEB` (the reference: *"the
      configuration of web URLs to crawl"*), or type `S3` whose bucket policy grants a
      **write** action to a public or external principal. Both are configuration.
    - **ASSUMED** — everything else, reported as **`CONDITIONAL`** and phrased *"IF an
      injection reaches…"*, because an agent's injection surface is frequently invisible
      to a cloud API.
  - A **publicly readable** knowledge-base bucket is deliberately *not* an entry — that
    is a data-exposure problem (`S3-09`), and conflating the two would put the flagship
    finding on every public bucket in the account. Only **write** grants let someone
    plant content. An **unreadable** bucket policy leaves the source assumed: an
    unreadable policy is not an open one.
  - **Attenuation is bounded and never reaches zero.** A guardrail that blocks prompt
    attacks, one IAM makes mandatory, and human confirmation each reduce the flow — but a
    guardrail raises the *cost* of an injection rather than making one impossible, and
    AWS's own reference records that guardrail input tags bypass the input check. A tool
    that let a control erase a path would teach operators the control is a boundary,
    which is the belief `AIGRD-01` exists to correct.
  - **An agent that reaches nothing produces no flow**, however proven its entry. An
    injection arriving somewhere harmless is not a finding, and a flagship that fired on
    every agent would be noise with a good name.
  - `TFLOW-01` is `INFERRED`; **`TFLOW-02` joins `AIPATH-01` in `_CONDITIONAL_IDS`** — the
    class defined in slice 0.4, reached deliberately this time rather than by correction.
  - **No new IAM action.** Every input was already read: `GetDataSource` (granted in 1.2)
    for the entry, the action-group detail for capabilities, the guardrail grades from
    2.1, and the bucket policies `S3-09`/`S3-10` already read. The one call new to the
    scanner is `ListAgentKnowledgeBases`, which `SecurityAudit` already grants — without
    it the injection surface would have to be treated as a property of the region, which
    would attribute one knowledge base's web crawler to every agent in the account.
  - The graph gains a `ToxicFlow` node and **no inbound edge**. Fabricating
    `internet -> agent` is what `_emit_ai_topology` refuses one layer down; doing it here
    would be the same error at the size of the flagship.
- **Phase 2 · slices 2.5–2.7 — Phase 2 complete.**
- **2.5 · agent credential exposure** (`AGC-07`, `AGC-08`).
  - **`AGC-07`** (HIGH · SC-12) — the AgentCore **token vault** is on a
    `ServiceManagedKey`. Not an encryption failure — a **custody** one. The vault holds
    the OAuth2 secrets and API keys agents use to reach systems *outside* AWS, whose logs
    and permission models this account cannot see. A customer-managed key gives three
    levers — revoke by disabling one key, see every decrypt in your own CloudTrail, narrow
    with a key policy — and a service-managed key gives none, for the one store whose use
    is otherwise invisible.
  - **`AGC-08`** (HIGH · SC-8) — a workload identity permits an OAuth2 return URL over
    plaintext `http://`, so an authorization code is handed back in the clear. Only the
    **scheme** is judged: whether AgentCore matches these by prefix, pattern or equality
    is undocumented, and a finding whose severity depends on undocumented matching
    semantics is a guess about someone else's implementation.
- **2.6 · GuardDuty AI Protection ingest, re-ranked** (`aws_aiprotect.py`, `AITHR-03`,
  `AITHR-04`).
  - **The verification pass found why this was needed at all.** `THREAT` already fetched
    GuardDuty findings — and filtered them at `severity >= 4`. GuardDuty's `Low` band is
    `< 4.0`, and **all three AI Protection types ship at `Low`**. So the ingest existed
    and structurally excluded exactly these findings. Fixed with a second, **type-filtered**
    query rather than a lower floor, which would have pulled in every `Low` in the account.
  - **`AITHR-03`** (HIGH · SI-4) — an AI Protection finding whose acting identity can
    escalate privilege or reach crown-jewel data. GuardDuty's `Low` is *correct* for a
    detector holding the event and not the environment; what changes the answer is the
    blast radius, which OverWatch already computes. When the identity is scoped, the
    finding says **the Low stands** — a tool that escalated everything would be as
    useless as one that escalated nothing.
  - **`AITHR-04`** (CRITICAL · SI-4) — a prompt injection the guardrail **detected and did
    not block**. AWS documents `contentPolicyFilters[].action` as `BLOCKED`, or `NONE` if
    the guardrail "detected the prompt attack but was configured only to report it". This
    is `AIGRD-02`'s configuration showing up as an outcome that already happened.
  - Each finding carries **AWS's own MITRE ATLAS technique** (`AML.T0040`, `AML.T0034`,
    `AML.T0051`), quoted rather than assigned.
  - Collected in `THREAT` (regional, where the detector is), assessed in `AI_THREAT`
    (global, after `DATA`, where the crown edges exist). No new IAM grant — `SecurityAudit`
    already grants `guardduty:Get*`/`List*`.
- **2.7 · NIST AI RMF, ISO/IEC 42001 and MITRE ATLAS in the compliance crosswalk**
  (40 → **43 frameworks**, 36 new edges across 20 NIST 800-53 controls).
  - **Mapped at the granularity each source can actually support**, which is the whole
    discipline of the slice. AI RMF is public → exact subcategories (`GOVERN 1.6`,
    `MEASURE 2.7`). ISO 42001 is **paywalled** → **objective level only** (`A.6`, `A.7`,
    `A.9`); writing `A.6.2.4` would look more precise and be less true, and the person
    holding the standard is exactly who would notice. ATLAS is a **threat** knowledge base,
    not a control catalog → an edge means the control **mitigates** the technique, and only
    the three technique IDs AWS publishes are used.
  - **No edge claims `high` confidence.** There is no official NIST 800-53 → AI RMF
    crosswalk; these are OverWatch's reading, and every note says so rather than borrowing
    an authority that does not exist.
- **Phase 2 · slice 2.4 — excessive agency and the human-in-the-loop gate**
  (`aws_agency.py`). OWASP LLM06 splits excessive agency into functionality, permissions
  and autonomy. The middle one was already covered by `AISPM-01/02`; this covers the
  other two, both readable from action-group configuration the scanner **already
  fetches** for `AGT-04`. **No new API call, no new IAM permission.**
  - **`AGY-01`** (CRITICAL · CM-7) — the agent holds `ANTHROPIC.Bash` (shell execution)
    or `ANTHROPIC.Computer` (desktop control).
  - **`AGY-02`** (HIGH · CM-7) — `AMAZON.CodeInterpreter` or `ANTHROPIC.TextEditor`. The
    sandbox around a code interpreter bounds the filesystem, not the credentials the code
    runs with; file *write* is how an injected instruction outlives the conversation that
    delivered it.
  - **`AGY-03`** (MEDIUM · AC-3) — **no action requires human confirmation.** AWS names
    `requireConfirmation` as the prompt-injection safeguard — *"You can safeguard your
    application from malicious prompt injections by requesting confirmation…"* — and
    states its default: *"By default, user confirmation is DISABLED if this field is not
    specified."* So the control AWS itself points at is off unless somebody turned it on,
    and nothing in a cloud inventory shows which agents left it off. Reported as coverage
    (`N of M gated`), matching the guardrail and EDR feeds.
  - Severity is split across three check IDs because `CHECK_SEVERITY` is per check ID: one
    ID would have to price a **shell** and a **text editor** identically, and the wrong
    one would be the shell. `AMAZON.UserInput` raises nothing — it lets the agent ask a
    question, which is the agent deferring rather than acting.
  - **Absent `requireConfirmation` counts as ungated**, and that is a *documented* default
    rather than an assumption — deliberately the opposite treatment from `requireMMDSV2`
    in slice 2.2, where the reference states no default and absent therefore stays
    unknown. Same shape of field, opposite handling, because the documentation differs.
  - **No consequence is inferred from a function's name.** Flagging `delete_account` while
    passing `get_weather` is a guess about semantics wearing the clothes of a configuration
    reading; it fails on any non-English convention, and the first false positive on a
    read-only `purge_cache` is what teaches an operator to skip the category. A test pins
    that no such heuristic creeps in.
  - OpenAPI action groups are reported as **un-assessed**, not ungated:
    `x-requireConfirmation` lives inside a schema payload that may be an S3 object we do
    not read. Calling it ungated invents a gap; calling it gated hides one.
  - The ledger now records that `bedrock:GetAgentActionGroup` buys **four** checks rather
    than one, so declining it names everything it forfeits.
- **D3 · a Cryptographic Bill of Materials** (`aws_cbom.py`, emitted on `--cbom FILE`).
  The xBOM skip is reversed **for cryptography only**. The regulatory driver (EO 14412, a
  FAR rule in flight) and the operational question are the same one — *which of this
  estate's cryptography does a quantum computer break* — and nobody can migrate what they
  have not enumerated.
  - **CycloneDX 1.6**, because `cryptoProperties` does not exist before it. The rest of
    the product emits 1.5 and that stays correct for those documents.
  - KMS keys become `related-crypto-material` (with `state` mapped from `KeyState` —
    `PendingDeletion` is `deactivated`, not `destroyed`, because ciphertext is still
    decryptable until the window closes), ACM certificates become `certificate`, and TLS
    listeners become `protocol`. Algorithms are emitted once and referenced.
  - **No new API call and no new IAM permission.** The material was already being read —
    `kms.describe_key` for KMS-02/03/04, `acm.describe_certificate` for ACM-01..05,
    `elb.describe_listeners` for ELB-02/03 — so the CBOM is a re-projection of responses
    the scanner already holds. A test pins that, so a future dedicated fetch is reminded
    the slice was approved on that basis.
  - **An inventory, not a verdict.** RSA-2048 and P-256 are the correct choice today and
    the wrong choice eventually; reporting them as failures would teach operators to
    dismiss the category. No check IDs, no severity, no posture-score impact — a document
    plus `quantum_exposure()` giving the count and the names, so a migration can be planned
    against a horizon the customer chooses. A test asserts the module emits no verdicts.
  - The document **states its own scope limit** in `metadata.properties`: an agentless scan
    cannot see cryptography inside a workload, and a CBOM that does not say so reads as a
    complete inventory to whoever did not build it.
  - `tests/fixtures/cyclonedx_1_6_crypto.json` holds the enums and property names
    **extracted verbatim** from the published schema, and `aws_cbom`'s constants are
    asserted against it. This is not ceremony: a *summary* of the schema gave
    `parameterizedBy` (real name `parameterSetIdentifier`), an `assetType` of `key` (there
    is none — keys are `related-crypto-material`), a `primitive` enum of algorithm names
    like "AES" (it is crypto primitives: `block-cipher`, `signature`, `kem`), and
    `executionEnvironment` values of `software`/`hybrid` (they are `software-plain-ram`,
    `software-tee`, `hardware`). Each would have produced a document that validates against
    nothing, and none would have failed a test written from the same summary.

- **`docs/DECISIONS.md` — the open product decisions, answered and enforced.** All six
  roadmap decisions (D1–D4, D6, D7; there is no D5) now have a recorded answer, the
  reasoning behind it, and — where one exists — the test that keeps it true.
  - **D2 · does customer prompt text enter the graph? — NO.** Deliberate, not merely
    not-yet-built. The wedge is the sovereign estate, where the security review is
    currently *one line*; reading prompt text turns that into a data-processing
    agreement. The detection value is already delivered by `AITHR-01`/`AITHR-02` from
    **CloudTrail management events alone** — no content, no new permission. Reversal
    conditions are recorded, including that the tripwire ships **before** the capability.
  - **D4 · AI red teaming — OUT OF SCOPE**, recorded as a declared non-goal rather than
    an answered question, under a new **Declared non-goals** section. Both forms are
    named, and the second is the one that matters more: *active probing of live
    endpoints* (whose CloudTrail signature **is** LLMjacking's — we would generate the
    exact events `AITHR-01` alarms on), and ***agentic* red teaming**, driving the
    customer's own tool-executing agent, which causes real **writes** by construction —
    an agent under test does not know the instruction is a drill, and neither does what
    it writes to. Not behind a flag: a flag makes it a supported capability with a
    support burden and an incident path. The section also states what we offer instead
    (toxic flow, graph-proven exploitability, pen-test ingest), because a non-goal that
    only says no reads as a gap.
    The roadmap's remaining charter-breaking items are **referenced, not ruled on** —
    promoting a recommendation to a decision nobody made is how a scope document stops
    being worth reading.
  - **D7 · the Guardrail sibling dependency — DECOUPLED.** Measured rather than recalled:
    11 commits, 2,524 LOC, no Dockerfile, no console entry point, no release workflow.
    OverWatch contains **zero** references to it, and `aws_airules.py` imports only
    `aws_cdr` and `aws_deepplane`. If ever integrated it is an *optional* detection source
    behind the connector plane, never a prerequisite.
  - **D3 · CBOM — BUILT.** Recorded first as deferred, then overruled: build it. The
    reversal covers **cryptography only**; AIBOM/HBOM/QBOM stay skipped.
  - **D1 and D6** are recorded as already taken (slices 1.2 and 1.5) so the file is the
    complete register rather than a list of leftovers.
- **`tests/test_decisions.py`** (10 tests) enforces the answers that have code
  consequences. D4's check is an **AST walk**, not a grep: `aws_aiguard` holds
  `"bedrock:invokemodel"` as a string because it analyses *policy text*, and `aws_airules`
  matches `InvokeModel` as a *CloudTrail event name* — a substring check would flag both
  and force someone to weaken the guard to get a green suite. Both the D4 and D7 guards
  were verified by planting a violation and confirming they fail.

- **Phase 2 · slice 2.3 — gateway authorization posture**, graded rather than counted.
  - **`AGC-05`** (CRITICAL · AC-3) — a gateway that **admits callers it never authorizes
    AND calls its targets with the gateway's own credentials.** Both halves are required,
    and this is the point of the slice: a boolean `authorizerType == "NONE"` check would
    be wrong in the direction that gets a scanner distrusted. AWS documents *both*
    permissive inbound modes as deliberate architectures — `AUTHENTICATE_ONLY` exists so a
    caller's token is verified and forwarded for the target to validate, `NONE` exists so
    an existing system keeps owning the decision. Paired with an outbound type that
    carries the caller's identity (`CALLER_IAM_CREDENTIALS`, `JWT_PASSTHROUGH`,
    on-behalf-of token exchange), the target still authorizes and the design is sound.
    The finding is the combination where it does not, and the developer guide states the
    consequence verbatim: *"The gateway execution role is shared across all targets
    configured with GATEWAY_IAM_ROLE. Its permissions are the upper bound for what any
    authorized caller can exercise through the gateway."* With inbound `NONE`, "any
    caller" includes unauthenticated ones.
    - Four verdicts: `ENFORCED` (gateway authorizes) · `DELEGATED` (caller's identity
      flows onward) · `COMPENSATED` (a policy engine or interceptor sits in front — WARN,
      confirm it covers every target) · `OPEN` (FAIL).
    - `AUTHENTICATE_ONLY` and `NONE` both grade `OPEN` against gateway credentials, and
      the message still distinguishes them: "any authenticated caller" vs
      "unauthenticated callers".
  - **`AGC-06`** (MEDIUM · SC-7) — `exceptionLevel: DEBUG`. Per the reference, *"granular
    exception messages are returned to help a user debug the gateway"* — which on a
    gateway whose callers are not all trusted describes the targets behind it to whoever
    provokes an error.
  - **An unreadable target list is `UNKNOWN`, not `OPEN`.** Reporting a CRITICAL on the
    strength of a refused `ListGatewayTargets` is the phantom-*finding* mirror of a
    phantom pass; empty-because-none and empty-because-refused are kept distinct.
  - Gateway execution roles are stashed into `_aispm_resources`, so `AISPM-01/02` grade
    the very role `AGC-05` names as the upper bound of a caller's reach.
  - Two new IAM actions (`GetGateway`, `ListGatewayTargets`) in both onboarding paths;
    the ledger's reported gap grows 13 → 15.

- **Phase 2 · slice 2.2 — the AgentCore estate** (`aws_agentcore.py`, new `AGENTCORE`
  section). Amazon Bedrock **AgentCore** is a different service from Bedrock Agents, with
  its own control plane (`bedrock-agentcore-control`) and its own IAM prefix
  (`bedrock-agentcore`). An account can run an entire agent estate there — runtimes,
  gateways, memory stores, browsers, code interpreters, workload identities, stored
  third-party credentials — and none of it appears in a Bedrock Agents inventory.
  - **`AGC-01`** (HIGH · CM-6) — the microVM metadata service does not require **MMDSv2**.
    This is EC2's IMDSv1 problem moved inside an agent, and worse there for one reason:
    exploiting IMDSv1 requires making the workload issue an attacker-chosen HTTP request,
    and *making a workload issue an attacker-chosen request is what prompt injection does
    as its normal mode of operation*. One induced GET returns the execution role's
    credentials. Matches `EC2-04`'s severity and control, because it is the same failure.
  - **`AGC-02`** (HIGH · SC-28) — secret-shaped environment variables on a runtime (up to
    50 vars × 5000 chars). Reports **names only, never values**, reusing
    `aws_secrets.env_secret_findings`. Worse than the Lambda equivalent because an agent
    is a machine designed to be talked into revealing what it can see.
  - **`AGC-03`** (MEDIUM · IA-5) — the estate's **external credential surface**. OAuth2
    and API-key providers hold credentials for systems outside AWS, where no IAM policy
    bounds them, no CloudTrail records their use and no KMS key protects what they open.
  - **`AGC-04`** (MEDIUM · CM-7) — the **code-execution surface**: browsers fetch
    arbitrary URLs, code interpreters run arbitrary code, both as the agent's identity.
  - **Runtimes are stashed into `_aispm_resources`** rather than given a parallel
    pipeline, so `AISPM-01/02/03`, the attack-path graph fusion and the guardrail
    coverage feed all apply to AgentCore for free — one implementation of "what can this
    agent's role do" instead of two that drift.
  - **Nine new IAM actions**, all `List`/`Get` config reads, added to both onboarding
    paths. SecurityAudit predates AgentCore entirely and grants none of them. The gap the
    ledger reports grows 4 → 13.
  - Renames the `BEDROCK_AGENTS` section label, which read **"AWS BEDROCK AGENT CORE"**
    while auditing the older `bedrock-agent` API — with a real AgentCore section present,
    two sections would have claimed the same name.
  - Two things checked rather than assumed, both of which changed the code: the published
    API reference is **ahead of the botocore we pin** (it documents Harnesses,
    PaymentConnectors, PolicyEngines and Registries, none of which exist in 1.40.51), so
    the operation set is taken from the pinned service model's own paginator file; and the
    `List` **result keys are not uniform** (`items` for gateways, `browserSummaries` for
    browsers, `memories` for memory), where one wrong guess yields a silently empty
    inventory that reads exactly like a clean account.
  - `network_posture()` deliberately exposes **no** `exposed`/`public`/`ingress` field and
    a test enforces that. The reference gives `networkMode` as `PUBLIC | VPC` and says
    nothing about inbound reachability; who may invoke a runtime is
    `authorizerConfiguration`'s question. This is the AIPATH-01 lesson applied before the
    mistake instead of after it.

### Added
- **Phase 1 · slice 1.5 — a local read-only MCP server** (`cnapp_mcp.py`), closing
  **decision D6**. An analyst can ask a scan questions in natural language instead of
  reading JSON. The server cannot scan, cannot change anything, and never talks to AWS —
  it reads a finished report.
  - **D6 was ruled "ship it enforced".** The server is inside the OverWatch boundary; an
    MCP client never is, and there is no version of this product where we control it.
    The roadmap proposed a warning inside the tool descriptions, but those are read by
    the *model*, not by the engineer editing a config file — a disclaimer, not a
    boundary. So the boundary is enforced instead:
    - **Fail-closed start.** Without `OVERWATCH_MCP_ACK_CLIENT_EGRESS=1` the server
      refuses to run and explains why on stderr, exiting `2`. This makes nobody safer by
      itself; it makes the egress a decision somebody made rather than a default nobody
      noticed.
    - **Identifiers redacted by default.** ARNs, 12-digit account IDs and IPv4 addresses
      become stable pseudonyms (`arn:aws:s3:::s3-7f3a2b`). The analysis travels — *"a
      public bucket reaches a crown datastore"* — and the identity does not. Serving real
      identifiers needs a second explicit flag, following the "hashed by default" line
      already drawn for D2. Pseudonyms are stable *within* a process so an analyst can
      correlate across answers, and different *across* processes so two transcripts
      cannot be joined on them.
    - **Every tool call audited** to a JSONL log — tool, arguments, whether identifiers
      were served, byte count and a SHA-256 of the payload. A digest rather than a second
      copy of the findings. We cannot audit what the client did with a response; we can
      say exactly what left the server, and that is the half we can honour.
  - **Section G of `tests/test_zero_telemetry.py`** pins what is ours to pin: the gate is
    fail-closed, the module imports neither the scanner nor boto3, redaction is the
    default *construction*, and nothing calls `print()` (the MCP spec requires that
    stdout carry protocol messages only). The section header states plainly what it
    **cannot** prove — that the client kept the data inside the boundary — because
    Sections A–F prove OverWatch sends nothing, and a local stdio server passes every one
    of them trivially while being the largest egress decision in the product.
  - Stdlib only, no MCP SDK: the transport is newline-delimited JSON-RPC 2.0, and a
    dependency whose transitive imports could reach a network would undercut the very
    guarantee Section G exists to make testable.
  - Tools: `overwatch_scan_summary`, `overwatch_coverage`, `overwatch_findings`,
    `overwatch_attack_paths`, `overwatch_check_reference`. `overwatch_coverage` is
    deliberately prominent and named in the server's `initialize` instructions, because
    a model asked "am I secure?" over a partial scan will otherwise answer from what it
    was handed — **an unevaluated control is not a passing control.**
  - `docs/MCP.md`, including the local-model configuration that is the only one where
    output stays inside the operator's boundary, and an explicit note that this is a
    *convenience* delta rather than a new capability: a scan already writes every finding
    and ARN to a JSON report that any client could be pointed at today.

- **Phase 2 · slice 2.1 — guardrail GRADING, and enforcement read from IAM text**
  (`aws_aiguard.py`). Every CNAPP, this one included, has checked a guardrail as a
  boolean: `BDR-02` PASSes any guardrail that exists. That boolean is satisfied by
  configurations which block nothing at all.
  - **`AIGRD-01`** (HIGH · CM-6) — no `PROMPT_ATTACK` filter, or one that does not block
    on input, or one below `MEDIUM` strength. Bedrock's six content-filter categories
    grade what a model *says*; only `PROMPT_ATTACK` addresses what a user makes it *do*.
    A guardrail can be a thorough content-safety filter and leave a tool-using agent
    entirely open to instruction hijacking.
  - **`AIGRD-02`** (HIGH · CM-6) — filters set to detect without blocking. The Bedrock
    reference defines action `NONE` exactly: *"Take no action but return detection
    information in the trace response."* Such a guardrail produces telemetry, lets the
    content through, and passes every presence check in the market.
  - **`AIGRD-03`** (HIGH · AC-3) — **the guardrail is available but not mandatory.**
    Attaching one to an agent does not stop a caller invoking the model without it; only
    the `bedrock:GuardrailIdentifier` condition key does, and only with BOTH halves AWS
    documents. The Allow half declines to grant when unmet; the *explicit Deny* is what
    closes the door — it holds *"no matter what other permissions the user might have."*
    A policy carrying the Allow and not the Deny reads like enforcement to a human
    reviewing it and is not. **Costs no new permission** — decided from identity-policy
    statements the scanner already collects.
  - **`AIGRD-04`** (MEDIUM · CM-5) — guardrail exists only as `DRAFT`: edits reach live
    traffic with no published artifact to diff, and a condition key cannot pin what has
    no version number.
  - Also surfaced as a **WARN, not a FAIL**: a role that enforces a guardrail *and* holds
    `InvokeAgent` / `InvokeInlineAgent` / `RetrieveAndGenerate`. AWS documents that those
    make internal `InvokeModel` calls which do not all carry a guardrail, so the Deny
    rejects them. It is the reason teams switch enforcement back off, and a FAIL here
    would push an operator to do exactly that.
  - **A fourth managed-policy gap, found the same way as the first three:**
    `bedrock:GetGuardrail` is not in SecurityAudit v92 — the same List-without-Get shape
    (`ListGuardrails` granted, `GetGuardrail` not) that slice 1.2 found three times.
    `ListGuardrails` returns `GuardrailSummary` only and carries no filter configuration,
    so strength cannot be read without it. Added to both the CloudFormation and Terraform
    onboarding paths; one `Get` buys three checks.
  - Two claims **deliberately not made**, recorded in the module docstring: that a bare
    guardrail ID in a Condition never matches (every AWS example uses the full ARN, but
    the reference does not state what the condition key resolves to at evaluation time —
    flagging it would be an inference about IAM internals dressed as a reading of the
    policy); and that enforcement is absolute (the same page documents that guardrail
    input tags can bypass the guardrail on the prompt, though it always applies on the
    response).

### Fixed
- A runtime `AccessDenied` on `bedrock:GetGuardrail` recorded only `AIGRD-01` as
  unevaluated, leaving `AIGRD-02` and `AIGRD-04` — blocked by the very same read —
  looking clean. That is a phantom pass produced inside the coverage manifest whose
  purpose is preventing them. The set is now derived from the permission ledger
  (`_checks_gated_by`), so a fifth check needing the same read is covered the day it is
  added rather than silently reporting itself as evaluated. The preflight path was
  already correct, having derived it from the ledger all along.

### Changed
- **`AIPATH-01` no longer claims an attack path it never observed.** Slice 0.3 established
  — with the SageMaker API reference quoted verbatim — that every input to
  `ai_network_exposed` is an **egress or isolation** signal, and made `_emit_ai_topology`
  refuse to emit the inbound `internet -[EXPOSED_TO]->` edge that would have made the
  finding enumerate as a real path. That refusal held. The finding's own **prose** did not:
  it went on opening `FUSED AI ATTACK PATH: network-exposed …`, and its detail page
  described "an attacker who reaches the model host". The graph and the sentence describing
  it disagreed for two slices, and only the graph was under test.
  - The message now leads with the two legs that **are** true — unrestricted egress, and a
    role that can escalate privilege or read crown data — and states the premise joining
    them instead of hiding it: *"No inbound route is asserted … IF the resource is
    compromised (prompt injection arrives in content, not over the network)…"*. The pair is
    still worth reporting, because the likeliest compromise of an AI resource needs no
    network route at all.
  - **Epistemic class `INFERRED` → `CONDITIONAL`.** Both legs are genuinely inferred; what
    joins them is a premise, not a derivation. `_CONDITIONAL_IDS` was built in slice 0.4 and
    left empty for Phase 3's toxic flow — its first member turned out to already exist and
    to have been shipping mislabelled, because **adding a category does not reclassify what
    came before it**.
  - **Severity `CRITICAL` → `HIGH`.** `CRITICAL` here means every link was observed
    (`ATTACK-01/02`) or the primitive needs no assumption (`IAMPE-01/03/04`). Nothing pinned
    the old value and sample data carries `AIPATH-01` only in the slice-1.1 permission
    ledger, never as a scored finding, so no fixture or demo output changed.
  - Remediation and detail steps no longer tell operators to re-scan and watch an
    `internet -> AI -> role -> crown` path disappear — it never appeared.
  - The "fused attack path" vocabulary is retired from the severity table, both AI-SPM
    docstrings and the test names, because that phrase *is* the claim in compressed form:
    left in place, the next reader finds a docstring describing a fused attack path beside a
    body that declines to build one, and concludes the body is the bug.

### Added
- `tests/test_aipath_conditional.py` (14 tests) pins **agreement between the finding and the
  graph**, which is the invariant that was missing: whenever `AIPATH-01` fires, the graph must
  carry no inbound edge to the node it names **and** the message must not tell the reader
  otherwise. Testing only the structure is what allowed the prose to drift. The absence
  assertion carries its own positive control (the `HAS_ROLE` edge must be found by the same
  query), so it cannot pass because the graph is empty or the key was misspelled.

## [2.35.0] — 2026

**Coverage-close Batch 1 — "surface over existing engines"** (from the Wiz use-case gap
analysis). Ten use-case gaps closed by exposing signals OverWatch's engines already produce
— no new scanning capability, no charter change. Everything stays agentless, read-only, and
zero-telemetry.

### Added
- **Cost / hygiene findings** (4 new checks, all `WARN`/`LOW` → **zero posture-score impact**;
  the score counts FAIL only): **EBS-05** orphaned (unattached) volumes, **EC2-09** unassociated
  Elastic IPs, **ELB-08** load balancers with no healthy backends, **RDS-13** idle databases
  (zero `DatabaseConnections` over a window, via read-only CloudWatch `GetMetricStatistics`).
  All read-only + **fail-open**, tagged NIST **CM-8** (already in the frozen 38-control universe,
  so it stays at 38).
- **Risk Dashboards** — six named, deep-linkable console screens rolling up the *existing*
  finding catalog by domain: **External Exposure · Data Security · Containers · AI Security ·
  Secrets · Excessive Access**. One shared `CategoryDashboard` over `/findings`—no new backend.
- **MTTR tile + issue burn-down chart** — the drift card now renders median-time-to-remediate
  and SLA breaches (from the already-live `GET /accounts/{id}/mttr`) plus an open-issue-backlog
  burn-down over recent scans (from the stored `total_open` history).
- **Report exports** — three new Reports sections: **Network exposure** (from the `EXPOSED_TO`
  graph edges), **Cross-account network** (trust-boundary-crossing findings), and a one-click
  **Executive HTML** report (assembled in-console, open → print-to-PDF; nothing leaves the
  boundary, no PDF dependency). Host-config report stays a documented, blocked placeholder
  pending the deferred EBS filesystem parse.
- **Projects (LBI / MBI / HBI business-impact grouping)** — read-only, **config-driven**
  (`CNAPP_PROJECTS` env/JSON; no DB table, no schema change) resource groupings with a
  per-project severity roll-up over the current finding catalog (glob + account match). Tier is
  **display-only** — it never feeds the posture or attack-path score (`aws_correlate` stays
  byte-frozen). New `GET /projects` + `/projects/{id}` (viewer-gated) and a `/projects` console.

### Notes
- Adversarial-verified (read-only fan-out): 8 candidates → **7 confirmed defects fixed +
  regression-tested** before release — EC2-09 now fails open (a denied read no longer flips
  CM-8), the dashboard/report/Projects client-side matchers were corrected to mirror the backend
  exactly (sample == live: code-point ordering, fnmatch character classes, all-accounts sweep),
  the Executive HTML no longer renders a `StatusCount` as prose and counts severity from findings
  (correct under org scope), and all finding text is HTML-escaped.

## [2.34.0] — 2026

**Phase-1 "turnkey the wedge + productize the graph"** — four builds that make OverWatch's
sovereign wedge complete and its existing engine legible: a signed offline vuln-feed bundle,
an interactive blast-radius query, the grounded copilot wired into the console, and the
read-only-by-default posture for the (in-progress) agentless EBS side-scan.

### Added
- **Offline vuln-feed bundle** (`overwatch-vulndb`) — the runtime ships a best-in-class
  matching engine but BYO catalog; this turns that into a turnkey, *signed* air-gap artifact.
  `scripts/overwatch_vulndb.py` (pure-stdlib) merges staged OSV + EPSS + KEV into the exact
  `{records, epss, kev, exploits}` JSON the `--vuln-db` loader already parses (records kept
  byte-exact; ecosystems scoped to the engine-matched set), and signs it with a **vendored
  pure-stdlib Ed25519** (`aws_ed25519.py`, RFC 8032, no new runtime dependency — keeps
  `requirements-core` boto3-only). `scripts/build_vulndb_bundle.sh` does the internet fetch in
  **bash** (curl — outside the Python zero-telemetry tripwire), exactly like
  `build_offline_bundle.sh`. New `--vuln-db-pubkey` opt-in: when set, the feed **must** carry a
  valid `<feed>.sig` — an unsigned, tampered, or unresolvable-key feed is **rejected
  fail-closed** (CWPP-04 WARN); unsigned feeds still load when no key is configured.
- **Blast-radius / reverse-reachability** — `SecurityGraph.reverse_reachable()` (an on-demand
  reverse walk; the stored graph + Neptune serialization stay byte-identical) + a read-only
  `GET /accounts/{id}/graph/blast-radius` route (viewer-gated, tenant-scoped) + an interactive
  `@xyflow` panel launched from any attack-path node: "what can this node reach (crown-jewels /
  admin) and what can reach it," over the frozen `aws_correlate.E_PATH` edge universe. The
  client computes it identically to the hub in sample mode (code-point-exact ordering parity).
- **"Ask OverWatch" copilot in the console** — the grounded, abstain-guarded RAG copilot was
  API-wired but had no UI; now a slide-over chat panel renders its answers + citations + a
  "grounded · retrieval-only" chip. The LLM stays a backend-only seam — the browser never
  calls a model host, so the air-gap holds.
- **Two-key EBS side-scan IAM split** — a new read-only `CnappSideScanReadOnly` grant
  (`enable_sidescan_read`, in the Terraform module + the CFN twin, parity-tested) so the
  **default** pre-existing-snapshot side-scan mode needs *zero* write IAM on the scanned
  account; point-in-time create-snapshot stays a separate opt-in write grant.
- **Agentless EBS filesystem partition plane** (`aws_sidescan_fs.py`) — a dependency-free
  GPT/MBR partition-table reader + Linux root-filesystem selection over the reassembled
  `SparseImageIO`, filling the pre-committed `DissectExtractor` seam. It fails **safe** on an
  encrypted (LUKS), LVM, or unreadable volume (honest note / `SideScanUnavailable` →
  CWPP-04 INFO) — never a false-clean inventory.

### Notes
- The userspace ext4/xfs *byte-parse* (via a pinned `dissect.target`) is a tracked **Linux-CI
  follow-on**: it needs golden filesystem images (`mkfs`) that can't be produced on the
  Windows dev host, so — matching the repo's existing `parse_windows_software_hive` /
  `parse_rpmdb_bdb` deferral discipline — `DissectExtractor` stays inert (INFO) until the
  parse is validated against a golden image on a Linux runner, at which point the flagship
  EC2 VM scan flips live.

## [2.33.0] — 2026

**Multi-tenancy hardening: workspace-scoped connectors** (closes the last MSSP isolation
gap). The connector framework was global — in a multi-tenant hub, tenant A could see,
manage, and receive tenant B's connectors. Now each connector binds to exactly one
workspace and every path is tenant-isolated. Single-tenant / no-`WorkspaceStore`
deployments stay **byte-identical** (filters engage only when a `WorkspaceStore` is wired).

### Added
- `connector_workspace` binding table (`SCHEMA_VERSION 8→9`, sqlite + Postgres twins) — a
  structural mirror of `workspace_accounts` (a *binding table*, not a column add, because
  the migration mechanism is additive-`CREATE TABLE IF NOT EXISTS` only — the repo has zero
  `ALTER TABLE`). Every pre-existing connector is backfilled to `ws-default` on open.
- `connector_gate` (mirrors `account_gate`) on every `{connector_id}` route — a cross-tenant
  or unknown connector returns **404** (existence-hiding, never 403). `POST /connectors`
  binds the new connector to the caller's workspace in the same transaction; the id-less
  reads (`GET /connectors`, `/notifications`, `/digests`) are filtered to the caller's
  workspace. Superadmins retain a cross-tenant read view (no extra schema).
- Delivery-path scoping: a scan of an account resolves *its* workspace, and `run_rules` /
  `run_digest` load ONLY that workspace's connectors/rules/ledger — so a cross-tenant
  delivery is structurally impossible (a foreign connector is absent from the match dict).

### Fixed
- A `rule_id` cross-read: a foreign rule id under your own connector previously returned the
  *other* tenant's rule body at HTTP 200 — now 404 (the rule must belong to the connector).
- **CDR needed no change** — detections are account-scoped and `/org/incidents` already fans
  out over workspace-filtered accounts; a regression test locks it.
- Read-only adversarial verification (10 agents) confirmed **5 defects → all fixed +
  regression-tested**: (HIGH) `preview_rules` (the rule dry-run) loaded connectors/rules
  globally, leaking another tenant's connector ids/names + rule ids — now scoped like
  `run_rules`; (MED) `delete_workspace` ignored bound connectors → an opaque 500 and an
  undeletable workspace — now a clean guard; (MED) the global-unique `connectors.name`
  collision surfaced as a 500 and a weak existence oracle — now a clean 400 that never
  discloses which tenant holds the name (per-workspace name uniqueness is a documented
  follow-up needing an index-drop migration). Full suite **1823 passing**.

## [2.32.0] — 2026

**Hub hardening: a psycopg3 connection pool for the Postgres backend** (the last deferred
scale item). Until now `PostgresBackend` held one connection and serialized *all* hub DB
work on a single process-wide lock — under the FastAPI threadpool, every request queued
behind every other. No behavior change; the sqlite path is byte-identical.

### Changed
- `cnapp_backend.Backend` gains a thread-local connection seam (`_conn()`): on the pooled
  path each operation borrows a connection from a `psycopg_pool.ConnectionPool` (real
  concurrency, no global lock), while a `transaction()` checks out ONE connection for its
  whole duration so nested ops reuse it and different threads run in parallel. The sqlite /
  injected-connection path is unchanged (single connection under the reentrant lock).
- `PostgresBackend.connect()` builds the pool (`min=2`/`max=10`, env-overridable via
  `CNAPP_DB_POOL_MIN`/`CNAPP_DB_POOL_MAX`) and **fails loud** at startup if Postgres is
  unreachable — never a silent sqlite fallback. The pool's `configure` callback forces
  `autocommit=True` on every connection (psycopg_pool defaults to `False`), preserving the
  no-idle-in-transaction guarantee the single-connection design had.
- `record_health`'s cross-connection read-modify-write (the `consecutive_failures` backoff)
  is now wrapped in `Backend.serialized()` — a pooled `transaction()` gives per-row
  atomicity but not mutual exclusion, so two concurrent validations on two pooled
  connections would otherwise lose an increment. On sqlite it is a reentrant no-op.
- `psycopg-pool==3.3.1` was already pinned; no new dependency. Full suite **1812 passing**.

## [2.31.0] — 2026

**Phase-4 Slice-5: agentless ECR registry enumeration + opt-in layer-pull.** Closes the
supply-chain loop — OverWatch now discovers and scans the registry itself, not only SBOMs a
CI pipeline pushes. Two tiers; `aws_correlate.py` byte-frozen; `SCHEMA_VERSION` stays 8; the
no-flag default path is unchanged except for the intended Tier-A coverage widening.

### Added — Tier A: enumeration + native scan findings (no new IAM grant)
- CNT-02 now enriches the newest-N **tagged** images per repo (was: the newest image only),
  reading Amazon's own scan findings (basic `findings[]` / enhanced `enhancedFindings[]`).
  Untagged images (usually orphaned build artifacts) are skipped. Bounded per repo
  (`--ecr-scan-max-images`, default 20) AND by a per-scan aggregate budget (400) so a large
  estate can't multiply `DescribeImageScanFindings` into a throttle/wall-time blow-up.
- Registry scan-mode detection (`get_registry_scanning_configuration`) records BASIC vs
  ENHANCED (surfaced in the console; hints where Tier B adds the most value).

### Added — Tier B: opt-in layer-pull → own SBOM (Inspector-independent)
- Two-key gate (both required): the `--side-scan-images` flag **and** the opt-in
  `CnappImageLayerPull` IAM grant. Pulls image layers, reconstructs the rootfs, and runs
  OverWatch's own SBOM→OSV/EPSS/KEV pipeline — coverage even when a registry uses basic
  scanning or none. New pure `aws_registry_sbom.py` (`select_registry_images` /
  `scan_registry_image` / `_package_to_component` / `registry_sbom_doc_id` / `to_cyclonedx`).
- New checks **CWPP-05** (HIGH) / **CWPP-06** (CRITICAL, KEV) for registry-image CVEs
  (CRITICAL/HIGH-or-KEV only, matching the Tier-A law), plus full risk/impact/remediation
  write-ups. Native (`ecr-native-scan`) and own-SBOM (`ecr-sidescan`) CVEs MERGE-converge on
  the same `ECRImage` node, split only by a `scan_source` property.
- Pulled SBOMs persist as durable Slice-4 snapshots (via `ingest_document`), so **diff /
  license policy / VEX apply for free**. A registry-only image (no inbound `RUNS_IMAGE`)
  carries `HAS_VULN` but never enters `E_PATH` — it ranks shift-left, never a false CRITICAL.

### Added — egress seam, IAM, API, console
- `aws_layer_fetch.py` — the shipped default `http_get`: the SOLE new network primitive,
  HTTPS + `*.amazonaws.com`-only (re-validated on every redirect), byte-capped, and
  fail-closed on a short read. Registered in `test_zero_telemetry.py` + NETWORK.md.
- `CnappImageLayerPull` opt-in grant in the CFN role + the count-gated Terraform module
  (`enable_image_layer_pull`, default false), repo-scoped + tag-gated on `cnapp:imagescan`;
  the always-on role never grants a layer-pull action (parity-tested, incl. Resource/Condition).
- Read-only routes `GET /accounts/{id}/registry/{repos,images}`; a console **Registry** tab
  on Supply Chain (repos → images, deployed vs registry-only, scan-source chips, and a
  "not reachable" shift-left label on registry-only CVEs).

### Verified
- Read-only adversarial verification (14 agents) confirmed **20 defects → 18 fixed +
  regression-tested**: (HIGH) the layer-fetch followed redirects, bypassing the HTTPS/AWS-only
  SSRF guard → a redirect-revalidating opener; (HIGH) a truncated download returned partial
  bytes → Content-Length validated, fail-closed; (HIGH) a corrupt/dropped layer still returned
  a "complete" scan (false-clean) → `merge_layers` now reports dropped-layer/truncation stats
  and the registry scan fail-closes `partial-rootfs`; (HIGH) CNT-02 per-CVE findings were
  swept into per-repo posture; (MED) size-cap bypass on unknown `imageSizeInBytes`; (MED)
  CWPP-05/06 emitted for every severity; (MED) posture-only repos hidden / registry-wide
  CNT-06 shown as a fake repo; (MED) no aggregate Tier-A budget; (MED) parity never checked
  the tag/resource scope; (LOW) snapshot CVE-set accumulated across feed changes → replace-set;
  and more. Full Python suite **1811 passing**; frontend build + lint + vitest green.

## [2.30.0] — 2026

**Phase-4 Slice-4: supply-chain ingest — SBOM snapshot/diff · license policy · standalone
VEX · a CI/CD image-scan Action.** Turns the external-vuln ingest plane into a durable,
diffable software-supply-chain timeline. Zero new AWS grant, zero scanned-account contact
(works purely off uploaded SBOM/VEX docs + the account's stored graph); `aws_correlate.py`
is byte-frozen. *(Registry scan scheduling — the only piece needing a new IAM grant — is a
separate fast-follow Slice-5.)*

### Added — SBOM snapshots + diff
- Every inventory-lane ingest (CycloneDX / SPDX / Syft) now persists a **durable SBOM
  snapshot** — the full component set (a superset of the matched packages, keeping purl-less
  OS packages) plus that scan's immutable CVE set — keyed idempotently by content hash.
- **`aws_sbom_diff.py`** (pure) diffs two snapshots of the same subject: components
  added / removed / version-changed / license-changed, and the CVE delta (new / fixed) from
  an immutable set-diff. New viewer routes `GET /accounts/{id}/sbom/{subjects,snapshots,diff}`
  and `/components` (account-isolated; the diff auto-pairs the latest two of a subject).

### Added — license policy (`aws_license.py`, pure)
- Captures the raw license of every component (CycloneDX `licenses[]` + evidence; SPDX
  `licenseConcluded`/`Declared`), normalizes it to a canonical SPDX id + category
  (deprecated-id fold, `WITH`-exception strip, expression resolution — `OR` → most-permissive
  arm, `AND` → most-restrictive), and evaluates a **config-overridable policy** (default:
  deny network-copyleft/proprietary, review strong-copyleft/unknown). Verdicts are computed
  **on read**, so a policy change needs no re-ingest. `GET /accounts/{id}/license-findings`
  (LIC-DENY → CM-7, LIC-REVIEW → CM-8; in the frozen 38-control crosswalk universe).

### Added — standalone VEX (`aws_vex.py`, pure)
- Parses **OpenVEX** and **CSAF-VEX** documents into a durable, subcomponent-scoped ledger
  (`vex_statements`). Suppression is **bidirectional** — a `not_affected`/`fixed` statement
  suppresses an already-ingested (node, cve) row AND a statement that arrives *before* the
  scan suppresses the new row, so a false-positive never resurrects on SBOM re-ingest.
  Suppression rides the existing `ingested_vulns.suppressed` column + the empty-path
  invariant, so `aws_correlate.py` is untouched (sha256-pinned by `test_correlate_frozen.py`).
  `GET /accounts/{id}/vex`.

### Added — CI/CD image-scan Action + ingest-only RBAC tier
- **`.github/actions/overwatch-image-scan/`** — a shell-only GitHub composite action: scan an
  already-built image with Trivy → post its CycloneDX SBOM to the hub's ingest endpoint.
  Read-only + zero-telemetry (no Python under `.github/`; scans an existing image, calls no
  cloud API; posts once over HTTPS with no redirects; fails closed on an empty token).
- A below-admin **`ingest`** RBAC tier (viewer < ingest < admin): a CI token can POST to
  `/ingest` but **cannot** onboard/delete accounts or run scans — so a leaked CI token can't
  compromise the account.

### Added — schema + console
- `SCHEMA_VERSION 7 → 8` (additive): `sbom_snapshots`, `sbom_components`, `sbom_snapshot_cves`,
  `vex_statements` (+ Postgres BIGINT twins).
- A new **Supply Chain** console screen (`/supply-chain`): SBOM Diff, Components & License, and
  VEX tabs, over zero-AWS sample fixtures.

### Notes
- `aws_correlate.py` is byte-unchanged; the ingest match lane (`packages` → `match_vulns`) is
  byte-identical (license capture rides a separate `components` output).

## [2.29.0] — 2026

**Phase-4 Slice-3: an interactive product tour + shareable deep links.** A guided, self-driving
tour that replays canned scenarios over the REAL console — navigating, setting scope, spotlighting
live elements, and opening real panels — plus the refactor that makes it possible: the URL is now
the single source of truth for scope and every open panel, so views are shareable, bookmarkable,
and refresh-safe. Frontend-only; `aws_live_scanner.py` and the hub API are unchanged.

### Added — URL-as-source-of-truth (shareable deep links)
- **Scope in the URL** (`?scope=<account>`; absent ⇒ org) — a pasted link carries both the scope and
  any open panel. `state/scope.tsx` now derives scope from the URL and clears panel params on a scope
  switch (an open panel from another account is never resolved to nothing).
- **`lib/deeplink.ts`** — a shared `useDeepLinkPanel(param)` hook binds each screen's open panel to a
  URL search param (functional updater preserves sibling params; panels default to `replace` history),
  plus URL-safe id codecs: a collision-free `pathId` (readable `internet__customers-db__<hash>`, since
  the engine emits parallel routes to the same crown) and a lossless `vulnKey`, with resolvers that run
  against the **unfiltered** catalog so a deep link opens its target even when the current filters would
  hide it.
- Every panel is now deep-linkable: Attack Paths `?path`, Findings / Remediation `?detail`,
  Vulnerabilities `?vuln` and `?upload`, Cloud Accounts `?onboard`, Settings `?tab`+`?connector`,
  Compliance `?framework`+`?controls`, Identity `?principal`, Inventory `?view`.

### Added — the product tour (`lib/tour/` + `components/tour/`)
- A portalled overlay (above the slide-overs / modals) that drives navigation + scope + panels by
  **navigating to one URL per step**, then spotlights a real element via a `data-tour` anchor resolved
  with a `MutationObserver` (waits past `<Loader/>` gates) and a post-open re-measure window (defeats
  the slide-over transform race). Auto-advance is gated on a settle-once flag, so it never restarts on
  scroll re-measures.
- **Hybrid** replay: auto-advancing steps plus take-the-wheel interactive beats where the user clicks
  the spotlighted real control to continue (a four-pane mask leaves that control clickable).
- **Five canned scenarios** grounded in the sample data: trace a critical attack path (flagship),
  reachability beats CVSS, triage & route a finding, keyless onboarding, and one-scan-every-framework.
- Three entry points: a floating launcher + scenario gallery (with session resume), a "Take a tour"
  item in the top bar, and a dismissible first-run prompt (never auto-starts).
- Accessibility: `inert` app-root + focus into the coachmark on auto steps; focus to the live control
  on interactive steps; `aria-live` step announcements; full keyboard map (Esc / ← / → / Space, ignored
  while typing); `prefers-reduced-motion` disables auto-advance, animated scroll, and transitions.

### Added — test harness + guardrails
- **Vitest** (the frontend's first JS test harness) — `deeplink.test.ts` (id codecs vs the real
  fixtures, incl. pathId-collision + vulnKey regressions) and `scenarios/scenarios.test.ts`, a guardrail
  that fails the build if any scenario references a drifted fixture id (path / vuln / finding / control)
  or a `data-tour` anchor that doesn't exist in source. Plus a DEV-only structural validator.

### Fixed — from read-only adversarial review (8 confirmed defects)
- Collision-free `pathId` (was `entry__terminal`, which opened the wrong parallel path); lossless
  single-param `?vuln=<vulnKey>` (was a lossy `?cve`+`?node` that could open the wrong row); the
  deep-linked vuln row is now exempt from the facet filters (was a silent no-op when off-path); the
  Ingest modal is gated to account scope (`?upload=1` in org scope targeted account "org"); the
  Compliance failing-controls chevron stays collapsible under a deep link; the tour keyboard handler no
  longer hijacks Esc/←/→ while typing in an input; the first-run prompt is marked seen on Start; and
  `waitForAnchor` takes an `AbortSignal` so a step change tears its `MutationObserver` down.

### Notes
- The console is byte-behaviorally unchanged when the tour is idle: the overlay renders `null` and
  mounts no listeners, and every `data-tour` addition is an inert attribute.

## [2.28.0] — 2026

**Phase-4 Slice-2: air-gapped / zero-telemetry packaging + a Terraform onboarding module + an
AWS Marketplace listing.** Packages OverWatch for offline / air-gapped deployment and adds a
second onboarding path (Terraform) and a distribution path (Marketplace). No scanner-engine
change; `aws_live_scanner.py`'s logic is untouched.

### Added — zero-telemetry proof + air-gapped packaging
- **`NETWORK.md`** — the complete egress inventory. OverWatch makes ZERO telemetry / analytics /
  phone-home / update-check calls; every egress is either an AWS API (boto3) or an
  operator-configured, opt-in, injected seam pointed at the operator's own resources. Enforced by
  **`tests/test_zero_telemetry.py`** — a tripwire that fails the moment a telemetry SDK, a network
  primitive outside the two allowlisted files, a hardcoded foreign host, a shell-out, or a loosened
  SSRF/TLS guard is introduced (recursive AST scan of every shipped module).
- **Offline packaging** — pinned `requirements.txt` / `requirements-core.txt` / `requirements-dev.txt`;
  a multi-stage non-root **`Dockerfile`** that installs from a wheelhouse with `--no-index` (zero
  build-time internet); **`scripts/build_offline_bundle.sh`** (wheelhouse + prebuilt SPA + image →
  one transfer tarball); a new fail-closed ASGI launcher **`cnapp_server.py`**
  (`uvicorn cnapp_server:create_app_from_env --factory`); and **`docs/AIRGAP_RUNBOOK.md`** (AWS via
  VPC endpoints, vuln bundle from disk, no public egress).

### Added — Terraform onboarding module (`deploy/terraform/scanner-role/`)
- An IaC alternative to the CloudFormation Launch-Stack flow that produces a role **byte-equivalent
  in effect** to `deploy/cnapp-scanner-role.yaml` (the read-only `CnappScannerRole` under your
  per-tenant ExternalId; `SecurityAudit` + `ViewOnlyAccess`, never `ReadOnlyAccess`; the same inline
  extras; every write/data grant an opt-in toggle; the EKS KSPM access-entry). A structural parity
  test (`tests/test_terraform_parity.py`) asserts the TF and CFN stay in lock-step action-for-action.

### Added — AWS Marketplace listing (`deploy/marketplace/`)
- A self-hosted **container product** (the buyer runs the hub in their own account — air-gappable,
  zero-telemetry): listing metadata, a buyer deploy template, and pricing tied to the Slice-1 metering
  (**accounts under management**) — a metered `MeterUsage` SKU plus a contract SKU for air-gapped
  buyers with no metering egress. Optional opt-in emitter `cnapp_marketplace_metering.py`
  (boto3-injected, offline-tested).

### Verified
- Read-only adversarial verification fixed **9 confirmed defects** (all with regression tests) —
  most were holes in the new guard/parity tests themselves: a **critical** dependency conflict
  (`boto3==1.40.51` requires `botocore<1.41.0`, so the `botocore==1.43.51` pin broke the whole
  offline build — corrected to `1.40.51`); the zero-telemetry tripwire only scanned root-level
  modules and missed the `from urllib import request` form, `subprocess`/shell-out egress, and
  sub-package code (now recursive + AST-hardened); the Terraform parity test never compared the four
  opt-in blocks or the EKS access entry, and used loose substring matching (now exact-set); the TF
  provider floor was below the EKS access-entry resources (`>= 5.33.0`); and `meter_hourly`'s
  documented duplicate no-op wasn't actually handled.

## [2.27.0] — 2026

**Phase-4 Slice-1: multi-tenancy / workspaces + workspace-scoped RBAC + usage metering (the MSSP play).**
One hub now serves many tenant *workspaces*, each isolated and metered — without breaking the
single-tenant deployment or any of the ~1623 pre-tenancy tests. `aws_live_scanner.py` (the scanner
engine) is unchanged; this is entirely in the hosted control plane.

### Added — data model (`SCHEMA_VERSION 6→7`, additive, sqlite + Postgres twins)
- `workspaces` (tenant orgs), `workspace_members` (principal→role directory), `workspace_accounts`
  (account→workspace binding; `account_id` PK ⇒ exactly one workspace per account),
  `platform_admins` (MSSP operators), and an append-only `usage_events` metering ledger
  (exactly-once via `UNIQUE(workspace_id, metric, event_key)`). A `ws-default` workspace is seeded
  and **every pre-existing account backfilled into it** at `cnapp_backend.backend_for`, so a
  single-tenant hub and the whole test suite behave identically.

### Added — workspace-scoped RBAC (`cnapp_api.py`)
- A frozen `Principal` (subject + `{workspace_id: role}` memberships + a platform-superadmin flag)
  from an injected `current_principal` hook (IdP/JWT claims in production), with a back-compat shim
  that maps the legacy `current_role` string onto the default workspace. The target workspace comes
  from an `X-Workspace-Id` header (member/superadmin only), and `require(min_role)` evaluates the
  role IN that workspace. New `require_superadmin`, `account_gate` (role + tenant isolation → **404**
  existence-hiding on a cross-tenant account), and `ws_admin_gate`/`ws_member_gate`. Fail-closed
  preserved (unset hook / non-member ⇒ deny).

### Added — tenant isolation + control plane (`cnapp_service.py`, `cnapp_workspace.py`)
- Every account-scoped route enforces `account_in_scope`; `list_accounts`/`org_*`/`trigger_scan`/
  `schedule_due_scans` are workspace-scoped (single-tenant / no-store ⇒ global, byte-identical);
  onboarding binds the account into the caller's workspace in the same txn (a cross-tenant re-onboard
  ⇒ **409**); a superadmin with no workspace selected gets an **all-workspaces** combined view.
  `WorkspaceStore` CRUD + `POST/GET/PUT/DELETE /workspaces`, member management, and
  `/admin/platform-admins`.

### Added — usage metering (`cnapp_metering.py`, billable = accounts under management)
- Fail-open `MeteringStore` (a metering error can never break a scan/onboard/ingest) recording an
  `account.active` monthly gauge (one per account per billing period, emitted at scan-complete +
  re-derivable by an idempotent `reconcile`), plus `account.onboarded` / `scan.completed` for
  observability. Per-workspace `GET /workspaces/{ws}/usage` and a superadmin cross-workspace
  `GET /admin/usage` + `POST /admin/usage/reconcile`.

### Verified
- Read-only adversarial verification fixed **5 confirmed defects** (all with regression tests): two
  cross-tenant leaks on routes where the account isn't a path param — `GET /scans/{job_id}` (a scan
  job carries `account_id`) and `POST /connectors/rules/preview` (account in the body) now isolate to
  404; `POST /scans/schedule-tick` was a single-tenant admin driving the *global* scheduler → now
  scoped to the caller's workspace; and two control-plane 500s (duplicate workspace slug → 409;
  member-add to a missing workspace → 404).

### Deferred (documented, next companion slice)
- **Connector + CDR/ingest tenant-scoping.** Connectors remain global (one `UNIQUE(name)` namespace +
  shared outbound secrets); a fast follow-up will add `workspace_id` to connectors + notification
  isolation. Until then a workspace admin can see/rotate another workspace's connector config.

## [2.26.0] — 2026

**Slice 3: AI-SPM pillar + CDR-lite streaming detection ingest + cloud-forensics timeline.**
Three defense-in-depth capabilities, each built on the existing attack-path graph with
**`aws_correlate.py` byte-unchanged** (proven by a test): they reuse the prop-based `crown_nodes`,
the `HAS_ROLE` / `CAN_READ_DATA` / `THREAT_ON` edge kinds, and the ingest reachability stack —
never a new special-case. All new NIST tags stay inside the frozen 38-control universe
(`AC-6`/`AC-3`/`SC-7`/`SI-4`), and every new read stays inside the read-only-of-config contract.

### Added — AI-SPM pillar (`aws_aispm.py`, pure)
- Turns the scattered Bedrock/SageMaker config checks into a coherent posture on the *blast radius
  of the identity an AI resource runs as*: `role_privesc_capable` (execution role can escalate),
  `role_reaches_crown` (a graph query over the `CAN_READ_DATA` edges the DSPM/Macie passes emit),
  `ai_network_exposed`, `is_ai_crown`.
- `_collect_aispm` runs **last in the DATA section (post-clobber)** off resources stashed pre-clobber
  in the SageMaker/Bedrock-agent sections: emits `AISPM-01` (privesc-capable role, HIGH/AC-6),
  `AISPM-02` (role reaches crown data, HIGH/AC-3), `AISPM-03` (no network isolation, MEDIUM/SC-7),
  and the fused **`AIPATH-01`** (CRITICAL/AC-6+SC-28 — a network-exposed AI resource whose role can
  escalate or read crown data). Emits a `HAS_ROLE` anchor so the correlate engine treats a
  compromised model/agent as a real hop; marks data-bearing Studio domains as crown terminals.
  Fail-open `AISPM-00` INFO when principals can't be enumerated (never a phantom PASS). No new AWS
  calls (reuses cached IAM principals + already-fetched describe payloads).

### Added — CDR-lite streaming detection ingest (`aws_cdr.py`, pure)
- A hosted, fail-open plane that folds live detection events onto the account's stored
  `graph_full` as `THREAT_ON` annotations and ranks each by **actual attack-path reachability**.
  Three normalizers — `normalize_guardduty` (reuses `map_guardduty_finding`; binds AccessKey
  detections to the real IAM principal), `normalize_asff` (Security Hub; skips
  ARCHIVED/SUPPRESSED/RESOLVED/[SAMPLE]), `normalize_cloudtrail_anomaly` (root-usage /
  security-tooling-tamper / credential-creation / denied — lighting the reserved THREAT-02
  semantics). `compute_detection_verdicts` re-runs `enumerate_paths` reusing
  `aws_ingest._ingest_predicates`, so a detection ON an internet→crown/admin path or directly on a
  crown store escalates to an **incident** — a detection on an isolated node never does (honest;
  no phantom escalation), and it collapses honestly when there is no scan yet.
- `cnapp_service.ingest_detection` / `list_detections` / `list_incidents` / `org_incidents` /
  `refresh_detection_escalation`; synthetic `THREAT-ING`/`THREAT-ING-KEV` catalog entries so
  incidents route through the existing on-attack-path connector rules. `cnapp_api`:
  `POST /accounts/{id}/detections` (admin), `GET …/detections`, `GET …/incidents`,
  `POST …/detections/refresh`, `GET /org/incidents`. New `cdr_detections` store
  (`SCHEMA_VERSION 5→6`, additive, sqlite + Postgres twins; dedup by id, preserves `first_seen`;
  cross-account ARN → 400).

### Added — cloud-forensics timeline (`aws_forensics.py`, pure)
- `build_timeline` reconstructs who-did-what-when around a resource from read-only CloudTrail
  management events and correlates it with the graph / findings / live CDR detections, flagging
  per-event anomalies with the same signals the CDR plane uses. Injected `trail_reader` seam
  (default `default_trail_lookup`, the only socket touch — `cloudtrail:LookupEvents`, mgmt-events
  only). `cnapp_service.forensics_timeline` + `GET /accounts/{id}/forensics/timeline` (viewer).
  INFO-only: `FORENSIC-00` is a fail-open marker (seam absent/denied → name the prereq, never a
  phantom clean timeline) and stays out of every scanner metadata map.

### Verified
- Read-only adversarial-verification pass over the whole slice fixed **2 confirmed defects**
  (both with regression tests): a GuardDuty AccessKey detection could false-join to a non-principal
  IAM node (instance-profile/policy/group) and fabricate a phantom incident — now bound to genuine
  principals only; and `refresh_detection_escalation` dropped `node_key`, so an initially-unmapped
  GuardDuty detection could never be re-mapped once a later scan graphed its resource — `node_key`
  is now persisted and restored.

## [2.25.0] — 2026

**Slice 2: grounded-RAG security copilot (scoped v1).** A copilot that answers natural-language
questions using ONLY this account's own scan output — the `finding_catalog`, ranked attack
`paths`, and choke points (the "remediation" is the per-finding steps + choke-point hints). No
external knowledge, no hallucination.

### Added — `aws_copilot.py` (pure, boto3-free, offline-first)
- `build_corpus(findings, paths, chokes)` turns the scan into retrievable documents; a
  self-contained **BM25** retriever (no embeddings, no network, deterministic); `detect_intent`
  routes top-risks / attack-paths / choke-points / how-to-fix questions to structured answers,
  else falls back to retrieval.
- `answer(question, corpus, llm=None)` — the default is an **EXTRACTIVE** synthesizer that composes
  the reply purely from retrieved corpus fields, so it cannot state a fact that is not in the scan.
  It **ABSTAINS** (rather than inventing) when a question shares no term with the scan corpus, and
  every answer carries **citations** that are always corpus ids (check IDs / path ids / choke node
  ids). An optional **injected LLM seam** (`(system, question, context) -> str`) gets ONLY the
  retrieved corpus as context plus a system prompt forbidding outside knowledge; an LLM error falls
  back to the grounded extractive answer (never fails the query).

### Added — hosted wiring
- `cnapp_service.copilot_answer(account_id, question)` / `org_copilot_answer(question)` build the
  corpus from the latest scan(s) and answer; the LLM seam is the optional `copilot_llm` constructor
  arg (default `None` → offline extractive). `cnapp_api` routes `POST /accounts/{id}/copilot` and
  `POST /org/copilot` (viewer RBAC; `CopilotReq{question}` is length-validated). The default scanner
  role and the engine are unchanged; the React console can call these directly (chat UI is a
  frontend follow-up).

## [2.24.0] — 2026

**Slice 1: DSPM surfaces + AWS-resident secrets + least-privilege policy generation.** Three
data/identity-security sub-features built on the existing DSPM crown-jewel, CIEM, and secrets
engines. `aws_correlate.py` is unchanged except a single 1-line data edit (adding
`OpenSearchDomain` to `CROWN_DATASTORE_KINDS`); every crown node is picked up by the prop-based
`crown_nodes`, and all new graph emission is post-clobber in the DATA section.

### Added — DSPM datastore surfaces
- Crown-jewel data classification now spans **DocumentDB, Neptune, MemoryDB, FSx, Kinesis Data
  Streams, Timestream, and OpenSearch** in addition to S3/RDS/Redshift/DynamoDB/EFS. DocDB and
  Neptune are split out of `describe_db_clusters` by `Engine` (zero new API); the rest are
  fail-open collectors (denied describe → a DSPM-01 INFO naming the store, never a phantom PASS).
  Extends `aws_deepplane.DSPM_READ_ACTIONS` with the new kinds (precise `es`/`kinesis`/`timestream`
  read actions; empty sets for DocDB/MemoryDB/FSx where auth is out-of-band → node emitted, no
  `CAN_READ_DATA` edge).
- **DSPM-03** (MEDIUM, AC-3) — a crown datastore with a public/cross-account **resource policy**
  (OpenSearch `AccessPolicies`), reusing `classify_resource_policy_stmt`; fine-grained-access-control
  domains are downgraded to WARN/paths-to-verify. (DSPM-04 backup-coverage and DSPM-05 CMK-vs-managed
  deferred — cross-cutting / FP-prone.)

### Added — AWS-resident secrets (new `aws_secrets.py`, pure)
- SSM Parameter Store posture: **SECRET-01** (HIGH, SC-28) plaintext `String` parameter with a
  credential-shaped name; **SECRET-02** (LOW, SC-12(1)) SecureString on the AWS-managed key not a CMK.
  Metadata-only (`describe_parameters`) — never a value read (`ssm:GetParameter`/`GetSecretValue`
  deliberately not used).
- A crown **`Secret`** graph node (Secrets Manager secrets + SSM SecureStrings) + a `CAN_READ_DATA`
  reader edge for every role whose identity policy can read it (reuses `role_can_read_store` with the
  new `SECRET_READ_ACTIONS`), so **internet → workload → role → Secret** surfaces as an attack path
  via the existing flagship; **SECRET-05** (HIGH, AC-6) is the reader finding. Only materialized when
  ≥1 role can read it (no graph clutter). **SECRET-00** is the fail-open INFO. (SECRET-03 staleness /
  SECRET-04 config-reference scans deferred — the latter overlaps existing LMB-03/ECS-04/EC2-07.)

### Added — least-privilege policy generation (new `aws_leastpriv.py`, pure) + CIEM-02
- `rightsize_policy` / `recommendation`: given a principal's GRANTED actions (GAAD) and USED
  services/actions (IAM service-last-accessed), emit a right-sized IAM policy document that drops
  never-used services and narrows `svc:*` wildcards to the used action set where action-level usage
  is known. Deterministic, offline, and honest: empty usage or an incomplete SLAD job → not
  recommended (**never a deny-all**); the window is stated and it is never auto-applied.
- **CIEM-02** (WARN) wires it into `--ciem` for the principals CIEM-01 already flags (bounding the
  extra ACTION_LEVEL SLAD cost); the generated policy + delta ride the `least_privilege` report
  side-channel. **CIEM-00** is the fail-open INFO. CIEM-02 is deliberately kept OUT of `COMPLIANCE_MAP`
  (a WARN counts as failing its mapped control, which would flip AC-6 for every over-permissioned
  principal). Uses only already-held grants (ACTION_LEVEL SLAD = same permission as SERVICE_LEVEL);
  the Access Analyzer `StartPolicyGeneration` live path is deferred.

### Compliance / tests
- Every new NIST mapping uses an **in-universe** control (SC-28/SC-12(1)/AC-3/AC-6) with the full
  framework tuple copied verbatim from an existing entry — the frozen 38-control crosswalk universe
  is byte-unchanged. New tests: `test_dspm_surfaces`, `test_secrets`, `test_secrets_collector`,
  `test_leastpriv`, `test_leastpriv_wiring`, and additions to `test_phase7_dspm`.

## [2.23.0] — 2026

**VPC Flow-Log network graph + SG/NACL micro-segmentation (Phase-3 · agentless coverage).**
A two-layer network-segmentation slice: an always-on, config-only static analysis of security
groups, plus an opt-in observed-traffic overlay that reads VPC Flow Logs to make evidence-based
tightening recommendations. `aws_correlate.py` is unchanged — the SG and observed-flow overlays
stay OUT of the traversable attack-path edge set, preserving the 4-gate reachability low-FP
guarantee.

### Added — Layer A: static SG micro-segmentation (`SEG-01..06`, always-on, ZERO new grant)
- Pure detection in `aws_exposure.py` (`microseg_findings`) over the SG/ENI dicts `_check_exposure`
  already fetches — no new API, no new IAM. A **distinct lens** from the 4-gate `compute_exposure`
  oracle: it flags an over-permissive SG even when the host is not internet-reachable, and covers
  only the sensitive ports **VPC-01 does not**, so the two never double-FAIL the same rule.
  - **SEG-01** world-open sensitive/non-web port on an attached SG (web-allowlist: 80/443/8443 to
    0.0.0.0/0 is not a finding); **SEG-02** overly-wide world-open range (`≥100` ports or `-1`
    all-traffic); **SEG-03** redundant/shadowed ingress rule (conservative single-rule cover, no
    FP on partial overlap); **SEG-04** unused SG (no ENI, no rule reference — fail-open when ENIs
    can't be enumerated); **SEG-05** SG-chaining to a world-open SG (transitive internet path);
    **SEG-06** internet-exposed SG that also allows unrestricted egress (exfil path).
- Graph overlay: config-only `SecurityGroup` nodes + `IN_SG` / `WORLD_OPEN` / `SG_ALLOWS_FROM`
  edges tagged `basis='sg-static', verified=False` and kept OUT of `aws_correlate.E_PATH` (never
  traversed) so config-level openness is never mistaken for reachability-verified exposure. The
  `SecurityGroup` node kind routes to `aws_remediate`'s `sg_scope_ingress` fix.

### Added — Layer B: VPC Flow-Log observed-traffic overlay (`FLOW-00..03`, opt-in `--flow-logs`)
- New boto3-free module `aws_flowlog.py`: the flow-log readability gate, `LogFormat` parser +
  required-field check, server-side CloudWatch Logs Insights query builders (`parse @message` →
  `stats … by`, prefers `pkt-srcaddr` for the true origin behind NAT/EKS), the world-open-port
  join, and the three deciders. The single socket-touching function `default_flow_read`
  (`start_query` → poll `get_query_results` → flattened rows) is the **injected seam**
  (`self._flow_read`), mirroring the KSPM K8s seam; tests replace it with canned Insights rows.
  - **FLOW-01** evidence-based scope-down (a 0.0.0.0/0 rule whose accepts collapse to a few /24s
    → "scope to these prefixes"); **FLOW-02** allowed-but-unused world-open port on an active ENI
    (removal candidate, WARN only, window stated); **FLOW-03** top blocked-inbound reject/recon
    talkers; **FLOW-00** fail-open INFO naming the exact missing prereq (flow logs off /
    S3-or-Firehose destination / custom LogFormat missing fields / `logs:StartQuery` denied /
    query timeout / empty window) — never a phantom PASS.
- Graph overlay: `ObservedCidr` nodes + `OBSERVED_FLOW` edges, and **annotation** of the existing
  4-gate `internet -EXPOSED_TO-> eni` edges with `observed` / `observed_src_cidrs` /
  `observed_zero_flow_ports` — evidence markers on the verified edges, never a parallel/traversable
  path (also kept out of `E_PATH`). Emitted inline in `_check_exposure` (post-clobber; no stash/replay).
- **Access model:** reading flow-log CONTENT is a NEW, OPTIONAL, resource-scoped grant
  (`logs:StartQuery` + `logs:GetQueryResults`) absent from both `SecurityAudit` and `ViewOnlyAccess`
  — it crosses the read-only-of-CONFIG line by action class, so it is opt-in, default-OFF, and
  windowed/server-side-aggregated to bound the per-GB-scanned Insights cost. The default scanner
  role is unchanged; a commented `CnappFlowLogInsights` opt-in block is added to
  `deploy/cnapp-scanner-role.yaml`. The S3-delivered path (needs `s3:GetObject`) is deliberately
  not supported. New `--flow-logs` CLI flag.

### Compliance / metadata
- `SEG-01/02/05` land in all four maps (`CHECK_SEVERITY`, `COMPLIANCE_MAP`, `REMEDIATION_MAP`,
  `aws_finding_detail.FINDING_DETAIL`); `SEG-06` and `FLOW-01/02` carry compliance (WARN). Every
  new NIST mapping uses an **in-universe** control (SC-7 / CM-7 / SI-4) — the frozen 38-control
  crosswalk universe is untouched.

### Tests
- `tests/test_exposure.py` — SEG-01..06 FP/FN catalog (incl. the web-ALB-is-not-a-finding case,
  VPC-01 dedup, partial-overlap-not-redundant, fail-open) + scanner-wiring & graph-overlay tests.
- `tests/test_phase3_flowlog.py` — `aws_flowlog` pure core, `default_flow_read` (fake logs client,
  timeout→stop_query), and `_check_flowlog` FLOW-00..03 + graph-annotation + full fail-open matrix.

## [2.22.0] — 2026

**Agentless KSPM + KIEM — CIS-EKS + Kubernetes RBAC via the read-only Kubernetes API, folded
into the attack-path graph (Phase-3 · agentless coverage).** OverWatch now reads Kubernetes
posture without an in-cluster agent, and discovers cross-plane attack paths that bridge a
compromised pod into the AWS account.

### Added — `aws_kube.py` (pure, boto3-free, socket-free core)
- The **EKS Kubernetes-API bearer-token minter** (`k8s-aws-v1.` presigned STS
  `GetCallerIdentity`, cluster-bound via the signed `x-k8s-aws-id` header — pure SigV4, offline),
  the EKS **access-policy tier** classifier, the **RBAC effective-privilege evaluator** (anonymous
  bindings, wildcard/cluster-admin, escalate/bind/impersonate, secret-read), and the **IRSA /
  Pod-Security / PSA / NetworkPolicy** classifiers + the reachability decision. READ-ONLY:
  effective RBAC is computed here from listed objects, so the scanner never issues a
  `*SubjectAccessReview` / `TokenReview` (those are POST/create).

### Added — layered, fail-open collection (`aws_live_scanner.py`)
- **Layer A (always on, no grant, no reachability):** the AWS **EKS Access Entries** API →
  AWS-principal cluster-admin / over-priv (**KIEM-01/02/03**), **EKS Pod Identity** →
  ServiceAccount→IAM-role edges, and the `authenticationMode` posture (**EKS-08**). Uses only
  `eks:List*/Describe*` already covered by `SecurityAudit` — no CFN change.
- **Layer B (optional, injected read-only K8s-API seam):** `GET`/`LIST` on RBAC / ServiceAccounts /
  Pods / Pod-Security-Admission labels / NetworkPolicies → **KSPM-01..07** (CIS Amazon EKS
  K8s-side). Reachability-gated (private-only endpoint / no grant / `CONFIG_MAP`-only →
  **KSPM-00** INFO naming the prerequisite; never a crash or a phantom PASS).

### Added — cross-plane graph + the marquee path
- New node kinds `EKSCluster` / `KubeServiceAccount` / `KubePod` / **`KubeAdminCapability`**
  (`crown_jewel=True`, picked up prop-based by `crown_nodes`). Every K8s edge reuses an existing
  `E_PATH` kind (`HAS_ROLE` / `CAN_ASSUME` / `CAN_PRIVESC_TO`), so **`aws_correlate.py` is
  UNCHANGED** (the `RUNS_IMAGE` ex-gate is kind-agnostic — a pod inherits image CVEs with no
  `_EXPLOIT_KINDS` edit, exactly like Fargate). Clobber-safe `_kube_payloads` stash → `_emit_one_kube`
  / `_replay_kube_edges`, emitted inline in EXPOSURE for exposed pods and replayed in VULN#40.
- **KIEM-04** — IRSA / Pod-Identity cross-plane: a ServiceAccount whose assumed AWS role reaches
  AWS admin or crown data. `enumerate_paths` discovers the ranked path
  `internet → exposed pod (image CVE) → ServiceAccount → IRSA role → AWS admin / crown`; an EKS pod
  behind an internet-facing ALB (ip-target = the pod's VPC-CNI IP) is the internet entry hop.

### Read-only + onboarding
- `GET`/`LIST` only on both planes. The Layer-B K8s API needs one *optional, opt-in* onboarding
  step (an EKS read access entry / read-only ClusterRole) documented in
  `deploy/cnapp-scanner-role.yaml`; the scanner never creates it. `VERSION` → 2.22.0.

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
