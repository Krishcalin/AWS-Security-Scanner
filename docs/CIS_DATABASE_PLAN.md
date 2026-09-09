# CIS AWS Database Services Benchmark v2.0.0 — implementation plan

## Status

| # | Scope | Planned | Actual | State |
|---|---|---:|---|---|
| 0 | The 98-row mapping table + `NOT_DETERMINABLE` | 0 | **98 rows**, as data in `engine/aws_cis_db_map.py` | done |
| 1 | Fix the AUR engine filter | 0 | **6** (DOCDB-04/05, NEP-01..04) | done |
| 2 | `CIS-DB` key + map the already-covered recs | 0 | **42 checks keyed**; 31 recommendations covered | done |
| 3 | TLS enforcement | ~4 | **4** (RDS-14, AUR-06, DOCDB-06, NEP-05) | done |
| 4 | Cluster-level 2.8/2.10; ElastiCache fields | ~3 | **4** (AUR-07/08, ELC-07/08) | done |
| 5 | MemoryDB | ~5 | **6** (MDB-01..06) | done |
| 6 | Neptune + Keyspaces + Timestream | ~10 | **2** (TS-01/02); Neptune landed in 1; Keyspaces declined | done |

**22 checks added. 503 → 525.** Sections 94 → 97 (NEPTUNE, MEMORYDB, TIMESTREAM).
Proven-failing 413 → 435; every new check is proven, so the count moved by exactly the
number added each time. Suite 6018 → 6151 passing.

**Three things went differently from the plan, and all three are worth recording:**

1. **Tranche 1 was not free.** The plan said 0 new checks. Filtering the Aurora loop alone
   would have *deleted* four real findings — DocumentDB deletion protection and snapshot
   encryption, and all of Neptune — so six ids exist to keep them under correct labels.
   Deleting findings is not a fix for mislabelling them.
2. **Keyspaces was built and withdrawn.** Its control-plane reads are authorised by
   `cassandra:Select`, the same action that reads table rows, and AWS offers no
   metadata-only alternative. `tests/test_perm_ledger.py` caught it. See
   `aws_cis_db.NOT_DETERMINABLE['keyspaces-needs-a-data-read-grant']` — a decision about
   the *grant*, not about feasibility.
3. **QLDB is declined on stronger grounds than proposed.** Not "AWS is retiring it", which
   is a judgement, but "botocore ships no service model for it", which is checkable and is
   asserted by a test.

**All seven tranches are now done.** Tranches 0 and 2 were blocked on the benchmark
document and are complete as of its arrival: see
[`CIS_DATABASE_BENCHMARK.md`](CIS_DATABASE_BENCHMARK.md) for all 98 recommendations
and what OverWatch does about each, and `engine/aws_cis_db_map.py` for the mapping
held as data so it cannot drift from the catalogue.

The mapping pass found one thing worth its own line: **the RDS instance loop still
scores Neptune and DocumentDB instances as RDS** — the tranche-1 cluster defect,
one level down. It is recorded in the benchmark document rather than fixed here,
because fixing it means adding Neptune and DocumentDB instance-level checks in the
same change, for exactly the reason tranche 1 grew from 0 checks to 6: filtering
alone would delete the only coverage of Neptune 9.8 and 9.9.

The rest of this document is the original plan as written, kept for the reasoning.
`docs/CIS_COMPUTE_BENCHMARK.md` is what the finished article looks like, and this should be
replaced by its equivalent (`docs/CIS_DATABASE_BENCHMARK.md`) once tranche 0 can run.

---

> **On the source document.** CIS Benchmarks may not be redistributed, and the PDF is
> deliberately not in this repository — it stays in the session scratchpad only. What is
> cited below is the recommendation *number*, which is a reference; every description is
> written from the underlying AWS behaviour rather than copied from the benchmark's own
> rationale, audit or remediation text. The same convention the Compute mapping uses.

---

## 1. What this benchmark actually is

98 recommendations across ten service sections:

| § | Service | Recs | OverWatch today |
|---|---|---:|---|
| 2 | Aurora | 11 | AUR-01..05, plus RDS-0x at instance level |
| 3 | RDS | 14 | RDS-01..06, 08, 11, 12, 13 |
| 4 | DynamoDB | 9 | DDB-01..05 |
| 5 | ElastiCache | 13 | ELC-01..06 |
| 6 | MemoryDB | 7 | **nothing** |
| 7 | DocumentDB | 12 | DOCDB-01..03 |
| 8 | Keyspaces | 4 | **nothing** — no `keyspaces` client call exists |
| 9 | Neptune | 11 | **nothing** — DSPM discovery only |
| 10 | Timestream | 10 | **nothing** — DSPM discovery only |
| 11 | QLDB | 7 | **nothing** — and see §6 below |

**Every single recommendation is marked "(Manual)". None is Automated.** That is the most
important fact about this document and it shapes everything below.

The Change History says v2.0.0 added exactly five things: database public access, delete
protection, IAM authentication, Aurora encryption at rest, and enforcing encryption in
transit at the database level. Those additions are precisely the recommendations that
carry a real, runnable CLI audit command. The pre-2.0.0 majority is largely console
click-paths, and a substantial number have an **empty Rationale and an empty Remediation
section**. A benchmark row with no rationale and no remediation is not a control; it is a
placeholder.

**Practical consequence:** the honest yield here is far below 98. Treating "98
recommendations" as "98 checks to write" would manufacture a large number of checks that
either cannot fire or assert something the AWS API does not expose. The Compute benchmark
had 82 recommendations and yielded 43 new checks; this one is weaker source material and
should be expected to yield proportionally less.

### Defects in the benchmark itself

Worth recording, because they will otherwise be rediscovered as "bugs" during
implementation:

- **5.8, 5.9, 5.10** sit under the ElastiCache heading, but their audit steps walk the
  **Amazon Keyspaces** console. They are misfiled.
- **5.7 and 5.10** share the same title.
- **7.3** instructs you to Modify an existing DocumentDB cluster to turn on encryption at
  rest. That is not possible — DocumentDB encryption is creation-time only, which
  OverWatch's own DOCDB-02 remediation text already states correctly.
- **3.13**'s audit command is `describe-db-clusters`, which returns nothing at all for a
  non-clustered RDS instance — the exact resource the section is about.
- **10.10**'s remediation carries leftover point-in-time-recovery text from 4.9.
- **5.13** audits `SnapshotRetentionLimit`, which is meaningless for a Memcached cluster.

Where a recommendation is implemented despite one of these, the check should follow the
*intent* and the doc row should say so.

---

## 2. Triage

Three buckets, following the Compute precedent. The full 98-row table is the first
deliverable (tranche 0), not a guess made here.

### (a) Already covered

Roughly 40 recommendations map onto checks that already exist — the RDS, DynamoDB,
ElastiCache and DocumentDB sections are in reasonable shape. These need a `CIS-DB`
compliance-map entry and a doc row, **not new code**. This is the cheapest and largest
single block of the whole exercise.

Two of these are only *partially* covered and need the check widened rather than a new one:

- **2.8 (Aurora backup retention)** and **2.10 (Aurora IAM auth)** — RDS-03 and RDS-08 read
  `BackupRetentionPeriod` and `IAMDatabaseAuthenticationEnabled` from
  `describe_db_instances`. For an Aurora cluster both settings live on the **cluster**, and
  a Serverless v1 / headless cluster has no instances to read at all. The fix is to read the
  same two fields from the cluster page that AUR-01/02/03 already fetches.

### (b) Real, machine-checkable gaps

Ranked by value:

1. **TLS enforcement at the database level** — CIS 2.3, 3.6, 7.4, 9.3. This spans Aurora,
   RDS, DocumentDB and Neptune, it is one of the five flagged v2.0.0 additions, and it is
   cleanly readable from `describe_db_parameters` / `describe_db_cluster_parameters`
   (`rds.force_ssl` for Postgres, `require_secure_transport` for MySQL/Aurora-MySQL, `tls`
   for DocumentDB/Neptune). **OverWatch has zero coverage of it** — a repo-wide search for
   `force_ssl`, `require_secure_transport`, `describe_db_parameters` and
   `describe_db_cluster_parameters` returns nothing. Note that ElastiCache in-transit
   encryption *is* covered, at `engine/aws_live_scanner.py:8510`, via the
   `TransitEncryptionEnabled` flag — that is a different mechanism and is not the gap.
   This is the single highest-value item in the plan.
2. **ElastiCache 5.11 / 5.12 / 5.13** — `SnapshotRetentionLimit`, `MultiAZ` and
   `ClusterEnabled` are not read anywhere. Three fields already present in a response the
   scanner is already paginating.
3. **MemoryDB (§6, 7 recs)** — the client is constructed exactly once, for DSPM crown-jewel
   discovery. No posture checks. `describe_clusters` carries encryption, TLS, ACL and
   snapshot-retention state.
4. **Neptune (§9, 11 recs)** — same situation, made worse by the defect in §3 below.
5. **Keyspaces (§8, 4 recs)** — no `keyspaces` client call exists anywhere in the codebase.
   Small section, so a small new module.
6. **Timestream (§10, 10 recs)** — client exists for DSPM only. Note that `_dspm_timestream`
   was fixed this cycle to walk `NextToken` directly because timestream-write declares no
   paginators; any new code must do the same.

### (c) Not determinable

The `NOT_DETERMINABLE` dict in `engine/aws_cis_compute.py` is the precedent: 5 of 82
Compute recommendations were declined **in data, with a written reason each**, rather than
registered as checks that could never fire. The Database benchmark needs the same treatment
and will need it more often, because so many rows are console walkthroughs.

Expect this bucket to be materially larger than Compute's 5. Categories:

- **In-database state** — database users, grants, password policies, schema-level
  encryption. Not readable from the control plane; reading it would require credentials
  into the database, which breaks the read-only-of-CONFIG charter.
- **Rows with no rationale and no remediation** — nothing to assert.
- **"Review X regularly" / "ensure a process exists"** — process controls, not resource
  state.
- **The misfiled 5.8–5.10** — cover them under Keyspaces where they belong, and record
  that decision.

A declined recommendation with a reason is a better product than a check that always
returns INFO. The coverage test should read the same dict the doc reads, so the two cannot
drift.

---

## 3. A pre-existing defect to fix first

**AUR-01/02/03 score DocumentDB and Neptune clusters as Aurora.**

The loop at `engine/aws_live_scanner.py:5415` iterates everything
`rds:DescribeDBClusters` returns, with **no `Engine` filter**. That API also returns
DocumentDB and Neptune clusters — a fact this codebase already knows and handles correctly
elsewhere, in the DSPM path at `engine/aws_live_scanner.py:17181`, which branches on
`Engine` to give docdb and neptune their own crown-jewel kinds precisely so they are not
"mis-labelled RDSCluster".

Proven, not inferred — feeding one unencrypted DocumentDB cluster and one unencrypted
Neptune cluster to `_check_rds()` produces:

```
FAIL AUR-01  my-docdb     Cluster storage encryption=OFF | my-docdb (docdb)
FAIL AUR-02  my-docdb     Cluster deletion protection=OFF | my-docdb
FAIL AUR-01  my-neptune   Cluster storage encryption=OFF | my-neptune (neptune)
FAIL AUR-02  my-neptune   Cluster deletion protection=OFF | my-neptune
```

Two consequences:

- **A DocumentDB cluster's encryption gap is reported twice** — once as AUR-01 (HIGH,
  "Cluster storage encryption") and once as DOCDB-02 (HIGH, same fact, correct service),
  since both RDS and DOCDB are in the default `SECTIONS` list. Same resource, same
  finding, two ids, two severities, and remediation text that contradicts itself: AUR-01
  offers a modify path, DOCDB-02 correctly says DocumentDB encryption cannot be changed
  in place.
- **Neptune posture is reported under Aurora labelling.** This is the more damaging half,
  because it makes §9 look partially covered when nothing in the codebase knows what
  Neptune is. Any Neptune work built on top of this would be built on a false baseline.

**Fix before any new Database checks land**, because the Neptune tranche depends on the
answer: filter the AUR loop to Aurora engines (`aurora`, `aurora-mysql`,
`aurora-postgresql`, plus the Multi-AZ DB cluster engines `mysql` and `postgres` the
comment at 5399 says the loop exists for), and route `docdb` / `neptune` to their own
handlers. Deletion protection and engine EOL are genuine controls for both — they should
keep being checked, under the right ids.

This is a behaviour change to shipped checks, so it needs its own commit, its own test,
and a `CHECK_FIRING.md` regeneration. It is not a refactor to fold into a feature tranche.

*(An earlier read of mine flagged RDS-03's `MultiAZ` as a dead local. That was wrong —
it is used at line 5263 and emits its own PASS/WARN pair. RDS-03 is fine.)*

---

## 4. Structure

### The `CIS-DB` compliance key

A new key, for the reason `CIS-COMPUTE` needed one: the 123 checks carrying a plain `CIS`
key are all **CIS AWS Foundations** numbering, and service benchmarks re-use those section
numbers for unrelated controls. Folding Database numbering into `CIS` would mis-cite every
mapping in both directions.

Requires adding `"CIS-DB"` to `ALLOWED_FRAMEWORKS` at
`tests/test_check_maps_lockstep.py:46`, which currently reads
`{"CIS", "CIS-COMPUTE", "PCI-DSS", "HIPAA", "SOC2", "NIST"}`.

### `engine/aws_cis_db.py`

Mirrors `engine/aws_cis_compute.py`: a pure module with no boto3 import, taking response
dicts and returning verdict dicts, so every rule is unit-testable without a client. Carries
its own `NOT_DETERMINABLE: Dict[str, str]`, its own `_cis(base, number)` helper, and an
`__all__` the coverage test reads.

### Section registration

New sections must be added in **four** places or they will not run: `SECTIONS` (the default
run list — 94 entries today), `SECTION_LABELS`, the section dispatch map, and optionally
`GLOBAL_SECTIONS`. A section present in dispatch but absent from `SECTIONS` never executes
on a default scan, which is the failure mode to watch for.

Sections needed: **MEMORYDB**, **KEYSPACES**, **NEPTUNE**. Timestream can extend an
existing section or take its own; that is a tranche-6 decision. None of these five
(`MEMORYDB`, `KEYSPACES`, `NEPTUNE`, `TIMESTREAM`, `QLDB`) is in `SECTIONS` today.

### Per-check obligations

Every new check pays the standard toll, and this is most of the real work:

- `CheckDef` in `engine/aws_checkdef.py` — validated at construction: severity in
  `SEVERITIES`; **all four** of PCI-DSS, HIPAA, SOC2, NIST mapped; remediation containing
  a literal `aws ` command; `risk` ≥ 200 characters; non-empty `impact`; ≥ 2 `steps`.
- `Perm(action, why)` for every new API call — read verb only, `why` ≥ 31 characters — and
  a `tests/perm_ledger_baseline.py --update` run. **New IAM actions mean customers must
  update their scanning role**, so the permission delta belongs in the release notes, not
  just the ledger.
- A test that drives the check to a real FAIL. `CHECK_FIRING.md` is generated, never
  hand-edited: `$env:OVERWATCH_RECORD_CHECKS = "fired.json"; python -m pytest tests/ -q`
  then `python scripts/check_firing.py --from fired.json`.
- Ratchet updates: `MIN_PROVEN_FAILING` in `tests/test_check_firing.py` (413 today), plus
  `python tests/test_suite_ratchet.py --update`. The staleness test requires the bounds sit
  within 5 of actual, so these cannot be left stale.

**Watch out:** `CHECK_SEVERITY` contains 42 duplicate keys. A dict literal keeps the last
one, so editing the first occurrence of an id silently changes nothing.

---

## 5. Tranches

Sequenced so each lands independently and the riskiest correction goes first.

| # | Scope | New checks | Notes |
|---|---|---:|---|
| **0** | The 98-row mapping table + `NOT_DETERMINABLE` with reasons | 0 | Decides everything below; produces `docs/CIS_DATABASE_BENCHMARK.md` |
| **1** | Fix the AUR engine filter; route docdb/neptune correctly | 0 | Behaviour change to shipped checks — own commit, own test |
| **2** | `CIS-DB` key + map the ~40 already-covered recs | 0 | Pure mapping; largest coverage gain per unit of work |
| **3** | **TLS enforcement** across Aurora/RDS/DocDB/Neptune | ~4 | The headline gap; needs `describe_db_*_parameters` + 2 new IAM actions |
| **4** | Widen 2.8 / 2.10 to cluster level; ElastiCache 5.11–5.13 | ~3 | All fields already in responses being paginated |
| **5** | MemoryDB posture (§6) | ~5 | New section, new client usage |
| **6** | Neptune (§9) + Keyspaces (§8) + Timestream (§10) | ~10 | Depends on tranche 1; Timestream must use `_tokens`, not `get_paginator` |

Tranches 0–2 involve no new checks and would move CIS-DB coverage from nothing to roughly
40 recommendations. If only part of this ships, that is the part worth shipping.

---

## 6. Recommendation: decline §11 (QLDB) wholesale

Seven recommendations, for a service **AWS is retiring**. Writing checks for a service with
a published end-of-life is work that becomes dead code on a known date, and a compliance
report that scores a customer against QLDB configuration is advising them to invest in a
platform they must leave.

Record all seven in `NOT_DETERMINABLE` with that as the stated reason — declined as a
product decision, not because the API cannot be read. That distinction should be visible in
the reason text so a future reader does not "fix" it.

If the appetite is to be comprehensive regardless, the counter-argument is that a customer
still running QLDB is exactly the customer who needs to be told to leave it. That argues
for **one** check — "QLDB ledgers exist in an account and the service is being
retired" — rather than seven configuration checks. That is the better version of covering
§11, and it is one check, not seven.
