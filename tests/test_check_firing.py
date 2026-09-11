"""The catalogue promises 460 checks. This is how many the suite proves.

WHY A RECORDING AND NOT A GREP. "Which checks can produce a finding" reads like a
source question and is not one. A check id reaches `_add` as a literal, a bare
variable (`fid`), a subscript (`f["id"]`) or a conditional, and every one of the
scanner's 90 sections uses at least one non-literal form. Four successive static
passes gave four different answers — 76, 48, 42, then 0 — and only the last was
honest, because nothing is provable that way. So `tests/conftest.py` records
`AWSLiveScanner._add` (the single point where every finding in the product is
constructed) across a real suite run, and `scripts/check_firing.py` turns that into
`docs/CHECK_FIRING.md`.

THE THREE STATES, and the distinction that carries the value:

  * PROVEN FAILING — a test drives the check to an actual FAIL. It works.
  * RUNS, NEVER FAILS — it emits, but nothing has made it report a problem. Not
    automatically a defect: a check may legitimately only ever warn. But `_add` reads
    severity, compliance and remediation from the maps ONLY for a FAIL — a WARN is
    forced to LOW and carries no remediation — so a check registered CRITICAL that
    only ever WARNs has never rendered what the catalogue advertises for it.
  * NEVER OBSERVED — no test makes it emit anything at all. This is where a genuinely
    dead check hides: THREAT-02 is registered in all four maps, carries a full
    remediation write-up, is counted in the published total, and is emitted by no code
    path anywhere. Nothing in the build said so until this file existed.

WHAT THIS FILE DOES NOT CLAIM. "Never observed in the suite" is not "cannot fire". It
is a TEST-COVERAGE fact: most are checks nobody has written a driving test for rather
than checks that are broken. The value is that the number is visible and can only go
down, and that a genuinely unreachable check can no longer hide among them.

The first tranche bore that out. `tests/test_unproven_checks_tranche1.py` drove 14
never-observed checks across four sections; seven reached FAIL on a genuinely bad
configuration, and seven could not — a topic with no CMK is exactly what SNS-01
describes and it emits WARN, so its declared MEDIUM is reachable only by making the
AWS call throw. None of the fourteen was broken. The dead ones are rarer than the
untested ones, which is why the count needs measuring rather than guessing.
"""
from __future__ import annotations

import io
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "CHECK_FIRING.md")

#: THE TWO ENDS RATCHET; THE MIDDLE IS A RESIDUAL. An earlier version of this file
#: also capped "runs but never fails", and that was wrong: driving a check from
#: "never observed" into that bucket is PROGRESS, and a ceiling on it scores progress
#: as regression. The first tranche of driven checks (tests/test_unproven_checks_
#: tranche1.py) moved 15 checks out of never-observed — 7 to proven-failing and 8 to
#: the middle — and tripped the ceiling it had just improved. Tranche 2 then moved
#: 5 more from the middle to proven-failing, including both CRITICALs (RDS-02, RDS-06).
#: Tranche 3 took the whole LOGGING section, which no test had ever called, straight
#: from never-observed to proven-failing. Tranche 4 did the same for the 14 IAM
#: privesc rules: their matcher was already well unit-tested as a pure function, but
#: those tests never reach `_add`, so no IAMPE finding had ever been constructed —
#: tested logic and a proven finding are different claims.
#:
#: LMB-08/LMB-09 (Lambda function URLs) are the first checks added SINCE this file
#: existed, and they arrived with driving tests rather than as two more entries in the
#: never-observed list: the catalogue went 458 -> 460 and proven-failing went 303 ->
#: 305, leaving the unobserved count flat. That is the shape a new check is supposed
#: to have, and the ratchet is what makes it the path of least resistance.
#:
#: The honest invariants are the ends: unobserved can only fall, proven-failing can
#: only rise. Lower/raise these when the doc is regenerated; never the other way.
#: NHI-01..05 are the first checks moved by fixing a REACHABILITY defect rather than
#: by writing a fixture. `engine/aws_nhi.py` was complete and callerless: imported by
#: three production modules (its CheckDefs register at import time, which is what put
#: the five ids in all four maps) and referenced by none, so the checks were
#: catalogued, counted in the published total, and could not fire. Wiring the NHI
#: section moved all five straight to proven-failing: 305 -> 310 and 70 -> 65.
#:
#: One of the five needed more than a caller. NHI-01 is gated on a `machine` verdict,
#: and a console password is CONFIGURED human evidence -- so `classify_principal`
#: never returns `machine` for the identity NHI-01 describes, and the check was
#: unsatisfiable through the module's own classifier. See
#: `AWSLiveScanner._nhi_classification`, and `test_nhi.py`, whose NHI-01 test supplies
#: a verdict by hand precisely because nothing else could.
#: The bucket-B pass then moved 17 more from the middle to proven-failing (310 -> 327,
#: and 85 -> 68 in the middle). Those were not new fixtures: each check already had a
#: test driving it to its bad configuration and asserting WARN, because the check had
#: always been able to detect the problem and had only ever been able to report it at
#: LOW with no remediation. Flipping the status and the expectation together is what
#: turned a detected condition into a rendered finding.
#: Four of the 21 had no driving test at all -- the condition was reachable and
#: nothing exercised it -- so the change would have shipped as an unproven claim,
#: which is the very thing this file exists to make visible. tests/test_bucketb_
#: driving.py closes those (SEC-02, WAF-04, KIEM-02, KSPM-04) and takes the ends to
#: 331 / 62.
#:
#: THE CIS COMPUTE BENCHMARK IS THE LARGEST SINGLE ADDITION THIS FILE HAS SEEN, and it
#: moved only the floor: 460 -> 503 registered, 331 -> 374 proven-failing, unobserved
#: DOWN from 62 to 61. Forty-three new checks and not one new entry in the unobserved
#: list is the shape the LMB-08/09 note above describes, held at forty-three times the
#: scale -- every one arrived with a test in tests/test_cis_compute.py that drives it to
#: an actual FAIL. That file also asserts the same invariant locally, over its own
#: declarations, so a forty-fourth check without a driving test fails immediately rather
#: than at the next regeneration of the doc.
#:
#: LSAIL-01 is the one check that moved for a reason other than being added: it had
#: never been observed because nothing built a Lightsail instance fixture, and the new
#: Lightsail cases do.
#:
#: TRANCHE 5 TOOK THE LOUDEST CLAIMS FIRST. Of the 61 never-observed checks, 26 were
#: declared CRITICAL or HIGH -- the catalogue telling an operator a finding is urgent
#: while nothing anywhere had seen it produced. An AST pass showed 22 of the 26 already
#: had a literal FAIL path and were simply never driven, because the nearest existing
#: fixture sets the SAFE value: ECS-02 (root user) was observed and ECS-01 (privileged)
#: was not, from the same loop over the same task definition, because nothing in the
#: suite had ever set `privileged: true`. tests/test_unproven_checks_tranche5.py drives
#: all 22, and EXTACCESS-02 came with them from a negative case.
#:
#: 61 -> 33 never observed and 374 -> 397 proven failing. Five more (BDR-03, HSM-01,
#: NFW-01, NFW-03, S3T-02) moved out of never-observed into the middle rather than to
#: proven, because the new fixtures make their sections run and they answer PASS on the
#: configuration under test. That is progress and the middle is a residual, not a
#: ceiling -- see the note at the top of this block.
#:
#: FOUR OF THE 26 ARE STILL NOT DRIVEN, and the reasons are recorded in that file's
#: DEFERRED map rather than left to be rediscovered: WAF-01 has no FAIL path at all
#: (its only posture WARN is "no Web ACLs in this scope", and a blanket FAIL would flag
#: every account with nothing to protect), and CWPP-01, SEG-02 and VULN-03 reach `_add`
#: through a non-literal id, so neither the static pass nor a reader can locate their
#: FAIL path. Those need the id made legible first.
#: TRANCHE 6 TOOK THE OTHER END: the 13 checks declared HIGH that RAN but had never been
#: driven to a failure. That bucket is easy to mistake for harmless and is not, because of
#: the asymmetry at the top of this file -- a check that has only ever PASSed or WARNed has
#: never once rendered the severity, compliance mapping or remediation the catalogue holds
#: for it. Eleven are driven by tests/test_unproven_checks_tranche6.py, and CFN-04 came
#: with them. 397 -> 409 proven failing; the middle falls 73 -> 61.
#:
#: THE OTHER TWO ARE NOT A COVERAGE GAP. BDR-05 and DDB-01 have exactly one literal FAIL
#: site each and it sits inside an `except` handler -- `_add("FAIL", ..., str(e))`. Their
#: declared HIGH is reachable only by making the AWS call throw, so a fixture would prove
#: the error handler rather than the check. They belong to a wider defect: eleven checks
#: report a FAILED READ as their finding while the security condition they exist for is a
#: WARN. That is fixed as its own change, not papered over with a fixture here.
#: THEN THE DEFECT BEHIND THOSE TWO WAS FIXED, and this file recorded something it was
#: built to record. Ten checks answered a failed AWS call with `_add("FAIL", <id>, ...,
#: str(e))`; `AWSLiveScanner._read_failed` replaced all ten with a WARN that names the
#: action and records the denial. BDR-05 and SNS-04 gained real FAIL paths and entered
#: proven-failing -- and EC2-05 LEFT IT. EC2-05 had been counted as proven only because a
#: test made describe_instances throw, so what this file had certified was its error
#: handler. A number that can fall when a false proof is withdrawn is the only kind worth
#: ratcheting. Net 409 -> 410, and 33 -> 31 never observed.
#:
#: THEN THE REMAINING 22 SITES WERE CONVERTED, and it happened a second time: VPC-01 left
#: proven-failing. VPC-01 is the product's most recognisable check -- a security group
#: opening SSH to 0.0.0.0/0 -- and what had certified it was a test that made
#: DescribeSecurityGroups throw. Its real detection path had never been driven. The total
#: is unchanged at 410 because that path is now driven in
#: tests/test_read_failure_is_not_a_finding.py, which is the honest version of the same
#: number: two checks that were counted for the wrong reason are now counted for the
#: right one.
#: TRANCHE 7 TOOK THE LAST OF THE HIGH-SEVERITY NEVER-OBSERVED CHECKS, and they were
#: last for a reason worth recording: three of the four reach `_add` through a
#: NON-LITERAL id, so the static pass that located every earlier tranche's FAIL path
#: could not see them. CWPP-01 is `fid = "CWPP-02" if m.kev else "CWPP-01"`; VULN-03 is
#: one arm of a four-way branch on Inspector's resource type; SEG-02 is not written in
#: the scanner at all — `aws_exposure.microseg_findings` returns dicts carrying their own
#: "id" and the scanner emits them by `f["id"]`. That is exactly why this file records
#: `_add` at runtime rather than grepping for it. 410 -> 413, 31 -> 28.
#:
#: WAF-01 IS THE ONE HIGH THAT REMAINS, and no fixture can close it: it has no FAIL path,
#: because its only posture finding is "no Web ACLs in this scope" and a blanket FAIL
#: would flag every account with nothing to protect. tests/test_unproven_checks_
#: tranche7.py pins that, with the shape a useful version would need, so the gap stays
#: visible and the decision gets made deliberately rather than by a fixture appearing.
#: 413 -> 419: DOCDB-04/05 and NEP-01..04, added by the CIS Database benchmark work as
#: the price of fixing a defect rather than as new coverage. AUR-01..05 iterated
#: `rds:DescribeDBClusters` with no `Engine` filter, and that API returns DocumentDB and
#: Neptune clusters too — so DocumentDB encryption was reported twice under two ids with
#: contradictory remediation, and Neptune posture was reported as Aurora. Filtering the
#: Aurora loop alone would have DELETED four real findings, so the six ids exist to keep
#: them, correctly labelled. All six are proven failing on the run that added them, which
#: is why this moves by exactly six. See tests/test_db_engine_routing.py.
#: 419 -> 423: RDS-14, AUR-06, DOCDB-06, NEP-05 — TLS enforcement, the one control in the
#: CIS Database benchmark that spans four services and that OverWatch had NO coverage of.
#: Every RDS engine accepts TLS and almost none require it; the difference lives in a
#: parameter group, and nothing in the product read one before this. All four are proven
#: failing, which is why this moves by exactly four. See tests/test_cis_db_tls.py.
#: 423 -> 427: AUR-07/08 read backup retention and IAM auth from the CLUSTER, which is
#: where Aurora holds them — RDS-03/RDS-08 read the instance fields, and a Serverless v1
#: cluster has no instances at all. ELC-07/08 read two fields that were already arriving
#: in a response the ElastiCache section paginated and never looked at. No new API call
#: and no new IAM grant between the four of them.
#: 427 -> 433: MDB-01..06. MemoryDB had NO posture coverage — the client was constructed
#: once in the whole product, for DSPM discovery — so an account could hold a durable
#: Redis datastore with unauthenticated access and nothing was reported. MDB-02 is the
#: one that matters: a passwordless ACL user is an observation, not an inference, and
#: MemoryDB creates one by default. See tests/test_cis_db_memorydb.py.
#: 433 -> 435: TS-01/TS-02. Timestream held DSPM discovery only, and both checks are
#: about the same overlooked surface -- with magnetic-store writes on, records that fail
#: validation are written by the SERVICE to an S3 bucket that no other check looks at.
#: Only two, not four: KS-01/KS-02 were written and WITHDRAWN because Keyspaces'
#: control-plane reads are authorised by cassandra:Select, which also reads table rows.
#: See tests/test_cis_db_keyspaces_timestream.py.
#: 435 -> 442: NEP-06..10, DOCDB-07/08 — the sibling-service checks the CIS Database
#: mapping identified, shipped together with the RDS instance-loop engine filter because
#: neither was safe alone. RDS-02 and RDS-03 were the ONLY coverage of Neptune public
#: accessibility and backup retention while the loop was unfiltered, so filtering first
#: would have deleted real findings; adding the checks first would have left every
#: Neptune instance reported twice. Six of the seven close a CIS-DB recommendation
#: (9.8, 9.9, 9.4, 9.5, 9.11, 7.9); DOCDB-07 closes none, because section 7 has no
#: public-accessibility control — which is a gap in the benchmark rather than a reason
#: to leave a public document database unreported.
#: See tests/test_db_engine_routing.py and tests/test_cis_db_mapping.py.
#: 442 -> 445: CREDEXP-01/02/03 — credential exposure joined to identity. Not new
#: capability so much as capability that could not be reached: `aws_ingest_credexp`
#: had been library-only for two versions, with no CLI flag, no API route and no
#: console surface, so a module that normalises a breach corpus and joins it to IAM
#: principals could not put a single finding in a report. Wiring it took the ingest
#: surface AND `iam:ListAccessKeys` together, which docs/PRODUCTION.md had already
#: recorded as one decision rather than two: without a live key inventory the key
#: join cannot happen, and it is the highest-value join the corpus offers.
#: CREDEXP-00 is deliberately unregistered — it is INFO-only, like AIDR-00, and
#: `_add` reads the catalogue for no status but FAIL.
#: See tests/test_ingest_credexp.py.
#: 445 -> 464: the nineteen CIS AWS Foundations v7.0.0 checks, all arriving proven. The
#: two other counts held exactly steady — 62 never-driven-to-failure and 28 never
#: observed — which is the number to look at rather than the headline. A batch of
#: nineteen is the classic way this product has previously grown its backlog by nineteen,
#: so `tests/test_cis_foundations.py` drives each one to a real FAIL through the scanner
#: rather than through its evaluator, and fifteen of them also have a "the read was
#: refused" case, because six of these checks are denied in every member account and a
#: silent denial reads as a clean organisation.
#: See tests/test_cis_foundations.py and docs/CIS_FOUNDATIONS_BENCHMARK.md.
#: 464 -> 473: the nine CIS AWS Database Services tranche-2 checks, closing the last of
#: the thirteen gaps tranche 1 recorded. The other four gaps did not become checks and
#: are not in this number: they turned out not to be buildable at all -- two are misfiled
#: in the benchmark and audit a service this product declines to read, one is absent from
#: the SDK, and one is a process control. Never-observed (28) and never-driven-to-failure
#: (62) both held exactly steady for the second batch running, which is the pair worth
#: watching: a batch of nine is the classic way this product has previously grown its
#: backlog by nine.
#: See tests/test_cis_db_tranche2.py and docs/CIS_DATABASE_BENCHMARK.md.
#: 473 -> 476: AL2-01/02/03, the CIS Amazon Linux 2 controls SSM Inventory can decide.
#: THREE, FROM A 287-RECOMMENDATION BENCHMARK, and the ratio is the point rather than an
#: embarrassment. 252 of those recommendations read file content, file modes or running
#: kernel state, which an agentless control-plane scanner cannot see; they are recorded in
#: engine/aws_cis_al2_map.py against the capability each waits on. Registering them would
#: have added 252 checks to the catalogue that this file would then have counted as
#: never-observed forever -- which is the number below, and the reason it did not move.
#: Never-observed (28) and never-driven-to-failure (62) held steady for the third batch
#: running.
#: See tests/test_cis_al2.py and docs/CIS_AL2_BENCHMARK.md.
#:
#: 476 -> 508, and NEVER-OBSERVED REACHES ZERO (tranche 8). Every registered check now
#: emits something somewhere, which is the first time that has been true. The ceiling is
#: 0 from here: a check arriving with no driving test breaks the build rather than
#: joining a backlog, because there is no longer a backlog for it to hide in.
#:
#: Three of the 28 were not fixture problems and are recorded here because the numbers
#: alone would misrepresent them:
#:   * SM-12 was UNREACHABLE. aws_sagemaker.notebook_platform was written, exported and
#:     unit tested with no production caller -- built-and-unreached one level below what
#:     tests/test_unreached_modules.py can see, since it asks whether a MODULE has a
#:     caller and aws_sagemaker plainly does. It is now wired.
#:   * THREAT-02 was RETIRED, not driven. It was the genuinely dead check this file was
#:     built to expose. Its control-plane-anomaly semantics live in
#:     aws_cdr.normalize_cloudtrail_anomaly and are emitted as THREAT-ING, so nothing is
#:     lost but a claim of coverage that did not exist.
#:   * WAF-01 gained no FAIL path. The useful question -- an internet-facing ALB with no
#:     Web ACL -- became WAF-06, a new id, so WAF-01 keeps its meaning for anyone already
#:     filtering on it. WAF-01, ACM-05 and SHAI-03 were all brought down to LOW to match
#:     what a WARN can actually render.
#: Registered stays 566: THREAT-02 out, WAF-06 in. It is a different 566.
#:
#: 508 -> 514, registered 566 -> 572 (CIS AWS Storage Services). Six new checks, six
#: driving tests, and the +6 here is the whole point of the ceiling being 0: the six
#: arrived WITH their fixtures rather than joining a backlog, so the two numbers moved
#: together in one commit. DRS-01..04 read Elastic Disaster Recovery -- the staging
#: subnet that holds a continuous copy of every protected disk -- and BCK-04/05 ask the
#: two questions that benchmark never asks: does the backup survive the region, and is
#: it held under a key this account can actually revoke.
#:
#: 514 -> 529, registered 572 -> 587 (CIS AWS End User Compute v1.2.0). Fifteen new
#: checks, fifteen driving tests, +15 exactly -- the second batch to land under the
#: zero ceiling and the second to show what it buys: the checks and their fixtures
#: arrive together or not at all. WKS-01..09 read Amazon WorkSpaces and APS-01..06
#: read AppStream 2.0, two services this product could not see at all. Two of the
#: fifteen answer no recommendation in the source document: WKS-08 (desktop users
#: are local administrators of their own machine) and APS-05 (the fleet still
#: answers IMDSv1).
MAX_NEVER_OBSERVED = 0
MIN_PROVEN_FAILING = 529


def doc_text() -> str:
    if not os.path.exists(DOC):
        pytest.fail(
            "docs/CHECK_FIRING.md is missing. Regenerate it:\n"
            "  OVERWATCH_RECORD_CHECKS=fired.json python -m pytest tests/ -q\n"
            "  python scripts/check_firing.py --from fired.json")
    return io.open(DOC, encoding="utf-8").read()


def headline(text: str):
    m = re.search(r"\*\*(\d+) registered checks\.\*\* (\d+) are proven to FAIL in the "
                  r"suite; (\d+) run but have never been driven to a failure; (\d+) "
                  r"were never observed", text)
    assert m, "the doc's headline sentence has changed shape; update this test"
    return tuple(int(g) for g in m.groups())


def test_the_doc_exists_and_is_generated():
    """Hand-editing it would turn a measurement into an assertion."""
    text = doc_text()
    assert "GENERATED FILE - DO NOT EDIT BY HAND" in text
    assert "scripts/check_firing.py" in text


def test_the_headline_adds_up():
    """Three states, no fourth, and they partition the catalogue. A doc whose numbers
    do not sum is a doc nobody can quote."""
    registered, failing, soft, unseen = headline(doc_text())
    assert failing + soft + unseen == registered


def test_the_doc_describes_the_current_catalogue():
    """A check added without regenerating leaves the doc describing a smaller product,
    and every number below becomes a statement about the past."""
    from engine.aws_live_scanner import CHECK_SEVERITY
    registered, _f, _s, _u = headline(doc_text())
    assert registered == len(CHECK_SEVERITY), (
        "docs/CHECK_FIRING.md covers %d checks, the catalogue now has %d. "
        "Regenerate it." % (registered, len(CHECK_SEVERITY)))


def test_unproven_checks_can_only_decrease():
    """THE RATCHET. A new check arrives unproven, so shipping one with no driving test
    pushes this past the ceiling. Lower the ceiling when coverage improves; never
    raise it to make a build pass."""
    _r, _f, _s, unseen = headline(doc_text())
    assert unseen <= MAX_NEVER_OBSERVED, (
        "%d checks are never observed, ceiling is %d. Write a test that drives the "
        "new check to a finding rather than raising this." % (unseen,
                                                              MAX_NEVER_OBSERVED))


def test_proven_failing_checks_can_only_increase():
    """The other end of the ratchet, and the one that measures real progress: a check
    is only proven when some test drives it to a FAIL, because `_add` reads severity,
    compliance and remediation from the catalogue for no other status."""
    _r, failing, _s, _u = headline(doc_text())
    assert failing >= MIN_PROVEN_FAILING, (
        "%d checks are proven to fail, the floor is %d. A check stopped failing, or "
        "a driving test was deleted." % (failing, MIN_PROVEN_FAILING))


def test_the_bounds_are_not_stale():
    """The half that keeps the ratchet honest. A bound left far from the real number
    stops being a ratchet and becomes decoration, so it is tightened in the same
    commit that moves the number."""
    _r, failing, _s, unseen = headline(doc_text())
    assert MAX_NEVER_OBSERVED - unseen <= 5, (
        "the never-observed ceiling (%d) is well above the actual (%d); lower it"
        % (MAX_NEVER_OBSERVED, unseen))
    assert failing - MIN_PROVEN_FAILING <= 5, (
        "the proven-failing floor (%d) is well below the actual (%d); raise it"
        % (MIN_PROVEN_FAILING, failing))


def test_threat_02_stays_retired():
    """Replaces `test_threat_02_is_still_listed_as_never_observed`, which offered two
    ways out — drive it, or retire it — and tranche 8 took the second. It was the one
    genuinely dead check: registered in all four maps, given a full remediation
    write-up, counted in the published total, emitted by nothing.

    Pinned in the new direction so it cannot drift back in as an unemitted id. If a
    real emit path is ever built, re-register it AND delete this test — the point is
    that the id never again exists in the catalogue without one."""
    from engine import aws_finding_detail
    from engine.aws_live_scanner import (CHECK_SEVERITY, COMPLIANCE_MAP,
                                         REMEDIATION_MAP)
    for name, m in (("CHECK_SEVERITY", CHECK_SEVERITY),
                    ("COMPLIANCE_MAP", COMPLIANCE_MAP),
                    ("REMEDIATION_MAP", REMEDIATION_MAP),
                    ("FINDING_DETAIL", aws_finding_detail.FINDING_DETAIL)):
        assert "THREAT-02" not in m, (
            f"THREAT-02 is back in {name}. It was retired because nothing emitted "
            f"it; re-registering it without an emit path recreates the exact defect "
            f"docs/CHECK_FIRING.md exists to expose.")


def test_the_never_observed_bucket_stays_empty():
    """The milestone tranche 8 reached, held. Every registered check emits something
    somewhere, so a new check without a driving test has nowhere to hide: it lands
    here as a build failure instead of joining a backlog."""
    text = doc_text()
    unseen = text.split("## Never observed")[1].split("##")[0]
    assert "None" in unseen, (
        "the never-observed bucket is no longer empty:\n" + unseen.strip()[:800])


def test_no_unregistered_check_reaches_a_failure():
    """`_add` looks up severity AND remediation by check id, so a FAIL whose id the
    catalogue does not know renders at the default MEDIUM with no remediation — a
    finding that silently misstates its own severity.

    Today's 28 unregistered ids are all INFO/WARN/PASS section markers, which is
    benign. The generator computes that from the recording and states it, so this can
    assert the fact rather than the shape: an earlier version of this test only
    checked the section was non-empty, which is not what its name says."""
    text = doc_text()
    if "## Emitted but not registered" not in text:
        return
    section = text.split("## Emitted but not registered")[1]
    m = re.search(r"\*\*Reaching FAIL: (.+?)\*\*", section)
    assert m, "the generator no longer states which unregistered ids reach FAIL"
    assert m.group(1).startswith("none"), (
        "unregistered check id(s) reach FAIL and render at the default severity with "
        "no remediation: %s. Register them, or stop them failing." % m.group(1))
