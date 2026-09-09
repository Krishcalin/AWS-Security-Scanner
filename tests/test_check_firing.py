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
MAX_NEVER_OBSERVED = 28
MIN_PROVEN_FAILING = 433


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


def test_threat_02_is_still_listed_as_never_observed():
    """The known dead check, pinned so it cannot be quietly forgotten. Either a test
    drives it, or the check is retired from the catalogue — both are progress, and
    both change this line deliberately."""
    text = doc_text()
    unseen = text.split("## Never observed")[1].split("## Runs, but never fails")[0]
    assert "`THREAT-02`" in unseen, (
        "THREAT-02 is no longer never-observed. If it now fires, delete this test; if "
        "it was retired from the catalogue, delete it here too.")


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
