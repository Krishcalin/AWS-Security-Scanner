"""The CIS AWS Database Services mapping, and the properties that make it worth quoting.

A 98-row compliance mapping is the sort of artefact that ends up in front of an auditor,
which is exactly why it must not be a hand-typed table sitting next to a catalogue that
moves. The mapping is data (`engine/aws_cis_db_map.py`), the document is rendered from it
(`scripts/cis_db_benchmark.py`), and these tests assert the things that would otherwise
rot silently:

  * every recommendation 2.1 … 11.7 appears exactly once, with no gaps and no inventions;
  * every check id named in the mapping actually exists in the catalogue;
  * the `CIS-DB` keys in COMPLIANCE_MAP agree with the mapping in BOTH directions;
  * a check is never presented as covering something it cannot FAIL on;
  * every decline names its reason, and the reason is recorded as data, not as prose.

The last two are the ones that keep it honest rather than merely consistent.
"""
from __future__ import annotations

import io
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_cis_db                                          # noqa: E402
from engine import aws_cis_db_map as M                                 # noqa: E402
from engine.aws_live_scanner import CHECK_SEVERITY as S                # noqa: E402
from engine.aws_live_scanner import COMPLIANCE_MAP as C                # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "CIS_DATABASE_BENCHMARK.md")
GEN = os.path.join(ROOT, "scripts", "cis_db_benchmark.py")

FAMS = set(M.FAMILY_SECTION)
OWNED = sorted(c for c in S if c.rsplit("-", 1)[0] in FAMS)


# ══════════════════════════════════════════════════════════════════════════════
# the mapping is complete and references only real things
# ══════════════════════════════════════════════════════════════════════════════
def test_every_recommendation_is_present_exactly_once():
    """98 rows, numbered 1..n within each of the ten sections. A missing row would read
    as a control nobody considered; an extra one would be a control that does not exist."""
    assert len(M.RECOMMENDATIONS) == 98
    for num, name, count in M.SECTIONS:
        got = sorted(int(r.split(".")[1]) for r in M.RECOMMENDATIONS
                     if r.split(".", 1)[0] == num)
        assert got == list(range(1, count + 1)), (
            f"section {num} ({name}) should be 1..{count}, got {got}")


def test_the_section_counts_sum_to_the_benchmark_total():
    assert sum(c for _n, _l, c in M.SECTIONS) == 98


def test_every_check_named_in_the_mapping_exists():
    """The failure this prevents: a check is renamed, the mapping keeps citing the old id,
    and the document goes on claiming coverage that nothing provides."""
    named = {c for _r, (_l, _v, ck, _n) in M.RECOMMENDATIONS.items() for c in ck}
    missing = sorted(c for c in named if c not in S)
    assert not missing, f"mapping cites checks that do not exist: {missing}"


def test_every_verdict_is_one_of_the_declared_ones():
    bad = {r: v[1] for r, v in M.RECOMMENDATIONS.items() if v[1] not in M.VERDICTS}
    assert not bad, f"unknown verdicts: {bad}"


# ══════════════════════════════════════════════════════════════════════════════
# the mapping and the compliance map agree — in both directions
# ══════════════════════════════════════════════════════════════════════════════
def test_every_cis_db_key_matches_the_mapping():
    """Forward direction: a key in COMPLIANCE_MAP must be the home the mapping computes."""
    keyed = {c: v["CIS-DB"] for c, v in C.items() if "CIS-DB" in v}
    assert keyed, "no CIS-DB keys are registered at all"
    wrong = {c: (v, M.recommendation_for(c)) for c, v in keyed.items()
             if v != M.recommendation_for(c)}
    assert not wrong, f"COMPLIANCE_MAP disagrees with the mapping (got, expected): {wrong}"


def test_every_check_with_a_home_carries_the_key():
    """Reverse direction, and the one that actually rots. A check added to the mapping
    without its compliance key would be described as covering a recommendation while
    reporting no CIS-DB citation on the finding itself."""
    expect = {c for c in OWNED if M.recommendation_for(c)}
    keyed = {c for c, v in C.items() if "CIS-DB" in v}
    assert not (expect - keyed), f"mapped but not keyed: {sorted(expect - keyed)}"
    assert not (keyed - expect), f"keyed but not mapped: {sorted(keyed - expect)}"


def test_the_key_only_ever_lands_on_database_checks():
    """A CIS-DB citation on an EC2 or IAM check would be a mis-citation, and the sort
    that survives review because the number looks plausible."""
    stray = sorted(c for c, v in C.items()
                   if "CIS-DB" in v and c.rsplit("-", 1)[0] not in FAMS)
    assert not stray, f"CIS-DB key on non-database checks: {stray}"


def test_the_home_of_a_check_is_in_its_own_service_section():
    """RDS-02 decides Aurora 2.9 and Neptune 9.8 as well as its own 3.12, and only 3.12
    belongs in the compliance map. This pins the precedence rule that decides that."""
    for c in OWNED:
        home = M.recommendation_for(c)
        if not home:
            continue
        assert home.split(".", 1)[0] == M.FAMILY_SECTION[c.rsplit("-", 1)[0]], (
            f"{c} is keyed to {home}, which is not its own service's section")


# ══════════════════════════════════════════════════════════════════════════════
# honesty
# ══════════════════════════════════════════════════════════════════════════════
def test_covered_means_a_check_is_named():
    empty = sorted(r for r, v in M.RECOMMENDATIONS.items()
                   if v[1] in (M.COVERED, M.PARTIAL) and not v[2])
    assert not empty, f"claimed as covered/observed with no check named: {empty}"


def test_nothing_is_covered_by_a_check_that_cannot_fail():
    """THE POINT OF THE PARTIAL VERDICT. RDS-05, DDB-01 and RDS-03's Multi-AZ arm read
    their setting and emit PASS or WARN and never FAIL. A check that cannot fail can tell
    you a value; it can never tell an operator they are non-compliant, so presenting one
    as `covered` would overstate the catalogue in the one document most likely to be
    quoted back at us.

    The list is asserted rather than derived: deriving it from the source would make the
    test agree with whatever the code does, which is not a test.
    """
    cannot_fail = {"RDS-05", "DDB-01", "DDB-03", "RDS-13"}
    src = io.open(os.path.join(ROOT, "engine", "aws_live_scanner.py"),
                  encoding="utf-8").read()
    for cid in sorted(cannot_fail):
        assert f'_add("FAIL", "{cid}"' not in src, (
            f"{cid} now has a FAIL path — re-examine whether the recommendations it "
            f"answers should be upgraded from 'observed only' to 'covered'")
    for rec, (_l, verdict, checks, _n) in M.RECOMMENDATIONS.items():
        if verdict == M.COVERED and set(checks) <= cannot_fail:
            raise AssertionError(
                f"{rec} is marked covered but every check named on it "
                f"({sorted(checks)}) can only PASS or WARN")


def _resolved_note(rec: str, seen=None) -> str:
    """A row's explanation, following an `As 8.1`-style cross-reference to its source.

    Rows legitimately say "As 5.2" rather than repeating a paragraph nine times. That is
    a reference, not an absence — but only if the row it points at actually explains
    itself, so this resolves the chain and refuses to loop.
    """
    seen = seen or set()
    note = M.RECOMMENDATIONS[rec][3]
    ref = re.fullmatch(r"As (\d+\.\d+)", note.strip())
    if ref and ref.group(1) not in seen and ref.group(1) in M.RECOMMENDATIONS:
        return _resolved_note(ref.group(1), seen | {rec})
    return note


def test_every_cross_reference_resolves():
    """An `As 9.9` pointing at a row that does not exist, or round in a circle, would be
    an explanation that reads as one without being one."""
    for rec in M.RECOMMENDATIONS:
        note = M.RECOMMENDATIONS[rec][3].strip()
        ref = re.fullmatch(r"As (\d+\.\d+)", note)
        if ref:
            assert ref.group(1) in M.RECOMMENDATIONS, (
                f"{rec} refers to {ref.group(1)}, which is not a recommendation")
            assert len(_resolved_note(rec)) > 20, (
                f"{rec} refers to {ref.group(1)}, which explains nothing itself")


def test_every_decline_points_at_a_recorded_reason():
    """A row that just says 'declined' is an omission wearing a decision's clothes. Each
    one has to be traceable to a reason held as DATA in aws_cis_db, not to prose."""
    assert aws_cis_db.NOT_DETERMINABLE, "the decline register is empty"
    declined = [r for r, v in M.RECOMMENDATIONS.items() if v[1] == M.DECLINED]
    assert declined, "no declines at all — did the register lose its contents?"
    for rec in declined:
        assert len(_resolved_note(rec)) > 20, f"{rec} is declined with no explanation"


def test_the_gaps_are_named_rather_than_rounded_away():
    """THE GAP LIST IS NOW EMPTY, and the assertion changed shape rather than being deleted.

    It used to require the list to be non-empty, on the reasoning that a coverage document
    reporting only its wins is marketing. Tranche 2 emptied it — nine gaps became checks
    and four became declines with recorded reasons — so requiring non-emptiness would now
    fail for the opposite of the reason it was written.

    What survives is the part that was always load-bearing: a `gap` has to say what would
    close it. An entry with no such note is a shortfall wearing a backlog item's clothes,
    and the next reader has nothing to act on."""
    gaps = sorted(r for r, v in M.RECOMMENDATIONS.items() if v[1] == M.NO_CHECK)
    for rec in gaps:
        assert len(_resolved_note(rec)) > 15, (
            f"{rec} is recorded as a gap without saying what would close it")


def test_the_four_reclassified_gaps_each_say_why_they_moved():
    """Tranche 2's more useful half. Four of the thirteen recorded gaps turned out not to
    be buildable at all, and a gap that quietly becomes a decline is indistinguishable
    from one somebody gave up on. Each names the reason in its own row."""
    moved = {"5.8": M.DECLINED, "5.9": M.DECLINED, "6.4": M.DECLINED, "10.8": M.PROCESS}
    for rec, verdict in moved.items():
        assert M.RECOMMENDATIONS[rec][1] == verdict, (
            f"{rec} should be {verdict}, is {M.RECOMMENDATIONS[rec][1]}")
        assert len(_resolved_note(rec)) > 60, (
            f"{rec} moved out of the gap list without an account of why")
    # 6.4's reason is a claim about the SDK, so it is held as data where the coverage
    # document and the tests read the same copy.
    assert "memorydb-audit-logging" in aws_cis_db.NOT_DETERMINABLE


def _rds_fails_on(engine: str):
    """Run the RDS section against ONE instance of `engine` and return the ids that FAIL.

    Behavioural on purpose. The first version of this test read the source for an engine
    filter and was fooled immediately: `_check_rds` mentions both `Engine` and
    NON_AURORA_CLUSTER_ENGINES for reasons that have nothing to do with filtering
    instances, so the text said "filtered" while the code was not. Running it settles the
    question that reading it could not.
    """
    from unittest.mock import MagicMock
    from test_live_scanner import make_scanner                          # noqa: WPS433

    s = make_scanner(sections=["RDS"])
    s.account = "123456789012"
    rds = MagicMock()
    inst = {"DBInstanceIdentifier": f"{engine}-1", "Engine": engine,
            "StorageEncrypted": False, "PubliclyAccessible": True,
            "BackupRetentionPeriod": 0, "DeletionProtection": False,
            "MultiAZ": False, "AutoMinorVersionUpgrade": False,
            "EngineVersion": "5.7.0", "DBInstanceStatus": "available",
            "IAMDatabaseAuthenticationEnabled": False}

    def _pager(op):
        p = MagicMock()
        p.paginate.return_value = ([{"DBInstances": [inst]}]
                                   if op == "describe_db_instances" else [{}])
        return p

    rds.get_paginator.side_effect = _pager
    rds.describe_db_snapshots.return_value = {"DBSnapshots": []}
    rds.describe_db_clusters.return_value = {"DBClusters": []}
    s._clients["rds:us-east-1"] = rds
    s._check_rds()
    return {r.check_id for r in s.results if r.status == "FAIL"}


def test_a_sibling_service_instance_produces_no_rds_finding():
    """The instance-filter defect this mapping found, now closed and pinned shut.

    Neptune and DocumentDB instances are returned by rds:DescribeDBInstances because they
    share the RDS control plane, and the instance loop used to score them: a single
    Neptune instance produced RDS-01, RDS-02, RDS-03 and RDS-04, none of which said
    Neptune anywhere. It was the tranche-1 cluster defect one level down.
    """
    for engine in ("neptune", "docdb"):
        fails = _rds_fails_on(engine)
        leaked = {c for c in fails if c.startswith("RDS-")}
        assert not leaked, (
            f"a {engine} instance produced {sorted(leaked)} — the engine filter in "
            f"_rds_instances() has regressed, and a {engine} exposure is being reported "
            f"under an RDS id with RDS remediation")


def test_the_engine_filter_is_a_deny_list_and_not_an_allow_list():
    """The property most likely to be lost by someone 'tightening' the filter, and the
    one whose loss is invisible: an allow-list of known engines silently stops scoring
    every RDS engine AWS ships after the day it was written. Only an engine that
    POSITIVELY declares itself another service is dropped — an unrecognised or absent
    Engine keeps being scored, which is the same rule NON_AURORA_CLUSTER_ENGINES uses one
    level up.
    """
    for engine in ("mysql", "postgres", "some-engine-aws-ships-in-2029", ""):
        fails = _rds_fails_on(engine)
        assert {"RDS-01", "RDS-02", "RDS-03", "RDS-04"} <= fails, (
            f"an instance with Engine={engine!r} produced only {sorted(fails)} — the "
            f"filter has become an allow-list, so unrecognised engines are no longer "
            f"scored at all")


def test_no_coverage_was_deleted_when_the_filter_landed():
    """The trap this change existed to avoid. RDS-02 and RDS-03 were the ONLY coverage of
    Neptune 9.8 and 9.9 while the loop was unfiltered, so filtering alone would have
    turned two 'decided elsewhere' rows into silence while the mapping still claimed they
    were decided. Filter and replacement had to ship together, and this asserts they did:
    both rows are covered, by Neptune checks, that can actually FAIL.
    """
    for rec in ("9.8", "9.9"):
        label, verdict, checks, _note = M.RECOMMENDATIONS[rec]
        assert verdict == M.COVERED, f"{rec} ({label}) is no longer covered"
        assert checks and all(c.startswith("NEP-") for c in checks), (
            f"{rec} must be decided by a Neptune check, not {list(checks)}")
    assert {"NEP-06", "NEP-07"} <= _fails_of(_neptune_section()), (
        "NEP-06/NEP-07 replaced RDS-02/RDS-03 for Neptune, so they must be able to FAIL "
        "— a check that cannot fail would leave 9.8 and 9.9 covered on paper only")


def _neptune_section():
    """Run the Neptune section against one deliberately bad cluster and instance."""
    from unittest.mock import MagicMock
    from test_live_scanner import make_scanner                          # noqa: WPS433

    s = make_scanner(sections=["NEPTUNE"])
    s.account = "123456789012"
    cluster = {"DBClusterIdentifier": "graph", "StorageEncrypted": False,
               "DeletionProtection": False, "BackupRetentionPeriod": 1,
               "IAMDatabaseAuthenticationEnabled": False,
               "EnabledCloudwatchLogsExports": [], "MultiAZ": False,
               "DBClusterParameterGroup": "pg"}
    inst = [{"DBInstanceIdentifier": "graph-1", "PubliclyAccessible": True,
             "DBClusterIdentifier": "graph"}]

    def _pager(op):
        p = MagicMock()
        if op == "describe_db_instances":
            p.paginate.return_value = [{"DBInstances": inst}]
        elif op == "describe_db_clusters":
            p.paginate.return_value = [{"DBClusters": [cluster]}]
        else:
            p.paginate.return_value = [{}]
        return p

    nep = MagicMock()
    nep.get_paginator.side_effect = _pager
    nep.describe_db_cluster_snapshots.return_value = {"DBClusterSnapshots": []}
    nep.describe_db_cluster_parameters.return_value = {"Parameters": []}
    s._clients["neptune:us-east-1"] = nep
    s._check_neptune()
    return s


def _fails_of(scanner):
    return {r.check_id for r in scanner.results if r.status == "FAIL"}


def test_the_four_sibling_gaps_are_closed_by_checks_that_can_fail():
    """7.9, 9.4, 9.5 and 9.11 were the four gaps worth closing: each already existed for
    a sibling service, and each reads a field the DescribeDBClusters call already
    returns. Recording them as covered is only true if the checks fire, so run them."""
    fired = _fails_of(_neptune_section())
    for rec, check in (("9.4", "NEP-08"), ("9.5", "NEP-09"), ("9.11", "NEP-10")):
        _label, verdict, checks, _note = M.RECOMMENDATIONS[rec]
        assert verdict == M.COVERED and check in checks, f"{rec} -> {check}"
        assert check in fired, (
            f"{rec} is recorded as covered by {check}, but {check} did not FAIL on a "
            f"cluster deliberately built to fail it")
    # 7.9 is DocumentDB, which is a different section and a different client.
    _label, verdict, checks, _note = M.RECOMMENDATIONS["7.9"]
    assert verdict == M.COVERED and "DOCDB-08" in checks


def test_the_neptune_only_checks_are_neptune_only_for_a_reason():
    """DocumentDB has no equivalent of NEP-08 or NEP-10, and that is a property of the
    service rather than a shortcut: the botocore service model shows DocumentDB clusters
    carry no IAMDatabaseAuthenticationEnabled and DocumentDB instances carry no MultiAZ.
    Asserting it here means a future 'why is there no DOCDB version of this?' is answered
    by a test rather than by a guess — and if AWS ever adds the fields, this fails and
    tells us to build them.
    """
    import botocore.session
    from botocore import xform_name

    sess = botocore.session.get_session()
    model = sess.get_service_model("docdb")
    ops = {xform_name(o): o for o in model.operation_names}

    clusters = model.operation_model(
        ops["describe_db_clusters"]).output_shape.members["DBClusters"].member
    assert "IAMDatabaseAuthenticationEnabled" not in clusters.members, (
        "DocumentDB clusters now expose IAMDatabaseAuthenticationEnabled — build the "
        "DocumentDB equivalent of NEP-08 and map it")

    instances = model.operation_model(
        ops["describe_db_instances"]).output_shape.members["DBInstances"].member
    assert "MultiAZ" not in instances.members, (
        "DocumentDB instances now expose MultiAZ — build the DocumentDB equivalent of "
        "NEP-10 and map it")


# ══════════════════════════════════════════════════════════════════════════════
# the document is generated, and stays that way
# ══════════════════════════════════════════════════════════════════════════════
def test_the_document_is_not_stale():
    from scripts import cis_db_benchmark                               # noqa: WPS433
    on_disk = io.open(DOC, encoding="utf-8", newline="").read()
    assert on_disk.replace("\r\n", "\n") == cis_db_benchmark.build().replace("\r\n", "\n"), (
        "docs/CIS_DATABASE_BENCHMARK.md is out of date — run "
        "`python scripts/cis_db_benchmark.py` and commit the result")


def test_the_document_names_its_generator():
    head = io.open(DOC, encoding="utf-8").read(2000)
    assert "GENERATED" in head and "cis_db_benchmark.py" in head


def test_the_document_carries_no_benchmark_prose():
    """The handling rule, enforced rather than remembered: recommendation numbers and
    counts are references; the benchmark's own section text is not ours to reproduce."""
    doc = io.open(DOC, encoding="utf-8").read()
    assert "may not be redistributed" in doc
    for lifted in ("Rationale:", "Audit:", "Remediation:", "Impact Statement",
                   "Profile Applicability", "Default Value:"):
        assert lifted not in doc, (
            f"{lifted!r} is a CIS section heading — the document must carry references "
            f"to the benchmark, not its contents")


def test_the_generator_runs_clean():
    r = subprocess.run([sys.executable, GEN], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, f"generator failed: {r.stderr[-800:]}"
