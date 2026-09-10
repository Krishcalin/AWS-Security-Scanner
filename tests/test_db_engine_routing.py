"""The Aurora checks used to score DocumentDB and Neptune clusters.

`rds:DescribeDBClusters` and `rds:DescribeDBClusterSnapshots` return DocumentDB and
Neptune resources alongside Aurora ones -- they are separate services sharing one control
plane. AUR-01..05 iterated the response with no `Engine` filter, so:

  * a DocumentDB cluster's encryption gap was reported TWICE, as AUR-01 and as DOCDB-02,
    with AUR-01 offering a `modify-db-cluster` fix that DocumentDB does not support
    (its encryption is creation-time only, which DOCDB-02's own remediation says); and
  * Neptune posture was reported under Aurora ids entirely, so section 9 of the CIS
    Database benchmark looked partly covered while nothing in the product knew what
    Neptune was.

The codebase already knew about the overlap: `_dspm_rds` branches on `Engine` to give
docdb and neptune their own crown-jewel kinds rather than "mis-labelling them RDSCluster".
The check path simply never did.

THE FILTER ALONE WOULD HAVE BEEN A COVERAGE REGRESSION -- deleting real findings is not a
fix for mislabelling them. So the four facts that only reached a report via an Aurora id
now have their own: DOCDB-04, DOCDB-05, NEP-01..04. These tests hold BOTH halves: the
Aurora ids no longer fire on foreign engines, AND the same estate still produces the same
findings under the right ones.

THEN THE SAME DEFECT WAS FOUND ONE LEVEL DOWN. Mapping the CIS Database benchmark row by
row turned up the instance loop, which had no engine filter either: `rds:DescribeDBInstances`
returns Neptune and DocumentDB instances too, so a single Neptune instance produced RDS-01,
RDS-02, RDS-03 and RDS-04 -- none of which said Neptune anywhere. It was found by RUNNING
the section rather than reading it; the first attempt read the source for a filter and was
fooled, because `_check_rds` mentions `Engine` and NON_AURORA_CLUSTER_ENGINES for reasons
that have nothing to do with instances.

It had the same shape as the cluster defect and needed the same answer. RDS-01 and RDS-04
merely double-reported, but RDS-02 and RDS-03 were the ONLY coverage of Neptune public
accessibility and backup retention, so filtering alone would again have deleted real
findings. Filter and replacements shipped together: `_rds_instances()` drops foreign
engines, and NEP-06..10 and DOCDB-07/08 report the facts under ids that name the service.
The instance-plane tests at the bottom of this file hold both halves the same way.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.aws_live_scanner import NON_AURORA_CLUSTER_ENGINES     # noqa: E402
from test_live_scanner import make_scanner                          # noqa: E402
from test_unproven_checks_tranche5 import _ids, _renders            # noqa: E402

OWN = "123456789012"
REGION = "us-east-1"


def _cluster(cid, engine, *, encrypted=False, deletion_protection=False):
    return {"DBClusterIdentifier": cid,
            "DBClusterArn": f"arn:aws:rds:{REGION}:{OWN}:cluster:{cid}",
            "Engine": engine, "EngineVersion": "1.0.0",
            "StorageEncrypted": encrypted,
            "DeletionProtection": deletion_protection}


def _snapshot(sid, engine, *, encrypted=False):
    return {"DBClusterSnapshotIdentifier": sid, "Engine": engine,
            "StorageEncrypted": encrypted}


# ══════════════════════════════════════════════════════════════════════════════
# The RDS plane — AUR-01..05 must see Aurora and nothing else
# ══════════════════════════════════════════════════════════════════════════════
def _rds_scanner(clusters, snapshots=()):
    """A scanner whose rds client returns exactly `clusters` and `snapshots`."""
    s = make_scanner(sections=["RDS"])
    s.account = OWN
    rds = MagicMock()

    def _pager(op):
        p = MagicMock()
        if op == "describe_db_clusters":
            p.paginate.return_value = [{"DBClusters": list(clusters)}]
        elif op == "describe_db_cluster_snapshots":
            p.paginate.return_value = [{"DBClusterSnapshots": list(snapshots)}]
        else:
            p.paginate.return_value = [{}]
        return p

    rds.get_paginator.side_effect = _pager
    rds.describe_db_instances.return_value = {"DBInstances": []}
    rds.describe_db_cluster_snapshot_attributes.return_value = {
        "DBClusterSnapshotAttributesResult": {"DBClusterSnapshotAttributes": []}}
    s._clients[f"rds:{REGION}"] = rds
    s._check_rds()
    return s


def test_a_documentdb_cluster_is_not_scored_as_aurora():
    """THE DEFECT. Before the filter this produced AUR-01 and AUR-02 FAILs on a cluster
    that is not Aurora and whose encryption cannot be fixed the way AUR-01 advises."""
    s = _rds_scanner([_cluster("my-docdb", "docdb")])
    assert not _ids(s, "AUR-01", "FAIL"), (
        "a DocumentDB cluster still FAILs the Aurora encryption check")
    assert not _ids(s, "AUR-02", "FAIL"), (
        "a DocumentDB cluster still FAILs the Aurora deletion-protection check")


def test_a_neptune_cluster_is_not_scored_as_aurora():
    s = _rds_scanner([_cluster("my-neptune", "neptune")])
    assert not _ids(s, "AUR-01", "FAIL")
    assert not _ids(s, "AUR-02", "FAIL")


def test_an_account_holding_only_documentdb_reads_as_no_aurora_clusters():
    """The filter runs BEFORE the empty test. If it ran after, an estate of DocumentDB
    clusters would produce neither the Aurora INFO nor any Aurora finding, and the
    section would be silent for a reason no reader could reconstruct."""
    s = _rds_scanner([_cluster("my-docdb", "docdb")])
    info = _ids(s, "AUR-01", "INFO")
    assert info and "No Aurora" in info[0].message, (
        "expected the no-Aurora-clusters INFO, saw: "
        + ", ".join(f"{r.status}:{r.message[:40]}" for r in _ids(s, "AUR-01")))


def test_a_real_aurora_cluster_still_fails_both_aurora_checks():
    """The other half of the ratchet. A filter that also silenced Aurora would pass every
    test above and be strictly worse than the defect."""
    s = _rds_scanner([_cluster("prod-aurora", "aurora-postgresql")])
    _renders(s, "AUR-01", "HIGH", contains="prod-aurora")
    _renders(s, "AUR-02", "MEDIUM", contains="prod-aurora")


def test_aurora_and_foreign_engines_in_one_response_split_correctly():
    """The realistic shape: one API response holding all three services."""
    s = _rds_scanner([_cluster("prod-aurora", "aurora-mysql"),
                      _cluster("my-docdb", "docdb"),
                      _cluster("my-neptune", "neptune")])
    failed = {r.resource for r in _ids(s, "AUR-01", "FAIL")}
    assert failed == {"prod-aurora"}, f"AUR-01 scored {sorted(failed)}"


def test_a_cluster_with_no_engine_field_is_still_scored():
    """PERMISSIVE BY DESIGN. The filter drops a cluster only when it POSITIVELY declares a
    foreign engine. An allow-list would silently drop every Aurora variant AWS adds next,
    which is the failure mode hardest to notice -- see NON_AURORA_CLUSTER_ENGINES."""
    s = _rds_scanner([{"DBClusterIdentifier": "mystery", "StorageEncrypted": False,
                       "DeletionProtection": False}])
    assert _ids(s, "AUR-01", "FAIL"), "a cluster with no Engine was silently dropped"


def test_the_deny_list_is_exactly_the_two_services_that_share_the_api():
    assert NON_AURORA_CLUSTER_ENGINES == {"docdb", "neptune"}


# ── snapshots: the same overlap, on the other API ───────────────────────────
def test_documentdb_and_neptune_snapshots_are_not_scored_as_aurora():
    s = _rds_scanner([], [_snapshot("docdb-snap", "docdb"),
                          _snapshot("neptune-snap", "neptune")])
    assert not _ids(s, "AUR-05", "FAIL"), (
        "a foreign-engine snapshot still FAILs the Aurora snapshot-encryption check")


def test_a_real_aurora_snapshot_still_fails():
    s = _rds_scanner([], [_snapshot("aurora-snap", "aurora")])
    _renders(s, "AUR-05", "HIGH", contains="aurora-snap")


# ══════════════════════════════════════════════════════════════════════════════
# DocumentDB — the two facts that used to arrive only via an Aurora id
# ══════════════════════════════════════════════════════════════════════════════
def _docdb_scanner(clusters=(), snapshots=(), attrs=(), instances=()):
    s = make_scanner(sections=["DOCDB"])
    s.account = OWN
    docdb = MagicMock()
    docdb.describe_db_cluster_snapshots.return_value = {
        "DBClusterSnapshots": list(snapshots)}
    docdb.describe_db_cluster_snapshot_attributes.return_value = {
        "DBClusterSnapshotAttributesResult": {
            "DBClusterSnapshotAttributes": list(attrs)}}
    docdb.describe_db_clusters.return_value = {"DBClusters": list(clusters)}

    def _pager(op):
        p = MagicMock()
        p.paginate.return_value = ([{"DBInstances": list(instances)}]
                                   if op == "describe_db_instances" else [{}])
        return p

    docdb.get_paginator.side_effect = _pager
    s._clients[f"docdb:{REGION}"] = docdb
    s._check_docdb()
    return s


def test_docdb04_deletion_protection_off_fails():
    """AUR-02 was the only thing reporting this, and it reached DocumentDB by accident.
    `docdb_cluster_posture` had always computed the field; nothing consumed it."""
    s = _docdb_scanner([_cluster("my-docdb", "docdb", deletion_protection=False)])
    _renders(s, "DOCDB-04", "MEDIUM", contains="my-docdb")


def test_docdb04_passes_when_deletion_protection_is_on():
    s = _docdb_scanner([_cluster("my-docdb", "docdb", deletion_protection=True)])
    assert not _ids(s, "DOCDB-04", "FAIL")
    assert _ids(s, "DOCDB-04", "PASS")


def test_docdb05_unencrypted_snapshot_fails():
    """AUR-05's replacement for DocumentDB snapshots."""
    s = _docdb_scanner(snapshots=[_snapshot("docdb-snap", "docdb", encrypted=False)])
    _renders(s, "DOCDB-05", "HIGH", contains="docdb-snap")


def test_docdb05_is_evaluated_even_when_the_attribute_read_fails():
    """ORDERING MATTERS. The snapshot-attribute read below DOCDB-05 `continue`s on
    failure. Evaluating encryption after it would mean a denied DescribeDBClusterSnapshot-
    Attributes silently cost us the encryption finding too -- two checks lost to one
    permission."""
    s = make_scanner(sections=["DOCDB"])
    s.account = OWN
    docdb = MagicMock()
    docdb.describe_db_cluster_snapshots.return_value = {
        "DBClusterSnapshots": [_snapshot("docdb-snap", "docdb", encrypted=False)]}
    docdb.describe_db_cluster_snapshot_attributes.side_effect = RuntimeError("denied")
    docdb.describe_db_clusters.return_value = {"DBClusters": []}
    s._clients[f"docdb:{REGION}"] = docdb
    s._check_docdb()
    _renders(s, "DOCDB-05", "HIGH", contains="docdb-snap")


def test_docdb_ignores_a_cluster_that_declares_another_engine():
    """The mirror of the Aurora filter. The docdb endpoint is a fork of the same control
    plane, so scoring whatever it returns has the same failure mode in reverse."""
    s = _docdb_scanner([_cluster("prod-aurora", "aurora-mysql")])
    assert not _ids(s, "DOCDB-04", "FAIL"), "an Aurora cluster was scored as DocumentDB"


# ══════════════════════════════════════════════════════════════════════════════
# Neptune — a section that did not exist, for findings that were already being made
# ══════════════════════════════════════════════════════════════════════════════
def _neptune_scanner(clusters=(), snapshots=(), attrs=(), cluster_error=None,
                     attr_error=None, instances=()):
    s = make_scanner(sections=["NEPTUNE"])
    s.account = OWN
    nep = MagicMock()

    def _pager(op):
        p = MagicMock()
        if op == "describe_db_clusters":
            if cluster_error:
                p.paginate.side_effect = cluster_error
            else:
                p.paginate.return_value = [{"DBClusters": list(clusters)}]
        elif op == "describe_db_cluster_snapshots":
            p.paginate.return_value = [{"DBClusterSnapshots": list(snapshots)}]
        elif op == "describe_db_instances":
            p.paginate.return_value = [{"DBInstances": list(instances)}]
        else:
            p.paginate.return_value = [{}]
        return p

    nep.get_paginator.side_effect = _pager
    if attr_error:
        nep.describe_db_cluster_snapshot_attributes.side_effect = attr_error
    else:
        nep.describe_db_cluster_snapshot_attributes.return_value = {
            "DBClusterSnapshotAttributesResult": {
                "DBClusterSnapshotAttributes": list(attrs)}}
    s._clients[f"neptune:{REGION}"] = nep
    s._check_neptune()
    return s


def test_nep01_unencrypted_cluster_fails():
    s = _neptune_scanner([_cluster("my-neptune", "neptune", encrypted=False)])
    _renders(s, "NEP-01", "HIGH", contains="my-neptune")


def test_nep01_passes_on_an_encrypted_cluster():
    s = _neptune_scanner([_cluster("my-neptune", "neptune", encrypted=True)])
    assert not _ids(s, "NEP-01", "FAIL")
    assert _ids(s, "NEP-01", "PASS")


def test_nep02_deletion_protection_off_fails():
    s = _neptune_scanner([_cluster("my-neptune", "neptune",
                                   deletion_protection=False)])
    _renders(s, "NEP-02", "MEDIUM", contains="my-neptune")


def test_nep03_public_snapshot_fails():
    s = _neptune_scanner(
        snapshots=[_snapshot("nep-snap", "neptune")],
        attrs=[{"AttributeName": "restore", "AttributeValues": ["all"]}])
    _renders(s, "NEP-03", "CRITICAL", contains="nep-snap")


def test_nep03_passes_when_the_snapshot_is_shared_with_nobody():
    s = _neptune_scanner(snapshots=[_snapshot("nep-snap", "neptune")], attrs=[])
    assert not _ids(s, "NEP-03", "FAIL")
    assert _ids(s, "NEP-03", "PASS")


def test_nep04_unencrypted_snapshot_fails():
    s = _neptune_scanner(snapshots=[_snapshot("nep-snap", "neptune",
                                              encrypted=False)])
    _renders(s, "NEP-04", "HIGH", contains="nep-snap")


def test_a_failed_neptune_read_is_a_warning_not_a_finding():
    """`_read_failed`, not a FAIL. A read we could not make is not a security finding,
    and reporting the exception text as one is the defect the previous cycle removed
    from 32 sites."""
    s = _neptune_scanner(cluster_error=RuntimeError("AccessDenied"))
    assert not _ids(s, "NEP-01", "FAIL"), "a failed read was reported as a finding"
    warns = _ids(s, "NEP-01", "WARN")
    assert warns and "NOT EVALUATED" in warns[0].message


def test_an_undetermined_snapshot_visibility_is_not_a_pass():
    """The most dangerous shape in the file: a snapshot whose restore attribute could not
    be read is UNKNOWN, and emitting nothing would render as 'not public'."""
    s = _neptune_scanner(snapshots=[_snapshot("nep-snap", "neptune", encrypted=True)],
                         attr_error=RuntimeError("AccessDenied"))
    assert not _ids(s, "NEP-03", "PASS"), (
        "an unreadable restore attribute was reported as not-public")
    assert _ids(s, "NEP-03", "WARN")


def test_neptune_ignores_a_cluster_that_declares_another_engine():
    s = _neptune_scanner([_cluster("prod-aurora", "aurora-mysql")])
    assert not _ids(s, "NEP-01", "FAIL"), "an Aurora cluster was scored as Neptune"


# ══════════════════════════════════════════════════════════════════════════════
# The property that makes the whole change safe
# ══════════════════════════════════════════════════════════════════════════════
def test_the_same_estate_produces_the_same_number_of_findings_under_new_ids():
    """THE ANTI-REGRESSION TEST. An unencrypted, unprotected DocumentDB cluster and the
    same Neptune cluster used to produce four Aurora FAILs between them. They still
    produce four FAILs -- DOCDB-02 and DOCDB-04, NEP-01 and NEP-02 -- so the filter
    moved the findings rather than deleting them."""
    docdb = _docdb_scanner([_cluster("my-docdb", "docdb")])
    nept = _neptune_scanner([_cluster("my-neptune", "neptune")])
    got = ({r.check_id for r in docdb.results if r.status == "FAIL"}
           | {r.check_id for r in nept.results if r.status == "FAIL"})
    assert {"DOCDB-02", "DOCDB-04", "NEP-01", "NEP-02"} <= got, (
        f"coverage was lost, not moved: {sorted(got)}")


# ══════════════════════════════════════════════════════════════════════════════
# The INSTANCE plane — the same defect one level down
# ══════════════════════════════════════════════════════════════════════════════
def _instance(iid, engine, **over):
    """A maximally non-compliant instance, so any check that CAN fire on it does."""
    inst = {"DBInstanceIdentifier": iid, "Engine": engine,
            "DBInstanceArn": f"arn:aws:rds:{REGION}:{OWN}:db:{iid}",
            "EngineVersion": "5.7.0", "DBInstanceStatus": "available",
            "StorageEncrypted": False, "PubliclyAccessible": True,
            "BackupRetentionPeriod": 0, "DeletionProtection": False,
            "MultiAZ": False, "AutoMinorVersionUpgrade": False,
            "IAMDatabaseAuthenticationEnabled": False}
    inst.update(over)
    return inst


def _rds_instance_scanner(instances):
    s = make_scanner(sections=["RDS"])
    s.account = OWN
    rds = MagicMock()

    def _pager(op):
        p = MagicMock()
        p.paginate.return_value = ([{"DBInstances": list(instances)}]
                                   if op == "describe_db_instances" else [{}])
        return p

    rds.get_paginator.side_effect = _pager
    rds.describe_db_snapshots.return_value = {"DBSnapshots": []}
    rds.describe_db_clusters.return_value = {"DBClusters": []}
    s._clients[f"rds:{REGION}"] = rds
    s._check_rds()
    return {r.check_id for r in s.results if r.status == "FAIL"}


def test_a_neptune_instance_produces_no_rds_finding():
    """THE DEFECT, one level down. Before the filter this produced RDS-01, RDS-02, RDS-03
    and RDS-04 on a resource that is not an RDS database, with RDS remediation."""
    leaked = {c for c in _rds_instance_scanner([_instance("graph-1", "neptune")])
              if c.startswith("RDS-")}
    assert not leaked, f"a Neptune instance was scored as RDS: {sorted(leaked)}"


def test_a_documentdb_instance_produces_no_rds_finding():
    leaked = {c for c in _rds_instance_scanner([_instance("docs-1", "docdb")])
              if c.startswith("RDS-")}
    assert not leaked, f"a DocumentDB instance was scored as RDS: {sorted(leaked)}"


def test_a_real_rds_instance_still_fails_everything_it_should():
    """The other half of the ratchet, and the reason the filter is not just a delete."""
    fails = _rds_instance_scanner([_instance("prod-mysql", "mysql")])
    assert {"RDS-01", "RDS-02", "RDS-03", "RDS-04"} <= fails, sorted(fails)


def test_an_unknown_engine_is_still_scored_at_the_instance_level():
    """PERMISSIVE BY DESIGN, exactly as at the cluster level. An allow-list would silently
    stop scoring every RDS engine AWS ships after the day it was written -- the failure
    mode hardest to notice, because the output is simply quieter."""
    for engine in ("some-engine-aws-ships-in-2029", ""):
        fails = _rds_instance_scanner([_instance("mystery", engine)])
        assert {"RDS-01", "RDS-02"} <= fails, (
            f"an instance with Engine={engine!r} was silently dropped: {sorted(fails)}")


def test_an_instance_with_no_engine_field_at_all_is_still_scored():
    inst = _instance("mystery", "mysql")
    del inst["Engine"]
    assert {"RDS-01", "RDS-02"} <= _rds_instance_scanner([inst]), (
        "an instance with no Engine key was silently dropped")


def test_a_mixed_response_splits_correctly():
    """The realistic shape: one DescribeDBInstances response holding all three services.
    The RDS instance must still be scored while its neighbours are not."""
    fails = _rds_instance_scanner([_instance("prod-mysql", "mysql"),
                                   _instance("graph-1", "neptune"),
                                   _instance("docs-1", "docdb")])
    assert {"RDS-01", "RDS-02", "RDS-03", "RDS-04"} <= fails, sorted(fails)


# ── the replacements, without which the filter above deletes coverage ────────
def test_nep06_public_instance_fails():
    """RDS-02's replacement for Neptune, and the more serious finding of the two: Neptune
    has no database users, so on a cluster without IAM auth the security group is the
    entire access control."""
    s = _neptune_scanner(instances=[{"DBInstanceIdentifier": "graph-1",
                                     "PubliclyAccessible": True}])
    _renders(s, "NEP-06", "CRITICAL", contains="graph-1")


def test_nep06_passes_on_a_private_instance():
    s = _neptune_scanner(instances=[{"DBInstanceIdentifier": "graph-1",
                                     "PubliclyAccessible": False}])
    assert not _ids(s, "NEP-06", "FAIL")
    assert _ids(s, "NEP-06", "PASS")


def test_nep07_short_retention_fails_and_seven_days_passes():
    """RDS-03's replacement, read from the CLUSTER because that is where Neptune holds it.
    Neptune's minimum retention is 1, so a check for 0 would never fire -- the decidable
    question is whether the window is long enough to find a problem inside."""
    bad = _neptune_scanner([_cluster("graph", "neptune", encrypted=True,
                                     deletion_protection=True)
                            | {"BackupRetentionPeriod": 1}])
    _renders(bad, "NEP-07", "MEDIUM", contains="graph")
    good = _neptune_scanner([_cluster("graph", "neptune", encrypted=True,
                                      deletion_protection=True)
                             | {"BackupRetentionPeriod": 7}])
    assert not _ids(good, "NEP-07", "FAIL")
    assert _ids(good, "NEP-07", "PASS")


def test_nep08_iam_auth_off_fails():
    s = _neptune_scanner([_cluster("graph", "neptune")
                          | {"IAMDatabaseAuthenticationEnabled": False}])
    _renders(s, "NEP-08", "HIGH", contains="graph")


def test_nep08_is_rated_above_the_aurora_equivalent():
    """Not a style preference. On Aurora, IAM auth off means static passwords -- a
    credential-hygiene problem. On Neptune it means no authentication exists at all,
    because the engine has no database users to have passwords."""
    from engine.aws_live_scanner import CHECK_SEVERITY
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert order.index(CHECK_SEVERITY["NEP-08"]) > order.index(CHECK_SEVERITY["AUR-08"])


def test_nep09_audit_export_missing_fails_and_present_passes():
    off = _neptune_scanner([_cluster("graph", "neptune")
                            | {"EnabledCloudwatchLogsExports": []}])
    _renders(off, "NEP-09", "MEDIUM", contains="graph")
    on = _neptune_scanner([_cluster("graph", "neptune")
                           | {"EnabledCloudwatchLogsExports": ["audit"]}])
    assert not _ids(on, "NEP-09", "FAIL")
    assert _ids(on, "NEP-09", "PASS")


def test_nep09_says_nothing_when_the_field_is_absent():
    """An absent list is not an empty one. AWS omitting the key would otherwise be read
    as 'no logs exported' and produce a finding from a fact we do not have."""
    s = _neptune_scanner([_cluster("graph", "neptune")])
    assert not _ids(s, "NEP-09", "FAIL"), (
        "a missing EnabledCloudwatchLogsExports was treated as an empty one")


def test_nep10_single_az_fails():
    s = _neptune_scanner([_cluster("graph", "neptune") | {"MultiAZ": False}])
    _renders(s, "NEP-10", "MEDIUM", contains="graph")


def test_docdb07_public_instance_fails():
    s = _docdb_scanner(instances=[{"DBInstanceIdentifier": "docs-1",
                                   "PubliclyAccessible": True}])
    _renders(s, "DOCDB-07", "CRITICAL", contains="docs-1")


def test_docdb08_short_retention_fails_and_seven_days_passes():
    bad = _docdb_scanner([_cluster("docs", "docdb") | {"BackupRetentionPeriod": 1}])
    _renders(bad, "DOCDB-08", "MEDIUM", contains="docs")
    good = _docdb_scanner([_cluster("docs", "docdb") | {"BackupRetentionPeriod": 7}])
    assert not _ids(good, "DOCDB-08", "FAIL")
    assert _ids(good, "DOCDB-08", "PASS")


def test_the_instance_replacements_cover_what_the_filter_removed():
    """THE ANTI-REGRESSION TEST for the instance plane, matching the cluster one above.
    A public, short-retention Neptune instance used to produce RDS-02 and RDS-03. It still
    produces two findings -- NEP-06 and NEP-07 -- so the filter moved them rather than
    deleting them. The DocumentDB half is DOCDB-07 and DOCDB-08.
    """
    nept = _neptune_scanner([_cluster("graph", "neptune")
                             | {"BackupRetentionPeriod": 1}],
                            instances=[{"DBInstanceIdentifier": "graph-1",
                                        "PubliclyAccessible": True}])
    docdb = _docdb_scanner([_cluster("docs", "docdb") | {"BackupRetentionPeriod": 1}],
                           instances=[{"DBInstanceIdentifier": "docs-1",
                                       "PubliclyAccessible": True}])
    got = ({r.check_id for r in nept.results if r.status == "FAIL"}
           | {r.check_id for r in docdb.results if r.status == "FAIL"})
    assert {"NEP-06", "NEP-07", "DOCDB-07", "DOCDB-08"} <= got, (
        f"coverage was lost, not moved: {sorted(got)}")


def test_the_sibling_sections_filter_their_own_instances_too():
    """The mirror of the RDS filter. The neptune and docdb endpoints are forks of the same
    control plane, so scoring whatever they return has the same failure mode in reverse."""
    nept = _neptune_scanner(instances=[{"DBInstanceIdentifier": "prod-mysql",
                                        "Engine": "mysql",
                                        "PubliclyAccessible": True}])
    assert not _ids(nept, "NEP-06", "FAIL"), "an RDS instance was scored as Neptune"
    docdb = _docdb_scanner(instances=[{"DBInstanceIdentifier": "prod-mysql",
                                       "Engine": "mysql",
                                       "PubliclyAccessible": True}])
    assert not _ids(docdb, "DOCDB-07", "FAIL"), "an RDS instance was scored as DocumentDB"


def test_a_failed_instance_read_is_a_warning_not_a_finding():
    """Same rule as the cluster read: a read we could not make is not a security finding.
    NEP-06 is CRITICAL, so reporting an AccessDenied as one would be a critical finding
    manufactured from an absence of information."""
    s = make_scanner(sections=["NEPTUNE"])
    s.account = OWN
    nep = MagicMock()

    def _pager(op):
        p = MagicMock()
        if op == "describe_db_instances":
            p.paginate.side_effect = RuntimeError("AccessDenied")
        else:
            p.paginate.return_value = [{}]
        return p

    nep.get_paginator.side_effect = _pager
    s._clients[f"neptune:{REGION}"] = nep
    s._check_neptune()
    assert not _ids(s, "NEP-06", "FAIL"), "a failed read was reported as a finding"
    warns = _ids(s, "NEP-06", "WARN")
    assert warns and "NOT EVALUATED" in warns[0].message
