"""Settings read from the plane that actually owns them.

TWO SPLITS AND TWO UNREAD FIELDS.

RDS-03 and RDS-08 read BackupRetentionPeriod and IAMDatabaseAuthenticationEnabled from
`describe_db_instances`. For an Aurora cluster the CLUSTER owns both, and an Aurora
Serverless v1 cluster has no instances at all -- so for exactly the resources where these
settings matter most, the instance-level checks were either reading a non-authoritative
value or reading nothing. AUR-07 and AUR-08 read the cluster page AUR-01..03 already
fetch, so they cost no new call and no new grant.

ELC-07 and ELC-08 read SnapshotRetentionLimit and MultiAZ, two fields sitting in a
response the ElastiCache section was already paginating and never looked at.

MultiAZ IS A STRING ENUM ('enabled'/'disabled'), not a boolean. A truthiness test would
read 'disabled' as True and pass every unprotected group -- a silent false clean, which
is why it is pinned here explicitly.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_cis_db                                       # noqa: E402
from test_live_scanner import make_scanner                          # noqa: E402
from test_unproven_checks_tranche5 import _ids, _renders            # noqa: E402

OWN = "123456789012"
REGION = "us-east-1"


# ══════════════════════════════════════════════════════════════════════════════
# AUR-07 / AUR-08 — the cluster plane
# ══════════════════════════════════════════════════════════════════════════════
def _aurora(cid="prod-aurora", engine="aurora-postgresql", **over):
    cl = {"DBClusterIdentifier": cid, "Engine": engine, "EngineVersion": "15.4",
          "DBClusterArn": f"arn:aws:rds:{REGION}:{OWN}:cluster:{cid}",
          "DBClusterParameterGroup": "cluster-pg",
          "StorageEncrypted": True, "DeletionProtection": True,
          "BackupRetentionPeriod": 7, "IAMDatabaseAuthenticationEnabled": True}
    cl.update(over)
    return cl


def _rds_scanner(clusters, params=(("rds.force_ssl", "1"),)):
    s = make_scanner(sections=["RDS"])
    s.account = OWN
    rds = MagicMock()

    def _pager(op):
        p = MagicMock()
        if op == "describe_db_clusters":
            p.paginate.return_value = [{"DBClusters": list(clusters)}]
        elif op in ("describe_db_parameters", "describe_db_cluster_parameters"):
            p.paginate.return_value = [{"Parameters": [
                {"ParameterName": n, "ParameterValue": v} for n, v in params]}]
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


def test_aur07_fails_on_the_aurora_default_of_one_day():
    """The threshold is <7 rather than ==0 ON PURPOSE. A cluster's minimum retention is
    1 day, so "backups off" is unreachable and a ==0 test would be a check that can never
    fire -- exactly what docs/CHECK_FIRING.md exists to catch. The real gap is the
    DEFAULT: a cluster nobody configured retains one day."""
    s = _rds_scanner([_aurora(BackupRetentionPeriod=1)])
    _renders(s, "AUR-07", "MEDIUM", contains="retention=1d")


def test_aur07_passes_at_seven_days():
    s = _rds_scanner([_aurora(BackupRetentionPeriod=7)])
    assert not _ids(s, "AUR-07", "FAIL")
    assert _ids(s, "AUR-07", "PASS")


def test_aur07_says_nothing_when_the_field_is_absent():
    """Absent is not zero. Reporting a missing field as "backups disabled" would be a
    confident wrong answer."""
    cl = _aurora()
    del cl["BackupRetentionPeriod"]
    s = _rds_scanner([cl])
    assert not _ids(s, "AUR-07")


def test_aur08_fails_when_cluster_iam_auth_is_off():
    s = _rds_scanner([_aurora(IAMDatabaseAuthenticationEnabled=False)])
    _renders(s, "AUR-08", "MEDIUM", contains="prod-aurora")


def test_aur08_passes_when_cluster_iam_auth_is_on():
    s = _rds_scanner([_aurora(IAMDatabaseAuthenticationEnabled=True)])
    assert not _ids(s, "AUR-08", "FAIL")
    assert _ids(s, "AUR-08", "PASS")


def test_aur08_is_silent_on_an_engine_that_does_not_offer_iam_auth():
    """IAM database authentication exists for MySQL/PostgreSQL/MariaDB/Aurora only.
    Reporting its absence on an engine that cannot have it is a finding nobody can fix --
    the same rule RDS-08 already applies at the instance level."""
    s = _rds_scanner([_aurora(engine="sqlserver-ee",
                              IAMDatabaseAuthenticationEnabled=False)])
    assert not _ids(s, "AUR-08", "FAIL")


def test_aur08_says_nothing_when_the_field_is_absent():
    cl = _aurora()
    del cl["IAMDatabaseAuthenticationEnabled"]
    s = _rds_scanner([cl])
    assert not _ids(s, "AUR-08")


def test_the_cluster_checks_do_not_reach_documentdb_or_neptune():
    """These ride the same loop the engine filter guards, so they inherit it -- and this
    asserts that rather than assuming it."""
    s = _rds_scanner([_aurora(cid="my-docdb", engine="docdb",
                              BackupRetentionPeriod=1,
                              IAMDatabaseAuthenticationEnabled=False),
                      _aurora(cid="my-neptune", engine="neptune",
                              BackupRetentionPeriod=1,
                              IAMDatabaseAuthenticationEnabled=False)])
    assert not _ids(s, "AUR-07", "FAIL")
    assert not _ids(s, "AUR-08", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# ELC-07 / ELC-08 — two fields already in a response nobody read
# ══════════════════════════════════════════════════════════════════════════════
def _rg(rgid="prod-redis", **over):
    g = {"ReplicationGroupId": rgid, "Engine": "redis",
         "AtRestEncryptionEnabled": True, "TransitEncryptionEnabled": True,
         "AuthTokenEnabled": True, "AutomaticFailover": "enabled",
         "UserGroupIds": ["ug-1"], "SnapshotRetentionLimit": 7,
         "MultiAZ": "enabled"}
    g.update(over)
    return g


def _elc_scanner(groups):
    s = make_scanner(sections=["ELASTICACHE"])
    s.account = OWN
    ec = MagicMock()
    ec.describe_replication_groups.return_value = {"ReplicationGroups": list(groups)}
    pager = MagicMock()
    pager.paginate.return_value = [{"CacheClusters": []}]
    ec.get_paginator.return_value = pager
    s._clients[f"elasticache:{REGION}"] = ec
    s._check_elasticache()
    return s


def test_elc07_fails_when_snapshots_are_disabled():
    s = _elc_scanner([_rg(SnapshotRetentionLimit=0)])
    _renders(s, "ELC-07", "MEDIUM", contains="prod-redis")


def test_elc07_passes_when_snapshots_are_retained():
    s = _elc_scanner([_rg(SnapshotRetentionLimit=5)])
    assert not _ids(s, "ELC-07", "FAIL")
    assert _ids(s, "ELC-07", "PASS")


def test_elc07_says_nothing_when_the_field_is_absent():
    g = _rg()
    del g["SnapshotRetentionLimit"]
    s = _elc_scanner([g])
    assert not _ids(s, "ELC-07")


def test_elc08_fails_when_multi_az_is_disabled():
    s = _elc_scanner([_rg(MultiAZ="disabled")])
    _renders(s, "ELC-08", "MEDIUM", contains="prod-redis")


def test_elc08_passes_when_multi_az_is_enabled():
    s = _elc_scanner([_rg(MultiAZ="enabled")])
    assert not _ids(s, "ELC-08", "FAIL")
    assert _ids(s, "ELC-08", "PASS")


def test_multi_az_is_a_string_enum_not_a_boolean():
    """THE BUG THIS PREVENTS. botocore types MultiAZ as a string with enum
    ['enabled', 'disabled']. `if rg.get("MultiAZ")` is truthy for BOTH values, so a
    boolean test would pass every single-AZ group in existence and report nothing --
    a silent false clean on a check that appears to be working."""
    s = _elc_scanner([_rg(MultiAZ="disabled")])
    assert _ids(s, "ELC-08", "FAIL"), (
        "'disabled' was treated as truthy — the check is testing the wrong thing")


def test_elc08_says_nothing_on_an_unrecognised_multi_az_value():
    """The enum could gain a transitional state, the way AutomaticFailover has
    'enabling'/'disabling'. Neither PASS nor FAIL is honest for one of those."""
    s = _elc_scanner([_rg(MultiAZ="enabling")])
    assert not _ids(s, "ELC-08")


def test_the_new_cache_checks_do_not_disturb_the_existing_ones():
    """ELC-01..06 ran off this same loop before. A regression here would be invisible in
    the new checks' own tests."""
    s = _elc_scanner([_rg(AtRestEncryptionEnabled=False)])
    assert _ids(s, "ELC-01", "FAIL")
    assert _ids(s, "ELC-02", "PASS")
    assert _ids(s, "ELC-06", "PASS")


# ══════════════════════════════════════════════════════════════════════════════
# What was deliberately NOT built
# ══════════════════════════════════════════════════════════════════════════════
def test_cluster_mode_is_declined_with_a_written_reason():
    """A benchmark recommendation is not automatically a security defect. Redis cluster
    mode is an architecture choice -- a single-shard group is a legitimate and common
    design -- so a check would fire on correct systems and bury the real findings.
    Recorded as a decision rather than left looking like an oversight."""
    assert "elasticache-cluster-mode" in aws_cis_db.DECLINED_AS_NOT_A_FINDING
    reason = aws_cis_db.DECLINED_AS_NOT_A_FINDING["elasticache-cluster-mode"]
    assert len(reason) > 80, "a decline without a real reason is just an omission"
    assert "ELC-04" in reason and "ELC-08" in reason, (
        "the decline should name what DOES cover the underlying concern")


def test_the_two_decline_dicts_stay_distinct():
    """NOT_DETERMINABLE means 'no control-plane read can decide this'.
    DECLINED_AS_NOT_A_FINDING means 'readable, and deliberately not reported'. Collapsing
    them would lose the difference between a limit and a judgement."""
    overlap = set(aws_cis_db.NOT_DETERMINABLE) & set(
        aws_cis_db.DECLINED_AS_NOT_A_FINDING)
    assert not overlap, f"an entry claims to be both: {sorted(overlap)}"
