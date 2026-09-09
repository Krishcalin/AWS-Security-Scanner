"""TLS enforcement: the control OverWatch had no coverage of at all.

Every RDS engine ACCEPTS TLS. Almost none REQUIRE it, and nothing in
`describe_db_instances` or `describe_db_clusters` says which — the setting lives in a
parameter group, so a product that never reads one cannot tell an encrypted estate from a
cleartext one. Before RDS-14/AUR-06/DOCDB-06/NEP-05 a repo-wide search for `force_ssl`,
`require_secure_transport`, `describe_db_parameters` and `describe_db_cluster_parameters`
returned nothing.

(ElastiCache in-transit encryption WAS already covered, at the `TransitEncryptionEnabled`
flag. That is a different mechanism on a different service and is not this gap.)

TWO HALVES. `aws_cis_db.tls_enforcement` decides, and is tested here as a pure function
against every engine family; the scanner reads the parameter group and is tested for the
wiring, the caching, and — the part most likely to be got wrong — what happens when the
answer is UNKNOWN.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_cis_db                                       # noqa: E402
from test_live_scanner import make_scanner                          # noqa: E402
from test_unproven_checks_tranche5 import _ids, _renders            # noqa: E402

OWN = "123456789012"
REGION = "us-east-1"


def _p(name, value):
    return {"ParameterName": name, "ParameterValue": value}


# ══════════════════════════════════════════════════════════════════════════════
# The pure rule
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("engine,param", [
    ("postgres", "rds.force_ssl"),
    ("aurora-postgresql", "rds.force_ssl"),
    ("sqlserver-ee", "rds.force_ssl"),
    ("sqlserver-web", "rds.force_ssl"),
    ("mysql", "require_secure_transport"),
    ("mariadb", "require_secure_transport"),
    ("aurora", "require_secure_transport"),
    ("aurora-mysql", "require_secure_transport"),
    ("docdb", "tls"),
    ("neptune", "neptune_enforce_ssl"),
])
def test_each_engine_maps_to_its_own_parameter(engine, param):
    """Getting the pair wrong is worse than not checking: a wrong NAME reads as absent
    and a wrong VALUE reads as not-enforced, and both are false FAILs on a database that
    is correctly configured."""
    pair = aws_cis_db.tls_parameter_for(engine)
    assert pair is not None, f"{engine} has no TLS parameter mapping"
    assert pair[0] == param


@pytest.mark.parametrize("engine,param,good,bad", [
    ("postgres", "rds.force_ssl", "1", "0"),
    ("aurora-postgresql", "rds.force_ssl", "1", "0"),
    ("sqlserver-se", "rds.force_ssl", "1", "0"),
    ("mysql", "require_secure_transport", "ON", "OFF"),
    ("aurora-mysql", "require_secure_transport", "1", "0"),
    ("docdb", "tls", "enabled", "disabled"),
    ("neptune", "neptune_enforce_ssl", "1", "0"),
])
def test_enforced_and_not_enforced_are_both_decidable(engine, param, good, bad):
    on = aws_cis_db.tls_enforcement(engine, [_p(param, good)], "pg")
    assert on["known"] and on["enforced"], on

    off = aws_cis_db.tls_enforcement(engine, [_p(param, bad)], "pg")
    assert off["known"] and not off["enforced"], off
    assert param in off["statement"]


def test_mysql_accepts_on_in_either_case():
    """MySQL renders this ON/OFF and Aurora also accepts 1/0. Casefolding is not a
    nicety here -- 'On' from one API version failing a check that 'ON' passes would be a
    false FAIL nobody could reproduce."""
    for v in ("ON", "on", "On", "1"):
        r = aws_cis_db.tls_enforcement("mysql", [_p("require_secure_transport", v)])
        assert r["enforced"], f"{v!r} was not read as enforced"


def test_an_absent_parameter_is_undecided_not_a_failure():
    """THE IMPORTANT ONE. DescribeDBParameters returns engine defaults alongside operator
    settings, so a parameter genuinely missing from the listing is unusual and means we
    could not decide -- not that the database is insecure. Resolving it to FAIL would put
    a HIGH finding on a correctly configured database; resolving it to PASS would be a
    false clean, which is worse."""
    r = aws_cis_db.tls_enforcement("postgres", [_p("log_statement", "all")], "pg-1")
    assert not r["known"]
    assert not r["enforced"]
    assert "rds.force_ssl" in r["reason"] and "pg-1" in r["reason"]


def test_a_parameter_with_no_value_is_undecided():
    for empty in (None, "", "   "):
        r = aws_cis_db.tls_enforcement("postgres", [_p("rds.force_ssl", empty)], "pg")
        assert not r["known"], f"{empty!r} was treated as decidable"


def test_oracle_is_undecided_with_a_reason_rather_than_guessed_at():
    """Oracle configures transport security through the option group and sqlnet, not a DB
    parameter. Inventing a parameter name for it would produce a confident wrong answer
    on every Oracle instance in existence."""
    r = aws_cis_db.tls_enforcement("oracle-se2", [], "pg")
    assert not r["known"]
    assert "option group" in r["reason"]


def test_an_unknown_engine_is_undecided_and_names_itself():
    r = aws_cis_db.tls_enforcement("db2-ae", [], "pg")
    assert not r["known"]
    assert "db2-ae" in r["reason"]


def test_a_missing_engine_is_undecided():
    for engine in (None, "", "   "):
        assert not aws_cis_db.tls_enforcement(engine, [_p("rds.force_ssl", "1")])["known"]


def test_malformed_parameter_rows_do_not_crash_the_rule():
    """The listing is an AWS response; a scanner that raises on an unexpected row takes
    the whole RDS section down with it."""
    r = aws_cis_db.tls_enforcement(
        "postgres", [None, "not-a-dict", 42, _p("rds.force_ssl", "1")], "pg")
    assert r["known"] and r["enforced"]


def test_the_module_is_pure():
    """Same charter as aws_cis_compute: no boto3, no network, no I/O, so every rule is
    testable without a client."""
    import inspect
    src = inspect.getsource(aws_cis_db)
    for banned in ("import boto3", "import botocore", "requests", "urllib"):
        assert banned not in src, f"aws_cis_db imports {banned}"


# ══════════════════════════════════════════════════════════════════════════════
# The wiring — RDS-14 and AUR-06
# ══════════════════════════════════════════════════════════════════════════════
def _rds_scanner(*, instances=(), clusters=(), params=None, param_error=None):
    s = make_scanner(sections=["RDS"])
    s.account = OWN
    rds = MagicMock()

    def _pager(op):
        p = MagicMock()
        if op == "describe_db_instances":
            p.paginate.return_value = [{"DBInstances": list(instances)}]
        elif op == "describe_db_clusters":
            p.paginate.return_value = [{"DBClusters": list(clusters)}]
        elif op in ("describe_db_parameters", "describe_db_cluster_parameters"):
            if param_error:
                p.paginate.side_effect = param_error
            else:
                p.paginate.return_value = [{"Parameters": list(params or [])}]
        else:
            p.paginate.return_value = [{}]
        return p

    rds.get_paginator.side_effect = _pager
    rds.describe_db_instances.return_value = {"DBInstances": list(instances)}
    rds.describe_db_cluster_snapshot_attributes.return_value = {
        "DBClusterSnapshotAttributesResult": {"DBClusterSnapshotAttributes": []}}
    s._clients[f"rds:{REGION}"] = rds
    s._rds_client_for_test = rds
    s._check_rds()
    return s


def _instance(iid, engine, group="default-pg"):
    return {"DBInstanceIdentifier": iid, "Engine": engine, "EngineVersion": "15.4",
            "DBParameterGroups": [{"DBParameterGroupName": group}],
            "StorageEncrypted": True, "PubliclyAccessible": False,
            "BackupRetentionPeriod": 7, "MultiAZ": True, "DeletionProtection": True,
            "AutoMinorVersionUpgrade": True, "MonitoringInterval": 60,
            "EnabledCloudwatchLogsExports": ["postgresql"],
            "IAMDatabaseAuthenticationEnabled": True}


def _cluster(cid, engine, group="default-cluster-pg"):
    return {"DBClusterIdentifier": cid, "Engine": engine, "EngineVersion": "15.4",
            "DBClusterArn": f"arn:aws:rds:{REGION}:{OWN}:cluster:{cid}",
            "DBClusterParameterGroup": group,
            "StorageEncrypted": True, "DeletionProtection": True}


def test_rds14_fails_when_the_instance_does_not_require_tls():
    s = _rds_scanner(instances=[_instance("prod-pg", "postgres")],
                     params=[_p("rds.force_ssl", "0")])
    _renders(s, "RDS-14", "HIGH", contains="rds.force_ssl=0")


def test_rds14_passes_when_the_instance_requires_tls():
    s = _rds_scanner(instances=[_instance("prod-pg", "postgres")],
                     params=[_p("rds.force_ssl", "1")])
    assert not _ids(s, "RDS-14", "FAIL")
    assert _ids(s, "RDS-14", "PASS")


def test_aur06_fails_on_a_cluster_that_does_not_require_tls():
    """The cluster parameter group, not the instance one -- an Aurora Serverless v1
    cluster has no instances for RDS-14 to read a group from at all."""
    s = _rds_scanner(clusters=[_cluster("prod-aurora", "aurora-postgresql")],
                     params=[_p("rds.force_ssl", "0")])
    _renders(s, "AUR-06", "HIGH", contains="prod-aurora")


def test_aur06_passes_when_the_cluster_requires_tls():
    s = _rds_scanner(clusters=[_cluster("prod-aurora", "aurora-mysql")],
                     params=[_p("require_secure_transport", "ON")])
    assert not _ids(s, "AUR-06", "FAIL")
    assert _ids(s, "AUR-06", "PASS")


def test_an_undecidable_answer_is_a_warning_never_a_pass():
    """THE FAILURE MODE THIS CHECK EXISTS TO END. Silence renders as 'encrypted in
    transit'. A parameter group we could read but that did not contain the parameter is
    UNKNOWN, and the report has to say so."""
    s = _rds_scanner(instances=[_instance("prod-pg", "postgres")],
                     params=[_p("log_statement", "all")])
    assert not _ids(s, "RDS-14", "PASS"), "an undecided verdict was reported as clean"
    assert not _ids(s, "RDS-14", "FAIL"), "an undecided verdict was reported as a failure"
    assert _ids(s, "RDS-14", "WARN")


def test_a_failed_parameter_read_is_a_warning_not_a_finding():
    s = _rds_scanner(instances=[_instance("prod-pg", "postgres")],
                     param_error=RuntimeError("AccessDenied"))
    assert not _ids(s, "RDS-14", "FAIL")
    warns = _ids(s, "RDS-14", "WARN")
    assert warns and "NOT EVALUATED" in warns[0].message


def test_an_instance_with_no_parameter_group_is_a_warning():
    inst = _instance("prod-pg", "postgres")
    inst["DBParameterGroups"] = []
    s = _rds_scanner(instances=[inst])
    assert _ids(s, "RDS-14", "WARN")
    assert not _ids(s, "RDS-14", "FAIL")


def test_an_oracle_instance_warns_rather_than_failing():
    """Oracle has no single deciding parameter. A FAIL here would be a HIGH finding on
    every Oracle instance in every account, forever, and it would be wrong."""
    s = _rds_scanner(instances=[_instance("prod-oracle", "oracle-se2")], params=[])
    assert not _ids(s, "RDS-14", "FAIL")
    assert _ids(s, "RDS-14", "WARN")


# ══════════════════════════════════════════════════════════════════════════════
# The cache — the reason this is affordable on a real fleet
# ══════════════════════════════════════════════════════════════════════════════
def test_a_shared_parameter_group_is_read_once_for_the_whole_fleet():
    """A group is shared by every instance using it, and reading one is several pages of
    a few hundred parameters. Without the cache a 50-instance fleet pays 50x for one
    answer."""
    s = _rds_scanner(
        instances=[_instance(f"db-{i}", "postgres", group="shared-pg")
                   for i in range(5)],
        params=[_p("rds.force_ssl", "0")])
    assert len(_ids(s, "RDS-14", "FAIL")) == 5, "not every instance was evaluated"
    calls = [c for c in s._rds_client_for_test.get_paginator.call_args_list
             if c.args and c.args[0] == "describe_db_parameters"]
    assert len(calls) == 1, (
        f"the shared parameter group was read {len(calls)} times, not once")


def test_distinct_parameter_groups_are_read_separately():
    s = _rds_scanner(
        instances=[_instance("db-a", "postgres", group="pg-a"),
                   _instance("db-b", "postgres", group="pg-b")],
        params=[_p("rds.force_ssl", "0")])
    calls = [c for c in s._rds_client_for_test.get_paginator.call_args_list
             if c.args and c.args[0] == "describe_db_parameters"]
    assert len(calls) == 2


def test_a_failed_group_read_is_not_retried_per_resource():
    """A denied read is denied for every instance sharing that group. Retrying it per
    instance turns one permission gap into a burst of identical throttled calls."""
    s = _rds_scanner(
        instances=[_instance(f"db-{i}", "postgres", group="shared-pg")
                   for i in range(4)],
        param_error=RuntimeError("AccessDenied"))
    assert len(_ids(s, "RDS-14", "WARN")) == 4, "every instance should still be reported"
    calls = [c for c in s._rds_client_for_test.get_paginator.call_args_list
             if c.args and c.args[0] == "describe_db_parameters"]
    assert len(calls) == 1, f"the failed read was attempted {len(calls)} times"


# ══════════════════════════════════════════════════════════════════════════════
# DOCDB-06 and NEP-05
# ══════════════════════════════════════════════════════════════════════════════
def test_docdb06_fails_when_tls_is_disabled():
    """DocumentDB ships with tls=enabled, so this being off is a deliberate change --
    usually a workaround for a client that could not do the CA bundle, never reverted."""
    s = make_scanner(sections=["DOCDB"])
    s.account = OWN
    docdb = MagicMock()
    docdb.describe_db_cluster_snapshots.return_value = {"DBClusterSnapshots": []}
    docdb.describe_db_clusters.return_value = {"DBClusters": [
        {"DBClusterIdentifier": "my-docdb", "Engine": "docdb",
         "DBClusterParameterGroup": "docdb-pg", "StorageEncrypted": True,
         "DeletionProtection": True, "EnabledCloudwatchLogsExports": ["audit"]}]}
    pager = MagicMock()
    pager.paginate.return_value = [{"Parameters": [_p("tls", "disabled")]}]
    docdb.get_paginator.return_value = pager
    s._clients[f"docdb:{REGION}"] = docdb
    s._check_docdb()
    _renders(s, "DOCDB-06", "HIGH", contains="my-docdb")


def test_nep05_fails_when_ssl_is_not_enforced():
    s = make_scanner(sections=["NEPTUNE"])
    s.account = OWN
    nep = MagicMock()

    def _pager(op):
        p = MagicMock()
        if op == "describe_db_clusters":
            p.paginate.return_value = [{"DBClusters": [
                {"DBClusterIdentifier": "my-neptune", "Engine": "neptune",
                 "DBClusterParameterGroup": "nep-pg", "StorageEncrypted": True,
                 "DeletionProtection": True}]}]
        elif op == "describe_db_cluster_parameters":
            p.paginate.return_value = [
                {"Parameters": [_p("neptune_enforce_ssl", "0")]}]
        else:
            p.paginate.return_value = [{}]
        return p

    nep.get_paginator.side_effect = _pager
    s._clients[f"neptune:{REGION}"] = nep
    s._check_neptune()
    _renders(s, "NEP-05", "HIGH", contains="my-neptune")


# ══════════════════════════════════════════════════════════════════════════════
# The gap this closes
# ══════════════════════════════════════════════════════════════════════════════
def test_these_four_are_the_only_tls_in_transit_database_checks():
    """A tripwire, not a tautology. If a fifth database TLS check appears it should join
    this list deliberately -- and if one of these four is deleted, the control silently
    stops being covered for that service."""
    from engine.aws_live_scanner import COMPLIANCE_MAP
    sc8 = {c for c, v in COMPLIANCE_MAP.items()
           if v.get("NIST") == "SC-8" and c.split("-")[0]
           in {"RDS", "AUR", "DOCDB", "NEP"}}
    assert sc8 == {"RDS-14", "AUR-06", "DOCDB-06", "NEP-05"}, sorted(sc8)
