"""Driving tests for the 9 CIS AWS Database Services tranche-2 checks.

Tranche 1 recorded thirteen recommendations as decidable-but-unbuilt. Nine are built here
and each is driven to an actual FAIL through `AWSLiveScanner`, not through its evaluator —
`docs/CHECK_FIRING.md` exists because this codebase has repeatedly shipped checks that were
registered in all five projections, counted in the published total, and could not fire.

THE OTHER FOUR ARE THE MORE INTERESTING RESULT and are tested too, in
`tests/test_cis_db_mapping.py`: working through them against the source document and the
shipped botocore models proved they are not buildable at all. 5.8 and 5.9 are misfiled
under ElastiCache and audit Amazon Keyspaces, which this product declines to read; 6.4 is
configurable only in the console and absent from the SDK; 10.8's audit is "Define
Monitoring Objectives". A gap that quietly becomes a decline is indistinguishable from one
somebody gave up on, so each names its reason in the mapping.

THE NEGATIVE CASES ARE NOT DECORATION. A check that fires unconditionally is worse than no
check, because it trains people to filter the id out. Every control here has at least one
case proving the compliant configuration is silent — and for the two fine-grained-access
checks that case is the one that matters most, because the naive version of those fires on
almost every application role in an estate.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_cis_db2 as D                                  # noqa: E402
from engine import aws_cis_db_map as M                               # noqa: E402
from test_live_scanner import MockClientError, make_scanner          # noqa: E402

OWN = "123456789012"
DENIED = MockClientError("AccessDeniedException", "not authorized")


# ── shared helpers ───────────────────────────────────────────────────────────────
def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _renders(s, cid, contains=None):
    """The finding fired AND carries what the catalogue holds for it."""
    from engine.aws_live_scanner import CHECK_SEVERITY
    hits = _ids(s, cid, "FAIL")
    assert hits, f"{cid} did not FAIL"
    r = hits[0]
    assert r.severity == CHECK_SEVERITY[cid], (
        f"{cid} rendered {r.severity!r}, catalogue says {CHECK_SEVERITY[cid]!r}")
    assert r.remediation_cmd, f"{cid} FAIL carries no remediation command"
    assert r.compliance.get("CIS-DB"), f"{cid} FAIL carries no CIS-DB citation"
    assert r.compliance["CIS-DB"] == M.recommendation_for(cid), (
        f"{cid} cites {r.compliance['CIS-DB']}, the mapping says "
        f"{M.recommendation_for(cid)}")
    if contains:
        assert contains in r.message, f"{cid} message lacks {contains!r}: {r.message}"
    return r


class _Pager:
    def __init__(self, key, items):
        self._key, self._items = key, items

    def paginate(self, **kw):
        return [{self._key: self._items}]


def _pagers(**by_method):
    def _get(method):
        spec = by_method.get(method)
        if spec is None:
            return _Pager("Unused", [])
        if isinstance(spec, Exception):
            raise spec
        return _Pager(*spec)
    return _get


def _stmt(actions, resources, condition=None, effect="Allow"):
    return {"effect": effect,
            "actions": {a.lower() for a in actions},
            "resources": set(resources),
            "not_actions": set(), "not_resources": set(),
            "condition": condition}


def _principal(name, statements, ptype="role"):
    return {"type": ptype, "name": name, "arn": f"arn:aws:iam::{OWN}:{ptype}/{name}",
            "statements": statements, "allow": set(), "deny": set()}


# ═════════════════════════════════════════════════════════════════════════════════
# 4.2 / 10.5 — fine-grained access control
# ═════════════════════════════════════════════════════════════════════════════════
def test_ddb06_fires_on_item_access_to_every_table():
    r = D.dynamodb_fine_grained_access(
        _principal("app", [_stmt(["dynamodb:GetItem", "dynamodb:PutItem"], ["*"])]))
    assert r["failed"] and "EVERY table" in r["statement"]


def test_ddb06_is_silent_on_a_role_scoped_to_one_table():
    """THE CASE THAT DEFINES THIS CHECK. A role holding GetItem on the table it owns is
    the normal, correct shape for a service. The naive version of 4.2 fires on it, which
    would put a finding on nearly every application role in an estate and train people to
    filter DDB-06 out — at which point the real finding is invisible too."""
    r = D.dynamodb_fine_grained_access(_principal("app", [_stmt(
        ["dynamodb:GetItem"], [f"arn:aws:dynamodb:eu-west-1:{OWN}:table/orders"])]))
    assert not r["failed"]


def test_ddb06_is_silent_when_a_leading_keys_condition_narrows_the_grant():
    """The compliant form the recommendation actually asks for."""
    cond = {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["${aws:userid}"]}}
    r = D.dynamodb_fine_grained_access(
        _principal("app", [_stmt(["dynamodb:Query"], ["*"], cond)]))
    assert not r["failed"]


def test_ddb06_reads_condition_keys_case_insensitively():
    """IAM matches condition keys case-insensitively, so a policy written
    `dynamodb:leadingkeys` is valid and equivalent. A case-sensitive check would fail a
    compliant policy for its spelling."""
    cond = {"ForAllValues:StringEquals": {"DynamoDB:LeadingKeys": ["x"]}}
    assert not D.dynamodb_fine_grained_access(
        _principal("app", [_stmt(["dynamodb:Query"], ["*"], cond)]))["failed"]


def test_ddb06_ignores_a_deny_statement():
    """A Deny on every table is a guardrail, not a grant. Reporting it would invert the
    finding."""
    r = D.dynamodb_fine_grained_access(_principal("app", [
        _stmt(["dynamodb:GetItem"], ["*"], effect="Deny")]))
    assert not r["failed"]


def test_ddb06_ignores_metadata_only_grants():
    """dynamodb:DescribeTable is metadata. Fine-grained access control is about items,
    and firing on a describe grant would be answering a different question."""
    r = D.dynamodb_fine_grained_access(
        _principal("app", [_stmt(["dynamodb:DescribeTable", "dynamodb:ListTables"],
                                 ["*"])]))
    assert not r["failed"]


def test_ts03_is_the_same_rule_for_timestream():
    assert D.timestream_fine_grained_access(
        _principal("q", [_stmt(["timestream:Select"], ["*"])]))["failed"]
    assert not D.timestream_fine_grained_access(
        _principal("q", [_stmt(["timestream:Select"],
                               [f"arn:aws:timestream:eu-west-1:{OWN}:database/m"])]
                   ))["failed"]


def test_ddb06_and_ts03_fire_through_the_scanner():
    s = make_scanner(sections=["DYNAMODB"])
    s.account = OWN
    s._iam_principals = [_principal("app", [_stmt(
        ["dynamodb:GetItem", "timestream:Select"], ["*"])])]
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _pagers(
        describe_vpc_endpoints=("VpcEndpoints", []),
        describe_route_tables=("RouteTables", []),
        describe_vpcs=("Vpcs", []))
    s._clients["ec2:us-east-1"] = ec2
    s._check_dynamodb_access_and_endpoints(True)
    _renders(s, "DDB-06", contains="EVERY table")

    s2 = make_scanner(sections=["TIMESTREAM"])
    s2.account = OWN
    s2._iam_principals = [_principal("q", [_stmt(["timestream:Select"], ["*"])])]
    s2._check_timestream_cis_db2([])
    _renders(s2, "TS-03", contains="every database and table")


def test_an_unreadable_principal_set_is_a_coverage_statement_not_a_pass():
    s = make_scanner(sections=["DYNAMODB"])
    s.account = OWN
    s._iam_principals = []
    s._fgac_principals("DDB-06", D.dynamodb_fine_grained_access, "DYNAMODB")
    infos = _ids(s, "DDB-06", "INFO")
    assert infos and "NOT EVALUATED" in infos[0].message
    assert not _ids(s, "DDB-06", "PASS")


# ═════════════════════════════════════════════════════════════════════════════════
# 4.5 — DynamoDB VPC endpoints
# ═════════════════════════════════════════════════════════════════════════════════
def test_ddb07_needs_tables_an_internet_path_and_no_endpoint():
    assert D.dynamodb_vpc_endpoint("vpc-1", True, True, [])["failed"]
    # no tables in the account -> no DynamoDB traffic to keep private
    assert not D.dynamodb_vpc_endpoint("vpc-1", False, True, [])["failed"]
    # isolated VPC -> nothing is crossing the public network whatever the list says
    assert not D.dynamodb_vpc_endpoint("vpc-1", True, False, [])["failed"]
    # the endpoint already exists
    assert not D.dynamodb_vpc_endpoint(
        "vpc-1", True, True, ["com.amazonaws.eu-west-1.dynamodb"])["failed"]


def test_ddb07_does_not_accept_a_different_services_endpoint():
    """An S3 gateway endpoint is not a DynamoDB one. Matching on 'an endpoint exists'
    would pass a VPC whose DynamoDB traffic still leaves through the NAT."""
    assert D.dynamodb_vpc_endpoint(
        "vpc-1", True, True, ["com.amazonaws.eu-west-1.s3"])["failed"]


def test_ddb07_fires_through_the_scanner():
    s = make_scanner(sections=["DYNAMODB"])
    s.account = OWN
    s._iam_principals = []
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _pagers(
        describe_vpc_endpoints=("VpcEndpoints", []),
        describe_route_tables=("RouteTables", [
            {"RouteTableId": "rtb-1", "VpcId": "vpc-1",
             "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}]}]),
        describe_vpcs=("Vpcs", [{"VpcId": "vpc-1"}]))
    s._clients["ec2:us-east-1"] = ec2
    s._check_dynamodb_access_and_endpoints(True)
    _renders(s, "DDB-07", contains="no DynamoDB gateway endpoint")


# ═════════════════════════════════════════════════════════════════════════════════
# 5.6 — ElastiCache log delivery
# ═════════════════════════════════════════════════════════════════════════════════
def test_elc09_fails_with_no_active_log_delivery():
    assert D.elasticache_log_delivery(
        {"ReplicationGroupId": "rg", "LogDeliveryConfigurations": []})["failed"]
    assert D.elasticache_log_delivery(
        {"ReplicationGroupId": "rg",
         "LogDeliveryConfigurations": [{"Status": "disabling"}]})["failed"]
    assert not D.elasticache_log_delivery(
        {"ReplicationGroupId": "rg",
         "LogDeliveryConfigurations": [{"Status": "active"}]})["failed"]


def test_elc09_treats_an_absent_key_as_unknown_not_as_absent():
    """A response that did not carry the field is not the same claim as a response that
    carried an empty one. Reporting the first as a failure would fail every group on an
    older API version."""
    r = D.elasticache_log_delivery({"ReplicationGroupId": "rg"})
    assert r["unknown"] and not r.get("failed")


def test_elc09_fires_through_the_scanner():
    s = make_scanner(sections=["ELASTICACHE"])
    s.account = OWN
    ec = MagicMock()
    ec.describe_replication_groups.return_value = {"ReplicationGroups": [
        {"ReplicationGroupId": "rg-1", "AtRestEncryptionEnabled": True,
         "TransitEncryptionEnabled": True, "AuthTokenEnabled": True,
         "LogDeliveryConfigurations": []}]}
    ec.describe_cache_clusters.return_value = {"CacheClusters": []}
    s._clients["elasticache:us-east-1"] = ec
    s._check_elasticache()
    _renders(s, "ELC-09", contains="delivers no logs")


# ═════════════════════════════════════════════════════════════════════════════════
# 6.6 — MemoryDB notifications
# ═════════════════════════════════════════════════════════════════════════════════
def test_mdb07_reads_the_lowercase_sns_member():
    """THE ERROR THE MODEL CHECK CAUGHT. MemoryDB's member is `SnsTopicArn`, not
    `SNSTopicArn`. A check written to the obvious spelling reads None on every cluster and
    fails all of them — always right, for entirely the wrong reason."""
    ok = {"Name": "c", "SnsTopicArn": "arn:aws:sns:eu-west-1:1:t",
          "SnsTopicStatus": "active"}
    assert not D.memorydb_notifications(ok)["failed"]
    # the misspelling a naive implementation would have used must NOT satisfy it
    assert D.memorydb_notifications(
        {"Name": "c", "SNSTopicArn": "arn:aws:sns:eu-west-1:1:t"})["failed"]


def test_mdb07_separates_no_topic_from_an_inactive_topic():
    none = D.memorydb_notifications({"Name": "c"})
    inactive = D.memorydb_notifications(
        {"Name": "c", "SnsTopicArn": "arn:aws:sns:eu-west-1:1:t",
         "SnsTopicStatus": "deleting"})
    assert none["failed"] and "no SNS notification topic" in none["statement"]
    assert inactive["failed"] and "not being delivered" in inactive["statement"]


def test_mdb07_fires_through_the_scanner():
    s = make_scanner(sections=["MEMORYDB"])
    s.account = OWN
    mdb = MagicMock()
    mdb.get_paginator.side_effect = _pagers(
        describe_users=("Users", []), describe_acls=("ACLs", []),
        describe_clusters=("Clusters", [
            {"Name": "mdb-1", "TLSEnabled": True, "ACLName": "open-access"}]))
    s._clients["memorydb:us-east-1"] = mdb
    s._check_memorydb()
    _renders(s, "MDB-07", contains="no SNS notification topic")


# ═════════════════════════════════════════════════════════════════════════════════
# 7.7 / 7.8 / 9.7 — DocumentDB and Neptune
# ═════════════════════════════════════════════════════════════════════════════════
def test_docdb09_fails_on_queued_maintenance():
    actions = [{"ResourceIdentifier": "arn:aws:rds:eu-west-1:1:cluster:c1",
                "PendingMaintenanceActionDetails": [{"Action": "system-update"}]}]
    r = D.docdb_pending_maintenance("c1", actions)
    assert r["failed"] and "system-update" in r["statement"]
    assert not D.docdb_pending_maintenance("c1", [])["failed"]
    assert D.docdb_pending_maintenance("c1", None)["unknown"]


def test_event_subscription_accepts_an_estate_wide_subscription():
    """A subscription with no SourceIdsList covers every source of its type, and that is
    the common and correct configuration for an estate-wide alerting topic. Requiring the
    cluster to be named would fail the better setup."""
    wide = [{"Enabled": True, "SourceType": "db-cluster", "SourceIdsList": []}]
    named = [{"Enabled": True, "SourceType": "db-cluster", "SourceIdsList": ["c1"]}]
    other = [{"Enabled": True, "SourceType": "db-cluster", "SourceIdsList": ["c9"]}]
    off = [{"Enabled": False, "SourceType": "db-cluster", "SourceIdsList": []}]
    assert not D.cluster_event_subscription("c1", "DocumentDB", wide)["failed"]
    assert not D.cluster_event_subscription("c1", "DocumentDB", named)["failed"]
    assert D.cluster_event_subscription("c1", "DocumentDB", other)["failed"]
    assert D.cluster_event_subscription("c1", "DocumentDB", off)["failed"]
    assert D.cluster_event_subscription("c1", "DocumentDB", None)["unknown"]


def test_docdb09_docdb10_and_nep11_fire_through_the_scanner():
    s = make_scanner(sections=["DOCDB"])
    s.account = OWN
    docdb = MagicMock()
    docdb.get_paginator.side_effect = _pagers(
        describe_pending_maintenance_actions=("PendingMaintenanceActions", [
            {"ResourceIdentifier": "arn:aws:rds:eu-west-1:1:cluster:c1",
             "PendingMaintenanceActionDetails": [{"Action": "db-upgrade"}]}]),
        describe_event_subscriptions=("EventSubscriptionsList", []))
    s._clients["docdb:us-east-1"] = docdb
    s._check_docdb_maintenance(docdb, ["c1"])
    s._cluster_event_subs(docdb, "DOCDB-10", "DOCDB", "DocumentDB", ["c1"])
    _renders(s, "DOCDB-09", contains="pending maintenance")
    _renders(s, "DOCDB-10", contains="no enabled event subscription")

    s2 = make_scanner(sections=["NEPTUNE"])
    s2.account = OWN
    nep = MagicMock()
    nep.get_paginator.side_effect = _pagers(
        describe_event_subscriptions=("EventSubscriptionsList", []))
    s2._clients["neptune:us-east-1"] = nep
    s2._cluster_event_subs(nep, "NEP-11", "NEPTUNE", "Neptune", ["g1"])
    _renders(s2, "NEP-11", contains="no enabled event subscription")


def test_the_event_subscription_checks_stay_distinct_from_the_audit_log_ones():
    """DOCDB-03 and NEP-09 ask whether the cluster RECORDS what happened inside it. These
    ask whether anybody is TOLD when something happens to it. A cluster can log perfectly
    and notify nobody, so folding them together would report one problem and fix neither."""
    assert M.recommendation_for("DOCDB-03") == "7.6"
    assert M.recommendation_for("DOCDB-10") == "7.8"
    assert M.recommendation_for("NEP-09") == "9.5"
    assert M.recommendation_for("NEP-11") == "9.7"


# ═════════════════════════════════════════════════════════════════════════════════
# 10.10 — Timestream backup coverage
# ═════════════════════════════════════════════════════════════════════════════════
def test_ts04_fails_for_a_table_no_backup_plan_selects():
    arn = f"arn:aws:timestream:eu-west-1:{OWN}:database/m/table/t"
    assert D.timestream_backup_coverage(arn, [])["failed"]
    assert not D.timestream_backup_coverage(arn, [arn])["failed"]
    assert not D.timestream_backup_coverage(arn, [arn.upper()])["failed"]
    assert D.timestream_backup_coverage(arn, None)["unknown"]


def test_ts04_fires_through_the_scanner():
    s = make_scanner(sections=["TIMESTREAM"])
    s.account = OWN
    s._iam_principals = []
    backup = MagicMock()
    backup.get_paginator.side_effect = _pagers(
        list_protected_resources=("Results", []))
    s._clients["backup:us-east-1"] = backup
    arn = f"arn:aws:timestream:eu-west-1:{OWN}:database/m/table/t"
    s._check_timestream_cis_db2([arn])
    _renders(s, "TS-04", contains="no AWS Backup plan")


# ═════════════════════════════════════════════════════════════════════════════════
# the batch as a whole
# ═════════════════════════════════════════════════════════════════════════════════
def test_every_new_check_is_declared_once_and_homed_where_the_mapping_says():
    ids = sorted(c.id for c in D.CHECKS)
    assert len(ids) == 9 and len(set(ids)) == 9, ids
    for c in D.CHECKS:
        rec = c.compliance.get("CIS-DB")
        assert rec in M.RECOMMENDATIONS, f"{c.id} cites {rec!r}, not in the benchmark"
        assert M.recommendation_for(c.id) == rec, (
            f"{c.id} is keyed to {rec} but the mapping homes it at "
            f"{M.recommendation_for(c.id)}")


def test_documentdb_and_neptune_are_granted_under_the_rds_namespace():
    """A REAL DEFECT THE LEDGER GUARD CAUGHT, pinned so it cannot come back.

    The boto3 CLIENT for these services is named `docdb` / `neptune`; the IAM ACTION that
    authorises it is `rds:`, because both share the RDS control plane and its namespace.
    The first version of this tranche declared `docdb:DescribePendingMaintenanceActions`
    and `neptune:DescribeEventSubscriptions` — actions that do not exist, which an
    operator would have pasted into a policy that then granted nothing at all.
    """
    from engine import aws_perm_ledger as L
    for cid in ("DOCDB-09", "DOCDB-10", "NEP-11"):
        actions = [r.action for r in L.requirements_for(cid)]
        assert actions, f"{cid} declares no permission at all"
        for a in actions:
            assert a.startswith("rds:"), (
                f"{cid} asks for {a!r}; DocumentDB and Neptune are authorised under the "
                f"rds: namespace, and their own prefixes are not real IAM services")


def test_the_gap_list_is_now_empty():
    """Thirteen recorded gaps: nine became checks, four became declines with reasons."""
    gaps = sorted(r for r, v in M.RECOMMENDATIONS.items() if v[1] == M.NO_CHECK)
    assert not gaps, f"still recorded as gaps: {gaps}"
