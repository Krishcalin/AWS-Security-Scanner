"""Phase 7 Batch 5 — DSPM: tag-driven crown-jewel datastores (RDS/RDSCluster/Redshift/
DynamoDB/EFS) without Macie + non-S3 CAN_READ_DATA. Pure helpers (is_crown_jewel_by_tags,
role_can_read_store) + _collect_dspm. Offline: MagicMock clients (no boto3, no AWS)."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner
from aws_graph import SecurityGraph
import aws_deepplane as D

ACCT = "123456789012"


def _tag(k, v):
    return {"Key": k, "Value": v}


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


# ── is_crown_jewel_by_tags ────────────────────────────────────────────────────
def test_classification_exact_value_crown():
    cj = D.is_crown_jewel_by_tags([_tag("DataClassification", "Confidential")])
    assert cj and cj["crown"] and cj["matched"] == ("DataClassification", "Confidential")


def test_high_availability_not_high():
    # exact-value match: 'high-availability' must NOT trigger on sensitive value 'high'
    assert D.is_crown_jewel_by_tags([_tag("Classification", "high-availability")]) is None


def test_boolean_key_truthy_crown():
    cj = D.is_crown_jewel_by_tags([_tag("PII", "true")])
    assert cj and cj["crown"] and cj["sensitivity"] == "flagged"


def test_boolean_key_false_not_crown():
    assert D.is_crown_jewel_by_tags([_tag("PII", "false")]) is None


def test_environment_prod_not_crown():
    assert D.is_crown_jewel_by_tags([_tag("Environment", "production")]) is None


def test_extra_keys_opt_in():
    assert D.is_crown_jewel_by_tags([_tag("Environment", "prod")],
                                    extra_keys={"environment"}, extra_values={"prod"})


def test_no_tags_none():
    assert D.is_crown_jewel_by_tags([]) is None
    assert D.is_crown_jewel_by_tags(None) is None


# ── role_can_read_store ───────────────────────────────────────────────────────
def _stmt(effect, actions, resources, condition=None, not_resources=None):
    return {"effect": effect, "actions": set(actions), "resources": set(resources),
            "not_resources": set(not_resources or []), "condition": condition}


DDB_ARN = f"arn:aws:dynamodb:us-east-1:{ACCT}:table/orders"
RDS_ARN = f"arn:aws:rds:us-east-1:{ACCT}:db:paydb"


def test_dynamodb_precise_match():
    st = [_stmt("Allow", {"dynamodb:getitem"}, {DDB_ARN.lower()})]
    assert D.role_can_read_store(st, DDB_ARN, D.DSPM_READ_ACTIONS["dynamodbtable"]) == {"conditioned": False}


def test_dynamodb_wrong_table_no_match():
    other = f"arn:aws:dynamodb:us-east-1:{ACCT}:table/other"
    st = [_stmt("Allow", {"dynamodb:getitem"}, {other.lower()})]
    assert D.role_can_read_store(st, DDB_ARN, D.DSPM_READ_ACTIONS["dynamodbtable"]) is None


def test_rds_coarse_dbuser_scope_is_fn():
    # a dbuser-scoped resource does NOT match the instance ARN -> coarse conservative FN
    st = [_stmt("Allow", {"rds-db:connect"}, {f"arn:aws:rds-db:us-east-1:{ACCT}:dbuser:x/app"})]
    assert D.role_can_read_store(st, RDS_ARN, D.DSPM_READ_ACTIONS["rdsinstance"]) is None


def test_rds_wildcard_matches_coarse():
    st = [_stmt("Allow", {"rds-db:connect"}, {"*"})]
    assert D.role_can_read_store(st, RDS_ARN, D.DSPM_READ_ACTIONS["rdsinstance"]) == {"conditioned": False}


def test_deny_precedence():
    st = [_stmt("Allow", {"dynamodb:getitem"}, {"*"}),
          _stmt("Deny", {"dynamodb:getitem"}, {"*"})]
    assert D.role_can_read_store(st, DDB_ARN, D.DSPM_READ_ACTIONS["dynamodbtable"]) is None


def test_not_resource_excludes():
    st = [_stmt("Allow", {"dynamodb:getitem"}, {"*"}, not_resources={DDB_ARN.lower()})]
    assert D.role_can_read_store(st, DDB_ARN, D.DSPM_READ_ACTIONS["dynamodbtable"]) is None


def test_conditioned_grant():
    st = [_stmt("Allow", {"dynamodb:getitem"}, {"*"}, condition={"Bool": {"x": "true"}})]
    assert D.role_can_read_store(st, DDB_ARN, D.DSPM_READ_ACTIONS["dynamodbtable"]) == {"conditioned": True}


def test_wrong_action_no_match():
    st = [_stmt("Allow", {"dynamodb:putitem"}, {"*"})]   # write, not a read action
    assert D.role_can_read_store(st, DDB_ARN, D.DSPM_READ_ACTIONS["dynamodbtable"]) is None


# ── _collect_dspm ─────────────────────────────────────────────────────────────
def _pager(key, items):
    p = MagicMock()
    p.paginate.return_value = [{key: items}]
    return p


def _empty(key):
    c = MagicMock()
    c.get_paginator.return_value = _pager(key, [])
    return c


def _empty_rds():
    c = MagicMock()
    c.get_paginator.side_effect = lambda op: _pager(
        "DBInstances" if "instances" in op else "DBClusters", [])
    return c


def _role(name, statements):
    return {"type": "role", "name": name, "arn": f"arn:aws:iam::{ACCT}:role/{name}",
            "statements": statements}


def _dspm_scanner(roles=None):
    s = make_scanner(sections=["DATA"])
    s.account = ACCT
    g = SecurityGraph()
    s.graph = g
    s._iam_principals = roles or []
    s._clients["rds:us-east-1"] = _empty_rds()
    s._clients["redshift:us-east-1"] = _empty("Clusters")
    s._clients["dynamodb:us-east-1"] = _empty("TableNames")
    s._clients["efs:us-east-1"] = _empty("FileSystems")
    # Slice 1: expanded DSPM surfaces — empty by default so _collect_dspm no-ops them
    s._clients["kinesis:us-east-1"] = _empty("StreamNames")
    s._clients["fsx:us-east-1"] = _empty("FileSystems")
    s._clients["timestream-write:us-east-1"] = _empty("Databases")
    _md = MagicMock()
    _md.describe_clusters.return_value = {"Clusters": []}
    s._clients["memorydb:us-east-1"] = _md
    _os = MagicMock()
    _os.list_domain_names.return_value = {"DomainNames": []}
    s._clients["opensearch:us-east-1"] = _os
    return s, g


def _rds_with(instances):
    c = MagicMock()
    c.get_paginator.side_effect = lambda op: _pager(
        "DBInstances" if "instances" in op else "DBClusters",
        instances if "instances" in op else [])
    return c


def test_dspm_rds_instance_crown_and_public():
    s, g = _dspm_scanner()
    s._clients["rds:us-east-1"] = _rds_with([{
        "DBInstanceArn": RDS_ARN, "DBInstanceIdentifier": "paydb",
        "PubliclyAccessible": True, "StorageEncrypted": False,
        "TagList": [_tag("DataClassification", "PII")]}])
    s._collect_dspm(g)
    node = g.node(RDS_ARN)
    assert node and node["kind"] == "RDSInstance" and node["props"]["crown_jewel"]
    assert "FAIL" in _status(s, "DSPM-01")
    assert "FAIL" in _status(s, "DSPM-02")            # publicly accessible


def test_dspm_merges_onto_eol_node():
    s, g = _dspm_scanner()
    g.add_node(RDS_ARN, "RDSInstance", instance_id="paydb")   # Phase-5 EOL node (same id)
    g.add_node("CVE-EOL", "Vulnerability")
    g.add_edge(RDS_ARN, "CVE-EOL", "HAS_VULN", scan_source="managed-eol")
    s._clients["rds:us-east-1"] = _rds_with([{
        "DBInstanceArn": RDS_ARN, "DBInstanceIdentifier": "paydb",
        "PubliclyAccessible": False, "StorageEncrypted": True,
        "TagList": [_tag("Sensitivity", "restricted")]}])
    s._collect_dspm(g)
    node = g.node(RDS_ARN)
    assert node["props"]["crown_jewel"] and node["kind"] == "RDSInstance"
    # the EOL HAS_VULN edge survives on the SAME node -> a vulnerable crown jewel
    assert any(e["kind"] == "HAS_VULN" for e in g.out_edges(RDS_ARN))


def test_dspm_dynamodb_not_public():
    s, g = _dspm_scanner()
    ddb = MagicMock()
    ddb.get_paginator.return_value = _pager("TableNames", ["orders"])
    ddb.list_tags_of_resource.return_value = {"Tags": [_tag("Sensitivity", "restricted")]}
    s._clients["dynamodb:us-east-1"] = ddb
    s._collect_dspm(g)
    node = g.node(DDB_ARN)
    assert node and node["kind"] == "DynamoDBTable"
    assert "FAIL" in _status(s, "DSPM-01")
    assert "FAIL" not in _status(s, "DSPM-02")        # DynamoDB is never network-public


def test_dspm_redshift_public():
    s, g = _dspm_scanner()
    rs = MagicMock()
    rs.get_paginator.return_value = _pager("Clusters", [{
        "ClusterIdentifier": "analytics", "PubliclyAccessible": True, "Encrypted": True,
        "Tags": [_tag("Compliance", "pci")]}])
    s._clients["redshift:us-east-1"] = rs
    s._collect_dspm(g)
    arn = f"arn:aws:redshift:us-east-1:{ACCT}:cluster:analytics"
    assert g.node(arn)["kind"] == "RedshiftCluster"
    assert "FAIL" in _status(s, "DSPM-02")


def test_dspm_efs_crown_not_public():
    s, g = _dspm_scanner()
    efs = MagicMock()
    fs_arn = f"arn:aws:elasticfilesystem:us-east-1:{ACCT}:file-system/fs-123"
    efs.get_paginator.return_value = _pager("FileSystems", [{
        "FileSystemArn": fs_arn, "FileSystemId": "fs-123", "Name": "shared",
        "Encrypted": True, "Tags": [_tag("phi", "yes")]}])
    s._clients["efs:us-east-1"] = efs
    s._collect_dspm(g)
    assert g.node(fs_arn)["kind"] == "EFSFileSystem"
    assert "FAIL" in _status(s, "DSPM-01")
    assert "FAIL" not in _status(s, "DSPM-02")        # EFS public parse deferred (fail-closed)


def test_dspm_can_read_data_edge():
    role = _role("reader", [_stmt("Allow", {"dynamodb:getitem"}, {"*"})])
    s, g = _dspm_scanner([role])
    ddb = MagicMock()
    ddb.get_paginator.return_value = _pager("TableNames", ["orders"])
    ddb.list_tags_of_resource.return_value = {"Tags": [_tag("Sensitivity", "restricted")]}
    s._clients["dynamodb:us-east-1"] = ddb
    s._collect_dspm(g)
    assert any(e["dst"] == DDB_ARN and e["kind"] == "CAN_READ_DATA"
               for e in g.out_edges(role["arn"]))
    assert "FAIL" in _status(s, "EXTACCESS-03")


def test_dspm_untagged_store_ignored():
    s, g = _dspm_scanner()
    s._clients["rds:us-east-1"] = _rds_with([{
        "DBInstanceArn": RDS_ARN, "DBInstanceIdentifier": "paydb",
        "PubliclyAccessible": True, "StorageEncrypted": True,
        "TagList": [_tag("Environment", "prod")]}])          # not a crown tag
    s._collect_dspm(g)
    assert g.node(RDS_ARN) is None
    assert not _status(s, "DSPM-01")                  # no crown -> no finding at all


def test_dspm_denied_describe_is_info_not_phantom():
    s, g = _dspm_scanner()
    rds = MagicMock()
    rds.get_paginator.side_effect = RuntimeError("AccessDenied")
    s._clients["rds:us-east-1"] = rds
    s._collect_dspm(g)
    assert "INFO" in _status(s, "DSPM-01")            # never a phantom all-clear


# ── Slice 1: expanded DSPM datastore surfaces ────────────────────────────────
def _rds_clusters(clusters):
    c = MagicMock()
    c.get_paginator.side_effect = lambda op: _pager(
        "DBInstances" if "instances" in op else "DBClusters",
        [] if "instances" in op else clusters)
    return c


def test_dspm_docdb_engine_branch_distinct_kind():
    s, g = _dspm_scanner()
    arn = f"arn:aws:rds:us-east-1:{ACCT}:cluster:docdb-1"
    s._clients["rds:us-east-1"] = _rds_clusters([{
        "DBClusterArn": arn, "DBClusterIdentifier": "docdb-1", "Engine": "docdb",
        "StorageEncrypted": True, "TagList": [_tag("DataClassification", "PHI")]}])
    s._collect_dspm(g)
    assert g.node(arn)["kind"] == "DocDBCluster"       # NOT RDSCluster
    assert g.node(arn)["props"]["crown_jewel"]


def test_dspm_neptune_engine_branch_distinct_kind():
    s, g = _dspm_scanner()
    arn = f"arn:aws:rds:us-east-1:{ACCT}:cluster:neptune-1"
    s._clients["rds:us-east-1"] = _rds_clusters([{
        "DBClusterArn": arn, "DBClusterIdentifier": "neptune-1", "Engine": "neptune",
        "StorageEncrypted": True, "TagList": [_tag("Sensitivity", "restricted")]}])
    s._collect_dspm(g)
    assert g.node(arn)["kind"] == "NeptuneCluster"


def test_dspm_ordinary_aurora_cluster_stays_rdscluster():
    s, g = _dspm_scanner()
    arn = f"arn:aws:rds:us-east-1:{ACCT}:cluster:aurora-1"
    s._clients["rds:us-east-1"] = _rds_clusters([{
        "DBClusterArn": arn, "DBClusterIdentifier": "aurora-1", "Engine": "aurora-postgresql",
        "StorageEncrypted": True, "TagList": [_tag("PII", "true")]}])
    s._collect_dspm(g)
    assert g.node(arn)["kind"] == "RDSCluster"


def test_dspm_kinesis_crown_with_reader_edge():
    s, g = _dspm_scanner([_role("reader", [_stmt(
        "Allow", {"kinesis:getrecords"},
        {f"arn:aws:kinesis:us-east-1:{ACCT}:stream/events".lower()})])])
    kin = MagicMock()
    kin.get_paginator.return_value = _pager("StreamNames", ["events"])
    kin.list_tags_for_stream.return_value = {"Tags": [_tag("DataClassification", "PCI")]}
    kin.describe_stream_summary.return_value = {"StreamDescriptionSummary": {
        "StreamARN": f"arn:aws:kinesis:us-east-1:{ACCT}:stream/events", "EncryptionType": "KMS"}}
    s._clients["kinesis:us-east-1"] = kin
    s._collect_dspm(g)
    arn = f"arn:aws:kinesis:us-east-1:{ACCT}:stream/events"
    assert g.node(arn)["kind"] == "KinesisStream" and g.node(arn)["props"]["crown_jewel"]
    assert any(e["kind"] == "CAN_READ_DATA" and e["dst"] == arn for e in g.out_edges(f"arn:aws:iam::{ACCT}:role/reader"))


def test_dspm_memorydb_crown_no_reader_edge_even_for_admin():
    admin = _role("admin", [_stmt("Allow", {"*"}, {"*"})])
    s, g = _dspm_scanner([admin])
    arn = f"arn:aws:memorydb:us-east-1:{ACCT}:cluster/cache1"
    md = MagicMock()
    md.describe_clusters.return_value = {"Clusters": [{"ARN": arn, "Name": "cache1", "KmsKeyId": "k"}]}
    md.list_tags.return_value = {"TagList": [_tag("crownjewel", "yes")]}
    s._clients["memorydb:us-east-1"] = md
    s._collect_dspm(g)
    assert g.node(arn)["kind"] == "MemoryDBCluster" and g.node(arn)["props"]["crown_jewel"]
    # empty read-action set => NO CAN_READ_DATA edge, even for a full-admin role
    assert not any(e["kind"] == "CAN_READ_DATA" for e in g.out_edges(f"arn:aws:iam::{ACCT}:role/admin"))


def test_dspm_fsx_crown_node():
    s, g = _dspm_scanner()
    arn = f"arn:aws:fsx:us-east-1:{ACCT}:file-system/fs-1"
    fsx = MagicMock()
    fsx.get_paginator.return_value = _pager("FileSystems", [{
        "FileSystemId": "fs-1", "ResourceARN": arn, "KmsKeyId": "k",
        "Tags": [_tag("Compliance", "HIPAA")]}])
    s._clients["fsx:us-east-1"] = fsx
    s._collect_dspm(g)
    assert g.node(arn)["kind"] == "FSxFileSystem" and g.node(arn)["props"]["crown_jewel"]


def test_dspm_timestream_crown_with_reader():
    tbl = f"arn:aws:timestream:us-east-1:{ACCT}:database/db/table/metrics"
    s, g = _dspm_scanner([_role("ts-reader", [_stmt("Allow", {"timestream:select"}, {tbl.lower()})])])
    ts = MagicMock()

    def get_pag(op):
        p = MagicMock()
        if "databases" in op:
            p.paginate.return_value = [{"Databases": [{"DatabaseName": "db"}]}]
        else:
            p.paginate.return_value = [{"Tables": [{"TableName": "metrics", "Arn": tbl}]}]
        return p
    ts.get_paginator.side_effect = get_pag
    ts.list_tags_for_resource.return_value = {"Tags": [_tag("DataClassification", "confidential")]}
    s._clients["timestream-write:us-east-1"] = ts
    s._collect_dspm(g)
    assert g.node(tbl)["kind"] == "TimestreamTable"
    assert any(e["kind"] == "CAN_READ_DATA" for e in g.out_edges(f"arn:aws:iam::{ACCT}:role/ts-reader"))


def test_dspm_kinesis_denied_is_info_not_phantom():
    s, g = _dspm_scanner()
    kin = MagicMock()
    kin.get_paginator.side_effect = RuntimeError("AccessDenied: kinesis:ListStreams")
    s._clients["kinesis:us-east-1"] = kin
    s._collect_dspm(g)
    assert "INFO" in _status(s, "DSPM-01")


# ── Slice 1 · Batch 3: OpenSearch + DSPM-03 (public resource policy) ─────────
def _opensearch(name, status):
    c = MagicMock()
    c.list_domain_names.return_value = {"DomainNames": [{"DomainName": name}]}
    c.describe_domain.return_value = {"DomainStatus": status}
    c.list_tags.return_value = {"TagList": status.pop("_tags", [])}
    return c


OS_ARN = f"arn:aws:es:us-east-1:{ACCT}:domain/prod-search"


def test_dspm_opensearch_public_crown():
    s, g = _dspm_scanner()
    s._clients["opensearch:us-east-1"] = _opensearch("prod-search", {
        "ARN": OS_ARN, "Endpoint": "search-prod.es.amazonaws.com",
        "EncryptionAtRestOptions": {"Enabled": True},
        "_tags": [_tag("DataClassification", "PII")]})
    s._collect_dspm(g)
    assert g.node(OS_ARN)["kind"] == "OpenSearchDomain" and g.node(OS_ARN)["props"]["crown_jewel"]
    assert "FAIL" in _status(s, "DSPM-02")             # public endpoint, no VPCOptions


def test_dspm_opensearch_vpc_not_public():
    s, g = _dspm_scanner()
    s._clients["opensearch:us-east-1"] = _opensearch("prod-search", {
        "ARN": OS_ARN, "Endpoint": "vpc-prod.es.amazonaws.com",
        "VPCOptions": {"VPCId": "vpc-1"},
        "_tags": [_tag("Sensitivity", "restricted")]})
    s._collect_dspm(g)
    assert g.node(OS_ARN)["props"]["crown_jewel"]
    assert "FAIL" not in _status(s, "DSPM-02")         # VPC-scoped => not public


def test_dspm03_public_access_policy_fail():
    s, g = _dspm_scanner()
    pol = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"es:ESHttpGet","Resource":"*"}]}'
    s._clients["opensearch:us-east-1"] = _opensearch("prod-search", {
        "ARN": OS_ARN, "VPCOptions": {"VPCId": "vpc-1"}, "AccessPolicies": pol,
        "_tags": [_tag("PII", "true")]})
    s._collect_dspm(g)
    assert "FAIL" in _status(s, "DSPM-03")


def test_dspm03_fgac_downgrades_to_warn():
    s, g = _dspm_scanner()
    pol = '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"es:*","Resource":"*"}]}'
    s._clients["opensearch:us-east-1"] = _opensearch("prod-search", {
        "ARN": OS_ARN, "VPCOptions": {"VPCId": "vpc-1"}, "AccessPolicies": pol,
        "AdvancedSecurityOptions": {"Enabled": True},
        "_tags": [_tag("PII", "true")]})
    s._collect_dspm(g)
    assert "WARN" in _status(s, "DSPM-03") and "FAIL" not in _status(s, "DSPM-03")


def test_dspm03_own_account_policy_no_finding():
    s, g = _dspm_scanner()
    pol = ('{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},'
           '"Action":"es:ESHttpGet","Resource":"*"}]}') % ACCT
    s._clients["opensearch:us-east-1"] = _opensearch("prod-search", {
        "ARN": OS_ARN, "VPCOptions": {"VPCId": "vpc-1"}, "AccessPolicies": pol,
        "_tags": [_tag("PII", "true")]})
    s._collect_dspm(g)
    assert not _status(s, "DSPM-03")                   # own-account principal => not exposed


def test_opensearchdomain_in_crown_kinds():
    import aws_correlate
    assert "OpenSearchDomain" in aws_correlate.CROWN_DATASTORE_KINDS


# ── Slice 1 adversarial-verify regressions ───────────────────────────────────
def test_dspm_memorydb_bounded_no_hang_and_info():
    # empty-page-carrying-a-token must NOT hang and MUST emit a truncation INFO (no phantom PASS)
    s, g = _dspm_scanner()
    md = MagicMock()
    md.describe_clusters.return_value = {"Clusters": [], "NextToken": "STUCK"}   # always a token
    s._clients["memorydb:us-east-1"] = md
    s._collect_dspm(g)                                   # terminates (bounded 50 pages)
    assert md.describe_clusters.call_count <= 51
    assert "INFO" in _status(s, "DSPM-01")


def test_dspm_opensearch_reader_edge_via_path_grant():
    dom = f"arn:aws:es:us-east-1:{ACCT}:domain/prod-search"
    reader = _role("es-reader", [_stmt("Allow", {"es:eshttpget"}, {f"{dom}/*".lower()})])
    s, g = _dspm_scanner([reader])
    s._clients["opensearch:us-east-1"] = _opensearch("prod-search", {
        "ARN": dom, "VPCOptions": {"VPCId": "vpc-1"}, "_tags": [_tag("PII", "true")]})
    s._collect_dspm(g)
    # es:ESHttpGet on domain/prod-search/* now correctly yields a reader edge (was an FN)
    assert any(e["kind"] == "CAN_READ_DATA" and e["dst"] == dom
               for e in g.out_edges(f"arn:aws:iam::{ACCT}:role/es-reader"))


def test_dspm_docdb_member_instance_skipped():
    s, g = _dspm_scanner([_role("r", [_stmt("Allow", {"rds-db:connect"}, {"*"})])])
    inst = f"arn:aws:rds:us-east-1:{ACCT}:db:docdb-inst"
    c = MagicMock()
    c.get_paginator.side_effect = lambda op: _pager(
        "DBInstances" if "instances" in op else "DBClusters",
        [{"DBInstanceArn": inst, "DBInstanceIdentifier": "docdb-inst", "Engine": "docdb",
          "StorageEncrypted": True, "TagList": [_tag("PII", "true")]}] if "instances" in op else [])
    s._clients["rds:us-east-1"] = c
    s._collect_dspm(g)
    # a DocDB MEMBER instance from describe_db_instances is not mis-kinded RDSInstance
    assert g.node(inst) is None
    assert not any(e["kind"] == "CAN_READ_DATA" for e in g.out_edges(f"arn:aws:iam::{ACCT}:role/r"))
