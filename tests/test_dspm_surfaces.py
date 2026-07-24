"""Slice 1 · Batch 1 — pure DSPM datastore-surface read-actions (aws_deepplane).
No boto3: exercises the new DSPM_READ_ACTIONS kinds through role_can_read_store."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_deepplane as D


def _stmt(actions, resources=("*",), effect="Allow", condition=None, not_resources=()):
    return {"actions": set(actions), "resources": set(resources),
            "not_resources": set(not_resources), "effect": effect, "condition": condition}


def test_new_read_action_kinds_present():
    for k in ("opensearchdomain", "kinesisstream", "timestreamtable", "neptunecluster",
              "docdbcluster", "memorydbcluster", "fsxfilesystem"):
        assert k in D.DSPM_READ_ACTIONS


def test_opensearch_precise_match():
    arn = "arn:aws:es:us-east-1:111:domain/prod"
    ra = D.DSPM_READ_ACTIONS["opensearchdomain"]
    assert D.role_can_read_store([_stmt({"es:eshttpget"}, {arn.lower()})], arn, ra) == {"conditioned": False}
    assert D.role_can_read_store([_stmt({"s3:getobject"}, {arn.lower()})], arn, ra) is None


def test_kinesis_and_timestream_precise():
    k_arn = "arn:aws:kinesis:us-east-1:111:stream/events"
    assert D.role_can_read_store([_stmt({"kinesis:getrecords"}, {k_arn.lower()})],
                                 k_arn, D.DSPM_READ_ACTIONS["kinesisstream"]) == {"conditioned": False}
    t_arn = "arn:aws:timestream:us-east-1:111:database/db/table/t"
    assert D.role_can_read_store([_stmt({"timestream:select"}, {t_arn.lower()})],
                                 t_arn, D.DSPM_READ_ACTIONS["timestreamtable"]) == {"conditioned": False}


def test_neptune_coarse_wildcard_only():
    arn = "arn:aws:rds:us-east-1:111:cluster:neptune-1"
    ra = D.DSPM_READ_ACTIONS["neptunecluster"]
    # a service/star-wildcard grant matches the cluster probe (coarse-but-safe)
    assert D.role_can_read_store([_stmt({"neptune-db:connect"}, {"*"})], arn, ra) == {"conditioned": False}
    # a narrow dbuser-ARN grant does NOT match the cluster ARN probe (documented FN)
    dbuser = "arn:aws:neptune-db:us-east-1:111:cluster-id/*/dbuser/alice"
    assert D.role_can_read_store([_stmt({"neptune-db:connect"}, {dbuser})], arn, ra) is None


def test_empty_read_actions_yield_no_edge():
    # Mongo/Redis-ACL/NFS auth is out-of-band: even a full-admin policy grants no CAN_READ_DATA
    for k in ("docdbcluster", "memorydbcluster", "fsxfilesystem"):
        assert D.role_can_read_store([_stmt({"*"}, {"*"})],
                                     "arn:aws:rds:us-east-1:111:cluster:c", D.DSPM_READ_ACTIONS[k]) is None
