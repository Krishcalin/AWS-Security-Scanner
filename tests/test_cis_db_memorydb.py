"""MemoryDB: a durable datastore the product could not see at all.

Before this the `memorydb` client was constructed exactly ONCE in the entire codebase,
for DSPM crown-jewel discovery. An account could hold a MemoryDB cluster with
unauthenticated access, no snapshots and TLS off, and OverWatch reported nothing about
any of it.

MDB-02 IS THE REASON THE SECTION IS WORTH HAVING, and it is an OBSERVATION rather than an
inference in the same sense DOCDB-01 is. MemoryDB authenticates through ACLs of named
users, and botocore's own enum for `Authentication.Type` is
['password', 'no-password', 'iam']. A 'no-password' user can be connected as by anything
that reaches the endpoint. MemoryDB creates one by DEFAULT, so the untouched cluster is
the exposed one -- and matching on the default ACL's NAME instead would have been a
heuristic that a rename defeats.
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

OPEN_USER = {"Name": "open-access", "Authentication": {"Type": "no-password"}}
PW_USER = {"Name": "app", "Authentication": {"Type": "password", "PasswordCount": 1}}
IAM_USER = {"Name": "svc", "Authentication": {"Type": "iam"}}


# ══════════════════════════════════════════════════════════════════════════════
# The pure rules
# ══════════════════════════════════════════════════════════════════════════════
def test_only_no_password_users_count_as_open():
    """'iam' is the STRONGEST option, not a weak one — it means short-lived credentials
    rather than a stored secret. Treating it as open would flag the best configuration
    available."""
    got = aws_cis_db.memorydb_open_users([OPEN_USER, PW_USER, IAM_USER])
    assert got == {"open-access"}


def test_open_user_detection_is_case_and_whitespace_tolerant():
    got = aws_cis_db.memorydb_open_users(
        [{"Name": "u", "Authentication": {"Type": " No-Password "}}])
    assert got == {"u"}


def test_malformed_user_rows_do_not_crash_the_rule():
    got = aws_cis_db.memorydb_open_users(
        [None, "nope", 7, {"Name": "u"}, {"Authentication": {"Type": "no-password"}},
         OPEN_USER])
    assert got == {"open-access"}, (
        "a row with no Name or no Authentication should be skipped, not counted")


def test_an_acl_with_no_open_user_is_absent_rather_than_empty():
    """So a caller cannot confuse 'checked and clean' with 'never checked' — an empty
    tuple in the map would read as falsy at the call site and mean the wrong thing."""
    acls = [{"Name": "locked", "UserNames": ["app", "svc"]},
            {"Name": "open", "UserNames": ["app", "open-access"]}]
    got = aws_cis_db.memorydb_acl_open_users(acls, frozenset({"open-access"}))
    assert set(got) == {"open"}
    assert got["open"] == ("open-access",)


def test_acl_resolution_survives_malformed_rows():
    got = aws_cis_db.memorydb_acl_open_users(
        [None, {"UserNames": ["open-access"]}, {"Name": "", "UserNames": ["open-access"]},
         {"Name": "ok", "UserNames": ["open-access"]}], frozenset({"open-access"}))
    assert set(got) == {"ok"}


# ══════════════════════════════════════════════════════════════════════════════
# The section
# ══════════════════════════════════════════════════════════════════════════════
def _cluster(name="prod-mdb", **over):
    c = {"Name": name, "TLSEnabled": True, "ACLName": "locked",
         "SnapshotRetentionLimit": 7, "KmsKeyId": "arn:aws:kms:...:key/abc",
         "AutoMinorVersionUpgrade": True, "AvailabilityMode": "multiaz",
         "Engine": "redis", "EngineVersion": "7.1"}
    c.update(over)
    return c


def _scanner(clusters=(), users=(PW_USER, OPEN_USER),
             acls=({"Name": "locked", "UserNames": ["app"]},
                   {"Name": "open-access-acl", "UserNames": ["open-access"]}),
             acl_error=None, cluster_error=None):
    s = make_scanner(sections=["MEMORYDB"])
    s.account = OWN
    mdb = MagicMock()

    def _pager(op):
        p = MagicMock()
        if op == "describe_clusters":
            if cluster_error:
                p.paginate.side_effect = cluster_error
            else:
                p.paginate.return_value = [{"Clusters": list(clusters)}]
        elif op == "describe_users":
            if acl_error:
                p.paginate.side_effect = acl_error
            else:
                p.paginate.return_value = [{"Users": list(users)}]
        elif op == "describe_acls":
            if acl_error:
                p.paginate.side_effect = acl_error
            else:
                p.paginate.return_value = [{"ACLs": list(acls)}]
        else:
            p.paginate.return_value = [{}]
        return p

    mdb.get_paginator.side_effect = _pager
    s._clients[f"memorydb:{REGION}"] = mdb
    s._check_memorydb()
    return s


def test_mdb02_fails_on_a_cluster_whose_acl_grants_a_passwordless_user():
    s = _scanner([_cluster(ACLName="open-access-acl")])
    r = _renders(s, "MDB-02", "CRITICAL", contains="open-access")
    assert "UNAUTHENTICATED" in r.message


def test_mdb02_passes_when_the_acl_grants_only_authenticated_users():
    s = _scanner([_cluster(ACLName="locked")])
    assert not _ids(s, "MDB-02", "FAIL")
    assert _ids(s, "MDB-02", "PASS")


def test_mdb02_is_undecided_once_when_the_acl_listing_cannot_be_read():
    """Not a FAIL and not a PASS — and reported ONCE for the section rather than once per
    cluster, because it is one failed read and repeating it per resource turns a single
    permission gap into a wall of identical findings."""
    s = _scanner([_cluster(name=f"c{i}") for i in range(3)],
                 acl_error=RuntimeError("AccessDenied"))
    assert not _ids(s, "MDB-02", "FAIL")
    assert not _ids(s, "MDB-02", "PASS")
    warns = _ids(s, "MDB-02", "WARN")
    assert len(warns) == 1, f"expected one section-level WARN, got {len(warns)}"
    assert "NOT EVALUATED" in warns[0].message


def test_mdb02_warns_on_a_cluster_that_names_no_acl():
    s = _scanner([_cluster(ACLName="")])
    assert _ids(s, "MDB-02", "WARN")
    assert not _ids(s, "MDB-02", "PASS")


def test_mdb01_fails_when_tls_is_off():
    s = _scanner([_cluster(TLSEnabled=False)])
    _renders(s, "MDB-01", "HIGH", contains="prod-mdb")


def test_mdb03_fails_when_snapshots_are_disabled():
    s = _scanner([_cluster(SnapshotRetentionLimit=0)])
    _renders(s, "MDB-03", "MEDIUM", contains="prod-mdb")


def test_mdb04_is_low_because_memorydb_is_always_encrypted():
    """The finding is key OWNERSHIP, not plaintext storage. Rating it HIGH alongside
    genuinely unencrypted datastores is how a risk score stops distinguishing between
    'readable by anyone with the disk' and 'encrypted with a key you do not manage'."""
    s = _scanner([_cluster(KmsKeyId=None)])
    r = _renders(s, "MDB-04", "LOW")
    assert "AWS-owned key" in r.message


def test_mdb04_passes_with_a_customer_managed_key():
    s = _scanner([_cluster()])
    assert not _ids(s, "MDB-04", "FAIL")
    assert _ids(s, "MDB-04", "PASS")


def test_mdb05_fails_when_minor_upgrades_are_manual():
    s = _scanner([_cluster(AutoMinorVersionUpgrade=False)])
    _renders(s, "MDB-05", "MEDIUM", contains="prod-mdb")


def test_mdb06_fails_on_a_single_az_cluster():
    s = _scanner([_cluster(AvailabilityMode="singleaz")])
    _renders(s, "MDB-06", "MEDIUM", contains="prod-mdb")


def test_mdb06_says_nothing_on_an_unrecognised_availability_mode():
    s = _scanner([_cluster(AvailabilityMode="transitioning")])
    assert not _ids(s, "MDB-06")


def test_absent_fields_produce_no_verdict_at_all():
    """Absent is not False. A cluster shape that omits a field -- an older API version,
    a partial response -- must not be reported as insecure."""
    bare = {"Name": "bare"}
    s = _scanner([bare])
    for cid in ("MDB-01", "MDB-03", "MDB-05", "MDB-06"):
        assert not _ids(s, cid), f"{cid} produced a verdict from an absent field"


def test_an_empty_region_says_so_rather_than_staying_silent():
    s = _scanner([])
    info = _ids(s, "MDB-01", "INFO")
    assert info and "No MemoryDB clusters" in info[0].message


def test_a_failed_cluster_read_is_a_warning_not_a_finding():
    s = _scanner(cluster_error=RuntimeError("AccessDenied"))
    assert not _ids(s, "MDB-01", "FAIL")
    warns = _ids(s, "MDB-01", "WARN")
    assert warns and "NOT EVALUATED" in warns[0].message


def test_the_whole_default_estate_is_reported():
    """The realistic shape: a cluster created with defaults and never configured. It is
    passwordless, and that is the point of the section."""
    s = _scanner([_cluster(ACLName="open-access-acl", TLSEnabled=False,
                           SnapshotRetentionLimit=0, KmsKeyId=None,
                           AutoMinorVersionUpgrade=False,
                           AvailabilityMode="singleaz")])
    failed = {r.check_id for r in s.results if r.status == "FAIL"}
    assert failed == {"MDB-01", "MDB-02", "MDB-03", "MDB-04", "MDB-05", "MDB-06"}, (
        f"expected all six, got {sorted(failed)}")


def test_the_section_is_in_the_default_run_list():
    """A section registered in dispatch but absent from SECTIONS never runs on a default
    scan — the exact defect that made four sections dead before."""
    from engine.aws_live_scanner import SECTIONS, SECTION_LABELS
    assert "MEMORYDB" in SECTIONS
    assert "MEMORYDB" in SECTION_LABELS
