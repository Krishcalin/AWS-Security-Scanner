"""Timestream — and two declines held to evidence rather than to opinion.

Timestream held DSPM crown-jewel discovery only, so it had no posture coverage. TS-01 and
TS-02 are about one overlooked surface: with magnetic-store writes enabled, records that
fail validation are written by the SERVICE to an S3 bucket. TS-02 asks whether that bucket
exists at all (without it the rejects are dropped silently) and TS-01 asks how the
customer data landing in it is encrypted.

`list_databases` and `list_tables` declare NO paginators. That is not incidental: calling
`get_paginator` on them raises before a request is made, which is precisely the bug that
made `_dspm_timestream` report "could not enumerate" on every scan for its entire
existence. There is a test below asserting get_paginator is never called.

TWO SECTIONS OF THE BENCHMARK ARE DECLINED HERE, and neither decline rests on a judgement
that could quietly go stale:

  * KEYSPACES, because its only control-plane read action is `cassandra:Select`, which is
    the same action that authorises reading table ROWS. The checks would have been
    trivial -- both fields are plain enums -- so this is a decision about the GRANT.
  * QLDB, because botocore ships no service model for it at all, so boto3 cannot
    construct a client and none of section 11 is BUILDABLE.

Both are asserted against the thing that makes them true, so if AWS changes either, a
test fails and the decision gets re-made.
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
# Timestream
# ══════════════════════════════════════════════════════════════════════════════
def _table(name="metrics", *, writes=True, bucket="rejects", option="SSE_KMS"):
    props = {"EnableMagneticStoreWrites": writes}
    if bucket:
        cfg = {"BucketName": bucket}
        if option:
            cfg["EncryptionOption"] = option
        props["MagneticStoreRejectedDataLocation"] = {"S3Configuration": cfg}
    return {"DatabaseName": "prod", "TableName": name,
            "MagneticStoreWriteProperties": props}


def _ts_scanner(tables=(), databases=({"DatabaseName": "prod"},), db_error=None):
    s = make_scanner(sections=["TIMESTREAM"])
    s.account = OWN
    ts = MagicMock()
    if db_error:
        ts.list_databases.side_effect = db_error
    else:
        ts.list_databases.return_value = {"Databases": list(databases)}
    ts.list_tables.return_value = {"Tables": list(tables)}
    # timestream-write declares NO paginators; touching one must be a hard error.
    ts.get_paginator.side_effect = AssertionError(
        "timestream-write has no paginators — get_paginator raises "
        "OperationNotPageableError before any request is made")
    s._clients[f"timestream-write:{REGION}"] = ts
    s._check_timestream()
    return s


def test_timestream_never_calls_get_paginator():
    """THE BUG THIS AVOIDS REPEATING. `_dspm_timestream` called get_paginator on
    list_databases; timestream-write declares no paginator for it, so the call raised
    before a single request and the handler reported "could not enumerate" on every scan
    forever -- indistinguishable, in a report, from an account with no Timestream."""
    s = _ts_scanner([_table()])
    assert _ids(s, "TS-02", "PASS"), "the section did not run at all"


def test_ts02_fails_when_writes_are_on_with_nowhere_for_rejects_to_go():
    s = _ts_scanner([_table(bucket=None)])
    _renders(s, "TS-02", "MEDIUM", contains="prod.metrics")


def test_ts01_fails_on_sse_s3():
    s = _ts_scanner([_table(option="SSE_S3")])
    r = _renders(s, "TS-01", "LOW")
    assert "SSE-S3" in r.message and "rejects" in r.message


def test_ts01_passes_on_sse_kms():
    s = _ts_scanner([_table(option="SSE_KMS")])
    assert not _ids(s, "TS-01", "FAIL")
    assert _ids(s, "TS-01", "PASS")


def test_a_table_without_magnetic_store_writes_is_not_reported():
    """Nothing is being diverted anywhere, so neither check has a subject. Reporting a
    missing rejected-data location on a table that rejects nothing is noise."""
    s = _ts_scanner([_table(writes=False, bucket=None)])
    assert not _ids(s, "TS-01")
    assert not _ids(s, "TS-02")


def test_ts01_is_not_evaluated_when_there_is_no_bucket_to_evaluate():
    """TS-02 owns the no-bucket case. Emitting TS-01 as well would report one gap
    twice."""
    s = _ts_scanner([_table(bucket=None)])
    assert not _ids(s, "TS-01")


def test_ts01_says_nothing_on_an_unrecognised_encryption_option():
    s = _ts_scanner([_table(option="SSE_SOMETHING_NEW")])
    assert not _ids(s, "TS-01")


def test_timestream_reports_an_empty_region():
    s = _ts_scanner([], databases=())
    info = _ids(s, "TS-01", "INFO")
    assert info and "No Timestream tables" in info[0].message


def test_a_failed_timestream_listing_is_a_warning_not_a_finding():
    s = _ts_scanner(db_error=RuntimeError("AccessDenied"))
    assert not _ids(s, "TS-01", "FAIL")
    warns = _ids(s, "TS-01", "WARN")
    assert warns and "NOT EVALUATED" in warns[0].message


def test_timestream_is_in_the_default_run_list():
    from engine.aws_live_scanner import SECTIONS, SECTION_LABELS
    assert "TIMESTREAM" in SECTIONS, "it would never run on a default scan"
    assert "TIMESTREAM" in SECTION_LABELS


# ══════════════════════════════════════════════════════════════════════════════
# Keyspaces — declined over the GRANT, not over feasibility
# ══════════════════════════════════════════════════════════════════════════════
def test_keyspaces_ships_no_checks_and_no_section():
    """The checks were written and then withdrawn. Amazon Keyspaces authorises
    ListKeyspaces, ListTables and GetTable under `cassandra:Select` -- the SAME action
    that authorises reading table rows -- and AWS offers no metadata-only alternative.
    Covering it would have added an action permitting customer-data reads to the default
    scanning role, which is the line this product's role is built on."""
    from engine.aws_live_scanner import CHECK_SEVERITY, SECTIONS
    assert not [c for c in CHECK_SEVERITY if c.startswith("KS-")]
    assert "KEYSPACES" not in SECTIONS


def test_the_keyspaces_decline_is_recorded_with_its_reason():
    reason = aws_cis_db.NOT_DETERMINABLE.get("keyspaces-needs-a-data-read-grant", "")
    assert "cassandra:Select" in reason, (
        "the decline should name the action that causes it")
    assert "opt-in" in reason, (
        "it should also name the shape a future version would take, so this reads as a "
        "deferred decision rather than a dead end")


def test_the_charter_line_the_keyspaces_decline_rests_on_still_exists():
    """A decline is only as durable as the rule it appeals to. If the read-only-of-CONFIG
    guard were ever removed, this decision would need re-making rather than standing on
    a rule nobody enforces any more."""
    import test_perm_ledger as tpl
    assert hasattr(tpl, "test_the_additive_policy_contains_only_read_actions")


def test_no_shipped_requirement_asks_for_a_data_read():
    """The property itself, asserted here too so this file documents what it relies on.
    cassandra:Select would have appeared in this list."""
    from engine import aws_perm_ledger as L
    banned = {"s3:getobject", "logs:startquery", "cassandra:select",
              "timestream:select", "dynamodb:getitem", "dynamodb:scan"}
    found = sorted({r.action for reqs in L.REQUIREMENTS.values() for r in reqs
                    if r.action.lower() in banned})
    assert not found, f"the scanning role would gain data-read actions: {found}"


# ══════════════════════════════════════════════════════════════════════════════
# QLDB — declined because it is unbuildable, which is checkable
# ══════════════════════════════════════════════════════════════════════════════
def test_qldb_has_no_service_model_at_all():
    """THE EVIDENCE FOR DECLINING SECTION 11, asserted rather than asserted-about.

    The plan proposed declining QLDB because AWS is retiring it, which is a judgement.
    The actual position is stronger and checkable: qldb has NO service model in the
    pinned botocore, so boto3 cannot construct a client for it and none of section 11 is
    BUILDABLE regardless of whether it would be worth building.

    Written as a test rather than a comment so that if AWS ever restores the model this
    fails and the decision gets re-made, instead of a stale judgement standing forever."""
    import botocore.session
    s = botocore.session.get_session()
    try:
        s.get_service_model("qldb")
    except Exception:
        return
    raise AssertionError(
        "botocore now ships a qldb service model — the decision to decline CIS Database "
        "section 11 rested on it being unbuildable, so that decision needs re-making. "
        "See aws_cis_db.NOT_DETERMINABLE['qldb-everything'].")


def test_the_qldb_decline_is_recorded_with_its_reason():
    reason = aws_cis_db.NOT_DETERMINABLE.get("qldb-everything", "")
    assert "botocore" in reason, "the decline should name the evidence, not the opinion"


def test_the_timestream_key_ownership_limit_is_recorded():
    """Timestream's database KmsKeyId is present whether the key is AWS-managed or
    customer-managed, with the same ARN shape and no distinguishing field -- so unlike
    KS-02 and MDB-04 this one genuinely cannot be decided, and guessing from the key id
    would be wrong in both directions."""
    reason = aws_cis_db.NOT_DETERMINABLE.get("timestream-database-key-ownership", "")
    assert len(reason) > 80 and "KmsKeyId" in reason


def test_every_decline_carries_a_real_reason():
    """A dict of ids with thin reasons is an omission wearing a decision's clothes."""
    for key, reason in aws_cis_db.NOT_DETERMINABLE.items():
        assert len(reason) > 100, f"{key} is declined without a real reason"
