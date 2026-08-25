"""Phase 3 · slice 3.3 — MCP-05, the half of a rug pull the account can see.

MCP-04 states the half nobody can see: a federated server that serves different tools
tomorrow leaves no trace here, because no API in the account returns its tool list. This
is the other half — a target repointed, a target added or removed, the gateway's own MCP
instructions rewritten. All of those are recorded, so all of them are diffable.

Three properties carry it, and two are about not crying wolf.

**A first sighting is not a change.** Reporting one would fire on every gateway the first
time an operator supplies a state DB — the noise that teaches people to ignore a
category. `aws_state` already makes this distinction for findings, where NEW is projected
rather than stored; the same rule applies here.

**No state DB, no check, and no complaint.** The config half (MCP-01..04) must not become
hostage to an opt-in flag, so the scan path stays stateless and the comparison happens at
the one seam that already holds the store.

**A change is asked about, not asserted.** The common case is the operator's own
deployment. A finding that announced a breach on every deployment would be wrong far more
often than right.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
from aws_live_scanner import AWSLiveScanner

ACCT = "123456789012"
ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/tools-a1b2c3d4e5"
T0 = aws_state.make_scan_ts(1_700_000_000)
T1 = aws_state.make_scan_ts(1_700_086_400)


@pytest.fixture()
def store():
    st = aws_state.StateStore.open(":memory:")
    st._migrate()
    yield st
    st.close()


def _scanner(surfaces):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["AGENTCORE"])
        s.account = ACCT
    s._client = lambda svc, region=None: MagicMock()
    s._mcp_surfaces = list(surfaces)
    return s


def surface(fingerprint="aaa", endpoints=("https://a.example/mcp",), count=1):
    return {"arn": ARN, "name": "tools", "fingerprint": fingerprint,
            "endpoints": list(endpoints), "target_count": count}


def _ids(s, cid):
    return [r for r in s.results if r.check_id == cid]


# ── the store ───────────────────────────────────────────────────────────────
def test_a_first_sighting_is_recorded_but_is_not_a_change(store):
    d = store.record_mcp_surface(ACCT, ARN, name="tools", fingerprint="aaa",
                                 endpoints=["https://a.example/mcp"], target_count=1,
                                 ts=T0)
    assert d["first_seen"] is True and d["changed"] is False


def test_an_identical_surface_is_not_a_change(store):
    for ts in (T0, T1):
        d = store.record_mcp_surface(ACCT, ARN, name="tools", fingerprint="aaa",
                                     endpoints=["https://a.example/mcp"],
                                     target_count=1, ts=ts)
    assert d["changed"] is False and d["change_count"] == 0


def test_a_repointed_target_is_a_change_and_names_both_endpoints(store):
    store.record_mcp_surface(ACCT, ARN, name="tools", fingerprint="aaa",
                             endpoints=["https://a.example/mcp"], target_count=1, ts=T0)
    d = store.record_mcp_surface(ACCT, ARN, name="tools", fingerprint="bbb",
                                 endpoints=["https://b.example/mcp"], target_count=1,
                                 ts=T1)
    assert d["changed"] is True
    assert d["added"] == ["https://b.example/mcp"]
    assert d["removed"] == ["https://a.example/mcp"]


def test_the_first_seen_epoch_survives_every_later_scan(store):
    """Including it in the update set would reset the age of every gateway on each run,
    which quietly destroys the only thing the row is for."""
    store.record_mcp_surface(ACCT, ARN, name="tools", fingerprint="aaa",
                             endpoints=[], target_count=0, ts=T0)
    store.record_mcp_surface(ACCT, ARN, name="tools", fingerprint="bbb",
                             endpoints=[], target_count=0, ts=T1)
    row = store.get_mcp_surface(ACCT, ARN)
    assert row["first_seen_epoch"] == T0.epoch
    assert row["last_seen_epoch"] == T1.epoch
    assert row["last_changed_epoch"] == T1.epoch


def test_changes_accumulate_rather_than_resetting(store):
    for n, fp in enumerate(("aaa", "bbb", "ccc")):
        d = store.record_mcp_surface(ACCT, ARN, name="tools", fingerprint=fp,
                                     endpoints=[], target_count=0,
                                     ts=aws_state.make_scan_ts(1_700_000_000 + n * 86400))
    assert d["change_count"] == 2


def test_an_unseen_gateway_reads_as_none(store):
    assert store.get_mcp_surface(ACCT, "arn:aws:...:gateway/never") is None


def test_two_accounts_do_not_share_a_surface(store):
    store.record_mcp_surface(ACCT, ARN, name="tools", fingerprint="aaa",
                             endpoints=[], target_count=0, ts=T0)
    assert store.get_mcp_surface("999999999999", ARN) is None


# ── the emitter ─────────────────────────────────────────────────────────────
def test_no_finding_on_the_first_scan(store):
    """The one that decides whether the check is usable. Every gateway in the account
    would light up the first time somebody passes --state."""
    s = _scanner([surface()])
    s._emit_mcp_drift(store, T0)
    assert not _ids(s, "MCP-05")


def test_a_changed_surface_raises_mcp05(store):
    s = _scanner([surface()])
    s._emit_mcp_drift(store, T0)
    s2 = _scanner([surface(fingerprint="bbb", endpoints=["https://b.example/mcp"])])
    s2._emit_mcp_drift(store, T1)
    f = _ids(s2, "MCP-05")
    assert len(f) == 1
    assert "now reaches https://b.example/mcp" in f[0].message
    assert "no longer reaches https://a.example/mcp" in f[0].message


def test_the_finding_asks_rather_than_asserts(store):
    """The common case is the operator's own deployment. A finding that announced a
    breach every time would be wrong far more often than right."""
    s = _scanner([surface()])
    s._emit_mcp_drift(store, T0)
    s2 = _scanner([surface(fingerprint="bbb")])
    s2._emit_mcp_drift(store, T1)
    msg = _ids(s2, "MCP-05")[0].message
    assert "Confirm it was yours" in msg
    assert "visible half" in msg


def test_a_change_with_the_same_endpoints_says_what_moved(store):
    """Instructions rewritten, or a target added whose endpoint list did not change.
    Saying nothing moved would contradict the finding's own existence."""
    s = _scanner([surface()])
    s._emit_mcp_drift(store, T0)
    s2 = _scanner([surface(fingerprint="bbb")])
    s2._emit_mcp_drift(store, T1)
    msg = _ids(s2, "MCP-05")[0].message
    assert "its MCP instructions or its target list" in msg


def test_a_gateway_that_gains_its_first_federated_target_is_caught(store):
    """The stash records every gateway, federated or not, precisely so this is visible.
    A comparison that only stored gateways already federating would miss the moment one
    starts."""
    s = _scanner([surface(fingerprint="none", endpoints=[], count=1)])
    s._emit_mcp_drift(store, T0)
    s2 = _scanner([surface(fingerprint="withmcp",
                           endpoints=["https://vendor.example/mcp"], count=2)])
    s2._emit_mcp_drift(store, T1)
    f = _ids(s2, "MCP-05")
    assert len(f) == 1 and "now reaches https://vendor.example/mcp" in f[0].message


def test_no_store_means_no_check_and_no_complaint(store):
    """The config half must not become hostage to an opt-in flag."""
    s = _scanner([surface()])
    s._emit_mcp_drift(None, T0)
    assert not s.results


def test_no_gateways_is_silent(store):
    s = _scanner([])
    s._emit_mcp_drift(store, T0)
    assert not _ids(s, "MCP-05")


def test_a_store_failure_costs_the_check_not_the_scan(store):
    broken = MagicMock()
    broken.record_mcp_surface.side_effect = Exception("db is gone")
    s = _scanner([surface()])
    s._emit_mcp_drift(broken, T0)          # must not raise
    assert not _ids(s, "MCP-05")


def test_each_gateway_is_compared_independently(store):
    other = dict(surface(), arn=ARN + "-2", name="other")
    s = _scanner([surface(), other])
    s._emit_mcp_drift(store, T0)
    s2 = _scanner([surface(), dict(other, fingerprint="moved",
                                   endpoints=["https://c.example/mcp"])])
    s2._emit_mcp_drift(store, T1)
    f = _ids(s2, "MCP-05")
    assert len(f) == 1 and "other" in f[0].message
