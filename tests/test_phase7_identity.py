"""Phase 7 Batch 4 — identity fusion (IDENTITY-01): a stale/long-unused ACTIVE access
key on an ADMIN-CAPABLE IAM user is a pre-auth account-takeover path. Draws
internet -EXPOSED_TO-> IAMUser so enumerate_paths finds internet->user->admin.
Offline: hand-built graph + synthetic credential-report rows (no boto3, no AWS)."""
import os
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner
from aws_graph import SecurityGraph

ACCT = "123456789012"


def _iso(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _row(user, arn, active="true", rotated_days=200, used_days=None):
    return {"user": user, "arn": arn,
            "access_key_1_active": active,
            "access_key_1_last_rotated": _iso(rotated_days),
            "access_key_1_last_used_date": (_iso(used_days) if used_days is not None else "N/A"),
            "access_key_2_active": "false"}


def _fusion_scanner(report, ok=True):
    s = make_scanner(sections=["EXPOSURE"])
    s.account = ACCT
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    admin = s._admin_cap_id()
    g.add_node(admin, "AdminCapability")
    s.graph = g
    s._cred_report = report
    s._cred_report_ok = ok
    return s, g, admin


def _admin_user(g, admin, name, conditioned=False):
    arn = f"arn:aws:iam::{ACCT}:user/{name}"
    g.add_node(arn, "IAMUser", name=name)
    g.add_edge(arn, admin, "CAN_PRIVESC_TO", conditioned=conditioned)
    return arn


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def test_stale_admin_key_fails_and_draws_edge():
    s, g, admin = _fusion_scanner([_row("alice", f"arn:aws:iam::{ACCT}:user/alice",
                                        rotated_days=200)])
    arn = _admin_user(g, admin, "alice")
    found = s._build_identity_fusion(g, admin)
    assert found
    assert any(e["dst"] == arn and e["kind"] == "EXPOSED_TO" and
               e["props"].get("basis") == "static-credential"
               for e in g.out_edges("internet"))
    assert "FAIL" in _status(s, "IDENTITY-01")


def test_long_unused_admin_key_fails():
    # active key rotated recently but unused for >45d
    row = _row("amy", f"arn:aws:iam::{ACCT}:user/amy", rotated_days=30, used_days=90)
    s, g, admin = _fusion_scanner([row])
    _admin_user(g, admin, "amy")
    assert s._build_identity_fusion(g, admin)
    assert "FAIL" in _status(s, "IDENTITY-01")


def test_non_admin_stale_key_no_finding():
    s, g, admin = _fusion_scanner([_row("bob", f"arn:aws:iam::{ACCT}:user/bob",
                                        rotated_days=200)])
    g.add_node(f"arn:aws:iam::{ACCT}:user/bob", "IAMUser", name="bob")   # no admin edge
    assert not s._build_identity_fusion(g, admin)
    assert not _status(s, "IDENTITY-01")


def test_fresh_in_use_admin_key_no_finding():
    row = _row("carol", f"arn:aws:iam::{ACCT}:user/carol", rotated_days=10, used_days=1)
    s, g, admin = _fusion_scanner([row])
    _admin_user(g, admin, "carol")
    assert not s._build_identity_fusion(g, admin)
    assert not _status(s, "IDENTITY-01")


def test_inactive_key_ignored():
    row = _row("dave", f"arn:aws:iam::{ACCT}:user/dave", active="false", rotated_days=300)
    s, g, admin = _fusion_scanner([row])
    _admin_user(g, admin, "dave")
    assert not s._build_identity_fusion(g, admin)


def test_conditioned_admin_is_warn():
    s, g, admin = _fusion_scanner([_row("dan", f"arn:aws:iam::{ACCT}:user/dan",
                                        rotated_days=200)])
    _admin_user(g, admin, "dan", conditioned=True)
    found = s._build_identity_fusion(g, admin)
    assert found
    assert "WARN" in _status(s, "IDENTITY-01")
    assert "FAIL" not in _status(s, "IDENTITY-01")


def test_unavailable_report_no_finding():
    s, g, admin = _fusion_scanner([], ok=False)
    assert not s._build_identity_fusion(g, admin)
    assert not _status(s, "IDENTITY-01")


def test_root_account_skipped():
    s, g, admin = _fusion_scanner([_row("<root_account>", f"arn:aws:iam::{ACCT}:root",
                                        rotated_days=300)])
    assert not s._build_identity_fusion(g, admin)


def test_user_not_in_graph_skipped():
    # report has an admin-looking user but no enumerated principal node -> skip
    s, g, admin = _fusion_scanner([_row("ghost", f"arn:aws:iam::{ACCT}:user/ghost",
                                        rotated_days=200)])
    assert not s._build_identity_fusion(g, admin)


def test_dedup_guard_runs_once():
    s, g, admin = _fusion_scanner([_row("eve", f"arn:aws:iam::{ACCT}:user/eve",
                                        rotated_days=200)])
    _admin_user(g, admin, "eve")
    assert s._build_identity_fusion(g, admin)
    assert not s._build_identity_fusion(g, admin)   # global guard: second call no-op


def test_fusion_path_is_discoverable_and_critical():
    import aws_correlate as C
    from aws_deepplane import is_exploitable
    s, g, admin = _fusion_scanner([_row("frank", f"arn:aws:iam::{ACCT}:user/frank",
                                        rotated_days=200)])
    arn = _admin_user(g, admin, "frank")
    s._build_identity_fusion(g, admin)
    paths = C.enumerate_paths(
        g, {"internet"}, admin, set(),
        lambda e: not (e.get("props") or {}).get("conditioned"),
        is_exploitable, lambda nid: False)
    hit = [p for p in paths if p.terminal == admin and arn in p.nodes]
    assert hit, "internet -> stale-key user -> admin must be a discoverable path"
    assert hit[0].severity == "CRITICAL"            # pre-auth unconditioned admin floor
