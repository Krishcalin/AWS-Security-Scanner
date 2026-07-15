"""Unit tests for aws_state — the SQLite finding-lifecycle / drift / waiver store.

Covers the two-axis lifecycle (NEW -> STILL_OPEN -> RESOLVED -> REOPENED),
MUTATED on severity bump, coverage-gated resolve (a partial scan must not
mass-resolve checks it never ran), idempotent re-scan (unchanged scan => empty
drift), waiver add/expiry re-gating, suppression removed from gating, MTTR
episode pairing, and the posture trend. All timestamps are injected (deterministic).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state as st


class R:
    """Minimal Result stand-in (aws_live_scanner.Result duck type)."""
    def __init__(self, status, check_id, resource, message="m", severity="HIGH",
                 section="SEC"):
        self.status = status
        self.check_id = check_id
        self.section = section
        self.resource = resource
        self.message = message
        self.severity = severity


DAY = 86400


def store():
    return st.StateStore.open(":memory:")


def ts(epoch):
    return st.make_scan_ts(epoch)


def scan(store, results, epoch, account="111122223333", region="global",
         scan_id=None, score=90.0):
    scan_id = scan_id or f"scan-{epoch}"
    store.record_scan(account, scan_id, ts(epoch), score,
                      st.severity_counts(results), region=region)
    drift = store.classify_and_diff(account, scan_id, ts(epoch), results, region=region)
    store.record_posture(account, scan_id, drift)
    return drift


# ── lifecycle ────────────────────────────────────────────────────────────────
def test_new_finding_is_new_then_still_open():
    s = store()
    r = [R("FAIL", "IAM-01", "role:admin")]
    d1 = scan(s, r, 1000)
    assert d1["new"] == ["IAM-01|role:admin"]
    assert d1["resolved"] == [] and d1["reopened"] == []

    d2 = scan(s, r, 2000)
    assert d2["new"] == [] and d2["resolved"] == [] and d2["reopened"] == []
    assert d2["still_open"] == 1


def test_resolve_when_gone_and_covered():
    s = store()
    scan(s, [R("FAIL", "IAM-01", "role:admin")], 1000)
    # next scan runs the same check (coverage) but finding is gone -> resolved
    d = scan(s, [R("PASS", "IAM-01", "all")], 2000)
    assert d["resolved"] == ["IAM-01|role:admin"]
    assert d["still_open"] == 0


def test_reopened_keeps_first_seen():
    s = store()
    r = [R("FAIL", "IAM-01", "role:admin")]
    scan(s, r, 1000)
    scan(s, [R("PASS", "IAM-01", "all")], 2000)     # resolved
    d = scan(s, r, 3000)                              # comes back
    assert d["reopened"] == ["IAM-01|role:admin"]
    assert d["new"] == []
    rows = s.open_findings("111122223333")
    assert rows[0]["first_seen_epoch"] == 1000       # first_seen preserved
    assert rows[0]["reopen_count"] == 1


def test_mutated_on_severity_bump():
    s = store()
    scan(s, [R("FAIL", "IAM-01", "role:admin", severity="MEDIUM")], 1000)
    d = scan(s, [R("FAIL", "IAM-01", "role:admin", severity="CRITICAL")], 2000)
    assert d["mutated"] == ["IAM-01|role:admin"]
    assert d["new"] == [] and d["resolved"] == []


def test_no_mutation_when_unchanged():
    s = store()
    r = [R("FAIL", "IAM-01", "role:admin", severity="HIGH", message="same")]
    scan(s, r, 1000)
    d = scan(s, r, 2000)
    assert d["mutated"] == []


# ── coverage-gated resolve ───────────────────────────────────────────────────
def test_partial_scan_does_not_mass_resolve():
    s = store()
    scan(s, [R("FAIL", "IAM-01", "role:admin"), R("FAIL", "S3-01", "bucket:x")], 1000)
    # a --sections IAM re-scan only covers IAM-01 (S3 not run); IAM-01 still fails.
    # S3-01 is unseen-but-uncovered and must NOT be mass-resolved.
    d = scan(s, [R("FAIL", "IAM-01", "role:admin")], 2000)
    assert d["resolved"] == []                       # S3-01 not in coverage -> untouched
    assert d["still_open"] == 2                       # both remain open
    open_keys = {r["finding_key"] for r in s.open_findings("111122223333")}
    assert open_keys == {"IAM-01|role:admin", "S3-01|bucket:x"}


GLOBAL = {"IAM", "S3"}


def test_global_finding_resolves_across_region_labels():
    # regression (adversarial rank 4): a region-independent (IAM/global) finding
    # first seen under one region label must resolve when remediated under another.
    s = store()
    acct = "111122223333"
    r1 = [R("FAIL", "IAM-01", "role:admin", section="IAM")]
    s.record_scan(acct, "s1", ts(1000), 90.0, st.severity_counts(r1), region="us-east-1")
    s.classify_and_diff(acct, "s1", ts(1000), r1, region="us-east-1", global_sections=GLOBAL)
    # remediated, scanned from a different region
    r2 = [R("PASS", "IAM-01", "all", section="IAM")]
    s.record_scan(acct, "s2", ts(2000), 100.0, st.severity_counts(r2), region="us-west-2")
    d = s.classify_and_diff(acct, "s2", ts(2000), r2, region="us-west-2", global_sections=GLOBAL)
    assert d["resolved"] == ["IAM-01|role:admin"]


def test_regional_finding_not_resolved_by_other_region():
    # the safe direction must hold: a regional finding is NOT mass-resolved by a
    # scan of a different region that never observed it.
    s = store()
    acct = "111122223333"
    r1 = [R("FAIL", "SG-01", "sg-1", section="EC2")]
    s.record_scan(acct, "s1", ts(1000), 90.0, st.severity_counts(r1), region="us-east-1")
    s.classify_and_diff(acct, "s1", ts(1000), r1, region="us-east-1", global_sections=GLOBAL)
    r2 = [R("PASS", "OTHER-01", "x", section="EC2")]
    s.record_scan(acct, "s2", ts(2000), 90.0, st.severity_counts(r2), region="us-west-2")
    d = s.classify_and_diff(acct, "s2", ts(2000), r2, region="us-west-2", global_sections=GLOBAL)
    assert d["resolved"] == []
    open_keys = {row["finding_key"] for row in s.open_findings(acct)}
    assert "SG-01|sg-1" in open_keys


def test_covered_check_resolves():
    s = store()
    scan(s, [R("FAIL", "IAM-01", "role:admin"), R("FAIL", "S3-01", "bucket:x")], 1000)
    # scan covering BOTH checks, IAM-01 gone -> only IAM-01 resolves
    d = scan(s, [R("PASS", "IAM-01", "all"), R("FAIL", "S3-01", "bucket:x")], 2000)
    assert d["resolved"] == ["IAM-01|role:admin"]
    assert d["still_open"] == 1


# ── idempotency ──────────────────────────────────────────────────────────────
def test_idempotent_rescan_empty_drift():
    s = store()
    r = [R("FAIL", "IAM-01", "role:admin"), R("WARN", "IAM-02", "user:bob")]
    scan(s, r, 1000)
    d = scan(s, r, 2000)
    assert d["new"] == [] and d["resolved"] == [] and d["reopened"] == [] and d["mutated"] == []


def test_finding_key_stable():
    assert st.finding_key("IAM-01", "role:admin") == "IAM-01|role:admin"
    assert st.finding_key("IAM-01", "  role:admin  ") == "IAM-01|role:admin"   # canon strips


# ── waivers / suppression ────────────────────────────────────────────────────
def test_exact_waiver_suppresses_from_gating():
    s = store()
    acct = "111122223333"
    s.apply_waiver({"type": "exact", "finding_key": "IAM-01|role:admin", "account": acct},
                   approver="secops", reason="risk accepted", created_epoch=500,
                   expires_epoch=None)
    results = [R("FAIL", "IAM-01", "role:admin")]
    gating, suppressed = s.filter_suppressed(acct, results, 1000)
    assert len(gating) == 0 and len(suppressed) == 1


def test_glob_waiver_matches():
    s = store()
    acct = "111122223333"
    s.apply_waiver({"type": "glob", "check_glob": "IAM-*", "resource_glob": "role:*",
                    "account": acct}, approver="a", reason="r", created_epoch=1)
    results = [R("FAIL", "IAM-05", "role:svc"), R("FAIL", "S3-01", "bucket:x")]
    gating, suppressed = s.filter_suppressed(acct, results, 1000)
    assert {r.check_id for r in suppressed} == {"IAM-05"}
    assert {r.check_id for r in gating} == {"S3-01"}


def test_expired_waiver_reenters_gating():
    s = store()
    acct = "111122223333"
    s.apply_waiver({"type": "exact", "finding_key": "IAM-01|role:admin", "account": acct},
                   approver="a", reason="r", created_epoch=500, expires_epoch=1500)
    results = [R("FAIL", "IAM-01", "role:admin")]
    # before expiry
    g, sup = s.filter_suppressed(acct, results, 1000)
    assert len(sup) == 1
    # after expiry (scan epoch past expires) -> back in gating, zero DB mutation
    g, sup = s.filter_suppressed(acct, results, 2000)
    assert len(sup) == 0 and len(g) == 1


def test_suppressed_finding_still_tracked_open():
    s = store()
    acct = "111122223333"
    s.apply_waiver({"type": "exact", "finding_key": "IAM-01|role:admin", "account": acct},
                   approver="a", reason="r", created_epoch=1)
    d = scan(s, [R("FAIL", "IAM-01", "role:admin")], 1000)
    assert d["suppressed"] == ["IAM-01|role:admin"]
    assert d["suppressed_count"] == 1
    # still stored as open, not deleted
    assert {r["finding_key"] for r in s.open_findings(acct)} == {"IAM-01|role:admin"}


def test_waiver_account_scoping():
    s = store()
    s.apply_waiver({"type": "exact", "finding_key": "IAM-01|role:admin",
                    "account": "999988887777"}, approver="a", reason="r", created_epoch=1)
    # waiver is for a different account -> does not suppress here
    g, sup = s.filter_suppressed("111122223333", [R("FAIL", "IAM-01", "role:admin")], 1000)
    assert len(sup) == 0


# ── MTTR / trend ─────────────────────────────────────────────────────────────
def test_mttr_episode_pairing():
    s = store()
    acct = "111122223333"
    scan(s, [R("FAIL", "IAM-01", "role:admin")], 1000)          # NEW at 1000
    scan(s, [R("PASS", "IAM-01", "all")], 1000 + 10 * DAY)      # RESOLVED at +10d
    m = s.mttr(acct)
    assert m["resolved_count"] == 1
    assert m["mean_seconds"] == 10 * DAY


def test_mttr_ignores_dormant_gap_on_reopen():
    s = store()
    acct = "111122223333"
    r = [R("FAIL", "IAM-01", "role:admin")]
    scan(s, r, 0)                       # NEW at 0
    scan(s, [R("PASS", "IAM-01", "all")], 2 * DAY)   # RESOLVED at 2d (episode 1 = 2d)
    scan(s, r, 100 * DAY)               # REOPENED at 100d
    scan(s, [R("PASS", "IAM-01", "all")], 103 * DAY)  # RESOLVED at 103d (episode 2 = 3d)
    m = s.mttr(acct)
    assert m["resolved_count"] == 2
    assert m["mean_seconds"] == (2 * DAY + 3 * DAY) / 2   # 2.5d, NOT spanning the gap


def test_mttr_by_severity_and_sla():
    s = store()
    acct = "111122223333"
    scan(s, [R("FAIL", "IAM-01", "r1", severity="CRITICAL")], 0)
    scan(s, [R("PASS", "IAM-01", "all")], 5 * DAY)
    scan(s, [R("FAIL", "S3-01", "r2", severity="LOW")], 0, scan_id="b0")
    m = s.mttr(acct, by_severity=True, sla_days=1, now_epoch=6 * DAY)
    assert "CRITICAL" in m["by_severity"]
    # S3-01 open since 0, now 6d, sla 1d -> over SLA
    assert m["open_over_sla"] >= 1


def test_trend_has_deltas():
    s = store()
    acct = "111122223333"
    scan(s, [R("FAIL", "IAM-01", "r")], 1000, score=90.0)
    scan(s, [R("FAIL", "IAM-01", "r"), R("FAIL", "S3-01", "b")], 2000, score=80.0)
    tr = s.trend(acct)
    assert len(tr) == 2
    assert tr[0]["delta"] is None
    assert tr[1]["delta"] == -10.0


def test_posture_delta_in_drift():
    s = store()
    acct = "111122223333"
    scan(s, [R("FAIL", "IAM-01", "r")], 1000, score=95.0)
    d = scan(s, [R("FAIL", "IAM-01", "r")], 2000, score=85.0)
    assert d["posture_delta"] == -10.0


# ── list_waivers state annotation ────────────────────────────────────────────
def test_list_waivers_states():
    s = store()
    acct = "111122223333"
    wid = s.apply_waiver({"type": "exact", "finding_key": "k", "account": acct},
                         approver="a", reason="r", created_epoch=1, expires_epoch=1500)
    lw = s.list_waivers(acct, scan_epoch=2000)
    assert lw[0]["state"] == "expired"
    s.revoke_waiver(wid)
    lw = s.list_waivers(acct, scan_epoch=1000)
    assert lw[0]["state"] == "revoked"
