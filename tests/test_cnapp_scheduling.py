#!/usr/bin/env python3
"""
Tests for continuous scheduled scanning + drift digests.

Covers: the scan-cadence grammar + scans_due + no-double-enqueue + scheduler_tick;
lifecycle wiring (worker -> StateStore drift/trend, fail-open); the pure drift-digest
builder (lossless counts, newly-on-path subset, material gating, windows, compliance
delta); per-type digest renders; run_digest opt-in + material/min_new gates + per-window
idempotency + coexistence with per-finding run_rules; and secret scrubbing. All on
:memory: with an injected clock + a fake http_post — no boto3, no sockets.
"""
import types

import aws_state
import cnapp_connectors as cc
import cnapp_validate as v
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService
from cnapp_worker import scheduler_tick


# ── harness ─────────────────────────────────────────────────────────────────────
class _Sess:
    def __init__(self, acct):
        self.acct = acct

    def client(self, service, **k):
        acct = self.acct

        class C:
            def get_caller_identity(self):
                return {"Account": acct}
        return C()


def _R(status, cid, sev="HIGH"):
    return types.SimpleNamespace(status=status, check_id=cid, section="S3", resource="b" + cid,
                                 message="m", severity=sev, compliance={}, remediation_cmd="")


def _runner_for(box):
    def runner(session, spec):
        g = SecurityGraph(); g.add_node("internet", "InternetSource")
        results = list(box[0])
        return types.SimpleNamespace(
            account=session.acct, region="us-east-1", graph=g, attack_paths=[], choke_points=[],
            results=results,
            _build_finding_catalog=lambda: [
                {"check_id": r.check_id, "severity": r.severity, "section": r.section, "risk": "x",
                 "status": "FAIL", "compliance": {}, "remediation_cmd": "", "impact": "", "steps": [],
                 "affected": [r.resource], "count": 1, "distinct": 1}
                for r in results if r.status == "FAIL"])
    return runner


def _svc(box, *, http_post, secret="https://hooks.slack.com/x", with_state=True, clk=None):
    clk = clk or {"t": 1000}
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be) if with_state else None
    store = cc.ConnectorStore(reg._be)
    svc = PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, val: "ssm://x", secret_reader=lambda r: secret, connectors=store,
        state=state, http_post=http_post, session_factory=lambda aid: _Sess(aid),
        scan_runner=_runner_for(box), hub_base="https://hub.x", clock=lambda: clk["t"])
    return svc, reg, store, state, clk


def _active(reg, aid, schedule="daily", now=1000):
    reg.upsert_account(aid, now_epoch=now, role_arn="r", external_id_ref="ssm://x", scan_schedule=schedule)
    reg.set_onboarding_status(aid, "active", now)
    reg.set_health(aid, "healthy", None, now)


def _poster():
    posts = []

    def post(url, *, headers, json_body=None, data=None, timeout=8.0, method="POST"):
        posts.append({"url": url, "json": json_body, "data": data})
        return cc.HttpResp(200, "ok")
    return post, posts


# ── cadence grammar ─────────────────────────────────────────────────────────────
def test_scan_interval_grammar():
    assert v.scan_interval(None) is None and v.scan_interval("") is None and v.scan_interval("off") is None
    assert v.scan_interval("hourly") == 3600 and v.scan_interval("daily") == 86400 and v.scan_interval("weekly") == 604800
    assert v.scan_interval("interval:120") == 120
    # non-positive intervals fail LOUD (never a silent no-scan)
    for bad in ("bogus", "interval:", "interval:x", "every-day", "interval:0", "interval:-5"):
        try:
            v.scan_interval(bad); assert False, bad
        except ValueError:
            pass


def test_failed_scan_backs_off_instead_of_flapping():
    reg = AccountRegistry.open(":memory:")
    _active(reg, "111111111111", "daily")
    # a scan fails at t=1010 (last_scan_at NOT stamped on 'error')
    reg.record_scan_job("111111111111", "j1", "error", now_epoch=1010, finished_at=1010, error="boom")
    assert reg.get_account("111111111111")["last_scan_at"] is None
    assert reg.scans_due(1011) == []                 # backing off (was: re-eligible every tick)
    assert reg.scans_due(1010 + 899) == []           # still within the 15-min backoff
    assert reg.scans_due(1010 + 900)                 # backoff elapsed -> retry
    # a subsequent success clears the backoff
    reg.record_scan_job("111111111111", "j2", "done", now_epoch=1010 + 900, finished_at=1010 + 900)
    assert reg.scans_due(1010 + 900) == []           # just succeeded -> normal cadence


# ── scans_due + scheduler ────────────────────────────────────────────────────────
def test_scans_due_selects_and_excludes():
    reg = AccountRegistry.open(":memory:")
    _active(reg, "111111111111", "daily")            # due (never scanned)
    _active(reg, "222222222222", "off")              # excluded — off
    _active(reg, "333333333333", "daily"); reg.set_health("333333333333", "unauthorized", None, 1000)  # excluded
    reg.upsert_account("444444444444", now_epoch=1000, scan_schedule="daily")  # excluded — not active
    due = {a["account_id"] for a in reg.scans_due(1000)}
    assert due == {"111111111111"}


def test_scans_due_respects_interval_and_running_job():
    reg = AccountRegistry.open(":memory:")
    _active(reg, "111111111111", "daily")
    reg.record_scan_job("111111111111", "j1", "done", now_epoch=1000, finished_at=1000)  # last_scan_at=1000
    assert reg.scans_due(1000) == []                 # just scanned
    assert reg.scans_due(1000 + 86400)               # due next day
    # a queued/running job excludes it even when due
    reg.record_scan_job("111111111111", "j2", "running", now_epoch=1000 + 86400, started_at=1000 + 86400)
    assert reg.scans_due(1000 + 86400) == []


def test_schedule_due_scans_no_double_enqueue():
    box = [[_R("FAIL", "S3-01")]]
    post, _ = _poster()
    svc, reg, *_ = _svc(box, http_post=post)
    _active(reg, "111111111111", "daily")
    assert len(svc.schedule_due_scans()) == 1
    assert svc.schedule_due_scans() == []            # a queued job already exists


def test_set_scan_schedule_validates():
    box = [[]]; post, _ = _poster()
    svc, reg, *_ = _svc(box, http_post=post)
    _active(reg, "111111111111", "off")
    svc.set_scan_schedule("111111111111", "weekly")
    assert reg.get_account("111111111111")["scan_schedule"] == "weekly"
    try:
        svc.set_scan_schedule("111111111111", "nonsense"); assert False
    except ValueError:
        pass


# ── lifecycle wiring ─────────────────────────────────────────────────────────────
def test_lifecycle_populates_drift_and_is_idempotent():
    box = [[_R("FAIL", "S3-01"), _R("FAIL", "S3-03")]]
    post, _ = _poster()
    svc, reg, store, state, clk = _svc(box, http_post=post)
    _active(reg, "123456789012", "daily")
    scheduler_tick(svc)
    assert len(state.trend("123456789012")) == 1
    assert svc.get_drift("123456789012")["new_count"] == 2
    # re-run same findings next day -> 0 new (idempotent)
    clk["t"] = 1000 + 86400
    scheduler_tick(svc)
    assert svc.get_drift("123456789012")["new_count"] == 0
    # remediate a finding: the check still RUNS (coverage) but now PASSes -> resolved=1
    clk["t"] = 1000 + 2 * 86400
    box[0] = [_R("FAIL", "S3-01"), _R("PASS", "S3-03")]
    scheduler_tick(svc)
    assert svc.get_drift("123456789012")["resolved_count"] == 1


def test_lifecycle_fail_open_without_state():
    box = [[_R("FAIL", "S3-01")]]
    post, _ = _poster()
    svc, reg, *_ = _svc(box, http_post=post, with_state=False)
    _active(reg, "123456789012", "daily")
    done = scheduler_tick(svc)["ran"]
    assert done and done[0]["status"] == "done"       # scan still completes with no state store


def test_lifecycle_error_never_fails_the_scan():
    box = [[_R("FAIL", "S3-01")]]
    post, _ = _poster()
    svc, reg, *_ = _svc(box, http_post=post)
    svc.record_lifecycle = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    _active(reg, "123456789012", "daily")
    done = scheduler_tick(svc)["ran"]
    assert done[0]["status"] == "done"


# ── digest builder (pure) ────────────────────────────────────────────────────────
def _drift(new=(), resolved=(), reopened=(), mutated=(), still_open=0, posture_delta=None):
    return {"new": list(new), "resolved": list(resolved), "reopened": list(reopened),
            "mutated": list(mutated), "still_open": still_open, "suppressed_count": 0,
            "posture_delta": posture_delta}


def test_build_digest_counts_lossless_and_onpath_subset():
    drift = _drift(new=["S3-01|a", "S3-01|b", "IAM-02|c"], resolved=["S3-09|x"], posture_delta=-5.0)
    catalog = {"S3-01": {"severity": "HIGH"}, "IAM-02": {"severity": "CRITICAL"}, "S3-09": {"severity": "LOW"}}
    d = cc.build_drift_digest(account="123456789012", scan_id="job-1", scan_epoch=1000, drift=drift,
                              trend=[{"posture_score": 80, "grade": "B"}], mttr={},
                              catalog_by_check=catalog, onpath={"IAM-02"}, window_id="job-1")
    assert d["counts"]["new"] == 3 and d["counts"]["resolved"] == 1   # lossless len()
    assert d["material_change"] is True
    checks = {x["check_id"] for x in d["newly_exposed"]}
    assert checks == {"S3-01", "IAM-02"}                              # deduped by check
    assert all(x in d["newly_exposed"] for x in d["newly_on_path"])   # subset
    assert d["newly_on_path"][0]["check_id"] == "IAM-02"


def test_newly_on_path_is_subset_even_when_over_top():
    # 12 new findings, only the 12th is on-path + LOW; with top=5 it must NOT appear in
    # newly_exposed AND must NOT appear in newly_on_path (subset holds by construction).
    new = [f"HI-{i:02d}|r" for i in range(11)] + ["LO-ON|r"]
    catalog = {f"HI-{i:02d}": {"severity": "HIGH"} for i in range(11)}
    catalog["LO-ON"] = {"severity": "LOW"}
    d = cc.build_drift_digest(account="1", scan_id="s", scan_epoch=1, drift=_drift(new=new),
                              trend=[{"posture_score": 50, "grade": "F"}], mttr={},
                              catalog_by_check=catalog, onpath={"LO-ON"}, window_id="s", top=5)
    exposed = {x["check_id"] for x in d["newly_exposed"]}
    assert all(x["check_id"] in exposed for x in d["newly_on_path"])   # subset invariant


def test_on_path_wins_severity_tie_in_top_cut():
    # two MEDIUMs, one on-path; with top=1 the on-path one must make the cut
    d = cc.build_drift_digest(account="1", scan_id="s", scan_epoch=1,
                              drift=_drift(new=["OFF|r", "ONP|r"]),
                              trend=[{"posture_score": 50, "grade": "F"}], mttr={},
                              catalog_by_check={"OFF": {"severity": "MEDIUM"}, "ONP": {"severity": "MEDIUM"}},
                              onpath={"ONP"}, window_id="s", top=1)
    assert d["newly_exposed"][0]["check_id"] == "ONP"


def test_build_digest_not_material_when_nothing_changed():
    d = cc.build_drift_digest(account="1", scan_id="s", scan_epoch=1, drift=_drift(still_open=5),
                              trend=[{"posture_score": 90, "grade": "A"}], mttr={},
                              catalog_by_check={}, onpath=set(), window_id="s")
    assert d["material_change"] is False and d["counts"]["new"] == 0


def test_digest_window_and_dedup_key():
    assert cc.digest_window("per_scan", "job-9", 1000) == "job-9"
    assert cc.digest_window("daily", "job-9", 1_700_000_000).startswith("d:")
    assert cc.digest_dedup_key("c1", "acct", "w") == "digest:c1:acct:w"


def test_compliance_delta():
    prev = {"PCI-DSS": {"pass_rate": 90.0, "failed_controls": ["1.1"]}}
    cur = {"PCI-DSS": {"pass_rate": 80.0, "failed_controls": ["1.1", "2.2"]}}
    delta = cc.compliance_delta(prev, cur)
    assert delta and delta[0]["pass_rate_delta"] == -10.0 and delta[0]["newly_failed_controls"] == ["2.2"]
    assert cc.compliance_delta(None, cur) is None      # first scan


# ── digest renders (pure, per type) ──────────────────────────────────────────────
def _digest():
    return cc.build_drift_digest(account="123456789012", scan_id="job-1", scan_epoch=1_700_000_000,
                                 drift=_drift(new=["S3-01|a"], posture_delta=-3.0),
                                 trend=[{"posture_score": 77, "grade": "C"}], mttr={"open_over_sla": 2, "sla_days": 30},
                                 catalog_by_check={"S3-01": {"severity": "HIGH"}}, onpath={"S3-01"},
                                 window_id="job-1", hub_base="https://hub.x")


def test_render_slack_digest_has_text_fallback():
    body = cc.render_slack_digest(cc.Connector("c", "slack", "S", True, {"mode": "webhook"}, "x"), _digest(), hub_base="https://hub.x")
    assert body["text"]
    assert any(b["type"] == "header" for b in body["blocks"])


def test_render_webhook_digest_is_byte_stable():
    c = cc.Connector("c", "webhook", "W", True, {"url": "https://h/x"}, "x")
    b1 = cc.render_webhook_digest(c, _digest(), event_id="e", now_epoch=1_700_000_000)
    b2 = cc.render_webhook_digest(c, _digest(), event_id="e", now_epoch=1_700_000_000)
    import json
    assert b1 == b2 and json.loads(b1)["type"] == "overwatch.drift_digest"


def test_render_pagerduty_digest_has_stable_dedup_key():
    body = cc.render_pagerduty_digest(cc.Connector("c", "pagerduty", "P", True, {}, "x"), _digest())
    assert body["dedup_key"] == "overwatch:digest:123456789012:job-1"
    assert body["payload"]["severity"] in ("info", "warning", "error")


# ── run_digest: opt-in, gates, idempotency, coexistence ──────────────────────────
def _store_with_digest_connector(only_material=True, min_new=0, globs=None):
    store = cc.ConnectorStore.open(":memory:")
    dcfg = {"enabled": True, "only_on_material_change": only_material, "min_new": min_new}
    if globs is not None:
        dcfg["account_globs"] = globs
    store.upsert_connector("c1", now_epoch=1, type="webhook", name="W",
                           config={"url": "https://h/x", "digest": dcfg}, secret_ref="ssm://x", enabled=True)
    return store


def test_run_digest_opt_in_and_idempotent():
    store = _store_with_digest_connector()
    post, posts = _poster()
    digest = _digest()
    r1 = cc.run_digest(store, digest, http_post=post, secret_reader=lambda r: "sek", now_epoch=10)
    r2 = cc.run_digest(store, digest, http_post=post, secret_reader=lambda r: "sek", now_epoch=11)
    assert r1.digested == 1 and r2.digested == 0      # 2nd is idempotent (same window)
    assert len(posts) == 1


def test_run_digest_retries_a_failed_delivery():
    """A transient delivery failure must be re-sendable on the next run_digest for the
    same window (at-least-once), not permanently dropped."""
    store = _store_with_digest_connector()
    calls = {"n": 0}

    def flaky(url, *, headers, json_body=None, data=None, timeout=8.0, method="POST"):
        calls["n"] += 1
        return cc.HttpResp(500, "boom") if calls["n"] == 1 else cc.HttpResp(200, "ok")
    r1 = cc.run_digest(store, _digest(), http_post=flaky, secret_reader=lambda r: "s", now_epoch=10)
    assert r1.digested == 0 and store.list_digests("c1")[0]["status"] == "failed"
    r2 = cc.run_digest(store, _digest(), http_post=flaky, secret_reader=lambda r: "s", now_epoch=11)
    assert r2.digested == 1 and store.list_digests("c1")[0]["status"] == "sent"   # retried, not dropped
    # once sent, a re-run is idempotent (no re-send)
    r3 = cc.run_digest(store, _digest(), http_post=flaky, secret_reader=lambda r: "s", now_epoch=12)
    assert r3.digested == 0


def test_run_digest_material_and_min_new_gates():
    post, posts = _poster()
    # not-material digest suppressed under only_on_material_change
    store = _store_with_digest_connector(only_material=True)
    flat = cc.build_drift_digest(account="123456789012", scan_id="s", scan_epoch=1, drift=_drift(still_open=3),
                                 trend=[{"posture_score": 90, "grade": "A"}], mttr={}, catalog_by_check={},
                                 onpath=set(), window_id="s")
    assert cc.run_digest(store, flat, http_post=post, secret_reader=lambda r: "s", now_epoch=1).digested == 0
    # min_new gate
    store2 = _store_with_digest_connector(min_new=5)
    assert cc.run_digest(store2, _digest(), http_post=post, secret_reader=lambda r: "s", now_epoch=1).digested == 0


def test_run_digest_account_globs():
    store = _store_with_digest_connector(globs=["9999*"])
    post, _ = _poster()
    assert cc.run_digest(store, _digest(), http_post=post, secret_reader=lambda r: "s", now_epoch=1).digested == 0


def test_digest_disabled_connector_skipped():
    store = cc.ConnectorStore.open(":memory:")
    store.upsert_connector("c1", now_epoch=1, type="webhook", name="W",
                           config={"url": "https://h/x", "digest": {"enabled": True}}, enabled=False)  # disabled
    post, _ = _poster()
    assert cc.run_digest(store, _digest(), http_post=post, secret_reader=lambda r: "s", now_epoch=1).digested == 0


# ── end-to-end via the worker: digest coexists with per-finding, scrubs secrets ──
def test_worker_fires_digest_only_when_material():
    box = [[_R("FAIL", "S3-01"), _R("FAIL", "S3-03")]]
    post, posts = _poster()
    svc, reg, store, state, clk = _svc(box, http_post=post)
    _active(reg, "123456789012", "daily")
    store.upsert_connector("c1", now_epoch=1, type="slack", name="S",
                           config={"mode": "webhook", "digest": {"enabled": True}},
                           secret_ref="ssm://x", enabled=True)
    scheduler_tick(svc)
    assert len(store.list_digests("c1")) == 1 and store.list_digests("c1")[0]["status"] == "sent"
    n = len(posts)
    clk["t"] = 1000 + 86400
    scheduler_tick(svc)                               # unchanged -> not material -> no new send
    assert len(store.list_digests("c1")) == 1 and len(posts) == n


def test_digest_scrubs_secret_from_error():
    secret = "SUPERSECRETURL999"
    store = _store_with_digest_connector()

    def bad(url, *, headers, json_body=None, data=None, timeout=8.0, method="POST"):
        return cc.HttpResp(500, f"upstream error at {secret}")
    cc.run_digest(store, _digest(), http_post=bad, secret_reader=lambda r: secret, now_epoch=1)
    import json
    assert secret not in json.dumps(store.list_digests("c1"))
