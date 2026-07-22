#!/usr/bin/env python3
"""
Offline tests for cnapp_connectors — the Phase-2 connector framework.

Every test runs on ConnectorStore.open(':memory:') with an injected clock + a fake
http_post; NO boto3, NO sockets. Covers: renderer golden shapes, request auth
assembly, response decode (incl. the Slack 200-but-failed trap), secret-leak
guards, the rule truth-table, match_finding fan-out/collapse, the plan() dedup
state machine, claim idempotency, resolve_stale coverage-gating, fold_digest, the
schema-v3 migration, and the read-only-on-targets assertion.
"""
import json

import pytest

import cnapp_connectors as cc


# ── fixtures ───────────────────────────────────────────────────────────────────
def _entry(**kw):
    base = dict(check_id="S3-01", section="S3", severity="HIGH", status="FAIL",
                compliance={"CIS": "2.1.1", "PCI-DSS": "1.3.1"},
                remediation_cmd="aws s3api put-public-access-block --bucket b ...",
                risk="Public S3 bucket exposes data. Anyone on the internet can read it.",
                impact="Data breach and compliance violation.",
                steps=["Block public access", "Re-scan"],
                affected=["db1", "db2", "db3"], count=5, distinct=3)
    base.update(kw)
    return base


def _finding(account="123456789012", on_path=True, **kw):
    return cc.to_finding(_entry(**kw), account, on_path)


def _fake_poster(resp: cc.HttpResp):
    calls = []

    def post(url, *, headers, json_body=None, data=None, timeout=8.0):
        calls.append({"url": url, "headers": headers, "json": json_body, "data": data})
        return resp
    return post, calls


def _reader(secret="TOKEN-abc123def456"):
    def r(ref):
        assert str(ref).startswith(("secretsmanager://", "ssm://")), ref
        return secret
    return r


def _writer(cid, val):
    return f"secretsmanager://overwatch/connectors/{cid}"


def _conn(type="jira", enabled=True, config=None, secret_ref="secretsmanager://x"):
    cfg = config if config is not None else {
        "site": "https://acme.atlassian.net", "email": "bot@acme.com", "project_key": "SEC"}
    return cc.Connector(connector_id="c1", type=type, name="c1", enabled=enabled,
                        config=cfg, secret_ref=secret_ref, created_at=1, updated_at=1)


def _rule(**kw):
    base = dict(id=1, connector_id="c1", enabled=True, priority=10, min_severity="HIGH")
    base.update(kw)
    return cc.ConnectorRule(**base)


# ── migration ──────────────────────────────────────────────────────────────────
def test_migration_v3_creates_connector_tables_idempotently():
    store = cc.ConnectorStore.open(":memory:")
    names = [r[0] for r in store._be.query_all(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name IN ('connectors','connector_rules','notification_log') ORDER BY name")]
    assert names == ["connector_rules", "connectors", "notification_log"]
    assert store._be.raw.execute("PRAGMA user_version").fetchone()[0] == 3
    store._be.migrate()          # replay is a no-op (IF NOT EXISTS)


def test_migration_leaves_existing_tables_intact():
    import aws_state
    s = aws_state.StateStore.open(":memory:")
    # v3 store still has the v1/v2 finding + account tables
    names = {r[0] for r in s._be.query_all(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"findings", "accounts", "connectors", "notification_log"} <= names


# ── renderers: golden shapes ────────────────────────────────────────────────────
def test_render_jira_description_is_adf_not_string():
    body = cc.render_jira(_conn(), _finding(), fingerprint="a" * 40)
    desc = body["fields"]["description"]
    assert desc["type"] == "doc" and desc["version"] == 1
    assert isinstance(desc["content"], list) and desc["content"]
    assert body["fields"]["summary"].startswith("[OverWatch] S3-01")
    assert body["fields"]["priority"]["name"] == "High"          # HIGH -> High


def test_render_jira_labels_have_no_spaces():
    body = cc.render_jira(_conn(), _finding(), fingerprint="deadbeef")
    for lbl in body["fields"]["labels"]:
        assert " " not in lbl
    assert "overwatch" in body["fields"]["labels"]
    assert "attack-path" in body["fields"]["labels"]
    assert any(lbl.startswith("owfp-") for lbl in body["fields"]["labels"])


def test_render_jira_priority_omitted_when_disabled():
    c = _conn(config={"site": "https://x.atlassian.net", "email": "b@x", "project_key": "SEC",
                      "set_priority": False})
    body = cc.render_jira(c, _finding())
    assert "priority" not in body["fields"]


def test_render_slack_has_text_fallback_and_block_limits():
    c = _conn(type="slack", config={"mode": "chat", "channel": "C0123"})
    body = cc.render_slack(c, _finding(), hub_base="https://hub.example.com")
    assert body["text"]                                          # fallback ALWAYS
    assert body["channel"] == "C0123"                            # chat mode only
    header = next(b for b in body["blocks"] if b["type"] == "header")
    assert header["text"]["type"] == "plain_text" and len(header["text"]["text"]) <= 150
    sec = next(b for b in body["blocks"] if b["type"] == "section" and "fields" in b)
    assert len(sec["fields"]) <= 10


def test_render_slack_webhook_mode_omits_channel():
    c = _conn(type="slack", config={"mode": "webhook"})
    body = cc.render_slack(c, _finding())
    assert "channel" not in body


def test_render_pagerduty_severity_is_lowercase_enum_and_dedup_stable():
    c = _conn(type="pagerduty", config={"region": "us"})
    body = cc.render_pagerduty(c, _finding())
    assert body["payload"]["severity"] == "error"               # HIGH -> error
    assert body["dedup_key"] == "overwatch:123456789012:S3-01"
    assert body["event_action"] == "trigger"
    assert "routing_key" not in body                            # injected at send


def test_render_splunk_targets_event_endpoint_fields_flat():
    c = _conn(type="splunk", config={"host": "hec.example.com", "port": 8088,
                                     "index": "cloudsec", "sourcetype": "overwatch:finding"})
    body = cc.render_splunk(c, _finding())
    assert body["index"] == "cloudsec"
    assert isinstance(body["event"]["compliance"], dict)        # nested dict stays in event
    assert all(not isinstance(v, (dict, list)) for v in body["fields"].values())
    assert "time" not in body                                   # omitted -> HEC receipt time


def test_render_webhook_is_byte_stable():
    c = _conn(type="webhook", config={"url": "https://hooks.example.com/x"})
    f = _finding()
    b1 = cc.render_webhook(c, f, event_id="ow_evt_1", now_epoch=1721600000)
    b2 = cc.render_webhook(c, f, event_id="ow_evt_1", now_epoch=1721600000)
    assert b1 == b2 and isinstance(b1, bytes)
    env = json.loads(b1)
    assert env["type"] == "overwatch.finding" and env["severity"] == "HIGH"
    assert env["severity_rank"] == 4 and env["data"]["check_id"] == "S3-01"


# ── request assembly: auth built from the transient secret ─────────────────────
def test_request_jira_builds_basic_auth_from_email_and_token():
    import base64
    c = _conn()
    req = cc.request_for(c, {"fields": {}}, "MY-TOKEN")
    auth = req.headers["Authorization"]
    assert auth.startswith("Basic ")
    decoded = base64.b64decode(auth.split(" ", 1)[1]).decode()
    assert decoded == "bot@acme.com:MY-TOKEN"                   # NOT the token alone
    assert req.url == "https://acme.atlassian.net/rest/api/3/issue"


def test_request_slack_chat_uses_bearer_webhook_uses_secret_url():
    chat = _conn(type="slack", config={"mode": "chat", "channel": "C1"})
    r1 = cc.request_for(chat, {"text": "x"}, "xoxb-123")
    assert r1.headers["Authorization"] == "Bearer xoxb-123"
    assert r1.url == "https://slack.com/api/chat.postMessage"
    hook = _conn(type="slack", config={"mode": "webhook"})
    r2 = cc.request_for(hook, {"text": "x"}, "https://hooks.slack.com/services/T/B/XYZ")
    assert r2.url == "https://hooks.slack.com/services/T/B/XYZ"
    assert "Authorization" not in r2.headers


def test_request_pagerduty_puts_routing_key_in_body_not_header():
    c = _conn(type="pagerduty", config={"region": "eu"})
    req = cc.request_for(c, {"event_action": "trigger", "payload": {}}, "RKEY")
    assert req.json_body["routing_key"] == "RKEY"
    assert "Authorization" not in req.headers
    assert req.url == "https://events.eu.pagerduty.com/v2/enqueue"


def test_request_splunk_uses_splunk_scheme_not_bearer():
    c = _conn(type="splunk", config={"host": "h", "port": 8088, "scheme": "https"})
    req = cc.request_for(c, {"event": {}}, "HECTOKEN")
    assert req.headers["Authorization"] == "Splunk HECTOKEN"
    assert req.url == "https://h:8088/services/collector/event"


def test_request_webhook_signs_exact_bytes_with_both_schemes():
    import base64
    import hashlib
    import hmac
    c = _conn(type="webhook", config={"url": "https://hooks.example.com/x"})
    raw = cc.render_webhook(c, _finding(), event_id="ow_evt_xyz", now_epoch=1721600000)
    req = cc.request_for(c, raw, "SIGNING-SECRET", event_id="ow_evt_xyz", now_epoch=1721600000)
    assert req.raw_body == raw                                  # posts the exact signed bytes
    key = b"SIGNING-SECRET"
    gh = hmac.new(key, raw, hashlib.sha256).hexdigest()
    assert req.headers["X-Hub-Signature-256"] == f"sha256={gh}"
    content = b"ow_evt_xyz.1721600000." + raw
    sig = base64.b64encode(hmac.new(key, content, hashlib.sha256).digest()).decode()
    assert req.headers["webhook-signature"] == f"v1,{sig}"


def test_request_webhook_unsigned_when_no_secret():
    c = _conn(type="webhook", config={"url": "https://hooks.example.com/x"}, secret_ref=None)
    req = cc.request_for(c, b"{}", None)
    assert "webhook-signature" not in req.headers


# ── response decode ─────────────────────────────────────────────────────────────
def test_interpret_jira_201_extracts_key_and_browse_link():
    c = _conn()
    res = cc.interpret_response(c, cc.HttpResp(201, json.dumps({"key": "SEC-9", "id": "1"})))
    assert res.ok and res.external_ref == "SEC-9"
    assert "browse/SEC-9" in res.detail


def test_interpret_slack_chat_200_but_ok_false_is_failure():
    c = _conn(type="slack", config={"mode": "chat", "channel": "C1"})
    res = cc.interpret_response(c, cc.HttpResp(200, json.dumps({"ok": False, "error": "channel_not_found"})))
    assert not res.ok and "channel_not_found" in res.error


def test_interpret_slack_webhook_ok_body():
    c = _conn(type="slack", config={"mode": "webhook"})
    assert cc.interpret_response(c, cc.HttpResp(200, "ok")).ok
    assert not cc.interpret_response(c, cc.HttpResp(403, "no_service")).ok


def test_interpret_pagerduty_needs_202_and_success():
    c = _conn(type="pagerduty", config={})
    good = cc.interpret_response(c, cc.HttpResp(202, json.dumps({"status": "success", "dedup_key": "d"})))
    assert good.ok and good.external_ref == "d"
    bad = cc.interpret_response(c, cc.HttpResp(400, json.dumps({"status": "invalid event", "errors": ["bad severity"]})))
    assert not bad.ok and "bad severity" in bad.error


def test_interpret_splunk_code_zero_is_success():
    c = _conn(type="splunk", config={})
    assert cc.interpret_response(c, cc.HttpResp(200, json.dumps({"text": "Success", "code": 0}))).ok
    assert not cc.interpret_response(c, cc.HttpResp(403, json.dumps({"text": "Invalid token", "code": 4}))).ok


# ── secret handling / leak guards ──────────────────────────────────────────────
def test_store_secret_rejects_schemeless_ref():
    with pytest.raises(ValueError):
        cc.store_secret("c1", "plaintext", secret_writer=lambda cid, v: "just-a-literal")
    ref = cc.store_secret("c1", "plaintext", secret_writer=_writer)
    assert ref.startswith("secretsmanager://")


def test_store_secret_rejects_too_short_secret():
    with pytest.raises(ValueError):
        cc.store_secret("c1", "short", secret_writer=_writer)      # < 8 chars


def test_scrub_redacts_any_length_secret():
    # the belt-and-suspenders backstop must not have a length hole
    assert "abc" not in cc._scrub("bad token abc echoed", "abc")
    assert "***" in cc._scrub("bad token abc echoed", "abc")


def test_mask_connector_never_exposes_secret():
    store = cc.ConnectorStore.open(":memory:")
    store.upsert_connector("c1", now_epoch=1, type="jira", name="J",
                           config={"site": "https://x.atlassian.net"},
                           secret_ref="secretsmanager://real/secret/value", enabled=True)
    c = store.get_connector("c1")
    masked = cc.ConnectorStore._mask_connector(c)
    assert "secret_ref" not in masked
    assert masked["secret_configured"] is True
    assert "real/secret/value" not in json.dumps(masked)


def test_dispatch_scrubs_secret_from_echoed_error():
    secret = "SUPERSECRETTOKEN123"
    c = _conn(enabled=True)
    # operator tool echoes the token back in a 401 body
    post, _ = _fake_poster(cc.HttpResp(401, f'{{"errorMessages":["bad creds {secret}"]}}'))
    res = cc.dispatch(c, _finding(), http_post=post, secret_reader=_reader(secret), now_epoch=1)
    assert not res.ok
    assert secret not in (res.error or "")
    assert "***" in (res.error or "")


def test_dispatch_disabled_connector_is_noop():
    c = _conn(enabled=False)
    post, calls = _fake_poster(cc.HttpResp(201, "{}"))
    res = cc.dispatch(c, _finding(), http_post=post, secret_reader=_reader(), now_epoch=1)
    assert not res.ok and not calls                            # NO http call made


def test_ledger_never_stores_the_resolved_secret():
    secret = "TOKENvalue987654"
    store = cc.ConnectorStore.open(":memory:")
    store.upsert_connector("c1", now_epoch=1, type="jira", name="J",
                           config={"site": "https://x.atlassian.net", "email": "b@x", "project_key": "SEC"},
                           secret_ref="secretsmanager://x", enabled=True)
    store.upsert_rule("c1", now_epoch=1, spec={"name": "r", "min_severity": "HIGH"})
    post, _ = _fake_poster(cc.HttpResp(201, json.dumps({"key": "SEC-1"})))
    cc.run_rules(store, [_finding()], {("123456789012", "S3-01")},
                 http_post=post, secret_reader=_reader(secret), now_epoch=10)
    blob = json.dumps(store.list_deliveries("c1"))
    assert secret not in blob


# ── rule truth-table ────────────────────────────────────────────────────────────
def test_rule_min_severity_floor():
    assert cc.rule_matches(_rule(min_severity="HIGH"), _finding(severity="HIGH"))
    assert cc.rule_matches(_rule(min_severity="HIGH"), _finding(severity="CRITICAL"))
    assert not cc.rule_matches(_rule(min_severity="HIGH"), _finding(severity="MEDIUM"))


def test_rule_not_check_globs_veto():
    r = _rule(check_globs=["S3-*"], not_check_globs=["S3-01"])
    assert not cc.rule_matches(r, _finding(check_id="S3-01"))
    assert cc.rule_matches(r, _finding(check_id="S3-02"))


def test_rule_on_attack_path_tristate():
    assert cc.rule_matches(_rule(on_attack_path=None), _finding(on_path=True))
    assert cc.rule_matches(_rule(on_attack_path=None), _finding(on_path=False))
    assert cc.rule_matches(_rule(on_attack_path=True), _finding(on_path=True))
    assert not cc.rule_matches(_rule(on_attack_path=True), _finding(on_path=False))


def test_rule_frameworks_and_status_and_thresholds():
    assert cc.rule_matches(_rule(frameworks=["PCI-DSS"]), _finding())
    assert not cc.rule_matches(_rule(frameworks=["HIPAA"]), _finding())
    assert not cc.rule_matches(_rule(statuses=["WARN"]), _finding(status="FAIL"))
    assert not cc.rule_matches(_rule(min_distinct=10), _finding())      # distinct=3 < 10
    assert cc.rule_matches(_rule(min_distinct=2), _finding())


def test_rule_severities_allowlist_overrides_default_high_floor():
    """A rule authored with only sub-HIGH severities (min_severity left at its
    default 'HIGH') must still match — the explicit allowlist is authoritative."""
    r = _rule(min_severity="HIGH", severities=["LOW", "MEDIUM"])
    assert cc.rule_matches(r, _finding(severity="LOW"))
    assert cc.rule_matches(r, _finding(severity="MEDIUM"))
    assert not cc.rule_matches(r, _finding(severity="HIGH"))            # not in the allowlist
    # the store round-trip preserves it (min_severity column defaults to HIGH)
    store = cc.ConnectorStore.open(":memory:")
    store.upsert_connector("c1", now_epoch=1, type="slack", name="S", config={}, enabled=True)
    rid = store.upsert_rule("c1", now_epoch=1, spec={"severities": ["LOW", "MEDIUM"]})
    hydrated = store.get_rule(rid)
    assert cc.rule_matches(hydrated, _finding(severity="LOW"))


# ── match_finding: fan-out, collapse, ordering ─────────────────────────────────
def test_match_finding_disabled_or_absent_connector_yields_nothing():
    f = _finding()
    conns = {"c1": _conn(enabled=False)}
    assert cc.match_finding([_rule(connector_ids=["c1"])], f, conns) == []
    assert cc.match_finding([_rule(connector_ids=["missing"])], f, {}) == []


def test_match_finding_collapses_two_rules_to_same_connector():
    f = _finding()
    conns = {"c1": _conn(enabled=True)}
    r1 = _rule(id=1, priority=10, connector_ids=["c1"])
    r2 = _rule(id=2, priority=20, connector_ids=["c1"])
    actions = cc.match_finding([r1, r2], f, conns)
    assert len(actions) == 1                                    # collapsed per (conn, dedup_key)
    assert actions[0].rule_id == 1                              # highest-priority wins


def test_match_finding_stop_on_match_halts_lower_rules():
    f = _finding()
    conns = {"c1": _conn(enabled=True), "c2": cc.Connector("c2", "slack", "c2", True, {"mode": "webhook"}, "secretsmanager://y")}
    r1 = _rule(id=1, priority=10, connector_ids=["c1"], stop_on_match=True)
    r2 = _rule(id=2, priority=20, connector_ids=["c2"])
    actions = cc.match_finding([r1, r2], f, conns)
    assert {a.connector_id for a in actions} == {"c1"}


# ── plan() state machine ────────────────────────────────────────────────────────
def _action(dedup="dk1", rule_id=1, fp="fp-a", kind="new"):
    return cc.ConnectorAction(connector_id="c1", rule_id=rule_id, account="123456789012",
                              check_id="S3-01", identity="123456789012|S3-01", dedup_key=dedup,
                              fingerprint=fp, severity="HIGH", kind=kind, finding=_finding())


def test_plan_new_then_suppressed_on_unchanged_rerun():
    rules = {1: _rule(id=1, dedup_mode="notify_once")}
    sends, ups = cc.plan([_action()], {}, now_epoch=100, rules_by_id=rules)
    assert len(sends) == 1 and sends[0].kind == "new"
    # feed the resulting (DELIVERED) ledger row back — a re-run suppresses
    row = cc.LedgerRow(connector_id="c1", dedup_key="dk1", account="123456789012",
                       check_id="S3-01", rule_id=1, state="open", kind="new", fingerprint="fp-a",
                       first_notified_epoch=100, last_notified_epoch=100, notify_count=1,
                       status="sent", id=1)
    sends2, _ = cc.plan([_action()], {"dk1": row}, now_epoch=200, rules_by_id=rules)
    assert sends2 == []


def test_plan_reopened_when_prior_resolved():
    rules = {1: _rule(id=1)}
    row = cc.LedgerRow("c1", "dk1", "123456789012", "S3-01", 1, "resolved", "new", "fp-a",
                       100, 100, 1, id=1)
    sends, _ = cc.plan([_action()], {"dk1": row}, now_epoch=300, rules_by_id=rules)
    assert sends and sends[0].kind == "reopened"


def test_plan_escalated_on_worsened_fingerprint():
    rules = {1: _rule(id=1, renotify_on_escalation=True)}
    row = cc.LedgerRow("c1", "dk1", "123456789012", "S3-01", 1, "open", "new", "fp-OLD",
                       100, 100, 1, status="sent", id=1)
    sends, _ = cc.plan([_action(fp="fp-NEW")], {"dk1": row}, now_epoch=150, rules_by_id=rules)
    assert sends and sends[0].kind == "escalated"


def test_plan_retries_a_failed_delivery():
    """A transient failure (status='failed', still open) must re-send next scan —
    not be permanently suppressed as if delivered."""
    rules = {1: _rule(id=1, dedup_mode="notify_once")}
    row = cc.LedgerRow("c1", "dk1", "123456789012", "S3-01", 1, "open", "new", "fp-a",
                       100, 100, 1, status="failed", id=1)
    sends, _ = cc.plan([_action()], {"dk1": row}, now_epoch=200, rules_by_id=rules)
    assert sends and sends[0].kind == "retry"


def test_plan_reminder_after_throttle_window():
    rules = {1: _rule(id=1, dedup_mode="renotify", throttle_seconds=3600)}
    row = cc.LedgerRow("c1", "dk1", "123456789012", "S3-01", 1, "open", "new", "fp-a",
                       1000, 1000, 1, status="sent", id=1)
    # inside window -> suppressed
    s1, _ = cc.plan([_action()], {"dk1": row}, now_epoch=2000, rules_by_id=rules)
    assert s1 == []
    # past window -> reminder
    s2, _ = cc.plan([_action()], {"dk1": dict_row(row)}, now_epoch=1000 + 3601, rules_by_id=rules)
    assert s2 and s2[0].kind == "reminder"


def dict_row(row):        # helper: fresh copy so plan()'s in-place snapshot edits don't bleed
    return cc.LedgerRow(**{**row.__dict__})


# ── claim idempotency ──────────────────────────────────────────────────────────
def test_claim_notification_is_idempotent():
    store = cc.ConnectorStore.open(":memory:")
    store.upsert_connector("c1", now_epoch=1, type="jira", name="J", config={}, enabled=True)
    up = cc.LedgerUpsert(action=_action(), is_new=True, state="open", kind="new",
                         fingerprint="fp-a", notify_epoch=10, notify_count=1)
    first = store.claim_notification(up, now_epoch=10)
    second = store.claim_notification(up, now_epoch=11)
    assert isinstance(first, int) and second is None           # second claim loses


def test_delete_connector_succeeds_with_a_ledger_row_present():
    """notification_log has a NOT-NULL FK to connectors; deleting a connector that
    has delivery rows must not raise a FOREIGN KEY constraint (it clears them first,
    atomically)."""
    store = cc.ConnectorStore.open(":memory:")
    store.upsert_connector("c1", now_epoch=1, type="jira", name="J", config={}, enabled=True)
    up = cc.LedgerUpsert(action=_action(), is_new=True, state="open", kind="new",
                         fingerprint="fp", notify_epoch=1, notify_count=1)
    store.claim_notification(up, now_epoch=1)
    store.delete_connector("c1")                               # must not raise
    assert store.get_connector("c1") is None
    assert store.list_deliveries("c1") == []


# ── resolve_stale coverage gating ──────────────────────────────────────────────
def test_resolve_stale_only_closes_covered_absent_findings():
    row = cc.LedgerRow("c1", "dk1", "123456789012", "S3-01", 1, "open", "new", "fp",
                       100, 100, 1, id=1)
    rules = {1: _rule(id=1, notify_on_resolve=True)}
    # covered + absent -> resolved
    acts, freed = cc.resolve_stale([row], present_dedup_keys=set(),
                                   scan_coverage={("123456789012", "S3-01")},
                                   rules_by_id=rules, now_epoch=500)
    assert freed == ["dk1"] and acts and acts[0].kind == "resolved"
    # NOT covered -> left open (no mass-close on a partial scan)
    acts2, freed2 = cc.resolve_stale([row], present_dedup_keys=set(),
                                     scan_coverage=set(), rules_by_id=rules, now_epoch=500)
    assert freed2 == [] and acts2 == []


def test_resolve_stale_keeps_still_failing_open():
    row = cc.LedgerRow("c1", "dk1", "123456789012", "S3-01", 1, "open", "new", "fp",
                       100, 100, 1, id=1)
    acts, freed = cc.resolve_stale([row], present_dedup_keys={"dk1"},
                                   scan_coverage={("123456789012", "S3-01")},
                                   rules_by_id={1: _rule(id=1)}, now_epoch=500)
    assert freed == [] and acts == []


# ── dedup_key stability (rule-change must not re-key / re-send) ─────────────────
def test_dedup_key_is_stable_across_a_change_of_winning_rule():
    """dedup_key is keyed on (connector_id, identity) ONLY — NOT rule_id — so which
    overlapping rule wins the collapse never re-keys (and thus never re-sends /
    false-resolves) an unchanged finding."""
    f = _finding()
    conns = {"c1": _conn(enabled=True)}
    a_r1 = cc.match_finding([_rule(id=1, priority=10)], f, conns)[0]
    a_r5 = cc.match_finding([_rule(id=5, priority=10)], f, conns)[0]
    assert a_r1.dedup_key == a_r5.dedup_key                     # same finding+destination
    assert a_r1.dedup_key == cc.dedup_key("c1", cc.finding_identity(f))


# ── run_rules: a failed send is retried on the next scan ───────────────────────
def test_run_rules_retries_after_a_transient_failure():
    store = cc.ConnectorStore.open(":memory:")
    store.upsert_connector("c1", now_epoch=1, type="webhook", name="W",
                           config={"url": "https://hooks.example.com/x"},
                           secret_ref="secretsmanager://x", enabled=True)
    store.upsert_rule("c1", now_epoch=1, spec={"name": "all", "min_severity": "LOW"})
    calls = {"n": 0}

    def flaky(url, *, headers, json_body=None, data=None, timeout=8.0):
        calls["n"] += 1
        return cc.HttpResp(500, "boom") if calls["n"] == 1 else cc.HttpResp(204, "")
    r1 = cc.run_rules(store, [_finding()], {("123456789012", "S3-01")},
                      http_post=flaky, secret_reader=_reader(), now_epoch=10)
    assert r1.failed == 1 and r1.sent == 0
    r2 = cc.run_rules(store, [_finding()], {("123456789012", "S3-01")},
                      http_post=flaky, secret_reader=_reader(), now_epoch=20)
    assert r2.sent == 1                                         # retried, not suppressed
    assert store.list_deliveries("c1")[0]["status"] == "sent"


# ── test_ping ───────────────────────────────────────────────────────────────────
def test_test_ping_jira_uses_GET_not_POST():
    """The harmless Jira connectivity test hits GET /rest/api/3/myself — a POST to
    /myself would 405 against real Jira. The seam must carry the verb."""
    c = _conn(type="jira", enabled=True)
    seen = {}

    def post(url, *, headers, json_body=None, data=None, timeout=8.0, method="POST"):
        seen["url"] = url; seen["method"] = method
        return cc.HttpResp(200, json.dumps({"accountId": "5b1", "displayName": "Bot"}))
    res = cc.test_ping(c, http_post=post, secret_reader=_reader(), now_epoch=1)
    assert res.ok and seen["method"] == "GET" and seen["url"].endswith("/rest/api/3/myself")


def test_test_ping_disabled_connector_sends_nothing():
    c = _conn(type="slack", enabled=False, config={"mode": "webhook"})
    calls = []

    def post(url, *, headers, json_body=None, data=None, timeout=8.0, method="POST"):
        calls.append(url); return cc.HttpResp(200, "ok")
    res = cc.test_ping(c, http_post=post, secret_reader=_reader(), now_epoch=1)
    assert not res.ok and not calls


# ── read-only-on-targets ────────────────────────────────────────────────────────
def test_run_rules_makes_no_aws_call():
    """The whole run touches ONLY http_post — no assume_role_fn/client_factory/boto3
    collaborator is ever constructed or invoked."""
    store = cc.ConnectorStore.open(":memory:")
    store.upsert_connector("c1", now_epoch=1, type="webhook", name="W",
                           config={"url": "https://hooks.example.com/x"},
                           secret_ref="secretsmanager://x", enabled=True)
    store.upsert_rule("c1", now_epoch=1, spec={"name": "all", "min_severity": "LOW"})
    posts = []

    def post(url, *, headers, json_body=None, data=None, timeout=8.0):
        posts.append(url)
        return cc.HttpResp(204, "")
    res = cc.run_rules(store, [_finding()], {("123456789012", "S3-01")},
                       http_post=post, secret_reader=_reader(), now_epoch=10)
    assert res.sent == 1
    assert all(u.startswith("https://hooks.example.com") for u in posts)   # operator tool only
