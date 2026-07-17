"""Offline tests for cnapp_service.PlatformService — the injected-dependency facade.
Drives onboarding -> validate -> scan -> results with dict/fake collaborators and
zero boto3. Also locks serialize_scanner in lockstep with the engine's save_json."""
import json
import os
import sys
import tempfile
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_live_scanner as als
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import (InMemoryResultStore, PlatformService, ScanSpec,
                           aggregate_overview, serialize_scanner)

ACCT = "210987654321"
HUB = "arn:aws:iam::555000111222:role/CnappHubRole"


# ── fakes ─────────────────────────────────────────────────────────────────────
class FakeSession:
    def __init__(self, acct):
        self.acct = acct
    def client(self, service, **k):
        acct = self.acct
        class C:
            def get_caller_identity(self):
                return {"Account": acct}
        return C()


def _stub_client_factory(acct):
    class STS:
        def get_caller_identity(self):
            return {"Account": acct}
    class EC2:
        def describe_regions(self):
            return {"Regions": []}
    return lambda creds, svc, reg: {"sts": STS(), "ec2": EC2()}[svc]


def _result(status, cid, sec, res, msg, sev):
    return types.SimpleNamespace(status=status, check_id=cid, section=sec, resource=res,
                                 message=msg, severity=sev, compliance={}, remediation_cmd="")


def _fake_runner(session, spec):
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    return types.SimpleNamespace(
        account=session.acct, region="us-east-1", graph=g, attack_paths=[], choke_points=[],
        results=[_result("FAIL", "S3-01", "S3", "b", "public | b", "HIGH"),
                 _result("PASS", "S3-02", "S3", "c", "ok", "")])


def _svc(**over):
    reg = AccountRegistry.open(":memory:")
    clk = {"t": 1000}
    def clock():
        clk["t"] += 10
        return clk["t"]
    store = {}
    def _writer(a, v):
        ref = f"secretsmanager://x/{a}"
        store[ref] = v
        return ref
    kw = dict(
        registry=reg, results=InMemoryResultStore(), hub_role_arn=HUB,
        cfn_template_url="https://h/cnapp.yaml",
        secret_writer=_writer,
        secret_reader=lambda ref: store[ref],
        session_factory=lambda aid: FakeSession(aid),
        assume_role_fn=lambda role, xid, sess, reg_: {"k": "v"},
        client_factory=_stub_client_factory(ACCT),
        scan_runner=_fake_runner, clock=clock)
    kw.update(over)
    return PlatformService(**kw), reg


def test_onboard_registers_pending_and_returns_launch_url():
    svc, reg = _svc()
    out = svc.init_onboarding(ACCT, method="org", alias="prod")
    assert out["cfn_launch_url"].startswith("https://console.aws.amazon.com/cloudformation")
    a = reg.get_account(ACCT)
    assert a["onboarding_status"] == "pending" and a["onboarding_method"] == "org"
    assert a["role_arn"] == f"arn:aws:iam::{ACCT}:role/CnappScannerRole"


def test_validate_flips_status_active():
    svc, reg = _svc()
    svc.init_onboarding(ACCT)
    out = svc.validate_account(ACCT)
    assert out["health"] == "healthy"
    assert reg.get_account(ACCT)["onboarding_status"] == "active"


def test_validate_unauthorized_denies():
    class Boto(Exception):
        def __init__(s):
            s.response = {"Error": {"Code": "AccessDenied"}}
    svc, reg = _svc(assume_role_fn=lambda *a: (_ for _ in ()).throw(Boto()))
    svc.init_onboarding(ACCT)
    out = svc.validate_account(ACCT)
    assert out["health"] == "unauthorized"
    assert reg.get_account(ACCT)["onboarding_status"] == "denied"


def test_validate_unknown_account_raises():
    svc, reg = _svc()
    with pytest.raises(KeyError):
        svc.validate_account("999999999999")


def test_trigger_scan_only_active_accounts():
    svc, reg = _svc()
    svc.init_onboarding(ACCT)                      # pending
    reg.upsert_account("998877665544", now_epoch=1)
    reg.set_onboarding_status("998877665544", "active", 2)
    # all=True enqueues only the active one
    jids = svc.trigger_scan(all=True)
    assert len(jids) == 1
    assert reg.get_scan_job(jids[0])["account_id"] == "998877665544"
    # explicit pending id is filtered out
    assert svc.trigger_scan([ACCT]) == []


def test_list_accounts_masks_secret_ref():
    svc, reg = _svc()
    svc.init_onboarding(ACCT)
    a = svc.list_accounts()[0]
    assert "external_id_ref" not in a
    assert a["external_id_configured"] is True


def test_get_issues_filters_fail_warn():
    svc, reg = _svc()
    svc.results.put(ACCT, {"results": [
        {"status": "FAIL", "check_id": "S3-01", "severity": "HIGH"},
        {"status": "PASS", "check_id": "S3-02", "severity": ""},
        {"status": "WARN", "check_id": "IAM-09", "severity": "MEDIUM"}]})
    ids = {i["check_id"] for i in svc.get_issues(ACCT)}
    assert ids == {"S3-01", "IAM-09"}
    assert [i["check_id"] for i in svc.get_issues(ACCT, severity="HIGH")] == ["S3-01"]


def test_serialize_scanner_lockstep_with_save_json():
    """serialize_scanner mirrors save_json field-for-field (plus graph_full)."""
    sc = als.AWSLiveScanner(region="us-east-1", sections=["S3"])
    sc.account = ACCT
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("arn:aws:s3:::crown", "S3Bucket", crown_jewel=True)
    sc.graph = g
    sc.results = [_result("FAIL", "S3-01", "S3", "b", "public | b", "HIGH"),
                  _result("PASS", "S3-02", "S3", "c", "ok", "")]
    sc.attack_paths = []
    sc.choke_points = []
    d = serialize_scanner(sc)
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "o.json")
        sc.save_json(p)
        sj = json.loads(open(p, encoding="utf-8").read())
    for k in ("account", "region", "posture_score", "posture_grade", "summary",
              "compliance_scorecard", "graph", "attack_paths", "choke_points"):
        assert d[k] == sj[k], f"field {k} diverged from save_json"
    assert d["graph_full"] == g.to_dict()
    assert d["posture_score"] == als.compute_risk_score(sc.results)


def test_org_overview_aggregates_active_accounts():
    svc, reg = _svc()
    # two active accounts with stored payloads
    for aid, fails, crit in [("111111111111", 2, 1), ("222222222222", 0, 0)]:
        reg.upsert_account(aid, now_epoch=1)
        reg.set_onboarding_status(aid, "active", 2)
        svc.results.put(aid, {
            "account": aid, "region": "us-east-1", "posture_score": 100 - 15 * fails,
            "summary": {"PASS": 5, "FAIL": fails, "WARN": 0, "INFO": 0},
            "attack_paths": [{"severity": "CRITICAL", "terminal_kind": "data",
                              "terminal": f"arn:aws:s3:::pii-{aid}", "score": 90}] * crit,
            "choke_points": []})
    ov = svc.org_overview()
    assert ov["accounts_scanned"] == 2
    assert ov["summary"]["FAIL"] == 2
    assert ov["critical_attack_paths"] == 1
    assert ov["crown_jewels_at_risk"] == 1
    assert ov["accounts"][0]["critical_paths"] == 1        # sorted worst-first


def test_aggregate_overview_pure_empty():
    ov = aggregate_overview([])
    assert ov["accounts_scanned"] == 0 and ov["org_posture_score"] == 100.0
    assert ov["critical_attack_paths"] == 0
