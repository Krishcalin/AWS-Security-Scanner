"""Connector + CDR tenant isolation (a wired WorkspaceStore): cross-tenant connector 404
per route, rule_id cross-read 404, delivery scoped to the account's workspace, id-less
reads scoped, CDR /org/incidents + per-account isolation, and the single-tenant
(no WorkspaceStore) byte-identical guarantee. Skips if fastapi absent."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_api
from cnapp_api import Principal

pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI, reason="fastapi not installed")

import aws_state
import cnapp_connectors as cc
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService
from cnapp_workspace import WorkspaceStore

A_ACCT = "111111111111"
B_ACCT = "222222222222"


def _svc(*, multitenant=True):
    reg = AccountRegistry.open(":memory:")
    ws = WorkspaceStore(reg._be) if multitenant else None
    results = InMemoryResultStore()
    svc = PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=aws_state.StateStore(reg._be),
        workspaces=ws, clock=lambda: 5000)
    if multitenant:
        ws.create_workspace("ws-a", name="Acme", now_epoch=1)
        ws.create_workspace("ws-b", name="Beta", now_epoch=1)
        for acct, w in ((A_ACCT, "ws-a"), (B_ACCT, "ws-b")):
            reg.upsert_account(acct, now_epoch=1)
            reg.set_onboarding_status(acct, "active", 1)
            reg.bind_account(acct, w, now_epoch=1)
            results.put(acct, {"account": acct, "finding_catalog": [],
                               "attack_paths": [], "results": []})
    return svc


def _client(principal, svc):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc, current_principal=lambda: principal))


def _member(ws, role="admin"):
    return Principal(subject="u@x", memberships={ws: role})


_SEQ = [0]


def _connector(svc, workspace_id, name=None):
    """Create a connector bound to a workspace (via the service); return its id.
    Names are globally unique (a connectors.name UNIQUE constraint), so auto-number."""
    _SEQ[0] += 1
    return svc.create_connector(type="slack", name=name or f"c{_SEQ[0]}", config={},
                                workspace_id=workspace_id)["connector_id"]


# ── list + per-route cross-tenant isolation ──────────────────────────────────
def test_tenant_lists_only_own_connectors():
    svc = _svc()
    _connector(svc, "ws-a", "a1")
    _connector(svc, "ws-b", "b1")
    ca = _client(_member("ws-a"), svc)
    got = {c["name"] for c in ca.get("/connectors", headers={"X-Workspace-Id": "ws-a"}).json()}
    assert got == {"a1"}


def test_cross_tenant_connector_routes_are_404():
    svc = _svc()
    cid_b = _connector(svc, "ws-b")
    ca = _client(_member("ws-a"), svc)
    H = {"X-Workspace-Id": "ws-a"}
    assert ca.get(f"/connectors/{cid_b}", headers=H).status_code == 404
    assert ca.put(f"/connectors/{cid_b}", json={"name": "x"}, headers=H).status_code == 404
    assert ca.post(f"/connectors/{cid_b}/enable", json={"enabled": True}, headers=H).status_code == 404
    assert ca.post(f"/connectors/{cid_b}/rotate-secret", json={"secret": "topsecret123"},
                   headers=H).status_code == 404
    assert ca.post(f"/connectors/{cid_b}/test", headers=H).status_code == 404
    assert ca.delete(f"/connectors/{cid_b}", headers=H).status_code == 404
    assert ca.get(f"/connectors/{cid_b}/rules", headers=H).status_code == 404
    assert ca.get(f"/connectors/{cid_b}/deliveries", headers=H).status_code == 404
    assert ca.get(f"/connectors/{cid_b}/digests", headers=H).status_code == 404
    # …and A's own connector IS reachable
    cid_a = _connector(svc, "ws-a")
    assert ca.get(f"/connectors/{cid_a}", headers=H).status_code == 200


def test_connector_created_bound_to_caller_workspace_and_hidden_from_others():
    svc = _svc()
    ca = _client(_member("ws-a"), svc)
    cid = ca.post("/connectors", json={"type": "slack", "name": "n", "config": {}},
                  headers={"X-Workspace-Id": "ws-a"}).json()["connector_id"]
    assert svc.workspaces.workspace_of_connector(cid) == "ws-a"
    cb = _client(_member("ws-b"), svc)
    assert cb.get(f"/connectors/{cid}", headers={"X-Workspace-Id": "ws-b"}).status_code == 404


def test_rule_id_cross_read_is_404():
    svc = _svc()
    store = svc._require_connectors()
    cid_a = _connector(svc, "ws-a")
    cid_b = _connector(svc, "ws-b")
    rid_b = store.upsert_rule(cid_b, now_epoch=1, spec={"name": "rb"})
    ca = _client(_member("ws-a"), svc)
    # A owns cid_a (gate passes), but rid_b belongs to B's connector -> 404, never B's rule body
    r = ca.put(f"/connectors/{cid_a}/rules/{rid_b}", json={"spec": {"name": "hijack"}},
               headers={"X-Workspace-Id": "ws-a"})
    assert r.status_code == 404


# ── delivery-path scoping (structural: the mechanism the isolation relies on) ─
def test_delivery_path_loads_only_the_accounts_workspace_connectors():
    svc = _svc()
    store = svc._require_connectors()
    cid_a = _connector(svc, "ws-a")
    cid_b = _connector(svc, "ws-b")
    # the workspace resolved for delivering A's account's notifications is ws-a …
    assert svc._account_ws(A_ACCT) == "ws-a"
    # … so run_rules loads ONLY ws-a's connectors — B's is structurally invisible to the
    # match gate (connectors.get(cid_b) is None) ⇒ cross-tenant delivery is impossible.
    loaded = {c.connector_id for c in store.list_connectors(workspace_id=svc._account_ws(A_ACCT))}
    assert loaded == {cid_a} and cid_b not in loaded


# ── CDR isolation (regression lock — no CDR code change) ─────────────────────
def test_cdr_cross_tenant_account_incidents_404():
    ca = _client(_member("ws-a", role="viewer"), _svc())
    H = {"X-Workspace-Id": "ws-a"}
    assert ca.get(f"/accounts/{B_ACCT}/incidents", headers=H).status_code == 404
    assert ca.get(f"/accounts/{A_ACCT}/incidents", headers=H).status_code == 200


def test_cdr_org_incidents_excludes_other_tenant():
    svc = _svc()
    svc.state.upsert_cdr_detection(B_ACCT, {"id": "d-b", "source": "guardduty", "type": "x",
                                            "title": "B incident", "severity": "HIGH",
                                            "incident": True, "priority_score": 90}, 100)
    ca = _client(_member("ws-a", role="viewer"), svc)
    assert ca.get("/org/incidents", headers={"X-Workspace-Id": "ws-a"}).json() == []   # excluded
    cb = _client(_member("ws-b", role="viewer"), svc)
    assert len(cb.get("/org/incidents", headers={"X-Workspace-Id": "ws-b"}).json()) == 1   # B sees it


# ── adversarial-verify regressions ────────────────────────────────────────────
def test_preview_rules_scoped_to_workspace():
    # the dry-run must NOT leak another tenant's connectors/rules (twin of run_rules).
    svc = _svc()
    store = svc._require_connectors()
    cid_a = _connector(svc, "ws-a")
    cid_b = _connector(svc, "ws-b")
    for cid in (cid_a, cid_b):                       # both would match a HIGH finding globally
        svc.set_connector_enabled(cid, True)
        store.upsert_rule(cid, now_epoch=1, spec={"name": f"r-{cid}", "min_severity": "LOW",
                                                  "account_glob": "*", "status_filter": "FAIL"})
    svc.results.put(A_ACCT, {"account": A_ACCT, "attack_paths": [], "results": [],
                             "finding_catalog": [{"check_id": "IAM-01", "severity": "CRITICAL",
                                                  "status": "FAIL", "section": "IAM",
                                                  "affected": ["r1"], "risk": "x", "impact": "y",
                                                  "steps": ["s"], "count": 1}]})
    rows = svc.preview_rules(A_ACCT)                 # A previews their OWN account
    fired = {r.get("connector_id") for r in rows}
    assert cid_a in fired                            # A's connector fires (proves the match works)
    assert cid_b not in fired                        # …but B's is never even loaded (scoped)


def test_delete_workspace_with_bound_connector_is_clean_400_not_500():
    svc = _svc()
    _connector(svc, "ws-b")                          # bind a connector to ws-b
    # detach ws-b's account so the ACCOUNT guard doesn't mask the CONNECTOR guard under test
    svc.workspaces._be.execute("DELETE FROM workspace_accounts WHERE workspace_id=?", ("ws-b",))
    with pytest.raises(ValueError):                  # a clean guard, never an opaque IntegrityError/500
        svc.workspaces.delete_workspace("ws-b")


def test_duplicate_connector_name_is_clean_400_not_500():
    svc = _svc()
    svc.create_connector(type="slack", name="dupe", config={}, workspace_id="ws-a")
    with pytest.raises(ValueError):                  # graceful (never a 500), no tenant disclosed
        svc.create_connector(type="slack", name="dupe", config={}, workspace_id="ws-b")


# ── single-tenant (no WorkspaceStore) byte-identical: gate never 404s, global ─
def test_single_tenant_connectors_are_global():
    svc = _svc(multitenant=False)
    cid1 = svc.create_connector(type="slack", name="c1", config={})["connector_id"]
    svc.create_connector(type="slack", name="c2", config={})
    ca = _client(Principal(subject="root", is_superadmin=True), svc)
    assert len(ca.get("/connectors").json()) == 2          # all connectors, unscoped
    assert ca.get(f"/connectors/{cid1}").status_code == 200   # connector_gate never 404s
