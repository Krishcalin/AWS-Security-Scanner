"""The Application registry, reachable.

WHAT THIS CLOSES
----------------
`cnapp_application` shipped as a tested library with no caller: the table existed,
the store worked, and nothing in the product could create an application. Six
specification defects were fixed in modules the console never reached, and this is
the first of them being wired.

THE THREE PROPERTIES THAT MATTER AT THE API BOUNDARY
-----------------------------------------------------
1. **Writes are admin, reads are auditor.** An Application decides WHOSE findings
   these are and who receives the scorecard. Editing one re-attributes other
   people's work, which is an administrative act rather than a viewer action.

2. **An application cannot cross a workspace.** Attribution assigns a customer's
   findings to an owner; leaking that across a tenant boundary would put one
   customer's estate on another customer's scorecard. Asserted in both directions.

3. **Warnings ride along with the object.** A mis-scoped application does not fail
   loudly -- it renders a scorecard, reports zero findings, and is
   indistinguishable from one that is genuinely clean. The 201 carries the
   warnings so the console can say so at the moment of saving, rather than leaving
   the author to infer it from a suspiciously good grade weeks later.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_api
from cnapp_api import Principal

pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI,
                                reason="fastapi not installed")

import aws_state  # noqa: E402
import cnapp_application  # noqa: E402
from cnapp_registry import AccountRegistry  # noqa: E402
from cnapp_service import InMemoryResultStore, PlatformService  # noqa: E402
from cnapp_workspace import WorkspaceStore  # noqa: E402

SUPER = Principal(subject="root", is_superadmin=True)


def _svc(with_registry=True):
    reg = AccountRegistry.open(":memory:")
    return PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="a",
        cfn_template_url="b", secret_writer=lambda a, v: "ssm://x",
        secret_reader=lambda r: "x", state=aws_state.StateStore(reg._be),
        workspaces=WorkspaceStore(reg._be),
        applications=(cnapp_application.ApplicationStore(reg._be)
                      if with_registry else None),
        clock=lambda: 5000)


def _client(svc=None, principal=SUPER):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc or _svc(),
                                           current_principal=lambda: principal))


def _ws(c, wsid="ws-a"):
    c.post("/workspaces", json={"workspace_id": wsid, "name": wsid})
    return wsid


BODY = {"name": "Payments", "owner": "team-payments", "criticality": "high",
        "accounts": ["111111111111"]}


def _hdr(wsid):
    return {"X-Workspace-Id": wsid}


# ── the route exists and round-trips ────────────────────────────────────────

def test_create_then_get_round_trips(client_ws=None):
    c = _client()
    ws = _ws(c)
    made = c.post("/applications", json=BODY, headers=_hdr(ws))
    assert made.status_code == 201, made.text
    app_id = made.json()["id"]

    got = c.get(f"/applications/{app_id}", headers=_hdr(ws))
    assert got.status_code == 200
    body = got.json()
    assert body["name"] == "Payments"
    assert body["owner"] == "team-payments"
    assert body["accounts"] == ["111111111111"]


def test_list_returns_what_was_created():
    c = _client()
    ws = _ws(c)
    c.post("/applications", json=BODY, headers=_hdr(ws))
    c.post("/applications", json={**BODY, "name": "Analytics"}, headers=_hdr(ws))
    names = {a["name"] for a in c.get("/applications", headers=_hdr(ws)).json()}
    assert names == {"Payments", "Analytics"}


def test_update_merges_and_get_reflects_it():
    c = _client()
    ws = _ws(c)
    app_id = c.post("/applications", json=BODY, headers=_hdr(ws)).json()["id"]
    up = c.put(f"/applications/{app_id}", json={"criticality": "crown-jewel"},
               headers=_hdr(ws))
    assert up.status_code == 200
    assert up.json()["criticality"] == "crown-jewel"
    assert up.json()["owner"] == "team-payments", "unspecified fields survive"


def test_delete_then_get_is_404():
    c = _client()
    ws = _ws(c)
    app_id = c.post("/applications", json=BODY, headers=_hdr(ws)).json()["id"]
    assert c.delete(f"/applications/{app_id}", headers=_hdr(ws)).status_code == 204
    assert c.get(f"/applications/{app_id}", headers=_hdr(ws)).status_code == 404


def test_unknown_application_is_404_not_500():
    c = _client()
    ws = _ws(c)
    assert c.get("/applications/nope", headers=_hdr(ws)).status_code == 404
    assert c.put("/applications/nope", json={"owner": "x"},
                 headers=_hdr(ws)).status_code == 404
    assert c.delete("/applications/nope", headers=_hdr(ws)).status_code == 404


# ── validation surfaces as 400, not as a stored mistake ────────────────────

def test_a_key_only_tag_selector_is_a_400_with_the_reason():
    c = _client()
    ws = _ws(c)
    r = c.post("/applications",
               json={**BODY, "tag_selectors": [{"key": "App", "value": ""}]},
               headers=_hdr(ws))
    assert r.status_code == 400
    assert "claims every resource" in r.text


def test_a_malformed_account_id_is_a_400():
    c = _client()
    ws = _ws(c)
    r = c.post("/applications", json={**BODY, "accounts": ["11111111111"]},
               headers=_hdr(ws))
    assert r.status_code == 400
    assert "12-digit" in r.text


def test_an_unknown_criticality_is_rejected_by_the_model():
    c = _client()
    ws = _ws(c)
    r = c.post("/applications", json={**BODY, "criticality": "extremely"},
               headers=_hdr(ws))
    assert r.status_code == 422, "the pattern on the request model catches it first"


def test_a_duplicate_name_is_a_400_not_a_second_row():
    c = _client()
    ws = _ws(c)
    c.post("/applications", json=BODY, headers=_hdr(ws))
    r = c.post("/applications", json=BODY, headers=_hdr(ws))
    assert r.status_code == 400 and "already exists" in r.text
    assert len(c.get("/applications", headers=_hdr(ws)).json()) == 1


# ── warnings ride along with the object ────────────────────────────────────

def test_an_application_with_no_owner_is_created_with_a_warning():
    c = _client()
    ws = _ws(c)
    r = c.post("/applications", json={**BODY, "owner": ""}, headers=_hdr(ws))
    assert r.status_code == 201, "a missing owner warns; it does not refuse"
    assert any("accountable owner" in w for w in r.json()["warnings"])


def test_an_application_that_can_never_match_says_so_at_save_time():
    c = _client()
    ws = _ws(c)
    r = c.post("/applications",
               json={"name": "Ghost", "owner": "t", "criticality": "high"},
               headers=_hdr(ws))
    assert r.status_code == 201
    assert any("always score as clean" in w for w in r.json()["warnings"])


def test_a_fully_specified_application_warns_about_nothing():
    c = _client()
    ws = _ws(c)
    assert c.post("/applications", json=BODY,
                  headers=_hdr(ws)).json()["warnings"] == []


def test_warnings_appear_on_read_and_update_too():
    c = _client()
    ws = _ws(c)
    app_id = c.post("/applications", json={**BODY, "owner": ""},
                    headers=_hdr(ws)).json()["id"]
    assert c.get(f"/applications/{app_id}", headers=_hdr(ws)).json()["warnings"]
    assert c.get("/applications", headers=_hdr(ws)).json()[0]["warnings"]
    cleared = c.put(f"/applications/{app_id}", json={"owner": "team-x"},
                    headers=_hdr(ws))
    assert cleared.json()["warnings"] == [], "fixing it clears the warning"


# ── tenancy: both directions ───────────────────────────────────────────────

def test_the_same_name_is_allowed_in_a_different_workspace():
    c = _client()
    a, b = _ws(c, "ws-a"), _ws(c, "ws-b")
    assert c.post("/applications", json=BODY, headers=_hdr(a)).status_code == 201
    assert c.post("/applications", json=BODY, headers=_hdr(b)).status_code == 201, (
        "two tenants may each run an application called Payments")


def test_an_application_is_invisible_from_another_workspace():
    c = _client()
    a, b = _ws(c, "ws-a"), _ws(c, "ws-b")
    app_id = c.post("/applications", json=BODY, headers=_hdr(a)).json()["id"]
    assert c.get("/applications", headers=_hdr(b)).json() == []
    assert c.get(f"/applications/{app_id}", headers=_hdr(b)).status_code == 404


def test_an_application_is_not_writable_from_another_workspace():
    """Attribution decides whose findings these are. Editing across a tenant
    boundary would put one customer's estate on another customer's scorecard."""
    c = _client()
    a, b = _ws(c, "ws-a"), _ws(c, "ws-b")
    app_id = c.post("/applications", json=BODY, headers=_hdr(a)).json()["id"]
    assert c.put(f"/applications/{app_id}", json={"owner": "attacker"},
                 headers=_hdr(b)).status_code == 404
    assert c.delete(f"/applications/{app_id}", headers=_hdr(b)).status_code == 404
    assert c.get(f"/applications/{app_id}",
                 headers=_hdr(a)).json()["owner"] == "team-payments"


def test_the_workspace_header_is_actually_honoured():
    """Guards the tests above from being vacuous: if the header were ignored and
    everything landed in one default workspace, isolation would 'pass' trivially."""
    c = _client()
    a, b = _ws(c, "ws-a"), _ws(c, "ws-b")
    c.post("/applications", json=BODY, headers=_hdr(a))
    c.post("/applications", json={**BODY, "name": "Other"}, headers=_hdr(b))
    assert [x["name"] for x in c.get("/applications", headers=_hdr(a)).json()] == ["Payments"]
    assert [x["name"] for x in c.get("/applications", headers=_hdr(b)).json()] == ["Other"]


# ── RBAC ───────────────────────────────────────────────────────────────────

def test_a_viewer_can_read_but_not_write():
    """An Application decides who receives the scorecard and whose work is whose.
    Authoring one is administrative; reading the registry is not."""
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    svc = _svc()
    admin = TestClient(cnapp_api.create_app(svc, current_principal=lambda: SUPER))
    ws = _ws(admin)
    admin.post("/applications", json=BODY, headers=_hdr(ws))

    viewer = Principal(subject="v", memberships={ws: "viewer"})
    vc = TestClient(cnapp_api.create_app(svc, current_principal=lambda: viewer))
    assert vc.get("/applications", headers=_hdr(ws)).status_code == 200
    assert vc.post("/applications", json={**BODY, "name": "X"},
                   headers=_hdr(ws)).status_code == 403
    assert vc.delete("/applications/whatever", headers=_hdr(ws)).status_code == 403


# ── the deployment may not have the registry at all ────────────────────────

def test_routes_501_when_the_registry_is_not_enabled():
    c = _client(_svc(with_registry=False))
    ws = _ws(c)
    for call in (lambda: c.get("/applications", headers=_hdr(ws)),
                 lambda: c.post("/applications", json=BODY, headers=_hdr(ws))):
        r = call()
        assert r.status_code == 501, r.text
        assert "not enabled" in r.text
