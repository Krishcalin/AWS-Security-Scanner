"""GET /scorecards — FR-2 reaching the console, and what it honestly cannot say yet.

WHAT THIS CLOSES
----------------
aws_scorecard assembled a portfolio pack from four modules and nothing called it.
This is the route, and it is deliberately the last of the four wirings rather than
the first: a scorecard is only worth serving once attribution, SLA and the
exception segregation underneath it are real.

WHAT IT CANNOT SAY YET, AND WHY THAT IS THE POINT
--------------------------------------------------
Three inputs are genuinely absent today, and the pack withholds each with a stated
reason rather than defaulting it:

  * no risk factors per application  -> every grade is WITHHELD
  * no asset counts per application  -> peer rank is WITHHELD (OW2-SC-004)
  * no prior period                  -> no trend, not "0% change"

`test_the_pack_withholds_what_it_cannot_measure` pins all three. A future commit
that wires live factors should turn grades ON and that test should be updated
deliberately; what must never happen is a grade appearing because someone defaulted
a missing factor to zero.

WHAT IS REAL
------------
Attribution and its coverage, open counts, the closure rate with its D4 exception
pairing, and OW2-SC-008 segregation driven by live waivers — one approval both
excepts the finding and pauses its clock, which is the same decision having both
of its effects.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hub import cnapp_api
from hub.cnapp_api import Principal

pytestmark = pytest.mark.skipif(not cnapp_api._HAVE_FASTAPI,
                                reason="fastapi not installed")

from store import aws_state  # noqa: E402
from hub import cnapp_application  # noqa: E402
from hub.cnapp_registry import AccountRegistry  # noqa: E402
from hub.cnapp_service import InMemoryResultStore, PlatformService  # noqa: E402
from hub.cnapp_workspace import WorkspaceStore  # noqa: E402

SUPER = Principal(subject="root", is_superadmin=True)
DAY = 86_400
T0 = 1_700_000_000
NOW = T0 + 90 * DAY
ACCT = "111111111111"
WS = "ws-a"


def _svc(with_registry=True, with_state=True):
    reg = AccountRegistry.open(":memory:")
    st = aws_state.StateStore(reg._be) if with_state else None
    return PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="a",
        cfn_template_url="b", secret_writer=lambda a, v: "ssm://x",
        secret_reader=lambda r: "x", state=st,
        workspaces=WorkspaceStore(reg._be),
        applications=(cnapp_application.ApplicationStore(reg._be)
                      if with_registry else None),
        clock=lambda: NOW)


def _client(svc):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc, current_principal=lambda: SUPER))


def _hdr():
    return {"X-Workspace-Id": WS}


def _seed(svc, findings):
    """Put an active account and some findings in front of the assembler."""
    c = _client(svc)
    c.post("/workspaces", json={"workspace_id": WS, "name": WS})
    svc.registry.upsert_account(ACCT, now_epoch=T0)
    svc.registry.set_onboarding_status(ACCT, "active", T0)
    # No bare try/except here: the first draft swallowed a failing bind and every
    # test then asserted against an empty pack for the wrong reason.
    svc.registry.bind_account(ACCT, WS, T0)
    be = svc.state._be
    for f in findings:
        be.execute(
            "INSERT INTO findings(account, finding_key, region, check_id, section, "
            "resource, message, severity, result_status, status, first_seen_epoch, "
            "first_seen_iso, last_seen_epoch, last_seen_iso, resolved_epoch, "
            "last_scan_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ACCT, f["k"], "global", f.get("check", "IAM-01"), "IAM",
             f.get("resource", "arn:" + f["k"]), "m", f["sev"], "FAIL",
             f.get("status", "open"), f.get("first", T0), "i",
             f.get("first", T0), "i", f.get("resolved"), "s1"))
    return c


def _app(c, **kw):
    body = {"name": "Payments", "owner": "team-pay", "criticality": "high",
            "accounts": [ACCT], **kw}
    r = c.post("/applications", json=body, headers=_hdr())
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ── the route serves a pack ─────────────────────────────────────────────────

def test_the_pack_attributes_findings_to_an_application():
    svc = _svc()
    c = _seed(svc, [{"k": "a", "sev": "CRITICAL"}, {"k": "b", "sev": "HIGH"}])
    _app(c)
    d = c.get("/scorecards", headers=_hdr()).json()
    card = [s for s in d["scorecards"] if s["name"] == "Payments"][0]
    assert card["open_critical"] == 1 and card["open_high"] == 1
    assert card["owner"] == "team-pay"


def test_the_pack_states_its_coverage_beside_the_scorecards():
    svc = _svc()
    c = _seed(svc, [{"k": "a", "sev": "HIGH"}])
    _app(c)
    d = c.get("/scorecards", headers=_hdr()).json()
    assert d["coverage"]["pct"] == 100.0
    assert d["headline"]


def test_findings_no_application_claims_get_an_unowned_row():
    svc = _svc()
    c = _seed(svc, [{"k": "a", "sev": "HIGH"}])
    # An application that matches nothing in this account.
    c.post("/applications", json={"name": "Other", "owner": "t",
                                  "criticality": "high",
                                  "accounts": ["222222222222"]}, headers=_hdr())
    d = c.get("/scorecards", headers=_hdr()).json()
    unowned = [s for s in d["scorecards"] if s["app_id"] == "__unattributed__"]
    assert unowned and unowned[0]["findings_total"] == 1
    assert unowned[0]["owner"] == ""
    assert d["coverage"]["complete"] is False


# ── what it honestly cannot say yet ────────────────────────────────────────

def test_the_pack_withholds_what_it_cannot_measure():
    """Live factors are wired now, so the REASON changed and the answer did not.

    An account with findings and a declared criticality but no graph, no ingested
    vulnerabilities and no posture history has 47% of the model measured -- below
    the 50% floor -- so the composite is refused rather than published. Updated
    deliberately when factors were wired, which is what the previous version of
    this test asked for.
    """
    svc = _svc()
    c = _seed(svc, [{"k": "a", "sev": "HIGH"}])
    _app(c)
    card = [s for s in c.get("/scorecards", headers=_hdr()).json()["scorecards"]
            if s["name"] == "Payments"][0]

    assert card["grade"] is None and card["posture"] is None
    assert "not a composite" in card["grade_withheld"]
    assert "47%" in card["grade_withheld"], "findings + criticality only"

    assert card["rank"] is None
    assert "by size, not by security" in card["rank_withheld"]

    assert card["trend"] is None
    assert any("first scorecard" in c_ for c_ in card["caveats"])


def test_an_unscanned_account_does_not_score_exposure_as_a_measured_zero():
    """The false zero this wiring nearly shipped.

    aws_factors reads `paths=[]` as "the graph was built and found nothing" and
    `paths=None` as "no graph exists". Passing [] for an account that was never
    scanned scored exposure a measured 0.0, which pushed weight coverage over the
    floor and produced a grade of B built on a fact nobody established.
    """
    svc = _svc()
    c = _seed(svc, [{"k": "a", "sev": "HIGH"}])
    _app(c)
    card = [s for s in c.get("/scorecards", headers=_hdr()).json()["scorecards"]
            if s["name"] == "Payments"][0]
    assert card["grade"] is None, (
        "no scan result means no graph means exposure is unmeasured, not zero")


# ── OW2-SC-008: a live waiver segregates AND pauses ────────────────────────

def test_a_waiver_segregates_the_finding_without_hiding_it():
    svc = _svc()
    c = _seed(svc, [{"k": "a", "sev": "CRITICAL"}, {"k": "b", "sev": "CRITICAL"}])
    _app(c)
    svc.state._be.execute(
        "INSERT INTO waivers(match_type, finding_key, account, region, approver, "
        "reason, created_epoch, expires_epoch, revoked) "
        "VALUES('exact', 'b', ?, '*', 'ciso', 'vendor patch pending', ?, ?, 0)",
        (ACCT, T0, NOW + 30 * DAY))

    card = [s for s in c.get("/scorecards", headers=_hdr()).json()["scorecards"]
            if s["name"] == "Payments"][0]
    assert card["open_critical"] == 1, "the excepted one leaves the open count"
    assert card["excepted"] == 1, "and is reported in its own field"
    assert card["findings_total"] == 2, "and is not dropped"
    assert any("counted separately" in x for x in card["caveats"])


def test_a_revoked_waiver_does_not_except_anything():
    svc = _svc()
    c = _seed(svc, [{"k": "a", "sev": "CRITICAL"}])
    _app(c)
    svc.state._be.execute(
        "INSERT INTO waivers(match_type, finding_key, account, region, approver, "
        "reason, created_epoch, expires_epoch, revoked) "
        "VALUES('exact', 'a', ?, '*', 'ciso', 'r', ?, ?, 1)",
        (ACCT, T0, NOW + 30 * DAY))
    card = [s for s in c.get("/scorecards", headers=_hdr()).json()["scorecards"]
            if s["name"] == "Payments"][0]
    assert card["excepted"] == 0 and card["open_critical"] == 1


# ── the closure rate needs closed findings, and gets them ──────────────────

def test_a_closed_finding_is_counted_so_the_rate_is_not_a_false_zero():
    """open_findings alone would report 0% closure for a team that closed
    everything -- wrong in the pessimistic direction, and equally wrong."""
    svc = _svc()
    c = _seed(svc, [{"k": "c1", "sev": "CRITICAL", "status": "resolved",
                     "resolved": T0 + 3 * DAY}])
    _app(c)
    card = [s for s in c.get("/scorecards", headers=_hdr()).json()["scorecards"]
            if s["name"] == "Payments"][0]
    assert card["sla"]["considered"] == 1
    assert card["sla"]["pct"] == 100.0


def test_the_sla_line_never_reports_a_rate_without_its_approvals():
    svc = _svc()
    c = _seed(svc, [{"k": "c1", "sev": "CRITICAL", "status": "resolved",
                     "resolved": T0 + 200 * DAY}])
    _app(c)
    svc.state._be.execute(
        "INSERT INTO waivers(match_type, finding_key, account, region, approver, "
        "reason, created_epoch, expires_epoch, revoked) "
        "VALUES('exact', 'c1', ?, '*', 'ciso', 'vendor patch pending', ?, ?, 0)",
        (ACCT, T0 + 5 * DAY, NOW + 365 * DAY))
    card = [s for s in c.get("/scorecards", headers=_hdr()).json()["scorecards"]
            if s["name"] == "Payments"][0]
    # The waiver both excepts it and pauses its clock: one approval, both effects.
    assert card["excepted"] == 1
    assert "exception" in card["sla_line"] or card["sla"]["considered"] == 0


def test_findings_for_period_returns_open_plus_resolved_since():
    svc = _svc()
    _seed(svc, [{"k": "open1", "sev": "HIGH"},
                {"k": "old", "sev": "HIGH", "status": "resolved",
                 "resolved": T0 + 1 * DAY},
                {"k": "recent", "sev": "HIGH", "status": "resolved",
                 "resolved": T0 + 80 * DAY}])
    keys = {r["finding_key"] for r in
            svc.state.findings_for_period(ACCT, since_epoch=T0 + 30 * DAY)}
    assert keys == {"open1", "recent"}, "the old closure is outside the window"
    allk = {r["finding_key"] for r in svc.state.findings_for_period(ACCT)}
    assert allk == {"open1", "old", "recent"}


# ── RBAC and availability ──────────────────────────────────────────────────

def test_a_viewer_can_read_a_scorecard():
    """An owner reading their own grade should not need write access."""
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    svc = _svc()
    c = _seed(svc, [{"k": "a", "sev": "HIGH"}])
    _app(c)
    viewer = Principal(subject="v", memberships={WS: "viewer"})
    vc = TestClient(cnapp_api.create_app(svc, current_principal=lambda: viewer))
    assert vc.get("/scorecards", headers=_hdr()).status_code == 200


def test_the_route_501s_without_the_registry_rather_than_returning_an_empty_pack():
    """An empty pack and an absent feature look identical to a console. They must
    not."""
    svc = _svc(with_registry=False)
    c = _client(svc)
    c.post("/workspaces", json={"workspace_id": WS, "name": WS})
    r = c.get("/scorecards", headers=_hdr())
    assert r.status_code == 501
    assert "application registry" in r.text


def test_the_pack_is_reproducible():
    svc = _svc()
    c = _seed(svc, [{"k": "a", "sev": "HIGH"}])
    _app(c)
    a = c.get("/scorecards", headers=_hdr()).json()
    b = c.get("/scorecards", headers=_hdr()).json()
    assert a == b
