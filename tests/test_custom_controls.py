"""User-authored Controls: validation, tenancy, and the guarantees that bound them.

WHAT THIS FEATURE CHANGED
-------------------------
A Control -- a saved WQL query that surfaces as a finding -- already existed, but only
as `CNAPP_CONTROLS`: an environment variable, read once at boot, identical for every
workspace, editable only by whoever could restart the server. This makes it an authored
object with CRUD, per-workspace persistence, and an optional compliance binding.

THE THREE PROPERTIES THAT MATTER, AND WHY
------------------------------------------
1. **The WQL validator runs on WRITE.** A control carries a query against the security
   graph. If a bad query were only caught at read time it would become an inert control
   that silently matches nothing forever, and the author would believe it was watching
   something. `aws_wql.parse` is the typed, bounded security boundary and it must reject
   at authoring time, with a message.

2. **A control cannot cross a workspace.** Controls surface as findings in every account
   in their workspace. One tenant's authored query appearing in another tenant's console
   is a cross-tenant data leak, so every read and write is workspace-explicit and the
   tests below assert isolation in both directions.

3. **An authored control can never move the posture score.** `aws_controls.control_finding`
   emits WARN and the score counts FAIL. That is what stops a customer from authoring a
   query that grades their own posture -- which would make the number meaningless as a
   comparison. It is asserted here rather than assumed, because it is the property most
   likely to be "fixed" by someone who thinks WARN is a bug.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_controls  # noqa: E402
import cnapp_backend  # noqa: E402
import cnapp_customcontrol as cc  # noqa: E402

GOOD_QUERY = {"kind": "S3Bucket",
              "where": {"pred": "prop", "field": "public", "op": "eq", "value": True}}


@pytest.fixture()
def store(tmp_path):
    be = cnapp_backend.backend_for(f"sqlite:///{tmp_path/'t.db'}", check_same_thread=False)
    return cc.CustomControlStore(be, now=lambda: 1000)


def body(**kw):
    return {"name": "Public buckets", "query": GOOD_QUERY, **kw}


# ── validation ──────────────────────────────────────────────────────────────
def test_a_valid_control_normalizes_to_the_shape_the_renderer_consumes():
    """The stored shape IS aws_controls.control_finding's input -- no translation layer,
    so a control cannot render differently from how it was authored."""
    c = cc.validate(body(severity="HIGH", description="d", remediation_cmd="aws s3api ..."))
    assert set(c) >= {"id", "name", "query", "severity", "section", "compliance",
                      "remediation_cmd", "enabled"}
    finding = aws_controls.control_finding(c, "123456789012", [{"id": "arn:x", "kind": "S3Bucket"}])
    assert finding["check_id"].startswith(aws_controls.CONTROL_PREFIX)
    assert finding["severity"] == "HIGH"


def test_a_malformed_query_is_rejected_at_authoring_time_not_silently_inert():
    """THE point of validating on write. An unknown WQL predicate must be a message to
    the author, not a control that matches nothing for the next year."""
    with pytest.raises(cc.ControlError) as e:
        cc.validate(body(query={"kind": "S3Bucket", "where": {"pred": "nope"}}))
    assert "not valid WQL" in str(e.value)


@pytest.mark.parametrize("bad", [None, "", "   "])
def test_a_control_must_be_named(bad):
    with pytest.raises(cc.ControlError):
        cc.validate({"name": bad, "query": GOOD_QUERY})


def test_a_control_must_carry_a_query():
    with pytest.raises(cc.ControlError):
        cc.validate({"name": "x"})


def test_an_unknown_severity_is_rejected_rather_than_defaulted():
    """aws_controls.control_severity silently defaults an unknown band to MEDIUM. That is
    right at render time and wrong at authoring time -- an author who typed 'SEV1' should
    be told, not quietly given a MEDIUM."""
    with pytest.raises(cc.ControlError):
        cc.validate(body(severity="SEV1"))


def test_the_query_is_stored_PARSED_so_it_cannot_read_back_as_something_else():
    c = cc.validate(body())
    import aws_wql
    assert c["query"] == aws_wql.parse(GOOD_QUERY)


def test_an_oversized_query_is_refused():
    huge = {"kind": "S3Bucket", "where": {"pred": "or", "of": [
        {"pred": "prop", "field": "name", "op": "eq", "value": "x" * 400}
        for _ in range(60)]}}
    with pytest.raises(cc.ControlError):
        cc.validate(body(query=huge))


@pytest.mark.parametrize("field,limit", [("name", cc.MAX_NAME),
                                         ("description", cc.MAX_DESCRIPTION),
                                         ("remediation_cmd", cc.MAX_REMEDIATION)])
def test_oversized_text_fields_are_refused(field, limit):
    with pytest.raises(cc.ControlError):
        cc.validate(body(**{field: "x" * (limit + 1)}))


def test_compliance_must_map_strings_to_strings():
    with pytest.raises(cc.ControlError):
        cc.validate(body(compliance={"PCI-DSS": 11}))


def test_a_compliance_binding_survives_validation():
    """The half of this feature that makes a customer's own check count toward their own
    framework."""
    c = cc.validate(body(compliance={"PCI-DSS": "1.2.1", "SOC2": "CC6.6"}))
    assert c["compliance"] == {"PCI-DSS": "1.2.1", "SOC2": "CC6.6"}


# ── CRUD ────────────────────────────────────────────────────────────────────
def test_create_then_read_back(store):
    made = store.create("ws-a", body(), created_by="alice")
    assert made["id"] and made["created_by"] == "alice" and made["source"] == "custom"
    assert store.get("ws-a", made["id"])["name"] == "Public buckets"


def test_update_changes_only_what_was_sent(store):
    made = store.create("ws-a", body(description="original"))
    out = store.update("ws-a", made["id"], {"severity": "CRITICAL"})
    assert out["severity"] == "CRITICAL"
    assert out["description"] == "original"          # not clobbered by the partial update


def test_update_revalidates_the_query(store):
    made = store.create("ws-a", body())
    with pytest.raises(cc.ControlError):
        store.update("ws-a", made["id"], {"query": {"where": {"pred": "nope"}}})


def test_update_of_a_missing_control_returns_none_not_an_error(store):
    assert store.update("ws-a", "c-nope", {"severity": "LOW"}) is None


def test_delete_reports_whether_it_deleted_anything(store):
    made = store.create("ws-a", body())
    assert store.delete("ws-a", made["id"]) is True
    assert store.delete("ws-a", made["id"]) is False


def test_a_duplicate_name_in_the_same_workspace_is_refused(store):
    store.create("ws-a", body())
    with pytest.raises(cc.ControlError):
        store.create("ws-a", body())


def test_the_per_workspace_cap_is_enforced(store, monkeypatch):
    monkeypatch.setattr(cc, "MAX_CONTROLS_PER_WORKSPACE", 2)
    store.create("ws-a", body(name="one"))
    store.create("ws-a", body(name="two"))
    with pytest.raises(cc.ControlError):
        store.create("ws-a", body(name="three"))


# ── tenancy: the property whose failure is a data leak ──────────────────────
def test_two_workspaces_may_each_have_a_control_with_the_same_name(store):
    """Name uniqueness is per workspace. A global unique index would let one tenant
    block a name for every other tenant."""
    store.create("ws-a", body())
    store.create("ws-b", body())          # must not raise
    assert len(store.list("ws-a")) == 1 and len(store.list("ws-b")) == 1


def test_a_control_is_not_visible_from_another_workspace(store):
    made = store.create("ws-a", body())
    assert store.get("ws-b", made["id"]) is None
    assert store.list("ws-b") == []


def test_a_control_cannot_be_updated_from_another_workspace(store):
    made = store.create("ws-a", body())
    assert store.update("ws-b", made["id"], {"severity": "LOW"}) is None
    assert store.get("ws-a", made["id"])["severity"] == "MEDIUM"


def test_a_control_cannot_be_deleted_from_another_workspace(store):
    made = store.create("ws-a", body())
    assert store.delete("ws-b", made["id"]) is False
    assert store.get("ws-a", made["id"]) is not None


def test_enabled_only_filters(store):
    store.create("ws-a", body(name="on"))
    off = store.create("ws-a", body(name="off"))
    store.update("ws-a", off["id"], {"enabled": False})
    assert [c["name"] for c in store.list("ws-a", enabled_only=True)] == ["on"]


# ── the guarantee that bounds the whole feature ─────────────────────────────
def test_an_authored_control_renders_as_WARN_and_can_never_be_FAIL(store):
    """THE invariant. The posture score counts FAIL findings, baked at scan time. If an
    authored control could emit FAIL, a customer could author a query that moves the
    number they are being measured on, and the score would stop meaning anything across
    accounts. Every severity band must still render WARN."""
    for sev in cc.SEVERITIES:
        c = cc.validate(body(name=f"n-{sev}", severity=sev))
        f = aws_controls.control_finding(c, "123456789012", [{"id": "arn:x", "kind": "S3Bucket"}])
        assert f["status"] == "WARN", f"{sev} rendered as {f['status']}"


def test_a_control_whose_stored_query_is_corrupt_degrades_to_inert(store):
    """Read-time fail-safe. A row whose JSON will not decode must not take the whole
    control list down with it -- cnapp_service then drops it for having no query."""
    made = store.create("ws-a", body())
    store._be.execute("UPDATE custom_controls SET query_json=? WHERE control_id=?",
                      ("{not json", made["id"]))
    rows = store.list("ws-a")
    assert len(rows) == 1 and rows[0]["query"] is None
