"""The Application registry: the storage AD-02 needed and nobody had.

WHAT THIS CLOSES
----------------
`aws_ownership` already knew how to attribute a finding to an application and how to
report what it could not attribute. It had nowhere for an application to LIVE:
`Application` was a dataclass a caller constructed by hand, so FR-2 scorecards had no
registry to be per-application about, and AD-02 -- the dependency OW2-SRS-001 files as
an *assumption* -- stayed unsatisfiable in practice.

THE THREE PROPERTIES THAT MATTER
---------------------------------
1. **Validation runs on WRITE, and the dataclass IS the rule set.** `validate()`
   constructs a real `aws_ownership.Application`, so the registry and the attributor
   cannot disagree about what a valid application is. A rule added to one is enforced
   by the other for free.

2. **A mis-scoped application does not fail loudly.** It renders a scorecard, reports
   zero findings, and is indistinguishable from an application that is genuinely clean.
   That is why `warnings_for` exists and why it reuses `attribution_health` rather than
   restating its rules -- the save-time warning and the scan-time report must not drift.

3. **Fatal rejects, warning does not.** An operator mid-onboarding may legitimately
   create an application before its owner is known. Refusing that would push the
   registry into a spreadsheet, where nothing validates it at all.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_ownership  # noqa: E402
from hub import cnapp_application as ca  # noqa: E402
from store import cnapp_backend  # noqa: E402

WS, OTHER = "ws-1", "ws-2"


@pytest.fixture()
def store(tmp_path):
    be = cnapp_backend.backend_for(f"sqlite:///{tmp_path/'t.db'}",
                                   check_same_thread=False)
    return ca.ApplicationStore(be, now=lambda: 1000)


def body(**kw):
    return {"name": "Payments", "owner": "team-payments", "criticality": "high",
            "accounts": ["111111111111"], **kw}


# ── validation is the ownership dataclass ───────────────────────────────────

def test_a_valid_body_normalizes_to_the_shape_the_attributor_consumes():
    rec = ca.validate(body(portfolio="digital"))
    app = ca.as_application(rec)
    assert isinstance(app, aws_ownership.Application)
    assert app.app_id == rec["id"] and app.owner == "team-payments"
    # And it actually attributes.
    att = aws_ownership.attribute("arn:x", {}, "111111111111", [app])
    assert att.app_id == rec["id"] and att.rule == aws_ownership.RULE_ACCOUNT


def test_a_key_only_tag_selector_is_rejected_at_authoring_time():
    # aws_ownership refuses it because it would claim every resource bearing the
    # key. The registry must refuse it too, with the same reason.
    with pytest.raises(ca.ApplicationError, match="claims every resource"):
        ca.validate(body(tag_selectors=[{"key": "App", "value": ""}]))


def test_an_unknown_criticality_is_rejected():
    with pytest.raises(ca.ApplicationError, match="criticality"):
        ca.validate(body(criticality="extremely"))


def test_a_name_is_required():
    with pytest.raises(ca.ApplicationError, match="needs a name"):
        ca.validate(body(name="  "))


def test_a_malformed_account_id_is_rejected_rather_than_owning_nothing():
    with pytest.raises(ca.ApplicationError, match="12-digit"):
        ca.validate(body(accounts=["11111111111"]))       # 11 digits


def test_a_comma_joined_string_is_rejected_not_silently_one_selector():
    with pytest.raises(ca.ApplicationError, match="matches nothing"):
        ca.validate(body(accounts="111111111111,222222222222"))


def test_selectors_accept_both_object_and_pair_form():
    a = ca.validate(body(tag_selectors=[{"key": "App", "value": "pay"}]))
    b = ca.validate(body(tag_selectors=[["App", "pay"]]))
    assert a["tag_selectors"] == b["tag_selectors"] == (("App", "pay"),)


def test_a_malformed_selector_says_what_shape_was_expected():
    with pytest.raises(ca.ApplicationError, match="key, value"):
        ca.validate(body(tag_selectors=["App=pay"]))


def test_duplicate_accounts_and_arns_are_deduped_in_order():
    rec = ca.validate(body(accounts=["111111111111", "111111111111",
                                     "222222222222"]))
    assert rec["accounts"] == ("111111111111", "222222222222")


def test_an_id_is_generated_when_absent_and_validated_when_supplied():
    assert ca.validate(body())["id"].startswith("app-")
    assert ca.validate(body(id="payments"))["id"] == "payments"
    with pytest.raises(ca.ApplicationError, match="lowercase alphanumeric"):
        ca.validate(body(id="Payments Prod!"))


# ── warnings do not reject, and reuse attribution_health ────────────────────

def test_an_application_with_no_owner_is_saved_with_a_warning_not_refused():
    rec = ca.validate(body(owner=""))
    w = ca.warnings_for(rec)
    assert any("accountable owner" in x for x in w)


def test_an_application_with_no_selectors_warns_that_it_will_always_score_clean():
    rec = ca.validate({"name": "Ghost", "owner": "t", "criticality": "high"})
    assert any("always score as clean" in x for x in ca.warnings_for(rec))


def test_unclassified_criticality_warns_rather_than_being_treated_as_standard():
    rec = ca.validate({"name": "X", "owner": "t", "accounts": ["111111111111"]})
    assert any("crown-jewel prioritisation" in x for x in ca.warnings_for(rec))


def test_a_fully_specified_application_warns_about_nothing():
    assert ca.warnings_for(ca.validate(body())) == ()


def test_warnings_come_from_attribution_health_not_a_restatement():
    # If the two drifted, a save-time warning would disagree with the scan-time
    # health report about the same application.
    rec = ca.validate(body(owner=""))
    app = ca.as_application(rec)
    assert set(ca.warnings_for(rec)) == {
        i.detail for i in aws_ownership.attribution_health([app])}


# ── CRUD ────────────────────────────────────────────────────────────────────

def test_create_then_get_round_trips_every_field(store):
    made = store.create(WS, body(portfolio="digital",
                                 tag_selectors=[["App", "pay"]],
                                 resource_arns=["arn:aws:s3:::pay"]),
                        created_by="alice")
    got = store.get(WS, made["id"])
    assert got["name"] == "Payments" and got["owner"] == "team-payments"
    assert got["criticality"] == "high" and got["portfolio"] == "digital"
    assert got["accounts"] == ("111111111111",)
    assert got["tag_selectors"] == (("App", "pay"),)
    assert got["resource_arns"] == ("arn:aws:s3:::pay",)
    assert got["created_by"] == "alice"


def test_list_is_ordered_and_scoped(store):
    store.create(WS, body(name="Zulu"))
    store.create(WS, body(name="Alpha"))
    assert [a["name"] for a in store.list(WS)] == ["Alpha", "Zulu"]


def test_update_merges_and_revalidates(store):
    made = store.create(WS, body())
    up = store.update(WS, made["id"], {"criticality": "crown-jewel"})
    assert up["criticality"] == "crown-jewel"
    assert up["owner"] == "team-payments", "unspecified fields survive the merge"
    with pytest.raises(ca.ApplicationError):
        store.update(WS, made["id"], {"criticality": "nonsense"})


def test_update_of_an_unknown_application_returns_none(store):
    assert store.update(WS, "nope", {"owner": "x"}) is None


def test_delete_reports_whether_anything_was_removed(store):
    made = store.create(WS, body())
    assert store.delete(WS, made["id"]) is True
    assert store.delete(WS, made["id"]) is False
    assert store.get(WS, made["id"]) is None


def test_duplicate_name_in_the_same_workspace_is_refused(store):
    store.create(WS, body())
    with pytest.raises(ca.ApplicationError, match="already exists"):
        store.create(WS, body(name="payments"))       # case-insensitive


def test_the_workspace_limit_is_enforced(store, monkeypatch):
    monkeypatch.setattr(ca, "MAX_APPS_PER_WORKSPACE", 2)
    store.create(WS, body(name="A"))
    store.create(WS, body(name="B"))
    with pytest.raises(ca.ApplicationError, match="limit 2"):
        store.create(WS, body(name="C"))


# ── tenancy: both directions ────────────────────────────────────────────────

def test_the_same_name_is_allowed_in_a_different_workspace(store):
    store.create(WS, body())
    other = store.create(OTHER, body())
    assert other["name"] == "Payments", (
        "two tenants may each run an application called Payments")


def test_an_application_is_not_readable_from_another_workspace(store):
    made = store.create(WS, body())
    assert store.get(OTHER, made["id"]) is None
    assert store.list(OTHER) == []


def test_an_application_is_not_writable_from_another_workspace(store):
    made = store.create(WS, body())
    assert store.update(OTHER, made["id"], {"owner": "attacker"}) is None
    assert store.delete(OTHER, made["id"]) is False
    assert store.get(WS, made["id"])["owner"] == "team-payments"


# ── the bridge to attribution ───────────────────────────────────────────────

def test_applications_returns_the_registry_ready_to_attribute(store):
    store.create(WS, body(name="Payments", accounts=["111111111111"]))
    # Deliberately NOT via body(): its default accounts would make Analytics claim
    # the same account, and attribution would correctly return AMBIGUOUS. That is
    # asserted separately below.
    store.create(WS, {"name": "Analytics", "owner": "team-data",
                      "criticality": "high",
                      "tag_selectors": [["App", "analytics"]]})
    apps = store.applications(WS)
    assert len(apps) == 2
    assert all(isinstance(a, aws_ownership.Application) for a in apps)

    findings = [{"resource": "arn:a", "account": "111111111111"},
                {"resource": "arn:b", "account": "999999999999"}]
    buckets, cov = aws_ownership.attribute_findings(findings, apps)
    assert cov.attributed == 1 and cov.unattributed == 1
    assert aws_ownership.UNATTRIBUTED in buckets


def test_two_stored_applications_claiming_one_account_are_ambiguous(store):
    """The refusal to guess survives the round-trip through storage.

    Two applications that each claim account 111111111111 contest every finding in
    it. Awarding the finding to whichever row the database returned first would make
    ownership depend on ORDER BY, which is how a tool bills the wrong team.
    """
    store.create(WS, body(name="Payments"))
    store.create(WS, body(name="Billing"))          # same default account
    buckets, cov = aws_ownership.attribute_findings(
        [{"resource": "arn:a", "account": "111111111111"}], store.applications(WS))
    assert cov.ambiguous == 1 and cov.attributed == 0
    _, att = buckets[aws_ownership.UNATTRIBUTED][0]
    assert att.rule == aws_ownership.AMBIGUOUS
    assert len(att.candidates) == 2


def test_applications_of_an_empty_workspace_is_empty_not_an_error(store):
    assert store.applications(OTHER) == ()


# ── read-time fail-safe ─────────────────────────────────────────────────────

def test_unreadable_stored_json_degrades_that_list_not_the_registry(store):
    made = store.create(WS, body(tag_selectors=[["App", "pay"]]))
    store._be.execute(
        "UPDATE applications SET tag_selectors_json='{not json' WHERE app_id=?",
        (made["id"],))
    got = store.get(WS, made["id"])
    assert got is not None, "one bad column must not take the registry down"
    assert got["tag_selectors"] == ()
    assert got["accounts"] == ("111111111111",), "the other columns survive"


# ── schema ──────────────────────────────────────────────────────────────────

def test_the_applications_table_exists_in_both_dialects():
    from store import aws_state
    from store import aws_state_dialect
    assert "CREATE TABLE IF NOT EXISTS applications(" in aws_state._DDL
    assert any("applications(" in d for d in aws_state_dialect.POSTGRES_DDL)
    assert aws_state.SCHEMA_VERSION >= 17
