"""OW2-AR-002 baseline rules: shipped enabled, and honest about two of the five.

WHAT THIS CLOSES
----------------
The SRS says five rules "shall ship enabled (configurable thereafter)". They did
not exist, so every connector -- including the ServiceDesk Plus one -- fired
nothing until an operator hand-authored a rule. A ticketing integration that files
no tickets is the quietest kind of not-working.

THE TWO TESTS THAT MATTER
-------------------------
1. `test_two_rules_declare_the_gap_between_ar002_and_what_we_can_do`. Three of the
   five map cleanly onto the connector plane. Rule (b) asks for a *change record*
   and rule (e) for a *workflow*; OverWatch has neither, so both file tickets and
   SAY SO -- in the rule name, which reaches the console and the delivery ledger.
   Silently redefining "raise a change record" as "file a ticket" and calling
   AR-002 satisfied is the failure this test exists to prevent.

2. `test_rules_ship_enabled_but_the_connector_does_not`. "Shall ship enabled" and
   "safe by default" look contradictory and are not: the rules are seeded ON while
   the connector is created OFF, so turning it on stays a deliberate act.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_connectors as C  # noqa: E402


# ── the catalogue ───────────────────────────────────────────────────────────

def test_all_five_ar002_clauses_are_present():
    refs = {r["srs"] for r in C.BASELINE_RULES}
    assert refs == {"OW2-AR-002(%s)" % c for c in "abcde"}


def test_two_rules_declare_the_gap_between_ar002_and_what_we_can_do():
    gaps = {r["srs"]: r["gap"] for r in C.BASELINE_RULES if r["gap"]}
    assert "OW2-AR-002(b)" in gaps and "change record" in gaps["OW2-AR-002(b)"]
    assert "OW2-AR-002(e)" in gaps and "not a workflow" in gaps["OW2-AR-002(e)"]


def test_the_gap_reaches_the_rule_name_not_only_this_file():
    """A caveat only a developer can read is not a caveat."""
    b = [r for r in C.BASELINE_RULES if r["srs"] == "OW2-AR-002(b)"][0]
    name = C.baseline_rule_spec(b)["name"]
    assert "change record" in name, "the gap must be visible in the console"


def test_the_root_usage_rule_records_that_five_minutes_is_not_its_to_promise():
    d = [r for r in C.BASELINE_RULES if r["srs"] == "OW2-AR-002(d)"][0]
    assert "scan cadence" in d["gap"], (
        "the <=5-minute window is a delivery-latency property, not a predicate")


def test_only_two_rules_are_fully_clean():
    clean = {r["srs"] for r in C.BASELINE_RULES if not r["gap"]}
    assert clean == {"OW2-AR-002(a)", "OW2-AR-002(c)"}, (
        "a, c are clean; d matches but qualifies its latency claim")


# ── the globs point at checks that exist ────────────────────────────────────

def test_every_baseline_glob_matches_a_real_check():
    """A glob that matches nothing fails SILENTLY, which is the whole problem
    this rule set exists to solve."""
    import fnmatch
    import aws_live_scanner as als
    known = set(als.CHECK_SEVERITY)
    for rule in C.BASELINE_RULES:
        for glob in rule["spec"]["check_globs"]:
            hits = [k for k in known if fnmatch.fnmatchcase(k, glob)]
            assert hits, "%s: glob %r matches no known check" % (rule["srs"], glob)


def test_the_public_bucket_rule_targets_the_public_bucket_checks():
    a = [r for r in C.BASELINE_RULES if r["srs"] == "OW2-AR-002(a)"][0]
    assert set(a["spec"]["check_globs"]) == {"S3-01", "S3-09"}


def test_the_mfa_rule_targets_user_mfa_not_root_mfa():
    c = [r for r in C.BASELINE_RULES if r["srs"] == "OW2-AR-002(c)"][0]
    assert c["spec"]["check_globs"] == ["IAM-04"], (
        "AR-002(c) is 'user without MFA'; IAM-01 is the root MFA check")


def test_the_vuln_rule_only_fires_on_critical():
    b = [r for r in C.BASELINE_RULES if r["srs"] == "OW2-AR-002(b)"][0]
    assert b["spec"]["min_severity"] == "CRITICAL"


def test_root_usage_outranks_everything_else():
    by_srs = {r["srs"]: r["spec"]["priority"] for r in C.BASELINE_RULES}
    assert by_srs["OW2-AR-002(d)"] < min(
        v for k, v in by_srs.items() if k != "OW2-AR-002(d)")


# ── suitability per connector type ──────────────────────────────────────────

def test_a_ticketing_connector_gets_every_rule():
    assert len(C.baseline_rules_for("sdp")) == 5
    assert len(C.baseline_rules_for("jira")) == 5


def test_pagerduty_only_gets_the_page_worthy_one():
    """Paging on-call at 3am for a misconfiguration nobody can act on is how an
    integration gets muted, and a muted integration reports zero."""
    rules = C.baseline_rules_for("pagerduty")
    assert [r["srs"] for r in rules] == ["OW2-AR-002(d)"]


def test_an_unknown_connector_type_gets_nothing_rather_than_everything():
    assert C.baseline_rules_for("nope") == []
    assert C.baseline_rules_for("") == []


def test_the_catalogue_is_not_mutated_by_a_caller():
    first = C.baseline_rules_for("sdp")
    first[0]["name"] = "clobbered"
    assert C.baseline_rules_for("sdp")[0]["name"] != "clobbered"


# ── the seeded spec ─────────────────────────────────────────────────────────

def test_a_seeded_rule_is_enabled_and_names_its_clause():
    spec = C.baseline_rule_spec(C.BASELINE_RULES[0])
    assert spec["enabled"] is True
    assert spec["name"].startswith("OW2-AR-002(a) - ")
    assert spec["created_by"] == "baseline"


def test_the_spec_round_trips_through_the_rule_matcher():
    """The rules must actually match findings, not merely store cleanly."""
    rule = C.ConnectorRule(id=1, connector_id="c1",
                           **{k: v for k, v in C.BASELINE_RULES[0]["spec"].items()
                              if k != "priority"})
    hit = C.EnrichedFinding(
        check_id="S3-09", section="S3", severity="HIGH", status="FAIL",
        compliance={}, remediation_cmd="", risk="", impact="", steps=[],
        affected=["arn:aws:s3:::b"], count=1, distinct=1, account="1" * 12)
    miss = C.EnrichedFinding(
        check_id="EC2-04", section="EC2", severity="HIGH", status="FAIL",
        compliance={}, remediation_cmd="", risk="", impact="", steps=[],
        affected=["i-1"], count=1, distinct=1, account="1" * 12)
    assert C.rule_matches(rule, hit) is True
    assert C.rule_matches(rule, miss) is False


def test_a_low_severity_finding_does_not_trip_the_critical_vuln_rule():
    b = [r for r in C.BASELINE_RULES if r["srs"] == "OW2-AR-002(b)"][0]
    rule = C.ConnectorRule(id=1, connector_id="c1",
                           **{k: v for k, v in b["spec"].items() if k != "priority"})
    low = C.EnrichedFinding(
        check_id="VULN-01", section="VULN", severity="HIGH", status="FAIL",
        compliance={}, remediation_cmd="", risk="", impact="", steps=[],
        affected=["i-1"], count=1, distinct=1, account="1" * 12)
    assert C.rule_matches(rule, low) is False, "CRITICAL floor means CRITICAL"


# ── seeding, end to end ─────────────────────────────────────────────────────

def _svc(tmp_path):
    import aws_state
    import cnapp_backend
    from cnapp_registry import AccountRegistry
    from cnapp_service import InMemoryResultStore, PlatformService
    from cnapp_workspace import WorkspaceStore
    reg = AccountRegistry.open(str(tmp_path / "t.db"))
    store = C.ConnectorStore(reg._be)
    svc = PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="a",
        cfn_template_url="b", secret_writer=lambda a, v: "ssm://x",
        secret_reader=lambda r: "x", state=aws_state.StateStore(reg._be),
        workspaces=WorkspaceStore(reg._be), connectors=store, clock=lambda: 5000)
    return svc, store


def test_rules_ship_enabled_but_the_connector_does_not(tmp_path):
    """OW2-AR-002 says the rules ship enabled; safe-by-default says a connector
    does not send until told to. Both hold: the rules are ON and nothing fires."""
    svc, store = _svc(tmp_path)
    out = svc.create_connector(type="sdp", name="SDP", config={},
                               secret="a-long-enough-token")
    assert out["enabled"] is False, "the connector is off until enabled"
    rules = store.list_rules(out["connector_id"])
    assert len(rules) == 5 and all(r.enabled for r in rules)


def test_what_was_armed_comes_back_with_the_connector(tmp_path):
    """A rule the operator cannot see is a rule they cannot disable."""
    svc, _ = _svc(tmp_path)
    out = svc.create_connector(type="sdp", name="SDP", config={},
                               secret="a-long-enough-token")
    armed = out["baseline_rules"]
    assert len(armed) == 5
    assert any(a["gap"] for a in armed), "the two gaps travel out through the API"


def test_seeding_can_be_declined(tmp_path):
    svc, store = _svc(tmp_path)
    out = svc.create_connector(type="jira", name="J", config={},
                               secret="a-long-enough-token", seed_baseline=False)
    assert store.list_rules(out["connector_id"]) == []
    assert out["baseline_rules"] == []


def test_pagerduty_is_seeded_only_with_the_page_worthy_rule(tmp_path):
    svc, store = _svc(tmp_path)
    out = svc.create_connector(type="pagerduty", name="PD", config={},
                               secret="a-long-enough-token")
    assert len(store.list_rules(out["connector_id"])) == 1


# ── the constraint that rejected sdp, and the error that lied about it ──────

def test_an_existing_database_is_migrated_to_accept_sdp(tmp_path):
    """CREATE TABLE IF NOT EXISTS never touches an existing table, so a database
    created before ServiceDesk Plus keeps the five-type CHECK however it is
    stamped -- and the symptom is a connector that cannot be created."""
    import sqlite3
    import aws_state_dialect
    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.executescript(
        "CREATE TABLE connectors("
        " connector_id TEXT PRIMARY KEY,"
        " type TEXT NOT NULL CHECK(type IN "
        "  ('jira','slack','pagerduty','splunk','webhook')),"
        " name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,"
        " config_json TEXT NOT NULL DEFAULT '{}', secret_ref TEXT, created_by TEXT,"
        " last_test_at INTEGER, last_test_status TEXT, last_test_detail TEXT,"
        " created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);")
    old.execute("INSERT INTO connectors(connector_id,type,name,created_at,updated_at)"
                " VALUES('c-old','jira','Legacy',1,1)")
    old.commit()
    assert aws_state_dialect.sqlite_needs_connector_type_upgrade(old) is True
    old.close()

    import cnapp_backend
    be = cnapp_backend.backend_for("sqlite:///" + path, check_same_thread=False)
    row = be.query_one("SELECT sql FROM sqlite_master WHERE name='connectors'")
    assert "'sdp'" in dict(row)["sql"], "the rebuild widened the CHECK"
    kept = be.query_all("SELECT connector_id FROM connectors")
    assert [dict(r)["connector_id"] for r in kept] == ["c-old"], (
        "the existing connector survived the table rebuild")


def test_the_rebuild_does_not_cascade_away_existing_rules(tmp_path):
    """connector_rules cascades on a connectors delete. A rebuild that drops the
    parent table with foreign keys ON silently deletes every rule in the hub."""
    import cnapp_backend
    path = str(tmp_path / "r.db")
    be = cnapp_backend.backend_for("sqlite:///" + path, check_same_thread=False)
    store = C.ConnectorStore(be)
    store.upsert_connector("c1", now_epoch=1, type="jira", name="J", config={})
    store.upsert_rule("c1", now_epoch=1, spec={"name": "keepme"})
    assert len(store.list_rules("c1")) == 1

    # Force the old CHECK back, then reopen so the rebuild runs over real data.
    be.execute("UPDATE connectors SET type='jira'")
    raw = be.raw
    raw.execute("PRAGMA foreign_keys=OFF")
    raw.executescript(
        "ALTER TABLE connectors RENAME TO connectors__tmp;"
        "CREATE TABLE connectors("
        " connector_id TEXT PRIMARY KEY,"
        " type TEXT NOT NULL CHECK(type IN "
        "  ('jira','slack','pagerduty','splunk','webhook')),"
        " name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,"
        " config_json TEXT NOT NULL DEFAULT '{}', secret_ref TEXT, created_by TEXT,"
        " last_test_at INTEGER, last_test_status TEXT, last_test_detail TEXT,"
        " created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);"
        "INSERT INTO connectors SELECT connector_id,type,name,enabled,config_json,"
        " secret_ref,created_by,last_test_at,last_test_status,last_test_detail,"
        " created_at,updated_at FROM connectors__tmp;"
        "DROP TABLE connectors__tmp;")
    raw.commit()
    be.close()

    be2 = cnapp_backend.backend_for("sqlite:///" + path, check_same_thread=False)
    store2 = C.ConnectorStore(be2)
    assert [r.name for r in store2.list_rules("c1")] == ["keepme"], (
        "the rules must survive the parent-table rebuild")


def test_a_check_failure_is_not_reported_as_a_name_collision():
    """sqlite3.IntegrityError covers UNIQUE and CHECK alike. Reporting a rejected
    TYPE as 'name already in use' sends the operator hunting a collision that
    does not exist."""
    import sqlite3
    check = sqlite3.IntegrityError("CHECK constraint failed: type IN ('jira')")
    unique = sqlite3.IntegrityError("UNIQUE constraint failed: connectors.name")
    assert C._is_unique_violation(check) is False
    assert C._is_unique_violation(unique) is True


# ── the same widening, on the engine that is actually deployed ─────────────

def _types_in(text):
    """The CONNECTOR types a CHECK clause admits, as a set.

    Scoped by naming 'jira': the schema carries a SECOND `type IN (...)` on
    connector_rules for the match mode ('exact','glob'), and taking the first
    match compares the wrong constraint -- which is how this helper was first
    written. It failed loudly rather than passing on the wrong pair, which is
    the only reason it was caught.
    """
    import re
    hits = [m.group(1) for m in re.finditer(r"type IN \(([^)]*)\)", text)
            if "'jira'" in m.group(1)]
    assert len(hits) == 1, (
        "expected exactly one connector-type CHECK, found %d" % len(hits))
    return {t.strip().strip("'") for t in hits[0].split(",")}


def test_postgres_also_widens_the_connector_type_check():
    """The sqlite rebuild alone left the DEPLOYED engine refusing 'sdp'.

    CREATE TABLE IF NOT EXISTS leaves an existing table alone on Postgres too,
    so a database created before ServiceDesk Plus keeps the five-type CHECK and
    the connector cannot be created at all -- a fix that works only on the
    development engine is not a fix.
    """
    import aws_state_dialect
    joined = " ".join(aws_state_dialect.POSTGRES_ALTERS)
    assert "connectors_type_check" in joined
    assert "'sdp'" in joined


def test_the_postgres_connector_upgrade_is_idempotent():
    """migrate() runs on every open; a DROP without IF EXISTS fails the second
    time and takes the whole startup with it."""
    import aws_state_dialect
    stmts = [s for s in aws_state_dialect.POSTGRES_ALTERS
             if "connectors_type_check" in s]
    assert len(stmts) == 2
    assert "DROP CONSTRAINT IF EXISTS" in stmts[0]
    assert stmts[1].startswith("ALTER TABLE connectors ADD CONSTRAINT")


def test_both_engines_admit_exactly_the_same_connector_types():
    """Drift between the two CHECKs means a connector that works in development
    and is rejected in production, or the reverse. Pin them to each other and to
    the type list the engine itself dispatches on."""
    import aws_state
    import aws_state_dialect
    pg = _types_in(" ".join(
        s for s in aws_state_dialect.POSTGRES_ALTERS if "connectors" in s))
    lite = _types_in(" ".join(aws_state_dialect.SQLITE_CONNECTOR_TYPE_REBUILD))
    ddl = _types_in(aws_state._DDL)
    assert pg == lite == ddl == set(C._CONNECTOR_TYPES), (
        "the two CHECKs, the DDL and the engine's own type list must agree")
