"""The demo seeder, and the markers that keep synthetic posture identifiable.

The risk this guards is not a broken screen. It is a seeded hub being
screenshotted and presented as a customer's posture, so most of these tests are
about the rows staying self-identifying and `--purge` selecting exactly them.
"""
from __future__ import annotations

import json
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import seed_demo_data as seed  # noqa: E402


@pytest.fixture(scope="module")
def rows():
    return seed.build(random.Random(seed.RANDOM_SEED))


# ── the shape the user asked for ────────────────────────────────────────────
def test_five_organisations_with_ten_accounts_each(rows):
    assert len(rows["workspaces"]) == 5
    assert len(rows["accounts"]) == 50
    assert len(rows["workspace_accounts"]) == 50


def test_every_account_belongs_to_exactly_one_workspace(rows):
    """`workspace_accounts.account_id` is the PRIMARY KEY, so a second binding
    is a constraint violation rather than a second tenant seeing the account."""
    bound = [r[0] for r in rows["workspace_accounts"]]
    assert len(bound) == len(set(bound))


def test_each_workspace_gets_exactly_ten(rows):
    by_ws = {}
    for account_id, workspace_id, _ in rows["workspace_accounts"]:
        by_ws.setdefault(workspace_id, []).append(account_id)
    assert sorted(len(v) for v in by_ws.values()) == [10] * 5


# ── the markers ─────────────────────────────────────────────────────────────
def test_every_account_id_carries_the_demo_prefix(rows):
    """`--purge` selects on this. If an id ever escapes the prefix, purge
    leaves it behind and the hub keeps a synthetic account forever."""
    for row in rows["accounts"]:
        assert seed.is_demo_account(row[0]), row[0]


def test_every_account_id_is_a_valid_twelve_digit_id(rows):
    """`accounts.account_id` is CHECK(length=12). An 11-digit id fails at the
    database rather than here, which is a worse place to find out."""
    for row in rows["accounts"]:
        assert len(row[0]) == 12 and row[0].isdigit(), row[0]


def test_account_ids_are_unique(rows):
    ids = [r[0] for r in rows["accounts"]]
    assert len(ids) == len(set(ids))


def test_every_alias_says_it_is_a_demo(rows):
    """The marking has to survive into a screenshot of a list, where the id
    may be truncated but the alias is what a reader looks at."""
    for row in rows["accounts"]:
        assert row[1].endswith(seed.DEMO_ALIAS_SUFFIX), row[1]


def test_every_workspace_slug_says_it_is_a_demo(rows):
    for row in rows["workspaces"]:
        assert row[2].startswith(seed.DEMO_SLUG_PREFIX), row[2]


def test_every_scan_is_stamped_demo(rows):
    """So a finding exported to JSON still says where it came from after it
    has left the console."""
    for row in rows["scans"]:
        assert str(row[-1]).startswith("DEMO-"), row[-1]


# ── the data has to be real enough to click through ─────────────────────────
def test_findings_use_check_ids_from_the_products_own_catalogue(rows):
    """A demo built on invented check ids shows screens no real scan can
    reproduce, and the first person to open a remediation write-up finds
    nothing there."""
    import aws_finding_detail as detail

    known = set(detail.FINDING_DETAIL)
    used = {row[4] for row in rows["findings"]}
    assert used and used <= known


def test_finding_severities_match_the_catalogue(rows):
    """Not chosen at random. A check whose real severity is MEDIUM must not
    appear as CRITICAL, or the demo teaches the wrong severity for a real
    check id."""
    import aws_live_scanner as scanner

    for row in rows["findings"]:
        check_id, severity = row[4], row[8]
        assert scanner.CHECK_SEVERITY.get(check_id) == severity, check_id


def test_finding_status_is_within_the_schema_check(rows):
    for row in rows["findings"]:
        assert row[10] in ("open", "resolved")


def test_a_resolved_finding_has_a_resolved_epoch_and_an_open_one_does_not(rows):
    for row in rows["findings"]:
        status, resolved_epoch = row[10], row[17]
        assert (resolved_epoch is not None) == (status == "resolved")


def test_account_health_and_status_are_within_the_schema_checks(rows):
    for row in rows["accounts"]:
        assert row[4] in ("pending", "active", "denied", "disabled")
        assert row[9] in ("unknown", "validating", "healthy", "degraded",
                          "unauthorized")


def test_enabled_regions_is_valid_json(rows):
    for row in rows["accounts"]:
        assert isinstance(json.loads(row[7]), list)


# ── the contrast is the point ───────────────────────────────────────────────
def test_the_organisations_are_not_all_the_same(rows):
    """A demo where every tenant looks alike demonstrates nothing. Atlas is
    seeded to look bad and Harbor to look quiet; if that inverts, the profiles
    have stopped meaning anything."""
    by_account = {}
    for row in rows["accounts"]:
        by_account[row[0]] = row[1]

    critical = {}
    for row in rows["findings"]:
        if row[8] == "CRITICAL" and row[10] == "open":
            alias = by_account.get(row[0], "")
            org = alias.split("-")[0]
            critical[org] = critical.get(org, 0) + 1

    assert critical.get("atlas", 0) > critical.get("harbor", 0)
    assert critical.get("atlas", 0) > critical.get("northwind", 0)


def test_reachability_can_outrank_raw_severity(rows):
    """THE ARGUMENT THE VULNERABILITY SCREEN EXISTS TO MAKE. If the seeded
    scores cannot demonstrate a reachable MEDIUM beating an unreachable
    CRITICAL, the demo shows a CVSS-sorted list like everybody else's."""
    scores = {"MEDIUM": [], "CRITICAL": []}
    for row in rows["ingested_vulns"]:
        severity, score = row[7], row[18]
        if severity in scores:
            scores[severity].append(score)
    assert scores["MEDIUM"] and scores["CRITICAL"]
    assert max(scores["MEDIUM"]) > min(scores["CRITICAL"])


def test_kev_and_reachability_flags_are_zero_or_one(rows):
    for row in rows["ingested_vulns"]:
        for index in (10, 14, 15, 16):
            assert row[index] in (0, 1)


def test_a_vuln_that_reaches_a_crown_jewel_is_on_a_path(rows):
    """`reaches_crown` without `on_attack_path` is incoherent — there is no
    way to reach a crown jewel except along a path."""
    for row in rows["ingested_vulns"]:
        on_path, crown = row[15], row[16]
        if crown:
            assert on_path, row[1]


# ── determinism ─────────────────────────────────────────────────────────────
def test_two_builds_produce_the_same_hub():
    """A demo that changes between rehearsal and delivery is worse than one
    that is obviously canned."""
    first = seed.build(random.Random(seed.RANDOM_SEED))
    second = seed.build(random.Random(seed.RANDOM_SEED))
    assert first["accounts"] == second["accounts"]
    assert len(first["findings"]) == len(second["findings"])


def test_building_touches_no_database(monkeypatch):
    """`--dry-run` has to be honest about that, and the only way to be sure is
    that the builder cannot connect at all."""
    def explode(*_a, **_k):
        raise AssertionError("build() must not open a connection")

    monkeypatch.setattr(seed, "_connect", explode)
    assert seed.build(random.Random(1))["accounts"]


def test_insert_statements_exist_for_every_table_the_builder_fills(rows):
    """A table built and never inserted is silent: the run reports a count and
    the console shows nothing."""
    for table in seed._ORDER:
        assert table in seed._INSERTS
    assert set(rows) == set(seed._ORDER)


def test_workspace_accounts_is_inserted_after_both_its_parents():
    """It references accounts AND workspaces, so it cannot lead — a foreign
    key violation here would abort the whole seeding transaction."""
    order = list(seed._ORDER)
    assert order.index("workspace_accounts") > order.index("accounts")
    assert order.index("workspace_accounts") > order.index("workspaces")


# ── the scan payload: the layer the empty tabs were missing ─────────────────
# Findings, Overview, Attack Paths, Inventory, Compliance and Remediation all
# read a scan PAYLOAD through ResultStore, not the findings table. Seeding the
# table without the payload is exactly why those tabs were blank while Cloud
# Accounts and Vulnerabilities were not.

def test_every_account_gets_a_scan_payload(rows):
    assert len(rows["scan_results"]) == len(rows["accounts"])


def test_the_payload_carries_what_the_screens_read(rows):
    payload = json.loads(rows["scan_results"][0][1])
    for key in ("finding_catalog", "attack_paths", "choke_points", "graph",
                "summary", "compliance", "posture_score", "posture_grade"):
        assert key in payload, key


def test_the_catalog_is_grouped_by_check_not_by_resource(rows):
    """`serialize_scanner` produces one card per check with its affected
    resources collected. One card per resource would render a Findings screen
    no real scan can reproduce."""
    payload = json.loads(rows["scan_results"][0][1])
    ids = [c["check_id"] for c in payload["finding_catalog"]]
    assert ids and len(ids) == len(set(ids))


def test_the_catalog_agrees_with_the_findings_table(rows):
    """The two layers describe the same scan. If they diverge, the Findings
    screen and the drift/MTTR tiles disagree about what was found — and both
    look authoritative."""
    by_account = {}
    for row in rows["findings"]:
        if row[10] == "open":
            by_account.setdefault(row[0], set()).add(row[4])

    for account_id, _payload_json, _scan, _ts in rows["scan_results"]:
        payload = json.loads(_payload_json)
        catalog = {c["check_id"] for c in payload["finding_catalog"]}
        assert catalog == by_account.get(account_id, set()), account_id


def test_the_payload_severity_counts_match_its_own_catalog(rows):
    for _a, payload_json, _s, _t in rows["scan_results"]:
        payload = json.loads(payload_json)
        counted = {}
        for card in payload["finding_catalog"]:
            counted[card["severity"]] = counted.get(card["severity"], 0) + card["count"]
        for severity, total in payload["severity_counts"].items():
            assert counted.get(severity, 0) == total, severity


def test_graph_edges_only_reference_nodes_the_graph_declares(rows):
    """A graph built beside the paths rather than from them shows edges into
    nodes that do not exist, which renders as a broken diagram."""
    for _a, payload_json, _s, _t in rows["scan_results"]:
        graph = json.loads(payload_json)["graph"]
        declared = {n["id"] for n in graph["nodes"]}
        for edge in graph["edges"]:
            assert edge["source"] in declared and edge["target"] in declared


def test_a_choke_point_is_on_more_than_one_path(rows):
    """A node on a single path is not a choke point — fixing it breaks one
    path, which is just a finding."""
    for _a, payload_json, _s, _t in rows["scan_results"]:
        payload = json.loads(payload_json)
        for choke in payload["choke_points"]:
            assert choke["paths"] > 1


def test_the_worst_org_has_the_busiest_graph(rows):
    """Path count scales with criticals, so the org seeded to look bad is the
    one whose Attack Paths screen has something on it."""
    by_alias = {r[0]: r[1] for r in rows["accounts"]}
    paths = {}
    for account_id, payload_json, _s, _t in rows["scan_results"]:
        org = by_alias[account_id].split("-")[0]
        paths[org] = paths.get(org, 0) + len(json.loads(payload_json)["attack_paths"])
    assert paths.get("atlas", 0) > paths.get("harbor", 0)


# ── purge has to cover every foreign key, not just the ones we hit ──────────
def test_purge_covers_every_child_of_accounts_and_workspaces():
    """THE BUG THIS CATCHES ALREADY HAPPENED. `scan_jobs` references accounts
    and was missing from the purge list, so purge died with a
    ForeignKeyViolation — against rows the APP had created by scheduling a
    scan on a seeded account.

    Derived from the DDL rather than restated, so a table added later fails
    here instead of on somebody's machine mid-demo.
    """
    import aws_state_dialect

    covered = {t for t, _ in seed.ACCOUNT_CHILDREN} | set(seed.WORKSPACE_CHILDREN)
    ddl = "\n".join(aws_state_dialect.POSTGRES_DDL)

    missing = []
    for statement in aws_state_dialect.POSTGRES_DDL:
        if "CREATE TABLE" not in statement:
            continue
        name = statement.split("CREATE TABLE IF NOT EXISTS", 1)[-1].split("(")[0].strip()
        if not name or name in covered:
            continue
        # Does this table point at accounts or workspaces?
        if ("REFERENCES accounts(" in statement
                or "REFERENCES workspaces(" in statement):
            missing.append(name)
    assert missing == [], f"purge would fail on: {missing}"


def test_accounts_is_deleted_last_among_its_children():
    """Children first, or the delete violates the very keys it is clearing."""
    order = [t for t, _ in seed.ACCOUNT_CHILDREN]
    assert order[-1] == "accounts"
    assert order.index("workspace_accounts") < order.index("accounts")
    assert order.index("scan_jobs") < order.index("accounts")
