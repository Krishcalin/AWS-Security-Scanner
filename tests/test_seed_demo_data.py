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
    that is obviously canned.

    The clock is pinned because it is an INPUT to the build, not incidental to it:
    every account row embeds `now`. Reading it twice made this test fail roughly
    whenever the two builds landed either side of a second boundary — a flake that
    teaches people a red suite means 'run it again'."""
    fixed_now = 1_760_000_000
    first = seed.build(random.Random(seed.RANDOM_SEED), now=fixed_now)
    second = seed.build(random.Random(seed.RANDOM_SEED), now=fixed_now)
    assert first["accounts"] == second["accounts"]
    assert len(first["findings"]) == len(second["findings"])
    assert first == second, "the whole hub must be reproducible, not just accounts"


def test_the_clock_is_an_input_not_an_ambient_read():
    """The property the test above depends on. If build() goes back to reading
    time.time() unconditionally, this fails rather than the determinism test
    failing intermittently and being re-run until green."""
    a = seed.build(random.Random(seed.RANDOM_SEED), now=1_700_000_000)
    b = seed.build(random.Random(seed.RANDOM_SEED), now=1_800_000_000)
    assert a["accounts"] != b["accounts"], "now= is being ignored"


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
        # CIEM cards are DISPLAY-ONLY, exactly as the real service's
        # get_finding_catalog appends controls / EDR / DSPM coverage entries
        # that have no findings-table row either. They feed the Excessive
        # Access dashboard and are excluded from this comparison on purpose.
        catalog = {c["check_id"] for c in payload["finding_catalog"]
                   if not c["check_id"].startswith("CIEM-")}
        assert catalog == by_account.get(account_id, set()), account_id


def test_the_payload_severity_counts_match_its_own_catalog(rows):
    for _a, payload_json, _s, _t in rows["scan_results"]:
        payload = json.loads(payload_json)
        counted = {}
        for card in payload["finding_catalog"]:
            if card["check_id"].startswith("CIEM-"):
                continue          # display-only; see the note above
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


def test_every_path_node_exists_in_the_graph(rows):
    """The property the graph docstring CLAIMED and the code did not have.

    `_attack_paths` used to invent `ec2/i-demo<random>` and `role/arn:...` ids
    while `_graph` invented a different `i-demo<random>` and used full ARNs, so
    only `internet` appeared in both -- 1 of 11 path node ids existed in the
    graph. Nothing looked broken because the old renderer drew the path's own
    node list and never looked anything up; the moment a view wanted a node's
    kind, its crown-jewel prop, or why a hop was possible, it got nothing.

    Adjacent to test_graph_edges_only_reference_nodes_the_graph_declares, which
    checks the graph against ITSELF and therefore passed throughout."""
    for _a, payload_json, _s, _t in rows["scan_results"]:
        payload = json.loads(payload_json)
        declared = {n["id"] for n in payload["graph"]["nodes"]}
        for path in payload["attack_paths"]:
            missing = [n for n in path["nodes"] if n not in declared]
            assert not missing, (
                f"attack path references nodes the graph does not declare: "
                f"{missing}. Paths are walked out of the graph -- if this fails, "
                f"something is inventing node ids again.")


def test_every_path_edge_is_a_real_graph_edge(rows):
    """A path hop must be an edge the graph declares, with the same kind.

    Node identity alone is not enough: a path could name two real nodes with no
    relationship between them, which reads as a capability the estate does not
    have."""
    for _a, payload_json, _s, _t in rows["scan_results"]:
        payload = json.loads(payload_json)
        real = {(e["source"], e["target"], e["kind"])
                for e in payload["graph"]["edges"]}
        for path in payload["attack_paths"]:
            for edge in path["edges"]:
                assert len(edge) == 3, (
                    f"path edge {edge} carries no relationship kind -- the "
                    f"console can only draw an unlabelled arrow for it")
                assert tuple(edge) in real, (
                    f"path claims a hop the graph does not declare: {edge}")


def test_every_path_hop_kind_is_one_the_correlator_traverses(rows):
    """A demo that traverses an edge kind the real engine treats as an
    annotation would teach a viewer a path shape that cannot occur."""
    import aws_correlate
    for _a, payload_json, _s, _t in rows["scan_results"]:
        for path in json.loads(payload_json)["attack_paths"]:
            for edge in path["edges"]:
                assert edge[2] in aws_correlate.E_PATH, (
                    f"path hop kind {edge[2]!r} is not in aws_correlate.E_PATH, "
                    f"so the real correlator would never walk it")


def test_a_choke_point_is_on_more_than_one_path(rows):
    """A node on a single path is not a choke point — fixing it breaks one
    path, which is just a finding."""
    for _a, payload_json, _s, _t in rows["scan_results"]:
        payload = json.loads(payload_json)
        for choke in payload["choke_points"]:
            assert choke["paths_severed"] > 1


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


# ── the payload must match the console's DECLARED types ─────────────────────
# Written after guessing a shape wrong twice. The Compliance screen died on
# "r.failed_controls is not iterable" because _compliance invented
# {passed, failed, total, percent}; choke_points had the same fault and would
# have died next. Both are now read FROM frontend/src/api/types.ts, so the
# next mismatch fails here rather than in a browser.

import re  # noqa: E402

TYPES_TS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "frontend", "src", "api", "types.ts")


def _required_fields(interface: str) -> set:
    """Non-optional field names the console declares for one interface."""
    with open(TYPES_TS, encoding="utf-8") as handle:
        source = handle.read()
    match = re.search(r"export interface " + interface + r"\s*\{(.*?)\n\}",
                      source, re.S)
    assert match, f"{interface} not found in types.ts"
    fields = set()
    for line in match.group(1).split("\n"):
        line = line.split("//")[0].strip()
        found = re.match(r"([A-Za-z_][A-Za-z0-9_]*)(\??)\s*:", line)
        if found and not found.group(2):        # skip optional (name?: T)
            fields.add(found.group(1))
    return fields


def _payloads(rows):
    return [json.loads(r[1]) for r in rows["scan_results"]]


def test_attack_paths_carry_every_declared_field(rows):
    required = _required_fields("AttackPath")
    for payload in _payloads(rows):
        for path in payload["attack_paths"]:
            missing = required - set(path)
            assert not missing, missing


def test_choke_points_carry_every_declared_field(rows):
    """THE SECOND SHAPE THIS CAUGHT. Emitting {node, paths, max_score} left the
    console with nothing it recognised."""
    required = _required_fields("ChokePoint")
    seen_any = False
    for payload in _payloads(rows):
        for choke in payload["choke_points"]:
            seen_any = True
            missing = required - set(choke)
            assert not missing, missing
    assert seen_any, "no choke points seeded — the check proved nothing"


def test_compliance_cards_carry_every_declared_field(rows):
    """THE ONE THAT REACHED A BROWSER: 'r.failed_controls is not iterable'."""
    required = _required_fields("ComplianceFramework")
    for payload in _payloads(rows):
        for framework, card in payload["compliance"].items():
            missing = required - set(card)
            assert not missing, f"{framework}: {missing}"
            assert isinstance(card["failed_controls"], list)


def test_compliance_is_built_by_the_products_own_scorecard(rows):
    """Not reproduced from its output. The control universe has to come from
    COMPLIANCE_MAP exactly as a real scan's does, or the demo shows totals no
    scan can produce."""
    import aws_live_scanner as scanner

    universe = {f: set() for f in scanner.COMPLIANCE_FRAMEWORKS}
    for tags in scanner.COMPLIANCE_MAP.values():
        for framework, control in (tags or {}).items():
            if framework in universe and control:
                universe[framework].add(control)

    for payload in _payloads(rows):
        for framework, card in payload["compliance"].items():
            assert card["controls_total"] == len(universe[framework]), framework
            assert set(card["failed_controls"]) <= universe[framework]


def test_a_failed_control_traces_to_a_failing_check(rows):
    """A control is failed BECAUSE a check that references it failed. A
    scorecard that moves independently of the findings is a number nobody can
    justify when asked."""
    import aws_live_scanner as scanner

    for payload in _payloads(rows):
        tagged = {}
        for card in payload["finding_catalog"]:
            for framework, control in (scanner.COMPLIANCE_MAP.get(
                    card["check_id"]) or {}).items():
                tagged.setdefault(framework, set()).add(control)
        for framework, card in payload["compliance"].items():
            assert set(card["failed_controls"]) == tagged.get(framework, set())


def test_the_excessive_access_dashboard_has_a_feed(rows):
    """`Excessive Access` filters the catalog on the CIEM- prefix. Those checks
    are emitted at runtime by aws_unused.py and are absent from FINDING_DETAIL
    and CHECK_SEVERITY, so a seeder drawing only from that catalogue produces
    none — which is exactly why the dashboard was empty."""
    for _a, payload_json, _s, _t in rows["scan_results"]:
        payload = json.loads(payload_json)
        ciem = [c for c in payload["finding_catalog"]
                if c["check_id"].startswith("CIEM-")]
        assert ciem, "no CIEM cards — Excessive Access would be empty"
        for card in ciem:
            assert card["affected"] and card["severity"] == "LOW"


def test_identity_can_find_principals_and_their_edges(rows):
    """`Identity.tsx` filters nodes on kind IAMRole/IAMUser and reads edge
    kinds. The first graph emitted `IamRole` and edges with no `kind` at all,
    so the screen rendered nothing and looked like an empty estate."""
    for _a, payload_json, _s, _t in rows["scan_results"]:
        graph = json.loads(payload_json)["graph_full"]
        roles = [n for n in graph["nodes"] if n["kind"] in ("IAMRole", "IAMUser")]
        assert roles
        assert all("kind" in e for e in graph["edges"])
        kinds = {e["kind"] for e in graph["edges"]}
        assert {"CAN_PRIVESC_TO", "CAN_READ_DATA"} <= kinds


def test_data_security_has_classified_crown_jewels(rows):
    """`aws_dspm.compute_inventory` selects crowns on the `crown_jewel` prop
    and counts CAN_READ_DATA edges into each."""
    import aws_dspm
    import aws_graph

    for account_id, payload_json, _s, _t in rows["scan_results"]:
        graph = aws_graph.SecurityGraph.from_dict(
            json.loads(payload_json)["graph_full"])
        inventory = aws_dspm.compute_inventory(graph, account=account_id)
        assert inventory["stores"], account_id
        # One store is deliberately left unclassified: the gap list is the
        # honest half of that screen and a demo with no gaps hides it.
        assert inventory["classification_gaps"]


def test_supply_chain_has_two_snapshots_per_subject(rows):
    """The Supply Chain headline is the DIFF between builds. One snapshot per
    subject renders an inventory, which is a different screen."""
    by_subject = {}
    for row in rows["sbom_snapshots"]:
        by_subject.setdefault((row[1], row[3]), []).append(row[0])
    assert by_subject
    assert all(len(v) >= 2 for v in by_subject.values())


def test_every_sbom_component_belongs_to_a_seeded_snapshot(rows):
    """`sbom_components.snapshot_id` is a real foreign key."""
    snapshots = {row[0] for row in rows["sbom_snapshots"]}
    for row in rows["sbom_components"]:
        assert row[0] in snapshots


def test_the_licence_corpus_is_not_uniformly_permissive(rows):
    """A licence-policy screen where everything is MIT has nothing to decide."""
    categories = {row[9] for row in rows["sbom_components"]}
    assert "permissive" in categories
    assert categories & {"strong-copyleft", "commercial-unfriendly"}
