"""Drift guard for the cross-language WQL parity fixture.

frontend/src/lib/__fixtures__/wql_parity.json is the contract that pins wql.ts to aws_wql.py.
wql.test.ts replays it through the TS engine; THIS test asserts the committed file still equals
what aws_wql.evaluate produces today — so a change to aws_wql.py that isn't reflected in the
fixture (and therefore not verified against the TS mirror) fails CI here with a clear message:
regenerate via `python scripts/gen_wql_parity.py`. Pure/offline."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import gen_wql_parity as gen


def _committed() -> dict:
    with open(gen.FIXTURE_PATH, encoding="utf-8") as f:
        return json.load(f)


def test_fixture_exists():
    assert os.path.exists(gen.FIXTURE_PATH), "run: python scripts/gen_wql_parity.py"


def test_committed_fixture_matches_engine():
    # round-trip through JSON so the comparison is value-based (tuples->lists, etc.), exactly
    # as the committed file was written; any divergence means the fixture is stale.
    fresh = json.loads(json.dumps(gen.build_fixture()))
    committed = _committed()
    assert committed["graph"] == fresh["graph"], "graph drifted — regenerate the WQL parity fixture"
    assert [c["name"] for c in committed["cases"]] == [c["name"] for c in fresh["cases"]]
    for cf, cc in zip(fresh["cases"], committed["cases"]):
        assert cc["query"] == cf["query"], f"query drift in case {cf['name']}"
        assert cc["expected"] == cf["expected"], (
            f"expected-rows drift in case {cf['name']} — aws_wql.py changed but the fixture "
            f"wasn't regenerated (python scripts/gen_wql_parity.py)")
    # controls section (aws_controls.control_finding is the oracle for controls.ts)
    assert committed.get("controls") == fresh["controls"], (
        "controls drift — aws_wql.py or aws_controls.py changed but the fixture wasn't "
        "regenerated (python scripts/gen_wql_parity.py)")
    # dspm section (aws_dspm.classify is the oracle for dspm.ts)
    assert committed.get("dspm") == fresh["dspm"], (
        "dspm drift — aws_dspm.py changed but the fixture wasn't regenerated "
        "(python scripts/gen_wql_parity.py)")
    # policy section (aws_policy is the oracle for policy.ts)
    assert committed.get("policy_catalog") == fresh["policy_catalog"], "policy_catalog drift — regenerate the fixture"
    assert committed.get("policies") == fresh["policies"], (
        "policies drift — aws_policy.py changed but the fixture wasn't regenerated "
        "(python scripts/gen_wql_parity.py)")


def test_battery_is_comprehensive():
    fx = gen.build_fixture()
    assert len(fx["cases"]) >= 30
    preds = {"kind", "has_prop", "prop", "prop_glob", "has_edge", "reachable_from", "reaches", "crown_jewel"}
    seen: set = set()

    def walk(p):
        if not isinstance(p, dict):
            return
        if p.get("op") in ("and", "or", "not"):
            for c in p["of"]:
                walk(c)
        elif "pred" in p:
            seen.add(p["pred"])

    for c in fx["cases"]:
        walk(c["query"].get("where"))
    assert preds <= seen, f"battery misses predicates: {preds - seen}"


@pytest.mark.parametrize("name,min_ids", [
    ("flagship_exposed_crown_s3", {"arn:aws:s3:::crown-public"}),
    ("reaches_admin_all", {"arn:aws:iam::1:role/Zeus", "arn:aws:iam::1:role/AdminRole"}),
    ("determinism_codepoint_roles", set()),
])
def test_key_cases_have_expected_shape(name, min_ids):
    fx = gen.build_fixture()
    case = next(c for c in fx["cases"] if c["name"] == name)
    ids = {n["id"] for n in case["expected"]["nodes"]}
    assert min_ids <= ids
    if name == "determinism_codepoint_roles":
        # code-point tie-break: AdminRole(0x41) < Zeus(0x5A) < apollo(0x61)
        assert [n["id"] for n in case["expected"]["nodes"]] == [
            "arn:aws:iam::1:role/AdminRole", "arn:aws:iam::1:role/Zeus", "arn:aws:iam::1:role/apollo"]
