"""Phase 5 · slice 5.2 — data-perimeter posture.

OverWatch recommends `aws:PrincipalOrgID` in some twenty remediation strings and has
never checked whether the estate has one. These tests defend the three things that make
the check honest rather than merely present.

**The matrix is AWS's, and it is asymmetric.** Identity -> RCP + endpoint policy (not
SCP); resource -> SCP + endpoint policy (not RCP); network -> SCP + RCP. A control in the
wrong policy type is not a weaker perimeter, it is not that perimeter — an SCP cannot
constrain who reaches your resources however it is written.

**Presence is not enforcement.** Establishing that a perimeter holds means evaluating
authorization for every principal, resource and path. No configuration read does that.

**Unreadable is not absent.** Organizations reads fail from a member account.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_perimeter as P


def pol(key, effect="Deny", op="StringNotEquals", value="o-abc123"):
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": effect, "Action": "*", "Resource": "*",
        "Condition": {op: {key: value}}}]}


# ── the model itself ────────────────────────────────────────────────────────
def test_all_three_objectives_are_modelled():
    assert set(P.OBJECTIVES) == set(P.PERIMETER_MODEL)
    assert len(P.OBJECTIVES) == 3


def test_the_identity_perimeter_is_rcp_and_endpoint_not_scp():
    """AWS's asymmetry. An SCP bounds what MY principals may do, so it cannot say who
    may reach my resources -- that is an RCP's job."""
    t = P.PERIMETER_MODEL[P.OBJ_IDENTITY]["policy_types"]
    assert set(t) == {P.RCP, P.VPCE}
    assert P.SCP not in t


def test_the_resource_perimeter_is_scp_and_endpoint_not_rcp():
    t = P.PERIMETER_MODEL[P.OBJ_RESOURCE]["policy_types"]
    assert set(t) == {P.SCP, P.VPCE}
    assert P.RCP not in t


def test_the_network_perimeter_is_scp_and_rcp():
    assert set(P.PERIMETER_MODEL[P.OBJ_NETWORK]["policy_types"]) == {P.SCP, P.RCP}


def test_the_primary_keys_are_the_ones_aws_names():
    assert P.PERIMETER_MODEL[P.OBJ_IDENTITY]["primary"] == ("aws:principalorgid",)
    assert P.PERIMETER_MODEL[P.OBJ_RESOURCE]["primary"] == ("aws:resourceorgid",)
    assert set(P.PERIMETER_MODEL[P.OBJ_NETWORK]["primary"]) == {"aws:sourceip",
                                                                "aws:sourcevpc"}


def test_an_unverified_key_is_absent_rather_than_assumed():
    """aws:VpcSourceIp did not verify against the condition-keys reference. Asserting a
    key on a failed verification is the phantom this module exists to avoid."""
    blob = repr(P.PERIMETER_MODEL)
    assert "vpcsourceip" not in blob


# ── parsing ─────────────────────────────────────────────────────────────────
def test_a_dict_policy_parses():
    st = P.parse_policy(pol("aws:PrincipalOrgID"))
    assert len(st) == 1 and st[0]["effect"] == "Deny"


def test_a_json_string_policy_parses():
    import json
    assert len(P.parse_policy(json.dumps(pol("aws:PrincipalOrgID")))) == 1


def test_a_url_encoded_policy_parses():
    """Organizations returns policy content as a string; some APIs URL-encode it."""
    import json
    from urllib.parse import quote
    assert len(P.parse_policy(quote(json.dumps(pol("aws:PrincipalOrgID"))))) == 1


def test_the_principal_is_kept():
    """The scanner's own normalizer drops Principal, which RCPs and endpoint policies
    need -- which is why this module parses for itself."""
    d = pol("aws:PrincipalOrgID")
    d["Statement"][0]["Principal"] = "*"
    assert P.parse_policy(d)[0]["principals"] == "*"


def test_the_condition_is_kept():
    st = P.parse_policy(pol("aws:PrincipalOrgID"))[0]
    assert st["condition"] == {"StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"}}


@pytest.mark.parametrize("bad", [None, "", "not json", b"\xff\xfe", 7, [], {}])
def test_malformed_policies_parse_to_nothing_rather_than_raising(bad):
    assert P.parse_policy(bad) == []


# ── condition-key extraction ────────────────────────────────────────────────
def test_keys_are_lowercased():
    st = P.parse_policy(pol("aws:PrincipalOrgID"))[0]
    assert P.statement_keys(st) == {"aws:principalorgid"}


def test_a_decorated_operator_still_yields_the_key():
    """ForAnyValue:/IfExists decoration does not change which key is tested."""
    st = P.parse_policy(pol("aws:PrincipalOrgID", op="StringNotEqualsIfExists"))[0]
    assert P.statement_keys(st) == {"aws:principalorgid"}


def test_no_condition_yields_no_keys():
    assert P.statement_keys({"condition": None}) == set()


# ── the objective verdicts ──────────────────────────────────────────────────
def test_an_rcp_with_principalorgid_meets_the_identity_perimeter():
    r = P.assess_objective(P.OBJ_IDENTITY,
                           {P.RCP: [pol("aws:PrincipalOrgID")], P.VPCE: []})
    assert r["verdict"] == P.MET


def test_an_scp_with_principalorgid_does_NOT_meet_the_identity_perimeter():
    """The load-bearing test. A control in the wrong policy type is not a weaker
    perimeter -- an SCP cannot constrain who reaches your resources however it is
    written. An intuition that drew a symmetric 3x3 would pass this wrongly."""
    r = P.assess_objective(P.OBJ_IDENTITY,
                           {P.RCP: [], P.VPCE: [], P.SCP: [pol("aws:PrincipalOrgID")]})
    assert r["verdict"] == P.UNMET


def test_an_rcp_with_resourceorgid_does_NOT_meet_the_resource_perimeter():
    r = P.assess_objective(P.OBJ_RESOURCE,
                           {P.SCP: [], P.VPCE: [], P.RCP: [pol("aws:ResourceOrgID")]})
    assert r["verdict"] == P.UNMET


def test_an_scp_with_resourceorgid_meets_the_resource_perimeter():
    r = P.assess_objective(P.OBJ_RESOURCE,
                           {P.SCP: [pol("aws:ResourceOrgID")], P.VPCE: []})
    assert r["verdict"] == P.MET


def test_a_granular_key_alone_is_partial_not_met():
    r = P.assess_objective(P.OBJ_IDENTITY,
                           {P.RCP: [pol("aws:PrincipalAccount")], P.VPCE: []})
    assert r["verdict"] == P.PARTIAL


def test_nothing_relevant_is_unmet():
    r = P.assess_objective(P.OBJ_NETWORK, {P.SCP: [], P.RCP: []})
    assert r["verdict"] == P.UNMET


def test_an_unreadable_layer_is_not_a_pass():
    """Organizations reads fail from a member account. Unreadable is not absent."""
    r = P.assess_objective(P.OBJ_IDENTITY, {})       # no key present at all == unread
    assert r["verdict"] == P.UNREADABLE
    assert r["verdict"] != P.MET


def test_a_primary_hit_with_one_layer_unread_is_met_but_a_partial_view():
    """AWS's objectives have two clauses -- "trusted identities can access my RESOURCES"
    (RCP) and "...are allowed from my NETWORKS" (endpoint policy). Endpoint policies are
    per-Region, so requiring both for MET would mean no estate could ever score. The
    unread layer limits the VIEW, not the control, and is said out loud."""
    r = P.assess_objective(P.OBJ_IDENTITY, {P.RCP: [pol("aws:PrincipalOrgID")]})
    assert r["verdict"] == P.MET
    assert r["partial_view"] is True
    assert P.VPCE in r["unreadable_types"]
    assert "partial VIEW" in r["statement"]


def test_a_fully_read_objective_is_not_flagged_as_a_partial_view():
    r = P.assess_objective(P.OBJ_IDENTITY,
                           {P.RCP: [pol("aws:PrincipalOrgID")], P.VPCE: []})
    assert r["partial_view"] is False
    assert "partial VIEW" not in r["statement"]


def test_the_evidence_names_the_policy_type_and_the_key():
    r = P.assess_objective(P.OBJ_IDENTITY,
                           {P.RCP: [pol("aws:PrincipalOrgID")], P.VPCE: []})
    assert ("RCP", "aws:principalorgid") in r["evidence"]


def test_an_expected_exception_key_is_not_counted_as_a_perimeter_control():
    """aws:PrincipalIsAWSService is the documented way to exempt a service principal
    from a Deny -- you cannot write NotPrincipal against one. Flagging it as a control,
    or as a weakness, would both be wrong."""
    r = P.assess_objective(P.OBJ_IDENTITY,
                           {P.RCP: [pol("aws:PrincipalIsAWSService", value="true")],
                            P.VPCE: []})
    assert r["verdict"] == P.UNMET


# ── the estate roll-up ──────────────────────────────────────────────────────
def _full():
    return {P.SCP: [pol("aws:ResourceOrgID"), pol("aws:SourceVpc")],
            P.RCP: [pol("aws:PrincipalOrgID"), pol("aws:SourceIp")],
            P.VPCE: []}


def test_a_complete_perimeter_scores_three_of_three():
    e = P.assess_estate(_full())
    assert e["met"] == 3 and e["complete"] is True


def test_an_empty_estate_is_unmet_not_unreadable():
    e = P.assess_estate({P.SCP: [], P.RCP: [], P.VPCE: []})
    assert e["unmet"] == 3 and e["unreadable"] == 0


def test_no_readable_layer_at_all_is_unreadable_not_unmet():
    e = P.assess_estate({})
    assert e["unreadable"] == 3 and e["unmet"] == 0
    assert "not clean" in e["statement"]


def test_unreadable_is_counted_apart_from_unmet():
    e = P.assess_estate({P.SCP: [pol("aws:ResourceOrgID")]})
    assert e["unreadable"] + e["unmet"] + e["met"] + e["partial"] == e["total"]


def test_the_estate_statement_says_presence_not_effect():
    e = P.assess_estate(_full())
    assert "PRESENCE and SHAPE" in e["statement"]


# ── the honesty invariants ──────────────────────────────────────────────────
def _all_strings():
    out = [P.assess_estate(_full())["statement"], P.assess_estate({})["statement"]]
    for layers in (_full(), {}, {P.SCP: [], P.RCP: [], P.VPCE: []},
                   {P.RCP: [pol("aws:PrincipalAccount")]}):
        for o in P.OBJECTIVES:
            r = P.assess_objective(o, layers)
            out.append(r["statement"])
            out.append(P.describe_objective(r))
    out += list(P.SCOPE_NOTES.values())
    return " ".join(out).lower()


@pytest.mark.parametrize("verb", ["enforced", "prevented", "blocked", "guaranteed"])
def test_no_output_ever_claims_the_perimeter_takes_effect(verb):
    """Presence is not effect. Establishing that a perimeter holds requires evaluating
    authorization for every principal, resource and path -- not a configuration read."""
    assert verb not in _all_strings()


def test_the_scp_management_account_hole_is_stated_not_assumed_known():
    assert "management account" in P.SCOPE_NOTES[P.SCP]
    assert "service-linked roles" in P.SCOPE_NOTES[P.SCP]


def test_the_endpoint_cross_region_limit_is_stated():
    """A cross-Region request does not traverse the endpoint, so the policy never
    evaluates -- an endpoint policy alone is not a Region-wide claim."""
    assert "cross-Region" in P.SCOPE_NOTES[P.VPCE]


def test_a_met_objective_produces_no_gap_line():
    r = P.assess_objective(P.OBJ_IDENTITY,
                           {P.RCP: [pol("aws:PrincipalOrgID")], P.VPCE: []})
    assert P.describe_objective(r) == ""


def test_an_unreadable_objective_produces_no_gap_line():
    """Never assert a gap from a layer that was not read."""
    assert P.describe_objective(P.assess_objective(P.OBJ_IDENTITY, {})) == ""


def test_an_unmet_objective_produces_a_gap_line_naming_the_right_policy_types():
    r = P.assess_objective(P.OBJ_IDENTITY, {P.RCP: [], P.VPCE: []})
    line = P.describe_objective(r)
    assert "RCP" in line and "aws:principalorgid" in line
    assert "SCP" not in line


# ── robustness ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, {}, "x", 7])
def test_nothing_raises_on_malformed_input(bad):
    P.assess_objective(P.OBJ_IDENTITY, bad if isinstance(bad, dict) else None)
    P.assess_estate(bad if isinstance(bad, dict) else None)
    P.describe_objective(bad if isinstance(bad, dict) else None)
    P.statement_keys(bad if isinstance(bad, dict) else None)


def test_an_unknown_objective_does_not_raise():
    assert P.assess_objective("nope", {})["verdict"] == P.UNREADABLE


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(P), re.M)
