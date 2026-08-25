"""Phase 4 · slice 4.4 — AI nobody told the security team about.

Shadow AI is not a property of a resource. A knowledge base built by the ML platform team
in the governed region is the system working; the identical resource built by an
application role in a region nobody scans is the thing this slice surfaces. An inventory
cannot tell those apart, which is why this asks *who* and *where* rather than *what*.

Two restraints carry most of these tests.

**With no declared owner set, nothing fires.** An operator who has not told OverWatch who
owns AI would otherwise get a finding for every legitimate creator on the first scan, and
a check that fires on the correct configuration is one people switch off.

**The third-party SaaS half is declared, not attempted.** Flow logs record IPs, not
hostnames, and the major providers sit behind shared CDN ranges — so an address-matching
rule fires on unrelated sites and misses any provider that rotated an address. That is a
detection surface whose misses read as passes, which slice 3.2 refused to build for
injection phrasings; refusing it once is worth nothing if the next slice does it.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_shadowai as SA

ML_ROLE = "arn:aws:iam::123456789012:role/MLPlatform"
APP_ROLE = "arn:aws:iam::123456789012:role/PaymentsApp"


def ev(name="CreateAgent", arn=ML_ROLE, region="us-east-1", session=None):
    ident = arn
    if session:
        acct = arn.split(":")[4]
        role = arn.rsplit("/", 1)[-1]
        ident = f"arn:aws:sts::{acct}:assumed-role/{role}/{session}"
    return {"eventName": name, "awsRegion": region,
            "userIdentity": {"arn": ident, "type": "AssumedRole"}}


# ── who created what ────────────────────────────────────────────────────────
def test_only_creation_events_count():
    """Usage is AITHR-01's question and needs data events most accounts do not have.
    Creation is the moment shadow AI becomes visible."""
    found = SA.creators([ev("CreateAgent"), ev("GetAgent"), ev("ListAgents")])
    assert list(found) == [ML_ROLE]
    assert found[ML_ROLE]["count"] == 1


def test_sessions_collapse_to_their_role():
    """Ten sessions of one role are one creator. Reporting them as ten would bury the
    answer in its own noise."""
    found = SA.creators([ev(session="s1"), ev(session="s2"), ev(session="s3")])
    assert list(found) == [ML_ROLE]
    assert found[ML_ROLE]["count"] == 3


def test_regions_and_kinds_are_collected_per_creator():
    found = SA.creators([ev("CreateAgent", region="us-east-1"),
                         ev("CreateKnowledgeBase", region="eu-west-1")])
    row = found[ML_ROLE]
    assert row["regions"] == ["eu-west-1", "us-east-1"]
    assert row["events"] == ["CreateAgent", "CreateKnowledgeBase"]


def test_an_event_with_no_identity_is_skipped():
    assert SA.creators([{"eventName": "CreateAgent", "userIdentity": {}}]) == {}


@pytest.mark.parametrize("bad", [None, [], [None], ["x"], [{"eventName": 7}]])
def test_nothing_raises_on_malformed_events(bad):
    SA.creators(bad)


# ── the declared owner set ──────────────────────────────────────────────────
def test_with_no_declared_set_nothing_is_undeclared():
    """The load-bearing restraint. Without it every legitimate creator is a finding on
    the first scan, and a check that fires on the correct configuration gets turned
    off."""
    found = SA.creators([ev(arn=APP_ROLE)])
    assert SA.undeclared_creators(found, None) == []
    assert SA.undeclared_creators(found, []) == []


def test_a_declared_creator_is_not_reported():
    found = SA.creators([ev(arn=ML_ROLE)])
    assert SA.undeclared_creators(found, [ML_ROLE]) == []


def test_an_undeclared_creator_is_reported():
    found = SA.creators([ev(arn=APP_ROLE)])
    out = SA.undeclared_creators(found, [ML_ROLE])
    assert len(out) == 1 and out[0]["principal"] == APP_ROLE


def test_a_declared_set_may_name_bare_role_names():
    """Operators write 'MLPlatform', not the full ARN, and refusing that would make the
    feature annoying enough to go unused."""
    found = SA.creators([ev(arn=ML_ROLE)])
    assert SA.undeclared_creators(found, ["MLPlatform"]) == []


def test_matching_is_case_insensitive():
    found = SA.creators([ev(arn=ML_ROLE)])
    assert SA.undeclared_creators(found, ["mlplatform"]) == []


def test_the_description_names_who_what_and_where():
    found = SA.creators([ev("CreateKnowledgeBase", arn=APP_ROLE, region="ap-south-1")])
    line = SA.describe_creator(found[APP_ROLE])
    assert "PaymentsApp" in line and "CreateKnowledgeBase" in line
    assert "ap-south-1" in line


# ── regions ─────────────────────────────────────────────────────────────────
def test_active_regions_is_the_union():
    found = SA.creators([ev(region="us-east-1"), ev(region="eu-west-1", arn=APP_ROLE)])
    assert SA.active_regions(found) == {"us-east-1", "eu-west-1"}


def test_active_regions_of_nothing_is_empty():
    assert SA.active_regions(None) == set()


# ── the VPC endpoint substitute ─────────────────────────────────────────────
def epn(vpc="vpc-1", service="com.amazonaws.us-east-1.bedrock-runtime"):
    return {"VpcId": vpc, "ServiceName": service, "VpcEndpointType": "Interface"}


def test_a_bedrock_endpoint_is_recognised_in_any_region():
    """The service name is regional, so hardcoding one would make this silently find
    nothing everywhere else."""
    for region in ("us-east-1", "eu-west-1", "ap-southeast-2"):
        p = SA.vpc_endpoint_posture([epn(service=f"com.amazonaws.{region}.bedrock")])
        assert p["any"] is True, region


def test_all_four_bedrock_endpoint_services_count():
    for svc in SA.BEDROCK_ENDPOINT_SERVICES:
        p = SA.vpc_endpoint_posture([epn(service=f"com.amazonaws.us-east-1.{svc}")])
        assert p["any"] is True, svc


def test_a_non_bedrock_endpoint_does_not_count():
    p = SA.vpc_endpoint_posture([epn(service="com.amazonaws.us-east-1.s3")])
    assert p["any"] is False


def test_vpcs_without_an_endpoint_are_named():
    p = SA.vpc_endpoint_posture([epn(vpc="vpc-1")], vpc_ids=["vpc-1", "vpc-2"])
    assert p["with_endpoint"] == {"vpc-1": ["bedrock-runtime"]}
    assert p["without_endpoint"] == ["vpc-2"]


def test_with_no_vpc_list_only_endpoint_owners_are_known():
    """Nothing can be said about VPCs that were never enumerated, and inventing them
    would be a finding about resources this scan never saw."""
    p = SA.vpc_endpoint_posture([epn(vpc="vpc-1")])
    assert p["without_endpoint"] == []


def test_no_endpoints_and_no_vpcs_is_unchecked_rather_than_failing():
    p = SA.vpc_endpoint_posture([], [])
    assert p["checked"] is False and p["any"] is False


# ── the declared gap ────────────────────────────────────────────────────────
def test_the_saas_gap_is_stated_plainly():
    """A reader who sees a shadow-AI section with no mention of hosted assistants will
    assume they were covered."""
    assert "NOT detectable" in SA.SAAS_NOT_DETECTABLE
    assert "egress proxy or a CASB" in SA.SAAS_NOT_DETECTABLE
    assert "flow logs record IP addresses" in SA.SAAS_NOT_DETECTABLE


def test_the_module_attempts_no_ip_matching():
    """No provider IP list, no CIDR table. Shipping one would be a detection surface
    whose misses read as passes."""
    import ast
    import inspect

    # Docstrings stripped, for the third time this pattern has come up: the module names
    # Cloudflare precisely to explain why matching IPs does not work, and a guard that
    # fires on that sentence pushes the reasoning out of the file to keep itself quiet.
    # Executable code is what is policed -- an IP rule has to live there.
    tree = ast.parse(inspect.getsource(SA))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            b = node.body
            if (b and isinstance(b[0], ast.Expr) and isinstance(b[0].value, ast.Constant)
                    and isinstance(b[0].value.value, str)):
                b.pop(0)
    code = ast.unparse(tree).lower()
    for banned in ("openai", "anthropic.com", "cidr", "ip_ranges", "ipaddress",
                   "ip_network", "inet_aton"):
        assert banned not in code, f"{banned} suggests an IP-matching rule"


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(SA), re.M)
