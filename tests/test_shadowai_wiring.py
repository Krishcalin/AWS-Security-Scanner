"""Phase 4 · slice 4.4 — the scanner surface for shadow AI.

Three behaviours are load-bearing, and all three are about not crying wolf.

**Without a declared owner set, `SHAI-01` does not fire.** It lists what it found as an
INFO instead. A check that flags every legitimate creator on an operator's first scan is
a check they turn off, and then it never fires on the one that mattered either.

**A refused CloudTrail read is not an empty account.** "Nobody built AI here" and "we
could not ask" are different claims, and only one of them is reassuring.

**The third-party SaaS gap is stated on every scan.** A reader who sees a shadow-AI
section with no mention of hosted assistants will assume they were covered — the same
phantom-pass-by-omission `MCP-04` and the `VEC-*` findings exist to prevent. Decision
**D9** records why the proposed flow-log approach was refused rather than approximated.
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_perm_ledger as L
import aws_shadowai as SA
from aws_live_scanner import AWSLiveScanner

ML_ROLE = "arn:aws:iam::123456789012:role/MLPlatform"
APP_ROLE = "arn:aws:iam::123456789012:role/PaymentsApp"


def _scanner(clients, owners=(), scanned=("us-east-1",)):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["SHADOW_AI"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: clients.get(svc, MagicMock())
    s._ai_owners = tuple(owners)
    s._coverage.scanned_regions = list(scanned)
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _ct(events=(), denied=False):
    c = MagicMock()
    if denied:
        c.get_paginator.side_effect = Exception("AccessDeniedException")
        return c
    rows = [{"CloudTrailEvent": json.dumps(e)} for e in events]
    pag = MagicMock()
    pag.paginate.return_value = [{"Events": rows}]
    c.get_paginator.return_value = pag
    return c


def ev(name="CreateAgent", arn=ML_ROLE, region="us-east-1"):
    return {"eventName": name, "awsRegion": region, "userIdentity": {"arn": arn}}


def _ec2(endpoints=(), vpcs=("vpc-1",)):
    c = MagicMock()
    c.describe_vpc_endpoints.return_value = {"VpcEndpoints": list(endpoints)}
    c.describe_vpcs.return_value = {"Vpcs": [{"VpcId": v} for v in vpcs]}
    return c


# ── the declared owner set ──────────────────────────────────────────────────
def test_without_a_declared_set_nothing_fails():
    """The load-bearing restraint. Flagging every legitimate creator on the first scan
    is how a check gets turned off before it ever catches anything."""
    s = _scanner({"cloudtrail": _ct([ev(arn=APP_ROLE)])})
    s._check_undeclared_ai_creators()
    assert not _ids(s, "SHAI-01", "FAIL")
    info = _ids(s, "SHAI-00", "INFO")
    assert any("No owner set was declared" in r.message for r in info)
    assert any(APP_ROLE in r.message for r in info)


def test_an_undeclared_creator_fails_once_a_set_exists():
    s = _scanner({"cloudtrail": _ct([ev(arn=APP_ROLE)])}, owners=[ML_ROLE])
    s._check_undeclared_ai_creators()
    f = _ids(s, "SHAI-01", "FAIL")
    assert len(f) == 1 and "PaymentsApp" in f[0].message


def test_a_declared_creator_passes():
    s = _scanner({"cloudtrail": _ct([ev(arn=ML_ROLE)])}, owners=["MLPlatform"])
    s._check_undeclared_ai_creators()
    assert _ids(s, "SHAI-01", "PASS") and not _ids(s, "SHAI-01", "FAIL")


def test_only_creation_events_are_considered():
    """Usage is AITHR-01's question, and it needs data events most accounts do not
    have. Creation is the moment shadow AI becomes visible."""
    s = _scanner({"cloudtrail": _ct([ev("GetAgent", arn=APP_ROLE),
                                     ev("ListAgents", arn=APP_ROLE)])},
                 owners=[ML_ROLE])
    s._check_undeclared_ai_creators()
    assert not _ids(s, "SHAI-01")


def test_no_ai_events_at_all_is_silent():
    s = _scanner({"cloudtrail": _ct([])}, owners=[ML_ROLE])
    s._check_undeclared_ai_creators()
    assert not _ids(s, "SHAI-01") and not _ids(s, "SHAI-02")


# ── regions ─────────────────────────────────────────────────────────────────
def test_ai_built_in_an_unscanned_region_is_reported():
    """Every other AI check ran against the scanned regions, so for these resources the
    posture is unknown rather than clean."""
    s = _scanner({"cloudtrail": _ct([ev(region="ap-south-1")])},
                 owners=[ML_ROLE], scanned=["us-east-1"])
    s._check_undeclared_ai_creators()
    f = _ids(s, "SHAI-02", "FAIL")
    assert f and "ap-south-1" in f[0].message
    assert "unknown rather than clean" in f[0].message


def test_ai_built_only_in_scanned_regions_raises_nothing():
    s = _scanner({"cloudtrail": _ct([ev(region="us-east-1")])},
                 owners=[ML_ROLE], scanned=["us-east-1"])
    s._check_undeclared_ai_creators()
    assert not _ids(s, "SHAI-02")


# ── refused reads ───────────────────────────────────────────────────────────
def test_a_denied_cloudtrail_read_is_not_an_empty_account():
    """'Nobody built AI here' and 'we could not ask' are different claims, and only one
    of them is reassuring."""
    s = _scanner({"cloudtrail": _ct(denied=True)}, owners=[ML_ROLE])
    s._check_undeclared_ai_creators()
    assert not _ids(s, "SHAI-01", "PASS")
    for cid in ("SHAI-01", "SHAI-02"):
        assert cid in s._coverage.not_evaluated
    assert any("not the same as nobody having built any" in r.message
               for r in _ids(s, "SHAI-00"))


def test_a_denied_endpoint_read_is_a_coverage_note():
    ec2 = _ec2()
    ec2.describe_vpc_endpoints.side_effect = Exception("AccessDeniedException")
    s = _scanner({"ec2": ec2})
    with patch.object(s, "_is_access_denied", return_value=True):
        s._check_bedrock_private_path()
    assert "SHAI-03" in s._coverage.not_evaluated
    assert not _ids(s, "SHAI-03", "PASS")


# ── the VPC endpoint substitute ─────────────────────────────────────────────
def test_a_vpc_without_a_bedrock_endpoint_warns():
    s = _scanner({"ec2": _ec2(endpoints=[], vpcs=["vpc-1"])})
    s._check_bedrock_private_path()
    w = _ids(s, "SHAI-03", "WARN")
    assert w and "vpc-1" in w[0].message
    assert "no VPC endpoint policy can bound which models" in w[0].message


def test_the_finding_says_it_may_not_apply():
    """OverWatch cannot tell from configuration which VPCs use Bedrock, and pretending
    otherwise would put a finding on every unrelated VPC in the account."""
    s = _scanner({"ec2": _ec2(endpoints=[], vpcs=["vpc-1"])})
    s._check_bedrock_private_path()
    assert "Not applicable if the VPC does not use Bedrock" in \
        _ids(s, "SHAI-03", "WARN")[0].message


def test_a_vpc_with_an_endpoint_passes():
    ep = {"VpcId": "vpc-1", "ServiceName": "com.amazonaws.us-east-1.bedrock-runtime"}
    s = _scanner({"ec2": _ec2(endpoints=[ep], vpcs=["vpc-1"])})
    s._check_bedrock_private_path()
    assert _ids(s, "SHAI-03", "PASS")


def test_no_vpcs_at_all_raises_nothing():
    s = _scanner({"ec2": _ec2(endpoints=[], vpcs=[])})
    s._check_bedrock_private_path()
    assert not _ids(s, "SHAI-03")


# ── the declared gap ────────────────────────────────────────────────────────
def test_the_saas_gap_is_stated_on_every_scan():
    s = _scanner({"cloudtrail": _ct([]), "ec2": _ec2()})
    s._check_shadow_ai()
    info = _ids(s, "SHAI-00", "INFO")
    assert any("NOT detectable" in r.message for r in info)
    assert any("egress proxy or a CASB" in r.message for r in info)


# ── the CLI seam ────────────────────────────────────────────────────────────
def test_the_owner_flag_reaches_the_scanner():
    """Every test above sets _ai_owners by hand. This is the one that crosses the seam
    from the flag — the gap that made --pentest-results dead code in slice 3.5."""
    import aws_live_scanner as A
    from types import SimpleNamespace
    s = _scanner({})
    args = SimpleNamespace(
        ai_owners="MLPlatform, arn:aws:iam::1:role/Other", pentest_results=None,
        tool_patterns=None, side_scan=False, side_scan_targets=None,
        side_scan_tag=None, side_scan_max=10, side_scan_secrets=False,
        side_scan_images=False, side_scan_images_max=1, ecr_scan_max_images=20,
        vuln_db=None, vuln_db_pubkey=None, flow_logs=False)
    A._apply_phase6_config(s, args)
    assert s._ai_owners == ("MLPlatform", "arn:aws:iam::1:role/Other")


def test_an_absent_flag_leaves_an_empty_owner_set():
    import aws_live_scanner as A
    from types import SimpleNamespace
    s = _scanner({}, owners=["stale"])
    args = SimpleNamespace(
        ai_owners="", pentest_results=None, tool_patterns=None, side_scan=False,
        side_scan_targets=None, side_scan_tag=None, side_scan_max=10,
        side_scan_secrets=False, side_scan_images=False, side_scan_images_max=1,
        ecr_scan_max_images=20, vuln_db=None, vuln_db_pubkey=None, flow_logs=False)
    A._apply_phase6_config(s, args)
    assert s._ai_owners == ()


# ── the ledger ──────────────────────────────────────────────────────────────
def test_every_shadow_ai_check_is_in_the_ledger():
    import aws_live_scanner as A
    shai = {c for c in A.CHECK_SEVERITY if c.startswith("SHAI-")}
    assert shai <= set(L.REQUIREMENTS), shai - set(L.REQUIREMENTS)


def test_the_ledger_asks_for_no_flow_log_content():
    """D9. logs:StartQuery is the flow-log content read, and refusing the IP-matching
    approach means never needing it."""
    actions = {r.action for cid, reqs in L.REQUIREMENTS.items()
               if cid.startswith("SHAI-") for r in reqs}
    for banned in ("logs:StartQuery", "logs:GetQueryResults", "s3:GetObject"):
        assert banned not in actions, banned
