"""Phase 5 · slice 5.2 — the scanner surface for the data perimeter.

Two defects the smoke test caught here, both phantoms, both pinned below.

**Absence needs a complete read.** A member-account scan reads the (empty) endpoint
layer and is denied Organizations. Reporting that as "no perimeter" manufactures a
finding out of a permission error, so an objective with any unread layer and no evidence
is UNREADABLE, never UNMET.

**`_paginate_all` swallows every exception and returns `[]`.** Routing the org walk
through it would turn a denied `ListPoliciesForTarget` into "no policies exist" — so this
section paginates by hand, and a denial actually reaches the caller.
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_live_scanner as A
from engine import aws_perimeter as P
from engine import aws_perm_ledger as L


def doc(key, value="o-abc"):
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Action": "*", "Resource": "*",
        "Condition": {"StringNotEquals": {key: value}}}]})


def _org(scp_keys=(), rcp_keys=(), deny_list=False, deny_describe=False,
         no_org=False, endpoints=None, deny_endpoints=False):
    org = MagicMock()
    if no_org:
        org.describe_organization.side_effect = Exception("AWSOrganizationsNotInUseException")
    else:
        org.describe_organization.return_value = {"Organization": {"Id": "o-abc"}}
    org.list_parents.return_value = {"Parents": [{"Id": "r-root", "Type": "ROOT"}]}
    ids = {}

    def _list(TargetId=None, Filter=None, **kw):
        if deny_list:
            raise Exception("AccessDeniedException")
        keys = scp_keys if Filter == "SERVICE_CONTROL_POLICY" else rcp_keys
        out = []
        for i, k in enumerate(keys):
            pid = f"{Filter}-{TargetId}-{i}"
            ids[pid] = k
            out.append({"Id": pid})
        return {"Policies": out}

    def _describe(PolicyId=None):
        if deny_describe:
            raise Exception("AccessDeniedException")
        return {"Policy": {"Content": doc(ids[PolicyId])}}

    org.list_policies_for_target.side_effect = _list
    org.describe_policy.side_effect = _describe

    ec2 = MagicMock()
    if deny_endpoints:
        ec2.describe_vpc_endpoints.side_effect = Exception("AccessDeniedException")
    else:
        ec2.describe_vpc_endpoints.return_value = {
            "VpcEndpoints": [{"PolicyDocument": d} for d in (endpoints or [])]}
    return org, ec2


def _run(**kw):
    org, ec2 = _org(**kw)
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["IAM"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: org if svc == "organizations" else ec2
    s._is_access_denied = lambda e: "AccessDenied" in str(e)
    s._check_data_perimeter()
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


FULL = {"scp_keys": ("aws:ResourceOrgID", "aws:SourceVpc"),
        "rcp_keys": ("aws:PrincipalOrgID", "aws:SourceIp")}


# ── the happy path ──────────────────────────────────────────────────────────
def test_a_complete_perimeter_passes_all_three():
    s = _run(**FULL)
    for cid in ("PERIM-01", "PERIM-02", "PERIM-03"):
        assert _ids(s, cid, "PASS"), cid


def test_the_summary_counts_three_of_three():
    s = _run(**FULL)
    assert "3 of 3" in _ids(s, "PERIM-00", "INFO")[0].message


def test_an_empty_org_fails_all_three():
    s = _run(scp_keys=(), rcp_keys=())
    for cid in ("PERIM-01", "PERIM-02", "PERIM-03"):
        assert _ids(s, cid, "FAIL"), cid


# ── AWS's asymmetry, at the scanner surface ─────────────────────────────────
def test_principalorgid_in_an_scp_does_not_pass_the_identity_perimeter():
    """The load-bearing wiring test. An SCP bounds what MY principals may do, so it
    cannot constrain who reaches my resources -- however it is written."""
    s = _run(scp_keys=("aws:PrincipalOrgID",), rcp_keys=())
    assert _ids(s, "PERIM-01", "FAIL")
    assert not _ids(s, "PERIM-01", "PASS")


def test_resourceorgid_in_an_rcp_does_not_pass_the_resource_perimeter():
    s = _run(scp_keys=(), rcp_keys=("aws:ResourceOrgID",))
    assert _ids(s, "PERIM-02", "FAIL")
    assert not _ids(s, "PERIM-02", "PASS")


def test_an_endpoint_policy_can_carry_the_identity_perimeter():
    """AWS names VPC endpoint policies for the from-my-networks half of the objective."""
    s = _run(scp_keys=(), rcp_keys=(), endpoints=[doc("aws:PrincipalOrgID")])
    assert _ids(s, "PERIM-01", "PASS")


# ── the phantom guards ──────────────────────────────────────────────────────
def test_a_denied_list_is_a_coverage_note_not_a_finding():
    """_paginate_all swallows exceptions into [], which would read as 'no policies
    exist'. This section paginates by hand so the denial actually surfaces."""
    s = _run(deny_list=True)
    for cid in ("PERIM-01", "PERIM-02", "PERIM-03"):
        assert cid in s._coverage.not_evaluated, cid
        assert not _ids(s, cid, "FAIL"), cid
        assert not _ids(s, cid, "PASS"), cid


def test_a_denied_describe_is_also_a_coverage_note():
    s = _run(scp_keys=("aws:ResourceOrgID",), deny_describe=True)
    assert "PERIM-02" in s._coverage.not_evaluated
    assert not _ids(s, "PERIM-02", "FAIL")


def test_the_denied_note_names_the_action():
    s = _run(deny_list=True)
    actions = " ".join(str(v) for v in s._coverage.not_evaluated.values())
    assert "organizations:" in actions


def test_a_readable_empty_endpoint_layer_does_not_license_an_absence_claim():
    """The exact defect the smoke test caught: the endpoint layer read fine and was
    empty, Organizations was denied, and all three objectives reported 'no policy
    carries the key' -- a finding manufactured out of a permission error."""
    s = _run(deny_list=True, endpoints=[])
    assert not _ids(s, "PERIM-01", "FAIL")
    assert "PERIM-01" in s._coverage.not_evaluated


def test_no_organization_is_not_a_pass():
    s = _run(no_org=True)
    for cid in ("PERIM-01", "PERIM-02", "PERIM-03"):
        assert not _ids(s, cid, "PASS"), cid


def test_denied_endpoints_alone_still_allow_the_org_evidence_to_stand():
    """A denied endpoint read limits the VIEW; it does not erase an RCP that was read."""
    s = _run(**FULL, deny_endpoints=True)
    assert _ids(s, "PERIM-01", "PASS")


def test_the_summary_is_emitted_once_even_when_everything_is_denied():
    s = _run(deny_list=True)
    info = _ids(s, "PERIM-00", "INFO")
    assert len(info) == 1 and "not clean" in info[0].message


def test_the_summary_says_presence_not_effect():
    s = _run(**FULL)
    assert "PRESENCE and SHAPE" in _ids(s, "PERIM-00", "INFO")[0].message


def test_the_region_scope_of_endpoint_policies_is_stated():
    """Endpoint policies are per-Region; the summary must not imply a global read."""
    s = _run(**FULL)
    assert "per-Region" in _ids(s, "PERIM-00", "INFO")[0].message


@pytest.mark.parametrize("verb", ["enforced", "prevented", "blocked"])
def test_no_emitted_finding_claims_the_perimeter_takes_effect(verb):
    s = _run(**FULL)
    blob = " ".join(r.message for r in s.results).lower()
    assert verb not in blob


# ── the ledger ──────────────────────────────────────────────────────────────
def test_the_slice_records_what_declining_the_grant_costs():
    for cid in ("PERIM-01", "PERIM-02", "PERIM-03"):
        assert cid in L.REQUIREMENTS
        assert all(r.action.startswith("organizations:")
                   for r in L.REQUIREMENTS[cid]), cid


def test_the_ledger_actions_are_read_verbs():
    for cid in ("PERIM-01", "PERIM-02", "PERIM-03"):
        for r in L.REQUIREMENTS[cid]:
            verb = r.action.split(":", 1)[1]
            assert verb.startswith(("List", "Describe", "Get")), r.action


# ── the composition with slice 5.1 ──────────────────────────────────────────
def test_the_data_access_function_now_reaches_optimal_through_the_perimeter():
    """Everything already mapped to Data/Data access is a PER-RESOURCE control -- this
    bucket policy, that external grant. CISA's Optimal asks for access governed by
    enterprise-wide rules rather than resource by resource, which is what a data
    perimeter is: the organization-wide floor under every individual policy."""
    from engine import aws_ztmm as Z
    m = Z.ZTMM_MAPPING[("Data", "Data access")]
    assert set(m[Z.OPTIMAL]) == {"PERIM-01", "PERIM-02"}


def test_the_network_segmentation_function_reaches_optimal_through_perim_03():
    from engine import aws_ztmm as Z
    assert Z.ZTMM_MAPPING[("Networks", "Network segmentation")][Z.OPTIMAL] == ["PERIM-03"]


def test_an_advice_only_check_is_not_scored_as_a_control():
    """SEGREC-01 is an INFO recommendation, not a pass/fail control. A ZTMM function
    cannot be scored on advice -- it would count as unscored forever, or worse, as a
    gap the operator can never close."""
    from engine import aws_ztmm as Z
    assert "SEGREC-01" not in repr(Z.ZTMM_MAPPING)


def test_the_composed_data_access_function_scores_optimal_when_the_perimeter_passes():
    from engine import aws_ztmm as Z

    class R:
        def __init__(self, c, st):
            self.check_id, self.status = c, st
    rows = [R(c, "PASS") for c in ("S3-01", "S3-09", "S3-10", "EXTACCESS-02",
                                   "PERIM-01", "PERIM-02")]
    assert Z.score_function("Data", "Data access", Z.ZTMM_MAPPING, rows)["stage"] == Z.OPTIMAL


def test_a_missing_perimeter_holds_data_access_at_advanced():
    from engine import aws_ztmm as Z

    class R:
        def __init__(self, c, st):
            self.check_id, self.status = c, st
    rows = [R(c, "PASS") for c in ("S3-01", "S3-09", "S3-10", "EXTACCESS-02", "PERIM-02")]
    rows.append(R("PERIM-01", "FAIL"))
    assert Z.score_function("Data", "Data access", Z.ZTMM_MAPPING, rows)["stage"] == Z.ADVANCED


# ── the hang this section introduced, and its guard ─────────────────────────
def test_a_bare_magicmock_client_terminates_rather_than_spinning():
    """The regression that cost a suite run. The org walk paginates by hand, and the
    exit condition was `if not token: break`. A MagicMock's .get("NextToken") returns a
    truthy MagicMock, so the loop never exited -- and because this section is called
    from _check_iam, EVERY pre-existing test that reaches the IAM section with mock
    clients hung. A continuation token is a string; anything else ends the walk."""
    import threading
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["IAM"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: MagicMock()
    done = threading.Event()

    def _go():
        try:
            s._check_data_perimeter()
        finally:
            done.set()

    t = threading.Thread(target=_go, daemon=True)
    t.start()
    assert done.wait(timeout=20), "_check_data_perimeter did not terminate"


def test_a_non_string_continuation_token_ends_the_walk():
    org, ec2 = _org(**FULL)
    org.list_policies_for_target.side_effect = None
    org.list_policies_for_target.return_value = {"Policies": [], "NextToken": object()}
    with patch("engine.aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["IAM"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: org if svc == "organizations" else ec2
    s._is_access_denied = lambda e: False
    s._check_data_perimeter()
    assert _ids(s, "PERIM-00", "INFO")
