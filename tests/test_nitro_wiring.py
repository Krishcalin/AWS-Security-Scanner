"""Phase 5 · slice 5.3 — the scanner surface for platform traffic encryption.

The slice composes with 5.1 rather than merely stacking beside it: CISA's Optimal for the
Networks / Traffic encryption function asks for encryption applied *"to the extent
possible"*, and an edge certificate never touches the traffic between instances. These
two checks are the only readable evidence about that layer, so that function could not
have reached Optimal before this slice existed.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_live_scanner as A
import aws_nitro as N
import aws_perm_ledger as L
import aws_ztmm as Z


def _ec2(instances, types, types_denied=False):
    c = MagicMock()
    c.describe_instances.return_value = {
        "Reservations": [{"Instances": list(instances)}]}
    if types_denied:
        c.describe_instance_types.side_effect = Exception("AccessDeniedException")
    else:
        c.describe_instance_types.return_value = {"InstanceTypes": list(types)}
    return c


def _scanner(client):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["EC2"])
        s.account = "123456789012"
    s._client = lambda svc, region=None: client
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def inst(iid, itype, state="running"):
    return {"InstanceId": iid, "InstanceType": itype, "State": {"Name": state}}


def tinfo(name, encrypts=True, hypervisor="nitro", omit=False):
    net = {}
    if not omit:
        net["EncryptionInTransitSupported"] = encrypts
    return {"InstanceType": name, "Hypervisor": hypervisor, "NetworkInfo": net}


def _run(instances, types, **kw):
    s = _scanner(_ec2(instances, types, **kw))
    s._check_platform_encryption()
    return s


def test_an_encrypting_type_passes():
    s = _run([inst("i-1", "m5.large")], [tinfo("m5.large", encrypts=True)])
    assert _ids(s, "NITRO-01", "PASS")
    assert not _ids(s, "NITRO-01", "FAIL")


def test_a_non_encrypting_type_is_reported():
    s = _run([inst("i-2", "t2.micro")],
             [tinfo("t2.micro", encrypts=False, hypervisor="xen")])
    f = _ids(s, "NITRO-01", "FAIL")
    assert f and "encrypted only if the application does it" in f[0].message


def test_the_finding_never_claims_traffic_was_exposed():
    """A capability claim, not an observation. OverWatch cannot watch a packet."""
    s = _run([inst("i-2", "t2.micro")], [tinfo("t2.micro", encrypts=False)])
    blob = " ".join(r.message for r in s.results).lower()
    assert "exposed" not in blob and "intercepted" not in blob


def test_a_xen_instance_raises_the_platform_generation_finding():
    s = _run([inst("i-2", "t2.micro")],
             [tinfo("t2.micro", encrypts=False, hypervisor="xen")])
    f = _ids(s, "NITRO-02", "FAIL")
    assert f and "Nitro Enclaves" in f[0].message


def test_a_nitro_instance_raises_no_hypervisor_finding():
    s = _run([inst("i-1", "m5.large")], [tinfo("m5.large", hypervisor="nitro")])
    assert not _ids(s, "NITRO-02")


def test_a_stopped_instance_is_not_reported():
    """A stopped instance has no traffic to encrypt."""
    s = _run([inst("i-3", "t2.micro", state="stopped")],
             [tinfo("t2.micro", encrypts=False)])
    assert not _ids(s, "NITRO-01", "FAIL")


def test_an_unresolvable_type_is_neither_pass_nor_fail():
    """Unknown is not unencrypted — folding the two together turns a coverage gap into
    a finding."""
    s = _run([inst("i-4", "exotic.9xlarge")], [])
    assert not _ids(s, "NITRO-01", "FAIL")
    assert not _ids(s, "NITRO-01", "PASS")


def test_an_absent_field_is_not_treated_as_unencrypted():
    s = _run([inst("i-5", "m4.large")], [tinfo("m4.large", omit=True)])
    assert not _ids(s, "NITRO-01", "FAIL")


def test_the_estate_summary_is_emitted_once():
    s = _run([inst("i-1", "m5.large"), inst("i-2", "t2.micro")],
             [tinfo("m5.large"), tinfo("t2.micro", encrypts=False)])
    info = _ids(s, "NITRO-00", "INFO")
    assert len(info) == 1 and "1 of 2 running instance(s)" in info[0].message


def test_the_summary_repeats_the_aws_scope():
    s = _run([inst("i-1", "m5.large")], [tinfo("m5.large")])
    assert "BETWEEN INSTANCES" in _ids(s, "NITRO-00", "INFO")[0].message


def test_a_denied_type_read_is_a_coverage_note_not_a_pass():
    s = _scanner(_ec2([inst("i-1", "m5.large")], [], types_denied=True))
    with patch.object(s, "_is_access_denied", return_value=True):
        s._check_platform_encryption()
    for cid in ("NITRO-01", "NITRO-02"):
        assert cid in s._coverage.not_evaluated
    assert not _ids(s, "NITRO-01", "PASS")


def test_no_instances_emits_nothing():
    s = _run([], [])
    assert not [r for r in s.results if r.check_id.startswith("NITRO")]


# ── the composition with slice 5.1 ──────────────────────────────────────────
def test_the_ztmm_traffic_encryption_function_now_reaches_optimal():
    """The point of the slice. CISA's Optimal asks for encryption applied to the extent
    possible, and TLS at an edge never touches traffic between instances."""
    key = ("Networks", "Traffic encryption")
    assert Z.OPTIMAL in Z.ZTMM_MAPPING[key]
    assert set(Z.ZTMM_MAPPING[key][Z.OPTIMAL]) == {"NITRO-01", "NITRO-02"}


def test_the_composed_function_scores_optimal_when_everything_passes():
    class R:
        def __init__(self, c, st):
            self.check_id, self.status = c, st
    passing = [R(c, "PASS") for c in
               ("ELB-01", "ACM-01", "ACM-02", "NITRO-01", "NITRO-02")]
    r = Z.score_function("Networks", "Traffic encryption", Z.ZTMM_MAPPING, passing)
    assert r["stage"] == Z.OPTIMAL


def test_a_nitro_gap_holds_the_function_at_advanced():
    class R:
        def __init__(self, c, st):
            self.check_id, self.status = c, st
    rows = [R(c, "PASS") for c in ("ELB-01", "ACM-01", "ACM-02", "NITRO-02")]
    rows.append(R("NITRO-01", "FAIL"))
    r = Z.score_function("Networks", "Traffic encryption", Z.ZTMM_MAPPING, rows)
    assert r["stage"] == Z.ADVANCED


def test_the_slice_needs_no_new_iam_action():
    """ec2:DescribeInstanceTypes falls under SecurityAudit's ec2:Describe*."""
    for cid in ("NITRO-01", "NITRO-02"):
        assert cid in L.REQUIREMENTS
        assert all(r.action.startswith("ec2:Describe") for r in L.REQUIREMENTS[cid])
