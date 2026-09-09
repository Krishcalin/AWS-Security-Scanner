"""Tranche 7 — the last never-observed HIGH checks, and why they were last.

THREE OF THESE REACH `_add` THROUGH A NON-LITERAL ID, which is why every previous
tranche skipped them: the static pass that located each earlier tranche's FAIL path
searches for `_add("FAIL", "<ID>", ...)`, and none of these is written that way.

  * `CWPP-01` is `fid = "CWPP-02" if m.kev else "CWPP-01"` — the id depends on whether
    the CVE is on the KEV catalogue, so the non-KEV branch is the one nothing drove.
  * `VULN-03` is one arm of a four-way `fid, tag = ...` on the Inspector resource type;
    only the ECR-container-image arm produces it.
  * `SEG-02` is not written in the scanner at all. `aws_exposure.microseg_findings`
    returns dicts carrying their own `"id"`, and the scanner emits them by `f["id"]`.

None of that is a defect — a check id computed from the finding is often the clearest
way to write it — but it does mean "which checks can fire" is not answerable by reading
for a literal, which is the whole reason `docs/CHECK_FIRING.md` records `_add` at runtime
instead of grepping for it.

`WAF-01` is the fourth and is genuinely different: it has no FAIL path at all. It is
addressed at the bottom of this file rather than driven, because giving it one is a
product decision, not a fixture.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_exposure, aws_graph                            # noqa: E402
from engine import aws_live_scanner as A                              # noqa: E402
from test_live_scanner import make_scanner                            # noqa: E402
from test_unproven_checks_tranche5 import _ids, _renders              # noqa: E402

OWN = "123456789012"
REGION = "us-east-1"


# ══════════════════════════════════════════════════════════════════════════════
# SEG-02 (HIGH) — an attached security group opening a wide range to the world
# ══════════════════════════════════════════════════════════════════════════════
def _sg(gid, from_port, to_port, proto="tcp"):
    return {"GroupId": gid, "GroupName": "app", "VpcId": "vpc-1",
            "IpPermissions": [{"IpProtocol": proto, "FromPort": from_port,
                               "ToPort": to_port,
                               "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                               "Ipv6Ranges": []}],
            "IpPermissionsEgress": []}


def _eni(gid):
    return {"NetworkInterfaceId": "eni-1", "SubnetId": "subnet-1", "VpcId": "vpc-1",
            "Groups": [{"GroupId": gid}], "Status": "in-use"}


def test_seg02_wide_world_open_range_on_an_attached_group_fails():
    """WIDE_SPAN is 100 ports. A range that big is not a service, it is an oversight."""
    found = aws_exposure.microseg_findings([_sg("sg-1", 1000, 2000)], [_eni("sg-1")])
    seg02 = [f for f in found if f["id"] == "SEG-02"]
    assert seg02, "no SEG-02 for a 1001-port world-open range"
    assert seg02[0]["status"] == "FAIL"
    assert "overly-wide port range" in seg02[0]["message"]


def test_seg02_is_silent_on_an_unattached_group():
    """A security group attached to no ENI protects nothing and reaches nothing, so a
    wide range in it is not an exposure — it is a leftover."""
    found = aws_exposure.microseg_findings([_sg("sg-1", 1000, 2000)], [])
    assert not [f for f in found if f["id"] == "SEG-02"]


def test_seg02_is_silent_on_a_narrow_range():
    found = aws_exposure.microseg_findings([_sg("sg-1", 443, 443)], [_eni("sg-1")])
    assert not [f for f in found if f["id"] == "SEG-02"]


def test_seg02_suppresses_seg01_for_the_same_group():
    """The wide-range finding subsumes the sensitive-port one; reporting both would
    count one misconfiguration twice."""
    found = aws_exposure.microseg_findings([_sg("sg-1", 1, 65535)], [_eni("sg-1")])
    ids = {f["id"] for f in found}
    assert "SEG-02" in ids and "SEG-01" not in ids


def test_seg02_renders_through_the_scanner():
    """The producer returns dicts; the scanner emits them by `f["id"]`. That indirection
    is exactly why no static pass could find this check's FAIL path."""
    s = make_scanner(sections=["EXPOSURE"])
    s.account = OWN
    s.graph = aws_graph.SecurityGraph()
    for f in aws_exposure.microseg_findings([_sg("sg-1", 1000, 2000)], [_eni("sg-1")]):
        s._add(f["status"], f["id"], "EXPOSURE", f["resource"], f["message"])
    _renders(s, "SEG-02", "HIGH", contains="overly-wide port range")


# ══════════════════════════════════════════════════════════════════════════════
# VULN-03 (HIGH) — an Inspector finding on an ECR container image
# ══════════════════════════════════════════════════════════════════════════════
IMAGE_ARN = f"arn:aws:ecr:{REGION}:{OWN}:repository/app/sha256:abc"


def _inspector(findings, *, ecr=True):
    insp = MagicMock()
    insp.batch_get_account_status.return_value = {"accounts": [{"resourceState": {
        "ec2": {"status": "ENABLED"},
        "ecr": {"status": "ENABLED" if ecr else "DISABLED"},
        "lambda": {"status": "ENABLED"}}}]}
    insp.get_paginator.return_value.paginate.return_value = [{"findings": findings}]
    insp.batch_get_finding_details.return_value = {"findingDetails": []}
    s = make_scanner(sections=["VULN"])
    s.account = OWN
    s.graph = aws_graph.SecurityGraph()
    s._clients[f"inspector2:{REGION}"] = insp
    return s


def _finding(resource_type, resource_id, *, severity="HIGH", cve="CVE-2024-0001"):
    return {
        "findingArn": f"arn:aws:inspector2:{REGION}:{OWN}:finding/{cve}",
        "severity": severity, "status": "ACTIVE", "type": "PACKAGE_VULNERABILITY",
        "packageVulnerabilityDetails": {
            "vulnerabilityId": cve,
            "vulnerablePackages": [{"name": "openssl", "version": "1.0",
                                    "fixedInVersion": "1.1"}]},
        "epss": {"score": 0.4},
        "exploitAvailable": "YES", "fixAvailable": "YES",
        "resources": [{"type": resource_type, "id": resource_id}],
    }


def test_vuln03_container_image_vulnerability_fails():
    """The ECR arm of a four-way branch on Inspector's resource type. VULN-01 (the
    catch-all) was driven long ago; this arm never was."""
    s = _inspector([_finding("AWS_ECR_CONTAINER_IMAGE", IMAGE_ARN)])
    s._check_vuln()
    _renders(s, "VULN-03", "HIGH", contains="container-image")


def test_a_container_cve_is_reported_once_as_vuln03_not_also_as_vuln02():
    """The four-way branch is an if/elif chain, so exactly one id is produced per
    finding. KEV outranks resource type — that arm is VULN-02's — and a container CVE
    that is not on KEV must not be counted under both."""
    s = _inspector([_finding("AWS_ECR_CONTAINER_IMAGE", IMAGE_ARN)])
    s._check_vuln()
    seen = {r.check_id for r in s.results if r.status == "FAIL"}
    assert "VULN-03" in seen and "VULN-02" not in seen


def test_vuln03_is_not_used_for_an_ec2_finding():
    s = _inspector([_finding("AWS_EC2_INSTANCE", "i-1")])
    s._check_vuln()
    assert not _ids(s, "VULN-03", "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# WAF-01 (HIGH) — the one that is not a fixture problem
# ══════════════════════════════════════════════════════════════════════════════
#: WAF-01 has NO FAIL path. Its only posture finding is a WARN saying "no Web ACLs in
#: this scope", and a blanket FAIL would flag every account that has nothing needing a
#: WAF — an unactionable finding on a correct estate, which is the WAF-01 shape the
#: bucket-B pass named and deliberately left alone.
#:
#: Giving it one is a product decision with a real cost, so it is recorded here rather
#: than quietly invented: the defensible version is "an internet-facing ALB, API Gateway
#: or CloudFront distribution exists AND no Web ACL is associated with it", which is a
#: different check from the one WAF-01 currently is, needs the exposure graph, and would
#: change what the id means for anyone already filtering on it.
WAF_01_NEEDS_A_PRODUCT_DECISION = (
    "WAF-01 warns when a scope has no Web ACLs. Making that a FAIL would flag every "
    "account with nothing to protect; the useful version is 'an internet-facing entry "
    "point exists with no Web ACL attached', which is a new check rather than a status "
    "flip on this one.")


def test_waf01_still_has_no_fail_path_and_the_reason_is_recorded():
    """Pinned so the gap stays visible. If WAF-01 gains a FAIL path, this test fails and
    whoever added it has to delete the note above — which is the point: the decision
    gets made deliberately rather than by a fixture appearing."""
    import ast
    import io
    src = io.open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "engine", "aws_live_scanner.py"), encoding="utf-8").read()
    fails = [n for n in ast.walk(ast.parse(src))
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "_add" and len(n.args) >= 2
             and isinstance(n.args[0], ast.Constant) and n.args[0].value == "FAIL"
             and isinstance(n.args[1], ast.Constant) and n.args[1].value == "WAF-01"]
    assert not fails, (
        "WAF-01 has gained a FAIL path. That is fine — but it changes what the id means "
        "for anyone filtering on it, so delete WAF_01_NEEDS_A_PRODUCT_DECISION and this "
        "test deliberately rather than leaving a stale note behind.")
    assert len(WAF_01_NEEDS_A_PRODUCT_DECISION) > 120


# ══════════════════════════════════════════════════════════════════════════════
# CWPP-01 (HIGH) — the non-KEV arm of the agentless side-scan
#
# `fid = "CWPP-02" if m.kev else "CWPP-01"`. The existing integration test supplies a
# CVE that IS on the KEV catalogue, so it has always driven CWPP-02 and never the arm
# beside it. The difference is one element of one set.
# ══════════════════════════════════════════════════════════════════════════════
from engine import aws_sidescan as _ss                                # noqa: E402

_DPKG = (b"Package: openssl\nStatus: install ok installed\n"
         b"Version: 3.0.2-0ubuntu1.1\nArchitecture: amd64\n\n")


class _Ctx:
    def __init__(self, ext):
        self._ext = ext

    def __enter__(self):
        return self._ext

    def __exit__(self, *a):
        return False


def _osv_record(cve, fixed="3.0.2-0ubuntu1.15"):
    return {"id": cve, "aliases": [cve],
            "affected": [{"package": {"ecosystem": "Ubuntu:22.04", "name": "openssl"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"},
                                                 {"fixed": fixed}]}],
                          "database_specific": {"severity": "CRITICAL"}}],
            "severity": [{"type": "CVSS_V3", "score": "9.8"}]}


def _sidescan_scanner(*, kev):
    s = make_scanner(sections=["SIDESCAN"])
    s.account = OWN
    s.side_scan = True
    g = aws_graph.SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("eni-1", "NetworkInterface")
    g.add_node(s._instance_arn("i-1"), "EC2Instance", instance_id="i-1")
    g.add_edge("internet", "eni-1", "EXPOSED_TO")
    g.add_edge("eni-1", s._instance_arn("i-1"), "ATTACHED_TO")
    s.graph = g
    ext = _ss.DictExtractor({"/etc/os-release": b"ID=ubuntu\nVERSION_ID=22.04\n",
                             "/var/lib/dpkg/status": _DPKG})
    s._sidescan_extractor_opener = lambda vol_ids, iid: _Ctx(ext)
    feed = _ss.OSVFeed.from_records([_osv_record("CVE-2024-9999")])
    s._load_vuln_db = lambda: (feed, {"CVE-2024-9999": 0.9},
                               {"CVE-2024-9999"} if kev else set(), set())
    return s


def test_cwpp01_non_kev_vulnerability_on_a_side_scanned_host_fails():
    """Most CVEs are not on KEV, so this arm is the common case in production and was
    the one nothing had ever exercised."""
    s = _sidescan_scanner(kev=False)
    s._check_side_scan()
    _renders(s, "CWPP-01", "HIGH", contains="CVE-2024-9999")
    assert not _ids(s, "CWPP-02", "FAIL"), "a non-KEV CVE must not be reported as KEV"


def test_cwpp02_is_still_the_kev_arm():
    """The pair has to stay distinguishable: if both arms produced the same id the
    prioritisation the split exists for would be gone."""
    s = _sidescan_scanner(kev=True)
    s._check_side_scan()
    assert _ids(s, "CWPP-02", "FAIL") and not _ids(s, "CWPP-01", "FAIL")
