"""The CIS Amazon Linux 2 Benchmark v4.0.0 mapping, and the three checks that can fire.

THE INTERESTING PROPERTY OF THIS BATCH IS WHAT IT DID NOT BUILD. The benchmark has 287
recommendations and 252 of them read state OverWatch cannot see — file content, file
modes, running kernel parameters. Registering checks for those would have put the largest
block of registered-but-unreachable ids in this product's history into the catalogue,
which is the exact failure `docs/CHECK_FIRING.md` measures. So the mapping records them
against the CAPABILITY each is blocked on, and only the 35 that SSM Inventory can decide
became checks.

These tests therefore assert two different things: that the three checks fire and render
correctly, and that the mapping is honest about the other 252 — that nothing is filed as
covered without a check, that every blocked row names a real blocker, and that no check
was registered for a row nothing can decide.
"""
from __future__ import annotations

import io
import os
import re
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_cis_al2 as A                                # noqa: E402
from engine import aws_cis_al2_map as M                            # noqa: E402
from test_live_scanner import MockClientError, make_scanner        # noqa: E402

OWN = "123456789012"
IID = "i-0abc123"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _renders(s, cid, contains=None):
    from engine.aws_live_scanner import CHECK_SEVERITY
    hits = _ids(s, cid, "FAIL")
    assert hits, f"{cid} did not FAIL"
    r = hits[0]
    assert r.severity == CHECK_SEVERITY[cid]
    assert r.remediation_cmd, f"{cid} carries no remediation"
    assert r.compliance.get("CIS-AL2"), f"{cid} carries no CIS-AL2 citation"
    if contains:
        assert contains in r.message, f"{cid} lacks {contains!r}: {r.message}"
    return r


class _Pager:
    def __init__(self, key, items):
        self._key, self._items = key, items

    def paginate(self, **kw):
        return [{self._key: self._items}]


def _scanner(*, managed=True, apps=None, svcs=None, platform="Linux"):
    s = make_scanner(sections=["AMAZONLINUX"])
    s.account = OWN
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = lambda m: _Pager(
        "Reservations", [{"Instances": [{"InstanceId": IID}]}])
    s._clients["ec2:us-east-1"] = ec2

    ssm = MagicMock()
    info = ([{"InstanceId": IID, "ResourceType": "EC2Instance",
              "PingStatus": "Online", "PlatformType": platform}] if managed else [])
    ssm.get_paginator.side_effect = lambda m: _Pager("InstanceInformationList", info)

    def entries(InstanceId=None, TypeName=None, **kw):
        table = {A.APPLICATION_TYPE: apps, A.SERVICE_TYPE: svcs}
        v = table.get(TypeName)
        if v is None:
            raise MockClientError("InvalidTypeNameException", "not collected")
        return {"Entries": v}

    ssm.list_inventory_entries.side_effect = entries
    s._clients["ssm:us-east-1"] = ssm
    return s


def _pkg(name, version="1.0"):
    return {"Name": name, "Version": version}


#: a host with every required package and nothing prohibited
CLEAN = [_pkg(p) for p in A.REQUIRED_PACKAGES]


# ═════════════════════════════════════════════════════════════════════════════════
# the three checks
# ═════════════════════════════════════════════════════════════════════════════════
def test_al2_01_fires_on_a_prohibited_package():
    s = _scanner(apps=CLEAN + [_pkg("telnet-server", "0.17")], svcs=[])
    s._check_amazonlinux()
    r = _renders(s, "AL2-01", contains="telnet-server")
    assert "cleartext" in r.message
    assert "CIS-AL2 2.2.15" in r.message, r.message


def test_al2_01_reports_one_finding_per_package_not_per_host():
    """An operator remediates a package at a time. Collapsing twelve prohibited packages
    into one finding gives them a single row to tick off against twelve decisions."""
    s = _scanner(apps=CLEAN + [_pkg("telnet-server"), _pkg("vsftpd"), _pkg("squid")],
                 svcs=[])
    s._check_amazonlinux()
    got = {r.resource for r in _ids(s, "AL2-01", "FAIL")}
    assert got == {f"{IID}/telnet-server", f"{IID}/vsftpd", f"{IID}/squid"}, got


def test_al2_02_fires_when_a_required_package_is_absent():
    s = _scanner(apps=[_pkg(p) for p in A.REQUIRED_PACKAGES if p != "audit"], svcs=[])
    s._check_amazonlinux()
    r = _renders(s, "AL2-02", contains="audit")
    assert "no kernel audit trail" in r.message


def test_al2_03_fires_on_an_enabled_prohibited_unit():
    s = _scanner(apps=CLEAN,
                 svcs=[{"Name": "telnet.socket", "Status": "running"}])
    s._check_amazonlinux()
    r = _renders(s, "AL2-03", contains="telnet.socket")
    assert "listening" in r.message


def test_al2_03_is_rated_above_al2_01_and_the_reason_is_in_the_finding():
    """An installed package is latent surface; an enabled unit is a socket listening now.
    Rating them the same would tell an operator the two are equally urgent."""
    from engine.aws_live_scanner import CHECK_SEVERITY
    assert CHECK_SEVERITY["AL2-03"] == "HIGH"
    assert CHECK_SEVERITY["AL2-01"] == "MEDIUM"


def test_a_stopped_unit_does_not_fire():
    s = _scanner(apps=CLEAN,
                 svcs=[{"Name": "telnet.socket", "Status": "stopped",
                        "StartType": "disabled"}])
    s._check_amazonlinux()
    assert not _ids(s, "AL2-03", "FAIL")


def test_a_clean_host_produces_no_failures():
    s = _scanner(apps=CLEAN, svcs=[])
    s._check_amazonlinux()
    for cid in ("AL2-01", "AL2-02", "AL2-03"):
        assert not _ids(s, cid, "FAIL"), cid
    assert _ids(s, "AL2-01", "PASS")


# ═════════════════════════════════════════════════════════════════════════════════
# the honesty of "not assessed"
# ═════════════════════════════════════════════════════════════════════════════════
def test_an_unmanaged_host_is_a_coverage_statement_not_a_pass():
    """THE FAILURE THIS PREVENTS. Every check returns an empty list when its inventory is
    missing, and an empty list of findings is indistinguishable from a compliant host."""
    s = _scanner(managed=False)
    s._check_amazonlinux()
    infos = _ids(s, "AL2-00", "INFO")
    assert infos and "NOT assessed" in infos[0].message
    assert "not a pass" in infos[0].message
    for cid in ("AL2-01", "AL2-02", "AL2-03"):
        assert not _ids(s, cid, "PASS") and not _ids(s, cid, "FAIL"), cid


def test_an_ssm_managed_host_with_no_package_inventory_is_also_not_assessed():
    s = _scanner(apps=None, svcs=None)
    s._check_amazonlinux()
    infos = _ids(s, "AL2-00", "INFO")
    assert infos and "no AWS:Application inventory" in infos[0].message


def test_absent_service_inventory_is_stated_rather_than_assumed():
    """AWS:Service collects Windows services; whether a Linux host reports anything under
    it is not something this module asserts. It reads what is there and says what was not
    decided, instead of hard-coding a claim about AWS's inventory schema."""
    s = _scanner(apps=CLEAN, svcs=None)
    s._check_amazonlinux()
    info = _ids(s, "AL2-00", "INFO")[0]
    assert "Service state was not assessed" in info.message
    assert not _ids(s, "AL2-03", "FAIL")


def test_missing_required_packages_says_nothing_on_an_empty_listing():
    """An inventory that was never collected and one that is genuinely empty produce the
    same empty list. Treating the second as "nothing is installed" would fail every
    required package on a host nobody has inventoried."""
    assert A.missing_required_packages(IID, None) == []
    assert A.missing_required_packages(IID, []) == []
    assert A.missing_required_packages(IID, [_pkg("sudo")])


def test_a_windows_host_is_left_to_winvuln():
    s = _scanner(apps=CLEAN, svcs=[], platform="Windows")
    s._check_amazonlinux()
    assert not s.results, "a Windows host must not be assessed against a Linux benchmark"


# ═════════════════════════════════════════════════════════════════════════════════
# the mapping
# ═════════════════════════════════════════════════════════════════════════════════
def test_every_recommendation_is_present_once():
    assert len(M.RECOMMENDATIONS) == 287
    assert sum(c for _n, _l, c, _v in M.SUBSECTIONS) == 287


def test_the_subsection_counts_agree_with_the_rows():
    for num, label, count, covered in M.SUBSECTIONS:
        rows = [r for r in M.RECOMMENDATIONS
                if ".".join(r.split(".")[:2]) == num]
        assert len(rows) == count, f"{num}: declared {count}, has {len(rows)}"
        got = sum(1 for r in rows if M.RECOMMENDATIONS[r][1] == M.COVERED)
        assert got == covered, f"{num}: declared {covered} covered, has {got}"


def test_covered_means_a_real_check_and_blocked_means_a_real_blocker():
    from engine.aws_live_scanner import CHECK_SEVERITY
    for rec, (src, verdict, checks, blocker) in M.RECOMMENDATIONS.items():
        assert src in M.SOURCES, f"{rec}: unknown source {src!r}"
        assert verdict in M.VERDICTS, f"{rec}: unknown verdict {verdict!r}"
        if verdict == M.COVERED:
            assert checks, f"{rec} is covered by nothing"
            for c in checks:
                assert c in CHECK_SEVERITY, f"{rec} cites {c}, which does not exist"
            assert not blocker, f"{rec} is covered AND blocked"
        else:
            assert not checks, f"{rec} is blocked but names checks"
            assert blocker in M.BLOCKERS, f"{rec}: unknown blocker {blocker!r}"


def test_every_blocker_says_what_would_unblock_it():
    """A blocker with no account of what would lift it is an excuse, not a record."""
    assert M.BLOCKERS
    for name, why in M.BLOCKERS.items():
        assert len(why) > 120, f"{name} is asserted without an explanation"


def test_no_check_claims_a_recommendation_the_mapping_says_is_blocked():
    """The direction that would actually mislead. A check citing a blocked row would be
    claiming coverage of state the product cannot see."""
    from engine.aws_live_scanner import COMPLIANCE_MAP
    for check, fw in COMPLIANCE_MAP.items():
        rec = fw.get("CIS-AL2")
        if not rec:
            continue
        assert rec in M.RECOMMENDATIONS, f"{check} cites {rec!r}, not in the benchmark"
        assert M.RECOMMENDATIONS[rec][1] == M.COVERED, (
            f"{check} cites {rec}, which the mapping records as blocked")


def test_the_shape_of_the_problem_is_recorded_not_rounded_away():
    """The uncomfortable number is the point of the mapping. If a future change quietly
    reclassifies rows to make coverage look better, this notices."""
    by = M.by_source()
    assert sum(by.values()) == 287
    covered = sum(1 for v in M.RECOMMENDATIONS.values() if v[1] == M.COVERED)
    assert covered == 35, f"covered is {covered}; if that moved, say why in the commit"
    # The overwhelming majority reads in-guest state, and that is why this benchmark
    # cannot be covered by a control-plane scanner today.
    assert by["FILE"] + by["FILEMODE"] + by["ACCOUNT"] + by["KERNEL"] > 200


# ═════════════════════════════════════════════════════════════════════════════════
# the licence condition
# ═════════════════════════════════════════════════════════════════════════════════
def test_the_mapping_reproduces_no_recommendation_titles():
    """A STRONGER POSITION THAN THE SIBLING MAPPINGS NEEDED. Those carry a one-line label
    per row, written from the AWS behaviour. This one carries none at all — the rows are
    number plus classification — so there is nothing that could be mistaken for the
    benchmark's own wording. The tell for a lifted title is CIS's imperative voice."""
    src = io.open(os.path.join(ROOT, "engine", "aws_cis_al2_map.py"),
                  encoding="utf-8").read()
    for lifted in ('"Ensure ', "'Ensure ", '"Configure ', '"Disable ', '"Limit '):
        assert lifted not in src, f"{lifted!r} reads like a benchmark title"
    for heading in ("Rationale:", "Audit:", "Remediation:", "Impact:",
                    "Default Value:", "Profile Applicability:"):
        assert heading not in src, f"{heading!r} is a benchmark section heading"


def test_no_amazon_linux_benchmark_pdf_is_in_the_repository():
    hits = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "node_modules", "__pycache__", ".venv")]
        for f in files:
            low = f.lower()
            if low.endswith((".pdf", ".epub")) and ("amazon_linux" in low
                                                    or "amazon linux" in low):
                hits.append(os.path.join(base, f))
    assert not hits, f"benchmark document(s) in the repository: {hits}"
