"""Regression tests for the 14 adversarial-verify findings on the ingest slice.

Each test pins a CONFIRMED defect so it can never silently return. Pure/offline."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import cnapp_connectors as cc
from aws_graph import SecurityGraph
from aws_sidescan import EnrichedMatch
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService
import aws_ingest as ing
from aws_ingest import (parse_document, parse_purl, _image_repo_tag,
                        compute_reachability_verdicts, diff_reachability)

ACCT = "111122223333"
INST = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
ROLE = f"arn:aws:iam::{ACCT}:role/r-1"
PROF = f"arn:aws:iam::{ACCT}:instance-profile/p-1"
BUCKET = "arn:aws:s3:::crown-data"


def _kev(cve, node=INST, kind="EC2Instance", suppressed=False):
    m = EnrichedMatch(cve=cve, osv_id=cve, package="p", installed_version="1",
                      fixed_version="2", severity="CRITICAL", cvss_base=10.0, epss=0.9,
                      kev=True, exploit_available="YES", ecosystem="Maven")
    return {"node_id": node, "node_kind": kind, "match": m, "suppressed": suppressed,
            "tool": "trivy", "doc_id": "d1"}


def _path_graph(runs_image=False, admin=False):
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("eni-1", "NetworkInterface")
    g.add_node(INST, "EC2Instance", instance_id="i-1")
    g.add_edge("internet", "eni-1", "EXPOSED_TO")
    g.add_edge("eni-1", INST, "ATTACHED_TO")
    g.add_node(PROF, "InstanceProfile"); g.add_edge(INST, PROF, "HAS_INSTANCE_PROFILE")
    g.add_node(ROLE, "IAMRole"); g.add_edge(PROF, ROLE, "HAS_ROLE")
    if admin:
        g.add_node(f"capability:admin:{ACCT}", "AdminCapability")
        g.add_edge(ROLE, f"capability:admin:{ACCT}", "CAN_PRIVESC_TO", conditioned=False)
    else:
        g.add_node(BUCKET, "S3Bucket", crown_jewel=True)
        g.add_edge(ROLE, BUCKET, "CAN_READ_DATA", conditioned=False)
    if runs_image:
        g.add_node("img-node", "ECRImage", repository="team/api")
        g.add_edge(INST, "img-node", "RUNS_IMAGE")
    return g


# ── #1 non-dict parser rows fail soft (no crash → no HTTP 500) ────────────────
def test_malformed_cdx_component_does_not_crash():
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {},
           "components": ["oops", {"bom-ref": "c1", "name": "x", "version": "1",
                                   "purl": "pkg:pypi/x@1"}]}
    pd = parse_document(doc)          # must NOT raise AttributeError
    assert pd.lane == "inventory" and any(p.name == "x" for p in pd.packages)


def test_malformed_sarif_run_and_spdx_pkg_do_not_crash():
    sarif = {"version": "2.1.0", "runs": ["bad", {"tool": {"driver": {"name": "Trivy",
             "rules": [{"id": "CVE-2021-1"}]}}, "results": []}]}
    assert parse_document(sarif).lane == "findings"
    spdx = {"spdxVersion": "SPDX-2.3", "creationInfo": {"creators": ["Tool: syft"]},
            "packages": ["nope", {"SPDXID": "p", "name": "x", "versionInfo": "1",
                                  "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                                    "referenceType": "purl",
                                                    "referenceLocator": "pkg:pypi/x@1"}]}]}
    assert any(p.name == "x" for p in parse_document(spdx).packages)


# ── #2 openSUSE Leap distro resolves to the native ecosystem ─────────────────
def test_opensuse_leap_distro_ecosystem():
    for distro, eco in (("opensuse-leap-15.5", "openSUSE:Leap:15.5"),
                        ("opensuse-15.5", "openSUSE:Leap:15.5"),
                        ("ubuntu-22.04", "Ubuntu:22.04"),
                        ("amazon-2", "Amazon Linux:2"),
                        ("debian-12", "Debian:12")):
        p = parse_purl(f"pkg:rpm/x/libxml2@2.10.3?distro={distro}")
        assert p.ecosystem == eco, f"{distro} -> {p.ecosystem} != {eco}"


# ── #3 empty vulnerabilities[] stays in the FINDINGS lane (clean verdict) ─────
def test_empty_vulnerabilities_array_is_findings_lane_not_inventory():
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {},
           "vulnerabilities": [],
           "components": [{"bom-ref": "c1", "name": "requests", "version": "2.19.0",
                           "purl": "pkg:pypi/requests@2.19.0"}]}
    pd = parse_document(doc)
    assert pd.lane == "findings" and pd.findings == []     # scanner said clean → no CVEs


# ── #4 / #7 ECRImage owner inherits reachability via RUNS_IMAGE ──────────────
def test_ingested_kev_on_image_inherits_workload_path():
    g = _path_graph(runs_image=True)
    verdicts, _ = compute_reachability_verdicts(g.to_dict(), [_kev("CVE-IMG", node="img-node",
                                                                   kind="ECRImage")])
    v = verdicts[("img-node", "CVE-IMG")]
    assert v["on_attack_path"] is True and v["priority_band"] == "CRITICAL"
    assert v["priority_score"] >= 90                        # the workload's data path


# ── #5 / #8 VEX-suppressed sibling does not inherit the path ──────────────────
def test_suppressed_cve_never_on_path_despite_sibling():
    g = _path_graph()
    owned = [_kev("CVE-A"), _kev("CVE-B", suppressed=True)]   # same node, B suppressed
    verdicts, _ = compute_reachability_verdicts(g.to_dict(), owned)
    assert verdicts[("arn:aws:ec2:us-east-1:111122223333:instance/i-1", "CVE-A")]["on_attack_path"] is True
    vb = verdicts[(INST, "CVE-B")]
    assert vb["on_attack_path"] is False and vb["priority_band"] != "CRITICAL"


def test_suppressed_cve_on_admin_path_not_critical():
    g = _path_graph(admin=True)
    verdicts, _ = compute_reachability_verdicts(g.to_dict(), [_kev("CVE-S", suppressed=True)])
    assert verdicts[(INST, "CVE-S")]["on_attack_path"] is False


# ── #6 namespaced repo:tag resolves to the native ECRImage node ──────────────
def test_image_repo_tag_preserves_namespace():
    assert _image_repo_tag("123.dkr.ecr.us-east-1.amazonaws.com/team/api:v1") == {"repo": "team/api", "tag": "v1"}
    assert _image_repo_tag("app:v2") == {"repo": "app", "tag": "v2"}


def test_resolve_owner_namespaced_repo_binds_native_node():
    g = SecurityGraph()
    g.add_node("123.dkr.ecr.us-east-1.amazonaws.com/team/api:v1", "ECRImage", repository="team/api")
    nid, kind, status = ing.resolve_owner(
        g, ACCT, target_resource="123.dkr.ecr.us-east-1.amazonaws.com/team/api:v1")
    assert status == "resolved" and kind == "ECRImage"


# ── #5/#8/#11/#14 suppressed CVE never in became_reachable ───────────────────
def test_diff_reachability_excludes_suppressed():
    verdicts = {(INST, "CVE-X"): {"on_attack_path": True, "suppressed": True,
                                  "priority_band": "CRITICAL"}}
    became, gone = diff_reachability([{"node_id": INST, "cve": "CVE-X",
                                       "on_attack_path": False}], verdicts)
    assert became == [] and gone == []


# ── #9 NULLS LAST: a null-epss row never outranks a real one, both engines ────
def test_sort_epss_nulls_last():
    s = aws_state.StateStore.open(":memory:")
    for cve, epss in (("CVE-HI", 0.9), ("CVE-NULL", None)):
        s.upsert_ingested_vuln({"account": ACCT, "node_id": INST, "cve": cve,
                                "node_kind": "EC2Instance", "package": "p",
                                "installed_version": "1", "fixed_version": "2",
                                "severity": "HIGH", "cvss_base": 8.0, "epss": epss,
                                "kev": False, "exploit_available": None,
                                "sources": ["ingest:trivy"], "suppressed": False,
                                "mapping_status": "resolved", "last_seen_epoch": 1000})
    top = s.list_ingested_vulns(ACCT, sort="epss", limit=1)
    assert top[0]["cve"] == "CVE-HI"                        # null epss sorts LAST, never first


# ── #10 min_band/source filter applied BEFORE limit ──────────────────────────
def test_min_band_filter_survives_limit():
    s = aws_state.StateStore.open(":memory:")
    # 3 LOW rows (higher priority_score) then 1 CRITICAL — limit=1 must still find CRITICAL
    rows = [("CVE-L1", 30, "LOW"), ("CVE-L2", 29, "LOW"), ("CVE-L3", 28, "LOW"),
            ("CVE-C", 20, "CRITICAL")]
    for cve, score, band in rows:
        s.upsert_ingested_vuln({"account": ACCT, "node_id": INST, "cve": cve,
                                "node_kind": "EC2Instance", "package": "p",
                                "installed_version": "1", "fixed_version": None,
                                "severity": band, "cvss_base": 5.0, "epss": None,
                                "kev": False, "exploit_available": None,
                                "sources": ["ingest:trivy"], "suppressed": False,
                                "mapping_status": "resolved", "last_seen_epoch": 1000})
        s.write_ingested_verdict(ACCT, INST, cve, {"priority_score": score,
                                                   "priority_band": band})
    got = s.list_ingested_vulns(ACCT, min_band="CRITICAL", limit=1)
    assert [r["cve"] for r in got] == ["CVE-C"]             # not truncated away by LIMIT


# ── #12 refreshed bundle rebuilds the OSV feed (no stale cache) ───────────────
def test_osv_feed_rebuilds_on_bundle_change():
    reg = AccountRegistry.open(":memory:")
    box = {"records": []}
    svc = PlatformService(
        registry=reg, results=InMemoryResultStore(), hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "x", secret_reader=lambda r: "x",
        state=aws_state.StateStore(reg._be), vuln_bundle=lambda: {"records": box["records"],
        "epss": {}, "kev": set(), "exploits": set()}, clock=lambda: 1)
    f1 = svc._osv_feed(svc._vuln_bundle())
    box["records"] = [{"id": "CVE-1", "affected": [{"package": {"ecosystem": "PyPI", "name": "x"}}]}]
    f2 = svc._osv_feed(svc._vuln_bundle())
    assert f1 is not f2                                     # new records list → rebuilt feed


# ── #13 viewer read routes fail-open (no state → [] not 500) ─────────────────
def test_vuln_reads_fail_open_without_state():
    svc = PlatformService(
        registry=AccountRegistry.open(":memory:"), results=InMemoryResultStore(),
        hub_role_arn="a", cfn_template_url="b", secret_writer=lambda a, v: "x",
        secret_reader=lambda r: "x", state=None, clock=lambda: 1)
    assert svc.list_vulns(ACCT) == [] and svc.get_vuln(ACCT, "CVE-1") == []
    assert svc.list_ingest_docs(ACCT) == [] and svc.org_vulns() == []
