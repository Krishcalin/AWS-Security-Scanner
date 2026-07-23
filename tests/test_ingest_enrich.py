"""B3 — enrich / own / VEX / ownership resolver.

Verifies single-source enrichment (KEV/EPSS/exploit from the SAME bundle as a
native side-scan, byte-identical), native-parity severity on a cve_index HIT,
doc-fallback on a MISS, VEX suppress-but-track, and the ownership resolver
(ARN exact/infer, image digest/repo:tag, unmapped fallback, cross-account guard).
Pure/offline."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_ingest as ing
from aws_ingest import (IngestedFinding, build_cve_index, enrich_finding,
                        vex_suppressed, resolve_owner, emit_ingested_edges)
from aws_sidescan import Package, enrich_match
from aws_graph import SecurityGraph


# ── bundle fixtures ──────────────────────────────────────────────────────────
LOG4SHELL_REC = {
    "id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"],
    "database_specific": {"severity": "CRITICAL"},
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "affected": [{"package": {"ecosystem": "Maven",
                              "name": "org.apache.logging.log4j:log4j-core"}}],
}
EPSS = {"CVE-2021-44228": 0.975, "CVE-2023-0464": 0.10}
KEV = {"CVE-2021-44228"}
EXPLOITS = {"CVE-2021-44228"}


def _finding(cve="CVE-2021-44228", osv_id="GHSA-jfh8-c2jp-5v3q", sev="HIGH", cvss=8.0):
    return IngestedFinding(
        cve=cve, osv_id=osv_id, source_tool="grype", source_format="cyclonedx",
        package="org.apache.logging.log4j:log4j-core", installed_version="2.14.1",
        fixed_version="2.17.1", purl=None, ecosystem="Maven",
        severity=sev, cvss_base=cvss)


# ── cve_index ────────────────────────────────────────────────────────────────
def test_build_cve_index_by_cve_and_alias():
    idx = build_cve_index([LOG4SHELL_REC])
    assert idx.get("CVE-2021-44228") is LOG4SHELL_REC          # via prefer_cve + alias
    assert idx.get("GHSA-JFH8-C2JP-5V3Q") is LOG4SHELL_REC     # via id alias (uppercased)


# ── enrichment parity (single-source) ────────────────────────────────────────
def test_enrich_hit_native_parity():
    idx = build_cve_index([LOG4SHELL_REC])
    m = enrich_finding(_finding(sev="LOW", cvss=1.0), idx, EPSS, KEV, EXPLOITS)
    # doc said LOW/1.0 — but the feed KNOWS this CVE, so severity/cvss are native-parity
    assert m.cve == "CVE-2021-44228"
    assert m.severity == "CRITICAL"                            # from OSV rec, NOT doc "LOW"
    assert m.cvss_base and m.cvss_base >= 9.0                  # computed from CVSS vector
    assert m.kev is True and m.exploit_available == "YES"
    assert m.epss == 0.975


def test_enrich_hit_is_byte_identical_to_native_sidescan():
    """The ingested match must equal a native side-scan match of the same CVE
    (same rec + same bundle) on every enrichment field."""
    idx = build_cve_index([LOG4SHELL_REC])
    ingested = enrich_finding(_finding(), idx, EPSS, KEV, EXPLOITS)
    pkg = Package(name="org.apache.logging.log4j:log4j-core", version="2.14.1", arch="",
                  source="", source_version="2.14.1", ecosystem="Maven", purl="", origin="")
    native = enrich_match(LOG4SHELL_REC, pkg, "2.17.1", EPSS, KEV, EXPLOITS)
    assert (ingested.cve, ingested.severity, ingested.cvss_base, ingested.epss,
            ingested.kev, ingested.exploit_available) == \
           (native.cve, native.severity, native.cvss_base, native.epss,
            native.kev, native.exploit_available)


def test_enrich_miss_uses_doc_band_but_bundle_kev():
    """CVE unknown to the feed → doc severity/cvss are the display fallback, yet
    KEV/EPSS still come only from the bundle (never inferred from the doc)."""
    m = enrich_finding(_finding(cve="CVE-2029-99999", osv_id="CVE-2029-99999",
                                sev="HIGH", cvss=7.7), {}, EPSS, KEV, EXPLOITS)
    assert m.cve == "CVE-2029-99999"
    assert m.severity == "HIGH" and m.cvss_base == 7.7         # doc fallback
    assert m.kev is False and m.exploit_available is None      # bundle says unknown
    assert m.epss is None


def test_enrich_never_infers_kev_from_severity():
    m = enrich_finding(_finding(cve="CVE-2030-1", osv_id="CVE-2030-1", sev="CRITICAL",
                                cvss=9.9), {}, {}, set(), set())
    assert m.kev is False and m.exploit_available is None


# ── VEX ──────────────────────────────────────────────────────────────────────
def test_vex_suppressed_states():
    for s in ("not_affected", "false_positive", "resolved", "resolved_with_pedigree"):
        assert vex_suppressed(s) is True
    for s in ("exploitable", "in_triage", None, ""):
        assert vex_suppressed(s) is False


# ── ownership resolver ───────────────────────────────────────────────────────
def _graph_with_image(node_id, digest=None, repo=None, kind="ECRImage"):
    g = SecurityGraph()
    g.add_node(node_id, kind, digest=digest, repository=repo)
    return g


def test_resolve_owner_exact_arn_node():
    g = SecurityGraph()
    g.add_node("arn:aws:ec2:us-east-1:111122223333:instance/i-abc", "EC2Instance")
    nid, kind, status = resolve_owner(
        g, "111122223333",
        target_resource="arn:aws:ec2:us-east-1:111122223333:instance/i-abc")
    assert kind == "EC2Instance" and status == "resolved"


def test_resolve_owner_arn_not_in_graph_infers_kind():
    g = SecurityGraph()
    nid, kind, status = resolve_owner(
        g, "111122223333",
        target_resource="arn:aws:lambda:us-east-1:111122223333:function:svc")
    assert kind == "LambdaFunction" and status == "resolved"


def test_resolve_owner_cross_account_arn_raises():
    g = SecurityGraph()
    with pytest.raises(ValueError):
        resolve_owner(g, "111122223333",
                      target_resource="arn:aws:ec2:us-east-1:999999999999:instance/i-x")


def test_resolve_owner_by_digest():
    dig = "sha256:" + "a" * 64
    g = _graph_with_image(f"111.dkr.ecr.us-east-1.amazonaws.com/app@{dig}", digest=dig,
                          repo="app")
    nid, kind, status = resolve_owner(g, "111",
                                      subject_locator=f"pkg:oci/app@{dig}")
    assert status == "resolved" and kind == "ECRImage" and dig in nid.lower()


def test_resolve_owner_by_repo_tag():
    g = _graph_with_image("111.dkr.ecr.us-east-1.amazonaws.com/app:v2", repo="app")
    nid, kind, status = resolve_owner(g, "111", target_resource="app:v2")
    assert status == "resolved" and nid.endswith(":v2")


def test_resolve_owner_unmapped_fallback():
    g = SecurityGraph()
    dig = "sha256:" + "b" * 64
    nid, kind, status = resolve_owner(g, "111", subject_locator=f"myimg@{dig}")
    assert status == "unmapped" and kind == "ECRImage" and nid.startswith("ingest:image:")


# ── emit provenance ──────────────────────────────────────────────────────────
def test_emit_ingested_edges_tags_provenance_and_merges():
    idx = build_cve_index([LOG4SHELL_REC])
    m = enrich_finding(_finding(), idx, EPSS, KEV, EXPLOITS)
    g = SecurityGraph()
    n = emit_ingested_edges(g, "arn:img", "ECRImage", [m], "sha256:doc", "grype")
    assert n == 1
    e = g.out_edges("arn:img", ["HAS_VULN"])[0]
    assert e["props"]["scan_source"] == "ingest:grype"
    # re-emitting the same (node, cve) MERGEs — still one edge
    emit_ingested_edges(g, "arn:img", "ECRImage", [m], "sha256:doc", "grype")
    assert len(g.out_edges("arn:img", ["HAS_VULN"])) == 1
