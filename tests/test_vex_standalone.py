"""Phase-4 Slice-4 · B6 — standalone VEX ingest (OpenVEX + CSAF) + durable, bidirectional,
subcomponent-scoped suppression that rides the UNCHANGED aws_correlate empty-path invariant."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_vex
import aws_state
import cnapp_connectors as cc
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"
INST = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
ROLE = f"arn:aws:iam::{ACCT}:role/r-1"
PROF = f"arn:aws:iam::{ACCT}:instance-profile/p-1"
BUCKET = "arn:aws:s3:::crown-data"
BUNDLE = {"records": [{"id": "CVE-2021-44228", "aliases": ["CVE-2021-44228"],
                       "database_specific": {"severity": "CRITICAL"}, "severity": [{"score": 10.0}]}],
          "epss": {"CVE-2021-44228": 0.97}, "kev": {"CVE-2021-44228"}, "exploits": {"CVE-2021-44228"}}


def _svc():
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be)
    results = InMemoryResultStore()
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("eni-1", "NetworkInterface")
    g.add_node(INST, "EC2Instance", instance_id="i-1")
    g.add_edge("internet", "eni-1", "EXPOSED_TO", ports="tcp/443")
    g.add_edge("eni-1", INST, "ATTACHED_TO")
    g.add_node(PROF, "InstanceProfile"); g.add_edge(INST, PROF, "HAS_INSTANCE_PROFILE")
    g.add_node(ROLE, "IAMRole", name="r-1"); g.add_edge(PROF, ROLE, "HAS_ROLE")
    g.add_node(BUCKET, "S3Bucket", crown_jewel=True)
    g.add_edge(ROLE, BUCKET, "CAN_READ_DATA", conditioned=False)
    results.put(ACCT, {"account": ACCT, "graph_full": g.to_dict(),
                       "attack_paths": [], "finding_catalog": [], "results": []})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state, vuln_bundle=BUNDLE, clock=lambda: 5000)


def _sarif(cve="CVE-2021-44228"):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Trivy", "rules": [{"id": cve}]}},
        "results": [{"ruleId": cve, "level": "error",
                     "message": {"text": "Package: log4j-core\nInstalled Version: 2.14.1\nFixed Version: 2.17.1"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": INST}}}]}]}]}


def _openvex(cve="CVE-2021-44228", status="not_affected", subcomponent=None):
    prod = {"@id": "pkg:oci/app"}
    if subcomponent:
        prod["subcomponents"] = [{"@id": subcomponent}]
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "vex-1",
            "statements": [{"vulnerability": {"name": cve}, "products": [prod], "status": status,
                            "justification": "vulnerable_code_not_in_execute_path"}]}


CSAF = {
    "document": {"category": "csaf_vex", "title": "VEX"},
    "product_tree": {"full_product_names": [
        {"product_id": "PROD-1", "name": "log4j",
         "product_identification_helper": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}}]},
    "vulnerabilities": [{"cve": "CVE-2021-44228", "product_status": {"known_not_affected": ["PROD-1"]},
                         "flags": [{"label": "vulnerable_code_not_present"}]}],
}


# ── parsers ───────────────────────────────────────────────────────────────────
def test_openvex_parse_subcomponent_scoping():
    stmts = aws_vex.parse_openvex(_openvex(subcomponent="pkg:maven/x/log4j-core@2.14.1"))
    assert len(stmts) == 1
    s = stmts[0]
    assert s.cve == "CVE-2021-44228" and s.status == "not_affected"
    assert s.purl == "pkg:maven/x/log4j-core@2.14.1"       # subcomponent-scoped, not product-wide


def test_openvex_product_wide_when_no_subcomponent():
    s = aws_vex.parse_openvex(_openvex())[0]
    assert s.purl is None                                   # product-wide


def test_csaf_parse_resolves_purl_via_product_tree():
    stmts = aws_vex.parse_csaf_vex(CSAF)
    assert len(stmts) == 1
    s = stmts[0]
    assert s.cve == "CVE-2021-44228" and s.status == "not_affected"
    assert s.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert s.justification == "vulnerable_code_not_present"


def test_sniff_never_claims_cyclonedx_or_spdx():
    assert aws_vex.sniff_vex({"bomFormat": "CycloneDX"}) is None
    assert aws_vex.sniff_vex({"spdxVersion": "SPDX-2.3", "@context": "openvex"}) is None
    assert aws_vex.sniff_vex(_openvex()) == "openvex"
    assert aws_vex.sniff_vex(CSAF) == "csaf"


# ── bidirectional, durable suppression through the ingest path ────────────────
def test_vex_after_vuln_suppresses_and_severs_path():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_sarif(), target_resource=INST)
    row = svc.list_vulns(ACCT)[0]
    assert row["on_attack_path"] is True and row["suppressed"] is False
    res = svc.ingest_document(ACCT, doc=_openvex(status="not_affected"), target_resource=INST)
    assert res["lane"] == "vex" and res["vex_suppressed"] == 1
    row = svc.list_vulns(ACCT)[0]
    assert row["suppressed"] is True and row["on_attack_path"] is False   # empty path (I11)


def test_vex_before_vuln_suppresses_on_ingest():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_openvex(status="not_affected"), target_resource=INST)
    svc.ingest_document(ACCT, doc=_sarif(), target_resource=INST)
    assert svc.list_vulns(ACCT)[0]["suppressed"] is True


def test_vex_sticky_across_reingest():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_sarif(), target_resource=INST)
    svc.ingest_document(ACCT, doc=_openvex(status="not_affected"), target_resource=INST)
    svc.ingest_document(ACCT, doc=_sarif(), target_resource=INST)         # re-ingest the vuln
    assert svc.list_vulns(ACCT)[0]["suppressed"] is True                  # not resurrected


def test_affected_vex_does_not_suppress():
    svc = _svc()
    svc.ingest_document(ACCT, doc=_sarif(), target_resource=INST)
    svc.ingest_document(ACCT, doc=_openvex(status="affected"), target_resource=INST)
    assert svc.list_vulns(ACCT)[0]["suppressed"] is False
    assert {s["status"] for s in svc.list_vex_statements(ACCT)} == {"affected"}


def test_subcomponent_vex_does_not_over_suppress():
    # regression (HIGH): a subcomponent-scoped not_affected must NOT suppress the node-level
    # (node,cve) row — ingested_vulns has no purl dimension, so only product-wide '*' suppresses.
    svc = _svc()
    svc.ingest_document(ACCT, doc=_sarif(), target_resource=INST)
    sub = _openvex(status="not_affected", subcomponent="pkg:maven/other/unrelated-lib@1.0")
    svc.ingest_document(ACCT, doc=sub, target_resource=INST)
    row = svc.list_vulns(ACCT)[0]
    assert row["suppressed"] is False and row["on_attack_path"] is True   # not over-suppressed
    # the subcomponent statement is still recorded for display
    assert any(s["purl_identity"] != "*" for s in svc.list_vex_statements(ACCT))


def test_inline_vex_not_clobbered_by_unrelated_standalone():
    # regression (#9): an embedded CycloneDX not_affected is recorded to the durable ledger, so
    # a standalone VEX about a DIFFERENT cve can't un-suppress it (the old bug overwrote the
    # suppressed flag with standalone-only state).
    svc = _svc()
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {},
           "components": [{"bom-ref": "c1", "name": "log4j-core", "version": "2.14.1",
                           "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
           "vulnerabilities": [{"id": "CVE-2021-44228", "ratings": [{"severity": "critical"}],
                                "analysis": {"state": "not_affected"}, "affects": [{"ref": "c1"}]}]}
    svc.ingest_document(ACCT, doc=cdx, target_resource=INST)
    assert svc.list_vulns(ACCT)[0]["suppressed"] is True
    svc.ingest_document(ACCT, doc=_openvex(cve="CVE-2099-9999", status="affected"), target_resource=INST)
    log4 = [r for r in svc.list_vulns(ACCT) if r["cve"] == "CVE-2021-44228"][0]
    assert log4["suppressed"] is True                      # untouched by the unrelated statement


def test_csaf_cve_from_ids_text_fallback():
    # regression (#10): a CSAF vuln with no top-level `cve`, only ids[{system_name:CVE,text:...}]
    doc = {"document": {"category": "csaf_vex"},
           "product_tree": {"full_product_names": [{"product_id": "P1", "name": "x",
                            "product_identification_helper": {"purl": "pkg:npm/x@1"}}]},
           "vulnerabilities": [{"ids": [{"system_name": "CVE", "text": "CVE-2023-1234"}],
                                "product_status": {"known_not_affected": ["P1"]}}]}
    stmts = aws_vex.parse_csaf_vex(doc)
    assert len(stmts) == 1 and stmts[0].cve == "CVE-2023-1234" and stmts[0].purl == "pkg:npm/x@1"


def test_csaf_indexes_relationship_products():
    # regression (#11): composite product_ids defined via product_tree.relationships resolve.
    doc = {"document": {"category": "csaf_vex"},
           "product_tree": {"relationships": [{"full_product_name": {"product_id": "REL-1",
                            "product_identification_helper": {"purl": "pkg:rpm/redhat/log4j@2.14"}}}]},
           "vulnerabilities": [{"cve": "CVE-2021-44228", "product_status": {"known_not_affected": ["REL-1"]}}]}
    stmts = aws_vex.parse_csaf_vex(doc)
    assert stmts[0].purl == "pkg:rpm/redhat/log4j@2.14"
