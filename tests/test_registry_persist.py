"""Phase-4 Slice-5 · B6 — a pulled registry image's SBOM persists as a durable Slice-4
snapshot (under the repo subject, so diff/license/VEX apply), idempotently.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_ingest
import aws_registry_sbom as R
import aws_state
import cnapp_connectors as cc
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"
RURI = f"{ACCT}.dkr.ecr.us-east-1.amazonaws.com/app"
NODE = f"{RURI}@sha256:img"


def _comp(name, version, purl, eco="Debian:12", lic=None):
    return aws_ingest.Component(
        name=name, version=version, purl=purl,
        purl_identity=aws_ingest.purl_identity(purl, name, eco),
        ecosystem=eco, origin="dpkg", license_raw=lic)


# ── to_cyclonedx (pure) ──────────────────────────────────────────────────────
def test_to_cyclonedx_deterministic_and_maps_fields():
    comps = [_comp("zlib", "1.2.13", "pkg:deb/debian/zlib@1.2.13"),
             _comp("openssl", "1.1.1w", "pkg:deb/debian/openssl@1.1.1w", lic="OpenSSL")]
    a = R.to_cyclonedx(NODE, comps)
    b = R.to_cyclonedx(NODE, list(reversed(comps)))
    assert a == b                                     # order-independent -> stable doc bytes
    assert a["bomFormat"] == "CycloneDX"
    names = [c["name"] for c in a["components"]]
    assert names == sorted(names)
    oss = next(c for c in a["components"] if c["name"] == "openssl")
    assert oss["purl"] == "pkg:deb/debian/openssl@1.1.1w"
    assert oss["licenses"][0]["license"]["name"] == "OpenSSL"


def test_to_cyclonedx_purl_less_component():
    c = aws_ingest.Component("libc", "2.36", None, "libc@Debian:12", "Debian:12", "dpkg", None)
    doc = R.to_cyclonedx(NODE, [c])
    comp = doc["components"][0]
    assert "purl" not in comp and comp["bom-ref"] == "libc@Debian:12"


# ── persistence via the ingest_document inventory lane ───────────────────────
def _svc():
    reg = AccountRegistry.open(":memory:")
    state = aws_state.StateStore(reg._be)
    results = InMemoryResultStore()
    g = SecurityGraph()
    g.add_node(NODE, "ECRImage", repository="app", digest="sha256:img", image_uri=RURI)
    results.put(ACCT, {"account": ACCT, "graph_full": g.to_dict(),
                       "attack_paths": [], "finding_catalog": [], "results": []})
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "ssm://x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state,
        vuln_bundle={"records": [], "epss": {}, "kev": set(), "exploits": set()},
        clock=lambda: 5000)


def test_registry_sbom_persists_under_repo_subject():
    svc = _svc()
    doc = R.to_cyclonedx(NODE, [_comp("openssl", "1.1.1w", "pkg:deb/debian/openssl@1.1.1w")])
    res = svc.ingest_document(ACCT, doc=doc, source_tool="ecr-sidescan", target_resource=NODE)
    assert res["lane"] == "inventory"
    snaps = svc.state.list_sbom_snapshots(ACCT)
    assert len(snaps) == 1
    assert snaps[0]["subject_key"] == RURI            # @digest stripped -> the diff axis is the repo
    comps = svc.state.get_snapshot_components(snaps[0]["snapshot_id"])
    assert any(c["name"] == "openssl" for c in comps)


def test_registry_sbom_reingest_is_idempotent():
    svc = _svc()
    doc = R.to_cyclonedx(NODE, [_comp("openssl", "1.1.1w", "pkg:deb/debian/openssl@1.1.1w")])
    svc.ingest_document(ACCT, doc=doc, source_tool="ecr-sidescan", target_resource=NODE)
    svc.ingest_document(ACCT, doc=doc, source_tool="ecr-sidescan", target_resource=NODE)
    assert len(svc.state.list_sbom_snapshots(ACCT)) == 1   # same content -> no duplicate snapshot


def test_snapshot_cve_set_is_replaced_not_accumulated():
    # a re-sweep of the SAME snapshot against a newer feed (a fixed CVE) must REPLACE the CVE
    # set, not accumulate stale rows.
    import aws_state
    from cnapp_registry import AccountRegistry
    reg = AccountRegistry.open(":memory:")
    st = aws_state.StateStore(reg._be)
    with reg._be.transaction():
        st.record_sbom_snapshot({"snapshot_id": "s1", "account": ACCT, "node_id": "n",
                                 "subject_key": "k", "source_format": "cyclonedx",
                                 "source_tool": "ecr-sidescan", "component_count": 0,
                                 "ingested_epoch": 1})
        st.insert_snapshot_cves("s1", [{"cve": "CVE-A"}, {"cve": "CVE-B"}])
    with reg._be.transaction():
        st.insert_snapshot_cves("s1", [{"cve": "CVE-B"}])   # re-sweep: CVE-A now fixed
    cves = {r["cve"] for r in reg._be.query_all(
        "SELECT cve FROM sbom_snapshot_cves WHERE snapshot_id=?", ("s1",))}
    assert cves == {"CVE-B"}                            # CVE-A cleared, not accumulated
