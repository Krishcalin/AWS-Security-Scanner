"""Phase-4 Slice-5 — aws_registry_sbom pure helpers (B2 adapter + doc-id).

The Tier-B orchestrator helpers (select_registry_images / scan_registry_image) are
covered in test_registry_scan.py (B3); this file covers the pure adapter + id.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_registry_sbom as R
import aws_ingest
import aws_sidescan


def _pkg(name="openssl", version="1.1.1w",
         purl="pkg:deb/debian/openssl@1.1.1w?arch=amd64",
         ecosystem="Debian:12", origin="dpkg"):
    return aws_sidescan.Package(
        name=name, version=version, arch="amd64", source=name,
        source_version=version, ecosystem=ecosystem, purl=purl, origin=origin)


def test_package_to_component_maps_fields():
    c = R._package_to_component(_pkg())
    assert isinstance(c, aws_ingest.Component)
    assert c.name == "openssl" and c.version == "1.1.1w"
    assert c.purl == "pkg:deb/debian/openssl@1.1.1w?arch=amd64"
    assert c.ecosystem == "Debian:12" and c.origin == "dpkg"
    assert c.license_raw is None                        # rootfs scan has no license string
    # purl_identity is the canonical, version-stripped purl
    assert c.purl_identity == aws_ingest.canonical_purl_identity(c.purl)
    assert "@1.1.1w" not in c.purl_identity


def test_package_to_component_purl_less_gets_synthetic_identity():
    c = R._package_to_component(_pkg(purl=""))
    assert c.purl is None
    assert c.purl_identity == "openssl@Debian:12"       # synthetic name@ecosystem, never empty


def test_package_to_component_blank_origin_falls_back():
    c = R._package_to_component(_pkg(origin=""))
    assert c.origin == "registry"


def _comps():
    return [
        R._package_to_component(_pkg()),
        R._package_to_component(_pkg("zlib", "1.2.13", purl="pkg:deb/debian/zlib@1.2.13")),
    ]


def test_registry_doc_id_stable_and_order_independent():
    comps = _comps()
    a = R.registry_sbom_doc_id("r.dkr.ecr.us-east-1.amazonaws.com/app", "sha256:abc", comps)
    b = R.registry_sbom_doc_id("r.dkr.ecr.us-east-1.amazonaws.com/app", "sha256:abc",
                               list(reversed(comps)))
    assert a == b                                       # same content -> same id, order-independent


def test_registry_doc_id_changes_on_component_or_digest_change():
    comps = _comps()
    base = R.registry_sbom_doc_id("r/app", "sha256:abc", comps)
    more = comps + [R._package_to_component(_pkg("curl", "8.0", purl="pkg:deb/debian/curl@8.0"))]
    assert R.registry_sbom_doc_id("r/app", "sha256:abc", more) != base   # component drift
    assert R.registry_sbom_doc_id("r/app", "sha256:xyz", comps) != base  # different image digest
