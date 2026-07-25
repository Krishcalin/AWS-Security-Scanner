"""Phase-4 Slice-4 · B2 — SBOM component + license capture (parser).

Adds a full ``components`` set (superset of ``packages`` — keeps purl-less rows) + raw
license capture to the CycloneDX/SPDX inventory lanes, plus the purl_identity / subject_key
diff axes. The match lane (``packages``) must be byte-identical — proven by the existing
test_ingest suite staying green + the superset assertion here."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_ingest as ing

CDX = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "metadata": {"component": {"purl": "pkg:oci/payments-api", "bom-ref": "root"},
                 "tools": {"components": [{"name": "trivy"}]}},
    "components": [
        {"bom-ref": "c1", "name": "log4j-core", "version": "2.14.1",
         "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
         "licenses": [{"license": {"id": "Apache-2.0"}}]},
        {"bom-ref": "c2", "name": "somelib", "version": "1.0", "purl": "pkg:npm/somelib@1.0",
         "licenses": [{"expression": "MIT OR GPL-3.0-only"}]},
        {"bom-ref": "c3", "name": "dual", "version": "3", "purl": "pkg:npm/dual@3",
         "licenses": [{"license": {"id": "MIT"}}, {"license": {"name": "BSD-3-Clause"}}]},
        {"bom-ref": "c4", "name": "osthing", "version": "2.31"},          # purl-less
    ],
}

SPDX = {
    "spdxVersion": "SPDX-2.3", "creationInfo": {"creators": ["Tool: syft-1.0"]},
    "documentDescribes": ["SPDXRef-Image"],
    "packages": [
        {"SPDXID": "SPDXRef-Image", "name": "payments-api"},             # describe root → skipped
        {"SPDXID": "SPDXRef-p1", "name": "log4j-core", "versionInfo": "2.14.1",
         "licenseConcluded": "Apache-2.0", "licenseDeclared": "NOASSERTION",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                           "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]},
        {"SPDXID": "SPDXRef-p2", "name": "osthing", "versionInfo": "2.31",
         "licenseConcluded": "NOASSERTION", "licenseDeclared": "GPL-2.0-only"},   # purl-less
    ],
}


def _by_name(components):
    return {c.name: c for c in components}


def test_cyclonedx_inventory_captures_full_component_set_and_license():
    d = ing.parse_cyclonedx(CDX)
    assert d.lane == "inventory"
    # packages = match lane (purl'd only); components = full set (incl the purl-less osthing)
    assert len(d.packages) == 3
    assert len(d.components) == 4
    by = _by_name(d.components)
    assert by["log4j-core"].license_raw == "Apache-2.0"
    assert by["somelib"].license_raw == "MIT OR GPL-3.0-only"     # expression preserved raw
    assert by["dual"].license_raw == "MIT AND BSD-3-Clause"       # multiple concrete → AND
    assert by["osthing"].purl is None and by["osthing"].purl_identity == "osthing"


def test_cyclonedx_purl_identity_strips_version():
    d = ing.parse_cyclonedx(CDX)
    log4j = _by_name(d.components)["log4j-core"]
    assert log4j.purl_identity == "pkg:maven/org.apache.logging.log4j/log4j-core"   # no @version


def test_spdx_inventory_license_and_superset():
    d = ing.parse_spdx(SPDX)
    assert d.lane == "inventory"
    assert len(d.packages) == 1                                   # only the purl'd log4j
    assert len(d.components) == 2                                 # + purl-less osthing (superset)
    by = _by_name(d.components)
    assert by["log4j-core"].license_raw == "Apache-2.0"          # licenseConcluded preferred
    assert by["osthing"].license_raw == "GPL-2.0-only"          # NOASSERTION concluded → declared
    assert by["osthing"].purl_identity == "osthing"


def test_findings_lane_is_untouched():
    # a CycloneDX with vulnerabilities[] stays on the findings lane — no components
    d = ing.parse_cyclonedx({**CDX, "vulnerabilities": []})
    assert d.lane == "findings" and d.components == []


def test_canonical_purl_identity():
    assert ing.canonical_purl_identity("pkg:PyPI/Foo@1.0?b=2&a=1#sub") == "pkg:pypi/Foo?a=1&b=2#sub"
    assert ing.canonical_purl_identity("pkg:deb/debian/libc6@2.31?distro=debian-11") == \
        "pkg:deb/debian/libc6?distro=debian-11"
    assert ing.canonical_purl_identity("not-a-purl") == "not-a-purl"


def test_purl_identity_fallback():
    assert ing.purl_identity(None, "openssl", "apk") == "openssl@apk"
    assert ing.purl_identity(None, "", "") == "unknown"


def test_cdx_license_and_join_parenthesizes_compound_arms():
    # regression: an expression arm + an id arm must AND as (expr) AND id so SPDX precedence
    # (AND binds tighter than OR) can't drop the mandatory GPL obligation.
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"bom-ref": "c1", "name": "dual", "version": "1", "purl": "pkg:npm/dual@1",
         "licenses": [{"expression": "MIT OR Apache-2.0"}, {"license": {"id": "GPL-3.0-only"}}]}]}
    raw = ing.parse_cyclonedx(doc).components[0].license_raw
    assert raw == "(MIT OR Apache-2.0) AND GPL-3.0-only"
    import aws_license as lic
    assert lic.normalize_spdx(raw) == ("GPL-3.0-only", "strong_copyleft")   # not silently permissive


def test_cdx_captures_components_without_bom_ref():
    # regression: a spec-valid component that omits bom-ref must still land in the snapshot set.
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"bom-ref": "c1", "name": "withref", "version": "1", "purl": "pkg:npm/withref@1"},
        {"name": "noref", "version": "2", "purl": "pkg:npm/noref@2"},
        {"name": "nested-parent", "components": [{"name": "nested-child", "purl": "pkg:npm/child@3"}]}]}
    names = {c.name for c in ing.parse_cyclonedx(doc).components}
    assert {"withref", "noref", "nested-child"} <= names


def test_subject_key_container_strips_tag_and_digest():
    ecr = "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-api:v1.2@sha256:abcd"
    assert ing.subject_key(ecr, "ECRImage") == "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-api"
    # a non-image node is its own subject
    assert ing.subject_key("arn:aws:lambda:us-east-1:1:function:foo", "Lambda") == \
        "arn:aws:lambda:us-east-1:1:function:foo"
