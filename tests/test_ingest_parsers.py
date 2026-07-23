"""B2 — pure ingest parsers: SARIF / CycloneDX / SPDX + purl->Package.

Realistic per-tool shapes (Trivy/Grype/Snyk SARIF; Trivy/Grype CDX-with-vulns;
Syft/Trivy SPDX inventory). Pure/offline: dict-in, dataclass-out, no I/O."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_ingest as ing
from aws_ingest import parse_document, parse_purl


# ── purl -> Package (inverse of _purl / _lang_purl) ──────────────────────────
def test_parse_purl_deb_with_distro():
    p = parse_purl("pkg:deb/debian/openssl@3.0.11-1?arch=amd64&distro=debian-12")
    assert p.origin == "dpkg" and p.name == "openssl"
    assert p.version == "3.0.11-1" and p.arch == "amd64"
    assert p.ecosystem == "Debian:12"


def test_parse_purl_ubuntu_full_version_eco():
    p = parse_purl("pkg:deb/ubuntu/bash@5.1-6ubuntu1?distro=ubuntu-22.04")
    assert p.ecosystem == "Ubuntu:22.04"


def test_parse_purl_alpine_eco():
    p = parse_purl("pkg:apk/alpine/musl@1.2.3-r4?distro=alpine-3.18.4")
    assert p.origin == "apk" and p.ecosystem == "Alpine:v3.18"


def test_parse_purl_rpm_amazon_alias_and_epoch():
    p = parse_purl("pkg:rpm/amzn/glibc@2.26-60?arch=x86_64&distro=amazon-2&epoch=2")
    assert p.origin == "rpm" and p.ecosystem == "Amazon Linux:2"
    assert p.version == "2:2.26-60"                       # epoch folded in for EVR cmp


def test_parse_purl_os_no_distro_is_low_fidelity():
    p = parse_purl("pkg:deb/debian/curl@7.88.0")
    assert p.origin == "dpkg" and p.ecosystem == ""       # flagged by caller, not fabricated


def test_parse_purl_pypi_pep503_normalized():
    p = parse_purl("pkg:pypi/PyYAML@6.0")
    assert p.ecosystem == "PyPI" and p.name == "pyyaml"   # _pep503 lowercases + collapses
    assert p.purl == "pkg:pypi/pyyaml@6.0"


def test_parse_purl_npm_scoped():
    p = parse_purl("pkg:npm/%40angular/core@15.2.0")
    assert p.origin == "npm" and p.name == "@angular/core"
    assert p.ecosystem == "npm"


def test_parse_purl_golang_strips_v():
    p = parse_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.0")
    assert p.origin == "go" and p.ecosystem == "Go"
    assert p.version == "1.9.0" and p.name == "github.com/gin-gonic/gin"


def test_parse_purl_maven_group_artifact():
    p = parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
    assert p.origin == "maven" and p.ecosystem == "Maven"
    assert p.name == "org.apache.logging.log4j:log4j-core"


def test_parse_purl_rejects_non_purl():
    assert parse_purl("not-a-purl") is None
    assert parse_purl("") is None


def test_parse_purl_versionless_does_not_misparse():
    # a version-less purl is valid; the type/name must survive (version empty),
    # never mis-split so that coord becomes '' and name is lost.
    p = parse_purl("pkg:pypi/requests")
    assert p is not None and p.name == "requests" and p.version == ""


# ── SARIF: Trivy ─────────────────────────────────────────────────────────────
def _trivy_sarif():
    return {
        "version": "2.1.0", "$schema": "sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "Trivy", "rules": [{
                "id": "CVE-2022-28346",
                "help": {"text": "Package: django\nInstalled Version: 3.2.0\n"
                                 "Fixed Version: 3.2.13\nSeverity: CRITICAL"},
                "properties": {"security-severity": "9.8",
                               "tags": ["vulnerability", "CRITICAL", "django"]},
            }]}},
            "results": [{
                "ruleId": "CVE-2022-28346",
                "level": "error",
                "message": {"text": "Package: django\nInstalled Version: 3.2.0\n"
                                    "Fixed Version: 3.2.13"},
                "locations": [{"physicalLocation": {"artifactLocation": {
                    "uri": "myimage:latest (debian 12)"}}}],
            }],
        }],
    }


def test_sarif_trivy_extracts_cve_pkg_cvss():
    pd = parse_document(_trivy_sarif())
    assert pd.lane == "findings" and pd.source_tool == "trivy"
    assert pd.subject_locator == "myimage:latest (debian 12)"
    assert len(pd.findings) == 1
    f = pd.findings[0]
    assert f.cve == "CVE-2022-28346" and f.package == "django"
    assert f.installed_version == "3.2.0" and f.fixed_version == "3.2.13"
    assert f.severity == "CRITICAL" and f.cvss_base == 9.8


def test_sarif_trivy_strips_old_sev_prefix():
    doc = _trivy_sarif()
    doc["runs"][0]["results"][0]["ruleId"] = "[CRITICAL] CVE-2022-28346"
    f = parse_document(doc).findings[0]
    assert f.cve == "CVE-2022-28346"


# ── SARIF: Grype (ruleId = CVE-...-pkgname) ──────────────────────────────────
def test_sarif_grype_recovers_cve_from_suffixed_ruleid():
    doc = {
        "version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "grype", "rules": [
                {"id": "CVE-2021-44228-log4j-core",
                 "properties": {"security-severity": "10.0"}}]}},
            "results": [{
                "ruleId": "CVE-2021-44228-log4j-core",
                "message": {"text": "A critical vulnerability in java package: "
                                    "log4j-core, version 2.14.1 was found."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app:1"}}}],
            }],
        }],
    }
    f = parse_document(doc).findings[0]
    # pkg name itself contains a hyphen — must NOT split on first '-'
    assert f.cve == "CVE-2021-44228" and f.package == "log4j-core"
    assert f.installed_version == "2.14.1"


# ── SARIF: Snyk (SNYK-id ruleId, CVE in fullDescription; 0/N CVEs) ───────────
def test_sarif_snyk_regexes_cve_and_keeps_snyk_id():
    doc = {
        "version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "Snyk Open Source", "rules": [{
                "id": "SNYK-PYTHON-DJANGO-1234",
                "shortDescription": {"text": "High severity ... in django"},
                "fullDescription": {"text": "(CVE-2022-28346) in django@3.2.0 SQLi"},
                "properties": {"security-severity": "8.8", "tags": ["CWE-89"]},
            }]}},
            "results": [{"ruleId": "SNYK-PYTHON-DJANGO-1234", "level": "error",
                         "message": {"text": "..."},
                         "locations": [{"physicalLocation": {"artifactLocation": {
                             "uri": "requirements.txt"}}}]}],
        }],
    }
    f = parse_document(doc).findings[0]
    assert f.cve == "CVE-2022-28346" and f.osv_id == "SNYK-PYTHON-DJANGO-1234"
    assert f.package == "django" and f.installed_version == "3.2.0"
    assert f.cvss_base == 8.8


def test_sarif_codeql_excluded():
    doc = {
        "version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "CodeQL", "rules": [
                {"id": "py/sql-injection"}]}},
            "results": [{"ruleId": "py/sql-injection",
                         "locations": [{"physicalLocation": {"artifactLocation": {
                             "uri": "app.py"}}}]}],
        }],
    }
    pd = parse_document(doc)
    assert pd.findings == [] and any("CodeQL" in n for n in pd.notes)


# ── CycloneDX with vulnerabilities[] (Trivy: bom-ref==purl) ──────────────────
def test_cdx_trivy_vuln_resolves_purl_bomref():
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"component": {"purl": "pkg:oci/myimage@sha256:abc"},
                     "tools": {"components": [{"name": "trivy"}]}},
        "components": [{"bom-ref": "pkg:deb/debian/openssl@3.0.11?distro=debian-12",
                        "name": "openssl", "version": "3.0.11",
                        "purl": "pkg:deb/debian/openssl@3.0.11?distro=debian-12"}],
        "vulnerabilities": [{
            "id": "CVE-2023-0464", "bom-ref": "urn:uuid:1",
            "ratings": [{"source": {"name": "nvd"}, "score": 7.5, "method": "CVSSv31",
                         "severity": "high"}],
            "affects": [{"ref": "pkg:deb/debian/openssl@3.0.11?distro=debian-12"}],
        }],
    }
    pd = parse_document(doc)
    assert pd.lane == "findings" and pd.source_tool == "trivy"
    assert pd.subject_locator == "pkg:oci/myimage@sha256:abc"
    f = pd.findings[0]
    assert f.cve == "CVE-2023-0464" and f.package == "openssl"
    assert f.severity == "HIGH" and f.cvss_base == 7.5
    assert f.ecosystem == "Debian:12"


def test_cdx_grype_opaque_bomref_index_hop():
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "metadata": {"tools": {"components": [{"name": "grype"}]}},
        "components": [{"bom-ref": "opaque-123", "name": "log4j-core",
                        "version": "2.14.1",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
        "vulnerabilities": [{
            "id": "GHSA-jfh8-c2jp-5v3q",
            "references": [{"id": "CVE-2021-44228"}],
            "ratings": [{"severity": "critical", "method": "CVSSv31", "score": 10.0}],
            "affects": [{"ref": "opaque-123"}],
        }],
    }
    f = parse_document(doc).findings[0]
    assert f.cve == "CVE-2021-44228" and f.osv_id == "GHSA-jfh8-c2jp-5v3q"
    assert f.package == "log4j-core" and f.severity == "CRITICAL"


def test_cdx_vex_state_captured():
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {},
        "components": [{"bom-ref": "c1", "name": "openssl", "version": "3.0.0",
                        "purl": "pkg:deb/debian/openssl@3.0.0?distro=debian-12"}],
        "vulnerabilities": [{
            "id": "CVE-2023-0464",
            "ratings": [{"severity": "high"}],
            "analysis": {"state": "not_affected", "justification": "code_not_reachable"},
            "affects": [{"ref": "c1"}],
        }],
    }
    f = parse_document(doc).findings[0]
    assert f.vex_state == "not_affected"


def test_cdx_components_only_is_inventory_lane():
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.4",
        "metadata": {"tools": [{"name": "syft"}]},
        "components": [
            {"bom-ref": "c1", "name": "requests", "version": "2.31.0",
             "purl": "pkg:pypi/requests@2.31.0"},
            {"bom-ref": "c2", "name": "openssl", "version": "3.0.11",
             "purl": "pkg:deb/debian/openssl@3.0.11?distro=debian-12"},
        ],
    }
    pd = parse_document(doc)
    assert pd.lane == "inventory" and len(pd.packages) == 2
    ecos = {p.ecosystem for p in pd.packages}
    assert "PyPI" in ecos and "Debian:12" in ecos


# ── SPDX 2.3 (inventory only) ────────────────────────────────────────────────
def test_spdx_purl_to_package_and_subject():
    doc = {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {"creators": ["Tool: trivy-0.50.0", "Organization: aquasecurity"]},
        "documentDescribes": ["SPDXRef-Image"],
        "packages": [
            {"SPDXID": "SPDXRef-Image", "name": "myimage", "versionInfo": "NOASSERTION",
             "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                               "referenceType": "purl",
                               "referenceLocator": "pkg:oci/myimage@sha256:deadbeef"}]},
            {"SPDXID": "SPDXRef-openssl", "name": "openssl", "versionInfo": "3.0.11",
             "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                               "referenceType": "purl",
                               "referenceLocator": "pkg:deb/debian/openssl@3.0.11?distro=debian-12"}]},
            {"SPDXID": "SPDXRef-req", "name": "requests", "versionInfo": "2.31.0",
             "externalRefs": [{"referenceCategory": "PACKAGE_MANAGER",   # 2.2 underscore
                               "referenceType": "purl",
                               "referenceLocator": "pkg:pypi/requests@2.31.0"}]},
        ],
    }
    pd = parse_document(doc)
    assert pd.lane == "inventory" and pd.source_tool == "trivy"
    assert pd.subject_locator == "pkg:oci/myimage@sha256:deadbeef"
    names = {p.name for p in pd.packages}
    assert names == {"openssl", "requests"}               # the oci root app node is skipped


def test_spdx_missing_distro_low_fidelity_note():
    doc = {
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {"creators": ["Tool: syft-1.0"]},
        "packages": [{"SPDXID": "SPDXRef-p", "name": "openssl", "versionInfo": "3.0.11",
                      "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                        "referenceType": "purl",
                                        "referenceLocator": "pkg:deb/debian/openssl@3.0.11"}]}],
    }
    pd = parse_document(doc)
    assert len(pd.packages) == 1 and pd.packages[0].ecosystem == ""
    assert any("low-fidelity" in n for n in pd.notes)


# ── dispatch / robustness ────────────────────────────────────────────────────
def test_sniff_and_dispatch_unknown_raises():
    import pytest
    with pytest.raises(ValueError):
        parse_document({"hello": "world"})


def test_doc_content_id_stable_and_order_insensitive():
    a = ing.doc_content_id({"b": 2, "a": 1})
    b = ing.doc_content_id({"a": 1, "b": 2})
    assert a == b and a.startswith("sha256:")
