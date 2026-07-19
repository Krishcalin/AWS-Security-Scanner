"""Phase 3 (vuln-engine unlock) — language app-dependency CVE (CWPP-06): the
ecosystem version comparators (semver/PEP440/gem), the lockfile parsers
(npm/pip/poetry/go/gem/cargo), the two matcher fixes (SEMVER range eval + gated
EVR fallback), and end-to-end via DictExtractor. Pure, offline, no disk/network."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_sidescan as ss


# ── semver 2.0 comparator (npm/Go/crates.io) ─────────────────────────────────
def test_semver_ordering():
    c = ss.semver_vercmp
    assert c("1.2.3", "1.2.3") == 0
    assert c("1.2.10", "1.2.9") == 1          # numeric, not lexical
    assert c("1.2.3", "1.10.0") == -1
    assert c("1.0.0-alpha", "1.0.0") == -1    # release > prerelease
    # full SemVer §11 precedence chain
    order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
             "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
    for a, b in zip(order, order[1:]):
        assert c(a, b) == -1, (a, b)
    assert c("v1.2.3", "1.2.3") == 0          # leading v stripped
    assert c("1.2.3+build.5", "1.2.3+other") == 0    # build metadata ignored
    assert c("1.2", "1.2.0") == 0             # short version padded


# ── PEP 440 comparator (PyPI) ────────────────────────────────────────────────
def test_pep440_ordering():
    c = ss.pep440_vercmp
    order = ["1.0.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1", "1.1"]
    for a, b in zip(order, order[1:]):
        assert c(a, b) == -1, (a, b)
    assert c("1.0", "1.0.0") == 0             # trailing-zero release strip
    assert c("1!1.0", "2.0") == 1             # epoch dominates
    assert c("1.0+local", "1.0") == 1         # local > public
    assert c("1.0.0", "1.0.0") == 0
    assert c("beta", "1.0") in (-1, 1)        # non-PEP440 -> string fallback, no crash


# ── RubyGems Gem::Version comparator ─────────────────────────────────────────
def test_gem_ordering():
    c = ss.gem_vercmp
    assert c("1.0.0", "1.0") == 0             # trailing zero
    assert c("1.0.a", "1.0") == -1            # prerelease (string seg) < release
    assert c("1.0.0.beta1", "1.0.0") == -1
    assert c("1.2.10", "1.2.9") == 1
    assert c("1.0.a10", "1.0.a9") == 1        # numeric within string tail


def test_cmp_for_dispatch():
    assert ss.cmp_for("npm") is ss.semver_vercmp
    assert ss.cmp_for("go") is ss.semver_vercmp
    assert ss.cmp_for("cargo") is ss.semver_vercmp
    assert ss.cmp_for("pypi") is ss.pep440_vercmp
    assert ss.cmp_for("gem") is ss.gem_vercmp
    assert ss.cmp_for("dpkg") is ss.dpkg_vercmp   # unchanged


# ── lockfile parsers ─────────────────────────────────────────────────────────
def test_parse_package_lock_v3():
    data = b'''{"lockfileVersion": 3, "packages": {
        "": {"name": "app", "version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/@babel/core": {"version": "7.24.0"},
        "node_modules/ws": {"version": "8.0.0", "link": true}
    }}'''
    pkgs = ss.parse_package_lock(data)
    names = {(p.name, p.version) for p in pkgs}
    assert ("lodash", "4.17.20") in names
    assert ("@babel/core", "7.24.0") in names   # scoped name from last node_modules/
    assert not any(p.name == "ws" for p in pkgs)  # link=workspace skipped
    assert not any(p.name == "app" for p in pkgs) # root project skipped
    assert all(p.ecosystem == "npm" and p.origin == "npm" for p in pkgs)


def test_parse_package_lock_v1():
    data = b'''{"lockfileVersion": 1, "dependencies": {
        "express": {"version": "4.18.0", "dependencies": {"qs": {"version": "6.5.2"}}}
    }}'''
    pkgs = {(p.name, p.version) for p in ss.parse_package_lock(data)}
    assert ("express", "4.18.0") in pkgs and ("qs", "6.5.2") in pkgs   # transitive


def test_parse_yarn_lock_v1():
    data = b'''"lodash@^4.0.0", lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@babel/core@^7.0.0":
  version "7.24.0"
'''
    pkgs = {(p.name, p.version) for p in ss.parse_yarn_lock(data)}
    assert ("lodash", "4.17.21") in pkgs and ("@babel/core", "7.24.0") in pkgs


def test_parse_pipfile_lock():
    data = b'''{"default": {"Django": {"version": "==3.2.0"}, "zope.interface": {"version": "==5.4.0"}},
                "develop": {"pytest": {"version": "==7.0.0"}},
                "_meta": {}}'''
    pkgs = {(p.name, p.version) for p in ss.parse_pipfile_lock(data)}
    assert ("django", "3.2.0") in pkgs            # == stripped, PEP503 lowercased
    assert ("zope-interface", "5.4.0") in pkgs    # PEP503 . -> -
    assert ("pytest", "7.0.0") in pkgs            # develop included


def test_parse_poetry_lock():
    data = b'''[[package]]
name = "Jinja2"
version = "3.1.2"

[[package]]
name = "localdep"
version = "0.1.0"
[package.source]
type = "directory"
url = "../localdep"
'''
    pkgs = {(p.name, p.version) for p in ss.parse_poetry_lock(data)}
    assert ("jinja2", "3.1.2") in pkgs
    assert not any(p.name == "localdep" for p in ss.parse_poetry_lock(data))  # directory source skipped


def test_parse_go_mod():
    data = b'''module example.com/app
go 1.21
require (
    github.com/gin-gonic/gin v1.9.0
    github.com/google/uuid v1.3.0 // indirect
)
require github.com/pkg/errors v0.9.1
replace github.com/gin-gonic/gin => github.com/gin-gonic/gin v1.9.1
'''
    pkgs = {(p.name, p.version) for p in ss.parse_go_mod(data)}
    assert ("github.com/google/uuid", "1.3.0") in pkgs      # v stripped, indirect kept
    assert ("github.com/pkg/errors", "0.9.1") in pkgs
    assert ("github.com/gin-gonic/gin", "1.9.1") in pkgs    # replace applied
    assert not any(v == "1.9.0" for _, v in pkgs)           # replaced version not emitted


def test_parse_gemfile_lock():
    data = b'''GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.0)
    nokogiri (1.15.0-x86_64-linux)
      racc (~> 1.4)

PLATFORMS
  x86_64-linux
'''
    pkgs = {(p.name, p.version) for p in ss.parse_gemfile_lock(data)}
    assert ("rails", "7.0.0") in pkgs
    assert ("nokogiri", "1.15.0") in pkgs      # platform suffix stripped
    assert not any(p.name == "racc" for p in ss.parse_gemfile_lock(data))  # constraint line skipped


def test_parse_cargo_lock():
    data = b'''[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
'''
    pkgs = ss.parse_cargo_lock(data)
    assert ("serde", "1.0.190") in {(p.name, p.version) for p in pkgs}
    assert not any(p.name == "app" for p in pkgs)   # workspace crate (no source) skipped
    assert pkgs[0].ecosystem == "crates.io" and pkgs[0].origin == "cargo"


def test_parse_requirements_only_exact_pins():
    data = b'''django==3.2.0
requests>=2.0        # a range, not a pin
flask==2.0.*         # wildcard = range
-r other.txt
Jinja2==3.1.2 ; python_version < "3.11"
'''
    pkgs = {(p.name, p.version) for p in ss.parse_requirements(data)}
    assert ("django", "3.2.0") in pkgs and ("jinja2", "3.1.2") in pkgs
    assert not any(n == "requests" for n, _ in pkgs)   # non-pinned dropped
    assert not any(n == "flask" for n, _ in pkgs)      # wildcard dropped


# ── MATCHER FIX #1: SEMVER ranges (npm/Go) are now evaluated ─────────────────
def _semver_osv(cve, eco, name, introduced, fixed):
    return {"id": cve, "aliases": [cve],
            "affected": [{"package": {"ecosystem": eco, "name": name},
                          "ranges": [{"type": "SEMVER",
                                      "events": [{"introduced": introduced}, {"fixed": fixed}]}]}],
            "severity": [{"type": "CVSS_V3", "score": "7.5"}]}


def test_semver_range_now_matched():
    inv = [ss._lang_pkg("go", "github.com/foo/bar", "1.2.0"),
           ss._lang_pkg("npm", "lodash", "4.17.20")]
    feed = ss.OSVFeed.from_records([
        _semver_osv("CVE-2024-1", "Go", "github.com/foo/bar", "1.0.0", "1.3.0"),
        _semver_osv("CVE-2024-2", "npm", "lodash", "4.0.0", "4.17.21")])
    vulns = ss.match_vulns(inv, feed, {}, set())
    cves = {v.cve for v in vulns}
    assert "CVE-2024-1" in cves and "CVE-2024-2" in cves   # SEMVER ranges evaluated


def test_semver_range_not_affected_when_fixed():
    inv = [ss._lang_pkg("npm", "lodash", "4.17.21")]      # exactly the fixed version
    feed = ss.OSVFeed.from_records([_semver_osv("CVE-2024-2", "npm", "lodash", "4.0.0", "4.17.21")])
    assert ss.match_vulns(inv, feed, {}, set()) == []


# ── MATCHER FIX #2: EVR-strip fallback gated to rpm/dpkg (no language FP) ─────
def test_language_prerelease_not_false_matched_by_versions_list():
    # OSV versions:["1.2.3"]; installed npm prerelease "1.2.3-beta" must NOT collapse
    rec = {"id": "CVE-X", "aliases": ["CVE-X"],
           "affected": [{"package": {"ecosystem": "npm", "name": "pkg"}, "versions": ["1.2.3"]}],
           "severity": [{"type": "CVSS_V3", "score": "5.0"}]}
    feed = ss.OSVFeed.from_records([rec])
    assert ss.match_vulns([ss._lang_pkg("npm", "pkg", "1.2.3-beta")], feed, {}, set()) == []
    # the exact release still matches
    assert ss.match_vulns([ss._lang_pkg("npm", "pkg", "1.2.3")], feed, {}, set())


# ── end-to-end: language lockfile on the filesystem -> app-dependency CVE ─────
def test_sidescan_app_dependency_end_to_end():
    ext = ss.DictExtractor({
        "/etc/os-release": b"ID=ubuntu\nVERSION_ID=22.04\n",
        "/var/lib/dpkg/status": b"",
        "/app/package-lock.json": b'{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}',
    })
    feed = ss.OSVFeed.from_records([_semver_osv("CVE-2024-2", "npm", "lodash", "4.0.0", "4.17.21")])
    res = ss.sidescan_filesystem(ext, feed, {}, set(), instance_id="i-1")
    assert any(p.name == "lodash" for p in res.packages)
    assert any(v.cve == "CVE-2024-2" for v in res.vulns)


# ── SBOM export (CycloneDX 1.5 + SPDX 2.3) ───────────────────────────────────
def _sbom_inv():
    return [ss._lang_pkg("npm", "lodash", "4.17.20"),
            ss._lang_pkg("pypi", "django", "3.2.0"),
            ss._lang_pkg("npm", "lodash", "4.17.20")]   # duplicate -> deduped


def test_sbom_cyclonedx_shape_and_dedup():
    doc = ss.sbom_cyclonedx(_sbom_inv(), created="2026-07-19T00:00:00Z",
                            serial="urn:uuid:1111")
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert doc["serialNumber"] == "urn:uuid:1111"
    assert len(doc["components"]) == 2                  # deduped
    comp = next(c for c in doc["components"] if c["name"] == "lodash")
    assert comp["type"] == "library" and comp["version"] == "4.17.20"
    assert comp["purl"] == "pkg:npm/lodash@4.17.20" and comp["bom-ref"] == comp["purl"]


def test_sbom_spdx_shape():
    doc = ss.sbom_spdx(_sbom_inv(), created="2026-07-19T00:00:00Z", name="w")
    assert doc["spdxVersion"] == "SPDX-2.3" and doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert len(doc["packages"]) == 2
    ids = {p["SPDXID"] for p in doc["packages"]}
    assert ids == {"SPDXRef-Package-0", "SPDXRef-Package-1"}   # unique
    p0 = doc["packages"][0]
    assert p0["downloadLocation"] == "NOASSERTION"
    assert p0["externalRefs"][0]["referenceType"] == "purl"


def test_sbom_deterministic():
    inv = _sbom_inv()
    import json as _j
    a = _j.dumps(ss.sbom_cyclonedx(inv, created="T"), sort_keys=True)
    b = _j.dumps(ss.sbom_cyclonedx(inv, created="T"), sort_keys=True)
    assert a == b                                       # same input -> identical output


def test_sidescan_app_deps_without_os_release():
    # a scratch/app-only image with no /etc/os-release must still scan lockfiles
    ext = ss.DictExtractor({
        "/app/Gemfile.lock": b"GEM\n  specs:\n    rails (7.0.0)\n\nPLATFORMS\n  ruby\n"})
    feed = ss.OSVFeed.from_records([
        {"id": "CVE-R", "aliases": ["CVE-R"],
         "affected": [{"package": {"ecosystem": "RubyGems", "name": "rails"},
                       "ranges": [{"type": "ECOSYSTEM",
                                   "events": [{"introduced": "0"}, {"fixed": "7.0.1"}]}]}],
         "severity": [{"type": "CVSS_V3", "score": "9.0"}]}])
    res = ss.sidescan_filesystem(ext, feed, {}, set())
    assert res.os is None
    assert any(v.cve == "CVE-R" for v in res.vulns)   # app deps scanned despite no OS
