"""Unit tests for aws_sidescan — the pure agentless CWPP core.

Heaviest coverage on the three ecosystem-correct version comparators (semver is
wrong for all three — this is where correctness lives), then inventory parsers,
the OSV matcher + affected-range evaluation, secrets, and the HAS_VULN edge shape
(which must be 1:1 with aws_live_scanner._check_vuln so aws_correlate is unchanged).
"""
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_sidescan as ss
from aws_graph import SecurityGraph


# ── dpkg version comparison ──────────────────────────────────────────────────
@pytest.mark.parametrize("a,b,exp", [
    ("1.0", "1.0", 0),
    ("2.0", "1.0", 1),
    ("1.0", "2.0", -1),
    ("1.0-1", "1.0-2", -1),
    ("1.0-2", "1.0-1", 1),
    ("1.0~rc1", "1.0", -1),          # tilde is pre-release
    ("1.0", "1.0~rc1", 1),
    ("1.0~~", "1.0~", -1),
    ("1:1.0", "2.0", 1),             # epoch dominates
    ("1.0-1ubuntu1", "1.0-1", 1),    # revision suffix
    ("2.3.4-1", "2.3.4-1", 0),
    ("1.0.0", "1.0", 1),
    ("0:1.2-3", "1.2-3", 0),         # explicit epoch 0 == none
])
def test_dpkg_vercmp(a, b, exp):
    assert ss.dpkg_vercmp(a, b) == exp


# ── rpm version comparison ───────────────────────────────────────────────────
@pytest.mark.parametrize("a,b,exp", [
    ("1.0", "1.0", 0),
    ("1.0", "1.1", -1),
    ("1.1", "1.0", 1),
    ("1.0.1", "1.0", 1),
    ("1.0~beta", "1.0", -1),         # tilde pre-release
    ("1.0", "1.0^20240101", -1),     # caret post-release
    ("1.a", "1.1", -1),              # numeric segment outranks alpha
    ("1.0-1.el9", "1.0-2.el9", -1),  # release
    ("2.el9", "10.el9", -1),         # numeric release, longer wins
    ("1.01", "1.1", 0),              # leading zeros stripped
])
def test_rpm_vercmp_str(a, b, exp):
    assert ss.rpm_vercmp_str(a, b) == exp


def test_rpm_evr_epoch():
    assert ss.rpm_vercmp(ss.EVR(1, "1.0", "1"), ss.EVR(0, "2.0", "1")) == 1
    assert ss.rpm_vercmp(ss.EVR(0, "1.0", "1"), ss.EVR(0, "1.0", "1")) == 0


def test_rpm_backport_release_ordering():
    # openssl-1.0.2k-19.el7_9 vs -16.el7_9 -> the backported higher release is newer
    assert ss.rpm_vercmp_str("1.0.2k-19.el7_9", "1.0.2k-16.el7_9") == 1


# ── apk version comparison ───────────────────────────────────────────────────
@pytest.mark.parametrize("a,b,exp", [
    ("1.0", "1.0", 0),
    ("1.0", "1.0.1", -1),
    ("1.2.3-r0", "1.2.3-r1", -1),
    ("1.2.3-r2", "1.2.3-r1", 1),
    ("1.2.3_alpha1", "1.2.3", -1),   # pre-release suffix
    ("1.2.3_rc1", "1.2.3", -1),
    ("1.2.3", "1.2.3_p1", -1),       # _p is post-release
    ("1.2.3a", "1.2.3", 1),          # trailing letter
    ("1.2.3_alpha1", "1.2.3_beta1", -1),
])
def test_apk_vercmp(a, b, exp):
    assert ss.apk_vercmp(a, b) == exp


def test_cmp_for_dispatch():
    assert ss.cmp_for("dpkg") is ss.dpkg_vercmp
    assert ss.cmp_for("apk") is ss.apk_vercmp
    assert ss.cmp_for("rpm")("1.0", "1.1") == -1


# ── os-release + ecosystem ───────────────────────────────────────────────────
def test_os_release_ubuntu():
    data = b'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\n'
    osr = ss.parse_os_release(data)
    assert osr.id == "ubuntu" and osr.ecosystem == "Ubuntu:22.04" and osr.pkgmgr == "dpkg"


def test_os_release_debian_major_only():
    osr = ss.parse_os_release(b'ID=debian\nVERSION_ID="12"\n')
    assert osr.ecosystem == "Debian:12" and osr.pkgmgr == "dpkg"


def test_os_release_alpine():
    osr = ss.parse_os_release(b"ID=alpine\nVERSION_ID=3.19.1\n")
    assert osr.ecosystem == "Alpine:v3.19" and osr.pkgmgr == "apk"


def test_os_release_none_without_id():
    assert ss.parse_os_release(b"NAME=foo\n") is None


# ── inventory parsers ────────────────────────────────────────────────────────
DPKG = b"""Package: openssl
Status: install ok installed
Version: 3.0.2-0ubuntu1.10
Architecture: amd64
Source: openssl (3.0.2-0ubuntu1.10)

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: bash
Status: install ok installed
Version: 5.1-6ubuntu1
Architecture: amd64
"""


def test_parse_dpkg_status_keeps_only_installed():
    osr = ss.parse_os_release(b"ID=ubuntu\nVERSION_ID=22.04\n")
    pkgs = ss.parse_dpkg_status(DPKG, osr)
    names = {p.name for p in pkgs}
    assert names == {"openssl", "bash"}            # deinstalled dropped
    o = next(p for p in pkgs if p.name == "openssl")
    assert o.source == "openssl" and o.version == "3.0.2-0ubuntu1.10" and o.origin == "dpkg"


def test_parse_apk_installed():
    osr = ss.parse_os_release(b"ID=alpine\nVERSION_ID=3.19\n")
    data = b"P:musl\nV:1.2.4-r2\nA:x86_64\no:musl\n\nP:busybox\nV:1.36.1-r5\nA:x86_64\no:busybox\n"
    pkgs = ss.parse_apk_installed(data, osr)
    assert {p.name for p in pkgs} == {"musl", "busybox"}
    assert next(p for p in pkgs if p.name == "musl").version == "1.2.4-r2"


def test_parse_rpm_manifest():
    osr = ss.parse_os_release(b"ID=rocky\nVERSION_ID=9.3\n")
    text = b"openssl\t1\t3.0.7\t18.el9_2\tx86_64\topenssl-3.0.7-18.el9_2.src.rpm\n"
    pkgs = ss.parse_rpm_manifest(text, osr)
    assert len(pkgs) == 1
    assert pkgs[0].name == "openssl" and pkgs[0].version == "1:3.0.7-18.el9_2"
    assert pkgs[0].source == "openssl" and pkgs[0].origin == "rpm"


# ── rpm header blob (pure struct) ────────────────────────────────────────────
def _build_rpm_blob(tags):
    """tags: list of (tag, type, value). type 6=string, 4=int32."""
    store = b""
    index = b""
    for tag, typ, val in tags:
        offset = len(store)
        if typ == 6:
            store += val.encode() + b"\x00"
        elif typ == 4:
            store += struct.pack(">I", val)
        index += struct.pack(">IIii", tag, typ, offset, 1)
    hdr = struct.pack(">II", len(tags), len(store)) + index + store
    return ss._RPM_MAGIC + b"\x00\x00\x00\x00" + hdr


def test_parse_rpm_header_blob():
    blob = _build_rpm_blob([
        (1000, 6, "openssl"), (1001, 6, "3.0.7"), (1002, 6, "18.el9"),
        (1003, 4, 1), (1022, 6, "x86_64"), (1044, 6, "openssl-3.0.7-18.el9.src.rpm"),
    ])
    h = ss.parse_rpm_header_blob(blob)
    assert h.name == "openssl" and h.version == "3.0.7" and h.release == "18.el9"
    assert h.epoch == 1 and h.arch == "x86_64"


def test_parse_rpmdb_sqlite_rejects_bdb():
    osr = ss.parse_os_release(b"ID=centos\nVERSION_ID=7\n")
    with pytest.raises(ss.Unsupported):
        ss.parse_rpmdb_sqlite(b"\x00\x01\x02not-sqlite", osr)


# ── OSV matcher + affected ranges ────────────────────────────────────────────
def _osv(cve, eco, name, introduced, fixed, severity="HIGH"):
    return {
        "id": cve, "aliases": [cve],
        "affected": [{
            "package": {"ecosystem": eco, "name": name},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": introduced}, {"fixed": fixed}]}],
            "database_specific": {"severity": severity},
        }],
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
    }


def test_version_affected_basic():
    ev = [{"introduced": "0"}, {"fixed": "1.2.3-1"}]
    assert ss.version_affected("1.2.0-1", ev, ss.dpkg_vercmp) == (True, "1.2.3-1")
    assert ss.version_affected("1.2.3-1", ev, ss.dpkg_vercmp) == (False, None)
    assert ss.version_affected("1.3.0", ev, ss.dpkg_vercmp) == (False, None)


def test_match_vulns_affected():
    osr = ss.parse_os_release(b"ID=ubuntu\nVERSION_ID=22.04\n")
    inv = ss.parse_dpkg_status(DPKG, osr)
    feed = ss.OSVFeed.from_records([
        _osv("CVE-2024-0001", "Ubuntu:22.04", "openssl", "0", "3.0.2-0ubuntu1.15"),
    ])
    matches = ss.match_vulns(inv, feed, {"CVE-2024-0001": 0.9}, {"CVE-2024-0001"})
    assert len(matches) == 1
    m = matches[0]
    assert m.cve == "CVE-2024-0001" and m.package == "openssl"
    assert m.fixed_version == "3.0.2-0ubuntu1.15" and m.kev is True
    assert m.epss == 0.9 and m.severity == "HIGH"


def test_match_vulns_not_affected_when_patched():
    osr = ss.parse_os_release(b"ID=ubuntu\nVERSION_ID=22.04\n")
    inv = ss.parse_dpkg_status(DPKG, osr)
    feed = ss.OSVFeed.from_records([
        _osv("CVE-2024-0002", "Ubuntu:22.04", "openssl", "0", "3.0.2-0ubuntu1.5"),
    ])
    # installed 3.0.2-0ubuntu1.10 >= fixed 3.0.2-0ubuntu1.5 -> not affected
    assert ss.match_vulns(inv, feed, {}, set()) == []


def test_match_vulns_dedup_source_binary():
    osr = ss.parse_os_release(b"ID=ubuntu\nVERSION_ID=22.04\n")
    inv = ss.parse_dpkg_status(DPKG, osr)
    # a record that matches both the binary name and (hypothetically) source
    feed = ss.OSVFeed.from_records([
        _osv("CVE-2024-0003", "Ubuntu:22.04", "openssl", "0", "9.9.9"),
    ])
    matches = ss.match_vulns(inv, feed, {}, set())
    assert len([m for m in matches if m.cve == "CVE-2024-0003"]) == 1


# ── secrets ──────────────────────────────────────────────────────────────────
def test_scan_secrets_path_and_content():
    ext = ss.DictExtractor({
        "/root/.ssh/id_rsa": b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n",
        "/root/.ssh/id_rsa.pub": b"ssh-rsa AAAA...",
        "/home/app/.env": b"AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        "/etc/app.conf": b"aws_key=AKIA1234567890ABCDEF\n",
    })
    findings = ss.scan_secrets(ext, roots=("/root", "/home", "/etc"))
    kinds = {f.kind for f in findings}
    assert "ssh-private-key" in kinds        # id_rsa flagged
    assert "private-key" in kinds            # BEGIN ... PRIVATE KEY content
    assert "aws-access-key" in kinds
    # .pub must NOT be flagged as a private key path
    assert not any(f.path.endswith(".pub") and f.kind == "ssh-private-key" for f in findings)
    # only a preview is stored, never the full secret
    ak = next(f for f in findings if f.kind == "aws-access-key")
    assert "…" in ak.match_preview and "1234567890" not in ak.match_preview


def test_scan_secrets_denylists_example_keys():
    ext = ss.DictExtractor({"/etc/x": b"AKIAIOSFODNN7EXAMPLE\n"})
    assert ss.scan_secrets(ext, roots=("/etc",)) == []


def test_shannon_entropy():
    assert ss.shannon_entropy("aaaa") == 0.0
    assert ss.shannon_entropy("abcd") == 2.0


# ── HAS_VULN edge shape (must feed aws_correlate unchanged) ───────────────────
def test_emit_vuln_edges_shape_matches_inspector():
    import aws_deepplane
    g = SecurityGraph()
    m = ss.EnrichedMatch(cve="CVE-2024-0009", osv_id="CVE-2024-0009", package="openssl",
                         installed_version="3.0.2-0ubuntu1.10", fixed_version="3.0.2-0ubuntu1.15",
                         severity="CRITICAL", cvss_base=9.8, epss=0.94, kev=True,
                         exploit_available="YES", ecosystem="Ubuntu:22.04")
    n = ss.emit_vuln_edges(g, "arn:aws:ec2:eu-west-1:1:instance/i-1", "i-1", [m], "snap-1")
    assert n == 1
    edges = list(g.edges("HAS_VULN"))
    assert len(edges) == 1
    props = edges[0]["props"]
    for k in ("cve", "severity", "epss", "kev", "exploit_available", "fix_available", "finding_arn"):
        assert k in props
    # the vuln node must be exploitable per the injected predicate correlate uses
    vnode = g.node("CVE-2024-0009")["props"]
    assert aws_deepplane.is_exploitable(vnode) is True
    # instance node kind MUST be EC2Instance (or correlate skips it)
    assert g.node("arn:aws:ec2:eu-west-1:1:instance/i-1")["kind"] == "EC2Instance"


def test_emit_vuln_edges_merge_idempotent():
    g = SecurityGraph()
    m = ss.EnrichedMatch(cve="CVE-2024-0010", osv_id="x", package="p", installed_version="1",
                         fixed_version=None, severity="HIGH", cvss_base=7.0, epss=0.1,
                         kev=False, exploit_available=None, ecosystem="Ubuntu:22.04")
    ss.emit_vuln_edges(g, "arn:i-2", "i-2", [m])
    ss.emit_vuln_edges(g, "arn:i-2", "i-2", [m])       # re-scan converges
    assert len(list(g.edges("HAS_VULN"))) == 1


# ── end-to-end orchestrator + fail-open ──────────────────────────────────────
def test_sidescan_filesystem_end_to_end():
    ext = ss.DictExtractor({
        "/etc/os-release": b"ID=ubuntu\nVERSION_ID=22.04\n",
        "/var/lib/dpkg/status": DPKG,
        "/root/.aws/credentials": b"[default]\naws_secret_access_key=abc\n",
    })
    feed = ss.OSVFeed.from_records([
        _osv("CVE-2024-1000", "Ubuntu:22.04", "bash", "0", "5.9-0ubuntu1"),
    ])
    res = ss.sidescan_filesystem(ext, feed, {"CVE-2024-1000": 0.3}, set(), instance_id="i-9")
    assert res.os.id == "ubuntu"
    assert {p.name for p in res.packages} == {"openssl", "bash"}
    assert [m.cve for m in res.vulns] == ["CVE-2024-1000"]
    assert any(s.kind == "aws-credentials" for s in res.secrets)


def test_sidescan_failopen_no_osrelease():
    ext = ss.DictExtractor({"/some/file": b"data"})
    res = ss.sidescan_filesystem(ext, None, {}, set())
    assert res.os is None and res.packages == [] and res.vulns == []
    assert any("os-release" in n for n in res.notes)


def test_sidescan_failopen_no_feed():
    ext = ss.DictExtractor({"/etc/os-release": b"ID=ubuntu\nVERSION_ID=22.04\n",
                            "/var/lib/dpkg/status": DPKG})
    res = ss.sidescan_filesystem(ext, None, {}, set())
    assert len(res.packages) == 2 and res.vulns == []
    assert any("feed" in n for n in res.notes)


def test_sidescan_failopen_unsupported_rpmdb():
    ext = ss.DictExtractor({"/etc/os-release": b"ID=centos\nVERSION_ID=7\n",
                            "/var/lib/rpm/Packages": b"\x00bdb"})
    res = ss.sidescan_filesystem(ext, None, {}, set())
    assert res.packages == []
    assert any("not decodable" in n for n in res.notes)
