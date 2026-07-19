#!/usr/bin/env python3
"""
aws_sidescan.py — Agentless workload side-scan core (CNAPP Phase 6, CWPP).

The Wiz/Orca-defining capability, as a PURE, dependency-free core: given a
read-only view of a workload's filesystem (a FilesystemExtractor — in production
backed by an EBS snapshot, in tests by an in-memory dict), inventory its OS
packages, match them against a vulnerability feed, and scan for on-disk secrets —
with NO agent on the instance. The resulting CVEs are emitted as `HAS_VULN` graph
edges shaped EXACTLY like Amazon Inspector's, so agentless findings feed the SAME
attack-path correlation (ATTACK-02) even when Inspector is not enabled.

Design invariants
-----------------
* **Pure** — stdlib only (no boto3, no DB driver, no kernel/mount). Every function
  is unit-testable with a hand-built ``DictExtractor`` + hand-built OSV/EPSS/KEV
  records. Raw ext4/xfs/ntfs block parsing is NOT faked — it lives behind the
  injected :class:`FilesystemExtractor` seam (production impls are deferred to the
  EBS I/O module).
* **Fail-open** — a missing os-release / unreadable package DB / absent feed
  degrades to an empty result with a ``notes`` entry: NEVER a crash, NEVER a
  phantom finding, NEVER a false-clean PASS on a host we could not read.
* **Read-only & non-exfil** — secrets are reported by kind/path with only a
  first4…last4 preview; the scanner must never become a secret-exfil vector.
* **Feeds the graph unchanged** — the emitted edge props match
  ``aws_live_scanner._check_vuln`` (cve/severity/epss/kev/exploit_available/
  fix_available/finding_arn) so ``aws_correlate.is_exploitable`` works unchanged
  and MERGE-converges with any Inspector edge on the same (instance, cve).

Ecosystem-correct version comparison (dpkg/rpm/apk) is where correctness lives —
semver is WRONG for all three. See dpkg_vercmp / rpm_vercmp / apk_vercmp.
"""

from __future__ import annotations

import io
import json
import math
import re
import struct
import tarfile
from dataclasses import dataclass, field
from typing import (AbstractSet, Callable, Dict, Iterator, List, Mapping,
                    Optional, Protocol, Tuple)

EPSS_HIGH = 0.5   # mirror aws_deepplane.EPSS_HIGH (FIRST.org probability 0..1)


# ── filesystem seam (the deferral boundary) ──────────────────────────────────
@dataclass(frozen=True)
class FileStat:
    size: int
    mode: int
    mtime: int
    is_symlink: bool


class FilesystemExtractor(Protocol):
    """Read-only view of an extracted workload filesystem. Production impls
    (loop-mount / userspace-fs / attach-mount over an EBS snapshot) live in the
    deferred EBS I/O module; :class:`DictExtractor` is the pure test impl."""
    def read_file(self, path: str) -> Optional[bytes]: ...
    def exists(self, path: str) -> bool: ...
    def walk(self, root: str, max_files: int) -> Iterator[str]: ...
    def stat(self, path: str) -> Optional[FileStat]: ...


class DictExtractor:
    """Pure, in-memory FilesystemExtractor over ``{path: bytes}`` — the ships-now
    test double so the whole core is exercisable without a real disk."""

    def __init__(self, files: Mapping[str, bytes]):
        self._f = dict(files)

    def read_file(self, path: str) -> Optional[bytes]:
        return self._f.get(path)

    def exists(self, path: str) -> bool:
        return path in self._f

    def walk(self, root: str, max_files: int) -> Iterator[str]:
        n = 0
        for p in sorted(self._f):
            if p.startswith(root):
                yield p
                n += 1
                if n >= max_files:
                    return

    def stat(self, path: str) -> Optional[FileStat]:
        b = self._f.get(path)
        if b is None:
            return None
        return FileStat(size=len(b), mode=0o600, mtime=0, is_symlink=False)


# ── OCI/Docker image-layer overlay (container-image side-scan = CWPP-05) ───────
def _norm_tar_path(name: str) -> Optional[str]:
    """Normalize a tar member name to a relative path; None if it escapes ('..')."""
    parts: List[str] = []
    for seg in (name or "").replace("\\", "/").split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            return None                       # tar-slip guard
        parts.append(seg)
    return "/".join(parts)


def merge_layers(layers: List[bytes], *, max_file_bytes: int = 10_000_000,
                 max_total_bytes: int = 1_000_000_000, max_entries: int = 500_000,
                 notes: Optional[List[str]] = None) -> Dict[str, bytes]:
    """Overlay OCI/Docker image layers (each a gzip/tar changeset, BOTTOM-TO-TOP)
    into a merged absolute-path -> content map, honoring whiteouts. PURE and
    fail-open: an unreadable layer/member becomes a note, never a crash. Feeds
    ImageLayerExtractor so the UNCHANGED sidescan pipeline runs on the image."""
    merged: Dict[str, bytes] = {}
    symlinks: List[Tuple[str, str]] = []
    total = 0
    entries = 0
    for blob in layers:
        if entries >= max_entries:
            break
        try:
            tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
        except Exception as e:
            if notes is not None:
                notes.append(f"image layer unreadable: {e}")
            continue
        files_this: Dict[str, bytes] = {}
        layer_files: Dict[str, bytes] = {}    # for in-layer hardlink resolution
        opaque: List[str] = []
        whiteout: List[str] = []
        try:
            members = tf.getmembers()
        except Exception:
            members = []
        for m in members:
            entries += 1
            if entries > max_entries:
                break
            try:
                name = m.name
                base = name.rsplit("/", 1)[-1]
                dirn = name[:len(name) - len(base)].rstrip("/")
                if base == ".wh..wh..opq":
                    d = _norm_tar_path(dirn)
                    if d is not None:
                        opaque.append(d)
                    continue
                if base.startswith(".wh.") and len(base) > 4:
                    tgt = _norm_tar_path((dirn + "/" + base[4:]) if dirn else base[4:])
                    if tgt is not None:
                        whiteout.append(tgt)
                    continue
                rel = _norm_tar_path(name)
                if rel is None or m.isdir() or m.ischr() or m.isblk() or m.isfifo():
                    continue
                if m.issym():
                    symlinks.append(("/" + rel, m.linkname))
                    continue
                if m.islnk():
                    src = _norm_tar_path(m.linkname)
                    if src in layer_files:
                        files_this[rel] = layer_files[src]
                    continue
                if m.isfile():
                    if (m.size or 0) > max_file_bytes or total > max_total_bytes:
                        continue
                    f = tf.extractfile(m)
                    if f is None:
                        continue
                    data = f.read(max_file_bytes + 1)
                    if len(data) > max_file_bytes:
                        continue
                    files_this[rel] = data
                    layer_files[rel] = data
                    total += len(data)
            except Exception:
                continue
        # whiteouts hit LOWER layers only: delete from `merged` BEFORE folding this layer
        for d in opaque:
            pref = "/" + d
            for k in [k for k in merged if k == pref or k.startswith(pref + "/")]:
                del merged[k]
        for t in whiteout:
            p = "/" + t
            for k in [k for k in merged if k == p or k.startswith(p + "/")]:
                del merged[k]
        for rel, data in files_this.items():
            merged["/" + rel] = data
        try:
            tf.close()
        except Exception:
            pass
    # best-effort single-hop symlink resolution (bake target bytes into the link path)
    for linkpath, target in symlinks:
        base = linkpath.rsplit("/", 1)[0]
        if target.startswith("/"):
            resolved = "/" + "/".join(s for s in target.split("/") if s and s != ".")
        else:
            parts = [s for s in base.strip("/").split("/") if s]
            for seg in target.split("/"):
                if seg in ("", "."):
                    continue
                if seg == "..":
                    if parts:
                        parts.pop()
                else:
                    parts.append(seg)
            resolved = "/" + "/".join(parts)
        if resolved in merged:
            merged[linkpath] = merged[resolved]
    return merged


class ImageLayerExtractor(DictExtractor):
    """FilesystemExtractor over a merged OCI/Docker image (layers bottom-to-top).
    Subclasses DictExtractor so read_file/exists/walk/stat are the already-validated
    pure implementations — an image scans byte-identically to the test double."""

    def __init__(self, layers: List[bytes], *, notes: Optional[List[str]] = None,
                 **caps):
        super().__init__(merge_layers(layers, notes=notes, **caps))


# ── data shapes ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class OSRelease:
    id: str
    version_id: str
    version_codename: str
    id_like: str
    ecosystem: str          # OSV ecosystem, e.g. "Ubuntu:22.04", "Debian:12"
    pkgmgr: str             # dpkg | rpm | apk


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    arch: str
    source: str
    source_version: str
    ecosystem: str
    purl: str
    origin: str             # dpkg | rpm | apk (which comparator applies)


@dataclass(frozen=True)
class RpmHeader:
    name: str
    version: str
    release: str
    epoch: Optional[int]
    arch: str
    sourcerpm: str


@dataclass(frozen=True)
class EVR:
    epoch: int
    version: str
    release: str


@dataclass(frozen=True)
class EnrichedMatch:
    cve: str
    osv_id: str
    package: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    cvss_base: Optional[float]
    epss: Optional[float]
    kev: bool
    exploit_available: Optional[str]   # "YES" or None (never a bool, never "NO")
    ecosystem: str


@dataclass(frozen=True)
class VulnEdge:
    node_arn: str
    cve: str
    props: Dict


@dataclass(frozen=True)
class SecretFinding:
    kind: str
    path: str
    line: int
    match_preview: str
    entropy: float
    severity: str


@dataclass
class SideScanResult:
    os: Optional[OSRelease]
    packages: List[Package]
    vulns: List[EnrichedMatch]
    secrets: List[SecretFinding]
    notes: List[str] = field(default_factory=list)


class Unsupported(Exception):
    """A package-DB container we can parse the location of but not the format
    (e.g. RPM Berkeley-DB / NDB). Surfaced as an INFO note, never a crash."""


# ── OS release + ecosystem resolution ────────────────────────────────────────
# (distro id, version-id prefix match) -> (OSV ecosystem template, pkgmgr)
_ECO = {
    "ubuntu": ("Ubuntu:{v}", "dpkg"),
    "debian": ("Debian:{vmaj}", "dpkg"),
    "alpine": ("Alpine:v{vmm}", "apk"),
    "rhel": ("Red Hat:{vmaj}", "rpm"),
    "redhat": ("Red Hat:{vmaj}", "rpm"),
    "centos": ("CentOS:{vmaj}", "rpm"),
    "rocky": ("Rocky Linux:{vmaj}", "rpm"),
    "almalinux": ("AlmaLinux:{vmaj}", "rpm"),
    "amzn": ("Amazon Linux:{vmaj}", "rpm"),
    "fedora": ("Fedora:{vmaj}", "rpm"),
    "opensuse-leap": ("openSUSE:Leap:{v}", "rpm"),
    "sles": ("SUSE Linux Enterprise:{vmaj}", "rpm"),
}


def _shell_unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    return v


def parse_os_release(data: bytes) -> Optional[OSRelease]:
    """Parse /etc/os-release (shell KEY=VALUE). Returns None if no ID is found."""
    if not data:
        return None
    kv: Dict[str, str] = {}
    for raw in data.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        kv[k.strip()] = _shell_unquote(v)
    did = kv.get("ID", "").lower()
    if not did:
        return None
    vid = kv.get("VERSION_ID", "")
    vmaj = vid.split(".")[0] if vid else ""
    vmm = ".".join(vid.split(".")[:2]) if vid else ""
    tmpl, pkgmgr = _ECO.get(did, ("", ""))
    eco = tmpl.format(v=vid, vmaj=vmaj, vmm=vmm) if tmpl else ""
    if not pkgmgr:
        # Unknown distro: guess pkgmgr from id_like so inventory still runs.
        like = kv.get("ID_LIKE", "").lower()
        if "debian" in like:
            pkgmgr = "dpkg"
        elif any(x in like for x in ("rhel", "fedora", "suse")):
            pkgmgr = "rpm"
        elif "alpine" in like:
            pkgmgr = "apk"
    return OSRelease(id=did, version_id=vid,
                     version_codename=kv.get("VERSION_CODENAME", ""),
                     id_like=kv.get("ID_LIKE", ""), ecosystem=eco, pkgmgr=pkgmgr)


# ── package inventory parsers ─────────────────────────────────────────────────
def _purl(pkgmgr: str, distro_id: str, name: str, version: str, arch: str) -> str:
    typ = {"dpkg": "deb", "rpm": "rpm", "apk": "apk"}.get(pkgmgr, pkgmgr)
    ns = {"deb": "debian", "rpm": distro_id, "apk": "alpine"}.get(typ, distro_id)
    q = f"?arch={arch}" if arch else ""
    return f"pkg:{typ}/{ns}/{name}@{version}{q}"


def to_purl(pkg_mgr, distro_id, name, version, arch, epoch=None, distro_ver=None) -> str:
    v = f"{epoch}:{version}" if epoch else version
    return _purl(pkg_mgr, distro_id, name, v, arch)


def parse_dpkg_status(data: bytes, os: OSRelease) -> List[Package]:
    """Parse Debian/Ubuntu /var/lib/dpkg/status (RFC822 stanzas). Keeps only
    'install ok installed' packages (dropping deinstall/config-files avoids the
    purged-package false positive)."""
    if not data:
        return []
    out: List[Package] = []
    for stanza in re.split(rb"\n\s*\n", data):
        if not stanza.strip():
            continue
        fields: Dict[str, str] = {}
        key = None
        for line in stanza.decode("utf-8", "replace").splitlines():
            if line[:1] in (" ", "\t"):
                continue  # continuation (e.g. multi-line Description)
            if ":" in line:
                key, _, val = line.partition(":")
                fields[key.strip()] = val.strip()
        if fields.get("Status") != "install ok installed":
            continue
        name = fields.get("Package", "")
        if not name:
            continue
        version = fields.get("Version", "")
        arch = fields.get("Architecture", "")
        source = name
        source_version = version
        src = fields.get("Source", "")
        if src:
            m = re.match(r"^(\S+)(?:\s+\(([^)]+)\))?$", src)
            if m:
                source = m.group(1)
                source_version = m.group(2) or version
        out.append(Package(name=name, version=version, arch=arch, source=source,
                           source_version=source_version, ecosystem=os.ecosystem,
                           purl=_purl("dpkg", os.id, name, version, arch),
                           origin="dpkg"))
    return out


def parse_apk_installed(data: bytes, os: OSRelease) -> List[Package]:
    """Parse Alpine /lib/apk/db/installed (single-letter keys, blank-line sep)."""
    if not data:
        return []
    out: List[Package] = []
    for stanza in re.split(rb"\n\s*\n", data):
        if not stanza.strip():
            continue
        f: Dict[str, str] = {}
        for line in stanza.decode("utf-8", "replace").splitlines():
            if len(line) >= 2 and line[1] == ":":
                f[line[0]] = line[2:]
        name = f.get("P", "")
        if not name:
            continue
        version = f.get("V", "")
        arch = f.get("A", "")
        origin_pkg = f.get("o", name)   # source package
        out.append(Package(name=name, version=version, arch=arch, source=origin_pkg,
                           source_version=version, ecosystem=os.ecosystem,
                           purl=_purl("apk", os.id, name, version, arch),
                           origin="apk"))
    return out


def parse_rpm_manifest(text: bytes, os: OSRelease) -> List[Package]:
    """Parse a textual rpm manifest (one pkg per line, tab-separated
    name\\tepoch\\tversion\\trelease\\tarch\\tsourcerpm — the `rpm -qa --qf` dump
    format), the portable fallback when the binary rpmdb cannot be decoded."""
    if not text:
        return []
    out: List[Package] = []
    for line in text.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        if len(cols) < 4:
            continue
        name, epoch, ver, rel = cols[0], cols[1], cols[2], cols[3]
        arch = cols[4] if len(cols) > 4 else ""
        srcrpm = cols[5] if len(cols) > 5 else ""
        epoch = epoch if epoch and epoch not in ("(none)", "0") else ""
        evr = (f"{epoch}:" if epoch else "") + f"{ver}-{rel}"
        source = _srcrpm_name(srcrpm) or name
        out.append(Package(name=name, version=evr, arch=arch, source=source,
                           source_version=evr, ecosystem=os.ecosystem,
                           purl=_purl("rpm", os.id, name, evr, arch),
                           origin="rpm"))
    return out


def _srcrpm_name(srcrpm: str) -> str:
    """foo-1.2-3.el9.src.rpm -> foo (strip -version-release.src.rpm)."""
    if not srcrpm:
        return ""
    s = re.sub(r"\.src\.rpm$", "", srcrpm)
    # strip trailing -version-release
    return re.sub(r"-[^-]+-[^-]+$", "", s)


# RPM header tags
_RPMTAG = {1000: "name", 1001: "version", 1002: "release", 1003: "epoch",
           1022: "arch", 1044: "sourcerpm"}
_RPM_MAGIC = b"\x8e\xad\xe8\x01"


def parse_rpm_header_blob(blob: bytes) -> Optional[RpmHeader]:
    """Parse a single RPM header blob (pure struct.unpack) into the 6 tags we
    need. Returns None on a malformed/short blob."""
    if not blob or len(blob) < 16:
        return None
    off = 0
    if blob[:4] == _RPM_MAGIC:
        off = 8   # 4-byte magic+version, 4-byte reserved
    if len(blob) < off + 8:
        return None
    nindex, hsize = struct.unpack(">II", blob[off:off + 8])
    off += 8
    idx_end = off + nindex * 16
    if idx_end + hsize > len(blob) or nindex > 100000:
        return None
    store = blob[idx_end:idx_end + hsize]
    vals: Dict[str, object] = {}
    for i in range(nindex):
        tag, typ, offset, count = struct.unpack(">IIii", blob[off + i * 16:off + i * 16 + 16])
        name = _RPMTAG.get(tag)
        if name is None:
            continue
        if typ == 4:    # INT32
            if offset + 4 <= len(store):
                vals[name] = struct.unpack(">I", store[offset:offset + 4])[0]
        elif typ in (6, 8, 9):   # STRING / STRING_ARRAY / I18NSTRING
            end = store.find(b"\x00", offset)
            if end >= 0:
                vals[name] = store[offset:end].decode("utf-8", "replace")
    if "name" not in vals:
        return None
    return RpmHeader(name=str(vals.get("name", "")), version=str(vals.get("version", "")),
                     release=str(vals.get("release", "")),
                     epoch=vals.get("epoch") if isinstance(vals.get("epoch"), int) else None,
                     arch=str(vals.get("arch", "")), sourcerpm=str(vals.get("sourcerpm", "")))


def parse_rpmdb_sqlite(db_bytes: bytes, os: OSRelease) -> List[Package]:
    """Parse a modern (RPM 4.16+) sqlite rpmdb: SELECT the Packages blobs and
    decode each header. Raises :class:`Unsupported` for a Berkeley-DB / NDB
    container (older RHEL/SLE) so the caller emits an INFO note (documented FN)."""
    if db_bytes[:16] != b"SQLite format 3\x00":
        raise Unsupported("rpmdb is not sqlite (Berkeley-DB/NDB container)")
    import os as _os
    import sqlite3
    import tempfile
    fd, tmp = tempfile.mkstemp(suffix=".sqlite")
    try:
        with _os.fdopen(fd, "wb") as fh:
            fh.write(db_bytes)
        conn = sqlite3.connect(tmp)
        try:
            rows = conn.execute("SELECT blob FROM Packages").fetchall()
        finally:
            conn.close()
    finally:
        try:
            _os.unlink(tmp)
        except OSError:
            pass
    out: List[Package] = []
    for (blob,) in rows:
        h = parse_rpm_header_blob(blob if isinstance(blob, (bytes, bytearray)) else bytes(blob))
        if h is None or h.name in ("gpg-pubkey",):
            continue
        epoch = f"{h.epoch}:" if h.epoch else ""
        evr = f"{epoch}{h.version}-{h.release}"
        source = _srcrpm_name(h.sourcerpm) or h.name
        out.append(Package(name=h.name, version=evr, arch=h.arch, source=source,
                           source_version=evr, ecosystem=os.ecosystem,
                           purl=_purl("rpm", os.id, h.name, evr, h.arch), origin="rpm"))
    return out


def detect_fs(read_fn: Callable[[int, int], bytes]) -> str:
    """Sniff the filesystem/container type from magic bytes so an encrypted or
    unsupported volume yields an honest 'unsupported' (→ INFO note) instead of a
    false-clean empty inventory. ``read_fn(offset, length)`` reads raw bytes.
    Returns 'ext' | 'xfs' | 'luks' | 'gpt' | 'unknown'."""
    try:
        if read_fn(0, 6) == b"LUKS\xba\xbe":
            return "luks"
        if read_fn(0, 4) == b"XFSB":
            return "xfs"
        if read_fn(0x438, 2) == b"\x53\xef":          # ext2/3/4 superblock magic 0xEF53 (LE)
            return "ext"
        if read_fn(512, 8) == b"EFI PART":            # GPT header at LBA1
            return "gpt"
    except Exception:
        return "unknown"
    return "unknown"


# ── rpm Berkeley-DB (RHEL7/CentOS7) — DEFERRED ───────────────────────────────
def parse_rpmdb_bdb(db: bytes):
    """Decode a legacy Berkeley-DB rpmdb (RHEL7/CentOS7). DEFERRED: a correct
    BDB-hash-page + overflow-chain walker plus a deterministic offline fixture is
    a sizable undertaking; until it lands, collect_inventory surfaces an INFO note
    (never a crash, never a false-clean). Raises Unsupported."""
    raise Unsupported("rpmdb Berkeley-DB decode is deferred (use a modern sqlite rpmdb)")


def collect_inventory(ext: FilesystemExtractor, os: OSRelease) -> List[Package]:
    """Dispatch to the right parser by pkgmgr. rpm tries the sqlite rpmdb, then a
    textual manifest. Raises Unsupported only for an undecodable rpmdb container."""
    if os.pkgmgr == "dpkg":
        data = ext.read_file("/var/lib/dpkg/status")
        return parse_dpkg_status(data, os) if data else []
    if os.pkgmgr == "apk":
        data = ext.read_file("/lib/apk/db/installed")
        return parse_apk_installed(data, os) if data else []
    if os.pkgmgr == "rpm":
        for p in ("/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite"):
            db = ext.read_file(p)
            if db:
                return parse_rpmdb_sqlite(db, os)   # may raise Unsupported
        for p in ("/var/lib/rpm/Packages.manifest", "/var/lib/rpm/.manifest"):
            man = ext.read_file(p)
            if man:
                return parse_rpm_manifest(man, os)
        db = ext.read_file("/var/lib/rpm/Packages")
        if db:
            raise Unsupported("rpmdb Berkeley-DB (Packages) not decodable")
        return []
    return []


# ── version comparators (ecosystem-correct; semver is WRONG for all three) ────
def _deb_order(c: str) -> int:
    if c == "":
        return 0
    if c.isdigit():
        return 0          # a digit terminates the non-digit part (dpkg Policy 5.6.12);
                          # weight 0 sorts it BELOW letters and ABOVE '~'
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256    # non-alpha, non-digit sorts after letters


def _deb_verrevcmp(a: str, b: str) -> int:
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _deb_order(a[i]) if i < la else 0
            bc = _deb_order(b[j]) if j < lb else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and a[i].isdigit() and j < lb and b[j].isdigit():
            if first_diff == 0:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def _split_deb(v: str) -> Tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, _, v = v.partition(":")
        try:
            epoch = int(e)
        except ValueError:
            epoch = 0
    if "-" in v:
        upstream, _, revision = v.rpartition("-")
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def dpkg_vercmp(a: str, b: str) -> int:
    ea, ua, ra = _split_deb(a)
    eb, ub, rb = _split_deb(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _deb_verrevcmp(ua, ub)
    if c:
        return c
    return _deb_verrevcmp(ra, rb)


def _rpm_segcmp(a: str, b: str) -> int:
    """rpmvercmp on a single label (version or release)."""
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while i < la and not (a[i].isalnum() or a[i] in "~^"):
            i += 1
        while j < lb and not (b[j].isalnum() or b[j] in "~^"):
            j += 1
        # tilde: pre-release, lowest
        at = i < la and a[i] == "~"
        bt = j < lb and b[j] == "~"
        if at or bt:
            if not at:
                return 1
            if not bt:
                return -1
            i += 1
            j += 1
            continue
        # caret: post-release
        ac = i < la and a[i] == "^"
        bc = j < lb and b[j] == "^"
        if ac or bc:
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if not ac:
                return 1
            if not bc:
                return -1
            i += 1
            j += 1
            continue
        if i >= la or j >= lb:
            break
        si, sj = i, j
        if a[i].isdigit():
            while i < la and a[i].isdigit():
                i += 1
            sa, isnum = a[si:i], True
        else:
            while i < la and a[i].isalpha():
                i += 1
            sa, isnum = a[si:i], False
        if b[j].isdigit():
            while j < lb and b[j].isdigit():
                j += 1
            sb = b[sj:j]
            if not isnum:
                return -1   # numeric segment outranks alpha
        else:
            while j < lb and b[j].isalpha():
                j += 1
            sb = b[sj:j]
            if isnum:
                return 1
        if isnum:
            sa = sa.lstrip("0") or "0"
            sb = sb.lstrip("0") or "0"
            if len(sa) != len(sb):
                return -1 if len(sa) < len(sb) else 1
        if sa != sb:
            return -1 if sa < sb else 1
    if i >= la and j >= lb:
        return 0
    return 1 if i < la else -1


def rpm_vercmp(a_evr: EVR, b_evr: EVR) -> int:
    if a_evr.epoch != b_evr.epoch:
        return -1 if a_evr.epoch < b_evr.epoch else 1
    c = _rpm_segcmp(a_evr.version, b_evr.version)
    if c:
        return c
    return _rpm_segcmp(a_evr.release, b_evr.release)


def _to_evr(v: str) -> EVR:
    epoch = 0
    if ":" in v:
        e, _, v = v.partition(":")
        try:
            epoch = int(e)
        except ValueError:
            epoch = 0
    if "-" in v:
        ver, _, rel = v.rpartition("-")
    else:
        ver, rel = v, ""
    return EVR(epoch, ver, rel)


def rpm_vercmp_str(a: str, b: str) -> int:
    return rpm_vercmp(_to_evr(a), _to_evr(b))


_APK_SUFFIX = {"alpha": 0, "beta": 1, "pre": 2, "rc": 3, "": 4,
               "cvs": 5, "svn": 6, "git": 7, "p": 9}


def _apk_parse(v: str):
    rev = 0
    m = re.search(r"-r(\d+)$", v)
    if m:
        rev = int(m.group(1))
        v = v[:m.start()]
    suffix_w, suffix_n = _APK_SUFFIX[""], 0
    ms = re.search(r"_(alpha|beta|pre|rc|cvs|svn|git|p)(\d*)", v)
    if ms:
        suffix_w = _APK_SUFFIX[ms.group(1)]
        suffix_n = int(ms.group(2)) if ms.group(2) else 0
        v = v[:ms.start()]
    letter = ""
    ml = re.match(r"^([0-9.]*)([a-z]?)$", v)
    if ml:
        numpart, letter = ml.group(1), ml.group(2)
    else:
        numpart = v
    nums = [int(x) for x in numpart.split(".") if x != ""]
    return nums, letter, suffix_w, suffix_n, rev


def apk_vercmp(a: str, b: str) -> int:
    na, la, swa, sna, ra = _apk_parse(a)
    nb, lb, swb, snb, rb = _apk_parse(b)
    for x, y in zip(na, nb):
        if x != y:
            return -1 if x < y else 1
    if len(na) != len(nb):
        # trailing non-zero segment makes the longer version greater
        tail = na[len(nb):] if len(na) > len(nb) else nb[len(na):]
        if any(t != 0 for t in tail):
            return 1 if len(na) > len(nb) else -1
    if la != lb:
        return -1 if la < lb else 1
    if swa != swb:
        return -1 if swa < swb else 1
    if sna != snb:
        return -1 if sna < snb else 1
    if ra != rb:
        return -1 if ra < rb else 1
    return 0


# ── language-ecosystem version comparators ───────────────────────────────────
# semver (npm/Go/crates.io), PEP 440 (PyPI), Gem::Version (RubyGems). Each returns
# strictly -1/0/1 as version_affected requires. dpkg/rpm/apk are WRONG for these
# (prerelease/epoch/post/local ordering differs).
def _semver_parse(v: str):
    v = (v or "").strip()
    if v[:1] in ("v", "V", "="):
        v = v[1:]
    v = v.split("+", 1)[0]                     # SemVer §10: build metadata ignored
    core, _, pre = v.partition("-")
    nums = []
    for part in core.split("."):
        try:
            nums.append(int(part))
        except ValueError:
            nums.append(0)
    return (nums or [0]), pre


def _semver_pre_cmp(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return 1                              # release > prerelease
    if not b:
        return -1
    ai, bi = a.split("."), b.split(".")
    for x, y in zip(ai, bi):
        xd, yd = x.isdigit(), y.isdigit()
        if xd and yd:
            c = (int(x) > int(y)) - (int(x) < int(y))
        elif xd:
            c = -1                            # numeric identifier < alphanumeric
        elif yd:
            c = 1
        else:
            c = (x > y) - (x < y)
        if c:
            return c
    return (len(ai) > len(bi)) - (len(ai) < len(bi))   # longer prerelease set wins


def semver_vercmp(a: str, b: str) -> int:
    an, ap = _semver_parse(a)
    bn, bp = _semver_parse(b)
    n = max(len(an), len(bn))                  # compare ALL core parts (pad shorter)
    an = an + [0] * (n - len(an))
    bn = bn + [0] * (n - len(bn))
    if an != bn:
        return (an > bn) - (an < bn)
    return _semver_pre_cmp(ap, bp)


def _gem_canonical(v: str):
    segs = [int(t) if t.isdigit() else t for t in re.findall(r"\d+|[A-Za-z]+", v or "")]
    first_str = next((i for i, s in enumerate(segs) if isinstance(s, str)), len(segs))
    num_part, str_part = segs[:first_str], segs[first_str:]
    while num_part and num_part[-1] == 0:
        num_part.pop()
    while str_part and str_part[-1] == 0:
        str_part.pop()
    return num_part + str_part


def gem_vercmp(a: str, b: str) -> int:
    L, R = _gem_canonical(a), _gem_canonical(b)
    for i in range(max(len(L), len(R))):
        lhs = L[i] if i < len(L) else 0
        rhs = R[i] if i < len(R) else 0
        if lhs == rhs:
            continue
        l_str, r_str = isinstance(lhs, str), isinstance(rhs, str)
        if l_str and not r_str:
            return -1                         # string segment < numeric (prerelease low)
        if r_str and not l_str:
            return 1
        return -1 if lhs < rhs else 1
    return 0


class _InfType:
    def __init__(self, sign): self._s = sign
    def __repr__(self): return "Inf" if self._s > 0 else "-Inf"
    def __eq__(self, o): return isinstance(o, _InfType) and o._s == self._s
    def __hash__(self): return hash(("_Inf", self._s))
    def __lt__(self, o): return self._s < 0 and not (self == o)
    def __le__(self, o): return self._s < 0 or self == o
    def __gt__(self, o): return self._s > 0 and not (self == o)
    def __ge__(self, o): return self._s > 0 or self == o


_POS_INF, _NEG_INF = _InfType(1), _InfType(-1)
_PEP440_RE = re.compile(r"""
    ^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?P<pre>[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d+)?)?
    (?P<post>(?:-(?P<post_n1>\d+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n>\d+)?))?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$
""", re.VERBOSE | re.IGNORECASE)


def _pep440_key(v: str):
    m = _PEP440_RE.match(v or "")
    if not m:
        return None
    epoch = int(m.group("epoch") or 0)
    rel = [int(x) for x in m.group("release").split(".")]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    release = tuple(rel)
    pre = None
    if m.group("pre_l"):
        l = m.group("pre_l").lower()
        l = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}.get(l, l)
        pre = (l, int(m.group("pre_n") or 0))
    post = None
    if m.group("post_n1") is not None:
        post = int(m.group("post_n1"))
    elif m.group("post_l"):
        post = int(m.group("post_n") or 0)
    dev = int(m.group("dev_n") or 0) if m.group("dev") else None
    local = m.group("local")
    _pre = _NEG_INF if (pre is None and post is None and dev is not None) else (
        _POS_INF if pre is None else pre)
    _post = _NEG_INF if post is None else post
    _dev = _POS_INF if dev is None else dev
    _local = _NEG_INF if local is None else tuple(
        (int(p), "") if p.isdigit() else (_NEG_INF, p.lower())      # PEP 440 lowercases local
        for p in re.split(r"[-_.]", local))
    return (epoch, release, _pre, _post, _dev, _local)


def pep440_vercmp(a: str, b: str) -> int:
    ka, kb = _pep440_key(a), _pep440_key(b)
    if ka is None or kb is None:            # non-PEP440 (e.g. a URL/git ref) -> string fallback
        return (a > b) - (a < b)
    return (ka > kb) - (ka < kb)


def cmp_for(origin: str) -> Callable[[str, str], int]:
    if origin == "dpkg":
        return dpkg_vercmp
    if origin == "rpm":
        return rpm_vercmp_str
    if origin == "apk":
        return apk_vercmp
    if origin in ("npm", "go", "golang", "cargo", "crates.io"):
        return semver_vercmp
    if origin == "pypi":
        return pep440_vercmp
    if origin in ("gem", "rubygems"):
        return gem_vercmp
    return dpkg_vercmp


# ── OSV feed + affected-range evaluation ─────────────────────────────────────
class OSVFeed:
    """Index of OSV records by (ecosystem, name) and by purl."""

    def __init__(self):
        self._by_name: Dict[Tuple[str, str], List[dict]] = {}
        self._by_purl: Dict[str, List[dict]] = {}

    @classmethod
    def from_records(cls, records: List[dict]) -> "OSVFeed":
        feed = cls()
        for rec in records or []:
            if rec.get("withdrawn"):
                continue
            for aff in rec.get("affected", []):
                pkg = aff.get("package", {})
                eco = pkg.get("ecosystem", "")
                name = pkg.get("name", "")
                if eco and name:
                    feed._by_name.setdefault((eco, name.lower()), []).append(rec)
                purl = pkg.get("purl")
                if purl:
                    feed._by_purl.setdefault(purl, []).append(rec)
        return feed

    def query(self, ecosystem: str, name: str, purl: Optional[str] = None) -> List[dict]:
        out: List[dict] = []
        seen = set()
        for rec in self._by_name.get((ecosystem, (name or "").lower()), []):
            if id(rec) not in seen:
                seen.add(id(rec))
                out.append(rec)
        if purl:
            for rec in self._by_purl.get(purl, []):
                if id(rec) not in seen:
                    seen.add(id(rec))
                    out.append(rec)
        return out


def version_affected(installed: str, events: List[dict], cmp) -> Tuple[bool, Optional[str]]:
    """Evaluate an OSV ECOSYSTEM range. Returns (affected, applicable_fixed).
    "0" is negative infinity (from-the-beginning). Assumes events are OSV-ordered
    (introduced before its fixed/last_affected)."""
    affected = False
    applicable_fixed = None
    for ev in events:
        if "introduced" in ev:
            v = ev["introduced"]
            if v == "0" or cmp(installed, v) >= 0:
                affected = True
        elif "fixed" in ev:
            v = ev["fixed"]
            if cmp(installed, v) >= 0:
                affected = False
                applicable_fixed = None
            elif affected and applicable_fixed is None:
                applicable_fixed = v
        elif "last_affected" in ev:
            if cmp(installed, ev["last_affected"]) > 0:
                affected = False
    return affected, applicable_fixed


def prefer_cve(rec: dict) -> str:
    ids = [rec.get("id", "")] + list(rec.get("aliases", []))
    for i in ids:
        if str(i).upper().startswith("CVE-"):
            return str(i).upper()
    return str(rec.get("id", "")).upper()


def _cvss3_base_from_vector(vector: str) -> Optional[float]:
    """Compute the CVSS v3.0/3.1 base score from a vector string
    (e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'). Returns None for
    non-v3 vectors (v2/v4) or malformed input — the caller then falls back to
    the database-specific severity band."""
    if not vector or not vector.upper().startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        scope_changed = m["S"] == "C"
        pr_key = m["PR"]
        pr = ({"N": 0.85, "L": 0.68, "H": 0.5} if scope_changed
              else {"N": 0.85, "L": 0.62, "H": 0.27})[pr_key]
        imp = {"H": 0.56, "L": 0.22, "N": 0.0}
        c, i, a = imp[m["C"]], imp[m["I"]], imp[m["A"]]
    except (KeyError, ValueError):
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 * (impact + exploitability) if scope_changed
           else impact + exploitability)
    return _cvss_roundup(min(raw, 10.0))


def _cvss_roundup(x: float) -> float:
    """CVSS v3.1 roundup — round up to one decimal, avoiding binary-float drift."""
    n = int(round(x * 100000))
    if n % 10000 == 0:
        return n / 100000.0
    return (math.floor(n / 10000) + 1) / 10.0


def _cvss_base(rec: dict) -> Optional[float]:
    for s in rec.get("severity", []):
        score = s.get("score")
        try:
            return float(score)
        except (TypeError, ValueError):
            # score is a CVSS vector string — compute the v3 base score from it
            vec = _cvss3_base_from_vector(str(score))
            if vec is not None:
                return vec
            continue
    return None


def _band(cvss: Optional[float]) -> str:
    if cvss is None:
        return "MEDIUM"
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def _severity(rec: dict) -> str:
    ds = (rec.get("database_specific") or {}).get("severity")
    if ds:
        return str(ds).upper()
    for aff in rec.get("affected", []):
        s = (aff.get("database_specific") or {}).get("severity")
        if s:
            return str(s).upper()
    return _band(_cvss_base(rec))


def enrich_match(rec: dict, pkg: Package, fixed: Optional[str],
                 epss: Mapping[str, float], kev: AbstractSet[str],
                 exploits: AbstractSet[str]) -> EnrichedMatch:
    cve = prefer_cve(rec)
    ep = epss.get(cve)
    return EnrichedMatch(
        cve=cve, osv_id=str(rec.get("id", "")), package=pkg.name,
        installed_version=pkg.version, fixed_version=fixed,
        severity=_severity(rec), cvss_base=_cvss_base(rec),
        epss=float(ep) if isinstance(ep, (int, float)) else None,
        kev=cve in kev,
        exploit_available="YES" if cve in exploits else None,
        ecosystem=pkg.ecosystem)


def match_vulns(inv: List[Package], feed: OSVFeed, epss_feed: Mapping[str, float],
                kev_set: AbstractSet[str], exploit_set: AbstractSet[str] = frozenset(),
                instance_id: str = "") -> List[EnrichedMatch]:
    """Match a package inventory against an OSV feed with ecosystem-correct
    version comparison. Dedups (cve, binary-name) to kill source-vs-binary
    double-counting."""
    out: List[EnrichedMatch] = []
    seen: set = set()
    for pkg in inv:
        cmp = cmp_for(pkg.origin)
        recs = feed.query(pkg.ecosystem, pkg.name, pkg.purl)
        if pkg.source and pkg.source != pkg.name:
            recs = recs + feed.query(pkg.ecosystem, pkg.source)
        for rec in recs:
            affected, fixed = _record_affects(rec, pkg, cmp)
            if not affected:
                continue
            cve = prefer_cve(rec)
            key = (cve, pkg.name)
            if key in seen:
                continue
            seen.add(key)
            out.append(enrich_match(rec, pkg, fixed, epss_feed, kev_set, exploit_set))
    return out


def _record_affects(rec: dict, pkg: Package, cmp) -> Tuple[bool, Optional[str]]:
    """Does this OSV record affect this package? Requires an ecosystem+name match
    on one of the record's `affected` entries, then evaluates ECOSYSTEM ranges or
    the explicit `versions` list."""
    for aff in rec.get("affected", []):
        p = aff.get("package", {})
        if p.get("ecosystem") != pkg.ecosystem:
            continue
        aname = (p.get("name") or "").lower()
        if aname not in (pkg.name.lower(), (pkg.source or "").lower()):
            continue
        for rng in aff.get("ranges", []):
            rtype = rng.get("type")
            # SEMVER ranges (npm/Go/crates.io) ALWAYS use the semver comparator,
            # regardless of origin; ECOSYSTEM ranges use the origin's comparator.
            if rtype == "SEMVER":
                rcmp = semver_vercmp
            elif rtype == "ECOSYSTEM":
                rcmp = cmp
            else:
                continue                      # GIT ranges are not version-evaluable here
            ok, fixed = version_affected(pkg.version, rng.get("events", []), rcmp)
            if ok:
                return True, fixed
        vlist = aff.get("versions") or []
        if pkg.version in vlist:
            return True, None
        # EVR-stripping fallback is rpm/dpkg-only: a language prerelease like
        # '1.2.3-beta' must NOT collapse to '1.2.3' and false-match versions:['1.2.3'].
        if pkg.origin in ("rpm", "dpkg") and _to_evr(pkg.version).version in vlist:
            return True, None
    return False, None


# ── language dependency lockfile parsers (app-dependency CVE = CWPP-06) ───────
# Each yields the existing Package dataclass; the OSV pipeline (match_vulns/OSVFeed/
# version_affected) is reused UNCHANGED. source=name suppresses match_vulns' Linux
# binary-vs-source second query; arch="". ecosystem is the byte-exact OSV string.
_OSV_ECO = {"npm": "npm", "pypi": "PyPI", "go": "Go", "gem": "RubyGems",
            "cargo": "crates.io", "maven": "Maven"}


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name or "").lower()


def _lang_purl(origin: str, name: str, version: str) -> str:
    if origin == "npm":
        nm = ("%40" + name[1:]) if name.startswith("@") else name
        return f"pkg:npm/{nm}@{version}"
    if origin == "pypi":
        return f"pkg:pypi/{name}@{version}"
    if origin == "go":
        return f"pkg:golang/{name}@v{version}"
    if origin == "gem":
        return f"pkg:gem/{name}@{version}"
    if origin == "cargo":
        return f"pkg:cargo/{name}@{version}"
    if origin == "maven":
        gid, _, aid = name.partition(":")
        return f"pkg:maven/{gid}/{aid}@{version}"
    return f"pkg:{origin}/{name}@{version}"


def _lang_pkg(origin: str, name: str, version: str) -> Package:
    return Package(name=name, version=version, arch="", source=name,
                   source_version=version, ecosystem=_OSV_ECO[origin],
                   purl=_lang_purl(origin, name, version), origin=origin)


def _asdict_text(data) -> str:
    return data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else (data or "")


def parse_package_lock(data) -> List[Package]:
    """npm package-lock.json / npm-shrinkwrap.json (lockfileVersion 1 vs 2/3)."""
    out: List[Package] = []
    try:
        d = json.loads(_asdict_text(data))
    except Exception:
        return out
    seen = set()

    def add(name, ver):
        if name and ver and isinstance(ver, str) and (name, ver) not in seen:
            seen.add((name, ver))
            out.append(_lang_pkg("npm", name, ver))

    lfv = d.get("lockfileVersion", 1)
    if lfv >= 2 and isinstance(d.get("packages"), dict):
        for path, meta in d["packages"].items():
            if not path or not isinstance(meta, dict) or meta.get("link"):
                continue                      # "" is the root project; link=workspace symlink
            # workspace members are keyed by on-disk path (no node_modules/) — use meta name
            name = (path.rsplit("node_modules/", 1)[-1] if "node_modules/" in path
                    else meta.get("name"))
            add(name, meta.get("version"))
    else:
        def walk(deps):
            if not isinstance(deps, dict):
                return
            for name, node in deps.items():
                if isinstance(node, dict):
                    add(name, node.get("version"))
                    walk(node.get("dependencies"))
        walk(d.get("dependencies"))
    return out


def parse_yarn_lock(data) -> List[Package]:
    """Yarn v1 classic (custom text) + Yarn Berry v2+ (YAML-ish). The resolved
    exact version is the `version "x"` / `version: x` line; descriptors hold ranges."""
    text = _asdict_text(data)
    out: List[Package] = []
    seen = set()
    descriptors: List[str] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[0] not in (" ", "\t"):                 # block header (descriptor keys)
            hdr = raw.rstrip(":").strip()
            if "@" not in hdr:                        # Berry structural key (__metadata:) — skip
                descriptors = []
                continue
            descriptors = [d.strip().strip('"') for d in hdr.split(",")]
            continue
        m = re.match(r'\s*version:?\s+"?([^"\s]+)"?\s*$', raw)
        if not m or not descriptors:
            continue
        ver = m.group(1)
        for desc in descriptors:
            # Berry protocol: name@npm:range / name@workspace:... — keep only npm/plain
            if "@npm:" in desc:
                name = desc.split("@npm:", 1)[0]
            elif re.search(r"@(workspace|file|link|portal|patch|exec):", desc):
                continue
            else:
                name = desc.rsplit("@", 1)[0]
            name = name.strip()
            if name and (name, ver) not in seen:
                seen.add((name, ver))
                out.append(_lang_pkg("npm", name, ver))
        descriptors = []
    return out


def parse_pipfile_lock(data) -> List[Package]:
    """Pipenv Pipfile.lock (JSON; default + develop, versions stored as '==X')."""
    out: List[Package] = []
    try:
        d = json.loads(_asdict_text(data))
    except Exception:
        return out
    seen = set()
    for group in ("default", "develop"):
        for name, meta in (d.get(group) or {}).items():
            ver = meta.get("version") if isinstance(meta, dict) else None
            if not ver or not isinstance(ver, str):
                continue                      # VCS/editable entries have no version
            v = ver[2:] if ver.startswith("==") else ver
            nm = _pep503(name)
            if (nm, v) not in seen:
                seen.add((nm, v))
                out.append(_lang_pkg("pypi", nm, v))
    return out


def parse_poetry_lock(data) -> List[Package]:
    """Poetry poetry.lock (TOML [[package]]). Minimal stdlib-only regex reader
    (3.10-compatible, no tomllib). Skips git/directory/file/url sources."""
    text = _asdict_text(data)
    out: List[Package] = []
    seen = set()
    for blk in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
        nm = re.search(r'(?m)^\s*name\s*=\s*"([^"]+)"', blk)
        ver = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', blk)
        if not nm or not ver:
            continue
        if re.search(r'(?m)^\s*type\s*=\s*"(git|directory|file|url)"', blk):
            continue                          # non-PyPI source
        name, v = _pep503(nm.group(1)), ver.group(1)
        if (name, v) not in seen:
            seen.add((name, v))
            out.append(_lang_pkg("pypi", name, v))
    return out


def _toml_packages(text: str):
    """Yield {key: str-val} for each [[package]] block, stopping at the first
    sub-table line. Enough for poetry.lock/Cargo.lock top-level string fields."""
    for blk in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
        fields: Dict[str, str] = {}
        for line in blk.splitlines():
            if line.startswith("["):
                break
            m = re.match(r'\s*([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"', line)
            if m:
                fields.setdefault(m.group(1), m.group(2))
        if fields:
            yield fields


def parse_cargo_lock(data) -> List[Package]:
    """Rust Cargo.lock (TOML [[package]]). Only real crates.io registry releases."""
    out: List[Package] = []
    seen = set()
    for f in _toml_packages(_asdict_text(data)):
        name, ver, src = f.get("name"), f.get("version"), f.get("source", "")
        if not name or not ver or not src.startswith("registry+"):
            continue                          # workspace crate / git+ / path+ -> skip
        if (name, ver) not in seen:
            seen.add((name, ver))
            out.append(_lang_pkg("cargo", name, ver))
    return out


def parse_go_mod(data) -> List[Package]:
    """Go go.mod require directives (MVS-selected versions; go.sum is NOT used —
    it over-reports). Honors single-line AND factored-block replace/exclude, and
    version-qualified replaces; strips the leading 'v'."""
    text = _asdict_text(data)
    lines = text.splitlines()
    out: List[Package] = []
    seen = set()
    # replaces keyed by (path, lhs_version_or_None); value None = local-path replace
    replaces: Dict[Tuple[str, Optional[str]], Optional[Tuple[str, Optional[str]]]] = {}
    excludes = set()

    def record_replace(entry: str):
        m = re.match(r'^(\S+)(?:\s+(\S+))?\s+=>\s+(\S+)(?:\s+(\S+))?\s*$',
                     entry.split("//", 1)[0].strip())
        if not m:
            return
        old, oldv, new, newv = m.group(1), m.group(2), m.group(3), m.group(4)
        replaces[(old, oldv)] = None if new.startswith((".", "/")) else (new, newv)

    def record_exclude(entry: str):
        p = entry.split("//", 1)[0].split()
        if len(p) >= 2:
            excludes.add((p[0], p[1]))

    # pass 1 — collect replace/exclude (single-line + factored block)
    block = None
    for line in lines:
        s = line.strip()
        if block == "replace":
            if s == ")":
                block = None
            elif s:
                record_replace(s)
            continue
        if block == "exclude":
            if s == ")":
                block = None
            elif s:
                record_exclude(s)
            continue
        if s.startswith("replace ("):
            block = "replace"
        elif s.startswith("exclude ("):
            block = "exclude"
        elif s.startswith("replace "):
            record_replace(s[8:])
        elif s.startswith("exclude "):
            record_exclude(s[8:])

    def add(path, ver):
        if (path, ver) in excludes:
            return
        r_key = (path, ver) if (path, ver) in replaces else (
            (path, None) if (path, None) in replaces else None)
        if r_key is not None:
            r = replaces[r_key]
            if r is None or r[1] is None:
                return                        # replaced by a local path -> not a release
            path, ver = r[0], r[1]
        v = ver[1:] if ver[:1] == "v" else ver
        if path and v and (path, v) not in seen:
            seen.add((path, v))
            out.append(_lang_pkg("go", path, v))

    # pass 2 — requires
    in_block = False
    for line in lines:
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block:
            if s == ")":
                in_block = False
                continue
            if s and not s.startswith("//"):
                parts = s.split()
                if len(parts) >= 2:
                    add(parts[0], parts[1])
        elif s.startswith("require "):
            parts = s[8:].split()
            if len(parts) >= 2:
                add(parts[0], parts[1])
    return out


def parse_gemfile_lock(data) -> List[Package]:
    """Ruby Gemfile.lock — the GEM section's specs: block (4-space-indented resolved
    versions in parens). Strips a platform suffix (nokogiri (1.15.0-x86_64-linux))."""
    text = _asdict_text(data)
    out: List[Package] = []
    seen = set()
    section = None
    in_specs = False
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.strip()
            in_specs = False
            continue
        if section == "GEM" and line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            m = re.match(r'^    ([A-Za-z0-9._-]+) \(([^)]+)\)\s*$', line)
            if m:
                name = m.group(1)
                ver = m.group(2).split("-", 1)[0]      # drop platform suffix
                if (name, ver) not in seen:
                    seen.add((name, ver))
                    out.append(_lang_pkg("gem", name, ver))
    return out


def parse_requirements(data) -> List[Package]:
    """pip requirements.txt — best-effort: only single '==' / '===' exact pins
    (a manifest, not a lockfile; ranges and transitive deps are not captured)."""
    text = _asdict_text(data)
    out: List[Package] = []
    seen = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0]                   # drop env marker
        # drop pip-compile/pip-freeze --hash options and a trailing '\' continuation
        # (a hash-pinned exact pin is still an exact pin — must not be silently dropped)
        line = re.split(r'\s+(?:--hash|\\)', line, 1)[0].strip()
        m = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s,;]+)\s*$', line)
        if not m or "*" in m.group(2):                # wildcard pin is a range
            continue
        nm, ver = _pep503(m.group(1)), m.group(2)
        if (nm, ver) not in seen:
            seen.add((nm, ver))
            out.append(_lang_pkg("pypi", nm, ver))
    return out


# Installed-package metadata (no lockfile needed) — container/Lambda artifacts often
# ship the INSTALLED tree (node_modules, site-packages, gems) with no lockfile.
def parse_node_package_json(data) -> List[Package]:
    """An INSTALLED node_modules/<pkg>/package.json -> [Package] (npm). Only valid
    under node_modules/ (there the version is the exact resolved release)."""
    try:
        d = json.loads(_asdict_text(data))
    except Exception:
        return []
    name, ver = d.get("name"), d.get("version")
    if not name or not isinstance(ver, str) or not ver:
        return []
    return [_lang_pkg("npm", name, ver)]


def parse_python_metadata(data) -> List[Package]:
    """An installed *.dist-info/METADATA or *.egg-info/PKG-INFO (RFC822 headers) ->
    [Package] (PyPI)."""
    name = ver = None
    for line in _asdict_text(data).splitlines():
        if not line.strip():
            break                             # blank line ends the header block
        if line.startswith("Name:") and name is None:
            name = line[5:].strip()
        elif line.startswith("Version:") and ver is None:
            ver = line[8:].strip()
    if not name or not ver:
        return []
    return [_lang_pkg("pypi", _pep503(name), ver)]


def parse_gemspec_name(path: str) -> List[Package]:
    """An installed specifications/<name>-<version>[-platform].gemspec -> [Package]
    (RubyGems), taken from the filename (the gemspec body is executable Ruby)."""
    base = path.rsplit("/", 1)[-1]
    if not base.endswith(".gemspec"):
        return []
    m = re.match(r'^(.+?)-(\d[\w.]*)', base[:-len(".gemspec")])
    if not m:
        return []
    return [_lang_pkg("gem", m.group(1), m.group(2))]


_LOCKFILE_PARSERS = {
    "package-lock.json":   parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock":           parse_yarn_lock,
    "Pipfile.lock":        parse_pipfile_lock,
    "poetry.lock":         parse_poetry_lock,
    "Cargo.lock":          parse_cargo_lock,
    "go.mod":              parse_go_mod,
    "Gemfile.lock":        parse_gemfile_lock,
    "requirements.txt":    parse_requirements,
}


def collect_app_packages(ext: FilesystemExtractor,
                         roots=("/app", "/srv", "/opt", "/var/task", "/home", "/var/www",
                                "/usr/src", "/usr/local/src", "/workspace", "/code", "/root"),
                         max_files: int = 20000, max_file_bytes: int = 5_000_000,
                         notes: Optional[List[str]] = None) -> List[Package]:
    """Walk the extracted filesystem for language dependency lockfiles AND installed-
    package metadata (node_modules/*/package.json, *.dist-info/METADATA, *.egg-info/
    PKG-INFO, gems specifications/*.gemspec) and return a de-duplicated Package
    inventory (fed to the unchanged OSV matcher = CWPP-06). Installed metadata gives
    recall on container/Lambda artifacts that ship no lockfile. Fail-open."""
    out: List[Package] = []
    seen = set()

    def _emit(pkgs):
        for p in pkgs:
            key = (p.origin, p.name, p.version)
            if key not in seen:
                seen.add(key)
                out.append(p)

    for root in roots:
        try:
            for path in ext.walk(root, max_files):
                base = path.rsplit("/", 1)[-1]
                parser = _LOCKFILE_PARSERS.get(base)
                if parser is not None:
                    fn = parser
                elif base == "package.json" and "node_modules/" in path:
                    fn = parse_node_package_json
                elif (base == "METADATA" and ".dist-info/" in path) or \
                     (base == "PKG-INFO" and ".egg-info/" in path):
                    fn = parse_python_metadata
                elif base.endswith(".gemspec") and "specifications/" in path:
                    _emit(parse_gemspec_name(path))          # from filename, no read
                    continue
                else:
                    continue
                data = ext.read_file(path)
                if not data or len(data) > max_file_bytes:
                    continue
                try:
                    _emit(fn(data))
                except Exception as e:
                    if notes is not None:
                        notes.append(f"manifest parse failed for {path}: {e}")
        except Exception:
            continue
    return out


# ── SBOM export (CycloneDX 1.5 + SPDX 2.3) ───────────────────────────────────
# Pure + deterministic: timestamps/serial/namespace are passed in (never generated
# here), so identical inventory -> byte-identical SBOM (testable, reproducible).
def _sbom_components(packages: List[Package]) -> List[Package]:
    seen, out = set(), []
    for p in packages:
        key = p.purl or (p.origin, p.name, p.version)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def sbom_cyclonedx(packages: List[Package], *, created: Optional[str] = None,
                   component_name: str = "scanned-workload",
                   serial: Optional[str] = None) -> dict:
    """CycloneDX 1.5 SBOM document (dict; caller json.dumps). Each Package -> a
    library component with name/version/purl and a purl bom-ref."""
    comps = _sbom_components(packages)
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "container", "name": component_name}},
        "components": [
            {"type": "library",
             "bom-ref": p.purl or f"{p.origin}:{p.name}@{p.version}",
             "name": p.name, "version": p.version,
             **({"purl": p.purl} if p.purl else {})}
            for p in comps
        ],
    }
    if serial:
        doc["serialNumber"] = serial
    if created:
        doc["metadata"]["timestamp"] = created
    return doc


def sbom_spdx(packages: List[Package], *, created: Optional[str] = None,
              name: str = "scanned-workload",
              namespace: str = "https://overwatch.local/sbom/scanned-workload") -> dict:
    """SPDX 2.3 SBOM document (dict; caller json.dumps). Each Package -> an SPDX
    package with versionInfo + a PACKAGE-MANAGER purl externalRef."""
    comps = _sbom_components(packages)
    pkgs = []
    for i, p in enumerate(comps):
        entry = {
            "SPDXID": f"SPDXRef-Package-{i}",
            "name": p.name,
            "versionInfo": p.version,
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if p.purl:
            entry["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": p.purl}]
        pkgs.append(entry)
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": namespace,
        "creationInfo": {"creators": ["Tool: OverWatch-sidescan"]},
        "packages": pkgs,
    }
    if created:
        doc["creationInfo"]["created"] = created
    return doc


# ── secrets ───────────────────────────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


_SECRET_PATHS = [
    ("ssh-private-key", re.compile(r"/\.ssh/id_[^/]*$")),
    ("ssh-private-key", re.compile(r"/etc/ssh/ssh_host_.*_key$")),
    ("aws-credentials", re.compile(r"/\.aws/credentials$")),
    ("kubeconfig", re.compile(r"/\.kube/config$")),
    ("kubeconfig", re.compile(r"/etc/kubernetes/admin\.conf$")),
    ("dotenv", re.compile(r"/\.env$")),
    ("netrc", re.compile(r"/\.netrc$")),
    ("pgpass", re.compile(r"/\.pgpass$")),
    ("docker-config", re.compile(r"/\.docker/config\.json$")),
]

_SECRET_CONTENT = [
    # NOT entropy-gated: AKIA/ASIA + 16 base32 is a deterministic, near-zero-FP
    # prefix format whose max Shannon entropy (log2(20)=4.32) sits at the 4.0 gate,
    # so gating would drop the majority of real key IDs. _SECRET_DENY covers examples.
    ("aws-access-key", re.compile(rb"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), False),
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), False),
    ("github-pat", re.compile(rb"\bghp_[0-9A-Za-z]{36}\b"), False),
    ("slack-token", re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{10,}"), False),
    ("jwt", re.compile(rb"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}"), True),
    ("gcp-service-account", re.compile(rb'"type"\s*:\s*"service_account"'), False),
]

_SECRET_DENY = {"AKIAIOSFODNN7EXAMPLE", "changeme", "EXAMPLE"}


def _preview(m: bytes) -> str:
    s = m.decode("utf-8", "replace")
    if len(s) <= 10:
        return s[:2] + "…"
    return s[:4] + "…" + s[-4:]


def scan_secrets(ext: FilesystemExtractor, roots=("/home", "/root", "/etc", "/var/www", "/opt", "/srv"),
                 max_files: int = 20000, max_file_bytes: int = 1_000_000,
                 entropy_min: float = 4.0) -> List[SecretFinding]:
    """Scan the extracted filesystem for on-disk secrets: known sensitive paths +
    content regexes (entropy-gated for the noisy ones). Only a first4…last4
    preview is retained — never the secret itself."""
    out: List[SecretFinding] = []
    scanned = 0
    seen_paths: set = set()
    # (a) known sensitive paths
    for root in roots:
        for path in ext.walk(root, max_files):
            if scanned >= max_files:
                break
            for kind, rx in _SECRET_PATHS:
                if rx.search(path) and not path.endswith(".pub"):
                    out.append(SecretFinding(kind=kind, path=path, line=0,
                                             match_preview="(file present)", entropy=0.0,
                                             severity="HIGH"))
                    seen_paths.add(path)
            # (b) content scan
            data = ext.read_file(path)
            scanned += 1
            if not data or len(data) > max_file_bytes:
                continue
            for kind, rx, entropy_gated in _SECRET_CONTENT:
                for m in rx.finditer(data):
                    tok = m.group(0)
                    tok_s = tok.decode("utf-8", "replace")
                    if any(d in tok_s for d in _SECRET_DENY):
                        continue
                    if entropy_gated and shannon_entropy(tok_s) < entropy_min:
                        continue
                    line = data[:m.start()].count(b"\n") + 1
                    out.append(SecretFinding(kind=kind, path=path, line=line,
                                             match_preview=_preview(tok),
                                             entropy=round(shannon_entropy(tok_s), 2),
                                             severity="HIGH"))
    return out


def scan_text_secrets(data, source: str = "", entropy_min: float = 4.0) -> List[SecretFinding]:
    """Scan an in-memory blob (e.g. EC2 user-data, a config string) for embedded
    secrets using the same content regexes as scan_secrets. Only a first4…last4
    preview is retained — never the secret itself."""
    out: List[SecretFinding] = []
    if not data:
        return out
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    for kind, rx, entropy_gated in _SECRET_CONTENT:
        for m in rx.finditer(data):
            tok = m.group(0)
            tok_s = tok.decode("utf-8", "replace")
            if any(d in tok_s for d in _SECRET_DENY):
                continue
            if entropy_gated and shannon_entropy(tok_s) < entropy_min:
                continue
            line = data[:m.start()].count(b"\n") + 1
            out.append(SecretFinding(kind=kind, path=source, line=line,
                                     match_preview=_preview(tok),
                                     entropy=round(shannon_entropy(tok_s), 2),
                                     severity="HIGH"))
    return out


# ── graph emit (HAS_VULN edges, 1:1 with Inspector) ──────────────────────────
def to_has_vuln_edges(instance_arn: str, matches: List[EnrichedMatch],
                      snapshot_id: str = "") -> List[VulnEdge]:
    """Convert enriched matches to graph-ready HAS_VULN edges whose props match
    aws_live_scanner._check_vuln exactly (so aws_correlate is unchanged), plus a
    few harmless side-scan extras (fixed_version/package/installed_version/source)."""
    out: List[VulnEdge] = []
    for m in matches:
        props = {
            "cve": m.cve, "severity": m.severity, "epss": m.epss, "kev": m.kev,
            "exploit_available": m.exploit_available,
            "fix_available": "YES" if m.fixed_version else "NO",
            "finding_arn": f"sidescan:{snapshot_id}:{m.cve}",
            "fixed_version": m.fixed_version, "package": m.package,
            # NB: prop key must NOT be "source"/"target"/"id"/"kind" — those
            # collide with the node-link edge-endpoint keys in graph.to_dict().
            "installed_version": m.installed_version, "scan_source": "side-scan",
        }
        out.append(VulnEdge(node_arn=instance_arn, cve=m.cve, props=props))
    return out


def emit_vuln_edges(graph, instance_arn: str, instance_id: str,
                    matches: List[EnrichedMatch], snapshot_id: str = "") -> int:
    """Mutate the SecurityGraph directly (MERGE-idempotent, converges with
    Inspector). Returns the number of HAS_VULN edges added. The instance node
    kind MUST be EC2Instance or aws_correlate._path_exploitability skips it."""
    graph.add_node(instance_arn, "EC2Instance", instance_id=instance_id)
    n = 0
    for e in to_has_vuln_edges(instance_arn, matches, snapshot_id):
        graph.add_node(e.cve, "Vulnerability", severity=e.props["severity"],
                       epss=e.props["epss"], kev=e.props["kev"],
                       exploit_available=e.props["exploit_available"],
                       fix_available=e.props["fix_available"])
        graph.add_edge(instance_arn, e.cve, "HAS_VULN", **e.props)
        n += 1
    return n


# ── orchestrator ──────────────────────────────────────────────────────────────
def sidescan_filesystem(ext: FilesystemExtractor, feed: Optional[OSVFeed],
                        epss: Mapping[str, float], kev: AbstractSet[str],
                        exploits: AbstractSet[str] = frozenset(), *,
                        instance_id: str = "", do_secrets: bool = True) -> SideScanResult:
    """End-to-end pure side-scan of an extracted filesystem. Fail-open at every
    step: each degradation is a `notes` entry, never a crash or phantom finding."""
    notes: List[str] = []
    osr = None
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        data = ext.read_file(p)
        if data:
            osr = parse_os_release(data)
            break

    # OS package inventory (best-effort; may be empty for a scratch/app-only image)
    packages: List[Package] = []
    if osr is None:
        notes.append("no /etc/os-release readable — OS package inventory skipped")
    elif not osr.pkgmgr:
        notes.append(f"unknown distro '{osr.id}' — OS package inventory skipped")
    elif not osr.ecosystem:
        notes.append(f"no OSV ecosystem for '{osr.id}:{osr.version_id}' — OS packages unmatched")
        try:
            packages = collect_inventory(ext, osr)
        except Unsupported as e:
            notes.append(f"package DB not decodable ({e}) — OS inventory skipped for this host")
    else:
        try:
            packages = collect_inventory(ext, osr)
        except Unsupported as e:
            notes.append(f"package DB not decodable ({e}) — OS inventory skipped for this host")

    # language app-dependency inventory (independent of OS detection = CWPP-06)
    packages = packages + collect_app_packages(ext, notes=notes)

    vulns: List[EnrichedMatch] = []
    if feed is None:
        notes.append("no vulnerability feed (--vuln-db) — CVE match skipped; inventory only")
    elif packages:
        vulns = match_vulns(packages, feed, epss, kev, exploits, instance_id=instance_id)
    secrets = scan_secrets(ext) if do_secrets else []
    return SideScanResult(os=osr, packages=packages, vulns=vulns, secrets=secrets, notes=notes)
