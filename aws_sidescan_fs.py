#!/usr/bin/env python3
"""aws_sidescan_fs.py — userspace filesystem extractor for the agentless EBS side-scan
(CNAPP P1, the "last mile" of the side-scan program).

Two layers:

1. **Partition plane (SHIPPED, pure, tested).** A dependency-free GPT/MBR partition-table
   reader + root-filesystem selector over the reassembled ``SparseImageIO`` bytes
   (:mod:`aws_sidescan_ebs`). It locates the Linux root partition and sniffs its filesystem
   via :func:`aws_sidescan.detect_fs`, so an encrypted (LUKS), LVM, or unsupported volume
   yields an HONEST note — never a false-clean empty inventory.

2. **DissectExtractor (the FilesystemExtractor adapter, DEFERRED per repo convention).**
   The pre-committed seam ``aws_sidescan_ebs._LiveMountedSnapshots`` imports
   ``aws_sidescan_fs.DissectExtractor``. The real userspace ext4/xfs/LVM parse is intended
   to ride Fox-IT's pure-Python ``dissect.target`` (product decision, air-gap-wheelhouse
   pinned). It is DEFERRED exactly like :func:`aws_sidescan.parse_rpmdb_bdb` /
   :func:`aws_sidescan.parse_windows_software_hive`: there is no offline-validatable real-data
   path on the dev host (no ``mkfs`` on Windows; ``dissect`` not installed), and a
   synthetic-only fixture risks confirming a mis-read. Until a golden ext4/xfs image is
   committed and the parse validated against it on a Linux CI runner, ``DissectExtractor``
   raises :class:`SideScanUnavailable` (→ the scanner degrades to a clean CWPP-04 INFO) —
   it NEVER returns a guessed inventory (which could false-clean a vulnerable host).

   Follow-on validation gate (Linux CI): pin+hash ``dissect.target`` into the offline
   wheelhouse; generate tiny golden ext4 + xfs images (``mkfs`` on a Linux runner); wire the
   dissect volume/fs adapter to the FilesystemExtractor Protocol; assert a golden image scans
   byte-identically to a :class:`aws_sidescan.DictExtractor` double; then flip VERSION.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional

from aws_sidescan import detect_fs
from aws_sidescan_ebs import SideScanUnavailable

SECTOR = 512
_ZERO_GUID = b"\x00" * 16

# on-disk (mixed-endian) type GUIDs we recognize for root selection / honest notes
_GUID_EFI = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")   # EFI System
_GUID_SWAP = bytes.fromhex("6dfd5706aba4c44384e50933c84b4f4f")  # Linux swap
_GUID_BIOS = bytes.fromhex("48616821496f6e6f744e656564454649") # BIOS boot
_GUID_LVM = bytes.fromhex("79d3d6e607f5c244a23c238f2a3df928")   # Linux LVM
_MBR_SWAP = "82"   # Linux swap
_MBR_LVM = "8e"    # Linux LVM
_MBR_EFI = "ef"    # EFI (FAT)


@dataclass(frozen=True)
class Partition:
    index: int
    start: int          # byte offset of the partition on the volume
    size: int           # size in bytes (0 if unknown)
    scheme: str         # 'gpt' | 'mbr'
    type_id: str        # GPT type-GUID hex (32 chars) | MBR type byte hex (2 chars)


@dataclass(frozen=True)
class RootProbe:
    offset: Optional[int]   # byte offset of the root filesystem (None if none readable)
    fstype: str             # 'ext' | 'xfs' | 'luks' | 'lvm' | 'unknown'
    scheme: str             # 'gpt' | 'mbr' | 'none'
    note: Optional[str]     # honest reason when offset is None (encrypted / lvm / not found)


def _read(io, offset: int, length: int) -> bytes:
    """Read ``length`` bytes at absolute ``offset`` from a seekable byte source."""
    io.seek(offset)
    data = io.read(length)
    return data if data is not None else b""


# ── partition-table reader (pure, dependency-free) ────────────────────────────
def read_partitions(io) -> List[Partition]:
    """Enumerate partitions from a GPT (preferred) or MBR table over ``io`` (a seekable
    read-only byte source — e.g. ``SparseImageIO``). Returns [] for a bare/partitionless
    volume. Tolerant: a short/holey read yields fewer partitions, never a crash."""
    try:
        if _read(io, SECTOR, 8) == b"EFI PART":
            return _read_gpt(io)
        mbr = _read(io, 0, SECTOR)
        if len(mbr) >= SECTOR and mbr[510:512] == b"\x55\xaa":
            return _read_mbr(mbr)
    except Exception:
        return []
    return []


def _read_gpt(io) -> List[Partition]:
    hdr = _read(io, SECTOR, 96)
    if len(hdr) < 96:
        return []
    part_lba = struct.unpack_from("<Q", hdr, 72)[0]
    num = min(struct.unpack_from("<I", hdr, 80)[0], 128)     # cap at the spec's typical 128
    esize = struct.unpack_from("<I", hdr, 84)[0] or 128
    if not (16 <= esize <= 4096) or part_lba == 0:
        return []
    out: List[Partition] = []
    for i in range(num):
        e = _read(io, part_lba * SECTOR + i * esize, esize)
        if len(e) < 128:
            break
        type_guid = e[0:16]
        if type_guid == _ZERO_GUID:
            continue
        first = struct.unpack_from("<Q", e, 32)[0]
        last = struct.unpack_from("<Q", e, 40)[0]
        if last < first:
            continue
        out.append(Partition(index=i, start=first * SECTOR, size=(last - first + 1) * SECTOR,
                             scheme="gpt", type_id=type_guid.hex()))
    return out


def _read_mbr(mbr: bytes) -> List[Partition]:
    out: List[Partition] = []
    for i in range(4):
        e = mbr[0x1BE + i * 16: 0x1BE + i * 16 + 16]
        if len(e) < 16:
            break
        ptype = e[4]
        if ptype == 0:
            continue
        start_lba = struct.unpack_from("<I", e, 8)[0]
        nsectors = struct.unpack_from("<I", e, 12)[0]
        if start_lba == 0:                       # 0 == the protective/boot sector, not a real part
            continue
        out.append(Partition(index=i, start=start_lba * SECTOR, size=nsectors * SECTOR,
                             scheme="mbr", type_id=f"{ptype:02x}"))
    return out


def _is_lvm(p: Partition) -> bool:
    return (p.scheme == "gpt" and bytes.fromhex(p.type_id) == _GUID_LVM) or \
           (p.scheme == "mbr" and p.type_id == _MBR_LVM)


def _is_skippable(p: Partition) -> bool:
    """EFI/swap/BIOS-boot partitions never hold a Linux root fs — skip so a tiny ESP
    is never mistaken for the root."""
    if p.scheme == "gpt":
        g = bytes.fromhex(p.type_id)
        return g in (_GUID_EFI, _GUID_SWAP, _GUID_BIOS)
    return p.type_id in (_MBR_SWAP, _MBR_EFI)


# ── root-filesystem selection ─────────────────────────────────────────────────
def probe_root(io) -> RootProbe:
    """Locate the root filesystem on a reassembled volume and sniff its type. Picks the
    LARGEST partition carrying an ext/xfs superblock; falls back to a bare (partitionless)
    ext/xfs volume. Returns an honest RootProbe with ``offset=None`` + a note for encrypted
    (LUKS), LVM, or unsupported volumes — the caller MUST surface that as INFO, never scan an
    empty rootfs as clean."""
    parts = read_partitions(io)
    if not parts:
        fs = detect_fs(lambda o, length: _read(io, o, length))
        if fs in ("ext", "xfs"):
            return RootProbe(offset=0, fstype=fs, scheme="none", note=None)
        if fs == "luks":
            return RootProbe(None, "luks", "none", "encrypted (LUKS) volume — cannot read without the key")
        return RootProbe(None, "unknown", "none",
                         "no partition table and no ext/xfs superblock at offset 0")

    candidates: List[tuple] = []
    saw_luks = saw_lvm = False
    for p in parts:
        if _is_skippable(p):
            continue
        if _is_lvm(p):
            saw_lvm = True
            continue
        fs = detect_fs(lambda o, length, _s=p.start: _read(io, _s + o, length))
        if fs in ("ext", "xfs"):
            candidates.append((p, fs))
        elif fs == "luks":
            saw_luks = True

    if candidates:
        p, fs = max(candidates, key=lambda t: t[0].size)
        return RootProbe(offset=p.start, fstype=fs, scheme=p.scheme, note=None)
    if saw_luks:
        return RootProbe(None, "luks", parts[0].scheme,
                         "encrypted (LUKS) volume — cannot read without the key")
    if saw_lvm:
        return RootProbe(None, "lvm", parts[0].scheme,
                         "LVM logical volume — userspace LVM resolution pending (dissect.volume)")
    return RootProbe(None, "unknown", parts[0].scheme,
                     "no directly-readable ext/xfs root partition found")


# ── the FilesystemExtractor adapter (DEFERRED per repo convention) ────────────
class DissectExtractor:
    """Context manager over a reassembled ``SparseImage`` that yields a
    :class:`aws_sidescan.FilesystemExtractor` (read_file/exists/walk/stat) for the workload
    root filesystem — the pre-committed seam ``aws_sidescan_ebs`` binds as its extractor
    factory. The real userspace ext4/xfs/LVM parse (via ``dissect.target``) is DEFERRED
    until it can be validated against a golden image on a Linux CI runner (see the module
    docstring). Until then ``__enter__`` NEVER returns a guessed inventory: it raises
    :class:`SideScanUnavailable` with an honest reason, so the scanner degrades to a clean
    CWPP-04 INFO rather than a false clean bill of health."""

    def __init__(self, image, *, notes: Optional[List[str]] = None):
        self._image = image                          # a SparseImage (or a seekable IO)
        self.notes: List[str] = notes if notes is not None else []
        self.probe: Optional[RootProbe] = None

    def _open_io(self):
        img = self._image
        return img.as_file() if hasattr(img, "as_file") else img

    def __enter__(self):
        probe = probe_root(self._open_io())
        self.probe = probe
        # Honest, never-false-clean outcomes for the volumes we cannot (yet) read.
        if probe.fstype == "luks":
            raise SideScanUnavailable("encrypted (LUKS) volume — cannot read without the key")
        if probe.fstype == "lvm":
            raise SideScanUnavailable(
                "LVM root — userspace LVM resolution via dissect.volume is deferred")
        if probe.offset is None:
            raise SideScanUnavailable(probe.note or "no readable root filesystem found")
        # A readable ext/xfs root WAS located — the byte source and partition are resolved.
        # The userspace parse itself is deferred (no offline-validatable path on this host);
        # raising here keeps the read-only invariant AND the never-false-clean invariant. The
        # Linux-CI follow-on wires dissect.target and flips this to a real extractor.
        try:
            import dissect.target  # noqa: F401
        except Exception:
            raise SideScanUnavailable(
                f"{probe.fstype} root located at offset {probe.offset}, but dissect.target is "
                "not installed — userspace filesystem parse unavailable")
        raise SideScanUnavailable(
            f"{probe.fstype} root located at offset {probe.offset}; userspace parse via "
            "dissect.target is pending golden-image validation (Linux CI)")

    def __exit__(self, *exc):
        return False
