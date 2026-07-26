"""Extractor engine B1 — aws_sidescan_fs partition-table reader + root-fs selection, and
the DissectExtractor never-false-clean contract. The partition plane is pure and fully
validatable here (synthetic GPT/MBR images with real superblock magics); the userspace
ext4/xfs PARSE is deferred to a Linux-CI golden-image gate, so DissectExtractor must raise
SideScanUnavailable (→ CWPP-04 INFO), never return a guessed extractor. Offline, no boto."""
import io
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_sidescan_fs as fsx
from aws_sidescan_ebs import SideScanUnavailable

SECTOR = fsx.SECTOR
G_LINUX = bytes.fromhex("af3dc60f838472478e793d69d8477de4")   # Linux filesystem


# ── synthetic image builders ──────────────────────────────────────────────────
def _ext_magic(buf: bytearray, base: int):
    buf[base + 0x438:base + 0x43A] = b"\x53\xef"

def _xfs_magic(buf: bytearray, base: int):
    buf[base:base + 4] = b"XFSB"

def _luks_magic(buf: bytearray, base: int):
    buf[base:base + 6] = b"LUKS\xba\xbe"


def _gpt(parts):
    """parts: list of (type_guid_bytes, start_lba, num_lba, magic_writer|None)."""
    entries_lba, esize = 2, 128
    end = max((s + n) for _g, s, n, _w in parts) if parts else 4
    buf = bytearray((end + 8) * SECTOR)
    struct.pack_into("<8s", buf, SECTOR, b"EFI PART")
    struct.pack_into("<Q", buf, SECTOR + 72, entries_lba)
    struct.pack_into("<I", buf, SECTOR + 80, len(parts))
    struct.pack_into("<I", buf, SECTOR + 84, esize)
    for i, (guid, start, num, _w) in enumerate(parts):
        off = entries_lba * SECTOR + i * esize
        buf[off:off + 16] = guid
        struct.pack_into("<Q", buf, off + 32, start)
        struct.pack_into("<Q", buf, off + 40, start + num - 1)
    for _g, start, _n, writer in parts:
        if writer:
            writer(buf, start * SECTOR)
    return io.BytesIO(bytes(buf))


def _mbr(parts):
    """parts: list of (type_byte, start_lba, num_lba, magic_writer|None)."""
    end = max((s + n) for _t, s, n, _w in parts) if parts else 4
    buf = bytearray((end + 8) * SECTOR)
    buf[510:512] = b"\x55\xaa"
    for i, (ptype, start, num, _w) in enumerate(parts):
        off = 0x1BE + i * 16
        buf[off + 4] = ptype
        struct.pack_into("<I", buf, off + 8, start)
        struct.pack_into("<I", buf, off + 12, num)
    for _t, start, _n, writer in parts:
        if writer:
            writer(buf, start * SECTOR)
    return io.BytesIO(bytes(buf))


# ── partition-table reader ────────────────────────────────────────────────────
def test_gpt_single_ext_root():
    img = _gpt([(G_LINUX, 34, 200, _ext_magic)])
    parts = fsx.read_partitions(img)
    assert len(parts) == 1 and parts[0].scheme == "gpt" and parts[0].start == 34 * SECTOR
    r = fsx.probe_root(img)
    assert r.offset == 34 * SECTOR and r.fstype == "ext" and r.note is None


def test_gpt_picks_largest_ext_and_skips_efi():
    img = _gpt([
        (fsx._GUID_EFI, 2050, 200, None),          # ESP — skipped by GUID
        (G_LINUX, 2250, 100, _ext_magic),          # small root
        (G_LINUX, 2400, 500, _ext_magic),          # LARGER root — must win
    ])
    r = fsx.probe_root(img)
    assert r.offset == 2400 * SECTOR and r.fstype == "ext"


def test_gpt_xfs_root():
    r = fsx.probe_root(_gpt([(G_LINUX, 34, 300, _xfs_magic)]))
    assert r.fstype == "xfs" and r.offset == 34 * SECTOR


def test_gpt_luks_is_honest_note_not_clean():
    r = fsx.probe_root(_gpt([(G_LINUX, 34, 200, _luks_magic)]))
    assert r.offset is None and r.fstype == "luks" and "LUKS" in r.note


def test_gpt_lvm_is_honest_note():
    r = fsx.probe_root(_gpt([(fsx._GUID_LVM, 34, 500, None)]))
    assert r.offset is None and r.fstype == "lvm" and "LVM" in r.note


def test_mbr_linux_ext_root():
    img = _mbr([(0x83, 2048, 400, _ext_magic)])          # 0x83 = Linux
    parts = fsx.read_partitions(img)
    assert len(parts) == 1 and parts[0].scheme == "mbr"
    r = fsx.probe_root(img)
    assert r.offset == 2048 * SECTOR and r.fstype == "ext"


def test_bare_ext_no_partition_table():
    buf = bytearray(0x1000)
    _ext_magic(buf, 0)
    r = fsx.probe_root(io.BytesIO(bytes(buf)))
    assert r.offset == 0 and r.fstype == "ext" and r.scheme == "none"


def test_garbage_volume_is_unknown_not_clean():
    r = fsx.probe_root(io.BytesIO(b"\x00" * 0x2000))
    assert r.offset is None and r.fstype == "unknown" and r.note


def test_holey_read_does_not_crash():
    # a truncated image (short read past EOF) must degrade, never raise
    r = fsx.probe_root(io.BytesIO(b"EFI"))       # too short to be a real GPT
    assert r.offset is None


# ── DissectExtractor: never a false-clean ─────────────────────────────────────
def test_dissect_extractor_on_ext_defers_not_clean():
    # a readable ext root is LOCATED, but the userspace parse is deferred -> raise (INFO),
    # NEVER yield an (empty) extractor that would false-clean a vulnerable host.
    ext = fsx.DissectExtractor(_gpt([(G_LINUX, 34, 200, _ext_magic)]))
    with pytest.raises(SideScanUnavailable):
        ext.__enter__()
    assert ext.probe is not None and ext.probe.fstype == "ext" and ext.probe.offset == 34 * SECTOR


def test_dissect_extractor_luks_reports_encrypted():
    ext = fsx.DissectExtractor(_gpt([(G_LINUX, 34, 200, _luks_magic)]))
    with pytest.raises(SideScanUnavailable, match="LUKS"):
        ext.__enter__()


def test_dissect_extractor_unknown_reports_reason():
    ext = fsx.DissectExtractor(io.BytesIO(b"\x00" * 0x2000))
    with pytest.raises(SideScanUnavailable):
        ext.__enter__()


def test_dissect_extractor_accepts_sparseimage_as_file():
    # the real seam feeds a SparseImage (has .as_file()); the extractor must adapt it.
    from aws_sidescan_ebs import SparseImage
    buf = bytearray(0x1000)
    _ext_magic(buf, 0)
    img = SparseImage(1)
    img.put(0, bytes(buf))                       # block 0 holds the (bare) ext superblock
    ext = fsx.DissectExtractor(img)
    with pytest.raises(SideScanUnavailable):
        ext.__enter__()
    assert ext.probe.fstype == "ext"             # located via SparseImageIO
