"""Unit tests for aws_sidescan_ebs — the PURE EBS block-plane (planning, checksum,
sparse reassembly, delta zeroing, provenance-guarded cleanup) against a fake
injected EBS/EC2 client. The live I/O runner + real fs extraction is deferred."""
import base64
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_sidescan_ebs as eb


def _chk(data):
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


class FakeEBS:
    """Canned EBS Direct API. blocks: {index: bytes}. Supports paging."""
    def __init__(self, blocks, vol_gib=1, changed=None, page=1000):
        self._blocks = blocks
        self._vol = vol_gib
        self._changed = changed or {}
        self._page = page

    def list_snapshot_blocks(self, SnapshotId, NextToken=None, **kw):
        items = sorted(self._blocks)
        start = int(NextToken) if NextToken else 0
        chunk = items[start:start + self._page]
        resp = {"Blocks": [{"BlockIndex": i, "BlockToken": f"tok-{SnapshotId}-{i}"} for i in chunk],
                "VolumeSize": self._vol, "BlockSize": eb.BLOCK_SIZE}
        if start + self._page < len(items):
            resp["NextToken"] = str(start + self._page)
        return resp

    def list_changed_blocks(self, FirstSnapshotId, SecondSnapshotId, NextToken=None, **kw):
        blocks = []
        for i, second in sorted(self._changed.items()):
            b = {"BlockIndex": i, "FirstBlockToken": f"f-{i}"}
            if second is not None:
                b["SecondBlockToken"] = f"s-{i}"
            blocks.append(b)
        return {"ChangedBlocks": blocks, "VolumeSize": self._vol, "BlockSize": eb.BLOCK_SIZE}

    def get_snapshot_block(self, SnapshotId, BlockIndex, BlockToken):
        data = self._blocks[BlockIndex]
        return {"BlockData": _Body(data), "DataLength": len(data),
                "Checksum": _chk(data), "ChecksumAlgorithm": "SHA256"}


class _Body:
    def __init__(self, data):
        self._d = data

    def read(self):
        return self._d


# ── planning ─────────────────────────────────────────────────────────────────
def test_build_full_plan():
    ebs = FakeEBS({0: b"a" * 10, 5: b"b" * 10, 9: b"c" * 10})
    plan = eb.build_full_plan(ebs, "snap-1")
    assert [r.index for r in plan.blocks] == [0, 5, 9]
    assert plan.total_blocks_listed == 3 and plan.capped is False
    assert plan.volume_size_gib == 1


def test_build_full_plan_paginates():
    ebs = FakeEBS({i: b"x" for i in range(2500)}, page=1000)
    plan = eb.build_full_plan(ebs, "snap-1")
    assert len(plan.blocks) == 2500


def test_build_full_plan_capped():
    ebs = FakeEBS({i: b"x" for i in range(100)})
    plan = eb.build_full_plan(ebs, "snap-1", max_blocks=10)
    assert len(plan.blocks) == 10 and plan.capped is True
    assert plan.total_blocks_listed == 100


def test_build_delta_plan_zeroes_removed_blocks():
    # index 5 changed (has second token), index 7 removed (second token None)
    ebs = FakeEBS({5: b"new"}, changed={5: "present", 7: None})
    plan = eb.build_delta_plan(ebs, "snap-2", "snap-1")
    assert [r.index for r in plan.blocks] == [5]
    assert plan.zeroed_indexes == (7,)
    assert plan.base_snapshot_id == "snap-1"


# ── checksum ─────────────────────────────────────────────────────────────────
def test_verify_block_checksum():
    data = b"hello world"
    assert eb.verify_block_checksum(data, _chk(data)) is True
    assert eb.verify_block_checksum(data, _chk(b"other")) is False
    assert eb.verify_block_checksum(data, _chk(data), "MD5") is False


def test_fetch_block_verifies():
    ebs = FakeEBS({3: b"payload"})
    data = eb.fetch_block(ebs, "snap-1", eb.BlockRef(3, "tok-3"))
    assert data == b"payload"


def test_fetch_block_raises_on_bad_checksum():
    class BadEBS(FakeEBS):
        def get_snapshot_block(self, **kw):
            return {"BlockData": _Body(b"corrupt"), "Checksum": _chk(b"clean"),
                    "ChecksumAlgorithm": "SHA256"}
    with pytest.raises(eb.ChecksumMismatch):
        eb.fetch_block(BadEBS({0: b"x"}), "snap-1", eb.BlockRef(0, "t"))


# ── sparse image ─────────────────────────────────────────────────────────────
def test_sparse_image_read_with_holes():
    img = eb.SparseImage(1, block_size=4)
    img.put(0, b"AAAA")
    img.put(2, b"CCCC")
    # block 1 is a hole -> zeros
    assert img.read(0, 12) == b"AAAA" + b"\x00\x00\x00\x00" + b"CCCC"
    assert img.written_bytes() == 8


def test_sparse_image_cross_block_read():
    img = eb.SparseImage(1, block_size=4)
    img.put(0, b"AABB")
    img.put(1, b"CCDD")
    assert img.read(2, 4) == b"BBCC"


def test_sparse_image_zero_for_delta():
    img = eb.SparseImage(1, block_size=4)
    img.put(3, b"DATA")
    img.zero(3)          # removed in target snapshot
    assert img.read(12, 4) == b"\x00\x00\x00\x00"


def test_apply_plan_reassembles():
    blocks = {0: b"A" * eb.BLOCK_SIZE, 1: b"B" * eb.BLOCK_SIZE}
    ebs = FakeEBS(blocks, vol_gib=1)
    plan = eb.build_full_plan(ebs, "snap-1")
    img = eb.SparseImage(1)
    eb.apply_plan(ebs, plan, img)
    assert img.written_indexes() == {0, 1}
    assert img.read(0, 4) == b"AAAA"


def test_apply_plan_applies_delta_zeroing():
    ebs = FakeEBS({5: b"Z" * eb.BLOCK_SIZE}, changed={5: "present", 7: None})
    plan = eb.build_delta_plan(ebs, "snap-2", "snap-1")
    img = eb.SparseImage(1)
    img.put(7, b"OLD")           # from cached base
    eb.apply_plan(ebs, plan, img)
    assert 7 not in img.written_indexes()   # zeroed
    assert 5 in img.written_indexes()


def test_apply_plan_rebinds_on_expiry():
    calls = {"n": 0}
    good = {0: b"A" * eb.BLOCK_SIZE}

    class ExpiringEBS(FakeEBS):
        def get_snapshot_block(self, SnapshotId, BlockIndex, BlockToken):
            if BlockToken.startswith("stale-"):
                raise Exception("ExpiredTokenException")
            return super().get_snapshot_block(SnapshotId=SnapshotId, BlockIndex=BlockIndex,
                                              BlockToken=BlockToken)

        def list_snapshot_blocks(self, SnapshotId, NextToken=None, **kw):
            calls["n"] += 1
            r = super().list_snapshot_blocks(SnapshotId, NextToken, **kw)
            prefix = "stale" if calls["n"] == 1 else "fresh"   # rebind refreshes
            for b in r["Blocks"]:
                b["BlockToken"] = f"{prefix}-{b['BlockIndex']}"
            return r
    ebs = ExpiringEBS(good, vol_gib=1)
    plan = eb.build_full_plan(ebs, "snap-1")
    img = eb.apply_plan(ebs, plan, eb.SparseImage(1))
    assert img.written_indexes() == {0}
    assert calls["n"] >= 2        # re-listed to rebind


# ── plan stats ───────────────────────────────────────────────────────────────
def test_plan_stats():
    ebs = FakeEBS({0: b"x", 1: b"y"})
    st = eb.plan_stats(eb.build_full_plan(ebs, "snap-1"))
    assert st["blocks_to_fetch"] == 2 and st["incremental"] is False
    assert st["bytes_to_fetch"] == 2 * eb.BLOCK_SIZE


# ── target selection ─────────────────────────────────────────────────────────
def test_pick_target_volumes_root_first():
    page = {"Reservations": [{"Instances": [{
        "InstanceId": "i-1", "RootDeviceName": "/dev/xvda",
        "BlockDeviceMappings": [
            {"DeviceName": "/dev/xvdf", "Ebs": {"VolumeId": "vol-data"}},
            {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-root"}},
        ]}]}]}
    assert eb.pick_target_volumes(page, "i-1") == ["vol-root", "vol-data"]


def test_pick_target_volumes_missing_instance():
    assert eb.pick_target_volumes({"Reservations": []}, "i-x") == []


# ── cleanup + provenance ─────────────────────────────────────────────────────
def test_cleanup_plan_order_later_first():
    art = eb.ScanArtifacts(scan_id="s1", created_snapshot_id="snap-c",
                           copied_snapshot_id="snap-cp", created_volume_id="vol-x",
                           attachment_device="/dev/sdf", shared_with=["999"])
    steps = [a for a, _ in eb.cleanup_plan(art)]
    # detach before delete volume; volume before snapshots; copied before created
    assert steps == ["detach_volume", "delete_volume", "unshare_snapshot",
                     "delete_snapshot", "delete_snapshot"]


def test_cleanup_plan_only_owned_resources():
    art = eb.ScanArtifacts(scan_id="s1", created_snapshot_id="snap-c")
    steps = eb.cleanup_plan(art)
    assert steps == [("delete_snapshot", {"SnapshotId": "snap-c"})]


def test_is_owned_guard():
    assert eb.is_owned({eb.OWNER_TAG: "s1"}, "s1") is True
    assert eb.is_owned({eb.OWNER_TAG: "other"}, "s1") is False
    assert eb.is_owned({}, "s1") is False
    assert eb.is_owned({eb.OWNER_TAG: ""}, "") is False   # empty scan_id never owns


# ── deferred live extractor degrades cleanly ─────────────────────────────────
def test_mounted_snapshots_deferred_raises():
    cm = eb.mounted_snapshots(None, None, ["vol-1"], scan_id="s1")
    with pytest.raises(eb.SideScanUnavailable):
        cm.__enter__()
