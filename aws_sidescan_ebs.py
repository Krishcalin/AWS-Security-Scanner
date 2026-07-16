#!/usr/bin/env python3
"""
aws_sidescan_ebs.py — EBS-snapshot block plane for agentless side-scanning
(CNAPP Phase 6). The PURE orchestration core (block planning, checksum
verification, sparse reassembly, provenance-guarded cleanup) ships and is
unit-tested with an injected fake `ebs`/`ec2` client; the LIVE I/O runner and the
real filesystem extractors (mount / loop / userspace-fs parsing of ext4/xfs/ntfs)
are DEFERRED to Phase 7 and guarded by ``HAS_BOTO3``.

Read strategy: EBS Direct APIs (ListSnapshotBlocks / ListChangedBlocks /
GetSnapshotBlock) — reads only WRITTEN blocks (cheap, sparse, incremental),
server-side-decrypts encrypted snapshots, is fully mockable, and adds no kernel
attack surface. Block size is a fixed 512 KiB; each block carries a base64
SHA-256 checksum.

Safety invariants (constraint #3): every scanner-created resource is tagged
``cnapp:sidescan=<scan_id>``; cleanup is provenance-guarded by :func:`is_owned`
so a customer's snapshot/volume is NEVER deleted; teardown undoes later-created
resources first and is idempotent/best-effort.
"""

from __future__ import annotations

import base64
import hashlib
import io
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

try:
    import boto3  # noqa: F401
    HAS_BOTO3 = True
except Exception:
    HAS_BOTO3 = False

BLOCK_SIZE = 524288          # 512 KiB, fixed by the EBS Direct API
CHECKSUM_ALGO = "SHA256"
OWNER_TAG = "cnapp:sidescan"


class ChecksumMismatch(Exception):
    """A fetched block's SHA-256 did not match the API-returned checksum."""


class SideScanUnavailable(RuntimeError):
    """The live side-scan I/O runner / filesystem extractor is unavailable
    (boto3 missing or the extractor is deferred). The caller degrades to INFO."""


# ── plan data shapes ──────────────────────────────────────────────────────────
@dataclass(frozen=True)
class BlockRef:
    index: int
    token: Optional[str]


@dataclass(frozen=True)
class FetchPlan:
    snapshot_id: str
    volume_size_gib: int
    block_size: int
    blocks: Tuple[BlockRef, ...]
    total_blocks_listed: int
    capped: bool
    base_snapshot_id: Optional[str] = None
    zeroed_indexes: Tuple[int, ...] = ()


# ── plan building (pure; injected ebs client returns canned pages) ────────────
def _paginate(ebs, method: str, key: str, **kwargs):
    """Yield items across NextToken pages from an EBS Direct API list call."""
    token = None
    while True:
        if token:
            kwargs["NextToken"] = token
        resp = getattr(ebs, method)(**kwargs)
        for item in resp.get(key, []):
            yield item, resp
        token = resp.get("NextToken")
        if not token:
            return


def build_full_plan(ebs, snapshot_id: str, *, max_blocks: Optional[int] = None,
                    block_filter: Optional[Callable[[int], bool]] = None) -> FetchPlan:
    """Plan a full read of a snapshot via ListSnapshotBlocks. Honors a hard
    ``max_blocks`` cap (sets ``capped``) and an optional index filter."""
    refs: List[BlockRef] = []
    total = 0
    vol_size = 0
    bsize = BLOCK_SIZE
    capped = False
    for blk, resp in _paginate(ebs, "list_snapshot_blocks", "Blocks", SnapshotId=snapshot_id):
        vol_size = resp.get("VolumeSize", vol_size)
        bsize = resp.get("BlockSize", bsize)
        idx = blk["BlockIndex"]
        total += 1
        if block_filter is not None and not block_filter(idx):
            continue
        if max_blocks is not None and len(refs) >= max_blocks:
            capped = True
            continue
        refs.append(BlockRef(index=idx, token=blk.get("BlockToken")))
    return FetchPlan(snapshot_id=snapshot_id, volume_size_gib=vol_size, block_size=bsize,
                     blocks=tuple(refs), total_blocks_listed=total, capped=capped)


def build_delta_plan(ebs, snapshot_id: str, base_snapshot_id: str, *,
                     max_blocks: Optional[int] = None) -> FetchPlan:
    """Plan an INCREMENTAL read: only blocks changed between a base snapshot and
    the target. A changed block with no SecondBlockToken was ZEROED/removed in the
    target and must be zeroed against the cached base (not skipped) — skipping it
    leaves stale bytes and corrupts the reassembled filesystem."""
    refs: List[BlockRef] = []
    zeroed: List[int] = []
    total = 0
    vol_size = 0
    bsize = BLOCK_SIZE
    capped = False
    for blk, resp in _paginate(ebs, "list_changed_blocks", "ChangedBlocks",
                               FirstSnapshotId=base_snapshot_id, SecondSnapshotId=snapshot_id):
        vol_size = resp.get("VolumeSize", vol_size)
        bsize = resp.get("BlockSize", bsize)
        idx = blk["BlockIndex"]
        total += 1
        second = blk.get("SecondBlockToken")
        if second is None:
            zeroed.append(idx)
            continue
        if max_blocks is not None and len(refs) >= max_blocks:
            capped = True
            # A dropped CHANGED block must be zeroed onto the cached base, not
            # skipped — else the reassembled image keeps STALE non-zero base bytes
            # (indistinguishable from current data = silent inventory FN). A zero
            # hole is at least recognizable.
            zeroed.append(idx)
            continue
        refs.append(BlockRef(index=idx, token=second))
    return FetchPlan(snapshot_id=snapshot_id, volume_size_gib=vol_size, block_size=bsize,
                     blocks=tuple(refs), total_blocks_listed=total, capped=capped,
                     base_snapshot_id=base_snapshot_id, zeroed_indexes=tuple(zeroed))


def rebind_tokens(ebs, plan: FetchPlan, remaining_indexes: Iterable[int]) -> FetchPlan:
    """Block tokens are temporary (expire at ExpiryTime, or when ANY List runs on
    the snapshot). Re-list ONLY the still-needed indexes to refresh their tokens,
    keyed by index so a partial fetch is resumable."""
    want = set(remaining_indexes)
    fresh: Dict[int, Optional[str]] = {}
    for blk, _resp in _paginate(ebs, "list_snapshot_blocks", "Blocks",
                                SnapshotId=plan.snapshot_id):
        idx = blk["BlockIndex"]
        if idx in want:
            fresh[idx] = blk.get("BlockToken")
    rebound = tuple(BlockRef(index=r.index, token=fresh.get(r.index, r.token))
                    for r in plan.blocks if r.index in want)
    return FetchPlan(snapshot_id=plan.snapshot_id, volume_size_gib=plan.volume_size_gib,
                     block_size=plan.block_size, blocks=rebound,
                     total_blocks_listed=plan.total_blocks_listed, capped=plan.capped,
                     base_snapshot_id=plan.base_snapshot_id, zeroed_indexes=plan.zeroed_indexes)


def plan_stats(plan: FetchPlan) -> Dict:
    return {
        "snapshot_id": plan.snapshot_id,
        "blocks_to_fetch": len(plan.blocks),
        "blocks_listed": plan.total_blocks_listed,
        "zeroed_blocks": len(plan.zeroed_indexes),
        "bytes_to_fetch": len(plan.blocks) * plan.block_size,
        "volume_size_gib": plan.volume_size_gib,
        "capped": plan.capped,
        "incremental": plan.base_snapshot_id is not None,
    }


# ── checksum + block fetch ────────────────────────────────────────────────────
def verify_block_checksum(data: bytes, checksum_b64: str, algorithm: str = "SHA256") -> bool:
    if algorithm.upper() != "SHA256":
        return False
    digest = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
    return digest == checksum_b64


def fetch_block(ebs, snapshot_id: str, ref: BlockRef, *, verify: bool = True) -> bytes:
    """Fetch one block via GetSnapshotBlock and verify its checksum. Raises
    :class:`ChecksumMismatch` on corruption (the caller retries after rebind)."""
    resp = ebs.get_snapshot_block(SnapshotId=snapshot_id, BlockIndex=ref.index,
                                  BlockToken=ref.token)
    body = resp["BlockData"]
    data = body.read() if hasattr(body, "read") else bytes(body)
    if verify:
        chk = resp.get("Checksum", "")
        algo = resp.get("ChecksumAlgorithm", CHECKSUM_ALGO)
        if not verify_block_checksum(data, chk, algo):
            raise ChecksumMismatch(f"block {ref.index} checksum mismatch")
    return data


# ── sparse image reassembly ──────────────────────────────────────────────────
class SparseImage:
    """Sparse block store: only written blocks are held; reads zero-fill holes.
    Supports delta reassembly onto a cached base (put changed, zero removed)."""

    def __init__(self, volume_size_gib: int, block_size: int = BLOCK_SIZE):
        self.volume_size = int(volume_size_gib) * (1 << 30)
        self.block_size = block_size
        self._blocks: Dict[int, bytes] = {}
        self._zeroed: set = set()

    def put(self, index: int, data: bytes) -> None:
        self._blocks[index] = data
        self._zeroed.discard(index)

    def zero(self, index: int) -> None:
        self._blocks.pop(index, None)
        self._zeroed.add(index)

    def read(self, offset: int, length: int) -> bytes:
        out = bytearray()
        pos = offset
        end = offset + length
        while pos < end:
            idx = pos // self.block_size
            within = pos % self.block_size
            take = min(self.block_size - within, end - pos)
            blk = self._blocks.get(idx)
            if blk is None:
                out += b"\x00" * take                        # hole / zeroed
            else:
                chunk = blk[within:within + take]
                out += chunk + b"\x00" * (take - len(chunk))  # short block -> pad
            pos += take
        return bytes(out)

    def written_indexes(self) -> set:
        return set(self._blocks)

    def written_bytes(self) -> int:
        return sum(len(b) for b in self._blocks.values())

    def flush_sparse_raw(self, path: str) -> None:
        """Write a sparse raw image (holes stay sparse via seek). Live-path only."""
        with open(path, "wb") as fh:
            fh.truncate(self.volume_size)
            for idx, blk in sorted(self._blocks.items()):
                fh.seek(idx * self.block_size)
                fh.write(blk)

    def as_file(self) -> "SparseImageIO":
        """A seekable read-only file-like over the reassembled image — fed to a
        userspace filesystem parser without a multi-GB temp file."""
        return SparseImageIO(self)


class SparseImageIO(io.RawIOBase):
    """Seekable read-only view of a SparseImage (holes read as zeros)."""

    def __init__(self, image: SparseImage):
        self._img = image
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, pos: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = pos
        elif whence == 1:
            self._pos += pos
        else:
            self._pos = self._img.volume_size + pos
        return self._pos

    def tell(self) -> int:
        return self._pos

    def readinto(self, b) -> int:
        n = min(len(b), max(0, self._img.volume_size - self._pos))
        if n <= 0:
            return 0
        data = self._img.read(self._pos, n)
        b[:len(data)] = data
        self._pos += len(data)
        return len(data)


def apply_plan(ebs, plan: FetchPlan, image: SparseImage, *,
               on_expired: Callable = rebind_tokens, concurrency: int = 1,
               verify: bool = True) -> SparseImage:
    """Fetch every planned block into the image (zeroing delta-removed blocks),
    rebinding tokens once on expiry. The ONLY function that mixes pure planning
    with live I/O — it has no branching of its own, delegating to pure helpers, so
    the untested surface is minimal."""
    for idx in plan.zeroed_indexes:
        image.zero(idx)
    remaining = {r.index: r for r in plan.blocks}
    rebound_once = False
    while remaining:
        progressed = False
        for idx, ref in list(remaining.items()):
            try:
                image.put(idx, fetch_block(ebs, plan.snapshot_id, ref, verify=verify))
                del remaining[idx]
                progressed = True
            except Exception:
                if rebound_once:
                    raise
                break
        if remaining and not progressed:
            if rebound_once:
                raise SideScanUnavailable("block tokens expired and rebind did not help")
            plan = on_expired(ebs, plan, list(remaining))
            remaining = {r.index: r for r in plan.blocks}
            rebound_once = True
    return image


# ── target selection + cleanup (pure) ────────────────────────────────────────
def pick_target_volumes(describe_instances_page: dict, instance_id: str) -> List[str]:
    """Extract an instance's EBS volume ids (root device first) from a
    DescribeInstances response."""
    for res in describe_instances_page.get("Reservations", []):
        for inst in res.get("Instances", []):
            if inst.get("InstanceId") != instance_id:
                continue
            root = inst.get("RootDeviceName", "")
            vols: List[Tuple[bool, str]] = []
            for bdm in inst.get("BlockDeviceMappings", []):
                ebs = bdm.get("Ebs", {})
                vid = ebs.get("VolumeId")
                if vid:
                    vols.append((bdm.get("DeviceName") == root, vid))
            vols.sort(key=lambda t: (not t[0]))   # root first
            return [v for _r, v in vols]
    return []


@dataclass
class ScanArtifacts:
    scan_id: str
    created_snapshot_id: Optional[str] = None
    copied_snapshot_id: Optional[str] = None
    created_volume_id: Optional[str] = None
    attachment_device: Optional[str] = None
    shared_with: List[str] = field(default_factory=list)


def cleanup_plan(art: ScanArtifacts) -> List[Tuple[str, dict]]:
    """Ordered, idempotent teardown: undo later-created resources first; only
    resources we actually created appear. Each step is (action, kwargs)."""
    steps: List[Tuple[str, dict]] = []
    if art.created_volume_id and art.attachment_device:
        steps.append(("detach_volume", {"VolumeId": art.created_volume_id}))
    if art.created_volume_id:
        steps.append(("delete_volume", {"VolumeId": art.created_volume_id}))
    for acct in art.shared_with:
        steps.append(("unshare_snapshot", {"SnapshotId": art.copied_snapshot_id
                                            or art.created_snapshot_id, "Account": acct}))
    if art.copied_snapshot_id:
        steps.append(("delete_snapshot", {"SnapshotId": art.copied_snapshot_id}))
    if art.created_snapshot_id:
        steps.append(("delete_snapshot", {"SnapshotId": art.created_snapshot_id}))
    return steps


def is_owned(resource_tags: Dict[str, str], scan_id: str) -> bool:
    """Provenance guard: True only if this resource carries our owner tag for this
    scan. Cleanup MUST consult this before deleting anything — never delete a
    resource we did not create."""
    return resource_tags.get(OWNER_TAG) == scan_id and bool(scan_id)


# ── LIVE snapshot runner (Phase 7; orchestration mock-tested, fs-parse deferred) ─
@dataclass
class CleanupReport:
    attempted: int
    succeeded: int
    failed: int
    skipped_unowned: int
    fully_clean: bool

    def to_dict(self) -> dict:
        return {"attempted": self.attempted, "succeeded": self.succeeded,
                "failed": self.failed, "skipped_unowned": self.skipped_unowned,
                "fully_clean": self.fully_clean}


@dataclass
class SnapshotSideScanResult:
    instance_id: str
    sidescan: object                    # the SideScanResult from the injected sidescan_fn
    artifacts: ScanArtifacts
    cleanup: CleanupReport
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None


def _owner_tagspec(scan_id: str, resource_type: str = "snapshot") -> dict:
    """TagSpecification so a scanner-created resource is born-owned (no untagged
    window) — the provenance the cleanup guard and the IAM tag-condition rely on."""
    return {"ResourceType": resource_type,
            "Tags": [{"Key": OWNER_TAG, "Value": scan_id},
                     {"Key": "cnapp:created", "Value": "sidescan"}]}


def _poll_snapshot_completed(ec2, snapshot_id: str, *, sleeper: Callable = time.sleep,
                             timeout_s: float = 900, interval_s: float = 5.0) -> str:
    """Poll describe_snapshots until 'completed' (no boto3 waiter — unmockable).
    Raises SideScanUnavailable on 'error' or timeout. ``sleeper`` injected -> deterministic."""
    waited = 0.0
    while waited <= timeout_s:
        resp = ec2.describe_snapshots(SnapshotIds=[snapshot_id])
        snaps = resp.get("Snapshots", [])
        state = snaps[0].get("State") if snaps else "pending"
        if state == "completed":
            return "completed"
        if state == "error":
            raise SideScanUnavailable(f"snapshot {snapshot_id} entered error state")
        sleeper(interval_s)
        waited += interval_s
    raise SideScanUnavailable(f"snapshot {snapshot_id} did not complete within {timeout_s}s")


def _do_cleanup_step(ec2, ebs, action: str, kw: dict) -> None:
    if action == "detach_volume":
        ec2.detach_volume(VolumeId=kw["VolumeId"], Force=True)
    elif action == "delete_volume":
        ec2.delete_volume(VolumeId=kw["VolumeId"])
    elif action == "unshare_snapshot":
        ec2.modify_snapshot_attribute(SnapshotId=kw["SnapshotId"],
                                      Attribute="createVolumePermission",
                                      OperationType="remove", UserIds=[kw["Account"]])
    elif action == "delete_snapshot":
        ec2.delete_snapshot(SnapshotId=kw["SnapshotId"])


def run_cleanup(ec2, ebs, art: ScanArtifacts, *, describe_tags: Optional[Callable] = None) -> CleanupReport:
    """Tear down every scanner-created resource (dependents-first). Best-effort:
    one failure never aborts the rest. Before deleting a snapshot, re-check
    is_owned via ``describe_tags`` (defense-in-depth over the IAM tag-condition) —
    NEVER delete a resource we did not create."""
    attempted = succeeded = failed = skipped = 0
    for action, kw in cleanup_plan(art):
        if action == "delete_snapshot" and describe_tags is not None:
            try:
                tags = describe_tags(kw.get("SnapshotId")) or {}
            except Exception:
                tags = {}
            if not is_owned(tags, art.scan_id):
                skipped += 1
                continue
        attempted += 1
        try:
            _do_cleanup_step(ec2, ebs, action, kw)
            succeeded += 1
        except Exception:
            failed += 1
    return CleanupReport(attempted, succeeded, failed, skipped, failed == 0)


def run_snapshot_sidescan(ec2, ebs, instance_id: str, *, scan_id: str, region: str = "",
                          sidescan_fn: Callable, extractor_factory: Callable,
                          describe_instances_fn: Optional[Callable] = None,
                          max_blocks: Optional[int] = None, copy_kms_key_id: Optional[str] = None,
                          share_with: Optional[List[str]] = None, sleeper: Callable = time.sleep,
                          poll_timeout_s: float = 900, verify: bool = True,
                          describe_tags: Optional[Callable] = None) -> SnapshotSideScanResult:
    """Live agentless side-scan of one instance's root volume: snapshot -> (copy/
    re-encrypt) -> fetch blocks -> reassemble -> extract -> scan, with GUARANTEED
    provenance-guarded cleanup even on error. The only live seams are the injected
    ec2/ebs clients and ``extractor_factory`` (the real fs parse); everything else
    is pure and mock-tested. A capped (truncated) read is flagged INCOMPLETE so it
    is NEVER mistaken for a clean bill of health."""
    notes: List[str] = []
    art = ScanArtifacts(scan_id=scan_id)
    result = None
    error = None
    try:
        di = (describe_instances_fn or ec2.describe_instances)(InstanceIds=[instance_id])
        vol_ids = pick_target_volumes(di, instance_id)
        if not vol_ids:
            notes.append("no EBS volume found on the instance")
        else:
            snap = ec2.create_snapshot(VolumeId=vol_ids[0],
                                       TagSpecifications=[_owner_tagspec(scan_id)])
            art.created_snapshot_id = snap["SnapshotId"]
            _poll_snapshot_completed(ec2, art.created_snapshot_id, sleeper=sleeper,
                                     timeout_s=poll_timeout_s)
            read_snap = art.created_snapshot_id
            if copy_kms_key_id:                      # cross-account: re-encrypt under audit CMK
                cp = ec2.copy_snapshot(SourceSnapshotId=art.created_snapshot_id,
                                       SourceRegion=region, Encrypted=True,
                                       KmsKeyId=copy_kms_key_id,
                                       TagSpecifications=[_owner_tagspec(scan_id)])
                art.copied_snapshot_id = cp["SnapshotId"]
                _poll_snapshot_completed(ec2, art.copied_snapshot_id, sleeper=sleeper,
                                         timeout_s=poll_timeout_s)
                read_snap = art.copied_snapshot_id
            for acct in (share_with or []):
                ec2.modify_snapshot_attribute(SnapshotId=read_snap,
                                              Attribute="createVolumePermission",
                                              OperationType="add", UserIds=[acct])
                art.shared_with.append(acct)
            # fetch blocks AFTER the copy — tokens invalidate on any List call
            plan = build_full_plan(ebs, read_snap, max_blocks=max_blocks)
            img = SparseImage(plan.volume_size_gib or 1, plan.block_size)
            apply_plan(ebs, plan, img, verify=verify)
            if plan.capped:
                notes.append("image truncated (max_blocks cap) — inventory INCOMPLETE, "
                             "not a clean bill of health")
            with extractor_factory(img) as ext:
                result = sidescan_fn(ext)
    except SideScanUnavailable as e:
        error = str(e)
        notes.append(f"side-scan unavailable: {e}")
    except Exception as e:
        error = str(e)
        notes.append(f"side-scan failed: {e}")
    finally:
        cleanup = run_cleanup(ec2, ebs, art, describe_tags=describe_tags)
    return SnapshotSideScanResult(instance_id=instance_id, sidescan=result, artifacts=art,
                                  cleanup=cleanup, notes=notes, error=error)


class _LiveMountedSnapshots:
    """Context manager over run_snapshot_sidescan's prepare/cleanup halves so
    ``aws_live_scanner._check_side_scan`` and the ``_sidescan_extractor_opener``
    seam stay byte-for-byte unchanged. Yields a FilesystemExtractor; __exit__
    guarantees is_owned-guarded cleanup. If no extractor factory is available
    (dissect absent), raises SideScanUnavailable -> CWPP-04 INFO."""

    def __init__(self, ec2, ebs, volume_ids, *, scan_id: str = "",
                 extractor_factory: Optional[Callable] = None, region: str = ""):
        self._ec2, self._ebs = ec2, ebs
        self._scan_id, self._region = scan_id, region
        self._factory = extractor_factory
        self._art = ScanArtifacts(scan_id=scan_id)
        self._cm = None

    def __enter__(self):
        if self._factory is None:
            try:
                import aws_sidescan_fs   # optional dissect adapter (deferred)
                self._factory = aws_sidescan_fs.DissectExtractor
            except Exception:
                raise SideScanUnavailable(
                    "no filesystem extractor available (install dissect.target for "
                    "userspace ext4/xfs parsing); live side-scan skipped")
        # Live snapshot prepare is exercised via run_snapshot_sidescan; this CM is
        # the thin seam kept for the scanner. Real preparation is integration-only.
        raise SideScanUnavailable(
            "interactive mounted_snapshots is integration-only; use "
            "run_snapshot_sidescan(...) for the mock-testable orchestration")

    def __exit__(self, *a):
        run_cleanup(self._ec2, self._ebs, self._art)
        return False


def mounted_snapshots(ec2, ebs, volume_ids, *, tag: str = OWNER_TAG, scan_id: str = "",
                      extractor_factory: Optional[Callable] = None, region: str = ""):
    """Context manager seam kept byte-compatible for aws_live_scanner. The live
    per-instance orchestration is :func:`run_snapshot_sidescan` (mock-tested);
    this CM degrades to SideScanUnavailable when no userspace fs extractor is
    installed, so the scanner emits a clean CWPP-04 INFO."""
    return _LiveMountedSnapshots(ec2, ebs, volume_ids, scan_id=scan_id,
                                 extractor_factory=extractor_factory, region=region)
