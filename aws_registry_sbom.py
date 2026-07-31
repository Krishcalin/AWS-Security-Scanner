"""aws_registry_sbom.py — Phase-4 Slice-5 helpers for agentless ECR registry scanning.

PURE module: no network primitive, no boto3 client construction. Tier-B layer-pull
turns each pulled image's OS-package inventory into a durable, CycloneDX-shaped SBOM
snapshot, reusing the Slice-4 supply-chain persistence + diff/license/VEX machinery.

The layer bytes themselves are fetched via an INJECTED ``http_get`` seam (see
``aws_layer_fetch.http_get`` or the hub-injected boundary) that is threaded through
``aws_sidescan_image.fetch_ecr_layers`` — never from this module. That keeps the
zero-telemetry tripwire (``tests/test_zero_telemetry.py``) confined to one allowlisted
egress file.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import AbstractSet, Callable, List, Mapping, Optional

import aws_ingest
import aws_sidescan
import aws_sidescan_image

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _package_to_component(pkg) -> "aws_ingest.Component":
    """Adapt an ``aws_sidescan.Package`` (OS-package inventory row from a pulled image
    rootfs) to an ``aws_ingest.Component`` for durable snapshot persistence.

    OS-package databases carry no license string, so ``license_raw`` is ``None`` — a
    license only ever arrives via an SPDX/CycloneDX *ingest*, not a rootfs scan.
    """
    purl = pkg.purl or None
    return aws_ingest.Component(
        name=pkg.name,
        version=pkg.version,
        purl=purl,
        purl_identity=aws_ingest.purl_identity(purl, pkg.name, pkg.ecosystem),
        ecosystem=pkg.ecosystem,
        origin=pkg.origin or "registry",
        license_raw=None,
    )


def registry_sbom_doc_id(repo_uri: str, digest: str,
                         components: List["aws_ingest.Component"]) -> str:
    """A stable, content-addressed document id for a pulled registry image's SBOM.

    Keyed on (repo_uri, image digest, the component set) so a re-sweep of an UNCHANGED
    image yields the identical id — the snapshot writer treats that as an idempotent
    no-op, never a duplicate snapshot. A digest is already content-addressed; the
    component hash is a belt-and-suspenders guard against feed/parser drift, and it is
    order-independent (components are sorted first).
    """
    idents = sorted(f"{c.purl_identity}@{c.version}" for c in components)
    payload = "\x00".join([repo_uri or "", digest or "", *idents])
    dig = hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:16]
    return f"ecr-sidescan:{repo_uri}@{digest}#{dig}"


# ── Tier-B orchestrator helpers (B3): enumerate + pull-and-scan ───────────────
@dataclass
class RegistryImageResult:
    """One pulled registry image's scan outcome. ``ok`` is True ONLY when the rootfs was
    fully reconstructed and scanned; a pull failure / denial / oversize sets ok=False
    with a ``note`` (fail-open — Tier-A native findings still stand, no false data)."""
    digest: str
    tags: List[str]
    node_id: str                       # {repo_uri}@{digest}: converges with CNT-02 / RUNS_IMAGE / Inspector
    ok: bool
    result: Optional["aws_sidescan.SideScanResult"]
    components: List["aws_ingest.Component"]
    doc_id: Optional[str]
    note: str = ""


def select_registry_images(ecr, repo: str, *, newest_n: int,
                           max_image_bytes: Optional[int] = None,
                           notes: Optional[List[str]] = None) -> List[dict]:
    """The newest-N *tagged* images in a repo (by imagePushedAt), deduped by digest and
    filtered by an optional compressed-size cap. Untagged images are skipped (G1).
    Fail-open: any read error returns [] with a note."""
    try:
        imgs: List[dict] = []
        for page in ecr.get_paginator("describe_images").paginate(
                repositoryName=repo, filter={"tagStatus": "TAGGED"}):
            imgs.extend(page.get("imageDetails", []))
    except Exception as e:
        if notes is not None:
            notes.append(f"describe_images failed for {repo}: {e}")
        return []
    seen: set = set()
    out: List[dict] = []
    for d in sorted(imgs, key=lambda x: x.get("imagePushedAt") or _EPOCH, reverse=True):
        dg = d.get("imageDigest")
        if not dg or dg in seen or not d.get("imageTags"):
            continue                                  # skip digest-less / dup / untagged
        if max_image_bytes and (d.get("imageSizeInBytes") or 0) > max_image_bytes:
            if notes is not None:
                notes.append(f"{repo}@{dg[:19]} exceeds size cap — skipped")
            continue
        seen.add(dg)
        out.append(d)
        if len(out) >= max(1, newest_n):
            break
    return out


def scan_registry_image(ecr, repo: str, repo_uri: str, image_detail: dict, *,
                        http_get: Callable[[str], bytes],
                        feed: "Optional[aws_sidescan.OSVFeed]",
                        epss: Mapping[str, float], kev: AbstractSet[str],
                        exploits: AbstractSet[str] = frozenset(),
                        max_layers: int = 200, max_image_bytes: Optional[int] = None,
                        do_secrets: bool = True,
                        notes: Optional[List[str]] = None) -> RegistryImageResult:
    """Pull ONE image's layers (via the injected ``http_get``), reconstruct the rootfs,
    and run the OSV side-scan. FAIL-CLOSED on an integrity failure — a dropped layer
    would yield a partial rootfs (false clean / false alarm), so the whole image is
    dropped (never a partial result). Any pull failure/denial returns ok=False with a
    note; the caller keeps Tier-A native findings and emits an INFO. Never raises."""
    n = notes if notes is not None else []
    digest = image_detail.get("imageDigest") or ""
    tags = list(image_detail.get("imageTags") or [])
    node_id = f"{repo_uri}@{digest}"

    def _fail(note):
        return RegistryImageResult(digest, tags, node_id, False, None, [], None, note)

    # pre-filter only a KNOWN oversized image (unknown size falls through to the post-fetch
    # byte bound below — never a silent bypass of the cap).
    size = image_detail.get("imageSizeInBytes")
    if max_image_bytes and isinstance(size, (int, float)) and size > max_image_bytes:
        n.append(f"{repo}@{digest[:19]} exceeds size cap — skipped")
        return _fail("oversized")
    try:
        layers = aws_sidescan_image.fetch_ecr_layers(
            ecr, repo, {"imageDigest": digest}, http_get=http_get,
            max_layers=max_layers, notes=n)
    except aws_sidescan_image.ImageFetchUnavailable as e:
        n.append(f"{repo}@{digest[:19]} layer pull incomplete (fail-closed): {e}")
        return _fail(f"pull-failed: {e}")
    except Exception as e:                            # denial / unexpected — never a partial scan
        n.append(f"{repo}@{digest[:19]} layer pull denied/unavailable: {e}")
        return _fail(f"denied: {e}")
    return scan_pulled_layers(
        layers, repo=repo, repo_uri=repo_uri, digest=digest, tags=tags, node_id=node_id,
        feed=feed, epss=epss, kev=kev, exploits=exploits, max_image_bytes=max_image_bytes,
        do_secrets=do_secrets, notes=n)


def scan_pulled_layers(layers: List[bytes], *, repo: str, repo_uri: str, digest: str,
                       tags: List[str], node_id: str, feed, epss: Mapping[str, float],
                       kev: AbstractSet[str], exploits: AbstractSet[str] = frozenset(),
                       max_image_bytes: Optional[int] = None, do_secrets: bool = True,
                       notes: Optional[List[str]] = None) -> RegistryImageResult:
    """The REGISTRY-AGNOSTIC half of an image scan: reconstruct the rootfs from already-pulled
    ``layers`` and run the OSV side-scan. FAIL-CLOSED on a partial rootfs (a dropped/corrupt layer
    would yield a false-clean/false-alarm). Shared by the ECR path (``scan_registry_image``) and
    the non-AWS OCI path (``aws_registry_oci``) so their fail-closed contract can never diverge."""
    n = notes if notes is not None else []

    def _fail(note):
        return RegistryImageResult(digest, tags, node_id, False, None, [], None, note)

    if not layers:
        n.append(f"{repo}@{digest[:19]} has no scannable linux layers")
        return _fail("no-layers")
    # post-fetch byte bound: caps an unknown/under-reported image size at the actual reconstructed
    # size (defense in depth over the per-layer http_get cap).
    total = sum(len(b) for b in layers)
    if max_image_bytes and total > max_image_bytes:
        n.append(f"{repo}@{digest[:19]} pulled bytes exceed size cap — skipped")
        return _fail("oversized")
    # FAIL-CLOSED on a partial rootfs: if any WHOLE layer failed to open (corrupt blob) or the
    # entry cap was hit, the merged filesystem is incomplete -> a missing package DB would read as
    # a false-clean scan. Drop the image rather than scan a partial rootfs.
    stats: dict = {}
    ext = aws_sidescan.ImageLayerExtractor(layers, notes=n, stats=stats)
    if stats.get("dropped_layers") or stats.get("truncated"):
        n.append(f"{repo}@{digest[:19]} rootfs incomplete "
                 f"(dropped_layers={stats.get('dropped_layers', 0)}, "
                 f"truncated={bool(stats.get('truncated'))}) — fail-closed")
        return _fail("partial-rootfs")
    res = aws_sidescan.sidescan_filesystem(
        ext, feed, epss, kev, exploits, instance_id=node_id, do_secrets=do_secrets)
    n.extend(res.notes)
    components = [_package_to_component(p) for p in res.packages]
    doc_id = registry_sbom_doc_id(repo_uri, digest, components) if components else None
    return RegistryImageResult(digest, tags, node_id, True, res, components, doc_id, "")


def to_cyclonedx(node_id: str, components: List["aws_ingest.Component"]) -> dict:
    """Shape a pulled image's components into a minimal, DETERMINISTIC CycloneDX inventory
    doc so it flows through the existing ``PlatformService.ingest_document`` inventory lane
    → a durable SBOM snapshot (diff / license / VEX for free). Components are sorted and no
    timestamp is emitted, so the same image content yields byte-identical bytes → a stable
    ``doc_content_id`` → an idempotent re-ingest (never a duplicate snapshot)."""
    comps = []
    for c in sorted(components, key=lambda x: (x.purl_identity, x.version, x.name)):
        d = {"type": "library", "name": c.name, "version": c.version,
             "bom-ref": c.purl or f"{c.name}@{c.ecosystem}"}
        if c.purl:
            d["purl"] = c.purl
        if c.license_raw:
            d["licenses"] = [{"license": {"name": c.license_raw}}]
        comps.append(d)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"component": {"type": "container", "name": node_id, "bom-ref": node_id},
                     "tools": {"components": [{"name": "ecr-sidescan"}]}},
        "components": comps,
    }
