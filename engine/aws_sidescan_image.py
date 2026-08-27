"""Live ECR image-layer fetch bridge for the agentless container side-scan (CWPP-05).

fetch_ecr_layers resolves an ECR image's ordered filesystem-layer bytes (bottom-to-top),
handling manifest lists (linux/amd64 selection) and skipping config/foreign/zstd layers.
The layer bytes are downloaded via an INJECTED http_get so the whole thing is mock-testable
up to the network boundary; feed the result to aws_sidescan.ImageLayerExtractor. Fail-open.
"""
import json
from typing import Callable, Dict, List, Optional

_CONFIG_TYPES = {
    "application/vnd.docker.container.image.v1+json",
    "application/vnd.oci.image.config.v1+json",
}
_SKIP_LAYER_TYPES = {                          # non-distributable/foreign (Windows base)
    "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
}
_MANIFEST_LIST_TYPES = {
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
}
_MANIFEST_TYPES = [
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
]


class ImageFetchUnavailable(Exception):
    """A container image manifest could not be fetched/decoded (never a false-clean)."""


def _select_child_digest(index: Dict, os_: str = "linux", arch: str = "amd64") -> Optional[str]:
    """Pick the linux/amd64 child from a manifest list/index (skip attestation/unknown)."""
    for m in index.get("manifests", []):
        p = m.get("platform", {}) or {}
        if p.get("os") == os_ and p.get("architecture") == arch:
            return m.get("digest")
    for m in index.get("manifests", []):       # fallback: any LINUX child (never windows/darwin)
        if (m.get("platform", {}) or {}).get("os") == os_:
            return m.get("digest")
    return None                                # non-linux-only image -> None (surfaces a note)


def fetch_ecr_layers(ecr_client, repository_name: str, image_id: Dict, *,
                     http_get: Callable[[str], bytes], max_layers: int = 200,
                     notes: Optional[List[str]] = None) -> List[bytes]:
    """Return an ECR image's ordered filesystem-layer bytes (bottom-to-top) for
    ImageLayerExtractor. image_id is a boto3 ecr imageId dict, e.g. {'imageDigest': ...}
    or {'imageTag': ...}. Resolves a manifest list to linux/amd64; skips config/foreign/
    zstd layers. Fail-open (a failed layer is a note, not a crash)."""
    def _manifest(iid: Dict):
        resp = ecr_client.batch_get_image(
            repositoryName=repository_name, imageIds=[iid],
            acceptedMediaTypes=list(_MANIFEST_LIST_TYPES) + _MANIFEST_TYPES)
        images = resp.get("images", [])
        if not images:
            return None
        return json.loads(images[0]["imageManifest"])

    try:
        man = _manifest(image_id)
    except Exception as e:
        raise ImageFetchUnavailable(f"batch_get_image failed: {e}")
    if man is None:
        raise ImageFetchUnavailable("image not found")
    if man.get("mediaType") in _MANIFEST_LIST_TYPES or "manifests" in man:
        child = _select_child_digest(man)
        if not child:
            if notes is not None:
                notes.append("no linux/amd64 child manifest")
            return []
        try:
            man = _manifest({"imageDigest": child})
        except Exception as e:
            raise ImageFetchUnavailable(f"child manifest fetch failed: {e}")
        if man is None:
            return []
    layers: List[bytes] = []
    for layer in (man.get("layers", []) or [])[:max_layers]:
        lmt = layer.get("mediaType", "")
        if lmt in _CONFIG_TYPES or lmt in _SKIP_LAYER_TYPES:
            continue
        if lmt.endswith("+zstd"):
            if notes is not None:
                notes.append(f"zstd layer skipped ({layer.get('digest')})")
            continue
        digest = layer.get("digest")
        if not digest:
            continue
        # FAIL-CLOSED: a dropped middle layer silently corrupts the overlay (stale
        # vulnerable version => false alarm; missing package DB => false clean), so a
        # layer download failure aborts the whole image scan rather than returning a
        # partial rootfs (mirrors the manifest-fetch fail-closed contract).
        try:
            url = ecr_client.get_download_url_for_layer(
                repositoryName=repository_name, layerDigest=digest).get("downloadUrl")
            if not url:
                raise ImageFetchUnavailable(f"no download URL for layer {digest}")
            layers.append(http_get(url))
        except ImageFetchUnavailable:
            raise
        except Exception as e:
            raise ImageFetchUnavailable(f"layer fetch failed ({digest}): {e}")
    return layers
