"""aws_layer_fetch.py — the SOLE new network primitive in Phase-4 Slice-5.

The production default for the ``http_get`` seam that ``aws_sidescan_image.fetch_ecr_layers``
injects: a hardened, read-only GET of an ECR layer blob from the **presigned S3 URL** that
``ecr:GetDownloadUrlForLayer`` mints at runtime. boto3 cannot return layer bytes (the op
returns only the presigned URL, and the presign IS the authorization), so a raw HTTPS GET is
unavoidable — it is confined to THIS file, which is registered in
``tests/test_zero_telemetry.py:EGRESS_ALLOWLIST`` and NETWORK.md.

Guarantees (mirroring the connector/kube egress seams): **HTTPS-only**, **AWS-endpoint-only**
(host must end in ``.amazonaws.com`` — presigned ECR layer URLs are S3 bucket hosts), a hard
**byte cap**, and a **timeout**. Any deviation raises ``LayerFetchError`` so the caller
fail-CLOSES the image (never scans a partial rootfs). Off unless BOTH the ``--side-scan-images``
flag and the opt-in ``CnappImageLayerPull`` IAM grant are present.
"""
from __future__ import annotations

import ssl
import urllib.request
from urllib.parse import urlparse

# Per-layer hard ceiling — a defense against a hostile/huge blob exhausting memory.
MAX_LAYER_BYTES = 500 * 1024 * 1024        # 500 MiB
DEFAULT_TIMEOUT = 30.0

_AWS_HOST_SUFFIX = ".amazonaws.com"


class LayerFetchError(Exception):
    """A presigned-URL layer blob could not be SAFELY fetched — the caller fail-closes
    the whole image rather than reconstructing a partial (false-clean) rootfs."""


def _ok_host(url: str) -> bool:
    p = urlparse(url or "")
    return p.scheme == "https" and (p.hostname or "").lower().endswith(_AWS_HOST_SUFFIX)


class _AwsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Re-apply the https + ``*.amazonaws.com`` guard on EVERY 3xx target, so a redirect
    can never escape the layer-fetch guarantee (an S3/ECR endpoint that 302s to a
    downgraded http://, a foreign host, or link-local IMDS is refused — urlopen then
    raises, and the caller fail-closes the image)."""
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        if not _ok_host(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, hdrs, newurl)


def http_get(url: str, *, max_bytes: int = MAX_LAYER_BYTES,
             timeout: float = DEFAULT_TIMEOUT) -> bytes:
    """Fetch one ECR layer blob from its presigned S3 URL. HTTPS + ``*.amazonaws.com``
    only (re-checked on every redirect), byte-capped, timed out; TLS verified against the
    system trust store (S3 uses a public CA). Raises ``LayerFetchError`` on any deviation
    — and, critically, on a SHORT read (a body truncated below its declared Content-Length),
    so it never returns partial bytes that would reconstruct a false-clean rootfs.

    ``url`` is a runtime value minted by ``ecr:GetDownloadUrlForLayer``; there is no
    hardcoded host anywhere in this module.
    """
    if not _ok_host(url):
        p = urlparse(url or "")
        if p.scheme != "https":
            raise LayerFetchError("layer URL must be https")
        raise LayerFetchError(f"layer host is not an AWS endpoint: {(p.hostname or '')!r}")
    ctx = ssl.create_default_context()             # verify TLS against system roots
    opener = urllib.request.build_opener(
        _AwsOnlyRedirect(), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = resp.read(max_bytes + 1)        # read one extra byte to detect overflow
            declared = resp.headers.get("Content-Length")
    except LayerFetchError:
        raise
    except Exception as e:                         # network / TLS / HTTP / blocked-redirect
        raise LayerFetchError(f"layer fetch failed: {e}")
    if len(data) > max_bytes:
        raise LayerFetchError(f"layer exceeds the {max_bytes}-byte cap")
    # FAIL-CLOSED on a short read: read(amt) does a single readinto and does NOT raise on an
    # early EOF, so a dropped connection returns a truncated blob. A body shorter than its
    # declared Content-Length is a corrupt layer -> abort (never a partial rootfs).
    if declared is not None:
        try:
            want = int(declared)
        except (TypeError, ValueError):
            want = None
        if want is not None and len(data) < want:
            raise LayerFetchError(f"layer truncated: got {len(data)} of {want} bytes")
    return data
