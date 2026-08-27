"""aws_layer_fetch.py — the SOLE new network primitive for agentless registry layer pulls.

The production default for the ``http_get`` seam that ``aws_sidescan_image.fetch_ecr_layers``
injects: a hardened, read-only GET of an ECR layer blob from the **presigned S3 URL** that
``ecr:GetDownloadUrlForLayer`` mints at runtime. boto3 cannot return layer bytes (the op returns
only the presigned URL, and the presign IS the authorization), so a raw HTTPS GET is unavoidable
— confined to THIS file, which is registered in ``tests/test_zero_telemetry.py:EGRESS_ALLOWLIST``
and NETWORK.md.

Batch 6 generalizes the SAME hardened primitive to **non-AWS OCI registries** (GHCR / Docker Hub /
Harbor / ACR) via the Docker Registry v2 token dance, keeping ALL registry egress inside this one
allowlisted file. The SSRF/TLS posture stays TIGHT:

  * **HTTPS-only**, always (no downgrade, re-checked on every redirect).
  * **Per-call host allowlist.** ``http_get`` / ``registry_request`` refuse any host not in the
    caller's ``allowed_hosts`` set — which is built ONLY from the operator-configured registry host
    + the auth realm host learned at runtime from the ``WWW-Authenticate`` challenge (a runtime
    value, exactly like ECR's presigned URL). ECR keeps its ``.amazonaws.com`` default when
    ``allowed_hosts`` is omitted. There is NO hardcoded registry host anywhere.
  * **Blob redirect (the one loosening, mirroring ECR's presign model).** A ``/v2/…/blobs/…`` GET
    on the allowlisted registry host may 3xx to an operator-chosen blob store whose host cannot be
    pre-known. ``registry_blob_get`` follows that redirect ONLY to an HTTPS host that is not an
    SSRF target (link-local / cloud-metadata / loopback are refused). The operator-configured
    registry is trusted to direct us to its own blob store — the same trust ECR's presigned S3
    redirect already relies on — but never to IMDS/metadata.
  * A hard **byte cap**, a **timeout**, **TLS verified** against the system trust store, and a
    **short-read fail-close** (a body below its declared Content-Length aborts) so a truncated blob
    can never reconstruct a false-clean rootfs. Any deviation raises ``LayerFetchError``.
"""
from __future__ import annotations

import ipaddress
import re
import ssl
import urllib.error
import urllib.request
from typing import Dict, Iterable, Optional, Tuple
from urllib.parse import urlparse

# Per-layer/blob hard ceiling — defense against a hostile/huge blob exhausting memory.
MAX_LAYER_BYTES = 500 * 1024 * 1024        # 500 MiB
MAX_META_BYTES = 8 * 1024 * 1024           # manifests + token responses are small
DEFAULT_TIMEOUT = 30.0

_AWS_HOST_SUFFIX = ".amazonaws.com"


class LayerFetchError(Exception):
    """A layer/registry request could not be SAFELY completed — the caller fail-closes the
    whole image rather than reconstructing a partial (false-clean) rootfs."""


def _host(url: str) -> str:
    return (urlparse(url or "").hostname or "").lower()


def _is_https(url: str) -> bool:
    return urlparse(url or "").scheme == "https"


_METADATA_NAMES = ("localhost", "metadata.google.internal", "metadata.goog", "metadata")
_ALIBABA_IMDS = "100.100.100.200"                  # RFC6598 shared space; explicit belt-and-suspenders


def _decode_ip(host: str):
    """Interpret ``host`` as an IP LITERAL in any of the forms a resolver would accept — dotted
    IPv4, IPv6, IPv4-mapped IPv6 (``::ffff:127.0.0.1``), a bare decimal integer (``2130706433``),
    or hex (``0x7f000001``) — returning an ``ipaddress`` object, else None. Textual matching alone
    is not enough: ``getaddrinfo`` maps all of these to the same address, so an SSRF filter must
    normalise before deciding (a dotted-decimal-only blocklist is trivially bypassed)."""
    h = (host or "").strip().strip("[]")
    if not h:
        return None
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if re.fullmatch(r"[0-9]+", h):                 # bare decimal integer IPv4 (e.g. 2130706433)
        try:
            return ipaddress.ip_address(int(h))
        except (ValueError, ipaddress.AddressValueError):
            return None
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", h):      # hex integer (e.g. 0x7f000001)
        try:
            return ipaddress.ip_address(int(h, 16))
        except (ValueError, ipaddress.AddressValueError):
            return None
    return None


def _is_ssrf_target(host: str) -> bool:
    """Hosts a blob-redirect must NEVER reach: cloud metadata + link-local + loopback + any
    private/reserved/unspecified address, in ANY literal encoding. (The operator-configured
    registry host itself is allowlisted per-call and exempt from this — a self-hosted Harbor may
    legitimately be internal; only UNTRUSTED redirect targets are checked.)"""
    h = (host or "").strip().strip("[]").lower()
    if not h or h in _METADATA_NAMES:
        return True
    ip = _decode_ip(h)
    if ip is None:
        return False                               # a normal DNS hostname → allowed (TLS-verified)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped                        # unwrap ::ffff:a.b.c.d to the embedded IPv4
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_unspecified or ip.is_multicast or str(ip) == _ALIBABA_IMDS)


def _host_allowed(url: str, allowed_hosts: Optional[Iterable[str]]) -> bool:
    """HTTPS + host in the per-call allowlist (or the ``.amazonaws.com`` default for ECR).

    PORT-AWARE: an allowlist entry may carry a port (a self-hosted Harbor at ``harbor.corp:5000``
    is configured, and the URL is built, as ``host:port``). We match either the bare hostname or the
    ``host:port`` authority — so a port-qualified registry is NOT spuriously refused (``urlparse``
    strips the port from ``.hostname``), while a redirect to a DIFFERENT host is still rejected."""
    if not _is_https(url):
        return False
    p = urlparse(url or "")
    host = (p.hostname or "").lower()
    if allowed_hosts is None:
        return host.endswith(_AWS_HOST_SUFFIX)
    try:
        port = p.port
    except ValueError:                             # malformed port in the authority → refuse
        return False
    authority = f"{host}:{port}" if port else host
    allow = {a.lower() for a in allowed_hosts}
    return authority in allow or host in allow


class _AllowlistRedirect(urllib.request.HTTPRedirectHandler):
    """Re-apply the https + host-allowlist guard on EVERY 3xx target (a redirect can never escape
    the allowlist). ``allowed_hosts=None`` keeps the ECR ``.amazonaws.com`` guard."""
    def __init__(self, allowed_hosts: Optional[Iterable[str]]):
        self._allowed = None if allowed_hosts is None else {a.lower() for a in allowed_hosts}

    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        if not _host_allowed(newurl, self._allowed):
            return None
        return super().redirect_request(req, fp, code, msg, hdrs, newurl)


class _BlobRedirect(urllib.request.HTTPRedirectHandler):
    """Blob-only redirect policy: follow a 3xx to an HTTPS host that is NOT an SSRF target — the
    operator-trusted registry may direct us to its own (unknowable-in-advance) blob store, exactly
    as ECR redirects to a presigned S3 host, but never to IMDS/metadata/loopback.

    SECURITY: on a CROSS-HOST redirect the ``Authorization`` header is STRIPPED. The registry Bearer
    authorizes ONLY the registry host; a blob store (S3/GCS/Azure Blob) authorizes via presigned
    query params, so the credential must never travel to the redirect target — otherwise a hostile
    registry could 3xx the blob GET to a host it controls and harvest the token. (Python's urllib
    preserves Authorization across redirects before 3.13, so we cannot rely on the stdlib to do it.)"""
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        if not _is_https(newurl) or _is_ssrf_target(_host(newurl)):
            return None
        new = super().redirect_request(req, fp, code, msg, hdrs, newurl)
        if new is not None and _host(newurl) != _host(req.full_url):
            new.remove_header("Authorization")             # never forward the Bearer off-host
        return new


def _read_capped(resp, max_bytes: int) -> bytes:
    data = resp.read(max_bytes + 1)                # one extra byte to detect overflow
    if len(data) > max_bytes:
        raise LayerFetchError(f"response exceeds the {max_bytes}-byte cap")
    # FAIL-CLOSED on a short read: read(amt) does a single readinto and does NOT raise on early EOF,
    # so a dropped connection returns a truncated body -> a corrupt layer. Abort (never partial).
    declared = resp.headers.get("Content-Length")
    if declared is not None:
        try:
            want = int(declared)
        except (TypeError, ValueError):
            want = None
        if want is not None and len(data) < want:
            raise LayerFetchError(f"response truncated: got {len(data)} of {want} bytes")
    return data


def http_get(url: str, *, max_bytes: int = MAX_LAYER_BYTES, timeout: float = DEFAULT_TIMEOUT,
             allowed_hosts: Optional[Iterable[str]] = None,
             headers: Optional[Dict[str, str]] = None) -> bytes:
    """Fetch one layer/manifest blob. HTTPS + host-allowlist only (re-checked on every redirect;
    ``allowed_hosts=None`` → the ECR ``.amazonaws.com`` default), byte-capped, timed out, TLS
    verified, short-read fail-closed. Raises ``LayerFetchError`` on any deviation. ``url`` is a
    runtime value (ECR presign / registry blob URL) — no hardcoded host in this module."""
    if not _host_allowed(url, allowed_hosts):
        if not _is_https(url):
            raise LayerFetchError("layer URL must be https")
        raise LayerFetchError(f"layer host not allowed: {_host(url)!r}")
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        _AllowlistRedirect(allowed_hosts), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return _read_capped(resp, max_bytes)
    except LayerFetchError:
        raise
    except Exception as e:
        raise LayerFetchError(f"layer fetch failed: {e}")


def registry_request(url: str, *, allowed_hosts: Iterable[str], headers: Optional[Dict[str, str]] = None,
                     method: str = "GET", data: Optional[bytes] = None,
                     max_bytes: int = MAX_META_BYTES, timeout: float = DEFAULT_TIMEOUT
                     ) -> Tuple[int, Dict[str, str], bytes]:
    """A Docker Registry v2 control request (``/v2/``, token exchange, manifest GET). Returns
    ``(status, headers, body)`` and does NOT raise on a 4xx — the caller reads a ``401
    WWW-Authenticate`` challenge. HTTPS + strict host-allowlist (no redirect off the allowlist),
    byte-capped, TLS verified. ``allowed_hosts`` is REQUIRED (the config host + challenge realm)."""
    if not _host_allowed(url, allowed_hosts):
        raise LayerFetchError(f"registry host not allowed: {_host(url)!r} (https + allowlist required)")
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        _AllowlistRedirect(allowed_hosts), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, method=method, data=data, headers=headers or {})
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = _read_capped(resp, max_bytes)
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
    except urllib.error.HTTPError as e:            # 4xx/5xx — return the status (read the challenge)
        try:
            body = _read_capped(e, max_bytes)
        except Exception:
            body = b""
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body
    except LayerFetchError:
        raise
    except Exception as e:
        raise LayerFetchError(f"registry request failed: {e}")


def registry_blob_get(url: str, *, headers: Optional[Dict[str, str]] = None,
                      allowed_hosts: Iterable[str], max_bytes: int = MAX_LAYER_BYTES,
                      timeout: float = DEFAULT_TIMEOUT) -> bytes:
    """Fetch an OCI layer blob (``/v2/<repo>/blobs/<digest>``). The INITIAL request must hit an
    allowlisted registry host; a 3xx to the operator's blob store is followed only to an HTTPS host
    that is not an SSRF target (see ``_BlobRedirect``). Byte-capped + short-read fail-closed."""
    if not _host_allowed(url, allowed_hosts):
        raise LayerFetchError(f"blob host not allowed: {_host(url)!r} (https + allowlist required)")
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        _BlobRedirect(), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return _read_capped(resp, max_bytes)
    except LayerFetchError:
        raise
    except Exception as e:
        raise LayerFetchError(f"blob fetch failed: {e}")
