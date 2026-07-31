#!/usr/bin/env python3
"""aws_registry_oci.py — Docker Registry v2 (OCI) pull adapter for NON-AWS registries.

The agentless side-scan already speaks OCI for ECR; this generalizes the PULL half to registries
that speak the standard Docker Registry v2 HTTP API — GitHub GHCR, Docker Hub, Harbor, Azure ACR —
via the Bearer-realm token dance. Everything downstream of "here are the layer bytes" is REUSED
unchanged (``aws_registry_sbom.scan_pulled_layers`` → rootfs → OSV/secrets → CycloneDX snapshot →
diff/license/VEX), so ``aws_correlate`` stays byte-frozen and the fail-closed contract can't diverge.

PURE: every network call goes through INJECTED seams — ``request`` (aws_layer_fetch.registry_request:
token + manifest, returns status/headers/body, no raise on 4xx) and ``blob_get``
(aws_layer_fetch.registry_blob_get: layer blobs, byte-capped, SSRF-guarded redirect) — so the whole
token-dance + manifest + layer-pull is mock-testable up to the network boundary. NO hardcoded
registry host: the registry host is operator-config, the auth realm host is read at runtime from the
``WWW-Authenticate`` challenge. GCR / Google Artifact Registry is DEFERRED (its OAuth needs RS256
JWT signing, and the air-gap wheelhouse intentionally ships no ``cryptography``).
"""
from __future__ import annotations

import base64
import json
import re
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

import aws_registry_sbom
from aws_sidescan_image import (ImageFetchUnavailable, _CONFIG_TYPES, _MANIFEST_LIST_TYPES,
                                _MANIFEST_TYPES, _SKIP_LAYER_TYPES, _select_child_digest)

_DOCKERHUB_HOST = "registry-1.docker.io"


class RegistryAuthError(Exception):
    """The Registry v2 token dance failed (bad creds / unexpected challenge). Never a false-clean."""


# ── image-reference parsing ───────────────────────────────────────────────────
def parse_ref(ref: str) -> Tuple[str, str, str]:
    """``[host[:port]/]repository[:tag|@digest]`` → ``(host, repository, reference)``. A first
    segment containing ``.``/``:``/``localhost`` is the registry host; otherwise Docker Hub is
    assumed and a single-name repo is namespaced under ``library/``. Default reference ``latest``."""
    s = (ref or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    reference = "latest"
    if "@" in s:                                       # digest pin
        s, reference = s.rsplit("@", 1)
    elif ":" in s.rsplit("/", 1)[-1]:                  # a tag colon lives in the LAST path segment
        s, reference = s.rsplit(":", 1)
    first = s.split("/", 1)[0]
    if "/" in s and ("." in first or ":" in first or first == "localhost"):
        host, repo = s.split("/", 1)
    else:
        host, repo = _DOCKERHUB_HOST, s
        if "/" not in repo:
            repo = "library/" + repo                   # docker official images
    return host.lower(), repo, reference


# ── the Bearer-realm token dance (GHCR / Docker Hub / Harbor / ACR-admin) ──────
def _parse_challenge(header: str) -> Optional[Dict[str, str]]:
    if not header or not header.strip().lower().startswith("bearer "):
        return None
    return {m.group(1).lower(): m.group(2) for m in re.finditer(r'(\w+)="([^"]*)"', header)}


def obtain_bearer(host: str, repository: str, creds: Optional[dict], *,
                  request: Callable) -> Optional[str]:
    """Resolve a pull Bearer token: probe ``/v2/``; on ``401`` read the ``WWW-Authenticate``
    challenge, exchange the operator's Basic credential (or anonymously) at the challenge realm for
    a pull-scoped token. Returns None when the registry needs no auth. Raises RegistryAuthError."""
    creds = creds or {}
    if creds.get("bearer"):                            # operator-supplied token (e.g. short-lived)
        return str(creds["bearer"])
    status, headers, _ = request(f"https://{host}/v2/", allowed_hosts={host})
    if status == 200:
        return None
    if status != 401:
        raise RegistryAuthError(f"unexpected /v2/ status {status}")
    ch = _parse_challenge(headers.get("www-authenticate", ""))
    realm = (ch or {}).get("realm")
    if not realm or urlparse(realm).scheme != "https":
        raise RegistryAuthError("no https Bearer realm in the auth challenge")
    realm_host = (urlparse(realm).hostname or "").lower()
    scope = (ch.get("scope") or f"repository:{repository}:pull")
    q = urlencode([(k, v) for k, v in (("service", ch.get("service", "")), ("scope", scope)) if v])
    token_url = realm + (("&" if "?" in realm else "?") + q if q else "")
    req_headers: Dict[str, str] = {}
    if creds.get("username") is not None:
        basic = base64.b64encode(f"{creds['username']}:{creds.get('password', '')}".encode()).decode()
        req_headers["Authorization"] = "Basic " + basic
    status2, _, body = request(token_url, allowed_hosts={host, realm_host}, headers=req_headers)
    if status2 != 200:
        raise RegistryAuthError(f"token exchange failed ({status2}) at the auth realm")
    try:
        tok = json.loads(body or b"{}")
    except Exception:
        raise RegistryAuthError("auth response was not JSON")
    bearer = tok.get("token") or tok.get("access_token")
    if not bearer:
        raise RegistryAuthError("no token in the auth response")
    return str(bearer)


# ── manifest + layer pull ──────────────────────────────────────────────────────
def fetch_manifest(host: str, repository: str, reference: str, bearer: Optional[str], *,
                   request: Callable) -> Tuple[dict, str]:
    """GET ``/v2/<repo>/manifests/<ref>`` → ``(manifest, content_digest)`` (the digest from the
    ``Docker-Content-Digest`` header, for a stable node/SBOM identity)."""
    headers = {"Accept": ", ".join(list(_MANIFEST_LIST_TYPES) + _MANIFEST_TYPES)}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    status, resp_headers, body = request(
        f"https://{host}/v2/{repository}/manifests/{reference}", allowed_hosts={host}, headers=headers)
    if status != 200:
        raise ImageFetchUnavailable(f"manifest {reference} status {status}")
    try:
        man = json.loads(body or b"{}")
    except Exception:
        raise ImageFetchUnavailable("manifest was not JSON")
    return man, (resp_headers.get("docker-content-digest") or "")


_MOVING_TAGS = ("latest", "stable", "release", "current", "edge", "main")


def _tag_recency_key(tag: str):
    """A best-effort 'newest-first' sort key (higher = newer). The Registry v2 ``/tags/list`` gives
    NO push timestamp, so we approximate: moving tags (``latest``/``stable``/…) rank highest, then
    version-ish tags by their numeric components DESCENDING (so ``1.10`` > ``1.9`` > ``1.2``), then
    everything else. Used with ``reverse=True``. This is a heuristic, not a true chronological order
    — but it matches operator intent for the common semver/moving-tag repo far better than the
    alphabetical order the raw list arrives in (where ``latest`` and high versions sort LAST)."""
    t = tag.lower()
    if t in _MOVING_TAGS:
        return (3, ())
    nums = tuple(int(x) for x in re.findall(r"\d+", tag)[:8])
    if nums:
        return (2, nums)
    return (1, ())


def list_tags(host: str, repository: str, bearer: Optional[str], *, request: Callable,
              max_tags: int = 500) -> List[str]:
    """Enumerate a repo's tags via ``GET /v2/<repo>/tags/list``, ordered BEST-EFFORT newest-first
    (see ``_tag_recency_key``) and bounded to ``max_tags`` — so a downstream ``[:newest_n]`` slice
    picks the newest N, not the alphabetically-first N. FAIL-OPEN — an error / non-200 returns ``[]``
    (nothing enumerated, honest) rather than raising: enumeration is a convenience over explicit
    refs, never a source of a false-clean scan."""
    headers = {"Authorization": "Bearer " + bearer} if bearer else {}
    try:
        status, _, body = request(f"https://{host}/v2/{repository}/tags/list",
                                  allowed_hosts={host}, headers=headers)
        if status != 200:
            return []
        data = json.loads(body or b"{}")
    except Exception:
        return []
    tags = [str(t) for t in (data.get("tags") or []) if str(t).strip()]
    # sort by recency DESC, tie-broken by tag text DESC, for a deterministic newest-first order
    ordered = sorted(tags, key=lambda t: (_tag_recency_key(t), t), reverse=True)
    return ordered[:max(1, max_tags)]


def pull_layers(ref: str, creds: Optional[dict], *, request: Callable, blob_get: Callable,
                max_layers: int = 200, max_image_bytes: Optional[int] = None,
                notes: Optional[List[str]] = None) -> Tuple[List[bytes], str]:
    """Return ``(ordered rootfs layer bytes, resolved image digest)`` for the OCI image ``ref``.
    Resolves a manifest list to its linux/amd64 child. Config + foreign/non-distributable layers are
    legitimately NOT part of a linux rootfs and are skipped.

    FAIL-CLOSED on anything that would leave a PARTIAL rootfs scanned as clean — because the manifest
    is served by an UNTRUSTED registry (unlike ECR's first-party manifest). A zstd layer we cannot
    decompress (tarfile has no zstd codec, and the air-gap wheelhouse ships none), a rootfs layer
    entry with no digest, a manifest declaring MORE than ``max_layers`` layers, or a failed blob all
    raise ImageFetchUnavailable rather than silently dropping bytes (which merge_layers could not see
    → an empty package DB would read as a false-clean). A running ``max_image_bytes`` budget caps
    peak memory so a hostile registry cannot make us buffer an unbounded image before the size gate."""
    host, repository, reference = parse_ref(ref)
    bearer = obtain_bearer(host, repository, creds, request=request)
    man, digest = fetch_manifest(host, repository, reference, bearer, request=request)
    if man.get("mediaType") in _MANIFEST_LIST_TYPES or "manifests" in man:
        child = _select_child_digest(man)
        if not child:
            if notes is not None:
                notes.append("no linux/amd64 child manifest")
            return [], (digest or reference)
        man, child_digest = fetch_manifest(host, repository, child, bearer, request=request)
        digest = child_digest or child
    resolved = digest or (reference if reference.startswith("sha256:") else "")
    raw = man.get("layers", []) or []
    if len(raw) > max_layers:                          # truncating would silently drop a rootfs layer
        raise ImageFetchUnavailable(
            f"manifest declares {len(raw)} layers (> max_layers={max_layers}) — refusing a truncated rootfs")
    layers: List[bytes] = []
    budget = max_image_bytes
    hdrs = {"Authorization": "Bearer " + bearer} if bearer else {}
    for layer in raw:
        lmt = layer.get("mediaType", "")
        if lmt in _CONFIG_TYPES or lmt in _SKIP_LAYER_TYPES:
            continue                                   # config / foreign — not a linux rootfs layer
        if lmt.endswith("+zstd"):                      # cannot decompress → would be a partial rootfs
            raise ImageFetchUnavailable(
                f"zstd layer cannot be decompressed (partial rootfs): {layer.get('digest')}")
        ld = layer.get("digest")
        if not ld:                                     # a rootfs layer with no digest → malformed manifest
            raise ImageFetchUnavailable("rootfs layer entry has no digest — refusing a partial rootfs")
        try:
            url = f"https://{host}/v2/{repository}/blobs/{ld}"
            b = (blob_get(url, headers=hdrs, allowed_hosts={host}) if budget is None
                 else blob_get(url, headers=hdrs, allowed_hosts={host}, max_bytes=max(1, budget + 1)))
        except ImageFetchUnavailable:
            raise
        except Exception as e:
            raise ImageFetchUnavailable(f"layer blob fetch failed ({ld}): {e}")
        layers.append(b)
        if budget is not None:
            budget -= len(b)
            if budget < 0:                             # bounds PEAK memory, not just the post-fetch total
                raise ImageFetchUnavailable("image exceeds max_image_bytes — refusing (fail-closed)")
    return layers, resolved


def scan_oci_image(ref: str, creds: Optional[dict], *, request: Callable, blob_get: Callable,
                   feed, epss, kev, exploits=frozenset(), max_layers: int = 200,
                   max_image_bytes: Optional[int] = None, do_secrets: bool = True,
                   notes: Optional[List[str]] = None):
    """Pull an OCI image from a non-AWS registry and run the SHARED rootfs+OSV scan. Never raises:
    a pull/auth failure returns an ``ok=False`` RegistryImageResult with a note (the caller keeps
    any native findings), exactly like the ECR ``scan_registry_image`` contract."""
    host, repository, reference = parse_ref(ref)
    n = notes if notes is not None else []
    repo_uri = f"{host}/{repository}"

    def _fail(node_id, note):
        return aws_registry_sbom.RegistryImageResult(reference, [reference], node_id, False, None, [], None, note)

    try:
        layers, digest = pull_layers(ref, creds, request=request, blob_get=blob_get,
                                     max_layers=max_layers, max_image_bytes=max_image_bytes, notes=n)
    except (ImageFetchUnavailable, RegistryAuthError) as e:
        n.append(f"{repo_uri}:{reference} pull incomplete (fail-closed): {e}")
        return _fail(f"{repo_uri}:{reference}", f"pull-failed: {e}")
    except Exception as e:                              # denial / unexpected — never a partial scan
        n.append(f"{repo_uri}:{reference} denied/unavailable: {e}")
        return _fail(f"{repo_uri}:{reference}", f"denied: {e}")
    id_digest = digest or reference
    node_id = f"{repo_uri}@{digest}" if digest else f"{repo_uri}:{reference}"
    return aws_registry_sbom.scan_pulled_layers(
        layers, repo=repository, repo_uri=repo_uri, digest=id_digest, tags=[reference],
        node_id=node_id, feed=feed, epss=epss, kev=kev, exploits=exploits,
        max_image_bytes=max_image_bytes, do_secrets=do_secrets, notes=n)
