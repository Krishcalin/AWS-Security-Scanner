"""Batch 6 · R1 — aws_registry_oci: the non-AWS Docker Registry v2 (OCI) pull adapter.

Every network call is an injected seam, so the whole Bearer-realm token dance + manifest
resolution + layer pull is exercised with an in-memory mock registry (no socket). One real
gzip-tar layer drives the end-to-end scan_oci_image → scan_pulled_layers reuse path.
"""
import io
import json
import os
import sys
import tarfile
from urllib.parse import urlparse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_registry_oci as OCI
from aws_sidescan_image import ImageFetchUnavailable

_GZIP_LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip"
_OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
_CONFIG = "application/vnd.oci.image.config.v1+json"
_FOREIGN = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
_INDEX = "application/vnd.oci.image.index.v1+json"
_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_CHALLENGE = ('Bearer realm="https://auth.example.com/token",'
              'service="reg.example.com",scope="repository:app:pull"')


def _layer(files):
    """One gzip-tar image layer (bytes) from {relpath: bytes}."""
    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode="w:gz")
    for path, data in files.items():
        ti = tarfile.TarInfo(path)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    tf.close()
    return buf.getvalue()


class MockReg:
    """Stand-in for aws_layer_fetch.registry_request + registry_blob_get.

    manifests: reference -> (manifest_dict, content_digest); blobs: digest -> bytes.
    Records every call's allowed_hosts so the tests can assert the SSRF allowlist wiring.
    """
    def __init__(self, *, needs_auth=True, manifests=None, blobs=None, token="TOK",
                 probe_status=None, token_status=200, tags=None):
        self.needs_auth = needs_auth
        self.manifests = manifests or {}
        self.blobs = blobs or {}
        self.token = token
        self.probe_status = probe_status          # override /v2/ status (e.g. 500)
        self.token_status = token_status
        self.tags = tags or {}                    # repo -> [tag, ...]
        self.requests = []                        # (url, allowed_hosts, headers)
        self.blob_requests = []

    def request(self, url, *, allowed_hosts, headers=None, method="GET", data=None,
                max_bytes=None, timeout=None):
        self.requests.append((url, set(allowed_hosts), dict(headers or {})))
        path = urlparse(url).path
        if path.endswith("/tags/list"):
            repo = path[len("/v2/"):-len("/tags/list")]
            if repo not in self.tags:
                return 404, {}, b""
            return 200, {}, json.dumps({"name": repo, "tags": self.tags[repo]}).encode()
        if "/manifests/" in path:
            ref = path.split("/manifests/", 1)[1]
            if ref not in self.manifests:
                return 404, {}, b""
            man, digest = self.manifests[ref]
            return 200, {"docker-content-digest": digest}, json.dumps(man).encode()
        if path == "/v2/":
            if self.probe_status is not None:
                return self.probe_status, {}, b""
            if self.needs_auth:
                return 401, {"www-authenticate": _CHALLENGE}, b""
            return 200, {}, b""
        if "/token" in path:
            if self.token_status != 200:
                return self.token_status, {}, b""
            return 200, {}, json.dumps({"token": self.token}).encode()
        return 404, {}, b""

    def blob_get(self, url, *, headers=None, allowed_hosts, max_bytes=None, timeout=None):
        self.blob_requests.append((url, set(allowed_hosts), dict(headers or {})))
        digest = urlparse(url).path.split("/blobs/", 1)[1]
        blob = self.blobs[digest]
        if isinstance(blob, Exception):
            raise blob
        return blob


# ── parse_ref ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ref,expected", [
    ("ghcr.io/org/app:1.2.3", ("ghcr.io", "org/app", "1.2.3")),
    ("reg.example.com:5000/team/app", ("reg.example.com:5000", "team/app", "latest")),
    ("reg.example.com:5000/team/app:2.0", ("reg.example.com:5000", "team/app", "2.0")),
    ("alpine", ("registry-1.docker.io", "library/alpine", "latest")),
    ("nginx:1.25", ("registry-1.docker.io", "library/nginx", "1.25")),
    ("org/app", ("registry-1.docker.io", "org/app", "latest")),
    ("library/alpine@sha256:dead", ("registry-1.docker.io", "library/alpine", "sha256:dead")),
    ("GHCR.IO/Org/App:V1", ("ghcr.io", "Org/App", "V1")),        # host lowercased, repo preserved
])
def test_parse_ref(ref, expected):
    assert OCI.parse_ref(ref) == expected


# ── _parse_challenge ──────────────────────────────────────────────────────────
def test_parse_challenge_extracts_params():
    ch = OCI._parse_challenge(_CHALLENGE)
    assert ch["realm"] == "https://auth.example.com/token"
    assert ch["service"] == "reg.example.com"
    assert ch["scope"] == "repository:app:pull"


def test_parse_challenge_non_bearer_is_none():
    assert OCI._parse_challenge('Basic realm="x"') is None
    assert OCI._parse_challenge("") is None


# ── obtain_bearer ─────────────────────────────────────────────────────────────
def test_obtain_bearer_token_dance_and_allowlist():
    reg = MockReg()
    tok = OCI.obtain_bearer("reg.example.com", "app", {"username": "u", "password": "p"},
                            request=reg.request)
    assert tok == "TOK"
    # the token exchange is allowed ONLY the registry host + the realm host learned at runtime
    token_call = next(c for c in reg.requests if "/token" in c[0])
    assert token_call[1] == {"reg.example.com", "auth.example.com"}
    assert token_call[2]["Authorization"].startswith("Basic ")


def test_obtain_bearer_anonymous_registry_returns_none():
    reg = MockReg(needs_auth=False)
    assert OCI.obtain_bearer("reg.example.com", "app", None, request=reg.request) is None


def test_obtain_bearer_supplied_token_short_circuits():
    reg = MockReg()
    assert OCI.obtain_bearer("reg.example.com", "app", {"bearer": "PRESET"},
                             request=reg.request) == "PRESET"
    assert reg.requests == []                     # no network when a token is supplied


def test_obtain_bearer_unexpected_status_raises():
    with pytest.raises(OCI.RegistryAuthError):
        OCI.obtain_bearer("reg.example.com", "app", None,
                          request=MockReg(probe_status=500).request)


def test_obtain_bearer_token_exchange_failure_raises():
    with pytest.raises(OCI.RegistryAuthError):
        OCI.obtain_bearer("reg.example.com", "app", {"username": "u", "password": "bad"},
                          request=MockReg(token_status=401).request)


def test_obtain_bearer_non_https_realm_refused():
    reg = MockReg()
    reg.needs_auth = True

    def bad_request(url, *, allowed_hosts, headers=None, **kw):
        return 401, {"www-authenticate": 'Bearer realm="http://auth.example.com/token"'}, b""

    with pytest.raises(OCI.RegistryAuthError):
        OCI.obtain_bearer("reg.example.com", "app", None, request=bad_request)


# ── fetch_manifest ────────────────────────────────────────────────────────────
def test_fetch_manifest_returns_manifest_and_digest():
    man = {"mediaType": _MANIFEST, "layers": []}
    reg = MockReg(manifests={"v1": (man, "sha256:img")})
    got, digest = OCI.fetch_manifest("reg.example.com", "app", "v1", "TOK", request=reg.request)
    assert got == man and digest == "sha256:img"
    assert reg.requests[0][2]["Authorization"] == "Bearer TOK"


def test_fetch_manifest_error_status_raises():
    reg = MockReg()                               # no manifests registered -> 404
    with pytest.raises(ImageFetchUnavailable):
        OCI.fetch_manifest("reg.example.com", "app", "missing", "TOK", request=reg.request)


# ── pull_layers ───────────────────────────────────────────────────────────────
def test_pull_layers_single_manifest():
    man = {"mediaType": _MANIFEST, "layers": [
        {"mediaType": _CONFIG, "digest": "sha256:cfg"},        # config -> legitimately skipped
        {"mediaType": _GZIP_LAYER, "digest": "sha256:L1"},
        {"mediaType": _FOREIGN, "digest": "sha256:win"}]}      # foreign/non-distributable -> skipped
    reg = MockReg(manifests={"v1": (man, "sha256:img")}, blobs={"sha256:L1": b"LAYER"})
    layers, digest = OCI.pull_layers("reg.example.com/app:v1", None,
                                     request=reg.request, blob_get=reg.blob_get)
    assert layers == [b"LAYER"] and digest == "sha256:img"
    assert reg.blob_requests[0][1] == {"reg.example.com"}       # blob host allowlisted


def test_pull_layers_fail_closed_on_zstd_layer():
    # a zstd rootfs layer cannot be decompressed -> skipping it would be a partial rootfs (false clean)
    man = {"mediaType": _MANIFEST, "layers": [
        {"mediaType": _GZIP_LAYER, "digest": "sha256:L1"},
        {"mediaType": _OCI_LAYER + "+zstd", "digest": "sha256:z"}]}
    reg = MockReg(manifests={"v1": (man, "sha256:img")}, blobs={"sha256:L1": b"LAYER"})
    with pytest.raises(ImageFetchUnavailable):
        OCI.pull_layers("reg.example.com/app:v1", None, request=reg.request, blob_get=reg.blob_get)


def test_pull_layers_fail_closed_on_missing_digest():
    man = {"mediaType": _MANIFEST, "layers": [
        {"mediaType": _GZIP_LAYER, "digest": "sha256:L1"},
        {"mediaType": _GZIP_LAYER}]}                            # rootfs layer with no digest
    reg = MockReg(manifests={"v1": (man, "sha256:img")}, blobs={"sha256:L1": b"LAYER"})
    with pytest.raises(ImageFetchUnavailable):
        OCI.pull_layers("reg.example.com/app:v1", None, request=reg.request, blob_get=reg.blob_get)


def test_pull_layers_fail_closed_when_over_max_layers():
    man = {"mediaType": _MANIFEST, "layers": [
        {"mediaType": _GZIP_LAYER, "digest": f"sha256:L{i}"} for i in range(5)]}
    reg = MockReg(manifests={"v1": (man, "sha256:img")},
                  blobs={f"sha256:L{i}": b"X" for i in range(5)})
    with pytest.raises(ImageFetchUnavailable):
        OCI.pull_layers("reg.example.com/app:v1", None, request=reg.request,
                        blob_get=reg.blob_get, max_layers=3)


def test_pull_layers_budget_caps_peak_and_fails_closed():
    man = {"mediaType": _MANIFEST, "layers": [
        {"mediaType": _GZIP_LAYER, "digest": "sha256:L1"},
        {"mediaType": _GZIP_LAYER, "digest": "sha256:L2"}]}
    reg = MockReg(manifests={"v1": (man, "sha256:img")},
                  blobs={"sha256:L1": b"X" * 40, "sha256:L2": b"Y" * 40})
    with pytest.raises(ImageFetchUnavailable):
        OCI.pull_layers("reg.example.com/app:v1", None, request=reg.request,
                        blob_get=reg.blob_get, max_image_bytes=50)   # 40 + 40 > 50
    # the per-blob max_bytes cap was threaded so a single blob cannot exceed the remaining budget
    assert all(c[0] for c in reg.blob_requests)


def test_pull_layers_resolves_manifest_list_to_linux_child():
    index = {"mediaType": _INDEX, "manifests": [
        {"platform": {"os": "windows", "architecture": "amd64"}, "digest": "sha256:win"},
        {"platform": {"os": "linux", "architecture": "amd64"}, "digest": "sha256:child"}]}
    child = {"mediaType": _MANIFEST, "layers": [{"mediaType": _GZIP_LAYER, "digest": "sha256:L1"}]}
    reg = MockReg(manifests={"v1": (index, "sha256:idx"), "sha256:child": (child, "sha256:child")},
                  blobs={"sha256:L1": b"LAYER"})
    layers, digest = OCI.pull_layers("reg.example.com/app:v1", {"bearer": "T"},
                                     request=reg.request, blob_get=reg.blob_get)
    assert layers == [b"LAYER"] and digest == "sha256:child"


def test_pull_layers_no_linux_child_returns_empty():
    index = {"mediaType": _INDEX, "manifests": [
        {"platform": {"os": "windows", "architecture": "amd64"}, "digest": "sha256:win"}]}
    reg = MockReg(manifests={"v1": (index, "sha256:idx")})
    notes = []
    layers, _ = OCI.pull_layers("reg.example.com/app:v1", {"bearer": "T"},
                                request=reg.request, blob_get=reg.blob_get, notes=notes)
    assert layers == [] and any("no linux/amd64" in n for n in notes)


def test_pull_layers_fail_closed_on_blob_failure():
    man = {"mediaType": _MANIFEST, "layers": [{"mediaType": _GZIP_LAYER, "digest": "sha256:L1"}]}
    reg = MockReg(manifests={"v1": (man, "sha256:img")},
                  blobs={"sha256:L1": RuntimeError("connection reset")})
    with pytest.raises(ImageFetchUnavailable):
        OCI.pull_layers("reg.example.com/app:v1", {"bearer": "T"},
                        request=reg.request, blob_get=reg.blob_get)


# ── list_tags (enumeration, newest-first, fail-open) ──────────────────────────
def test_list_tags_orders_newest_first_bounded():
    reg = MockReg(tags={"app": ["1.2", "1.10", "1.9", "latest"]})
    # 'latest' pinned first, then version-ish DESC (1.10 > 1.9 > 1.2) — NOT alphabetical
    assert OCI.list_tags("reg.example.com", "app", "TOK", request=reg.request) == \
        ["latest", "1.10", "1.9", "1.2"]
    assert OCI.list_tags("reg.example.com", "app", "TOK", request=reg.request, max_tags=2) == \
        ["latest", "1.10"]


def test_list_tags_fail_open_on_missing_repo():
    reg = MockReg()                               # no tags registered -> 404
    assert OCI.list_tags("reg.example.com", "nope", "TOK", request=reg.request) == []


# ── scan_oci_image (end-to-end reuse of scan_pulled_layers) ───────────────────
def test_scan_oci_image_builds_components():
    layer = _layer({"app/node_modules/lodash/package.json":
                    b'{"name":"lodash","version":"4.17.20"}'})
    man = {"mediaType": _MANIFEST, "layers": [{"mediaType": _GZIP_LAYER, "digest": "sha256:L1"}]}
    reg = MockReg(needs_auth=False, manifests={"v1": (man, "sha256:img")},
                  blobs={"sha256:L1": layer})
    notes = []
    r = OCI.scan_oci_image("reg.example.com/app:v1", None, request=reg.request,
                           blob_get=reg.blob_get, feed=None, epss={}, kev=frozenset(), notes=notes)
    assert r.ok is True
    assert r.node_id == "reg.example.com/app@sha256:img"
    assert "lodash" in {c.name for c in r.components}
    assert r.doc_id and r.doc_id.startswith("ecr-sidescan:")


def test_scan_oci_image_pull_failure_returns_not_ok():
    man = {"mediaType": _MANIFEST, "layers": [{"mediaType": _GZIP_LAYER, "digest": "sha256:L1"}]}
    reg = MockReg(needs_auth=False, manifests={"v1": (man, "sha256:img")},
                  blobs={"sha256:L1": RuntimeError("AccessDenied")})
    notes = []
    r = OCI.scan_oci_image("reg.example.com/app:v1", None, request=reg.request,
                           blob_get=reg.blob_get, feed=None, epss={}, kev=frozenset(), notes=notes)
    assert r.ok is False and r.result is None and r.components == []
    assert r.note.startswith("pull-failed:")
    assert notes


def test_scan_oci_image_auth_failure_returns_not_ok():
    reg = MockReg(token_status=403)               # 401 challenge, then token exchange denied
    r = OCI.scan_oci_image("reg.example.com/app:v1", {"username": "u", "password": "bad"},
                           request=reg.request, blob_get=reg.blob_get, feed=None, epss={},
                           kev=frozenset())
    assert r.ok is False and r.note.startswith("pull-failed:")
