"""Batch 6 · R2 — aws_registry_connectors: the non-AWS registry connector config layer.

Config-boundary validation, host qualification, secret-ref → creds shaping (transient, never
persisted), and the API mask. Pure: the SecretReader is an injected callable, no socket.
"""
import io
import json
import os
import sys
import tarfile
from urllib.parse import urlparse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_registry_connectors as RC


def _reader(mapping):
    def read(ref):
        if ref not in mapping:
            raise KeyError(ref)
        return mapping[ref]
    return read


def _layer(files):
    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode="w:gz")
    for path, data in files.items():
        ti = tarfile.TarInfo(path)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    tf.close()
    return buf.getvalue()


_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_GZIP_LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip"


class MockReg:
    """Anonymous mock registry serving /v2/, tags, manifests, and blobs for scan_connector."""
    def __init__(self, *, manifests=None, blobs=None, tags=None):
        self.manifests = manifests or {}
        self.blobs = blobs or {}
        self.tags = tags or {}

    def request(self, url, *, allowed_hosts, headers=None, method="GET", data=None,
                max_bytes=None, timeout=None):
        path = urlparse(url).path
        if path == "/v2/":
            return 200, {}, b""                   # anonymous
        if path.endswith("/tags/list"):
            repo = path[len("/v2/"):-len("/tags/list")]
            return (200, {}, json.dumps({"tags": self.tags.get(repo, [])}).encode())
        if "/manifests/" in path:
            ref = path.split("/manifests/", 1)[1]
            if ref not in self.manifests:
                return 404, {}, b""
            man, digest = self.manifests[ref]
            return 200, {"docker-content-digest": digest}, json.dumps(man).encode()
        return 404, {}, b""

    def blob_get(self, url, *, headers=None, allowed_hosts, max_bytes=None, timeout=None):
        return self.blobs[urlparse(url).path.split("/blobs/", 1)[1]]


# ── parse_connector: happy paths ──────────────────────────────────────────────
def test_ghcr_default_host_and_token_auth():
    rc = RC.parse_connector({"connector_id": "gh", "type": "ghcr",
                             "secret_ref": "secretsmanager://ghcr-pat", "images": ["org/app:1.0"]})
    assert rc.host == "ghcr.io" and rc.auth == "token"
    assert RC.image_refs(rc) == ["ghcr.io/org/app:1.0"]


def test_dockerhub_default_host_basic_auth():
    rc = RC.parse_connector({"connector_id": "dh", "type": "dockerhub", "username": "acme",
                             "secret_ref": "ssm://dh-pat"})
    assert rc.host == "registry-1.docker.io" and rc.auth == "basic" and rc.username == "acme"


def test_harbor_requires_explicit_host():
    rc = RC.parse_connector({"connector_id": "hb", "type": "harbor", "host": "harbor.corp.internal",
                             "username": "robot$scanner", "secret_ref": "ssm://harbor"})
    assert rc.host == "harbor.corp.internal" and rc.auth == "basic"


def test_acr_service_principal_is_plain_basic():
    # ACR accepts an SP's client-id/secret directly as Basic (docker login -u <id> -p <secret>),
    # so it is the SAME generic dance — no special adapter, just basic auth.
    rc = RC.parse_connector({"connector_id": "acr", "type": "acr", "host": "myreg.azurecr.io",
                             "username": "00000000-0000-0000-0000-000000000000",
                             "secret_ref": "secretsmanager://acr-sp"})
    assert rc.auth == "basic" and rc.host == "myreg.azurecr.io"


def test_anonymous_public_registry():
    rc = RC.parse_connector({"connector_id": "pub", "type": "dockerhub", "images": ["library/alpine"]})
    assert rc.auth == "anonymous" and rc.secret_ref is None


# ── parse_connector: rejects (config boundary) ────────────────────────────────
@pytest.mark.parametrize("bad", [
    {},                                                             # no id
    {"connector_id": "x", "type": "quay"},                          # unknown type
    {"connector_id": "x", "type": "harbor"},                        # host required
    {"connector_id": "x", "type": "harbor", "host": "https://h/x"}, # scheme/path in host
    {"connector_id": "x", "type": "ghcr", "auth": "basic", "secret_ref": "ssm://p"},  # basic w/o user
    {"connector_id": "x", "type": "ghcr", "auth": "token"},         # token w/o secret_ref
    {"connector_id": "x", "type": "ghcr", "secret_ref": "vault://p"},  # non-resolvable scheme
    {"connector_id": "x", "type": "ghcr", "newest_n": "many"},      # bad int
])
def test_parse_rejects_malformed(bad):
    with pytest.raises(RC.RegistryConnectorError):
        RC.parse_connector(bad)


# ── load_connectors: fail-safe skip + dedup ───────────────────────────────────
def test_load_skips_bad_and_dedupes():
    raw = {"registries": [
        {"connector_id": "ok", "type": "ghcr", "images": ["o/a"]},
        {"connector_id": "bad", "type": "quay"},                    # dropped
        {"connector_id": "ok", "type": "dockerhub"},                # dup id -> dropped
    ]}
    got = RC.load_connectors(raw)
    assert [c.connector_id for c in got] == ["ok"]
    assert got[0].type == "ghcr"                                    # first wins


# ── qualify_ref ───────────────────────────────────────────────────────────────
def test_qualify_ref_prefixes_host_and_is_idempotent():
    rc = RC.parse_connector({"connector_id": "hb", "type": "harbor", "host": "harbor.corp",
                             "images": []})
    assert RC.qualify_ref(rc, "team/app:1.0") == "harbor.corp/team/app:1.0"
    assert RC.qualify_ref(rc, "harbor.corp/team/app:1.0") == "harbor.corp/team/app:1.0"
    # an already-registry-qualified ref (dot in first segment) is left alone
    assert RC.qualify_ref(rc, "other.reg/x:1") == "other.reg/x:1"
    # SECURITY: a single-segment TAGGED image must qualify to the connector host — a tag colon must
    # NOT be mistaken for a host:port colon (else it would route to Docker Hub, leaking the cred).
    assert RC.qualify_ref(rc, "backend:prod") == "harbor.corp/backend:prod"
    assert RC.qualify_ref(rc, "backend@sha256:dead") == "harbor.corp/backend@sha256:dead"
    assert RC.qualify_ref(rc, "backend") == "harbor.corp/backend"


# ── resolve_creds (transient secret) ──────────────────────────────────────────
def test_resolve_creds_basic():
    rc = RC.parse_connector({"connector_id": "dh", "type": "dockerhub", "username": "acme",
                             "secret_ref": "ssm://dh"})
    creds = RC.resolve_creds(rc, secret_reader=_reader({"ssm://dh": "s3cr3t-token"}))
    assert creds == {"username": "acme", "password": "s3cr3t-token"}


def test_resolve_creds_token():
    rc = RC.parse_connector({"connector_id": "gh", "type": "ghcr", "secret_ref": "ssm://gh"})
    creds = RC.resolve_creds(rc, secret_reader=_reader({"ssm://gh": "ghp_xxx"}))
    assert creds == {"bearer": "ghp_xxx"}


def test_resolve_creds_anonymous_is_none():
    rc = RC.parse_connector({"connector_id": "pub", "type": "dockerhub"})
    assert RC.resolve_creds(rc, secret_reader=_reader({})) is None


def test_resolve_creds_empty_secret_fails_closed():
    rc = RC.parse_connector({"connector_id": "gh", "type": "ghcr", "secret_ref": "ssm://gh"})
    with pytest.raises(RC.RegistryConnectorError):
        RC.resolve_creds(rc, secret_reader=_reader({"ssm://gh": ""}))


# ── scan_connector (impure boundary, injected seams) ──────────────────────────
def _one_image_reg(repo="team/app", tag="v1", pkg="lodash", version="4.17.20"):
    layer = _layer({f"app/node_modules/{pkg}/package.json":
                    json.dumps({"name": pkg, "version": version}).encode()})
    man = {"mediaType": _MANIFEST, "layers": [{"mediaType": _GZIP_LAYER, "digest": "sha256:L1"}]}
    return MockReg(manifests={tag: (man, "sha256:img"), "sha256:img": (man, "sha256:img")},
                  blobs={"sha256:L1": layer}, tags={repo: [tag]})


def test_scan_connector_explicit_image():
    rc = RC.parse_connector({"connector_id": "hb", "type": "harbor", "host": "harbor.corp",
                             "enabled": True, "images": ["team/app:v1"]})
    reg = _one_image_reg()
    notes = []
    out = RC.scan_connector(rc, request=reg.request, blob_get=reg.blob_get,
                            secret_reader=_reader({}), feed=None, epss={}, kev=frozenset(),
                            notes=notes)
    assert len(out) == 1
    ref, res = out[0]
    assert ref == "harbor.corp/team/app:v1" and res.ok is True
    assert "lodash" in {c.name for c in res.components}
    view = RC.registry_image_view(rc, ref, res)
    assert view["deployed"] is False
    assert view["scan_sources"] == ["oci-sidescan:harbor"]
    assert view["registry_type"] == "harbor" and view["digest"] == "sha256:img"
    assert view["repository"] == "team/app"


def test_scan_connector_enumerates_repositories_newest_first_bounded():
    rc = RC.parse_connector({"connector_id": "hb", "type": "harbor", "host": "harbor.corp",
                             "enabled": True, "repositories": ["team/app"], "newest_n": 1})
    reg = _one_image_reg(tag="v3")                 # the manifest is served for whatever tag is requested
    reg.tags = {"team/app": ["v1", "v2", "v3"]}    # newest_n=1 -> the NEWEST (v3), not alphabetical v1
    out = RC.scan_connector(rc, request=reg.request, blob_get=reg.blob_get,
                            secret_reader=_reader({}), feed=None, epss={}, kev=frozenset())
    assert [r for r, _ in out] == ["harbor.corp/team/app:v3"]


def test_scan_connector_refuses_host_mismatch():
    # a ref that resolves to a host other than the connector host must be REFUSED (never pulled),
    # so the connector credential can never travel to a third-party registry.
    rc = RC.parse_connector({"connector_id": "gh", "type": "ghcr", "enabled": True,
                             "images": ["ghcr.io/org/app:v1", "docker.io/evil/app:v1"]})
    reg = _one_image_reg()
    notes = []
    out = RC.scan_connector(rc, request=reg.request, blob_get=reg.blob_get,
                            secret_reader=_reader({}), feed=None, epss={}, kev=frozenset(), notes=notes)
    assert [r for r, _ in out] == ["ghcr.io/org/app:v1"]           # only the on-host ref pulled
    assert any("refusing" in n and "docker.io/evil/app" in n for n in notes)


def test_scan_connector_disabled_scans_nothing():
    rc = RC.parse_connector({"connector_id": "hb", "type": "harbor", "host": "harbor.corp",
                             "enabled": False, "images": ["team/app:v1"]})
    out = RC.scan_connector(rc, request=_one_image_reg().request, blob_get=lambda *a, **k: b"",
                            secret_reader=_reader({}), feed=None, epss={}, kev=frozenset())
    assert out == []


def test_scan_connector_secret_store_error_is_safe_noop():
    # a secret_reader that RAISES (missing/denied secret in a real store) must not crash the sweep
    rc = RC.parse_connector({"connector_id": "gh", "type": "ghcr", "enabled": True,
                             "secret_ref": "ssm://gh", "images": ["org/app:v1"]})
    def boom(_ref):
        raise RuntimeError("AccessDeniedException")
    notes = []
    out = RC.scan_connector(rc, request=_one_image_reg().request, blob_get=lambda *a, **k: b"",
                            secret_reader=boom, feed=None, epss={}, kev=frozenset(), notes=notes)
    assert out == [] and any("secret store error" in n for n in notes)
    assert not any("AccessDenied" in n for n in notes)          # raw exception text not leaked


def test_scan_connector_missing_secret_notes_and_skips():
    rc = RC.parse_connector({"connector_id": "gh", "type": "ghcr", "enabled": True,
                             "secret_ref": "ssm://gh", "images": ["org/app:v1"]})
    notes = []
    out = RC.scan_connector(rc, request=_one_image_reg().request, blob_get=lambda *a, **k: b"",
                            secret_reader=_reader({"ssm://gh": ""}),   # resolves empty -> fail-closed
                            feed=None, epss={}, kev=frozenset(), notes=notes)
    assert out == [] and any("credential unavailable" in n for n in notes)


# ── mask_connector (no secret leakage) ────────────────────────────────────────
def test_mask_drops_secret_ref():
    rc = RC.parse_connector({"connector_id": "gh", "type": "ghcr", "secret_ref": "ssm://gh-pat"})
    m = RC.mask_connector(rc)
    assert m["secret_configured"] is True
    assert "secret_ref" not in m and "ssm://gh-pat" not in str(m)
