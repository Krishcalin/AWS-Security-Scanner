"""Batch 6 · R3 — PlatformService non-AWS registry connector wiring: list (secret-masked),
scan (agentless pull + side-scan via injected egress seams), cached image rows, and the
/registries* routes. The egress seams (registry_request / registry_blob_get) are injected fakes,
so no socket is touched and the whole flow is offline. Config-driven — no DB schema."""
import io
import json
import os
import sys
import tarfile
from urllib.parse import urlparse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_state
import cnapp_connectors as cc
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_GZIP_LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def _layer(files):
    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode="w:gz")
    for path, data in files.items():
        ti = tarfile.TarInfo(path)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    tf.close()
    return buf.getvalue()


class _Reg:
    """Anonymous mock registry (one image with a lodash package) for the injected seams."""
    def __init__(self):
        layer = _layer({"app/node_modules/lodash/package.json":
                        b'{"name":"lodash","version":"4.17.20"}'})
        man = {"mediaType": _MANIFEST, "layers": [{"mediaType": _GZIP_LAYER, "digest": "sha256:L1"}]}
        self._man = (man, "sha256:img")
        self._blob = layer

    def request(self, url, *, allowed_hosts, headers=None, method="GET", data=None,
                max_bytes=None, timeout=None):
        path = urlparse(url).path
        if path == "/v2/":
            return 200, {}, b""
        if "/manifests/" in path:
            man, digest = self._man
            return 200, {"docker-content-digest": digest}, json.dumps(man).encode()
        return 404, {}, b""

    def blob_get(self, url, *, headers=None, allowed_hosts, max_bytes=None, timeout=None):
        return self._blob


GHCR_CONN = {"connector_id": "ghcr-main", "type": "ghcr", "enabled": True,
             "secret_ref": "ssm://ghcr", "images": ["org/app:v1"]}
PUB_CONN = {"connector_id": "pub", "type": "harbor", "host": "harbor.corp", "enabled": True,
            "images": ["team/api:1.0"]}
DISABLED_CONN = {"connector_id": "off", "type": "dockerhub", "images": ["library/nginx"]}


def _svc(connectors, *, reg=None):
    r = AccountRegistry.open(":memory:")
    reg = reg or _Reg()
    return PlatformService(
        registry=r, results=InMemoryResultStore(), hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "x", secret_reader=lambda ref: "tok",
        connectors=cc.ConnectorStore(r._be), state=aws_state.StateStore(r._be),
        registry_connectors=connectors,
        registry_request=reg.request, registry_blob_get=reg.blob_get, clock=lambda: 5000)


# ── list (secret-masked, config-driven) ───────────────────────────────────────
def test_list_connectors_masks_secret_and_precedes_scan():
    svc = _svc([GHCR_CONN, DISABLED_CONN])
    rows = {r["connector_id"]: r for r in svc.list_registry_connectors()}
    assert rows["ghcr-main"]["secret_configured"] is True
    assert "secret_ref" not in rows["ghcr-main"] and "ssm://ghcr" not in str(rows)
    assert rows["ghcr-main"]["host"] == "ghcr.io"
    assert rows["ghcr-main"]["last_scan"] is None                 # nothing scanned yet
    assert rows["off"]["enabled"] is False


def test_bad_connector_dropped_on_load():
    svc = _svc([GHCR_CONN, {"connector_id": "x", "type": "quay"}])  # unknown type dropped
    assert [r["connector_id"] for r in svc.list_registry_connectors()] == ["ghcr-main"]


# ── scan (agentless pull + side-scan via injected seams) ──────────────────────
def test_scan_connector_pulls_and_sidescans():
    svc = _svc([GHCR_CONN])
    res = svc.scan_registry_connector("ghcr-main")
    assert len(res["images"]) == 1
    im = res["images"][0]
    assert im["ok"] is True and im["deployed"] is False
    assert im["scan_sources"] == ["oci-sidescan:ghcr"]
    assert im["components"] >= 1 and im["digest"] == "sha256:img"
    # cached: a subsequent list carries the last-scan summary + images endpoint returns the row
    rows = {r["connector_id"]: r for r in svc.list_registry_connectors()}
    assert rows["ghcr-main"]["last_scan"]["images"] == 1
    assert svc.list_registry_connector_images("ghcr-main")[0]["node_id"] == im["node_id"]


def test_scan_unknown_connector_is_safe_noop():
    svc = _svc([GHCR_CONN])
    res = svc.scan_registry_connector("nope")
    assert res["images"] == [] and any("unknown" in n for n in res["notes"])


def test_scan_disabled_connector_is_safe_noop():
    svc = _svc([DISABLED_CONN])
    res = svc.scan_registry_connector("off")
    assert res["images"] == [] and any("disabled" in n for n in res["notes"])


def test_images_empty_before_scan():
    assert _svc([GHCR_CONN]).list_registry_connector_images() == []


# ── API routes ────────────────────────────────────────────────────────────────
try:
    import cnapp_api
    _HAVE_FASTAPI = cnapp_api._HAVE_FASTAPI
except Exception:
    _HAVE_FASTAPI = False

api = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi not installed")


def _client(svc, role="admin"):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    return TestClient(cnapp_api.create_app(svc, current_role=lambda: role))


@api
def test_route_registries_list_and_scan():
    c = _client(_svc([GHCR_CONN]))
    r = c.get("/registries")
    assert r.status_code == 200 and r.json()[0]["connector_id"] == "ghcr-main"
    s = c.post("/registries/ghcr-main/scan")
    assert s.status_code == 200 and len(s.json()["images"]) == 1
    imgs = c.get("/registries/images")
    assert imgs.status_code == 200 and imgs.json()[0]["scan_sources"] == ["oci-sidescan:ghcr"]


@api
def test_route_scan_requires_admin():
    c = _client(_svc([GHCR_CONN]), role="viewer")
    assert c.post("/registries/ghcr-main/scan").status_code == 403
    assert c.get("/registries").status_code == 200          # viewer may list
