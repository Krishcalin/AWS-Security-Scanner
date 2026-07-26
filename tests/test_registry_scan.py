"""Phase-4 Slice-5 — aws_registry_sbom Tier-B orchestrator helpers (B3).

select_registry_images (newest-N tagged, deduped, size-capped, fail-open) and
scan_registry_image (pull → overlay → OSV side-scan; fail-closed on integrity).
"""
import io
import json
import os
import sys
import tarfile
from datetime import datetime, timezone
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aws_registry_sbom as R
from test_live_scanner import MockPaginator


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


def _dt(month):
    return datetime(2026, month, 1, tzinfo=timezone.utc)


def _ecr_images(images):
    ecr = MagicMock()
    ecr.get_paginator.return_value = MockPaginator("imageDetails", images)
    return ecr


def _ecr_one_image(layer_digest="sha256:L1"):
    """A mock ecr whose batch_get_image returns a single v2 manifest with one gzip layer."""
    ecr = MagicMock()
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": layer_digest}]})
    ecr.batch_get_image.return_value = {"images": [{"imageManifest": manifest}]}
    ecr.get_download_url_for_layer.return_value = {"downloadUrl": "https://layer-blob"}
    return ecr


# ── select_registry_images ───────────────────────────────────────────────────
def test_select_newest_tagged_bounded_untagged_skipped():
    images = [
        {"imageDigest": "sha256:a", "imageTags": ["v3"], "imagePushedAt": _dt(3)},
        {"imageDigest": "sha256:b", "imageTags": ["v2"], "imagePushedAt": _dt(2)},
        {"imageDigest": "sha256:c", "imageTags": ["v1"], "imagePushedAt": _dt(1)},
        {"imageDigest": "sha256:d", "imagePushedAt": _dt(6)},           # untagged, newest -> skipped
    ]
    sel = R.select_registry_images(_ecr_images(images), "app", newest_n=2)
    assert [d["imageDigest"] for d in sel] == ["sha256:a", "sha256:b"]  # newest-2 tagged


def test_select_dedupes_by_digest():
    images = [{"imageDigest": "sha256:x", "imageTags": ["a"], "imagePushedAt": _dt(2)},
              {"imageDigest": "sha256:x", "imageTags": ["b"], "imagePushedAt": _dt(1)}]
    sel = R.select_registry_images(_ecr_images(images), "app", newest_n=5)
    assert len(sel) == 1


def test_select_size_cap_skips_oversized():
    images = [{"imageDigest": "sha256:big", "imageTags": ["v1"], "imageSizeInBytes": 9999},
              {"imageDigest": "sha256:sm", "imageTags": ["v2"], "imageSizeInBytes": 10}]
    notes = []
    sel = R.select_registry_images(_ecr_images(images), "app", newest_n=5,
                                   max_image_bytes=100, notes=notes)
    assert {d["imageDigest"] for d in sel} == {"sha256:sm"}
    assert any("exceeds size" in n for n in notes)


def test_select_fail_open_on_read_error():
    ecr = MagicMock()
    ecr.get_paginator.side_effect = RuntimeError("AccessDenied")
    notes = []
    assert R.select_registry_images(ecr, "app", newest_n=5, notes=notes) == []
    assert notes


# ── scan_registry_image ──────────────────────────────────────────────────────
def test_scan_image_builds_components_and_docid():
    layer = _layer({"app/node_modules/lodash/package.json":
                    b'{"name":"lodash","version":"4.17.20"}'})
    ecr = _ecr_one_image()
    notes = []
    r = R.scan_registry_image(
        ecr, "app", "1.dkr.ecr.us-east-1.amazonaws.com/app",
        {"imageDigest": "sha256:img", "imageTags": ["v1"]},
        http_get=lambda u: layer, feed=None, epss={}, kev=frozenset(), notes=notes)
    assert r.ok is True
    assert r.node_id == "1.dkr.ecr.us-east-1.amazonaws.com/app@sha256:img"
    assert "lodash" in {c.name for c in r.components}
    assert r.doc_id and r.doc_id.startswith("ecr-sidescan:")
    assert r.tags == ["v1"]


def test_scan_image_fail_closed_on_dropped_layer():
    ecr = _ecr_one_image()
    ecr.get_download_url_for_layer.side_effect = RuntimeError("AccessDenied")   # pull fails
    notes = []
    r = R.scan_registry_image(
        ecr, "app", "r/app", {"imageDigest": "sha256:img", "imageTags": ["v1"]},
        http_get=lambda u: b"x", feed=None, epss={}, kev=frozenset(), notes=notes)
    assert r.ok is False and r.result is None and r.components == [] and r.doc_id is None
    assert notes                                        # a note explains the drop


def test_scan_image_no_scannable_linux_layers():
    ecr = MagicMock()
    index = json.dumps({"mediaType": "application/vnd.oci.image.index.v1+json",
                        "manifests": [{"platform": {"os": "windows", "architecture": "amd64"},
                                       "digest": "sha256:w"}]})
    ecr.batch_get_image.return_value = {"images": [{"imageManifest": index}]}
    r = R.scan_registry_image(
        ecr, "app", "r/app", {"imageDigest": "sha256:img", "imageTags": ["v1"]},
        http_get=lambda u: b"", feed=None, epss={}, kev=frozenset())
    assert r.ok is False and r.note == "no-layers"


def test_scan_image_oversized_never_pulls():
    ecr = MagicMock()
    r = R.scan_registry_image(
        ecr, "app", "r/app",
        {"imageDigest": "sha256:img", "imageTags": ["v1"], "imageSizeInBytes": 10 ** 9},
        http_get=lambda u: b"", feed=None, epss={}, kev=frozenset(), max_image_bytes=1000)
    assert r.ok is False and r.note == "oversized"
    ecr.batch_get_image.assert_not_called()


def test_scan_image_fail_closed_on_corrupt_layer():
    # a downloaded-but-corrupt layer (bad gzip) must fail-closed, not scan a partial rootfs.
    ecr = _ecr_one_image()
    r = R.scan_registry_image(
        ecr, "app", "r/app", {"imageDigest": "sha256:img", "imageTags": ["v1"]},
        http_get=lambda u: b"not-a-valid-gzip-tar", feed=None, epss={}, kev=frozenset())
    assert r.ok is False and r.note == "partial-rootfs"


def test_scan_image_unknown_size_post_fetch_byte_cap():
    # imageSizeInBytes absent (unknown) must NOT bypass the cap — the post-fetch total bounds it.
    ecr = _ecr_one_image()
    r = R.scan_registry_image(
        ecr, "app", "r/app", {"imageDigest": "sha256:img", "imageTags": ["v1"]},
        http_get=lambda u: b"X" * 5000, feed=None, epss={}, kev=frozenset(), max_image_bytes=1000)
    assert r.ok is False and r.note == "oversized"
