"""Regressions for the 12 adversarial-verify fixes on Phase 4 (container/Lambda scan):
symlink overlay (blocker), roots/cap/npm-gate/lambda-bomb/manifest-linux/fetch-fail-closed
(major), root-opaque/py-metadata/gemspec/lambda-note/partition (minor)."""
import io
import os
import sys
import zipfile
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import aws_sidescan as ss
import aws_sidescan_lambda as lam
import aws_sidescan_image as img
import aws_live_scanner as A
from test_phase4_containers import _layer, _zip


# 1 (BLOCKER). symlink overlay: upper real file / whiteout beats a lower symlink
def test_symlink_lower_does_not_clobber_upper_real_file():
    base = _layer({"shared/clean.json": b"CLEAN"}, symlinks=[("app/lock", "../shared/clean.json")])
    upper = _layer({"app/lock": b"REAL"})          # upper replaces the symlink with a real file
    m = ss.merge_layers([base, upper])
    assert m["/app/lock"] == b"REAL"               # upper wins (was clobbered back to CLEAN)


def test_symlink_lower_not_resurrected_by_whiteout():
    base = _layer({"shared/x": b"V"}, symlinks=[("app/lock", "../shared/x")])
    upper = _layer(whiteouts=["app/lock"])         # dependency removed in the upper layer
    m = ss.merge_layers([base, upper])
    assert "/app/lock" not in m                    # not resurrected from the lower target


def test_symlink_still_baked_when_surviving_no_marker_leak():
    m = ss.merge_layers([_layer({"real/config": b"data"},
                                symlinks=[("link/config", "../real/config")])])
    assert m.get("/link/config") == b"data"
    assert not any(isinstance(v, tuple) for v in m.values())   # no marker tuple leaks


def test_symlink_chain_resolves_deterministically():
    # a -> b -> real/lock.json : a 2-hop chain must bake the real bytes regardless of
    # tar member order (was order-dependent single-hop, verify nit fixed to fixed-point).
    m = ss.merge_layers([_layer(
        {"real/lock.json": b'{"name":"x"}'},
        symlinks=[("app/lock", "./mid"), ("app/mid", "../real/lock.json")])])
    assert m.get("/app/lock") == b'{"name":"x"}'
    assert m.get("/app/mid") == b'{"name":"x"}'
    assert not any(isinstance(v, tuple) for v in m.values())


def test_symlink_cycle_dropped_not_leaked():
    m = ss.merge_layers([_layer(symlinks=[("a/x", "./y"), ("a/y", "./x")])])
    assert "/a/x" not in m and "/a/y" not in m          # cycle -> dropped, never a tuple
    assert not any(isinstance(v, tuple) for v in m.values())


# 8. root-level opaque clears the whole lower tree
def test_root_opaque_clears_lower():
    m = ss.merge_layers([_layer({"a": b"1", "b/c": b"2"}), _layer({"d": b"n"}, opaque_dirs=[""])])
    assert set(m) == {"/d"}


# 2. default roots cover python:3.x / ruby:3.x install locations
def test_collect_app_packages_usr_local_lib_roots():
    ext = ss.DictExtractor({
        "/usr/local/lib/python3.11/site-packages/django-3.2.0.dist-info/METADATA":
            b"Name: Django\nVersion: 3.2.0\n\n",
        "/usr/local/bundle/specifications/rails-7.0.0.gemspec": b"# ruby"})
    names = {(p.name, p.origin) for p in ss.collect_app_packages(ext)}
    assert ("django", "pypi") in names and ("rails", "gem") in names


# 3. walk truncation emits a note (no silent false-clean)
def test_collect_app_packages_truncation_note():
    files = {f"/app/node_modules/f{i}/x.txt": b"" for i in range(30)}
    files["/app/requirements.txt"] = b"flask==2.0.0\n"
    notes = []
    ss.collect_app_packages(ss.DictExtractor(files), max_files=5, notes=notes)
    assert any("truncated" in n for n in notes)


# 4. npm package-root gate: test fixtures under node_modules are NOT emitted
def test_node_package_json_skips_fixtures():
    ext = ss.DictExtractor({
        "/app/node_modules/eslint/package.json": b'{"name":"eslint","version":"8.0.0"}',
        "/app/node_modules/eslint/tests/fixtures/p/package.json":
            b'{"name":"totally-not-installed","version":"0.0.1"}',
        "/app/node_modules/@scope/pkg/package.json": b'{"name":"@scope/pkg","version":"1.0.0"}',
        "/app/node_modules/a/node_modules/b/package.json": b'{"name":"b","version":"2.0.0"}'})
    names = {p.name for p in ss.collect_app_packages(ext)}
    assert "eslint" in names and "@scope/pkg" in names and "b" in names   # real deps kept
    assert "totally-not-installed" not in names                          # fixture skipped


# 9. python METADATA: a folded whitespace-only continuation line before Version
def test_parse_python_metadata_folded_continuation():
    meta = b"Metadata-Version: 2.1\nName: foo\nLicense: line1\n        \n        line2\nVersion: 9.9.9\n\n"
    pkgs = ss.parse_python_metadata(meta)
    assert pkgs and (pkgs[0].name, pkgs[0].version) == ("foo", "9.9.9")


# 10. gemspec: a name containing a '-<digit>' segment before the version
def test_parse_gemspec_name_dash_digit_name():
    assert ss.parse_gemspec_name("specifications/foo-2-bar-1.0.0.gemspec")[0].name == "foo-2-bar"
    assert ss.parse_gemspec_name("specifications/bootstrap-4-rails-5.1.0.gemspec")[0].version == "5.1.0"
    assert ss.parse_gemspec_name("specifications/rails-7.0.0.gemspec")[0].version == "7.0.0"   # unchanged
    nk = ss.parse_gemspec_name("specifications/nokogiri-1.15.0-x86_64-linux.gemspec")
    assert (nk[0].name, nk[0].version) == ("nokogiri", "1.15.0")          # platform still stripped


# 5. lambda zip-bomb: bounded read (declared size may be understated)
def test_lambda_zip_bomb_bounded():
    buf = io.BytesIO()
    zf = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    zf.writestr("big.bin", b"\x00" * 2_000_000)
    zf.close()
    m = lam.merge_lambda_artifact(buf.getvalue(), max_file_bytes=1000)
    assert "/var/task/big.bin" not in m


# 11. lambda oversize entry emits a note
def test_lambda_oversize_emits_note():
    notes = []
    lam.merge_lambda_artifact(_zip({"huge.js": b"x" * 2000}), max_file_bytes=1000, notes=notes)
    assert any("skipped" in n for n in notes)


# 6. manifest-list fallback must not pick a windows child over a linux one
def test_fetch_ecr_layers_fallback_prefers_linux():
    ecr = MagicMock()
    index = json.dumps({"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
        {"digest": "sha256:win", "platform": {"os": "windows", "architecture": "amd64"}},
        {"digest": "sha256:linarm", "platform": {"os": "linux", "architecture": "arm64"}}]})
    child = json.dumps({"mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:l"}]})

    def _bgi(repositoryName, imageIds, acceptedMediaTypes):
        want = imageIds[0].get("imageDigest") == "sha256:linarm"
        return {"images": [{"imageManifest": child if want else index}]}
    ecr.batch_get_image.side_effect = _bgi
    ecr.get_download_url_for_layer.return_value = {"downloadUrl": "https://l"}
    assert img.fetch_ecr_layers(ecr, "app", {"imageDigest": "t"}, http_get=lambda u: b"L") == [b"L"]


def test_fetch_ecr_layers_no_linux_child_empty_with_note():
    ecr = MagicMock()
    index = json.dumps({"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
        {"digest": "sha256:win", "platform": {"os": "windows", "architecture": "amd64"}}]})
    ecr.batch_get_image.return_value = {"images": [{"imageManifest": index}]}
    notes = []
    out = img.fetch_ecr_layers(ecr, "app", {"imageDigest": "t"}, http_get=lambda u: b"", notes=notes)
    assert out == [] and any("linux" in n for n in notes)


# 7. fetch_ecr_layers fail-closed: a dropped layer aborts (no partial rootfs)
def test_fetch_ecr_layers_layer_download_fails_closed():
    ecr = MagicMock()
    manifest = json.dumps({"mediaType": "application/vnd.oci.image.manifest.v1+json", "layers": [
        {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:l1"},
        {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:l2"}]})
    ecr.batch_get_image.return_value = {"images": [{"imageManifest": manifest}]}
    ecr.get_download_url_for_layer.side_effect = \
        lambda repositoryName, layerDigest: {"downloadUrl": f"https://{layerDigest}"}

    def _get(u):
        if "l2" in u:
            raise RuntimeError("presigned URL expired")
        return b"L1"
    try:
        img.fetch_ecr_layers(ecr, "app", {"imageDigest": "t"}, http_get=_get)
        assert False, "should fail-closed, not return a partial overlay"
    except img.ImageFetchUnavailable:
        pass


# 12. partition-aware node ids (aws-cn / aws-us-gov)
def test_ecr_image_node_ids_partitions():
    cn = A.ecr_image_node_ids("1", "cn-north-1", "app", "sha256:x")
    assert cn[0] == "1.dkr.ecr.cn-north-1.amazonaws.com.cn/app@sha256:x"
    assert cn[1] == "arn:aws-cn:ecr:cn-north-1:1:repository/app/sha256:x"
    assert A.ecr_image_node_ids("1", "us-gov-west-1", "app", "sha256:x")[1].startswith("arn:aws-us-gov:ecr:")
    assert A.ecr_image_node_ids("1", "us-east-1", "app", "sha256:x")[1] == \
        "arn:aws:ecr:us-east-1:1:repository/app/sha256:x"    # commercial unchanged
