"""Phase 4 (container-image + Lambda dependency scanning). Batch A: the OCI/Docker
layer overlay (merge_layers + ImageLayerExtractor) that presents a merged image
rootfs through the FilesystemExtractor Protocol and feeds the UNCHANGED Phase-3
side-scan pipeline. Pure/offline: synthetic tar.gz layers, no AWS, no disk."""
import io
import os
import sys
import tarfile
import zipfile
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_sidescan as ss
import aws_sidescan_lambda as lam


def _zip(files):
    buf = io.BytesIO()
    zf = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    for path, data in files.items():
        zf.writestr(path, data)
    zf.close()
    return buf.getvalue()


_LODASH_OSV = {"id": "CVE-2024-2", "aliases": ["CVE-2024-2"],
               "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                             "ranges": [{"type": "SEMVER",
                                         "events": [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}]}]}],
               "severity": [{"type": "CVSS_V3", "score": "7.5"}]}


def _layer(files=None, whiteouts=(), opaque_dirs=(), symlinks=()):
    """Build one gzip-tar image layer (bytes) from {relpath: bytes} + markers."""
    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode="w:gz")
    for path, data in (files or {}).items():
        ti = tarfile.TarInfo(path)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    for wo in whiteouts:
        d, _, b = wo.rpartition("/")
        marker = (d + "/.wh." + b) if d else ".wh." + b
        ti = tarfile.TarInfo(marker)
        ti.size = 0
        tf.addfile(ti, io.BytesIO(b""))
    for od in opaque_dirs:
        ti = tarfile.TarInfo(od.rstrip("/") + "/.wh..wh..opq")
        ti.size = 0
        tf.addfile(ti, io.BytesIO(b""))
    for link, target in symlinks:
        ti = tarfile.TarInfo(link)
        ti.type = tarfile.SYMTYPE
        ti.linkname = target
        tf.addfile(ti)
    tf.close()
    return buf.getvalue()


def test_merge_layers_overlay_upper_wins():
    m = ss.merge_layers([_layer({"etc/motd": b"lower", "app/keep": b"k"}),
                         _layer({"etc/motd": b"upper"})])
    assert m["/etc/motd"] == b"upper" and m["/app/keep"] == b"k"


def test_merge_layers_whiteout_deletes_lower():
    m = ss.merge_layers([_layer({"app/gone": b"x", "app/stay": b"y"}),
                         _layer(whiteouts=["app/gone"])])
    assert "/app/gone" not in m and m["/app/stay"] == b"y"


def test_merge_layers_opaque_dir_clears_lower_subtree():
    m = ss.merge_layers([_layer({"data/a": b"1", "data/sub/b": b"2", "other/c": b"3"}),
                         _layer({"data/new": b"n"}, opaque_dirs=["data"])])
    assert "/data/a" not in m and "/data/sub/b" not in m       # opaque cleared subtree
    assert m["/data/new"] == b"n" and m["/other/c"] == b"3"    # own file + sibling dir kept


def test_merge_layers_whiteout_applies_to_lower_only():
    # a whiteout + a re-add of the same path in the SAME layer -> the re-add wins
    m = ss.merge_layers([_layer({"x/f": b"old"}),
                         _layer({"x/f": b"new"}, whiteouts=["x/f"])])
    assert m["/x/f"] == b"new"


def test_merge_layers_symlink_baked():
    m = ss.merge_layers([_layer({"real/config": b"data"},
                                symlinks=[("link/config", "../real/config")])])
    assert m.get("/link/config") == b"data"


def test_merge_layers_bad_layer_fail_open():
    notes = []
    m = ss.merge_layers([b"not-a-tar-blob", _layer({"a": b"1"})], notes=notes)
    assert m["/a"] == b"1" and notes                          # bad layer noted, good kept


def test_merge_layers_traversal_guard():
    m = ss.merge_layers([_layer({"../escape": b"bad", "ok/file": b"good"})])
    assert not any("escape" in k for k in m) and m["/ok/file"] == b"good"


def test_merge_layers_file_size_cap():
    big = _layer({"huge": b"x" * 2000})
    m = ss.merge_layers([big], max_file_bytes=1000)
    assert "/huge" not in m                                    # oversize file skipped


def test_image_extractor_is_filesystem_extractor():
    ext = ss.ImageLayerExtractor([_layer({"etc/os-release": b"ID=alpine\nVERSION_ID=3.19\n"})])
    assert ext.read_file("/etc/os-release").startswith(b"ID=alpine")
    assert ext.exists("/etc/os-release") and not ext.exists("/nope")
    assert "/etc/os-release" in list(ext.walk("/etc", 100))


# ── installed-package metadata (no lockfile) — the recall lever ──────────────
def test_parse_node_package_json():
    pkgs = ss.parse_node_package_json(b'{"name":"lodash","version":"4.17.20"}')
    assert (pkgs[0].name, pkgs[0].version, pkgs[0].origin) == ("lodash", "4.17.20", "npm")
    assert ss.parse_node_package_json(b'{"name":"x"}') == []          # no version


def test_parse_python_metadata():
    meta = b"Metadata-Version: 2.1\nName: Django\nVersion: 3.2.0\nSummary: x\n\nbody\n"
    pkgs = ss.parse_python_metadata(meta)
    assert (pkgs[0].name, pkgs[0].version) == ("django", "3.2.0")     # PEP503-normalized


def test_parse_gemspec_name():
    assert ss.parse_gemspec_name("x/specifications/rails-7.0.0.gemspec")[0].name == "rails"
    nk = ss.parse_gemspec_name("specifications/nokogiri-1.15.0-x86_64-linux.gemspec")
    assert (nk[0].name, nk[0].version) == ("nokogiri", "1.15.0")      # platform ignored


def test_image_installed_metadata_no_lockfile():
    # a distroless-style image: no lockfile, just the installed trees
    layer = _layer({
        "app/node_modules/lodash/package.json": b'{"name":"lodash","version":"4.17.20"}',
        "usr/lib/python3.11/site-packages/django-3.2.0.dist-info/METADATA":
            b"Name: Django\nVersion: 3.2.0\n\n",   # under /usr/lib -> not a default root
        "opt/lib/ruby/gems/3.2.0/specifications/rails-7.0.0.gemspec": b"# ruby",
    })
    pkgs = ss.collect_app_packages(ss.ImageLayerExtractor([layer]))
    names = {(p.name, p.origin) for p in pkgs}
    assert ("lodash", "npm") in names               # node_modules/*/package.json
    assert ("rails", "gem") in names                # gemspec under /opt (a default root)


def test_image_end_to_end_app_dependency_cve():
    base = _layer({"etc/os-release": b"ID=ubuntu\nVERSION_ID=22.04\n",
                   "var/lib/dpkg/status": b""})
    app = _layer({"app/package-lock.json":
                  b'{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}'})
    ext = ss.ImageLayerExtractor([base, app])
    feed = ss.OSVFeed.from_records([{"id": "CVE-2024-2", "aliases": ["CVE-2024-2"],
        "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                      "ranges": [{"type": "SEMVER",
                                  "events": [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}]}]}],
        "severity": [{"type": "CVSS_V3", "score": "7.5"}]}])
    res = ss.sidescan_filesystem(ext, feed, {}, set())
    assert any(p.name == "lodash" for p in res.packages)
    assert any(v.cve == "CVE-2024-2" for v in res.vulns)      # image CVE via unchanged pipeline


# ── Lambda artifact extractor (LMB-07) ───────────────────────────────────────
def test_merge_lambda_artifact_roots():
    fn = _zip({"index.js": b"x", "node_modules/lodash/package.json":
               b'{"name":"lodash","version":"1.0.0"}'})
    layer = _zip({"nodejs/node_modules/ws/package.json": b'{"name":"ws","version":"8.0.0"}'})
    m = lam.merge_lambda_artifact(fn, [layer])
    assert "/var/task/index.js" in m                         # function code -> /var/task
    assert "/opt/nodejs/node_modules/ws/package.json" in m   # layer -> /opt


def test_merge_lambda_layer_overwrites_earlier():
    m = lam.merge_lambda_artifact(None, [_zip({"nodejs/x": b"L1"}), _zip({"nodejs/x": b"L2"})])
    assert m["/opt/nodejs/x"] == b"L2"                        # later layer wins


def test_lambda_artifact_end_to_end():
    fn = _zip({"node_modules/lodash/package.json": b'{"name":"lodash","version":"4.17.20"}'})
    ext = lam.LambdaArtifactExtractor(fn)
    feed = ss.OSVFeed.from_records([_LODASH_OSV])
    res = ss.sidescan_filesystem(ext, feed, {}, set())
    assert any(v.cve == "CVE-2024-2" for v in res.vulns)     # Lambda dep CVE via unchanged pipeline


def test_lambda_artifact_bad_zip_fail_open():
    notes = []
    m = lam.merge_lambda_artifact(b"not-a-zip", notes=notes)
    assert m == {} and notes


def test_lambda_artifact_traversal_guard():
    m = lam.merge_lambda_artifact(_zip({"../evil": b"x", "ok.py": b"y"}))
    assert "/var/task/ok.py" in m and not any("evil" in k for k in m)


def test_fetch_lambda_artifact_zip():
    lmb = MagicMock()
    lmb.get_function.return_value = {
        "Configuration": {"PackageType": "Zip", "Layers": [{"Arn": "arn:layer:1"}]},
        "Code": {"Location": "https://code"}}
    lmb.get_layer_version_by_arn.return_value = {"Content": {"Location": "https://layer"}}
    blobs = {"https://code": b"CODEZIP", "https://layer": b"LAYERZIP"}
    fz, lz, pt = lam.fetch_lambda_artifact(lmb, "fn", http_get=lambda u: blobs[u])
    assert fz == b"CODEZIP" and lz == [b"LAYERZIP"] and pt == "Zip"


def test_fetch_lambda_image_packagetype_routes_to_ecr():
    lmb = MagicMock()
    lmb.get_function.return_value = {"Configuration": {"PackageType": "Image"},
                                     "Code": {"ImageUri": "1.dkr.ecr..."}}
    fz, lz, pt = lam.fetch_lambda_artifact(lmb, "fn", http_get=lambda u: b"")
    assert pt == "Image" and fz is None and lz == []


def test_fetch_lambda_get_function_error_raises():
    lmb = MagicMock()
    lmb.get_function.side_effect = RuntimeError("AccessDenied")
    try:
        lam.fetch_lambda_artifact(lmb, "fn", http_get=lambda u: b"")
        assert False, "should raise LambdaArtifactUnavailable"
    except lam.LambdaArtifactUnavailable:
        pass
