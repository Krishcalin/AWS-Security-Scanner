"""Phase-4 Slice-5 · B5 — the _scan_registry_images orchestrator (Tier-B layer-pull).

Two-key gate (off by default), CWPP-05/06 emission, native+sidescan convergence on one
ECRImage node, and fail-open on a denied pull.
"""
import io
import json
import os
import sys
import tarfile
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aws_sidescan
from test_live_scanner import make_scanner, MockPaginator

_URI = "1.dkr.ecr.us-east-1.amazonaws.com/app"
_NODE = f"{_URI}@sha256:img"

_REPO = {"repositoryName": "app", "repositoryUri": _URI,
         "imageScanningConfiguration": {"scanOnPush": True},
         "encryptionConfiguration": {"encryptionType": "AES256"}}

# lodash 4.17.20 is < fixed 4.17.21 -> vulnerable
_LODASH_OSV = {"id": "CVE-2024-2", "aliases": ["CVE-2024-2"],
               "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                             "ranges": [{"type": "SEMVER",
                                         "events": [{"introduced": "4.0.0"},
                                                    {"fixed": "4.17.21"}]}]}],
               "severity": [{"type": "CVSS_V3", "score": "7.5"}]}


def _layer(files):
    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode="w:gz")
    for path, data in files.items():
        ti = tarfile.TarInfo(path)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    tf.close()
    return buf.getvalue()


_LODASH_LAYER = _layer({"app/node_modules/lodash/package.json":
                        b'{"name":"lodash","version":"4.17.20"}'})


def _ecr(native_findings, images=None, layer_digest="sha256:L1"):
    images = images or [{"imageDigest": "sha256:img", "imageTags": ["v1"], "imagePushedAt": 1}]
    ecr = MagicMock()
    ecr.describe_repositories.return_value = {"repositories": [_REPO]}
    ecr.get_paginator.return_value = MockPaginator("imageDetails", images)
    ecr.describe_image_scan_findings.return_value = {"imageScanFindings": native_findings}
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": layer_digest}]})
    ecr.batch_get_image.return_value = {"images": [{"imageManifest": manifest}]}
    ecr.get_download_url_for_layer.return_value = {"downloadUrl": "https://layer"}
    return ecr


def _scanner(ecr, *, images_on=False, feed_recs=(_LODASH_OSV,), kev=frozenset()):
    s = make_scanner(["ECR"])
    s._clients["ecr:us-east-1"] = ecr
    if images_on:
        s.side_scan_images = True
        s._layer_get = lambda u: _LODASH_LAYER
        feed = aws_sidescan.OSVFeed.from_records(list(feed_recs))
        s._vuln_db_bundle = (feed, {}, set(kev), set())
        s._vuln_db_loaded = True
    return s


def test_registry_sidescan_off_by_default():
    ecr = _ecr({"findings": []})
    s = _scanner(ecr, images_on=False)
    s._check_ecr()
    assert not any(r.check_id in ("CWPP-05", "CWPP-06") for r in s.results)
    ecr.batch_get_image.assert_not_called()               # no layer pull without the flag


def test_registry_sidescan_emits_and_converges_on_one_node():
    ecr = _ecr({"findings": [{"name": "CVE-NATIVE-1", "severity": "HIGH"}]})
    s = _scanner(ecr, images_on=True)
    s._check_ecr()
    # Tier-B own-SBOM CVE surfaces as CWPP-05
    assert any(r.check_id == "CWPP-05" and "CVE-2024-2" in r.message for r in s.results)
    # native (CNT-02) + sidescan both landed HAS_VULN on the SAME ECRImage node
    hv = [e for e in s.graph.to_dict()["edges"]
          if e["kind"] == "HAS_VULN" and e["source"] == _NODE]
    sources = {e.get("scan_source") for e in hv}
    assert "ecr-native-scan" in sources and "ecr-sidescan" in sources


def test_registry_sidescan_kev_is_critical_cwpp06():
    ecr = _ecr({"findings": []})
    s = _scanner(ecr, images_on=True, kev={"CVE-2024-2"})
    s._check_ecr()
    assert any(r.check_id == "CWPP-06" and r.severity == "CRITICAL" for r in s.results)
    assert not any(r.check_id == "CWPP-05" for r in s.results)   # KEV routes to 06, not 05


def test_registry_sidescan_pull_denied_fails_open():
    ecr = _ecr({"findings": []})
    ecr.get_download_url_for_layer.side_effect = RuntimeError("AccessDenied")
    s = _scanner(ecr, images_on=True)
    s._check_ecr()
    assert not any(r.check_id in ("CWPP-05", "CWPP-06") for r in s.results)   # no false CVE
    assert any(r.check_id == "CWPP-04" and r.status == "INFO"
               and "skipped" in r.message for r in s.results)


_LODASH_MED = {"id": "CVE-2024-9", "aliases": ["CVE-2024-9"],
               "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                             "ranges": [{"type": "SEMVER",
                                         "events": [{"introduced": "4.0.0"},
                                                    {"fixed": "4.17.21"}]}]}],
               "severity": [{"type": "CVSS_V3", "score": "5.0"}]}   # -> MEDIUM band


def test_registry_sidescan_filters_low_medium_non_kev():
    # a MEDIUM, non-KEV registry CVE must NOT emit a CWPP finding (matches Tier-A's CRIT/HIGH law).
    ecr = _ecr({"findings": []})
    s = _scanner(ecr, images_on=True, feed_recs=(_LODASH_MED,))
    s._check_ecr()
    assert not any(r.check_id in ("CWPP-05", "CWPP-06") for r in s.results)


def test_registry_only_image_stays_off_attack_path():
    # A registry-only image (no inbound RUNS_IMAGE from a reachable workload, no EXPOSED_TO)
    # carries HAS_VULN but can NEVER enter an attack path: nothing routes INTO it via an
    # E_PATH edge, and there is no internet source. So aws_correlate stays byte-frozen and a
    # registry KEV never becomes a false CRITICAL — it ranks shift-left.
    import aws_correlate
    ecr = _ecr({"findings": []})
    s = _scanner(ecr, images_on=True, kev={"CVE-2024-2"})       # even a KEV image
    s._check_ecr()
    edges = s.graph.to_dict()["edges"]
    assert any(e["kind"] == "HAS_VULN" and e["source"] == _NODE for e in edges)   # KEV is on the node
    inbound_path_edges = [e for e in edges
                          if e["target"] == _NODE and e["kind"] in aws_correlate.E_PATH]
    assert inbound_path_edges == []                             # nothing routes INTO the image
    assert s.graph.node("internet") is None                    # no entry seed -> no path at all
