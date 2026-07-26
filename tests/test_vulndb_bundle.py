"""overwatch-vulndb offline feed builder — assembles the {records,epss,kev,exploits} JSON the
runtime already parses, and signs it (vendored Ed25519). Validates: the merged feed is
consumable by the real matcher (OSVFeed.from_records), ecosystem scoping + withdrawn drops,
zip bulk archives, EPSS/KEV parsing, and the sign→verify (+ tamper) round-trip. Pure/offline."""
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import overwatch_vulndb as ovd
import aws_ed25519
from aws_sidescan import OSVFeed


def _osv(cid, eco, name, introduced="0", fixed="9.9", withdrawn=False):
    rec = {"id": cid, "affected": [{"package": {"ecosystem": eco, "name": name},
           "ranges": [{"type": "ECOSYSTEM",
                       "events": [{"introduced": introduced}, {"fixed": fixed}]}]}],
           "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    if withdrawn:
        rec["withdrawn"] = "2020-01-01T00:00:00Z"
    return rec


def _write(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)


def test_build_merges_and_is_matcher_consumable(tmp_path):
    osv = tmp_path / "osv"
    osv.mkdir()
    _write(osv / "a.json", _osv("CVE-2021-1", "Debian:12", "openssl"))
    _write(osv / "b.json", [_osv("CVE-2021-2", "npm", "lodash")])   # a list member
    epss = tmp_path / "epss.csv"
    epss.write_text("#model_version:v2\ncve,epss,percentile\nCVE-2021-1,0.97,0.99\n", encoding="utf-8")
    kev = tmp_path / "kev.json"
    _write(kev, {"vulnerabilities": [{"cveID": "CVE-2021-1"}]})
    out = tmp_path / "feed.json"

    rc = ovd.main(["build", "--osv", str(osv), "--epss", str(epss), "--kev", str(kev), "--out", str(out)])
    assert rc == 0
    feed = json.loads(out.read_text())
    assert {r["id"] for r in feed["records"]} == {"CVE-2021-1", "CVE-2021-2"}
    assert feed["epss"] == {"CVE-2021-1": 0.97}
    assert feed["kev"] == ["CVE-2021-1"]
    # the real engine can index + query the merged records (byte-exact ecosystem preserved)
    hits = OSVFeed.from_records(feed["records"]).query("Debian:12", "openssl")
    assert len(hits) == 1 and hits[0]["id"] == "CVE-2021-1"
    # a manifest lands beside the feed with a matching sha256
    man = json.loads((tmp_path / "feed.json.manifest.json").read_text())
    assert man["record_count"] == 2 and man["feed_sha256"]


def test_out_of_scope_ecosystem_and_withdrawn_dropped(tmp_path):
    osv = tmp_path / "osv"
    osv.mkdir()
    _write(osv / "keep.json", _osv("CVE-1", "Ubuntu:22.04", "bash"))
    _write(osv / "drop_eco.json", _osv("CVE-2", "Packagist", "monolog"))   # not engine-matched
    _write(osv / "drop_wd.json", _osv("CVE-3", "npm", "leftpad", withdrawn=True))
    out = tmp_path / "feed.json"
    ovd.main(["build", "--osv", str(osv), "--out", str(out)])
    ids = {r["id"] for r in json.loads(out.read_text())["records"]}
    assert ids == {"CVE-1"}


def test_ecosystem_override(tmp_path):
    osv = tmp_path / "osv"
    osv.mkdir()
    _write(osv / "a.json", _osv("CVE-1", "Packagist", "monolog"))
    out = tmp_path / "feed.json"
    ovd.main(["build", "--osv", str(osv), "--ecosystems", "packagist", "--out", str(out)])
    assert {r["id"] for r in json.loads(out.read_text())["records"]} == {"CVE-1"}


def test_osv_bulk_zip_archive(tmp_path):
    zpath = tmp_path / "all.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("CVE-2021-1.json", json.dumps(_osv("CVE-2021-1", "Alpine:v3.18", "musl")))
        z.writestr("CVE-2021-2.json", json.dumps(_osv("CVE-2021-2", "Alpine:v3.18", "busybox")))
        z.writestr("README.txt", "ignored non-json member")
    recs = ovd.load_osv(str(zpath), ovd.DEFAULT_ECOSYSTEMS)
    assert {r["id"] for r in recs} == {"CVE-2021-1", "CVE-2021-2"}


def test_epss_gzip_and_kev_parsing(tmp_path):
    import gzip
    gz = tmp_path / "epss.csv.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as fh:
        fh.write("#model\ncve,epss,percentile\nCVE-9,0.5,0.8\nnotacve,1,1\n")
    assert ovd.load_epss(str(gz)) == {"CVE-9": 0.5}
    kev = tmp_path / "kev.json"
    _write(kev, {"vulnerabilities": [{"cveID": "CVE-9"}, {"cveID": "CVE-9"}, {"other": 1}]})
    assert ovd.load_kev(str(kev)) == ["CVE-9"]


def test_sign_verify_round_trip_and_tamper(tmp_path, capsys):
    # keygen -> build+sign -> verify OK -> tamper -> verify FAIL (exit 1)
    ovd.main(["keygen", "--out-prefix", str(tmp_path / "k")])
    osv = tmp_path / "osv"; osv.mkdir()
    _write(osv / "a.json", _osv("CVE-1", "Debian:12", "openssl"))
    out = tmp_path / "feed.json"
    ovd.main(["build", "--osv", str(osv), "--out", str(out), "--key", str(tmp_path / "k.key")])
    assert (tmp_path / "feed.json.sig").exists()
    assert ovd.main(["verify", "--pub", str(tmp_path / "k.pub"), "--in", str(out)]) == 0

    tampered = json.loads(out.read_text())
    tampered["kev"] = ["CVE-INJECTED"]
    out.write_text(json.dumps(tampered, sort_keys=True, separators=(",", ":")))
    assert ovd.main(["verify", "--pub", str(tmp_path / "k.pub"), "--in", str(out)]) == 1


def test_verify_matches_runtime_ed25519(tmp_path):
    # the CLI's sign and the runtime's aws_ed25519.verify agree over the exact file bytes
    ovd.main(["keygen", "--out-prefix", str(tmp_path / "k")])
    f = tmp_path / "feed.json"
    f.write_bytes(b'{"records":[],"epss":{},"kev":[],"exploits":[]}')
    ovd.main(["sign", "--key", str(tmp_path / "k.key"), "--in", str(f)])
    pub = bytes.fromhex((tmp_path / "k.pub").read_text().strip())
    sig = bytes.fromhex((tmp_path / "feed.json.sig").read_text().strip())
    assert aws_ed25519.verify(pub, f.read_bytes(), sig) is True
